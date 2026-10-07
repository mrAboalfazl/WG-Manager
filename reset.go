package main

import (
	"database/sql"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

type resetCounters struct{ rx, tx, ovpn int64 }
type resetCounterReader func(Config, Peer) (resetCounters, error)

// Sample the same counter sources used by enforcement. Zero only the billing
// period; a live tunnel's cumulative counters become the next period's baseline.
// Counter read failures must return an error instead of claiming a reset worked.
func readResetCounters(cfg Config, p Peer) (resetCounters, error) {
	c := resetCounters{p.LastRx, p.LastTx, p.LastOvpnBytes}
	if p.PublicKey != "" {
		out, err := run("wg", "show", cfg.Interface, "transfer")
		if err != nil {
			return c, fmt.Errorf("cannot read WireGuard counters: %w", err)
		}
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || fields[0] != p.PublicKey {
				continue
			}
			if len(fields) != 3 {
				return c, fmt.Errorf("invalid WireGuard counter row")
			}
			rx, rxErr := strconv.ParseInt(fields[1], 10, 64)
			tx, txErr := strconv.ParseInt(fields[2], 10, 64)
			if rxErr != nil || txErr != nil || rx < 0 || tx < 0 {
				return c, fmt.Errorf("invalid WireGuard byte counters")
			}
			c.rx, c.tx = rx, tx
		}
	}
	if p.OvpnCN != "" {
		if cfg.OvpnMgmt == "" && cfg.OvpnStatus == "" {
			return c, fmt.Errorf("OpenVPN traffic tracking is not configured")
		}
		statusFile := resolveOvpnStatus(cfg)
		if statusFile != "" {
			if b, err := os.ReadFile(statusFile); err == nil {
				info, err := os.Stat(statusFile)
				if err != nil || time.Since(info.ModTime()) > 2*time.Minute {
					return c, fmt.Errorf("OpenVPN status is stale; retry after accounting recovers")
				}
				if !strings.Contains("\n"+strings.ReplaceAll(string(b), "\r", ""), "\nEND") {
					return c, fmt.Errorf("OpenVPN status is incomplete; retry reset")
				}
				c.ovpn = parseOvpnStatus(string(b))[p.OvpnCN]
				return c, nil
			}
		}
		if cfg.OvpnMgmt == "" {
			return c, fmt.Errorf("cannot read OpenVPN counters")
		}
		usage, err := ovpnUsageMgmt(cfg.OvpnMgmt)
		if err != nil {
			return c, fmt.Errorf("cannot read OpenVPN counters: %w", err)
		}
		c.ovpn = usage[p.OvpnCN]
	}
	return c, nil
}

// Serialize with the serve process's enforcement loop. Fetch the peer after
// acquiring the lock so a reset never uses a stale baseline from the request.
func rechargePeer(db *sql.DB, cfg Config, username string, m map[string]any, snapshot resetCounterReader) error {
	enforceMu.Lock()
	defer enforceMu.Unlock()
	p, ok := getPeer(db, username)
	if !ok {
		return fmt.Errorf("no such user %q", username)
	}
	reset, _ := m["reset"].(bool)
	if v, present := m["reset"]; present {
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("reset must be a boolean")
		}
	}
	for _, key := range []string{"set_gb", "add_gb"} {
		if v, present := m[key]; present {
			n, ok := v.(float64)
			if !ok || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) || n >= float64(math.MaxInt64)/(1024*1024*1024) {
				return fmt.Errorf("%s must be a non-negative GB amount", key)
			}
		}
	}
	_, hasSet := m["set_gb"]
	_, hasAdd := m["add_gb"]
	if !reset && !hasSet && !hasAdd {
		return fmt.Errorf("recharge needs reset, set_gb, or add_gb")
	}
	var counters resetCounters
	if reset {
		var err error
		counters, err = snapshot(cfg, p)
		if err != nil {
			return err
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if reset {
		_, err = tx.Exec(`UPDATE peers SET used_bytes=0,used_ovpn_bytes=0,
			last_rx=?,last_tx=?,last_ovpn_bytes=?,updated_at=? WHERE id=?`,
			counters.rx, counters.tx, counters.ovpn, nowUTC(), p.ID)
		if err != nil {
			return err
		}
	}
	if v, ok := m["set_gb"].(float64); ok {
		if _, err := tx.Exec("UPDATE peers SET quota_bytes=?,updated_at=? WHERE id=?", gbToBytes(v), nowUTC(), p.ID); err != nil {
			return err
		}
	}
	if v, ok := m["add_gb"].(float64); ok {
		if _, err := tx.Exec("UPDATE peers SET quota_bytes=quota_bytes+?,updated_at=? WHERE id=?", gbToBytes(v), nowUTC(), p.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
