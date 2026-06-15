package main

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// wgTransfer returns pubkey -> {rx,tx} cumulative byte counters (since interface up).
func wgTransfer(iface string) map[string][2]int64 {
	m := map[string][2]int64{}
	out, err := run("wg", "show", iface, "transfer")
	if err != nil {
		return m
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 {
			rx, _ := strconv.ParseInt(f[1], 10, 64)
			tx, _ := strconv.ParseInt(f[2], 10, 64)
			m[f[0]] = [2]int64{rx, tx}
		}
	}
	return m
}

// ensureIPSet makes sure the block ipset and its FORWARD drop rules exist (idempotent).
// Blocked peers' tunnel IPs go in the set; their forwarded traffic (both directions) is
// dropped — the WireGuard handshake stays up, only data is blocked, and unblock is instant.
func ensureIPSet(cfg Config) {
	run("ipset", "create", cfg.IPSet, "hash:ip", "-exist")
	ensureDropRule(cfg.IPSet, "src")
	ensureDropRule(cfg.IPSet, "dst")
}

func ensureDropRule(setName, dir string) {
	check := []string{"-C", "FORWARD", "-m", "set", "--match-set", setName, dir, "-j", "DROP"}
	if _, err := run("iptables", check...); err != nil {
		run("iptables", "-I", "FORWARD", "1", "-m", "set", "--match-set", setName, dir, "-j", "DROP")
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// usedTotal is a user's COMBINED usage across WireGuard and OpenVPN — the single number a
// per-user quota is measured against (e.g. 20 GB over WG + 30 GB over OVPN = 50 GB).
func usedTotal(p Peer) int64 { return p.UsedBytes + p.UsedOvpnBytes }

// effectiveBlocked: a peer is blocked if disabled, expired, or over the combined quota.
func effectiveBlocked(p Peer, now time.Time) bool {
	if !p.Enabled {
		return true
	}
	if p.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, p.ExpiresAt); err == nil && now.After(t) {
			return true
		}
	}
	if p.QuotaBytes > 0 && usedTotal(p) >= p.QuotaBytes {
		return true
	}
	return false
}

// enforceTick: update cumulative usage (delta carry-over, survives counter resets) and
// sync the block ipset to the set of peers that should be blocked.
func enforceTick(db *sql.DB, cfg Config) {
	ensureIPSet(cfg)
	tr := wgTransfer(cfg.Interface)
	ov := ovpnUsage(cfg.OvpnMgmt) // CN -> session bytes; empty map when OVPN is not configured
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	for _, p := range allPeers(db) {
		// WireGuard usage (per pubkey; rx/tx counters reset when the interface restarts).
		if cur, ok := tr[p.PublicKey]; ok && p.PublicKey != "" {
			rx, tx := cur[0], cur[1]
			drx := rx - p.LastRx
			if rx < p.LastRx { // counter reset (reboot / peer re-add)
				drx = rx
			}
			dtx := tx - p.LastTx
			if tx < p.LastTx {
				dtx = tx
			}
			p.UsedBytes += drx + dtx
			p.LastRx, p.LastTx = rx, tx
			db.Exec("UPDATE peers SET used_bytes=?,last_rx=?,last_tx=?,updated_at=? WHERE id=?",
				p.UsedBytes, rx, tx, nowStr, p.ID)
		}
		// OpenVPN usage (per CN; single byte counter resets on reconnect).
		if p.OvpnCN != "" {
			if cur, ok := ov[p.OvpnCN]; ok {
				d := cur - p.LastOvpnBytes
				if cur < p.LastOvpnBytes { // reconnect -> counter reset
					d = cur
				}
				p.UsedOvpnBytes += d
				p.LastOvpnBytes = cur
				db.Exec("UPDATE peers SET used_ovpn_bytes=?,last_ovpn_bytes=?,updated_at=? WHERE id=?",
					p.UsedOvpnBytes, cur, nowStr, p.ID)
			}
		}
		// Combined-quota enforcement: when over the shared cap, block BOTH tunnel IPs in
		// the one ipset (the FORWARD drop is interface-agnostic, so it covers wg0 and tun0).
		blocked := effectiveBlocked(p, now)
		for _, ip := range []string{p.Address, p.OvpnIP} {
			if ip == "" {
				continue
			}
			if blocked {
				run("ipset", "add", cfg.IPSet, ip, "-exist")
			} else {
				run("ipset", "del", cfg.IPSet, ip)
			}
		}
		if blocked != p.Blocked {
			db.Exec("UPDATE peers SET blocked=? WHERE id=?", b2i(blocked), p.ID)
		}
	}
}

// cmdServe runs the enforcement loop forever (systemd service). Phase 3 starts the API here too.
func cmdServe() {
	cfg := loadConfig()
	db := openDB(cfg.DB)
	defer db.Close()
	interval := time.Duration(cfg.IntervalS) * time.Second
	if interval <= 0 {
		interval = 180 * time.Second
	}
	fmt.Printf("wgmgr serve: enforcing every %s (iface=%s ipset=%s)\n", interval, cfg.Interface, cfg.IPSet)
	startAPI(cfg, db) // Phase 3: non-blocking; no-op until implemented
	for {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					fmt.Fprintf(os.Stderr, "enforce tick error: %v\n", rec)
				}
			}()
			enforceTick(db, cfg)
		}()
		time.Sleep(interval)
	}
}
