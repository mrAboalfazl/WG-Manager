package main

import (
	"database/sql"
	"net/http"
)

// resetUsageBaselines keeps the live tunnel counters as the starting point for
// the next accounting period. A reset must never set these to zero: WireGuard
// and OpenVPN both expose cumulative counters, so doing that would count all
// traffic since the interface/session started again on the next enforcement tick.
func resetUsageBaselines(p Peer, wg map[string][2]int64, ovpn map[string]int64) (rx, tx, ovpnBytes int64) {
	rx, tx, ovpnBytes = p.LastRx, p.LastTx, p.LastOvpnBytes
	if p.PublicKey != "" {
		if cur, ok := wg[p.PublicKey]; ok {
			rx, tx = cur[0], cur[1]
		}
	}
	if p.OvpnCN != "" {
		if cur, ok := ovpn[p.OvpnCN]; ok {
			ovpnBytes = cur
		}
	}
	return
}

// resetPeerUsage archives the current WG and OpenVPN period, advances both
// lifetime counters, and starts a new period at the current live counters.
// The same function is used by the panel API and CLI so their behavior cannot
// drift. The enforcement mutex makes the read/insert/update sequence atomic
// with respect to the background accounting loop.
func resetPeerUsage(db *sql.DB, cfg Config, p Peer) error {
	enforceMu.Lock()
	defer enforceMu.Unlock()

	wg := wgTransfer(cfg.Interface)
	ovpn := ovpnUsage(cfg)
	txDB, err := db.Begin()
	if err != nil {
		return err
	}
	defer txDB.Rollback()

	var current Peer
	var username string
	var usedWG, usedOvpn, lifetimeWG, lifetimeOvpn int64
	if err := txDB.QueryRow(`SELECT username,public_key,last_rx,last_tx,ovpn_cn,last_ovpn_bytes,
		used_bytes,used_ovpn_bytes,lifetime_wg_bytes,lifetime_ovpn_bytes
		FROM peers WHERE id=?`, p.ID).Scan(&username, &current.PublicKey, &current.LastRx, &current.LastTx,
		&current.OvpnCN, &current.LastOvpnBytes, &usedWG, &usedOvpn, &lifetimeWG, &lifetimeOvpn); err != nil {
		return err
	}
	rx, tx, lastOvpn := resetUsageBaselines(current, wg, ovpn)
	periodTotal := usedWG + usedOvpn
	cumulativeTotal := lifetimeWG + lifetimeOvpn + periodTotal
	resetAt := nowUTC()
	if _, err := txDB.Exec(`INSERT INTO traffic_history
		(peer_id,username,reset_at,wg_bytes,ovpn_bytes,total_bytes)
		VALUES(?,?,?,?,?,?)`, p.ID, username, resetAt, usedWG, usedOvpn, cumulativeTotal); err != nil {
		return err
	}
	if _, err := txDB.Exec(`UPDATE peers SET
		lifetime_wg_bytes=lifetime_wg_bytes+?,
		lifetime_ovpn_bytes=lifetime_ovpn_bytes+?,
		used_bytes=0,last_rx=?,last_tx=?,
		used_ovpn_bytes=0,last_ovpn_bytes=?,updated_at=?
		WHERE id=?`, usedWG, usedOvpn, rx, tx, lastOvpn, resetAt, p.ID); err != nil {
		return err
	}
	if err := txDB.Commit(); err != nil {
		return err
	}
	return nil
}

func usageJSON(wg, ovpn int64) map[string]any {
	return map[string]any{
		"wg_bytes":    wg,
		"wg_gb":       bytesToGB(wg),
		"ovpn_bytes":  ovpn,
		"ovpn_gb":     bytesToGB(ovpn),
		"total_bytes": wg + ovpn,
		"total_gb":    bytesToGB(wg + ovpn),
	}
}

func (a *api) trafficHistory(w http.ResponseWriter, r *http.Request) {
	p := a.mustPeer(r)
	rows, err := a.db.Query(`SELECT reset_at,wg_bytes,ovpn_bytes,total_bytes
		FROM traffic_history WHERE peer_id=? ORDER BY id DESC`, p.ID)
	if err != nil {
		die("query traffic history: %v", err)
	}
	defer rows.Close()
	history := []map[string]any{}
	for rows.Next() {
		var resetAt string
		var wg, ovpn, total int64
		if err := rows.Scan(&resetAt, &wg, &ovpn, &total); err != nil {
			die("scan traffic history: %v", err)
		}
		row := usageJSON(wg, ovpn)
		row["reset_at"] = resetAt
		row["cumulative_total_bytes"] = total
		row["cumulative_total_gb"] = bytesToGB(total)
		history = append(history, row)
	}
	if err := rows.Err(); err != nil {
		die("read traffic history: %v", err)
	}
	writeJSON(w, 200, map[string]any{
		"username": p.Username,
		"current":  usageJSON(p.UsedBytes, p.UsedOvpnBytes),
		"lifetime": usageJSON(p.LifetimeWGBytes, p.LifetimeOvpnBytes),
		"total":    usageJSON(p.LifetimeWGBytes+p.UsedBytes, p.LifetimeOvpnBytes+p.UsedOvpnBytes),
		"resets":   history,
	})
}
