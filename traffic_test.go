package main

import (
	"path/filepath"
	"testing"
)

func TestResetUsageBaselinesUsesLiveCounters(t *testing.T) {
	p := Peer{PublicKey: "wg-key", LastRx: 10, LastTx: 20, OvpnCN: "alice", LastOvpnBytes: 30}
	rx, tx, ovpn := resetUsageBaselines(p,
		map[string][2]int64{"wg-key": {110, 220}},
		map[string]int64{"alice": 330})
	if rx != 110 || tx != 220 || ovpn != 330 {
		t.Fatalf("live baselines = %d,%d,%d; want 110,220,330", rx, tx, ovpn)
	}

	// A failed/unavailable counter source must not move the baseline backwards to
	// zero, otherwise the next successful tick would recount old traffic.
	rx, tx, ovpn = resetUsageBaselines(p, map[string][2]int64{}, map[string]int64{})
	if rx != 10 || tx != 20 || ovpn != 30 {
		t.Fatalf("missing-counter baselines = %d,%d,%d; want 10,20,30", rx, tx, ovpn)
	}
}

func TestResetPeerUsageArchivesBothProtocols(t *testing.T) {
	db := openDB(filepath.Join(t.TempDir(), "wgmgr.db"))
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO peers(
		username,public_key,address,quota_bytes,used_bytes,last_rx,last_tx,
		used_ovpn_bytes,last_ovpn_bytes,enabled,created_at,updated_at)
		VALUES('alice','','',0,120,10,20,80,30,1,?,?)`, nowUTC(), nowUTC()); err != nil {
		t.Fatal(err)
	}
	p, ok := getPeer(db, "alice")
	if !ok {
		t.Fatal("seeded peer not found")
	}
	if err := resetPeerUsage(db, Config{}, p); err != nil {
		t.Fatalf("reset: %v", err)
	}

	p, _ = getPeer(db, "alice")
	if p.UsedBytes != 0 || p.UsedOvpnBytes != 0 || p.LifetimeWGBytes != 120 || p.LifetimeOvpnBytes != 80 {
		t.Fatalf("after reset: current=%d/%d lifetime=%d/%d", p.UsedBytes, p.UsedOvpnBytes, p.LifetimeWGBytes, p.LifetimeOvpnBytes)
	}
	var resets int
	var wg, ovpn, total int64
	if err := db.QueryRow(`SELECT COUNT(*),COALESCE(MAX(wg_bytes),0),COALESCE(MAX(ovpn_bytes),0),COALESCE(MAX(total_bytes),0)
		FROM traffic_history WHERE peer_id=?`, p.ID).Scan(&resets, &wg, &ovpn, &total); err != nil {
		t.Fatal(err)
	}
	if resets != 1 || wg != 120 || ovpn != 80 || total != 200 {
		t.Fatalf("history = count %d, wg %d, ovpn %d, total %d; want 1,120,80,200", resets, wg, ovpn, total)
	}
}
