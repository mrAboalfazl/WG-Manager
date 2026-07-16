package main

import (
	"path/filepath"
	"testing"
)

func TestMigrationExportImportPreservesUserState(t *testing.T) {
	src := openDB(filepath.Join(t.TempDir(), "src.db"))
	defer src.Close()
	if _, err := src.Exec(`INSERT INTO peers(
		username,public_key,private_key,preshared_key,address,
		quota_bytes,used_bytes,last_rx,last_tx,expires_at,enabled,blocked,
		ovpn_cn,ovpn_ip,ovpn_enabled,used_ovpn_bytes,last_ovpn_bytes,ovpn_cert,ovpn_key,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"alice", "wgpub", "wgpriv", "psk", "10.66.66.2",
		int64(50), int64(20), int64(3), int64(4), "2026-08-01T00:00:00Z", 1, 0,
		"alice", "10.8.0.2", 1, int64(7), int64(8), "cert", "key", nowUTC(), nowUTC()); err != nil {
		t.Fatalf("seed source: %v", err)
	}

	data := encodeMigration(src)
	dst := openDB(filepath.Join(t.TempDir(), "dst.db"))
	defer dst.Close()
	created, updated := importMigration(dst, Config{}, data, false)
	if created != 1 || updated != 0 {
		t.Fatalf("created=%d updated=%d, want 1/0", created, updated)
	}
	p, ok := getPeer(dst, "alice")
	if !ok {
		t.Fatal("imported peer missing")
	}
	if p.PublicKey != "wgpub" || p.PrivateKey != "wgpriv" || p.PSK != "psk" || p.Address != "10.66.66.2" {
		t.Fatalf("WireGuard identity not preserved: %+v", p)
	}
	if p.QuotaBytes != 50 || p.UsedBytes != 20 || p.UsedOvpnBytes != 7 || p.ExpiresAt != "2026-08-01T00:00:00Z" {
		t.Fatalf("quota/usage/expiry not preserved: %+v", p)
	}
	if p.OvpnCN != "alice" || p.OvpnIP != "10.8.0.2" || p.OvpnCert != "cert" || p.OvpnKey != "key" {
		t.Fatalf("OpenVPN identity not preserved: %+v", p)
	}
}
