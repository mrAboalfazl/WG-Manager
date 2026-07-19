package main

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seedMigrationPeer(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db := openDB(dbPath)
	if _, err := db.Exec(`INSERT INTO peers(
		username,public_key,private_key,preshared_key,address,
		quota_bytes,used_bytes,last_rx,last_tx,expires_at,enabled,blocked,
		ovpn_cn,ovpn_ip,ovpn_enabled,used_ovpn_bytes,last_ovpn_bytes,ovpn_cert,ovpn_key,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"alice", "wgpub", "wgpriv", "psk", "10.66.66.2",
		int64(50), int64(20), int64(3), int64(4), "2026-08-01T00:00:00Z", 1, 0,
		"alice", "10.8.0.2", 1, int64(7), int64(8), "cert", "key", nowUTC(), nowUTC()); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	return db
}

func TestMigrationExportImportPreservesUserState(t *testing.T) {
	src := seedMigrationPeer(t, filepath.Join(t.TempDir(), "src.db"))
	defer src.Close()

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

func TestMigrationBundleRestoresServerFilesAndPreservesEndpoint(t *testing.T) {
	srcDir := t.TempDir()
	src := seedMigrationPeer(t, filepath.Join(srcDir, "src.db"))
	defer src.Close()

	srcCfg := Config{
		Interface:    "wg0",
		WGConf:       filepath.Join(srcDir, "wg0.conf"),
		Params:       filepath.Join(srcDir, "params"),
		OvpnDir:      filepath.Join(srcDir, "openvpn"),
		OvpnSubnet:   "10.8.0.0/24",
		OvpnPort:     "1194",
		OvpnProto:    "udp",
		OvpnEndpoint: "old.example.com",
		OvpnDNS:      "1.1.1.1",
		OvpnMgmt:     "unix:/run/wgmgr/ovpn.sock",
		OvpnMSSFix:   "1360",
	}
	if err := os.WriteFile(srcCfg.Params, []byte("SERVER_PUB_IP=old.example.com\nSERVER_PORT=51820\nSERVER_PUB_KEY=serverpub\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcCfg.WGConf, []byte("[Interface]\nPrivateKey = old-server-private\nAddress = 10.66.66.1/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(srcCfg.OvpnDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"ca.crt":      "ca",
		"ca.key":      "cakey",
		"server.crt":  "servercrt",
		"server.key":  "serverkey",
		"tc.key":      "tlscrypt",
		"server.conf": "server 10.8.0.0 255.255.255.0\n",
	} {
		if err := os.WriteFile(filepath.Join(srcCfg.OvpnDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	bundle := encodeMigrationBundle(src, srcCfg)
	zr, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		t.Fatalf("bundle is not a zip: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range zr.File {
		seen[f.Name] = true
	}
	for _, name := range []string{"manifest.json", "users.json", "wireguard/params", "wireguard/wg0.conf", "openvpn/ca.key", "openvpn/server.conf"} {
		if !seen[name] {
			t.Fatalf("bundle missing %s", name)
		}
	}

	dstDir := t.TempDir()
	dst := openDB(filepath.Join(dstDir, "dst.db"))
	defer dst.Close()
	dstCfg := Config{
		Interface: "wg0",
		WGConf:    filepath.Join(dstDir, "wg0.conf"),
		Params:    filepath.Join(dstDir, "params"),
		DB:        filepath.Join(dstDir, "dst.db"),
		OvpnDir:   filepath.Join(dstDir, "openvpn"),
	}
	created, updated := importMigrationBundle(dst, dstCfg, bundle, false)
	if created != 1 || updated != 0 {
		t.Fatalf("created=%d updated=%d, want 1/0", created, updated)
	}
	params, err := os.ReadFile(dstCfg.Params)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(params), "SERVER_PUB_IP=old.example.com") || !strings.Contains(string(params), "SERVER_PORT=51820") {
		t.Fatalf("foreign WireGuard endpoint/port not preserved:\n%s", params)
	}
	wgConf, err := os.ReadFile(dstCfg.WGConf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wgConf), "old-server-private") {
		t.Fatalf("WireGuard server identity not restored:\n%s", wgConf)
	}
	caKey, err := os.ReadFile(filepath.Join(dstCfg.OvpnDir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(caKey) != "cakey" {
		t.Fatalf("OpenVPN CA key not restored: %q", caKey)
	}
	p, ok := getPeer(dst, "alice")
	if !ok || p.OvpnIP != "10.8.0.2" || p.UsedBytes != 20 || p.UsedOvpnBytes != 7 {
		t.Fatalf("user state not restored: ok=%t peer=%+v", ok, p)
	}
}
