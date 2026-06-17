package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// peerJSON must expose the combined (WG+OVPN) usage the UI shows, plus the per-protocol split.
func TestPeerJSONCombined(t *testing.T) {
	const GB = int64(1024 * 1024 * 1024)
	p := Peer{Username: "alice", UsedBytes: 2 * GB, UsedOvpnBytes: 3 * GB, QuotaBytes: 10 * GB,
		OvpnCN: "alice", OvpnIP: "10.8.0.2", OvpnEnabled: true}
	j := peerJSON(p)
	if j["has_ovpn"] != true {
		t.Errorf("has_ovpn should be true")
	}
	if got := j["used_total_bytes"].(int64); got != 5*GB {
		t.Errorf("used_total_bytes=%d want %d", got, 5*GB)
	}
	if got := j["used_total_gb"].(float64); got != 5.0 {
		t.Errorf("used_total_gb=%v want 5", got)
	}
	if got := j["used_ovpn_gb"].(float64); got != 3.0 {
		t.Errorf("used_ovpn_gb=%v want 3", got)
	}
	if got := j["used_gb"].(float64); got != 2.0 { // WG only, unchanged meaning
		t.Errorf("used_gb (WG)=%v want 2", got)
	}
	// WG-only user
	if peerJSON(Peer{Username: "bob", UsedBytes: GB})["has_ovpn"] != false {
		t.Errorf("WG-only user must report has_ovpn=false")
	}
}

// ovpnConfigForPeer assembles a self-contained .ovpn from the on-disk CA/tls-crypt + the
// peer's stored cert/key.
func TestOvpnConfigForPeer(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := ovpnEnsureCA(dir)
	writeFileMode(filepath.Join(dir, "tc.key"), ovpnGenTLSCrypt(), 0o600)
	cert, key := ovpnIssueCert(ca, caKey, "alice", false)
	cfg := Config{OvpnDir: dir, OvpnProto: "udp", OvpnEndpoint: "vpn.example.com", OvpnPort: "1194"}
	out := ovpnConfigForPeer(cfg, Peer{Username: "alice", OvpnCN: "alice", OvpnCert: cert, OvpnKey: key})
	for _, want := range []string{"remote vpn.example.com 1194", "<ca>", "<cert>", "<tls-crypt>", "remote-cert-tls server"} {
		if !strings.Contains(out, want) {
			t.Errorf(".ovpn missing %q", want)
		}
	}
}
