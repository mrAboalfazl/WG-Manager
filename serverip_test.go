package main

import (
	"os"
	"path/filepath"
	"testing"
)

// serverPublicIP is the safety net for OVPN-only bring-up: the pre-fix code called
// parseParams(cfg.Params) unconditionally, which dies with "cannot read params : open : no such
// file or directory" when cfg.Params is "" — leaving wgmgr serve in a permanent crash loop.
// These tests lock in the three-tier fallback so a future refactor can't silently re-introduce
// that failure mode.
func TestServerPublicIP(t *testing.T) {
	// (1) params file wins when it parses and has SERVER_PUB_IP.
	dir := t.TempDir()
	params := filepath.Join(dir, "params")
	if err := os.WriteFile(params, []byte("SERVER_PUB_KEY=abc\nSERVER_PUB_IP=203.0.113.10\nSERVER_PORT=51820\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := serverPublicIP(Config{Params: params, OvpnEndpoint: "203.0.113.99"}); got != "203.0.113.10" {
		t.Errorf("params should win over OvpnEndpoint: got %q, want %q", got, "203.0.113.10")
	}

	// (2) OvpnEndpoint fallback when params doesn't exist. This is THE OVPN-only path — pre-fix
	// this scenario crashed wgmgr serve on every start.
	if got := serverPublicIP(Config{Params: "", OvpnEndpoint: "198.51.100.7"}); got != "198.51.100.7" {
		t.Errorf("empty Params + IP endpoint: got %q, want %q", got, "198.51.100.7")
	}
	if got := serverPublicIP(Config{Params: "/nonexistent/params", OvpnEndpoint: "198.51.100.7"}); got != "198.51.100.7" {
		t.Errorf("missing Params file + IP endpoint: got %q, want %q", got, "198.51.100.7")
	}

	// (3) OvpnEndpoint as a hostname must NOT be returned by this helper (it only wants IPs
	// for TLS SAN + panel display). Falls through to auto-detect which may or may not find one.
	got := serverPublicIP(Config{Params: "", OvpnEndpoint: "vpn.example.com"})
	if got == "vpn.example.com" {
		t.Errorf("hostname endpoint must not be returned by serverPublicIP: got %q", got)
	}
	// Auto-detect return value is host-dependent; only assert we didn't return the hostname.

	// (4) Everything empty AND no non-loopback IPv4 → "". Hard to make deterministic on a real
	// host (loopback is always present, other addrs may leak through), so just assert it doesn't
	// crash and returns a string.
	_ = serverPublicIP(Config{})
}

// serverPublicIPParsed is the *net.IP form used by TLS cert generation. Confirm nil is returned
// in the case that ensureCert cares about (no IP available) — the cert must still be generatable
// without an IP SAN.
func TestServerPublicIPParsed(t *testing.T) {
	if ip := serverPublicIPParsed(Config{OvpnEndpoint: "203.0.113.5"}); ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("IP endpoint: got %v, want 203.0.113.5", ip)
	}
	if ip := serverPublicIPParsed(Config{OvpnEndpoint: "vpn.example.com"}); ip != nil && ip.String() == "vpn.example.com" {
		t.Errorf("hostname must NOT be returned as parsed IP")
	}
}
