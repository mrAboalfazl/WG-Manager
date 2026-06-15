package main

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
)

func parseCertPEM(t *testing.T, p string) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode([]byte(p))
	if blk == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

// The server cert must validate for serverAuth and the client cert for clientAuth against
// the CA — i.e. OpenVPN's `remote-cert-tls server` and client-cert verification will pass.
func TestOvpnPKIChain(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := ovpnEnsureCA(dir)
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	srvPEM, _ := ovpnIssueCert(ca, caKey, "server", true)
	cliPEM, _ := ovpnIssueCert(ca, caKey, "alice", false)

	if _, err := parseCertPEM(t, srvPEM).Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("server cert should verify for serverAuth: %v", err)
	}
	if _, err := parseCertPEM(t, cliPEM).Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("client cert should verify for clientAuth: %v", err)
	}
	// A client cert must NOT pass a serverAuth check (wrong EKU).
	if _, err := parseCertPEM(t, cliPEM).Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Errorf("client cert must not satisfy serverAuth")
	}
	if cn := parseCertPEM(t, cliPEM).Subject.CommonName; cn != "alice" {
		t.Errorf("client CN=%q want alice", cn)
	}

	// CA is reused (loaded, not regenerated) on the second call.
	ca2, _ := ovpnEnsureCA(dir)
	if !ca2.Equal(ca) {
		t.Errorf("ovpnEnsureCA should reuse the existing CA")
	}
}

func TestOvpnTLSCryptFormat(t *testing.T) {
	k := ovpnGenTLSCrypt()
	if !strings.HasPrefix(k, "-----BEGIN OpenVPN Static key V1-----\n") {
		t.Errorf("missing BEGIN marker")
	}
	if !strings.Contains(k, "\n-----END OpenVPN Static key V1-----\n") {
		t.Errorf("missing END marker")
	}
	var hexLines int
	for _, l := range strings.Split(k, "\n") {
		if len(l) == 32 {
			hexLines++
		}
	}
	if hexLines != 16 { // 256 bytes = 512 hex chars = 16 lines of 32
		t.Errorf("expected 16 hex lines, got %d", hexLines)
	}
}

func TestOvpnClientConfig(t *testing.T) {
	cfg := Config{OvpnProto: "udp", OvpnEndpoint: "vpn.example.com", OvpnPort: "1194"}
	out := ovpnClientConfig(cfg, "CA", "CERT", "KEY", "TC")
	for _, want := range []string{
		"remote vpn.example.com 1194", "proto udp", "remote-cert-tls server",
		"<ca>", "<cert>", "<key>", "<tls-crypt>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf(".ovpn missing %q", want)
		}
	}
}

func TestOvpnNextFreeIP(t *testing.T) {
	db := openDB(filepath.Join(t.TempDir(), "t.db"))
	defer db.Close()
	// .1 is the server; .2 is taken by an existing user → next free is .3.
	if _, err := db.Exec("INSERT INTO peers(username,public_key,address,ovpn_ip,created_at,updated_at) VALUES(?,?,?,?,?,?)",
		"u1", "pk1", "10.66.66.2", "10.8.0.2", nowUTC(), nowUTC()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := ovpnNextFreeIP(db, "10.8.0.0/24"); got != "10.8.0.3" {
		t.Errorf("nextFreeIP=%s want 10.8.0.3", got)
	}
}
