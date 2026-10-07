package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func resetFixture(t *testing.T) (*sql.DB, *api) {
	t.Helper()
	db := openDB(filepath.Join(t.TempDir(), "reset.db"))
	t.Cleanup(func() { db.Close() })
	_, err := db.Exec(`INSERT INTO peers(username,public_key,address,used_bytes,last_rx,last_tx,
		ovpn_cn,used_ovpn_bytes,last_ovpn_bytes,quota_bytes,created_at,updated_at)
		VALUES('alice','test-key','10.66.66.2',800,100,200,'alice',900,300,1500,?,?)`, nowUTC(), nowUTC())
	if err != nil {
		t.Fatal(err)
	}
	return db, &api{db: db, cfg: Config{APIToken: "test-token"}}
}

func resetRequest(a *api, body, token string, reader resetCounterReader, reconcile func()) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /peers/{name}/recharge", a.guard(func(w http.ResponseWriter, r *http.Request) {
		a.rechargeWith(w, r, reader, reconcile)
	}))
	r := httptest.NewRequest("POST", "/peers/alice/recharge", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestRechargeResetBothProtocolsAndSubsequentAccounting(t *testing.T) {
	for _, protocol := range []string{"wg", "ovpn", "both"} {
		t.Run(protocol, func(t *testing.T) {
			db, a := resetFixture(t)
			if protocol == "wg" {
				db.Exec("UPDATE peers SET ovpn_cn='',used_ovpn_bytes=0,last_ovpn_bytes=0")
			}
			if protocol == "ovpn" {
				db.Exec("UPDATE peers SET public_key='',address='',used_bytes=0,last_rx=0,last_tx=0")
			}
			before, _ := getPeer(db, "alice")
			sample := resetCounters{500, 600, 1200}
			calls := 0
			reader := func(_ Config, p Peer) (resetCounters, error) {
				calls++
				if p.ID != before.ID {
					t.Fatal("wrong peer sampled")
				}
				return sample, nil
			}
			w := resetRequest(a, `{"reset":true}`, "test-token", reader, func() {})
			if w.Code != 200 {
				t.Fatalf("reset: %d %s", w.Code, w.Body.String())
			}
			var response map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response["used_total_bytes"] != float64(0) {
				t.Fatalf("API did not reset both protocols: %v", response["used_total_bytes"])
			}
			p, _ := getPeer(db, "alice")
			if usedTotal(p) != 0 || p.LastRx != 500 || p.LastTx != 600 || p.LastOvpnBytes != 1200 || calls != 1 {
				t.Fatalf("reset failed: used=%d baselines=%d/%d/%d calls=%d", usedTotal(p), p.LastRx, p.LastTx, p.LastOvpnBytes, calls)
			}
			if p.QuotaBytes != before.QuotaBytes || p.PublicKey != before.PublicKey || p.OvpnCN != before.OvpnCN || p.Enabled != before.Enabled {
				t.Fatal("reset changed quota, credentials, or enabled state")
			}
			// The unchanged live counters must yield zero; new traffic alone is billable.
			if sample.rx-p.LastRx+sample.tx-p.LastTx+sample.ovpn-p.LastOvpnBytes != 0 {
				t.Fatal("old traffic would be counted again")
			}
			if (sample.rx+7)-p.LastRx+(sample.tx+11)-p.LastTx+(sample.ovpn+13)-p.LastOvpnBytes != 31 {
				t.Fatal("new traffic accounting is incorrect")
			}
			if effectiveBlocked(p, time.Now()) {
				t.Fatal("quota-only block survives reset")
			}
			p.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
			if !effectiveBlocked(p, time.Now()) {
				t.Fatal("reset must not renew an expired user")
			}
		})
	}
}

func TestRechargeFailureDoesNotClaimSuccessOrModifyData(t *testing.T) {
	for _, failure := range []string{"counter", "database", "invalid-reset", "malformed-json", "unauthorized"} {
		t.Run(failure, func(t *testing.T) {
			db, a := resetFixture(t)
			before, _ := getPeer(db, "alice")
			reader := func(Config, Peer) (resetCounters, error) { return resetCounters{500, 600, 1200}, nil }
			body, token := `{"reset":true,"set_gb":2}`, "test-token"
			want := 400
			switch failure {
			case "counter":
				reader = func(Config, Peer) (resetCounters, error) {
					return resetCounters{}, errors.New("counter source unavailable")
				}
			case "database":
				_, err := db.Exec(`CREATE TRIGGER reject_quota BEFORE UPDATE OF quota_bytes ON peers BEGIN SELECT RAISE(ABORT,'test failure'); END`)
				if err != nil {
					t.Fatal(err)
				}
			case "invalid-reset":
				body = `{"reset":"true"}`
			case "malformed-json":
				body = `{"reset":`
			case "unauthorized":
				token, want = "wrong-token", 401
			}
			reconciled := false
			w := resetRequest(a, body, token, reader, func() { reconciled = true })
			if w.Code != want || reconciled {
				t.Fatalf("failed reset: code=%d reconcile=%v body=%s", w.Code, reconciled, w.Body.String())
			}
			after, _ := getPeer(db, "alice")
			if before != after {
				t.Fatal("failed reset modified user data")
			}
		})
	}
}

func TestResetOpenVPNStatusAndDisconnectedBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.log")
	cfg := Config{OvpnStatus: path}
	p := Peer{OvpnCN: "alice", LastOvpnBytes: 999}
	status := "OpenVPN CLIENT LIST\nCommon Name,Real Address,Bytes Received,Bytes Sent,Connected Since\nalice,192.0.2.1:1234,700,300,date\nROUTING TABLE\nEND\n"
	if err := os.WriteFile(path, []byte(status), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := readResetCounters(cfg, p)
	if err != nil || c.ovpn != 1000 {
		t.Fatalf("connected: %v %v", c, err)
	}
	if err := os.WriteFile(path, []byte("OpenVPN CLIENT LIST\nROUTING TABLE\nEND\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err = readResetCounters(cfg, p)
	if err != nil || c.ovpn != 0 {
		t.Fatalf("disconnected: %v %v", c, err)
	}
	if err := os.WriteFile(path, []byte("OpenVPN CLIENT LIST\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readResetCounters(cfg, p); err == nil {
		t.Fatal("incomplete status accepted")
	}
	if err := os.WriteFile(path, []byte(status), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	os.Chtimes(path, old, old)
	if _, err = readResetCounters(cfg, p); err == nil {
		t.Fatal("stale status accepted")
	}
}

// Exercise the real HTTP reset handler AND real enforcement code on Linux with
// isolated command fixtures. Never invoke the host's wg/ipset/iptables binaries.
func TestLinuxResetHandlerDoesNotRecountTraffic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux command fixture integration")
	}
	db, a := resetFixture(t)
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write("wg", "#!/bin/sh\nprintf 'test-key 500 600\\n'\n")
	write("ipset", "#!/bin/sh\nexit 0\n")
	write("iptables", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", dir)
	a.cfg.Interface, a.cfg.IPSet = "fixture0", "fixture_blocked"
	a.cfg.OvpnStatus = filepath.Join(dir, "status.log")
	write("status.log", "CLIENT_LIST,alice,192.0.2.1,10.8.0.2,,700,500,date\nEND\n")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /peers/{name}/recharge", a.guard(a.recharge))
	request := func() {
		r := httptest.NewRequest("POST", "/peers/alice/recharge", strings.NewReader(`{"reset":true}`))
		r.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("HTTP reset failed: %d %s", w.Code, w.Body.String())
		}
	}
	request()
	for i := 0; i < 3; i++ {
		enforceTick(db, a.cfg)
		p, _ := getPeer(db, "alice")
		if usedTotal(p) != 0 || p.Blocked {
			t.Fatalf("tick %d restored old usage: %d blocked=%v", i, usedTotal(p), p.Blocked)
		}
	}
	write("wg", "#!/bin/sh\nprintf 'test-key 507 611\\n'\n")
	write("status.log", "CLIENT_LIST,alice,192.0.2.1,10.8.0.2,,707,506,date\nEND\n")
	enforceTick(db, a.cfg)
	p, _ := getPeer(db, "alice")
	if p.UsedBytes != 18 || p.UsedOvpnBytes != 13 {
		t.Fatalf("new traffic: WG=%d OVPN=%d", p.UsedBytes, p.UsedOvpnBytes)
	}
	request()
	p, _ = getPeer(db, "alice")
	if usedTotal(p) != 0 {
		t.Fatal("second reset failed")
	}
}
