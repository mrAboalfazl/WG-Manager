package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type api struct {
	cfg Config
	db  *sql.DB
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// ensureCert generates a long-lived self-signed TLS cert (for the server's public IP)
// if one isn't present. The website backend pins this cert (or trusts it) + uses the token.
func ensureCert(cfg Config) {
	if fileExists(cfg.TLSCert) && fileExists(cfg.TLSKey) {
		return
	}
	os.MkdirAll(filepath.Dir(cfg.TLSCert), 0o700)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		die("gen tls key: %v", err)
	}
	pm := parseParams(cfg.Params)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               pkix.Name{CommonName: "wgmgr"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(pm["SERVER_PUB_IP"]); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		die("create cert: %v", err)
	}
	cf, err := os.OpenFile(cfg.TLSCert, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		die("write cert: %v", err)
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kf, err := os.OpenFile(cfg.TLSKey, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		die("write key: %v", err)
	}
	pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	kf.Close()
}

func startAPI(cfg Config, db *sql.DB) {
	if cfg.APIListen == "" || cfg.APIToken == "" {
		fmt.Fprintln(os.Stderr, "api: disabled (no listen/token configured)")
		return
	}
	ensureCert(cfg)
	a := &api{cfg, db}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.serveUI)
	mux.HandleFunc("POST /login", a.login)
	mux.HandleFunc("POST /change-password", a.guard(a.changePassword))
	mux.HandleFunc("GET /peers/{name}/qr", a.guard(a.qrPeer))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /peers", a.guard(a.listPeers))
	mux.HandleFunc("POST /peers", a.guard(a.createPeer))
	mux.HandleFunc("GET /peers/{name}", a.guard(a.showPeer))
	mux.HandleFunc("DELETE /peers/{name}", a.guard(a.deletePeer))
	mux.HandleFunc("GET /peers/{name}/config", a.guard(a.getConfig))
	mux.HandleFunc("POST /peers/{name}/recharge", a.guard(a.recharge))
	mux.HandleFunc("POST /peers/{name}/renew", a.guard(a.renew))
	mux.HandleFunc("POST /peers/{name}/quota", a.guard(a.setQuota))
	mux.HandleFunc("POST /peers/{name}/enable", a.guard(a.enableH))
	mux.HandleFunc("POST /peers/{name}/disable", a.guard(a.disableH))
	// Mount everything under the configured web base path (e.g. /a1b2c3). Empty base =
	// root = unchanged behavior. Outside the prefix nothing is registered, so the bare
	// root 404s and the panel is dark to scanners hitting IP:PORT/.
	var handler http.Handler = mux
	bp := normBase(cfg.BasePath)
	if bp != "" {
		outer := http.NewServeMux()
		outer.Handle(bp+"/", http.StripPrefix(bp, mux))
		handler = outer
	}
	srv := &http.Server{Addr: cfg.APIListen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		fmt.Printf("api: HTTPS listening on %s (path %s/)\n", cfg.APIListen, bp)
		if err := srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil {
			fmt.Fprintf(os.Stderr, "api: server stopped: %v\n", err)
		}
	}()
}

func authOK(r *http.Request, token string) bool {
	if token == "" {
		return false
	}
	supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if supplied == "" {
		supplied = r.Header.Get("X-API-Token")
	}
	return subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) == 1
}

// guard adds bearer-token auth + per-request panic recovery (a bad request returns JSON,
// never crashes the daemon).
func (a *api) guard(h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authOK(r, a.cfg.APIToken) {
			writeJSON(w, 401, map[string]any{"error": "unauthorized"})
			return
		}
		defer func() {
			if rec := recover(); rec != nil {
				msg := fmt.Sprint(rec)
				if de, ok := rec.(dieError); ok {
					msg = de.msg
				}
				writeJSON(w, 400, map[string]any{"error": msg})
			}
		}()
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request) map[string]any {
	m := map[string]any{}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&m)
	}
	return m
}

func bytesToGB(b int64) float64 { return float64(b) / (1024 * 1024 * 1024) }
func gbToBytes(v float64) int64  { return int64(v * 1024 * 1024 * 1024) }

func peerJSON(p Peer) map[string]any {
	return map[string]any{
		"username":   p.Username,
		"address":    p.Address,
		"public_key": p.PublicKey,
		"used_bytes": p.UsedBytes,
		"used_gb":    bytesToGB(p.UsedBytes),
		"quota_bytes": p.QuotaBytes,
		"quota_gb":   bytesToGB(p.QuotaBytes),
		"expires_at": p.ExpiresAt,
		"enabled":    p.Enabled,
		"blocked":    p.Blocked,
	}
}

func (a *api) mustPeer(r *http.Request) Peer {
	p, ok := getPeer(a.db, r.PathValue("name"))
	if !ok {
		die("no such user %q", r.PathValue("name"))
	}
	return p
}

func wgHandshakes(iface string) map[string]int64 {
	m := map[string]int64{}
	out, err := run("wg", "show", iface, "latest-handshakes")
	if err != nil {
		return m
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			ts, _ := strconv.ParseInt(f[1], 10, 64)
			m[f[0]] = ts
		}
	}
	return m
}

func liveJSON(p Peer, hs map[string]int64, now int64) map[string]any {
	j := peerJSON(p)
	ts := hs[p.PublicKey]
	j["last_handshake"] = ts
	j["online"] = ts > 0 && now-ts < 180
	return j
}

func (a *api) listPeers(w http.ResponseWriter, r *http.Request) {
	hs := wgHandshakes(a.cfg.Interface)
	now := time.Now().Unix()
	out := []map[string]any{}
	for _, p := range allPeers(a.db) {
		out = append(out, liveJSON(p, hs, now))
	}
	writeJSON(w, 200, map[string]any{"peers": out, "server": parseParams(a.cfg.Params)["SERVER_PUB_IP"]})
}

func (a *api) showPeer(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, liveJSON(a.mustPeer(r), wgHandshakes(a.cfg.Interface), time.Now().Unix()))
}

func (a *api) createPeer(w http.ResponseWriter, r *http.Request) {
	m := readJSON(r)
	username, _ := m["username"].(string)
	username = strings.TrimSpace(username)
	if username == "" {
		die("username required")
	}
	if _, ok := getPeer(a.db, username); ok {
		die("user %q already exists", username)
	}
	var quota int64
	if v, ok := m["quota_gb"].(float64); ok {
		quota = gbToBytes(v)
	}
	expires := ""
	if v, ok := m["days"].(float64); ok && v > 0 {
		expires = time.Now().UTC().AddDate(0, 0, int(v)).Format(time.RFC3339)
	}
	priv, pub, psk := genKeys()
	ip := nextFreeIP(a.db, a.cfg.WGConf)
	if _, err := a.db.Exec(`INSERT INTO peers(username,public_key,private_key,preshared_key,address,quota_bytes,expires_at,enabled,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,1,?,?)`, username, pub, priv, psk, ip, quota, expires, nowUTC(), nowUTC()); err != nil {
		die("insert: %v", err)
	}
	renderConf(a.db, a.cfg, false)
	p, _ := getPeer(a.db, username)
	resp := peerJSON(p)
	resp["client_config"] = clientConfig(a.db, a.cfg, p)
	writeJSON(w, 201, resp)
}

func (a *api) deletePeer(w http.ResponseWriter, r *http.Request) {
	p := a.mustPeer(r)
	a.db.Exec("DELETE FROM peers WHERE id=?", p.ID)
	renderConf(a.db, a.cfg, true)
	writeJSON(w, 200, map[string]any{"deleted": p.Username})
}

func (a *api) getConfig(w http.ResponseWriter, r *http.Request) {
	p := a.mustPeer(r)
	if p.PrivateKey == "" {
		die("no stored private key for %q", p.Username)
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(clientConfig(a.db, a.cfg, p)))
}

func (a *api) recharge(w http.ResponseWriter, r *http.Request) {
	p := a.mustPeer(r)
	m := readJSON(r)
	if reset, _ := m["reset"].(bool); reset {
		a.db.Exec("UPDATE peers SET used_bytes=0,last_rx=0,last_tx=0,updated_at=? WHERE id=?", nowUTC(), p.ID)
	}
	if v, ok := m["set_gb"].(float64); ok {
		a.db.Exec("UPDATE peers SET quota_bytes=?,updated_at=? WHERE id=?", gbToBytes(v), nowUTC(), p.ID)
	}
	if v, ok := m["add_gb"].(float64); ok {
		a.db.Exec("UPDATE peers SET quota_bytes=quota_bytes+?,updated_at=? WHERE id=?", gbToBytes(v), nowUTC(), p.ID)
	}
	writeJSON(w, 200, peerJSON(a.mustPeer(r)))
}

func (a *api) renew(w http.ResponseWriter, r *http.Request) {
	p := a.mustPeer(r)
	m := readJSON(r)
	now := time.Now().UTC()
	var exp string
	if v, ok := m["add_days"].(float64); ok {
		// extend from the later of now / current expiry (don't lose unused time)
		base := now
		if p.ExpiresAt != "" {
			if t, err := time.Parse(time.RFC3339, p.ExpiresAt); err == nil && t.After(now) {
				base = t
			}
		}
		exp = base.AddDate(0, 0, int(v)).Format(time.RFC3339)
	} else if v, ok := m["days"].(float64); ok {
		if v > 0 { // days<=0 -> clear expiry (never expires)
			exp = now.AddDate(0, 0, int(v)).Format(time.RFC3339)
		}
	} else if s, ok := m["expires_at"].(string); ok {
		exp = s
	} else {
		die("renew needs add_days, days, or expires_at")
	}
	a.db.Exec("UPDATE peers SET expires_at=?,updated_at=? WHERE id=?", exp, nowUTC(), p.ID)
	writeJSON(w, 200, peerJSON(a.mustPeer(r)))
}

func (a *api) setQuota(w http.ResponseWriter, r *http.Request) {
	p := a.mustPeer(r)
	m := readJSON(r)
	v, ok := m["quota_gb"].(float64)
	if !ok {
		die("quota_gb required")
	}
	a.db.Exec("UPDATE peers SET quota_bytes=?,updated_at=? WHERE id=?", gbToBytes(v), nowUTC(), p.ID)
	writeJSON(w, 200, peerJSON(a.mustPeer(r)))
}

func (a *api) enableH(w http.ResponseWriter, r *http.Request) {
	p := a.mustPeer(r)
	a.db.Exec("UPDATE peers SET enabled=1,updated_at=? WHERE id=?", nowUTC(), p.ID)
	writeJSON(w, 200, peerJSON(a.mustPeer(r)))
}

func (a *api) disableH(w http.ResponseWriter, r *http.Request) {
	p := a.mustPeer(r)
	a.db.Exec("UPDATE peers SET enabled=0,updated_at=? WHERE id=?", nowUTC(), p.ID)
	writeJSON(w, 200, peerJSON(a.mustPeer(r)))
}

// changePassword updates the panel/admin password (verifies the current one first).
// The bearer token is unchanged, so the current session stays valid.
func (a *api) changePassword(w http.ResponseWriter, r *http.Request) {
	m := readJSON(r)
	cur, _ := m["current_password"].(string)
	nw, _ := m["new_password"].(string)
	if len(nw) < 4 {
		die("new password must be at least 4 characters")
	}
	if a.cfg.AdminPassHash != "" && !checkPass(a.cfg.AdminPassHash, cur) {
		die("current password is incorrect")
	}
	newHash := hashPass(nw)
	cfg := loadConfig()
	cfg.AdminPassHash = newHash
	saveConfig(cfg)
	a.cfg.AdminPassHash = newHash
	writeJSON(w, 200, map[string]any{"ok": true})
}
