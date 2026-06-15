// wgmgr — lightweight WireGuard user & quota manager.
// Phase 1: config/params, SQLite store, peer CRUD, import, client config rendering.
// The DB is the source of truth; wg0.conf's [Peer] section is rendered from it and
// applied live with `wg syncconf` (never wg-quick down/up — existing sessions are kept).
package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const configPath = "/etc/wgmgr/config.json"

// peerMarker delimits the wgmgr-managed [Peer] region in wg0.conf. Everything ABOVE
// the first marker/peer (the [Interface] block + PostUp/PostDown) is preserved verbatim.
const peerMarker = "# >>> wgmgr managed peers (do not edit below) >>>"

type Config struct {
	Interface  string `json:"interface"`
	WGConf     string `json:"wg_conf"`
	Params     string `json:"params"`
	DB         string `json:"db"`
	ClientsDir string `json:"clients_dir"`
	APIListen  string `json:"api_listen"`
	APIToken   string `json:"api_token"`
	BasePath   string `json:"base_path"` // panel web path prefix, e.g. "/a1b2c3"; "" = root (existing installs stay at root)
	TLSCert    string `json:"tls_cert"`
	TLSKey     string `json:"tls_key"`
	IntervalS     int    `json:"enforce_interval_sec"`
	IPSet         string `json:"ipset_name"`
	AdminUser     string `json:"admin_user"`
	AdminPassHash string `json:"admin_pass_hash"`
}

type Peer struct {
	ID         int64
	Username   string
	PublicKey  string
	PrivateKey string
	PSK        string
	Address    string // host IP without /32, e.g. 10.66.66.4
	QuotaBytes int64
	UsedBytes  int64
	LastRx     int64
	LastTx     int64
	ExpiresAt  string // ISO-8601 UTC, "" = never
	Enabled    bool
	Blocked    bool
}

type dieError struct{ msg string }

func (e dieError) Error() string { return e.msg }

// die panics with a dieError; CLI main() and the API guard recover it (so a bad API
// request returns an error instead of crashing the long-running daemon).
func die(format string, a ...interface{}) {
	panic(dieError{fmt.Sprintf(format, a...)})
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func mustRun(name string, args ...string) string {
	out, err := run(name, args...)
	if err != nil {
		die("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return out
}

// ---------- config + params ----------

func loadConfig() Config {
	b, err := os.ReadFile(configPath)
	if err != nil {
		die("cannot read %s (run `wgmgr init` first): %v", configPath, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		die("bad config %s: %v", configPath, err)
	}
	return c
}

func saveConfig(c Config) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		die("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, b, 0o600); err != nil {
		die("write config: %v", err)
	}
}

// normBase normalizes a web base path to "" (root) or "/segment" (leading slash, no
// trailing slash). "", "/", and "///" all mean root.
func normBase(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "/")
	if s == "" {
		return ""
	}
	return "/" + s
}

func parseParams(path string) map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		die("cannot read params %s: %v", path, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			m[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return m
}

// ---------- store ----------

func openDB(path string) *sql.DB {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		die("mkdir db dir: %v", err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)")
	if err != nil {
		die("open db: %v", err)
	}
	schema := `CREATE TABLE IF NOT EXISTS peers(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		public_key TEXT UNIQUE NOT NULL,
		private_key TEXT DEFAULT '',
		preshared_key TEXT DEFAULT '',
		address TEXT UNIQUE NOT NULL,
		quota_bytes INTEGER NOT NULL DEFAULT 0,
		used_bytes INTEGER NOT NULL DEFAULT 0,
		last_rx INTEGER NOT NULL DEFAULT 0,
		last_tx INTEGER NOT NULL DEFAULT 0,
		expires_at TEXT DEFAULT '',
		enabled INTEGER NOT NULL DEFAULT 1,
		blocked INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		notes TEXT DEFAULT ''
	);
	CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);`
	if _, err := db.Exec(schema); err != nil {
		die("migrate: %v", err)
	}
	return db
}

func scanPeer(rows interface{ Scan(...interface{}) error }) (Peer, error) {
	var p Peer
	var enabled, blocked int
	err := rows.Scan(&p.ID, &p.Username, &p.PublicKey, &p.PrivateKey, &p.PSK, &p.Address,
		&p.QuotaBytes, &p.UsedBytes, &p.LastRx, &p.LastTx, &p.ExpiresAt, &enabled, &blocked)
	p.Enabled = enabled != 0
	p.Blocked = blocked != 0
	return p, err
}

const peerCols = "id,username,public_key,private_key,preshared_key,address,quota_bytes,used_bytes,last_rx,last_tx,expires_at,enabled,blocked"

func allPeers(db *sql.DB) []Peer {
	rows, err := db.Query("SELECT " + peerCols + " FROM peers ORDER BY id")
	if err != nil {
		die("query peers: %v", err)
	}
	defer rows.Close()
	var ps []Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			die("scan: %v", err)
		}
		ps = append(ps, p)
	}
	return ps
}

func getPeer(db *sql.DB, username string) (Peer, bool) {
	row := db.QueryRow("SELECT "+peerCols+" FROM peers WHERE username=?", username)
	p, err := scanPeer(row)
	if err == sql.ErrNoRows {
		return Peer{}, false
	}
	if err != nil {
		die("get peer: %v", err)
	}
	return p, true
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// ---------- wireguard helpers ----------

func genKeys() (priv, pub, psk string) {
	priv = strings.TrimSpace(mustRun("wg", "genkey"))
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(priv + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		die("wg pubkey: %v: %s", err, out)
	}
	pub = strings.TrimSpace(string(out))
	psk = strings.TrimSpace(mustRun("wg", "genpsk"))
	return
}

// interfaceHead returns the part of wg0.conf above the managed peer region (the
// [Interface] block + PostUp/PostDown), and the subnet/server address parsed from it.
func interfaceHead(conf string) (head string, ipnet *net.IPNet, serverIP net.IP) {
	b, err := os.ReadFile(conf)
	if err != nil {
		die("read %s: %v", conf, err)
	}
	lines := strings.Split(string(b), "\n")
	var headLines []string
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == peerMarker || t == "[Peer]" || strings.HasPrefix(t, "### Client") || strings.HasPrefix(t, "# >>> wgmgr") {
			break
		}
		headLines = append(headLines, l)
		if strings.HasPrefix(strings.ToLower(t), "address") {
			// Address = 10.66.66.1/24[, fd42::1/64]
			val := t[strings.Index(t, "=")+1:]
			first := strings.TrimSpace(strings.Split(val, ",")[0])
			ip, n, err := net.ParseCIDR(first)
			if err == nil {
				ipnet = n
				serverIP = ip
			}
		}
	}
	if ipnet == nil {
		die("could not parse Address/subnet from %s", conf)
	}
	return strings.Join(headLines, "\n"), ipnet, serverIP
}

func nextFreeIP(db *sql.DB, conf string) string {
	_, ipnet, serverIP := interfaceHead(conf)
	used := map[string]bool{serverIP.String(): true}
	for _, p := range allPeers(db) {
		used[p.Address] = true
	}
	ip := serverIP.Mask(ipnet.Mask)
	for i := 0; i < 65534; i++ {
		ip = nextIP(ip)
		if !ipnet.Contains(ip) {
			break
		}
		s := ip.String()
		if strings.HasSuffix(s, ".0") || used[s] {
			continue
		}
		return s
	}
	die("no free IP in %s", ipnet.String())
	return ""
}

func nextIP(ip net.IP) net.IP {
	ip = ip.To4()
	out := make(net.IP, 4)
	copy(out, ip)
	for i := 3; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// livePeers returns the set of peer public keys currently in the running interface.
func livePeers(iface string) map[string]bool {
	m := map[string]bool{}
	out, err := run("wg", "show", iface, "peers")
	if err != nil {
		return m
	}
	for _, f := range strings.Fields(out) {
		m[f] = true
	}
	return m
}

// renderConf rewrites wg0.conf: preserved [Interface] head + DB-rendered peers, then
// applies it live with `wg syncconf` (adds/removes peers without bouncing the interface).
// Guard: unless force, refuse if a live peer is missing from the DB (prevents dropping
// un-imported peers and disconnecting their users).
func renderConf(db *sql.DB, cfg Config, force bool) {
	if !force {
		dbset := map[string]bool{}
		for _, p := range allPeers(db) {
			dbset[p.PublicKey] = true
		}
		for pk := range livePeers(cfg.Interface) {
			if !dbset[pk] {
				die("refusing to render: live peer %s is not in the wgmgr DB — run `wgmgr import` first", pk)
			}
		}
	}
	head, _, _ := interfaceHead(cfg.WGConf)
	var b strings.Builder
	b.WriteString(strings.TrimRight(head, "\n"))
	b.WriteString("\n\n" + peerMarker + "\n")
	for _, p := range allPeers(db) {
		b.WriteString(fmt.Sprintf("\n### wgmgr:%s\n[Peer]\nPublicKey = %s\n", p.Username, p.PublicKey))
		if p.PSK != "" {
			b.WriteString("PresharedKey = " + p.PSK + "\n")
		}
		b.WriteString("AllowedIPs = " + p.Address + "/32\n")
	}
	tmp := cfg.WGConf + ".wgmgr.tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		die("write conf: %v", err)
	}
	if err := os.Rename(tmp, cfg.WGConf); err != nil {
		die("replace conf: %v", err)
	}
	applyLive(cfg)
}

// applyLive: wg syncconf <iface> <(wg-quick strip <iface>) — but without process
// substitution: strip to a temp file, then syncconf from it.
func applyLive(cfg Config) {
	stripped := mustRun("wg-quick", "strip", cfg.Interface)
	tmp := filepath.Join(os.TempDir(), "wgmgr-"+cfg.Interface+".strip")
	if err := os.WriteFile(tmp, []byte(stripped), 0o600); err != nil {
		die("write strip: %v", err)
	}
	defer os.Remove(tmp)
	if out, err := run("wg", "syncconf", cfg.Interface, tmp); err != nil {
		die("wg syncconf: %v: %s", err, out)
	}
}

func clientConfig(db *sql.DB, cfg Config, p Peer) string {
	pm := parseParams(cfg.Params)
	dns := pm["CLIENT_DNS_1"]
	if pm["CLIENT_DNS_2"] != "" {
		dns += ", " + pm["CLIENT_DNS_2"]
	}
	allowed := pm["ALLOWED_IPS"]
	if allowed == "" {
		allowed = "0.0.0.0/0,::/0"
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + p.PrivateKey + "\n")
	b.WriteString("Address = " + p.Address + "/32\n")
	b.WriteString("DNS = " + dns + "\n\n")
	b.WriteString("[Peer]\n")
	b.WriteString("PublicKey = " + pm["SERVER_PUB_KEY"] + "\n")
	if p.PSK != "" {
		b.WriteString("PresharedKey = " + p.PSK + "\n")
	}
	b.WriteString("Endpoint = " + pm["SERVER_PUB_IP"] + ":" + pm["SERVER_PORT"] + "\n")
	b.WriteString("AllowedIPs = " + allowed + "\n")
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

func gb(bytes int64) string {
	return fmt.Sprintf("%.2f", float64(bytes)/(1024*1024*1024))
}

// ---------- commands ----------

// cmdInit creates a fresh /etc/wgmgr/config.json. It refuses to overwrite an existing
// config (which would silently reset the API token + admin password) unless --force.
// A random secret web base path is generated by default, so the panel is served at
// https://IP:PORT/<base>/ rather than the bare root; override with --base-path <p>
// (use --base-path / for root). Existing installs are never touched here.
func cmdInit(args []string) {
	_, flags := parseFlags(args)
	if _, err := os.Stat(configPath); err == nil && flags["force"] != "true" {
		die("config already exists at %s — refusing to overwrite (would reset API token + admin password). Use --force to recreate.", configPath)
	}
	cfg := Config{
		Interface: "wg0", WGConf: "/etc/wireguard/wg0.conf", Params: "/etc/wireguard/params",
		DB: "/var/lib/wgmgr/wgmgr.db", ClientsDir: "/etc/wireguard/clients",
		APIListen: ":8443", TLSCert: "/etc/wgmgr/cert.pem", TLSKey: "/etc/wgmgr/key.pem",
		IntervalS: 180, IPSet: "wgmgr_blocked",
	}
	// generate API token if none
	tok := make([]byte, 32)
	rand.Read(tok)
	cfg.APIToken = hex.EncodeToString(tok)
	pwb := make([]byte, 6)
	rand.Read(pwb)
	adminPass := hex.EncodeToString(pwb)
	cfg.AdminUser = "admin"
	cfg.AdminPassHash = hashPass(adminPass)
	// Secret web base path: random by default, or caller-supplied via --base-path.
	if v, ok := flags["base-path"]; ok {
		cfg.BasePath = normBase(v)
	} else {
		bp := make([]byte, 8)
		rand.Read(bp)
		cfg.BasePath = "/" + hex.EncodeToString(bp)
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		die("mkdir config dir: %v", err)
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, b, 0o600); err != nil {
		die("write config: %v", err)
	}
	db := openDB(cfg.DB)
	defer db.Close()
	// sanity: parse params + interface
	pm := parseParams(cfg.Params)
	_, ipnet, srv := interfaceHead(cfg.WGConf)
	fmt.Printf("initialized. iface=%s subnet=%s server=%s db=%s\n", cfg.Interface, ipnet, srv, cfg.DB)
	fmt.Printf("API token written to %s (keep secret)\n", configPath)
	fmt.Printf("panel login: admin / %s  (change anytime: wgmgr set-login <user> <pass>)\n", adminPass)
	fmt.Printf("panel URL: https://%s%s%s/\n", pm["SERVER_PUB_IP"], cfg.APIListen, cfg.BasePath)
}

// cmdImport pulls existing peers from wg0.conf into the DB. Optional arg: path to a
// legacy users.db (e.g. the backed-up one) to recover client private keys + quotas.
func cmdImport(args []string) {
	cfg := loadConfig()
	db := openDB(cfg.DB)
	defer db.Close()

	// optional legacy users.db for private keys / quotas / expiry
	legacy := map[string]Peer{} // by public_key
	if len(args) > 0 {
		ldb, err := sql.Open("sqlite", "file:"+args[0]+"?mode=ro")
		if err == nil {
			rows, err := ldb.Query("SELECT username,public_key,private_key,ip_address,traffic_limit_bytes,traffic_used_bytes,expires_at,is_active FROM users")
			if err == nil {
				for rows.Next() {
					var u, pub, priv, ip, exp sql.NullString
					var lim, used sql.NullInt64
					var act sql.NullInt64
					rows.Scan(&u, &pub, &priv, &ip, &lim, &used, &exp, &act)
					lp := Peer{Username: u.String, PublicKey: pub.String, PrivateKey: priv.String,
						QuotaBytes: lim.Int64, UsedBytes: used.Int64, ExpiresAt: exp.String, Enabled: act.Int64 != 0}
					legacy[pub.String] = lp
				}
				rows.Close()
			}
			ldb.Close()
			fmt.Printf("loaded %d legacy records from %s\n", len(legacy), args[0])
		} else {
			fmt.Printf("warning: cannot open legacy db %s: %v\n", args[0], err)
		}
	}

	b, err := os.ReadFile(cfg.WGConf)
	if err != nil {
		die("read conf: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	var name, pub, psk, ip string
	flush := func() {
		if pub == "" || ip == "" {
			name, pub, psk, ip = "", "", "", ""
			return
		}
		if name == "" {
			name = "peer-" + pub[:6]
		}
		host := strings.Split(ip, "/")[0]
		lp := legacy[pub]
		priv := lp.PrivateKey
		quota := lp.QuotaBytes
		used := lp.UsedBytes
		exp := lp.ExpiresAt
		if _, ok := getPeer(db, name); !ok {
			_, err := db.Exec(`INSERT OR IGNORE INTO peers(username,public_key,private_key,preshared_key,address,quota_bytes,used_bytes,expires_at,enabled,created_at,updated_at)
				VALUES(?,?,?,?,?,?,?,?,1,?,?)`,
				name, pub, priv, psk, host, quota, used, exp, nowUTC(), nowUTC())
			if err != nil {
				fmt.Printf("  skip %s: %v\n", name, err)
			} else {
				fmt.Printf("  imported %s (%s) priv=%v quota=%sGB\n", name, host, priv != "", gb(quota))
			}
		}
		name, pub, psk, ip = "", "", "", ""
	}
	for _, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "### Client "):
			flush()
			name = strings.TrimSpace(strings.TrimPrefix(t, "### Client"))
		case strings.HasPrefix(t, "### wgmgr:"):
			flush()
			name = strings.TrimSpace(strings.TrimPrefix(t, "### wgmgr:"))
		case t == "[Peer]":
			// keep current name
		case strings.HasPrefix(t, "PublicKey"):
			pub = strings.TrimSpace(t[strings.Index(t, "=")+1:])
		case strings.HasPrefix(t, "PresharedKey"):
			psk = strings.TrimSpace(t[strings.Index(t, "=")+1:])
		case strings.HasPrefix(t, "AllowedIPs"):
			ip = strings.TrimSpace(strings.Split(t[strings.Index(t, "=")+1:], ",")[0])
		}
	}
	flush()
	fmt.Println("import done. Run `wgmgr render` to take ownership of the peer section.")
}

func parseFlags(args []string) (positional []string, flags map[string]string) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			key := strings.TrimPrefix(a, "--")
			if eq := strings.Index(key, "="); eq >= 0 {
				flags[key[:eq]] = key[eq+1:]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[key] = args[i+1]
				i++
			} else {
				flags[key] = "true"
			}
		} else {
			positional = append(positional, a)
		}
	}
	return
}

func cmdAdd(args []string) {
	pos, flags := parseFlags(args)
	if len(pos) < 1 {
		die("usage: wgmgr add <username> [--quota-gb N] [--days D]")
	}
	username := pos[0]
	cfg := loadConfig()
	db := openDB(cfg.DB)
	defer db.Close()
	if _, ok := getPeer(db, username); ok {
		die("user %q already exists", username)
	}
	var quota int64
	if v := flags["quota-gb"]; v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			die("bad --quota-gb")
		}
		quota = int64(f * 1024 * 1024 * 1024)
	}
	expires := ""
	if v := flags["days"]; v != "" {
		d, err := strconv.Atoi(v)
		if err != nil {
			die("bad --days")
		}
		expires = time.Now().UTC().AddDate(0, 0, d).Format(time.RFC3339)
	}
	priv, pub, psk := genKeys()
	ip := nextFreeIP(db, cfg.WGConf)
	_, err := db.Exec(`INSERT INTO peers(username,public_key,private_key,preshared_key,address,quota_bytes,expires_at,enabled,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,1,?,?)`, username, pub, priv, psk, ip, quota, expires, nowUTC(), nowUTC())
	if err != nil {
		die("insert: %v", err)
	}
	renderConf(db, cfg, false)
	p, _ := getPeer(db, username)
	fmt.Println(clientConfig(db, cfg, p))
}

func cmdRemove(args []string) {
	if len(args) < 1 {
		die("usage: wgmgr rm <username>")
	}
	cfg := loadConfig()
	db := openDB(cfg.DB)
	defer db.Close()
	res, err := db.Exec("DELETE FROM peers WHERE username=?", args[0])
	if err != nil {
		die("delete: %v", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		die("no such user %q", args[0])
	}
	renderConf(db, cfg, true)
	fmt.Println("removed", args[0])
}

func cmdList() {
	cfg := loadConfig()
	db := openDB(cfg.DB)
	defer db.Close()
	ps := allPeers(db)
	sort.Slice(ps, func(i, j int) bool { return ps[i].Username < ps[j].Username })
	fmt.Printf("%-16s %-16s %-10s %-10s %-22s %-8s %s\n", "USER", "IP", "USED(GB)", "QUOTA(GB)", "EXPIRES", "ENABLED", "BLOCKED")
	for _, p := range ps {
		q := gb(p.QuotaBytes)
		if p.QuotaBytes == 0 {
			q = "∞"
		}
		exp := p.ExpiresAt
		if exp == "" {
			exp = "never"
		}
		fmt.Printf("%-16s %-16s %-10s %-10s %-22s %-8t %t\n",
			p.Username, p.Address, gb(p.UsedBytes), q, exp, p.Enabled, p.Blocked)
	}
}

func cmdShow(args []string) {
	if len(args) < 1 {
		die("usage: wgmgr show <username>")
	}
	cfg := loadConfig()
	db := openDB(cfg.DB)
	defer db.Close()
	p, ok := getPeer(db, args[0])
	if !ok {
		die("no such user %q", args[0])
	}
	fmt.Printf("username:   %s\nip:         %s\npublic_key: %s\nused:       %s GB\nquota:      %s GB\nexpires:    %s\nenabled:    %t\nblocked:    %t\n",
		p.Username, p.Address, p.PublicKey, gb(p.UsedBytes), gb(p.QuotaBytes), p.ExpiresAt, p.Enabled, p.Blocked)
	if p.PrivateKey != "" {
		fmt.Println("\n--- client config ---")
		fmt.Println(clientConfig(db, cfg, p))
	} else {
		fmt.Println("\n(no stored private key — cannot re-emit config for this user)")
	}
}

func cmdConfig(args []string) {
	if len(args) < 1 {
		die("usage: wgmgr config <username>")
	}
	cfg := loadConfig()
	db := openDB(cfg.DB)
	defer db.Close()
	p, ok := getPeer(db, args[0])
	if !ok {
		die("no such user %q", args[0])
	}
	if p.PrivateKey == "" {
		die("no stored private key for %q", args[0])
	}
	fmt.Print(clientConfig(db, cfg, p))
}

func setField(args []string, usage string, apply func(db *sql.DB, p Peer, cfg Config)) {
	if len(args) < 1 {
		die(usage)
	}
	cfg := loadConfig()
	db := openDB(cfg.DB)
	defer db.Close()
	p, ok := getPeer(db, args[0])
	if !ok {
		die("no such user %q", args[0])
	}
	apply(db, p, cfg)
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			if de, ok := r.(dieError); ok {
				fmt.Fprintln(os.Stderr, "wgmgr: "+de.msg)
				os.Exit(1)
			}
			panic(r)
		}
	}()
	if len(os.Args) < 2 {
		fmt.Println("wgmgr <init|import|add|rm|list|show|config|set-quota|renew|enable|disable|render|serve|set-login|set-base-path> ...")
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	switch cmd {
	case "init":
		cmdInit(args)
	case "import":
		cmdImport(args)
	case "add":
		cmdAdd(args)
	case "rm", "remove", "del":
		cmdRemove(args)
	case "list":
		cmdList()
	case "show":
		cmdShow(args)
	case "config":
		cmdConfig(args)
	case "render":
		cfg := loadConfig()
		db := openDB(cfg.DB)
		defer db.Close()
		renderConf(db, cfg, false)
		fmt.Println("rendered wg0.conf peer section from DB and applied (wg syncconf)")
	case "enforce":
		cfg := loadConfig()
		db := openDB(cfg.DB)
		defer db.Close()
		enforceTick(db, cfg)
		fmt.Println("enforce tick done")
	case "serve":
		cmdServe()
	case "set-login":
		if len(args) < 2 {
			die("usage: wgmgr set-login <username> <password>")
		}
		cfg := loadConfig()
		cfg.AdminUser = args[0]
		cfg.AdminPassHash = hashPass(args[1])
		saveConfig(cfg)
		fmt.Println("panel login updated for user", args[0])
	case "set-base-path":
		if len(args) < 1 {
			die("usage: wgmgr set-base-path <path|/>   (e.g. /a1b2c3 ; use / to serve at root)")
		}
		cfg := loadConfig()
		cfg.BasePath = normBase(args[0])
		saveConfig(cfg)
		pm := parseParams(cfg.Params)
		if cfg.BasePath == "" {
			fmt.Println("panel base path cleared — serving at root. Restart wgmgr to apply.")
		} else {
			fmt.Printf("panel base path set to %s — restart wgmgr to apply.\n", cfg.BasePath)
		}
		fmt.Printf("panel URL: https://%s%s%s/\n", pm["SERVER_PUB_IP"], cfg.APIListen, cfg.BasePath)
	case "set-quota":
		setField(args, "usage: wgmgr set-quota <username> <GB>", func(db *sql.DB, p Peer, cfg Config) {
			if len(args) < 2 {
				die("usage: wgmgr set-quota <username> <GB>")
			}
			f, err := strconv.ParseFloat(args[1], 64)
			if err != nil {
				die("bad GB value")
			}
			db.Exec("UPDATE peers SET quota_bytes=?,updated_at=? WHERE id=?", int64(f*1024*1024*1024), nowUTC(), p.ID)
			fmt.Printf("%s quota set to %s GB\n", p.Username, args[1])
		})
	case "recharge":
		setField(args, "usage: wgmgr recharge <username> [--reset] [--add-gb N] [--set-gb N]", func(db *sql.DB, p Peer, cfg Config) {
			_, flags := parseFlags(args[1:])
			if flags["reset"] == "true" {
				db.Exec("UPDATE peers SET used_bytes=0,last_rx=0,last_tx=0,updated_at=? WHERE id=?", nowUTC(), p.ID)
			}
			if v := flags["set-gb"]; v != "" {
				f, _ := strconv.ParseFloat(v, 64)
				db.Exec("UPDATE peers SET quota_bytes=?,updated_at=? WHERE id=?", int64(f*1024*1024*1024), nowUTC(), p.ID)
			}
			if v := flags["add-gb"]; v != "" {
				f, _ := strconv.ParseFloat(v, 64)
				db.Exec("UPDATE peers SET quota_bytes=quota_bytes+?,updated_at=? WHERE id=?", int64(f*1024*1024*1024), nowUTC(), p.ID)
			}
			fmt.Printf("%s recharged\n", p.Username)
		})
	case "renew":
		setField(args, "usage: wgmgr renew <username> <days-from-now>", func(db *sql.DB, p Peer, cfg Config) {
			if len(args) < 2 {
				die("usage: wgmgr renew <username> <days-from-now>")
			}
			d, err := strconv.Atoi(args[1])
			if err != nil {
				die("bad days")
			}
			exp := time.Now().UTC().AddDate(0, 0, d).Format(time.RFC3339)
			db.Exec("UPDATE peers SET expires_at=?,updated_at=? WHERE id=?", exp, nowUTC(), p.ID)
			fmt.Printf("%s renewed until %s\n", p.Username, exp)
		})
	case "enable":
		setField(args, "usage: wgmgr enable <username>", func(db *sql.DB, p Peer, cfg Config) {
			db.Exec("UPDATE peers SET enabled=1,updated_at=? WHERE id=?", nowUTC(), p.ID)
			fmt.Printf("%s enabled\n", p.Username)
		})
	case "disable":
		setField(args, "usage: wgmgr disable <username>", func(db *sql.DB, p Peer, cfg Config) {
			db.Exec("UPDATE peers SET enabled=0,updated_at=? WHERE id=?", nowUTC(), p.ID)
			fmt.Printf("%s disabled\n", p.Username)
		})
	default:
		die("unknown command %q", cmd)
	}
}
