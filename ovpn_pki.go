package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// OpenVPN PKI + provisioning. We mint an EC (P-256) PKI in Go — no easy-rsa dependency and
// no slow DH params (EC certs + `dh none` use ECDHE). This mirrors how api.go already makes
// the panel's self-signed TLS cert, and keeps wgmgr a single self-contained binary.

func ovpnGenKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		die("ovpn: gen key: %v", err)
	}
	return k
}

func pemBlock(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func keyPEM(k *ecdsa.PrivateKey) string {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		die("ovpn: marshal key: %v", err)
	}
	return pemBlock("EC PRIVATE KEY", der)
}

func randSerial() *big.Int {
	b := make([]byte, 16)
	rand.Read(b)
	return new(big.Int).SetBytes(b)
}

func writeFileMode(path, content string, mode os.FileMode) {
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		die("ovpn: write %s: %v", path, err)
	}
}

func readFileStr(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		die("ovpn: read %s: %v", path, err)
	}
	return string(b)
}

func loadCert(path string) *x509.Certificate {
	blk, _ := pem.Decode([]byte(readFileStr(path)))
	if blk == nil {
		die("ovpn: no PEM in %s", path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		die("ovpn: parse cert %s: %v", path, err)
	}
	return c
}

func loadKey(path string) *ecdsa.PrivateKey {
	blk, _ := pem.Decode([]byte(readFileStr(path)))
	if blk == nil {
		die("ovpn: no PEM in %s", path)
	}
	k, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		die("ovpn: parse key %s: %v", path, err)
	}
	return k
}

// ovpnEnsureCA loads the CA from dir, creating it (ca.crt/ca.key) on first use.
func ovpnEnsureCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey) {
	crtPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if fileExists(crtPath) && fileExists(keyPath) {
		return loadCert(crtPath), loadKey(keyPath)
	}
	key := ovpnGenKey()
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: "wgmgr-ovpn-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		die("ovpn: create CA: %v", err)
	}
	os.MkdirAll(dir, 0o700)
	writeFileMode(keyPath, keyPEM(key), 0o600)
	writeFileMode(crtPath, pemBlock("CERTIFICATE", der), 0o644)
	return loadCert(crtPath), key
}

// ovpnIssueCert mints a key+cert signed by the CA. server=true → serverAuth EKU (so clients'
// `remote-cert-tls server` accepts it); otherwise clientAuth.
func ovpnIssueCert(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, server bool) (certPEM, privPEM string) {
	key := ovpnGenKey()
	eku := x509.ExtKeyUsageClientAuth
	if server {
		eku = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		die("ovpn: sign cert %s: %v", cn, err)
	}
	return pemBlock("CERTIFICATE", der), keyPEM(key)
}

// ovpnGenTLSCrypt produces an OpenVPN "Static key V1" (256 bytes) for tls-crypt — the same
// format as `openvpn --genkey secret`: 16 lines of 32 hex chars between the BEGIN/END markers.
func ovpnGenTLSCrypt() string {
	b := make([]byte, 256)
	rand.Read(b)
	h := hex.EncodeToString(b)
	var sb strings.Builder
	sb.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(h); i += 32 {
		sb.WriteString(h[i : i+32])
		sb.WriteByte('\n')
	}
	sb.WriteString("-----END OpenVPN Static key V1-----\n")
	return sb.String()
}

func ovpnMask(cidr string) string {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		die("ovpn: bad subnet %s: %v", cidr, err)
	}
	return net.IP(n.Mask).String()
}

// ovpnNextFreeIP allocates the next unused address in the OVPN subnet (.1 is the server).
func ovpnNextFreeIP(db *sql.DB, subnet string) string {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		die("ovpn: bad subnet %s: %v", subnet, err)
	}
	used := map[string]bool{nextIP(ipnet.IP).String(): true} // server holds .1
	for _, p := range allPeers(db) {
		if p.OvpnIP != "" {
			used[p.OvpnIP] = true
		}
	}
	ip := ipnet.IP.Mask(ipnet.Mask)
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
	die("ovpn: no free IP in %s", subnet)
	return ""
}

// ovpnServerConf renders /etc/openvpn/server.conf from the config.
func ovpnServerConf(cfg Config) string {
	_, ipnet, err := net.ParseCIDR(cfg.OvpnSubnet)
	if err != nil {
		die("ovpn: bad subnet %s: %v", cfg.OvpnSubnet, err)
	}
	netaddr := ipnet.IP.String()
	mask := net.IP(ipnet.Mask).String()
	mgmt := ""
	if strings.HasPrefix(cfg.OvpnMgmt, "unix:") {
		mgmt = "management " + strings.TrimPrefix(cfg.OvpnMgmt, "unix:") + " unix"
	} else if h, p, ok := strings.Cut(cfg.OvpnMgmt, ":"); ok {
		mgmt = "management " + h + " " + p
	}
	d := cfg.OvpnDir
	return fmt.Sprintf(`# Generated by wgmgr ovpn-init — do not edit by hand.
port %s
proto %s
dev tun
topology subnet
server %s %s
ca %s/ca.crt
cert %s/server.crt
key %s/server.key
dh none
tls-crypt %s/tc.key
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
client-config-dir %s/ccd
ccd-exclusive
%s
keepalive 10 120
persist-key
persist-tun
user nobody
group nogroup
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS %s"
verb 3
explicit-exit-notify 1
`, cfg.OvpnPort, cfg.OvpnProto, netaddr, mask, d, d, d, d, d, mgmt, cfg.OvpnDNS)
}

// ovpnClientConfig renders a self-contained .ovpn (inline ca/cert/key/tls-crypt).
func ovpnClientConfig(cfg Config, caPEM, certPEM, keyPEM, tcPEM string) string {
	nl := func(s string) string { return strings.TrimRight(s, "\n") + "\n" }
	return fmt.Sprintf(`client
dev tun
proto %s
remote %s %s
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3
<ca>
%s</ca>
<cert>
%s</cert>
<key>
%s</key>
<tls-crypt>
%s</tls-crypt>
`, cfg.OvpnProto, cfg.OvpnEndpoint, cfg.OvpnPort, nl(caPEM), nl(certPEM), nl(keyPEM), nl(tcPEM))
}

// ovpnDefaults fills any unset OVPN config fields with sane defaults.
func ovpnDefaults(cfg *Config) {
	if cfg.OvpnDir == "" {
		cfg.OvpnDir = "/etc/openvpn"
	}
	if cfg.OvpnSubnet == "" {
		cfg.OvpnSubnet = "10.8.0.0/24"
	}
	if cfg.OvpnPort == "" {
		cfg.OvpnPort = "1194"
	}
	if cfg.OvpnProto == "" {
		cfg.OvpnProto = "udp"
	}
	if cfg.OvpnDNS == "" {
		cfg.OvpnDNS = "1.1.1.1"
	}
	if cfg.OvpnMgmt == "" {
		cfg.OvpnMgmt = "unix:/run/wgmgr/ovpn.sock"
	}
}

// ovpnAttach mints a client cert + static IP + CCD for an existing user and records the
// OpenVPN identity in the DB. Returns the assigned IP. Shared by the CLI and the panel API;
// the caller must ensure OVPN is initialized and the user has no existing OVPN identity.
func ovpnAttach(db *sql.DB, cfg Config, p Peer) string {
	ca, caKey := ovpnEnsureCA(cfg.OvpnDir)
	certPEM, keyPEM := ovpnIssueCert(ca, caKey, p.Username, false)
	ip := ovpnNextFreeIP(db, cfg.OvpnSubnet)
	writeFileMode(filepath.Join(cfg.OvpnDir, "ccd", p.Username),
		fmt.Sprintf("ifconfig-push %s %s\n", ip, ovpnMask(cfg.OvpnSubnet)), 0o644)
	if _, err := db.Exec("UPDATE peers SET ovpn_cn=?,ovpn_ip=?,ovpn_enabled=1,ovpn_cert=?,ovpn_key=?,updated_at=? WHERE id=?",
		p.Username, ip, certPEM, keyPEM, nowUTC(), p.ID); err != nil {
		die("ovpn attach: %v", err)
	}
	return ip
}

// ovpnDetach removes a user's OpenVPN identity: drops the CCD file (ccd-exclusive then
// blocks reconnects) and clears the OVPN fields + usage in the DB.
func ovpnDetach(db *sql.DB, cfg Config, p Peer) {
	os.Remove(filepath.Join(cfg.OvpnDir, "ccd", p.Username))
	if _, err := db.Exec("UPDATE peers SET ovpn_cn='',ovpn_ip='',ovpn_enabled=0,ovpn_cert='',ovpn_key='',used_ovpn_bytes=0,last_ovpn_bytes=0,updated_at=? WHERE id=?",
		nowUTC(), p.ID); err != nil {
		die("ovpn detach: %v", err)
	}
}

// ovpnConfigForPeer renders a user's .ovpn (CA + tls-crypt from disk, client cert/key from DB).
func ovpnConfigForPeer(cfg Config, p Peer) string {
	caPEM := readFileStr(filepath.Join(cfg.OvpnDir, "ca.crt"))
	tcPEM := readFileStr(filepath.Join(cfg.OvpnDir, "tc.key"))
	return ovpnClientConfig(cfg, caPEM, p.OvpnCert, p.OvpnKey, tcPEM)
}

// ---------- CLI commands ----------

// cmdOvpnInit sets up the OpenVPN server: PKI (CA + server cert + tls-crypt), the CCD dir,
// and server.conf. Idempotent — existing CA/server cert/tls-crypt are reused, only the
// config is rewritten. Flags: --dir --subnet --port --proto --dns --mgmt --endpoint.
func cmdOvpnInit(args []string) {
	_, flags := parseFlags(args)
	cfg := loadConfig()
	for k, set := range map[string]func(string){
		"dir":    func(v string) { cfg.OvpnDir = v },
		"subnet": func(v string) { cfg.OvpnSubnet = v },
		"port":   func(v string) { cfg.OvpnPort = v },
		"proto":  func(v string) { cfg.OvpnProto = v },
		"dns":    func(v string) { cfg.OvpnDNS = v },
		"mgmt":   func(v string) { cfg.OvpnMgmt = v },
	} {
		if v, ok := flags[k]; ok {
			set(v)
		}
	}
	ovpnDefaults(&cfg)
	if v, ok := flags["endpoint"]; ok {
		cfg.OvpnEndpoint = v
	}
	if cfg.OvpnEndpoint == "" {
		cfg.OvpnEndpoint = parseParams(cfg.Params)["SERVER_PUB_IP"]
	}

	os.MkdirAll(filepath.Join(cfg.OvpnDir, "ccd"), 0o700)
	ca, caKey := ovpnEnsureCA(cfg.OvpnDir)
	srvCrt, srvKey := filepath.Join(cfg.OvpnDir, "server.crt"), filepath.Join(cfg.OvpnDir, "server.key")
	if !(fileExists(srvCrt) && fileExists(srvKey)) {
		cp, kp := ovpnIssueCert(ca, caKey, "server", true)
		writeFileMode(srvCrt, cp, 0o644)
		writeFileMode(srvKey, kp, 0o600)
	}
	tc := filepath.Join(cfg.OvpnDir, "tc.key")
	if !fileExists(tc) {
		writeFileMode(tc, ovpnGenTLSCrypt(), 0o600)
	}
	writeFileMode(filepath.Join(cfg.OvpnDir, "server.conf"), ovpnServerConf(cfg), 0o644)
	saveConfig(cfg)
	fmt.Printf("openvpn initialized: dir=%s subnet=%s %s/%s endpoint=%s mgmt=%s\n",
		cfg.OvpnDir, cfg.OvpnSubnet, cfg.OvpnProto, cfg.OvpnPort, cfg.OvpnEndpoint, cfg.OvpnMgmt)
	fmt.Printf("config written to %s/server.conf — start it with: systemctl enable --now openvpn@server\n", cfg.OvpnDir)
}

// cmdOvpnAdd attaches an OpenVPN identity (client cert + static IP + CCD) to an EXISTING user,
// so their OVPN traffic counts toward the same combined quota as their WireGuard traffic.
func cmdOvpnAdd(args []string) {
	if len(args) < 1 {
		die("usage: wgmgr ovpn-add <username>")
	}
	cfg := loadConfig()
	ovpnDefaults(&cfg)
	if !fileExists(filepath.Join(cfg.OvpnDir, "ca.crt")) {
		die("openvpn is not initialized — run `wgmgr ovpn-init` first")
	}
	db := openDB(cfg.DB)
	defer db.Close()
	p, ok := getPeer(db, args[0])
	if !ok {
		die("no such user %q — create it first with `wgmgr add %s`", args[0], args[0])
	}
	if p.OvpnCN != "" {
		die("user %q already has an OpenVPN identity", p.Username)
	}
	ip := ovpnAttach(db, cfg, p)
	fmt.Printf("openvpn identity added for %s (ip %s). Get the profile: wgmgr ovpn-config %s\n", p.Username, ip, p.Username)
}

// cmdOvpnConfig prints a user's .ovpn profile (CA + tls-crypt from disk, client cert/key from DB).
func cmdOvpnConfig(args []string) {
	if len(args) < 1 {
		die("usage: wgmgr ovpn-config <username>")
	}
	cfg := loadConfig()
	ovpnDefaults(&cfg)
	db := openDB(cfg.DB)
	defer db.Close()
	p, ok := getPeer(db, args[0])
	if !ok {
		die("no such user %q", args[0])
	}
	if p.OvpnCN == "" || p.OvpnCert == "" {
		die("user %q has no OpenVPN identity — run `wgmgr ovpn-add %s`", args[0], args[0])
	}
	fmt.Print(ovpnConfigForPeer(cfg, p))
}

// cmdOvpnRm detaches a user's OpenVPN identity: removes their CCD file (with ccd-exclusive
// that also blocks reconnects) and clears the OVPN fields/usage in the DB.
func cmdOvpnRm(args []string) {
	if len(args) < 1 {
		die("usage: wgmgr ovpn-rm <username>")
	}
	cfg := loadConfig()
	ovpnDefaults(&cfg)
	db := openDB(cfg.DB)
	defer db.Close()
	p, ok := getPeer(db, args[0])
	if !ok {
		die("no such user %q", args[0])
	}
	ovpnDetach(db, cfg, p)
	fmt.Printf("openvpn identity removed for %s\n", p.Username)
}
