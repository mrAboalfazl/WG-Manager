package main

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	migrationUsersFile     = "users.json"
	migrationManifestFile  = "manifest.json"
	migrationBundleMaxFile = 64 << 20
)

type migrationFile struct {
	Version    int             `json:"version"`
	ExportedAt string          `json:"exported_at"`
	Peers      []migrationPeer `json:"peers"`
}

type migrationPeer struct {
	Username      string `json:"username"`
	PublicKey     string `json:"public_key"`
	PrivateKey    string `json:"private_key"`
	PresharedKey  string `json:"preshared_key"`
	Address       string `json:"address"`
	QuotaBytes    int64  `json:"quota_bytes"`
	UsedBytes     int64  `json:"used_bytes"`
	LastRx        int64  `json:"last_rx"`
	LastTx        int64  `json:"last_tx"`
	ExpiresAt     string `json:"expires_at"`
	Enabled       bool   `json:"enabled"`
	Blocked       bool   `json:"blocked"`
	OvpnCN        string `json:"ovpn_cn"`
	OvpnIP        string `json:"ovpn_ip"`
	OvpnEnabled   bool   `json:"ovpn_enabled"`
	UsedOvpnBytes int64  `json:"used_ovpn_bytes"`
	LastOvpnBytes int64  `json:"last_ovpn_bytes"`
	OvpnCert      string `json:"ovpn_cert"`
	OvpnKey       string `json:"ovpn_key"`
}

type migrationBundleManifest struct {
	Version    int                        `json:"version"`
	ExportedAt string                     `json:"exported_at"`
	Includes   []string                   `json:"includes"`
	WireGuard  migrationWireGuardSettings `json:"wireguard,omitempty"`
	OpenVPN    migrationOpenVPNSettings   `json:"openvpn,omitempty"`
}

type migrationWireGuardSettings struct {
	Interface string `json:"interface,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
}

type migrationOpenVPNSettings struct {
	Subnet   string `json:"subnet,omitempty"`
	Port     string `json:"port,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	DNS      string `json:"dns,omitempty"`
	Mgmt     string `json:"mgmt,omitempty"`
	MSSFix   string `json:"mssfix,omitempty"`
	TunMTU   string `json:"tun_mtu,omitempty"`
}

type migrationBundleEntry struct {
	data []byte
	mode os.FileMode
}

func migrationFromDB(db *sql.DB) migrationFile {
	m := migrationFile{
		Version:    1,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for _, p := range allPeers(db) {
		m.Peers = append(m.Peers, migrationPeer{
			Username:      p.Username,
			PublicKey:     p.PublicKey,
			PrivateKey:    p.PrivateKey,
			PresharedKey:  p.PSK,
			Address:       p.Address,
			QuotaBytes:    p.QuotaBytes,
			UsedBytes:     p.UsedBytes,
			LastRx:        p.LastRx,
			LastTx:        p.LastTx,
			ExpiresAt:     p.ExpiresAt,
			Enabled:       p.Enabled,
			Blocked:       p.Blocked,
			OvpnCN:        p.OvpnCN,
			OvpnIP:        p.OvpnIP,
			OvpnEnabled:   p.OvpnEnabled,
			UsedOvpnBytes: p.UsedOvpnBytes,
			LastOvpnBytes: p.LastOvpnBytes,
			OvpnCert:      p.OvpnCert,
			OvpnKey:       p.OvpnKey,
		})
	}
	return m
}

func parseParamsData(data []byte) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
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

func readParamsIfExists(path string) map[string]string {
	if path == "" {
		return map[string]string{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	return parseParamsData(b)
}

func encodeMigration(db *sql.DB) []byte {
	b, err := json.MarshalIndent(migrationFromDB(db), "", "  ")
	if err != nil {
		die("export users: %v", err)
	}
	b = append(b, '\n')
	return b
}

func writeMigrationFile(db *sql.DB, path string) {
	if path == "" || path == "-" {
		os.Stdout.Write(encodeMigration(db))
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." {
		die("mkdir export dir: %v", err)
	}
	if err := os.WriteFile(path, encodeMigration(db), 0o600); err != nil {
		die("write export: %v", err)
	}
}

func addBundleFile(zw *zip.Writer, name string, data []byte, mode os.FileMode) {
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	if mode == 0 {
		mode = 0o600
	}
	h.SetMode(mode)
	w, err := zw.CreateHeader(h)
	if err != nil {
		die("bundle: create %s: %v", name, err)
	}
	if _, err := w.Write(data); err != nil {
		die("bundle: write %s: %v", name, err)
	}
}

func addExistingBundleFile(zw *zip.Writer, includes *[]string, bundleName, path string, fallbackMode os.FileMode) {
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		die("bundle: read %s: %v", path, err)
	}
	mode := fallbackMode
	if st, err := os.Stat(path); err == nil && st.Mode().Perm() != 0 {
		mode = st.Mode().Perm()
	}
	addBundleFile(zw, bundleName, b, mode)
	*includes = append(*includes, bundleName)
}

func buildMigrationBundleManifest(cfg Config, includes []string) migrationBundleManifest {
	pm := readParamsIfExists(cfg.Params)
	m := migrationBundleManifest{
		Version:    1,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Includes:   includes,
		WireGuard: migrationWireGuardSettings{
			Interface: cfg.Interface,
			Endpoint:  pm["SERVER_PUB_IP"],
		},
	}
	hasOpenVPN := false
	for _, name := range includes {
		if strings.HasPrefix(name, "openvpn/") {
			hasOpenVPN = true
			break
		}
	}
	if hasOpenVPN {
		m.OpenVPN = migrationOpenVPNSettings{
			Subnet:   cfg.OvpnSubnet,
			Port:     cfg.OvpnPort,
			Proto:    cfg.OvpnProto,
			Endpoint: cfg.OvpnEndpoint,
			DNS:      cfg.OvpnDNS,
			Mgmt:     cfg.OvpnMgmt,
			MSSFix:   cfg.OvpnMSSFix,
			TunMTU:   cfg.OvpnTunMTU,
		}
	}
	return m
}

func openVPNConfiguredForMigration(cfg Config) bool {
	return cfg.OvpnDir != "" || cfg.OvpnSubnet != "" || cfg.OvpnPort != "" ||
		cfg.OvpnProto != "" || cfg.OvpnEndpoint != "" || cfg.OvpnMgmt != ""
}

func encodeMigrationBundle(db *sql.DB, cfg Config) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	includes := []string{migrationUsersFile}
	addBundleFile(zw, migrationUsersFile, encodeMigration(db), 0o600)

	addExistingBundleFile(zw, &includes, "wireguard/params", cfg.Params, 0o600)
	addExistingBundleFile(zw, &includes, "wireguard/wg0.conf", cfg.WGConf, 0o600)

	if openVPNConfiguredForMigration(cfg) {
		ovpnCfg := cfg
		ovpnDefaults(&ovpnCfg)
		for _, item := range []struct {
			name string
			mode os.FileMode
		}{
			{"ca.crt", 0o644},
			{"ca.key", 0o600},
			{"server.crt", 0o644},
			{"server.key", 0o600},
			{"tc.key", 0o600},
			{"server.conf", 0o644},
		} {
			addExistingBundleFile(zw, &includes, "openvpn/"+item.name, filepath.Join(ovpnCfg.OvpnDir, item.name), item.mode)
		}
	}

	manifest := buildMigrationBundleManifest(cfg, includes)
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		die("bundle: manifest: %v", err)
	}
	addBundleFile(zw, migrationManifestFile, append(mb, '\n'), 0o600)
	if err := zw.Close(); err != nil {
		die("bundle: close: %v", err)
	}
	return buf.Bytes()
}

func writeMigrationBundleFile(db *sql.DB, cfg Config, path string) {
	if path == "" || path == "-" {
		os.Stdout.Write(encodeMigrationBundle(db, cfg))
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." {
		die("mkdir export dir: %v", err)
	}
	if err := os.WriteFile(path, encodeMigrationBundle(db, cfg), 0o600); err != nil {
		die("write bundle: %v", err)
	}
}

func decodeMigration(data []byte) migrationFile {
	var m migrationFile
	if err := json.Unmarshal(data, &m); err != nil {
		die("bad migration JSON: %v", err)
	}
	if m.Version == 0 {
		m.Version = 1
	}
	if m.Version != 1 {
		die("unsupported migration version %d", m.Version)
	}
	return m
}

func importMigration(db *sql.DB, cfg Config, data []byte, apply bool) (created, updated int) {
	m := decodeMigration(data)
	tx, err := db.Begin()
	if err != nil {
		die("begin import: %v", err)
	}
	defer tx.Rollback()
	for _, p := range m.Peers {
		if p.Username == "" {
			die("migration contains a user with empty username")
		}
		existing, ok := getPeer(db, p.Username)
		if ok {
			if _, err := tx.Exec(`UPDATE peers SET
				public_key=?,private_key=?,preshared_key=?,address=?,
				quota_bytes=?,used_bytes=?,last_rx=?,last_tx=?,expires_at=?,enabled=?,blocked=?,
				ovpn_cn=?,ovpn_ip=?,ovpn_enabled=?,used_ovpn_bytes=?,last_ovpn_bytes=?,ovpn_cert=?,ovpn_key=?,updated_at=?
				WHERE id=?`,
				p.PublicKey, p.PrivateKey, p.PresharedKey, p.Address,
				p.QuotaBytes, p.UsedBytes, p.LastRx, p.LastTx, p.ExpiresAt, b2i(p.Enabled), b2i(p.Blocked),
				p.OvpnCN, p.OvpnIP, b2i(p.OvpnEnabled), p.UsedOvpnBytes, p.LastOvpnBytes, p.OvpnCert, p.OvpnKey, nowUTC(),
				existing.ID); err != nil {
				die("update %s: %v", p.Username, err)
			}
			updated++
			continue
		}
		if _, err := tx.Exec(`INSERT INTO peers(
			username,public_key,private_key,preshared_key,address,
			quota_bytes,used_bytes,last_rx,last_tx,expires_at,enabled,blocked,
			ovpn_cn,ovpn_ip,ovpn_enabled,used_ovpn_bytes,last_ovpn_bytes,ovpn_cert,ovpn_key,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			p.Username, p.PublicKey, p.PrivateKey, p.PresharedKey, p.Address,
			p.QuotaBytes, p.UsedBytes, p.LastRx, p.LastTx, p.ExpiresAt, b2i(p.Enabled), b2i(p.Blocked),
			p.OvpnCN, p.OvpnIP, b2i(p.OvpnEnabled), p.UsedOvpnBytes, p.LastOvpnBytes, p.OvpnCert, p.OvpnKey, nowUTC(), nowUTC()); err != nil {
			die("insert %s: %v", p.Username, err)
		}
		created++
	}
	if err := tx.Commit(); err != nil {
		die("commit import: %v", err)
	}
	if apply {
		applyMigrationState(db, cfg)
	}
	return created, updated
}

func readMigrationBundle(data []byte) (map[string]migrationBundleEntry, bool) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, false
	}
	entries := map[string]migrationBundleEntry{}
	for _, f := range zr.File {
		name := filepath.ToSlash(f.Name)
		if f.FileInfo().IsDir() || !knownMigrationBundleEntry(name) {
			continue
		}
		if f.UncompressedSize64 > migrationBundleMaxFile {
			die("bundle: %s is too large", name)
		}
		rc, err := f.Open()
		if err != nil {
			die("bundle: open %s: %v", name, err)
		}
		b, err := io.ReadAll(io.LimitReader(rc, migrationBundleMaxFile+1))
		rc.Close()
		if err != nil {
			die("bundle: read %s: %v", name, err)
		}
		if len(b) > migrationBundleMaxFile {
			die("bundle: %s is too large", name)
		}
		entries[name] = migrationBundleEntry{data: b, mode: f.Mode().Perm()}
	}
	if len(entries) == 0 {
		die("bundle: no supported files found")
	}
	return entries, true
}

func knownMigrationBundleEntry(name string) bool {
	switch name {
	case migrationManifestFile, migrationUsersFile,
		"wireguard/params", "wireguard/wg0.conf",
		"openvpn/ca.crt", "openvpn/ca.key", "openvpn/server.crt",
		"openvpn/server.key", "openvpn/tc.key", "openvpn/server.conf":
		return true
	default:
		return false
	}
}

func decodeBundleManifest(entries map[string]migrationBundleEntry) migrationBundleManifest {
	var m migrationBundleManifest
	if e, ok := entries[migrationManifestFile]; ok {
		if err := json.Unmarshal(e.data, &m); err != nil {
			die("bundle: bad manifest: %v", err)
		}
	}
	if m.Version == 0 {
		m.Version = 1
	}
	if m.Version != 1 {
		die("bundle: unsupported manifest version %d", m.Version)
	}
	return m
}

func applyBundleConfig(cfg *Config, manifest migrationBundleManifest, entries map[string]migrationBundleEntry) {
	if hasBundlePrefix(entries, "wireguard/") {
		if cfg.Interface == "" {
			if manifest.WireGuard.Interface != "" {
				cfg.Interface = manifest.WireGuard.Interface
			} else {
				cfg.Interface = "wg0"
			}
		}
		if cfg.WGConf == "" {
			cfg.WGConf = "/etc/wireguard/wg0.conf"
		}
		if cfg.Params == "" {
			cfg.Params = "/etc/wireguard/params"
		}
	}
	if hasBundlePrefix(entries, "openvpn/") {
		if cfg.OvpnDir == "" {
			cfg.OvpnDir = "/etc/openvpn"
		}
		if manifest.OpenVPN.Subnet != "" {
			cfg.OvpnSubnet = manifest.OpenVPN.Subnet
		}
		if manifest.OpenVPN.Port != "" {
			cfg.OvpnPort = manifest.OpenVPN.Port
		}
		if manifest.OpenVPN.Proto != "" {
			cfg.OvpnProto = manifest.OpenVPN.Proto
		}
		if manifest.OpenVPN.DNS != "" {
			cfg.OvpnDNS = manifest.OpenVPN.DNS
		}
		if manifest.OpenVPN.Mgmt != "" {
			cfg.OvpnMgmt = manifest.OpenVPN.Mgmt
		}
		if manifest.OpenVPN.MSSFix != "" {
			cfg.OvpnMSSFix = manifest.OpenVPN.MSSFix
		}
		if manifest.OpenVPN.TunMTU != "" {
			cfg.OvpnTunMTU = manifest.OpenVPN.TunMTU
		}
		if manifest.OpenVPN.Endpoint != "" {
			cfg.OvpnEndpoint = manifest.OpenVPN.Endpoint
		}
		ovpnDefaults(cfg)
	}
}

func hasBundlePrefix(entries map[string]migrationBundleEntry, prefix string) bool {
	for name := range entries {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func restoreBundleFile(path string, e migrationBundleEntry, mode os.FileMode) {
	if path == "" {
		return
	}
	if mode == 0 {
		mode = e.mode
	}
	if mode == 0 {
		mode = 0o600
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		die("bundle: mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, e.data, mode); err != nil {
		die("bundle: restore %s: %v", path, err)
	}
	os.Chmod(path, mode)
}

func restoreMigrationBundleFiles(cfg Config, entries map[string]migrationBundleEntry) {
	if e, ok := entries["wireguard/params"]; ok {
		restoreBundleFile(cfg.Params, e, e.mode)
	}
	if e, ok := entries["wireguard/wg0.conf"]; ok {
		restoreBundleFile(cfg.WGConf, e, 0o600)
	}
	ovpnFiles := map[string]os.FileMode{
		"ca.crt":      0o644,
		"ca.key":      0o600,
		"server.crt":  0o644,
		"server.key":  0o600,
		"tc.key":      0o600,
		"server.conf": 0o644,
	}
	for name, mode := range ovpnFiles {
		if e, ok := entries["openvpn/"+name]; ok {
			restoreBundleFile(filepath.Join(cfg.OvpnDir, name), e, mode)
		}
	}
}

func importMigrationBundle(db *sql.DB, cfg Config, data []byte, apply bool) (created, updated int) {
	entries, ok := readMigrationBundle(data)
	if !ok {
		return importMigration(db, cfg, data, apply)
	}
	users, ok := entries[migrationUsersFile]
	if !ok {
		die("bundle: missing %s", migrationUsersFile)
	}
	manifest := decodeBundleManifest(entries)
	applyBundleConfig(&cfg, manifest, entries)
	created, updated = importMigration(db, cfg, users.data, false)
	restoreMigrationBundleFiles(cfg, entries)
	if apply {
		saveConfig(cfg)
		applyMigrationState(db, cfg)
	}
	return created, updated
}

func applyMigrationState(db *sql.DB, cfg Config) {
	if cfg.WGConf != "" && fileExists(cfg.WGConf) {
		renderConf(db, cfg, true)
	}
	if cfg.OvpnSubnet != "" || cfg.OvpnDir != "" {
		ovpnDefaults(&cfg)
		ccdDir := filepath.Join(cfg.OvpnDir, "ccd")
		os.MkdirAll(ccdDir, 0o755)
		os.Chmod(cfg.OvpnDir, 0o755)
		os.Chmod(ccdDir, 0o755)
		for _, p := range allPeers(db) {
			if p.OvpnCN == "" || p.OvpnIP == "" {
				continue
			}
			ccdFile := filepath.Join(ccdDir, p.OvpnCN)
			writeFileMode(ccdFile, "ifconfig-push "+p.OvpnIP+" "+ovpnMask(cfg.OvpnSubnet)+"\n", 0o644)
			os.Chmod(ccdFile, 0o644)
		}
		syncOpenVPNServerUnitConfig(cfg)
	}
}

func syncOpenVPNServerUnitConfig(cfg Config) {
	if cfg.OvpnDir != "/etc/openvpn" {
		return
	}
	src := filepath.Join(cfg.OvpnDir, "server.conf")
	if !fileExists(src) {
		return
	}
	b, err := os.ReadFile(src)
	if err != nil {
		die("openvpn: read server.conf: %v", err)
	}
	dst := filepath.Join(cfg.OvpnDir, "server", "server.conf")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		die("openvpn: mkdir server unit dir: %v", err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		die("openvpn: write server unit config: %v", err)
	}
}
