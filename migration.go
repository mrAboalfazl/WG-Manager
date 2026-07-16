package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
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
	}
}
