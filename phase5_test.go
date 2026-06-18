package main

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// The Phase 5 migration must: rebuild an OLD-schema table (UNIQUE NOT NULL on
// public_key/address) without losing rows, then allow multiple OVPN-only users (empty WG
// fields) while still rejecting duplicate REAL WireGuard keys via the partial unique index.
func TestPhase5RelaxMigration(t *testing.T) {
	dbpath := filepath.Join(t.TempDir(), "t.db")

	// Build an OLD-schema DB by hand (pre-Phase-5: public_key/address UNIQUE NOT NULL).
	raw, err := sql.Open("sqlite", "file:"+dbpath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE peers(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		public_key TEXT UNIQUE NOT NULL,
		private_key TEXT DEFAULT '', preshared_key TEXT DEFAULT '',
		address TEXT UNIQUE NOT NULL,
		quota_bytes INTEGER NOT NULL DEFAULT 0, used_bytes INTEGER NOT NULL DEFAULT 0,
		last_rx INTEGER NOT NULL DEFAULT 0, last_tx INTEGER NOT NULL DEFAULT 0,
		expires_at TEXT DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, blocked INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL, updated_at TEXT NOT NULL, notes TEXT DEFAULT '');
		CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);`); err != nil {
		t.Fatalf("seed schema: %v", err)
	}
	if _, err := raw.Exec("INSERT INTO peers(username,public_key,address,created_at,updated_at) VALUES('wg1','PK1','10.66.66.2',?,?)", nowUTC(), nowUTC()); err != nil {
		t.Fatalf("seed row: %v", err)
	}
	raw.Close()

	// openDB() runs the additive ALTERs + the Phase 5 rebuild + partial indexes.
	db := openDB(dbpath)
	defer db.Close()

	if _, ok := getPeer(db, "wg1"); !ok {
		t.Fatalf("existing WG user lost during migration")
	}
	// Two OVPN-only users (empty public_key/address) must coexist.
	for _, u := range []string{"ov1", "ov2"} {
		if _, err := db.Exec("INSERT INTO peers(username,public_key,address,created_at,updated_at) VALUES(?,'','',?,?)", u, nowUTC(), nowUTC()); err != nil {
			t.Errorf("OVPN-only user %q insert should succeed, got: %v", u, err)
		}
	}
	// A duplicate REAL public_key must still be rejected (partial unique index).
	if _, err := db.Exec("INSERT INTO peers(username,public_key,address,created_at,updated_at) VALUES('dup','PK1','10.66.66.9',?,?)", nowUTC(), nowUTC()); err == nil {
		t.Errorf("duplicate non-empty public_key should be rejected by the partial unique index")
	}
}
