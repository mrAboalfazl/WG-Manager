package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestListOrphanCCDs is the safety net for the delete-flow fix: it verifies that CCD files
// with no matching DB row show up as orphans, that bserver_TEST_* is correctly classified
// as test-bot artifacts (safe to bulk-purge), and that a CN present in the live-clients
// map is marked Connected so it isn't accidentally kicked by the default --purge path.
func TestListOrphanCCDs(t *testing.T) {
	dir := t.TempDir()
	ccd := filepath.Join(dir, "ccd")
	if err := os.MkdirAll(ccd, 0o755); err != nil {
		t.Fatal(err)
	}
	// Seed the CCD dir with a realistic mix.
	writeCCD := func(name string) {
		if err := os.WriteFile(filepath.Join(ccd, name), []byte("ifconfig-push 10.8.0.9 255.255.255.0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeCCD("bit_18485_managed")             // has a DB row -> NOT an orphan
	writeCCD("bit_18470_orphan_disconnected") // orphan, not connected
	writeCCD("bit_18567_orphan_connected")    // orphan, currently connected
	writeCCD("bserver_TEST_995_stale")        // orphan, test-bot artifact
	if err := os.Mkdir(filepath.Join(ccd, "subdir_ignored"), 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := Config{OvpnDir: dir}
	dbUsers := map[string]bool{"bit_18485_managed": true}
	live := map[string]bool{"bit_18567_orphan_connected": true, "some_other_active_user": true}

	got, err := listOrphanCCDs(cfg, dbUsers, live)
	if err != nil {
		t.Fatalf("listOrphanCCDs: %v", err)
	}
	if n := len(got); n != 3 {
		t.Fatalf("orphan count = %d, want 3 (%v)", n, got)
	}

	byName := map[string]orphanEntry{}
	for _, o := range got {
		byName[o.Username] = o
	}

	// Managed user must not appear as an orphan.
	if _, has := byName["bit_18485_managed"]; has {
		t.Errorf("managed user leaked into orphan list")
	}
	// Test-bot artifact must be classified IsTest so --purge-test can safely pick it up.
	if o, ok := byName["bserver_TEST_995_stale"]; !ok || !o.IsTest {
		t.Errorf("bserver_TEST_995_stale not flagged as test-bot: %+v", o)
	}
	if o, ok := byName["bit_18470_orphan_disconnected"]; !ok || o.IsTest {
		t.Errorf("real orphan wrongly flagged as test: %+v", o)
	}
	// Currently-connected orphan must be marked so --purge (without --force) skips it.
	if o, ok := byName["bit_18567_orphan_connected"]; !ok || !o.Connected {
		t.Errorf("orphan_connected not flagged Connected: %+v", o)
	}
	if o := byName["bit_18470_orphan_disconnected"]; o.Connected {
		t.Errorf("disconnected orphan wrongly flagged Connected: %+v", o)
	}
}

// TestOrphanEmptyDir covers the "no OVPN yet / empty ccd" case — must not panic or error
// out of the daemon flow. Absent ccd/ dir returns an error we surface; empty ccd/ returns
// zero orphans cleanly.
func TestOrphanEmptyDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "ccd"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := listOrphanCCDs(Config{OvpnDir: dir}, nil, nil)
	if err != nil {
		t.Fatalf("empty ccd errored: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 orphans, got %d", len(got))
	}
	// Missing ccd/ dir: must return an error (operator sees it), not panic.
	if _, err := listOrphanCCDs(Config{OvpnDir: t.TempDir()}, nil, nil); err == nil {
		t.Errorf("missing ccd/ dir should return an error")
	}
}

// TestOvpnRemoveCCD confirms the helper actually deletes the file and is silent on missing
// files / empty inputs — the delete paths depend on that (they call it unconditionally).
func TestOvpnRemoveCCD(t *testing.T) {
	dir := t.TempDir()
	ccd := filepath.Join(dir, "ccd")
	if err := os.MkdirAll(ccd, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(ccd, "alice")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ovpnRemoveCCD(Config{OvpnDir: dir}, "alice")
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("expected %s to be gone, err=%v", p, err)
	}
	// Missing file: must not panic.
	ovpnRemoveCCD(Config{OvpnDir: dir}, "does-not-exist")
	// Empty inputs: must not do anything odd.
	ovpnRemoveCCD(Config{OvpnDir: ""}, "alice")
	ovpnRemoveCCD(Config{OvpnDir: dir}, "")
}
