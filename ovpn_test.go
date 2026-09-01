package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseOvpnStatus(t *testing.T) {
	out := "TITLE,OpenVPN 2.6.0\n" +
		"TIME,2026-06-15 10:00:00,1750000000\n" +
		"HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since\n" +
		"CLIENT_LIST,alice,1.2.3.4:5555,10.8.0.2,,1000,2000,2026-06-15 09:00:00\n" +
		"CLIENT_LIST,bob,5.6.7.8:6666,10.8.0.3,,500,500,2026-06-15 09:30:00\n" +
		"CLIENT_LIST,alice,9.9.9.9:7777,10.8.0.4,,10,15,2026-06-15 09:45:00\n" + // same CN on a 2nd device -> summed
		"CLIENT_LIST,UNDEF,2.2.2.2:1,,,,5,6\n" + // unauthenticated -> skipped
		"ROUTING_TABLE,10.8.0.2,alice,1.2.3.4:5555,2026-06-15 09:59:00\n" +
		"END\n"
	m := parseOvpnStatus(out)
	if got, want := m["alice"], int64(1000+2000+10+15); got != want {
		t.Errorf("alice=%d want %d", got, want)
	}
	if got, want := m["bob"], int64(1000); got != want {
		t.Errorf("bob=%d want %d", got, want)
	}
	if _, ok := m["UNDEF"]; ok {
		t.Errorf("UNDEF client must be skipped")
	}
	if len(m) != 2 {
		t.Errorf("expected 2 CNs, got %d", len(m))
	}
}

// The status FILE is version 1 (human/CSV) format — different columns from `status 2`. The
// file-based reader is what makes usage robust to a wedged management socket, so it must parse.
func TestParseOvpnStatusV1File(t *testing.T) {
	out := "OpenVPN CLIENT LIST\n" +
		"Updated,2026-08-12 10:54:45\n" +
		"Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n" +
		"alice,1.2.3.4:5555,1000,2000,2026-08-12 09:00:00\n" +
		"bob,5.6.7.8:6666,500,500,2026-08-12 09:30:00\n" +
		"alice,9.9.9.9:7777,10,15,2026-08-12 09:45:00\n" + // same CN 2nd device -> summed
		"ROUTING TABLE\n" +
		"Virtual Address,Common Name,Real Address,Last Ref\n" +
		"10.8.0.2,alice,1.2.3.4:5555,2026-08-12 10:54:44\n" + // must NOT be counted as usage
		"GLOBAL STATS\n" +
		"Max bcast/mcast queue length,22\n" +
		"END\n"
	m := parseOvpnStatus(out)
	if got, want := m["alice"], int64(1000+2000+10+15); got != want {
		t.Errorf("alice=%d want %d", got, want)
	}
	if got, want := m["bob"], int64(1000); got != want {
		t.Errorf("bob=%d want %d", got, want)
	}
	if len(m) != 2 {
		t.Errorf("expected 2 CNs, got %d (%v)", len(m), m)
	}
}

// resolveOvpnStatus is what stops v1.5.3's "silently zero on wrong path" mode: an operator
// override must be honored verbatim; a stale 0-byte file (leftover from a stopped unit) must
// NOT be picked as authoritative; among real candidates the newest one wins.
func TestResolveOvpnStatus(t *testing.T) {
	dir := t.TempDir()
	orig := ovpnStatusCandidates
	t.Cleanup(func() { ovpnStatusCandidates = orig })

	stale := filepath.Join(dir, "stale.status") // leftover 0-byte file
	old := filepath.Join(dir, "old.status")     // real, older
	fresh := filepath.Join(dir, "fresh.status") // real, newest — should win
	if err := os.WriteFile(stale, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte("TITLE,OpenVPN\nEND\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fresh, []byte("TITLE,OpenVPN\nEND\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Force strict mtime ordering (t.TempDir + WriteFile on some filesystems has 1s resolution).
	past := time.Now().Add(-2 * time.Hour)
	older := time.Now().Add(-1 * time.Hour)
	os.Chtimes(stale, past, past)
	os.Chtimes(old, older, older)
	os.Chtimes(fresh, time.Now(), time.Now())
	ovpnStatusCandidates = []string{
		stale, // 0-byte -> skipped even though "first"
		filepath.Join(dir, "missing.status"),
		old,
		fresh,
	}

	// Explicit override wins even when it's a nonexistent path — the caller must see the
	// misconfiguration through the "NOT counted" warning, not have it silently masked.
	if got := resolveOvpnStatus(Config{OvpnStatus: "/does/not/exist"}); got != "/does/not/exist" {
		t.Errorf("override ignored: got %q", got)
	}
	// Auto-probe: newest non-empty candidate wins; 0-byte and missing are skipped.
	if got := resolveOvpnStatus(Config{}); got != fresh {
		t.Errorf("auto-probe picked %q, want %q", got, fresh)
	}
	// All candidates missing -> "" so ovpnUsage falls through to the mgmt socket / warns.
	ovpnStatusCandidates = []string{filepath.Join(dir, "none1"), filepath.Join(dir, "none2")}
	if got := resolveOvpnStatus(Config{}); got != "" {
		t.Errorf("with no candidates, expected empty string, got %q", got)
	}
}

// The whole point of the feature: a single quota measured against WG + OVPN combined.
func TestCombinedQuotaBlocks(t *testing.T) {
	now := time.Now().UTC()
	const GB = int64(1024 * 1024 * 1024)
	p := Peer{Enabled: true, QuotaBytes: 50 * GB, UsedBytes: 20 * GB, UsedOvpnBytes: 30 * GB}
	if usedTotal(p) != 50*GB {
		t.Fatalf("usedTotal=%d want %d", usedTotal(p), 50*GB)
	}
	if !effectiveBlocked(p, now) {
		t.Errorf("20GB WG + 30GB OVPN should hit the 50GB combined cap")
	}
	p.UsedOvpnBytes = 29 * GB // 49 total
	if effectiveBlocked(p, now) {
		t.Errorf("49GB combined must not block under a 50GB cap")
	}
	// WG-only user, no OVPN identity — unchanged behavior.
	wgOnly := Peer{Enabled: true, QuotaBytes: 10 * GB, UsedBytes: 11 * GB}
	if !effectiveBlocked(wgOnly, now) {
		t.Errorf("WG-only over-quota user should still block")
	}
}
