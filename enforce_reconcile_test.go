package main

import (
	"reflect"
	"sort"
	"testing"
)

// parseIpsetSave has to survive real-world ipset output: an empty set (only a `create` line),
// a set with several members, members with per-entry options (timeout N), and — defensively —
// stray lines for a differently-named set that must be filtered out.
func TestParseIpsetSave(t *testing.T) {
	empty := "create wgmgr_blocked hash:ip family inet hashsize 1024 maxelem 65536\n"
	if got := parseIpsetSave("wgmgr_blocked", empty); len(got) != 0 {
		t.Errorf("empty set: expected 0 members, got %v", got)
	}
	with := "create wgmgr_blocked hash:ip family inet hashsize 1024 maxelem 65536\n" +
		"add wgmgr_blocked 10.66.66.5\n" +
		"add wgmgr_blocked 10.8.0.42 timeout 60\n" +
		"add wgmgr_blocked 10.66.66.7\n"
	got := parseIpsetSave("wgmgr_blocked", with)
	want := []string{"10.66.66.5", "10.8.0.42", "10.66.66.7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("with members: got %v want %v", got, want)
	}
	// Lines for a differently-named set must NOT bleed into our reconcile — we could be
	// reading a shared ipset list output someday.
	cross := "add wgmgr_blocked 10.66.66.5\n" +
		"add someone_else 10.99.99.99\n" +
		"add wgmgr_blocked 10.8.0.42\n"
	got = parseIpsetSave("wgmgr_blocked", cross)
	want = []string{"10.66.66.5", "10.8.0.42"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cross-set: got %v want %v", got, want)
	}
	// Empty input must not panic.
	if got := parseIpsetSave("wgmgr_blocked", ""); len(got) != 0 {
		t.Errorf("empty string: expected 0 members, got %v", got)
	}
}

// staleIPs is the core of the reconcile pass — given the ipset's current members and the
// set of IPs owned by live peers, it returns the members no peer claims (safe to delete).
// A regression here could either leak stale blocks (harmless) or wrongly delete a live
// block (would let an expired user out), so lock the semantics down.
func TestStaleIPs(t *testing.T) {
	cases := []struct {
		name string
		have []string
		want map[string]bool
		out  []string
	}{
		{"empty inputs", nil, nil, nil},
		{"all claimed", []string{"10.66.66.5", "10.8.0.42"},
			map[string]bool{"10.66.66.5": true, "10.8.0.42": true}, nil},
		{"none claimed", []string{"10.66.66.99", "10.8.0.99"}, map[string]bool{}, []string{"10.66.66.99", "10.8.0.99"}},
		{"mixed", []string{"10.66.66.5", "10.66.66.99", "10.8.0.42", "10.8.0.99"},
			map[string]bool{"10.66.66.5": true, "10.8.0.42": true},
			[]string{"10.66.66.99", "10.8.0.99"}},
		// A live peer's IP present in `want` but NOT in `have` isn't our concern here:
		// the enforce loop adds/keeps live blocks separately; reconcile only sweeps stragglers.
		{"want superset of have", []string{"10.66.66.5"},
			map[string]bool{"10.66.66.5": true, "10.8.0.42": true, "10.8.0.99": true}, nil},
	}
	for _, c := range cases {
		got := staleIPs(c.have, c.want)
		// Sort both for order-independence; staleIPs preserves input order but that's not
		// a promised invariant — the caller only uses the slice to feed `ipset del`.
		sort.Strings(got)
		sort.Strings(c.out)
		if !reflect.DeepEqual(got, c.out) {
			t.Errorf("%s: staleIPs(%v, %v) = %v, want %v", c.name, c.have, c.want, got, c.out)
		}
	}
}
