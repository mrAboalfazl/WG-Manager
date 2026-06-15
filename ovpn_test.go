package main

import (
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
