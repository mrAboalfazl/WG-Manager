package main

import "testing"

func TestIsNewer(t *testing.T) {
	cases := []struct {
		latest, installed string
		want              bool
	}{
		// Real-world comparisons the panel will make.
		{"v1.7.0", "v1.6.1", true},
		{"v1.6.1", "v1.6.1", false},
		{"v1.6.0", "v1.6.1", false},
		{"v1.10.0", "v1.9.9", true}, // numeric compare, not string ("10" > "9" only numerically)
		{"v2.0.0", "v1.99.99", true},
		// Empty / equal inputs must not claim an update is available.
		{"", "v1.6.1", false},
		{"v1.6.1", "", false},
		// Dev / source builds should ALWAYS see a release as newer, so a fresh dev install
		// running the panel sees the Update button and can move onto a proper release.
		{"v1.6.1", "dev", true},
		{"v1.6.1", "source-abc1234", true},
		// Prerelease suffixes should not confuse the base-version compare (best-effort).
		{"v1.7.0-rc1", "v1.6.1", true},
		{"v1.6.1", "v1.6.1-rc1", false}, // parseable both ways after stripping; tie -> not newer
	}
	for _, c := range cases {
		if got := isNewer(c.latest, c.installed); got != c.want {
			t.Errorf("isNewer(%q, %q)=%v want %v", c.latest, c.installed, got, c.want)
		}
	}
}

func TestSemParts(t *testing.T) {
	ok := func(s string, want [3]int) {
		got, ok := semParts(s)
		if !ok || got != want {
			t.Errorf("semParts(%q)=%v,%v want %v,true", s, got, ok, want)
		}
	}
	ok("v1.6.1", [3]int{1, 6, 1})
	ok("1.6.1", [3]int{1, 6, 1})
	ok("v2", [3]int{2, 0, 0})
	ok("v1.6", [3]int{1, 6, 0})
	ok("v1.6.1-rc2", [3]int{1, 6, 1})
	ok("v1.6.1+meta", [3]int{1, 6, 1})
	// Non-numeric must return ok=false so the caller falls back to string compare.
	if _, ok := semParts("dev"); ok {
		t.Errorf("semParts(dev) should not parse")
	}
	if _, ok := semParts("source-abc1234"); ok {
		t.Errorf("semParts(source-...) should not parse")
	}
}
