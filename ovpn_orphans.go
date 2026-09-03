package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// orphanEntry is one CCD file that has no matching wgmgr DB row. IsTest flags automation
// artifacts (bserver_TEST_*) so the operator can bulk-purge them safely; Connected is only
// true when the CN is present in OpenVPN's current status file (means kicking it disrupts
// a live session — a --force is required to purge those).
type orphanEntry struct {
	Username  string
	CCDMTime  time.Time
	IsTest    bool
	Connected bool
}

// listOrphanCCDs scans <OvpnDir>/ccd, filters out entries with a matching DB row, and
// annotates the survivors. dbUsernames and liveCNs are passed in so this is trivially
// testable (no filesystem calls beyond the CCD directory listing).
func listOrphanCCDs(cfg Config, dbUsernames map[string]bool, liveCNs map[string]bool) ([]orphanEntry, error) {
	ccdDir := filepath.Join(cfg.OvpnDir, "ccd")
	entries, err := os.ReadDir(ccdDir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", ccdDir, err)
	}
	var out []orphanEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if dbUsernames[name] {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, orphanEntry{
			Username:  name,
			CCDMTime:  fi.ModTime(),
			IsTest:    strings.HasPrefix(name, "bserver_TEST_"),
			Connected: liveCNs[name],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

// cmdOvpnOrphans implements `wgmgr ovpn-orphans [--purge-test|--purge] [--force] [--dry-run]`.
// Default (no flags) is a listing — never destructive. Purge modes:
//   - --purge-test        : delete only bserver_TEST_* CCDs (test-bot artifacts, safe)
//   - --purge             : delete all orphans NOT currently connected
//   - --purge --force     : delete every orphan (kicks anyone currently connected)
//   - --dry-run           : with any --purge*, print what would be deleted without deleting
func cmdOvpnOrphans(args []string) {
	_, flags := parseFlags(args)
	purgeTest := flags["purge-test"] == "true"
	purgeAll := flags["purge"] == "true"
	force := flags["force"] == "true"
	dryRun := flags["dry-run"] == "true"
	if purgeTest && purgeAll {
		die("choose one of --purge-test or --purge, not both")
	}

	cfg := loadConfig()
	if cfg.OvpnDir == "" {
		die("OpenVPN is not configured on this host (cfg.OvpnDir is empty)")
	}
	db := openDB(cfg.DB)
	defer db.Close()

	dbUsers := map[string]bool{}
	for _, p := range allPeers(db) {
		dbUsers[p.Username] = true
	}
	live := ovpnUsage(cfg) // CN -> bytes; presence == currently connected
	liveSet := make(map[string]bool, len(live))
	for cn := range live {
		liveSet[cn] = true
	}

	orphans, err := listOrphanCCDs(cfg, dbUsers, liveSet)
	if err != nil {
		die("scan CCDs: %v", err)
	}

	// Listing / summary mode (default when no --purge* flag is present).
	if !purgeTest && !purgeAll {
		printOrphanReport(orphans)
		return
	}

	// Build the actual delete-set based on selector + force flag.
	var target []orphanEntry
	var label string
	switch {
	case purgeTest:
		label = "test-bot CCDs (bserver_TEST_*)"
		for _, o := range orphans {
			if o.IsTest {
				target = append(target, o)
			}
		}
	case purgeAll && force:
		label = "ALL orphans (including currently-connected — these clients will be kicked)"
		target = orphans
	case purgeAll:
		label = "orphans not currently connected"
		for _, o := range orphans {
			if !o.Connected {
				target = append(target, o)
			}
		}
	}

	fmt.Printf("wgmgr ovpn-orphans: %s\n  candidates: %d (of %d total orphans)\n",
		label, len(target), len(orphans))
	if len(target) == 0 {
		fmt.Println("  nothing to delete.")
		return
	}
	if dryRun {
		fmt.Println("  --dry-run set, listing without deleting:")
		for _, o := range target {
			printOrphanRow(o)
		}
		return
	}
	if purgeAll && !force {
		// Warn if anyone connected is being SKIPPED — that's the safe default but easy to miss.
		skipped := 0
		for _, o := range orphans {
			if !o.IsTest && o.Connected {
				skipped++
			}
		}
		if skipped > 0 {
			fmt.Printf("  (skipping %d currently-connected orphans; pass --force to remove them too)\n", skipped)
		}
	}
	deleted := 0
	for _, o := range target {
		p := filepath.Join(cfg.OvpnDir, "ccd", o.Username)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "  skip %s: %v\n", o.Username, err)
			continue
		}
		deleted++
	}
	fmt.Printf("removed %d orphan CCD file(s).\n", deleted)
	if force {
		fmt.Println("note: currently-connected clients will drop at their next reconnect (ccd-exclusive).")
	}
}

func printOrphanReport(orphans []orphanEntry) {
	total, testCount, realCount, connected := len(orphans), 0, 0, 0
	for _, o := range orphans {
		if o.IsTest {
			testCount++
		} else {
			realCount++
		}
		if o.Connected {
			connected++
		}
	}
	fmt.Printf("wgmgr ovpn-orphans: %d orphan CCD files\n", total)
	fmt.Printf("  test-bot (bserver_TEST_*): %d   real users: %d   currently connected: %d\n\n",
		testCount, realCount, connected)
	if total == 0 {
		return
	}
	fmt.Printf("%-40s %-8s %-9s %s\n", "USERNAME", "TYPE", "STATE", "CCD MTIME")
	for _, o := range orphans {
		printOrphanRow(o)
	}
	fmt.Println()
	fmt.Println("Actions:")
	fmt.Println("  wgmgr ovpn-orphans --purge-test           # remove only bserver_TEST_* CCDs")
	fmt.Println("  wgmgr ovpn-orphans --purge                # remove orphans NOT currently connected")
	fmt.Println("  wgmgr ovpn-orphans --purge --force        # remove ALL orphans (kicks anyone connected)")
	fmt.Println("  ... add --dry-run to any --purge* to preview without deleting.")
}

func printOrphanRow(o orphanEntry) {
	typ := "user"
	if o.IsTest {
		typ = "test"
	}
	state := "-"
	if o.Connected {
		state = "connected"
	}
	fmt.Printf("%-40s %-8s %-9s %s\n", o.Username, typ, state, o.CCDMTime.UTC().Format(time.RFC3339))
}
