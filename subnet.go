package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Subnet capacity. Installs before v1.8 shipped /24 pools (10.66.66.0/24 for WireGuard,
// 10.8.0.0/24 for OpenVPN) → ~253 users per protocol. `wgmgr expand-subnet` widens a
// pool IN PLACE: the server keeps its tunnel IP and every user keeps theirs (the old /24
// is a subset of the new /16), so existing client configs stay valid — a WG client only
// carries its own /32 + AllowedIPs, and an OVPN client gets ip+mask pushed from CCD.

const (
	defaultExpandPrefix = 16 // target pool size: ~65k users per protocol
	minExpandPrefix     = 16 // refuse anything wider — it would just invite route clashes
)

// hostAllocatable reports whether ip may be handed to a user: inside n, not its network
// or broadcast address, and not ending in .0/.255. The last rule costs ~2 addresses per
// 256 but sidesteps clients/routers that mishandle such hosts (and it is what keeps the
// /24 broadcast .255 from ever being issued again).
func hostAllocatable(ip net.IP, n *net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil || !n.Contains(ip4) {
		return false
	}
	if ip4[3] == 0 || ip4[3] == 255 {
		return false
	}
	return !ip4.Equal(n.IP.Mask(n.Mask)) && !ip4.Equal(broadcastAddr(n))
}

func broadcastAddr(n *net.IPNet) net.IP {
	base := n.IP.Mask(n.Mask).To4()
	out := make(net.IP, 4)
	for i := range out {
		out[i] = base[i] | ^n.Mask[len(n.Mask)-4+i]
	}
	return out
}

// nextFreeHost returns the lowest allocatable address in n that is not in used.
func nextFreeHost(n *net.IPNet, used map[string]bool) (string, bool) {
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return "", false
	}
	size := 1 << uint(32-ones)
	ip := n.IP.Mask(n.Mask).To4()
	for i := 0; i < size; i++ {
		if hostAllocatable(ip, n) && !used[ip.String()] {
			return ip.String(), true
		}
		ip = nextIP(ip)
	}
	return "", false
}

// widenCIDR re-expresses cidr with a shorter prefix. keepHost=true keeps the host part
// ("10.66.66.1/24" → "10.66.66.1/16", the WG interface Address form); false yields the
// network form ("10.8.0.0/24" → "10.8.0.0/16", the OpenVPN subnet form). changed=false
// when cidr is already that wide or wider.
func widenCIDR(cidr string, prefix int, keepHost bool) (string, bool, error) {
	ip, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || ip.To4() == nil {
		return "", false, fmt.Errorf("not an IPv4 CIDR: %q", cidr)
	}
	if prefix < minExpandPrefix || prefix > 30 {
		return "", false, fmt.Errorf("prefix /%d out of range (/%d../30)", prefix, minExpandPrefix)
	}
	ones, _ := n.Mask.Size()
	if ones <= prefix {
		return cidr, false, nil
	}
	m := net.CIDRMask(prefix, 32)
	if keepHost {
		return fmt.Sprintf("%s/%d", ip.To4(), prefix), true, nil
	}
	return fmt.Sprintf("%s/%d", ip.To4().Mask(m), prefix), true, nil
}

func networkOf(cidr string) string {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	return n.String()
}

// rewriteWGHead swaps the interface Address (first IPv4 entry only — an IPv6 entry is
// kept) and any literal mention of the old network (e.g. a PostUp `-s 10.66.66.0/24`) in
// the [Interface] head. The peer section is left alone: it only holds /32s.
func rewriteWGHead(conf, oldAddr, newAddr string) string {
	oldNet, newNet := networkOf(oldAddr), networkOf(newAddr)
	lines := strings.Split(conf, "\n")
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if isHeadEnd(t) {
			break
		}
		if strings.HasPrefix(strings.ToLower(t), "address") && strings.Contains(l, oldAddr) {
			lines[i] = strings.Replace(l, oldAddr, newAddr, 1)
			continue
		}
		if oldNet != "" && strings.Contains(l, oldNet) {
			lines[i] = strings.ReplaceAll(l, oldNet, newNet)
		}
	}
	return strings.Join(lines, "\n")
}

// rewriteOvpnServerLine replaces only the `server <net> <mask>` directive, so hand edits
// and directives from older templates survive. ok=false when there is no such line.
func rewriteOvpnServerLine(conf, subnet string) (string, bool) {
	_, n, err := net.ParseCIDR(subnet)
	if err != nil {
		return conf, false
	}
	lines := strings.Split(conf, "\n")
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) >= 3 && f[0] == "server" {
			lines[i] = "server " + n.IP.String() + " " + net.IP(n.Mask).String()
			return strings.Join(lines, "\n"), true
		}
	}
	return conf, false
}

type netEntry struct {
	Dev string
	Net *net.IPNet
}

// parseIPRoutes reads `ip -4 -o route show` / `ip -4 -o addr show` output into (dev, net)
// pairs. "default" routes are skipped — every subnet overlaps 0.0.0.0/0.
func parseIPRoutes(out string) []netEntry {
	var res []netEntry
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 1 {
			switch f[0] { // typed routes: "unreachable 10.8.0.0/16 ..." — the type isn't a dest
			case "blackhole", "unreachable", "prohibit", "throw", "local", "broadcast", "anycast", "multicast":
				f = f[1:]
			}
		}
		if len(f) == 0 || f[0] == "default" {
			continue
		}
		var cidr, dev string
		if len(f) >= 4 && f[2] == "inet" { // addr form: "2: eth0    inet 10.0.0.5/24 brd ..."
			cidr, dev = f[3], f[1]
		} else { // route form: "10.0.0.0/24 dev eth0 proto kernel ..."
			cidr = f[0]
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "dev" {
					dev = f[i+1]
				}
			}
		}
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		if _, n, err := net.ParseCIDR(cidr); err == nil && n.IP.To4() != nil {
			res = append(res, netEntry{Dev: dev, Net: n})
		}
	}
	return res
}

func netsOverlap(a, b *net.IPNet) bool { return a.Contains(b.IP) || b.Contains(a.IP) }

// poolDevs returns the devices holding a route/address inside the pool — i.e. the pool's
// own interface(s). Another VPN's tun1 elsewhere in the range is NOT one of them.
func poolDevs(pool *net.IPNet, entries []netEntry, extra ...string) func(string) bool {
	own := map[string]bool{}
	for _, d := range extra {
		if d != "" {
			own[d] = true
		}
	}
	po, _ := pool.Mask.Size()
	for _, e := range entries {
		eo, _ := e.Net.Mask.Size()
		if e.Dev != "" && eo >= po && pool.Contains(e.Net.IP) {
			own[e.Dev] = true
		}
	}
	return func(d string) bool { return own[d] }
}

// subnetConflicts lists host routes/addresses that the widened pool would newly collide
// with. Entries on the pool's own device(s) or already inside the old pool are ignored.
func subnetConflicts(oldNet, newNet *net.IPNet, ownDev func(string) bool, entries []netEntry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		if ownDev(e.Dev) || netsOverlap(oldNet, e.Net) || !netsOverlap(newNet, e.Net) {
			continue
		}
		s := e.Net.String() + " dev " + e.Dev
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// splitRule tokenizes one `iptables -S` line, honouring double quotes (comments).
func splitRule(line string) []string {
	var toks []string
	var cur strings.Builder
	inQ, have := false, false
	for _, r := range line {
		switch {
		case r == '"':
			inQ = !inQ
			have = true
		case (r == ' ' || r == '\t') && !inQ:
			if have {
				toks = append(toks, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if have {
		toks = append(toks, cur.String())
	}
	return toks
}

// widenRuleArgs turns `iptables -t <table> -S` output into insert commands that add a
// copy of every rule mentioning oldNet with newNet instead, placed directly before the
// original (so ACCEPT/MASQUERADE ordering relative to DROPs is preserved). Commands are
// returned last-rule-first so each precomputed position stays valid while inserting.
// Each entry is [checkArgs, insertArgs]. Rules with a NEGATED match (`! -s oldNet`) go to
// manual instead: a copy can't help there — the original keeps matching (and e.g.
// dropping) the new part of the range, so an operator has to edit those by hand.
func widenRuleArgs(table, saveOut, oldNet, newNet string) (cmds [][2][]string, manual []string) {
	pos := map[string]int{}
	for _, line := range strings.Split(saveOut, "\n") {
		toks := splitRule(strings.TrimSpace(line))
		if len(toks) < 2 || toks[0] != "-A" {
			continue
		}
		chain := toks[1]
		pos[chain]++
		hit, negated := false, false
		rule := make([]string, 0, len(toks)-2)
		for _, t := range toks[2:] {
			if t == oldNet {
				t, hit = newNet, true
				// iptables -S prints negation as "! -s NET": the "!" sits two tokens back.
				if n := len(rule); n >= 2 && rule[n-2] == "!" {
					negated = true
				}
			}
			rule = append(rule, t)
		}
		if !hit {
			continue
		}
		if negated {
			manual = append(manual, "-t "+table+" "+strings.TrimSpace(line))
			continue
		}
		check := append([]string{"-w", "-t", table, "-C", chain}, rule...)
		insert := append([]string{"-w", "-t", table, "-I", chain, strconv.Itoa(pos[chain])}, rule...)
		cmds = append(cmds, [2][]string{check, insert})
	}
	for i, j := 0, len(cmds)-1; i < j; i, j = i+1, j-1 {
		cmds[i], cmds[j] = cmds[j], cmds[i]
	}
	return cmds, manual
}

// widenFirewall mirrors live iptables rules from oldNet to newNet (idempotent via -C).
func widenFirewall(oldNet, newNet string) {
	if _, err := run("iptables", "-w", "-S"); err != nil {
		return // no iptables on this host
	}
	for _, table := range []string{"filter", "nat", "mangle"} {
		out, err := run("iptables", "-w", "-t", table, "-S")
		if err != nil {
			continue
		}
		cmds, manual := widenRuleArgs(table, out, oldNet, newNet)
		for _, m := range manual {
			fmt.Printf("  WARNING: negated rule must be edited by hand for %s: iptables %s\n", newNet, m)
		}
		for _, c := range cmds {
			if _, err := run("iptables", c[0]...); err == nil {
				continue // already present
			}
			if o, err := run("iptables", c[1]...); err != nil {
				fmt.Fprintf(os.Stderr, "warning: iptables %s: %v %s\n", strings.Join(c[1], " "), err, o)
			} else {
				fmt.Printf("  firewall: iptables %s\n", strings.Join(c[1][1:], " "))
			}
		}
	}
	// Persistent rule files we don't own: point them out rather than edit them.
	for _, f := range []string{"/etc/iptables/rules.v4", "/etc/ufw/before.rules", "/etc/ufw/user.rules", "/etc/sysconfig/iptables"} {
		if b, err := os.ReadFile(f); err == nil && strings.Contains(string(b), oldNet) {
			fmt.Printf("  note: %s mentions %s — add %s there too so it survives a firewall reload\n", f, oldNet, newNet)
		}
	}
}

func backupFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		die("backup %s: %v", path, err)
	}
	bak := path + ".bak-" + time.Now().UTC().Format("20060102T150405Z")
	st, _ := os.Stat(path)
	mode := os.FileMode(0o600)
	if st != nil {
		mode = st.Mode().Perm()
	}
	if err := os.WriteFile(bak, b, mode); err != nil {
		die("backup %s: %v", path, err)
	}
	return bak
}

func hostNetEntries() []netEntry {
	var out []netEntry
	if s, err := run("ip", "-4", "-o", "route", "show"); err == nil {
		out = append(out, parseIPRoutes(s)...)
	}
	if s, err := run("ip", "-4", "-o", "addr", "show"); err == nil {
		out = append(out, parseIPRoutes(s)...)
	}
	return out
}

// expandPlan is what cmdExpandSubnet will do; empty fields = nothing for that protocol.
// Conflicts are kept per protocol so --auto can still widen the pool that is clean.
type expandPlan struct {
	WGOldAddr, WGNewAddr string // interface Address, host form
	OvOldNet, OvNewNet   string // OpenVPN subnet, network form
	WGConflicts          []string
	OvConflicts          []string
}

func (p expandPlan) empty() bool { return p.WGNewAddr == "" && p.OvNewNet == "" }

func buildExpandPlan(cfg Config, ovpnOn bool, prefix int, entries []netEntry) expandPlan {
	var p expandPlan
	wgCur := ""
	if cfg.WGConf != "" && fileExists(cfg.WGConf) {
		_, ipnet, srv := interfaceHead(cfg.WGConf)
		wgCur = ipnet.String()
		ones, _ := ipnet.Mask.Size()
		old := fmt.Sprintf("%s/%d", srv, ones)
		nw, changed, err := widenCIDR(old, prefix, true)
		if err != nil {
			die("wireguard: %v", err)
		}
		if changed {
			p.WGOldAddr, p.WGNewAddr = old, nw
		}
	}
	ovCur := ""
	if ovpnOn {
		ovCur = networkOf(cfg.OvpnSubnet)
		nw, changed, err := widenCIDR(cfg.OvpnSubnet, prefix, false)
		if err != nil {
			die("openvpn: %v", err)
		}
		if changed {
			p.OvOldNet, p.OvNewNet = ovCur, nw
		}
	}
	if p.WGNewAddr != "" {
		_, oldN, _ := net.ParseCIDR(p.WGOldAddr)
		_, newN, _ := net.ParseCIDR(p.WGNewAddr)
		own := poolDevs(oldN, entries, cfg.Interface)
		p.WGConflicts = prefixAll("wireguard "+newN.String()+" overlaps ", subnetConflicts(oldN, newN, own, entries))
		for _, o := range []string{ovCur, p.OvNewNet} {
			if _, on, err := net.ParseCIDR(o); err == nil && netsOverlap(newN, on) {
				p.WGConflicts = append(p.WGConflicts, "wireguard "+newN.String()+" overlaps openvpn "+on.String())
				break
			}
		}
	}
	if p.OvNewNet != "" {
		_, oldN, _ := net.ParseCIDR(p.OvOldNet)
		_, newN, _ := net.ParseCIDR(p.OvNewNet)
		// OpenVPN's `server` directive puts the server on network+1. If the old subnet
		// isn't aligned to the new prefix that address changes (10.8.5.1 -> 10.8.0.1) and
		// anything bound to the old server IP breaks — refuse instead.
		if oldSrv, newSrv := nextIP(oldN.IP), nextIP(newN.IP); !oldSrv.Equal(newSrv) {
			p.OvConflicts = append(p.OvConflicts, fmt.Sprintf("openvpn server IP would move %s -> %s (%s is not aligned to /%d)", oldSrv, newSrv, oldN, prefix))
		}
		own := poolDevs(oldN, entries)
		p.OvConflicts = append(p.OvConflicts, prefixAll("openvpn "+newN.String()+" overlaps ", subnetConflicts(oldN, newN, own, entries))...)
		for _, o := range []string{wgCur, networkOf(p.WGNewAddr)} {
			if _, wn, err := net.ParseCIDR(o); err == nil && netsOverlap(newN, wn) {
				p.OvConflicts = append(p.OvConflicts, "openvpn "+newN.String()+" overlaps wireguard "+wn.String())
				break
			}
		}
	}
	sort.Strings(p.WGConflicts)
	sort.Strings(p.OvConflicts)
	return p
}

func prefixAll(pre string, xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = pre + x
	}
	return out
}

func ovpnConfigured(cfg Config) bool {
	if cfg.OvpnSubnet == "" {
		return false
	}
	dir := cfg.OvpnDir
	if dir == "" {
		dir = "/etc/openvpn"
	}
	return fileExists(filepath.Join(dir, "server.conf"))
}

// cmdExpandSubnet: wgmgr expand-subnet [--prefix 16] [--dry-run] [--yes] [--auto]
// --auto is for install.sh: no prompt; a protocol whose widening would clash is reported
// and left alone while the other one still proceeds (exit 0); wgmgr.service is not
// restarted (the installer restarts it right after).
func cmdExpandSubnet(args []string) { expandSubnet(args, nil) }

// expandSubnet takes the caller's stdin reader (the menu's) so buffered input isn't split
// between two readers; nil = make one.
func expandSubnet(args []string, in *bufio.Reader) {
	_, flags := parseFlags(args)
	auto := flags["auto"] == "true"
	prefix := defaultExpandPrefix
	if v, ok := flags["prefix"]; ok {
		n, err := strconv.Atoi(strings.TrimPrefix(v, "/"))
		if err != nil {
			die("bad --prefix %q", v)
		}
		prefix = n
	}
	cfg := loadConfig()
	ovpnOn := ovpnConfigured(cfg)
	if ovpnOn {
		ovpnDefaults(&cfg)
	}
	plan := buildExpandPlan(cfg, ovpnOn, prefix, hostNetEntries())
	if plan.empty() {
		fmt.Printf("subnets already /%d or wider — nothing to do\n", prefix)
		return
	}
	fmt.Println("subnet expansion plan (users keep their IPs; existing client configs stay valid):")
	if plan.WGNewAddr != "" {
		fmt.Printf("  wireguard: %s -> %s  (brief blip on %s while the address is swapped)\n", plan.WGOldAddr, plan.WGNewAddr, cfg.Interface)
	}
	if plan.OvNewNet != "" {
		fmt.Printf("  openvpn:   %s -> %s  (OpenVPN restarts; clients reconnect automatically)\n", plan.OvOldNet, plan.OvNewNet)
	}
	conflicts := append(append([]string{}, plan.WGConflicts...), plan.OvConflicts...)
	for _, c := range conflicts {
		fmt.Println("  conflict:", c)
	}
	if len(conflicts) > 0 {
		if !auto {
			die("refusing to expand: resolve the conflicts above or pick a smaller --prefix (e.g. 20)")
		}
		if len(plan.WGConflicts) > 0 {
			fmt.Println("  wireguard expansion skipped")
			plan.WGOldAddr, plan.WGNewAddr = "", ""
		}
		if len(plan.OvConflicts) > 0 {
			fmt.Println("  openvpn expansion skipped")
			plan.OvOldNet, plan.OvNewNet = "", ""
		}
		if plan.empty() {
			fmt.Println("subnet expansion skipped")
			return
		}
	}
	if flags["dry-run"] == "true" {
		return
	}
	if !auto && flags["yes"] != "true" {
		if in == nil {
			if !isInteractive() {
				die("expand-subnet requires --yes when stdin is not interactive")
			}
			in = bufio.NewReader(os.Stdin)
		}
		if !confirm(in, "Apply?") {
			fmt.Println("cancelled")
			return
		}
	}
	if plan.WGNewAddr != "" {
		expandWireGuard(cfg, plan.WGOldAddr, plan.WGNewAddr)
	}
	if plan.OvNewNet != "" {
		expandOpenVPN(cfg, plan.OvOldNet, plan.OvNewNet)
	}
	if !auto && serviceState("wgmgr.service") == "active" {
		run("systemctl", "restart", "wgmgr.service")
		fmt.Println("restarted wgmgr.service")
	}
	fmt.Println("subnet expansion done")
}

func expandWireGuard(cfg Config, oldAddr, newAddr string) {
	db := openDB(cfg.DB)
	defer db.Close()
	bak := backupFile(cfg.WGConf)
	// Re-read right before writing, and rebuild the peer section from the DB (the source of
	// truth) so a peer the panel added while we ran is not lost. If the live interface has
	// peers the DB doesn't know, keep the file's own peer section (renderConf's guard).
	b, err := os.ReadFile(cfg.WGConf)
	if err != nil {
		die("read %s: %v", cfg.WGConf, err)
	}
	conf := rewriteWGHead(string(b), oldAddr, newAddr)
	if livePeersInDB(db, cfg.Interface) {
		conf = strings.TrimRight(confHead(conf), "\n") + renderPeerSection(db)
	}
	tmp := cfg.WGConf + ".wgmgr-expand.tmp" // not renderConf's .wgmgr.tmp
	if err := os.WriteFile(tmp, []byte(conf), 0o600); err != nil {
		die("write conf: %v", err)
	}
	if err := os.Rename(tmp, cfg.WGConf); err != nil {
		die("replace conf: %v", err)
	}
	fmt.Printf("  wireguard: %s updated (backup %s)\n", cfg.WGConf, bak)
	// Live swap: add the wide address first, then drop the narrow one, so there is never a
	// moment with no route to the pool. wg syncconf doesn't touch interface addresses.
	if _, err := run("ip", "link", "show", cfg.Interface); err != nil {
		fmt.Printf("  wireguard: %s is not up — the new address applies on next start\n", cfg.Interface)
	} else {
		if out, err := run("ip", "-4", "addr", "add", newAddr, "dev", cfg.Interface); err != nil && !strings.Contains(out, "File exists") {
			die("ip addr add %s dev %s: %v %s", newAddr, cfg.Interface, err, out)
		}
		if out, err := run("ip", "-4", "addr", "del", oldAddr, "dev", cfg.Interface); err != nil && !strings.Contains(out, "Cannot assign") {
			fmt.Fprintf(os.Stderr, "warning: ip addr del %s dev %s: %v %s\n", oldAddr, cfg.Interface, err, out)
		}
		fmt.Printf("  wireguard: %s now %s\n", cfg.Interface, newAddr)
	}
	widenFirewall(networkOf(oldAddr), networkOf(newAddr))
}

// livePeersInDB reports whether every peer on the running interface is in the DB (true
// when the interface is down or `wg` is missing — nothing live to lose).
func livePeersInDB(db *sql.DB, iface string) bool {
	known := map[string]bool{}
	for _, p := range allPeers(db) {
		known[p.PublicKey] = true
	}
	for pk := range livePeers(iface) {
		if !known[pk] {
			return false
		}
	}
	return true
}

func expandOpenVPN(cfg Config, oldNet, newNet string) {
	conf := filepath.Join(cfg.OvpnDir, "server.conf")
	b, err := os.ReadFile(conf)
	if err != nil {
		die("read %s: %v", conf, err)
	}
	out, ok := rewriteOvpnServerLine(string(b), newNet)
	if !ok {
		die("openvpn: no `server <net> <mask>` line in %s — not touching it", conf)
	}
	bak := backupFile(conf)
	writeFileMode(conf, out, 0o644)
	cfg.OvpnSubnet = newNet
	// openvpn-server@server reads server/server.conf — normally a symlink to this file, but a
	// plain copy on migrated/older boxes. Keep it in step or the unit restarts on the old /24.
	syncOpenVPNServerUnitConfig(cfg)
	fmt.Printf("  openvpn: %s updated (backup %s)\n", conf, bak)
	db := openDB(cfg.DB)
	mask := ovpnMask(newNet)
	n := 0
	for _, p := range allPeers(db) {
		if p.OvpnCN == "" || p.OvpnIP == "" {
			continue
		}
		ccd := filepath.Join(cfg.OvpnDir, "ccd", p.Username)
		if !fileExists(ccd) {
			continue // no CCD = deliberately locked out (ccd-exclusive); don't resurrect it
		}
		writeFileMode(ccd, fmt.Sprintf("ifconfig-push %s %s\n", p.OvpnIP, mask), 0o644)
		os.Chmod(ccd, 0o644)
		n++
	}
	db.Close()
	fmt.Printf("  openvpn: rewrote %d CCD file(s) with mask %s\n", n, mask)
	saveConfig(cfg)
	widenFirewall(oldNet, newNet)
	// The routing preflight reads ovpn_subnet from config.json — rerun it so NAT/forward
	// (iptables, nftables or firewalld flavour) covers the new range persistently.
	if _, err := run("systemctl", "cat", "wgmgr-openvpn-routing.service"); err == nil {
		if _, err := run("systemctl", "restart", "wgmgr-openvpn-routing.service"); err == nil {
			fmt.Println("  openvpn: routing preflight re-applied")
		}
	}
	if unit := existingOpenVPNUnit(); unit != "" {
		if out, err := run("systemctl", "restart", unit); err != nil {
			fmt.Fprintf(os.Stderr, "warning: systemctl restart %s: %v %s\n", unit, err, out)
		} else {
			fmt.Printf("  openvpn: restarted %s\n", unit)
		}
	}
}
