package main

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func mustNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestHostAllocatable(t *testing.T) {
	n24, n16 := mustNet(t, "10.66.66.0/24"), mustNet(t, "10.66.0.0/16")
	cases := []struct {
		ip   string
		n    *net.IPNet
		want bool
	}{
		{"10.66.66.1", n24, true},
		{"10.66.66.0", n24, false},   // network
		{"10.66.66.255", n24, false}, // broadcast — the old allocator handed this out
		{"10.66.67.1", n24, false},   // outside
		{"10.66.1.0", n16, false},    // .0 inside a /16: skipped on purpose
		{"10.66.1.255", n16, false},
		{"10.66.1.1", n16, true},
		{"10.66.255.255", n16, false},
	}
	for _, c := range cases {
		if got := hostAllocatable(net.ParseIP(c.ip), c.n); got != c.want {
			t.Errorf("hostAllocatable(%s, %s) = %v, want %v", c.ip, c.n, got, c.want)
		}
	}
}

func TestNextFreeHost(t *testing.T) {
	n24 := mustNet(t, "10.66.66.0/24")
	used := map[string]bool{"10.66.66.1": true}
	for i := 2; i <= 254; i++ {
		used["10.66.66."+strconv.Itoa(i)] = true
	}
	if ip, ok := nextFreeHost(n24, used); ok {
		t.Fatalf("full /24 returned %s; must not hand out the broadcast", ip)
	}
	// Same users after widening to /16: capacity appears, nobody moves.
	n16 := mustNet(t, "10.66.0.0/16")
	if ip, ok := nextFreeHost(n16, used); !ok || ip != "10.66.0.1" {
		t.Fatalf("widened pool next = %q,%v want 10.66.0.1", ip, ok)
	}
	// Skips past a fully used x.y.0.* block, over .255/.0, to x.y.1.1.
	for i := 1; i <= 254; i++ {
		used["10.66.0."+strconv.Itoa(i)] = true
	}
	if ip, _ := nextFreeHost(n16, used); ip != "10.66.1.1" {
		t.Fatalf("next = %s want 10.66.1.1", ip)
	}
}

func TestWidenCIDR(t *testing.T) {
	cases := []struct {
		in       string
		prefix   int
		keepHost bool
		want     string
		changed  bool
		wantErr  bool
	}{
		{"10.66.66.1/24", 16, true, "10.66.66.1/16", true, false},
		{"10.8.0.0/24", 16, false, "10.8.0.0/16", true, false},
		{"10.8.5.0/24", 16, false, "10.8.0.0/16", true, false},
		{"10.8.0.0/24", 20, false, "10.8.0.0/20", true, false},
		{"10.66.0.1/16", 16, true, "10.66.0.1/16", false, false},
		{"10.66.0.1/16", 20, true, "10.66.0.1/16", false, false}, // never narrows
		{"10.0.0.1/24", 8, true, "", false, true},                // too wide
		{"fd42::1/64", 16, true, "", false, true},
	}
	for _, c := range cases {
		got, changed, err := widenCIDR(c.in, c.prefix, c.keepHost)
		if (err != nil) != c.wantErr || got != c.want || changed != c.changed {
			t.Errorf("widenCIDR(%s,%d,%v) = %q,%v,%v want %q,%v,err=%v", c.in, c.prefix, c.keepHost, got, changed, err, c.want, c.changed, c.wantErr)
		}
	}
}

func TestRewriteWGHead(t *testing.T) {
	in := "[Interface]\nAddress = 10.66.66.1/24,fd42:42:42::1/64\nListenPort = 51820\n" +
		"PostUp = iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE\n\n" +
		peerMarker + "\n\n### wgmgr:alice\n[Peer]\nPublicKey = x\nAllowedIPs = 10.66.66.2/32\n"
	out := rewriteWGHead(in, "10.66.66.1/24", "10.66.66.1/16")
	for _, want := range []string{
		"Address = 10.66.66.1/16,fd42:42:42::1/64\n",
		"-s 10.66.0.0/16 -o eth0",
		"AllowedIPs = 10.66.66.2/32\n", // peers untouched
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "/24") {
		t.Errorf("old /24 left behind:\n%s", out)
	}
}

func TestParseIPRoutesAndConflicts(t *testing.T) {
	routes := "default via 1.2.3.1 dev eth0 proto dhcp\n" +
		"10.66.66.0/24 dev wg0 proto kernel scope link src 10.66.66.1\n" +
		"10.66.200.0/24 dev docker0 proto kernel scope link src 10.66.200.1\n" +
		"10.8.0.0/24 dev tun0 proto kernel scope link src 10.8.0.1\n" +
		"172.17.0.0/16 dev br0 proto kernel\n"
	addrs := "2: eth0    inet 1.2.3.4/24 brd 1.2.3.255 scope global eth0\\       valid_lft forever\n" +
		"5: wg0    inet 10.66.66.1/24 scope global wg0\\       valid_lft forever\n"
	e := append(parseIPRoutes(routes), parseIPRoutes(addrs)...)
	if len(e) != 6 {
		t.Fatalf("parsed %d entries: %+v", len(e), e)
	}
	own := func(d string) bool { return d == "wg0" }
	got := subnetConflicts(mustNet(t, "10.66.66.0/24"), mustNet(t, "10.66.0.0/16"), own, e)
	if want := []string{"10.66.200.0/24 dev docker0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("conflicts = %v want %v", got, want)
	}
	ovOld := mustNet(t, "10.8.0.0/24")
	if got := subnetConflicts(ovOld, mustNet(t, "10.8.0.0/16"), poolDevs(ovOld, e), e); len(got) != 0 {
		t.Fatalf("unexpected openvpn conflicts %v", got)
	}
	// Another VPN on tun1 and a typed (unreachable) route inside the new range must count;
	// only the device that carries the old pool (tun0) is "ours".
	e2 := append(e, parseIPRoutes("10.8.50.0/24 dev tun1 proto kernel\nunreachable 10.8.99.0/24 proto static\n")...)
	got = subnetConflicts(ovOld, mustNet(t, "10.8.0.0/16"), poolDevs(ovOld, e2), e2)
	if want := []string{"10.8.50.0/24 dev tun1", "10.8.99.0/24 dev "}; !reflect.DeepEqual(got, want) {
		t.Fatalf("conflicts = %q want %q", got, want)
	}
}

func TestOvpnAttachNewUserRollsBackOnFullPool(t *testing.T) {
	dir := t.TempDir()
	db := openDB(filepath.Join(dir, "t.db"))
	defer db.Close()
	cfg := Config{OvpnDir: dir, OvpnSubnet: "10.8.0.0/29"} // hosts .1(server) .2-.6
	os.MkdirAll(filepath.Join(dir, "ccd"), 0o755)
	for i := 2; i <= 6; i++ {
		db.Exec("INSERT INTO peers(username,public_key,address,ovpn_cn,ovpn_ip,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
			"u"+strconv.Itoa(i), "", "", "u"+strconv.Itoa(i), "10.8.0."+strconv.Itoa(i), nowUTC(), nowUTC())
	}
	db.Exec("INSERT INTO peers(username,public_key,address,created_at,updated_at) VALUES('late','','',?,?)", nowUTC(), nowUTC())
	p, _ := getPeer(db, "late")
	func() {
		defer func() {
			r := recover()
			if de, ok := r.(dieError); !ok || !strings.Contains(de.msg, "no free IP") {
				t.Fatalf("want a 'no free IP' die, got %v", r)
			}
		}()
		ovpnAttachNewUser(db, cfg, p)
	}()
	if _, ok := getPeer(db, "late"); ok {
		t.Fatal("ghost row left behind after a failed OpenVPN attach")
	}
	if g := ghostUsers(db); len(g) != 0 {
		t.Fatalf("ghostUsers = %v", g)
	}
}

func TestGhostUsers(t *testing.T) {
	db := openDB(filepath.Join(t.TempDir(), "t.db"))
	defer db.Close()
	for _, r := range [][]string{{"wg", "pk", ""}, {"ov", "", "ov"}, {"ghost", "", ""}} {
		db.Exec("INSERT INTO peers(username,public_key,address,ovpn_cn,created_at,updated_at) VALUES(?,?,'',?,?,?)",
			r[0], r[1], r[2], nowUTC(), nowUTC())
	}
	if g := ghostUsers(db); !reflect.DeepEqual(g, []string{"ghost"}) {
		t.Fatalf("ghostUsers = %v", g)
	}
}

func TestUpdateLaunchDetachesFromService(t *testing.T) {
	name, args := updateLaunch(true)
	if name != "systemd-run" || args[0] != "--unit="+updateUnit || args[len(args)-3] != "bash" {
		t.Fatalf("systemd launch = %s %v", name, args)
	}
	if !strings.Contains(args[len(args)-1], updateInstallerCommand) || strings.HasSuffix(args[len(args)-1], "&") {
		t.Fatalf("script = %q", args[len(args)-1])
	}
	name, args = updateLaunch(false)
	if name != "bash" || !strings.HasSuffix(args[1], " &") {
		t.Fatalf("fallback launch = %s %v", name, args)
	}
}

func TestWidenRuleArgs(t *testing.T) {
	save := "-P FORWARD DROP\n" +
		"-A FORWARD -m set --match-set wgmgr_blocked src -j DROP\n" +
		"-A FORWARD -s 10.8.0.0/24 -j ACCEPT\n" +
		"-A FORWARD -i eth0 -j ACCEPT\n" +
		"-A FORWARD -d 10.8.0.0/24 -m comment --comment \"ovpn back\" -j ACCEPT\n" +
		"-A INPUT -i tun+ -s 10.8.0.0/24 -j ACCEPT\n" +
		"-A FORWARD ! -s 10.8.0.0/24 -o eth0 -j DROP\n"
	got, manual := widenRuleArgs("filter", save, "10.8.0.0/24", "10.8.0.0/16")
	// A negated match can't be fixed by adding a copy (the original keeps dropping the new
	// range) — it must be reported for a manual edit, not copied.
	if len(manual) != 1 || !strings.Contains(manual[0], "! -s 10.8.0.0/24") {
		t.Fatalf("manual = %v", manual)
	}
	want := [][]string{ // last rule first, each inserted at its original position
		{"-w", "-t", "filter", "-I", "INPUT", "1", "-i", "tun+", "-s", "10.8.0.0/16", "-j", "ACCEPT"},
		{"-w", "-t", "filter", "-I", "FORWARD", "4", "-d", "10.8.0.0/16", "-m", "comment", "--comment", "ovpn back", "-j", "ACCEPT"},
		{"-w", "-t", "filter", "-I", "FORWARD", "2", "-s", "10.8.0.0/16", "-j", "ACCEPT"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d commands: %v", len(got), got)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i][1], want[i]) {
			t.Errorf("insert[%d] = %v\nwant      %v", i, got[i][1], want[i])
		}
		if got[i][0][3] != "-C" {
			t.Errorf("check[%d] = %v", i, got[i][0])
		}
	}
}

func TestBuildExpandPlan(t *testing.T) {
	dir := t.TempDir()
	wg := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wg, []byte("[Interface]\nAddress = 10.66.66.1/24\nListenPort = 51820\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Interface: "wg0", WGConf: wg, OvpnSubnet: "10.8.0.0/24"}
	p := buildExpandPlan(cfg, true, 16, nil)
	if p.WGOldAddr != "10.66.66.1/24" || p.WGNewAddr != "10.66.66.1/16" || p.OvOldNet != "10.8.0.0/24" || p.OvNewNet != "10.8.0.0/16" ||
		len(p.WGConflicts)+len(p.OvConflicts) != 0 {
		t.Fatalf("plan = %+v", p)
	}
	// Already wide: nothing to do.
	cfg.OvpnSubnet = "10.8.0.0/16"
	os.WriteFile(wg, []byte("[Interface]\nAddress = 10.66.66.1/16\n"), 0o600)
	if p := buildExpandPlan(cfg, true, 16, nil); !p.empty() {
		t.Fatalf("expected empty plan, got %+v", p)
	}
	// Widening one pool into the other is a conflict — charged to the protocol widened.
	os.WriteFile(wg, []byte("[Interface]\nAddress = 10.8.200.1/24\n"), 0o600)
	cfg.OvpnSubnet = "10.8.0.0/24"
	if p := buildExpandPlan(cfg, true, 16, nil); len(p.WGConflicts) == 0 || len(p.OvConflicts) == 0 {
		t.Fatalf("expected wg/ovpn overlap conflicts on both, got %+v", p)
	}
	// A clash on one protocol leaves the other clean, so --auto can still widen it.
	os.WriteFile(wg, []byte("[Interface]\nAddress = 10.66.66.1/24\n"), 0o600)
	docker := []netEntry{{Dev: "docker0", Net: mustNet(t, "10.66.200.0/24")}}
	if p := buildExpandPlan(cfg, true, 16, docker); len(p.WGConflicts) != 1 || len(p.OvConflicts) != 0 {
		t.Fatalf("expected only a wireguard conflict, got %+v", p)
	}
	// OpenVPN subnet not aligned to the new prefix: the server IP would move → refused.
	cfg.OvpnSubnet = "10.8.5.0/24"
	p = buildExpandPlan(cfg, true, 16, nil)
	if len(p.OvConflicts) != 1 || !strings.Contains(p.OvConflicts[0], "server IP would move 10.8.5.1 -> 10.8.0.1") {
		t.Fatalf("expected alignment conflict, got %+v", p.OvConflicts)
	}
}

func TestRewriteOvpnServerLine(t *testing.T) {
	in := "port 1194\n# custom bits survive\npush \"route 192.168.5.0 255.255.255.0\"\nserver 10.8.0.0 255.255.255.0\ntls-crypt /etc/openvpn/old-tc.key\n"
	out, ok := rewriteOvpnServerLine(in, "10.8.0.0/16")
	want := strings.Replace(in, "server 10.8.0.0 255.255.255.0", "server 10.8.0.0 255.255.0.0", 1)
	if !ok || out != want {
		t.Fatalf("got ok=%v\n%s", ok, out)
	}
	if _, ok := rewriteOvpnServerLine("port 1194\n", "10.8.0.0/16"); ok {
		t.Fatal("no server line must report ok=false")
	}
}

func TestConfHeadAndPeerSection(t *testing.T) {
	db := openDB(filepath.Join(t.TempDir(), "t.db"))
	defer db.Close()
	for _, r := range [][]string{{"alice", "pkA", "10.66.66.2"}, {"ovonly", "", ""}} {
		if _, err := db.Exec("INSERT INTO peers(username,public_key,address,created_at,updated_at) VALUES(?,?,?,?,?)",
			r[0], r[1], r[2], nowUTC(), nowUTC()); err != nil {
			t.Fatal(err)
		}
	}
	conf := "[Interface]\nAddress = 10.66.66.1/16\n\n" + peerMarker + "\n\n### wgmgr:stale\n[Peer]\nPublicKey = old\n"
	if h := confHead(conf); h != "[Interface]\nAddress = 10.66.66.1/16\n" {
		t.Fatalf("confHead = %q", h)
	}
	sec := renderPeerSection(db)
	if !strings.Contains(sec, "### wgmgr:alice\n[Peer]\nPublicKey = pkA\nAllowedIPs = 10.66.66.2/32\n") || strings.Contains(sec, "ovonly") {
		t.Fatalf("peer section:\n%s", sec)
	}
}
