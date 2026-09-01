package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// ovpnStatusCandidates is the list of paths OpenVPN commonly writes its --status file to,
// tried in order when cfg.OvpnStatus is unset. Different systemd units on different distros
// pick different paths — hard-coding one caused v1.5.3 to silently miss OVPN usage on hosts
// where openvpn-server@ was the running unit (Debian/Ubuntu default) instead of the older
// wgmgr-shipped openvpn@ path. The auto-probe below picks the newest non-empty candidate,
// so operators don't need per-host ovpn_status overrides.
var ovpnStatusCandidates = []string{
	"/run/openvpn-server/status-server.log", // openvpn-server@server.service (modern Debian/Ubuntu)
	"/run/openvpn-server/server.status",     // same unit, alternate name some installers use
	"/run/openvpn/server.status",            // wgmgr's shipped path (openvpn@server.service style)
	"/var/log/openvpn/status.log",           // occasional older layout
}

// resolveOvpnStatus picks the --status file to read.
//   - Explicit cfg.OvpnStatus wins even when stale/empty; an operator override should surface
//     misconfiguration through the normal "NOT counted this tick" warning, not be silently
//     replaced by auto-detection.
//   - Otherwise, iterate ovpnStatusCandidates and pick the most recently modified one that
//     exists AND is non-empty. A 0-byte candidate is almost always a leftover from a stopped
//     unit (observed on live servers) — treating it as authoritative "no clients" is what
//     silently zeroed accounting in v1.5.3.
//   - Returns "" when nothing qualifies, letting ovpnUsage fall through to the mgmt socket
//     and log a failure.
func resolveOvpnStatus(cfg Config) string {
	if cfg.OvpnStatus != "" {
		return cfg.OvpnStatus
	}
	var best string
	var bestMod time.Time
	for _, p := range ovpnStatusCandidates {
		fi, err := os.Stat(p)
		if err != nil || fi.Size() == 0 {
			continue
		}
		if fi.ModTime().After(bestMod) {
			best, bestMod = p, fi.ModTime()
		}
	}
	return best
}

// parseOvpnStatus parses OpenVPN status output and returns Common Name -> total bytes
// transferred this session (received + sent). It accepts BOTH machine formats so the same
// code works against the management socket and the on-disk status file:
//
//   - status-version 2 / `status 2` (management socket): rows are
//     "CLIENT_LIST,<cn>,<real>,<virt>,<virt6>,<rx>,<tx>,<since>,..." — bytes at fields 5,6.
//   - status-version 1 (the plain `--status` file): a
//     "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since" header followed by
//     "<cn>,<real>,<rx>,<tx>,<since>" rows until ROUTING TABLE / GLOBAL STATS — bytes at 2,3.
//
// OpenVPN's per-client counters reset on reconnect, so callers must carry deltas over the same
// way the WireGuard path does. A CN that appears more than once (multiple devices) is summed;
// header/title/routing lines and UNDEF (unauthenticated) clients are ignored.
func parseOvpnStatus(out string) map[string]int64 {
	m := map[string]int64{}
	inV1Clients := false // true while inside the v1 file's "CLIENT LIST" section
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		f := strings.Split(line, ",")
		switch {
		case len(f) >= 7 && f[0] == "CLIENT_LIST": // v2 (management socket)
			addOvpnBytes(m, f[1], f[5], f[6])
		case len(f) >= 5 && f[0] == "Common Name" && f[2] == "Bytes Received": // v1 client header
			inV1Clients = true
		case f[0] == "ROUTING TABLE" || f[0] == "GLOBAL STATS" || f[0] == "END":
			inV1Clients = false
		case inV1Clients && len(f) >= 4: // v1 client row
			addOvpnBytes(m, f[0], f[2], f[3])
		}
	}
	return m
}

func addOvpnBytes(m map[string]int64, cn, rxStr, txStr string) {
	cn = strings.TrimSpace(cn)
	if cn == "" || cn == "UNDEF" {
		return
	}
	rx, _ := strconv.ParseInt(strings.TrimSpace(rxStr), 10, 64)
	tx, _ := strconv.ParseInt(strings.TrimSpace(txStr), 10, 64)
	m[cn] += rx + tx
}

// ovpnUsage returns Common Name -> total session bytes for every OpenVPN client, for the
// enforce loop to delta-accumulate. It prefers OpenVPN's --status FILE (cfg.OvpnStatus, or the
// newest non-empty candidate under /run/openvpn*): the file has no single-client limit and is
// rewritten every few seconds, so it can't be wedged the way the management socket can (the
// socket accepts one client at a time and a single stuck session makes every later connect()
// return ECONNREFUSED — which silently froze usage accounting in the field). The management
// socket is kept as a fallback for older installs.
//
// Returns an empty map when OVPN isn't configured. When OVPN IS configured but no source can be
// read, it logs to stderr — a stalled reader must be visible, not look like "no traffic".
func ovpnUsage(cfg Config) map[string]int64 {
	if cfg.OvpnMgmt == "" && cfg.OvpnStatus == "" {
		return map[string]int64{} // OVPN usage tracking off — WG-only install, unchanged behavior
	}
	// Primary: the status file. A readable file is authoritative even when it lists zero
	// clients (nobody connected) — we do NOT fall through to the socket in that case.
	// resolveOvpnStatus already skipped 0-byte / missing candidates, so an empty parse here
	// really does mean "OpenVPN is up with nobody connected".
	statusFile := resolveOvpnStatus(cfg)
	if statusFile != "" {
		if b, err := os.ReadFile(statusFile); err == nil {
			return parseOvpnStatus(string(b))
		}
	}
	// Fallback: the management socket (older installs / status file not yet written).
	if cfg.OvpnMgmt != "" {
		if m, err := ovpnUsageMgmt(cfg.OvpnMgmt); err == nil {
			return m
		} else {
			fmt.Fprintf(os.Stderr, "ovpn: usage read failed (no readable --status file found among %v, mgmt %q: %v) — OpenVPN usage NOT counted this tick\n", ovpnStatusCandidates, cfg.OvpnMgmt, err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "ovpn: no readable --status file found among %v and no mgmt socket configured — OpenVPN usage NOT counted this tick\n", ovpnStatusCandidates)
	}
	return map[string]int64{}
}

// ovpnUsageMgmt dials the OpenVPN management interface, asks for `status 2`, and returns
// CN -> total session bytes. mgmt is "unix:/run/wgmgr/ovpn.sock" or "host:port". Unlike the old
// version it surfaces errors to the caller instead of swallowing them, so a broken socket is
// logged rather than silently zeroing usage.
func ovpnUsageMgmt(mgmt string) (map[string]int64, error) {
	network, addr := "tcp", mgmt
	if strings.HasPrefix(mgmt, "unix:") {
		network, addr = "unix", strings.TrimPrefix(mgmt, "unix:")
	}
	conn, err := net.DialTimeout(network, addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("status 2\n")); err != nil {
		return nil, err
	}
	var b strings.Builder
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		b.WriteString(line)
		b.WriteByte('\n')
		if strings.HasPrefix(line, "END") {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	conn.Write([]byte("quit\n"))
	return parseOvpnStatus(b.String()), nil
}
