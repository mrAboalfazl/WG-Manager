package main

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"time"
)

// parseOvpnStatus parses OpenVPN's `status 2` (machine-readable) output and returns a map
// of Common Name -> total bytes transferred this session (received + sent). OpenVPN's
// per-client counters reset on reconnect, so callers must carry deltas over the same way
// the WireGuard path does. Header/title/routing lines are ignored; only CLIENT_LIST rows
// count. A CN that appears more than once (multiple devices) is summed.
//
// CLIENT_LIST layout:
//
//	CLIENT_LIST,<Common Name>,<Real Address>,<Virtual Addr>,<Virtual IPv6>,<Bytes Recv>,<Bytes Sent>,...
func parseOvpnStatus(out string) map[string]int64 {
	m := map[string]int64{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), ",")
		if len(f) < 7 || f[0] != "CLIENT_LIST" {
			continue
		}
		cn := strings.TrimSpace(f[1])
		if cn == "" || cn == "UNDEF" {
			continue
		}
		rx, _ := strconv.ParseInt(strings.TrimSpace(f[5]), 10, 64)
		tx, _ := strconv.ParseInt(strings.TrimSpace(f[6]), 10, 64)
		m[cn] += rx + tx
	}
	return m
}

// ovpnUsage dials the OpenVPN management interface, asks for `status 2`, and returns
// CN -> total session bytes. mgmt is "unix:/run/wgmgr/ovpn.sock" or "host:port". An empty
// address or any error yields an empty map — OpenVPN simply contributes no usage this tick
// (so a WG-only install behaves exactly as before).
func ovpnUsage(mgmt string) map[string]int64 {
	if mgmt == "" {
		return map[string]int64{}
	}
	network, addr := "tcp", mgmt
	if strings.HasPrefix(mgmt, "unix:") {
		network, addr = "unix", strings.TrimPrefix(mgmt, "unix:")
	}
	conn, err := net.DialTimeout(network, addr, 3*time.Second)
	if err != nil {
		return map[string]int64{}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("status 2\n")); err != nil {
		return map[string]int64{}
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
	conn.Write([]byte("quit\n"))
	return parseOvpnStatus(b.String())
}
