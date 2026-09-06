package main

import (
	"net"
	"os"
	"strings"
)

// serverPublicIP returns the server's best-known public IP, or "" if it can't be determined.
// Resolution order:
//  1. /etc/wireguard/params → SERVER_PUB_IP (WG-installed hosts have this).
//  2. cfg.OvpnEndpoint if it parses as an IP (OVPN-only hosts have this after ovpn-init).
//  3. Auto-detect via net.InterfaceAddrs — first non-loopback IPv4 (last-resort fallback so
//     the panel can still render + the TLS cert can still get an IP SAN on a WG-less box).
//
// Callers (ensureCert, listPeers, cmdOvpnInit) previously did the equivalent of
// parseParams(cfg.Params) with no guard; on OpenVPN-only installs cfg.Params is "", parseParams
// dies with "cannot read params : open : no such file or directory", and wgmgr serve crash-loops.
// Every parseParams call site that only wants the server IP should go through this helper.
func serverPublicIP(cfg Config) string {
	// (1) params file, when it exists and parses.
	if cfg.Params != "" {
		if b, err := os.ReadFile(cfg.Params); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "SERVER_PUB_IP") {
					if i := strings.Index(line, "="); i >= 0 {
						v := strings.TrimSpace(line[i+1:])
						if v != "" {
							return v
						}
					}
				}
			}
		}
	}
	// (2) OVPN endpoint if it looks like an IP (skip if it's a hostname).
	if ip := net.ParseIP(cfg.OvpnEndpoint); ip != nil {
		return cfg.OvpnEndpoint
	}
	// (3) auto-detect: first non-loopback, non-link-local IPv4 on any interface.
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			v4 := ipn.IP.To4()
			if v4 == nil || v4.IsPrivate() {
				continue // prefer a routable public IPv4; a private one is usually the wg0/tun0 self-IP
			}
			return v4.String()
		}
	}
	return ""
}

// serverPublicIPParsed is the net.IP form for callers (like ensureCert) that need to add it
// to a x509 SubjectAltName. Returns nil when serverPublicIP() returned "" or a non-IP hostname.
func serverPublicIPParsed(cfg Config) net.IP {
	return net.ParseIP(serverPublicIP(cfg))
}
