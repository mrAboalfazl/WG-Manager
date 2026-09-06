package main

import (
	"embed"
	"net/http"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

//go:embed ui/index.html
var uiFS embed.FS

// serveUI serves the single-page panel shell (no auth — contains no secrets; the app
// authenticates its API calls with the token the admin enters at login).
func (a *api) serveUI(w http.ResponseWriter, r *http.Request) {
	b, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "ui not found", 500)
		return
	}
	// Inject the web base path so the SPA's fetch() calls target /<base>/... not /...
	html := strings.Replace(string(b), "__WGMGR_BASE__", normBase(a.cfg.BasePath), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// qrPeer returns a PNG QR code of the peer's WireGuard client config (token-guarded).
// OpenVPN .ovpn files carry embedded CA/cert/key PEMs — typically 3-4KB, far past the
// practical QR-code payload limit — so OVPN-only users get a friendly error instead of
// an unscannable QR (or the old raw die on missing PrivateKey).
func (a *api) qrPeer(w http.ResponseWriter, r *http.Request) {
	p := a.mustPeer(r)
	if p.PrivateKey == "" {
		if p.OvpnCert != "" {
			die("QR is unavailable for OpenVPN-only users (the .ovpn is too large to encode) — use the Config button to download the .ovpn instead")
		}
		die("no stored config for %q — user has neither WireGuard nor OpenVPN credentials", p.Username)
	}
	png, err := qrcode.Encode(clientConfig(a.db, a.cfg, p), qrcode.Medium, 360)
	if err != nil {
		die("qr encode: %v", err)
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}
