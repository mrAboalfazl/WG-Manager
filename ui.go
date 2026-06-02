package main

import (
	"embed"
	"net/http"

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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

// qrPeer returns a PNG QR code of the peer's client config (token-guarded).
func (a *api) qrPeer(w http.ResponseWriter, r *http.Request) {
	p := a.mustPeer(r)
	if p.PrivateKey == "" {
		die("no stored private key for %q", p.Username)
	}
	png, err := qrcode.Encode(clientConfig(a.db, a.cfg, p), qrcode.Medium, 360)
	if err != nil {
		die("qr encode: %v", err)
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}
