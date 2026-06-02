#!/usr/bin/env bash
# WG-Manager (wgmgr) installer — deploy the user/quota/API/panel layer onto a server
# that already runs native (kernel) WireGuard. Idempotent; safe to re-run to update.
#
#   curl -fsSL https://raw.githubusercontent.com/mrAboalfazl/WG-Manager/main/install.sh | bash
#
set -euo pipefail
REPO="mrAboalfazl/WG-Manager"
PREFIX=/usr/local/bin
IFACE="${WG_IFACE:-wg0}"
say(){ printf '\033[0;36m[wgmgr]\033[0m %s\n' "$*"; }
err(){ printf '\033[0;31m[wgmgr] %s\033[0m\n' "$*" >&2; }

[ "$(id -u)" = 0 ] || { err "please run as root"; exit 1; }

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64;;
  aarch64|arm64) ARCH=arm64;;
  *) err "unsupported arch: $(uname -m)"; exit 1;;
esac

say "installing dependencies (ipset, wireguard-tools)…"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ipset wireguard-tools curl >/dev/null 2>&1 || true
fi
command -v wg >/dev/null 2>&1 || { err "wireguard-tools (wg) not found — set up WireGuard first."; exit 1; }

if [ ! -f "/etc/wireguard/${IFACE}.conf" ] || [ ! -f /etc/wireguard/params ]; then
  err "expected /etc/wireguard/${IFACE}.conf and /etc/wireguard/params (a native WireGuard install)."
  err "Install WireGuard first (e.g. the angristan 'wireguard-install.sh'), then re-run this."
  exit 1
fi

# --- obtain the binary: prefer a published release, else build from source ---
say "fetching wgmgr binary (${ARCH})…"
if curl -fsSL "https://github.com/${REPO}/releases/latest/download/wgmgr-linux-${ARCH}" -o "${PREFIX}/wgmgr.new"; then
  say "downloaded latest release"
elif command -v go >/dev/null 2>&1; then
  say "no release asset reachable — building from source with Go…"
  tmp="$(mktemp -d)"; git clone --depth 1 "https://github.com/${REPO}.git" "$tmp" >/dev/null 2>&1
  ( cd "$tmp" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "${PREFIX}/wgmgr.new" . )
  rm -rf "$tmp"
else
  err "couldn't download a release binary and Go isn't installed to build from source."; exit 1
fi
chmod +x "${PREFIX}/wgmgr.new"
# atomic replace (avoids 'text file busy' if the daemon is running)
mv -f "${PREFIX}/wgmgr.new" "${PREFIX}/wgmgr"

# --- init config + admin credentials (only on first install) ---
if [ ! -f /etc/wgmgr/config.json ]; then
  say "first-time init (generates API token + random admin password)…"
  "${PREFIX}/wgmgr" init
fi

# --- import existing peers into the DB, then take ownership of the peer section ---
if grep -q '\[Peer\]' "/etc/wireguard/${IFACE}.conf" 2>/dev/null; then
  say "importing existing peers…"
  "${PREFIX}/wgmgr" import || true
fi
"${PREFIX}/wgmgr" render || true

# --- systemd service ---
say "installing systemd service…"
cat > /etc/systemd/system/wgmgr.service <<UNIT
[Unit]
Description=wgmgr (WireGuard user/quota manager + enforcement)
After=wg-quick@${IFACE}.service network-online.target
Wants=wg-quick@${IFACE}.service

[Service]
Type=simple
ExecStart=${PREFIX}/wgmgr serve
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now wgmgr.service

IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
say "done ✅"
say "Panel:  https://${IP}:8443   (login = admin / the password printed above)"
say "API:    token in /etc/wgmgr/config.json  ·  docs: https://github.com/${REPO}/blob/main/docs/API.md"
say "CLI:    wgmgr list | add <user> --quota-gb N --days D | set-login <user> <pass>"
