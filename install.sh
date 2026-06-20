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

# Bootstrap a fresh native WireGuard server (only when none exists). Produces the
# /etc/wireguard/{params,wg0.conf} format wgmgr expects. Override via WG_PORT/WG_SUBNET/WG_DNS1/WG_DNS2.
bootstrap_wireguard(){
  say "no WireGuard found — setting up a fresh native WireGuard server…"
  local port="${WG_PORT:-51820}" subnet="${WG_SUBNET:-10.66.66.0/24}"
  local dns1="${WG_DNS1:-1.1.1.1}" dns2="${WG_DNS2:-1.0.0.1}"
  local nic; nic="$(ip -4 route ls default 2>/dev/null | awk '{print $5; exit}')"
  [ -n "$nic" ] || { err "could not detect the default network interface"; exit 1; }
  local pubip; pubip="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$pubip" ] || pubip="$(ip -4 addr show "$nic" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  local priv pub; priv="$(wg genkey)"; pub="$(printf '%s' "$priv" | wg pubkey)"
  local cidr="${subnet##*/}" srvip="${subnet%.*}.1"
  umask 077; mkdir -p /etc/wireguard
  cat > /etc/wireguard/params <<P
SERVER_PUB_IP=${pubip}
SERVER_PUB_NIC=${nic}
SERVER_WG_NIC=${IFACE}
SERVER_WG_IPV4=${srvip}
SERVER_PORT=${port}
SERVER_PRIV_KEY=${priv}
SERVER_PUB_KEY=${pub}
CLIENT_DNS_1=${dns1}
CLIENT_DNS_2=${dns2}
ALLOWED_IPS=0.0.0.0/0
P
  cat > "/etc/wireguard/${IFACE}.conf" <<C
[Interface]
Address = ${srvip}/${cidr}
ListenPort = ${port}
PrivateKey = ${priv}
PostUp = iptables -I INPUT -p udp --dport ${port} -j ACCEPT
PostUp = iptables -I FORWARD -i ${nic} -o ${IFACE} -j ACCEPT
PostUp = iptables -I FORWARD -i ${IFACE} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${nic} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${port} -j ACCEPT
PostDown = iptables -D FORWARD -i ${nic} -o ${IFACE} -j ACCEPT
PostDown = iptables -D FORWARD -i ${IFACE} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${nic} -j MASQUERADE
C
  chmod 600 "/etc/wireguard/${IFACE}.conf" /etc/wireguard/params
  echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wg-forward.conf
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  systemctl enable --now "wg-quick@${IFACE}" >/dev/null 2>&1
  say "WireGuard up: ${IFACE} udp/${port}, subnet ${subnet}, egress ${nic}, public ${pubip}"
}

# Optional: add OpenVPN alongside WireGuard (set INSTALL_OVPN=1). Users then get a single
# COMBINED quota across both protocols via `wgmgr ovpn-add <user>`. Overrides: OVPN_PORT /
# OVPN_PROTO / OVPN_SUBNET / OVPN_ENDPOINT. (Generated here; validate on a real server.)
bootstrap_openvpn(){
  [ "${INSTALL_OVPN:-0}" = "1" ] || return 0
  command -v openvpn >/dev/null 2>&1 || { err "openvpn not installed; skipping OVPN setup"; return 0; }
  say "setting up OpenVPN (combined-quota with WireGuard)…"
  local nic; nic="$(ip -4 route ls default 2>/dev/null | awk '{print $5; exit}')"
  local subnet="${OVPN_SUBNET:-10.8.0.0/24}"
  mkdir -p /run/wgmgr
  printf 'd /run/wgmgr 0755 root root -\n' > /etc/tmpfiles.d/wgmgr.conf
  "${PREFIX}/wgmgr" ovpn-init ${OVPN_PORT:+--port "$OVPN_PORT"} ${OVPN_PROTO:+--proto "$OVPN_PROTO"} \
    ${OVPN_SUBNET:+--subnet "$OVPN_SUBNET"} ${OVPN_ENDPOINT:+--endpoint "$OVPN_ENDPOINT"} \
    || { err "wgmgr ovpn-init failed; skipping"; return 0; }
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  # NAT + forward for the OVPN subnet. APPEND (-A) the ACCEPTs so they sit BELOW wgmgr's
  # position-1 ipset DROP rule — a blocked user must be dropped before being accepted.
  iptables -t nat -C POSTROUTING -s "$subnet" -o "$nic" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$subnet" -o "$nic" -j MASQUERADE
  iptables -C FORWARD -s "$subnet" -j ACCEPT 2>/dev/null || iptables -A FORWARD -s "$subnet" -j ACCEPT
  iptables -C FORWARD -d "$subnet" -j ACCEPT 2>/dev/null || iptables -A FORWARD -d "$subnet" -j ACCEPT
  ( netfilter-persistent save || iptables-save > /etc/iptables/rules.v4 ) >/dev/null 2>&1 \
    || say "note: persist iptables yourself so the OVPN NAT survives reboot"
  # Ubuntu's canonical unit is openvpn-server@server (reads /etc/openvpn/server/server.conf);
  # fall back to the legacy openvpn@server (reads /etc/openvpn/server.conf). Verified on 22.04.
  mkdir -p /etc/openvpn/server
  cp -f /etc/openvpn/server.conf /etc/openvpn/server/server.conf
  if systemctl enable --now openvpn-server@server 2>/dev/null && systemctl is-active --quiet openvpn-server@server; then
    say "OpenVPN service: openvpn-server@server"
  else
    systemctl enable --now openvpn@server >/dev/null 2>&1 || true
    say "OpenVPN service: openvpn@server (legacy)"
  fi
  systemctl restart wgmgr.service >/dev/null 2>&1 || true  # reload config so the enforce loop reads ovpn_mgmt
  say "OpenVPN up: proto $(awk '/^proto/{print $2}' /etc/openvpn/server.conf) port $(awk '/^port/{print $2}' /etc/openvpn/server.conf) subnet ${subnet}"
}

[ "$(id -u)" = 0 ] || { err "please run as root"; exit 1; }

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64;;
  aarch64|arm64) ARCH=arm64;;
  *) err "unsupported arch: $(uname -m)"; exit 1;;
esac

# --- interactive selection: ask which VPN(s) + which ports when run by hand on a terminal.
# Skipped entirely for automation (no tty, or the choice pre-set via env vars), so piped/cron
# installs stay non-interactive. Works through `curl | bash` because we read from /dev/tty.
if [ -r /dev/tty ] && [ -z "${INSTALL_OVPN+x}" ] && [ -z "${INSTALL_WG+x}" ]; then
  printf '\nWhich VPN(s) to install?\n  1) WireGuard only (default)\n  2) OpenVPN only\n  3) Both WireGuard + OpenVPN\nchoice [1]: ' > /dev/tty
  read -r _c < /dev/tty || _c=1
  case "$_c" in
    2) INSTALL_WG=0; INSTALL_OVPN=1 ;;
    3) INSTALL_OVPN=1 ;;
    *) : ;;   # 1 / empty -> WireGuard only
  esac
  if [ "${INSTALL_WG:-1}" != "0" ] && [ -z "${WG_PORT+x}" ]; then
    printf 'WireGuard UDP port [51820]: ' > /dev/tty; read -r _p < /dev/tty || _p=""
    if [ -n "$_p" ]; then WG_PORT="$_p"; fi
  fi
  if [ "${INSTALL_OVPN:-0}" = "1" ] && [ -z "${OVPN_PORT+x}" ]; then
    printf 'OpenVPN UDP port [1194]: ' > /dev/tty; read -r _p < /dev/tty || _p=""
    if [ -n "$_p" ]; then OVPN_PORT="$_p"; fi
  fi
fi

# OpenVPN-only install (INSTALL_WG=0) implies OpenVPN.
[ "${INSTALL_WG:-1}" = "0" ] && INSTALL_OVPN=1

OVPN_PKG=""
[ "${INSTALL_OVPN:-0}" = "1" ] && OVPN_PKG="openvpn"
say "installing dependencies (ipset, wireguard-tools${OVPN_PKG:+, openvpn})…"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ipset wireguard-tools curl $OVPN_PKG >/dev/null 2>&1 || true
fi
command -v wg >/dev/null 2>&1 || { err "wireguard-tools (wg) not found — set up WireGuard first."; exit 1; }

if [ "${INSTALL_WG:-1}" != "0" ] && { [ ! -f "/etc/wireguard/${IFACE}.conf" ] || [ ! -f /etc/wireguard/params ]; }; then
  bootstrap_wireguard
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
  if [ "${INSTALL_WG:-1}" = "0" ]; then
    say "first-time init (OpenVPN-only — no WireGuard)…"
    "${PREFIX}/wgmgr" init --ovpn-only
  else
    say "first-time init (generates API token + random admin password)…"
    "${PREFIX}/wgmgr" init
  fi
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

bootstrap_openvpn

IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
# secret web base path the panel/API are served under (empty when upgrading a pre-base-path install)
BASE="$(sed -n 's/.*"base_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/wgmgr/config.json 2>/dev/null)"
say "done ✅"
say "Panel:  https://${IP}:8443${BASE}/   (login = admin / the password printed above)"
say "API:    base https://${IP}:8443${BASE}  ·  token in /etc/wgmgr/config.json  ·  docs: https://github.com/${REPO}/blob/main/docs/API.md"
say "CLI:    wgmgr list | add <user> --quota-gb N --days D | set-login <user> <pass> | set-base-path </p>"
[ "${INSTALL_OVPN:-0}" = "1" ] && say "OpenVPN: wgmgr ovpn-add <user> → profile: wgmgr ovpn-config <user>  (counts toward the SAME quota as WireGuard)"
