# WG-Manager (`wgmgr`)

A small, single-binary manager that adds **user management, traffic quotas, time/renewals,
a REST API, and a web panel** on top of a **native (kernel) WireGuard** server — without
Docker and without replacing or destabilizing WireGuard itself.

It was built for reliability: the kernel data plane is never touched the wrong way. The DB is
the source of truth and changes are applied with `wg syncconf` (the tunnel is never bounced),
and quota/expiry are enforced by blocking a peer's **data** via an `ipset` firewall drop — the
handshake stays up, other users are unaffected, and a renewed/recharged user reconnects with
their **existing config** (no re-issue).

## Features
- 👤 **Users**: create / delete / list, auto keypair + IP allocation, client config + QR.
- 📊 **Quotas**: per-user data caps (GB), cumulative usage that survives reboots.
- ⏱ **Time**: expiry dates, renew/extend (keeps the same config).
- 🔁 **Recharge**: reset usage, top-up or set quota.
- ⛔ **Enforcement**: auto-block on quota/expiry/disable via `ipset` (no disconnect of others).
- 🌐 **Web panel**: dark dashboard (stats, usage bars, online/blocked, add/recharge/renew/QR).
- 🔌 **REST API** (HTTPS + token) for website/backend integration — see [`docs/API.md`](docs/API.md).
- 🖥 **CLI** for SSH admin.
- Single static Go binary + one systemd service. No Docker, no Node, no external runtime.

## Requirements
- Linux (Ubuntu/Debian tested), root.
- An existing **native WireGuard** install with `/etc/wireguard/wg0.conf` + `/etc/wireguard/params`
  (e.g. the popular [`angristan/wireguard-install`](https://github.com/angristan/wireguard-install)).
- `ipset`, `wireguard-tools` (the installer adds these).

## Install / update
```bash
curl -fsSL https://raw.githubusercontent.com/mrAboalfazl/WG-Manager/main/install.sh | bash
```
It installs deps, drops the `wgmgr` binary, imports any existing peers, generates an API token +
a **random admin password** (printed once), and starts the service. Re-run anytime to update.

After install:
- **Panel:** `https://<server-ip>:8443` — log in as `admin` / the printed password (self-signed
  cert → accept the browser warning). Change it: `wgmgr set-login <user> <pass>`.
- **API token:** in `/etc/wgmgr/config.json`.

## CLI
```
wgmgr add <user> [--quota-gb N] [--days D]   # create (prints client config)
wgmgr list | show <user> | config <user>     # view / re-emit config
wgmgr set-quota <user> <GB>
wgmgr recharge <user> [--reset] [--add-gb N] [--set-gb N]
wgmgr renew <user> <days>                     # extend time
wgmgr enable|disable|rm <user>
wgmgr set-login <user> <pass>                 # panel/admin credentials
wgmgr import                                  # import peers from wg0.conf into the DB
wgmgr render                                  # rewrite wg0.conf peer section from DB + apply
wgmgr serve                                   # daemon: enforcement loop + HTTPS API (systemd)
```

## API
HTTPS + bearer token on `:8443`. Full reference, payloads, examples, and a backend integration
recipe: **[`docs/API.md`](docs/API.md)**.

## How it works (brief)
- SQLite (`/var/lib/wgmgr/wgmgr.db`) is the source of truth → renders the `[Peer]` section of
  `wg0.conf` (the `[Interface]` block is preserved verbatim) and applies it with `wg syncconf`.
- A daemon enforces every ~3 min: updates cumulative usage from `wg show transfer` and syncs an
  `ipset` of peers that are over-quota / expired / disabled (a `FORWARD` drop rule blocks their data).
- The web panel + API are served by the same binary on `:8443` (self-signed TLS).

## Security notes
- The API token is **full admin** — keep it secret; restrict `:8443` to trusted IPs if possible.
- Quota enforcement is **poll-based** (~3 min), so it's near-real-time, not byte-exact.
- The panel/API use a self-signed cert by default; put it behind a real cert/reverse-proxy for
  public use, or pin the cert in your backend.

## Build from source
```bash
git clone https://github.com/mrAboalfazl/WG-Manager.git && cd WG-Manager
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o wgmgr .
```
(Go 1.23+. Pure-Go deps — cross-compiles to a static binary.)

## License
MIT — see [LICENSE](LICENSE).
