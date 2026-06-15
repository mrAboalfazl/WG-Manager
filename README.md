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
- **A fresh server is fine** — the installer sets up native WireGuard automatically if none exists
  (override defaults with `WG_PORT`, `WG_SUBNET`, `WG_DNS1`, `WG_DNS2`).
- If you **already run native WireGuard** (e.g. [`angristan/wireguard-install`](https://github.com/angristan/wireguard-install)),
  it's detected and used as-is. `ipset` / `wireguard-tools` are installed automatically.

## Install / update
```bash
curl -fsSL https://raw.githubusercontent.com/mrAboalfazl/WG-Manager/main/install.sh | bash
```
It installs deps, **sets up native WireGuard if none exists**, drops the `wgmgr` binary, imports any
existing peers, generates an API token + a **random admin password** (printed once), and starts the
service. Re-run anytime to update. Customize the WireGuard bootstrap, e.g.:
```bash
curl -fsSL https://raw.githubusercontent.com/mrAboalfazl/WG-Manager/main/install.sh | WG_PORT=51820 WG_SUBNET=10.8.0.0/24 bash
```

After install:
- **Panel:** served on a **secret web path** printed at the end of install, e.g.
  `https://<server-ip>:8443/<path>/` (the bare `https://<server-ip>:8443/` returns 404 — the panel is
  hidden from scanners). Log in as `admin` / the printed password (self-signed cert → accept the browser
  warning). Change the password from the panel's **⚙ Settings** or `wgmgr set-login <user> <pass>`;
  change the path with `wgmgr set-base-path </p>` (use `/` to serve at the root, the old behavior).
- **API token:** view or **regenerate** it from the panel's **⚙ Settings**, or read it on the server
  in `/etc/wgmgr/config.json` (`api_token`). Regenerating invalidates the old token immediately — update
  any backend that uses it.

## CLI
```
wgmgr add <user> [--quota-gb N] [--days D]   # create (prints client config)
wgmgr list | show <user> | config <user>     # view / re-emit config
wgmgr set-quota <user> <GB>
wgmgr recharge <user> [--reset] [--add-gb N] [--set-gb N]
wgmgr renew <user> <days>                     # extend time
wgmgr enable|disable|rm <user>
wgmgr set-login <user> <pass>                 # panel/admin credentials
wgmgr set-base-path </path|/>                 # serve the panel/API under a secret web path (/ = root)
wgmgr import                                  # import peers from wg0.conf into the DB
wgmgr render                                  # rewrite wg0.conf peer section from DB + apply
wgmgr serve                                   # daemon: enforcement loop + HTTPS API (systemd)
```

## API
HTTPS + bearer token on `:8443`, under the **same secret web base path as the panel** (e.g.
`https://<ip>:8443/<path>/peers`). The path is printed at install and stored as `base_path` in
`/etc/wgmgr/config.json`. Full reference, payloads, examples, and a backend integration recipe:
**[`docs/API.md`](docs/API.md)**.

## How it works (brief)
- SQLite (`/var/lib/wgmgr/wgmgr.db`) is the source of truth → renders the `[Peer]` section of
  `wg0.conf` (the `[Interface]` block is preserved verbatim) and applies it with `wg syncconf`.
- A daemon enforces every ~3 min: updates cumulative usage from `wg show transfer` and syncs an
  `ipset` of peers that are over-quota / expired / disabled (a `FORWARD` drop rule blocks their data).
- The web panel + API are served by the same binary on `:8443` (self-signed TLS).

## Security notes
- The API token is **full admin** — keep it secret; restrict `:8443` to trusted IPs if possible.
- The panel/API are served under a random **secret web path** (`base_path`) and the bare root 404s —
  defense-in-depth on top of the token/login, not a replacement for them.
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
