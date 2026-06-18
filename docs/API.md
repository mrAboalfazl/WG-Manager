# wgmgr — Backend Integration / REST API

HTTPS + bearer-token API for managing **WireGuard and OpenVPN** users, quotas, time, and usage.
Served by the `wgmgr` daemon on `:8443` (same binary as the web panel). Designed to be driven by a
website/backend, not a browser.

Each **user** can have a WireGuard identity, an OpenVPN identity, or **both**, and has **one shared
quota** — WG + OVPN usage are summed and the user is blocked on both when the combined total exceeds
the cap.

> ### ⚠️ Two things that changed and will break old integrations
> 1. **Every request now goes under a secret base path** (`https://IP:8443/<base_path>/…`), not the bare
>    root. The bare root returns `404`. See **Base URL** below.
> 2. **The API token can be rotated** from the panel/API — if someone regenerates it, your stored token
>    stops working immediately and must be updated.

---

## Connection

| | |
|---|---|
| **Base URL** | `https://<SERVER_IP>:8443<base_path>` — `base_path` is the **secret web path** stored in `/etc/wgmgr/config.json` (`"base_path"`) and printed at install. e.g. `https://1.2.3.4:8443/a1b2c3`. Hitting the bare root 404s. (Empty `base_path` = served at root — only on legacy installs.) |
| **Auth** | header `Authorization: Bearer <API_TOKEN>` (or `X-API-Token: <API_TOKEN>`) on every call except `/healthz` and `/login` |
| **Token** | `"api_token"` in `/etc/wgmgr/config.json`; also viewable/rotatable from the panel ⚙ Settings or `GET/POST /api-token*`. Rotating **invalidates the old token immediately**. |
| **TLS** | self-signed by default — pin the cert in your backend, or skip verification (`-k`) for testing |
| **Content-Type** | send `application/json` for POSTs with a body |

Get the base path, token, and cert fingerprint on the server:
```bash
python3 -c "import json;c=json.load(open('/etc/wgmgr/config.json'));print('base_path=',c.get('base_path',''));print('token=',c['api_token'])"
openssl x509 -in /etc/wgmgr/cert.pem -noout -fingerprint -sha256   # to pin in your backend
```

> Call from your backend, not browser JS (no CORS headers are sent). The token is **full admin** —
> keep it secret; restrict `:8443` to trusted IPs where you can.

---

## User object

`GET /peers` and `GET /peers/{name}` return this. (`online` / `last_handshake` are only present in
those two list/show calls — they reflect the WireGuard handshake.)

```jsonc
{
  "username": "alice",
  "address":  "10.66.66.5",          // WireGuard tunnel IP ("" if user has no WG identity)
  "public_key": "….=",               // WireGuard public key

  "used_bytes":  1234567,            // WireGuard usage
  "used_gb":     0.0011,
  "used_ovpn_bytes": 987654,         // OpenVPN usage
  "used_ovpn_gb":    0.0009,
  "used_total_bytes": 2222221,       // WG + OVPN  ← THIS is what the quota measures
  "used_total_gb":    0.0020,

  "quota_bytes": 53687091200,        // 0 = unlimited. ONE cap across both protocols.
  "quota_gb":    50,
  "expires_at":  "2026-07-02T00:00:00Z",  // "" = never

  "enabled":  true,                  // admin on/off switch
  "blocked":  false,                 // currently cut off (over quota / expired / disabled)

  "has_ovpn":     true,              // user has an OpenVPN identity
  "ovpn_enabled": true,
  "ovpn_ip":      "10.8.0.2",        // OpenVPN tunnel IP (static)

  "online": true,                    // WireGuard handshake within ~3 min (list/show only)
  "last_handshake": 1780320000       // epoch, 0 = never (list/show only)
}
```

To show usage in your UI, use **`used_total_gb` / `quota_gb`** (the combined number). `used_gb` and
`used_ovpn_gb` are the per-protocol breakdown.

---

## Endpoints (auth required unless marked public; all under the base path)

```
GET    /healthz                       (public) -> "ok"
POST   /login          (public)  {username,password} -> { token }   # token == the API token
POST   /change-password          {current_password,new_password} -> { ok:true }
GET    /api-token                -> { token }              # view the API token
POST   /api-token/regenerate     -> { token }              # rotate (old token dies immediately)

# Users
GET    /peers                    -> { peers:[<user>,…], server:"<ip>" }
POST   /peers                    {username, quota_gb?, days?, ovpn_only?:bool}
                                 -> 201 { <user>, client_config:"<WireGuard .conf | .ovpn>" }
                                 #  ovpn_only:true -> user with NO WireGuard; client_config is the .ovpn
GET    /peers/{name}             -> <user>
DELETE /peers/{name}             -> { deleted:"name" }
POST   /peers/{name}/quota       {quota_gb}                       -> <user>   # set the shared cap
POST   /peers/{name}/recharge    {reset?:bool, set_gb?:num, add_gb?:num} -> <user>
POST   /peers/{name}/renew       {add_days?:num | days?:num | expires_at?:"RFC3339"} -> <user>
POST   /peers/{name}/enable                                       -> <user>
POST   /peers/{name}/disable                                      -> <user>

# WireGuard config files (generated server-side)
GET    /peers/{name}/config      -> text/plain  (WireGuard .conf)
GET    /peers/{name}/qr          -> image/png   (QR of the WireGuard .conf)

# OpenVPN  (usage counts toward the SAME quota as WireGuard)
POST   /peers/{name}/ovpn        -> 201 { ovpn_ip, client_config:"<.ovpn text>" }  # attach OVPN identity
GET    /peers/{name}/ovpn-config -> text/plain  (.ovpn)
DELETE /peers/{name}/ovpn        -> { ok:true }                                    # detach OVPN identity
```

Errors: HTTP 4xx with `{"error":"…"}`; missing/bad token → `401 {"error":"unauthorized"}`.
`POST /peers/{name}/ovpn` returns `400 {"error":"OpenVPN is not set up on this server yet …"}` if the
server hasn't been `ovpn-init`'d.

- **renew**: `add_days` extends from the *current* expiry (keeps unused days — preferred); `days` sets
  N days from now (`days:0` = never); `expires_at` sets an exact date.
- After `renew` / `recharge` / `enable`, the user is unblocked on the next enforce tick (≤3 min) and
  their **existing config reconnects automatically — no re-issue needed** (same for WG and OVPN).

---

## Creating a user and getting their config files

The backend never writes config files itself — it **asks the API to generate them** and stores/serves
the returned text.

**1. Create the user (WireGuard).** Keys + IP are allocated server-side; the `.conf` comes back in the response:
```bash
curl -sk -H "$H" -H 'Content-Type: application/json' \
     -d '{"username":"alice","quota_gb":50,"days":30}' \
     "$B/peers"
# -> 201 { "username":"alice", ..., "client_config":"[Interface]\nPrivateKey=…\n[Peer]\n…" }
```
Save `client_config` as `alice.conf` (or render the QR via `GET $B/peers/alice/qr`).

**2. Add OpenVPN to that same user (optional).** Mints a client cert + static IP and returns the `.ovpn`:
```bash
curl -sk -H "$H" -X POST "$B/peers/alice/ovpn"
# -> 201 { "ovpn_ip":"10.8.0.2", "client_config":"client\ndev tun\nremote … 1194\n<ca>…</ca>…" }
```
Save `client_config` as `alice.ovpn`. The user's OpenVPN traffic now counts toward the same `quota_gb`.

**3. Re-fetch configs anytime** (e.g. user lost the file): `GET $B/peers/alice/config` (WG) or
`GET $B/peers/alice/ovpn-config` (OVPN). These don't change unless you delete/re-add the identity, so
renewing or recharging never forces a re-download.

> The server must have OpenVPN initialized once (`wgmgr ovpn-init`, or the installer with
> `INSTALL_OVPN=1`) before step 2 works. WireGuard-only users skip step 2 entirely.

**OpenVPN-only user (no WireGuard):** `POST /peers {"username":"bob","quota_gb":50,"ovpn_only":true}`
creates the user with no WG identity and returns the `.ovpn` directly in `client_config` (one step).
This is what you use on an **OpenVPN-only server** (installed with `INSTALL_WG=0`), where regular
`POST /peers` has no WireGuard to allocate.

---

## Feature → call

| Feature | Call |
|---|---|
| Create user (WG) | `POST /peers {username, quota_gb, days}` → store username, give `client_config`/QR |
| Add OpenVPN to a user | `POST /peers/{n}/ovpn` → give the returned `.ovpn` |
| Remove OpenVPN | `DELETE /peers/{n}/ovpn` |
| Set the (shared) quota | `POST /peers/{n}/quota {"quota_gb":50}` |
| Recharge data | `POST /peers/{n}/recharge {"reset":true}` / `{"add_gb":N}` / `{"set_gb":N}` |
| Renew time | `POST /peers/{n}/renew {"add_days":30}` |
| View combined usage | `GET /peers` or `GET /peers/{n}` → `used_total_gb` |
| Suspend / resume | `POST /peers/{n}/disable` · `/enable` |
| Delete user | `DELETE /peers/{n}` (removes WG **and** OVPN) |
| Re-download config | `GET /peers/{n}/config` · `/qr` · `/ovpn-config` |

---

## Worked example

```bash
TOKEN=…                                   # from /etc/wgmgr/config.json  ("api_token")
BASE=/a1b2c3                              # from /etc/wgmgr/config.json  ("base_path")  ← REQUIRED
B="https://<SERVER_IP>:8443${BASE}"
H="Authorization: Bearer $TOKEN"

curl -sk -H "$H" -H 'Content-Type: application/json' -d '{"username":"alice","quota_gb":50,"days":30}' "$B/peers"
curl -sk -H "$H" -X POST "$B/peers/alice/ovpn"        # add OpenVPN, get .ovpn
curl -sk -H "$H" "$B/peers/alice"                     # usage: used_total_gb / quota_gb
curl -sk -H "$H" -d '{"add_days":30}' "$B/peers/alice/renew"
curl -sk -H "$H" -d '{"reset":true}'  "$B/peers/alice/recharge"
curl -sk -H "$H" -X DELETE "$B/peers/alice"
```
(`-k` skips TLS verification for testing; pin the cert in production.)

---

## Integration recipe

Your app's DB owns `your_user_id → { username }`; wgmgr owns the VPN identities and the shared quota.

- **Signup:** `POST /peers` → store the username, deliver the WireGuard config. If the plan includes
  OpenVPN, also `POST /peers/{n}/ovpn` and deliver the `.ovpn`.
- **Top-up data:** `POST /peers/{n}/recharge {"add_gb":N}` (or `{"reset":true}` to reset usage).
- **Renew:** `POST /peers/{n}/renew {"add_days":30}` (configs keep working — no re-download).
- **Show usage:** `GET /peers/{n}` → `used_total_gb` vs `quota_gb` (and the `used_gb` / `used_ovpn_gb`
  split if you want to show per-protocol).
- **Suspend non-payers:** `disable`; **cancel:** `DELETE`.

**Store the base path and token in your backend config** (e.g. `WGMGR_URL=https://IP:8443/<base_path>`,
`WGMGR_TOKEN=…`) and treat both as rotatable — if the admin changes the secret path or regenerates the
token from the panel, update them on your side.
