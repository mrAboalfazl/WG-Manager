# wgmgr — REST API

HTTPS + bearer-token API for managing WireGuard users, quotas, time, and usage. Served by the
`wgmgr` daemon on `:8443` (same binary as the web panel). Designed to be driven by a website
backend.

## Connection
| | |
|---|---|
| Base URL | `https://<SERVER_IP>:8443` |
| Auth | header `Authorization: Bearer <API_TOKEN>`  (or `X-API-Token: <API_TOKEN>`) |
| Token | in `/etc/wgmgr/config.json` on the server (`api_token`) |
| TLS | self-signed by default — pin the cert in your backend, or skip verification for testing |

> **Call from your backend, not from browser JS** (no CORS headers are sent). The token is
> full admin — keep it secret; restrict `:8443` to trusted IPs where possible.

Get the token / cert on the server:
```bash
python3 -c "import json;print(json.load(open('/etc/wgmgr/config.json'))['api_token'])"
openssl x509 -in /etc/wgmgr/cert.pem -noout -fingerprint -sha256   # to pin
```

## Peer object
```json
{
  "username": "alice", "address": "10.66.66.5", "public_key": "….=",
  "used_bytes": 1234567, "used_gb": 0.0011,
  "quota_bytes": 53687091200, "quota_gb": 50,      // 0 = unlimited
  "expires_at": "2026-07-02T00:00:00Z",            // "" = never
  "enabled": true, "blocked": false,
  "online": true, "last_handshake": 1780320000     // epoch, 0 = never
}
```

## Endpoints (auth required unless marked public)
```
GET    /healthz                          (public) -> "ok"
POST   /login            (public)  {username, password}  -> { token }
GET    /peers                      -> { peers: [ <peer>, … ], server: "<ip>" }
POST   /peers                      {username, quota_gb?, days?}
                                   -> 201 { <peer>, client_config: "<.conf text>" }
GET    /peers/{name}               -> <peer>
DELETE /peers/{name}               -> { deleted: "name" }
GET    /peers/{name}/config        -> text/plain  (client .conf)
GET    /peers/{name}/qr            -> image/png   (QR of the config)
POST   /peers/{name}/recharge      {reset?: bool, set_gb?: num, add_gb?: num} -> <peer>
POST   /peers/{name}/renew         {add_days?: num | days?: num | expires_at?: "RFC3339"} -> <peer>
POST   /peers/{name}/quota         {quota_gb: num} -> <peer>
POST   /peers/{name}/enable                        -> <peer>
POST   /peers/{name}/disable                       -> <peer>
```
Errors: HTTP 4xx with `{"error":"…"}`; unauthorized → `401 {"error":"unauthorized"}`.

- `renew`: `add_days` extends from the current expiry (doesn't lose unused days, preferred);
  `days` sets N days from now (`days:0` = never); `expires_at` sets an exact date.
- After `renew`/`recharge`/`enable`, the user is unblocked on the next enforce tick (≤3 min) and
  their **existing config reconnects automatically — no re-issue**.

## Feature → endpoint
| Feature | Call |
|---|---|
| Create user | `POST /peers {username, quota_gb, days}` → store `public_key`, give `client_config`/QR |
| Recharge data | `POST /peers/{n}/recharge {"reset":true}` / `{"add_gb":N}` / `{"set_gb":N}` |
| Renew time | `POST /peers/{n}/renew {"add_days":30}` |
| View usage | `GET /peers` or `GET /peers/{n}` |
| Suspend / resume | `POST /peers/{n}/disable` · `/enable` |
| Delete | `DELETE /peers/{n}` |
| Re-download config | `GET /peers/{n}/config` or `/qr` |

## Example
```bash
TOKEN=…                          # from /etc/wgmgr/config.json
B=https://<SERVER_IP>:8443; H="Authorization: Bearer $TOKEN"
curl -sk -H "$H" -H 'Content-Type: application/json' -d '{"username":"alice","quota_gb":50,"days":30}' $B/peers
curl -sk -H "$H" $B/peers/alice
curl -sk -H "$H" -d '{"add_days":30}' $B/peers/alice/renew
curl -sk -H "$H" -d '{"reset":true}'  $B/peers/alice/recharge
curl -sk -H "$H" -X DELETE $B/peers/alice
```
(`-k` skips verification for testing; pin the cert in production.)

## Integration recipe
Your app's DB owns `your_user_id → { username, public_key }` (wgmgr only manages WireGuard peers).
On signup → `POST /peers` (store `public_key`, deliver config). On renewal → `renew {add_days}`
(+ `recharge {reset:true}` if the plan resets data). On top-up → `recharge {add_gb}`. Show usage
from `GET /peers/{n}`. Suspend non-payers with `disable`; cancel with `DELETE`.
