# Security Review — Controller ⇄ SLEP ⇄ Connect

Scope: how the three Sysible services **authenticate to and interact with each
other**, and the trust boundaries between them. This is an interaction-surface
review, not a full per-service audit. Findings are ranked; the ones marked
**(fixed)** were addressed in the same change that added this document.

## 1. The trust map

```
 Browser ──cookie(HTTPS)──▶ Connect ──X-API-Key(HTTPS,TOFU)──▶ Controller ──agent/SSH──▶ hosts
 Browser ──cookie(HTTPS)──▶ SLEP    ──X-API-Key(HTTPS,TOFU)──▶ Controller
 SLEP ──SSH(managed key, via jump host)──▶ provisioned VMs ──agent self-enroll──▶ Controller
 Agent ──enroll-token(one-time) then agent_secret──▶ Controller  (outbound only)
```

| Edge | Auth | Transport | Notes |
|---|---|---|---|
| Browser → any console | signed http-only session cookie | HTTPS | first-run admin; per-service |
| SLEP → Controller | machine **API key** (`X-API-Key`) | HTTPS + **TOFU** cert pin | `/remote/hosts`, `/agents`, `/remote/agent-bundle`, `/remote/controller-key` |
| Connect → Controller | machine **API key** (`X-API-Key`) | HTTPS + **TOFU** cert pin | `/remote/hosts`, `/agents`, `/remote/hosts/{n}/terminal/*` |
| Controller → agent host | `agent_secret` bound to `host_id` | agent-initiated **outbound** poll | no inbound SSH needed |
| Controller → SSH host | controller-owned SSH key | SSH | key installed at enroll |
| Agent enroll | **single-use** enroll token | HTTPS | leaked bundle can't enroll twice |
| SLEP → VM | SLEP managed SSH key (± jump host) | SSH | key baked via cloud-init |

## 2. What's solid

- **No standing inbound to hosts.** Agent hosts are driven over their own outbound
  channel; the terminal proxy rides that same channel. NAT'd, inbound-firewalled
  hosts never expose SSH.
- **Single-use enrollment tokens** — a captured agent bundle can't silently enroll
  a second host, and a force-deleted agent's secret is invalidated on next heartbeat.
- **TLS trust-on-first-use with pinning** on both SLEP→Controller and
  Connect→Controller: after first contact a rotated/forged cert is rejected, so
  the machine key isn't replayed to an impostor.
- **Injection surfaces are closed**: SLEP's salt roster builds a concrete, quoted
  `ProxyCommand`; SSH host fields are charset-validated on ingest in both SLEP and
  Connect; Connect's SSH sessions use paramiko (host/user/port as separate params —
  no shell argv), and now **pin host keys** (a changed key is rejected).
- **Console API keys never reach the browser** — every console is a BFF; the key
  stays server-side, the browser holds only the session cookie.
- **Run-as identity** (Controller): actions execute as the acting admin's OS
  account, derived from the signed login token, not anything the client sends.

## 3. Findings

### F1 — Connect's Controller API key concentrates authority · **High**
Connect proxies terminals with the Controller **machine API key and no admin
token**. The Controller's `_check_terminal_owner` treats a token-less call as
trusted (the API key *is* the boundary there), so **whoever can sign into Connect
can open a shell on any host that key can reach**. If Connect holds a full,
unscoped machine key, a single Connect admin ≈ Controller superuser for terminals.
- **Mitigation**: issue Connect a **scoped/least-privilege** machine API key
  (environment-scoped where Enterprise supports it), not the root key. Treat the
  Connect admin credential as equivalent in blast radius to that key. Consider a
  Controller-side capability that marks a key "terminal-only" / environment-bounded.
- **Follow-up**: have Connect forward an operator identity so the Controller's
  owner-binding and audit trail attribute the session to a person, not just "the
  Connect key". (Requires a Controller-side accepted identity header bound to the key.)

### F2 — Controller API key stored in plaintext at rest (Connect) · **Medium** · **(fixed)**
The key was written to `~/.sysible-connect/controller.json` mode `0600` — plaintext
on disk (backups, snapshots, an attacker with that uid). Now the key is **encrypted
at rest** (`backend/secret.py`, Fernet) under a per-install `secret.key` (0600); the
config stores `api_key_enc` and the plaintext key exists only in memory. A legacy
plaintext key is tolerated and re-encrypted on next save.

### F3 — Session cookie missing `Secure` under HTTPS · **Medium** · **(fixed)**
The Connect session cookie was `HttpOnly; SameSite=Lax` but not `Secure`, so on a
mixed or downgraded connection it could ride over plain HTTP. Now that Connect
serves HTTPS by default, the cookie is set `Secure` when the request is HTTPS.

### F4 — Weak default admin credentials (Connect) · **Medium** · **(fixed)**
`admin` / `admin` was seeded when `SYSIBLE_CONNECT_PASSWORD` was unset. Now, when
no password is provided, a random one is generated and printed once to the logs and
the account is flagged **must-change**, so there is no standing default login.

### F5 — No SSRF guard on Connect's Controller URL · **Low** · **(fixed)**
A Connect admin could point the Controller URL at an internal service; the TOFU
cert fetch + API calls would dial it. Connect is single-admin (low blast radius),
but SLEP already SSRF-guards its Controller URL (blocks loopback/link-local/
metadata). Connect now applies the same guard for parity.

### F6 — First-contact TOFU window · **Low / accepted**
Trust-on-first-use means the *very first* SLEP→Controller or Connect→Controller
call trusts whatever cert is presented; a MITM present at that instant could pin
itself. Acceptable for a LAN control plane and strictly better than blanket
`verify=false`, but for high-assurance installs pin the Controller CA out-of-band
(`SLEP_CONTROLLER_CA`, or ship the cert) instead of relying on first-use.

### F7 — Connect binds `0.0.0.0` by default · **Low / operational**
Reachable on every interface. Now HTTPS, but still: firewall the console port to
the admin network, or bind a specific NIC (`HOST=…`). Documented in `run.sh`.

### F8 — No rate limiting on Connect login · **Low** · **(fixed)**
Connect's `/api/login` now throttles per client-IP + username: 5 failures triggers a
5-minute lockout (the correct password is refused during it too), cleared on a
successful login. Process-local, sufficient for a single-node console.

## 4. Status

Addressed: **F2** (key encrypted at rest), **F3** (Secure cookie), **F4** (no
default admin/admin), **F5** (SSRF guard), **F8** (login throttle).

Remaining:
1. **F1** — scope the machine key Connect uses (biggest blast-radius reduction; a
   Controller-side capability + a forwarded operator identity). The top follow-up.
2. **F6** — pin the Controller CA out-of-band for installs that leave the LAN.
3. **F7** — firewall/bind the console port operationally.

## 5. Non-findings worth stating

- The terminal proxy does **not** widen host reachability beyond what the
  Controller already has — it reuses the Controller's transport, so Connect can't
  reach a host the Controller can't.
- Secrets for SSH hosts added directly in Connect (password/key) are stored
  server-side and never returned to the browser (list surfaces `has_*` flags only).
- Cross-service calls are all machine-authenticated and TLS-pinned; there is no
  anonymous or network-trust-based edge between the services.
