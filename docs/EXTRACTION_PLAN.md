# Sysible Connect — Extraction Plan

Derived from a full read across four layers: React SPA → BFF (`webgui/server.py` +
`client/` SDK) → Controller backend (`backend/`) → host agent (`host_agent/agent.py`).
All paths are relative to the `Sysible-Controller` repo unless noted.

Connect is **not** a self-contained module today; it is a feature *thread* woven through
the shared host-management stack. The SSH-host store, file transfer, and the pure-SSH
terminal are cleanly Connect. The **agent-host terminal is co-owned by the Controller
core and the agent**, which is the single biggest obstacle to a clean cut.

---

## 1. Connect-only files (move wholesale)

**Backend**
- `backend/remote_routes.py` — the entire `/remote` router: SSH-host store (`hosts.json`),
  controller keypair, `/enroll-ssh`, `/hosts/{name}/exec`, terminal open/read/write/close/
  resize, SFTP upload/download, in-process PTY session buffers. ~100% Connect domain — but
  the core imports ~9 helper symbols from it (see §2/§3), so the file moves, the import
  surface does not: it needs a shim/boundary.
- `backend/models/remote_models.py` — Pydantic models for the `/remote` routes
  (`AddHostRequest`, `EnrollSSHRequest`, `ExecRequest`, `TerminalWriteRequest`,
  `TerminalResizeRequest`). Imported only by `remote_routes.py`.

**Frontend**
- `webgui/frontend/src/views/Connect.jsx` — the Connect page.
- `webgui/frontend/src/components/FileTransfer.jsx` — per-host upload/download + remote picker.
- `webgui/frontend/src/components/StandaloneTerminal.jsx` — pop-out terminal (`?term=<hostId>`).
- `webgui/frontend/src/components/TerminalSession.jsx` — one xterm.js instance + websocket
  to `/api/terminal/ws`; the only consumer of `terminalWsUrl()`.

**Tests**
- `tests/test_ssh_host_delete.py`, `tests/test_ssh_host_injection.py`.

**Connect-only dependencies**
- `paramiko==5.0.0` (`requirements.txt`) — imported only by `remote_routes.py`.
- `@xterm/xterm`, `@xterm/addon-fit`, `@xterm/addon-search` (`webgui/frontend/package.json`)
  — used only by `TerminalSession.jsx`.

> `components/HostResults.jsx` is **NOT** Connect-only — it is imported by `ResultsPane.jsx`,
> `PkgResults.jsx`, `views/ToolPage.jsx`, `views/UserGroupPage.jsx`, `views/Updates.jsx` and
> `Connect.jsx`. **Duplicate** it into Connect; do not move it.

---

## 2. Shared / mixed files (split, or remove the Connect parts)

- **`backend/app.py`** — the core coupling site:
  - Imports (≈123–134): `router as remote_router`, `_ensure_controller_key`,
    `agent_ssh_enable_command`, `register_agent_ssh_host`, `forget_agent_ssh_host`,
    `sync_agent_ssh_environment`, `ssh_host_exists`, `get/set_agent_ssh_state`, `AGENT_SSH_MARKER`.
  - Router mount (≈290): `app.include_router(remote_router, dependencies=[Depends(require_api_key)])`.
  - Agent→SSH auto-mirror (≈450–619): `_forget_ssh_for_deleted_agent`, `_agent_ssh_shadow_enabled`
    (gated by `SYSIBLE_AGENT_SSH_TERMINAL`, OFF by default), `_maybe_enroll_agent_ssh`
    (called on enroll/heartbeat), `_consume_ssh_enable_result` (on task result).
  - Agent-hosted PTY proxy (≈1607–1627): `POST /agents/{id}/pty/{sid}/output` and
    `GET /agents/{id}/pty/{sid}/io` — bridge the agent's shell to Connect's session buffers
    via `pty_push_output`/`pty_take_input`. **Authenticated by the per-host agent secret.**
  - `sudo_connect` per-admin flag (≈3081, 3259–3272) — a Connect permission stored in the core DB.
- **`backend/remote_routes.py`** — every route is Connect; the **core-facing helpers** are the
  split seam: `register_agent_ssh_host`, `forget_agent_ssh_host`, `sync_agent_ssh_environment`,
  `get/set/get_all_agent_ssh_state(s)`, `ssh_host_exists`, `_ensure_controller_key`,
  `agent_ssh_enable_command`, `load_hosts`/`save_hosts`, `pty_push_output`/`pty_take_input`,
  `AGENT_SSH_MARKER`. `open_terminal` **branches**: agent host → `queue_task(kind="pty_open")`
  (core path); non-agent → paramiko (pure Connect path).
- **`webgui/server.py`** (BFF) — Connect routes to move: `/api/terminal/ws` (websocket),
  `/api/checkin`, `/api/enroll-ssh`, `/api/controller-key`, `/api/ssh-host/{name}` DELETE,
  `/api/ssh-hosts` DELETE, `/api/files/{upload,download}`, `set_admin_sudo_connect`. The
  websocket carries the `sudo_connect` session gate + origin/auth checks. Core keeps `/api/hosts`
  (merged picker) and `/api/fleet`.
- **`client/_api_users.py`** — Connect functions are the remote-host/terminal/file helpers
  (`list_hosts`, `delete_host`, `get_controller_key`, `enroll_ssh`, `set_host_environment`,
  `exec_remote`, `open/write/read/close/resize_terminal`, `upload_file_ssh`, `download_file_ssh`).
  The user/group + password helpers stay.
- **`client/_api_dispatch.py`** — `list_merged_hosts` merges agent hosts + SSH hosts; core needs
  the agent half, the SSH half + `ssh_terminal_state` is Connect.
- **`webgui/frontend/src/App.jsx`** — remove `Connect`/`StandaloneTerminal` imports,
  `MODULE_TITLES.connect`, the NAV entry, the `go()` special-case, the `?term=` route, and the
  `?view=connect` standalone shell.
- **`webgui/frontend/src/api.js`** — Connect methods: `checkin`, `controllerKey`, `enrollSsh`,
  `deleteSshHost`, `deleteAllSshHosts`, `uploadFile`, `downloadUrl`, `terminalWsUrl()`.
- **`webgui/frontend/src/featureSearch.js`** — the "Sysible Connect" search entry.
- **`backend/edition.py`** — not build-gating, but its host-cap comments document the Connect
  boundary; update them (and decide the fate of the name-only `enforce_host_limit` path that
  `remote_routes` uses).
- **`host_agent/agent.py`** — ships the agent-side PTY bridge (`_start_pty_session`, `_pty_bridge`,
  `_pty_child_exec`, `_pty_post_output`, `_pty_poll_io`) and the `ssh_enable` task. Core agent
  code that exists to serve Connect.

Mixed tests: `test_agent_ssh_shadow_optin.py`, `test_reenroll_reconcile.py`,
`test_security_fixes.py`, and `conftest.py` (clears `remote_routes._PTY`/`_TERMINAL_SESSIONS`,
seeds `hosts.json`).

---

## 3. Shared dependencies (become a cross-service boundary)

1. **Auth / RBAC** — `backend/auth.py`: `require_api_key` (X-API-Key), `require_superuser`
   (X-Sysible-Admin-Token, resolved against the core `administrators` table). A standalone
   Connect must validate the same tokens or trust a Controller-minted one.
2. **`hosts.json` + controller keypair** — `SYSIBLE_HOSTS_FILE`, `CONTROLLER_KEY_PATH`. Move
   with Connect, but core calls `_ensure_controller_key` when minting the agent SSH-enable task.
3. **Agent-SSH auto-mirror** — bidirectional in-process state: core calls into Connect on every
   enroll/heartbeat/disenroll; Connect's `open_terminal` calls back into core (`queue_task`).
4. **Agent-hosted terminal = shared in-process PTY buffers** — `remote_routes._PTY` /
   `_TERMINAL_SESSIONS` written by core's `/agents/{id}/pty/*` (agent-secret auth) and read by
   the BFF websocket (admin-session auth). Two auth domains meet in one in-memory dict.
5. **Merged host list** — `/api/hosts` → `list_merged_hosts` blends agent inventory + SSH hosts.
   Becomes a cross-service join.
6. **Core DB** — `administrators.sudo_connect` column is a Connect permission in the Controller DB.
7. **Agent secret** — the agent-hosted terminal authenticates agent→controller with
   `verify_agent(host_id, secret)`, issued by core enrollment.
8. **BFF-proxied terminals** — the browser never talks to the Controller directly; the terminal
   websocket terminates in `webgui/server.py`.
9. **TLS/portal** — shared, not Connect-specific; does not block the cut.

---

## 4. CE/EE build wiring to remove when Connect leaves

There is **no separate edition flag** for Connect — it ships in the single Community build.
"Removing Connect from CE/EE" = removing its wiring from these spots:

- `backend/app.py`: drop the `remote_routes` import block; drop `include_router(remote_router…)`;
  remove the agent→SSH auto-enroll section + call sites; remove the agent-hosted PTY proxy
  endpoints (or move them into Connect); remove `set_administrator_sudo_connect_route` + the flag.
- `backend/db.py`: drop the `administrators.sudo_connect` column + migration + SELECT.
- `backend/edition.py`: update the host-cap comments; decide the name-only `enforce_host_limit` path.
- `requirements.txt`: remove `paramiko==5.0.0` (keep `python-multipart`, `cryptography`).
- `webgui/frontend/package.json`: remove the three `@xterm/*` deps.
- `webgui/server.py`: remove the Connect BFF routes + `sudo_connect` session plumbing.
- `client/_api_users.py`: remove the remote-host/terminal/file functions.
- `client/_api_dispatch.py`: strip the SSH branch + `ssh_terminal_state` from `list_merged_hosts`.
- `webgui/frontend/src/App.jsx`, `api.js`, `featureSearch.js`: remove the Connect nav/routes/methods/search.
- Tests: delete the Connect-only ones; de-Connect the mixed ones + `conftest.py`.

**No PyInstaller/.spec exists; `sysible_controller` is a prebuilt binary and the Dockerfile has no
Connect-specific lines** — so beyond `requirements.txt` and the frontend `package.json`, there is
no build-script edition gate to touch. The agent (`host_agent/agent.py`) still ships PTY +
ssh-enable code regardless; removing Connect from the *server/UI* does not remove its agent-side
surface unless the agent is also rebuilt.

---

## 5. Extraction plan (ordered)

**The clean 80% (move almost as-is):** `remote_routes.py`, `remote_models.py`, `Connect.jsx`,
`FileTransfer/StandaloneTerminal/TerminalSession.jsx`, the `_api_users.py` SDK slice, the Connect
BFF routes, `paramiko`, `@xterm/*`, `hosts.json`, the controller keypair,
`test_ssh_host_{delete,injection}.py`.

**The hard 20% (agent terminal) — the central decision.** A standalone Connect cannot serve
agent-host terminals without either (a) the Controller relaying agent PTY frames to Connect over a
new internal API, or (b) Connect gaining agent-secret validation + task-queue access (reaching into
the Controller DB).

**Recommended minimum-viable shape:**
1. **Consume the Controller via API** the way the BFF already does — admin-token validation,
   agent host list + `last_seen`, task enqueue (`pty_open`/`ssh_enable`), agent PTY frame relay.
   Formalize these as Connect's upstream contract instead of in-process imports.
2. **Move the agent-SSH auto-mirror out of core.** It's OFF by default (`SYSIBLE_AGENT_SSH_TERMINAL`);
   dropping it removes `app.py` ≈450–619 wholesale (cleanest cut) — or replace with a Controller event.
3. **Keep the agent PTY relay endpoints in the Controller** (agent-secret auth stays there) and have
   Connect's websocket read/write them via the Controller API. Agent terminals then work with zero
   agent changes.
4. **Auth boundary.** Connect trusts a Controller-minted admin token (validate via a `/whoami` call)
   and carries the `sudo_connect` claim in that token instead of a local DB column.
5. **Shared code → duplicate, not library.** `HostResults.jsx` and the SSH-input validators are
   small; duplicate them into Connect to avoid a versioned dependency between two young repos.

**Risks / unknowns**
- Agent terminals are make-or-break: if Connect must serve them, this is a distributed-systems
  change, not a file move. If "Connect = pure-SSH hosts only" is acceptable, the cut is far simpler —
  but that drops the terminal for the majority (agent) hosts, which the current UI shows uniformly.
- `hosts.json` + `list_merged_hosts` split-brain: decide the source of truth for the merged picker.
- Prebuilt `sysible_controller` binary — no in-repo build recipe to update.
- `conftest.py` reaches into `remote_routes` internals; the Controller suite must stop importing
  Connect internals once the module leaves.

**Suggested order:** (1) duplicate shared bits; (2) move pure-Connect files + `paramiko`/`@xterm`;
(3) stand Connect up against the Controller API for auth + host list; (4) decide agent-terminal
ownership and wire the PTY relay; (5) delete Connect wiring from the Controller (§4); (6) migrate/split tests.
