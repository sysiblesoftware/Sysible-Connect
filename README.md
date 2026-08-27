# Sysible Connect

**Status: local prep scaffold (not yet a running service).** Staged for extraction
from `Sysible-Controller` as part of the SLOP (Sysible Linux Operations Platform)
split. Nothing here is wired up yet — this repo is a starting point plus the plan
to finish the cut. See `docs/EXTRACTION_PLAN.md`.

## What Sysible Connect is

The **SSH / terminal / file-transfer** side of host management — as opposed to the
Controller's core **agent-based** fleet management. Concretely:

- The **managed-SSH-host store** (`hosts.json`) + the shared controller keypair.
- **Password enrollment** of a host over SSH (`/enroll-ssh`).
- **Ad-hoc remote exec** on an SSH host.
- **Interactive terminals** (xterm.js in the browser → websocket → PTY).
- **SFTP file upload/download** to/from a host.
- The **Connect** web page (host tree, terminal pop-out, fleet actions, file transfer).

## What's in this scaffold

| Path | Origin | Notes |
|---|---|---|
| `backend/remote_routes.py` | Controller | The whole `/remote` router. Moves wholesale, but the Controller core imports ~9 helper symbols from it — those become an API boundary (see plan §3). |
| `backend/models/remote_models.py` | Controller | Pydantic models for the `/remote` routes. Connect-only. |
| `webgui/frontend/src/views/Connect.jsx` | Controller | The Connect page. |
| `webgui/frontend/src/components/{FileTransfer,StandaloneTerminal,TerminalSession}.jsx` | Controller | Connect-only UI. |
| `webgui/frontend/src/components/HostResults.jsx` | Controller | **Shared** (6 views use it in the Controller) — copied here to be *duplicated*, not moved. |
| `tests/test_ssh_host_{delete,injection}.py` | Controller | Connect-only tests. |

## The one hard problem (read before starting)

Connect's terminal has **two** transports:

- **Pure-SSH hosts** — paramiko, fully self-contained. Standalone Connect can own this.
- **Agent hosts** — the terminal is **co-owned by the Controller core and the agent**:
  the agent runs the PTY and posts frames to the Controller (`/agents/{id}/pty/*`,
  authenticated by the per-host agent secret), and the browser websocket reads them
  from shared in-process buffers. This is **not** a file move — it needs an API/relay
  boundary. The `docs/EXTRACTION_PLAN.md` lays out the options.

## Next (tomorrow)

1. Duplicate the shared bits (`HostResults`, SSH-input validators).
2. Stand this up against a Controller API for auth + the host list.
3. Decide agent-terminal ownership and wire the PTY relay.
4. Remove Connect's wiring from the Controller CE/EE (exact spots in the plan).
5. Split/migrate the tests.

Until step 4 runs, **the Controller (CE/EE) is unchanged** — this repo only stages the move.
