# Sysible Connect

The fleet **terminal workspace** for the Sysible suite: a self-contained web app
that gives you browser terminals, an SSH-host inventory, file transfer, and
fleet actions across every host — on its own or wired to a Sysible Controller.

## What it does

- **Browser terminals** (xterm.js → websocket → PTY) to a local shell, a
  directly-added SSH host, or a Controller-managed host (proxied through the
  Controller, so it works even for NAT'd agents with no inbound SSH).
- **Drag-to-open workspaces** — split panes, multiple workspaces, pop-out windows.
- **Host inventory** — add SSH hosts directly, or **sync the fleet from a
  Controller** (agents + SSH hosts), with online/offline status.
- **Run-as** — connect to the Controller with a username & password and terminals
  run as that operator's account (their sudo), attributed in the Controller audit
  log, instead of root.
- **Fleet actions** — run a command across every host; restart agents; reboot /
  power off (guarded).
- **File transfer** — SFTP upload/download for directly-added SSH hosts.
- **Light / dark** theme, HTTPS by default, session-cookie auth with a login
  throttle, and secrets encrypted at rest.

## Run it

**Dev (from a checkout):**
```bash
./run.sh            # venv + deps + build the SPA + serve HTTPS on :8700
```
The first-run admin password is printed once in the console output.

**Container:**
```bash
docker compose -f deploy/docker-compose.yml up -d --build
# open https://localhost:8700   (admin password is printed once in the logs)
```
Or manage it with the suite CLI (from the Controller checkout):
`sysible_ctl connect update | logs | status | …`.

State (login, host inventory, the encrypted Controller link, the per-install
secret key, the TLS cert) lives in `~/.sysible-connect` for the dev runner, or the
`connect-data` volume for the container.

## Layout

| Path | What |
|---|---|
| `backend/` | FastAPI app: `app` (routes + terminal websocket), `auth`, `hosts`, `controller` (sync + terminal proxy + run-as), `terminals`, `fleet`, `files`, `secret`. |
| `webgui/frontend/` | React/Vite SPA: the workspace, login, and the xterm terminal. |
| `run.sh` | Self-bootstrapping dev runner (venv, SPA build, self-signed TLS, uvicorn). |
| `deploy/` | `Dockerfile`, `docker-compose.yml`, `entrypoint.sh` for the container. |
| `docs/SECURITY_REVIEW.md` | Cross-service (Controller ⇄ SLEP ⇄ Connect) trust-boundary review. |

## Tests

```bash
pytest
```
