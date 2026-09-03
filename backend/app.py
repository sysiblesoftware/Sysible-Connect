"""Sysible Connect — standalone browser terminal workspace.

A self-contained FastAPI service: its own login, an SSH-host inventory, and a
websocket that bridges a browser xterm to either a shell on this server or an
interactive SSH session on a managed host. Serves the built SPA in production.
"""
from __future__ import annotations

import asyncio
import hmac
import logging
import os
import threading
import time
from urllib.parse import urlsplit

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from fastapi import File, Form, UploadFile

from . import audit, auth, controller, files, fleet, hosts, terminals

# Server-side trail for websocket refusals. A close before accept() is invisible
# in the app's own audit log (that is written after accept), so without this a
# refused terminal leaves no record anywhere on the server either.
_log = logging.getLogger("sysible.connect")

# A WebSocket close reason is capped at 123 BYTES by RFC 6455. Go over and the
# frame is invalid — the browser reports a bare code with no reason, which is the
# blank terminal all over again. Truncate on a UTF-8 boundary so a long asserted
# role or a future longer message degrades to a shorter sentence instead of
# silently losing the explanation entirely. The full text goes to the log.
_WS_REASON_MAX = 123


async def _ws_refuse(ws, code: int, reason: str, log_detail: str = ""):
    """Close a websocket BEFORE accept with a reason the browser can display."""
    _log.warning("terminal websocket refused (%s): %s", code, log_detail or reason)
    b = reason.encode("utf-8")
    if len(b) > _WS_REASON_MAX:
        reason = b[:_WS_REASON_MAX].decode("utf-8", "ignore")
    await ws.close(code=code, reason=reason)

COOKIE = "sysible_connect_session"
_DIST = Path(__file__).resolve().parent.parent / "webgui" / "frontend" / "dist"

app = FastAPI(title="Sysible Connect")
auth.ensure_admin()


# Bound request bodies so an unbounded upload can't exhaust memory: the file-upload
# route reads the whole body into RAM (await file.read()), so without a cap a single
# request could OOM the process. 64 MiB default (file transfers to hosts can be
# sizeable), overridable. Enforced at the ASGI layer against the ACTUAL streamed
# bytes, not just Content-Length — a Content-Length-only check is trivially bypassed
# with Transfer-Encoding: chunked. Only HTTP is bounded; the terminal websocket
# (a different ASGI scope) passes straight through, so live sessions are unaffected.
_MAX_REQUEST_BYTES = int(os.environ.get("SYSIBLE_CONNECT_MAX_REQUEST_BYTES", str(64 * 1024 * 1024)))


class _BodyLimitASGI:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        for k, v in scope.get("headers") or []:
            if k == b"content-length" and v.isdigit() and int(v) > self.max_bytes:
                return await self._too_large(scope, send)
        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            body += message.get("body", b"")
            more_body = message.get("more_body", False)
            if len(body) > self.max_bytes:
                return await self._too_large(scope, send)
        sent = False

        async def replay_receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)

    async def _too_large(self, scope, send):
        async def _noop_receive():
            return {"type": "http.request", "body": b"", "more_body": False}
        await JSONResponse({"detail": "Request body too large."}, status_code=413)(scope, _noop_receive, send)


app.add_middleware(_BodyLimitASGI, max_bytes=_MAX_REQUEST_BYTES)


# Defense-in-depth response headers. Connect serves an HTML SPA + a live terminal
# UI, so clickjacking of the PTY/fleet controls is the real risk — hence
# frame-ancestors + X-Frame-Options. They are 'self' / SAMEORIGIN rather than
# 'none' / DENY: behind the SLOP gateway every app shares ONE origin, and SLOP
# Administration hosts each app's own settings UI in-page instead of keeping a
# second copy that drifts. 'self' still refuses every OTHER site, so a foreign
# page cannot frame the terminal either way. Behind the gateway these are also
# stamped at the edge; setting them here protects the standalone deploy too. A
# lone frame-ancestors CSP directive blocks framing WITHOUT restricting the SPA's
# own resource/websocket loading, so it can't break the console (a strict
# default-src is deliberately not forced here — that needs a per-build CSP).
@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Content-Security-Policy", "frame-ancestors 'self'")
    if _is_https(request):
        resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return resp


# ------------------------------------------------------ SLOP SSO gateway trust
# When Connect runs behind the SLOP single-sign-on gateway, an upstream Caddy
# reverse proxy authenticates the browser and injects identity headers on every
# proxied request (and on the websocket upgrade handshake):
#   X-Sysible-User: <username>
#   X-Sysible-Role: <role>          role ∈ {superuser, operator, auditor}
#   X-Sysible-Auth: <shared secret> proves the request came through the gateway
# In that mode Connect trusts the gateway-asserted identity INSTEAD of requiring
# its own cookie login. OFF by default, so standalone Connect is unchanged.
#
# TRUST BOUNDARY: in SSO mode Connect is reachable ONLY through the gateway, and
# the gateway stamps X-Sysible-Auth with the shared secret on every request it
# forwards. A browser hitting Connect directly cannot know that secret, so it can
# never spoof an identity — the secret check IS the boundary. It holds regardless
# of container network IPs, and Connect (unlike SLEP) has no BFF/second proxy
# layer, so there is no client-supplied copy to strip: the match is the whole gate.
#
# Env is read once at module load (matching the SYSIBLE_CONNECT_* / auth.py
# convention); the request headers are read per call.
_TRUST_GATEWAY = os.getenv("SYSIBLE_CONNECT_TRUST_GATEWAY_AUTH", "0") == "1"
_SSO_SECRET = os.getenv("SYSIBLE_SSO_SHARED_SECRET", "")

# SLOP asserts one of {superuser, operator, auditor} in X-Sysible-Role. Only these
# two may take state-changing actions (open terminals, run fleet commands, add/remove
# hosts, transfer files, manage the Controller link); 'auditor' is read-only oversight,
# and anything else (empty/unknown) fails closed. Standalone Connect has NO role
# source, so this floor is only ever consulted when a gateway identity is present.
_PRIVILEGED_ROLES = {"superuser", "operator"}

# Origin check for the terminal websocket (defeats cross-site WebSocket hijacking:
# a browser cannot forge Origin, so refusing a foreign one stops another site from
# opening this PTY over the victim's ambient session).
#
# The default is SAME-ORIGIN, computed per request — NOT a fixed hostname. It used
# to default to "https://connect.slop.lan", from the era when each app had its own
# subdomain. SLOP is now ONE origin addressed by path and answers on whatever IP or
# name the client used, so the browser sends e.g. "https://192.168.8.239"; that
# never matched, every upgrade was closed with 4403, and Connect could not open a
# single terminal behind the gateway. Nothing in SLOP set the variable either, so
# the broken default was always the one in force.
#
# Set SYSIBLE_CONNECT_ALLOWED_ORIGINS (comma-separated, exact origins) only when
# the browser's origin genuinely differs from the host this service is addressed
# as — e.g. an outer proxy that rewrites Host. Empty = same-origin, which is what
# every stock deployment wants.
_ALLOWED_ORIGINS = {o.strip() for o in os.getenv(
    "SYSIBLE_CONNECT_ALLOWED_ORIGINS", "").split(",") if o.strip()}


def _ws_origin_ok(headers) -> bool:
    """True when the websocket's Origin is allowed. Fails closed on a missing
    Origin — the real console always sends one."""
    origin = headers.get("origin")
    if not origin:
        return False
    if _ALLOWED_ORIGINS:                      # explicit override configured
        return origin in _ALLOWED_ORIGINS
    # Same-origin: compare the Origin's host with the host THIS request was
    # addressed to. Caddy preserves the client's Host and sets X-Forwarded-Host,
    # so this works by raw IP or any name with nothing to configure. Host-only
    # (port/scheme excluded) matches the IdP's own same-origin gate, so the whole
    # platform judges "same site" the same way.
    self_host = (headers.get("x-forwarded-host") or headers.get("host") or "")
    self_host = self_host.split(",")[0].strip().lower().rsplit(":", 1)[0].strip("[]")
    try:
        origin_host = (urlsplit(origin).hostname or "").lower()
    except ValueError:
        return False
    return bool(self_host) and origin_host == self_host

# FAIL CLOSED: trust mode on but no shared secret means we cannot prove a request
# actually came through the gateway, so identity headers must NOT be honored. Warn
# once at startup so the misconfiguration is obvious in the logs.
if _TRUST_GATEWAY and not _SSO_SECRET:
    print("[sysible-connect] SYSIBLE_CONNECT_TRUST_GATEWAY_AUTH=1 but "
          "SYSIBLE_SSO_SHARED_SECRET is empty — gateway identity headers will be "
          "IGNORED (fail closed). Set the shared secret to enable SSO trust mode.",
          flush=True)


def gateway_identity(headers) -> str | None:
    """Return the gateway-asserted username when SSO trust mode is active and the
    request provably came through the gateway; otherwise None.

    `headers` is any case-insensitive header mapping — a Starlette Request.headers
    and a WebSocket.headers both qualify. Honors the identity ONLY when trust mode
    is enabled AND a shared secret is configured AND the request's X-Sysible-Auth
    matches it (constant-time) AND the asserted user is non-empty. Every other case
    fails closed to None, so a caller that cannot present the secret can never
    inject an identity.
    """
    if not (_TRUST_GATEWAY and _SSO_SECRET):
        return None
    if not hmac.compare_digest(headers.get("x-sysible-auth", ""), _SSO_SECRET):
        return None
    user = (headers.get("x-sysible-user") or "").strip()
    return user or None


def acting_identity(headers) -> dict | None:
    """The acting operator to forward to the Controller as the run-as identity, or
    None when there is no gateway-asserted one (standalone Connect, or a request that
    can't present the shared secret).

    Built from the SAME trust check as gateway_identity, so a browser can never put
    its own name in here: without the secret both are None. The Controller re-checks
    the secret on its side before honoring the headers — this is a relay of a
    verified identity, not a new assertion.
    """
    user = gateway_identity(headers)
    if not user:
        return None
    return {"user": user, "role": gateway_role(headers) or ""}


def gateway_role(headers) -> str | None:
    """The gateway-asserted role (lower-cased) ONLY when SSO trust mode is active and
    the request provably came through the gateway; otherwise None. Standalone Connect
    has no role source, so it always returns None and the role floor is never applied
    there. In trust mode an absent header yields "" (an unrecognized role → denied)."""
    if not gateway_identity(headers):
        return None
    return (headers.get("x-sysible-role") or "").strip().lower()


# --------------------------------------------------------------------- auth
def sso_only() -> bool:
    """True when SLOP is the identity authority for this instance.

    In that mode Connect must have NO identity source of its own. Connect's port
    is published on the host, so anything it still accepts locally is a second
    way in that the gateway never sees — a local session would survive signing
    out of SLOP, and a local password would be an account SLOP administration
    does not manage. Both are exactly what single sign-on is supposed to remove.
    """
    return bool(_TRUST_GATEWAY and _SSO_SECRET)


def current_user(request: Request) -> str:
    # SSO gateway trust takes precedence: if the request provably came through the
    # gateway, trust its asserted identity and skip the cookie path entirely.
    gw = gateway_identity(request.headers)
    if gw:
        # Surface the asserted role so require_operator can enforce the read-only floor.
        request.state.role = request.headers.get("x-sysible-role", "")
        return gw
    if sso_only():
        # No gateway identity and SLOP owns identity → this request did not come
        # through the front door. Refuse rather than falling back to a local
        # session: that fallback is what let a Connect-local login outlive a SLOP
        # sign-out, and what let someone reach Connect directly on its published
        # port with an account SLOP knows nothing about.
        raise HTTPException(status_code=401,
                            detail="Sign in at the Sysible Linux Operations Platform.")
    user = auth.session_user(request.cookies.get(COOKIE))
    if not user:
        raise HTTPException(status_code=401, detail="Not signed in.")
    return user


def require_operator(request: Request, user: str = Depends(current_user)) -> str:
    """Authorization floor for state-changing / shell routes. In gateway-trust (SSO)
    mode a read-only 'auditor' — and any empty/unrecognized asserted role — is rejected
    with 403 (fail closed). Standalone Connect has no role source (gateway_role → None),
    so its existing single-user behavior is left unchanged."""
    role = gateway_role(request.headers)
    if role is not None and role not in _PRIVILEGED_ROLES:
        raise HTTPException(status_code=403,
                            detail="This action requires an operator role; auditor accounts are read-only.")
    return user


def _is_https(request: Request) -> bool:
    """True if the client's connection is TLS — directly, or via a terminating proxy
    that sets X-Forwarded-Proto. Gates the cookie's Secure attribute."""
    if request.url.scheme == "https":
        return True
    xfp = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return xfp == "https"


# In-memory brute-force throttle for the password login (per client IP + username).
# Connect is the one password login reachable without already holding a session, so
# it gets a lockout after a burst of failures. Process-local (no DB) — fine for a
# single-node console.
_LOGIN_FAIL: dict = {}
_LOGIN_MAX = 5              # failures before a lockout
_LOGIN_LOCK_S = 300        # lockout duration


def _client_ip(request: Request) -> str:
    """The real client IP for the login throttle. Behind a reverse proxy (the SLOP
    gateway, or any front proxy in a standalone deploy) the direct peer is the proxy,
    which APPENDS the real client to the right of X-Forwarded-For — so the LAST hop is
    the trusted client. The first hop is client-supplied and spoofable (an attacker
    could rotate it to dodge the throttle, or forge a victim's IP); take the rightmost.
    No proxy → the direct peer. Mirrors the SLOP IdP/SLEP client-IP derivation."""
    xff = (request.headers.get("x-forwarded-for") or "").split(",")[-1].strip()
    if xff:
        return xff
    return request.client.host if request.client else "?"


def _throttle_key(request: Request, user: str) -> str:
    return f"{_client_ip(request)}:{user.lower()}"


@app.post("/api/login")
def login(request: Request, response: Response, body: dict = Body(...)):
    # In SSO gateway-trust mode the gateway is the ONLY auth path: the local password
    # login is disabled so an attacker reaching :8700 directly can't spray the local
    # admin credential (and can't lock a username out) bypassing the gateway.
    if _TRUST_GATEWAY and _SSO_SECRET:
        raise HTTPException(status_code=403,
                            detail="Connect has no separate login — sign in at the Sysible "
                                   "Linux Operations Platform. Accounts are managed in SLOP "
                                   "Administration.")
    user = str(body.get("username") or "").strip()
    pw = str(body.get("password") or "")
    key = _throttle_key(request, user)
    now = time.time()
    st = _LOGIN_FAIL.get(key)
    if st and st.get("until", 0) > now:
        audit.log(user or "(unknown)", "login_throttled", detail=f"ip={_client_ip(request)}", ok=False)
        raise HTTPException(status_code=429,
                            detail="Too many failed attempts — try again in a few minutes.")
    if not auth.verify(user, pw):
        st = _LOGIN_FAIL.setdefault(key, {"n": 0, "until": 0})
        st["n"] += 1
        if st["n"] >= _LOGIN_MAX:
            st["until"] = now + _LOGIN_LOCK_S
            st["n"] = 0
        audit.log(user or "(unknown)", "login_failed", detail=f"ip={_client_ip(request)}", ok=False)
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    _LOGIN_FAIL.pop(key, None)   # clear on success
    token = auth.new_session(user)
    # Secure when served over TLS (the default) so the session cookie never rides
    # plain HTTP; omitted on a plain-HTTP dev/proxy setup so login still works there.
    response.set_cookie(COOKIE, token, httponly=True, samesite="lax",
                        secure=_is_https(request), max_age=12 * 3600)
    audit.log(user, "login", detail=f"ip={_client_ip(request)}")
    return {"user": user, "must_change": auth.must_change()}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    _who = auth.session_user(request.cookies.get(COOKIE)) or gateway_identity(request.headers) or ""
    auth.revoke(request.cookies.get(COOKIE))
    audit.log(_who, "logout")
    response.delete_cookie(COOKIE)
    return {"ok": True}


@app.get("/api/me")
def me(request: Request):
    # In gateway trust mode reflect the header identity so the SPA renders as
    # logged-in; a gateway user has no local password, so never flag must-change.
    gw = gateway_identity(request.headers)
    if gw:
        return {"user": gw, "must_change": False}
    user = auth.session_user(request.cookies.get(COOKIE))
    if not user:
        return JSONResponse({"user": None}, status_code=200)
    return {"user": user, "must_change": auth.must_change()}


@app.post("/api/change-password")
def change_password(request: Request, body: dict = Body(...), user: str = Depends(current_user)):
    new = str(body.get("new_password") or "")
    if len(new) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    auth.set_password(new)
    audit.log(user, "password_changed")
    return {"ok": True}


# -------------------------------------------------------------------- hosts
@app.get("/api/hosts")
def list_hosts(user: str = Depends(current_user)):
    return {"hosts": hosts.list_hosts()}


@app.post("/api/hosts")
def add_host(body: dict = Body(...), user: str = Depends(require_operator)):
    try:
        hosts.add_host(
            str(body.get("name") or "").strip(), str(body.get("address") or "").strip(),
            str(body.get("user") or "root").strip(), int(body.get("port") or 22),
            str(body.get("password") or ""), str(body.get("key") or ""))
    except ValueError as e:
        audit.log(user, "host_add", str(body.get("name") or ""), str(e), ok=False)
        raise HTTPException(status_code=400, detail=str(e))
    # Identifying metadata only — the credential in the body is never logged.
    audit.log(user, "host_add", str(body.get("name") or ""),
              f"{body.get('user') or 'root'}@{body.get('address') or ''}:{body.get('port') or 22}")
    return {"ok": True}


@app.delete("/api/hosts/{name}")
def delete_host(name: str, user: str = Depends(require_operator)):
    gone = hosts.delete_host(name)
    audit.log(user, "host_delete", name, ok=bool(gone))
    return {"deleted": gone}


# ------------------------------------------------------------- file transfer
@app.post("/api/hosts/{name}/files/list")
def files_list(name: str, body: dict = Body(default=None), user: str = Depends(require_operator)):
    try:
        return files.list_dir(name, str((body or {}).get("path") or "."))
    except files.FileError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/hosts/{name}/files/download")
def files_download(name: str, path: str, user: str = Depends(require_operator)):
    try:
        data = files.download(name, path)
    except files.FileError as e:
        raise HTTPException(status_code=400, detail=str(e))
    fname = (path.rsplit("/", 1)[-1] or "download").replace('"', "")
    return Response(content=data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.post("/api/hosts/{name}/files/upload")
async def files_upload(name: str, path: str = Form(...), file: UploadFile = File(...),
                       user: str = Depends(require_operator)):
    dest = path if path.endswith("/") else path
    # If a directory was given, append the uploaded filename.
    if dest.endswith("/"):
        dest = dest + (file.filename or "upload")
    try:
        size = files.upload(name, dest, await file.read())
    except files.FileError as e:
        audit.log(user, "file_upload", name, f"{dest}: {e}", ok=False)
        raise HTTPException(status_code=400, detail=str(e))
    audit.log(user, "file_upload", name, f"{dest} ({size} bytes)")
    return {"ok": True, "path": dest, "size": size}


@app.post("/api/hosts/ping")
def ping_hosts(user: str = Depends(current_user)):
    """Reachability probe for every host: a short TCP connect to its SSH port. A
    Controller-synced host with no address (a NAT'd agent) can't be dialed directly —
    it's reported as reachable-via-Controller rather than down."""
    import socket
    from concurrent.futures import ThreadPoolExecutor

    def probe(h):
        addr, port = h.get("address", ""), int(h.get("port") or 22)
        if not addr:
            return {"name": h["name"], "reachable": None, "detail": "via Controller"}
        t0 = time.time()
        try:
            with socket.create_connection((addr, port), timeout=3):
                return {"name": h["name"], "reachable": True, "ms": int((time.time() - t0) * 1000)}
        except OSError as e:
            return {"name": h["name"], "reachable": False, "detail": str(e)[:80]}

    hs = hosts.list_hosts()
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(probe, hs)) if hs else []
    return {"results": results}


# ------------------------------------------------------------------ controller
def _req_host(request) -> str:
    """The host the browser reached Connect on — the gateway's host, so SSO auto-attach
    can find the local Controller. Prefer the gateway-forwarded host, fall back to Host."""
    return (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0].strip()


@app.get("/api/controller")
def controller_status(request: Request, user: str = Depends(current_user)):
    # Pass the acting operator so an SSO attach reports the real run-as instead of
    # "no run-as" (under SSO the identity is per-request, never stored).
    return controller.status(host=_req_host(request),
                             identity=acting_identity(request.headers))


@app.post("/api/controller")
def controller_connect(body: dict = Body(...), user: str = Depends(require_operator)):
    b = body or {}
    base = str(b.get("base_url") or "").strip()
    try:
        # Prefer username/password (the friendly path) when provided; else the API key.
        if b.get("username") or b.get("password"):
            out = controller.connect_with_credentials(
                base, str(b.get("username") or "").strip(), str(b.get("password") or ""),
                str(b.get("totp_code") or "").strip())
        else:
            out = controller.connect(base, str(b.get("api_key") or "").strip())
    except controller.ControllerError as e:
        audit.log(user, "controller_attach", base, str(e), ok=False)
        raise HTTPException(status_code=400, detail=str(e))
    # The Controller URL only — the credential used to attach is never logged.
    audit.log(user, "controller_attach", base)
    return out


@app.delete("/api/controller")
def controller_disconnect(user: str = Depends(require_operator)):
    controller.disconnect()
    audit.log(user, "controller_detach")
    return {"connected": False}


@app.post("/api/controller/sync")
def controller_sync(request: Request, user: str = Depends(require_operator)):
    controller.note_gateway_host(_req_host(request))   # ensure the derived URL is known
    try:
        return controller.sync()
    except controller.ControllerError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------- fleet actions
@app.post("/api/fleet/run")
def fleet_run(request: Request, body: dict = Body(...),
              user: str = Depends(require_operator)):
    """Run one command across hosts (default: all). Uses the terminal transport, so
    it reaches agent, SSH, and local hosts alike. Returns per-host output."""
    command = str(body.get("command") or "")
    names = body.get("hosts")
    if not names:
        names = [h["name"] for h in hosts.list_hosts()]
    try:
        results = fleet.run(command, list(names),
                            identity=acting_identity(request.headers))
    except ValueError as e:
        audit.log(user, "fleet_run", ",".join(map(str, names))[:200], str(e), ok=False)
        raise HTTPException(status_code=400, detail=str(e))
    # The command and which hosts it hit — never the command OUTPUT.
    audit.log(user, "fleet_run", f"{len(list(names))} host(s)", command[:500])
    return {"results": results}


# ------------------------------------------------------------------ terminal
@app.websocket("/api/terminal/ws")
async def terminal_ws(ws: WebSocket):
    # Cross-site WebSocket hijacking defense: a browser can't forge the Origin header,
    # so an exact allowlist match (checked BEFORE accept) stops a sibling *.slop.lan
    # page from opening this PTY over the victim's ambient session. A missing Origin is
    # rejected too — the legitimate SPA always sends one.
    # Every refusal below carries a REASON. A close before accept() sends no
    # message frame, so the browser gets nothing to display: the console showed a
    # terminal pane with a blinking cursor and no text at all, indistinguishable
    # from a session that opened and stayed quiet. That ambiguity cost days —
    # "Connect still not working" with no way to tell a refused websocket from a
    # silent agent. The close frame's reason field crosses to the browser even on
    # a pre-accept close, so use it.
    if not _ws_origin_ok(ws.headers):
        await _ws_refuse(ws, 4403,
                         "Refused: this page's origin may not open a terminal. "
                         "Use the SLOP gateway address.",
                         log_detail=f"bad Origin {ws.headers.get('origin')!r}")
        return
    # The websocket bypasses current_user, so gateway trust is applied here
    # separately. Caddy forwards the X-Sysible-* headers on the WS upgrade too, so
    # ws.headers carries them; fall back to the session cookie for standalone Connect.
    gw = gateway_identity(ws.headers)
    # Same rule as current_user: under SSO the gateway is the ONLY identity source,
    # so a leftover local cookie can't open a shell after a SLOP sign-out.
    local = None if sso_only() else auth.session_user(ws.cookies.get(COOKIE))
    if not (gw or local):
        await _ws_refuse(ws, 4401,
                         "Refused: not signed in — the gateway asserted no "
                         "X-Sysible-User on this upgrade.",
                         log_detail=(f"no identity (sso_only={sso_only()}, "
                                     f"user header present="
                                     f"{bool(ws.headers.get('x-sysible-user'))}, "
                                     f"secret ok={bool(gateway_identity(ws.headers))})"))
        return
    # Role floor (SSO mode): a terminal is the shell primitive, so a read-only auditor —
    # and any empty/unrecognized asserted role — is denied here, mirroring
    # require_operator on the HTTP routes. Fail closed. Standalone Connect (no gateway
    # identity) is unaffected.
    if gw:
        role = (ws.headers.get("x-sysible-role") or "").strip().lower()
        if role not in _PRIVILEGED_ROLES:
            # The role is attacker-influenced text; bound it so it can't eat the
            # whole 123-byte budget and push the actionable part out of the frame.
            shown = (role or "none")[:24]
            await _ws_refuse(ws, 4403,
                             f"Refused: role ({shown}) may not open a terminal; "
                             "needs operator or superuser (SLOP Administration).",
                             log_detail=(f"role {role!r} not in "
                                         f"{sorted(_PRIVILEGED_ROLES)} (user {gw})"))
            return
    await ws.accept()
    kind = ws.query_params.get("kind", "local")
    # A shell was handed out: record who, and to which host. Typed input and session
    # output are NEVER recorded — only that the session was opened.
    audit.log(gw or local or "", "terminal_open",
              ws.query_params.get("host", "") or kind, f"kind={kind}")
    try:
        cols = int(ws.query_params.get("cols", 80))
        rows = int(ws.query_params.get("rows", 24))
    except ValueError:
        cols, rows = 80, 24
    host = None
    if kind in ("ssh", "controller"):
        host = hosts.get_host(ws.query_params.get("host", ""))
        if not host:
            await ws.send_json({"t": "error", "d": "Host not found."})
            await ws.close()
            return
        # Route by where the host came from, not just the requested kind: a host
        # synced from a Controller proxies through it (works for NAT'd agent hosts
        # with no inbound SSH); a locally-added host uses direct SSH.
        kind = "controller" if host.get("source") == "controller" else "ssh"
    try:
        # Forward the signed-in operator so the shell runs AS their account on the
        # host (with their sudo) and the Controller attributes it to them, instead of
        # every SSO terminal landing as the Controller's default account.
        sess = terminals.open_session(kind, host=host, cols=cols, rows=rows,
                                      identity=acting_identity(ws.headers))
    except Exception as e:  # noqa: BLE001 — surface the connect error to the terminal
        await ws.send_json({"t": "error", "d": str(e)})
        await ws.close()
        return

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def reader():
        while True:
            data = sess.read()
            loop.call_soon_threadsafe(queue.put_nowait, data or None)
            if not data:
                break

    threading.Thread(target=reader, daemon=True).start()

    async def pump_out():
        while True:
            data = await queue.get()
            if data is None:
                await ws.send_json({"t": "exit"})
                return
            await ws.send_json({"t": "o", "d": data.decode("utf-8", "replace")})

    out_task = asyncio.create_task(pump_out())
    try:
        while True:
            msg = await ws.receive_json()
            mt = msg.get("t")
            if mt == "i":
                sess.write(str(msg.get("d", "")).encode())
            elif mt == "r":
                sess.resize(int(msg.get("cols", 80)), int(msg.get("rows", 24)))
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        sess.close()
        out_task.cancel()


# --------------------------------------------------------------------- SPA
@app.get("/api/audit")
def api_audit(request: Request, limit: int = 100, since_id: int = 0,
              user: str = Depends(current_user)) -> dict:
    """Connect's audit trail, newest first. Deliberately readable by ANY signed-in
    identity including a read-only auditor — oversight is exactly an auditor's job,
    and the trail carries no secrets. Same {entries:[...]} shape as SLEP and
    Flashback so Sysible Visualizer aggregates every app with one client."""
    return {"entries": audit.list_entries(limit, since_id)}


@app.get("/healthz")
def healthz():
    return {"ok": True}


if _DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        # Serve real files from the built SPA tree; fall back to index.html for
        # client-side routes. SECURITY: resolve() collapses any '..' (even percent-
        # encoded, since the ASGI layer has already decoded the path) and the
        # containment check rejects anything that escapes the dist tree, so this
        # catch-all can never read arbitrary host files (e.g. /proc/self/environ,
        # /data/auth.json). A '..' segment is refused up front as defense-in-depth.
        base = _DIST.resolve()
        if full_path and ".." not in full_path.split("/"):
            candidate = (base / full_path).resolve()
            if candidate.is_file() and candidate.is_relative_to(base):
                return FileResponse(candidate)
        return FileResponse(base / "index.html")
