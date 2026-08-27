"""Sysible Connect — standalone browser terminal workspace.

A self-contained FastAPI service: its own login, an SSH-host inventory, and a
websocket that bridges a browser xterm to either a shell on this server or an
interactive SSH session on a managed host. Serves the built SPA in production.
"""
from __future__ import annotations

import asyncio
import threading

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from . import auth, controller, hosts, terminals

COOKIE = "sysible_connect_session"
_DIST = Path(__file__).resolve().parent.parent / "webgui" / "frontend" / "dist"

app = FastAPI(title="Sysible Connect")
auth.ensure_admin()


# --------------------------------------------------------------------- auth
def current_user(request: Request) -> str:
    user = auth.session_user(request.cookies.get(COOKIE))
    if not user:
        raise HTTPException(status_code=401, detail="Not signed in.")
    return user


def _is_https(request: Request) -> bool:
    """True if the client's connection is TLS — directly, or via a terminating proxy
    that sets X-Forwarded-Proto. Gates the cookie's Secure attribute."""
    if request.url.scheme == "https":
        return True
    xfp = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return xfp == "https"


@app.post("/api/login")
def login(request: Request, response: Response, body: dict = Body(...)):
    user = str(body.get("username") or "").strip()
    pw = str(body.get("password") or "")
    if not auth.verify(user, pw):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = auth.new_session(user)
    # Secure when served over TLS (the default) so the session cookie never rides
    # plain HTTP; omitted on a plain-HTTP dev/proxy setup so login still works there.
    response.set_cookie(COOKIE, token, httponly=True, samesite="lax",
                        secure=_is_https(request), max_age=12 * 3600)
    return {"user": user, "must_change": auth.must_change()}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    auth.revoke(request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE)
    return {"ok": True}


@app.get("/api/me")
def me(request: Request):
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
    return {"ok": True}


# -------------------------------------------------------------------- hosts
@app.get("/api/hosts")
def list_hosts(user: str = Depends(current_user)):
    return {"hosts": hosts.list_hosts()}


@app.post("/api/hosts")
def add_host(body: dict = Body(...), user: str = Depends(current_user)):
    try:
        hosts.add_host(
            str(body.get("name") or "").strip(), str(body.get("address") or "").strip(),
            str(body.get("user") or "root").strip(), int(body.get("port") or 22),
            str(body.get("password") or ""), str(body.get("key") or ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True}


@app.delete("/api/hosts/{name}")
def delete_host(name: str, user: str = Depends(current_user)):
    return {"deleted": hosts.delete_host(name)}


# ------------------------------------------------------------------ controller
@app.get("/api/controller")
def controller_status(user: str = Depends(current_user)):
    return controller.status()


@app.post("/api/controller")
def controller_connect(body: dict = Body(...), user: str = Depends(current_user)):
    try:
        return controller.connect(str(body.get("base_url") or "").strip(),
                                  str(body.get("api_key") or "").strip())
    except controller.ControllerError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/controller")
def controller_disconnect(user: str = Depends(current_user)):
    controller.disconnect()
    return {"connected": False}


@app.post("/api/controller/sync")
def controller_sync(user: str = Depends(current_user)):
    try:
        return controller.sync()
    except controller.ControllerError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ------------------------------------------------------------------ terminal
@app.websocket("/api/terminal/ws")
async def terminal_ws(ws: WebSocket):
    if not auth.session_user(ws.cookies.get(COOKIE)):
        await ws.close(code=4401)
        return
    await ws.accept()
    kind = ws.query_params.get("kind", "local")
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
        sess = terminals.open_session(kind, host=host, cols=cols, rows=rows)
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
@app.get("/healthz")
def healthz():
    return {"ok": True}


if _DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        # Serve real files; fall back to index.html for client-side routes.
        candidate = (_DIST / full_path)
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_DIST / "index.html")
