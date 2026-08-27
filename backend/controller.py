"""Sysible Connect ↔ Sysible Controller integration.

Connect can attach to a Sysible Controller (its backend API, `https://host:9000`,
authenticated by the machine API key) to:

  * **sync** the Controller's fleet — agent hosts (`GET /agents`) and SSH-managed
    hosts (`GET /remote/hosts`) — into Connect's own host list, and
  * **proxy terminals** through the Controller, reusing its transport (the agent's
    outbound PTY channel, or the Controller's SSH key), so you can open a shell on
    ANY fleet host from Connect — including NAT'd, agent-only hosts with no inbound
    SSH — without holding those hosts' credentials yourself.

A standalone/on-prem Controller usually serves a self-signed cert; it's trusted on
first use (TOFU) and pinned. The API key is stored 0600 and never returned to the
browser.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import ssl
from pathlib import Path
from urllib.parse import urlparse

import requests

from .auth import DATA_DIR
from . import hosts as host_store
from . import secret

_CFG = DATA_DIR / "controller.json"
_CA = DATA_DIR / "controller_ca.pem"


class ControllerError(Exception):
    pass


# --------------------------------------------------------------- config store
def _load() -> dict:
    try:
        d = json.loads(_CFG.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(d, dict):
        return {}
    # API key is stored encrypted (api_key_enc); decrypt into memory. A legacy
    # plaintext api_key is tolerated and re-encrypted on the next save.
    if d.get("api_key_enc"):
        d["api_key"] = secret.decrypt(d.pop("api_key_enc"))
    return d


def _save(cfg: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    out = dict(cfg)
    if out.get("api_key"):
        out["api_key_enc"] = secret.encrypt(out.pop("api_key"))
    out.pop("api_key", None)          # never write the key in plaintext
    fd = os.open(str(_CFG), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(out).encode())
    finally:
        os.close(fd)


def status() -> dict:
    """Public connection state — never includes the API key."""
    cfg = _load()
    return {"connected": bool(cfg.get("base_url") and cfg.get("api_key")),
            "base_url": cfg.get("base_url", "")}


def disconnect() -> None:
    for p in (_CFG, _CA):
        try:
            p.unlink()
        except OSError:
            pass


def _normalize(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if url and "://" not in url:
        url = "https://" + url
    return url


def _guard_url(url: str) -> None:
    """SSRF guard (parity with SLEP): resolve the Controller host and refuse
    loopback, link-local (incl. cloud metadata 169.254.169.254), unspecified,
    multicast and reserved addresses, so 'connect a Controller' can't be aimed at an
    internal service. Private LAN ranges stay allowed (real on-prem Controllers)."""
    host = urlparse(url).hostname or ""
    if not host:
        raise ControllerError("Invalid Controller URL.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return  # let the real request surface a clean DNS error
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            raise ControllerError(
                f"Refusing to connect to {host} ({ip}): loopback/link-local/reserved "
                "addresses (including cloud metadata) are blocked.")


# ------------------------------------------------------------------ TLS TOFU
def _ca_path(pem: str) -> str | None:
    if not pem:
        return None
    fd = os.open(str(_CA), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem.encode())
    finally:
        os.close(fd)
    return str(_CA)


def _fetch_server_cert(base_url: str) -> str:
    u = urlparse(base_url)
    if u.scheme != "https" or not u.hostname:
        raise ControllerError("A certificate can only be pinned for an https Controller URL.")
    try:
        return ssl.get_server_certificate((u.hostname, u.port or 443), timeout=15)
    except Exception as e:  # noqa: BLE001
        raise ControllerError(f"could not fetch the Controller's certificate: {e}")


# ------------------------------------------------------------- HTTP transport
def _request(cfg: dict, method: str, path: str, *, json_body=None, timeout=20):
    """One Controller API call with the machine key; trust-on-first-use the
    self-signed cert on a verify failure (pin it into cfg and retry once)."""
    url = cfg["base_url"] + path
    headers = {"X-API-Key": cfg["api_key"]}
    verify = _ca_path(cfg.get("tls_cert", "")) or True
    try:
        return requests.request(method, url, headers=headers, json=json_body,
                                verify=verify, timeout=timeout)
    except requests.exceptions.SSLError:
        pem = _fetch_server_cert(cfg["base_url"])
        cfg["tls_cert"] = pem
        return requests.request(method, url, headers=headers, json=json_body,
                                verify=_ca_path(pem), timeout=timeout)
    except requests.exceptions.RequestException as e:
        raise ControllerError(f"could not reach the Controller at {cfg['base_url']}: {e}")


def connect(base_url: str, api_key: str) -> dict:
    """Validate + save a Controller connection (probes /remote/hosts, TOFU-pins the
    cert). Returns the public status."""
    base = _normalize(base_url)
    if not base or not api_key:
        raise ControllerError("Controller URL and API key are both required.")
    _guard_url(base)
    cfg = {"base_url": base, "api_key": str(api_key), "tls_cert": ""}
    r = _request(cfg, "GET", "/remote/hosts")
    if r.status_code in (401, 403):
        raise ControllerError("The Controller rejected that API key.")
    if r.status_code != 200:
        raise ControllerError(f"The Controller returned HTTP {r.status_code} for /remote/hosts.")
    _save(cfg)
    return status()


# --------------------------------------------------------------- fleet + sync
def _fleet(cfg: dict) -> tuple[dict, list]:
    r = _request(cfg, "GET", "/remote/hosts")
    if r.status_code != 200:
        raise ControllerError(f"Could not list Controller hosts (HTTP {r.status_code}).")
    try:
        ssh_hosts = r.json()
    except ValueError:
        ssh_hosts = {}
    if not isinstance(ssh_hosts, dict):
        ssh_hosts = {}
    agents = []
    ra = _request(cfg, "GET", "/agents")
    if ra.status_code == 200:
        try:
            agents = ra.json().get("agents", []) or []
        except ValueError:
            agents = []
    return ssh_hosts, agents


def sync() -> dict:
    """Import the Controller's fleet into Connect's host store. Agent hosts and SSH
    hosts are tagged source='controller' so their terminals proxy through the
    Controller (reusing its transport) rather than needing a direct SSH credential."""
    cfg = _load()
    if not cfg.get("base_url"):
        raise ControllerError("No Controller connected.")
    ssh_hosts, agents = _fleet(cfg)
    _save(cfg)   # persist a cert refreshed by TOFU during the calls

    imported = skipped = 0

    def _imp(name, address, user, port, environment, transport):
        nonlocal imported, skipped
        name = (name or "").strip()
        if not host_store.valid_name(name):
            skipped += 1
            return
        # address may be blank for a NAT'd agent — that's fine, the terminal proxies
        # by NAME through the Controller and never dials the address directly.
        host_store.upsert_controller_host(
            name, address=address or "", user=user or "root", port=int(port or 22),
            environment=environment or "", transport=transport)
        imported += 1

    for name, h in ssh_hosts.items():
        h = h or {}
        _imp(name, str(h.get("ip", "")), str(h.get("user") or "root"),
             h.get("port", 22), str(h.get("environment", "")), "ssh")
    for a in agents:
        a = a or {}
        _imp(str(a.get("hostname", "")), str(a.get("ip", "")), "root", 22,
             str(a.get("environment", "")), "agent")

    return {"imported": imported, "skipped": skipped,
            "ssh_hosts": len(ssh_hosts), "agents": len(agents),
            "controller": cfg["base_url"]}


# --------------------------------------------------- terminal proxy transport
class TerminalProxy:
    """A live terminal on a Controller-managed host, driven over the Controller's
    HTTP terminal API. Presents the same read/write/resize/alive/close interface as
    the local/SSH sessions so the websocket pump doesn't care how it's transported.
    read() long-polls the Controller and blocks until output arrives or the shell
    ends (b'')."""

    kind = "controller"

    def __init__(self, host_name: str, cols: int = 80, rows: int = 24):
        self._cfg = _load()
        if not self._cfg.get("base_url"):
            raise ControllerError("No Controller connected.")
        self._closed = False
        r = _request(self._cfg, "POST", f"/remote/hosts/{host_name}/terminal/open")
        if r.status_code == 503:
            raise ControllerError("This host's agent isn't checking in right now — try again once it's online.")
        if r.status_code in (401, 403):
            raise ControllerError("The Controller refused to open a terminal on this host (permission).")
        if r.status_code != 200:
            detail = f"HTTP {r.status_code}"
            try:
                detail = r.json().get("detail") or detail
            except ValueError:
                pass
            raise ControllerError(f"Could not open a terminal on '{host_name}': {detail}")
        self._sid = r.json().get("session_id")
        if not self._sid:
            raise ControllerError("The Controller did not return a terminal session.")
        if cols != 80 or rows != 24:
            self.resize(cols, rows)

    def read(self, n: int = 65536) -> bytes:
        while not self._closed:
            try:
                r = _request(self._cfg, "GET", f"/remote/terminal/{self._sid}/read", timeout=60)
            except ControllerError:
                self._closed = True
                return b""
            if r.status_code != 200:
                self._closed = True
                return b""
            body = r.json()
            data = body.get("data") or ""
            if body.get("closed"):
                self._closed = True
            if data:
                return data.encode("utf-8", "replace")
            if self._closed:
                return b""
            # idle long-poll returned nothing — poll again (the Controller side waits)
        return b""

    def write(self, data: bytes):
        try:
            _request(self._cfg, "POST", f"/remote/terminal/{self._sid}/write",
                     json_body={"data": data.decode("utf-8", "replace")})
        except ControllerError:
            self._closed = True

    def resize(self, cols: int, rows: int):
        try:
            _request(self._cfg, "POST", f"/remote/terminal/{self._sid}/resize",
                     json_body={"cols": int(cols), "rows": int(rows)})
        except ControllerError:
            pass

    def alive(self) -> bool:
        return not self._closed

    def close(self):
        self._closed = True
        try:
            _request(self._cfg, "POST", f"/remote/terminal/{self._sid}/close")
        except ControllerError:
            pass
