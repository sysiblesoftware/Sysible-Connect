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
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3.connection
import urllib3.connectionpool

from .auth import DATA_DIR
from . import hosts as host_store
from . import secret

_CFG = DATA_DIR / "controller.json"
_CA = DATA_DIR / "controller_ca.pem"

# ---------------------------------------------------- SLOP SSO auto-attach
# In the SLOP stack every app runs behind the gateway on one host, and the gateway
# stamps X-Sysible-Auth (the shared secret) on every request. When Connect is in SSO
# trust mode AND told where the local Controller's backend API is, it attaches to it
# AUTOMATICALLY — no operator "log in to the Controller" step and no machine API key to
# provision: Connect proves it's a trusted co-located app by presenting that same shared
# secret to the Controller (which trusts the gateway secret on its fleet/remote routes).
# A manually-saved connection still wins, so standalone Connect is unchanged.
_TRUST_GATEWAY = os.getenv("SYSIBLE_CONNECT_TRUST_GATEWAY_AUTH", "0") == "1"
_SSO_SECRET = os.getenv("SYSIBLE_SSO_SHARED_SECRET", "")
# The local Controller backend API (e.g. https://sysible-controller:9000). Set by the
# SLOP orchestrator; use the Controller's service name / LAN address, not localhost
# (the SSRF guard blocks loopback, and in the compose stack services address each other
# by name anyway).
_LOCAL_CONTROLLER_URL = os.getenv("SYSIBLE_CONNECT_CONTROLLER_URL", "").strip()
# The Controller backend API port (published on the same host in the SLOP stack).
_CONTROLLER_PORT = (os.getenv("SYSIBLE_CONNECT_CONTROLLER_PORT", "9000").strip() or "9000")
# In SSO mode, if no explicit Controller URL is configured, DERIVE one from the host the
# browser reached Connect on (the gateway host) + the Controller's port — so auto-attach
# "just works" behind the gateway with zero extra config, exactly like when Connect was
# embedded in the Controller. Cached once a request tells us the host (status() runs on
# page load), so the tokenless terminal/sync paths — which have no request — can use it.
_DERIVED_CONTROLLER_URL = None


def note_gateway_host(host: str) -> None:
    """Record the host the browser reached Connect on so SSO auto-attach can target the
    local Controller at https://<host>:<port> when no explicit SYSIBLE_CONNECT_CONTROLLER_URL
    is set. No-op unless SSO trust is on and no explicit URL is configured."""
    global _DERIVED_CONTROLLER_URL
    if _LOCAL_CONTROLLER_URL or not (_TRUST_GATEWAY and _SSO_SECRET):
        return
    h = (host or "").strip()
    if not h:
        return
    # Strip a :port from a host:port form; leave an IPv6 literal ([..]) alone.
    if not h.startswith("[") and ":" in h:
        h = h.rsplit(":", 1)[0]
    _DERIVED_CONTROLLER_URL = f"https://{h}:{_CONTROLLER_PORT}"


def _sso_cfg() -> dict | None:
    """The auto-attach config for the local Controller when SSO trust mode is active
    (trust on + shared secret) AND a Controller URL is known — configured explicitly, or
    derived from the gateway host. Marked sso=True so the request path authenticates with
    the shared secret instead of a machine API key."""
    if not (_TRUST_GATEWAY and _SSO_SECRET):
        return None
    url = _LOCAL_CONTROLLER_URL or (_DERIVED_CONTROLLER_URL or "")
    if not url:
        return None
    return {"base_url": _normalize(url), "sso": True, "tls_cert": ""}


class ControllerError(Exception):
    pass


# ------------------------------------------------------- SSRF pin (peer re-check)
# _guard_url resolves + validates the target's addresses up front, but `requests`
# (and ssl) re-resolve the hostname independently, so a DNS-rebinding / TTL-0 flip
# between the check and the connect could still land on an internal address (e.g.
# cloud metadata 169.254.169.254). To close that TOCTOU gap, every outbound call
# goes through a session whose connections re-validate the ACTUAL peer address at
# TCP connect time and abort BEFORE any request bytes / credentials are sent.
def _blocked_ip(ip) -> bool:
    """True if `ip` (an ipaddress address) is one an on-host SSRF must never reach:
    loopback, link-local (incl. cloud metadata), unspecified, multicast or reserved.
    Private LAN ranges are intentionally allowed (real on-prem Controllers)."""
    return (ip.is_loopback or ip.is_link_local or ip.is_unspecified
            or ip.is_multicast or ip.is_reserved)


def _vet_addr(raw: str):
    """Parse `raw` to an ipaddress, collapsing an IPv4-mapped / NAT64 IPv6 form to the
    embedded IPv4 first so e.g. ::ffff:169.254.169.254 can't smuggle a blocked address
    past the v6 checks. Returns None if it doesn't parse."""
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def _assert_peer_allowed(sock) -> None:
    try:
        peer = sock.getpeername()[0]
    except OSError:
        return
    ip = _vet_addr(peer)
    if ip is not None and _blocked_ip(ip):
        try:
            sock.close()
        except OSError:
            pass
        raise OSError(f"SSRF guard: refusing to send to blocked peer address {peer}")


class _PinnedHTTPSConnection(urllib3.connection.HTTPSConnection):
    def connect(self):
        super().connect()
        _assert_peer_allowed(self.sock)


class _PinnedHTTPConnection(urllib3.connection.HTTPConnection):
    def connect(self):
        super().connect()
        _assert_peer_allowed(self.sock)


class _PinnedHTTPSPool(urllib3.connectionpool.HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class _PinnedHTTPPool(urllib3.connectionpool.HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _SsrfGuardAdapter(requests.adapters.HTTPAdapter):
    """A requests adapter whose connections re-validate the peer address at TCP connect
    time and abort if it's a blocked (internal) address — closing the DNS-rebinding
    window a resolve-then-connect guard alone leaves open."""

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": _PinnedHTTPPool, "https": _PinnedHTTPSPool}


_SESSION = requests.Session()
_SESSION.mount("https://", _SsrfGuardAdapter())
_SESSION.mount("http://", _SsrfGuardAdapter())


def _do_request(method, url, *, headers=None, json_body=None, verify=None, timeout=20):
    """Single outbound-HTTP choke point for all Controller calls. Routes through the
    SSRF-pinned session so a peer that rebinds to an internal address is refused before
    the request is sent. Tests patch THIS seam to mock the Controller's API."""
    return _SESSION.request(method, url, headers=headers, json=json_body,
                            verify=verify, timeout=timeout)


# --------------------------------------------------------------- config store
def _read_nofollow(path) -> bytes:
    """Read a file refusing to follow a symlink at the final component (O_NOFOLLOW),
    so a pre-planted symlink at the path can't redirect the read to a substituted file."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return os.read(fd, 1_000_000)
    finally:
        os.close(fd)


def _write_nofollow(path, data: bytes) -> None:
    """Write `data` to `path` at 0600: create race-safe (O_EXCL|O_NOFOLLOW) on first
    write, overwrite in place (O_NOFOLLOW|O_TRUNC) thereafter — never following a
    pre-planted symlink, closing the create race and the symlink-redirect on rewrite."""
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fd = os.open(str(path), os.O_WRONLY | os.O_NOFOLLOW | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _load() -> dict:
    try:
        d = json.loads(_read_nofollow(_CFG))
    except (OSError, ValueError, json.JSONDecodeError):
        # No manually-saved connection → auto-attach to the local Controller in SSO mode.
        return _sso_cfg() or {}
    if not isinstance(d, dict):
        return _sso_cfg() or {}
    # API key is stored encrypted (api_key_enc); decrypt into memory. A legacy
    # plaintext api_key is tolerated and re-encrypted on the next save.
    if d.get("api_key_enc"):
        d["api_key"] = secret.decrypt(d.pop("api_key_enc"))
    # The admin identity token (for run-as attribution) is stored encrypted too.
    if d.get("admin_token_enc"):
        d["admin_token"] = secret.decrypt(d.pop("admin_token_enc"))
    return d


def _save(cfg: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    out = dict(cfg)
    if out.get("api_key"):
        out["api_key_enc"] = secret.encrypt(out.pop("api_key"))
    out.pop("api_key", None)          # never write the key in plaintext
    if out.get("admin_token"):
        out["admin_token_enc"] = secret.encrypt(out.pop("admin_token"))
    out.pop("admin_token", None)      # never write the identity token in plaintext
    _write_nofollow(_CFG, json.dumps(out).encode())


def status(host: str = None, identity: dict = None) -> dict:
    """Public connection state — never includes the API key. `host` (the gateway host
    the browser reached Connect on) lets SSO auto-attach derive the local Controller URL
    when none is configured. `identity` is the acting operator from the gateway headers
    on THIS request, used to report the run-as under SSO."""
    if host:
        note_gateway_host(host)
    cfg = _load()
    # Connected when we hold a machine API key (manual attach) OR we're auto-attached to
    # the local Controller over SSO (shared-secret transport, no key needed).
    connected = bool(cfg.get("base_url") and (cfg.get("api_key") or cfg.get("sso")))
    # Who terminals/exec run AS on the hosts (that account + its sudo), and who the
    # Controller attributes them to.
    #   * manual username/password attach -> the saved admin_user (a stored token),
    #   * SSO auto-attach -> the operator on THIS request, forwarded per call from the
    #     gateway headers (there is no stored identity, and there must not be one: the
    #     run-as has to follow whoever is signed in, not whoever attached).
    # It used to read admin_user only, which is never set under SSO, so the console
    # showed "API-key connect (no run-as)" for a signed-in operator on an SSO attach.
    run_as = cfg.get("admin_user", "")
    if not run_as and cfg.get("sso") and identity:
        run_as = (identity.get("user") or "")
    return {"connected": connected,
            "base_url": cfg.get("base_url", ""),
            # True when the connection is the automatic local SSO attach (no manual
            # Controller login) rather than a saved URL + key.
            "sso": bool(cfg.get("sso")),
            "run_as": run_as}


def connect_with_credentials(base_url: str, username: str, password: str, totp_code: str = "") -> dict:
    """Connect using a Controller superuser's console username + password: exchange
    them for the backend API key via POST /auth/api-key (the friendly path, same as
    SLEP), TOFU-pin the cert, then save. Returns the public status."""
    base = _normalize(base_url)
    if not base:
        raise ControllerError("Controller URL is required.")
    if not (username and password):
        raise ControllerError("Controller username and password are required.")
    _guard_url(base)
    payload = {"username": username, "password": password}
    if totp_code:
        payload["totp_code"] = totp_code
    cert = ""
    try:
        resp = _do_request("POST", base + "/auth/api-key", json_body=payload, verify=True, timeout=20)
    except requests.exceptions.SSLError:
        cert = _fetch_server_cert(base)
        resp = _do_request("POST", base + "/auth/api-key", json_body=payload,
                          verify=_ca_path(cert), timeout=20)
    except requests.exceptions.RequestException as e:
        raise ControllerError(f"could not reach the Controller at {base}: {e}")
    if resp.status_code == 404:
        raise ControllerError("This Controller doesn't support username/password connect (older "
                              "build) — use its backend API key instead.")
    if resp.status_code in (401, 403, 429):
        detail = "The Controller rejected those credentials."
        try:
            detail = resp.json().get("detail") or detail
        except ValueError:
            pass
        raise ControllerError(detail)
    if resp.status_code != 200:
        raise ControllerError(f"The Controller returned HTTP {resp.status_code}.")
    try:
        data = resp.json()
    except ValueError:
        raise ControllerError("The Controller's response was not JSON.")
    if data.get("status") == "mfa_required":
        raise ControllerError("This account uses multi-factor authentication — add the current code.")
    key = data.get("api_key")
    if not key:
        raise ControllerError("The Controller did not return an API key.")
    cfg = {"base_url": base, "api_key": str(key), "tls_cert": cert}
    # Also mint an admin IDENTITY token for this operator via /admin/login, so the
    # Controller runs terminals/exec as their own run-as account (attributed, sudo-
    # constrained) instead of root. Best-effort: if it can't be obtained (older
    # Controller, MFA, non-superuser), we still connect — terminals just fall back to
    # the Controller's default account, exactly as before.
    cfg["admin_token"] = _mint_admin_token(cfg, username, password, totp_code)
    if cfg["admin_token"]:
        cfg["admin_user"] = username    # who terminals/exec run as (shown in the UI)
    r = _request(cfg, "GET", "/remote/hosts")   # validate the exchanged key
    if r.status_code != 200:
        raise ControllerError(f"Connected, but /remote/hosts returned HTTP {r.status_code}.")
    _save(cfg)
    return status()


def _mint_admin_token(cfg: dict, username: str, password: str, totp_code: str = "") -> str:
    """Exchange the operator's console credentials for a Controller admin identity
    token (POST /admin/login, which itself needs the API key we just got). The token
    lets dispatch attribute and run tasks AS this operator's account. Returns "" on
    any failure — run-as is a best-effort enhancement, never a connect blocker."""
    payload = {"username": username, "password": password}
    if totp_code:
        payload["totp_code"] = totp_code
    try:
        r = _request(cfg, "POST", "/admin/login", json_body=payload, timeout=20)
    except ControllerError:
        return ""
    if r.status_code != 200:
        return ""
    try:
        return str(r.json().get("token") or "")
    except ValueError:
        return ""


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


def _guard_url(url: str) -> list[str]:
    """SSRF guard (parity with SLEP): resolve the Controller host and refuse
    loopback, link-local (incl. cloud metadata 169.254.169.254), unspecified,
    multicast and reserved addresses, so 'connect a Controller' can't be aimed at an
    internal service. Private LAN ranges stay allowed (real on-prem Controllers).

    FAILS CLOSED: an unresolvable host is a hard rejection (not an allow), and EVERY
    resolved address must pass — a single blocked address rejects the whole name, so
    a split-horizon / partly-internal answer can't slip through. Returns the vetted
    address list so callers can pin the connection to a checked IP."""
    host = urlparse(url).hostname or ""
    if not host:
        raise ControllerError("Invalid Controller URL.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ControllerError(
            f"Refusing to connect to {host}: its address could not be resolved ({e}).")
    vetted: list[str] = []
    for info in infos:
        raw = info[4][0]
        ip = _vet_addr(raw)
        if ip is None:
            continue
        if _blocked_ip(ip):
            raise ControllerError(
                f"Refusing to connect to {host} ({ip}): loopback/link-local/reserved "
                "addresses (including cloud metadata) are blocked.")
        vetted.append(raw)
    if not vetted:
        raise ControllerError(f"Refusing to connect to {host}: it resolved to no usable address.")
    return vetted


# ------------------------------------------------------------------ TLS TOFU
def _ca_path(pem: str) -> str | None:
    if not pem:
        return None
    _write_nofollow(_CA, pem.encode())
    return str(_CA)


def _fetch_server_cert(base_url: str) -> str:
    u = urlparse(base_url)
    if u.scheme != "https" or not u.hostname:
        raise ControllerError("A certificate can only be pinned for an https Controller URL.")
    # Pin the cert fetch to a vetted address (parity with the request path): resolve +
    # validate, then connect the TLS socket directly to that IP with SNI = hostname, so
    # ssl's own re-resolution can't be rebound to an internal service.
    ip = _guard_url(base_url)[0]
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False          # TOFU: we're fetching an untrusted cert to pin it
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, u.port or 443), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=u.hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
        return ssl.DER_cert_to_PEM_cert(der)
    except ControllerError:
        raise
    except Exception as e:  # noqa: BLE001
        raise ControllerError(f"could not fetch the Controller's certificate: {e}")


# ------------------------------------------------------------- HTTP transport
def _request(cfg: dict, method: str, path: str, *, json_body=None, timeout=20, identity=None):
    """One Controller API call; trust-on-first-use the self-signed cert on a verify
    failure (pin it into cfg and retry once).

    Auth is one of two modes:
      * SSO auto-attach (cfg['sso']): present the SLOP shared secret as X-Sysible-Auth,
        which the local Controller trusts on its fleet/remote routes — no machine key.
        `identity` = {"user","role"} forwards the acting operator (from the gateway
        headers on the incoming request) for attribution/run-as.
      * Manual attach: the stored machine API key (X-API-Key), plus the admin identity
        token when we hold one (username/password connect)."""
    url = cfg["base_url"] + path
    if cfg.get("sso"):
        headers = {"X-Sysible-Auth": _SSO_SECRET}
        # Forward the acting operator so the Controller attributes/runs-as them, exactly
        # as the gateway would. Best-effort — the shared secret is what authenticates.
        if identity and identity.get("user"):
            headers["X-Sysible-User"] = identity["user"]
            if identity.get("role"):
                headers["X-Sysible-Role"] = identity["role"]
    else:
        headers = {"X-API-Key": cfg["api_key"]}
        # Attributed "run-as" identity: when we hold an admin token (username/password
        # connect), send it so the Controller runs terminals/exec AS that operator's
        # own account with their sudo — not as the SSH login user (root). Without it the
        # Controller falls back to the tokenless root path.
        if cfg.get("admin_token"):
            headers["X-Sysible-Admin-Token"] = cfg["admin_token"]
    verify = _ca_path(cfg.get("tls_cert", "")) or True
    try:
        return _do_request(method, url, headers=headers, json_body=json_body,
                           verify=verify, timeout=timeout)
    except requests.exceptions.SSLError:
        pem = _fetch_server_cert(cfg["base_url"])
        cfg["tls_cert"] = pem
        return _do_request(method, url, headers=headers, json_body=json_body,
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
    if not cfg.get("sso"):
        _save(cfg)   # persist a cert refreshed by TOFU during the calls
    # (In SSO auto-attach mode we don't persist — the env stays authoritative for the
    #  local Controller URL, and the cert re-pins cheaply on each sync.)

    imported = skipped = 0
    online_n = offline_n = 0
    # An agent is "offline" when its last heartbeat is older than this many seconds —
    # matching the Controller's own health threshold (SYSIBLE_HEALTH_OFFLINE_S, default
    # 300). Override on Connect with SYSIBLE_CONNECT_OFFLINE_S if needed.
    now = time.time()
    offline_after = int(os.getenv("SYSIBLE_CONNECT_OFFLINE_S") or 300)

    def _imp(name, address, user, port, environment, transport, online=None, last_seen=0):
        nonlocal imported, skipped
        name = (name or "").strip()
        if not host_store.valid_name(name):
            skipped += 1
            return
        # address may be blank for a NAT'd agent — that's fine, the terminal proxies
        # by NAME through the Controller and never dials the address directly.
        host_store.upsert_controller_host(
            name, address=address or "", user=user or "root", port=int(port or 22),
            environment=environment or "", transport=transport,
            online=online, last_seen=last_seen)
        imported += 1

    for name, h in ssh_hosts.items():
        h = h or {}
        # SSH hosts on the Controller are targets, not heartbeating agents — liveness
        # is unknown here, so leave online=None (Connect can still TCP-ping them).
        _imp(name, str(h.get("ip", "")), str(h.get("user") or "root"),
             h.get("port", 22), str(h.get("environment", "")), "ssh")
    for a in agents:
        a = a or {}
        if a.get("revoked"):
            continue   # a revoked agent isn't a usable host — don't import it
        last_seen = float(a.get("last_seen") or 0)
        # online iff the Controller heard from it within the window; unknown if it has
        # never reported (last_seen 0) — treat that as offline so it isn't shown green.
        online = (now - last_seen) <= offline_after if last_seen else False
        online_n += 1 if online else 0
        offline_n += 0 if online else 1
        _imp(str(a.get("hostname", "")), str(a.get("ip", "")), "root", 22,
             str(a.get("environment", "")), "agent", online=online, last_seen=last_seen)

    return {"imported": imported, "skipped": skipped,
            "ssh_hosts": len(ssh_hosts), "agents": len(agents),
            "online": online_n, "offline": offline_n,
            "controller": cfg["base_url"]}


# --------------------------------------------------- terminal proxy transport
class TerminalProxy:
    """A live terminal on a Controller-managed host, driven over the Controller's
    HTTP terminal API. Presents the same read/write/resize/alive/close interface as
    the local/SSH sessions so the websocket pump doesn't care how it's transported.
    read() long-polls the Controller and blocks until output arrives or the shell
    ends (b'')."""

    kind = "controller"

    def __init__(self, host_name: str, cols: int = 80, rows: int = 24, identity: dict = None):
        self._cfg = _load()
        if not self._cfg.get("base_url"):
            raise ControllerError("No Controller connected.")
        self._closed = False
        # The acting operator, forwarded on EVERY call in this session (not just the
        # open): the Controller resolves the run-as identity per request, so a read or
        # write without it would fall back to the default account mid-session.
        self._ident = identity or None
        # One-shot: a stalled session explains itself once, not on every poll.
        self._told_waiting = False
        r = _request(self._cfg, "POST", f"/remote/hosts/{host_name}/terminal/open",
                     identity=self._ident)
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
                r = _request(self._cfg, "GET", f"/remote/terminal/{self._sid}/read",
                             timeout=60, identity=self._ident)
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
                self._told_waiting = True   # real output — never explain again
                return data.encode("utf-8", "replace")
            if self._closed:
                return b""
            # The open only QUEUES work for the host's agent, so a terminal can
            # connect and then draw nothing at all — a blank pane with a cursor and
            # no clue whether the agent has not collected the request yet, took it
            # and went quiet, or is not checking in. The Controller works out which
            # and says so; show it once, dimmed, instead of an empty screen.
            why = body.get("waiting")
            if why and not self._told_waiting:
                self._told_waiting = True
                return (f"\r\n\x1b[90m[sysible] {why}\x1b[0m\r\n").encode()
            # idle long-poll returned nothing — poll again (the Controller side waits)
        return b""

    def read_available(self, timeout: float = 0.7) -> bytes:
        """One read poll for fleet capture (the Controller side long-polls briefly and
        returns, possibly empty). b'' means idle-or-closed."""
        if self._closed:
            return b""
        try:
            r = _request(self._cfg, "GET", f"/remote/terminal/{self._sid}/read",
                         timeout=60, identity=self._ident)
        except ControllerError:
            self._closed = True
            return b""
        if r.status_code != 200:
            self._closed = True
            return b""
        body = r.json()
        if body.get("closed"):
            self._closed = True
        return (body.get("data") or "").encode("utf-8", "replace")

    def write(self, data: bytes):
        try:
            _request(self._cfg, "POST", f"/remote/terminal/{self._sid}/write",
                     json_body={"data": data.decode("utf-8", "replace")},
                     identity=self._ident)
        except ControllerError:
            self._closed = True

    def resize(self, cols: int, rows: int):
        try:
            _request(self._cfg, "POST", f"/remote/terminal/{self._sid}/resize",
                     json_body={"cols": int(cols), "rows": int(rows)},
                     identity=self._ident)
        except ControllerError:
            pass

    def alive(self) -> bool:
        return not self._closed

    def close(self):
        self._closed = True
        try:
            _request(self._cfg, "POST", f"/remote/terminal/{self._sid}/close",
                     identity=self._ident)
        except ControllerError:
            pass
