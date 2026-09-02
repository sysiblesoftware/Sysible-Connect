"""Sysible Connect — the append-only audit trail.

Connect is the one app that hands an operator a real shell on a real host, yet it
kept no record of who did what: logins, terminal sessions, fleet commands, file
transfers and inventory changes all left no trace. This module is that record.

Storage matches the rest of Connect: one small file under DATA_DIR, written with
the same symlink-refusing hardening as auth.py / secret.py (O_NOFOLLOW, 0600).
It is JSON Lines and strictly APPEND-ONLY, so a write is a single short line and
concurrent writers can't interleave a partial record.

The read shape — {"entries": [{id, ts, actor, action, target, detail, ok}]},
newest first, with a since_id cursor — deliberately matches SLEP's /audit and
Flashback's /api/audit so Sysible Visualizer aggregates every app the same way.

NEVER log a secret. Host passwords/keys, the Controller password/api_key/totp,
typed terminal input and command OUTPUT must not reach this file; callers pass
only identifying metadata (who, what action, which target).
"""
from __future__ import annotations

import json
import os
import threading
import time

from .auth import DATA_DIR

_AUDIT_FILE = DATA_DIR / "audit.jsonl"
_LOCK = threading.RLock()

# Bound the file so a long-lived console can't grow it without limit. When it goes
# over, the oldest entries are dropped (authorized retention, like the Controller's).
MAX_ROWS = int(os.getenv("SYSIBLE_CONNECT_AUDIT_MAX_ROWS", "5000"))

_next_id = None          # lazily seeded from the file, then kept in memory


def _read_all() -> list[dict]:
    """Every entry, oldest first. A corrupt line is skipped rather than fatal —
    an unreadable audit file must never take the console down."""
    try:
        fd = os.open(str(_AUDIT_FILE), os.O_RDONLY | os.O_NOFOLLOW)
    except (FileNotFoundError, OSError):
        return []
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            out = []
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    out.append(rec)
            return out
    except OSError:
        return []


def _trim_locked(entries: list[dict]) -> None:
    """Rewrite the file keeping only the newest MAX_ROWS entries."""
    keep = entries[-MAX_ROWS:]
    tmp = _AUDIT_FILE.with_suffix(".jsonl.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for rec in keep:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    os.replace(str(tmp), str(_AUDIT_FILE))


def log(actor: str, action: str, target: str = "", detail: str = "", ok: bool = True) -> None:
    """Append one entry. NEVER raises: an audit write failing must not break the
    action the user asked for (it is a record of the work, not part of it)."""
    global _next_id
    try:
        with _LOCK:
            existing = None
            if _next_id is None:
                existing = _read_all()
                _next_id = max((int(r.get("id") or 0) for r in existing), default=0) + 1
            rec = {
                "id": _next_id,
                "ts": time.time(),
                "actor": str(actor or ""),
                "action": str(action or ""),
                "target": str(target or ""),
                "detail": str(detail or "")[:2000],
                "ok": bool(ok),
            }
            _next_id += 1
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(_AUDIT_FILE),
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            # Trim occasionally rather than on every write.
            if rec["id"] % 500 == 0:
                entries = existing if existing is not None else _read_all()
                if len(entries) > MAX_ROWS:
                    _trim_locked(entries)
    except Exception:
        pass


def list_entries(limit: int = 100, since_id: int = 0) -> list[dict]:
    """Newest-first entries with id > since_id. Limit clamped 1..500, matching the
    other Sysible apps' audit read contract."""
    limit = max(1, min(int(limit or 100), 500))
    since_id = max(0, int(since_id or 0))
    with _LOCK:
        entries = _read_all()
    rows = [r for r in entries if int(r.get("id") or 0) > since_id]
    rows.sort(key=lambda r: int(r.get("id") or 0), reverse=True)
    return rows[:limit]
