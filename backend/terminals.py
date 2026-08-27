"""Terminal sessions for Sysible Connect.

Two kinds, one interface (read/write/resize/alive/close):
  * LocalSession — a shell on the Connect server itself, via a real PTY.
  * SshSession   — an interactive shell on a managed host, via paramiko.

Each session's read() BLOCKS until data (or EOF → b""), so the app runs one
reader thread per session and pumps bytes to the websocket. Writes and resizes
come back the other way. Secrets (host password/key) never leave the backend.
"""
from __future__ import annotations

import fcntl
import io
import os
import pty
import shutil
import struct
import subprocess
import termios


class LocalSession:
    """A login shell on the Connect host, wired to a PTY."""

    kind = "local"

    def __init__(self, cols: int = 80, rows: int = 24, cwd: str | None = None):
        shell = os.environ.get("SHELL") or shutil.which("bash") or "/bin/sh"
        self.master, slave = pty.openpty()
        self._set_size(cols, rows)
        env = dict(os.environ, TERM="xterm-256color")
        self.proc = subprocess.Popen(
            [shell, "-l"], stdin=slave, stdout=slave, stderr=slave,
            preexec_fn=os.setsid, env=env, cwd=cwd or os.path.expanduser("~"), close_fds=True)
        os.close(slave)

    def _set_size(self, cols: int, rows: int):
        try:
            fcntl.ioctl(self.master, termios.TIOCSWINSZ,
                        struct.pack("HHHH", max(1, rows), max(1, cols), 0, 0))
        except OSError:
            pass

    def read(self, n: int = 65536) -> bytes:
        try:
            return os.read(self.master, n)
        except OSError:
            return b""

    def write(self, data: bytes):
        try:
            os.write(self.master, data)
        except OSError:
            pass

    def resize(self, cols: int, rows: int):
        self._set_size(cols, rows)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def close(self):
        try:
            self.proc.terminate()
        except Exception:  # noqa: BLE001
            pass
        try:
            os.close(self.master)
        except OSError:
            pass


def _load_private_key(text: str):
    import paramiko
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except Exception:  # noqa: BLE001 — wrong type, try the next
            continue
    raise ValueError("Unsupported or encrypted private key.")


class SshSession:
    """An interactive shell on a managed host over SSH (paramiko)."""

    kind = "ssh"

    def __init__(self, host: dict, cols: int = 80, rows: int = 24):
        import paramiko
        addr = str(host.get("address", "")).strip("[]")
        user = str(host.get("user") or "root")
        port = int(host.get("port", 22))
        self.client = paramiko.SSHClient()
        # TODO: pin host keys (known_hosts) — AutoAdd is the MVP default.
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        base = dict(hostname=addr, port=port, username=user, timeout=20, banner_timeout=20)
        if host.get("key"):
            self.client.connect(pkey=_load_private_key(host["key"]),
                                allow_agent=False, look_for_keys=False, **base)
        elif host.get("password"):
            self.client.connect(password=host["password"],
                                allow_agent=False, look_for_keys=False, **base)
        else:
            # No stored credential — fall back to the agent / default keys.
            self.client.connect(allow_agent=True, look_for_keys=True, **base)
        self.chan = self.client.invoke_shell(term="xterm-256color", width=cols, height=rows)
        self.chan.settimeout(None)   # blocking recv → one reader thread per session

    def read(self, n: int = 65536) -> bytes:
        try:
            return self.chan.recv(n)          # b"" on EOF
        except Exception:  # noqa: BLE001
            return b""

    def write(self, data: bytes):
        try:
            self.chan.sendall(data)
        except Exception:  # noqa: BLE001
            pass

    def resize(self, cols: int, rows: int):
        try:
            self.chan.resize_pty(width=max(1, cols), height=max(1, rows))
        except Exception:  # noqa: BLE001
            pass

    def alive(self) -> bool:
        return not self.chan.closed

    def close(self):
        try:
            self.chan.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.client.close()
        except Exception:  # noqa: BLE001
            pass


def open_session(kind: str, *, host: dict | None = None, cols: int = 80, rows: int = 24):
    """Factory: 'local' → a server shell; 'ssh' → direct SSH to `host`;
    'controller' → a shell on a Controller-managed host, proxied THROUGH the
    connected Controller (agent PTY or its SSH key), so no local credential and no
    inbound SSH to the host are needed."""
    if kind == "controller":
        if not host or not host.get("name"):
            raise ValueError("A Controller terminal needs a host.")
        from . import controller   # lazy: local shells don't need requests
        return controller.TerminalProxy(str(host["name"]), cols, rows)
    if kind == "ssh":
        if not host:
            raise ValueError("An SSH terminal needs a host.")
        return SshSession(host, cols, rows)
    return LocalSession(cols, rows)
