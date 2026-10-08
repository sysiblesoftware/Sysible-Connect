"""The console port must be restrictable.

This file's own compose comment has said "the SLOP installer wires this up" since
before the installer did — publishing :8700 on every interface let a LAN client
hit Connect directly and skip Caddy, and with it the gateway's HSTS/CSP/frame
headers and the platform's central login throttle. (Not a way in: Connect fails
closed without the shared secret. Surface area, which is still worth removing.)

The installer now sets this bind to the docker bridge gateway, the address Caddy
reaches Connect through.
"""
import re
from pathlib import Path

COMPOSE = (Path(__file__).resolve().parents[1] / "deploy" / "docker-compose.yml").read_text(
    encoding="utf-8")


def _console_line():
    for ln in COMPOSE.splitlines():
        if re.match(r'^\s*-\s*"[^"]*8700:8700', ln):
            return ln.strip()
    raise AssertionError("no 8700 port mapping in deploy/docker-compose.yml")


def test_the_console_bind_is_a_variable():
    assert "SYSIBLE_CONNECT_BIND" in _console_line(), "the console port is not restrictable"


def test_it_defaults_to_every_interface():
    """A STANDALONE Connect has no gateway in front of it, so the default has to
    stay what it always was. Only the installer narrows it."""
    assert "${SYSIBLE_CONNECT_BIND:-0.0.0.0}" in _console_line(), _console_line()
