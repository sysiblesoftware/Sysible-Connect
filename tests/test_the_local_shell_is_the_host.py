""""Local shell" gave you a shell inside the Connect container.

Reported as "when I open a local shell why does it not have sudo?", from a
prompt reading `connect@65cceb1ed1ce` — a container id, not a server. The
operator was in a minimal Debian image as the unprivileged `connect` user: no
sudo, an empty /opt, and none of the machine they were trying to administer.

Installing sudo there would have answered the error message instead of the
question: root in a throwaway container still cannot see the host.

So LocalSession enters PID 1's namespaces, which needs `pid: host` and the
capabilities to call setns. When it cannot, it falls back to the container shell
and SAYS SO on the first line — a silent fallback is indistinguishable from the
original bug, which is how this went unnoticed in the first place.
"""
import os
import pathlib
import re
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

TERMINALS = (HERE / "backend" / "terminals.py").read_text()
APP = (HERE / "backend" / "app.py").read_text()
COMPOSE = (HERE / "deploy" / "docker-compose.yml").read_text()
DOCKERFILE = (HERE / "deploy" / "Dockerfile").read_text()

from backend import terminals  # noqa: E402


class TestItTriesToReachTheHost:
    def test_it_enters_the_host_namespaces(self):
        assert "nsenter" in TERMINALS
        for ns in ("-m", "-u", "-i", "-n", "-p"):
            assert f'"{ns}"' in TERMINALS, f"namespace flag {ns} is gone"

    def test_it_does_not_run_this_images_shell_on_the_host(self):
        """/bin/bash here may not exist over there, and a login shell must read
        the HOST's profile."""
        assert "command -v bash || command -v sh" in TERMINALS

    def test_availability_is_probed_not_assumed(self):
        """Readable /proc/1/ns/mnt is not the same as enterable: without
        CAP_SYS_ADMIN setns fails at the moment of use, which would be a terminal
        that dies the instant it opens."""
        assert re.search(r'"nsenter",\s*"-t",\s*"1".*"true"', TERMINALS, re.S), \
            "nothing probes that entering actually works"

    def test_it_can_be_refused(self):
        assert "SYSIBLE_CONNECT_HOST_SHELL" in TERMINALS


class TestTheFallbackIsHonest:
    """The original bug was not the container shell — it was not SAYING it was
    one."""

    def test_a_reason_is_kept(self):
        assert "degraded_reason" in TERMINALS

    def test_there_is_a_banner_for_each_case(self):
        assert "def banner" in TERMINALS
        assert "Sysible host shell" in TERMINALS
        assert "NOT the Sysible host" in TERMINALS

    def test_the_container_banner_names_the_symptom_that_was_reported(self):
        assert "no sudo" in TERMINALS, \
            "the banner does not connect itself to what the operator will hit"

    @pytest.mark.parametrize("env", ["0", "no"])
    def test_disabling_it_reports_unavailable_rather_than_crashing(self, env, monkeypatch):
        monkeypatch.setenv("SYSIBLE_CONNECT_HOST_SHELL", env)
        ok, why = terminals.host_shell_available()
        assert ok is False and why

    def test_availability_never_raises(self, monkeypatch):
        """It runs on the path that opens a terminal; an exception here is a
        terminal that will not open at all."""
        monkeypatch.setattr(terminals.shutil, "which", lambda _n: None)
        ok, why = terminals.host_shell_available()
        assert ok is False and "nsenter" in why


class TestTheHostShellIsSuperuserOnly:
    """Terminals are operator-or-superuser. A HOST shell is root on the server,
    which is more than an operator should hold."""

    def test_the_gate_exists(self):
        assert "a host shell needs superuser" in APP

    def test_it_gates_on_what_the_session_would_be(self):
        """A local terminal where the namespaces are unreachable is just a
        container shell and needs no extra privilege."""
        assert "host_shell_available()" in APP

    def test_it_does_not_read_a_conditionally_bound_name(self):
        """`role` is assigned only inside `if gw:`. Reading it unconditionally
        raises NameError on a standalone Connect — a security check that takes
        the whole feature down with it. Caught before this shipped."""
        m = re.search(r'kind = ws\.query_params\.get\("kind", "local"\)(.*?)\n    # A shell was handed out',
                      APP, re.S)
        assert m, "the terminal gate is not in the expected shape"
        # The check is about what the CODE reads, so strip the two things that
        # legitimately contain the word: comment prose, and the header name
        # "x-sysible-role" inside a string literal. Both matched a naive regex
        # and made this test fail on correct code.
        gate = "\n".join(l for l in m.group(1).splitlines()
                         if not l.strip().startswith("#"))
        gate = re.sub(r'"[^"]*"|\'[^\']*\'', '""', gate)
        assert re.search(r"(?<![_\w.-])role(?![_\w])", gate) is None, \
            "the gate reads `role`, which does not exist on a standalone Connect"


class TestTheContainerIsBuiltForIt:
    def test_compose_shares_the_host_pid_namespace(self):
        import yaml
        c = yaml.safe_load(COMPOSE)["services"]["connect"]
        assert c.get("pid") == "host", "PID 1 is this container's init, so nsenter has nothing to enter"
        assert "SYS_ADMIN" in (c.get("cap_add") or []), "setns will be denied"

    def test_compose_says_what_it_grants(self):
        assert "root on the Sysible host" in COMPOSE, \
            "a reader of this file cannot see what these three settings hand out"

    def test_the_image_has_nsenter(self):
        assert "util-linux" in DOCKERFILE
        assert "command -v nsenter" in DOCKERFILE, \
            "a base that drops util-linux would silently turn every local shell "\
            "back into a container shell"
