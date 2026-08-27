"""Shared fixtures for the Sysible Connect test-suite.

The data dir is redirected to a temp path BEFORE any backend import, so
auth.DATA_DIR (and hosts.py, which imports it) resolve to an isolated store
rather than the developer's ~/.sysible-connect. The admin is seeded from the
env so login works with a known password.
"""
import os
import tempfile

os.environ["SYSIBLE_CONNECT_DATA"] = tempfile.mkdtemp(prefix="connect-test-")
os.environ.setdefault("SYSIBLE_CONNECT_USER", "admin")
os.environ.setdefault("SYSIBLE_CONNECT_PASSWORD", "test1234")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import backend.app as app_module  # noqa: E402
import backend.auth as auth  # noqa: E402
import backend.hosts as hosts  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate():
    """Empty host store, no Controller connection, and a seeded admin before every
    test, so order never matters."""
    with hosts._LOCK:
        hosts._save({})
    import backend.controller as controller
    controller.disconnect()
    auth.ensure_admin()
    yield


@pytest.fixture
def client():
    """Unauthenticated TestClient."""
    return TestClient(app_module.app)


@pytest.fixture
def auth_client():
    """TestClient with a live admin session (cookies persist on the instance)."""
    c = TestClient(app_module.app)
    r = c.post("/api/login", json={"username": "admin", "password": "test1234"})
    assert r.status_code == 200, r.text
    return c
