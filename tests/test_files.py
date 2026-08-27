"""File transfer routing/error paths (SFTP itself needs a live host)."""
import backend.hosts as hosts


def test_files_list_requires_auth(client):
    assert client.post("/api/hosts/x/files/list", json={"path": "."}).status_code == 401


def test_files_controller_host_rejected(auth_client):
    # A controller-synced host can't do file transfer with just the machine key (F1).
    hosts.upsert_controller_host("web1", address="10.0.0.11", transport="agent")
    r = auth_client.post("/api/hosts/web1/files/list", json={"path": "."})
    assert r.status_code == 400 and "Controller-scoped token" in r.json()["detail"]


def test_files_missing_host(auth_client):
    r = auth_client.post("/api/hosts/nope/files/list", json={"path": "."})
    assert r.status_code == 400 and "not found" in r.json()["detail"].lower()
