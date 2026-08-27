"""SSH host inventory: add, list (secrets never leave the backend), and delete
via Connect's own `/api/hosts` API (cookie-authenticated)."""


def test_add_then_delete(auth_client):
    auth_client.post("/api/hosts", json={"name": "box", "address": "10.0.0.9", "user": "root"})
    assert any(h["name"] == "box" for h in auth_client.get("/api/hosts").json()["hosts"])

    r = auth_client.delete("/api/hosts/box")
    assert r.status_code == 200 and r.json()["deleted"] is True
    assert not any(h["name"] == "box" for h in auth_client.get("/api/hosts").json()["hosts"])


def test_delete_missing_is_false(auth_client):
    r = auth_client.delete("/api/hosts/nope")
    assert r.status_code == 200 and r.json()["deleted"] is False


def test_secrets_never_returned(auth_client):
    auth_client.post("/api/hosts", json={"name": "sec", "address": "10.0.0.9",
                                         "user": "root", "password": "s3cret", "key": "PRIVKEY"})
    h = next(x for x in auth_client.get("/api/hosts").json()["hosts"] if x["name"] == "sec")
    # The list surfaces has_password/has_key flags, never the stored secret material.
    assert "password" not in h and "key" not in h
    assert h["has_password"] is True and h["has_key"] is True


def test_list_and_delete_require_auth(client):
    assert client.get("/api/hosts").status_code == 401
    assert client.delete("/api/hosts/anything").status_code == 401
