"""Host reachability ping (TCP connect), incl. the via-Controller (no-address) case."""
import backend.hosts as hosts


def test_ping_requires_auth(client):
    assert client.post("/api/hosts/ping").status_code == 401


def test_ping_reports_reachability(auth_client):
    # A closed local port → reachable False; a no-address controller host → None.
    auth_client.post("/api/hosts", json={"name": "closed", "address": "127.0.0.1", "user": "root", "port": 1})
    hosts.upsert_controller_host("nat-box", address="", environment="dev", transport="agent")
    res = {x["name"]: x for x in auth_client.post("/api/hosts/ping").json()["results"]}
    assert res["closed"]["reachable"] is False
    assert res["nat-box"]["reachable"] is None and "Controller" in res["nat-box"]["detail"]
