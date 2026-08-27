"""Security: SSH host fields (name / address / user) are strictly validated on
ingest so nothing option-looking or shell-metacharacter-laden is ever stored.

Connect opens SSH sessions with paramiko (hostname/username/port as separate
parameters — no shell argv), so there is no ssh-option-injection surface even
before this; the validation is defense-in-depth and keeps the stored inventory
clean. `POST /api/hosts` answers 400 on a rejected field.
"""


def _add(auth_client, **body):
    return auth_client.post("/api/hosts", json=body)


def test_option_injection_user_rejected(auth_client):
    r = _add(auth_client, name="evil", address="1.2.3.4", user="-oProxyCommand=sh -c id #")
    assert r.status_code == 400, r.text


def test_metachars_in_address_rejected(auth_client):
    r = _add(auth_client, name="evil2", address="1.2.3.4; touch /tmp/x", user="root")
    assert r.status_code == 400


def test_leading_dash_address_rejected(auth_client):
    r = _add(auth_client, name="evil3", address="-oProxyCommand=x", user="root")
    assert r.status_code == 400


def test_space_in_address_rejected(auth_client):
    r = _add(auth_client, name="evil4", address="1.2.3.4 -oProxyCommand=x", user="root")
    assert r.status_code == 400


def test_bad_name_rejected(auth_client):
    r = _add(auth_client, name="../etc/passwd", address="1.2.3.4", user="root")
    assert r.status_code == 400


def test_bad_port_rejected(auth_client):
    r = _add(auth_client, name="p", address="1.2.3.4", user="root", port=70000)
    assert r.status_code == 400


def test_valid_host_accepted(auth_client):
    r = _add(auth_client, name="web1", address="10.0.0.5", user="deploy", port=2222)
    assert r.status_code == 200, r.text
    names = [h["name"] for h in auth_client.get("/api/hosts").json()["hosts"]]
    assert "web1" in names


def test_valid_ipv6_and_hostname_accepted(auth_client):
    assert _add(auth_client, name="v6", address="[2001:db8::1]", user="root").status_code == 200
    assert _add(auth_client, name="dns", address="host.example.com", user="root").status_code == 200


def test_add_requires_auth(client):
    r = client.post("/api/hosts", json={"name": "x", "address": "1.2.3.4", "user": "root"})
    assert r.status_code == 401
