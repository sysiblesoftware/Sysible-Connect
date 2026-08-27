"""Brute-force throttle on the Connect password login (F8)."""


def test_login_locks_out_after_repeated_failures(client):
    for _ in range(5):
        assert client.post("/api/login", json={"username": "admin", "password": "nope"}).status_code == 401
    # 6th failure within the window is locked out...
    assert client.post("/api/login", json={"username": "admin", "password": "nope"}).status_code == 429
    # ...and even the CORRECT password is refused during the lockout.
    assert client.post("/api/login", json={"username": "admin", "password": "test1234"}).status_code == 429


def test_successful_login_clears_failures(client):
    for _ in range(3):
        client.post("/api/login", json={"username": "admin", "password": "nope"})
    assert client.post("/api/login", json={"username": "admin", "password": "test1234"}).status_code == 200
    # counter reset — a fresh burst starts from zero
    for _ in range(4):
        assert client.post("/api/login", json={"username": "admin", "password": "nope"}).status_code == 401
