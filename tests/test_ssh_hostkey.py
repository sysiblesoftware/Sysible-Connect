"""Direct-SSH host-key pinning (trust-on-first-use): a host's key is recorded on
first contact and persisted; a client loading that file knows the host, and a
DIFFERENT key for the same host is a mismatch paramiko rejects."""
import paramiko

import backend.terminals as t


def test_tofu_records_and_persists_key(tmp_path, monkeypatch):
    monkeypatch.setattr(t, "_KNOWN_HOSTS", tmp_path / "known_hosts")
    key = paramiko.RSAKey.generate(2048)

    # First contact: the policy records + saves the host key.
    c1 = paramiko.SSHClient()
    t._tofu_policy().missing_host_key(c1, "10.0.0.5", key)
    assert (tmp_path / "known_hosts").exists()

    # A fresh client loads the pinned key and now knows the host.
    c2 = paramiko.SSHClient()
    t._load_known_hosts(c2)
    entry = c2.get_host_keys().lookup("10.0.0.5")
    assert entry is not None and entry.get(key.get_name()) is not None


def test_changed_key_is_a_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr(t, "_KNOWN_HOSTS", tmp_path / "known_hosts")
    original = paramiko.RSAKey.generate(2048)
    t._tofu_policy().missing_host_key(paramiko.SSHClient(), "10.0.0.9", original)

    # A different key presented for the same host is NOT the pinned one.
    c = paramiko.SSHClient()
    t._load_known_hosts(c)
    pinned = c.get_host_keys().lookup("10.0.0.9").get(original.get_name())
    imposter = paramiko.RSAKey.generate(2048)
    assert pinned == original and pinned != imposter


def test_missing_known_hosts_is_tolerated(tmp_path, monkeypatch):
    monkeypatch.setattr(t, "_KNOWN_HOSTS", tmp_path / "does-not-exist")
    # No file yet → loading is a clean no-op (connecting must not blow up).
    t._load_known_hosts(paramiko.SSHClient())
