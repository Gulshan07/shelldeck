"""Run: .venv/bin/python test_p0.py"""
import os
import stat
import tempfile

os.environ["EAZY_HOME"] = tempfile.mkdtemp()

from eazyconnector import store  # noqa: E402
from eazyconnector.server import _origin_ok  # noqa: E402


def test_vault_roundtrip():
    store.init_home()
    v = store.Vault()
    assert not v.exists and not v.unlocked

    v.create("correct horse battery")
    v.put("c1", {"password": "hunter2", "key_pem": None})
    assert v.get("c1") == {"password": "hunter2"}, "empty values must not be stored"

    v.lock()
    assert not v.unlocked
    try:
        v.get("c1")
        raise AssertionError("locked vault must refuse reads")
    except store.Locked:
        pass

    v2 = store.Vault()
    try:
        v2.unlock("wrong password")
        raise AssertionError("wrong password must not decrypt")
    except store.BadPassword:
        pass

    v2.unlock("correct horse battery")
    assert v2.get("c1")["password"] == "hunter2"


def test_secrets_never_in_plain_config():
    store.save_config({"connections": [{"id": "c1", "host": "h", "user": "u"}]})
    assert b"hunter2" not in store.CONFIG.read_bytes()
    assert b"hunter2" not in store.VAULT.read_bytes(), "vault must be ciphertext"


def test_file_modes():
    for p in (store.CONFIG, store.VAULT):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600, f"{p} must be 0600 on a shared machine"
    assert stat.S_IMODE(store.HOME.stat().st_mode) == 0o700


def test_origin_guard():
    def scope(origin, host="127.0.0.1:9999"):
        h = [(b"host", host.encode())]
        if origin:
            h.append((b"origin", origin.encode()))
        return {"headers": h}

    assert _origin_ok(scope("http://127.0.0.1:9999"))
    assert not _origin_ok(scope("http://evil.example")), "cross-origin must be rejected"
    assert not _origin_ok(scope("http://127.0.0.1:1234")), "wrong port must be rejected"
    assert _origin_ok(scope(None)), "non-browser client allowed (still needs the token)"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("\nall passed")
