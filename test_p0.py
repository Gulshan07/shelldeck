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


def test_known_hosts_entries_actually_match():
    """A "[host]:22" line parses fine but matches nothing, so the host stays
    untrusted and re-prompts forever. Port 22 is the case that broke."""
    import asyncssh
    from eazyconnector.server import known_hosts_entry

    key = asyncssh.generate_private_key("ssh-ed25519")
    path = store.HOME / "kh_test"
    # asyncssh looks up the DEFAULT port as None, not 22. Querying 22 explicitly
    # makes a "[host]:22" line look valid when it is not, so mirror the real call.
    for host, port, lookup_port in [("10.0.0.1", 22, None), ("10.0.0.2", 2222, 2222)]:
        store.write_private(path, known_hosts_entry(host, port, key).encode())
        trusted = asyncssh.match_known_hosts(str(path), host, host, lookup_port)[0]
        assert any(k.export_public_key() == key.export_public_key() for k in trusted), \
            f"entry for {host}:{port} matched nothing at connect time"

    # and prove the old bracketed form really is the broken one
    store.write_private(path, f"[10.0.0.1]:22 {key.export_public_key().decode().strip()}\n".encode())
    assert not asyncssh.match_known_hosts(str(path), "10.0.0.1", "10.0.0.1", None)[0], \
        "expected [host]:22 to match nothing"
    path.unlink()


def test_parse_forward():
    from eazyconnector.server import parse_forward

    assert parse_forward("L 8080:localhost:3306") == ("L", 8080, "localhost", 3306)
    assert parse_forward("R 9090:10.0.0.1:22") == ("R", 9090, "10.0.0.1", 22)
    assert parse_forward("D 1080") == ("D", 1080, None, None)
    # IPv6 literal destination: only the last colon separates the port
    assert parse_forward("L 5000:::1:80") == ("L", 5000, "::1", 80)

    for bad in ["X 1:h:2", "L 8080", "L 0:h:80", "L 70000:h:80", "L 8080:h:abc", "", "D"]:
        try:
            parse_forward(bad)
            raise AssertionError(f"{bad!r} should have been rejected")
        except ValueError:
            pass


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
