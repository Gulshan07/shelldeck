"""Run: .venv/bin/python test_p0.py"""
import os
import stat
import tempfile

os.environ["SHELLDECK_HOME"] = tempfile.mkdtemp()

from shelldeck import store  # noqa: E402
from shelldeck.server import _origin_ok, next_clone_name  # noqa: E402


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


def test_rekey_master_password():
    from shelldeck import store as st
    import tempfile
    st.HOME = st.Path(tempfile.mkdtemp()); st.HOME.chmod(0o700)
    st.VAULT = st.HOME / "vault.enc"
    st.CONFIG = st.HOME / "config.json"

    v = st.Vault()
    v.create("old-password-1")
    v.put("c1", {"password": "hunter2", "key_pem": "PEMDATA"})

    # wrong current password is refused, vault unchanged
    try:
        v.rekey("not-the-old-one", "new-password-2")
        raise AssertionError("rekey with wrong old password must fail")
    except st.BadPassword:
        pass

    v.rekey("old-password-1", "new-password-2")
    assert v.get("c1")["password"] == "hunter2", "secrets must survive a rekey"

    # a fresh unlock proves the on-disk blob was re-encrypted under the new password
    fresh = st.Vault()
    try:
        fresh.unlock("old-password-1")
        raise AssertionError("old password must no longer unlock the vault")
    except st.BadPassword:
        pass
    fresh.unlock("new-password-2")
    assert fresh.get("c1")["key_pem"] == "PEMDATA"


def test_session_log_encrypted_roundtrip():
    import tempfile
    from shelldeck import store as st, session_log as sl
    st.HOME = st.Path(tempfile.mkdtemp()); st.HOME.chmod(0o700)
    st.LOGS = st.HOME / "logs"
    v = st.Vault(); v.create("logpw-eight")

    log = sl.SessionLog(v, "prod/db-01")
    secret_line = b"password: hunter2\r\nsudo token 123456\r\n"
    log.write(secret_line)
    log.write(b"more output\r\n")
    log.close()

    raw = st.LOGS.joinpath(*[]) and None  # noqa
    disk = log.path.read_bytes()
    assert b"hunter2" not in disk and b"123456" not in disk, "log plaintext must not touch disk"
    assert log.path.suffix == ".eclog"

    text = sl.read_log(v, log.path)
    assert b"hunter2" in text and b"more output" in text, "decrypt must recover the session"
    assert b"=== prod/db-01" in text, "header written"

    # timed frames for playback: monotonic non-decreasing ms, still secret-free on disk
    frames = list(sl.read_frames(v, log.path))
    assert len(frames) >= 3 and all(isinstance(ms, int) for ms, _ in frames)
    ms_values = [ms for ms, _ in frames]
    assert ms_values == sorted(ms_values), "frame timestamps must be non-decreasing"
    assert b"hunter2" in b"".join(d for _, d in frames)

    # a locked vault cannot read the log back
    v.lock()
    try:
        sl.read_log(v, log.path); raise AssertionError("locked vault decrypted a log")
    except st.Locked:
        pass


def test_session_log_cap():
    import tempfile
    from shelldeck import store as st, session_log as sl
    st.HOME = st.Path(tempfile.mkdtemp()); st.HOME.chmod(0o700)
    st.LOGS = st.HOME / "logs"
    v = st.Vault(); v.create("logpw-eight")
    sl.CAP_BYTES = 1000                     # tiny cap for the test
    log = sl.SessionLog(v, "big")
    for _ in range(50):
        log.write(b"x" * 100)               # 5000 bytes into a 1000 cap
    log.close()
    text = sl.read_log(v, log.path)
    assert b"truncated" in text, "must stop and mark truncation, not grow forever"
    assert text.count(b"x") <= 1100, "should not keep writing past the cap"
    sl.CAP_BYTES = 50 * 1024 * 1024


def test_log_path_traversal_blocked():
    import tempfile
    from shelldeck import store as st, server
    st.LOGS = st.Path(tempfile.mkdtemp())
    server.store.LOGS = st.LOGS
    assert server._log_path("../../etc/passwd") is None
    assert server._log_path("ok.txt") is None, "only .eclog allowed"
    assert server._log_path("session.eclog") is not None


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
    from shelldeck.server import known_hosts_entry

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


def test_macro_parse():
    from shelldeck.macros import parse
    steps = parse("send sudo -i\nexpect password:\nsend secret\nsleep 2\n# comment\n\nbare line")
    assert steps == [
        ("send", "sudo -i\n"),
        ("expect", "password:"),
        ("send", "secret\n"),
        ("sleep", 2.0),
        ("send", "bare line\n"),      # anything unrecognised is treated as send
    ], steps
    assert parse("send! y")[0] == ("send", "y"), "send! must not append a newline"

    # indented steps (as pasted from an example) must still parse as steps, not
    # get typed literally
    indented = parse("expect [#$]\n    send sudo bash\n\texpect password:")
    assert indented == [("expect", "[#$]"), ("send", "sudo bash\n"), ("expect", "password:")], indented

    # steps merged onto one line by spaces (paste-from-terminal) must split back
    merged = parse("expect [#$]        send sudo bash\nexpect mysql>   send use db;")
    assert merged == [("expect", "[#$]"), ("send", "sudo bash\n"),
                      ("expect", "mysql>"), ("send", "use db;\n")], merged
    # but a normal send with internal spaces is left alone
    assert parse("send echo  hello  world") == [("send", "echo  hello  world\n")]


def test_macro_expect_regex():
    """expect is regex (Ásbrú-style), so a shell prompt matches; a bad pattern
    falls back to literal so it never crashes."""
    import asyncio
    from shelldeck.macros import run

    async def go():
        recent = bytearray(b"ubuntu@web-01:~$ ")           # a real-ish prompt
        writes = []
        # regex [#$] should match the trailing $ immediately, then send fires
        it = run([("expect", "[#$]"), ("send", "ls\n")], lambda b: writes.append(b), recent)
        statuses = [s async for s in it]
        assert any("matched" in s for s in statuses), statuses
        assert writes == [b"ls\n"], writes

        # an invalid regex must not raise; it becomes a literal match
        recent2 = bytearray(b"see the [bracket] here")
        it2 = run([("expect", "[bracket")], lambda b: None, recent2)  # unbalanced [
        got = [s async for s in it2]
        assert any("matched" in s for s in got), got

    asyncio.run(go())


def test_parse_forward():
    from shelldeck.server import parse_forward

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


def test_totp_rfc6238():
    """RFC 6238 Appendix B test vectors (SHA-1, 8 digits, seed "12345678901234567890")."""
    import base64
    from shelldeck.vpn import totp

    seed = base64.b32encode(b"12345678901234567890").decode()
    for when, expected in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                           (1234567890, "89005924"), (2000000000, "69279037"),
                           (20000000000, "65353130")]:
        got = totp(seed, when=when, digits=8)
        assert got == expected, f"t={when}: got {got}, want {expected}"

    # formatting details that break real logins
    assert len(totp(seed, when=59)) == 6
    assert totp("jbswy 3dp ehpk3pxp", when=59) == totp("JBSWY3DPEHPK3PXP", when=59), \
        "must tolerate lowercase and the spaces authenticator apps display"
    # same 30s window -> same code; next window -> different
    assert totp(seed, when=100) == totp(seed, when=119)
    assert totp(seed, when=100) != totp(seed, when=130)


MIGRATION = ("otpauth-migration://offline?data=CigKCkhlbGxvId6tvu8SC2d1bHNoYW5AdnBuGgdWaXRyYXlhIAEoATACCj4KIDEy"
             "MzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyEgtvcHNAZXhhbXBsZRoHRXhhbXBsZSACKAIwAgojCg5jb3VudGVyLXNl"
             "Y3JldBIDb2xkGgZMZWdhY3kgASgBMAEQARgBIAA%3D")


def test_totp_algorithms():
    """RFC 6238 Appendix B, SHA-256 and SHA-512 seeds."""
    from shelldeck.vpn import totp
    import base64
    b32 = lambda raw: base64.b32encode(raw).decode()
    assert totp(b32(b"12345678901234567890123456789012"), when=59, digits=8, algorithm="SHA256") == "46119246"
    assert totp(b32(b"1234567890123456789012345678901234567890123456789012345678901234"),
                when=59, digits=8, algorithm="SHA512") == "90693936"


def test_parse_totp_input():
    from shelldeck.vpn import parse_totp_input, code_for, totp
    [a] = parse_totp_input(" jbsw y3dp ehpk 3pxp== ")
    assert a == {"label": "", "issuer": "", "secret": "JBSWY3DPEHPK3PXP",
                 "digits": 6, "period": 30, "algorithm": "SHA1"}
    [a] = parse_totp_input("otpauth://totp/Vitraya%3Agulshan%40vpn?secret=jbswy3dpehpk3pxp"
                           "&issuer=Vitraya&digits=8&period=60&algorithm=SHA256")
    assert a == {"label": "Vitraya:gulshan@vpn", "issuer": "Vitraya", "secret": "JBSWY3DPEHPK3PXP",
                 "digits": 8, "period": 60, "algorithm": "SHA256"}
    # Google export: two TOTP accounts; the HOTP entry is dropped
    accts = parse_totp_input(MIGRATION)
    assert [(x["label"], x["issuer"], x["digits"], x["algorithm"]) for x in accts] == [
        ("gulshan@vpn", "Vitraya", 6, "SHA1"), ("ops@example", "Example", 8, "SHA256")]
    assert accts[0]["secret"] == "JBSWY3DPEHPK3PXP" and accts[0]["period"] == 30
    # the same link with the data left unencoded
    assert parse_totp_input(MIGRATION.replace("%3D", "=")) == accts
    # base64 '+' that a form or chat app turned into a space still decodes
    import base64, urllib.parse
    one = bytes([0x0a, 19, 0x0a, 5, 0, 0, 0xfb, 0xef, 0xbe, 0x12, 1, 0x78, 0x1a, 1, 0x79, 0x20, 1, 0x28, 1, 0x30, 2])
    b64 = base64.b64encode(one).decode()
    assert "+" in b64, b64
    for data in (urllib.parse.quote(b64, safe=""), b64, b64.replace("+", " ")):
        [x] = parse_totp_input("otpauth-migration://offline?data=" + data)
        assert x["secret"] == base64.b32encode(b"\x00\x00\xfb\xef\xbe").decode().rstrip("="), data
    for bad, msg in [("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1", "HOTP"),
                     ("hello world!", "not a TOTP key"),
                     ("otpauth://totp/x?issuer=nokey", "not a TOTP key"),
                     ("otpauth-migration://offline?data=%%%", "not a TOTP key"),
                     ("", "not a TOTP key")]:
        try:
            parse_totp_input(bad)
            raise AssertionError(bad)
        except ValueError as e:
            assert msg in str(e), (bad, e)
    assert code_for({"totp_secret": "JBSWY3DPEHPK3PXP"}, when=59) == totp("JBSWY3DPEHPK3PXP", when=59)
    assert code_for({"totp_secret": "JBSWY3DPEHPK3PXP", "totp_digits": 8, "totp_period": 60,
                     "totp_algorithm": "SHA256"}, when=59) == totp(
                         "JBSWY3DPEHPK3PXP", when=59, digits=8, period=60, algorithm="SHA256")
    assert code_for({}) == ""


def test_vpn_password_dialects():
    import base64
    from shelldeck.vpn import build_password, detect_dialect

    assert build_password("concat", "hunter2", "123456") == "hunter2123456"
    scrv1 = build_password("scrv1", "hunter2", "123456")
    kind, pw, code = scrv1.split(":")
    assert kind == "SCRV1"
    assert base64.b64decode(pw) == b"hunter2" and base64.b64decode(code) == b"123456"
    # a password containing ':' must survive, which is exactly why base64 is used
    weird = build_password("scrv1", "a:b:c", "000001")
    assert base64.b64decode(weird.split(":")[1]) == b"a:b:c"
    # no TOTP configured -> password unchanged
    assert build_password("scrv1", "hunter2", "") == "hunter2"

    # the real Vitraya profile's directive picks SCRV1
    assert detect_dialect('client\nstatic-challenge "Enter Authenticator Code" 1\n') == "scrv1"
    assert detect_dialect("client\nauth-user-pass\n") == "concat"


def test_management_quoting():
    from shelldeck.vpn import _esc
    assert _esc('pa"ss\\word') == 'pa\\"ss\\\\word'


def test_import_ssh_config():
    from shelldeck.importers import from_ssh_config

    conns, warnings = from_ssh_config(
        "Host bastion\n  HostName 10.0.0.1\n  User ubuntu\n  IdentityFile ~/k.pem\n"
        "Host app\n  HostName 10.0.0.2\n  User deploy\n  Port 2222\n  ProxyJump bastion\n"
        "Host *.internal\n  User root\n")            # pattern must be skipped
    by = {c["name"]: c for c in conns}
    assert set(by) == {"bastion", "app"}, "host patterns should be skipped"
    assert by["bastion"]["auth"] == "key" and by["bastion"]["_keyfile"].endswith("k.pem")
    assert by["app"]["port"] == 2222
    assert by["app"]["jump"] == by["bastion"]["id"], "ProxyJump must link to the bastion"

    # ProxyJump to an unknown host warns and stays direct
    conns, warnings = from_ssh_config("Host x\n  HostName h\n  ProxyJump ghost\n")
    assert conns[0]["jump"] == "" and any("ghost" in w for w in warnings)


def test_import_asbru():
    from shelldeck.importers import from_asbru

    data = {"environments": {
        "g1": {"_is_group": True, "name": "PROD", "parent": "__PAC__ROOT__"},
        "g2": {"_is_group": True, "name": "db", "parent": "g1"},
        "c1": {"name": "mongo", "method": "SSH", "ip": "10.0.0.9", "port": 22,
               "passphrase user": "ubuntu", "public key": "/keys/a.pem", "parent": "g2",
               "use proxy": 3, "jump ip": "1.2.3.4", "jump user": "ubuntu", "jump port": 22,
               "jump key": "/keys/j.pem", "pass": "ENCRYPTED-BLOB"},
        "c2": {"name": "web", "method": "SSH", "ip": "10.0.0.8", "port": 22,
               "passphrase user": "ubuntu", "use proxy": 3, "jump ip": "1.2.3.4",
               "jump user": "ubuntu", "jump port": 22, "parent": "g1"},
        "c3": {"name": "legacy", "method": "RDP", "ip": "10.0.0.7", "parent": "g1"},
    }}
    conns, warnings = from_asbru(data)
    by = {c["name"]: c for c in conns}

    assert "legacy" not in by and any("RDP" in w for w in warnings), "non-SSH must be skipped"
    assert by["mongo"]["group"] == "PROD/db"
    assert by["mongo"]["user"] == "ubuntu", "login user comes from 'passphrase user'"
    assert by["mongo"]["auth"] == "key" and by["mongo"]["_keyfile"] == "/keys/a.pem"
    # a single synthesized jump host, shared by both connections that use it
    jumps = [c for c in conns if c["group"] == "Ásbrú/jump hosts"]
    assert len(jumps) == 1, f"expected one deduped jump host, got {len(jumps)}"
    assert by["mongo"]["jump"] == jumps[0]["id"] == by["web"]["jump"]
    # the encrypted password is never carried into the result
    assert not any("pass" in c or "ENCRYPTED" in str(c.values()) for c in conns)


def test_export_bundle_carries_no_secrets():
    """The whole point of the export is that it is safe to hand to a colleague."""
    from shelldeck.importers import to_bundle, SHAREABLE
    import json as _json

    conns = [
        {"id": "a1", "name": "bastion", "group": "prod", "host": "10.0.0.1", "port": 22,
         "user": "ubuntu", "auth": "key", "jump": "", "forwards": [],
         "key_path": "/home/me/keys/bastion.pem", "proto": "ssh"},
        {"id": "a2", "name": "db", "group": "prod", "host": "10.0.0.2", "port": 22,
         "user": "ubuntu", "auth": "password", "jump": "a1",
         "forwards": ["L 3306:localhost:3306"], "log": True, "keepalive": 15,
         "macros": ["mysql-login"], "autorun_macro": "mysql-login",
         "local_before": "aws sso login", "remote_command": "cd /srv", "proto": "ssh"},
    ]
    bundle = to_bundle(conns)
    # scan the rows only: the bundle's own `note` mentions these words on purpose
    blob = _json.dumps(bundle["connections"]).lower().replace('"password"', '""')

    # nothing secret may appear, and no field outside the allow-list may ride along
    for banned in ("password", "key_pem", "passphrase", "totp", "ovpn", "sudo"):
        assert banned not in blob, f"{banned!r} leaked into the export"
    assert "no passwords" in bundle["note"].lower(), "the bundle should say what it omits"
    allowed = set(SHAREABLE) | {"jump_name"}
    for row in bundle["connections"]:
        assert set(row) <= allowed, f"unexpected exported field(s): {set(row) - allowed}"
    assert "id" not in bundle["connections"][0], "local ids must not be exported"

    # a jump host travels as a name, because ids are local to one vault
    db = next(r for r in bundle["connections"] if r["name"] == "db")
    assert db["jump_name"] == "bastion"
    assert "jump" not in db
    # macro names are listed, bodies are not
    assert bundle["macros_referenced"] == ["mysql-login"]


def test_bundle_round_trip_relinks_jump_by_name():
    from shelldeck.importers import to_bundle, from_bundle

    conns = [
        {"id": "x", "name": "bastion", "group": "g", "host": "10.0.0.1", "port": 22,
         "user": "u", "auth": "key", "jump": "", "forwards": [], "proto": "ssh"},
        {"id": "y", "name": "app", "group": "g", "host": "10.0.0.2", "port": 2222,
         "user": "deploy", "auth": "password", "jump": "x",
         "forwards": ["D 1080"], "keepalive": 15, "log": True, "proto": "ssh"},
        {"id": "z", "name": "console", "group": "g", "host": "", "port": 22, "user": "",
         "auth": "password", "jump": "", "forwards": [], "proto": "serial",
         "serial_device": "/dev/ttyUSB0", "baud": 9600},
    ]
    back, warnings = from_bundle(to_bundle(conns))
    by = {c["name"]: c for c in back}
    assert set(by) == {"bastion", "app", "console"}
    # the link survived even though every id is freshly generated
    assert by["app"]["jump"] == by["bastion"]["id"] != "x"
    assert by["app"]["port"] == 2222 and by["app"]["forwards"] == ["D 1080"]
    assert by["app"]["keepalive"] == 15 and by["app"]["log"] is True
    assert by["console"]["proto"] == "serial" and by["console"]["serial_device"] == "/dev/ttyUSB0"
    # imported entries carry no secrets to write
    assert all("password" not in c and "key_pem" not in c for c in back)

    # a dangling jump warns instead of pointing at nothing
    partial = to_bundle(conns)
    partial["connections"] = [r for r in partial["connections"] if r["name"] != "bastion"]
    back2, warns2 = from_bundle(partial)
    assert next(c for c in back2 if c["name"] == "app")["jump"] == ""
    assert any("bastion" in w and "not in this file" in w for w in warns2)

    # junk is refused
    for bad in ({}, {"connections": []}, {"shelldeck_export": 99}):
        try:
            from_bundle(bad)
            raise AssertionError(f"should have refused {bad}")
        except ValueError:
            pass


def test_import_unreadable_key_stays_key_auth():
    """A key file that exists but cannot be read must not become a silent
    empty-password connection; it stays key-auth and fails loudly at connect."""
    import os, tempfile, stat
    from shelldeck.importers import from_asbru

    kf = tempfile.mktemp(suffix=".pem")
    open(kf, "w").write("KEY")
    os.chmod(kf, 0)                       # unreadable (root-owned files look like this)
    data = {"environments": {"c": {"name": "x", "method": "SSH", "ip": "h",
            "passphrase user": "u", "public key": kf, "parent": "__PAC__ROOT__"}}}
    conns, _ = from_asbru(data)
    c = conns[0]
    assert c["auth"] == "key" and c["_keyfile"] == kf, \
        "an unreadable key must stay key-auth so the failure is visible, not fall to password"
    os.chmod(kf, 0o600); os.unlink(kf)


def test_vault_dir_falls_back_to_the_old_name():
    """A vault made when the project was EazyConnector must keep opening.

    Only the master password can decrypt it, so pointing at a fresh empty
    ~/.shelldeck would look exactly like data loss to the person it happens to.
    """
    from pathlib import Path
    real_home, real_env = Path.home, os.environ.pop("SHELLDECK_HOME", None)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            Path.home = staticmethod(lambda: Path(tmp))

            (Path(tmp) / ".eazyconnector").mkdir()
            assert store._home().name == ".eazyconnector", \
                "an existing pre-rename vault directory must still be used"

            (Path(tmp) / ".shelldeck").mkdir()
            assert store._home().name == ".shelldeck", \
                "once the new directory exists it wins"

        with tempfile.TemporaryDirectory() as tmp:      # neither exists yet
            Path.home = staticmethod(lambda: Path(tmp))
            assert store._home().name == ".shelldeck", \
                "a fresh install must use the new name"
    finally:
        Path.home = real_home
        if real_env is not None:
            os.environ["SHELLDECK_HOME"] = real_env


def test_clone_names_do_not_collide_or_stack():
    assert next_clone_name("web", {"web"}) == "web-1"
    assert next_clone_name("web", {"web", "web-1"}) == "web-2"
    # a host really called web-01 keeps its number instead of becoming web-1
    assert next_clone_name("web-01", {"web-01"}) == "web-01-1"
    # but cloning a clone continues the series rather than nesting suffixes
    assert next_clone_name("web-01-1", {"web-01", "web-01-1"}) == "web-01-2"
    # names are only taken within the group, so an empty group starts at -1
    assert next_clone_name("web", set()) == "web-1"


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
