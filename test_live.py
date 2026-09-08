"""Real uvicorn + real WebSocket handshake. TestClient fakes WebSockets in-process,
so it cannot catch a missing uvicorn ws implementation. This can.
Run: .venv/bin/python test_live.py"""
import asyncio, json, os, socket, tempfile, threading
os.environ["SHELLDECK_HOME"] = tempfile.mkdtemp()

import asyncssh, httpx, uvicorn, websockets
from shelldeck import store, server

SSHD_PORT, PW = 2298, "s3cret"


async def fake_sshd():
    async def handler(proc):
        if proc.command:                      # exec request, e.g. the SFTP search
            r = await asyncio.create_subprocess_shell(
                proc.command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await r.communicate()
            proc.stdout.write(out.decode(errors="replace"))
            proc.exit(r.returncode or 0)
            return
        proc.stdout.write("hi\r\n")
        while True:
            try:
                line = await proc.stdin.readline()
            except asyncssh.TerminalSizeChanged:
                continue          # a real PTY server keeps reading after SIGWINCH
            if not line:
                break
            proc.stdout.write(f"you said: {line.strip()}\r\n")
        proc.exit(0)

    class S(asyncssh.SSHServer):
        def begin_auth(self, u): return True
        def password_auth_supported(self): return True
        def validate_password(self, u, p): return p == PW
        def connection_requested(self, *a): return True  # permit forwarded channels

    await asyncssh.create_server(S, "127.0.0.1", SSHD_PORT, process_factory=handler,
                                 sftp_factory=True,
                                 server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")])


async def main():
    store.init_home()
    await fake_sshd()

    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    cfg = uvicorn.Config(server.app, host="127.0.0.1", port=port, log_level="error")
    uv = uvicorn.Server(cfg)
    threading.Thread(target=uv.run, daemon=True).start()
    for _ in range(50):
        await asyncio.sleep(0.1)
        if uv.started:
            break
    assert uv.started, "uvicorn did not start"

    server.vault.create("master-password-1")
    cid = "live1"
    store.save_config({"connections": [{
        "id": cid, "name": "live", "group": "", "host": "127.0.0.1", "port": SSHD_PORT,
        "user": "gulshan", "auth": "password", "jump": ""}]})
    server.vault.put(cid, {"password": PW})

    fwd_port = 2296
    store.save_config({"connections": [{
        "id": cid, "name": "live", "group": "", "host": "127.0.0.1", "port": SSHD_PORT,
        "user": "gulshan", "auth": "password", "jump": "",
        "forwards": [f"L {fwd_port}:127.0.0.1:{SSHD_PORT}"]}]})

    origin = f"http://127.0.0.1:{port}"
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                  additional_headers={"Origin": origin}) as ws:
        print("ok  uvicorn accepted the WebSocket upgrade")
        await ws.send(json.dumps({"token": server.TOKEN, "id": cid, "cols": 80, "rows": 24}))

        msg = json.loads(await ws.recv())
        assert msg["type"] == "hostkey", msg
        await ws.send(json.dumps({"accept": True}))
        ready = json.loads(await ws.recv())
        assert ready["type"] == "ready", ready
        print("ok  ssh session ready over a real socket")
        assert ready["forwards"] == [f"L 127.0.0.1:{fwd_port} \u2192 127.0.0.1:{SSHD_PORT}"], ready
        # the forwarded port must actually carry traffic: the sshd banner proves it
        r, w = await asyncio.open_connection("127.0.0.1", fwd_port)
        banner = await asyncio.wait_for(r.readline(), timeout=5)
        w.close()
        assert banner.startswith(b"SSH-2.0"), banner
        print("ok  local forward carried traffic:", banner.decode().strip())

        # a nonsense resize must be ignored, not kill the shell
        await ws.send(json.dumps({"type": "resize", "cols": 0, "rows": 0}))
        await ws.send(json.dumps({"type": "resize", "cols": "wat", "rows": None}))
        await ws.send(json.dumps({"type": "bogus"}))
        await ws.send(b"ping\n")
        buf = b""
        while b"you said" not in buf:
            chunk = await ws.recv()
            if isinstance(chunk, bytes):
                buf += chunk
        assert b"you said: ping" in buf
        print("ok  shell survived bad control messages:", buf.decode().strip().splitlines()[-1])
        await ws.send(json.dumps({"type": "resize", "cols": 100, "rows": 40}))
        await ws.send(b"again\n")
        buf = b""
        while b"again" not in buf:
            c = await ws.recv()
            if isinstance(c, bytes):
                buf += c
        print("ok  still interactive after a valid resize")

    # cross-origin must be refused even with a valid token
    try:
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                      additional_headers={"Origin": "http://evil.example"}) as ws:
            await ws.send(json.dumps({"token": server.TOKEN, "id": cid}))
            await asyncio.wait_for(ws.recv(), timeout=3)
        raise AssertionError("cross-origin WebSocket was accepted!")
    except (websockets.exceptions.ConnectionClosed, websockets.exceptions.InvalidStatus):
        print("ok  cross-origin WebSocket refused")

    # --- import from ssh_config and Ásbrú -----------------------------------
    import tempfile as _tf, yaml as _yaml
    keyfile = _tf.mktemp(suffix=".pem")
    open(keyfile, "w").write("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDATA\n-----END OPENSSH PRIVATE KEY-----\n")
    sshcfg = _tf.mktemp()
    open(sshcfg, "w").write(
        f"Host jump\n  HostName 10.9.0.1\n  User ubuntu\n  IdentityFile {keyfile}\n"
        f"Host app\n  HostName 10.9.0.2\n  User deploy\n  ProxyJump jump\n")
    asbrufile = _tf.mktemp(suffix=".yml")
    _yaml.safe_dump({"environments": {
        "g": {"_is_group": True, "name": "PROD", "parent": "__PAC__ROOT__"},
        "c": {"name": "abox", "method": "SSH", "ip": "10.9.0.3", "port": 22,
              "passphrase user": "ubuntu", "parent": "g", "pass": "SECRETBLOB"}}}, open(asbrufile, "w"))

    async with httpx.AsyncClient(base_url=origin, headers={"Authorization": "Bearer " + server.TOKEN,
                                                           "Origin": origin}) as http:
        r = await http.post("/api/import/ssh_config/preview", json={"path": sshcfg})
        pv = r.json()
        assert r.status_code == 200, pv
        assert pv["new"] == 2 and pv["duplicates"] == 0, pv
        assert any(c["via"] == "jump" for c in pv["connections"]), "ProxyJump link missing in preview"
        print("ok  ssh_config preview: 2 new, jump link resolved")

        r = await http.post("/api/import/ssh_config/commit", json={"path": sshcfg})
        assert r.json()["created"] == 2 and r.json()["keys_imported"] == 1, r.json()
        cfg = store.load_config()
        app = next(c for c in cfg["connections"] if c["name"] == "app")
        jump = next(c for c in cfg["connections"] if c["name"] == "jump")
        assert app["jump"] == jump["id"], "jump link broken after commit"
        assert "FAKEKEYDATA" in server.vault.get(jump["id"])["key_pem"], "key not read into vault"
        assert b"FAKEKEYDATA" not in store.CONFIG.read_bytes(), "key leaked into plain config"
        print("ok  ssh_config commit: linked, key in vault, not in config")

        # re-import is idempotent
        r = await http.post("/api/import/ssh_config/commit", json={"path": sshcfg})
        assert r.json()["created"] == 0 and r.json()["skipped"] == 2, r.json()
        print("ok  re-import skips duplicates")

        # Ásbrú, and the encrypted password must never appear anywhere
        r = await http.post("/api/import/asbru/commit", json={"path": asbrufile})
        assert r.json()["created"] == 1, r.json()
        abox = next(c for c in store.load_config()["connections"] if c["name"] == "abox")
        assert abox["group"] == "PROD" and abox["user"] == "ubuntu"
        assert b"SECRETBLOB" not in store.CONFIG.read_bytes()
        assert b"SECRETBLOB" not in store.VAULT.read_bytes(), "Ásbrú password was imported!"
        print("ok  Ásbrú import keeps group, drops the encrypted password entirely")
        # editing a KEY connection without re-entering the PEM must keep the key.
        rc = await http.post("/api/connections", json={
            "name": "keyconn", "group": "g", "host": "10.5.5.5", "port": 22, "user": "ubuntu",
            "auth": "key", "key_pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"})
        kid = rc.json()["id"]
        assert "AAAA" in server.vault.get(kid)["key_pem"]
        await http.post("/api/connections", json={
            "id": kid, "name": "keyconn2", "group": "g", "host": "10.5.5.5",
            "port": 22, "user": "ubuntu", "auth": "key"})     # no key_pem in the edit
        assert "AAAA" in server.vault.get(kid)["key_pem"], "editing wiped the stored key"
        await http.delete(f"/api/connections/{kid}")
        print("ok  editing a key connection without re-entering the PEM keeps the key")

        # pre/post commands: local_before output appears, remote_command auto-runs after login
        rc = await http.post("/api/connections", json={
            "name": "cmds", "group": "g", "host": "127.0.0.1", "port": SSHD_PORT,
            "user": "u", "auth": "password", "password": PW, "keepalive": 15,
            "local_before": "echo LOCAL_BEFORE_MARKER",
            "remote_command": "auto-remote-cmd"})
        ccid = rc.json()["id"]
        assert rc.json()["keepalive"] == 15
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                  additional_headers={"Origin": origin}) as ws:
        await ws.send(json.dumps({"token": server.TOKEN, "id": ccid, "cols": 80, "rows": 24}))
        saw_local = saw_remote = False
        for _ in range(40):
            m = await ws.recv()
            if isinstance(m, bytes):
                if b"LOCAL_BEFORE_MARKER" in m: saw_local = True
                if b"auto-remote-cmd" in m: saw_remote = True   # sshd echoes it back
                if saw_local and saw_remote: break
            else:
                d = json.loads(m)
                if d.get("type") == "hostkey": await ws.send(json.dumps({"accept": True}))
        assert saw_local, "local_before output should reach the terminal"
        assert saw_remote, "remote_command should auto-run after login"
    print("ok  local pre-command runs and remote command auto-runs after login")

    # Cloning must carry the credentials over. The editor never receives stored
    # secrets, so a clone made in the browser would silently have no password --
    # you would only find out when the connection failed to authenticate.
    async with httpx.AsyncClient(base_url=origin, headers={"Authorization": "Bearer " + server.TOKEN,
                                                           "Origin": origin}) as h3:
        src = (await h3.post("/api/connections", json={
            "name": "clone-src", "group": "cloney", "host": "127.0.0.1", "port": SSHD_PORT,
            "user": "u", "auth": "password", "password": PW,
            "forwards": "L 8123:localhost:80"})).json()

        one = (await h3.post(f"/api/connections/{src['id']}/clone")).json()
        assert one["name"] == "clone-src-1", one["name"]
        assert one["group"] == "cloney", "a clone must stay in the source's group"
        assert one["id"] != src["id"], "a clone must be a new entry, not the same one"
        assert one["forwards"] == src["forwards"], "settings should come across"
        assert server.vault.get(one["id"]).get("password") == PW, \
            "the clone has no password: it would fail to authenticate"

        two = (await h3.post(f"/api/connections/{src['id']}/clone")).json()
        assert two["name"] == "clone-src-2", two["name"]
        three = (await h3.post(f"/api/connections/{one['id']}/clone")).json()
        assert three["name"] == "clone-src-3", f"cloning a clone stacked suffixes: {three['name']}"

        named = (await h3.post(f"/api/connections/{src['id']}/clone",
                               json={"name": "explicit"})).json()
        assert named["name"] == "explicit"

        missing = await h3.post("/api/connections/nope/clone")
        assert missing.status_code == 404, missing.status_code
    print("ok  clone keeps the group and credentials, numbers without stacking")
    # macros: store one, run it in a session, expect matches, follow-up sends
    async with httpx.AsyncClient(base_url=origin, headers={"Authorization": "Bearer " + server.TOKEN,
                                                           "Origin": origin}) as h2:
        await h2.post("/api/macros", json={"name": "greet",
            "body": "send hello-macro\nexpect you said: hello-macro\nsend after-expect"})
        assert any(m["name"] == "greet" for m in (await h2.get("/api/macros")).json())
        mr = await h2.post("/api/connections", json={
            "name": "macrotarget", "group": "g", "host": "127.0.0.1", "port": SSHD_PORT,
            "user": "u", "auth": "password", "password": PW})
        mtid = mr.json()["id"]
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                  additional_headers={"Origin": origin}) as ws:
        await ws.send(json.dumps({"token": server.TOKEN, "id": mtid, "cols": 80, "rows": 24}))
        m = json.loads(await ws.recv())
        if m["type"] == "hostkey":
            await ws.send(json.dumps({"accept": True})); m = json.loads(await ws.recv())
        assert m["type"] == "ready", m
        await ws.send(json.dumps({"type": "macro",
            "body": "send hello-macro\nexpect you said: hello-macro\nsend after-expect"}))
        saw_first = saw_second = macro_done = False
        for _ in range(80):
            msg = await asyncio.wait_for(ws.recv(), timeout=10)
            if isinstance(msg, bytes):
                if b"you said: hello-macro" in msg: saw_first = True
                if b"you said: after-expect" in msg: saw_second = True
            else:
                if json.loads(msg).get("type") == "macro_status" and json.loads(msg).get("done"):
                    macro_done = True
            if saw_second and macro_done: break
        assert saw_first, "macro's first send did not run"
        assert saw_second, "macro did not continue after the expect matched"
        assert macro_done, "macro never reported done"
    print("ok  macro ran: send, expect matched, follow-up send")
    # a macro attached to a connection auto-runs on connect
    async with httpx.AsyncClient(base_url=origin, headers={"Authorization": "Bearer " + server.TOKEN,
                                                           "Origin": origin}) as h3:
        await h3.post("/api/macros", json={"name": "auto-login",
            "body": "send auto-on-connect\nexpect you said: auto-on-connect\nsend then-this"})
        r = await h3.post("/api/connections", json={
            "name": "autorun", "group": "g", "host": "127.0.0.1", "port": SSHD_PORT,
            "user": "u", "auth": "password", "password": PW,
            "macros": ["auto-login"], "autorun_macro": "auto-login"})
        arid = r.json()["id"]
        assert r.json()["macros"] == ["auto-login"] and r.json()["autorun_macro"] == "auto-login"
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                  additional_headers={"Origin": origin}) as ws:
        await ws.send(json.dumps({"token": server.TOKEN, "id": arid, "cols": 80, "rows": 24}))
        m = json.loads(await ws.recv())
        if m["type"] == "hostkey":
            await ws.send(json.dumps({"accept": True})); m = json.loads(await ws.recv())
        assert m["type"] == "ready", m
        # no manual macro send: it should run itself after login
        saw_first = saw_second = False
        for _ in range(80):
            msg = await asyncio.wait_for(ws.recv(), timeout=10)
            if isinstance(msg, bytes):
                if b"you said: auto-on-connect" in msg: saw_first = True
                if b"you said: then-this" in msg: saw_second = True
            if saw_first and saw_second: break
        assert saw_first, "attached macro did not auto-run on connect"
        assert saw_second, "auto-run macro did not continue past the expect"
    print("ok  attached macro auto-runs on connect (login automation)")
    async with httpx.AsyncClient(base_url=origin, headers={"Authorization": "Bearer " + server.TOKEN,
                                                           "Origin": origin}) as http:

        # session logging: a logged terminal session is encrypted, listed, and read back
        rl = await http.post("/api/connections", json={
            "name": "logged", "group": "g", "host": "127.0.0.1", "port": SSHD_PORT,
            "user": "gulshan", "auth": "password", "password": PW, "log": True})
        lid = rl.json()["id"]
    # open a ws session that produces output, then close it
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                  additional_headers={"Origin": origin}) as ws:
        await ws.send(json.dumps({"token": server.TOKEN, "id": lid, "cols": 80, "rows": 24}))
        m = json.loads(await ws.recv())
        if m["type"] == "hostkey":
            await ws.send(json.dumps({"accept": True})); m = json.loads(await ws.recv())
        assert m["type"] == "ready", m
        await ws.send(b"echo LOGGED_MARKER\n")
        buf = b""
        while b"LOGGED_MARKER" not in buf:
            c = await ws.recv()
            if isinstance(c, bytes): buf += c
    await asyncio.sleep(0.3)   # let close() flush the footer
    async with httpx.AsyncClient(base_url=origin, headers={"Authorization": "Bearer " + server.TOKEN,
                                                           "Origin": origin}) as http:
        logs = (await http.get("/api/logs")).json()
        assert logs and logs[0]["file"].startswith("logged-"), logs
        # the .eclog on disk must not contain the marker in the clear
        raw = (store.LOGS / logs[0]["file"]).read_bytes()
        assert b"LOGGED_MARKER" not in raw, "session log is not encrypted on disk!"
        text = (await http.get(f"/api/logs/{logs[0]['file']}")).text
        assert "LOGGED_MARKER" in text, "decrypted log should contain the session output"
        print("ok  session logged, encrypted on disk, decrypted via the API")
        await http.delete(f"/api/logs/{logs[0]['file']}")
        assert (await http.get("/api/logs")).json() == []
        print("ok  log delete works")

    # --- export / import a shareable bundle ---------------------------------
    async with httpx.AsyncClient(base_url=origin, headers={"Authorization": "Bearer " + server.TOKEN,
                                                           "Origin": origin}) as h4:
        # a connection with a secret + a jump host pointing at it
        rb = await h4.post("/api/connections", json={
            "name": "bundle-bastion", "group": "shared", "host": "10.7.0.1", "port": 22,
            "user": "ubuntu", "auth": "password", "password": "BASTION-SECRET-PW"})
        bast = rb.json()["id"]
        await h4.post("/api/connections", json={
            "name": "bundle-app", "group": "shared", "host": "10.7.0.2", "port": 2222,
            "user": "deploy", "auth": "password", "password": "APP-SECRET-PW",
            "jump": bast, "forwards": "L 8081:localhost:80", "keepalive": 15})

        raw = (await h4.get("/api/export")).text
        assert "BASTION-SECRET-PW" not in raw and "APP-SECRET-PW" not in raw, \
            "the export leaked a stored password"
        bundle = json.loads(raw)
        app_row = next(r for r in bundle["connections"] if r["name"] == "bundle-app")
        assert app_row["jump_name"] == "bundle-bastion", app_row
        print("ok  export contains the structure and no stored passwords")

        # importing into the SAME vault is a no-op: everything is a duplicate
        pv = (await h4.post("/api/import/bundle/preview", json={"bundle": bundle})).json()
        assert pv["new"] == 0 and pv["duplicates"] == pv["total"], pv
        print(f"ok  re-importing your own export changes nothing ({pv['duplicates']} duplicates)")

    # now a DIFFERENT vault, as a colleague would have. Everything global is put
    # back afterwards so the rest of the suite still sees the original vault.
    import tempfile as _tf
    _orig = (store.HOME, store.CONFIG, store.VAULT, server.vault)
    other = _tf.mkdtemp()
    store.HOME = store.Path(other); store.HOME.chmod(0o700)
    store.CONFIG = store.HOME / "config.json"
    store.VAULT = store.HOME / "vault.enc"
    server.vault = store.Vault(); server.vault.create("colleague-master-pw")
    store.save_config({"connections": [], "vpns": []})
    async with httpx.AsyncClient(base_url=origin, headers={"Authorization": "Bearer " + server.TOKEN,
                                                           "Origin": origin}) as h5:
        pv = (await h5.post("/api/import/bundle/preview", json={"bundle": bundle})).json()
        assert pv["new"] > 0 and any(c["via"] == "bundle-bastion" for c in pv["connections"]), pv
        r = (await h5.post("/api/import/bundle/commit", json={"bundle": bundle})).json()
        # what the preview promised is what the import creates
        assert r["created"] == pv["new"], (r, pv["new"])
        cfg = store.load_config()
        by = {c["name"]: c for c in cfg["connections"]}
        # the jump link was rebuilt from the name against brand-new local ids
        assert by["bundle-app"]["jump"] == by["bundle-bastion"]["id"] != bast
        assert by["bundle-app"]["forwards"] == ["L 8081:localhost:80"]
        assert by["bundle-app"]["keepalive"] == 15
        # and it arrived with no credentials
        assert not server.vault.get(by["bundle-app"]["id"]).get("password")
        print("ok  colleague's vault: imported, jump re-linked by name, no credentials")

        r2 = (await h5.post("/api/import/bundle/commit", json={"bundle": bundle})).json()
        assert r2["created"] == 0, r2
        print("ok  importing the same file twice is idempotent")

        bad = (await h5.post("/api/import/bundle/preview", json={"bundle": {"nope": 1}}))
        assert bad.status_code == 400, bad.text
        print("ok  a non-Shelldeck file is refused")

    store.HOME, store.CONFIG, store.VAULT, server.vault = _orig

    # --- VPN profile storage: nothing sensitive in plain config -------------
    async with httpx.AsyncClient(base_url=origin, headers={"Authorization": "Bearer " + server.TOKEN,
                                                           "Origin": origin}) as http:
        r = await http.post("/api/vpns", json={
            "name": "Vitraya", "username": "gulshan", "dialect": "auto",
            "ovpn": 'client\nstatic-challenge "Enter Authenticator Code" 1\n'
                    '<key>\nSUPER-SECRET-PRIVATE-KEY\n</key>\n',
            "password": "corporate-secret", "totp_secret": "JBSWY3DPEHPK3PXP",
            "sudo_password": "my-sudo-pw"})
        assert r.status_code == 200, r.text
        assert r.json()["detected"] == "scrv1", r.json()
        blob = store.CONFIG.read_bytes()
        for leak in (b"SUPER-SECRET-PRIVATE-KEY", b"corporate-secret",
                     b"JBSWY3DPEHPK3PXP", b"my-sudo-pw"):
            assert leak not in blob, f"{leak!r} leaked into plain config.json"
        assert b"SUPER-SECRET-PRIVATE-KEY" not in store.VAULT.read_bytes(), "vault not encrypted"
        print("ok  vpn key, password, TOTP seed and sudo password stay out of config.json")

        vid = r.json()["id"]
        await http.post("/api/vpns", json={"id": vid, "name": "Vitraya renamed"})
        kept = server.vault.get("vpn:" + vid)
        assert kept["totp_secret"] == "JBSWY3DPEHPK3PXP" and "SUPER-SECRET" in kept["ovpn"]
        print("ok  editing a profile keeps its .ovpn and secrets")

        assert (await http.get("/api/vpn/status")).json()["state"] == "disconnected"
        assert (await http.post(f"/api/vpn/{vid}/up")).status_code in (200, 400)
        assert (await http.post("/api/vpn/nonexistent/up")).status_code == 404
        print("ok  vpn status and up/down endpoints respond")

        await http.delete(f"/api/vpns/{vid}")
        assert server.vault.get("vpn:" + vid) == {}
        print("ok  deleting a vpn profile wipes its secrets")

        # change the master password, then prove the swap took effect
        r = await http.post("/api/vault/change", json={"old": "master-password-1", "new": "brand-new-pw-9"})
        assert r.status_code == 200, r.text
        r = await http.post("/api/vault/change", json={"old": "master-password-1", "new": "another-valid-pw"})
        assert r.status_code == 403, "old password should no longer be accepted"
        r = await http.post("/api/vault/change", json={"old": "brand-new-pw-9", "new": "short"})
        assert r.status_code == 400, "an 8+ char minimum must be enforced"
        # the on-disk vault must now open only with the new password
        v2 = store.Vault()
        try:
            v2.unlock("master-password-1"); raise AssertionError("old password still unlocks")
        except store.BadPassword:
            pass
        v2.unlock("brand-new-pw-9")
        server.vault.rekey("brand-new-pw-9", "master-password-1")   # restore for later assertions
        print("ok  master password change re-encrypts the vault; old password stops working")

    # --- SFTP: list, upload, download over the real socket ------------------
    import base64
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/sftp",
                                  additional_headers={"Origin": origin}) as ws:
        await ws.send(json.dumps({"token": server.TOKEN, "id": cid, "path": os.environ["SHELLDECK_HOME"]}))
        msg = json.loads(await ws.recv())
        assert msg["type"] == "list", msg
        print("ok  sftp listed", len(msg["entries"]), "entries in", msg["path"])
        root = msg["path"]

        payload = b"hello from shelldeck\n" * 500
        await ws.send(json.dumps({"op": "put", "path": f"{root}/upload.bin", "size": len(payload)}))
        await ws.send(payload)
        assert json.loads(await ws.recv())["type"] == "uploaded"
        listing = json.loads(await ws.recv())
        up = next(e for e in listing["entries"] if e["name"] == "upload.bin")
        assert up["size"] == len(payload), up
        assert open(f"{root}/upload.bin", "rb").read() == payload, "uploaded bytes differ"
        print("ok  sftp upload wrote", up["size"], "bytes correctly")

        await ws.send(json.dumps({"op": "get", "path": f"{root}/upload.bin"}))
        head = json.loads(await ws.recv())
        assert head["type"] == "download" and head["name"] == "upload.bin", head
        got = b""
        while True:
            frame = await ws.recv()
            if isinstance(frame, bytes):
                got += frame
            else:
                assert json.loads(frame)["type"] == "download_end"
                break
        assert got == payload, f"downloaded {len(got)} bytes, expected {len(payload)}"
        print("ok  sftp download returned identical bytes")

        # multi-chunk upload, the way the browser actually sends one
        big = bytes(range(256)) * 4096          # 1 MiB
        await ws.send(json.dumps({"op": "put", "path": f"{root}/big.bin", "size": len(big)}))
        for o in range(0, len(big), 131072):
            await ws.send(big[o:o + 131072])
        assert json.loads(await ws.recv())["type"] == "uploaded"
        listing = json.loads(await ws.recv())
        assert listing["type"] == "list", listing
        assert open(f"{root}/big.bin", "rb").read() == big, "multi-chunk upload corrupted"
        print("ok  multi-chunk upload:", len(big), "bytes in 8 frames")

        # recursive server-side search
        os.makedirs(f"{root}/deep/nested", exist_ok=True)
        open(f"{root}/deep/nested/needle.log", "w").write("x" * 77)
        await ws.send(json.dumps({"op": "find", "path": root, "q": "needle"}))
        res = json.loads(await ws.recv())
        assert res["type"] == "found", res
        hit = next(e for e in res["entries"] if e["name"].endswith("needle.log"))
        assert hit["size"] == 77, hit
        print("ok  server-side find located", hit["name"], "with size", hit["size"])

        await ws.send(json.dumps({"op": "find", "path": root, "q": "no-such-thing-xyz"}))
        assert json.loads(await ws.recv())["entries"] == []
        print("ok  find returns empty rather than erroring")

        # a shell metacharacter in the term must not run as a command
        open(f"{root}/safe.txt", "w").write("ok")
        await ws.send(json.dumps({"op": "find", "path": root, "q": "'; touch /tmp/pwned_shelldeck; #"}))
        assert json.loads(await ws.recv())["entries"] == []
        assert not os.path.exists("/tmp/pwned_shelldeck"), "search term was executed as shell!"
        print("ok  search term is quoted, not executed")

        await ws.send(json.dumps({"op": "get", "path": f"{root}/nope"}))
        assert json.loads(await ws.recv())["type"] == "error"
        print("ok  sftp reports a missing file instead of hanging")

    print("\nlive passed")

asyncio.run(main())
