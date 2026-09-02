"""End-to-end: vault -> add connection -> TOFU host key -> SSH shell.
Run: .venv/bin/python test_e2e.py"""
import asyncio, os, tempfile, threading
os.environ["EAZY_HOME"] = tempfile.mkdtemp()

import asyncssh
from starlette.testclient import TestClient
from eazyconnector import store, server

PORT = 2299
PW = "s3cret-server-pw"


def start_fake_sshd():
    """Throwaway in-process sshd that echoes what you type."""
    async def handler(proc):
        proc.stdout.write("welcome\r\n")
        async for line in proc.stdin:
            if line.strip() == "quit":
                break
            proc.stdout.write(f"you said: {line.strip()}\r\n")
        proc.exit(0)

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username): return True
        def password_auth_supported(self): return True
        def validate_password(self, username, password): return password == PW

    loop = asyncio.new_event_loop()
    ready = threading.Event()

    async def run():
        key = asyncssh.generate_private_key("ssh-ed25519")
        await asyncssh.create_server(Server, "127.0.0.1", PORT, server_host_keys=[key],
                                     process_factory=handler)
        ready.set()
        await asyncio.Event().wait()

    threading.Thread(target=lambda: loop.run_until_complete(run()), daemon=True).start()
    ready.wait(5)


def main():
    store.init_home()
    start_fake_sshd()
    auth = {"Authorization": "Bearer " + server.TOKEN}

    with TestClient(server.app) as c:
        assert c.get("/api/vault").status_code == 401, "no token must be rejected"

        r = c.post("/api/vault/unlock", json={"password": "master-password-1"}, headers=auth)
        assert r.status_code == 200, r.text

        r = c.post("/api/connections", headers=auth, json={
            "name": "test", "group": "lab", "host": "127.0.0.1", "port": PORT,
            "user": "gulshan", "auth": "password", "password": PW})
        cid = r.json()["id"]
        print("ok  connection saved")

        assert PW.encode() not in store.CONFIG.read_bytes(), "password leaked into plain config!"
        print("ok  password absent from config.json")

        with c.websocket_connect("/ws/ssh") as ws:
            ws.send_json({"token": server.TOKEN, "id": cid, "cols": 80, "rows": 24})

            msg = ws.receive_json()
            assert msg["type"] == "hostkey", msg
            print("ok  unknown host key prompted:", msg["fingerprint"][:24] + "...")
            ws.send_json({"accept": True})

            assert ws.receive_json()["type"] == "ready"
            print("ok  ssh session ready")

            ws.send_bytes(b"hello there\n")
            buf = b""
            while b"you said" not in buf:
                buf += ws.receive_bytes()
            assert b"you said: hello there" in buf, buf
            print("ok  shell round-trip:", buf.decode().strip().splitlines()[-1])

        assert b"[127.0.0.1]:%d" % PORT in store.KNOWN_HOSTS.read_bytes()
        print("ok  host key persisted to known_hosts")

        # second connect must NOT prompt again
        with c.websocket_connect("/ws/ssh") as ws:
            ws.send_json({"token": server.TOKEN, "id": cid, "cols": 80, "rows": 24})
            assert ws.receive_json()["type"] == "ready", "should trust the pinned key now"
        print("ok  trusted host reconnects without prompting")

    print("\ne2e passed")


main()
