"""Real uvicorn + real WebSocket handshake. TestClient fakes WebSockets in-process,
so it cannot catch a missing uvicorn ws implementation. This can.
Run: .venv/bin/python test_live.py"""
import asyncio, json, os, socket, tempfile, threading
os.environ["EAZY_HOME"] = tempfile.mkdtemp()

import asyncssh, uvicorn, websockets
from eazyconnector import store, server

SSHD_PORT, PW = 2298, "s3cret"


async def fake_sshd():
    async def handler(proc):
        proc.stdout.write("hi\r\n")
        async for line in proc.stdin:
            proc.stdout.write(f"you said: {line.strip()}\r\n")
        proc.exit(0)

    class S(asyncssh.SSHServer):
        def begin_auth(self, u): return True
        def password_auth_supported(self): return True
        def validate_password(self, u, p): return p == PW

    await asyncssh.create_server(S, "127.0.0.1", SSHD_PORT, process_factory=handler,
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

    origin = f"http://127.0.0.1:{port}"
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                  additional_headers={"Origin": origin}) as ws:
        print("ok  uvicorn accepted the WebSocket upgrade")
        await ws.send(json.dumps({"token": server.TOKEN, "id": cid, "cols": 80, "rows": 24}))

        msg = json.loads(await ws.recv())
        assert msg["type"] == "hostkey", msg
        await ws.send(json.dumps({"accept": True}))
        assert json.loads(await ws.recv())["type"] == "ready"
        print("ok  ssh session ready over a real socket")

        await ws.send(b"ping\n")
        buf = b""
        while b"you said" not in buf:
            chunk = await ws.recv()
            if isinstance(chunk, bytes):
                buf += chunk
        assert b"you said: ping" in buf
        print("ok  shell round-trip:", buf.decode().strip().splitlines()[-1])

    # cross-origin must be refused even with a valid token
    try:
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                      additional_headers={"Origin": "http://evil.example"}) as ws:
            await ws.send(json.dumps({"token": server.TOKEN, "id": cid}))
            await asyncio.wait_for(ws.recv(), timeout=3)
        raise AssertionError("cross-origin WebSocket was accepted!")
    except (websockets.exceptions.ConnectionClosed, websockets.exceptions.InvalidStatus):
        print("ok  cross-origin WebSocket refused")

    print("\nlive passed")

asyncio.run(main())
