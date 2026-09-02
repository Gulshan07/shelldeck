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

    # --- SFTP: list, upload, download over the real socket ------------------
    import base64
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/sftp",
                                  additional_headers={"Origin": origin}) as ws:
        await ws.send(json.dumps({"token": server.TOKEN, "id": cid, "path": os.environ["EAZY_HOME"]}))
        msg = json.loads(await ws.recv())
        assert msg["type"] == "list", msg
        print("ok  sftp listed", len(msg["entries"]), "entries in", msg["path"])
        root = msg["path"]

        payload = b"hello from eazyconnector\n" * 500
        await ws.send(json.dumps({"op": "put", "path": f"{root}/upload.bin", "size": len(payload)}))
        await ws.send(payload)
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

        await ws.send(json.dumps({"op": "get", "path": f"{root}/nope"}))
        assert json.loads(await ws.recv())["type"] == "error"
        print("ok  sftp reports a missing file instead of hanging")

    print("\nlive passed")

asyncio.run(main())
