"""Telnet (and serial error-path) session over the real server.
Run: .venv/bin/python test_raw.py"""
import asyncio, json, os, socket, tempfile, threading
os.environ["SHELLDECK_HOME"] = tempfile.mkdtemp()
import uvicorn, websockets
from shelldeck import store, server

IAC, WILL, DO, ECHO, SGA = 255, 251, 253, 1, 3


async def fake_telnet(port):
    async def handle(reader, writer):
        # server negotiation the client must swallow, then a banner
        writer.write(bytes([IAC, WILL, ECHO, IAC, WILL, SGA]))
        writer.write(b"telnet-banner-ready\r\n")
        await writer.drain()
        while True:
            data = await reader.read(1024)
            if not data:
                break
            writer.write(b"echo:" + data)      # echo what the client typed
            await writer.drain()
    srv = await asyncio.start_server(handle, "127.0.0.1", port)
    return srv


async def main():
    store.init_home()
    s = socket.socket(); s.bind(("127.0.0.1", 0)); tport = s.getsockname()[1]; s.close()
    await fake_telnet(tport)

    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    uv = uvicorn.Server(uvicorn.Config(server.app, host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=uv.run, daemon=True).start()
    for _ in range(60):
        await asyncio.sleep(0.1)
        if uv.started: break

    server.vault.create("rawpw-eight")
    store.save_config({"connections": [
        {"id": "t1", "name": "switch", "group": "", "host": "127.0.0.1", "port": tport,
         "user": "", "auth": "password", "jump": "", "forwards": [], "proto": "telnet"},
        {"id": "s1", "name": "console", "group": "", "host": "", "port": 0, "user": "",
         "auth": "password", "jump": "", "forwards": [], "proto": "serial",
         "serial_device": "/dev/does-not-exist", "baud": 9600},
    ]})
    origin = f"http://127.0.0.1:{port}"

    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                  additional_headers={"Origin": origin}) as ws:
        await ws.send(json.dumps({"token": server.TOKEN, "id": "t1", "cols": 80, "rows": 24}))
        assert json.loads(await ws.recv())["type"] == "ready"
        buf = b""
        while b"telnet-banner-ready" not in buf:
            m = await ws.recv()
            if isinstance(m, bytes): buf += m
        assert bytes([IAC]) not in buf, "IAC negotiation bytes leaked into the terminal"
        print("ok  telnet connected, IAC stripped, banner shown")
        await ws.send(b"show version\r\n")
        buf = b""
        for _ in range(20):
            try:
                m = await asyncio.wait_for(ws.recv(), timeout=3)
            except asyncio.TimeoutError:
                break
            if isinstance(m, bytes): buf += m
            if b"echo:show version" in buf: break
        assert b"echo:show version" in buf, f"got: {buf!r}"
        print("ok  telnet input echoed back")
        # a macro works over telnet too
        await ws.send(json.dumps({"type": "macro", "body": "send enable\nexpect echo:enable\nsend conf t"}))
        got_enable = got_conf = False
        for _ in range(60):
            m = await asyncio.wait_for(ws.recv(), timeout=10)
            if isinstance(m, bytes):
                if b"echo:enable" in m: got_enable = True
                if b"echo:conf t" in m: got_conf = True
            if got_enable and got_conf: break
        assert got_enable and got_conf, "macro should run over telnet"
        print("ok  macro runs over telnet")

    # serial with a missing device must report cleanly, not hang or crash
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                  additional_headers={"Origin": origin}) as ws:
        await ws.send(json.dumps({"token": server.TOKEN, "id": "s1", "cols": 80, "rows": 24}))
        m = json.loads(await ws.recv())
        assert m["type"] == "error", m
        print("ok  serial missing device reported:", m["message"][:50])

    # serial success over a pseudo-terminal acting as the device
    import os as _os
    master, slave = _os.openpty()
    devname = _os.ttyname(slave)
    store.save_config({"connections": [
        {"id": "s2", "name": "pty", "group": "", "host": "", "port": 0, "user": "",
         "auth": "password", "jump": "", "forwards": [], "proto": "serial",
         "serial_device": devname, "baud": 115200}]})
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                  additional_headers={"Origin": origin}) as ws:
        await ws.send(json.dumps({"token": server.TOKEN, "id": "s2", "cols": 80, "rows": 24}))
        assert json.loads(await ws.recv())["type"] == "ready"
        _os.write(master, b"serial-device-hello\r\n")     # device -> us
        buf = b""
        for _ in range(20):
            try:
                m = await asyncio.wait_for(ws.recv(), timeout=3)
            except asyncio.TimeoutError:
                break
            if isinstance(m, bytes): buf += m
            if b"serial-device-hello" in buf: break
        assert b"serial-device-hello" in buf, f"got: {buf!r}"
        print("ok  serial device output reached the terminal")
    _os.close(master); _os.close(slave)

    print("\nraw passed")

asyncio.run(main())
