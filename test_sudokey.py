"""The unreadable-key sudo flow, end to end, with fake sudo + real sshd.
Run: .venv/bin/python test_sudokey.py"""
import asyncio, json, os, socket, tempfile, threading, time
os.environ["EAZY_HOME"] = tempfile.mkdtemp()
os.environ["PATH"] = os.path.abspath("testbin") + os.pathsep + os.environ["PATH"]
os.environ["FAKE_SUDO_PASSWORD"] = "my-sudo-pw"

import asyncssh, uvicorn, websockets
from eazyconnector import store, server

SSHD_PORT = 2293


async def sshd(authorized_key):
    async def handler(proc):
        proc.stdout.write("ok\r\n"); proc.exit(0)
    class S(asyncssh.SSHServer):
        def begin_auth(self, u): return True
        def public_key_auth_supported(self): return True
    await asyncssh.create_server(
        S, "127.0.0.1", SSHD_PORT, process_factory=handler,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        authorized_client_keys=authorized_key)


async def main():
    store.init_home()
    # a client key the sshd will accept
    ckey = asyncssh.generate_private_key("ssh-ed25519")
    keypath = os.path.join(os.environ["EAZY_HOME"], "root_owned.pem")
    open(keypath, "w").write(ckey.export_private_key().decode())
    authp = os.path.join(os.environ["EAZY_HOME"], "authorized")
    open(authp, "w").write(ckey.export_public_key().decode())
    await sshd(authp)

    # simulate "root-owned, unreadable": chmod 000 so open() raises PermissionError
    os.chmod(keypath, 0)

    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    uv = uvicorn.Server(uvicorn.Config(server.app, host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=uv.run, daemon=True).start()
    for _ in range(60):
        await asyncio.sleep(0.1)
        if uv.started: break

    server.vault.create("m")
    cid = "k1"
    store.save_config({"connections": [{
        "id": cid, "name": "rootkey", "group": "", "host": "127.0.0.1", "port": SSHD_PORT,
        "user": "ubuntu", "auth": "key", "jump": "", "forwards": [], "key_path": keypath}]})
    server.vault.put(cid, {})            # no key_pem: it's unreadable on disk
    store.KNOWN_HOSTS.write_text(server.known_hosts_entry(
        "127.0.0.1", SSHD_PORT, await asyncssh.get_server_host_key("127.0.0.1", port=SSHD_PORT)))

    origin = f"http://127.0.0.1:{port}"

    # 1. wrong sudo password -> clear failure, key not cached
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                  additional_headers={"Origin": origin}) as ws:
        await ws.send(json.dumps({"token": server.TOKEN, "id": cid, "cols": 80, "rows": 24}))
        m = json.loads(await ws.recv())
        assert m["type"] == "need_key_sudo" and m["path"] == keypath, m
        await ws.send(json.dumps({"sudo_password": "WRONG"}))
        m = json.loads(await ws.recv())
        assert m["type"] == "error" and "sudo" in m["message"].lower(), m
    assert not server.vault.get(cid).get("key_pem"), "a failed sudo must not cache anything"
    print("ok  wrong sudo password reported, nothing cached")

    # 2. correct sudo password -> key read, cached, session connects
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                  additional_headers={"Origin": origin}) as ws:
        await ws.send(json.dumps({"token": server.TOKEN, "id": cid, "cols": 80, "rows": 24}))
        m = json.loads(await ws.recv())
        assert m["type"] == "need_key_sudo", m
        await ws.send(json.dumps({"sudo_password": "my-sudo-pw"}))
        m = json.loads(await ws.recv())
        assert m["type"] == "ready", m
    assert server.vault.get(cid)["key_pem"].startswith("-----BEGIN"), "key should be cached now"
    print("ok  correct sudo read the root-owned key and connected")

    # 3. second connect must NOT ask for sudo again
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws/ssh",
                                  additional_headers={"Origin": origin}) as ws:
        await ws.send(json.dumps({"token": server.TOKEN, "id": cid, "cols": 80, "rows": 24}))
        m = json.loads(await ws.recv())
        assert m["type"] == "ready", f"should reuse the cached key, got {m}"
    print("ok  cached key reused, no second sudo prompt")

    print("\nsudokey passed")

asyncio.run(main())
