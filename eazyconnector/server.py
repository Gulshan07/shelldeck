"""Local-only HTTP + WebSocket server. Secrets never cross to the browser."""
import asyncio
import contextlib
import json
import posixpath
import secrets
import shlex
import stat
import time
import uuid
from pathlib import Path

import asyncssh
from starlette.applications import Starlette
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles

from . import store

STATIC = Path(__file__).parent / "static"
IDLE_LOCK_SECONDS = 15 * 60

TOKEN = secrets.token_urlsafe(32)
vault = store.Vault()
_last_activity = time.monotonic()


def _touch():
    global _last_activity
    _last_activity = time.monotonic()


def _authed(request) -> bool:
    header = request.headers.get("authorization", "")
    return header.startswith("Bearer ") and secrets.compare_digest(header[7:], TOKEN)


def _origin_ok(scope) -> bool:
    """Reject anything not served by us: blocks CSRF and DNS rebinding."""
    origin = dict(scope["headers"]).get(b"origin", b"").decode()
    if not origin:
        return True  # non-browser client; still needs the token
    host = dict(scope["headers"]).get(b"host", b"").decode()
    return origin in (f"http://{host}", f"https://{host}")


def api(handler):
    async def wrapper(request):
        if not _origin_ok(request.scope) or not _authed(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        _touch()
        try:
            return await handler(request)
        except store.Locked:
            return JSONResponse({"error": "locked"}, status_code=423)
        except store.BadPassword:
            return JSONResponse({"error": "wrong password"}, status_code=403)

    return wrapper


# --- vault ---------------------------------------------------------------


@api
async def vault_status(request):
    return JSONResponse({"exists": vault.exists, "unlocked": vault.unlocked})


@api
async def vault_unlock(request):
    body = await request.json()
    password = body.get("password", "")
    if not vault.exists:
        if len(password) < 8:
            return JSONResponse({"error": "master password must be 8+ characters"}, status_code=400)
        await asyncio.to_thread(vault.create, password)
    else:
        await asyncio.to_thread(vault.unlock, password)
    return JSONResponse({"unlocked": True})


@api
async def vault_lock(request):
    vault.lock()
    return JSONResponse({"unlocked": False})


# --- connections ---------------------------------------------------------


@api
async def connections(request):
    cfg = store.load_config()
    if request.method == "GET":
        return JSONResponse(cfg["connections"])

    body = await request.json()
    conn = {
        "id": body.get("id") or uuid.uuid4().hex,
        "name": body["name"],
        "group": body.get("group", ""),
        "host": body["host"],
        "port": int(body.get("port") or 22),
        "user": body["user"],
        "auth": body.get("auth", "password"),
        "jump": body.get("jump", ""),
        "forwards": [l.strip() for l in (body.get("forwards") or "").splitlines() if l.strip()],
    }
    for rule in conn["forwards"]:
        try:
            parse_forward(rule)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
    rest = [c for c in cfg["connections"] if c["id"] != conn["id"]]
    cfg["connections"] = sorted(rest + [conn], key=lambda c: (c["group"], c["name"]))
    store.save_config(cfg)
    vault.put(conn["id"], {
        "password": body.get("password"),
        "key_pem": body.get("key_pem"),
        "passphrase": body.get("passphrase"),
    })
    return JSONResponse(conn)


@api
async def delete_connection(request):
    cid = request.path_params["cid"]
    cfg = store.load_config()
    cfg["connections"] = [c for c in cfg["connections"] if c["id"] != cid]
    store.save_config(cfg)
    vault.delete(cid)
    return JSONResponse({"deleted": cid})


# --- ssh -----------------------------------------------------------------


def known_hosts_entry(host, port, key) -> str:
    """OpenSSH brackets the host only for non-default ports. A "[host]:22" line
    matches nothing, so the host stays untrusted and re-prompts forever."""
    target = host if port == 22 else f"[{host}]:{port}"
    return f"{target} {key.export_public_key().decode().strip()}\n"


def parse_forward(rule: str):
    """L 8080:localhost:3306 | R 9090:localhost:22 | D 1080 -> (kind, port, host, port)"""
    parts = rule.split(None, 1)
    kind = parts[0].upper() if parts else ""
    if kind not in ("L", "R", "D") or len(parts) != 2:
        raise ValueError(f"bad rule {rule!r}: expected 'L <port>:<host>:<port>', 'R ...' or 'D <port>'")

    def port(v):
        n = int(v)
        if not 1 <= n <= 65535:
            raise ValueError(f"bad port {v!r} in {rule!r}")
        return n

    if kind == "D":
        return ("D", port(parts[1].strip()), None, None)
    listen, _, dest = parts[1].partition(":")
    dhost, _, dport = dest.rpartition(":")
    if not dhost or not dport:
        raise ValueError(f"bad rule {rule!r}: need '<port>:<host>:<port>'")
    return (kind, port(listen), dhost, port(dport))


async def _start_forwards(client, conn, stack):
    """Listeners bind to 127.0.0.1: on a shared machine 0.0.0.0 would expose the
    tunnel to every other user on this box."""
    started = []
    for rule in conn.get("forwards", []):
        kind, lport, dhost, dport = parse_forward(rule)
        if kind == "L":
            listener = await client.forward_local_port("127.0.0.1", lport, dhost, dport)
            desc = f"L 127.0.0.1:{lport} → {dhost}:{dport}"
        elif kind == "D":
            listener = await client.forward_socks("127.0.0.1", lport)
            desc = f"D socks5 127.0.0.1:{lport}"
        else:
            listener = await client.forward_remote_port("", lport, dhost, dport)
            desc = f"R remote:{lport} → {dhost}:{dport}"
        stack.callback(listener.close)
        started.append(desc)
    return started


async def _say(ws, payload) -> bool:
    """Send, tolerating a client that already went away. True if it landed."""
    try:
        await ws.send_json(payload)
        return True
    except Exception:
        return False


def _find(cid):
    return next((c for c in store.load_config()["connections"] if c["id"] == cid), None)


async def _open_chain(cid, ws, stack, chain=()):
    """Open a connection, first opening its jump host (recursively) as a tunnel."""
    conn = _find(cid)
    if conn is None:
        raise ValueError("connection not found")
    if cid in chain:
        raise ValueError("jump host chain loops back on itself")
    tunnel = None
    if conn.get("jump"):
        tunnel = await _open_chain(conn["jump"], ws, stack, chain + (cid,))
    client = await _connect(conn, cid, ws, tunnel)
    return await stack.enter_async_context(client)


async def _connect(conn, cid, ws, tunnel=None):
    """Connect with TOFU host-key verification. Never disables verification."""
    secrets_ = vault.get(cid)
    kwargs = dict(
        host=conn["host"], port=conn["port"], username=conn["user"],
        known_hosts=str(store.KNOWN_HOSTS), keepalive_interval=30, tunnel=tunnel,
    )
    if conn["auth"] == "key" and secrets_.get("key_pem"):
        kwargs["client_keys"] = [asyncssh.import_private_key(
            secrets_["key_pem"], secrets_.get("passphrase") or None)]
    else:
        kwargs["password"] = secrets_.get("password") or ""
        kwargs["client_keys"] = []

    store.KNOWN_HOSTS.touch(mode=0o600, exist_ok=True)
    try:
        return await asyncssh.connect(**kwargs)
    except asyncssh.HostKeyNotVerifiable:
        key = await asyncssh.get_server_host_key(conn["host"], port=conn["port"], tunnel=tunnel)
        if not await _say(ws, {"type": "hostkey", "host": f"{conn['host']}:{conn['port']}",
                               "name": conn["name"], "fingerprint": key.get_fingerprint(),
                               "algo": key.get_algorithm()}):
            raise ConnectionAbortedError("client left before the host key was confirmed")
        reply = await ws.receive_json()
        if reply.get("accept") is not True:
            raise ConnectionAbortedError("host key rejected")
        with open(store.KNOWN_HOSTS, "a") as f:
            f.write(known_hosts_entry(conn["host"], conn["port"], key))
        return await asyncssh.connect(**kwargs)


async def ssh_ws(ws):
    conn, first = await _ws_session(ws)
    if conn is None:
        return
    cid = first["id"]

    async with contextlib.AsyncExitStack() as stack:
        try:
            client = await _open_chain(cid, ws, stack)
        except Exception as e:
            print(f"[eazyconnector] {conn['name']}: {type(e).__name__}: {e}")
            await _say(ws, {"type": "error", "message": f"{type(e).__name__}: {e}"})
            with contextlib.suppress(Exception):
                await ws.close()
            return

        proc = await client.create_process(
            term_type="xterm-256color",
            term_size=(first.get("cols", 80), first.get("rows", 24)),
            encoding=None,
        )
        try:
            fwd = await _start_forwards(client, conn, stack)
        except Exception as e:
            fwd = []
            await _say(ws, {"type": "warn", "message": f"port forwarding: {e}"})
        await _say(ws, {"type": "ready", "forwards": fwd})

        async def pump_out():
            while not proc.stdout.at_eof():
                data = await proc.stdout.read(65536)
                if not data:
                    break
                await ws.send_bytes(data)

        out = asyncio.create_task(pump_out())
        try:
            while True:
                try:
                    msg = await ws.receive()
                except Exception:
                    break
                if msg["type"] == "websocket.disconnect":
                    break
                _touch()
                # One bad control message must not take the shell down with it.
                try:
                    if msg.get("bytes") is not None:
                        proc.stdin.write(msg["bytes"])
                    elif msg.get("text"):
                        ctl = json.loads(msg["text"])
                        if ctl.get("type") == "resize":
                            cols, rows = int(ctl["cols"]), int(ctl["rows"])
                            if cols > 0 and rows > 0:
                                proc.change_terminal_size(cols, rows)
                except Exception as e:
                    print(f"[eazyconnector] {conn['name']}: ignoring {type(e).__name__}: {e}")
        finally:
            out.cancel()
            proc.close()


# --- sftp ----------------------------------------------------------------

CHUNK = 128 * 1024
FIND_TIMEOUT = 20


async def _ws_session(ws):
    """Shared front half of both WebSocket endpoints: origin, token, connection."""
    if not _origin_ok(ws.scope):
        await ws.close(code=1008)
        return None, None
    await ws.accept()
    first = await ws.receive_json()
    if not secrets.compare_digest(first.get("token", ""), TOKEN):
        await ws.close(code=1008)
        return None, None
    _touch()
    conn = _find(first.get("id"))
    if conn is None or not vault.unlocked:
        await _say(ws, {"type": "error", "message": "unknown connection or vault locked"})
        with contextlib.suppress(Exception):
            await ws.close()
        return None, None
    return conn, first


async def _listdir(sftp, path):
    real = await sftp.realpath(path)
    entries = []
    for e in await sftp.readdir(real):
        if e.filename in (".", ".."):
            continue
        entries.append({
            "name": e.filename,
            "dir": stat.S_ISDIR(e.attrs.permissions or 0),
            "size": e.attrs.size or 0,
            "mtime": e.attrs.mtime or 0,
        })
    entries.sort(key=lambda x: (not x["dir"], x["name"].lower()))
    return {"type": "list", "path": real, "entries": entries}


async def _find_files(client, sftp, base, term):
    """Recursive search on the server. GNU find prints the metadata in one shot;
    anything else falls back to stat-ing the (capped) hits."""
    term = term.strip()
    if not term:
        return {"type": "found", "q": term, "entries": []}
    pat = shlex.quote(f"*{term}*")
    base_q = shlex.quote(base)
    fast = (f"find {base_q} -maxdepth 8 -iname {pat} -printf '%y\\t%s\\t%p\\n' "
            f"2>/dev/null | head -n 300")
    # A find over a huge tree must not wedge the pane forever.
    async def run(cmd):
        return await asyncio.wait_for(client.run(cmd, check=False), FIND_TIMEOUT)

    try:
        r = await run(fast)
    except asyncio.TimeoutError:
        return {"type": "found", "q": term, "entries": [],
                "note": f"search timed out after {FIND_TIMEOUT}s"}
    entries = []
    if r.stdout.strip():
        for line in r.stdout.splitlines():
            kind, _, rest = line.partition("\t")
            size, _, path = rest.partition("\t")
            if path:
                entries.append({"name": path, "dir": kind == "d", "size": int(size or 0)})
    else:
        try:
            r = await run(f"find {base_q} -maxdepth 8 -iname {pat} 2>/dev/null | head -n 300")
        except asyncio.TimeoutError:
            return {"type": "found", "q": term, "entries": [],
                    "note": f"search timed out after {FIND_TIMEOUT}s"}
        for path in r.stdout.splitlines():
            try:
                a = await sftp.stat(path)
                entries.append({"name": path, "dir": stat.S_ISDIR(a.permissions or 0),
                                "size": a.size or 0})
            except Exception:
                entries.append({"name": path, "dir": False, "size": 0})
    entries.sort(key=lambda e: (not e["dir"], e["name"].lower()))
    return {"type": "found", "q": term, "entries": entries}


async def sftp_ws(ws):
    conn, first = await _ws_session(ws)
    if conn is None:
        return

    async with contextlib.AsyncExitStack() as stack:
        try:
            client = await _open_chain(first["id"], ws, stack)
            sftp = await client.start_sftp_client()
            stack.callback(sftp.exit)
            await _say(ws, await _listdir(sftp, first.get("path") or "."))
        except Exception as e:
            print(f"[eazyconnector] sftp {conn['name']}: {type(e).__name__}: {e}")
            await _say(ws, {"type": "error", "message": f"{type(e).__name__}: {e}"})
            with contextlib.suppress(Exception):
                await ws.close()
            return

        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            _touch()
            if not msg.get("text"):
                continue
            req = json.loads(msg["text"])
            op = req.get("op")
            try:
                if op == "ls":
                    await _say(ws, await _listdir(sftp, req["path"]))

                elif op == "get":
                    path = req["path"]
                    size = (await sftp.stat(path)).size or 0
                    await _say(ws, {"type": "download", "name": posixpath.basename(path), "size": size})
                    async with sftp.open(path, "rb") as f:
                        while True:
                            chunk = await f.read(CHUNK)
                            if not chunk:
                                break
                            await ws.send_bytes(chunk)
                    await _say(ws, {"type": "download_end"})

                elif op == "put":
                    # Binary frames follow until the announced size is reached.
                    remaining = int(req["size"])
                    async with sftp.open(req["path"], "wb") as f:
                        while remaining > 0:
                            frame = await ws.receive()
                            # Returning here unwinds the stack cleanly. Raising would
                            # loop back to ws.receive() after a disconnect, which is
                            # a RuntimeError, not something to report to a gone client.
                            if frame["type"] == "websocket.disconnect":
                                return
                            data = frame.get("bytes")
                            if data is None:
                                continue
                            await f.write(data)
                            remaining -= len(data)
                    await _say(ws, {"type": "uploaded", "name": posixpath.basename(req["path"])})
                    await _say(ws, await _listdir(sftp, posixpath.dirname(req["path"]) or "."))

                elif op == "find":
                    await _say(ws, await _find_files(client, sftp, req.get("path") or ".",
                                               req.get("q", "")))

                else:
                    await _say(ws, {"type": "error", "message": f"unknown op {op!r}"})
            except Exception as e:
                await _say(ws, {"type": "error", "message": f"{type(e).__name__}: {e}"})


# --- app -----------------------------------------------------------------


async def index(request):
    return FileResponse(STATIC / "index.html")


async def _idle_locker():
    while True:
        await asyncio.sleep(30)
        if vault.unlocked and time.monotonic() - _last_activity > IDLE_LOCK_SECONDS:
            vault.lock()


@contextlib.asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(_idle_locker())
    yield
    task.cancel()


app = Starlette(
    routes=[
        Route("/", index),
        Route("/api/vault", vault_status),
        Route("/api/vault/unlock", vault_unlock, methods=["POST"]),
        Route("/api/vault/lock", vault_lock, methods=["POST"]),
        Route("/api/connections", connections, methods=["GET", "POST"]),
        Route("/api/connections/{cid}", delete_connection, methods=["DELETE"]),
        WebSocketRoute("/ws/ssh", ssh_ws),
        WebSocketRoute("/ws/sftp", sftp_ws),
        Mount("/static", StaticFiles(directory=STATIC)),
    ],
    lifespan=lifespan,
)
