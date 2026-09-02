"""Local-only HTTP + WebSocket server. Secrets never cross to the browser."""
import asyncio
import contextlib
import json
import secrets
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
    }
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
    if not _origin_ok(ws.scope):
        await ws.close(code=1008)
        return
    await ws.accept()
    # Token arrives as the first message: keeps it out of URLs and access logs.
    first = await ws.receive_json()
    if not secrets.compare_digest(first.get("token", ""), TOKEN):
        await ws.close(code=1008)
        return
    _touch()

    cid = first.get("id")
    conn = _find(cid)
    if conn is None or not vault.unlocked:
        await _say(ws, {"type": "error", "message": "unknown connection or vault locked"})
        with contextlib.suppress(Exception):
            await ws.close()
        return

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
        await ws.send_json({"type": "ready"})

        async def pump_out():
            while not proc.stdout.at_eof():
                data = await proc.stdout.read(65536)
                if not data:
                    break
                await ws.send_bytes(data)

        out = asyncio.create_task(pump_out())
        try:
            while True:
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                if msg.get("bytes") is not None:
                    proc.stdin.write(msg["bytes"])
                elif msg.get("text"):
                    ctl = json.loads(msg["text"])
                    if ctl.get("type") == "resize":
                        proc.change_terminal_size(ctl["cols"], ctl["rows"])
                _touch()
        except Exception:
            pass
        finally:
            out.cancel()
            proc.close()


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
        Mount("/static", StaticFiles(directory=STATIC)),
    ],
    lifespan=lifespan,
)
