"""Local-only HTTP + WebSocket server. Secrets never cross to the browser."""
import asyncio
import contextlib
import json
import os
import posixpath
import re
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
from .vpn import Vpn, VpnError, code_for, detect_dialect, parse_totp_input, totp_mode_of
from . import importers, macros as macro_mod, platform, session_log

STATIC = Path(__file__).parent / "static"
IDLE_LOCK_SECONDS = 15 * 60

TOKEN = secrets.token_urlsafe(32)
vault = store.Vault()
vpn = Vpn()
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


@api
async def vault_change(request):
    if not vault.unlocked:
        return JSONResponse({"error": "locked"}, status_code=423)
    body = await request.json()
    old, new = body.get("old", ""), body.get("new", "")
    if len(new) < 8:
        return JSONResponse({"error": "new master password must be 8+ characters"}, status_code=400)
    try:
        await asyncio.to_thread(vault.rekey, old, new)
    except store.BadPassword:
        return JSONResponse({"error": "current password is wrong"}, status_code=403)
    return JSONResponse({"ok": True})


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
        "key_path": body.get("key_path", ""),
        "log": bool(body.get("log")),
        "keepalive": int(body.get("keepalive") or 30),
        "local_before": (body.get("local_before") or "").strip(),
        "remote_command": (body.get("remote_command") or "").strip(),
        "local_after": (body.get("local_after") or "").strip(),
        "macros": [m for m in (body.get("macros") or []) if m],
        "autorun_macro": body.get("autorun_macro") or "",
        "proto": body.get("proto") or "ssh",
        "serial_device": (body.get("serial_device") or "").strip(),
        "baud": int(body.get("baud") or 115200),
    }
    for rule in conn["forwards"]:
        try:
            parse_forward(rule)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
    rest = [c for c in cfg["connections"] if c["id"] != conn["id"]]
    cfg["connections"] = sorted(rest + [conn], key=lambda c: (c["group"], c["name"]))
    store.save_config(cfg)
    # The editor never shows stored secrets (they never leave the server), so a blank
    # field means "unchanged", not "clear it" — otherwise editing a key connection
    # and saving would wipe the key it never displayed.
    old = vault.get(conn["id"])
    vault.put(conn["id"], {
        "password": body.get("password") or old.get("password"),
        "key_pem": body.get("key_pem") or old.get("key_pem"),
        "passphrase": body.get("passphrase") or old.get("passphrase"),
    })
    return JSONResponse(conn)


def next_clone_name(name: str, taken: set) -> str:
    """`web-01` -> `web-01-1`; cloning that gives `web-01-2`, not `web-01-1-1`.

    A trailing `-N` counts as a clone suffix only when the name without it is
    really in the group, so a host genuinely called `web-01` keeps its number.
    """
    base = re.sub(r"-\d+$", "", name)
    if base == name or base not in taken:
        base = name
    n = 1
    while f"{base}-{n}" in taken:
        n += 1
    return f"{base}-{n}"


@api
async def clone_connection(request):
    """Duplicate a connection, credentials included, into the same group.

    Server-side because the editor never receives stored secrets, so a copy made
    in the browser would come back with no password or key.
    """
    cid = request.path_params["cid"]
    cfg = store.load_config()
    src = next((c for c in cfg["connections"] if c["id"] == cid), None)
    if not src:
        return JSONResponse({"error": "no such connection"}, status_code=404)

    body = await request.json() if await request.body() else {}
    group = src.get("group", "")
    taken = {c["name"] for c in cfg["connections"] if c.get("group", "") == group}
    name = (body.get("name") or "").strip() or next_clone_name(src["name"], taken)

    clone = {**src, "id": uuid.uuid4().hex, "name": name}
    cfg["connections"] = sorted(cfg["connections"] + [clone],
                                key=lambda c: (c["group"], c["name"]))
    store.save_config(cfg)
    vault.put(clone["id"], vault.get(cid))
    return JSONResponse(clone)


@api
async def delete_connection(request):
    cid = request.path_params["cid"]
    cfg = store.load_config()
    cfg["connections"] = [c for c in cfg["connections"] if c["id"] != cid]
    store.save_config(cfg)
    vault.delete(cid)
    return JSONResponse({"deleted": cid})


# --- import --------------------------------------------------------------

IMPORT_SOURCES = {
    "ssh_config": ("~/.ssh/config", "ssh"),
    "asbru": ("~/.config/asbru/asbru.yml", "asbru"),
    "bundle": (None, "bundle"),     # an exported Shelldeck file, sent in the body
}


def _parse_source(source: str, path: str):
    fp = os.path.expanduser(path)
    if not os.path.exists(fp):
        raise FileNotFoundError(fp)
    if source == "ssh_config":
        return importers.from_ssh_config(open(fp, encoding="utf-8", errors="replace").read())
    import yaml
    return importers.from_asbru(yaml.safe_load(open(fp, encoding="utf-8", errors="replace")))


def _dupe_key(c):
    # Serial connections have no host/port to compare, so key them by device+name;
    # otherwise every serial entry would collide and be skipped as a duplicate.
    if (c.get("proto") or "ssh") == "serial":
        return ("serial", (c.get("serial_device") or "").strip().lower(),
                (c.get("name") or "").strip().lower())
    return ((c.get("host") or "").strip().lower(), (c.get("user") or "").strip().lower(),
            int(c.get("port") or 22))


async def _resolve_import(source, body):
    """(connections, warnings, label) for any import source."""
    if source == "bundle":
        data = body.get("bundle")
        if not isinstance(data, dict):
            raise ValueError("no export file contents in the request")
        conns, warnings = importers.from_bundle(data)
        return conns, warnings, "shared export file"
    path = body.get("path") or IMPORT_SOURCES[source][0]
    conns, warnings = await asyncio.to_thread(_parse_source, source, path)
    return conns, warnings, os.path.expanduser(path)


@api
async def export_bundle(request):
    """Shareable snapshot: structure only, no secrets. See importers.SHAREABLE."""
    cfg = store.load_config()
    bundle = importers.to_bundle(cfg["connections"])
    bundle["exported"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    return JSONResponse(bundle)


@api
async def import_preview(request):
    source = request.path_params["source"]
    if source not in IMPORT_SOURCES:
        return JSONResponse({"error": "unknown source"}, status_code=404)
    body = await request.json() if request.method == "POST" else {}
    try:
        conns, warnings, label = await _resolve_import(source, body)
    except FileNotFoundError as e:
        return JSONResponse({"error": f"not found: {e}"}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": f"{type(e).__name__}: {e}"}, status_code=400)

    existing = {_dupe_key(c) for c in store.load_config()["connections"]}
    # Commit also collapses duplicates *within* one batch, so count them the same
    # way here — otherwise the preview promises more than the import creates.
    seen = set(existing)
    groups = {}
    key_missing, key_unreadable = [], []
    for c in conns:
        dk = _dupe_key(c)
        c["_dupe"] = dk in seen
        seen.add(dk)
        groups[c["group"]] = groups.get(c["group"], 0) + 1
        kf = c.get("_keyfile")
        if kf and not os.path.exists(kf):
            key_missing.append(kf)
        elif kf:
            try:
                open(kf, "rb").close()
            except OSError:
                key_unreadable.append(kf)
    return JSONResponse({
        "path": label,
        "total": len(conns),
        "new": sum(not c["_dupe"] for c in conns),
        "duplicates": sum(c["_dupe"] for c in conns),
        "groups": sorted(groups),
        "key_files_missing": sorted(set(key_missing)),
        "key_files_unreadable": sorted(set(key_unreadable)),
        "warnings": warnings,
        "connections": [{"name": c["name"], "group": c["group"],
                         "target": f"{c['user']}@{c['host']}:{c['port']}" if c["user"] else f"{c['host']}:{c['port']}",
                         "auth": c["auth"], "dupe": c["_dupe"],
                         "via": next((x["name"] for x in conns if x["id"] == c["jump"]), "")}
                        for c in conns],
    })


@api
async def import_commit(request):
    source = request.path_params["source"]
    if source not in IMPORT_SOURCES:
        return JSONResponse({"error": "unknown source"}, status_code=404)
    if not vault.unlocked:
        return JSONResponse({"error": "locked"}, status_code=423)
    body = await request.json()
    try:
        conns, warnings, _label = await _resolve_import(source, body)
    except Exception as e:
        return JSONResponse({"error": f"{type(e).__name__}: {e}"}, status_code=400)

    cfg = store.load_config()
    existing = {_dupe_key(c) for c in cfg["connections"]}
    # A jump host we skip as a duplicate must still resolve to the connection the
    # user already has, so links do not dangle.
    id_remap = {}
    for c in cfg["connections"]:
        id_remap.setdefault(_dupe_key(c), c["id"])

    created, skipped, key_read, key_failed = 0, 0, 0, []
    to_add = []
    for c in conns:
        dk = _dupe_key(c)
        if dk in existing:
            id_remap.setdefault(dk, id_remap.get(dk, c["id"]))
            skipped += 1
            continue
        id_remap[dk] = c["id"]
        existing.add(dk)
        to_add.append(c)

    for c in to_add:
        # Re-point a jump to whatever real id its target ended up with (existing or new).
        if c["jump"]:
            tgt = next((x for x in conns if x["id"] == c["jump"]), None)
            if tgt:
                c["jump"] = id_remap.get(_dupe_key(tgt), c["jump"])
        kf = c.pop("_keyfile", None)
        c.pop("_dupe", None)
        if kf:
            c["key_path"] = kf            # remembered so an unreadable key can be read later
        secrets_ = {}
        if c["auth"] == "key" and kf:
            try:
                secrets_["key_pem"] = open(kf, encoding="utf-8", errors="strict").read()
                key_read += 1
            except Exception as e:
                # Keep auth=key so connecting says "add the key" rather than silently
                # trying an empty password. Report why (often the file is root-owned).
                reason = "permission denied" if isinstance(e, PermissionError) else \
                         "not found" if isinstance(e, FileNotFoundError) else type(e).__name__
                key_failed.append(f"{c['name']}: cannot read {kf} ({reason})")
        cfg["connections"].append(c)
        vault.put(c["id"], secrets_)
        created += 1

    cfg["connections"].sort(key=lambda c: (c["group"], c["name"]))
    store.save_config(cfg)
    return JSONResponse({"created": created, "skipped": skipped, "keys_imported": key_read,
                         "key_failures": key_failed, "warnings": warnings})


# --- macros --------------------------------------------------------------


@api
async def macros_list(request):
    if not vault.unlocked:
        return JSONResponse({"error": "locked"}, status_code=423)
    store_ = vault.get("macros") or {}
    if request.method == "GET":
        # names + bodies; the UI needs the body to run it. It's already in the vault.
        return JSONResponse([{"name": k, "body": v} for k, v in sorted(store_.items())])
    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name:
        return JSONResponse({"error": "name required"}, status_code=400)
    store_ = dict(store_)
    store_[name] = body.get("body", "")
    vault.put("macros", store_)
    return JSONResponse({"ok": True})


@api
async def macro_delete(request):
    store_ = dict(vault.get("macros") or {})
    if store_.pop(request.path_params["name"], None) is not None:
        vault.put("macros", store_)
    return JSONResponse({"deleted": request.path_params["name"]})


# --- session logs --------------------------------------------------------


@api
async def logs_list(request):
    return JSONResponse(session_log.list_logs())


def _log_path(name):
    # Resolve inside LOGS only; reject any traversal.
    p = (store.LOGS / name).resolve()
    if p.parent != store.LOGS.resolve() or p.suffix != ".eclog":
        return None
    return p


@api
async def log_get(request):
    if not vault.unlocked:
        return JSONResponse({"error": "locked"}, status_code=423)
    p = _log_path(request.path_params["name"])
    if p is None or not p.exists():
        return JSONResponse({"error": "no such log"}, status_code=404)
    try:
        text = session_log.read_log(vault, p)
    except Exception as e:
        return JSONResponse({"error": f"could not decrypt: {e}"}, status_code=400)
    from starlette.responses import PlainTextResponse
    return PlainTextResponse(text.decode("utf-8", "replace"))


@api
async def log_frames(request):
    """Timed frames for playback: [[ms, base64], ...]."""
    if not vault.unlocked:
        return JSONResponse({"error": "locked"}, status_code=423)
    p = _log_path(request.path_params["name"])
    if p is None or not p.exists():
        return JSONResponse({"error": "no such log"}, status_code=404)
    import base64 as _b64
    try:
        frames = [[ms, _b64.b64encode(data).decode()]
                  for ms, data in session_log.read_frames(vault, p)]
    except Exception as e:
        return JSONResponse({"error": f"could not decrypt: {e}"}, status_code=400)
    return JSONResponse({"frames": frames})


@api
async def log_delete(request):
    p = _log_path(request.path_params["name"])
    if p is None:
        return JSONResponse({"error": "bad name"}, status_code=400)
    p.unlink(missing_ok=True)
    return JSONResponse({"deleted": request.path_params["name"]})


# --- vpn -----------------------------------------------------------------


@api
async def vpns(request):
    cfg = store.load_config()
    if request.method == "GET":
        return JSONResponse([{**v, "totp_mode": totp_mode_of(v, vault.get("vpn:" + v["id"]))}
                             for v in cfg.get("vpns", [])])

    body = await request.json()
    ovpn = body.get("ovpn") or ""
    vid = body.get("id") or uuid.uuid4().hex
    old = vault.get("vpn:" + vid)
    was = next((v for v in cfg.get("vpns", []) if v["id"] == vid), {})

    # Work out the authenticator setting before anything is written, so a
    # rejected save changes nothing.
    mode = body.get("totp_mode") or totp_mode_of(was, old)
    key = {k: v for k, v in old.items() if k.startswith("totp_")}
    fresh = False
    if body.get("totp_input"):
        try:
            accounts = parse_totp_input(body["totp_input"])
            pick = body.get("totp_account")
            if len(accounts) > 1 and pick in (None, ""):
                # Labels only: the keys stay on this side.
                return JSONResponse({"error": "choose an account", "accounts": [
                    {"index": i, "label": a["label"], "issuer": a["issuer"]}
                    for i, a in enumerate(accounts)]}, status_code=409)
            pick = int(pick or 0)
            if not 0 <= pick < len(accounts):
                raise ValueError("no such account in that export")
        except (ValueError, TypeError) as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        a = accounts[pick]
        key = {"totp_secret": a["secret"]}
        for name, default in (("digits", 6), ("period", 30), ("algorithm", "SHA1")):
            if a[name] != default:
                key["totp_" + name] = a[name]
        mode, fresh = "stored", True
    if mode not in ("none", "ask", "stored"):
        return JSONResponse({"error": "totp_mode must be none, ask or stored"}, status_code=400)
    if mode == "stored" and not key.get("totp_secret"):
        return JSONResponse({"error": "no authenticator key given"}, status_code=400)
    if mode != "stored":
        key = {}                      # an unused key does not stay in the vault
    prof = {
        "id": vid,
        "name": body["name"],
        "username": body.get("username", ""),
        "dialect": body.get("dialect") or "auto",
        "totp_mode": mode,
    }
    rest = [v for v in cfg.get("vpns", []) if v["id"] != prof["id"]]
    cfg["vpns"] = sorted(rest + [prof], key=lambda v: v["name"])
    store.save_config(cfg)

    secret = {
        # Keep the previously imported profile when the form leaves the box empty.
        "ovpn": ovpn or old.get("ovpn"),
        "password": body.get("password") or old.get("password"),
        "key_passphrase": body.get("key_passphrase") or old.get("key_passphrase"),
        "sudo_password": body.get("sudo_password") or old.get("sudo_password"),
        **key,
    }
    vault.put("vpn:" + vid, secret)
    if fresh:
        prof["totp_now"] = code_for(secret)   # once, so it can be checked against the phone
    prof["detected"] = detect_dialect(ovpn or old.get("ovpn") or "")
    return JSONResponse(prof)


@api
async def delete_vpn(request):
    vid = request.path_params["vid"]
    cfg = store.load_config()
    cfg["vpns"] = [v for v in cfg.get("vpns", []) if v["id"] != vid]
    store.save_config(cfg)
    vault.delete("vpn:" + vid)
    return JSONResponse({"deleted": vid})


@api
async def vpn_status(request):
    return JSONResponse(vpn.status())


@api
async def vpn_up(request):
    vid = request.path_params["vid"]
    prof = next((v for v in store.load_config().get("vpns", []) if v["id"] == vid), None)
    if prof is None:
        return JSONResponse({"error": "unknown vpn profile"}, status_code=404)
    try:
        await vpn.up(prof, vault.get("vpn:" + vid))
    except VpnError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    return JSONResponse(vpn.status())


@api
async def vpn_code(request):
    """The authenticator code for a profile that stores no key."""
    try:
        vpn.submit_code(str((await request.json()).get("code", "")))
    except VpnError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    return JSONResponse(vpn.status())


@api
async def vpn_down(request):
    await vpn.down()
    return JSONResponse(vpn.status())


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


async def _read_key_with_sudo(path, ws) -> bool:
    """Ask the browser for a sudo password and read a root-owned key with it,
    once. The password is used immediately and never stored."""
    await _say(ws, {"type": "need_key_sudo", "path": path})
    reply = await ws.receive_json()
    pw = reply.get("sudo_password")
    if not pw:
        return False
    proc = await asyncio.create_subprocess_exec(
        "sudo", "-S", "-p", "", "cat", path,          # exec, not shell: path is not interpolated
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate((pw + "\n").encode())
    del pw
    if proc.returncode != 0:
        raise ValueError("sudo could not read the key: "
                         + (err.decode(errors="replace").strip() or "wrong password?"))
    try:
        asyncssh.import_private_key(out.decode("utf-8", "strict"))
    except Exception as e:
        raise ValueError(f"that file is not a usable private key ({e})")
    # ponytail: caches a root-owned key into the user's vault so sudo is asked once.
    # The user consented by entering sudo; chown would be the alternative.
    return out.decode("utf-8")


async def _ensure_key(conn, cid, ws):
    """Make sure a key connection has its PEM in the vault, recovering an
    unreadable key file via sudo if the user allows it."""
    secrets_ = vault.get(cid)
    if conn["auth"] != "key" or secrets_.get("key_pem"):
        return
    path = conn.get("key_path")
    if not path or not os.path.exists(path):
        return                                        # _connect raises the clear error
    try:
        pem = open(path, encoding="utf-8", errors="strict").read()   # readable now?
    except PermissionError:
        if not platform.sudo_available():
            # No sudo (Windows): escalating is not something we can do for them.
            raise ValueError(f"{conn['name']}: cannot read {path}. Grant your user read "
                             "access to that file, or paste the key into the connection.")
        pem = await _read_key_with_sudo(path, ws)     # root-owned: ask for sudo
    secrets_ = dict(secrets_)
    secrets_["key_pem"] = pem
    vault.put(cid, secrets_)


async def _connect(conn, cid, ws, tunnel=None):
    """Connect with TOFU host-key verification. Never disables verification."""
    await _ensure_key(conn, cid, ws)
    secrets_ = vault.get(cid)
    kwargs = dict(
        host=conn["host"], port=conn["port"], username=conn["user"],
        known_hosts=str(store.KNOWN_HOSTS),
        keepalive_interval=int(conn.get("keepalive") or 30), tunnel=tunnel,
    )
    if conn["auth"] == "key":
        if not secrets_.get("key_pem"):
            raise ValueError(f"{conn['name']}: no private key stored — open the connection and add "
                             "the key file, or switch Auth to Password")
        try:
            key = asyncssh.import_private_key(
                secrets_["key_pem"], secrets_.get("passphrase") or None)
        except asyncssh.KeyImportError as e:
            raise ValueError(f"{conn['name']}: could not load the private key "
                             f"({e}). If it is passphrase-protected, add the passphrase.")
        kwargs["client_keys"] = [key]
    else:
        kwargs["password"] = secrets_.get("password") or ""
        kwargs["client_keys"] = []

    store.KNOWN_HOSTS.touch(exist_ok=True)
    platform.lock_file(store.KNOWN_HOSTS)
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


async def _run_local(cmd, ws, label):
    """Run a local command (the user's own, from their 0600 config) and stream
    its output into the terminal as dim text. Best-effort, 60s cap."""
    await _say_bytes_line(ws, f"\x1b[90m$ {cmd}\x1b[0m")
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, cwd=str(store.HOME), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), 60)
        if out:
            with contextlib.suppress(Exception):
                await ws.send_bytes(out.replace(b"\n", b"\r\n"))
        if proc.returncode:
            await _say_bytes_line(ws, f"\x1b[33m{label} exited {proc.returncode}\x1b[0m")
    except asyncio.TimeoutError:
        await _say_bytes_line(ws, f"\x1b[33m{label} timed out after 60s\x1b[0m")
    except Exception as e:
        await _say_bytes_line(ws, f"\x1b[33m{label}: {e}\x1b[0m")


async def _say_bytes_line(ws, text):
    with contextlib.suppress(Exception):
        await ws.send_bytes((text + "\r\n").encode())


# telnet negotiation bytes
_IAC, _SE, _SB, _WILL, _WONT, _DO, _DONT = 255, 240, 250, 251, 252, 253, 254


def _telnet_filter(data: bytes, writer) -> bytes:
    """Strip telnet IAC sequences and refuse every option, so the terminal sees
    clean text. ponytail: an IAC split across reads loses one byte — rare, and
    only worth a state machine if a device actually trips on it."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == _IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd in (_DO, _DONT, _WILL, _WONT) and i + 2 < len(data):
                opt = data[i + 2]
                if cmd == _DO:
                    writer.write(bytes([_IAC, _WONT, opt]))
                elif cmd == _WILL:
                    writer.write(bytes([_IAC, _DONT, opt]))
                i += 3
                continue
            if cmd == _SB:                      # sub-negotiation: skip to IAC SE
                j = i + 2
                while j + 1 < len(data) and not (data[j] == _IAC and data[j + 1] == _SE):
                    j += 1
                i = j + 2
                continue
            i += 2
            continue
        out.append(b)
        i += 1
    return bytes(out)


async def raw_session(ws, conn):
    """Telnet or serial: a plain byte stream, no SSH, no jump, no host key."""
    proto = conn["proto"]
    try:
        if proto == "telnet":
            reader, writer = await asyncio.open_connection(conn["host"], conn["port"])
        else:  # serial
            import serial_asyncio
            device = conn.get("serial_device") or conn["host"]
            reader, writer = await serial_asyncio.open_serial_connection(
                url=device, baudrate=int(conn.get("baud") or 115200))
    except ImportError:
        await _say(ws, {"type": "error", "message": "serial support needs pyserial-asyncio "
                        "(pip install pyserial-asyncio)"})
        with contextlib.suppress(Exception):
            await ws.close()
        return
    except Exception as e:
        await _say(ws, {"type": "error", "message": f"{type(e).__name__}: {e}"})
        with contextlib.suppress(Exception):
            await ws.close()
        return

    await _say(ws, {"type": "ready", "forwards": []})
    logger = session_log.SessionLog(vault, conn["name"]) if conn.get("log") else None
    recent = bytearray()

    async def pump():
        while True:
            data = await reader.read(65536)
            if not data:
                break
            if proto == "telnet":
                data = _telnet_filter(data, writer)
                if not data:
                    continue
            if logger:
                logger.write(data)
            recent.extend(data)
            del recent[:-16384]
            await ws.send_bytes(data)
        with contextlib.suppress(Exception):
            await ws.close()          # remote end hung up: same as the ssh pump

    async def run_macro(body):
        try:
            async for status in macro_mod.run(macro_mod.parse(body), writer.write, recent):
                await _say(ws, {"type": "macro_status", "message": status})
            await _say(ws, {"type": "macro_status", "message": "macro done", "done": True})
        except Exception as e:
            await _say(ws, {"type": "macro_status", "message": f"macro stopped: {e}",
                            "done": True, "error": True})

    out = asyncio.create_task(pump())
    try:
        while True:
            try:
                msg = await ws.receive()
            except Exception:
                break
            if msg["type"] == "websocket.disconnect":
                break
            _touch()
            try:
                if msg.get("bytes") is not None:
                    writer.write(msg["bytes"])
                elif msg.get("text"):
                    ctl = json.loads(msg["text"])
                    if ctl.get("type") == "macro" and ctl.get("body"):
                        asyncio.create_task(run_macro(ctl["body"]))
            except Exception as e:
                print(f"[shelldeck] {conn['name']}: ignoring {type(e).__name__}: {e}")
    finally:
        out.cancel()
        if logger:
            logger.close()
        with contextlib.suppress(Exception):
            writer.close()


async def ssh_ws(ws):
    conn, first = await _ws_session(ws)
    if conn is None:
        return
    if conn.get("proto") in ("telnet", "serial"):
        await raw_session(ws, conn)
        return
    cid = first["id"]

    async with contextlib.AsyncExitStack() as stack:
        if conn.get("local_before"):
            await _run_local(conn["local_before"], ws, "pre-connect command")
        try:
            client = await _open_chain(cid, ws, stack)
        except Exception as e:
            print(f"[shelldeck] {conn['name']}: {type(e).__name__}: {e}")
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

        if conn.get("remote_command"):
            # Auto-run after login, as if typed. Newline submits it.
            proc.stdin.write((conn["remote_command"] + "\n").encode())

        logger = session_log.SessionLog(vault, conn["name"]) if conn.get("log") else None

        recent = bytearray()   # last chunk of output, for macro `expect` matching

        async def pump_out_logged():
            while not proc.stdout.at_eof():
                data = await proc.stdout.read(65536)
                if not data:
                    break
                if logger:
                    logger.write(data)
                recent.extend(data)
                del recent[:-16384]      # keep only the tail
                await ws.send_bytes(data)
            # The shell ended (`exit`, logout, server gone): end the session here
            # too, or the pane keeps looking connected while its input goes nowhere.
            with contextlib.suppress(Exception):
                await ws.close()

        async def run_macro(body):
            try:
                async for status in macro_mod.run(macro_mod.parse(body), proc.stdin.write, recent):
                    await _say(ws, {"type": "macro_status", "message": status})
                await _say(ws, {"type": "macro_status", "message": "macro done", "done": True})
            except Exception as e:
                await _say(ws, {"type": "macro_status", "message": f"macro stopped: {e}",
                                "done": True, "error": True})

        out = asyncio.create_task(pump_out_logged())

        if conn.get("autorun_macro"):
            body = (vault.get("macros") or {}).get(conn["autorun_macro"])
            if body:
                asyncio.create_task(run_macro(body))
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
                        elif ctl.get("type") == "macro" and ctl.get("body"):
                            asyncio.create_task(run_macro(ctl["body"]))
                except Exception as e:
                    print(f"[shelldeck] {conn['name']}: ignoring {type(e).__name__}: {e}")
        finally:
            out.cancel()
            if logger:
                logger.close()
            proc.close()
            if conn.get("local_after"):
                await _run_local(conn["local_after"], ws, "post-disconnect command")


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
            print(f"[shelldeck] sftp {conn['name']}: {type(e).__name__}: {e}")
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
        Route("/api/vault/change", vault_change, methods=["POST"]),
        Route("/api/connections", connections, methods=["GET", "POST"]),
        Route("/api/connections/{cid}", delete_connection, methods=["DELETE"]),
        Route("/api/connections/{cid}/clone", clone_connection, methods=["POST"]),
        Route("/api/macros", macros_list, methods=["GET", "POST"]),
        Route("/api/macros/{name}", macro_delete, methods=["DELETE"]),
        Route("/api/logs", logs_list),
        Route("/api/logs/{name}", log_get, methods=["GET"]),
        Route("/api/logs/{name}/frames", log_frames),
        Route("/api/logs/{name}", log_delete, methods=["DELETE"]),
        Route("/api/export", export_bundle),
        Route("/api/import/{source}/preview", import_preview, methods=["GET", "POST"]),
        Route("/api/import/{source}/commit", import_commit, methods=["POST"]),
        Route("/api/vpns", vpns, methods=["GET", "POST"]),
        Route("/api/vpns/{vid}", delete_vpn, methods=["DELETE"]),
        Route("/api/vpn/status", vpn_status),
        Route("/api/vpn/{vid}/up", vpn_up, methods=["POST"]),
        Route("/api/vpn/code", vpn_code, methods=["POST"]),
        Route("/api/vpn/down", vpn_down, methods=["POST"]),
        WebSocketRoute("/ws/ssh", ssh_ws),
        WebSocketRoute("/ws/sftp", sftp_ws),
        Mount("/static", StaticFiles(directory=STATIC)),
    ],
    lifespan=lifespan,
)
