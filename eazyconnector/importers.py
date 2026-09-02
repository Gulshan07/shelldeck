"""Import connections from ssh_config and Ásbrú. Structure and key-file paths only —
never the encrypted passwords. Parsers are pure; key files are read by the caller.

Each parser returns (connections, warnings). A connection carries our schema plus a
private `_keyfile` (path to read into the vault) and a resolved `jump` (the generated
id of another connection in the same batch, or "").
"""
import os
import re
import uuid


def _gen():
    return uuid.uuid4().hex


def from_ssh_config(text: str) -> tuple[list, list]:
    """OpenSSH client config. ProxyJump links to another imported Host by alias."""
    hosts = []
    cur = None
    warnings = []

    def flush():
        nonlocal cur
        if cur and cur.get("host"):
            hosts.append(cur)
        cur = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        if "=" in key and not value:            # Host=foo form
            key, _, value = line.partition("=")
        key, value = key.strip().lower(), value.strip()

        if key == "host":
            flush()
            alias = value.split()[0]
            if "*" in alias or "?" in alias:    # a pattern, not a real host
                cur = None
                continue
            cur = {"id": _gen(), "name": alias, "group": "ssh_config", "alias": alias,
                   "host": alias, "port": 22, "user": "", "auth": "password",
                   "jump": "", "forwards": [], "_keyfile": None, "_proxyjump": None}
        elif cur is None:
            continue
        elif key == "hostname":
            cur["host"] = value
        elif key == "user":
            cur["user"] = value
        elif key == "port":
            cur["port"] = int(value) if value.isdigit() else 22
        elif key == "identityfile":
            cur["_keyfile"] = os.path.expanduser(value)
            cur["auth"] = "key"
        elif key == "proxyjump":
            cur["_proxyjump"] = value.split(",")[0].split()[-1]  # last hop, drop user@

    flush()

    by_alias = {h["alias"]: h for h in hosts}
    for h in hosts:
        pj = h.pop("_proxyjump", None)
        if pj and pj in by_alias:
            h["jump"] = by_alias[pj]["id"]
        elif pj:
            warnings.append(f"{h['name']}: ProxyJump '{pj}' has no matching Host, left direct")
        h.pop("alias", None)
    return hosts, warnings


def from_asbru(data: dict) -> tuple[list, list]:
    """Ásbrú asbru.yml. Groups become a path; inline jump hosts are synthesized."""
    env = data.get("environments", {})
    warnings = []

    def group_path(uuid_):
        parts = []
        seen = set()
        while uuid_ and uuid_ != "__PAC__ROOT__" and uuid_ not in seen:
            seen.add(uuid_)
            node = env.get(uuid_, {})
            if node.get("_is_group") and node.get("name"):
                parts.append(node["name"])
            uuid_ = node.get("parent")
        return "/".join(reversed(parts))

    conns = []
    jump_by_key = {}          # (ip,port,user) -> synthesized jump connection id

    for node in env.values():
        if not isinstance(node, dict) or node.get("_is_group") or not node.get("name"):
            continue
        if node.get("method") not in ("SSH", None):
            warnings.append(f"{node['name']}: method {node.get('method')!r} skipped (SSH only)")
            continue

        host = str(node.get("ip", "")).strip()
        if not host:
            warnings.append(f"{node['name']}: no host, skipped")
            continue

        # Ásbrú keeps the login user in 'passphrase user' for key auth.
        user = (node.get("user") or node.get("passphrase user") or "").strip()
        keyfile = (node.get("public key") or "").strip() or None
        conn = {
            "id": _gen(),
            "name": node["name"],
            "group": group_path(node.get("parent")),
            "host": host,
            "port": int(node.get("port") or 22),
            "user": user,
            "auth": "key" if keyfile else "password",
            "jump": "",
            "forwards": [],
            "_keyfile": os.path.expanduser(keyfile) if keyfile else None,
        }

        if node.get("use proxy") == 3 and str(node.get("jump ip", "")).strip():
            jhost = str(node["jump ip"]).strip()
            juser = (node.get("jump user") or "").strip()
            jport = int(node.get("jump port") or 22)
            jkey = (node.get("jump key") or "").strip() or None
            key = (jhost, jport, juser)
            if key not in jump_by_key:
                jc = {
                    "id": _gen(), "name": f"jump: {juser + '@' if juser else ''}{jhost}",
                    "group": "Ásbrú/jump hosts", "host": jhost, "port": jport, "user": juser,
                    "auth": "key" if jkey else "password", "jump": "", "forwards": [],
                    "_keyfile": os.path.expanduser(jkey) if jkey else None,
                }
                jump_by_key[key] = jc
            conn["jump"] = jump_by_key[key]["id"]

    # A synthesized jump that coincides with a real imported host is fine to keep
    # separate; deduplication against existing connections happens at commit time.
        conns.append(conn)

    return list(jump_by_key.values()) + conns, warnings
