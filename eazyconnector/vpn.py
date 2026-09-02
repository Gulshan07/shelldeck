"""Drive the system `openvpn` binary over its management interface.

Answers the auth prompt with the stored password and a freshly generated TOTP,
in whichever of the three dialects the server speaks.
"""
import asyncio
import base64
import contextlib
import hashlib
import hmac
import os
import re
import secrets as pysecrets
import struct
import time

from . import platform, store

CONNECT_TIMEOUT = 90
RUN_DIR = store.HOME / "run"


def totp(secret_b32: str, when: float | None = None, digits: int = 6, period: int = 30) -> str:
    """RFC 6238 TOTP. Twelve lines of stdlib beats a dependency."""
    raw = re.sub(r"\s+", "", secret_b32).upper()
    raw += "=" * (-len(raw) % 8)
    key = base64.b32decode(raw)
    counter = int((time.time() if when is None else when) // period)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (int.from_bytes(mac[off:off + 4], "big") & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def detect_dialect(ovpn_text: str) -> str:
    """How this profile wants the second factor delivered."""
    for line in ovpn_text.splitlines():
        if line.strip().startswith("static-challenge"):
            return "scrv1"
    return "concat"


def build_password(dialect: str, password: str, code: str) -> str:
    if not code:
        return password
    if dialect == "scrv1":
        b64 = lambda s: base64.b64encode(s.encode()).decode()
        return f"SCRV1:{b64(password)}:{b64(code)}"
    return password + code


def _esc(value: str) -> str:
    """Management protocol quoting: backslash and double quote."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


class VpnError(Exception):
    pass


class Vpn:
    """One VPN at a time.

    ponytail: a single active tunnel. Multiple simultaneous VPNs would need a
    manager keyed by profile id and per-tunnel routing decisions - add it only
    if two networks are ever genuinely needed at once.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        self.profile_id = None
        self.name = None
        self.state = "disconnected"
        self.detail = ""
        self.ip = ""
        self.since = None
        self.log = []
        self._proc = None
        self._writer = None
        self._task = None
        self._files = []

    def status(self) -> dict:
        return {
            "state": self.state, "detail": self.detail, "name": self.name,
            "profile_id": self.profile_id, "ip": self.ip,
            "uptime": int(time.time() - self.since) if self.since else 0,
            "log": self.log[-80:],
        }

    def _say(self, line: str):
        self.log.append(line)
        del self.log[:-400]

    # --- lifecycle -------------------------------------------------------

    async def up(self, profile: dict, secret: dict):
        if self.state in ("connecting", "connected"):
            raise VpnError(f"{self.name} is already {self.state}")
        if self._proc is not None and self._proc.returncode is None:
            # State can read failed while openvpn is alive (e.g. status was missed).
            # Starting another would leave two tunnels fighting over the routes.
            await self.down()
        openvpn = platform.find_openvpn()
        if not openvpn:
            raise VpnError("openvpn is not installed or not on PATH "
                           "(Linux: sudo apt install openvpn · macOS: brew install openvpn · "
                           "Windows: install OpenVPN)")
        ovpn = secret.get("ovpn")
        if not ovpn:
            raise VpnError("no .ovpn content stored for this profile")

        self.reset()
        self.profile_id, self.name = profile["id"], profile["name"]
        self.state, self.detail = "connecting", "starting openvpn"

        platform.make_private_dir(RUN_DIR)
        cfg = RUN_DIR / f"{profile['id']}.ovpn"
        pwf = RUN_DIR / f"{profile['id']}.mgmt"
        mgmt_pw = pysecrets.token_urlsafe(24)
        # The config carries the private key, so it exists only while connected.
        store.write_private(cfg, ovpn.encode())
        # Without a password anyone local could drive the management socket.
        store.write_private(pwf, (mgmt_pw + "\n").encode())
        self._files = [cfg, pwf]

        port = _free_port()
        argv = [openvpn, "--config", str(cfg), "--management", "127.0.0.1", str(port), str(pwf),
                "--management-query-passwords", "--management-hold",
                "--auth-nocache", "--verb", "3"]
        sudo_pw = secret.get("sudo_password")
        argv = platform.elevation_prefix(sudo_pw) + argv

        self._proc = await asyncio.create_subprocess_exec(
            *argv, cwd=str(RUN_DIR), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        if sudo_pw:
            self._proc.stdin.write((sudo_pw + "\n").encode())
            with contextlib.suppress(Exception):
                await self._proc.stdin.drain()

        asyncio.create_task(self._drain_output())
        self._task = asyncio.create_task(self._manage(port, mgmt_pw, profile, secret))

    async def down(self):
        if self._writer:
            with contextlib.suppress(Exception):
                self._writer.write(b"signal SIGTERM\n")
                await self._writer.drain()
                await asyncio.sleep(0.5)
        if self._proc and self._proc.returncode is None:
            with contextlib.suppress(Exception):
                # openvpn runs as root under sudo, so terminate() can be denied.
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), 5)
        if self._task:
            self._task.cancel()
        self._cleanup()
        self.state, self.detail, self.ip, self.since = "disconnected", "", "", None

    def _cleanup(self):
        for f in self._files:
            with contextlib.suppress(Exception):
                f.unlink()
        self._files = []

    async def _drain_output(self):
        """openvpn's own stderr/stdout: where sudo and config errors show up."""
        proc = self._proc
        while proc.stdout and not proc.stdout.at_eof():
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode(errors="replace").rstrip()
            if text:
                self._say(text)
                if "net_addr_v4_add:" in text and " dev tun" in text:
                    self.ip = text.split("net_addr_v4_add:")[1].split()[0].split("/")[0]
                elif "ifconfig " in text and "PUSH_REPLY" in text:
                    with contextlib.suppress(Exception):
                        self.ip = text.split("ifconfig ")[1].split(",")[0].split()[0]
                if "Initialization Sequence Completed" in text:
                    # Truth from openvpn itself, independent of the management protocol.
                    if self.state != "connected":
                        self.state, self.detail = "connected", "connected"
                        self.since = time.time()
                if "sudo:" in text or "a password is required" in text:
                    self.state = "failed"
                    self.detail = ("openvpn needs root. Store a sudo password in the profile, "
                                   "or allow it in sudoers.")
        await proc.wait()
        if self.state in ("connecting", "connected"):
            self.state = "failed" if self.state == "connecting" else "disconnected"
            self.detail = self.detail or f"openvpn exited ({proc.returncode})"
            self.since = None
        self._cleanup()

    # --- management interface --------------------------------------------

    async def _manage(self, port, mgmt_pw, profile, secret):
        reader = None
        for _ in range(60):                       # openvpn needs a moment to listen
            if self._proc.returncode is not None:
                return
            try:
                reader, self._writer = await asyncio.open_connection("127.0.0.1", port)
                break
            except OSError:
                await asyncio.sleep(0.25)
        if reader is None:
            self.state, self.detail = "failed", "management interface never came up"
            return

        dialect = profile.get("dialect") or "auto"
        if dialect == "auto":
            dialect = detect_dialect(secret.get("ovpn", ""))

        async def send(line):
            self._writer.write((line + "\n").encode())
            await self._writer.drain()

        # openvpn prints "ENTER PASSWORD:" with NO trailing newline, so waiting for a
        # line here deadlocks. It reads one line first regardless, so just send it.
        await send(mgmt_pw)
        # Do not wait for "SUCCESS: password is correct" to ask for state: that reply
        # can share a line with the prompt and be missed, and without "state on"
        # openvpn never reports CONNECTED. Ordering on the socket makes this safe.
        await send("state on")
        await send("hold release")

        async def lines():
            """Yield management lines, tolerating prompts that lack a newline."""
            buf = ""
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    return
                buf += chunk.decode(errors="replace")
                while "\n" in buf:
                    line, _, buf = buf.partition("\n")
                    line = line.rstrip("\r")
                    # "ENTER PASSWORD:" has no newline, so whatever openvpn says
                    # next shares its line. Drop the prompt, keep the remainder.
                    if line.startswith("ENTER PASSWORD:"):
                        line = line[len("ENTER PASSWORD:"):].lstrip()
                        if not line:
                            continue
                    yield line
                if buf.endswith(":") and "PASSWORD" in buf:   # bare prompt, no newline
                    yield buf.rstrip("\r")
                    buf = ""

        async def answer_auth(challenge_state=None):
            code = totp(secret["totp_secret"]) if secret.get("totp_secret") else ""
            if challenge_state:                    # dynamic challenge: code only
                value = f"CRV1::{challenge_state}::{code}"
            else:
                value = build_password(dialect, secret.get("password", ""), code)
            await send(f'username "Auth" "{_esc(profile.get("username", ""))}"')
            await send(f'password "Auth" "{_esc(value)}"')

        deadline = time.time() + CONNECT_TIMEOUT
        try:
            stream = lines()
            while True:
                # The deadline only bounds getting connected; a live tunnel is watched
                # indefinitely so a re-auth prompt gets answered with a fresh code.
                budget = None if self.state == "connected" else max(1, deadline - time.time())
                if budget is not None and time.time() >= deadline:
                    break
                try:
                    line = await asyncio.wait_for(stream.__anext__(), timeout=budget)
                except StopAsyncIteration:
                    break
                if not line:
                    continue
                if not line.startswith(">"):
                    self._say("mgmt: " + line)

                if line.startswith("SUCCESS: password is correct"):
                    self.detail = "negotiating"
                elif line.startswith(">HOLD:"):
                    await send("hold release")
                elif line.startswith(">PASSWORD:Need 'Auth'"):
                    self.detail = "sending password + TOTP"
                    await answer_auth()
                elif line.startswith(">PASSWORD:Need 'Private Key'"):
                    await send(f'password "Private Key" "{_esc(secret.get("key_passphrase", ""))}"')
                elif line.startswith(">PASSWORD:Verification Failed: 'Auth'"):
                    m = re.search(r"CRV1:[^:]*:([^:]+):", line)
                    if m:
                        # Server wants a fresh code; the last one may simply have expired.
                        self.detail = "answering challenge with a fresh code"
                        await answer_auth(m.group(1))
                    else:
                        self.state, self.detail = "failed", "authentication rejected"
                        return
                elif line.startswith(">STATE:"):
                    parts = line[len(">STATE:"):].split(",")
                    if len(parts) > 1:
                        name = parts[1]
                        self.detail = name
                        if name == "CONNECTED":
                            self.state = "connected"
                            self.ip = parts[3] if len(parts) > 3 else ""
                            self.since = time.time()
                            self.detail = "connected"
                        elif name == "EXITING":
                            self.state = "disconnected"
                            return
                elif line.startswith(">FATAL:") or line.startswith(">LOG:") and ",F," in line:
                    self.state, self.detail = "failed", line.split(":", 1)[-1][:200]
                    return
            if self.state == "connecting":
                self.state, self.detail = "failed", f"timed out after {CONNECT_TIMEOUT}s"
        except asyncio.TimeoutError:
            self.state, self.detail = "failed", f"timed out after {CONNECT_TIMEOUT}s"
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.state, self.detail = "failed", f"{type(e).__name__}: {e}"


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p
