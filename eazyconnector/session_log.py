"""Encrypted, append-only session logs.

A terminal log can contain anything typed on screen (a sudo password, a token),
so it is encrypted at rest under the vault master key, not left as plaintext.

Append-friendly format: a 7-byte magic, then frames of
  [4-byte length][4-byte ms-since-start][nonce||ct]
Each frame is one independent AES-GCM message, so we never rewrite the file. The
ms delta (plaintext metadata — timing isn't sensitive) drives recording playback.
Files without the magic are the old untimed format and still read back as text.
"""
import os
import re
import struct
import time
from datetime import datetime

from . import platform, store

MAGIC = b"ECLOG2\n"

CAP_BYTES = 50 * 1024 * 1024   # ponytail: fixed 50 MB/session; make per-profile if it ever bites


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:60] or "session"


class SessionLog:
    """Writes encrypted terminal output for one session. Best-effort: any write
    error disables the log rather than taking the session down with it."""

    def __init__(self, vault, conn_name: str):
        self.vault = vault
        self.written = 0
        self.truncated = False
        self.ok = True
        platform.make_private_dir(store.LOGS)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.path = store.LOGS / f"{_safe(conn_name)}-{stamp}.eclog"
        fd = platform.open_private(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        self._f = os.fdopen(fd, "wb")
        self._f.write(MAGIC)
        self._start = time.monotonic()
        self._frame(f"=== {conn_name} — {datetime.now().isoformat(timespec='seconds')} ===\r\n".encode())

    def _frame(self, data: bytes):
        try:
            blob = self.vault.encrypt(data)
            ms = int((time.monotonic() - self._start) * 1000)
            self._f.write(struct.pack(">II", len(blob), ms) + blob)
            self._f.flush()
        except Exception:
            self.ok = False        # vault locked or disk error: stop logging quietly

    def write(self, data: bytes):
        if not self.ok or self.truncated:
            return
        if self.written + len(data) > CAP_BYTES:
            self._frame(b"\r\n=== log truncated at 50 MB ===\r\n")
            self.truncated = True
            return
        self.written += len(data)
        self._frame(data)

    def close(self):
        try:
            self._frame(f"\r\n=== closed {datetime.now().isoformat(timespec='seconds')} ===\r\n".encode())
            self._f.close()
        except Exception:
            pass


def read_frames(vault, path):
    """Yield (ms, plaintext) per frame. Old untimed files replay at ms=0."""
    with open(path, "rb") as f:
        head = f.read(len(MAGIC))
        timed = head == MAGIC
        if not timed:
            f.seek(0)
        while True:
            hdr = f.read(8 if timed else 4)
            if len(hdr) < (8 if timed else 4):
                break
            if timed:
                n, ms = struct.unpack(">II", hdr)
            else:
                (n,) = struct.unpack(">I", hdr)
                ms = 0
            blob = f.read(n)
            if len(blob) < n:
                break
            yield ms, vault.decrypt(blob)


def read_log(vault, path) -> bytes:
    """Decrypt a whole .eclog back to the raw terminal bytes (no timing)."""
    return b"".join(data for _, data in read_frames(vault, path))


def list_logs():
    if not store.LOGS.exists():
        return []
    items = []
    for p in store.LOGS.glob("*.eclog"):
        st = p.stat()
        items.append({"file": p.name, "size": st.st_size, "mtime": int(st.st_mtime)})
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items
