"""Config (plain, no secrets) + vault (AES-256-GCM, scrypt master password)."""
import json
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import platform

def _home() -> Path:
    if env := os.environ.get("SHELLDECK_HOME"):
        return Path(env)
    home = Path.home() / ".shelldeck"
    # The project was called EazyConnector before 0.1.0. Anyone who ran it then
    # has a vault only their master password can open, so keep using it in place
    # rather than silently moving or orphaning it. Delete this once nobody has
    # a ~/.eazyconnector left.
    old = Path.home() / ".eazyconnector"
    return old if not home.exists() and old.is_dir() else home


HOME = _home()
CONFIG = HOME / "config.json"
VAULT = HOME / "vault.enc"
KNOWN_HOSTS = HOME / "known_hosts"
LOGS = HOME / "logs"
URL_FILE = HOME / "url"

SCRYPT_N = 1 << 17  # ~130MB of scrypt memory-hardness
SCRYPT_MAXMEM = 1 << 28  # OpenSSL defaults to 32MB and would refuse the above


def init_home():
    platform.set_umask()
    platform.make_private_dir(HOME)   # enforced every launch, not just at create


def write_private(path: Path, data: bytes):
    """Atomic 0600 write. Mode enforced on every write, not just creation."""
    tmp = path.with_name(path.name + ".tmp")
    fd = platform.open_private(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    platform.lock_file(path)


def load_config() -> dict:
    if not CONFIG.exists():
        return {"connections": []}
    return json.loads(CONFIG.read_text())


def save_config(cfg: dict):
    write_private(CONFIG, json.dumps(cfg, indent=2).encode())


class Locked(Exception):
    pass


class BadPassword(Exception):
    pass


class Vault:
    """Secrets keyed by connection id: {"password": ..., "key_pem": ..., "passphrase": ...}"""

    def __init__(self):
        self._key = None
        self._salt = None
        self._data = None

    @property
    def exists(self) -> bool:
        return VAULT.exists()

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    @staticmethod
    def _kdf(password: str, salt: bytes) -> bytes:
        import hashlib

        return hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=8, p=1, dklen=32,
                              maxmem=SCRYPT_MAXMEM)

    def create(self, password: str):
        self._salt = secrets.token_bytes(16)
        self._key = self._kdf(password, self._salt)
        self._data = {}
        self._flush()

    def unlock(self, password: str):
        blob = VAULT.read_bytes()
        salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
        key = self._kdf(password, salt)
        try:
            plain = AESGCM(key).decrypt(nonce, ct, None)
        except InvalidTag:
            raise BadPassword()
        self._salt, self._key, self._data = salt, key, json.loads(plain)

    def rekey(self, old_password: str, new_password: str):
        """Change the master password: verify old, re-encrypt under a new salt+key.
        Must already be unlocked so live sessions keep working."""
        if not self.unlocked:
            raise Locked()
        # Verify against the on-disk blob, not the in-memory key, so a stale unlock
        # cannot be used to re-key with the wrong old password.
        blob = VAULT.read_bytes()
        salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
        try:
            AESGCM(self._kdf(old_password, salt)).decrypt(nonce, ct, None)
        except InvalidTag:
            raise BadPassword()
        self._salt = secrets.token_bytes(16)
        self._key = self._kdf(new_password, self._salt)
        self._flush()

    def encrypt(self, data: bytes) -> bytes:
        """AES-GCM under the master key: nonce || ciphertext. For session logs."""
        self._require()
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(self._key).encrypt(nonce, data, None)

    def decrypt(self, blob: bytes) -> bytes:
        self._require()
        return AESGCM(self._key).decrypt(blob[:12], blob[12:], None)

    def lock(self):
        # ponytail: CPython can't reliably zero bytes in memory; mlock/secure-alloc
        # only if the threat model ever includes core dumps or swap forensics.
        self._key = self._data = self._salt = None

    def _require(self):
        if not self.unlocked:
            raise Locked()

    def get(self, cred_id: str) -> dict:
        self._require()
        return self._data.get(cred_id, {})

    def put(self, cred_id: str, secrets_dict: dict):
        self._require()
        self._data[cred_id] = {k: v for k, v in secrets_dict.items() if v}
        self._flush()

    def delete(self, cred_id: str):
        self._require()
        if self._data.pop(cred_id, None) is not None:
            self._flush()

    def _flush(self):
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self._key).encrypt(nonce, json.dumps(self._data).encode(), None)
        write_private(VAULT, self._salt + nonce + ct)
