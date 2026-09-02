"""Config (plain, no secrets) + vault (AES-256-GCM, scrypt master password)."""
import json
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOME = Path(os.environ.get("EAZY_HOME") or Path.home() / ".eazyconnector")
CONFIG = HOME / "config.json"
VAULT = HOME / "vault.enc"
KNOWN_HOSTS = HOME / "known_hosts"
URL_FILE = HOME / "url"

SCRYPT_N = 1 << 17  # ~130MB of scrypt memory-hardness
SCRYPT_MAXMEM = 1 << 28  # OpenSSL defaults to 32MB and would refuse the above


def init_home():
    os.umask(0o077)
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    HOME.chmod(0o700)  # enforce every launch, not just at create


def write_private(path: Path, data: bytes):
    """Atomic 0600 write. Mode enforced on every write, not just creation."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


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
