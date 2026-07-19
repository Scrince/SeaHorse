from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


VAULT_VERSION = 1
ALGORITHM = "AES-256-GCM"
KDF = {
    "type": "argon2id",
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4,
    "hash_len": 32,
}

# Bounds applied to vault-header KDF params (crafted files cannot OOM the process).
_KDF_TIME_MIN = 1
_KDF_TIME_MAX = 10
_KDF_MEMORY_MIN = 8_192  # KiB
_KDF_MEMORY_MAX = 1_048_576  # KiB (1 GiB)
_KDF_PARALLEL_MIN = 1
_KDF_PARALLEL_MAX = 8
_KDF_HASH_LEN = 32


class VaultError(Exception):
    pass


class InvalidPasswordError(VaultError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def _clamp_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def _sanitize_kdf_params(params: dict[str, Any] | None) -> dict[str, Any]:
    """Allowlist and clamp KDF parameters from a vault header."""
    active = dict(KDF)
    if params:
        # Only known keys; always force Argon2id + fixed hash length.
        if "time_cost" in params:
            active["time_cost"] = _clamp_int(
                params["time_cost"], KDF["time_cost"], _KDF_TIME_MIN, _KDF_TIME_MAX
            )
        if "memory_cost" in params:
            active["memory_cost"] = _clamp_int(
                params["memory_cost"], KDF["memory_cost"], _KDF_MEMORY_MIN, _KDF_MEMORY_MAX
            )
        if "parallelism" in params:
            active["parallelism"] = _clamp_int(
                params["parallelism"], KDF["parallelism"], _KDF_PARALLEL_MIN, _KDF_PARALLEL_MAX
            )
    active["type"] = "argon2id"
    active["hash_len"] = _KDF_HASH_LEN
    return active


def _derive_key(password: str, salt: bytes, params: dict[str, Any] | None = None) -> bytes:
    active = _sanitize_kdf_params(params)
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=int(active["time_cost"]),
        memory_cost=int(active["memory_cost"]),
        parallelism=int(active["parallelism"]),
        hash_len=int(active["hash_len"]),
        type=Type.ID,
    )


def _secure_chmod(path: Path, mode: int = 0o600) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


@dataclass
class SecretItem:
    id: str
    title: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    created: str = ""
    modified: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecretItem":
        return cls(
            id=str(data.get("id") or secrets.token_hex(8)),
            title=str(data.get("title") or "Untitled"),
            username=str(data.get("username") or ""),
            password=str(data.get("password") or ""),
            url=str(data.get("url") or ""),
            notes=str(data.get("notes") or ""),
            tags=list(data.get("tags") or []),
            created=str(data.get("created") or _now()),
            modified=str(data.get("modified") or _now()),
        )


class SecretsVault:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._password: str | None = None
        self.items: list[SecretItem] = []

    @property
    def unlocked(self) -> bool:
        return self._password is not None

    def exists(self) -> bool:
        return self.path.exists()

    def create(self, password: str) -> None:
        if not password:
            raise VaultError("Master password is required.")
        self._password = password
        self.items = []
        self.save()

    def unlock(self, password: str) -> None:
        if not self.path.exists():
            raise VaultError("Vault file does not exist.")
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            header = raw["header"]
            payload = _unb64(raw["payload"])
            salt = _unb64(header["salt"])
            nonce = _unb64(header["nonce"])
            kdf = _sanitize_kdf_params(header.get("kdf") if isinstance(header.get("kdf"), dict) else None)
            key = _derive_key(password, salt, kdf)
            plain = AESGCM(key).decrypt(nonce, payload, None)
            data = json.loads(plain.decode("utf-8"))
            self.items = [SecretItem.from_dict(x) for x in data.get("items", [])]
            self._password = password
        except InvalidTag as exc:
            raise InvalidPasswordError("Incorrect master password or corrupted vault.") from exc
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise VaultError("Vault file is malformed.") from exc

    def lock(self) -> None:
        self._password = None
        self.items = []

    def save(self) -> None:
        if self._password is None:
            raise VaultError("Vault is locked.")
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive_key(self._password, salt, KDF)
        body = {"items": [item.to_dict() for item in self.items]}
        plain = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        cipher = AESGCM(key).encrypt(nonce, plain, None)
        document = {
            "header": {
                "version": VAULT_VERSION,
                "algorithm": ALGORITHM,
                "salt": _b64(salt),
                "nonce": _b64(nonce),
                "kdf": dict(KDF),
            },
            "payload": _b64(cipher),
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            _secure_chmod(self.path.parent, 0o700)
        except OSError:
            pass
        payload = json.dumps(document, indent=2, ensure_ascii=False)
        tmp = self.path.with_name(self.path.name + ".tmp")
        last_error: Exception | None = None
        for _ in range(5):
            try:
                with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(payload)
                    fh.flush()
                    os.fsync(fh.fileno())
                _secure_chmod(tmp, 0o600)
                os.replace(tmp, self.path)
                _secure_chmod(self.path, 0o600)
                last_error = None
                break
            except OSError as exc:
                last_error = exc
                try:
                    if tmp.exists():
                        tmp.unlink()
                except OSError:
                    pass
        if last_error is not None:
            raise VaultError(f"Could not write vault file:\n{self.path}\n{last_error}") from last_error

    def add_item(self, item: SecretItem) -> None:
        if not item.created:
            item.created = _now()
        item.modified = _now()
        if not item.id:
            item.id = secrets.token_hex(8)
        self.items.append(item)
        self.save()

    def update_item(self, item: SecretItem) -> None:
        item.modified = _now()
        for i, existing in enumerate(self.items):
            if existing.id == item.id:
                self.items[i] = item
                self.save()
                return
        raise VaultError("Secret not found.")

    def delete_item(self, item_id: str) -> None:
        self.items = [x for x in self.items if x.id != item_id]
        self.save()

    def change_password(self, old_password: str, new_password: str) -> None:
        if self._password is None:
            raise VaultError("Vault is locked.")
        if old_password != self._password:
            raise InvalidPasswordError("Current master password is incorrect.")
        if not new_password:
            raise VaultError("New master password is required.")
        self._password = new_password
        self.save()
