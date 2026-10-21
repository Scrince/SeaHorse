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

_KDF_TIME_MIN = 1
_KDF_TIME_MAX = 10
_KDF_MEMORY_MIN = 8_192
_KDF_MEMORY_MAX = 1_048_576
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
    active = dict(KDF)
    if params:
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


def parse_import_payload(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict) and "items" in raw:
        if raw.get("redacted"):
            raise VaultError(
                "This file is a redacted export (passwords omitted) and cannot be imported."
            )
        rows = raw["items"]
    elif isinstance(raw, list):
        rows = raw
    else:
        raise VaultError('JSON must be a list of items or {"items": [...]}.')
    if not isinstance(rows, list):
        raise VaultError("Invalid items list.")
    cleaned: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("_redacted"):
            raise VaultError(
                "This file is a redacted export (passwords omitted) and cannot be imported."
            )
        cleaned.append(row)
    return cleaned


@dataclass
class SecretItem:
    id: str
    title: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    folder: str = ""
    created: str = ""
    modified: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecretItem":
        if not isinstance(data, dict):
            raise VaultError("Secret item is not an object.")
        raw_tags = data.get("tags")
        if isinstance(raw_tags, str):
            tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
        elif isinstance(raw_tags, (list, tuple, set)):
            tags = [str(t).strip() for t in raw_tags if str(t).strip()]
        else:
            tags = []
        return cls(
            id=str(data.get("id") or secrets.token_hex(8)),
            title=str(data.get("title") or "Untitled"),
            username=str(data.get("username") or ""),
            password=str(data.get("password") or ""),
            url=str(data.get("url") or ""),
            notes=str(data.get("notes") or ""),
            tags=tags,
            folder=str(data.get("folder") or ""),
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
            raw_text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise VaultError(f"Could not read vault file:\n{self.path}\n{exc}") from exc
        try:
            raw = json.loads(raw_text)
            header = raw["header"]
            payload = _unb64(raw["payload"])
            salt = _unb64(header["salt"])
            nonce = _unb64(header["nonce"])
            kdf_raw = header.get("kdf")
            kdf = _sanitize_kdf_params(kdf_raw if isinstance(kdf_raw, dict) else None)
            key = _derive_key(password, salt, kdf)
            plain = AESGCM(key).decrypt(nonce, payload, None)
            data = json.loads(plain.decode("utf-8"))
            raw_items = data.get("items") or []
            if not isinstance(raw_items, list):
                raise VaultError("Vault file is malformed.")
            items = []
            for entry in raw_items:
                if not isinstance(entry, dict):
                    raise VaultError("Vault file is malformed.")
                items.append(SecretItem.from_dict(entry))
            self.items = items
            self._password = password
        except InvalidTag as exc:
            raise InvalidPasswordError("Incorrect master password or corrupted vault.") from exc
        except VaultError:
            raise
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

    def add_item(self, item: SecretItem, *, persist: bool = True) -> None:
        if not item.created:
            item.created = _now()
        item.modified = _now()
        if not item.id:
            item.id = secrets.token_hex(8)
        self.items.append(item)
        if persist:
            self.save()

    def update_item(self, item: SecretItem, *, persist: bool = True) -> None:
        item.modified = _now()
        for i, existing in enumerate(self.items):
            if existing.id == item.id:
                self.items[i] = item
                if persist:
                    self.save()
                return
        raise VaultError("Secret not found.")

    def delete_item(self, item_id: str) -> None:
        remaining = [x for x in self.items if x.id != item_id]
        if len(remaining) == len(self.items):
            raise VaultError("Secret not found.")
        self.items = remaining
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
