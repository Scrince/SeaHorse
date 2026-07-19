from __future__ import annotations

import os
import sys
from pathlib import Path


class DataDirError(RuntimeError):
    pass


def app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def _secure_mkdir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def _secure_file(path: Path, mode: int = 0o600) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def data_dir() -> Path:
    root = app_root() / "SeaHorseData"
    try:
        _secure_mkdir(root)
        probe = root / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        raise DataDirError(
            f"Cannot write portable data directory:\n{root}\n\n"
            "Copy SeaHorse to a user-writable folder (Desktop, Documents, USB), "
            "not Program Files."
        ) from exc
    return root


def vault_path() -> Path:
    return data_dir() / "secrets.vault"


def portable_gnupg_home() -> Path:
    return _secure_mkdir(data_dir() / "gnupg")


def portable_ssh_dir() -> Path:
    return _secure_mkdir(data_dir() / "ssh")


def settings_path() -> Path:
    return data_dir() / "settings.json"
