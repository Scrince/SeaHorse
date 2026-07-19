from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
ICON = ROOT / "assets" / "seahorse.ico"


def main() -> int:
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--name",
        "SeaHorse",
        "--paths",
        str(SRC),
        "--distpath",
        str(ROOT / "dist"),
        "--workpath",
        str(ROOT / "build"),
        "--specpath",
        str(ROOT),
                                                    
        "--hidden-import",
        "crypto.vault",
        "--hidden-import",
        "gpg_backend.manager",
        "--hidden-import",
        "ssh_backend.manager",
        "--hidden-import",
        "gui.main_window",
        "--hidden-import",
        "utils.paths",
        "--hidden-import",
        "utils.themes",
        "--hidden-import",
        "version",
        "--collect-submodules",
        "PyQt6",
        str(SRC / "main.py"),
    ]
    if ICON.exists():
        cmd.extend(["--icon", str(ICON)])
    print("Running:", " ".join(cmd))
    code = subprocess.call(cmd, cwd=str(ROOT))
    if code == 0:
        readme = ROOT / "dist" / "SeaHorse" / "README-PORTABLE.txt"
        readme.write_text(
            "\n".join(
                [
                    "SeaHorse — Passwords and Keys (portable)",
                    "",
                    "Run: SeaHorse.exe",
                    "",
                    "Keep this entire folder together:",
                    "  SeaHorse.exe",
                    "  _internal\\",
                    "",
                    "Data is stored next to the EXE in:",
                    "  SeaHorseData\\",
                    "",
                    "Do not install under Program Files (needs write access).",
                    "",
                    "Optional:",
                    "  - Gpg4win for OpenPGP keys",
                    "  - Windows OpenSSH Client for SSH keys",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        print(f"Wrote {readme}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
