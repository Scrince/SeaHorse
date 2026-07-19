from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


class GpgError(Exception):
    pass


@dataclass
class GpgKeyInfo:
    key_type: str
    capabilities: str
    fingerprint: str
    key_id: str
    created: str
    expires: str
    uids: list[str]
    is_secret: bool


def _subprocess_kwargs() -> dict:
    kwargs: dict = {
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if sys.platform == "win32":
                                                                       
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        if flags:
            kwargs["creationflags"] = flags
    return kwargs


class GpgManager:
    def __init__(self, gnupg_home: Path | None = None) -> None:
        self.gnupg_home = gnupg_home
        self.gpg_path = self._find_gpg()

    def _find_gpg(self) -> str | None:
        for name in ("gpg", "gpg.exe"):
            found = shutil.which(name)
            if found:
                return found
        candidates = [
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "GnuPG" / "bin" / "gpg.exe",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "GnuPG" / "bin" / "gpg.exe",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Gpg4win" / "bin" / "gpg.exe",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Gpg4win" / "bin" / "gpg.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "GnuPG" / "bin" / "gpg.exe",
        ]
        for path in candidates:
            if path and path.exists():
                return str(path)
        return None

    @property
    def available(self) -> bool:
        return self.gpg_path is not None

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        if self.gnupg_home is not None:
            env["GNUPGHOME"] = str(self.gnupg_home)
            self._ensure_agent_config(self.gnupg_home)
        return env

    def _ensure_agent_config(self, home: Path) -> None:
        home.mkdir(parents=True, exist_ok=True)
        conf = home / "gpg-agent.conf"
        needed = "allow-loopback-pinentry"
        try:
            existing = conf.read_text(encoding="utf-8") if conf.exists() else ""
            if needed not in existing:
                with conf.open("a", encoding="utf-8") as fh:
                    if existing and not existing.endswith("\n"):
                        fh.write("\n")
                    fh.write(needed + "\n")
                self._reload_agent()
        except OSError:
            pass

    def _reload_agent(self) -> None:
                                                                                
        if not self.gpg_path:
            return
        gpgconf = Path(self.gpg_path).with_name("gpgconf.exe")
        if not gpgconf.exists():
            gpgconf = Path(self.gpg_path).with_name("gpgconf")
        if not gpgconf.exists():
            return
        try:
            subprocess.run(
                [str(gpgconf), "--kill", "gpg-agent"],
                timeout=15,
                check=False,
                env=self._env_no_agent_write(),
                **_subprocess_kwargs(),
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _env_no_agent_write(self) -> dict[str, str]:
        env = os.environ.copy()
        if self.gnupg_home is not None:
            env["GNUPGHOME"] = str(self.gnupg_home)
        return env

    def _run(
        self,
        args: list[str],
        input_text: str | None = None,
        timeout: int = 120,
        *,
        batch: bool = True,
        loopback: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        if not self.gpg_path:
            raise GpgError(
                "GnuPG was not found. Install Gpg4win (https://www.gpg4win.org/) "
                "or place gpg.exe on PATH."
            )
        cmd = [self.gpg_path]
        if batch:
            cmd.extend(["--batch", "--yes"])
        if loopback:
            cmd.extend(["--pinentry-mode", "loopback"])
        cmd.extend(["--status-fd", "2"])
        cmd.extend(args)
        try:
            return subprocess.run(
                cmd,
                input=input_text,
                timeout=timeout,
                check=False,
                env=self._env(),
                **_subprocess_kwargs(),
            )
        except subprocess.TimeoutExpired as exc:
            raise GpgError(
                "GnuPG command timed out. If the key has a passphrase, complete the "
                "pinentry prompt (or generate keys without a passphrase for fully batch use)."
            ) from exc
        except OSError as exc:
            raise GpgError(f"Failed to run GnuPG: {exc}") from exc

    def list_keys(self, secret: bool = False) -> list[GpgKeyInfo]:
        args = ["--with-colons", "--fixed-list-mode"]
        args.append("--list-secret-keys" if secret else "--list-keys")
        result = self._run(args)
        if result.returncode not in (0, 2):
            raise GpgError(result.stderr.strip() or "Failed to list keys.")
        return self._parse_colon_listing(result.stdout, secret=secret)

    def _parse_colon_listing(self, text: str, secret: bool) -> list[GpgKeyInfo]:
        keys: list[GpgKeyInfo] = []
        current: GpgKeyInfo | None = None
        for line in text.splitlines():
            parts = line.split(":")
            if len(parts) < 5:
                continue
            tag = parts[0]
            if tag in ("pub", "sec"):
                if current:
                    keys.append(current)
                algo = parts[3]
                created = parts[5]
                expires = parts[6]
                key_id = parts[4]
                caps = parts[11] if len(parts) > 11 else ""
                current = GpgKeyInfo(
                    key_type=algo,
                    capabilities=caps,
                    fingerprint="",
                    key_id=key_id,
                    created=created,
                    expires=expires or "never",
                    uids=[],
                    is_secret=secret or tag == "sec",
                )
            elif tag == "fpr" and current is not None:
                current.fingerprint = parts[9]
            elif tag == "uid" and current is not None:
                uid = parts[9]
                if uid:
                    current.uids.append(uid)
        if current:
            keys.append(current)
        return keys

    @staticmethod
    def _sanitize_batch_field(value: str, field_name: str, *, allow_empty: bool = False) -> str:
        """Reject control characters / batch-directive injection in GnuPG param lines."""
        text = (value or "").strip()
        if not text:
            if allow_empty:
                return ""
            raise GpgError(f"{field_name} is required.")
        if any(ord(ch) < 32 for ch in text) or "\x7f" in text:
            raise GpgError(f"{field_name} contains invalid control characters.")
        if "\n" in text or "\r" in text or "\x00" in text:
            raise GpgError(f"{field_name} must be a single line.")
        # Percent starts GnuPG batch directives (%no-protection, %commit, …).
        if "%" in text:
            raise GpgError(f"{field_name} must not contain '%'.")
        # Colons can confuse colon-delimited status output; block in identity fields.
        if field_name in {"Name", "Email"} and ":" in text:
            raise GpgError(f"{field_name} must not contain ':'.")
        if len(text) > 200:
            raise GpgError(f"{field_name} is too long.")
        return text

    @staticmethod
    def _sanitize_expire(expire: str) -> str:
        value = (expire or "0").strip() or "0"
        if not re.fullmatch(r"0|\d+[dwmy]?", value, flags=re.IGNORECASE):
            raise GpgError(
                "Expire date must be 0 (never) or a number with optional unit d/w/m/y."
            )
        return value

    def generate_key(
        self,
        name: str,
        email: str,
        passphrase: str = "",
        key_type: str = "ed25519",
        expire: str = "0",
    ) -> str:
        name_value = self._sanitize_batch_field(name, "Name")
        email_value = self._sanitize_batch_field(
            email.strip() or "user@localhost", "Email"
        )
        expire_value = self._sanitize_expire(expire)
        if passphrase:
            # Passphrase is still a batch field: block newlines / % injection.
            safe_pass = self._sanitize_batch_field(passphrase, "Passphrase")
            protection_lines = [f"Passphrase: {safe_pass}"]
        else:
            protection_lines = ["%no-protection"]

        if key_type.lower() in ("ed25519", "cv25519", "eddsa"):
            param_lines = [
                "Key-Type: EDDSA",
                "Key-Curve: Ed25519",
                "Key-Usage: sign",
                "Subkey-Type: ECDH",
                "Subkey-Curve: Curve25519",
                "Subkey-Usage: encrypt",
                f"Name-Real: {name_value}",
                f"Name-Email: {email_value}",
                f"Expire-Date: {expire_value}",
                *protection_lines,
                "%commit",
                "",
            ]
        else:
            param_lines = [
                "Key-Type: RSA",
                "Key-Length: 4096",
                "Subkey-Type: RSA",
                "Subkey-Length: 4096",
                f"Name-Real: {name_value}",
                f"Name-Email: {email_value}",
                f"Expire-Date: {expire_value}",
                *protection_lines,
                "%commit",
                "",
            ]
        params = "\n".join(param_lines)
        result = self._run(
            ["--full-generate-key"],
            input_text=params,
            timeout=300,
            loopback=True,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise GpgError(detail or "Key generation failed.")
        match = re.search(r"KEY_CREATED\s+\w+\s+([A-F0-9]{40})", result.stderr, re.I)
        if match:
            return match.group(1).upper()
        keys = self.list_keys(secret=True)
        if not keys:
            raise GpgError("Key generation finished but no secret key was found.")
        return keys[-1].fingerprint or keys[-1].key_id

    def export_public(self, fingerprint: str) -> str:
        result = self._run(["--armor", "--export", fingerprint])
        if result.returncode != 0 or "BEGIN PGP PUBLIC KEY" not in result.stdout:
            raise GpgError(result.stderr.strip() or "Public export failed.")
        return result.stdout

    def export_secret(self, fingerprint: str) -> str:
                                                                             
        result = self._run(
            ["--armor", "--export-secret-keys", fingerprint],
            batch=False,
            timeout=300,
        )
        if result.returncode != 0 or "BEGIN PGP PRIVATE KEY" not in (result.stdout or ""):
            raise GpgError(
                (result.stderr or result.stdout or "").strip()
                or "Secret export failed. If the key has a passphrase, complete the pinentry prompt."
            )
        return result.stdout

    def import_key(self, armored_or_path: str) -> str:
        path = Path(armored_or_path)
        if path.exists():
            result = self._run(["--import", str(path)])
        else:
            result = self._run(["--import"], input_text=armored_or_path)
        if result.returncode not in (0, 2):
            raise GpgError(result.stderr.strip() or "Import failed.")
        return result.stderr.strip() or "Import completed."

    def delete_key(self, fingerprint: str, secret: bool = False) -> None:
        if secret:
            result = self._run(["--delete-secret-and-public-key", fingerprint])
        else:
            result = self._run(["--delete-keys", fingerprint])
        if result.returncode not in (0, 2):
            raise GpgError(result.stderr.strip() or "Delete failed.")

    def encrypt_text(self, recipients: list[str], plaintext: str) -> str:
                                                                                 
        args = ["--armor", "--trust-model", "always", "--encrypt"]
        for r in recipients:
            args.extend(["--recipient", r])
        result = self._run(args, input_text=plaintext)
        if result.returncode != 0 or "BEGIN PGP MESSAGE" not in (result.stdout or ""):
            raise GpgError(result.stderr.strip() or "Encryption failed.")
        return result.stdout

    def decrypt_text(self, ciphertext: str) -> str:
                                                                              
        result = self._run(["--decrypt"], input_text=ciphertext, batch=False, timeout=300)
        if result.returncode != 0:
            raise GpgError(
                (result.stderr or "").strip()
                or "Decryption failed. If the key has a passphrase, complete the pinentry prompt."
            )
        return result.stdout

    def sign_text(self, plaintext: str) -> str:
        result = self._run(
            ["--armor", "--clearsign"],
            input_text=plaintext,
            batch=False,
            timeout=300,
        )
        if result.returncode != 0 or "BEGIN PGP SIGNED MESSAGE" not in (result.stdout or ""):
            raise GpgError(
                (result.stderr or "").strip()
                or "Signing failed. If the key has a passphrase, complete the pinentry prompt."
            )
        return result.stdout
