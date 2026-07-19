from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


class SshError(Exception):
    pass


@dataclass
class SshKeyInfo:
    name: str
    path: Path
    public_path: Path
    key_type: str
    fingerprint: str
    comment: str
    bits: str
    has_private: bool


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


class SshManager:
    def __init__(self, ssh_dir: Path) -> None:
        self.ssh_dir = ssh_dir
        self.ssh_dir.mkdir(parents=True, exist_ok=True)
        self.ssh_keygen = shutil.which("ssh-keygen") or self._find_ssh_keygen()

    def _find_ssh_keygen(self) -> str | None:
        import os

        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        candidates = [
            system_root / "System32" / "OpenSSH" / "ssh-keygen.exe",
            Path(r"C:\Windows\System32\OpenSSH\ssh-keygen.exe"),
            Path(r"C:\Program Files\Git\usr\bin\ssh-keygen.exe"),
            Path(r"C:\Program Files\OpenSSH\ssh-keygen.exe"),
        ]
        for path in candidates:
            if path.exists():
                return str(path)
        return None

    @property
    def available(self) -> bool:
        return self.ssh_keygen is not None

    def list_keys(self) -> list[SshKeyInfo]:
        keys: list[SshKeyInfo] = []
        for pub in sorted(self.ssh_dir.glob("*.pub")):
                                          
            private = Path(str(pub)[:-4]) if str(pub).endswith(".pub") else pub.with_suffix("")
            info = self._inspect(pub, private)
            if info:
                keys.append(info)
        for private in sorted(self.ssh_dir.iterdir()):
            if not private.is_file():
                continue
            if private.suffix == ".pub" or private.name.startswith("."):
                continue
            if private.name in {"config", "known_hosts", "authorized_keys", "known_hosts.old"}:
                continue
            pub = Path(str(private) + ".pub")
            if pub.exists():
                continue
            try:
                head = private.read_text(encoding="utf-8", errors="ignore")[:80]
            except OSError:
                continue
            if head.startswith("-----BEGIN"):
                info = self._inspect(pub if pub.exists() else private, private)
                if info and all(k.path != info.path for k in keys):
                    keys.append(info)
        return keys

    def _inspect(self, public_path: Path, private_path: Path) -> SshKeyInfo | None:
        target = public_path if public_path.exists() else private_path
        if not target.exists():
            return None
        key_type = "unknown"
        fingerprint = ""
        comment = ""
        bits = ""
        if self.ssh_keygen:
            try:
                result = subprocess.run(
                    [self.ssh_keygen, "-l", "-f", str(target)],
                    timeout=30,
                    check=False,
                    **_subprocess_kwargs(),
                )
                if result.returncode == 0 and result.stdout.strip():
                    parts = result.stdout.strip().split()
                    if len(parts) >= 3:
                        bits = parts[0]
                        fingerprint = parts[1]
                        key_type = parts[-1].strip("()")
                        if len(parts) > 3:
                            comment = " ".join(parts[2:-1])
            except (OSError, subprocess.TimeoutExpired):
                pass
        if public_path.exists() and not comment:
            try:
                line = public_path.read_text(encoding="utf-8").strip().split()
                if len(line) >= 3:
                    comment = line[2]
                if len(line) >= 1 and line[0].startswith("ssh-"):
                    key_type = line[0].replace("ssh-", "")
            except OSError:
                pass
        return SshKeyInfo(
            name=private_path.name if private_path.exists() else public_path.stem,
            path=private_path if private_path.exists() else public_path,
            public_path=public_path,
            key_type=key_type,
            fingerprint=fingerprint,
            comment=comment,
            bits=bits,
            has_private=private_path.exists(),
        )

    def generate_key(
        self,
        name: str = "id_ed25519",
        key_type: str = "ed25519",
        comment: str = "",
        passphrase: str = "",
        bits: int = 4096,
    ) -> SshKeyInfo:
        if not self.ssh_keygen:
            raise SshError(
                "ssh-keygen was not found. Install OpenSSH Client "
                "(Windows Settings → Optional features) or Git for Windows."
            )
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name.strip()) or "id_ed25519"
        private_path = self.ssh_dir / safe
        public_path = Path(str(private_path) + ".pub")
        if private_path.exists() or public_path.exists():
            raise SshError(f"Key already exists: {safe}")
        args = [
            self.ssh_keygen,
            "-q",
            "-t",
            key_type,
            "-f",
            str(private_path),
        ]
        if comment:
            cleaned_comment = "".join(ch for ch in comment if ord(ch) >= 32 and ch != "\x7f")
            if cleaned_comment:
                args.extend(["-C", cleaned_comment])
        if key_type in ("rsa", "rsa1"):
            args.extend(["-b", str(bits)])

        # Never put a non-empty passphrase on argv (visible via ps / audit logs).
        if not passphrase:
            args.extend(["-N", ""])
            result = subprocess.run(args, timeout=120, check=False, **_subprocess_kwargs())
        else:
            result = self._run_keygen_with_askpass(args, passphrase)

        if result.returncode != 0:
            private_path.unlink(missing_ok=True)
            public_path.unlink(missing_ok=True)
            raise SshError(
                (result.stderr or result.stdout or "").strip() or "ssh-keygen failed."
            )
        try:
            os.chmod(private_path, 0o600)
        except OSError:
            pass
        info = self._inspect(public_path, private_path)
        if not info:
            raise SshError("Key generated but could not be inspected.")
        return info

    def _run_keygen_with_askpass(
        self, args: list[str], passphrase: str
    ) -> subprocess.CompletedProcess[str]:
        """Run ssh-keygen without -N; supply passphrase only via SSH_ASKPASS."""
        with tempfile.TemporaryDirectory(prefix="seahorse-askpass-") as tmp:
            tmp_path = Path(tmp)
            secret_file = tmp_path / "secret"
            secret_file.write_bytes(passphrase.encode("utf-8"))
            try:
                os.chmod(secret_file, 0o600)
            except OSError:
                pass

            if sys.platform == "win32":
                askpass = tmp_path / "askpass.cmd"
                askpass.write_text(
                    "@echo off\r\n"
                    f'type "{secret_file}"\r\n',
                    encoding="utf-8",
                )
            else:
                askpass = tmp_path / "askpass.sh"
                askpass.write_text(
                    "#!/bin/sh\n"
                    f'cat "{secret_file}"\n'
                    "printf '\\n'\n",
                    encoding="utf-8",
                )
                try:
                    os.chmod(askpass, 0o700)
                except OSError:
                    pass

            env = os.environ.copy()
            env["SSH_ASKPASS"] = str(askpass)
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env.setdefault("DISPLAY", ":0")
            kwargs = _subprocess_kwargs()
            kwargs["env"] = env
            kwargs["stdin"] = subprocess.DEVNULL
            return subprocess.run(args, timeout=120, check=False, **kwargs)

    def read_public(self, key: SshKeyInfo) -> str:
        if key.public_path.exists():
            return key.public_path.read_text(encoding="utf-8")
        raise SshError("Public key file not found.")

    def read_private(self, key: SshKeyInfo) -> str:
        if key.has_private and key.path.exists():
            return key.path.read_text(encoding="utf-8")
        raise SshError("Private key file not found.")

    def import_key_pair(
        self, private_text: str = "", public_text: str = "", name: str = "imported_key"
    ) -> SshKeyInfo:
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name.strip()) or "imported_key"
        private_path = self.ssh_dir / safe
        public_path = Path(str(private_path) + ".pub")
        if private_path.exists() or public_path.exists():
            raise SshError(f"Key name already exists: {safe}")
        if private_text.strip():
            private_path.write_text(private_text.strip() + "\n", encoding="utf-8")
            try:
                                                                                      
                private_path.chmod(0o600)
            except OSError:
                pass
        if public_text.strip():
            public_path.write_text(public_text.strip() + "\n", encoding="utf-8")
        if not private_text.strip() and not public_text.strip():
            raise SshError("Provide a private and/or public key.")
        if private_text.strip() and not public_text.strip() and self.ssh_keygen:
                                                                                     
            result = subprocess.run(
                [self.ssh_keygen, "-y", "-f", str(private_path)],
                timeout=30,
                check=False,
                **_subprocess_kwargs(),
            )
            if result.returncode == 0 and result.stdout.strip():
                public_path.write_text(result.stdout.strip() + "\n", encoding="utf-8")
            elif not public_path.exists():
                raise SshError(
                    "Imported private key, but could not derive the public key. "
                    "If the private key has a passphrase, also import the .pub file."
                )
        info = self._inspect(public_path, private_path)
        if not info:
            raise SshError("Import failed.")
        return info

    def delete_key(self, key: SshKeyInfo) -> None:
        for path in {key.path, key.public_path}:
            if path.exists():
                path.unlink()
