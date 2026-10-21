# SeaHorse

Portable Windows desktop app inspired by Ubuntu/GNOME **Seahorse** ("Passwords and Keys").

**Version: 0.2.0**

SeaHorse stores login secrets in a local encrypted vault, and manages OpenPGP (GnuPG) and SSH keys in portable directories next to the app — no system keyring required.

## Features

- **Encrypted password vault** — AES-256-GCM with Argon2id key derivation
- **Folders & tags** — organize secrets with a folder field and comma-separated tags
- **Search** — filter by title, username, URL, notes, tags, and folder
- **Folder filter** — combo box to show only one folder
- **Auto-lock** — locks the vault after idle time (default 10 minutes; configurable)
- **Clipboard safety** — copied passwords clear after 30 seconds; flushed on lock and exit
- **JSON export / import** — full or redacted (passwords blanked) export; merge import
- **Password strength meter** — simple length / character-class meter in the editor
- **OpenPGP keys** — generate, import, export, encrypt/decrypt/sign (via GnuPG)
- **SSH keys** — generate, import, export public keys (via OpenSSH `ssh-keygen`)
- **Themes** — light and dark GNOME Adwaita-inspired styles
- **Portable layout** — all data under `SeaHorseData/` beside the app

## Run portable build

```
T:\SeaHorse\dist\SeaHorse\SeaHorse.exe
```

Keep the whole `dist\SeaHorse` folder (includes `_internal`).

## Run from source

```
cd /d T:\SeaHorse
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python src\main.py
```

## Tests

```
cd /d T:\SeaHorse
.venv\Scripts\activate
python -m pytest tests -q
```

Or:

```
python -m unittest discover -s tests -v
```

## Build

```
python build.py
powershell -File Sign-Release.ps1
```

## Portable data layout

```
SeaHorseData/
  secrets.vault      # encrypted password vault (JSON + AES-GCM payload)
  gnupg/             # portable GnuPG home
  ssh/               # portable SSH key files
  settings.json      # theme, auto_lock_minutes, etc.
```

Copy the entire SeaHorse folder (exe + `_internal` + `SeaHorseData`) to move or back up the install. Prefer user-writable locations (Desktop, Documents, USB) — not Program Files.

### Settings (`settings.json`)

| Key | Default | Description |
|-----|---------|-------------|
| `theme` | `"light"` | `"light"` or `"dark"` |
| `auto_lock_minutes` | `10` | Idle minutes before vault lock; `0` disables |

## Vault format (summary)

On disk, `secrets.vault` is JSON:

```json
{
  "header": {
    "version": 1,
    "algorithm": "AES-256-GCM",
    "salt": "<base64>",
    "nonce": "<base64>",
    "kdf": {
      "type": "argon2id",
      "time_cost": 3,
      "memory_cost": 65536,
      "parallelism": 4,
      "hash_len": 32
    }
  },
  "payload": "<base64 ciphertext+tag>"
}
```

Plaintext (after decrypt) is:

```json
{
  "items": [
    {
      "id": "...",
      "title": "...",
      "username": "...",
      "password": "...",
      "url": "...",
      "notes": "...",
      "tags": ["..."],
      "folder": "...",
      "created": "...",
      "modified": "..."
    }
  ]
}
```

KDF parameters read from a vault header are **clamped** (time, memory, parallelism) so a crafted file cannot force unbounded resource use.

## Backup

1. **Quit SeaHorse** so the vault is closed cleanly.
2. Copy the entire `SeaHorseData/` directory (or at least `secrets.vault`).
3. Store the backup offline or encrypted; the vault is already encrypted, but the master password is still required to open it.
4. Optionally export a **redacted** JSON inventory (menu → Export passwords redacted) for records without secrets.

**Warning:** Full JSON export contains passwords in cleartext. Treat export files as highly sensitive.

## Threat model (summary)

SeaHorse protects secrets **at rest** on a local disk against casual access and offline theft of the vault file (given a strong master password). It does **not** protect against a fully compromised host (malware with user privileges, memory scrapers, keyloggers).

See [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md) for details.

## Release signing

SeaHorse uses the same repo-local GPG layout as companion projects on `T:\`:

```
.gnupg-release/
  private-keys-v1.d/
    Master.txt
    Signing.txt
    Encryption.txt
    Authentication.txt
docs/
  SeaHorse_Release_Signing_2026_pubkey.asc
  SHA256SUMS
  SHA256SUMS.asc
```

Identity:

```
SeaHorse Release Signing (2026) <release@seahorse.local>
Primary: F8DF590FCD82D5230EC736E94A578E36E430FB08
```

Re-sign after a build:

```
powershell -File Sign-Release.ps1
```

Verify:

```
gpg --import docs\SeaHorse_Release_Signing_2026_pubkey.asc
gpg --verify dist\SeaHorse\SeaHorse.exe.asc dist\SeaHorse\SeaHorse.exe
gpg --verify docs\SHA256SUMS.asc docs\SHA256SUMS
```

## Version

Current: **0.2.0** — see [CHANGELOG.md](CHANGELOG.md).

## Windows installer

See [Windows installer and signature verification](docs/WINDOWS_INSTALLER.md) for the download path and verification steps.
