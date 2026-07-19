# SeaHorse

Portable Windows desktop app inspired by Ubuntu/GNOME **Seahorse** ("Passwords and Keys").

## Run portable build

```
T:\SeaHorse\dist\SeaHorse\SeaHorse.exe
```

Keep the whole `dist\SeaHorse` folder (includes `_internal`).

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

## Run from source

```
cd /d T:\SeaHorse
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python src\main.py
```

## Build

```
python build.py
powershell -File Sign-Release.ps1
```

## Portable data

```
SeaHorseData/
  secrets.vault
  gnupg/
  ssh/
  settings.json
```

## Version

Current: **0.1.0** (MVP)
