# Windows installer

Installs the application and runtime to the current user profile. It excludes vault, SSH key, and GnuPG data.

Installer: `release/windows/SeaHorse-Setup-0.2.0.exe`

SHA-256: `49fe3e6bccac1ba436e9cfd0f8389a39169e76f6e49e0571297b18db7b350a85`

Detached OpenPGP signature: `release/windows/SeaHorse-Setup-0.2.0.exe.asc`

This is a detached OpenPGP release signature, not a Windows Authenticode signature.

Public key: `docs/SeaHorse_Release_Signing_2026_pubkey.asc`
Fingerprint: `F8DF590FCD82D5230EC736E94A578E36E430FB08`

Compare the fingerprint above before importing the key. From the project root:

```powershell
gpg --show-keys docs/SeaHorse_Release_Signing_2026_pubkey.asc
gpg --import docs/SeaHorse_Release_Signing_2026_pubkey.asc
gpg --verify release/windows/SeaHorse-Setup-0.2.0.exe.asc release/windows/SeaHorse-Setup-0.2.0.exe
gpg --verify release/windows/SHA256SUMS.asc release/windows/SHA256SUMS
```
