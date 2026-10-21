# Threat model

## Scope

SeaHorse is a **local, offline-first** password and key manager for a single user on Windows. It is inspired by GNOME Seahorse but is a separate PyQt6 application.

In scope:

- Confidentiality of password entries stored in `secrets.vault`
- Integrity of the vault file against casual tampering
- Reducing accidental secret leakage via clipboard and idle unlocked sessions
- Portable isolation of GnuPG and SSH material under `SeaHorseData/`

Out of scope:

- Multi-user / multi-device sync protocols
- Cloud backup or remote attestation
- Browser autofill integration
- Hardware security modules / smart cards (beyond what stock GnuPG supports)
- Hardening against administrators or root-equivalent attackers on the same machine

## Assets

1. **Master password** — unlocks the vault; never stored on disk
2. **Vault plaintext** — titles, usernames, passwords, URLs, notes, tags, folders (in RAM while unlocked)
3. **Vault ciphertext** — `SeaHorseData/secrets.vault`
4. **OpenPGP secret keys** — under portable `gnupg/`
5. **SSH private keys** — under portable `ssh/`
6. **Settings** — non-secret preferences (`theme`, `auto_lock_minutes`)

## Adversaries (assumptions)

| Adversary | Capability | Goal |
|-----------|------------|------|
| Casual local user | Read files without master password | Steal passwords |
| Thief with disk image | Offline vault file | Brute-force / decrypt vault |
| Malicious vault file | Crafted JSON/KDF | Crash, DoS, or weak crypto |
| Shoulder-surfer / shared PC | Brief physical access | Read unlocked UI or clipboard |
| Malware as same user | Full process/memory/keylog | Steal everything |

## Trust boundaries

- **Trusted:** user-chosen master password strength; integrity of Python/PyQt/crypto wheels or frozen `_internal` build; host OS user boundary
- **Untrusted:** vault file contents from elsewhere; JSON import files; clipboard consumers; other processes

## Controls mapped to threats

### Offline vault theft

- **Control:** AES-256-GCM with random salt and nonce per save; Argon2id KDF (time/memory hard)
- **Residual risk:** Weak master passwords remain brute-forceable; GPU/ASIC cracking improves over time

### Wrong or corrupted vault

- **Control:** GCM tag verification → `InvalidPasswordError` / `VaultError`
- **Residual risk:** User cannot distinguish wrong password from some corruption modes without backup

### Crafted KDF parameters (DoS / weak hash)

- **Control:** `_sanitize_kdf_params` clamps time, memory, parallelism; forces Argon2id and fixed hash length
- **Residual risk:** Upper bounds still allow slow unlock (intentional for security)

### Clipboard residue

- **Control:** 30s auto-clear for secret copies; `flush()` on lock and `closeEvent`
- **Residual risk:** Other apps may snapshot clipboard during the window; OS clipboard history features

### Unlocked idle session

- **Control:** Idle auto-lock (default 10 minutes) via activity event filter + `QTimer`
- **Residual risk:** Auto-lock disabled by user; activity detection is best-effort

### Import/export mishandling

- **Control:** Redacted export option; import requires unlocked vault
- **Residual risk:** Full JSON export is cleartext; user error

### Path / portable data write failures

- **Control:** Data directory probe; refuse start with clear error if not writable
- **Residual risk:** User runs from non-writable location without noticing until first save

## Explicit non-goals

- Preventing DMA / cold-boot / hypervisor attacks
- Secure multi-party authentication
- Perfect forward secrecy across password changes beyond re-encrypting current items
- Sandboxing third-party GnuPG/OpenSSH behavior

## Recommended user practices

1. Use a strong, unique master passphrase.
2. Keep auto-lock enabled on shared machines.
3. Prefer redacted exports for sharing inventories.
4. Back up `secrets.vault` offline; test restore occasionally.
5. Verify release signatures before installing binaries.
6. Treat a malware-infected machine as a full compromise of SeaHorse secrets.

## Version

This document describes SeaHorse **0.2.0**.
