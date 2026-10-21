# Security

## Reporting issues

If you discover a vulnerability in SeaHorse, please treat it as sensitive:

1. Do **not** open a public issue with exploit details.
2. Prefer private disclosure to the project maintainer with steps to reproduce.
3. Allow reasonable time for a fix before public discussion.

This is a local personal utility; there is no formal bug-bounty program.

## What SeaHorse protects

| Asset | Protection |
|-------|------------|
| Password vault at rest | AES-256-GCM; key from Argon2id(master password, random salt) |
| Vault file integrity | GCM authentication tag; wrong password → `InvalidPasswordError` |
| Crafted vault KDF | Header KDF params clamped (time / memory / parallelism) |
| Clipboard secrets | Auto-clear ~30s; flushed on lock and app close |
| Idle exposure | Auto-lock (default 10 minutes; configurable / disable) |
| Portable GnuPG/SSH dirs | Data under app-local `SeaHorseData/` with restrictive chmod where OS allows |

## What SeaHorse does **not** protect against

- Malware running as your user (keyloggers, memory dumpers, screen capture)
- An attacker who already knows or can phish the master password
- Cleartext **JSON export** files (full export includes passwords)
- Physical access while the vault is **unlocked** in memory
- Compromised GnuPG/OpenSSH binaries on the host
- Side-channel or advanced cryptoanalytic attacks beyond standard library usage

## Master password guidance

- Prefer a long passphrase (multiple words) over a short complex password.
- Do not reuse the master password for websites or other services.
- Changing the master password re-encrypts the vault with a new salt/nonce.

## Clipboard

Copied **passwords** and usernames use a short-lived clipboard entry (default 30 seconds). Public SSH keys are not auto-cleared. Locking the vault or closing the window flushes any SeaHorse-copied secret still on the clipboard.

## Auto-lock

When the idle timer fires, SeaHorse:

1. Flushes the clipboard
2. Calls `vault.lock()` (clears in-memory items and master password)
3. Prompts to unlock again (or leaves the passwords view locked)

Disable auto-lock only on a machine you fully control and trust.

## Exports and backups

- **Redacted export** omits password values; safer for inventories.
- **Full export** is plaintext secrets — encrypt the file or delete after use.
- Back up `SeaHorseData/secrets.vault` only when the app is closed; keep backups offline when possible.

## Dependencies

Runtime crypto:

- [cryptography](https://cryptography.io/) — AES-GCM
- [argon2-cffi](https://github.com/hynek/argon2-cffi) — Argon2id

Keep the portable build folder intact; do not mix `_internal` DLLs from untrusted sources.

## Release integrity

Signed releases provide `SeaHorse.exe.asc` and `SHA256SUMS` / `SHA256SUMS.asc`. Verify signatures with the published release public key before running binaries from untrusted mirrors. See README for verification commands.
