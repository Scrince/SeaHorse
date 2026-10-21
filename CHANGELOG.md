# Changelog

All notable changes to SeaHorse are documented in this file.

## [0.2.0] — 2026-07-19

### Added

- **Folders** on secrets (`folder` field) with folder filter combo in the passwords view
- **Tags** editing in SecretEditor (comma-separated); tags shown in list rows and detail pane
- **Auto-lock** after idle time (default 10 minutes), with menu to set timeout; activity resets the timer
- In-session **Unlock** after lock / auto-lock (no restart required)
- **JSON export** of passwords (full and redacted) and **JSON import** (merge add/update)
- Simple **password strength meter** in SecretEditor (length + character classes)
- Settings persistence for `auto_lock_minutes` in `SeaHorseData/settings.json`
- Unit tests for vault create/unlock, wrong password, KDF clamp, CRUD, change password
- Documentation: expanded README, CHANGELOG, SECURITY, THREAT_MODEL
- `models` package re-exports `SecretItem`

### Enhanced

- Search matches title, username, URL, notes, tags, and folder (not only list label text)
- Clipboard flush on lock and window close (in addition to 30s auto-clear of copied secrets)
- Lock UX: locked state shows unlock hint; password actions re-prompt if locked

### Security

- Documented threat model and security practices
- KDF parameter clamping retained and covered by tests

## [0.1.0] — MVP

- Encrypted password vault (AES-256-GCM + Argon2id)
- OpenPGP and SSH key management (portable homes)
- Light/dark Adwaita-inspired UI
- Portable `SeaHorseData` layout
- Clipboard auto-clear for secrets (30s)
- Master password change
