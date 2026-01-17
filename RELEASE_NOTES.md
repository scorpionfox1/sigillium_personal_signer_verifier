## Release v0.4.0

### Assets
- **Linux**: built on **Ubuntu 22.04**
- **macOS**: **Apple Silicon (arm64)** build
- **Windows**: `windows-latest`

### Notes
This release introduces support for **multiple keyfiles under a single OS user account**, along with internal security and architecture cleanups.

The changes are designed to support real-world environments where multiple people may share a single desktop login, while preserving explicit identity boundaries inside the application.

---

## Notable Changes

### Multiple keyfiles per OS user
- Introduced support for **multiple encrypted keyfiles** under the same OS credential.
- Added a **Keyfile Select panel** at application startup.
- Once a keyfile is selected, it remains fixed for the lifetime of the app session (restart required to switch).

### Keyfile lifecycle simplification
- Removed `AppState` tracking of keyfile state.
- Missing or corrupted keyfiles are now **immediately quarantined** on detection.
- Eliminates intermediate or ambiguous keyfile states.

### Security log changes
- The **security log is now stored at the application directory level**, not per keyfile.
- Removed **intentional security events** from logging.
- The log now contains **only best-effort security hardening failures**.

### Error handling cleanup
- Introduced new error variants that no longer bypass standard error text in debug mode.
- Debug builds now surface the same structured `AppError` messages as release builds.

### Domain handling fix
- Corrected a bug where the app injected app-specific domain text during key operations.
- Domain strings are now fully user-controlled, restoring proper support for **third-party registries**.

---

## Compatibility & Troubleshooting

### Linux
- The Linux binary is dynamically linked and requires a **modern glibc**
  (Ubuntu 22.04+, Debian 12+, and many comparable distributions).
- If the executable does not run:
  - Ensure it is executable:
    `chmod +x ./sigillium-personal-signer-verifier`
  - Try running it from a terminal to view missing library errors.
  - Older or heavily customized distributions may not be supported.

### macOS
- This build targets **Apple Silicon (arm64)**.
- If macOS blocks the app:
  - Right-click → **Open**, or
  - Remove quarantine:
    `xattr -dr com.apple.quarantine <app>`

### Windows
- If Windows SmartScreen appears, select **More info → Run anyway**.
