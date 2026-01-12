## Release v0.3.0

### Assets
- **Linux**: built on **Ubuntu 22.04**
- **macOS**: **Apple Silicon (arm64)** build
- **Windows**: `windows-latest`

### Notes
This release focuses on stability and incremental improvements.  
Binaries are built on conservative, well-supported OS baselines to maximize compatibility.

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

---

## Building from Source

If the provided binaries do not work on your system, you can **build from source**:
- The full source code is included in this repository.
- Building locally allows you to target your exact OS version and environment.
