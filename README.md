# Sigillium Personal Signer / Verifier

A local desktop tool for managing **ed25519 signing keys** and producing **verifiable digital signatures**.

Sigillium Personal Signer / Verifier is designed for users who want **direct control over their keys**, **clear signing semantics**, and **offline operation**—without relying on web services, background agents, or remote infrastructure.

The application was originally built to support a broader ecosystem where keys are installed, registered, and rotated over time, but its functionality is general enough to be used as a standalone signer/verifier.

---

## What this app does

- Stores **multiple ed25519 keys** in a local encrypted keyfile.
- Allows you to **sign messages** and copy/paste the resulting signature.
- Allows you to **verify signatures** against:
  - the active key’s public key, or
  - a user-supplied public key.
- Supports signing and verifying:
  - **Plain text**
  - **JSON**, with deterministic canonicalization.
- Optionally validates JSON against a **JSON Schema at signing time**.

The app is **local-only**: no network access, no background services, no remote dependencies.

---

## Basic workflow

The application is organized around a small set of focused operations:

- Creating and unlocking an encrypted keyfile
- Installing, selecting, and uninstalling keys
- Signing and verifying text or JSON payloads
- Performing security-sensitive actions such as passphrase changes or keyfile destruction

Private key material is only available while the application is explicitly unlocked.

---

## Key model and identity intent

Keys in this app are intended to be human-installed and externally registered with other 3rd party services.

Each stored key includes:

- **Internal key ID**  
  A monotonic identifier intended to represent keys in the drop down selector in the app ui.

- **Domain**  
  A user-supplied domain string that is cryptographically bound into key derivation and metadata.  
  This helps prevent accidental cross-context key reuse.

- **Associated Key ID (optional)**  
  A user-defined identifier representing a **durable external identity**.  
  This allows a public key to be rotated if compromised while preserving identity continuity in other systems.

- **Label**  
  A human-friendly name.

Public keys are stored in the clear.  
Private keys are stored **encrypted at rest**.

### Key installation

Keys are currently installed from a **BIP39 mnemonic** plus domain.  
Importing raw private keys may be added in the future but is not part of v1.

---

## Signing and verification behavior

### Message modes
- **Text mode**: signs/verifies the raw message bytes.
- **JSON mode**: signs/verifies a deterministic canonical form of JSON.

### JSON Schema validation
When signing in JSON mode:
- A schema may be supplied by the user.
- If the JSON payload does **not** validate against the schema, signing is blocked.
- Schema validation is a **signing-time safety check**, not a verification requirement.

### Signature encoding
- Signatures are produced and verified in **base64**.
- Base64 is the canonical format for copy/paste and interoperability.

---

## Security posture

This application aims to be:

> **Better than “good enough” for software-based key handling, but not HSM-grade.**

It is designed for careful users on general-purpose operating systems who follow basic operational security practices (e.g. securely storing physical copies of mnemonics).

### What the app does

- **Encrypted keyfile at rest**
  - Passphrase-based key derivation using **Argon2id** (fixed parameters in v1).
  - Private keys encrypted with **ChaCha20-Poly1305**.
  - Encryption is bound to key metadata (AAD) to prevent ciphertext reuse in other contexts.

- **Keyfile integrity checking**
  - A keyed MAC is used to detect tampering or corruption.
  - Detected corruption causes the keyfile to be quarantined under a `corrupt.*` name.

- **Explicit lock / unlock lifecycle**
  - Private key material is only accessible while unlocked.
  - Sensitive buffers are zeroized when possible.

- **Best-effort OS hardening**
  - Attempts to reduce exposure via platform-specific measures (e.g., memory locking, restrictive file permissions).
  - These steps are opportunistic and non-fatal if unavailable.

### Best-effort failure logging

Failures of security hardening steps are recorded in a persistent log and surfaced in the Security panel.  
The log is intentionally narrow in scope and limited to security-relevant events.

### What the app does *not* claim

- Resistance to a compromised host OS.
- Protection against physical or forensic attacks.
- Hardware-backed key isolation.

---

## Data location

- The encrypted keyfile is stored in the OS-appropriate application data directory.
- File permissions are restricted where supported.

---

## Future work

Additional import paths, platform hardening, and configuration options may be explored in future versions.  
No specific features are committed beyond the existing signing model.

---

## Platform status

Sigillium Personal Signer / Verifier is distributed as **precompiled executables for Linux, Windows, and macOS**. However, this project is actively developed and routinely tested on Linux. While CI produces builds for Windows and macOS, those platforms are currently best-effort and may have rough edges (installer behavior, key storage, OS hardening, etc.). If you run the app on Windows/macOS, treat it as experimental and file issues with details about your OS version and logs.

---

Project status

This project is pre-1.0.

The core signing model, key storage format, and security posture are relatively stable, but breaking changes may still occur as the design is refined. Features, formats, or behaviors may change prior to a 1.0 release as the project matures.

---

## License

This project is licensed under the **MIT License**.  
See the `LICENSE` file for details.
