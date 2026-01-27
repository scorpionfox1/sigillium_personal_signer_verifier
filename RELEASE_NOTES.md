## Release v0.5.0

### Assets
- **Linux**: built on **Ubuntu 22.04**
- **macOS**: **Apple Silicon (arm64)** build
- **Windows**: `windows-latest`

---

### Notes

This release expands Sigillium’s signing capabilities with **structured signature output** and introduces an initial **Document Wizard** as a convenience workflow layered on top of the core signing engine.

The primary focus of v0.5.0 remains secure key handling and explicit signing semantics. The document tooling is intentionally scoped and may evolve independently.

---

## Notable Changes

### Signature record output mode

- Added a signing output mode that produces a **JSON signature record** instead of a raw signature string.
- A signature record contains:
  - the signed payload,
  - the base64-encoded signature, and
  - the signing public key.
- Introduced a configuration option allowing users to **customize JSON property names** used in the record.
- Optional inclusion of an associated key id is supported when configured and available.
- In JSON signing mode, the payload is embedded as structured JSON rather than as a string.

This feature enables direct interoperability with external registries, contract formats, and verification pipelines that require structured signing artifacts.

### Document Wizard (initial)

- Introduced a template-driven **Document Wizard** for producing structured JSON bundles intended for signing.
- Templates are defined in **JSON5** and contain human-readable document text, sections, and input specifications.
- The wizard guides the user through:
  - document review,
  - validated data entry, and
  - final confirmation prior to signing.
- The generated bundle separates:
  - document identity and expected document hash (from the template), and
  - user-provided inputs.

The Document Wizard is provided as a helper workflow and is not part of the application’s core security or key model.

---

## Compatibility & Troubleshooting

### Linux
- The Linux binary is dynamically linked and requires a **modern glibc**
  (Ubuntu 22.04+, Debian 12+, and many comparable distributions).
- If the executable does not run:
  - Ensure it is executable:
    `chmod +x ./sigillium-personal-signer-verifier`
  - Try running it from a terminal to view missing library errors.

### macOS
- This build targets **Apple Silicon (arm64)**.
- If macOS blocks the app:
  - Right-click → **Open**, or
  - Remove quarantine:
    `xattr -dr com.apple.quarantine <app>`

### Windows
- If Windows SmartScreen appears, select **More info → Run anyway**.

---

## Project status

Sigillium Personal Signer / Verifier remains **pre-1.0**.

The signing model and key storage format are stabilizing, while auxiliary tooling and UI flows may continue to change in future minor releases.

## Release v0.5.1

### Notes

This is a **workflow and UX refinement release** for v0.5.  
No cryptographic behavior, file formats, or signing semantics were changed.

---

## Notable Changes

### Connected document → sign → verify workflow

- Connected the Document Wizard directly to the signing panel via a **“Sign Doc Bundle”** action.
- Signing a document bundle now automatically:
  - selects JSON signing mode,
  - enables signature record output, and
  - pre-fills the signing payload.
- Added a **“Verify signature”** action on the signing panel, allowing immediate verification of the produced signature (including extraction from signature records).
- This enables a continuous, low-friction workflow:
  **prepare document → sign → verify**, without manual copying or mode changes.

These changes improve correctness and usability while preserving existing security and signing guarantees.
