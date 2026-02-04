# Sigillium Personal Signer / Verifier

A local desktop application for **secure key storage, deterministic signing, and signature verification**.

Sigillium Personal Signer / Verifier is designed for users who want direct custody of their signing keys, explicit control over what is being signed, and offline operation — without web services, background agents, or remote infrastructure.

The application is primarily a **signing tool**. All other features exist to support that goal.

---

## What this app does

- Stores one or more **ed25519 keys** in an encrypted local keyfile.
- Allows signing of messages with an explicitly selected key.
- Produces verifiable digital signatures with clear, inspectable semantics.
- Verifies signatures against:
  - the active key’s public key, or
  - a user-supplied public key.
- Supports signing and verifying:
  - Plain text
  - JSON, using deterministic canonicalization.
- Optionally validates JSON against a JSON Schema at signing time.
- Can output either a **raw signature** or a structured **signature record** JSON object.

The app is **local-only**: no network access, no background services, no remote dependencies.

---

## Core workflow

The application is organized around a small set of security-focused operations:

- Selecting or creating a keyfile at application startup
- Unlocking an encrypted keyfile
- Installing, selecting, and uninstalling keys
- Signing and verifying text or JSON messages
- Performing security-sensitive actions such as passphrase changes or keyfile destruction

Once a keyfile is selected, it remains active for the duration of the app session.  
Switching to a different keyfile requires closing and reopening the application.

Private key material is only available while the application is explicitly unlocked.

---

## Multiple keyfiles and shared systems

The application supports multiple encrypted keyfiles under a single OS user account.

This is a deliberate, pragmatic design choice intended to support real-world environments where more than one person may share the same desktop credentials (for example, small offices or shared workstations), while preserving explicit identity boundaries inside the application.

---

## Key model and identity intent

Keys in this app are intended to be **human-installed** and **externally registered** with third-party systems.

Each stored key includes:

- **Internal key ID**  
  A monotonic identifier used for UI selection and internal referencing.

- **Domain**  
  A user-supplied domain string that is cryptographically bound into key derivation and metadata.  
  The application does not inject any app-specific domain text, allowing keys to be used cleanly with independent registries or verification systems.

- **Associated Key ID (optional)**  
  A user-defined identifier representing a durable external identity.  
  This allows public keys to be rotated while preserving identity continuity elsewhere.

- **Label**  
  A human-friendly name for operator clarity.

Public keys are stored in the clear.  
Private keys are stored encrypted at rest.

### Key installation

Keys are currently installed from a **BIP39 mnemonic** plus domain.  
Importing raw private keys may be added in the future but is not part of v1.

---

## Signing and verification behavior

Sigillium signs **messages**.  
A message is the byte sequence presented to the signing engine, regardless of how it is represented at higher layers.

### Message modes

- **Text mode**: signs/verifies the raw message bytes.
- **JSON mode**: signs/verifies a deterministic canonical form of JSON.

### Signing output modes

When signing, the app can produce either:

- **Signature** — a raw base64-encoded signature, or
- **Signature record** — a structured JSON object containing:
  - the message,
  - the signature, and
  - the signing public key.

The signature record format is configurable via a small JSON configuration object, allowing users to control the property names used for:

- the message,
- the signature,
- the public key, and
- (optionally) the associated key id.

This allows the signer to integrate cleanly with external registries, contract formats, or verification pipelines that require specific field naming.

In JSON signing mode, the message is embedded as structured JSON (not as a JSON-encoded string).

The signing panel also provides a shortcut action that allows the user to immediately navigate to the verification panel after signing, carrying the signed message and produced signature forward automatically. This enables quick confirmation that the signature produced is valid without manual copying or reconfiguration.

### Message tag resolution

The signing panel supports optional message tag resolution at signing time.

When enabled, predefined template tags (for example `{{~assoc_key_id}}` or `{{~signed_utc}}`) are resolved immediately before signing, and the message text is rewritten prior to signature generation. This guarantees that the visible message content exactly matches the signed message.

Tag resolution is a preparatory transformation step and does not alter signature semantics or verification behavior.

### JSON Schema validation

When signing in JSON mode:

- A schema may be supplied by the user.
- If the JSON message does **not** validate against the schema, signing is blocked.
- Schema validation is a signing-time safety check, not a verification requirement.

### Signature encoding

- Signatures are produced and verified in **base64**.

---

## Message conventions used by Sigillium

Sigillium is a general-purpose signing tool.  
The message structures described below are **conventions used by Sigillium and its Document Wizard**, not requirements of the signing engine.

Other systems may define different message formats, all of which Sigillium can sign and verify as long as the message is well-defined.

### Document

A **document** is a structured JSON object representing a single human-readable document under Sigillium’s document conventions.

A document contains:
- a hash of the document text and the algorithm used to produce that hash, and
- an input object containing the values supplied for that document.

The document text itself is not signed directly; its hash anchors the document’s content.

### Document bundle

A **document bundle** is a structured JSON message composed of:
- a canonical identity (the publicly registered identity associated with the signing key),
- a signing timestamp (`signed_at_utc`), and
- an array of one or more documents.

A document bundle is a message and may be signed like any other message.

### Signature record

A **signature record** is a structured JSON object containing:
- a message,
- the signature of that message,
- the public key used to produce the signature, and
- optionally, the associated key id for that public key.

Signature records are an output format and do not alter signature semantics.

---

## Document wizard (auxiliary)

The application includes a **Document Wizard** as a convenience feature layered on top of the core signing engine.

The wizard allows users to load a JSON5 document template and step through a readable review-and-input flow, producing a document bundle according to Sigillium’s document conventions. At the end of the wizard flow, once a document bundle is created, a shortcut action navigates to the signing panel and automatically loads the bundle into the signing message field.

The wizard:
- renders human-readable document text,
- optionally displays a document-specific **About** screen prior to section review (informational only; not signed),
- gathers and validates user input, and
- emits a structured JSON message intended to be signed by the core signing engine.

The emitted JSON message may contain **signing-time tags**, which are resolved by the signing panel immediately prior to signature generation.

The Document Wizard does **not** perform cryptographic signing and does **not** define canonical meaning. Canonical meaning is established only by the message ultimately signed by the signing engine.

The Document Wizard is intentionally scoped as a helper workflow, not as a foundational component of the application’s security model.

---

## Project status

This project is **pre-1.0**.

The core signing model and key storage format are stabilizing, but UI flows, auxiliary tooling, and configuration ergonomics may continue to evolve prior to a 1.0 release.

---

## License

This project is licensed under the **MIT License**.  
See the `LICENSE` file for details.
