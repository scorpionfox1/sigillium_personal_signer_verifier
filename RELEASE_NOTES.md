## Release v0.7.0

### Notes

This release focuses on **Document Wizard UX and flow**, **safer keyfile persistence and concurrency**, and continued **polish** in error handling and clipboard ergonomics.

---

### Notable Changes

#### Document Wizard: About step and improved flow

- Added an optional per-document **About** screen (`doc_about`) shown before the document’s sections  
  (UI-only; not signed or canonical).
- Improved wizard navigation and layout:
  - clearer page skeleton,
  - navigation buttons placed below content,
  - reduced visual clutter.
- Document bundle produced by wizard no longer contains doc_identity object. Hash alone anchors document semantics.
- Added **Copy Raw Document Text to Clipboard** at the end of the wizard.
- Improved “Review & Build” behavior:
  - bundle build attempts are tracked to avoid repeated rebuild churn,
  - bundle can auto-build once eligible,
  - clearer explanation of what the bundle contains.
- Validation improvements:
  - inputs are validated before advancing from the Inputs step,
  - JSON inputs are synced and parsed on navigation with per-field error reporting.
- Standardized language in UI and code to use 'message' over 'payload'.

#### UI notices and warnings

- Added a bright, consistent **Notice** widget (`ui_notice`) and applied it to key warnings.
- Translation disclaimer text clarified to state explicitly that **only canonical document text is signed**.
- Simplified and standardized warning and help copy across panels.

#### Passphrase validation and errors

- Passphrase validation now returns structured `AppError` variants:
  - required
  - too short
  - too long
- User-facing error messages are clearer and consistently surfaced.
- Tests updated to reflect typed validation failures.

#### Keyfile durability, locking, and secret hygiene

- Keyfile writes now include a best-effort **directory fsync after atomic rename** to reduce crash-loss risk.
- Key install and uninstall operations now acquire the **keyfile lock** to prevent concurrent mutation.
- Key labels are stored as `Zeroizing<String>` in memory to reduce post-use exposure.

#### Internal refactors and cleanup

- Consolidated repeated public-key hex decoding into
  `crypto::decode_public_key_hex`.
- Cleaned up keyfile directory scanning and helper reuse.
- Expanded and reused clipboard helpers (`copy_label_with_button`) across panels.
- Refactored keyfile lock-path computation into a dedicated helper.

---
