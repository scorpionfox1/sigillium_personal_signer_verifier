## Release v0.6.0

### Notes

This release introduces a small but deliberate tightening of application semantics and UI flow.
The core signing model is unchanged, but several internal and user-facing behaviors have been made more explicit and less ambiguous.

---

## Notable Changes

### Explicit AppState construction

- Removed `impl Default for AppState`.
- Application state must now be constructed explicitly via the application initializer.
- This enforces required invariants (filesystem context, security log initialization) at construction time and prevents accidental creation of under-specified state in tests or internal tooling.

This is an internal breaking change and is the primary reason for the minor version bump.

---

### Tag resolution moved into signing flow

- Removed the manual **“Replace message tags”** button from the signing panel.
- Added a **Resolve tags mode** option to the signing panel (`True` / `False`, default: `True`).
- When enabled, tag resolution is performed automatically **at sign time**, immediately before signing.
- The message text is rewritten prior to signing so that the visible message exactly matches what is signed.

Tag resolution remains a preparatory transformation step and does not introduce new signing metadata or validation semantics.

---

### Tag semantics clarification

- Message tags are intended as explicit template markers, not general-purpose text substitution.
- Tags use a `{{~tag_name}}` form to reduce accidental collisions with normal message content.
- Tag resolution is deterministic and silent unless a hard internal failure occurs.

---

## Compatibility

- No changes to cryptographic primitives, key storage format, or signature verification behavior.
- Existing keyfiles and signatures remain fully compatible.
- Internal helpers or tests that previously relied on `AppState::default()` must be updated to use explicit initialization.

---

## Project status

Sigillium Personal Signer / Verifier remains **pre-1.0**.
Structural and UX refinements may continue to land in minor releases prior to a 1.0 stabilization point.
