// tests/golden_path_json.rs

mod common;

use sigillum_personal_signer_verifier_lib::{command, types::SignVerifyMode};

use crate::common::setup_one_active_key;

const PASSPHRASE: &str = "correct horse battery staple"; // length >= 15
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const DOMAIN: &str = "example.test";
const LABEL: &str = "Test Key";
const ASSOCIATED_ID: &str = "assoc-123";

// JSON payloads (note: semantically identical, different key order)
const JSON_OK: &str = r#"{"name":"Alice","age":30,"active":true}"#;
const JSON_OK_REORDERED: &str = r#"{"active":true,"age":30,"name":"Alice"}"#;
const JSON_BAD: &str = r#"{"name":"Alice","age":31,"active":true}"#;

const JSON_SCHEMA: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["name", "age", "active"],
  "properties": {
    "name":   { "type": "string" },
    "age":    { "type": "integer" },
    "active": { "type": "boolean" }
  }
}"#;

#[test]
fn golden_path_json_mode_create_install_select_sign_verify() {
    let env = setup_one_active_key(
        PASSPHRASE,
        MNEMONIC,
        DOMAIN,
        LABEL,
        Some(ASSOCIATED_ID),
        true,
    );

    let sig_b64 =
        command::sign_payload(JSON_OK, SignVerifyMode::Json, Some(JSON_SCHEMA), &env.state)
            .expect("sign_payload (json)");

    let ok = command::verify_payload(
        &env.pubkey_hex(),
        JSON_OK,
        &sig_b64,
        SignVerifyMode::Json,
        Some(JSON_SCHEMA),
    )
    .expect("verify_payload (json)");
    assert!(ok, "signature should verify for the original JSON payload");

    let ok_reordered = command::verify_payload(
        &env.pubkey_hex(),
        JSON_OK_REORDERED,
        &sig_b64,
        SignVerifyMode::Json,
        Some(JSON_SCHEMA),
    )
    .expect("verify_payload (json, reordered)");
    assert!(
        ok_reordered,
        "JSON signature should verify for semantically identical JSON with different key order"
    );

    let bad = command::verify_payload(
        &env.pubkey_hex(),
        JSON_BAD,
        &sig_b64,
        SignVerifyMode::Json,
        Some(JSON_SCHEMA),
    )
    .expect("verify_payload (json, tampered)");
    assert!(
        !bad,
        "signature must not verify for a different JSON payload"
    );
}
