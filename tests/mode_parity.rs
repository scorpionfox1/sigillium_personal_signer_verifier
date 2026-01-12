// tests/mode_parity.rs

mod common;

use sigillum_personal_signer_verifier_lib::{command, types::SignVerifyMode};

use crate::common::setup_one_active_key;

const PASSPHRASE: &str = "correct horse battery staple";
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const DOMAIN: &str = "example.test";
const LABEL: &str = "Test Key";

const TEXT_PAYLOAD: &str = "hello world";

const JSON_OK: &str = r#"{"name":"Alice","age":30,"active":true}"#;
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
fn sign_and_verify_work_in_both_text_and_json_modes() {
    let env = setup_one_active_key(PASSPHRASE, MNEMONIC, DOMAIN, LABEL, None, true);

    let sig_text = command::sign_payload(TEXT_PAYLOAD, SignVerifyMode::Text, None, &env.state)
        .expect("sign text");

    let ok_text = command::verify_payload(
        &env.pubkey_hex(),
        TEXT_PAYLOAD,
        &sig_text,
        SignVerifyMode::Text,
        None,
    )
    .expect("verify text");
    assert!(ok_text);

    let sig_json =
        command::sign_payload(JSON_OK, SignVerifyMode::Json, Some(JSON_SCHEMA), &env.state)
            .expect("sign json");

    let ok_json = command::verify_payload(
        &env.pubkey_hex(),
        JSON_OK,
        &sig_json,
        SignVerifyMode::Json,
        Some(JSON_SCHEMA),
    )
    .expect("verify json");
    assert!(ok_json);

    let cross1 = command::verify_payload(
        &env.pubkey_hex(),
        TEXT_PAYLOAD,
        &sig_json,
        SignVerifyMode::Text,
        None,
    )
    .expect("cross verify 1");
    assert!(!cross1);

    let cross2 = command::verify_payload(
        &env.pubkey_hex(),
        JSON_OK,
        &sig_text,
        SignVerifyMode::Json,
        Some(JSON_SCHEMA),
    )
    .expect("cross verify 2");
    assert!(!cross2);
}
