// tests/golden_path_string.rs

mod common;

use sigillum_personal_signer_verifier_lib::{command, types::SignVerifyMode};

use crate::common::setup_one_active_key;

const PASSPHRASE: &str = "correct horse battery staple"; // length >= 15
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const DOMAIN: &str = "example.test";
const LABEL: &str = "Test Key";
const ASSOCIATED_ID: &str = "assoc-123";
const MSG_OK: &str = "hello world";
const MSG_BAD: &str = "hello world!"; // different

#[test]
fn golden_path_string_mode_create_install_select_sign_verify() {
    let env = setup_one_active_key(
        PASSPHRASE,
        MNEMONIC,
        DOMAIN,
        LABEL,
        Some(ASSOCIATED_ID),
        true,
    );

    let sig_b64 = command::sign_payload(MSG_OK, SignVerifyMode::Text, None, &env.state)
        .expect("sign_payload (text)");

    let ok = command::verify_payload(
        &env.pubkey_hex(),
        MSG_OK,
        &sig_b64,
        SignVerifyMode::Text,
        None,
    )
    .expect("verify_payload (text)");
    assert!(ok, "signature should verify for the original message");

    let bad = command::verify_payload(
        &env.pubkey_hex(),
        MSG_BAD,
        &sig_b64,
        SignVerifyMode::Text,
        None,
    )
    .expect("verify_payload (text, wrong msg)");
    assert!(!bad, "signature must not verify for a different message");
}
