// tests/lock_gating.rs

mod common;

use sigillum_personal_signer_verifier_lib::{command, types::SignVerifyMode};

use crate::common::{setup_locked_keyfile, setup_one_active_key};

const PASSPHRASE: &str = "correct horse battery staple"; // length >= 15
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const DOMAIN: &str = "example.test";
const LABEL: &str = "Test Key";
const MSG: &str = "hello world";

#[test]
fn locked_app_cannot_sign() {
    let env = setup_locked_keyfile(PASSPHRASE);

    let res = command::sign_payload(MSG, SignVerifyMode::Text, None, &env.state);
    assert!(res.is_err(), "sign_payload should fail while app is locked");
}

#[test]
fn signing_requires_selecting_an_active_key() {
    // Start from a fully working env with one active key.
    let env = setup_one_active_key(PASSPHRASE, MNEMONIC, DOMAIN, LABEL, None, true);

    // Clear selection => signing should fail.
    command::clear_active_key(&env.state).expect("clear_active_key");

    let res = command::sign_payload(MSG, SignVerifyMode::Text, None, &env.state);
    assert!(
        res.is_err(),
        "sign_payload should fail when no active key is selected"
    );

    // Re-select => signing should succeed again.
    let (_ks, res) = command::select_active_key(env.key_id(), &env.state, &env.ctx());
    res.expect("select_active_key");

    let sig_b64 =
        command::sign_payload(MSG, SignVerifyMode::Text, None, &env.state).expect("sign_payload");

    let ok = command::verify_payload(&env.pubkey_hex(), MSG, &sig_b64, SignVerifyMode::Text, None)
        .expect("verify_payload");

    assert!(ok, "signature should verify after selecting active key");
}
