// tests/golden_path_string.rs

use sigillium_personal_signer_verifier_lib::{
    command,
    context::AppCtx,
    types::{AppState, SignVerifyMode},
};

const PASSPHRASE: &str = "correct horse battery staple";
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const DOMAIN_1: &str = "example.test";
const DOMAIN_2: &str = "example2.test";
const LABEL_1: &str = "Test Key 1";
const LABEL_2: &str = "Test Key 2";

const MSG: &str = "hello world";

#[test]
fn golden_path_string_two_keys_sign_verify_and_remove() {
    let td_state = tempfile::tempdir().unwrap();
    let td_keyfile = tempfile::tempdir().unwrap();

    let state = AppState::new_for_tests(td_state.path()).unwrap();
    let ctx = AppCtx::new(td_keyfile.path().to_path_buf());

    // Create a keyfile dir + select it in context
    let kf_dir = ctx.keyfiles_root().join("kf");
    std::fs::create_dir_all(&kf_dir).unwrap();
    ctx.set_selected_keyfile_dir(Some(kf_dir));

    command::create_keyfile(PASSPHRASE, &state, &ctx).unwrap();
    command::unlock_app(PASSPHRASE, &state, &ctx).unwrap();

    // Install key 1
    command::install_key(MNEMONIC, DOMAIN_1, LABEL_1, None, true, &state, &ctx).unwrap();

    // Install key 2 (same mnemonic, different domain)
    command::install_key(MNEMONIC, DOMAIN_2, LABEL_2, None, true, &state, &ctx).unwrap();

    // Read ids + pubkeys from meta cache
    let (key1_id, pub1_hex, _key2_id, pub2_hex) = {
        let metas = state.keys.lock().unwrap();

        let k1 = metas
            .iter()
            .find(|m| m.domain == DOMAIN_1)
            .expect("meta key1");
        let k2 = metas
            .iter()
            .find(|m| m.domain == DOMAIN_2)
            .expect("meta key2");

        (
            k1.id,
            hex::encode(k1.public_key),
            k2.id,
            hex::encode(k2.public_key),
        )
    };

    // Sign with key 1
    command::select_active_key(key1_id, &state, &ctx).unwrap();
    let sig = command::sign_payload(MSG, SignVerifyMode::Text, None, &state, None).unwrap();

    // Verify with key 2 pubkey (fail)
    let ok = command::verify_payload(&pub2_hex, MSG, &sig, SignVerifyMode::Text, None).unwrap();
    assert!(!ok);

    // Verify with key 1 pubkey (pass)
    let ok = command::verify_payload(&pub1_hex, MSG, &sig, SignVerifyMode::Text, None).unwrap();
    assert!(ok);
}
