// tests/passphrase_rotation.rs

mod common;

use sigillum_personal_signer_verifier_lib::{command, context::AppCtx, types::AppState};

const OLD: &str = "correct horse battery staple";
const NEW: &str = "this is a different passphrase";

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const DOMAIN: &str = "example.com";
const LABEL: &str = "My Key";

#[test]
fn passphrase_rotation_gates_unlock_and_signing_still_works() {
    // Keep tempdirs alive for the whole test.
    let td_state = tempfile::tempdir().expect("tempdir state");
    let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

    // ----- First run: create + unlock + install + select -----
    let state1 = AppState::new_for_tests(td_state.path()).expect("init_state");
    let ctx1 = AppCtx::new(td_keyfile.path().to_path_buf());

    command::keyfile_inspect::refresh_keyfile_state(&state1, &ctx1).expect("refresh_keyfile_state");

    command::create_keyfile(OLD, &state1, &ctx1).expect("create_keyfile");
    command::unlock_app(OLD, &state1, &ctx1).expect("unlock_app");

    let (_ks, res) = command::install_key(MNEMONIC, DOMAIN, LABEL, None, true, &state1, &ctx1);
    res.expect("install_key");

    let key_id = {
        let metas = state1.keys.lock().expect("keys lock");
        assert!(
            !metas.is_empty(),
            "expected at least one key meta after install"
        );
        metas[0].id
    };

    let (_ks, res) = command::select_active_key(key_id, &state1, &ctx1);
    res.expect("select_active_key");

    // Rotate passphrase while unlocked.
    let (_ks, res) = command::change_passphrase(OLD, NEW, &state1, &ctx1);
    res.expect("change_passphrase");

    // ----- “Restart”: new AppState, same keyfile directory -----
    drop(state1);

    let state2 = AppState::new_for_tests(td_state.path()).expect("init_state 2");
    let ctx2 = AppCtx::new(td_keyfile.path().to_path_buf());

    command::keyfile_inspect::refresh_keyfile_state(&state2, &ctx2)
        .expect("refresh_keyfile_state 2");

    // Old passphrase should fail to unlock.
    assert!(
        command::unlock_app(OLD, &state2, &ctx2).is_err(),
        "expected OLD passphrase to fail after rotation"
    );

    // New passphrase should unlock.
    command::unlock_app(NEW, &state2, &ctx2).expect("unlock_app with NEW");

    // Re-select the only key (id should persist, but we don’t assume it—read from cache).
    let key_id2 = {
        let metas = state2.keys.lock().expect("keys lock");
        assert!(!metas.is_empty(), "expected key meta cache after unlock");
        metas[0].id
    };

    let (_ks, res) = command::select_active_key(key_id2, &state2, &ctx2);
    res.expect("select_active_key 2");

    let pubkey_hex = {
        let metas = state2.keys.lock().expect("keys lock");
        let meta = metas.iter().find(|m| m.id == key_id2).expect("meta exists");
        hex::encode(meta.public_key)
    };

    // Sign + verify still works.
    let msg = "hello after passphrase rotation";
    let sig = command::sign_payload(
        msg,
        sigillum_personal_signer_verifier_lib::types::SignVerifyMode::Text,
        None,
        &state2,
    )
    .expect("sign_payload");

    let ok = command::verify_payload(
        &pubkey_hex,
        msg,
        &sig,
        sigillum_personal_signer_verifier_lib::types::SignVerifyMode::Text,
        None,
    )
    .expect("verify_payload");

    assert!(
        ok,
        "signature should verify after passphrase rotation + restart"
    );
}
