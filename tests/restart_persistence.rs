// tests/restart_persistence.rs

use sigillum_personal_signer_verifier_lib::{
    command,
    context::AppCtx,
    types::{AppState, SignVerifyMode},
};

const PASSPHRASE: &str = "correct horse battery staple";
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const DOMAIN: &str = "example.com";
const LABEL: &str = "My Key";

#[test]
fn restart_persistence_unlock_reload_select_and_sign() {
    // Keep tempdirs alive for whole test.
    let td_state = tempfile::tempdir().expect("tempdir state");
    let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

    // ----- First run -----
    let state1 = AppState::new_for_tests(td_state.path()).expect("init_state");
    let ctx1 = AppCtx::new(td_keyfile.path().to_path_buf());

    command::keyfile_inspect::refresh_keyfile_state(&state1, &ctx1).expect("refresh_keyfile_state");

    command::create_keyfile(PASSPHRASE, &state1, &ctx1).expect("create_keyfile");
    command::unlock_app(PASSPHRASE, &state1, &ctx1).expect("unlock_app");

    let (_ks, res) = command::install_key(MNEMONIC, DOMAIN, LABEL, None, true, &state1, &ctx1);
    res.expect("install_key");

    let key_id1 = {
        let metas = state1.keys.lock().expect("keys lock");
        assert!(
            !metas.is_empty(),
            "expected at least one key meta after install"
        );
        metas[0].id
    };

    let (_ks, res) = command::select_active_key(key_id1, &state1, &ctx1);
    res.expect("select_active_key");

    let pubkey_hex1 = {
        let metas = state1.keys.lock().expect("keys lock");
        let meta = metas.iter().find(|m| m.id == key_id1).expect("meta exists");
        hex::encode(meta.public_key)
    };

    let msg1 = "hello before restart";
    let sig1 = command::sign_payload(msg1, SignVerifyMode::Text, None, &state1).expect("sign 1");
    assert!(
        command::verify_payload(&pubkey_hex1, msg1, &sig1, SignVerifyMode::Text, None)
            .expect("verify 1"),
        "verify should succeed before restart"
    );

    // ----- “Restart”: new AppState, same keyfile dir -----
    drop(state1);

    let state2 = AppState::new_for_tests(td_state.path()).expect("init_state 2");
    let ctx2 = AppCtx::new(td_keyfile.path().to_path_buf());

    command::keyfile_inspect::refresh_keyfile_state(&state2, &ctx2)
        .expect("refresh_keyfile_state 2");
    command::unlock_app(PASSPHRASE, &state2, &ctx2).expect("unlock_app 2");

    // After unlock, key meta cache should be repopulated.
    let key_id2 = {
        let metas = state2.keys.lock().expect("keys lock");
        assert!(
            !metas.is_empty(),
            "expected key meta cache after unlock on restart"
        );
        metas[0].id
    };

    let (_ks, res) = command::select_active_key(key_id2, &state2, &ctx2);
    res.expect("select_active_key 2");

    let pubkey_hex2 = {
        let metas = state2.keys.lock().expect("keys lock");
        let meta = metas.iter().find(|m| m.id == key_id2).expect("meta exists");
        hex::encode(meta.public_key)
    };

    let msg2 = "hello after restart";
    let sig2 = command::sign_payload(msg2, SignVerifyMode::Text, None, &state2).expect("sign 2");
    assert!(
        command::verify_payload(&pubkey_hex2, msg2, &sig2, SignVerifyMode::Text, None)
            .expect("verify 2"),
        "verify should succeed after restart"
    );
}
