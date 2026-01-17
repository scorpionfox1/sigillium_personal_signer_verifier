// tests/common/mod.rs

#![allow(dead_code)]

use sigillium_personal_signer_verifier_lib::{
    command,
    context::AppCtx,
    types::{AppState, KeyId},
};

pub struct TestEnv {
    // Keep tempdirs alive for the duration of the test.
    _td_state: tempfile::TempDir,
    _td_keyfile: tempfile::TempDir,

    pub state: AppState,
    ctx: AppCtx,

    key_id: KeyId,
    pubkey_hex: String,
}

impl TestEnv {
    pub fn ctx(&self) -> &AppCtx {
        &self.ctx
    }
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }
    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }
}

pub struct LockedEnv {
    // Keep tempdirs alive for the duration of the test.
    _td_state: tempfile::TempDir,
    _td_keyfile: tempfile::TempDir,

    pub state: AppState,
    ctx: AppCtx,
}

impl LockedEnv {
    pub fn ctx(&self) -> &AppCtx {
        &self.ctx
    }
}

/// Creates a fresh app state + keyfile dir, creates keyfile, unlocks,
/// installs exactly one key, selects it active, and returns key id + pubkey hex.
pub fn setup_one_active_key(
    passphrase: &str,
    mnemonic: &str,
    domain: &str,
    label: &str,
    associated_id: Option<&str>,
    enforce_standard_domain: bool,
) -> TestEnv {
    let td_state = tempfile::tempdir().expect("tempdir state");
    let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

    let state = AppState::new_for_tests(td_state.path()).expect("init_state");
    let ctx = AppCtx::new(td_keyfile.path().to_path_buf());

    command::keyfile_inspect::refresh_keyfile_state(&state, &ctx).expect("refresh_keyfile_state");

    command::create_keyfile(passphrase, &state, &ctx).expect("create_keyfile");
    command::unlock_app(passphrase, &state, &ctx).expect("unlock_app");

    let (_ks, res) = command::install_key(
        mnemonic,
        domain,
        label,
        associated_id,
        enforce_standard_domain,
        &state,
        &ctx,
    );
    res.expect("install_key");

    let key_id = {
        let metas = state.keys.lock().expect("keys lock");
        assert!(
            !metas.is_empty(),
            "key meta cache should contain at least one key after install"
        );
        metas[0].id
    };

    let (_ks, res) = command::select_active_key(key_id, &state, &ctx);
    res.expect("select_active_key");

    let pubkey_hex = {
        let keys_guard = state.keys.lock().expect("keys lock");
        let meta = keys_guard
            .iter()
            .find(|m| m.id == key_id)
            .expect("meta for active key id should exist");
        hex::encode(meta.public_key)
    };

    assert!(
        pubkey_hex.len() == 64,
        "public key hex should be 64 chars, got {}",
        pubkey_hex.len()
    );

    TestEnv {
        _td_state: td_state,
        _td_keyfile: td_keyfile,
        state,
        ctx,
        key_id,
        pubkey_hex,
    }
}

/// Creates a fresh app state + keyfile dir, creates keyfile, but DOES NOT unlock.
pub fn setup_locked_keyfile(passphrase: &str) -> LockedEnv {
    let td_state = tempfile::tempdir().expect("tempdir state");
    let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

    let state = AppState::new_for_tests(td_state.path()).expect("init_state");
    let ctx = AppCtx::new(td_keyfile.path().to_path_buf());

    command::keyfile_inspect::refresh_keyfile_state(&state, &ctx).expect("refresh_keyfile_state");
    command::create_keyfile(passphrase, &state, &ctx).expect("create_keyfile");

    LockedEnv {
        _td_state: td_state,
        _td_keyfile: td_keyfile,
        state,
        ctx,
    }
}
