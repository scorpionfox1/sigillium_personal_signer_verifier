// tests/lifecycle.rs

use sigillium_personal_signer_verifier_lib::{
    command, context::AppCtx, keyfile_store::KeyfileStore, types::AppState,
};

const OLD: &str = "correct horse battery staple";
const NEW: &str = "this is a different passphrase";

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const DOMAIN_1: &str = "example.test";
const DOMAIN_2: &str = "example2.test";
const LABEL_1: &str = "Key 1";
const LABEL_2: &str = "Key 2";

#[test]
fn lifecycle_create_rotate_add_remove_self_destruct() {
    let td_state = tempfile::tempdir().expect("tempdir state");
    let td_app = tempfile::tempdir().expect("tempdir app");

    let state = AppState::new_for_tests(td_state.path()).expect("init_state");
    let ctx = AppCtx::new(td_app.path().to_path_buf());

    // Select a keyfile dir
    let kf_name = "kf";
    let kf_dir = ctx.keyfiles_root().join(kf_name);
    std::fs::create_dir_all(&kf_dir).expect("create keyfile dir");
    ctx.set_selected_keyfile_dir(Some(kf_dir.clone()));

    // Create keyfile + unlock
    command::create_keyfile(OLD, &state, &ctx).expect("create_keyfile");
    command::unlock_app(OLD, &state, &ctx).expect("unlock_app old");

    // Rotate passphrase (stay unlocked, secrets updated)
    command::change_passphrase(OLD, NEW, &state, &ctx).expect("change_passphrase");

    // Install 2 keys (same mnemonic, different domains)
    command::install_key(MNEMONIC, DOMAIN_1, LABEL_1, None, true, &state, &ctx)
        .expect("install key1");
    command::install_key(MNEMONIC, DOMAIN_2, LABEL_2, None, true, &state, &ctx)
        .expect("install key2");

    // Grab ids by domain from cache
    let (key1_id, key2_id) = {
        let metas = state.keys.lock().expect("keys lock");
        let k1 = metas
            .iter()
            .find(|m| m.domain == DOMAIN_1)
            .expect("meta k1");
        let k2 = metas
            .iter()
            .find(|m| m.domain == DOMAIN_2)
            .expect("meta k2");
        (k1.id, k2.id)
    };

    // Remove key2 (must be active)
    command::select_active_key(key2_id, &state, &ctx).expect("select key2");
    command::uninstall_active_key(&state, &ctx).expect("uninstall active (key2)");

    // Key2 gone; key1 still selectable
    assert!(command::select_active_key(key2_id, &state, &ctx).is_err());
    command::select_active_key(key1_id, &state, &ctx).expect("select key1");

    // Self-destruct: lock app, clear selection, destroy keyfile dir
    command::session::secure_prepare_for_quit(&state).expect("secure_prepare_for_quit");

    let store = KeyfileStore::new(ctx.keyfiles_root());
    store.destroy_keyfile_dir_by_name_best_effort(kf_name);

    ctx.set_selected_keyfile_dir(None);

    // Confirm deletion
    assert!(!kf_dir.exists(), "expected keyfile dir to be destroyed");
}
