// tests/golden_path_json.rs

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

const JSON_MSG: &str = r#"{"kind":"note","n":1}"#;

// Rejects: requires property "missing"
const BAD_SCHEMA: &str = r#"{
  "type":"object",
  "required":["missing"],
  "properties":{
    "kind":{"type":"string"},
    "n":{"type":"integer"}
  }
}"#;

// Accepts: requires kind + n with expected types
const GOOD_SCHEMA: &str = r#"{
  "type":"object",
  "required":["kind","n"],
  "properties":{
    "kind":{"type":"string"},
    "n":{"type":"integer"}
  },
  "additionalProperties": true
}"#;

#[test]
fn golden_path_json_two_keys_schema_branch_cross_verify_and_remove() {
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

    // Install key 1 + key 2 (same mnemonic, different domains)
    command::install_key(MNEMONIC, DOMAIN_1, LABEL_1, None, true, &state, &ctx).unwrap();
    command::install_key(MNEMONIC, DOMAIN_2, LABEL_2, None, true, &state, &ctx).unwrap();

    // Read ids + pubkeys from meta cache
    let (key1_id, pub1_hex, key2_id, pub2_hex) = {
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

    // ---- Schema branch with key 2 ----
    command::select_active_key(key2_id, &state, &ctx).unwrap();

    // Bad schema should reject signing
    assert!(
        command::sign_message(
            JSON_MSG,
            SignVerifyMode::Json,
            Some(BAD_SCHEMA),
            &state,
            None
        )
        .is_err(),
        "expected schema validation to reject signing"
    );

    // Good schema should allow signing
    let sig2 = command::sign_message(
        JSON_MSG,
        SignVerifyMode::Json,
        Some(GOOD_SCHEMA),
        &state,
        None,
    )
    .expect("sign key2 with good schema");

    // Cross-verify: key1 must fail, key2 must pass
    let ok = command::verify_message(
        &pub1_hex,
        JSON_MSG,
        &sig2,
        SignVerifyMode::Json,
        Some(GOOD_SCHEMA),
    )
    .expect("verify with key1 pub");
    assert!(!ok);

    let ok = command::verify_message(
        &pub2_hex,
        JSON_MSG,
        &sig2,
        SignVerifyMode::Json,
        Some(GOOD_SCHEMA),
    )
    .expect("verify with key2 pub");
    assert!(ok);

    // ---- Sign with key 1 under schema ----
    command::select_active_key(key1_id, &state, &ctx).unwrap();

    let sig1 = command::sign_message(
        JSON_MSG,
        SignVerifyMode::Json,
        Some(GOOD_SCHEMA),
        &state,
        None,
    )
    .expect("sign key1 with good schema");

    let ok = command::verify_message(
        &pub2_hex,
        JSON_MSG,
        &sig1,
        SignVerifyMode::Json,
        Some(GOOD_SCHEMA),
    )
    .expect("verify with key2 pub");
    assert!(!ok);

    let ok = command::verify_message(
        &pub1_hex,
        JSON_MSG,
        &sig1,
        SignVerifyMode::Json,
        Some(GOOD_SCHEMA),
    )
    .expect("verify with key1 pub");
    assert!(ok);

    // ---- No-schema branch: key1 should still sign/verify ----
    let sig1_ns = command::sign_message(JSON_MSG, SignVerifyMode::Json, None, &state, None)
        .expect("sign key1 without schema");

    let ok = command::verify_message(&pub1_hex, JSON_MSG, &sig1_ns, SignVerifyMode::Json, None)
        .expect("verify key1 without schema");
    assert!(ok);
}
