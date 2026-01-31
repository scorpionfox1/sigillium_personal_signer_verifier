// src/command/sign_verify.rs

use std::collections::HashMap;

use crate::{
    crypto,
    error::{AppError, AppResult},
    types::{AppState, SignOutputMode, SignVerifyMode, TAG_ASSOC_KEY_ID, TAG_SIGNED_UTC},
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::Utc;
use serde_json::Value;
use zeroize::Zeroizing;

use super::json_ops;

// ======================================================
// signing / verifying
// ======================================================

pub fn sign_payload(
    msg: &str,
    sign_verify_mode: SignVerifyMode,
    schema_json: Option<&str>,
    state: &AppState,
    config_json: Option<&str>,
) -> AppResult<String> {
    if msg.is_empty() {
        return Err(AppError::EmptyPayload);
    }

    // bytes we will sign
    let msg_bytes = Zeroizing::new(msg.as_bytes().to_vec());

    // What we sign:
    let (to_sign, payload_json_for_record): (Zeroizing<Vec<u8>>, Option<Value>) =
        match sign_verify_mode {
            SignVerifyMode::Text => (Zeroizing::new((*msg_bytes).clone()), None),

            SignVerifyMode::Json => {
                let s = std::str::from_utf8(&msg_bytes)
                    .map_err(|_| AppError::InvalidUtf8("invalid utf-8".into()))?;

                let instance: Value =
                    serde_json::from_str(s).map_err(|e| AppError::InvalidJson(e.to_string()))?;

                let digest = match schema_json {
                    Some(schema) => json_ops::canonicalize_json_2020_12(s, schema)?,
                    None => json_ops::canonicalize_json(s)?,
                };

                (Zeroizing::new(digest.to_vec()), Some(instance))
            }
        };

    let sig = crate::command_state::with_active_private(state, |privk| {
        Ok(crypto::sign_message(&*privk, &to_sign))
    })
    .map_err(AppError::Msg)?;

    let sig_base64 = STANDARD.encode(&sig);

    let output_mode = *state.sign_output_mode.lock().unwrap();
    if output_mode == SignOutputMode::Signature {
        return Ok(sig_base64);
    }

    // Record mode
    let config: Value = match config_json {
        Some(config_str) => serde_json::from_str(config_str)
            .map_err(|_| AppError::InvalidJson("Invalid config JSON".into()))?,
        None => Value::Object(serde_json::Map::new()),
    };

    // pull active ids from session
    let (active_key_id, active_associated_key_id) = {
        let s = state.session.lock().unwrap();
        (s.active_key_id, s.active_associated_key_id.clone())
    };

    let Some(active_key_id) = active_key_id else {
        return Err(AppError::NoActiveKeySelected);
    };

    // look up pub key for active key id
    let pub_key_hex = {
        let keys = state.keys.lock().unwrap();
        let key = keys
            .iter()
            .find(|k| k.id == active_key_id)
            .ok_or_else(|| AppError::MissingField("Public key not found".into()))?;
        hex::encode(key.public_key)
    };

    let record_value = create_signature_record(
        &config,
        msg,
        payload_json_for_record.as_ref(),
        &sig_base64,
        &pub_key_hex,
        active_associated_key_id,
    );

    // Output is a canonical JSON string.
    Ok(crate::json_canon::canonical_value_object_string(
        &record_value,
    )?)
}

pub fn verify_payload(
    public_key_hex: &str,
    msg: &str,
    signature_b64: &str,
    mode: SignVerifyMode,
    schema_json: Option<&str>,
) -> AppResult<bool> {
    if msg.is_empty() {
        return Err(AppError::EmptyPayload);
    }

    // --- message preparation ---
    let msg = Zeroizing::new(msg.as_bytes().to_vec());

    let to_verify: Zeroizing<Vec<u8>> = match mode {
        SignVerifyMode::Text => msg.clone(),
        SignVerifyMode::Json => {
            let s = std::str::from_utf8(&msg)
                .map_err(|_| AppError::InvalidUtf8("invalid utf-8".into()))?;

            let digest = match schema_json {
                Some(schema) => json_ops::canonicalize_json_2020_12(s, schema)?,
                None => json_ops::canonicalize_json(s)?,
            };

            Zeroizing::new(digest.to_vec())
        }
    };

    // --- decode public key: hex -> [u8; 32] ---
    let pk_bytes = hex::decode(public_key_hex.trim()).map_err(|_| AppError::InvalidPublicKeyHex)?;

    if pk_bytes.len() != 32 {
        return Err(AppError::InvalidPublicKeyLength);
    }

    let pk: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| AppError::InvalidPublicKeyLength)?;

    // --- decode signature: base64 -> [u8; 64] ---
    let sig_bytes = STANDARD
        .decode(signature_b64.trim())
        .map_err(|_| AppError::InvalidSignatureBase64)?;

    if sig_bytes.len() != 64 {
        return Err(AppError::InvalidSignatureLength);
    }

    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AppError::InvalidSignatureLength)?;

    // --- verify ---
    crypto::verify_message(&pk, &to_verify, &sig)
}

pub fn replace_tags(payload: &str, assoc_key_id: &str) -> String {
    let mut replacements = HashMap::new();
    replacements.insert(TAG_ASSOC_KEY_ID.to_string(), assoc_key_id.to_string());
    replacements.insert(TAG_SIGNED_UTC.to_string(), Utc::now().to_rfc3339());

    let mut result = payload.to_string();
    for (tag, value) in replacements {
        result = result.replace(&tag, &value);
    }
    result
}

fn create_signature_record(
    config: &Value,
    payload_text: &str,
    payload_json: Option<&Value>,
    signature: &str,
    pub_key: &str,
    assoc_key_id: Option<String>,
) -> Value {
    let mut record = serde_json::Map::new();

    // Always-included fields (with optional rename)
    // (support both "payload_name" (UI) and the older "msg_name")
    let payload_name = config
        .get("payload_name")
        .and_then(|v| v.as_str())
        .or_else(|| config.get("msg_name").and_then(|v| v.as_str()))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("message");

    let signature_name = config
        .get("signature_name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("signature");

    let pub_key_name = config
        .get("pub_key_name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("pub_key");

    // <-- key change: if JSON mode, embed as structured JSON value
    if let Some(v) = payload_json {
        record.insert(payload_name.to_string(), v.clone());
    } else {
        record.insert(
            payload_name.to_string(),
            Value::String(payload_text.to_string()),
        );
    }

    record.insert(
        signature_name.to_string(),
        Value::String(signature.to_string()),
    );
    record.insert(pub_key_name.to_string(), Value::String(pub_key.to_string()));

    // Optional assoc_key_id field:
    if config.get("assoc_key_id_name").is_some() {
        if let Some(id) = assoc_key_id {
            let name = config
                .get("assoc_key_id_name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("assoc_key_id");

            let value = if id.trim().is_empty() {
                Value::Null
            } else {
                Value::String(id)
            };

            record.insert(name.to_string(), value);
        }
    }

    Value::Object(record)
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{KeyMeta, SecretsState, SessionState, SignOutputMode};
    use regex::Regex;
    use serde_json::Value;
    use zeroize::Zeroizing;

    fn mk_state_with_active_private(privk: [u8; 32]) -> AppState {
        let td = tempfile::tempdir().expect("tempdir");
        let state = AppState::new_for_tests(td.path()).expect("new_for_tests");

        // session unlocked
        {
            let mut s = state.session.lock().unwrap();
            *s = SessionState {
                unlocked: true,
                active_key_id: Some(1),
                active_associated_key_id: None,
            };
        }

        // secrets present + active private set
        {
            let mut sec = state.secrets.lock().unwrap();
            *sec = Some(SecretsState {
                master_key: Zeroizing::new([9u8; 32]),
                active_private: Some(Zeroizing::new(privk)),
            });
        }

        // default to signature output for most tests
        {
            let mut m = state.sign_output_mode.lock().unwrap();
            *m = SignOutputMode::Signature;
        }

        // insert matching KeyMeta for active_key_id
        {
            let pubk = crypto::public_key_from_private(&privk);
            let mut keys = state.keys.lock().unwrap();
            keys.push(KeyMeta {
                id: 1,
                domain: "example.com".to_string(),
                public_key: pubk,
                label: "test-key".to_string(),
            });
        }

        state
    }

    #[test]
    fn sign_payload_rejects_empty_payload() {
        let state = mk_state_with_active_private([1u8; 32]);
        let err = sign_payload("", SignVerifyMode::Text, None, &state, None).unwrap_err();
        assert!(matches!(err, AppError::EmptyPayload));
    }

    #[test]
    fn verify_payload_rejects_empty_payload() {
        let err = verify_payload("00", "", "AA==", SignVerifyMode::Text, None).unwrap_err();
        assert!(matches!(err, AppError::EmptyPayload));
    }

    #[test]
    fn sign_payload_errors_when_locked_or_no_active_key() {
        let td = tempfile::tempdir().expect("tempdir");
        let state = AppState::new_for_tests(td.path()).expect("new_for_tests");

        // Locked => secrets None
        {
            let mut s = state.session.lock().unwrap();
            *s = SessionState {
                unlocked: false,
                active_key_id: None,
                active_associated_key_id: None,
            };
        }
        {
            let mut sec = state.secrets.lock().unwrap();
            *sec = None;
        }

        let err = sign_payload("hi", SignVerifyMode::Text, None, &state, None).unwrap_err();
        match err {
            AppError::Msg(s) => assert_eq!(s, AppError::AppLocked.to_string()),
            other => panic!("expected AppError::Msg(AppLocked), got {other:?}"),
        }

        // Unlocked but no active private => NoActiveKeySelected
        {
            let mut s = state.session.lock().unwrap();
            s.unlocked = true;
            s.active_key_id = Some(1);
        }
        {
            let mut sec = state.secrets.lock().unwrap();
            *sec = Some(SecretsState {
                master_key: Zeroizing::new([9u8; 32]),
                active_private: None,
            });
        }

        let err = sign_payload("hi", SignVerifyMode::Text, None, &state, None).unwrap_err();
        match err {
            AppError::Msg(s) => assert_eq!(s, AppError::NoActiveKeySelected.to_string()),
            other => panic!("expected AppError::Msg(NoActiveKeySelected), got {other:?}"),
        }
    }

    #[test]
    fn sign_and_verify_text_roundtrip() {
        let privk = crypto::derive_private_key_from_mnemonic_and_domain(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "example.com",
        )
        .expect("derive privk");
        let pubk = crypto::public_key_from_private(&privk);
        let pubk_hex = hex::encode(pubk);

        let state = mk_state_with_active_private(privk);

        let msg = "hello sigillium";
        let sig_b64 = sign_payload(msg, SignVerifyMode::Text, None, &state, None).expect("sign");

        let ok =
            verify_payload(&pubk_hex, msg, &sig_b64, SignVerifyMode::Text, None).expect("verify");
        assert!(ok);
    }

    #[test]
    fn sign_and_verify_json_roundtrip_is_order_invariant() {
        let privk = crypto::derive_private_key_from_mnemonic_and_domain(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "example.com",
        )
        .expect("derive privk");
        let pubk = crypto::public_key_from_private(&privk);
        let pubk_hex = hex::encode(pubk);

        let state = mk_state_with_active_private(privk);

        let msg1 = r#"{ "a": 1, "b": 2 }"#;
        let msg2 = r#"{ "b": 2, "a": 1 }"#;

        let sig_b64 = sign_payload(msg1, SignVerifyMode::Json, None, &state, None).expect("sign");
        let ok =
            verify_payload(&pubk_hex, msg2, &sig_b64, SignVerifyMode::Json, None).expect("verify");
        assert!(ok);
    }

    #[test]
    fn sign_payload_record_mode_returns_json_object() {
        let privk = crypto::derive_private_key_from_mnemonic_and_domain(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "example.com",
        )
        .expect("derive privk");

        let state = mk_state_with_active_private(privk);
        {
            let mut m = state.sign_output_mode.lock().unwrap();
            *m = SignOutputMode::Record;
        }

        let out =
            sign_payload("hello", SignVerifyMode::Text, None, &state, Some("{}")).expect("record");

        let v: Value = serde_json::from_str(&out).expect("json");
        let obj = v.as_object().expect("object");
        assert!(obj.contains_key("message"));
        assert!(obj.contains_key("signature"));
        assert!(obj.contains_key("pub_key"));
        assert!(!obj.contains_key("assoc_key_id")); // key_id only when assoc_key_id_name present
    }

    #[test]
    fn test_replace_tags() {
        let original_payload =
            "The key id is {{~assoc_key_id}} and the timestamp is {{~signed_utc}}.";
        let assoc_key_id = "test_key_id";

        let result = replace_tags(original_payload, assoc_key_id);

        assert!(result.contains("The key id is test_key_id"));

        let utc_pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)";
        let re = Regex::new(utc_pattern).unwrap();
        assert!(re.is_match(&result));
    }

    #[test]
    fn verify_rejects_invalid_public_key_hex_and_lengths() {
        let err = verify_payload("zz", "hi", "AA==", SignVerifyMode::Text, None).unwrap_err();
        assert!(matches!(err, AppError::InvalidPublicKeyHex));

        let pk31 = hex::encode([0u8; 31]);
        let err = verify_payload(&pk31, "hi", "AA==", SignVerifyMode::Text, None).unwrap_err();
        assert!(matches!(err, AppError::InvalidPublicKeyLength));
    }

    #[test]
    fn verify_rejects_invalid_signature_base64_and_lengths() {
        let pk = hex::encode([0u8; 32]);

        let err = verify_payload(&pk, "hi", "!!!!", SignVerifyMode::Text, None).unwrap_err();
        assert!(matches!(err, AppError::InvalidSignatureBase64));

        let err = verify_payload(&pk, "hi", "AA==", SignVerifyMode::Text, None).unwrap_err();
        assert!(matches!(err, AppError::InvalidSignatureLength));
    }

    #[test]
    fn record_includes_assoc_key_id_only_when_config_key_present() {
        let privk = crypto::derive_private_key_from_mnemonic_and_domain(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "example.com",
    )
    .expect("derive privk");

        let state = mk_state_with_active_private(privk);

        {
            let mut s = state.session.lock().unwrap();
            s.active_associated_key_id = Some("assoc_1".to_string());
        }

        {
            let mut m = state.sign_output_mode.lock().unwrap();
            *m = SignOutputMode::Record;
        }

        // No config -> assoc not included
        let out1 = sign_payload("hello", SignVerifyMode::Text, None, &state, None).unwrap();
        let v1: Value = serde_json::from_str(&out1).unwrap();
        let obj1 = v1.as_object().unwrap();
        assert!(obj1.get("assoc_key_id").is_none());

        // Config contains assoc_key_id_name but value unusable -> should include with default name
        let out2 = sign_payload(
            "hello",
            SignVerifyMode::Text,
            None,
            &state,
            Some(r#"{ "assoc_key_id_name": "" }"#),
        )
        .unwrap();
        let v2: Value = serde_json::from_str(&out2).unwrap();
        let obj2 = v2.as_object().unwrap();
        assert_eq!(
            obj2.get("assoc_key_id").and_then(|v| v.as_str()),
            Some("assoc_1")
        );

        // Config provides usable custom name -> should include under that name
        let out3 = sign_payload(
            "hello",
            SignVerifyMode::Text,
            None,
            &state,
            Some(r#"{ "assoc_key_id_name": "associated_key_id" }"#),
        )
        .unwrap();
        let v3: Value = serde_json::from_str(&out3).unwrap();
        let obj3 = v3.as_object().unwrap();
        assert_eq!(
            obj3.get("associated_key_id").and_then(|v| v.as_str()),
            Some("assoc_1")
        );
    }
}
