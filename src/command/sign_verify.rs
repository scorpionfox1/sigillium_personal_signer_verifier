// src/command/sign_verify.rs

use crate::{
    crypto,
    error::{AppError, AppResult},
    types::{AppState, SignVerifyMode},
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::Zeroizing;

use super::json_ops;

// ======================================================
// signing / verifying
// ======================================================

pub fn sign_payload(
    msg: &str,
    mode: SignVerifyMode,
    schema_json: Option<&str>,
    state: &AppState,
) -> AppResult<String> {
    if msg.is_empty() {
        return Err(AppError::EmptyPayload);
    }

    let msg = Zeroizing::new(msg.as_bytes().to_vec());

    let to_sign: Zeroizing<Vec<u8>> = match mode {
        SignVerifyMode::Text => msg,
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

    let sig = crate::command_state::with_active_private(state, |privk| {
        Ok(crypto::sign_message(&*privk, &to_sign))
    })
    .map_err(AppError::Msg)?;

    Ok(STANDARD.encode(sig))
}

pub fn verify_payload(
    public_key_hex: &str,
    msg: &str,
    signature_b64: &str,
    mode: SignVerifyMode,
    _schema_json: Option<&str>,
) -> AppResult<bool> {
    if msg.is_empty() {
        return Err(AppError::EmptyPayload);
    }

    // --- message preparation ---
    let msg = Zeroizing::new(msg.as_bytes().to_vec());

    let to_verify: Zeroizing<Vec<u8>> = match mode {
        SignVerifyMode::Text => msg,
        SignVerifyMode::Json => {
            let s = std::str::from_utf8(&msg)
                .map_err(|_| AppError::InvalidUtf8("invalid utf-8".into()))?;

            // Schema is never used on verify; verification must reproduce the exact bytes signed.
            let digest = json_ops::canonicalize_json(s)?;
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

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SecretsState, SessionState};
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

        state
    }

    #[test]
    fn sign_payload_rejects_empty_payload() {
        let state = mk_state_with_active_private([1u8; 32]);
        let err = sign_payload("", SignVerifyMode::Text, None, &state).unwrap_err();
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

        let err = sign_payload("hi", SignVerifyMode::Text, None, &state).unwrap_err();
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

        let err = sign_payload("hi", SignVerifyMode::Text, None, &state).unwrap_err();
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
        let sig_b64 = sign_payload(msg, SignVerifyMode::Text, None, &state).expect("sign");

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

        let sig_b64 = sign_payload(msg1, SignVerifyMode::Json, None, &state).expect("sign json");

        let ok = verify_payload(&pubk_hex, msg2, &sig_b64, SignVerifyMode::Json, None)
            .expect("verify json");
        assert!(ok);
    }

    #[test]
    fn sign_json_with_schema_still_verifies_without_schema() {
        // This matches your design: schema is only used during signing for validation/canonicalization,
        // verify reproduces bytes without schema.
        let privk = crypto::derive_private_key_from_mnemonic_and_domain(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "example.com",
        )
        .expect("derive privk");
        let pubk = crypto::public_key_from_private(&privk);
        let pubk_hex = hex::encode(pubk);

        let state = mk_state_with_active_private(privk);

        let schema = r#"
        {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "type": "object",
          "properties": { "a": { "type": "integer" } },
          "required": ["a"],
          "additionalProperties": true
        }
        "#;

        let msg = r#"{ "a": 1, "b": 2 }"#;
        let sig_b64 = sign_payload(msg, SignVerifyMode::Json, Some(schema), &state)
            .expect("sign json+schema");

        let ok =
            verify_payload(&pubk_hex, msg, &sig_b64, SignVerifyMode::Json, None).expect("verify");
        assert!(ok);
    }

    #[test]
    fn verify_rejects_invalid_public_key_hex_and_lengths() {
        // invalid hex
        let err = verify_payload("zz", "hi", "AA==", SignVerifyMode::Text, None).unwrap_err();
        assert!(matches!(err, AppError::InvalidPublicKeyHex));

        // wrong length (31 bytes => 62 hex chars)
        let pk31 = hex::encode([0u8; 31]);
        let err = verify_payload(&pk31, "hi", "AA==", SignVerifyMode::Text, None).unwrap_err();
        assert!(matches!(err, AppError::InvalidPublicKeyLength));
    }

    #[test]
    fn verify_rejects_invalid_signature_base64_and_lengths() {
        let pk = hex::encode([0u8; 32]);

        // invalid base64
        let err = verify_payload(&pk, "hi", "!!!!", SignVerifyMode::Text, None).unwrap_err();
        assert!(matches!(err, AppError::InvalidSignatureBase64));

        // valid base64 but wrong length (decodes to 1 byte)
        let err = verify_payload(&pk, "hi", "AA==", SignVerifyMode::Text, None).unwrap_err();
        assert!(matches!(err, AppError::InvalidSignatureLength));
    }
}
