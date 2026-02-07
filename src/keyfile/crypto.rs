// src/keyfile/crypto.rs

use crate::{
    keyfile::{
        types::{AadBytes, AadKind, KeyfileAad},
        KeyfileData,
    },
    notices::{AppNotice, AppResult},
    types::KeyId,
};
use argon2::{Argon2, Params};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

/// Derives a 32-byte encryption key using Argon2id.
///
/// Salt policy / invariant:
/// - `salt.len() == 0` is explicitly allowed (deterministic / domain-separated mode)
/// - `salt.len() > 0` must be at least 16 bytes
///
/// Note: There is no “no salt” value in this API—only `&[]` vs non-empty.
pub fn derive_encryption_key(passphrase: &str, salt: &[u8]) -> AppResult<[u8; 32]> {
    if !salt.is_empty() && salt.len() < 16 {
        return Err(AppNotice::InvalidSaltLength { len: salt.len() });
    }

    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| AppNotice::CryptoKdfParamsFailed(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| AppNotice::CryptoKdfFailed(e.to_string()))?;

    Ok(out)
}

/// Encrypt bytes with AEAD AAD.
///
/// Invariants:
/// - Nonce is always 12 bytes and must never be reused with the same key.
/// - AAD must be constructed via the keyfile AAD helpers in this module (do not ad-hoc).
pub fn encrypt_bytes_with_aad(
    master_key: &Zeroizing<[u8; 32]>,
    aad: &AadBytes,
    plaintext: &Zeroizing<Vec<u8>>,
) -> AppResult<([u8; 12], Vec<u8>)> {
    if aad.as_slice().is_empty() {
        return Err(AppNotice::InvalidAad("aad was empty".to_string()));
    }

    let cipher = cipher_from_master_key(master_key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|e| AppNotice::CryptoEncryptFailed(format!("{e:?}")))?;

    Ok((nonce_bytes, ciphertext))
}

/// Decrypt bytes with AEAD AAD.
///
/// Invariants:
/// - `nonce_bytes` must be exactly 12 bytes.
/// - AAD must match exactly what was used at encryption time.
pub fn decrypt_bytes_with_aad(
    master_key: &Zeroizing<[u8; 32]>,
    aad: &AadBytes,
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> AppResult<Zeroizing<Vec<u8>>> {
    if aad.as_slice().is_empty() {
        return Err(AppNotice::InvalidAad("aad was empty".to_string()));
    }

    if nonce_bytes.len() != 12 {
        return Err(AppNotice::InvalidNonceLength {
            expected: 12,
            got: nonce_bytes.len(),
        });
    }

    let cipher = cipher_from_master_key(master_key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let pt = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: aad.as_slice(),
            },
        )
        .map_err(|e| AppNotice::CryptoDecryptFailed(format!("{e:?}")))?;

    Ok(Zeroizing::new(pt))
}

pub fn encrypt_string_with_aad(
    master_key: &Zeroizing<[u8; 32]>,
    aad: &AadBytes,
    plaintext: &Zeroizing<String>,
) -> AppResult<(String, String)> {
    let pt_bytes = Zeroizing::new(plaintext.as_bytes().to_vec());
    let (nonce, ciphertext) = encrypt_bytes_with_aad(master_key, aad, &pt_bytes)?;

    Ok((
        general_purpose::STANDARD.encode(nonce),
        general_purpose::STANDARD.encode(ciphertext),
    ))
}

pub fn decrypt_string_with_aad(
    master_key: &Zeroizing<[u8; 32]>,
    aad: &AadBytes,
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> AppResult<Zeroizing<String>> {
    let nonce = decode_nonce12_b64(nonce_b64)?;

    let ciphertext = general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| AppNotice::InvalidCiphertextBase64(e.to_string()))?;

    let plaintext = decrypt_bytes_with_aad(master_key, aad, &nonce, &ciphertext)?;

    let s =
        String::from_utf8(plaintext.to_vec()).map_err(|e| AppNotice::InvalidUtf8(e.to_string()))?;

    Ok(Zeroizing::new(s))
}

pub fn decode_nonce12_b64(s: &str) -> AppResult<[u8; 12]> {
    let bytes = general_purpose::STANDARD
        .decode(s)
        .map_err(|e| AppNotice::InvalidNonceBase64(e.to_string()))?;

    if bytes.len() != 12 {
        return Err(AppNotice::InvalidNonceLength {
            expected: 12,
            got: bytes.len(),
        });
    }

    let mut out = [0u8; 12];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn aad_for_private_key(
    data: &KeyfileData,
    id: KeyId,
    domain: &str,
    pk_hex: &str,
) -> AadBytes {
    aad_bytes(AadKind::PrivateKey, data, id, domain, pk_hex)
}

pub(crate) fn aad_for_associated_key_id(
    data: &KeyfileData,
    id: KeyId,
    domain: &str,
    pk_hex: &str,
) -> AadBytes {
    aad_bytes(AadKind::AssociatedKeyId, data, id, domain, pk_hex)
}

pub(crate) fn aad_for_label(data: &KeyfileData, id: KeyId, domain: &str, pk_hex: &str) -> AadBytes {
    aad_bytes(AadKind::Label, data, id, domain, pk_hex)
}

// ======================================================
// Internal helpers
// ======================================================

fn aad_bytes(kind: AadKind, data: &KeyfileData, id: KeyId, domain: &str, pk_hex: &str) -> AadBytes {
    let aad = KeyfileAad {
        kind,
        version: data.version,
        format: data.format.clone(),
        app: data.app.clone(),
        id,
        domain: domain.to_owned(),
        pk_hex: pk_hex.to_owned(),
    }
    .to_bytes();

    AadBytes::new(aad)
}

fn cipher_from_master_key(master_key: &Zeroizing<[u8; 32]>) -> ChaCha20Poly1305 {
    let key = Key::from_slice(master_key.as_ref());
    ChaCha20Poly1305::new(key)
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyfile::types::{KEYFILE_FORMAT, KEYFILE_VERSION};
    use crate::notices::AppNotice;
    use crate::types::KeyId;
    use base64::engine::general_purpose;
    use zeroize::Zeroizing;

    fn mk_data() -> KeyfileData {
        KeyfileData {
            version: KEYFILE_VERSION,
            format: KEYFILE_FORMAT.to_string(),
            app: "sigillium".to_string(),
            salt: "".to_string(),
            file_mac_b64: None,
            keys: vec![],
        }
    }

    fn mk_aad() -> AadBytes {
        let data = mk_data();
        let id: KeyId = 1;
        aad_for_private_key(&data, id, "example.com", "deadbeef")
    }

    #[test]
    fn derive_encryption_key_rejects_empty_salt() {
        let err = derive_encryption_key("pw", &[]).unwrap_err();
        assert!(matches!(err, AppNotice::CryptoKdfFailed(_)));
    }

    #[test]
    fn derive_encryption_key_is_deterministic_with_fixed_salt() {
        let salt = [0x42u8; 16];
        let k1 = derive_encryption_key("pw", &salt).unwrap();
        let k2 = derive_encryption_key("pw", &salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_encryption_key_rejects_short_salt() {
        let err = derive_encryption_key("pw", &[0u8; 15]).unwrap_err();
        assert!(matches!(err, AppNotice::InvalidSaltLength { len: 15 }));
    }

    #[test]
    fn derive_encryption_key_accepts_16_byte_salt_and_is_deterministic() {
        let salt = [9u8; 16];
        let k1 = derive_encryption_key("pw", &salt).unwrap();
        let k2 = derive_encryption_key("pw", &salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn decode_nonce12_b64_rejects_bad_base64() {
        let err = decode_nonce12_b64("not base64!!!").unwrap_err();
        assert!(matches!(err, AppNotice::InvalidNonceBase64(_)));
    }

    #[test]
    fn decode_nonce12_b64_rejects_wrong_length() {
        let s = general_purpose::STANDARD.encode([0u8; 11]);
        let err = decode_nonce12_b64(&s).unwrap_err();
        assert!(matches!(
            err,
            AppNotice::InvalidNonceLength {
                expected: 12,
                got: 11
            }
        ));
    }

    #[test]
    fn encrypt_decrypt_bytes_roundtrip_with_aad() {
        let master_key = Zeroizing::new([7u8; 32]);
        let aad = mk_aad();
        let pt = Zeroizing::new(b"hello".to_vec());

        let (nonce, ct) = encrypt_bytes_with_aad(&master_key, &aad, &pt).unwrap();
        let out = decrypt_bytes_with_aad(&master_key, &aad, &nonce, &ct).unwrap();

        assert_eq!(out.as_slice(), b"hello");
    }

    #[test]
    fn encrypt_rejects_empty_aad() {
        let master_key = Zeroizing::new([7u8; 32]);
        let aad = AadBytes::new(vec![]);
        let pt = Zeroizing::new(b"hello".to_vec());

        let err = encrypt_bytes_with_aad(&master_key, &aad, &pt).unwrap_err();
        assert!(matches!(err, AppNotice::InvalidAad(_)));
    }

    #[test]
    fn decrypt_rejects_wrong_nonce_length() {
        let master_key = Zeroizing::new([7u8; 32]);
        let aad = mk_aad();

        let err = decrypt_bytes_with_aad(&master_key, &aad, &[0u8; 11], b"ct").unwrap_err();
        assert!(matches!(
            err,
            AppNotice::InvalidNonceLength {
                expected: 12,
                got: 11
            }
        ));
    }

    #[test]
    fn decrypt_fails_with_wrong_aad() {
        let master_key = Zeroizing::new([7u8; 32]);
        let aad1 = mk_aad();
        let aad2 = AadBytes::new(b"other-aad".to_vec());
        let pt = Zeroizing::new(b"hello".to_vec());

        let (nonce, ct) = encrypt_bytes_with_aad(&master_key, &aad1, &pt).unwrap();
        let err = decrypt_bytes_with_aad(&master_key, &aad2, &nonce, &ct).unwrap_err();

        assert!(matches!(err, AppNotice::CryptoDecryptFailed(_)));
    }

    #[test]
    fn encrypt_decrypt_string_roundtrip() {
        let master_key = Zeroizing::new([7u8; 32]);
        let aad = mk_aad();
        let s = Zeroizing::new("hi".to_string());

        let (nonce_b64, ct_b64) = encrypt_string_with_aad(&master_key, &aad, &s).unwrap();
        let out = decrypt_string_with_aad(&master_key, &aad, &nonce_b64, &ct_b64).unwrap();

        assert_eq!(out.as_str(), "hi");
    }
}
