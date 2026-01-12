// src/keyfile/crypto.rs

use crate::{
    error::{AppError, AppResult},
    keyfile::{
        types::{AadBytes, AadKind, KeyfileAad},
        KeyfileData,
    },
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
        return Err(AppError::InvalidSaltLength { len: salt.len() });
    }

    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| AppError::CryptoKdfParamsFailed(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| AppError::CryptoKdfFailed(e.to_string()))?;

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
        return Err(AppError::InvalidAad("aad was empty".to_string()));
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
        .map_err(|e| AppError::CryptoEncryptFailed(format!("{e:?}")))?;

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
        return Err(AppError::InvalidAad("aad was empty".to_string()));
    }

    if nonce_bytes.len() != 12 {
        return Err(AppError::InvalidNonceLength {
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
        .map_err(|e| AppError::CryptoDecryptFailed(format!("{e:?}")))?;

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
        .map_err(|e| AppError::InvalidCiphertextBase64(e.to_string()))?;

    let plaintext = decrypt_bytes_with_aad(master_key, aad, &nonce, &ciphertext)?;

    let s =
        String::from_utf8(plaintext.to_vec()).map_err(|e| AppError::InvalidUtf8(e.to_string()))?;

    Ok(Zeroizing::new(s))
}

pub fn decode_nonce12_b64(s: &str) -> AppResult<[u8; 12]> {
    let bytes = general_purpose::STANDARD
        .decode(s)
        .map_err(|e| AppError::InvalidNonceBase64(e.to_string()))?;

    if bytes.len() != 12 {
        return Err(AppError::InvalidNonceLength {
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
