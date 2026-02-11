// src/crypto.rs

use crate::notices::AppNotice;
use bip39::Mnemonic;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hex;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

//const KDF_CONTEXT: &[u8] = b"CatholicID v1"; // this app is intended to support 3rd party applicatoin so a app domain makes no sense
const DOMAIN_DELIM: u8 = 0x00;

pub fn derive_private_key_from_mnemonic_and_domain(
    mnemonic: &str,
    domain: &str,
) -> Result<[u8; 32], AppNotice> {
    let mnemonic = Mnemonic::parse(mnemonic).map_err(|_| AppNotice::InvalidMnemonic)?;

    // BIP39 seed (64 bytes), zeroized on drop
    let seed = Zeroizing::new(mnemonic.to_seed(""));

    let mut mac =
        Hmac::<Sha512>::new_from_slice(&seed[..]).map_err(|_| AppNotice::CryptoInitFailed)?;

    mac.update(&[DOMAIN_DELIM]);
    mac.update(domain.as_bytes());

    let result = mac.finalize().into_bytes();

    let mut out64 = Zeroizing::new([0u8; 64]);
    out64.copy_from_slice(&result);

    let mut private = [0u8; 32];
    private.copy_from_slice(&out64[..32]);

    Ok(private)
}

pub fn public_key_from_private(private: &[u8; 32]) -> [u8; 32] {
    let signing_key = SigningKey::from_bytes(private);
    let verifying_key = signing_key.verifying_key();

    let mut out = [0u8; 32];
    out.copy_from_slice(verifying_key.as_bytes());
    out
}

pub fn decode_public_key_hex(public_key_hex: &str) -> Result<[u8; 32], AppNotice> {
    let pk_bytes =
        hex::decode(public_key_hex.trim()).map_err(|_| AppNotice::InvalidPublicKeyHex)?;
    if pk_bytes.len() != 32 {
        return Err(AppNotice::InvalidPublicKeyLength);
    }

    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_bytes);
    Ok(pk)
}

// NOTE: No signature context prefix yet.
// Safe for v<1.0 single-purpose signing.
// Revisit if keys are reused across message types.
pub fn sign_message(private: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(private);
    let signature: Signature = signing_key.sign(msg);
    signature.to_bytes()
}

pub fn verify_message(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<bool, AppNotice> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| AppNotice::InvalidPublicKey)?;

    let signature = Signature::from_bytes(signature);
    Ok(verifying_key.verify(message, &signature).is_ok())
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn derive_private_key_rejects_invalid_mnemonic() {
        match derive_private_key_from_mnemonic_and_domain("not a real mnemonic", "example") {
            Err(AppNotice::InvalidMnemonic) => {}
            other => panic!("expected InvalidMnemonic, got {:?}", other),
        }
    }

    #[test]
    fn derive_private_key_is_deterministic() {
        let k1 = derive_private_key_from_mnemonic_and_domain(MNEMONIC_12, "example.com").unwrap();
        let k2 = derive_private_key_from_mnemonic_and_domain(MNEMONIC_12, "example.com").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_private_key_is_domain_separated() {
        let k1 = derive_private_key_from_mnemonic_and_domain(MNEMONIC_12, "example.com").unwrap();
        let k2 = derive_private_key_from_mnemonic_and_domain(MNEMONIC_12, "example.net").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn sign_and_verify_roundtrip_succeeds() {
        let privk =
            derive_private_key_from_mnemonic_and_domain(MNEMONIC_12, "example.com").unwrap();
        let pubk = public_key_from_private(&privk);

        let msg = b"hello";
        let sig = sign_message(&privk, msg);

        let ok = verify_message(&pubk, msg, &sig).unwrap();
        assert!(ok);
    }

    #[test]
    fn verify_returns_false_on_tampered_message() {
        let privk =
            derive_private_key_from_mnemonic_and_domain(MNEMONIC_12, "example.com").unwrap();
        let pubk = public_key_from_private(&privk);

        let msg = b"hello";
        let sig = sign_message(&privk, msg);

        let bad_msg = b"hell0";
        let ok = verify_message(&pubk, bad_msg, &sig).unwrap();
        assert!(!ok);
    }

    #[test]
    fn verify_returns_false_on_tampered_signature() {
        let privk =
            derive_private_key_from_mnemonic_and_domain(MNEMONIC_12, "example.com").unwrap();
        let pubk = public_key_from_private(&privk);

        let msg = b"hello";
        let mut sig = sign_message(&privk, msg);
        sig[0] ^= 0x01;

        let ok = verify_message(&pubk, msg, &sig).unwrap();
        assert!(!ok);
    }
}
