// src/crypto.rs

use crate::error::AppError;
use bip39::Mnemonic;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

const KDF_CONTEXT: &[u8] = b"CatholicID v1";
const DOMAIN_DELIM: u8 = 0x00;

pub fn derive_private_key_from_mnemonic_and_domain(
    mnemonic: &str,
    domain: &str,
) -> Result<[u8; 32], AppError> {
    let mnemonic = Mnemonic::parse(mnemonic).map_err(|_| AppError::InvalidMnemonic)?;

    // BIP39 seed (64 bytes), zeroized on drop
    let seed = Zeroizing::new(mnemonic.to_seed(""));

    let mut mac =
        Hmac::<Sha512>::new_from_slice(KDF_CONTEXT).map_err(|_| AppError::CryptoInitFailed)?;

    mac.update(&seed[..]);
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

pub fn sign_message(private: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(private);
    let signature: Signature = signing_key.sign(msg);
    signature.to_bytes()
}

pub fn verify_message(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<bool, AppError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| AppError::InvalidPublicKey)?;

    let signature = Signature::from_bytes(signature);
    Ok(verifying_key.verify(message, &signature).is_ok())
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn derive_private_key_is_deterministic_for_same_inputs() {
        let domain = "example.com";
        let k1 = derive_private_key_from_mnemonic_and_domain(TEST_MNEMONIC, domain).unwrap();
        let k2 = derive_private_key_from_mnemonic_and_domain(TEST_MNEMONIC, domain).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_private_key_is_domain_separated() {
        let k1 = derive_private_key_from_mnemonic_and_domain(TEST_MNEMONIC, "example.com").unwrap();
        let k2 = derive_private_key_from_mnemonic_and_domain(TEST_MNEMONIC, "other.com").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_private_key_rejects_invalid_mnemonic() {
        let err = derive_private_key_from_mnemonic_and_domain("not a real mnemonic", "example.com")
            .unwrap_err();
        assert!(matches!(err, AppError::InvalidMnemonic));
    }

    #[test]
    fn public_key_from_private_is_deterministic_and_nonzero() {
        let private =
            derive_private_key_from_mnemonic_and_domain(TEST_MNEMONIC, "example.com").unwrap();

        let p1 = public_key_from_private(&private);
        let p2 = public_key_from_private(&private);

        assert_eq!(p1, p2);
        assert_ne!(p1, [0u8; 32]);
    }

    #[test]
    fn sign_and_verify_roundtrip_succeeds() {
        let private =
            derive_private_key_from_mnemonic_and_domain(TEST_MNEMONIC, "example.com").unwrap();
        let public = public_key_from_private(&private);

        let msg = b"hello sigillium";
        let sig = sign_message(&private, msg);

        let ok = verify_message(&public, msg, &sig).unwrap();
        assert!(ok);
    }

    #[test]
    fn verify_fails_if_message_is_tampered() {
        let private =
            derive_private_key_from_mnemonic_and_domain(TEST_MNEMONIC, "example.com").unwrap();
        let public = public_key_from_private(&private);

        let msg = b"hello sigillium";
        let sig = sign_message(&private, msg);

        let mut tampered = msg.to_vec();
        tampered[0] ^= 0x01;

        let ok = verify_message(&public, &tampered, &sig).unwrap();
        assert!(!ok);
    }

    #[test]
    fn verify_fails_if_signature_is_tampered() {
        let private =
            derive_private_key_from_mnemonic_and_domain(TEST_MNEMONIC, "example.com").unwrap();
        let public = public_key_from_private(&private);

        let msg = b"hello sigillium";
        let mut sig = sign_message(&private, msg);
        sig[0] ^= 0x01;

        let ok = verify_message(&public, msg, &sig).unwrap();
        assert!(!ok);
    }

    // Stronger tripwire: known vector for the current derivation algorithm.
    // If you change KDF_CONTEXT, DOMAIN_DELIM, input ordering, or BIP39 seed settings,
    // this should fail immediately.
    #[test]
    fn derive_private_key_known_vector() {
        let domain = "example.com";
        let got = derive_private_key_from_mnemonic_and_domain(TEST_MNEMONIC, domain).unwrap();

        // Computed from:
        // BIP39 seed (passphrase="") then HMAC-SHA512(key="CatholicID v1", msg=seed||0x00||"example.com"),
        // taking the first 32 bytes.
        let expected_hex = "c08e9771fc73dd0856f463aa62146d409bc9e6e7e9ea8b6d4140122293eec73b";
        let expected: [u8; 32] = hex::decode(expected_hex).unwrap().try_into().unwrap();

        assert_eq!(got, expected);
    }
}
