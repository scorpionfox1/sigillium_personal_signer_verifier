// src/keyfile/types.rs

use crate::types::KeyId;
use serde::{Deserialize, Serialize};

pub const KEYFILE_VERSION: u32 = 1;
pub const KEYFILE_FORMAT: &str = "sigillium-keyfile";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyfileData {
    pub version: u32,
    pub format: String,
    pub app: String,
    pub salt: String, // base64(16)

    #[serde(default)]
    pub file_mac_b64: Option<String>,

    pub keys: Vec<KeyEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyEntry {
    pub id: KeyId,
    pub domain: String,
    pub public_key_hex: String,

    // encrypted private key
    pub key_nonce_b64: String,
    pub encrypted_private_key_b64: String,

    // encrypted associated_key_id
    pub associated_key_id: EncryptedString,

    // encrypted label (UX-only)
    pub label: EncryptedString,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedString {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

/// Identifies the purpose of AAD for keyfile encryption.
#[derive(Debug, Clone, Copy)]
pub enum AadKind {
    PrivateKey,
    AssociatedKeyId,
    Label,
}

impl AadKind {
    fn as_tag(self) -> &'static str {
        match self {
            AadKind::PrivateKey => "priv",
            AadKind::AssociatedKeyId => "assoc",
            AadKind::Label => "label",
        }
    }
}

/// Canonical, typed AAD for keyfile crypto operations.
#[derive(Debug, Clone)]
pub struct KeyfileAad {
    pub kind: AadKind,
    pub version: u32,
    pub format: String,
    pub app: String,
    pub id: KeyId,
    pub domain: String,
    pub pk_hex: String,
}

impl KeyfileAad {
    /// Produce canonical AAD bytes.
    /// Field order and separators are fixed and must never change.
    pub fn to_bytes(&self) -> Vec<u8> {
        format!(
            "k={};v={};fmt={};app={};id={};domain={};pk={}",
            self.kind.as_tag(),
            self.version,
            self.format,
            self.app,
            self.id,
            self.domain,
            self.pk_hex
        )
        .into_bytes()
    }
}

/// Strongly-typed AAD bytes to prevent misuse.
#[derive(Debug, Clone)]
pub struct AadBytes(Vec<u8>);

impl AadBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        AadBytes(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}
