// src/types.rs

use std::sync::Mutex;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::security_log::SecurityLog;

pub type KeyId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignVerifyMode {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignOutputMode {
    Signature,
    Record,
}

pub struct SessionState {
    pub unlocked: bool,
    pub active_key_id: Option<KeyId>,
    pub active_associated_key_id: Option<String>,
}

pub struct SecretsState {
    pub master_key: Zeroizing<[u8; 32]>,
    pub active_private: Option<Zeroizing<[u8; 32]>>,
}

#[derive(Debug, Clone)]
pub struct KeyMeta {
    pub id: KeyId,
    pub domain: String,
    pub public_key: [u8; 32],

    // decrypted in-memory only (encrypted at rest in keyfile)
    pub label: String,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ActiveKey {
    pub id: KeyId,
    pub private_key: Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
    pub associated_key_id: Zeroizing<String>,
    pub(crate) domain: String,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnlockedState {
    pub master_key: Zeroizing<[u8; 32]>,
    pub active_key: Option<ActiveKey>,
}

pub struct AppState {
    pub session: Mutex<SessionState>,
    pub secrets: Mutex<Option<SecretsState>>,
    pub keys: std::sync::Mutex<Vec<KeyMeta>>,
    pub sign_verify_mode: std::sync::Mutex<SignVerifyMode>,
    pub sign_output_mode: std::sync::Mutex<SignOutputMode>,
    pub sign_resolve_tag_mode: std::sync::Mutex<bool>,

    // persistent + in-memory security event log
    pub security_log: std::sync::Mutex<SecurityLog>,
}

// Tags used in signing records
pub const TAG_ASSOC_KEY_ID: &str = "{{~assoc_key_id}}";
pub const TAG_SIGNED_UTC: &str = "{{~signed_utc}}";
