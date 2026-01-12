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
pub enum KeyfileState {
    Missing,
    NotCorrupted,
    Corrupted,
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

    // keyfile presence / integrity state (startup populates this)
    pub keyfile_state: std::sync::Mutex<KeyfileState>,

    // persistent + in-memory security event log
    pub security_log: std::sync::Mutex<SecurityLog>,
}
