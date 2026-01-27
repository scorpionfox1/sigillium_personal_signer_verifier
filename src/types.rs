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

    // persistent + in-memory security event log
    pub security_log: std::sync::Mutex<SecurityLog>,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            session: std::sync::Mutex::new(SessionState {
                unlocked: false,
                active_key_id: None,
                active_associated_key_id: None,
            }),
            secrets: std::sync::Mutex::new(None),
            keys: std::sync::Mutex::new(Vec::new()),
            sign_verify_mode: std::sync::Mutex::new(SignVerifyMode::Text),
            sign_output_mode: std::sync::Mutex::new(SignOutputMode::Signature),
            security_log: std::sync::Mutex::new(
                crate::security_log::SecurityLog::init(std::env::temp_dir().as_path()).unwrap(),
            ),
        }
    }
}
