// src/security_log/model.rs

use serde::{Deserialize, Serialize};

pub const LOG_FILE_NAME: &str = "security.log.jsonl";
pub const LOG_BACKUP_NAME: &str = "security.log.jsonl.1";

pub const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_LOG_EVENTS: usize = 50;
pub const LOAD_TAIL_LINES: usize = 400;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum SecurityEventClass {
    BestEffortFailure,
    IntentionalSecurityEvent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: u64,
    pub ts_ms: u64,
    pub class: SecurityEventClass,
    pub kind: String,
    pub os: String,
    pub context: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
    pub msg: String,
}
