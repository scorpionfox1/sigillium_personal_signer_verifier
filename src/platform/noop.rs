// src/platform/noop.rs

use crate::platform::BestEffortFailure;
use std::fs;
use std::path::Path;

pub fn harden_process_best_effort() -> Vec<BestEffortFailure> {
    vec![BestEffortFailure {
        kind: "noop",
        errno: None,
        msg: "Process hardening not implemented for this target",
    }]
}

pub fn lock_bytes_best_effort(_buf: &mut [u8]) -> Option<BestEffortFailure> {
    Some(BestEffortFailure {
        kind: "noop",
        errno: None,
        msg: "Memory locking not implemented for this target",
    })
}

pub fn unlock_bytes_best_effort(_buf: &mut [u8]) -> Option<BestEffortFailure> {
    Some(BestEffortFailure {
        kind: "noop",
        errno: None,
        msg: "Memory unlocking not implemented for this target",
    })
}

pub fn lock_key32_best_effort(_key: &mut [u8; 32]) -> Option<BestEffortFailure> {
    Some(BestEffortFailure {
        kind: "noop",
        errno: None,
        msg: "Key memory locking not implemented for this target",
    })
}

pub fn unlock_key32_best_effort(_key: &mut [u8; 32]) -> Option<BestEffortFailure> {
    Some(BestEffortFailure {
        kind: "noop",
        errno: None,
        msg: "Key memory unlocking not implemented for this target",
    })
}

pub fn secure_delete_best_effort(path: &Path) -> (Result<(), String>, Vec<BestEffortFailure>) {
    // Fall back to normal deletion, but report that secure delete is not supported.
    let res = fs::remove_file(path).map_err(|e| format!("remove_file failed: {e}"));
    let warns = vec![BestEffortFailure {
        kind: "noop",
        errno: None,
        msg: "Secure delete not implemented for this target; performed normal delete",
    }];
    (res, warns)
}

pub fn restrict_dir_perms_best_effort(_path: &Path) -> Option<BestEffortFailure> {
    Some(BestEffortFailure {
        kind: "noop",
        errno: None,
        msg: "Directory permission restriction not implemented for this target",
    })
}

pub fn restrict_file_perms_best_effort(_path: &Path) -> Option<BestEffortFailure> {
    Some(BestEffortFailure {
        kind: "noop",
        errno: None,
        msg: "File permission restriction not implemented for this target",
    })
}

#[cfg(not(any(unix, windows)))]
pub fn is_stale_lock(pid: Option<u32>) -> bool {
    false // No-op: Always return false on non-supported platforms
}

pub fn fsync_dir_best_effort(dir: &std::path::Path) -> Option<BestEffortFailure> {
    None
}
