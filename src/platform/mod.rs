// src/platform/mod.rs

use std::path::Path;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
mod macos;

pub(crate) mod debug_faults;

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
mod noop;

// Select platform implementation once, then call through `imp::*`.
#[cfg(target_os = "linux")]
mod imp {
    pub use super::linux::*;
}

#[cfg(target_os = "windows")]
mod imp {
    pub use super::windows::*;
}

#[cfg(target_os = "macos")]
mod imp {
    pub use super::macos::*;
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
mod imp {
    pub use super::noop::*;
}

#[derive(Clone, Copy, Debug)]
pub struct BestEffortFailure {
    pub kind: &'static str,
    pub errno: Option<i32>,
    pub msg: &'static str,
}

// Stable op names for targeted debug fault injection.
const OP_HARDEN_PROCESS: &str = "harden_process_best_effort";
const OP_LOCK_KEY32: &str = "lock_key32_best_effort";
const OP_UNLOCK_KEY32: &str = "unlock_key32_best_effort";
const OP_SECURE_DELETE: &str = "secure_delete_best_effort";
const OP_RESTRICT_DIR_PERMS: &str = "restrict_dir_perms_best_effort";
const OP_RESTRICT_FILE_PERMS: &str = "restrict_file_perms_best_effort";
const OP_FSYNC_DIR: &str = "fsync_dir_best_effort";

// -------- process hardening --------

pub fn harden_process_best_effort() -> Vec<BestEffortFailure> {
    let injected = debug_faults::maybe_inject_soft_fail_vec(OP_HARDEN_PROCESS);
    if !injected.is_empty() {
        return injected;
    }

    imp::harden_process_best_effort()
}

// -------- memory locking (best-effort) --------

pub fn lock_key32_best_effort(key: &mut [u8; 32]) -> Option<BestEffortFailure> {
    if let Some(f) = debug_faults::maybe_inject_soft_fail(OP_LOCK_KEY32) {
        return Some(f);
    }

    imp::lock_bytes_best_effort(&mut key[..])
}

pub fn unlock_key32_best_effort(key: &mut [u8; 32]) -> Option<BestEffortFailure> {
    if let Some(f) = debug_faults::maybe_inject_soft_fail(OP_UNLOCK_KEY32) {
        return Some(f);
    }

    imp::unlock_bytes_best_effort(&mut key[..])
}

// -------- secure delete --------

pub fn secure_delete_best_effort(path: &Path) -> (Result<(), String>, Vec<BestEffortFailure>) {
    if let Some(err) = debug_faults::maybe_inject_hard_fail(OP_SECURE_DELETE) {
        return (Err(err), Vec::new());
    }

    let mut warns = debug_faults::maybe_inject_soft_fail_vec(OP_SECURE_DELETE);

    let (res, mut imp_warns) = imp::secure_delete_best_effort(path);
    warns.append(&mut imp_warns);

    (res, warns)
}

// -------- filesystem permissions (best-effort) --------

pub fn restrict_dir_perms_best_effort(path: &Path) -> Option<BestEffortFailure> {
    if let Some(f) = debug_faults::maybe_inject_soft_fail(OP_RESTRICT_DIR_PERMS) {
        return Some(f);
    }

    imp::restrict_dir_perms_best_effort(path)
}

pub fn restrict_file_perms_best_effort(path: &Path) -> Option<BestEffortFailure> {
    if let Some(f) = debug_faults::maybe_inject_soft_fail(OP_RESTRICT_FILE_PERMS) {
        return Some(f);
    }

    imp::restrict_file_perms_best_effort(path)
}

// -------- directory fsync (best-effort) --------

pub fn fsync_dir_best_effort(path: &Path) -> Option<BestEffortFailure> {
    if let Some(f) = debug_faults::maybe_inject_soft_fail(OP_FSYNC_DIR) {
        return Some(f);
    }

    imp::fsync_dir_best_effort(path)
}

// -------- prevent bad lock on file --------

pub fn is_stale_lock(pid: Option<u32>) -> bool {
    imp::is_stale_lock(pid)
}

// -------- atomic rename (replace existing) --------

pub fn rename_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        return imp::rename_replace(from, to);
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::fs::rename(from, to)
    }
}
