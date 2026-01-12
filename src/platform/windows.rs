// src/platform/windows.rs

use crate::platform::BestEffortFailure;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

pub fn harden_process_best_effort() -> Vec<BestEffortFailure> {
    // Linux hardens against core dumps (PR_SET_DUMPABLE=0, RLIMIT_CORE=0).
    //
    // Windows doesn't have a single direct equivalent we can rely on here without
    // additional Win32 APIs/features/crates. Keep as a no-op that succeeds.
    Vec::new()
}

pub fn lock_key32_best_effort(key: &mut [u8; 32]) -> Option<BestEffortFailure> {
    lock_bytes_best_effort(&mut key[..])
}

pub fn unlock_key32_best_effort(key: &mut [u8; 32]) -> Option<BestEffortFailure> {
    unlock_bytes_best_effort(&mut key[..])
}

pub fn lock_bytes_best_effort(buf: &mut [u8]) -> Option<BestEffortFailure> {
    if buf.is_empty() {
        return None;
    }

    unsafe {
        let ok = VirtualLock(buf.as_ptr() as *const core::ffi::c_void, buf.len());
        if ok != 0 {
            None
        } else {
            let errno = GetLastError() as i32;
            Some(BestEffortFailure {
                kind: "win_virtual_lock_failed",
                errno: Some(errno),
                msg: "VirtualLock failed",
            })
        }
    }
}

pub fn unlock_bytes_best_effort(buf: &mut [u8]) -> Option<BestEffortFailure> {
    if buf.is_empty() {
        return None;
    }

    unsafe {
        let ok = VirtualUnlock(buf.as_ptr() as *const core::ffi::c_void, buf.len());
        if ok != 0 {
            None
        } else {
            let errno = GetLastError() as i32;
            Some(BestEffortFailure {
                kind: "win_virtual_unlock_failed",
                errno: Some(errno),
                msg: "VirtualUnlock failed",
            })
        }
    }
}

// -------- secure delete (best-effort) --------

pub fn secure_delete_best_effort(path: &Path) -> (Result<(), String>, Vec<BestEffortFailure>) {
    let mut warns: Vec<BestEffortFailure> = Vec::new();

    if !path.exists() {
        return (Ok(()), warns);
    }

    // Overwrite: random, then zeros.
    if overwrite_file(path, true).is_err() {
        warns.push(BestEffortFailure {
            kind: "secure_delete_overwrite_random_failed",
            errno: None,
            msg: "Best-effort overwrite (random) failed",
        });
    }
    if overwrite_file(path, false).is_err() {
        warns.push(BestEffortFailure {
            kind: "secure_delete_overwrite_zeros_failed",
            errno: None,
            msg: "Best-effort overwrite (zeros) failed",
        });
    }

    // Rename to a temporary name before deleting (best-effort).
    let final_path = loop {
        let tmp = temp_rename_target(path);
        match fs::rename(path, &tmp) {
            Ok(_) => break tmp,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                warns.push(BestEffortFailure {
                    kind: "secure_delete_rename_failed",
                    errno: None,
                    msg: "Best-effort rename-before-delete failed",
                });
                break path.to_path_buf();
            }
        }
    };

    // Remove.
    match fs::remove_file(&final_path) {
        Ok(_) => (Ok(()), warns),
        Err(e) => (Err(format!("Remove file failed: {e}")), warns),
    }
}

fn overwrite_file(path: &Path, random: bool) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("Open failed: {e}"))?;

    let len = f
        .metadata()
        .map_err(|e| format!("Metadata failed: {e}"))?
        .len();

    f.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Seek failed: {e}"))?;

    let mut remaining = len;
    let mut buf = vec![0u8; 64 * 1024];

    while remaining > 0 {
        let chunk = std::cmp::min(remaining, buf.len() as u64) as usize;

        if random {
            fill_random_best_effort(&mut buf[..chunk]);
        } else {
            buf[..chunk].fill(0);
        }

        f.write_all(&buf[..chunk])
            .map_err(|e| format!("Write failed: {e}"))?;
        remaining -= chunk as u64;
    }

    // Best effort flush.
    let _ = f.flush();
    let _ = f.sync_all();
    Ok(())
}

fn fill_random_best_effort(buf: &mut [u8]) {
    let _ = getrandom::fill(buf);
}

fn temp_rename_target(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    let mut rnd = [0u8; 16];
    fill_random_best_effort(&mut rnd);
    let tag = hex::encode(rnd);

    parent.join(format!(".delete-{}.tmp", tag))
}

// -------- filesystem permissions (best-effort) --------
//
// We use `icacls` as a best-effort ACL hardening mechanism without introducing
// additional Windows security bindings.

pub fn restrict_dir_perms_best_effort(path: &Path) -> Option<BestEffortFailure> {
    icacls_lockdown_best_effort(
        path,
        "windows_icacls_dir_lockdown_failed",
        "icacls dir lockdown best-effort failed",
    )
}

pub fn restrict_file_perms_best_effort(path: &Path) -> Option<BestEffortFailure> {
    icacls_lockdown_best_effort(
        path,
        "windows_icacls_file_lockdown_failed",
        "icacls file lockdown best-effort failed",
    )
}

fn icacls_lockdown_best_effort(
    path: &Path,
    kind: &'static str,
    msg: &'static str,
) -> Option<BestEffortFailure> {
    let p = path.to_string_lossy().to_string();

    let user = match std::env::var("USERNAME") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            return Some(BestEffortFailure {
                kind: "windows_username_env_missing",
                errno: None,
                msg: "USERNAME env var missing; cannot icacls lockdown best-effort",
            });
        }
    };

    // Remove inheritance.
    let status1 = Command::new("icacls").args([&p, "/inheritance:r"]).status();

    if status1.as_ref().map(|s| s.success()).unwrap_or(false) == false {
        return Some(BestEffortFailure {
            kind,
            errno: None,
            msg,
        });
    }

    // Grant only current user full control (replace existing grants for that user).
    let grant = format!("{}:(F)", user);
    let status2 = Command::new("icacls")
        .args([&p, "/grant:r", &grant])
        .status();

    if status2.as_ref().map(|s| s.success()).unwrap_or(false) {
        None
    } else {
        Some(BestEffortFailure {
            kind,
            errno: None,
            msg,
        })
    }
}

pub fn is_stale_lock(pid: Option<u32>) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const STILL_ACTIVE: u32 = 259;

    let Some(pid) = pid else { return false };
    if pid == 0 {
        return false;
    }

    unsafe {
        // Try to open with minimal rights needed to query status.
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);

        if h == 0 {
            // Could be "no such process" or "access denied".
            // Be conservative: treat as NOT stale (same spirit as EPERM on unix).
            // If you want to be slightly more aggressive later, you can special-case
            // ERROR_INVALID_PARAMETER (87) here, but keep conservative for now.
            let _err = GetLastError();
            return false;
        }

        let mut exit_code: u32 = 0;
        let ok = GetExitCodeProcess(h, &mut exit_code as *mut u32);
        CloseHandle(h);

        if ok == 0 {
            // Couldn't query; conservative.
            return false;
        }

        // STILL_ACTIVE => alive => NOT stale
        // anything else => exited => stale
        exit_code != STILL_ACTIVE
    }
}

pub fn fsync_dir_best_effort(_dir: &std::path::Path) -> Option<BestEffortFailure> {
    None
}

pub fn rename_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let from_w = wide(from);
    let to_w = wide(to);

    unsafe {
        let ok = MoveFileExW(
            from_w.as_ptr(),
            to_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        );

        if ok == 0 {
            let errno = GetLastError() as i32;
            return Err(std::io::Error::from_raw_os_error(errno));
        }
    }

    Ok(())
}
