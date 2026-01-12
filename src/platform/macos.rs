// src/platform/macos.rs

use crate::platform::BestEffortFailure;
use libc;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub fn harden_process_best_effort() -> Vec<BestEffortFailure> {
    let mut fails = Vec::new();

    unsafe {
        // Disable core dumps (best-effort)
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let r = libc::setrlimit(libc::RLIMIT_CORE, &lim);
        if r != 0 {
            let errno = *libc::__error();
            fails.push(BestEffortFailure {
                kind: "macos_rlimit_core_failed",
                errno: Some(errno),
                msg: "setrlimit(RLIMIT_CORE,0) failed",
            });
        }
    }

    fails
}

pub fn lock_bytes_best_effort(buf: &mut [u8]) -> Option<BestEffortFailure> {
    unsafe {
        let r = libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len());
        if r == 0 {
            None
        } else {
            let errno = *libc::__error();
            Some(BestEffortFailure {
                kind: "macos_mlock_failed",
                errno: Some(errno),
                msg: "mlock failed",
            })
        }
    }
}

pub fn unlock_bytes_best_effort(buf: &mut [u8]) -> Option<BestEffortFailure> {
    unsafe {
        let r = libc::munlock(buf.as_ptr() as *const libc::c_void, buf.len());
        if r == 0 {
            None
        } else {
            let errno = *libc::__error();
            Some(BestEffortFailure {
                kind: "macos_munlock_failed",
                errno: Some(errno),
                msg: "munlock failed",
            })
        }
    }
}

// -------- secure delete (best-effort) --------

pub fn secure_delete_best_effort(path: &Path) -> (Result<(), String>, Vec<BestEffortFailure>) {
    let mut warns = Vec::new();

    if !path.exists() {
        return (Ok(()), warns);
    }

    // Overwrite with zeros (macOS does not guarantee physical overwrite on APFS)
    if overwrite_zeros(path).is_err() {
        warns.push(BestEffortFailure {
            kind: "macos_secure_delete_overwrite_failed",
            errno: None,
            msg: "best-effort overwrite failed",
        });
    }

    match std::fs::remove_file(path) {
        Ok(_) => (Ok(()), warns),
        Err(e) => (Err(format!("remove_file failed: {e}")), warns),
    }
}

fn overwrite_zeros(path: &Path) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("open failed: {e}"))?;

    let len = f
        .metadata()
        .map_err(|e| format!("metadata failed: {e}"))?
        .len();

    f.seek(SeekFrom::Start(0))
        .map_err(|e| format!("seek failed: {e}"))?;

    let mut remaining = len;
    let buf = [0u8; 8192];

    while remaining > 0 {
        let chunk = std::cmp::min(remaining, buf.len() as u64) as usize;
        f.write_all(&buf[..chunk])
            .map_err(|e| format!("write failed: {e}"))?;
        remaining -= chunk as u64;
    }

    let _ = f.flush();
    let _ = f.sync_all();
    Ok(())
}

// -------- filesystem permissions (best-effort) --------

pub fn restrict_dir_perms_best_effort(path: &Path) -> Option<BestEffortFailure> {
    chmod_nofollow_best_effort(
        path,
        0o700,
        true,
        "macos_chmod_dir_failed",
        "chmod 0700 failed for directory",
    )
}

pub fn restrict_file_perms_best_effort(path: &Path) -> Option<BestEffortFailure> {
    chmod_nofollow_best_effort(
        path,
        0o600,
        false,
        "macos_chmod_file_failed",
        "chmod 0600 failed for file",
    )
}

fn chmod_nofollow_best_effort(
    path: &Path,
    mode: u32,
    expect_dir: bool,
    kind: &'static str,
    msg: &'static str,
) -> Option<BestEffortFailure> {
    let c = match CString::new(path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            return Some(BestEffortFailure {
                kind: "macos_path_contains_nul",
                errno: None,
                msg: "path contains NUL byte",
            })
        }
    };

    unsafe {
        let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW);
        if fd < 0 {
            let errno = *libc::__error();
            return Some(BestEffortFailure {
                kind,
                errno: Some(errno),
                msg,
            });
        }

        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st as *mut _) != 0 {
            let errno = *libc::__error();
            let _ = libc::close(fd);
            return Some(BestEffortFailure {
                kind,
                errno: Some(errno),
                msg,
            });
        }

        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let is_reg = (st.st_mode & libc::S_IFMT) == libc::S_IFREG;

        if expect_dir && !is_dir {
            let _ = libc::close(fd);
            return Some(BestEffortFailure {
                kind: "macos_perm_target_not_dir",
                errno: None,
                msg: "target not directory",
            });
        }

        if !expect_dir && !is_reg {
            let _ = libc::close(fd);
            return Some(BestEffortFailure {
                kind: "macos_perm_target_not_file",
                errno: None,
                msg: "target not regular file",
            });
        }

        let mode: libc::mode_t = mode.try_into().unwrap();
        let r = libc::fchmod(fd, mode);
        let _ = libc::close(fd);

        if r == 0 {
            None
        } else {
            let errno = *libc::__error();
            Some(BestEffortFailure {
                kind,
                errno: Some(errno),
                msg,
            })
        }
    }
}

pub fn fsync_dir_best_effort(dir: &Path) -> Option<BestEffortFailure> {
    use std::os::unix::fs::OpenOptionsExt;

    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(dir)
    {
        Ok(f) => f,
        Err(e) => {
            return Some(BestEffortFailure {
                kind: "macos_fsync_dir_open_failed",
                errno: e.raw_os_error(),
                msg: "failed to open directory for fsync",
            })
        }
    };

    if let Err(e) = f.sync_all() {
        return Some(BestEffortFailure {
            kind: "macos_fsync_dir_failed",
            errno: e.raw_os_error(),
            msg: "directory fsync failed",
        });
    }

    None
}

pub fn is_stale_lock(pid: Option<u32>) -> bool {
    let Some(pid) = pid else { return false };
    if pid == 0 {
        return false;
    }

    let r = unsafe { libc::kill(pid as i32, 0) };
    if r == 0 {
        return false;
    }

    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => true,
        Some(libc::EPERM) => false,
        _ => false,
    }
}
