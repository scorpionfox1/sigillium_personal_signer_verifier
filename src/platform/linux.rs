// src/platform/linux.rs

use crate::platform::BestEffortFailure;
use libc;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub fn harden_process_best_effort() -> Vec<BestEffortFailure> {
    let mut fails: Vec<BestEffortFailure> = Vec::new();

    unsafe {
        // 1) Prevent the process from being dumpable (best-effort).
        let r = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        if r != 0 {
            let errno = *libc::__errno_location();
            fails.push(BestEffortFailure {
                kind: "linux_pr_set_dumpable_failed",
                errno: Some(errno),
                msg: "prctl(PR_SET_DUMPABLE,0) failed",
            });
        }

        // 2) Disable core dumps (best-effort).
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let r2 = libc::setrlimit(libc::RLIMIT_CORE, &lim);
        if r2 != 0 {
            let errno = *libc::__errno_location();
            fails.push(BestEffortFailure {
                kind: "linux_rlimit_core_failed",
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
            let errno = *libc::__errno_location();
            Some(BestEffortFailure {
                kind: "linux_mlock_failed",
                errno: Some(errno),
                msg: "mlock failed; buffer may be swappable on this system",
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
            let errno = *libc::__errno_location();
            Some(BestEffortFailure {
                kind: "linux_munlock_failed",
                errno: Some(errno),
                msg: "munlock failed; memory unlock did not complete cleanly",
            })
        }
    }
}

fn rename_for_wipe(original: &Path) -> Result<(PathBuf, bool), std::io::Error> {
    let parent = original.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "file has no parent directory")
    })?;

    loop {
        let mut suffix = [0u8; 16];
        let strong = fill_random_best_effort(&mut suffix);

        let name = format!(".delete-{:x}", u128::from_le_bytes(suffix));
        let target = parent.join(name);

        match std::fs::rename(original, &target) {
            Ok(()) => return Ok((target, strong)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

fn wipe_file_best_effort(path: &Path) -> Result<(), String> {
    let mut f: File = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("Failed to open file for wiping: {}", e))?;

    let len = f
        .metadata()
        .map_err(|e| format!("Failed to stat file: {}", e))?
        .len();

    fn wipe_pass(f: &mut File, len: u64, random: bool) -> Result<(), String> {
        let mut buf = [0u8; 8192];
        let mut remaining = len;

        f.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Seek failed: {}", e))?;

        while remaining > 0 {
            let chunk = std::cmp::min(remaining, buf.len() as u64) as usize;

            if random {
                fill_random_best_effort(&mut buf[..chunk]);
            } else {
                buf[..chunk].fill(0);
            }

            f.write_all(&buf[..chunk])
                .map_err(|e| format!("Overwrite failed: {}", e))?;

            remaining -= chunk as u64;
        }

        f.flush().map_err(|e| format!("Flush failed: {}", e))?;
        f.sync_all()
            .map_err(|e| format!("sync_all failed: {}", e))?;
        Ok(())
    }

    wipe_pass(&mut f, len, true)?;
    wipe_pass(&mut f, len, false)?;

    Ok(())
}

fn fill_random_best_effort(out: &mut [u8]) -> bool {
    // Returns true only if getrandom fully succeeded. If it fails/short-fills, we
    // still fill the remainder with a weak fallback so callers never use partially-zero
    // buffers unknowingly.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);

    unsafe {
        let mut filled = 0usize;
        while filled < out.len() {
            let p = out[filled..].as_mut_ptr() as *mut libc::c_void;
            let n = out.len() - filled;
            let r = libc::getrandom(p, n, 0);
            if r <= 0 {
                break;
            }
            filled += r as usize;
        }

        if filled == out.len() {
            return true;
        }

        // Weak fallback: pid + monotonic time + counter, repeated.
        let pid = libc::getpid() as u64;
        let mut ts: libc::timespec = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let _ = libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts as *mut _);

        let ctr = COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed = [
            pid.to_le_bytes(),
            (ts.tv_sec as u64).to_le_bytes(),
            (ts.tv_nsec as u64).to_le_bytes(),
            ctr.to_le_bytes(),
        ]
        .concat();

        for (i, b) in out[filled..].iter_mut().enumerate() {
            *b = seed[i % seed.len()];
        }

        false
    }
}

pub fn secure_delete_best_effort(path: &Path) -> (Result<(), String>, Vec<BestEffortFailure>) {
    let mut warns: Vec<BestEffortFailure> = Vec::new();

    if !path.exists() {
        return (Ok(()), warns);
    }

    let mut to_delete = path.to_path_buf();

    // rename best-effort; if it fails we still try to wipe/delete original
    match rename_for_wipe(path) {
        Ok((renamed, strong)) => {
            to_delete = renamed;
            if !strong {
                warns.push(BestEffortFailure {
                    kind: "linux_getrandom_failed",
                    errno: None,
                    msg: "getrandom failed; rename-for-wipe used weak fallback entropy",
                });
            }
            if wipe_file_best_effort(&to_delete).is_err() {
                warns.push(BestEffortFailure {
                    kind: "linux_secure_delete_wipe_failed",
                    errno: None,
                    msg: "secure delete wipe pass failed; proceeding with delete",
                });
            }
        }
        Err(e) => {
            warns.push(BestEffortFailure {
                kind: "linux_secure_delete_rename_failed",
                errno: e.raw_os_error(),
                msg: "secure delete rename-for-wipe failed; proceeding with delete",
            });
        }
    }

    // delete primary
    if let Err(e) = std::fs::remove_file(&to_delete) {
        warns.push(BestEffortFailure {
            kind: "linux_secure_delete_remove_failed",
            errno: e.raw_os_error(),
            msg: "secure delete remove_file failed; attempting fallback delete",
        });
    } else {
        // fsync parent dir (best-effort)
        if let Some(parent) = to_delete.parent() {
            match OpenOptions::new().read(true).open(parent) {
                Ok(dir) => {
                    if let Err(e) = dir.sync_all() {
                        warns.push(BestEffortFailure {
                            kind: "linux_secure_delete_dir_fsync_failed",
                            errno: e.raw_os_error(),
                            msg:
                                "secure delete parent dir fsync failed; delete may be less durable",
                        });
                    }
                }
                Err(e) => {
                    warns.push(BestEffortFailure {
                        kind: "linux_secure_delete_dir_open_failed",
                        errno: e.raw_os_error(),
                        msg: "secure delete could not open parent dir for fsync; delete may be less durable",
                    });
                }
            }
        }

        return (Ok(()), warns);
    }

    // fallback: try original path too
    if let Err(e) = std::fs::remove_file(path) {
        warns.push(BestEffortFailure {
            kind: "linux_secure_delete_remove_failed",
            errno: e.raw_os_error(),
            msg: "secure delete remove_file failed; file may remain on disk",
        });
    }

    (Ok(()), warns)
}

pub fn restrict_dir_perms_best_effort(path: &Path) -> Option<BestEffortFailure> {
    fchmod_nofollow_best_effort(
        path,
        0o700,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
        true,
        "linux_chmod_dir_failed",
        "chmod 0700 failed for app data dir",
    )
}

pub fn restrict_file_perms_best_effort(path: &Path) -> Option<BestEffortFailure> {
    fchmod_nofollow_best_effort(
        path,
        0o600,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        false,
        "linux_chmod_file_failed",
        "chmod 0600 failed for keyfile",
    )
}

fn fchmod_nofollow_best_effort(
    path: &Path,
    mode: u32,
    open_flags: i32,
    expect_dir: bool,
    kind: &'static str,
    msg: &'static str,
) -> Option<BestEffortFailure> {
    let c = match CString::new(path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            return Some(BestEffortFailure {
                kind: "linux_path_contains_nul",
                errno: None,
                msg: "path contains NUL byte; chmod not attempted",
            })
        }
    };

    unsafe {
        let fd = libc::open(c.as_ptr(), open_flags, 0);
        if fd < 0 {
            let errno = *libc::__errno_location();
            return Some(BestEffortFailure {
                kind,
                errno: Some(errno),
                msg,
            });
        }

        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st as *mut _) != 0 {
            let errno = *libc::__errno_location();
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
                kind: "linux_perm_target_not_dir",
                errno: None,
                msg: "permission target was not a directory; refusing to chmod",
            });
        }
        if !expect_dir && !is_reg {
            let _ = libc::close(fd);
            return Some(BestEffortFailure {
                kind: "linux_perm_target_not_file",
                errno: None,
                msg: "permission target was not a regular file; refusing to chmod",
            });
        }

        let r = libc::fchmod(fd, mode);
        let _ = libc::close(fd);

        if r == 0 {
            None
        } else {
            let errno = *libc::__errno_location();
            Some(BestEffortFailure {
                kind,
                errno: Some(errno),
                msg,
            })
        }
    }
}

pub fn is_stale_lock(pid: Option<u32>) -> bool {
    let Some(pid) = pid else { return false };
    if pid == 0 {
        return false;
    }

    let r = unsafe { libc::kill(pid as i32, 0) };
    if r == 0 {
        return false; // alive => NOT stale
    }

    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => true,  // no such process => stale
        Some(libc::EPERM) => false, // alive but no permission => NOT stale
        _ => false,                 // be conservative: assume alive => NOT stale
    }
}

pub fn fsync_dir_best_effort(dir: &std::path::Path) -> Option<BestEffortFailure> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(dir)
    {
        Ok(f) => f,
        Err(e) => {
            return Some(BestEffortFailure {
                kind: "fsync_dir",
                errno: e.raw_os_error(),
                msg: "Failed to open directory for fsync",
            })
        }
    };

    if let Err(e) = file.sync_all() {
        return Some(BestEffortFailure {
            kind: "fsync_dir",
            errno: e.raw_os_error(),
            msg: "Directory fsync failed",
        });
    }

    None
}
