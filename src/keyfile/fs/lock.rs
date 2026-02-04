// src/keyfile/fs/lock.rs

use crate::error::{AppError, AppResult};
use crate::platform::is_stale_lock;

use rand::rngs::OsRng;
use rand::RngCore;

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub(crate) const LOCK_STALE_AFTER: Duration = Duration::from_secs(300); // 5 minutes

pub(crate) struct KeyfileLock {
    lock_path: PathBuf,
    token: String,
}

impl Drop for KeyfileLock {
    fn drop(&mut self) {
        // Only remove if we still "own" it.
        let _ = remove_lock_if_token_matches(&self.lock_path, &self.token);
    }
}

pub(crate) fn acquire_keyfile_lock(keyfile_path: &Path) -> AppResult<KeyfileLock> {
    let lock_path = lock_path_for(keyfile_path)?;
    let parent = lock_path
        .parent()
        .ok_or_else(|| AppError::KeyfileFsLockFailed("invalid keyfile path".to_string()))?;

    fs::create_dir_all(parent).map_err(|e| AppError::KeyfileFsLockFailed(e.to_string()))?;

    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }

    match open_new_lockfile(&opts, &lock_path) {
        Ok(lock) => Ok(lock),
        Err(OpenLockError::AlreadyExists) => {
            if lock_is_stale(&lock_path) {
                let _ = fs::remove_file(&lock_path);
                match open_new_lockfile(&opts, &lock_path) {
                    Ok(lock) => Ok(lock),
                    Err(OpenLockError::AlreadyExists) => Err(AppError::KeyfileFsBusy),
                    Err(OpenLockError::Other(e)) => {
                        Err(AppError::KeyfileFsLockFailed(e.to_string()))
                    }
                }
            } else {
                Err(AppError::KeyfileFsBusy)
            }
        }
        Err(OpenLockError::Other(e)) => Err(AppError::KeyfileFsLockFailed(e.to_string())),
    }
}

enum OpenLockError {
    AlreadyExists,
    Other(std::io::Error),
}

fn open_new_lockfile(opts: &OpenOptions, lock_path: &Path) -> Result<KeyfileLock, OpenLockError> {
    match opts.open(lock_path) {
        Ok(mut f) => {
            let token = generate_lock_token();

            // B: strict write — if this fails, acquiring the lock fails.
            write_lock_contents(&mut f, &token).map_err(OpenLockError::Other)?;

            Ok(KeyfileLock {
                lock_path: lock_path.to_path_buf(),
                token,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(OpenLockError::AlreadyExists)
        }
        Err(e) => Err(OpenLockError::Other(e)),
    }
}

fn generate_lock_token() -> String {
    // 16 bytes is plenty for collision resistance here.
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    // hex without allocating a crate
    let mut s = String::with_capacity(32);
    for x in b {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{:02x}", x);
    }
    s
}

fn write_lock_contents(f: &mut std::fs::File, token: &str) -> std::io::Result<()> {
    let pid = std::process::id();
    let ts = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    writeln!(f, "pid={pid}")?;
    writeln!(f, "ts={ts}")?;
    writeln!(f, "token={token}")?;

    // Make sure contents are pushed out (helps correctness; still best-effort across FS types).
    f.sync_all()?;
    Ok(())
}

// A: only delete if token matches what we wrote.
fn remove_lock_if_token_matches(lock_path: &Path, expected: &str) -> std::io::Result<()> {
    let mut s = String::new();
    let mut f = match std::fs::File::open(lock_path) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };

    f.read_to_string(&mut s)?;

    for line in s.lines() {
        if let Some(v) = line.strip_prefix("token=") {
            if v.trim() == expected {
                return fs::remove_file(lock_path);
            } else {
                // Not ours: refuse to remove.
                return Ok(());
            }
        }
    }

    // No token line: refuse to remove.
    Ok(())
}

fn lock_is_stale(lock_path: &Path) -> bool {
    if let Ok(mut f) = std::fs::File::open(lock_path) {
        let mut s = String::new();
        if f.read_to_string(&mut s).is_ok() {
            let mut pid: Option<u32> = None;

            for line in s.lines() {
                if let Some(v) = line.strip_prefix("pid=") {
                    pid = v.parse::<u32>().ok();
                }

                if let Some(v) = line.strip_prefix("ts=") {
                    if let Ok(ts) = v.parse::<u64>() {
                        let then = std::time::UNIX_EPOCH + Duration::from_secs(ts);
                        if let Ok(age) = SystemTime::now().duration_since(then) {
                            if age > LOCK_STALE_AFTER {
                                return true;
                            }
                        }
                    }
                }
            }

            if let Some(p) = pid {
                if is_stale_lock(Some(p)) {
                    return true;
                }
            }
        }
    }

    if let Ok(meta) = fs::metadata(lock_path) {
        if let Ok(mtime) = meta.modified() {
            if let Ok(age) = SystemTime::now().duration_since(mtime) {
                return age > LOCK_STALE_AFTER;
            }
        }
    }

    false
}

// ======================================================
// Internal Helpers
// ======================================================

fn lock_path_for(keyfile_path: &Path) -> AppResult<PathBuf> {
    let parent = keyfile_path
        .parent()
        .ok_or_else(|| AppError::KeyfileFsLockFailed("invalid keyfile path".to_string()))?;

    let fname = keyfile_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("keyfile");

    Ok(parent.join(format!(".sigillium-keyfile.{}.lock", fname)))
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn lock_path_for(keyfile_path: &Path) -> PathBuf {
        let parent = keyfile_path.parent().unwrap();
        let fname = keyfile_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("keyfile");
        parent.join(format!(".sigillium-keyfile.{}.lock", fname))
    }

    fn write_lock(lock_path: &Path, pid: u32, ts: u64, token: &str) {
        let s = format!("pid={pid}\nts={ts}\ntoken={token}\n");
        std::fs::write(lock_path, s).unwrap();
    }

    #[test]
    fn acquire_then_drop_removes_lockfile() {
        let td = tempdir().unwrap();
        let keyfile_path = td.path().join("keyfile.json");
        let lock_path = lock_path_for(&keyfile_path);

        {
            let _guard = acquire_keyfile_lock(&keyfile_path).unwrap();
            assert!(lock_path.exists());
        }

        assert!(!lock_path.exists());
    }

    #[test]
    fn second_acquire_fails_when_lock_is_fresh() {
        let td = tempdir().unwrap();
        let keyfile_path = td.path().join("keyfile.json");

        let _guard = acquire_keyfile_lock(&keyfile_path).unwrap();
        match acquire_keyfile_lock(&keyfile_path) {
            Ok(_) => panic!("expected KeyfileFsBusy"),
            Err(AppError::KeyfileFsBusy) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
        };
    }

    #[test]
    fn stale_lock_is_removed_and_reacquired() {
        let td = tempdir().unwrap();
        let keyfile_path = td.path().join("keyfile.json");
        let lock_path = lock_path_for(&keyfile_path);

        // ts=0 => extremely stale by age check
        write_lock(&lock_path, 0, 0, "stale-token");
        assert!(lock_path.exists());

        let _guard = acquire_keyfile_lock(&keyfile_path).unwrap();
        assert!(lock_path.exists());
    }

    #[test]
    fn remove_lock_only_if_token_matches() {
        let td = tempdir().unwrap();
        let keyfile_path = td.path().join("keyfile.json");
        let lock_path = lock_path_for(&keyfile_path);

        write_lock(&lock_path, 123, 0, "abc");
        assert!(lock_path.exists());

        remove_lock_if_token_matches(&lock_path, "nope").unwrap();
        assert!(lock_path.exists());

        remove_lock_if_token_matches(&lock_path, "abc").unwrap();
        assert!(!lock_path.exists());
    }

    #[test]
    fn remove_lock_refuses_when_no_token_line() {
        let td = tempdir().unwrap();
        let lock_path = td.path().join(".sigillium-keyfile.keyfile.json.lock");

        std::fs::write(&lock_path, "pid=1\nts=0\n").unwrap();
        assert!(lock_path.exists());

        remove_lock_if_token_matches(&lock_path, "anything").unwrap();
        assert!(lock_path.exists());
    }
}
