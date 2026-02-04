// src/keyfile_store.rs

use std::path::{Path, PathBuf};

use crate::{error::AppResult, keyfile::KEYFILE_FILENAME, platform::secure_delete_best_effort};

#[derive(Debug, Clone)]
pub struct KeyfileListing {
    pub name: String,
    pub dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyfileDirRow {
    pub name: String,
    pub has_keyfile: bool,
}

const TOMBSTONE_FILE: &str = "TOMBSTONE";

// ------------------------------------------------------
// Store wrapper (preferred entry point)
// ------------------------------------------------------

#[derive(Debug, Clone)]
pub struct KeyfileStore {
    root: PathBuf,
}

impl KeyfileStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn list_keyfiles(&self) -> std::io::Result<Vec<String>> {
        list_keyfiles(&self.root)
    }

    pub fn list_keyfile_dirs(&self) -> std::io::Result<Vec<KeyfileDirRow>> {
        list_keyfile_dirs(&self.root)
    }

    pub fn keyfile_name_exists(&self, name: &str) -> bool {
        keyfile_name_exists(&self.root, name)
    }

    pub fn create_keyfile_dir(&self, name: &str) -> AppResult<PathBuf> {
        create_keyfile_dir(&self.root, name)
    }

    pub fn destroy_keyfile_dir_by_name_best_effort(&self, name: &str) {
        // best-effort by design
        if validate_keyfile_dir_name(name).is_err() {
            return;
        }
        let dir = self.root.join(name);
        destroy_keyfile_dir_best_effort(&dir);
    }
}

// ------------------------------------------------------
// Listing / validation / resolution
// ------------------------------------------------------

pub fn list_keyfiles(keyfiles_root: &Path) -> std::io::Result<Vec<String>> {
    let mut out = Vec::new();

    for dir in read_keyfile_dirs(keyfiles_root)? {
        // Tombstoned dirs are garbage-collected opportunistically.
        if dir.join(TOMBSTONE_FILE).exists() {
            destroy_keyfile_dir_best_effort(&dir);
            continue;
        }

        if dir.join(KEYFILE_FILENAME).is_file() {
            if let Some(name) = dir_name(&dir) {
                out.push(name.to_string());
            }
        }
    }

    out.sort();
    Ok(out)
}

pub fn list_keyfile_dirs(keyfiles_root: &Path) -> std::io::Result<Vec<KeyfileDirRow>> {
    let mut out = Vec::new();

    for dir in read_keyfile_dirs(keyfiles_root)? {
        let Some(name) = dir_name(&dir) else {
            continue;
        };

        if validate_keyfile_dir_name(name).is_err() {
            continue;
        }

        let has_keyfile = dir.join(KEYFILE_FILENAME).is_file();
        out.push(KeyfileDirRow {
            name: name.to_string(),
            has_keyfile,
        });
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn read_keyfile_dirs(keyfiles_root: &Path) -> std::io::Result<Vec<PathBuf>> {
    if !keyfiles_root.exists() {
        return Ok(Vec::new());
    }

    let dirs = std::fs::read_dir(keyfiles_root)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|dir| dir.is_dir())
        .collect::<Vec<_>>();
    Ok(dirs)
}

fn dir_name(dir: &Path) -> Option<&str> {
    dir.file_name().and_then(|s| s.to_str())
}

fn validate_keyfile_dir_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("empty");
    }

    if name == "." || name == ".." {
        return Err("reserved");
    }

    // Disallow path separators and NUL.
    if name.bytes().any(|b| b == b'/' || b == b'\\' || b == 0) {
        return Err("invalid_char");
    }

    // Reject ASCII control chars (0x00-0x1F) and DEL (0x7F).
    if name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("invalid_char");
    }

    // Reject Windows-forbidden filename characters.
    if name
        .chars()
        .any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    {
        return Err("invalid_char");
    }

    // Windows disallows trailing dots/spaces in path components.
    if name.ends_with('.') || name.ends_with(' ') {
        return Err("invalid_char");
    }

    // Reject Windows reserved device names (case-insensitive), including with an extension.
    let base = name.split('.').next().unwrap_or(name);
    let upper = base.to_ascii_uppercase();
    let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.starts_with("COM")
            && upper.len() == 4
            && matches!(upper.as_bytes()[3], b'1'..=b'9'))
        || (upper.starts_with("LPT")
            && upper.len() == 4
            && matches!(upper.as_bytes()[3], b'1'..=b'9'));
    if reserved {
        return Err("reserved");
    }

    Ok(())
}

pub fn keyfile_name_exists(keyfiles_root: &Path, name: &str) -> bool {
    keyfiles_root.join(name).join(KEYFILE_FILENAME).is_file()
}

// ------------------------------------------------------
// Directory ops (create / delete + tombstone)
// ------------------------------------------------------

pub fn create_keyfile_dir(root: &Path, name: &str) -> AppResult<PathBuf> {
    let dir = root.join(name);

    // Directory existence is allowed.
    // Keyfile existence is enforced at the file level.
    std::fs::create_dir_all(&dir)?;

    Ok(dir)
}

fn write_tombstone_best_effort(dir: &Path) {
    let _ = std::fs::write(dir.join(TOMBSTONE_FILE), b"");
}

fn destroy_dir_contents_best_effort(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.file_name().and_then(|n| n.to_str()) == Some(TOMBSTONE_FILE) {
            continue;
        }

        if path.is_file() {
            let _ = secure_delete_best_effort(&path);
            let _ = std::fs::remove_file(&path);
        } else if path.is_dir() {
            destroy_dir_contents_best_effort(&path);
            let _ = std::fs::remove_dir(&path);
        }
    }
}

pub fn destroy_keyfile_dir_best_effort(dir: &Path) {
    // best-effort: never propagate errors
    write_tombstone_best_effort(dir);
    destroy_dir_contents_best_effort(dir);
    let _ = std::fs::remove_file(dir.join(TOMBSTONE_FILE));
    let _ = std::fs::remove_dir(dir);
}

// ------------------------------------------------------
// Unit Tests
// ------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn touch(p: &Path) {
        std::fs::write(p, b"x").unwrap();
    }

    #[test]
    fn validate_keyfile_dir_name_rejects_empty_and_reserved() {
        assert_eq!(validate_keyfile_dir_name(""), Err("empty"));
        assert_eq!(validate_keyfile_dir_name("."), Err("reserved"));
        assert_eq!(validate_keyfile_dir_name(".."), Err("reserved"));
    }

    #[test]
    fn validate_keyfile_dir_name_rejects_separators_and_nul() {
        assert_eq!(validate_keyfile_dir_name("a/b"), Err("invalid_char"));
        assert_eq!(validate_keyfile_dir_name("a\\b"), Err("invalid_char"));
        assert_eq!(validate_keyfile_dir_name("a\0b"), Err("invalid_char"));
    }

    #[test]
    fn create_keyfile_dir_creates_root_and_dir() {
        let td = tempdir().unwrap();
        let root = td.path().join("keyfiles");
        assert!(!root.exists());

        let dir = create_keyfile_dir(&root, "alpha").unwrap();
        assert!(root.is_dir());
        assert!(dir.is_dir());
        assert_eq!(dir, root.join("alpha"));

        // duplicate is allowed (create_dir_all is idempotent)
        let dir2 = create_keyfile_dir(&root, "alpha").unwrap();
        assert_eq!(dir2, dir);
        assert!(dir2.is_dir());
    }

    #[test]
    fn list_keyfiles_only_returns_dirs_with_keyfile_json_sorted() {
        let td = tempdir().unwrap();
        let root = td.path();

        // non-dir entry
        touch(&root.join("notadir"));

        // valid keyfile dirs (names intentionally out of order)
        let d1 = root.join("b");
        let d2 = root.join("a");
        std::fs::create_dir_all(&d1).unwrap();
        std::fs::create_dir_all(&d2).unwrap();
        touch(&d1.join(KEYFILE_FILENAME));
        touch(&d2.join(KEYFILE_FILENAME));

        // dir without keyfile.json
        let d3 = root.join("c");
        std::fs::create_dir_all(&d3).unwrap();

        let got = list_keyfiles(root).unwrap();
        assert_eq!(got, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn list_keyfile_dirs_includes_valid_dirs_and_marks_missing_keyfile() {
        let td = tempdir().unwrap();
        let root = td.path();

        // valid named dirs
        let a = root.join("a");
        let b = root.join("b");
        let c = root.join("c");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::create_dir_all(&c).unwrap();

        touch(&b.join(KEYFILE_FILENAME));

        let got = list_keyfile_dirs(root).unwrap();
        assert_eq!(
            got,
            vec![
                KeyfileDirRow {
                    name: "a".to_string(),
                    has_keyfile: false
                },
                KeyfileDirRow {
                    name: "b".to_string(),
                    has_keyfile: true
                },
                KeyfileDirRow {
                    name: "c".to_string(),
                    has_keyfile: false
                },
            ]
        );
    }

    #[test]
    fn list_keyfiles_skips_tombstoned_dirs_and_opportunistically_gcs_them() {
        let td = tempdir().unwrap();
        let root = td.path();

        let doomed = root.join("doomed");
        std::fs::create_dir_all(&doomed).unwrap();
        touch(&doomed.join(TOMBSTONE_FILE));
        touch(&doomed.join(KEYFILE_FILENAME)); // even if present, tombstone wins

        let got = list_keyfiles(root).unwrap();
        assert!(got.is_empty());

        // GC is best-effort; do not assert it must be removed.
        // (If you want a hard guarantee, the implementation must stop being best-effort.)
    }

    #[test]
    fn list_keyfile_dirs_reports_tombstoned_dirs_like_any_other_dir() {
        let td = tempdir().unwrap();
        let root = td.path();

        let doomed = root.join("doomed");
        std::fs::create_dir_all(&doomed).unwrap();
        touch(&doomed.join(TOMBSTONE_FILE));
        touch(&doomed.join(KEYFILE_FILENAME));

        let got = list_keyfile_dirs(root).unwrap();
        assert_eq!(
            got,
            vec![KeyfileDirRow {
                name: "doomed".to_string(),
                has_keyfile: true
            }]
        );

        // No GC behavior is implemented for list_keyfile_dirs.
        assert!(doomed.exists());
    }

    #[test]
    fn validate_keyfile_dir_name_rejects_windows_forbidden_chars_and_trailing() {
        assert_eq!(validate_keyfile_dir_name("a:b"), Err("invalid_char"));
        assert_eq!(validate_keyfile_dir_name("a*b"), Err("invalid_char"));
        assert_eq!(validate_keyfile_dir_name("a?b"), Err("invalid_char"));
        assert_eq!(validate_keyfile_dir_name("a|b"), Err("invalid_char"));
        assert_eq!(validate_keyfile_dir_name("a<b"), Err("invalid_char"));
        assert_eq!(validate_keyfile_dir_name("a>b"), Err("invalid_char"));
        assert_eq!(validate_keyfile_dir_name("a\"b"), Err("invalid_char"));
        assert_eq!(validate_keyfile_dir_name("trail."), Err("invalid_char"));
        assert_eq!(validate_keyfile_dir_name("trail "), Err("invalid_char"));
    }

    #[test]
    fn validate_keyfile_dir_name_rejects_windows_device_names() {
        for n in [
            "con", "CON", "con.txt", "prn", "aux", "nul", "com1", "COM9.log", "lpt1", "LPT9.txt",
        ] {
            assert_eq!(validate_keyfile_dir_name(n), Err("reserved"), "name: {n}");
        }
    }
}
