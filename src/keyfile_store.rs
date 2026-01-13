use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::platform::secure_delete_best_effort;

#[derive(Debug, Clone)]
pub struct KeyfileListing {
    pub name: String,
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyfileMeta {
    pub name: String,
    pub label: Option<String>,
    pub created_at: i64,
    pub last_used: Option<i64>,
}

const META_FILE: &str = "meta.json";
const TOMBSTONE_FILE: &str = "TOMBSTONE";

pub fn list_keyfiles(keyfiles_root: &Path) -> Vec<KeyfileListing> {
    let mut out = Vec::new();

    let Ok(entries) = fs::read_dir(keyfiles_root) else {
        return out;
    };

    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }

        let keyfile_path = dir.join("sigillium.keyfile.json");
        if !keyfile_path.is_file() {
            continue;
        }

        let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        out.push(KeyfileListing {
            name: name.to_string(),
            dir,
        });
    }

    out
}

pub fn validate_keyfile_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("empty");
    }

    if name == "." || name == ".." {
        return Err("reserved");
    }

    if name.bytes().any(|b| b == b'/' || b == b'\\' || b == 0) {
        return Err("invalid_char");
    }

    Ok(())
}

pub fn keyfile_name_exists(keyfiles_root: &Path, name: &str) -> bool {
    keyfiles_root.join(name).is_dir()
}

pub fn read_keyfile_meta(dir: &Path) -> Option<KeyfileMeta> {
    let path = dir.join(META_FILE);
    let data = std::fs::read(path).ok()?;
    serde_json::from_slice(&data).ok()
}

pub fn write_keyfile_meta(dir: &Path, meta: &KeyfileMeta) -> std::io::Result<()> {
    let path = dir.join(META_FILE);
    let data = serde_json::to_vec_pretty(meta)?;
    std::fs::write(path, data)
}

pub fn create_keyfile_dir(
    keyfiles_root: &Path,
    name: &str,
    meta: &KeyfileMeta,
) -> std::io::Result<PathBuf> {
    validate_keyfile_name(name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid name"))?;

    let dir = keyfiles_root.join(name);

    std::fs::create_dir(&dir)?;

    write_keyfile_meta(&dir, meta)?;

    Ok(dir)
}

fn write_tombstone(dir: &Path) {
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

pub fn destroy_keyfile_dir(dir: &Path) {
    write_tombstone(dir);
    destroy_dir_contents_best_effort(dir);
    let _ = std::fs::remove_file(dir.join(TOMBSTONE_FILE));
    let _ = std::fs::remove_dir(dir);
}

pub fn resume_tombstones(keyfiles_root: &Path) {
    let Ok(entries) = std::fs::read_dir(keyfiles_root) else {
        return;
    };

    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }

        if dir.join(TOMBSTONE_FILE).exists() {
            destroy_keyfile_dir(&dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn list_keyfiles_ignores_dirs_missing_keyfile_json() {
        let td = tempfile::tempdir().expect("tempdir");
        let root = td.path().join("keyfiles");
        fs::create_dir_all(&root).expect("mkdir keyfiles root");

        // selectable
        let a = root.join("a");
        fs::create_dir_all(&a).expect("mkdir a");
        fs::write(a.join("sigillium.keyfile.json"), b"{}").expect("write keyfile");

        // non-selectable (missing keyfile.json)
        let b = root.join("b");
        fs::create_dir_all(&b).expect("mkdir b");

        let items = list_keyfiles(&root);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "a");
        assert_eq!(items[0].dir, a);
    }

    #[test]
    fn destroy_keyfile_dir_removes_dir() {
        let td = tempfile::tempdir().expect("tempdir");
        let dir = td.path().join("k1");
        fs::create_dir_all(&dir).expect("mkdir");

        fs::write(dir.join("sigillium.keyfile.json"), b"{}").expect("write keyfile");
        fs::write(dir.join("meta.json"), b"{}").expect("write meta");

        let nested = dir.join("nested");
        fs::create_dir_all(&nested).expect("mkdir nested");
        fs::write(nested.join("x.txt"), b"hi").expect("write nested file");

        destroy_keyfile_dir(&dir);

        assert!(!dir.exists());
    }

    #[test]
    fn resume_tombstones_removes_only_tombstoned_dirs() {
        let td = tempfile::tempdir().expect("tempdir");
        let root = td.path().join("keyfiles");
        fs::create_dir_all(&root).expect("mkdir keyfiles root");

        let dead = root.join("dead");
        fs::create_dir_all(&dead).expect("mkdir dead");
        fs::write(dead.join("sigillium.keyfile.json"), b"{}").expect("write keyfile");
        fs::write(dead.join(TOMBSTONE_FILE), b"").expect("write tombstone");

        let alive = root.join("alive");
        fs::create_dir_all(&alive).expect("mkdir alive");
        fs::write(alive.join("sigillium.keyfile.json"), b"{}").expect("write keyfile");

        resume_tombstones(&root);

        assert!(!dead.exists());
        assert!(alive.exists());
    }
}
