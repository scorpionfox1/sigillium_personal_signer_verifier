// src/keyfile/ops/test_support.rs

#![cfg(test)]

use rand::{rngs::OsRng, RngCore};
use std::fs;
use std::path::PathBuf;

use super::{append_key, read_master_key, write_blank_keyfile};
use crate::{error::AppResult, keyfile::KEYFILE_FILENAME};

pub struct OpsFixture {
    pub dir: PathBuf,
    pub path: PathBuf,
    pub passphrase: String,
    pub master_key: [u8; 32],
}

pub fn mk_fixture(passphrase: &str) -> AppResult<OpsFixture> {
    let mut rnd = [0u8; 16];
    OsRng.fill_bytes(&mut rnd);

    let dir = std::env::temp_dir().join(format!("sigillium_ops_test_{}", hex::encode(rnd)));
    fs::create_dir_all(&dir).unwrap();

    let path = dir.join(KEYFILE_FILENAME);

    write_blank_keyfile(&path)?;
    let master_key = read_master_key(&path, passphrase)?;

    Ok(OpsFixture {
        dir,
        path,
        passphrase: passphrase.to_string(),
        master_key,
    })
}

pub struct FixtureOneKey {
    pub fx: OpsFixture,
    pub key_id: crate::types::KeyId,
    pub public: [u8; 32],
    pub private: [u8; 32],
    pub domain: String,
    pub label: String,
}

pub fn mk_fixture_one_key(passphrase: &str, associated_key_id: &str) -> AppResult<FixtureOneKey> {
    let fx = mk_fixture(passphrase)?;

    let domain = "example.com".to_string();
    let label = "Test Key".to_string();

    let public = [4u8; 32];
    let private = [9u8; 32];

    // first key is always id=1 for a blank keyfile
    append_key(
        &fx.path,
        &fx.master_key,
        &domain,
        &label,
        &private,
        &public,
        associated_key_id,
    )?;

    Ok(FixtureOneKey {
        fx,
        key_id: 1,
        public,
        private,
        domain,
        label,
    })
}

impl Drop for OpsFixture {
    fn drop(&mut self) {
        // Allow keeping the temp dir for debugging:
        //   SIGILLIUM_KEEP_TEST_TMP=1 cargo test
        let keep = std::env::var("SIGILLIUM_KEEP_TEST_TMP")
            .ok()
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes"));

        if keep {
            return;
        }

        // Best-effort cleanup; never panic in Drop.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
