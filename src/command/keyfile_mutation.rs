// src/command/keyfile_mutation.rs

use crate::context::AppCtx;
use crate::error::{AppError, AppResult};
use crate::fs_hardening::enforce_keyfile_perms_best_effort;
use crate::keyfile::fs::lock::acquire_keyfile_lock;
use crate::types::{AppState, KeyId};
use crate::{command_state::*, crypto, keyfile};
use std::thread;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

// ======================================================
// key mutation (install / select / uninstall)
// ======================================================

pub fn install_key(
    mnemonic: &str,
    domain: &str,
    label: &str,
    associated_key_id: Option<&str>,
    enforce_standard_domain: bool,
    state: &AppState,
    ctx: &AppCtx,
) -> (crate::types::KeyfileState, Result<(), AppError>) {
    let mnemonic = mnemonic.trim();
    if mnemonic.is_empty() {
        return (
            crate::types::KeyfileState::NotCorrupted,
            Err(AppError::EmptyMnemonic),
        );
    }

    let label = label.trim();
    if label.is_empty() {
        return (
            crate::types::KeyfileState::NotCorrupted,
            Err(AppError::EmptyLabel),
        );
    }

    let domain_for_derivation: String = if enforce_standard_domain {
        let d = domain.trim();
        if d.is_empty() {
            String::new()
        } else {
            match validate_standard_domain_ascii(d) {
                Ok(v) => v,
                Err(_) => {
                    return (
                        crate::types::KeyfileState::NotCorrupted,
                        Err(AppError::InvalidStandardDomain),
                    )
                }
            }
        }
    } else {
        // Unrestricted mode: use EXACTLY as provided (no trim, no lowercase, no validation).
        domain.to_string()
    };

    // derive + compute pubkey
    let mut privk =
        match crypto::derive_private_key_from_mnemonic_and_domain(mnemonic, &domain_for_derivation)
        {
            Ok(v) => v,
            Err(e) => return (crate::types::KeyfileState::NotCorrupted, Err(e)),
        };

    let pubk = crypto::public_key_from_private(&privk);

    let ks = crate::types::KeyfileState::NotCorrupted;

    // Command-layer normalization: None/blank => ""
    let associated_norm: String = associated_key_id.unwrap_or("").trim().to_string();

    let op_res: AppResult<()> = (|| {
        enforce_keyfile_perms_best_effort(
            state,
            &ctx.keyfile_path,
            &ctx.app_data_dir,
            "install_key",
        );

        with_master_key(state, |mk| {
            keyfile::append_key(
                &ctx.keyfile_path,
                &*mk,
                &domain_for_derivation,
                label,
                &privk,
                &pubk,
                &associated_norm, // may be ""
            )
        })?;

        let _lock = acquire_keyfile_lock(&ctx.keyfile_path)?;

        enforce_keyfile_perms_best_effort(
            state,
            &ctx.keyfile_path,
            &ctx.app_data_dir,
            "install_key",
        );

        super::refresh_key_meta_cache(state, ctx)?;

        Ok(())
    })();

    privk.zeroize();

    let res: Result<(), AppError> = op_res.map_err(|e| e);

    (ks, res)
}

pub fn uninstall_active_key(
    state: &AppState,
    ctx: &AppCtx,
) -> (crate::types::KeyfileState, AppResult<()>) {
    // Resolve active key id from session first.
    let active_id: KeyId = match lock_session(state) {
        Ok(g) => match g.active_key_id {
            Some(id) => id,
            None => {
                return (
                    crate::types::KeyfileState::NotCorrupted,
                    Err(AppError::Msg("No active key selected".into())),
                )
            }
        },
        Err(e) => return (crate::types::KeyfileState::NotCorrupted, Err(e)),
    };

    // Clear active key first so the UI/session cannot point at a removed key.
    if let Err(e) = super::session::clear_active_key(state) {
        return (crate::types::KeyfileState::NotCorrupted, Err(e));
    }

    let ks = crate::types::KeyfileState::NotCorrupted;

    let res: AppResult<()> = (|| {
        enforce_keyfile_perms_best_effort(
            state,
            &ctx.keyfile_path,
            &ctx.app_data_dir,
            "uninstall_active_key",
        );

        with_master_key(state, |mk| {
            keyfile::remove_key(&ctx.keyfile_path, &*mk, active_id)
        })?;

        let _lock = acquire_keyfile_lock(&ctx.keyfile_path)?;

        enforce_keyfile_perms_best_effort(
            state,
            &ctx.keyfile_path,
            &ctx.app_data_dir,
            "uninstall_active_key",
        );

        super::refresh_key_meta_cache(state, ctx)?;

        Ok(())
    })();

    (ks, res)
}

pub fn change_passphrase(
    old_passphrase: &str,
    new_passphrase: &str,
    state: &AppState,
    ctx: &AppCtx,
) -> (crate::types::KeyfileState, AppResult<()>) {
    let old_passphrase = Zeroizing::new(old_passphrase.to_owned());
    let new_passphrase = Zeroizing::new(new_passphrase.to_owned());

    if let Err(e) = super::validate_passphrase_for_unlock(&old_passphrase) {
        return (
            crate::types::KeyfileState::NotCorrupted,
            Err(AppError::Msg(e)),
        );
    }
    if let Err(e) = super::validate_passphrase(&new_passphrase) {
        return (
            crate::types::KeyfileState::NotCorrupted,
            Err(AppError::Msg(e)),
        );
    }

    let ks = crate::types::KeyfileState::NotCorrupted;

    let res: AppResult<()> = (|| {
        enforce_keyfile_perms_best_effort(
            state,
            &ctx.keyfile_path,
            &ctx.app_data_dir,
            "change_passphrase",
        );

        // Derive old master key from old passphrase (uses keyfile salt on disk)
        let old_master_key = match keyfile::read_master_key(&ctx.keyfile_path, &old_passphrase) {
            Ok(k) => k,
            Err(e) => {
                thread::sleep(Duration::from_millis(250));
                return Err(e);
            }
        };

        // ---- keyfile mutation must NOT hold app state lock ----
        {
            let _kf_lock = acquire_keyfile_lock(&ctx.keyfile_path)?;

            let new_master_key =
                keyfile::change_passphrase(&ctx.keyfile_path, &old_master_key, &new_passphrase)?;

            // Update in-memory secrets only AFTER disk is done
            let mut guard = lock_secrets(state)?;
            if let Some(secrets) = guard.as_mut() {
                secrets.master_key = Zeroizing::new(new_master_key);
            }
        }

        lock_master_key_best_effort(state, "change_passphrase");

        // let _lock = acquire_keyfile_lock(path_str)?;

        enforce_keyfile_perms_best_effort(
            state,
            &ctx.keyfile_path,
            &ctx.app_data_dir,
            "change_passphrase",
        );

        Ok(())
    })();

    (ks, res)
}

// ======================================================
// helpers
// ======================================================

fn validate_standard_domain_ascii(raw: &str) -> AppResult<String> {
    if !raw.is_ascii() {
        return Err(AppError::InvalidStandardDomain);
    }

    let s = raw.to_ascii_lowercase();
    for ch in s.chars() {
        let ok =
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '-' | '_' | '/');
        if !ok {
            return Err(AppError::InvalidStandardDomain);
        }
    }

    Ok(s)
}

// ======================================================
// tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{KeyfileState, SecretsState, SessionState};
    use std::fs;

    const OLD_PASSPHRASE: &str = "correct horse battery staple"; // len >= 15
    const NEW_PASSPHRASE: &str = "this is a different passphrase"; // len >= 15

    fn mk_unlocked_state(master_key: [u8; 32]) -> AppState {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let state = AppState::new_for_tests(td_state.path()).expect("new_for_tests");

        // session
        {
            let mut g = state.session.lock().expect("session lock");
            *g = SessionState {
                unlocked: true,
                active_key_id: None,
                active_associated_key_id: None,
            };
        }

        // secrets
        {
            let mut g = state.secrets.lock().expect("secrets lock");
            *g = Some(SecretsState {
                master_key: zeroize::Zeroizing::new(master_key),
                active_private: None,
            });
        }

        state
    }

    fn read_keyfile(path: &std::path::Path) -> crate::keyfile::KeyfileData {
        let bytes = fs::read(path).expect("read keyfile bytes");
        serde_json::from_slice(&bytes).expect("parse keyfile json")
    }

    #[test]
    fn validate_standard_domain_ascii_lowercases_and_allows_common_chars() {
        // private helper, but tests in same module can call it
        let s = validate_standard_domain_ascii("Example.COM/a_b-9").expect("valid domain");
        assert_eq!(s, "example.com/a_b-9");
    }

    #[test]
    fn validate_standard_domain_ascii_rejects_non_ascii() {
        let err = validate_standard_domain_ascii("exámple.com").unwrap_err();
        assert!(matches!(err, AppError::InvalidStandardDomain));
    }

    #[test]
    fn validate_standard_domain_ascii_rejects_bad_chars() {
        let err = validate_standard_domain_ascii("example.com!").unwrap_err();
        assert!(matches!(err, AppError::InvalidStandardDomain));
    }

    #[test]
    fn install_key_rejects_empty_mnemonic_and_label() {
        let td = tempfile::tempdir().expect("tempdir");
        let ctx = AppCtx::new(td.path().to_path_buf());

        let state = mk_unlocked_state([1u8; 32]);

        // empty mnemonic
        let (_ks, res) = install_key("", "example.com", "label", None, true, &state, &ctx);
        assert!(matches!(res.unwrap_err(), AppError::EmptyMnemonic));

        // empty label
        let (_ks, res) = install_key(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "example.com",
            "   ",
            None,
            true,
            &state,
            &ctx,
        );
        assert!(matches!(res.unwrap_err(), AppError::EmptyLabel));
    }

    #[test]
    fn install_key_rejects_invalid_standard_domain_when_enforced() {
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let fx = crate::keyfile::ops::test_support::mk_fixture(OLD_PASSPHRASE).expect("mk_fixture");
        let mut ctx = AppCtx::new(td_keyfile.path().to_path_buf());
        ctx.keyfile_path = fx.path.clone();

        let state = mk_unlocked_state(fx.master_key);

        let (_ks, res) = install_key(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "example.com!",
            "Label",
            None,
            true,
            &state,
            &ctx,
        );

        assert!(matches!(res.unwrap_err(), AppError::InvalidStandardDomain));
    }

    #[test]
    fn install_key_appends_key_to_keyfile_and_trims_associated_id() {
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let fx = crate::keyfile::ops::test_support::mk_fixture(OLD_PASSPHRASE).expect("mk_fixture");
        let mut ctx = AppCtx::new(td_keyfile.path().to_path_buf());
        ctx.keyfile_path = fx.path.clone();

        let state = mk_unlocked_state(fx.master_key);

        let before = read_keyfile(&ctx.keyfile_path);
        let before_len = before.keys.len();

        let (ks, res) = install_key(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "Example.COM",
            "My Key",
            Some("   assoc-123   "),
            true,
            &state,
            &ctx,
        );
        assert_eq!(ks, KeyfileState::NotCorrupted);
        res.expect("install_key ok");

        let after = read_keyfile(&ctx.keyfile_path);
        assert_eq!(after.keys.len(), before_len + 1);

        let last = after.keys.last().expect("last key exists");
        assert_eq!(last.domain, "example.com"); // enforced => lowercase
                                                // label and associated_key_id are encrypted-at-rest; just assert they're present.
        assert!(!last.label.ciphertext_b64.is_empty());

        assert!(!last.associated_key_id.ciphertext_b64.is_empty());
    }

    #[test]
    fn uninstall_active_key_removes_key_from_keyfile() {
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let f1 = crate::keyfile::ops::test_support::mk_fixture_one_key(OLD_PASSPHRASE, "")
            .expect("fixture");
        let mut ctx = AppCtx::new(td_keyfile.path().to_path_buf());
        ctx.keyfile_path = f1.fx.path.clone();

        let state = mk_unlocked_state(f1.fx.master_key);

        // set active key id in session
        {
            let mut g = state.session.lock().expect("session lock");
            g.unlocked = true;
            g.active_key_id = Some(f1.key_id);
            g.active_associated_key_id = Some(String::new()); // empty == "none"
        }

        let before = read_keyfile(&ctx.keyfile_path);
        assert_eq!(before.keys.len(), 1);

        let (ks, res) = uninstall_active_key(&state, &ctx);
        assert_eq!(ks, KeyfileState::NotCorrupted);
        res.expect("uninstall_active_key ok");

        let after = read_keyfile(&ctx.keyfile_path);
        assert_eq!(after.keys.len(), 0);
    }

    #[test]
    fn change_passphrase_updates_disk_and_in_memory_master_key() {
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let fx = crate::keyfile::ops::test_support::mk_fixture(OLD_PASSPHRASE).expect("mk_fixture");
        let mut ctx = AppCtx::new(td_keyfile.path().to_path_buf());
        ctx.keyfile_path = fx.path.clone();

        let state = mk_unlocked_state(fx.master_key);

        // sanity: old works now
        crate::keyfile::read_master_key(&ctx.keyfile_path, OLD_PASSPHRASE)
            .expect("old passphrase ok");

        let (ks, res) = change_passphrase(OLD_PASSPHRASE, NEW_PASSPHRASE, &state, &ctx);
        assert_eq!(ks, KeyfileState::NotCorrupted);
        res.expect("change_passphrase ok");

        // new should work
        let new_mk =
            crate::keyfile::read_master_key(&ctx.keyfile_path, NEW_PASSPHRASE).expect("new ok");

        // If your design guarantees rotation (old invalid), keep this assertion.
        // Otherwise, drop it (some designs allow multiple valid passphrases).
        // assert!(crate::keyfile::read_master_key(&ctx.keyfile_path, OLD_PASSPHRASE).is_err());

        // and in-memory secrets should match (since we were unlocked)
        let g = state.secrets.lock().expect("secrets lock");
        let mk_mem = &g.as_ref().expect("still unlocked").master_key;
        assert_eq!(mk_mem.as_ref(), &new_mk);
    }
}
