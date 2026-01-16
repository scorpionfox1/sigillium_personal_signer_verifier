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
) -> AppResult<()> {
    let mnemonic = mnemonic.trim();
    if mnemonic.is_empty() {
        return Err(AppError::EmptyMnemonic);
    }

    let label = label.trim();
    if label.is_empty() {
        return Err(AppError::EmptyLabel);
    }

    let domain_for_derivation: String = if enforce_standard_domain {
        let d = domain.trim();
        if d.is_empty() {
            String::new()
        } else {
            validate_standard_domain_ascii(d).map_err(|_| AppError::InvalidStandardDomain)?
        }
    } else {
        // Unrestricted mode: use EXACTLY as provided (no trim, no lowercase, no validation).
        domain.to_string()
    };

    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    // Command-layer normalization: None/blank => ""
    let associated_norm: String = associated_key_id.unwrap_or("").trim().to_string();

    // derive + compute pubkey
    let mut privk =
        crypto::derive_private_key_from_mnemonic_and_domain(mnemonic, &domain_for_derivation)?;
    let pubk = crypto::public_key_from_private(&privk);

    let op_res: AppResult<()> = (|| {
        enforce_keyfile_perms_best_effort(state, &keyfile_path, &ctx.app_data_dir, "install_key");

        with_master_key(state, |mk| {
            keyfile::append_key(
                &keyfile_path,
                &*mk,
                &domain_for_derivation,
                label,
                &privk,
                &pubk,
                &associated_norm, // may be ""
            )
        })?;

        let _lock = acquire_keyfile_lock(&keyfile_path)?;

        enforce_keyfile_perms_best_effort(state, &keyfile_path, &ctx.app_data_dir, "install_key");

        super::refresh_key_meta_cache(state, ctx)?;

        Ok(())
    })();

    privk.zeroize();
    op_res
}

pub fn uninstall_active_key(state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    // Resolve active key id from session first.
    let active_id: KeyId = match lock_session(state) {
        Ok(g) => match g.active_key_id {
            Some(id) => id,
            None => return Err(AppError::Msg("No active key selected".into())),
        },
        Err(e) => return Err(e),
    };

    // Clear active key first so the UI/session cannot point at a removed key.
    super::session::clear_active_key(state)?;

    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    (|| {
        enforce_keyfile_perms_best_effort(
            state,
            &keyfile_path,
            &ctx.app_data_dir,
            "uninstall_active_key",
        );

        with_master_key(state, |mk| {
            keyfile::remove_key(&keyfile_path, &*mk, active_id)
        })?;

        let _lock = acquire_keyfile_lock(&keyfile_path)?;

        enforce_keyfile_perms_best_effort(
            state,
            &keyfile_path,
            &ctx.app_data_dir,
            "uninstall_active_key",
        );

        super::refresh_key_meta_cache(state, ctx)?;

        Ok(())
    })()
}

pub fn change_passphrase(
    old_passphrase: &str,
    new_passphrase: &str,
    state: &AppState,
    ctx: &AppCtx,
) -> AppResult<()> {
    let old_passphrase = Zeroizing::new(old_passphrase.to_owned());
    let new_passphrase = Zeroizing::new(new_passphrase.to_owned());

    super::validate_passphrase_for_unlock(&old_passphrase).map_err(AppError::Msg)?;
    super::validate_passphrase(&new_passphrase).map_err(AppError::Msg)?;

    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    (|| {
        enforce_keyfile_perms_best_effort(
            state,
            &keyfile_path,
            &ctx.app_data_dir,
            "change_passphrase",
        );

        // Derive old master key from old passphrase (uses keyfile salt on disk)
        let old_master_key = match keyfile::read_master_key(&keyfile_path, &old_passphrase) {
            Ok(k) => k,
            Err(e) => {
                thread::sleep(Duration::from_millis(250));
                return Err(e);
            }
        };

        // ---- keyfile mutation must NOT hold app state lock ----
        {
            let _kf_lock = acquire_keyfile_lock(&keyfile_path)?;

            let new_master_key =
                keyfile::change_passphrase(&keyfile_path, &old_master_key, &new_passphrase)?;

            // Update in-memory secrets only AFTER disk is done
            let mut guard = lock_secrets(state)?;
            if let Some(secrets) = guard.as_mut() {
                secrets.master_key = Zeroizing::new(new_master_key);
            }
        }

        lock_master_key_best_effort(state, "change_passphrase");

        enforce_keyfile_perms_best_effort(
            state,
            &keyfile_path,
            &ctx.app_data_dir,
            "change_passphrase",
        );

        Ok(())
    })()
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
