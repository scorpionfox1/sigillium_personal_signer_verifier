// src/command/keyfile_lifecycle.rs

use crate::context::AppCtx;
use crate::error::{AppError, AppResult};
use crate::fs_hardening::enforce_keyfile_perms_best_effort;
use crate::keyfile::fs::backup_keyfile_with_quarantine_prefix;
use crate::types::AppState;
use crate::{command_state::*, keyfile};
use zeroize::Zeroizing;

pub fn create_keyfile(passphrase: &str, state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    let passphrase = Zeroizing::new(passphrase.to_owned());
    super::validate_passphrase(&passphrase).map_err(AppError::Msg)?;

    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    let result: AppResult<()> = (|| {
        keyfile::write_blank_keyfile(&keyfile_path)?;

        enforce_keyfile_perms_best_effort(
            state,
            &keyfile_path,
            &ctx.app_data_dir,
            "create_keyfile",
        );

        // NEW: stamp file MAC immediately so unlock_app doesn't reject a fresh keyfile.
        let mk = keyfile::read_master_key(&keyfile_path, passphrase.as_str())?;
        let mut data = keyfile::fs::read_json(&keyfile_path)?;
        keyfile::validate::set_file_mac_in_place(&mut data, &mk)?;
        keyfile::fs::write_json(&keyfile_path, &data)?;
        // END NEW

        lock_app_inner_if_unlocked(state, "create_keyfile").map_err(AppError::Msg)?;

        Ok(())
    })();

    result
}

pub fn quarantine_keyfile_now(state: &AppState, ctx: &AppCtx) -> AppResult<()> {
    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    backup_keyfile_with_quarantine_prefix(&keyfile_path)?;
    ctx.set_selected_keyfile_dir(None);
    lock_app_inner_if_unlocked(state, "keyfile integrity failure").map_err(AppError::Msg)?;
    Ok(())
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{AppCtx, KEYFILE_NAME};
    use crate::types::{AppState, SecretsState, SessionState};
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    fn mk_state() -> AppState {
        AppState {
            session: std::sync::Mutex::new(SessionState {
                unlocked: false,
                active_key_id: None,
                active_associated_key_id: None,
            }),
            secrets: std::sync::Mutex::new(None),
            keys: std::sync::Mutex::new(Vec::new()),
            sign_verify_mode: std::sync::Mutex::new(crate::types::SignVerifyMode::Text),
            security_log: std::sync::Mutex::new(
                crate::security_log::SecurityLog::init(std::env::temp_dir().as_path()).unwrap(),
            ),
        }
    }

    fn unlock_state(state: &AppState) {
        *state.secrets.lock().unwrap() = Some(SecretsState {
            master_key: Zeroizing::new([1u8; 32]),
            active_private: None,
        });
        state.session.lock().unwrap().unlocked = true;
    }

    fn mk_ctx_with_selected_dir(td_path: &std::path::Path) -> (AppCtx, std::path::PathBuf) {
        let ctx = AppCtx::new(td_path.to_path_buf());
        let selected_dir = ctx.keyfiles_root().join("kf");
        std::fs::create_dir_all(&selected_dir).unwrap();
        ctx.set_selected_keyfile_dir(Some(selected_dir.clone()));
        (ctx, selected_dir)
    }

    #[test]
    fn create_keyfile_errors_when_no_keyfile_selected() {
        let state = mk_state();
        let td = tempdir().unwrap();
        let ctx = AppCtx::new(td.path().to_path_buf());

        let err = create_keyfile("passphrase", &state, &ctx).unwrap_err();
        assert!(matches!(err, AppError::Msg(_)));
    }

    #[test]
    fn create_keyfile_rejects_invalid_passphrase() {
        let state = mk_state();
        let td = tempdir().unwrap();
        let (ctx, _dir) = mk_ctx_with_selected_dir(td.path());

        let err = create_keyfile("", &state, &ctx).unwrap_err();
        assert!(matches!(err, AppError::Msg(_)));
    }

    #[test]
    fn create_keyfile_creates_file_stamps_mac_and_locks_app() {
        let state = mk_state();
        unlock_state(&state);

        let td = tempdir().unwrap();
        let (ctx, _dir) = mk_ctx_with_selected_dir(td.path());

        create_keyfile("correct horse battery staple", &state, &ctx).unwrap();

        let keyfile_path = ctx.current_keyfile_path().unwrap();
        assert!(keyfile_path.exists(), "keyfile must exist");

        let data = crate::keyfile::fs::read_json(&keyfile_path).unwrap();
        assert!(data.file_mac_b64.is_some(), "file MAC must be set");

        let session = state.session.lock().unwrap();
        assert!(!session.unlocked, "app must be locked after create");
    }

    #[test]
    fn quarantine_keyfile_errors_when_no_keyfile_selected() {
        let state = mk_state();
        let td = tempdir().unwrap();
        let ctx = AppCtx::new(td.path().to_path_buf());

        let err = quarantine_keyfile_now(&state, &ctx).unwrap_err();
        assert!(matches!(err, AppError::Msg(_)));
    }

    #[test]
    fn quarantine_keyfile_moves_file_clears_ctx_and_locks_app() {
        let state = mk_state();
        unlock_state(&state);

        let td = tempdir().unwrap();
        let (ctx, selected_dir) = mk_ctx_with_selected_dir(td.path());

        let keyfile_path = ctx.current_keyfile_path().unwrap();
        std::fs::write(&keyfile_path, b"dummy").unwrap();
        assert!(keyfile_path.exists());

        quarantine_keyfile_now(&state, &ctx).unwrap();

        // selection cleared
        assert!(
            ctx.current_keyfile_path().is_none(),
            "ctx selection cleared"
        );

        // original keyfile gone
        assert!(!keyfile_path.exists());

        // quarantined file exists in SAME directory as original
        let mut found = false;
        for e in std::fs::read_dir(&selected_dir).unwrap().flatten() {
            let p = e.path();
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                if name.starts_with("quarantine.") && name.ends_with(KEYFILE_NAME) {
                    found = true;
                    break;
                }
            }
        }
        assert!(
            found,
            "expected quarantine.*.{KEYFILE_NAME} in selected dir"
        );

        // app locked
        let session = state.session.lock().unwrap();
        assert!(!session.unlocked, "app must be locked after quarantine");
    }
}
