// src/command/keyfile_inspect.rs

use crate::{
    context::AppCtx,
    error::{AppError, AppResult},
    keyfile::check_keyfile_state,
    types::{AppState, KeyfileState},
};

pub fn refresh_keyfile_state(state: &AppState, ctx: &AppCtx) -> AppResult<KeyfileState> {
    let keyfile_path = ctx
        .current_keyfile_path()
        .ok_or_else(|| AppError::Msg("No keyfile selected".into()))?;

    let ks = match check_keyfile_state(&keyfile_path) {
        Ok(ks) => ks,
        Err(_e) => KeyfileState::Corrupted,
    };

    *state
        .keyfile_state
        .lock()
        .map_err(|_| AppError::Msg("Internal state lock failed".into()))? = ks;

    Ok(ks)
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KeyfileState;
    use crate::{context::AppCtx, types::AppState};
    use std::fs;

    const FIXED_KEYFILE_NAME: &str = "sigillium.keyfile.json";

    fn mk_ctx_with_empty_dir(root: &std::path::Path, name: &str) -> (AppCtx, std::path::PathBuf) {
        let kdir = root.join("keyfiles").join(name);
        fs::create_dir_all(&kdir).expect("mkdir keyfile dir");

        let mut ctx = AppCtx::new(root.to_path_buf());
        ctx.selected_keyfile_dir = Some(kdir.clone());

        (ctx, kdir)
    }

    #[test]
    fn refresh_keyfile_state_reports_missing_when_no_keyfile_exists() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");
        let (ctx, kdir) = mk_ctx_with_empty_dir(td_keyfile.path(), "k1");

        // Ensure file truly doesn't exist.
        assert!(
            !kdir.join(FIXED_KEYFILE_NAME).exists(),
            "test assumes keyfile.json does not exist"
        );

        let ks = refresh_keyfile_state(&state, &ctx).expect("refresh_keyfile_state");
        assert_eq!(ks, KeyfileState::Missing);
    }

    #[test]
    fn refresh_keyfile_state_reports_not_corrupted_when_keyfile_path_exists() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");

        // Create a valid keyfile using existing test fixture helpers.
        let fx = crate::keyfile::ops::test_support::mk_fixture("passphrase").expect("mk_fixture");

        let (ctx, kdir) = mk_ctx_with_empty_dir(td_keyfile.path(), "k1");
        let dst = kdir.join(FIXED_KEYFILE_NAME);
        fs::copy(&fx.path, &dst).expect("copy fixture keyfile");
        assert!(dst.exists());

        let ks = refresh_keyfile_state(&state, &ctx).expect("refresh_keyfile_state");
        assert_eq!(ks, KeyfileState::NotCorrupted);
    }
}
