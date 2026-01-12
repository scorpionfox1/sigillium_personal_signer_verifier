// src/command/keyfile_inspect.rs

use crate::{
    context::AppCtx,
    error::{AppError, AppResult},
    keyfile::check_keyfile_state,
    types::{AppState, KeyfileState},
};

pub fn refresh_keyfile_state(state: &AppState, ctx: &AppCtx) -> AppResult<KeyfileState> {
    let ks = match check_keyfile_state(&ctx.keyfile_path) {
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

    #[test]
    fn refresh_keyfile_state_reports_missing_when_no_keyfile_exists() {
        let td_state = tempfile::tempdir().expect("tempdir state");
        let td_keyfile = tempfile::tempdir().expect("tempdir keyfile");

        let state = AppState::new_for_tests(td_state.path()).expect("init_state");
        let ctx = AppCtx::new(td_keyfile.path().to_path_buf());

        // Ensure file truly doesn't exist.
        assert!(
            !ctx.keyfile_path.exists(),
            "test assumes keyfile_path does not exist"
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

        let mut ctx = AppCtx::new(td_keyfile.path().to_path_buf());
        ctx.keyfile_path = fx.path.clone();
        assert!(ctx.keyfile_path.exists());

        let ks = refresh_keyfile_state(&state, &ctx).expect("refresh_keyfile_state");
        assert_eq!(ks, KeyfileState::NotCorrupted);
    }
}
