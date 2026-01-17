// src/command_state.rs

use crate::{
    error::{AppError, AppResult},
    security_log::record_best_effort_platform_failures,
    types::{AppState, SecretsState, SessionState},
};
use std::sync::MutexGuard;
use zeroize::Zeroizing;

// ======================================================
// locking helpers
// ======================================================

pub fn lock_session<'a>(state: &'a AppState) -> AppResult<MutexGuard<'a, SessionState>> {
    state
        .session
        .lock()
        .map_err(|_| AppError::StateLockPoisoned)
}

pub fn lock_secrets<'a>(state: &'a AppState) -> AppResult<MutexGuard<'a, Option<SecretsState>>> {
    state
        .secrets
        .lock()
        .map_err(|_| AppError::StateLockPoisoned)
}

// ======================================================
// key access helpers (String boundary preserved)
// ======================================================

fn app_err_to_string(e: AppError) -> String {
    e.to_string()
}

pub fn with_master_key<T>(
    state: &AppState,
    f: impl FnOnce(&Zeroizing<[u8; 32]>) -> AppResult<T>,
) -> AppResult<T> {
    let guard = lock_secrets(state)?;
    let secrets = guard.as_ref().ok_or(AppError::AppLocked)?;
    f(&secrets.master_key)
}

pub fn with_active_private<T>(
    state: &AppState,
    f: impl FnOnce(&Zeroizing<[u8; 32]>) -> Result<T, String>,
) -> Result<T, String> {
    let guard = lock_secrets(state).map_err(app_err_to_string)?;
    let secrets = guard
        .as_ref()
        .ok_or_else(|| AppError::AppLocked.to_string())?;
    let privk = secrets
        .active_private
        .as_ref()
        .ok_or_else(|| AppError::NoActiveKeySelected.to_string())?;
    f(privk)
}

// ======================================================
// best-effort locking
// ======================================================

pub fn lock_master_key_best_effort(state: &AppState, context: &str) {
    let fail = lock_secrets(state).ok().and_then(|mut guard| {
        guard.as_mut().map(|secrets| {
            let mk: &mut [u8; 32] = &mut *secrets.master_key;
            crate::platform::lock_key32_best_effort(mk)
        })
    });

    record_best_effort_platform_failures(state, context, fail.into_iter().flatten());
}

// ======================================================
// app locking
// ======================================================

pub fn lock_app_inner(state: &AppState, context: &str) -> Result<(), String> {
    let mut active_fail = None;
    let mut master_fail = None;

    // Clear secrets first (and best-effort unlock key material)
    {
        let mut guard = lock_secrets(state).map_err(app_err_to_string)?;
        if let Some(sec) = guard.as_mut() {
            if let Some(active) = sec.active_private.as_mut() {
                active_fail = crate::platform::unlock_key32_best_effort(&mut *active);
            }
            master_fail = crate::platform::unlock_key32_best_effort(&mut *sec.master_key);
        }
        *guard = None;
    }

    // Clear session second
    {
        let mut session = lock_session(state).map_err(app_err_to_string)?;
        session.unlocked = false;
        session.active_key_id = None;
        session.active_associated_key_id = None;
    }

    record_best_effort_platform_failures(
        state,
        context,
        active_fail.into_iter().chain(master_fail),
    );

    state
        .keys
        .lock()
        .map_err(|_| AppError::StateLockPoisoned.to_string())?
        .clear();

    Ok(())
}

pub fn lock_app_inner_if_unlocked(state: &AppState, context: &str) -> Result<(), String> {
    let unlocked = {
        let session = lock_session(state).map_err(app_err_to_string)?;
        session.unlocked
    };

    if unlocked {
        lock_app_inner(state, context)?;
    }

    Ok(())
}

// ======================================================
// Unit Tests
// ======================================================

// src/command_state.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{security_log::SecurityLog, types::SignVerifyMode};
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    fn mk_state() -> AppState {
        let td = tempdir().expect("tempdir");

        AppState {
            session: std::sync::Mutex::new(SessionState {
                unlocked: false,
                active_key_id: None,
                active_associated_key_id: None,
            }),
            secrets: std::sync::Mutex::new(None),
            keys: std::sync::Mutex::new(Vec::new()),
            sign_verify_mode: std::sync::Mutex::new(SignVerifyMode::Text),
            security_log: std::sync::Mutex::new(
                SecurityLog::init(td.path()).expect("security log init"),
            ),
        }
    }

    fn unlock_with_master(state: &AppState, mk: [u8; 32]) {
        *state.secrets.lock().unwrap() = Some(SecretsState {
            master_key: Zeroizing::new(mk),
            active_private: None,
        });
        state.session.lock().unwrap().unlocked = true;
    }

    fn unlock_with_active(state: &AppState, mk: [u8; 32], privk: [u8; 32]) {
        *state.secrets.lock().unwrap() = Some(SecretsState {
            master_key: Zeroizing::new(mk),
            active_private: Some(Zeroizing::new(privk)),
        });
        state.session.lock().unwrap().unlocked = true;
    }

    // --------------------------------------------------
    // with_master_key
    // --------------------------------------------------

    #[test]
    fn with_master_key_fails_when_locked() {
        let state = mk_state();

        match with_master_key(&state, |_| Ok(())) {
            Err(AppError::AppLocked) => {}
            other => panic!("expected AppLocked, got {:?}", other),
        }
    }

    #[test]
    fn with_master_key_succeeds_when_unlocked() {
        let state = mk_state();
        unlock_with_master(&state, [7u8; 32]);

        let v = with_master_key(&state, |k| Ok(k[0])).unwrap();
        assert_eq!(v, 7);
    }

    // --------------------------------------------------
    // with_active_private
    // --------------------------------------------------

    #[test]
    fn with_active_private_fails_when_locked() {
        let state = mk_state();

        match with_active_private(&state, |_| Ok(())) {
            Err(s) => assert_eq!(s, AppError::AppLocked.to_string()),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn with_active_private_fails_when_no_active_key() {
        let state = mk_state();
        unlock_with_master(&state, [1u8; 32]);

        match with_active_private(&state, |_| Ok(())) {
            Err(s) => assert_eq!(s, AppError::NoActiveKeySelected.to_string()),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn with_active_private_succeeds() {
        let state = mk_state();
        unlock_with_active(&state, [2u8; 32], [9u8; 32]);

        let v = with_active_private(&state, |k| Ok(k[0])).unwrap();
        assert_eq!(v, 9);
    }

    // --------------------------------------------------
    // lock_app_inner
    // --------------------------------------------------

    #[test]
    fn lock_app_inner_clears_secrets_and_session() {
        let state = mk_state();
        unlock_with_active(&state, [3u8; 32], [4u8; 32]);

        {
            let mut s = state.session.lock().unwrap();
            s.active_key_id = Some(42);
            s.active_associated_key_id = Some("assoc".into());
        }

        lock_app_inner(&state, "test").expect("lock_app_inner");

        assert!(state.secrets.lock().unwrap().is_none());

        let s = state.session.lock().unwrap();
        assert!(!s.unlocked);
        assert!(s.active_key_id.is_none());
        assert!(s.active_associated_key_id.is_none());
    }
}
