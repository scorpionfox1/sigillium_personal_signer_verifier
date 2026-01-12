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
    }

    // Refactored to use plural failure logging
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

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn mk_state_locked() -> AppState {
        let dir = std::env::temp_dir().join("sigillium-cmdstate-test-locked");
        std::fs::create_dir_all(&dir).unwrap();
        AppState::new_for_tests(&dir).unwrap()
    }

    fn mk_state_unlocked(master: [u8; 32], active: Option<[u8; 32]>) -> AppState {
        let dir = std::env::temp_dir().join("sigillium-cmdstate-test-unlocked");
        std::fs::create_dir_all(&dir).unwrap();

        let state = AppState::new_for_tests(&dir).unwrap();

        // secrets
        {
            let mut secrets = state.secrets.lock().unwrap();
            *secrets = Some(SecretsState {
                master_key: Zeroizing::new(master),
                active_private: active.map(Zeroizing::new),
            });
        }

        // session
        {
            let mut session = state.session.lock().unwrap();
            session.unlocked = true;
            session.active_key_id = active.map(|_| 1);
        }

        state
    }

    #[test]
    fn with_master_key_errors_when_locked() {
        let state = mk_state_locked();
        let err = with_master_key(&state, |_| Ok(())).unwrap_err();
        assert!(matches!(err, AppError::AppLocked));
    }

    #[test]
    fn with_master_key_calls_closure_when_unlocked() {
        let state = mk_state_unlocked([7u8; 32], None);
        let got = with_master_key(&state, |mk| Ok(**mk)).unwrap();
        assert_eq!(got, [7u8; 32]);
    }

    #[test]
    fn with_active_private_errors_when_locked() {
        let state = mk_state_locked();
        let err = with_active_private(&state, |_| Ok(())).unwrap_err();
        assert_eq!(err, AppError::AppLocked.to_string());
    }

    #[test]
    fn with_active_private_errors_when_no_active_key() {
        let state = mk_state_unlocked([1u8; 32], None);
        let err = with_active_private(&state, |_| Ok(())).unwrap_err();
        assert_eq!(err, AppError::NoActiveKeySelected.to_string());
    }

    #[test]
    fn with_active_private_calls_closure_when_active_key_present() {
        let state = mk_state_unlocked([1u8; 32], Some([3u8; 32]));
        let got = with_active_private(&state, |k| Ok(**k)).unwrap();
        assert_eq!(got, [3u8; 32]);
    }

    #[test]
    fn lock_app_inner_clears_session_and_secrets() {
        let state = mk_state_unlocked([1u8; 32], Some([2u8; 32]));

        lock_app_inner(&state, "test").unwrap();

        assert!(state.secrets.lock().unwrap().is_none());
        let session = state.session.lock().unwrap();
        assert!(!session.unlocked);
        assert!(session.active_key_id.is_none());
        assert!(state.keys.lock().unwrap().is_empty());
    }

    #[test]
    fn lock_app_inner_if_unlocked_is_noop_when_locked() {
        let state = mk_state_locked();

        lock_app_inner_if_unlocked(&state, "test").unwrap();

        assert!(state.secrets.lock().unwrap().is_none());
        let session = state.session.lock().unwrap();
        assert!(!session.unlocked);
        assert!(session.active_key_id.is_none());
    }

    #[test]
    fn lock_app_inner_if_unlocked_locks_when_unlocked() {
        let state = mk_state_unlocked([1u8; 32], Some([2u8; 32]));

        lock_app_inner_if_unlocked(&state, "test").unwrap();

        assert!(state.secrets.lock().unwrap().is_none());
        let session = state.session.lock().unwrap();
        assert!(!session.unlocked);
        assert!(session.active_key_id.is_none());
    }
}
