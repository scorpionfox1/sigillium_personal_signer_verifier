// src/security_log/api.rs

use crate::platform;
use crate::types::AppState;

use super::model::SecurityEventClass;

pub fn record_best_effort_platform_failure(
    state: &AppState,
    context: &str,
    fail: platform::BestEffortFailure,
) {
    let mut slog = match state.security_log.lock() {
        Ok(g) => g,
        Err(_) => return,
    };

    slog.record_best_effort(
        SecurityEventClass::BestEffortFailure,
        fail.kind,
        context,
        fail.errno,
        fail.msg,
    );
}

pub fn record_best_effort_platform_failures<I>(state: &AppState, context: &str, fails: I)
where
    I: IntoIterator<Item = platform::BestEffortFailure>,
{
    for fail in fails {
        record_best_effort_platform_failure(state, context, fail);
    }
}

pub fn record_intentional_security_event(state: &AppState, context: &str, kind: &str, msg: &str) {
    let mut slog = match state.security_log.lock() {
        Ok(g) => g,
        Err(_) => return,
    };

    slog.record_intentional(kind, context, msg);
}

pub fn take_best_effort_warn_pending(state: &AppState) -> bool {
    match state.security_log.lock() {
        Ok(mut slog) => slog.take_best_effort_warn_pending(),
        Err(_) => false,
    }
}
