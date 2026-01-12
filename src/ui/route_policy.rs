// src/ui/route_policy.rs

use crate::ui::Route;
use sigillum_personal_signer_verifier_lib::types::KeyfileState;

/// Minimal routing context derived by ui/mod.rs
#[derive(Clone, Copy, Debug)]
pub struct RouteCtx {
    pub unlocked: bool,
    pub keyfile_state: KeyfileState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageClearPolicy {
    ClearAllNonLockPanels,
    ClearOnlyLockPanel,
}

/// Centralized route invariants (pure)
pub fn apply_route_guards(requested: Route, ctx: RouteCtx) -> Route {
    // If keyfile missing or corrupted, force CreateKeyfile
    match ctx.keyfile_state {
        KeyfileState::Missing | KeyfileState::Corrupted => return Route::CreateKeyfile,
        KeyfileState::NotCorrupted => {}
    }

    // If locked, force Locked (except CreateKeyfile handled above)
    if !ctx.unlocked && requested != Route::Locked {
        return Route::Locked;
    }

    requested
}

/// Message clearing policy (pure)
pub fn message_clear_policy(prev: Route, next: Route) -> MessageClearPolicy {
    // Preserve messages when moving to/from Locked; otherwise clear non-lock panels
    if prev != Route::Locked && next != Route::Locked {
        MessageClearPolicy::ClearAllNonLockPanels
    } else {
        MessageClearPolicy::ClearOnlyLockPanel
    }
}

pub fn entering_locked(prev: Route, next: Route) -> bool {
    next == Route::Locked && prev != Route::Locked
}
