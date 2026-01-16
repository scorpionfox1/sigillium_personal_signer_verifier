// src/ui/route_policy.rs

use crate::ui::Route;
use sigillium_personal_signer_verifier_lib::types::KeyfileState;

/// Minimal routing context derived by ui/mod.rs
#[derive(Clone, Copy, Debug)]
pub struct RouteCtx {
    pub keyfile_selected: bool,
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
    // If no keyfile is selected, always go to KeyfileSelect
    // (but allow CreateKeyfile via explicit button).
    if !ctx.keyfile_selected {
        if requested == Route::CreateKeyfile {
            return Route::CreateKeyfile;
        }
        return Route::KeyfileSelect;
    }

    // If keyfile missing or corrupted, force CreateKeyfile
    // (but allow KeyfileSelect so user can pick another one).
    match ctx.keyfile_state {
        KeyfileState::Missing | KeyfileState::Corrupted => {
            if requested == Route::KeyfileSelect {
                return Route::KeyfileSelect;
            }
            return Route::CreateKeyfile;
        }
        KeyfileState::NotCorrupted => {}
    }

    // If locked, force Locked (except CreateKeyfile/KeyfileSelect handled above)
    if !ctx.unlocked && requested != Route::Locked {
        return Route::Locked;
    }

    requested
}

/// Message clearing policy (pure)
pub fn message_clear_policy(prev: Route, next: Route) -> MessageClearPolicy {
    if prev != Route::Locked && next != Route::Locked {
        MessageClearPolicy::ClearAllNonLockPanels
    } else {
        MessageClearPolicy::ClearOnlyLockPanel
    }
}

pub fn entering_locked(prev: Route, next: Route) -> bool {
    next == Route::Locked && prev != Route::Locked
}
