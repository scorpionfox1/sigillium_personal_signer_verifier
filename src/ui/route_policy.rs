// src/ui/route_policy.rs

use crate::ui::Route;

/// Minimal routing context derived by ui/mod.rs
#[derive(Clone, Copy, Debug)]
pub struct RouteCtx {
    pub keyfile_selected: bool,
    pub unlocked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageClearPolicy {
    ClearAllNonLockPanels,
    ClearOnlyLockPanel,
}

/// Centralized route invariants (pure)
pub fn apply_route_guards(ctx: &RouteCtx, requested: Route) -> Route {
    // If no keyfile is selected, always go to KeyfileSelect
    // (but allow CreateKeyfile via explicit button).
    if !ctx.keyfile_selected {
        if requested == Route::CreateKeyfile {
            return Route::CreateKeyfile;
        }
        return Route::KeyfileSelect;
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
