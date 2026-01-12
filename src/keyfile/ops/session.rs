// src/keyfile/ops/session.rs

use crate::platform::BestEffortFailure;

// Best-effort lock of an in-memory private key.
//
// Commands should call this (not `crate::platform::*`) so platform details
// stay below the ops layer.
pub fn lock_private_key32_best_effort(key: &mut [u8; 32]) -> Option<BestEffortFailure> {
    crate::platform::lock_key32_best_effort(key)
}

// Best-effort unlock of an in-memory private key.
pub fn unlock_private_key32_best_effort(key: &mut [u8; 32]) -> Option<BestEffortFailure> {
    crate::platform::unlock_key32_best_effort(key)
}
