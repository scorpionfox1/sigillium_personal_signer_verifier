// src/keyfile/ops/mod.rs

use crate::keyfile::crypto::*;

// ======================================================
// Submodules
// ======================================================

pub mod inspect;
pub mod lifecycle;
pub mod mutation;
pub mod passphrase;
pub mod session;
#[cfg(test)]
pub mod test_support;

// ======================================================
// Re-exports (public API surface)
// ======================================================

pub use inspect::check_keyfile_state;
pub use inspect::decrypt_key_material;
pub use inspect::list_key_meta;
pub use inspect::read_json_verified_optional_mac;
pub use lifecycle::{cleanup_delete_tombstones, read_master_key, write_blank_keyfile};
pub use mutation::{append_key, remove_key};
pub use passphrase::change_passphrase;
pub use session::{lock_private_key32_best_effort, unlock_private_key32_best_effort};
