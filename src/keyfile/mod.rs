// src/keyfile/mod.rs

mod crypto;
pub(crate) mod fs;
pub(crate) mod ops;
mod types;
pub(crate) mod validate;

pub use ops::*;
pub use types::{EncryptedString, KeyEntry, KeyfileData};

pub use fs::backup_keyfile_with_corrupt_prefix;
pub use validate::validate_keyfile_structure_on_disk;
pub use validate::verify_keyfile_mac_on_disk;
