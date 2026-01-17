// src/keyfile/fs/mod.rs

mod io;
pub(crate) mod lock;

pub use io::backup_keyfile_with_quarantine_prefix;
pub(crate) use io::{read_json, write_json};
