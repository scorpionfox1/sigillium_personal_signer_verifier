// tests/quarantine_on_unlock.rs

mod common;

use sigillum_personal_signer_verifier_lib::command;

use crate::common::setup_one_active_key;

const PASSPHRASE: &str = "correct horse battery staple";
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const DOMAIN: &str = "example.test";
const LABEL: &str = "Test Key";

#[test]
fn quarantine_happens_on_select_active_key_when_keyfile_is_tampered() {
    let env = setup_one_active_key(PASSPHRASE, MNEMONIC, DOMAIN, LABEL, None, true);

    let parent = env.ctx().keyfile_path.parent().expect("keyfile parent");
    let fname = env
        .ctx()
        .keyfile_path
        .file_name()
        .expect("keyfile file_name")
        .to_string_lossy()
        .to_string();

    let before = count_corrupt_backups(parent, &fname);

    // --- tamper the keyfile on disk (break MAC) ---
    let original = std::fs::read_to_string(&env.ctx().keyfile_path).expect("read keyfile");
    let tampered = original.replacen(DOMAIN, "example.tamper", 1);
    assert_ne!(tampered, original, "tamper must change file");
    std::fs::write(&env.ctx().keyfile_path, tampered).expect("write tampered keyfile");

    // --- selecting a key should trigger quarantine on MAC mismatch ---
    let (ks, res) = command::select_active_key(env.key_id(), &env.state, &env.ctx());
    assert!(
        res.is_err(),
        "select_active_key should fail for tampered keyfile"
    );

    assert!(
        matches!(
            ks,
            sigillum_personal_signer_verifier_lib::types::KeyfileState::Missing
                | sigillum_personal_signer_verifier_lib::types::KeyfileState::Corrupted
        ),
        "expected Missing (quarantined away) or Corrupted, got: {:?}",
        ks
    );

    // If quarantine happened via rename, original path should be gone.
    assert!(
        !env.ctx().keyfile_path.exists(),
        "expected keyfile to be renamed away after quarantine"
    );

    let after = count_corrupt_backups(parent, &fname);
    assert_eq!(
        after,
        before + 1,
        "expected exactly one new corrupt.* backup file"
    );
}

// ======================================================
// Internal Helpers
// ======================================================

// ⬇️ put the helper here (top of file, under imports)
fn count_corrupt_backups(parent: &std::path::Path, fname: &str) -> usize {
    let mut n = 0usize;
    for ent in std::fs::read_dir(parent).expect("read_dir") {
        let ent = ent.expect("dir entry");
        let name = ent.file_name().to_string_lossy().to_string();

        if name == format!("corrupt.{fname}") {
            n += 1;
            continue;
        }

        if let Some(rest) = name.strip_prefix("corrupt.") {
            if let Some((_i, tail)) = rest.split_once('.') {
                if tail == fname {
                    n += 1;
                }
            }
        }
    }
    n
}
