// src/error.rs

use std::fmt;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserMsgKind {
    Success,
    Warn,
    Error,
    Info,
}

#[derive(Clone, Debug)]
pub struct UserMsg {
    pub kind: UserMsgKind,
    pub short: &'static str,
    pub detail: Option<String>,
}

#[derive(Debug)]
pub enum AppError {
    // --------------------------------------------------
    // generic / plumbing
    // --------------------------------------------------
    Io(std::io::Error),
    Msg(String),
    InternalStateLockFailed,
    StateLockPoisoned,
    InvalidPath,
    AppLocked,
    NoActiveKeySelected,
    KeyfileMissingOrCorrupted,

    // --------------------------------------------------
    // keyfile fs (IO / durability / locking)
    // --------------------------------------------------
    KeyfileFsReadFailed(String),
    KeyfileFsInvalidJson(String),
    KeyfileFsUnsupportedVersion { got: u32, expected: u32 },
    KeyfileFsMarkerMismatch,
    KeyfileFsTooLarge { bytes: u64, max: u64 },
    KeyfileFsWriteFailed(String),
    KeyfileFsSyncFailed(String),
    KeyfileFsRenameFailed(String),
    KeyfileFsBusy,
    KeyfileFsLockFailed(String),
    KeyfileFsBackupFailed(String),
    KeyfileFsBackupExhausted,

    // --------------------------------------------------
    // input / validation
    // --------------------------------------------------
    EmptyPayload,
    EmptyMnemonic,
    InvalidMnemonic,
    EmptyLabel,
    InvalidStandardDomain,

    // --------------------------------------------------
    // json / schema / canonicalization
    // --------------------------------------------------
    InvalidJson(String),
    JsonTooLarge,
    InvalidSchemaJson(String),
    SchemaTooLarge,
    SchemaRequired,
    SchemaWrongDraft,
    JsonNotObject,
    JsonCanonicalize(String),
    SchemaCompile(String),
    SchemaValidation(String),

    // --------------------------------------------------
    // keyfile invariants / parsing (logical, not IO)
    // --------------------------------------------------
    KeyfileMissing,
    KeyfileCorrupt,
    KeyfileStructCorrupted,
    KeyfileAlreadyExists,
    KeyfileVersionUnsupported,
    KeyfileFormatUnsupported,
    KeyfileAppMismatch,
    KeyfileMacMissing,
    KeyfileMacInvalid,
    KeyfileKeyMissing,
    KeyfileKeyIdNotFound,
    KeyfileAssociatedKeyIdAlreadySet,
    KeyfileDomainMismatch,
    KeyfilePublicKeyMismatch,
    KeyfileFsRemoveFailed(String),
    KeyfileFsIntentSerializeFailed(String),

    // --------------------------------------------------
    // encoding / decoding
    // --------------------------------------------------
    InvalidPublicKeyHex,
    InvalidPublicKeyLength,
    InvalidSignatureBase64,
    InvalidSignatureLength,
    InvalidNonceBase64(String),
    InvalidCiphertextBase64(String),
    InvalidUtf8(String),

    // --------------------------------------------------
    // crypto / kdf / aead
    // --------------------------------------------------
    InvalidAad(String),
    InvalidSaltLength { len: usize },
    InvalidNonceLength { expected: usize, got: usize },
    CryptoInitFailed,
    InvalidPublicKey,
    CryptoEncryptFailed(String),
    CryptoDecryptFailed(String),
    CryptoKdfParamsFailed(String),
    CryptoKdfFailed(String),

    // --------------------------------------------------
    // permissions / platform hardening
    // --------------------------------------------------
    KeyfilePermsEnforceFailed,
    KeyfilePermsInsufficient,
    PlatformHardeningFailed,
}

impl AppError {
    pub fn user_msg(&self) -> UserMsg {
        use AppError::*;

        let mut kind = UserMsgKind::Error;
        let detail = Some(self.to_string());

        let short: &'static str = match self {
            // generic
            Io(_) => "File operation failed.",
            Msg(_) => "Operation failed.",
            InternalStateLockFailed | StateLockPoisoned => "Internal state lock failed.",
            InvalidPath => "Invalid path.",
            AppLocked => "App is locked.",
            NoActiveKeySelected => "No active key selected.",
            KeyfileMissingOrCorrupted => "Keyfile missing or corrupted.",

            // keyfile fs
            KeyfileFsReadFailed(_) => "Failed to read keyfile.",
            KeyfileFsInvalidJson(_) => "Keyfile is corrupted.",
            KeyfileFsUnsupportedVersion { .. } => "Unsupported keyfile version.",
            KeyfileFsMarkerMismatch => "Not a Sigillium keyfile.",
            KeyfileFsTooLarge { .. } => "Keyfile is too large.",
            KeyfileFsWriteFailed(_) => "Failed to write keyfile.",
            KeyfileFsSyncFailed(_) => "Failed to sync keyfile.",
            KeyfileFsRenameFailed(_) => "Failed to replace keyfile.",
            KeyfileFsBusy => "Keyfile is busy.",
            KeyfileFsLockFailed(_) => "Failed to acquire keyfile lock.",
            KeyfileFsBackupFailed(_) => "Failed to preserve corrupted keyfile.",
            KeyfileFsBackupExhausted => "Too many corrupted keyfile backups.",
            KeyfileFsRemoveFailed(_) => "Failed to remove keyfile intent marker.",
            KeyfileFsIntentSerializeFailed(_) => "Failed to prepare keyfile operation.",

            // input
            EmptyPayload => "Payload is required.",
            EmptyMnemonic => "Mnemonic is required.",
            InvalidMnemonic => "Invalid mnemonic.",
            EmptyLabel => "Label is required.",
            InvalidStandardDomain => "Invalid domain.",

            // json / schema
            SchemaRequired => "Schema is required.",
            InvalidJson(_) => "Invalid JSON.",
            JsonTooLarge => "JSON too large.",
            InvalidSchemaJson(_) => "Invalid schema JSON.",
            SchemaTooLarge => "Schema too large.",
            SchemaWrongDraft => "Schema draft mismatch.",
            JsonNotObject => "JSON value must be an object.",
            JsonCanonicalize(_) => "JSON canonicalization failed.",
            SchemaCompile(_) => "Schema compilation failed.",
            SchemaValidation(_) => "Schema validation failed.",

            // keyfile logical
            KeyfileMissing => "Keyfile not found.",
            KeyfileCorrupt | KeyfileStructCorrupted => "Keyfile is corrupt.",
            KeyfileAlreadyExists => "Keyfile already exists.",
            KeyfileVersionUnsupported => "Keyfile version unsupported.",
            KeyfileFormatUnsupported => "Keyfile format unsupported.",
            KeyfileAppMismatch => "Keyfile app mismatch.",
            KeyfileMacMissing => "Keyfile MAC missing.",
            KeyfileMacInvalid => "Keyfile MAC invalid.",
            KeyfileKeyMissing => "Key missing in keyfile.",
            KeyfileKeyIdNotFound => "Key not found.",
            KeyfileAssociatedKeyIdAlreadySet => "Associated key ID already set.",
            KeyfileDomainMismatch => "Key domain mismatch.",
            KeyfilePublicKeyMismatch => "Public key mismatch.",

            // encoding
            InvalidPublicKeyHex => "Invalid public key encoding.",
            InvalidPublicKeyLength => "Invalid public key length.",
            InvalidSignatureBase64 => "Invalid signature encoding.",
            InvalidSignatureLength => "Invalid signature length.",
            InvalidNonceBase64(_) => "Invalid nonce encoding.",
            InvalidCiphertextBase64(_) => "Invalid ciphertext encoding.",
            InvalidUtf8(_) => "Invalid UTF-8.",

            // crypto
            InvalidAad(_) => "Internal cryptographic context error.",
            InvalidSaltLength { .. } => "Invalid salt length.",
            InvalidNonceLength { .. } => "Invalid nonce length.",
            CryptoInitFailed => "Cryptographic initialization failed.",
            InvalidPublicKey => "Invalid public key.",
            CryptoEncryptFailed(_) => "Encryption failed.",
            CryptoDecryptFailed(_) => "Decryption failed.",
            CryptoKdfParamsFailed(_) | CryptoKdfFailed(_) => "Key derivation failed.",

            // platform
            KeyfilePermsEnforceFailed => "Failed to enforce keyfile permissions.",
            KeyfilePermsInsufficient => "Keyfile permissions are insufficient.",
            PlatformHardeningFailed => {
                kind = UserMsgKind::Warn;
                "Some security hardening steps failed."
            }
        };

        UserMsg {
            kind,
            short,
            detail,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AppError::*;

        match self {
            Io(e) => write!(f, "io error: {e}"),
            Msg(s) => write!(f, "{s}"),
            InternalStateLockFailed => write!(f, "internal state lock failed"),
            StateLockPoisoned => write!(f, "state lock poisoned"),
            InvalidPath => write!(f, "invalid path"),
            AppLocked => write!(f, "app is locked"),
            NoActiveKeySelected => write!(f, "no active key selected"),
            KeyfileMissingOrCorrupted => write!(f, "keyfile missing or corrupted"),

            KeyfileFsReadFailed(s) => write!(f, "keyfile read failed: {s}"),
            KeyfileFsInvalidJson(s) => write!(f, "keyfile invalid json: {s}"),
            KeyfileFsUnsupportedVersion { got, expected } => {
                write!(
                    f,
                    "unsupported keyfile version: got={got} expected={expected}"
                )
            }
            KeyfileFsMarkerMismatch => write!(f, "keyfile marker mismatch"),
            KeyfileFsTooLarge { bytes, max } => write!(f, "keyfile too large: {bytes} > {max}"),
            KeyfileFsWriteFailed(s) => write!(f, "keyfile write failed: {s}"),
            KeyfileFsSyncFailed(s) => write!(f, "keyfile sync failed: {s}"),
            KeyfileFsRenameFailed(s) => write!(f, "keyfile rename failed: {s}"),
            KeyfileFsBusy => write!(f, "keyfile busy"),
            KeyfileFsLockFailed(s) => write!(f, "keyfile lock failed: {s}"),
            KeyfileFsBackupFailed(s) => write!(f, "keyfile backup failed: {s}"),
            KeyfileFsBackupExhausted => write!(f, "keyfile backup exhausted"),
            KeyfileFsRemoveFailed(s) => write!(f, "keyfile remove failed: {s}"),
            KeyfileFsIntentSerializeFailed(s) => write!(f, "keyfile intent serialize failed: {s}"),

            EmptyPayload => write!(f, "empty payload"),
            EmptyMnemonic => write!(f, "empty mnemonic"),
            InvalidMnemonic => write!(f, "invalid mnemonic"),
            EmptyLabel => write!(f, "empty label"),
            InvalidStandardDomain => write!(f, "invalid standard domain"),

            InvalidJson(s) => write!(f, "invalid json: {s}"),
            JsonTooLarge => write!(f, "json too large"),
            SchemaRequired => write!(f, "schema required"),
            InvalidSchemaJson(s) => write!(f, "invalid schema json: {s}"),
            SchemaTooLarge => write!(f, "schema too large"),
            SchemaWrongDraft => write!(f, "schema wrong draft"),
            JsonNotObject => write!(f, "json not object"),
            JsonCanonicalize(s) => write!(f, "json canonicalization failed: {s}"),
            SchemaCompile(s) => write!(f, "schema compile failed: {s}"),
            SchemaValidation(s) => write!(f, "schema validation failed: {s}"),

            KeyfileMissing => write!(f, "keyfile missing"),
            KeyfileCorrupt => write!(f, "keyfile corrupt"),
            KeyfileStructCorrupted => write!(f, "keyfile structure corrupted"),
            KeyfileAlreadyExists => write!(f, "keyfile already exists"),
            KeyfileVersionUnsupported => write!(f, "keyfile version unsupported"),
            KeyfileFormatUnsupported => write!(f, "keyfile format unsupported"),
            KeyfileAppMismatch => write!(f, "keyfile app mismatch"),
            KeyfileMacMissing => write!(f, "keyfile mac missing"),
            KeyfileMacInvalid => write!(f, "keyfile mac invalid"),
            KeyfileKeyMissing => write!(f, "key missing in keyfile"),
            KeyfileKeyIdNotFound => write!(f, "key id not found"),
            KeyfileAssociatedKeyIdAlreadySet => write!(f, "associated key id already set"),
            KeyfileDomainMismatch => write!(f, "key domain mismatch"),
            KeyfilePublicKeyMismatch => write!(f, "public key mismatch"),

            InvalidPublicKeyHex => write!(f, "invalid public key hex"),
            InvalidPublicKeyLength => write!(f, "invalid public key length"),
            InvalidSignatureBase64 => write!(f, "invalid signature base64"),
            InvalidSignatureLength => write!(f, "invalid signature length"),
            InvalidNonceBase64(s) => write!(f, "invalid nonce base64: {s}"),
            InvalidCiphertextBase64(s) => write!(f, "invalid ciphertext base64: {s}"),
            InvalidUtf8(s) => write!(f, "invalid utf-8: {s}"),

            InvalidAad(s) => write!(f, "invalid aad: {s}"),
            InvalidSaltLength { len } => write!(f, "invalid salt length: {len}"),
            InvalidNonceLength { expected, got } => {
                write!(f, "invalid nonce length: expected {expected}, got {got}")
            }
            CryptoInitFailed => write!(f, "crypto init failed"),
            InvalidPublicKey => write!(f, "invalid public key"),
            CryptoEncryptFailed(s) => write!(f, "encrypt failed: {s}"),
            CryptoDecryptFailed(s) => write!(f, "decrypt failed: {s}"),
            CryptoKdfParamsFailed(s) => write!(f, "kdf params failed: {s}"),
            CryptoKdfFailed(s) => write!(f, "kdf failed: {s}"),

            KeyfilePermsEnforceFailed => write!(f, "failed to enforce keyfile permissions"),
            KeyfilePermsInsufficient => write!(f, "insufficient keyfile permissions"),
            PlatformHardeningFailed => write!(f, "platform hardening failure"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e)
    }
}
