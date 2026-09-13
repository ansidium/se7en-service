#![deny(unsafe_code)]

//! Narrow, offline maintenance contract shared by the Windows service and its clients.

use std::{error::Error, fmt};

use serde_json::Value;
use sha2::{Digest, Sha256};

pub mod file_set;
pub mod protocol;
pub mod registry_scopes;
pub mod registry_set;
pub mod roots;
pub mod service_upgrade;
pub mod transaction;
pub mod trust;
#[cfg(windows)]
pub mod windows;

pub use file_set::{
    FileEntry, FileSet, FileSetAcceptance, GenerationRecord, VerifiedFileSet, verify_file_set,
};
pub use registry_scopes::{RegisteredRegistryScope, RegistryScopeRegistry, RegistryView};
pub use registry_set::{
    AllowedRegistryValue, RegistrySet, RegistrySetAcceptance, RegistryValue, RegistryValueKind,
    VerifiedRegistrySet, verify_registry_set,
};
pub use roots::{DirectoryIdentity, RegisteredRoot, RootRegistry};
pub use transaction::{
    CommitResult, LocalTransactionPlatform, MutationBoundary, MutationEvent, MutationFaultInjector,
    MutationKind, PreparedJob, RecoveryResult, TargetSnapshot, TransactionPlatform,
    TransactionPolicy, commit_file_set, prepare_file_set, recover_incomplete,
    recover_incomplete_with_policy,
};
pub use trust::{
    Keyring, KeyringAcceptance, ReleaseKey, VerifiedKeyring, verify_keyring,
    verify_keyring_with_root,
};

pub const MAX_IPC_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 1024;
/// rootId + '-' + decimal u64 generation + '-' + lowercase SHA-256 digest.
pub const MAX_JOB_ID_BYTES: usize = 64 + 1 + 20 + 1 + 64;
pub const MAX_FILE_ENTRIES: usize = 100_000;
pub const MAX_DECLARED_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024 * 1024;
pub const MAX_REGISTRY_SET_BYTES: usize = 64 * 1024;
pub const MAX_REGISTRY_ENTRIES: usize = 32;
pub const MAX_REGISTRY_VALUE_NAME_BYTES: usize = 256;
pub const MAX_REGISTRY_STRING_BYTES: usize = 16 * 1024;
pub const MAX_REGISTRY_BINARY_BYTES: usize = 16 * 1024;

pub const KEYRING_SIGNING_DOMAIN: &[u8] = b"7launcher-maintenance-keyring-v1";
pub const FILE_SET_SIGNING_DOMAIN: &[u8] = b"7launcher-file-set-v1";
pub const REGISTRY_SET_SIGNING_DOMAIN: &[u8] = b"7launcher-registry-set-v1";

/// Production offline trust anchor for replaceable maintenance keyrings.
/// The private seed is stored outside the repository and is not required at runtime.
pub const OFFLINE_ROOT_PUBLIC_KEY: [u8; 32] = [
    0x07, 0x63, 0xa6, 0xdd, 0x11, 0x62, 0x94, 0x8b, 0xbf, 0xb9, 0x9b, 0x0b, 0x7b, 0x0f, 0xfd, 0x98,
    0xfe, 0xf3, 0x74, 0x0a, 0x75, 0xb5, 0x50, 0x00, 0xf1, 0x04, 0xbd, 0xf7, 0x1a, 0xde, 0xc8, 0xd6,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    JsonInvalid,
    JsonNonCanonical,
    ManifestTooLarge,
    TrustSignature,
    TrustUnknownKey,
    KeyringRollback,
    KeyringConflict,
    FileSetRollback,
    GenerationConflict,
    FileSetPath,
    FileSetLimit,
    FileSetHash,
    RegistrySetRollback,
    RegistrySetLimit,
    RegistryScopeInvalid,
    RegistryScopeNotFound,
    RegistryScopeUnauthorized,
    RegistryValueInvalid,
    RegistryIo,
    ProductMismatch,
    ProtocolInvalid,
    ProtocolVersion,
    ProtocolTooLarge,
    RootInvalid,
    RootNotFound,
    RootUnauthorized,
    RootIdentity,
    StagingInvalid,
    InsufficientSpace,
    ServiceBusy,
    TransactionConflict,
    TransactionIo,
    TransactionState,
    RecoveryIncomplete,
}

impl ErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JsonInvalid => "E_JSON_INVALID",
            Self::JsonNonCanonical => "E_JSON_NON_CANONICAL",
            Self::ManifestTooLarge => "E_MANIFEST_TOO_LARGE",
            Self::TrustSignature => "E_TRUST_SIGNATURE",
            Self::TrustUnknownKey => "E_TRUST_UNKNOWN_KEY",
            Self::KeyringRollback => "E_KEYRING_ROLLBACK",
            Self::KeyringConflict => "E_KEYRING_CONFLICT",
            Self::FileSetRollback => "E_FILESET_ROLLBACK",
            Self::GenerationConflict => "E_GENERATION_CONFLICT",
            Self::FileSetPath => "E_FILESET_PATH",
            Self::FileSetLimit => "E_FILESET_LIMIT",
            Self::FileSetHash => "E_FILESET_HASH",
            Self::RegistrySetRollback => "E_REGISTRYSET_ROLLBACK",
            Self::RegistrySetLimit => "E_REGISTRYSET_LIMIT",
            Self::RegistryScopeInvalid => "E_REGISTRY_SCOPE_INVALID",
            Self::RegistryScopeNotFound => "E_REGISTRY_SCOPE_NOT_FOUND",
            Self::RegistryScopeUnauthorized => "E_REGISTRY_SCOPE_UNAUTHORIZED",
            Self::RegistryValueInvalid => "E_REGISTRY_VALUE_INVALID",
            Self::RegistryIo => "E_REGISTRY_IO",
            Self::ProductMismatch => "E_PRODUCT_MISMATCH",
            Self::ProtocolInvalid => "E_PROTOCOL_INVALID",
            Self::ProtocolVersion => "E_PROTOCOL_VERSION",
            Self::ProtocolTooLarge => "E_PROTOCOL_TOO_LARGE",
            Self::RootInvalid => "E_ROOT_INVALID",
            Self::RootNotFound => "E_ROOT_NOT_FOUND",
            Self::RootUnauthorized => "E_ROOT_UNAUTHORIZED",
            Self::RootIdentity => "E_ROOT_IDENTITY",
            Self::StagingInvalid => "E_STAGING_INVALID",
            Self::InsufficientSpace => "E_INSUFFICIENT_SPACE",
            Self::ServiceBusy => "E_SERVICE_BUSY",
            Self::TransactionConflict => "E_TRANSACTION_CONFLICT",
            Self::TransactionIo => "E_TRANSACTION_IO",
            Self::TransactionState => "E_TRANSACTION_STATE",
            Self::RecoveryIncomplete => "E_RECOVERY_INCOMPLETE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceError {
    code: ErrorCode,
    detail: &'static str,
    platform_status: Option<u32>,
}

impl MaintenanceError {
    pub(crate) const fn new(code: ErrorCode, detail: &'static str) -> Self {
        Self {
            code,
            detail,
            platform_status: None,
        }
    }

    pub(crate) const fn with_platform_status(
        code: ErrorCode,
        detail: &'static str,
        platform_status: u32,
    ) -> Self {
        Self {
            code,
            detail,
            platform_status: Some(platform_status),
        }
    }

    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    #[must_use]
    pub(crate) const fn detail(&self) -> &'static str {
        self.detail
    }

    #[must_use]
    pub(crate) const fn platform_status(&self) -> Option<u32> {
        self.platform_status
    }

    /// Creates a stable fail-closed error for an external platform-policy implementation.
    #[must_use]
    pub const fn policy_rejection(code: ErrorCode) -> Self {
        Self {
            code,
            detail: "platform policy rejected the operation",
            platform_status: None,
        }
    }
}

impl fmt::Display for MaintenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)?;
        if let Some(status) = self.platform_status {
            write!(formatter, " (platform status {status})")?;
        }
        Ok(())
    }
}

impl Error for MaintenanceError {}

pub type Result<T> = std::result::Result<T, MaintenanceError>;

#[must_use]
pub fn signing_message(domain: &[u8], canonical_payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + 1 + canonical_payload.len());
    message.extend_from_slice(domain);
    message.push(0);
    message.extend_from_slice(canonical_payload);
    message
}

pub fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    write_canonical(value, &mut output)?;
    Ok(output)
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if number.as_u64().is_none() && number.as_i64().is_none() {
                return Err(MaintenanceError::new(
                    ErrorCode::JsonInvalid,
                    "floating-point JSON numbers are not supported",
                ));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(string) => serde_json::to_writer(output, string).map_err(|_| {
            MaintenanceError::new(ErrorCode::JsonInvalid, "could not encode JSON string")
        })?,
        Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            output.push(b'{');
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).map_err(|_| {
                    MaintenanceError::new(ErrorCode::JsonInvalid, "could not encode JSON key")
                })?;
                output.push(b':');
                let item = object.get(key).ok_or_else(|| {
                    MaintenanceError::new(ErrorCode::JsonInvalid, "JSON object changed while read")
                })?;
                write_canonical(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub(crate) fn parse_canonical<T>(bytes: &[u8], maximum: usize) -> Result<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    if bytes.len() > maximum {
        return Err(MaintenanceError::new(
            ErrorCode::ManifestTooLarge,
            "signed document exceeds the configured bound",
        ));
    }
    let parsed: T = serde_json::from_slice(bytes).map_err(|_| {
        MaintenanceError::new(ErrorCode::JsonInvalid, "signed document is not strict JSON")
    })?;
    let value = serde_json::to_value(&parsed).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::JsonInvalid,
            "signed document cannot be re-encoded",
        )
    })?;
    if canonical_json(&value)? != bytes {
        return Err(MaintenanceError::new(
            ErrorCode::JsonNonCanonical,
            "signed document bytes are not canonical",
        ));
    }
    Ok(parsed)
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn decode_lower_hex<const N: usize>(value: &str, code: ErrorCode) -> Result<[u8; N]> {
    if value.len() != N * 2 {
        return Err(MaintenanceError::new(
            code,
            "hexadecimal value has the wrong length",
        ));
    }
    let mut decoded = [0_u8; N];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for (index, pair) in pairs.iter().enumerate() {
        decoded[index] = (hex_nibble(pair[0], code)? << 4) | hex_nibble(pair[1], code)?;
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8, code: ErrorCode) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(MaintenanceError::new(
            code,
            "hexadecimal value must use lowercase ASCII",
        )),
    }
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

pub(crate) fn valid_job_identifier(value: &str) -> bool {
    if value.len() > MAX_JOB_ID_BYTES {
        return false;
    }
    let mut parts = value.rsplitn(3, '-');
    let Some(digest) = parts.next() else {
        return false;
    };
    let Some(generation_text) = parts.next() else {
        return false;
    };
    let Some(root_id) = parts.next() else {
        return false;
    };
    if !valid_identifier(root_id)
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return false;
    }
    generation_text
        .parse::<u64>()
        .is_ok_and(|generation| generation > 0 && generation.to_string() == generation_text)
}
