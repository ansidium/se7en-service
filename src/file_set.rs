#![forbid(unsafe_code)]

use std::collections::HashSet;

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    ErrorCode, FILE_SET_SIGNING_DOMAIN, MAX_DECLARED_PAYLOAD_BYTES, MAX_FILE_ENTRIES,
    MAX_MANIFEST_BYTES, MAX_PATH_BYTES, MaintenanceError, Result, canonical_json, decode_lower_hex,
    parse_canonical, sha256, signing_message, trust::VerifiedKeyring, valid_identifier,
};

const FILE_SET_KIND: &str = "7launcher-file-set-v1";
const FILE_SET_SCHEMA: u64 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileSet {
    pub files: Vec<FileEntry>,
    pub generation: u64,
    pub key_id: String,
    pub kind: String,
    pub product_id: String,
    pub remove_files: Vec<String>,
    pub schema: u64,
    pub signature: String,
}

#[derive(Clone, Copy, Debug)]
pub struct GenerationRecord {
    pub generation: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub struct FileSetAcceptance<'a> {
    pub expected_product_id: &'a str,
    pub previous: Option<GenerationRecord>,
}

#[derive(Clone, Debug)]
pub struct VerifiedFileSet {
    file_set: FileSet,
    digest: [u8; 32],
}

impl VerifiedFileSet {
    #[must_use]
    pub const fn file_set(&self) -> &FileSet {
        &self.file_set
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

pub fn verify_file_set(
    bytes: &[u8],
    keyring: &VerifiedKeyring,
    acceptance: FileSetAcceptance<'_>,
) -> Result<VerifiedFileSet> {
    let file_set: FileSet = parse_canonical(bytes, MAX_MANIFEST_BYTES)?;
    if file_set.kind != FILE_SET_KIND || file_set.schema != FILE_SET_SCHEMA {
        return Err(MaintenanceError::new(
            ErrorCode::JsonInvalid,
            "file-set kind or schema is unsupported",
        ));
    }
    if !valid_identifier(&file_set.key_id) {
        return Err(MaintenanceError::new(
            ErrorCode::JsonInvalid,
            "file-set key ID is invalid",
        ));
    }

    let payload = json!({
        "files": file_set.files,
        "generation": file_set.generation,
        "keyId": file_set.key_id,
        "kind": file_set.kind,
        "productId": file_set.product_id,
        "removeFiles": file_set.remove_files,
        "schema": file_set.schema,
    });
    let payload_bytes = canonical_json(&payload)?;
    let signature_bytes = decode_lower_hex::<64>(&file_set.signature, ErrorCode::TrustSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    keyring
        .release_verifying_key(&file_set.key_id)?
        .verify_strict(
            &signing_message(FILE_SET_SIGNING_DOMAIN, &payload_bytes),
            &signature,
        )
        .map_err(|_| {
            MaintenanceError::new(ErrorCode::TrustSignature, "file-set signature is invalid")
        })?;

    validate_file_set(&file_set, acceptance.expected_product_id)?;
    let digest = sha256(bytes);
    if let Some(previous) = acceptance.previous {
        if file_set.generation < previous.generation {
            return Err(MaintenanceError::new(
                ErrorCode::FileSetRollback,
                "file-set generation is older than the accepted generation",
            ));
        }
        if file_set.generation == previous.generation && digest != previous.digest {
            return Err(MaintenanceError::new(
                ErrorCode::GenerationConflict,
                "file-set generation was reused with another digest",
            ));
        }
    }

    Ok(VerifiedFileSet { file_set, digest })
}

fn validate_file_set(file_set: &FileSet, expected_product_id: &str) -> Result<()> {
    if file_set.generation == 0 || !valid_identifier(&file_set.product_id) {
        return Err(MaintenanceError::new(
            ErrorCode::JsonInvalid,
            "file-set generation or product ID is invalid",
        ));
    }
    if file_set.product_id != expected_product_id {
        return Err(MaintenanceError::new(
            ErrorCode::ProductMismatch,
            "file set does not belong to the registered product",
        ));
    }
    let entry_count = file_set
        .files
        .len()
        .checked_add(file_set.remove_files.len())
        .ok_or_else(|| {
            MaintenanceError::new(ErrorCode::FileSetLimit, "file-set entry count overflowed")
        })?;
    if entry_count == 0 || entry_count > MAX_FILE_ENTRIES {
        return Err(MaintenanceError::new(
            ErrorCode::FileSetLimit,
            "file-set entry count is outside the allowed range",
        ));
    }

    let mut paths = HashSet::with_capacity(entry_count);
    let mut declared_size = 0_u64;
    for file in &file_set.files {
        validate_relative_path(&file.path)?;
        let normalized = file.path.to_lowercase();
        if !paths.insert(normalized) {
            return Err(MaintenanceError::new(
                ErrorCode::FileSetPath,
                "file-set paths must be unique",
            ));
        }
        decode_lower_hex::<32>(&file.sha256, ErrorCode::FileSetHash)?;
        declared_size = declared_size.checked_add(file.size).ok_or_else(|| {
            MaintenanceError::new(ErrorCode::FileSetLimit, "declared payload size overflowed")
        })?;
        if declared_size > MAX_DECLARED_PAYLOAD_BYTES {
            return Err(MaintenanceError::new(
                ErrorCode::FileSetLimit,
                "declared payload exceeds the configured bound",
            ));
        }
    }
    for path in &file_set.remove_files {
        validate_relative_path(path)?;
        if !paths.insert(path.to_lowercase()) {
            return Err(MaintenanceError::new(
                ErrorCode::FileSetPath,
                "create/replace and remove paths must not overlap",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path
            .bytes()
            .any(|byte| byte < 0x20 || b"<>:\"|?*".contains(&byte))
    {
        return Err(MaintenanceError::new(
            ErrorCode::FileSetPath,
            "file-set path is not a bounded canonical relative path",
        ));
    }

    for (index, component) in path.split('/').enumerate() {
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.ends_with([' ', '.'])
            || is_reserved_windows_name(component)
            || (index == 0 && component.eq_ignore_ascii_case(".7launcher-maintenance"))
        {
            return Err(MaintenanceError::new(
                ErrorCode::FileSetPath,
                "file-set path contains a forbidden component",
            ));
        }
    }
    Ok(())
}

fn is_reserved_windows_name(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(candidate, _)| candidate)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem.strip_prefix("COM").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || stem.strip_prefix("LPT").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
}
