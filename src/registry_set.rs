#![forbid(unsafe_code)]

use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    ErrorCode, GenerationRecord, MAX_REGISTRY_BINARY_BYTES, MAX_REGISTRY_ENTRIES,
    MAX_REGISTRY_SET_BYTES, MAX_REGISTRY_STRING_BYTES, MAX_REGISTRY_VALUE_NAME_BYTES,
    MaintenanceError, REGISTRY_SET_SIGNING_DOMAIN, Result, canonical_json, decode_lower_hex,
    parse_canonical, sha256, signing_message, trust::VerifiedKeyring, valid_identifier,
};

const REGISTRY_SET_KIND: &str = "7launcher-registry-set-v1";
const REGISTRY_SET_SCHEMA: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryValueKind {
    String,
    Dword,
    Binary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowedRegistryValue {
    pub name: String,
    #[serde(rename = "type")]
    pub value_type: RegistryValueKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum RegistryValue {
    String { name: String, data: String },
    Dword { name: String, data: u32 },
    Binary { name: String, data: String },
}

impl RegistryValue {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::String { name, .. } | Self::Dword { name, .. } | Self::Binary { name, .. } => {
                name
            }
        }
    }

    #[must_use]
    pub const fn value_type(&self) -> RegistryValueKind {
        match self {
            Self::String { .. } => RegistryValueKind::String,
            Self::Dword { .. } => RegistryValueKind::Dword,
            Self::Binary { .. } => RegistryValueKind::Binary,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrySet {
    pub generation: u64,
    pub key_id: String,
    pub kind: String,
    pub product_id: String,
    pub schema: u64,
    pub scope_id: String,
    pub signature: String,
    pub values: Vec<RegistryValue>,
}

#[derive(Clone, Copy, Debug)]
pub struct RegistrySetAcceptance<'a> {
    pub allowed_values: &'a [AllowedRegistryValue],
    pub expected_product_id: &'a str,
    pub expected_scope_id: &'a str,
    pub previous: Option<GenerationRecord>,
}

#[derive(Clone, Debug)]
pub struct VerifiedRegistrySet {
    digest: [u8; 32],
    registry_set: RegistrySet,
}

impl VerifiedRegistrySet {
    #[must_use]
    pub const fn registry_set(&self) -> &RegistrySet {
        &self.registry_set
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

pub fn verify_registry_set(
    bytes: &[u8],
    keyring: &VerifiedKeyring,
    acceptance: RegistrySetAcceptance<'_>,
) -> Result<VerifiedRegistrySet> {
    let registry_set: RegistrySet = parse_canonical(bytes, MAX_REGISTRY_SET_BYTES)?;
    if registry_set.kind != REGISTRY_SET_KIND || registry_set.schema != REGISTRY_SET_SCHEMA {
        return Err(MaintenanceError::new(
            ErrorCode::JsonInvalid,
            "registry-set kind or schema is unsupported",
        ));
    }
    if !valid_identifier(&registry_set.key_id) {
        return Err(MaintenanceError::new(
            ErrorCode::JsonInvalid,
            "registry-set key ID is invalid",
        ));
    }

    let payload = json!({
        "generation": registry_set.generation,
        "keyId": registry_set.key_id,
        "kind": registry_set.kind,
        "productId": registry_set.product_id,
        "schema": registry_set.schema,
        "scopeId": registry_set.scope_id,
        "values": registry_set.values,
    });
    let payload_bytes = canonical_json(&payload)?;
    let signature_bytes =
        decode_lower_hex::<64>(&registry_set.signature, ErrorCode::TrustSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    keyring
        .release_verifying_key(&registry_set.key_id)?
        .verify_strict(
            &signing_message(REGISTRY_SET_SIGNING_DOMAIN, &payload_bytes),
            &signature,
        )
        .map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TrustSignature,
                "registry-set signature is invalid",
            )
        })?;

    validate_registry_set(&registry_set, acceptance)?;
    let digest = sha256(bytes);
    if let Some(previous) = acceptance.previous {
        if registry_set.generation < previous.generation {
            return Err(MaintenanceError::new(
                ErrorCode::RegistrySetRollback,
                "registry-set generation is older than the accepted generation",
            ));
        }
        if registry_set.generation == previous.generation && digest != previous.digest {
            return Err(MaintenanceError::new(
                ErrorCode::GenerationConflict,
                "registry-set generation was reused with another digest",
            ));
        }
    }

    Ok(VerifiedRegistrySet {
        digest,
        registry_set,
    })
}

fn validate_registry_set(
    registry_set: &RegistrySet,
    acceptance: RegistrySetAcceptance<'_>,
) -> Result<()> {
    if registry_set.generation == 0
        || !valid_identifier(&registry_set.product_id)
        || !valid_identifier(&registry_set.scope_id)
    {
        return Err(MaintenanceError::new(
            ErrorCode::JsonInvalid,
            "registry-set generation, product ID, or scope ID is invalid",
        ));
    }
    if registry_set.product_id != acceptance.expected_product_id {
        return Err(MaintenanceError::new(
            ErrorCode::ProductMismatch,
            "registry set does not belong to the registered product",
        ));
    }
    if registry_set.scope_id != acceptance.expected_scope_id {
        return Err(MaintenanceError::new(
            ErrorCode::RegistryScopeInvalid,
            "registry set does not belong to the registered scope",
        ));
    }
    if registry_set.values.is_empty() || registry_set.values.len() > MAX_REGISTRY_ENTRIES {
        return Err(MaintenanceError::new(
            ErrorCode::RegistrySetLimit,
            "registry-set value count is outside the allowed range",
        ));
    }

    let mut names = HashSet::with_capacity(registry_set.values.len());
    for value in &registry_set.values {
        validate_registry_value_name(value.name())?;
        if !names.insert(value.name().to_lowercase()) {
            return Err(MaintenanceError::new(
                ErrorCode::RegistryValueInvalid,
                "registry-set value names must be unique",
            ));
        }
        if let RegistryValue::String { data, .. } = value
            && (data.len() > MAX_REGISTRY_STRING_BYTES || data.chars().any(|item| item == '\0'))
        {
            return Err(MaintenanceError::new(
                ErrorCode::RegistrySetLimit,
                "registry string data exceeds the bound or contains NUL",
            ));
        }
        if let RegistryValue::Binary { data, .. } = value {
            decode_registry_binary(data)?;
        }
        let allowed = acceptance.allowed_values.iter().any(|candidate| {
            candidate.name.eq_ignore_ascii_case(value.name())
                && candidate.value_type == value.value_type()
        });
        if !allowed {
            return Err(MaintenanceError::new(
                ErrorCode::RegistryScopeUnauthorized,
                "registry-set value is outside the registered allowlist",
            ));
        }
    }
    Ok(())
}

pub(crate) fn decode_registry_binary(data: &str) -> Result<Vec<u8>> {
    const MAX_ENCODED_BYTES: usize = MAX_REGISTRY_BINARY_BYTES.div_ceil(3) * 4;
    if data.len() > MAX_ENCODED_BYTES || !data.is_ascii() {
        return Err(MaintenanceError::new(
            ErrorCode::RegistrySetLimit,
            "registry binary data exceeds the encoded bound",
        ));
    }
    let decoded = BASE64_STANDARD.decode(data).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::JsonInvalid,
            "registry binary data is not valid canonical base64",
        )
    })?;
    if decoded.len() > MAX_REGISTRY_BINARY_BYTES {
        return Err(MaintenanceError::new(
            ErrorCode::RegistrySetLimit,
            "registry binary data exceeds the decoded bound",
        ));
    }
    if BASE64_STANDARD.encode(&decoded) != data {
        return Err(MaintenanceError::new(
            ErrorCode::JsonInvalid,
            "registry binary data is not canonical base64",
        ));
    }
    Ok(decoded)
}

pub fn validate_allowed_registry_values(values: &[AllowedRegistryValue]) -> Result<()> {
    if values.is_empty() || values.len() > MAX_REGISTRY_ENTRIES {
        return Err(MaintenanceError::new(
            ErrorCode::RegistrySetLimit,
            "registry scope allowlist is outside the allowed range",
        ));
    }
    let mut names = HashSet::with_capacity(values.len());
    for value in values {
        validate_registry_value_name(&value.name)?;
        if !names.insert(value.name.to_lowercase()) {
            return Err(MaintenanceError::new(
                ErrorCode::RegistryValueInvalid,
                "registry scope value names must be unique",
            ));
        }
    }
    Ok(())
}

fn validate_registry_value_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_REGISTRY_VALUE_NAME_BYTES
        || value
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        Err(MaintenanceError::new(
            ErrorCode::RegistryValueInvalid,
            "registry value name is invalid",
        ))
    } else {
        Ok(())
    }
}
