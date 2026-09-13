#![forbid(unsafe_code)]

use std::collections::HashSet;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    ErrorCode, KEYRING_SIGNING_DOMAIN, MAX_MANIFEST_BYTES, MaintenanceError,
    OFFLINE_ROOT_PUBLIC_KEY, Result, canonical_json, decode_lower_hex, parse_canonical, sha256,
    signing_message, valid_identifier,
};

const KEYRING_KIND: &str = "7launcher-maintenance-keyring-v1";
const KEYRING_SCHEMA: u64 = 1;
const MAX_RELEASE_KEYS: usize = 64;
const MAX_SIGNER_THUMBPRINTS: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseKey {
    pub key_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Keyring {
    pub authenticode_signer_thumbprints: Vec<String>,
    pub kind: String,
    pub release_keys: Vec<ReleaseKey>,
    pub schema: u64,
    pub signature: String,
    pub version: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KeyringAcceptance {
    pub minimum_version: u64,
    pub current_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct VerifiedKeyring {
    keyring: Keyring,
    digest: [u8; 32],
}

impl VerifiedKeyring {
    #[must_use]
    pub const fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn release_verifying_key(&self, key_id: &str) -> Result<VerifyingKey> {
        let release_key = self
            .keyring
            .release_keys
            .iter()
            .find(|entry| entry.key_id == key_id)
            .ok_or_else(|| {
                MaintenanceError::new(
                    ErrorCode::TrustUnknownKey,
                    "file set references an unknown release key",
                )
            })?;
        let bytes = decode_lower_hex::<32>(&release_key.public_key, ErrorCode::TrustUnknownKey)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| {
            MaintenanceError::new(ErrorCode::TrustUnknownKey, "release public key is invalid")
        })
    }
}

pub fn verify_keyring(bytes: &[u8], acceptance: KeyringAcceptance) -> Result<VerifiedKeyring> {
    verify_keyring_with_root(bytes, acceptance, &OFFLINE_ROOT_PUBLIC_KEY)
}

/// Verifies a keyring against an explicit trust anchor.
///
/// Production callers use [`verify_keyring`]. This entry point keeps deterministic
/// test vectors and offline release tooling independent from the private production root.
pub fn verify_keyring_with_root(
    bytes: &[u8],
    acceptance: KeyringAcceptance,
    root_public_key: &[u8; 32],
) -> Result<VerifiedKeyring> {
    let keyring: Keyring = parse_canonical(bytes, MAX_MANIFEST_BYTES)?;
    validate_keyring_shape(&keyring)?;

    let payload = json!({
        "authenticodeSignerThumbprints": keyring.authenticode_signer_thumbprints,
        "kind": keyring.kind,
        "releaseKeys": keyring.release_keys,
        "schema": keyring.schema,
        "version": keyring.version,
    });
    let payload_bytes = canonical_json(&payload)?;
    let signature_bytes = decode_lower_hex::<64>(&keyring.signature, ErrorCode::TrustSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let root_key = VerifyingKey::from_bytes(root_public_key).map_err(|_| {
        MaintenanceError::new(ErrorCode::TrustSignature, "root public key is invalid")
    })?;
    root_key
        .verify_strict(
            &signing_message(KEYRING_SIGNING_DOMAIN, &payload_bytes),
            &signature,
        )
        .map_err(|_| {
            MaintenanceError::new(ErrorCode::TrustSignature, "keyring signature is invalid")
        })?;

    let digest = sha256(bytes);
    if keyring.version < acceptance.minimum_version {
        return Err(MaintenanceError::new(
            ErrorCode::KeyringRollback,
            "keyring version is older than the accepted version",
        ));
    }
    if keyring.version == acceptance.minimum_version
        && acceptance.minimum_version != 0
        && acceptance
            .current_digest
            .is_some_and(|current| current != digest)
    {
        return Err(MaintenanceError::new(
            ErrorCode::KeyringConflict,
            "accepted keyring version has a different digest",
        ));
    }

    Ok(VerifiedKeyring { keyring, digest })
}

fn validate_keyring_shape(keyring: &Keyring) -> Result<()> {
    if keyring.kind != KEYRING_KIND || keyring.schema != KEYRING_SCHEMA || keyring.version == 0 {
        return Err(MaintenanceError::new(
            ErrorCode::JsonInvalid,
            "keyring kind, schema, or version is unsupported",
        ));
    }
    if keyring.release_keys.is_empty() || keyring.release_keys.len() > MAX_RELEASE_KEYS {
        return Err(MaintenanceError::new(
            ErrorCode::FileSetLimit,
            "keyring release-key count is outside the allowed range",
        ));
    }
    if keyring.authenticode_signer_thumbprints.len() > MAX_SIGNER_THUMBPRINTS {
        return Err(MaintenanceError::new(
            ErrorCode::FileSetLimit,
            "keyring signer-thumbprint count exceeds the bound",
        ));
    }

    let mut key_ids = HashSet::with_capacity(keyring.release_keys.len());
    for release_key in &keyring.release_keys {
        if !valid_identifier(&release_key.key_id) || !key_ids.insert(release_key.key_id.as_str()) {
            return Err(MaintenanceError::new(
                ErrorCode::JsonInvalid,
                "release key IDs must be valid and unique",
            ));
        }
        let public_key =
            decode_lower_hex::<32>(&release_key.public_key, ErrorCode::TrustUnknownKey)?;
        VerifyingKey::from_bytes(&public_key).map_err(|_| {
            MaintenanceError::new(ErrorCode::TrustUnknownKey, "release public key is invalid")
        })?;
    }

    let mut signer_thumbprints = HashSet::new();
    for thumbprint in &keyring.authenticode_signer_thumbprints {
        if !matches!(thumbprint.len(), 40 | 64)
            || !thumbprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !signer_thumbprints.insert(thumbprint.as_str())
        {
            return Err(MaintenanceError::new(
                ErrorCode::JsonInvalid,
                "signer thumbprints must be unique lowercase SHA-1 or SHA-256 hex",
            ));
        }
    }
    Ok(())
}
