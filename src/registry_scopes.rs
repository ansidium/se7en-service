#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    AllowedRegistryValue, ErrorCode, MaintenanceError, Result, canonical_json, parse_canonical,
    registry_set::validate_allowed_registry_values, valid_identifier,
};

const REGISTRY_SCOPE_REGISTRY_KIND: &str = "7launcher-maintenance-registry-scopes-v1";
const REGISTRY_SCOPE_REGISTRY_SCHEMA: u64 = 1;
const MAX_REGISTRY_SCOPE_REGISTRY_BYTES: usize = 1024 * 1024;
const MAX_REGISTERED_REGISTRY_SCOPES: usize = 256;
const MAX_REGISTRY_SUBKEY_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RegistryView {
    Registry32,
    Registry64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisteredRegistryScope {
    allowed_values: Vec<AllowedRegistryValue>,
    owner_sid: String,
    product_id: String,
    scope_id: String,
    subkey: String,
    view: RegistryView,
}

impl RegisteredRegistryScope {
    pub fn new(
        scope_id: &str,
        product_id: &str,
        view: RegistryView,
        subkey: &str,
        allowed_values: Vec<AllowedRegistryValue>,
        owner_sid: &str,
    ) -> Result<Self> {
        let scope = Self {
            allowed_values,
            owner_sid: owner_sid.to_owned(),
            product_id: product_id.to_owned(),
            scope_id: scope_id.to_owned(),
            subkey: subkey.to_owned(),
            view,
        };
        scope.validate_stored()?;
        Ok(scope)
    }

    #[must_use]
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    #[must_use]
    pub fn product_id(&self) -> &str {
        &self.product_id
    }

    #[must_use]
    pub const fn view(&self) -> RegistryView {
        self.view
    }

    #[must_use]
    pub fn subkey(&self) -> &str {
        &self.subkey
    }

    #[must_use]
    pub fn allowed_values(&self) -> &[AllowedRegistryValue] {
        &self.allowed_values
    }

    #[must_use]
    pub fn owner_sid(&self) -> &str {
        &self.owner_sid
    }

    fn validate_stored(&self) -> Result<()> {
        if !valid_identifier(&self.scope_id)
            || !valid_identifier(&self.product_id)
            || !valid_owner_sid(&self.owner_sid)
        {
            return Err(MaintenanceError::new(
                ErrorCode::RegistryScopeInvalid,
                "registry scope identity is invalid",
            ));
        }
        validate_registry_subkey(&self.subkey)?;
        validate_allowed_registry_values(&self.allowed_values)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryScopeRegistryDocument {
    kind: String,
    schema: u64,
    scopes: Vec<RegisteredRegistryScope>,
}

#[derive(Clone, Debug, Default)]
pub struct RegistryScopeRegistry {
    scopes: BTreeMap<String, RegisteredRegistryScope>,
}

impl RegistryScopeRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, scope: RegisteredRegistryScope) -> Result<()> {
        scope.validate_stored()?;
        if let Some(existing) = self.scopes.get(scope.scope_id()) {
            if existing == &scope {
                return Ok(());
            }
            return Err(MaintenanceError::new(
                ErrorCode::TransactionConflict,
                "registry scope ID is already registered with another policy",
            ));
        }
        if self.scopes.len() >= MAX_REGISTERED_REGISTRY_SCOPES {
            return Err(MaintenanceError::new(
                ErrorCode::RegistrySetLimit,
                "registered registry-scope count exceeds the bound",
            ));
        }
        self.scopes.insert(scope.scope_id.clone(), scope);
        Ok(())
    }

    pub fn unregister(
        &mut self,
        scope_id: &str,
        owner_sid: &str,
    ) -> Result<RegisteredRegistryScope> {
        let scope = self.resolve_owned(scope_id, owner_sid)?.clone();
        self.scopes.remove(scope_id).ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::RegistryScopeNotFound,
                "registry scope is not registered",
            )
        })?;
        Ok(scope)
    }

    pub fn resolve_owned(
        &self,
        scope_id: &str,
        owner_sid: &str,
    ) -> Result<&RegisteredRegistryScope> {
        let scope = self.scopes.get(scope_id).ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::RegistryScopeNotFound,
                "registry scope is not registered",
            )
        })?;
        if scope.owner_sid() != owner_sid {
            return Err(MaintenanceError::new(
                ErrorCode::RegistryScopeUnauthorized,
                "registry scope belongs to another user SID",
            ));
        }
        Ok(scope)
    }

    pub(crate) fn resolve_registered(&self, scope_id: &str) -> Result<&RegisteredRegistryScope> {
        self.scopes.get(scope_id).ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::RegistryScopeNotFound,
                "registry scope is not registered",
            )
        })
    }

    #[must_use]
    pub fn owned_scope_count(&self, owner_sid: &str) -> usize {
        self.scopes
            .values()
            .filter(|scope| scope.owner_sid() == owner_sid)
            .count()
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = match read_bounded(path, MAX_REGISTRY_SCOPE_REGISTRY_BYTES) {
            Ok(bytes) => bytes,
            Err(_) => read_bounded(&backup_path(path), MAX_REGISTRY_SCOPE_REGISTRY_BYTES).map_err(
                |_| {
                    MaintenanceError::new(
                        ErrorCode::RegistryScopeInvalid,
                        "registry-scope registry and backup cannot be read",
                    )
                },
            )?,
        };
        let document: RegistryScopeRegistryDocument =
            parse_canonical(&bytes, MAX_REGISTRY_SCOPE_REGISTRY_BYTES)?;
        if document.kind != REGISTRY_SCOPE_REGISTRY_KIND
            || document.schema != REGISTRY_SCOPE_REGISTRY_SCHEMA
            || document.scopes.len() > MAX_REGISTERED_REGISTRY_SCOPES
        {
            return Err(MaintenanceError::new(
                ErrorCode::RegistryScopeInvalid,
                "registry-scope registry schema or count is invalid",
            ));
        }
        let mut registry = Self::new();
        for scope in document.scopes {
            registry.register(scope)?;
        }
        Ok(registry)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let document = RegistryScopeRegistryDocument {
            kind: REGISTRY_SCOPE_REGISTRY_KIND.to_owned(),
            schema: REGISTRY_SCOPE_REGISTRY_SCHEMA,
            scopes: self.scopes.values().cloned().collect(),
        };
        let bytes = canonical_json(&serde_json::to_value(document).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::RegistryScopeInvalid,
                "registry-scope registry cannot be encoded",
            )
        })?)?;
        if bytes.len() > MAX_REGISTRY_SCOPE_REGISTRY_BYTES {
            return Err(MaintenanceError::new(
                ErrorCode::RegistrySetLimit,
                "registry-scope registry exceeds the bound",
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::RegistryScopeInvalid,
                "registry-scope registry has no parent",
            )
        })?;
        fs::create_dir_all(parent).map_err(registry_io)?;
        let temporary = temporary_path(path);
        let backup = backup_path(path);
        let mut output = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .map_err(registry_io)?;
        output.write_all(&bytes).map_err(registry_io)?;
        output.sync_all().map_err(registry_io)?;

        if path.exists() {
            if backup.exists() {
                fs::remove_file(&backup).map_err(registry_io)?;
            }
            fs::rename(path, &backup).map_err(registry_io)?;
        }
        if fs::rename(&temporary, path).is_err() {
            if backup.exists() {
                let _restore_result = fs::rename(&backup, path);
            }
            return Err(registry_io(std::io::Error::other(
                "registry-scope commit rename failed",
            )));
        }
        if backup.exists() {
            fs::remove_file(backup).map_err(registry_io)?;
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .and_then(|file| file.sync_all())
            .map_err(registry_io)
    }
}

pub(crate) fn validate_registry_subkey(value: &str) -> Result<()> {
    if value.len() > MAX_REGISTRY_SUBKEY_BYTES
        || !value.starts_with("SOFTWARE\\")
        || value.ends_with('\\')
        || value.contains('/')
        || value
            .chars()
            .any(|character| character == '\0' || character.is_control())
        || value
            .split('\\')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(MaintenanceError::new(
            ErrorCode::RegistryScopeInvalid,
            "registry subkey is not a canonical HKLM SOFTWARE path",
        ));
    }
    let folded = value.to_ascii_lowercase();
    const FORBIDDEN_PREFIXES: [&str; 6] = [
        "software\\classes",
        "software\\microsoft\\windows",
        "software\\policies",
        "software\\wow6432node\\classes",
        "software\\wow6432node\\microsoft\\windows",
        "software\\wow6432node\\policies",
    ];
    if folded.starts_with("software\\wow6432node\\")
        || FORBIDDEN_PREFIXES.iter().any(|prefix| {
            folded == *prefix
                || folded
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with('\\'))
        })
    {
        return Err(MaintenanceError::new(
            ErrorCode::RegistryScopeUnauthorized,
            "registry subkey belongs to a protected Windows policy or persistence area",
        ));
    }
    Ok(())
}

fn valid_owner_sid(value: &str) -> bool {
    value.starts_with("S-1-")
        && value.len() <= 184
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
}

fn temporary_path(path: &Path) -> PathBuf {
    path.with_extension("new")
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("bak")
}

fn read_bounded(path: &Path, maximum: usize) -> std::io::Result<Vec<u8>> {
    let file = OpenOptions::new().read(true).open(path)?;
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "registry-scope registry exceeds the configured bound",
        ));
    }
    Ok(bytes)
}

fn registry_io(_error: std::io::Error) -> MaintenanceError {
    MaintenanceError::new(ErrorCode::RegistryIo, "registry-scope state I/O failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RegistryValueKind;

    fn allowed() -> Vec<AllowedRegistryValue> {
        vec![AllowedRegistryValue {
            name: "Language".to_owned(),
            value_type: RegistryValueKind::String,
        }]
    }

    #[test]
    fn scope_accepts_game_vendor_key_and_rejects_windows_persistence_areas() {
        RegisteredRegistryScope::new(
            "sample-language",
            "sample-app",
            RegistryView::Registry32,
            r"SOFTWARE\ExampleVendor\SampleApp",
            allowed(),
            "S-1-5-21-1000",
        )
        .expect("game vendor key is allowed");

        for forbidden in [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Policies\SE7EN",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        ] {
            assert_eq!(
                RegisteredRegistryScope::new(
                    "forbidden-scope",
                    "sample-app",
                    RegistryView::Registry64,
                    forbidden,
                    allowed(),
                    "S-1-5-21-1000",
                )
                .expect_err("Windows persistence areas fail closed")
                .code(),
                ErrorCode::RegistryScopeUnauthorized
            );
        }
    }

    #[test]
    fn registry_resolves_scopes_only_for_the_bound_owner() {
        let mut registry = RegistryScopeRegistry::new();
        registry
            .register(
                RegisteredRegistryScope::new(
                    "sample-language",
                    "sample-app",
                    RegistryView::Registry32,
                    r"SOFTWARE\ExampleVendor\SampleApp",
                    allowed(),
                    "S-1-5-21-1000",
                )
                .expect("valid scope"),
            )
            .expect("register scope");
        assert_eq!(
            registry
                .resolve_owned("sample-language", "S-1-5-21-2000")
                .expect_err("another SID is rejected")
                .code(),
            ErrorCode::RegistryScopeUnauthorized
        );
    }
}
