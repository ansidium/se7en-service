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
    if !product_key_is_allowed(&value.to_ascii_lowercase()) {
        return Err(MaintenanceError::new(
            ErrorCode::RegistryScopeUnauthorized,
            "registry scope must be a product key outside Windows and platform namespaces",
        ));
    }
    Ok(())
}

/// Like the registry section of a Steam install script, a scope is one product's own key:
/// `SOFTWARE\<publisher>\<product>[\...]`. Publishers are open-ended, so the check rejects the
/// namespaces of Windows and of platforms that load code into other processes or apply policy.
/// The 32-bit view replaces explicit `WOW6432Node` paths.
fn product_key_is_allowed(folded: &str) -> bool {
    let components: Vec<&str> = folded.split('\\').collect();
    let (publisher, product) = match components.as_slice() {
        ["software", publisher, product, ..] => (*publisher, *product),
        _ => return false,
    };
    match publisher {
        // Windows, COM, default programs, policies and the 32-bit view.
        "classes"
        | "clients"
        | "policies"
        | "registeredapplications"
        | "windows"
        | "wow6432node" => false,
        // Only games published by Microsoft: SOFTWARE\Microsoft\Microsoft Games\<game>.
        "microsoft" => product == "microsoft games" && components.len() >= 4,
        // Vulkan and OpenCL layers and drivers load into every process that uses them.
        "khronos" => false,
        // Browser native-messaging hosts start programs; browser policies change security.
        "mozilla" => false,
        "google" => product != "chrome",
        _ => true,
    }
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
        RegisteredRegistryScope::new(
            "sample-classic",
            "sample-app",
            RegistryView::Registry32,
            r"SOFTWARE\Microsoft\Microsoft Games\SampleApp",
            allowed(),
            "S-1-5-21-1000",
        )
        .expect("a game key below SOFTWARE\\Microsoft is allowed");

        for forbidden in [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Policies\SE7EN",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\game.exe",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            r"SOFTWARE\Microsoft\Command Processor",
            r"SOFTWARE\Microsoft\Active Setup\Installed Components\{00000000-0000-0000-0000-000000000000}",
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
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

    fn scope_result(subkey: &str, value_name: &str) -> Result<RegisteredRegistryScope> {
        RegisteredRegistryScope::new(
            "policy-scope",
            "sample-app",
            RegistryView::Registry64,
            subkey,
            vec![AllowedRegistryValue {
                name: value_name.to_owned(),
                value_type: RegistryValueKind::String,
            }],
            "S-1-5-21-1000",
        )
    }

    #[test]
    fn scopes_are_product_keys_like_steam_install_scripts() {
        for allowed in [
            r"SOFTWARE\Rockstar Games\Grand Theft Auto V",
            r"SOFTWARE\Valve\Half-Life 2",
            r"SOFTWARE\Microsoft\Microsoft Games\Age of Empires II",
            r"SOFTWARE\SE7EN\ServiceE2E\RegistrySetV1",
        ] {
            scope_result(allowed, "Language").unwrap_or_else(|error| panic!("{allowed}: {error}"));
        }
        for forbidden in [
            // A whole publisher tree is not one product.
            r"SOFTWARE\ExampleVendor",
            r"SOFTWARE\Microsoft\Microsoft Games",
            // Platform namespaces that load code into other processes or set policy.
            r"SOFTWARE\Microsoft\Office\Addins",
            r"SOFTWARE\Microsoft\.NETFramework\AppContext",
            r"SOFTWARE\Khronos\Vulkan\ImplicitLayers",
            r"SOFTWARE\Khronos\OpenCL\Vendors",
            r"SOFTWARE\Google\Chrome\NativeMessagingHosts",
            r"SOFTWARE\Mozilla\NativeMessagingHosts",
            r"SOFTWARE\Clients\StartMenuInternet",
            r"SOFTWARE\RegisteredApplications\Example",
            r"SOFTWARE\Windows\Example",
        ] {
            assert_eq!(
                scope_result(forbidden, "Language")
                    .expect_err(forbidden)
                    .code(),
                ErrorCode::RegistryScopeUnauthorized,
                "{forbidden}"
            );
        }
        for value in [
            "Debugger",
            "AUTORUN",
            "StubPath",
            "AppInit_DLLs",
            "Userinit",
        ] {
            assert_eq!(
                scope_result(r"SOFTWARE\ExampleVendor\SampleApp", value)
                    .expect_err(value)
                    .code(),
                ErrorCode::RegistryValueInvalid,
                "{value}"
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
