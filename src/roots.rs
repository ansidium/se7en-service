#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    ErrorCode, MaintenanceError, Result, canonical_json, parse_canonical, protocol::RootKind,
    valid_identifier,
};

const ROOT_REGISTRY_KIND: &str = "7launcher-maintenance-roots-v1";
const ROOT_REGISTRY_SCHEMA: u64 = 1;
const MAX_ROOT_REGISTRY_BYTES: usize = 1024 * 1024;
// Root metadata is queried by exact root ID, so the count is independent from the 64 KiB IPC
// message bound. The registry itself remains bounded by both count and encoded byte size.
const MAX_REGISTERED_ROOTS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub volume_serial: u64,
    pub file_id: [u8; 16],
}

impl DirectoryIdentity {
    pub fn from_path(path: &Path) -> Result<Self> {
        let metadata = fs::metadata(path).map_err(|_| {
            MaintenanceError::new(ErrorCode::RootInvalid, "registered root cannot be opened")
        })?;
        if !metadata.is_dir() {
            return Err(MaintenanceError::new(
                ErrorCode::RootInvalid,
                "registered root is not a directory",
            ));
        }
        metadata_identity(&metadata, ErrorCode::RootInvalid)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisteredRoot {
    root_id: String,
    product_id: String,
    root_kind: RootKind,
    canonical_path: String,
    identity: DirectoryIdentity,
    owner_sid: String,
}

impl RegisteredRoot {
    pub(crate) fn from_canonical_identity(
        root_id: impl Into<String>,
        product_id: impl Into<String>,
        root_kind: RootKind,
        canonical_path: impl Into<String>,
        identity: DirectoryIdentity,
        owner_sid: impl Into<String>,
    ) -> Result<Self> {
        let root = Self {
            root_id: root_id.into(),
            product_id: product_id.into(),
            root_kind,
            canonical_path: canonical_path.into(),
            identity,
            owner_sid: owner_sid.into(),
        };
        root.validate_stored()?;
        Ok(root)
    }

    pub fn from_verified_path(
        root_id: impl Into<String>,
        product_id: impl Into<String>,
        root_kind: RootKind,
        path: &Path,
        owner_sid: impl Into<String>,
    ) -> Result<Self> {
        let root_id = root_id.into();
        let product_id = product_id.into();
        let owner_sid = owner_sid.into();
        if !valid_identifier(&root_id)
            || !valid_identifier(&product_id)
            || !valid_owner_sid(&owner_sid)
        {
            return Err(MaintenanceError::new(
                ErrorCode::RootInvalid,
                "registered root metadata is invalid",
            ));
        }
        let canonical = fs::canonicalize(path).map_err(|_| {
            MaintenanceError::new(ErrorCode::RootInvalid, "root path cannot be canonicalized")
        })?;
        let canonical_path = canonical.to_str().ok_or_else(|| {
            MaintenanceError::new(ErrorCode::RootInvalid, "root path must be UTF-8")
        })?;
        let identity = DirectoryIdentity::from_path(&canonical)?;
        Ok(Self {
            root_id,
            product_id,
            root_kind,
            canonical_path: canonical_path.to_owned(),
            identity,
            owner_sid,
        })
    }

    #[must_use]
    pub fn root_id(&self) -> &str {
        &self.root_id
    }

    #[must_use]
    pub fn product_id(&self) -> &str {
        &self.product_id
    }

    #[must_use]
    pub const fn root_kind(&self) -> RootKind {
        self.root_kind
    }

    #[must_use]
    pub fn canonical_path(&self) -> &Path {
        Path::new(&self.canonical_path)
    }

    #[must_use]
    pub const fn identity(&self) -> DirectoryIdentity {
        self.identity
    }

    #[must_use]
    pub fn owner_sid(&self) -> &str {
        &self.owner_sid
    }

    fn validate_stored(&self) -> Result<()> {
        if !valid_identifier(&self.root_id)
            || !valid_identifier(&self.product_id)
            || !valid_owner_sid(&self.owner_sid)
            || !self.canonical_path().is_absolute()
        {
            return Err(MaintenanceError::new(
                ErrorCode::RootInvalid,
                "stored root metadata is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RootRegistryDocument {
    kind: String,
    roots: Vec<RegisteredRoot>,
    schema: u64,
}

#[derive(Clone, Debug, Default)]
pub struct RootRegistry {
    roots: BTreeMap<String, RegisteredRoot>,
}

impl RootRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, root: RegisteredRoot) -> Result<()> {
        root.validate_stored()?;
        if self.roots.len() >= MAX_REGISTERED_ROOTS {
            return Err(MaintenanceError::new(
                ErrorCode::RootInvalid,
                "registered-root count exceeds the bound",
            ));
        }
        if self.roots.contains_key(root.root_id()) {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionConflict,
                "root ID is already registered",
            ));
        }
        self.roots.insert(root.root_id.clone(), root);
        Ok(())
    }

    pub fn unregister(&mut self, root_id: &str, caller_sid: &str) -> Result<RegisteredRoot> {
        let root = self.resolve_accessible(root_id, caller_sid)?.clone();
        self.roots.remove(root_id).ok_or_else(|| {
            MaintenanceError::new(ErrorCode::RootNotFound, "root ID is not registered")
        })?;
        Ok(root)
    }

    pub fn resolve_accessible(&self, root_id: &str, caller_sid: &str) -> Result<&RegisteredRoot> {
        let root = self.roots.get(root_id).ok_or_else(|| {
            MaintenanceError::new(ErrorCode::RootNotFound, "root ID is not registered")
        })?;
        if root.root_kind() != RootKind::Library && root.owner_sid() != caller_sid {
            return Err(MaintenanceError::new(
                ErrorCode::RootUnauthorized,
                "protected root belongs to another user SID",
            ));
        }
        Ok(root)
    }

    pub fn resolve_job(
        &self,
        root_id: &str,
        caller_sid: &str,
        product_id: &str,
    ) -> Result<&RegisteredRoot> {
        let root = self.resolve_accessible(root_id, caller_sid)?;
        if root.product_id() != product_id {
            return Err(MaintenanceError::new(
                ErrorCode::ProductMismatch,
                "registered root belongs to another product",
            ));
        }
        Ok(root)
    }

    #[must_use]
    pub fn accessible_root_count(&self, caller_sid: &str) -> usize {
        self.roots
            .values()
            .filter(|root| root.root_kind() == RootKind::Library || root.owner_sid() == caller_sid)
            .count()
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = match read_bounded(path, MAX_ROOT_REGISTRY_BYTES) {
            Ok(bytes) => bytes,
            Err(_) => read_bounded(&backup_path(path), MAX_ROOT_REGISTRY_BYTES).map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::RootInvalid,
                    "root registry and backup cannot be read",
                )
            })?,
        };
        let document: RootRegistryDocument = parse_canonical(&bytes, MAX_ROOT_REGISTRY_BYTES)?;
        if document.kind != ROOT_REGISTRY_KIND || document.schema != ROOT_REGISTRY_SCHEMA {
            return Err(MaintenanceError::new(
                ErrorCode::RootInvalid,
                "root registry schema is unsupported",
            ));
        }
        if document.roots.len() > MAX_REGISTERED_ROOTS {
            return Err(MaintenanceError::new(
                ErrorCode::RootInvalid,
                "registered-root count exceeds the bound",
            ));
        }
        let mut registry = Self::new();
        for root in document.roots {
            registry.register(root)?;
        }
        Ok(registry)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let document = RootRegistryDocument {
            kind: ROOT_REGISTRY_KIND.to_owned(),
            roots: self.roots.values().cloned().collect(),
            schema: ROOT_REGISTRY_SCHEMA,
        };
        let bytes = canonical_json(&serde_json::to_value(document).map_err(|_| {
            MaintenanceError::new(ErrorCode::RootInvalid, "root registry cannot be encoded")
        })?)?;
        if bytes.len() > MAX_ROOT_REGISTRY_BYTES {
            return Err(MaintenanceError::new(
                ErrorCode::RootInvalid,
                "root registry exceeds the bound",
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            MaintenanceError::new(ErrorCode::RootInvalid, "root registry has no parent")
        })?;
        fs::create_dir_all(parent).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "root registry parent cannot be made",
            )
        })?;
        let temporary = temporary_path(path);
        let backup = backup_path(path);
        let mut output = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| {
                MaintenanceError::new(ErrorCode::TransactionIo, "root registry temp cannot open")
            })?;
        output.write_all(&bytes).map_err(|_| {
            MaintenanceError::new(ErrorCode::TransactionIo, "root registry temp write failed")
        })?;
        output.sync_all().map_err(|_| {
            MaintenanceError::new(ErrorCode::TransactionIo, "root registry temp sync failed")
        })?;

        if path.exists() {
            if backup.exists() {
                fs::remove_file(&backup).map_err(|_| {
                    MaintenanceError::new(
                        ErrorCode::TransactionIo,
                        "stale root registry backup cannot be removed",
                    )
                })?;
            }
            fs::rename(path, &backup).map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "root registry backup rename failed",
                )
            })?;
        }
        if let Err(_error) = fs::rename(&temporary, path) {
            if backup.exists() {
                let _restore_result = fs::rename(&backup, path);
            }
            return Err(MaintenanceError::new(
                ErrorCode::TransactionIo,
                "root registry commit rename failed",
            ));
        }
        if backup.exists() {
            fs::remove_file(backup).map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "root registry backup cleanup failed",
                )
            })?;
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| {
                MaintenanceError::new(ErrorCode::TransactionIo, "root registry sync failed")
            })
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
    file.take((maximum as u64) + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "root registry exceeds the configured bound",
        ));
    }
    Ok(bytes)
}

#[cfg(windows)]
pub(crate) fn metadata_identity(
    metadata: &fs::Metadata,
    _code: ErrorCode,
) -> Result<DirectoryIdentity> {
    use std::os::windows::fs::MetadataExt;

    // Stable std does not expose Windows volume/file IDs yet. This safe identity is used only by
    // the hermetic local policy; the service policy replaces it with handle-based IDs in windows.rs.
    let mut file_id = [0_u8; 16];
    file_id[..8].copy_from_slice(&metadata.creation_time().to_le_bytes());
    file_id[8..12].copy_from_slice(&metadata.file_attributes().to_le_bytes());
    Ok(DirectoryIdentity {
        volume_serial: 0,
        file_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER_SID: &str = "S-1-5-21-1000";

    fn root(index: usize) -> RegisteredRoot {
        RegisteredRoot::from_canonical_identity(
            format!("launcher-{index}"),
            format!("product-{index}"),
            RootKind::Launcher,
            std::env::temp_dir()
                .join(format!("launcher-{index}"))
                .to_string_lossy(),
            DirectoryIdentity {
                volume_serial: 1,
                file_id: [u8::try_from(index % 256).expect("bounded index"); 16],
            },
            OWNER_SID,
        )
        .expect("valid synthetic root")
    }

    fn shared_library() -> RegisteredRoot {
        RegisteredRoot::from_canonical_identity(
            "shared-library",
            "7apps",
            RootKind::Library,
            std::env::temp_dir()
                .join("shared-library")
                .to_string_lossy(),
            DirectoryIdentity {
                volume_serial: 2,
                file_id: [7; 16],
            },
            OWNER_SID,
        )
        .expect("valid synthetic library")
    }

    #[test]
    fn registry_supports_sixty_plus_launchers_with_a_bounded_ceiling() {
        let mut registry = RootRegistry::new();
        for index in 0..MAX_REGISTERED_ROOTS {
            registry.register(root(index)).expect("root within bound");
        }
        assert_eq!(registry.accessible_root_count(OWNER_SID), 256);
        assert_eq!(
            registry
                .register(root(MAX_REGISTERED_ROOTS))
                .expect_err("root beyond bound is rejected")
                .code(),
            ErrorCode::RootInvalid
        );
    }

    #[test]
    fn library_is_shared_but_launcher_root_remains_owner_scoped() {
        let mut registry = RootRegistry::new();
        registry.register(root(0)).expect("launcher root");
        registry.register(shared_library()).expect("library root");

        assert!(
            registry
                .resolve_accessible("shared-library", "S-1-5-21-2000")
                .is_ok()
        );
        assert_eq!(registry.accessible_root_count("S-1-5-21-2000"), 1);
        assert_eq!(
            registry
                .resolve_accessible("launcher-0", "S-1-5-21-2000")
                .expect_err("launcher root remains owner-scoped")
                .code(),
            ErrorCode::RootUnauthorized
        );
        registry
            .unregister("shared-library", "S-1-5-21-2000")
            .expect("another elevated administrator may remove a shared library");
    }
}

#[cfg(unix)]
pub(crate) fn metadata_identity(
    metadata: &fs::Metadata,
    _code: ErrorCode,
) -> Result<DirectoryIdentity> {
    use std::os::unix::fs::MetadataExt;

    Ok(DirectoryIdentity {
        volume_serial: metadata.dev(),
        file_id: {
            let mut file_id = [0_u8; 16];
            file_id[..8].copy_from_slice(&metadata.ino().to_le_bytes());
            file_id
        },
    })
}
