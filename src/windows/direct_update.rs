//! User-token launcher updates. No SCM, registry registration, ACL change or elevation.
//! Signed metadata and payloads use the same trust chain as the service. Existing files
//! use ReplaceFileW so the launcher filename survives a helper crash; the durable journal
//! restores an interrupted group before WebView/companion files are loaded again.

use super::*;
use crate::{
    FileSetAcceptance, GenerationRecord, PreparedJob, TransactionPolicy, VerifiedFileSet,
    commit_file_set, prepare_file_set, recover_incomplete_with_policy,
};
use std::io::Take;
use windows::Win32::Storage::FileSystem::{
    FILE_SHARE_DELETE, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    REPLACE_FILE_FLAGS, ReplaceFileW,
};

const MAX_DIRECT_MANIFEST: usize = 65536;
const MAX_DIRECT_FILES: usize = 64;
const MAX_DIRECT_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DIRECT_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const DIRECT_DIRECTORY: &str = ".7launcher-direct-update";

fn error(code: ErrorCode, detail: &'static str) -> MaintenanceError {
    MaintenanceError::new(code, detail)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    read_bounded_to(path, MAX_DIRECT_MANIFEST)
}

fn read_bounded_to(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = open_absolute(
        path,
        FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .map_err(|_| {
        error(
            ErrorCode::StagingInvalid,
            "signed update document cannot be opened",
        )
    })?;
    ensure_safe_regular_file(&file)?;
    let mut bounded: Take<File> = file.take((maximum + 1) as u64);
    let mut bytes = Vec::new();
    bounded.read_to_end(&mut bytes).map_err(|_| {
        error(
            ErrorCode::StagingInvalid,
            "signed update document cannot be read",
        )
    })?;
    if bytes.len() > maximum {
        return Err(error(
            ErrorCode::ManifestTooLarge,
            "signed launcher update document is too large",
        ));
    }
    Ok(bytes)
}

fn path_allowed(path: &str, launcher: &str) -> bool {
    if crate::file_set::validate_relative_path(path).is_err()
        || path.len() > 240
        || !path
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-./".contains(&c))
    {
        return false;
    }
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() == 1 {
        return path == launcher
            || Path::new(path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("dll"));
    }
    parts.len() >= 3
        && parts[0].eq_ignore_ascii_case("7launcher")
        && parts[1].eq_ignore_ascii_case("resources")
        && !Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
}

fn launcher_identity(path: &Path) -> Result<(RegisteredRoot, String)> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| error(ErrorCode::RootInvalid, "launcher filename is not Unicode"))?;
    let product = name
        .strip_prefix("Run_")
        .or_else(|| name.strip_prefix("run_"))
        .and_then(|name| name.strip_suffix(".exe"))
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 55
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        })
        .ok_or_else(|| {
            error(
                ErrorCode::ProductMismatch,
                "launcher filename is not canonical",
            )
        })?;
    let parent = path
        .parent()
        .filter(|parent| parent.is_absolute())
        .ok_or_else(|| error(ErrorCode::RootInvalid, "launcher root is not absolute"))?;
    let handle = open_absolute_directory(parent, false)?;
    let canonical = final_path_owned(&handle)?;
    let canonical_text = canonical
        .to_str()
        .ok_or_else(|| error(ErrorCode::RootInvalid, "launcher root is not Unicode"))?;
    let root_id = format!(
        "direct-{}",
        &lower_hex(&crate::sha256(canonical_text.as_bytes()))[..32]
    );
    let root = RegisteredRoot::from_canonical_identity(
        root_id,
        format!("{}-launcher", product.to_ascii_lowercase()),
        crate::protocol::RootKind::Launcher,
        canonical_text,
        directory_identity(&handle)?,
        "S-1-5-18",
    )?;
    Ok((root, name.to_owned()))
}

fn validate_plan(manifest: &VerifiedFileSet, launcher: &str) -> Result<()> {
    let files = &manifest.file_set().files;
    if files.is_empty()
        || files.len() > MAX_DIRECT_FILES
        || !manifest.file_set().remove_files.is_empty()
        || files.iter().filter(|entry| entry.path == launcher).count() != 1
    {
        return Err(error(
            ErrorCode::FileSetLimit,
            "launcher update file count is invalid",
        ));
    }
    let mut total = 0_u64;
    for entry in files {
        if !path_allowed(&entry.path, launcher) {
            return Err(error(
                ErrorCode::FileSetPath,
                "launcher update path is not allowed",
            ));
        }
        total = total
            .checked_add(entry.size)
            .ok_or_else(|| error(ErrorCode::FileSetLimit, "launcher update size overflowed"))?;
        if entry.size == 0 || entry.size > MAX_DIRECT_FILE_BYTES || total > MAX_DIRECT_TOTAL_BYTES {
            return Err(error(
                ErrorCode::FileSetLimit,
                "launcher update size is outside its bound",
            ));
        }
    }
    Ok(())
}

/// Authenticate a bounded download plan without requiring a running service.
pub fn verify_direct_launcher_plan(
    manifest_path: &Path,
    keyring_path: &Path,
    launcher_path: &Path,
) -> Result<VerifiedFileSet> {
    let (root, launcher) = launcher_identity(launcher_path)?;
    let keyring = verify_keyring(&read_bounded(keyring_path)?, KeyringAcceptance::default())?;
    let manifest = verify_file_set(
        &read_bounded(manifest_path)?,
        &keyring,
        FileSetAcceptance {
            expected_product_id: root.product_id(),
            previous: None,
        },
    )?;
    validate_plan(&manifest, &launcher)?;
    Ok(manifest)
}

struct DirectContext {
    root: RegisteredRoot,
    launcher: String,
    directory: PathBuf,
    _lock: File,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcceptedRelease {
    keyring: crate::Keyring,
    file_set: crate::FileSet,
}

impl DirectContext {
    fn open(launcher_path: &Path) -> Result<Self> {
        let (root, launcher) = launcher_identity(launcher_path)?;
        let directory = root.canonical_path().join(DIRECT_DIRECTORY);
        let Some((_locks, _parent)) =
            lock_parent_chain(&root, &[DIRECT_DIRECTORY.to_owned()], true)?
        else {
            return Err(error(
                ErrorCode::TransactionIo,
                "direct update directory cannot be created",
            ));
        };
        // The lock is an ordinary user-owned file. Share mode 0 serializes helpers and
        // naturally releases on process exit; no stale PID or lock deletion is needed.
        let lock_path = directory.join("lock");
        let lock = open_absolute(
            &lock_path,
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            Default::default(),
            windows::Win32::Storage::FileSystem::OPEN_ALWAYS,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
        .map_err(|_| {
            error(
                ErrorCode::ServiceBusy,
                "another direct launcher update is running",
            )
        })?;
        ensure_safe_regular_file(&lock)?;
        Ok(Self {
            root,
            launcher,
            directory,
            _lock: lock,
        })
    }

    fn platform(&self, staging: BTreeMap<String, File>) -> Arc<DirectPlatform> {
        Arc::new(DirectPlatform {
            root: self.root.clone(),
            launcher: self.launcher.clone(),
            inner: WindowsTransactionPlatform::with_staging_files(staging),
        })
    }

    fn policy(&self, platform: Arc<DirectPlatform>) -> Result<TransactionPolicy> {
        TransactionPolicy::new(self.directory.clone(), platform)
    }

    fn trust(&self, keyring_path: &Path) -> Result<(Vec<u8>, VerifiedKeyring)> {
        let acceptance = if let Some((old, _)) = self.accepted_release()? {
            KeyringAcceptance {
                minimum_version: old.keyring().version,
                current_digest: Some(old.digest()),
            }
        } else {
            KeyringAcceptance::default()
        };
        let bytes = read_bounded(keyring_path)?;
        let verified = verify_keyring(&bytes, acceptance)?;
        // A helper which is not signed by an authorized publisher must not mutate files,
        // even when somebody invokes it directly instead of through the launcher.
        let executable = std::env::current_exe()
            .map_err(|_| error(ErrorCode::TrustSignature, "updater identity is unavailable"))?;
        let file = File::open(executable).map_err(|_| {
            error(
                ErrorCode::TrustSignature,
                "updater identity cannot be opened",
            )
        })?;
        verify_authenticode_signer(&file, &verified.keyring().authenticode_signer_thumbprints)?;
        Ok((bytes, verified))
    }

    fn accepted_release(&self) -> Result<Option<(VerifiedKeyring, VerifiedFileSet)>> {
        let path = self.directory.join("accepted-release-v1.json");
        if !path.exists() {
            return Ok(None);
        }
        let cache: AcceptedRelease = crate::parse_canonical(
            &read_bounded_to(&path, 2 * MAX_DIRECT_MANIFEST)?,
            2 * MAX_DIRECT_MANIFEST,
        )?;
        let keyring =
            verify_keyring(
                &crate::canonical_json(&serde_json::to_value(cache.keyring).map_err(|_| {
                    error(ErrorCode::JsonInvalid, "cached keyring cannot be encoded")
                })?)?,
                KeyringAcceptance::default(),
            )?;
        let manifest =
            verify_file_set(
                &crate::canonical_json(&serde_json::to_value(cache.file_set).map_err(|_| {
                    error(ErrorCode::JsonInvalid, "cached release cannot be encoded")
                })?)?,
                &keyring,
                FileSetAcceptance {
                    expected_product_id: self.root.product_id(),
                    previous: None,
                },
            )?;
        validate_plan(&manifest, &self.launcher)?;
        Ok(Some((keyring, manifest)))
    }

    fn recovery(&self) -> Result<()> {
        let policy = self.policy(self.platform(BTreeMap::new()))?;
        let jobs = self.directory.join("jobs");
        if jobs.exists() {
            let handle = open_absolute_directory(&jobs, false)?;
            drop(handle);
            // A direct update never queues operations. Bound recovery work even if the
            // writable game directory has been populated by another program.
            if fs::read_dir(&jobs)
                .map_err(|_| {
                    error(
                        ErrorCode::RecoveryIncomplete,
                        "direct update jobs cannot be enumerated",
                    )
                })?
                .take(3)
                .count()
                > 2
            {
                return Err(error(
                    ErrorCode::RecoveryIncomplete,
                    "too many direct update jobs",
                ));
            }
        }
        recover_incomplete_with_policy(policy)?;
        self.trim_empty_jobs();
        Ok(())
    }

    fn trim_empty_jobs(&self) {
        let _ = fs::remove_dir(self.directory.join("jobs"));
    }
}

fn replace_document(root: &RegisteredRoot, relative: &str, bytes: &[u8]) -> Result<()> {
    let temp = format!("{relative}.new");
    if let Some(old) =
        open_relative_file(root, &temp, FILE_READ_ATTRIBUTES.0 | DELETE.0, false, false)?
    {
        delete_by_handle(&old)?;
    }
    let mut file = open_relative_file(
        root,
        &temp,
        FILE_GENERIC_WRITE.0 | FILE_READ_ATTRIBUTES.0,
        true,
        true,
    )?
    .ok_or_else(|| error(ErrorCode::TransactionIo, "update receipt cannot be created"))?;
    file.write_all(bytes)
        .map_err(|_| error(ErrorCode::TransactionIo, "update receipt cannot be written"))?;
    file.sync_all()
        .map_err(|_| error(ErrorCode::TransactionIo, "update receipt cannot be flushed"))?;
    drop(file);
    move_atomic(root, &temp, relative, true)
}

/// Prepared operation holds its root, synchronization lock, and exact signed staging handles.
pub struct PreparedDirectUpdate {
    context: DirectContext,
    prepared: PreparedJob,
}

impl PreparedDirectUpdate {
    pub fn commit(self) -> Result<crate::CommitResult> {
        let Self { context, prepared } = self;
        let result = commit_file_set(prepared);
        if result.is_err() {
            context.recovery().map_err(|_| {
                error(
                    ErrorCode::RecoveryIncomplete,
                    "direct update rollback could not be completed",
                )
            })?;
        }
        context.trim_empty_jobs();
        result
    }

    pub fn cancel(self) -> Result<()> {
        let Self { context, prepared } = self;
        drop(prepared);
        context.recovery()
    }
}

pub fn prepare_direct_launcher_update(
    launcher_path: &Path,
    manifest_path: &Path,
    keyring_path: &Path,
    staging: &Path,
) -> Result<PreparedDirectUpdate> {
    let context = DirectContext::open(launcher_path)?;
    let (_keyring_bytes, keyring) = context.trust(keyring_path)?;
    context.recovery()?;
    let previous = if let Some((_, manifest)) = context.accepted_release()? {
        Some(GenerationRecord {
            generation: manifest.file_set().generation,
            digest: manifest.digest(),
        })
    } else {
        None
    };
    let manifest_bytes = read_bounded(manifest_path)?;
    let manifest = verify_file_set(
        &manifest_bytes,
        &keyring,
        FileSetAcceptance {
            expected_product_id: context.root.product_id(),
            previous,
        },
    )?;
    validate_plan(&manifest, &context.launcher)?;
    let current = open_relative_file(
        &context.root,
        &context.launcher,
        FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0,
        false,
        false,
    )?
    .ok_or_else(|| error(ErrorCode::RootIdentity, "installed launcher is absent"))?;
    verify_authenticode_signer(&current, &keyring.keyring().authenticode_signer_thumbprints)?;
    drop(current);
    let staging_handle = open_absolute_directory(staging, false)?;
    let staging_root = final_path_owned(&staging_handle)?;
    let mut handles = BTreeMap::new();
    for entry in &manifest.file_set().files {
        let file = open_relative_file(
            &staging_root,
            &entry.path,
            FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0,
            false,
            false,
        )?
        .ok_or_else(|| {
            error(
                ErrorCode::StagingInvalid,
                "launcher companion payload is absent",
            )
        })?;
        if entry.path == context.launcher {
            verify_authenticode_signer(&file, &keyring.keyring().authenticode_signer_thumbprints)?;
        }
        handles.insert(entry.path.clone(), file);
    }
    let platform = context.platform(handles);
    let prepared = prepare_file_set(
        &manifest,
        &context.root,
        &staging_root,
        context.policy(platform.clone())?,
    )?;
    // The journal owns verified private/same-volume copies now. Release download
    // handles before readiness so the launcher can remove its staging files.
    platform
        .inner
        .staging_files
        .lock()
        .map_err(|_| {
            error(
                ErrorCode::TransactionState,
                "direct staging handles are poisoned",
            )
        })?
        .clear();
    drop(platform);
    // Floors are persisted only after every signed payload was verified and prepared.
    // A failed commit may retry this exact digest, but cannot accept an older generation.
    let cache = crate::canonical_json(&serde_json::json!({
        "keyring": keyring.keyring(), "fileSet": manifest.file_set()
    }))?;
    if let Err(e) = replace_document(
        &context.root,
        &format!("{DIRECT_DIRECTORY}/accepted-release-v1.json"),
        &cache,
    ) {
        drop(prepared);
        context.recovery()?;
        return Err(e);
    }
    Ok(PreparedDirectUpdate { context, prepared })
}

pub fn recover_direct_launcher_update(launcher_path: &Path, keyring_path: &Path) -> Result<()> {
    let context = DirectContext::open(launcher_path)?;
    context.trust(keyring_path)?;
    context.recovery()
}

struct DirectPlatform {
    root: RegisteredRoot,
    launcher: String,
    inner: WindowsTransactionPlatform,
}

impl DirectPlatform {
    fn bound(&self, root: &RegisteredRoot) -> Result<()> {
        if root != &self.root {
            return Err(error(
                ErrorCode::RootIdentity,
                "direct journal belongs to another root",
            ));
        }
        self.inner.verify_root_identity(root)
    }
    fn target(&self, root: &RegisteredRoot, path: &str) -> Result<()> {
        self.bound(root)?;
        if !path_allowed(path, &self.launcher) {
            return Err(error(
                ErrorCode::FileSetPath,
                "direct journal path is not allowed",
            ));
        }
        Ok(())
    }
}

impl TransactionPlatform for DirectPlatform {
    fn uses_atomic_replacement(&self) -> bool {
        true
    }
    fn verify_root_identity(&self, root: &RegisteredRoot) -> Result<()> {
        self.bound(root)
    }
    fn root_is_missing(&self, _root: &RegisteredRoot) -> bool {
        false
    }
    fn available_space(&self, path: &Path) -> Result<u64> {
        self.inner.available_space(path)
    }
    fn same_volume(&self, left: &Path, right: &Path) -> Result<bool> {
        self.inner.same_volume(left, right)
    }
    fn open_staging_payload(&self, root: &Path, path: &str) -> Result<Box<dyn Read + Send>> {
        self.inner.open_staging_payload(root, path)
    }
    fn inspect_target(&self, root: &RegisteredRoot, path: &str) -> Result<Option<TargetSnapshot>> {
        self.target(root, path)?;
        self.inner.inspect_target(root, path)
    }
    fn prepare_target_payload(
        &self,
        root: &RegisteredRoot,
        job: &str,
        index: u32,
        payload: &Path,
        expected: &FileEntry,
    ) -> Result<()> {
        self.target(root, &expected.path)?;
        self.inner
            .prepare_target_payload(root, job, index, payload, expected)
    }
    fn atomic_replace_target(
        &self,
        root: &RegisteredRoot,
        job: &str,
        index: u32,
        path: &str,
        original: Option<TargetSnapshot>,
    ) -> Result<bool> {
        self.target(root, path)?;
        if self.inner.inspect_target(root, path)? != original {
            return Err(error(
                ErrorCode::RootIdentity,
                "direct target changed before replacement",
            ));
        }
        // Release only the verified leaf immediately before ReplaceFileW. Parent chains
        // remain locked across the call, denying junction/rename escapes.
        let held = self
            .inner
            .target_handles
            .lock()
            .map_err(|_| {
                error(
                    ErrorCode::TransactionState,
                    "direct target handles are poisoned",
                )
            })?
            .remove(&WindowsTransactionPlatform::target_key(root, path));
        drop(held);
        if original.is_some() {
            replace_atomic(
                root,
                &prepared_relative_path(job, index),
                path,
                Some(&backup_relative_path(job, index)),
            )?;
        } else {
            move_atomic(root, &prepared_relative_path(job, index), path, false)?;
        }
        Ok(true)
    }
    fn atomic_restore_backup(
        &self,
        root: &RegisteredRoot,
        job: &str,
        index: u32,
        path: &str,
    ) -> Result<bool> {
        self.target(root, path)?;
        let target = self.inner.inspect_target(root, path)?;
        let held = self
            .inner
            .target_handles
            .lock()
            .map_err(|_| {
                error(
                    ErrorCode::TransactionState,
                    "direct target handles are poisoned",
                )
            })?
            .remove(&WindowsTransactionPlatform::target_key(root, path));
        drop(held);
        if target.is_some() {
            replace_atomic(root, &backup_relative_path(job, index), path, None)?;
        } else {
            move_atomic(root, &backup_relative_path(job, index), path, false)?;
        }
        Ok(true)
    }
    fn backup_exists(&self, root: &RegisteredRoot, job: &str, index: u32) -> Result<bool> {
        self.bound(root)?;
        self.inner.backup_exists(root, job, index)
    }
    fn delete_target(&self, root: &RegisteredRoot, path: &str) -> Result<()> {
        self.target(root, path)?;
        self.inner.delete_target(root, path)
    }
    fn cleanup_job(&self, root: &RegisteredRoot, job: &str, private: &Path) -> Result<()> {
        self.bound(root)?;
        let expected = root
            .canonical_path()
            .join(DIRECT_DIRECTORY)
            .join("jobs")
            .join(job);
        if private != expected {
            return Err(error(
                ErrorCode::RootIdentity,
                "direct journal directory escaped its root",
            ));
        }
        self.inner.cleanup_job(root, job, private)
    }
}

fn locked_leaf(root: &RegisteredRoot, path: &str, create: bool) -> Result<(Vec<File>, PathBuf)> {
    let components = relative_components(path)?;
    let (leaf, parents) = components
        .split_last()
        .ok_or_else(|| error(ErrorCode::FileSetPath, "atomic update path is empty"))?;
    let (locks, parent) = lock_parent_chain(root, parents, create)?
        .ok_or_else(|| error(ErrorCode::RootIdentity, "atomic update parent is absent"))?;
    Ok((locks, parent.join(leaf)))
}

fn replace_atomic(
    root: &RegisteredRoot,
    source: &str,
    target: &str,
    backup: Option<&str>,
) -> Result<()> {
    let (_source_locks, source) = locked_leaf(root, source, false)?;
    let (_target_locks, target) = locked_leaf(root, target, true)?;
    let backup_locked = backup
        .map(|path| locked_leaf(root, path, true))
        .transpose()?;
    if backup_locked
        .as_ref()
        .is_some_and(|(_, path)| path.exists())
    {
        return Err(error(
            ErrorCode::TransactionConflict,
            "direct update backup already exists",
        ));
    }
    let source_file = open_absolute(
        &source,
        FILE_READ_ATTRIBUTES.0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .map_err(|_| error(ErrorCode::TransactionIo, "atomic source cannot be opened"))?;
    ensure_safe_regular_file(&source_file)?;
    let target_file = open_absolute(
        &target,
        FILE_READ_ATTRIBUTES.0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .map_err(|_| error(ErrorCode::TransactionIo, "atomic target cannot be opened"))?;
    ensure_safe_regular_file(&target_file)?;
    let source = wide_null(
        source
            .to_str()
            .ok_or_else(|| error(ErrorCode::FileSetPath, "atomic source is not Unicode"))?,
    );
    let target = wide_null(
        target
            .to_str()
            .ok_or_else(|| error(ErrorCode::FileSetPath, "atomic target is not Unicode"))?,
    );
    let backup = backup_locked
        .as_ref()
        .map(|(_, path)| {
            path.to_str()
                .ok_or_else(|| error(ErrorCode::FileSetPath, "atomic backup is not Unicode"))
        })
        .transpose()?
        .map(wide_null);
    // SAFETY: all strings are NUL-terminated and live through the synchronous call;
    // root and every source/target/backup parent remain held without delete sharing.
    unsafe {
        ReplaceFileW(
            PCWSTR(target.as_ptr()),
            PCWSTR(source.as_ptr()),
            backup
                .as_ref()
                .map_or(PCWSTR::null(), |path| PCWSTR(path.as_ptr())),
            REPLACE_FILE_FLAGS(0),
            None,
            None,
        )
    }
    .map_err(|_| error(ErrorCode::TransactionIo, "direct atomic replacement failed"))
}

fn move_atomic(root: &RegisteredRoot, source: &str, target: &str, replace: bool) -> Result<()> {
    let (_source_locks, source_path) = locked_leaf(root, source, false)?;
    let (_target_locks, target_path) = locked_leaf(root, target, true)?;
    let source_file = open_absolute(
        &source_path,
        FILE_READ_ATTRIBUTES.0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .map_err(|_| error(ErrorCode::TransactionIo, "atomic source cannot be opened"))?;
    ensure_safe_regular_file(&source_file)?;
    if let Some(target) = open_relative_file(root, target, FILE_READ_ATTRIBUTES.0, false, false)? {
        ensure_safe_regular_file(&target)?;
    }
    let source = wide_null(
        source_path
            .to_str()
            .ok_or_else(|| error(ErrorCode::FileSetPath, "atomic source is not Unicode"))?,
    );
    let target = wide_null(
        target_path
            .to_str()
            .ok_or_else(|| error(ErrorCode::FileSetPath, "atomic target is not Unicode"))?,
    );
    // SAFETY: names live through the call; parent chains are locked without delete
    // sharing, and the source/target metadata were checked for reparse/hardlink escape.
    unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(target.as_ptr()),
            if replace {
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
            } else {
                MOVEFILE_WRITE_THROUGH
            },
        )
    }
    .map_err(|_| error(ErrorCode::TransactionIo, "direct atomic rename failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MutationBoundary, MutationEvent, MutationFaultInjector, MutationKind};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    const OLD_EXE: &[u8] = b"old launcher fixture";
    const OLD_DLL: &[u8] = b"old browser companion fixture";
    const NEW_EXE: &[u8] = b"new launcher fixture";
    const NEW_DLL: &[u8] = b"new browser companion fixture";
    const RESOURCE: &[u8] = b"small new resource";

    struct Fixture {
        base: PathBuf,
        root: PathBuf,
        staging: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().join(format!(
                "7launcher-direct-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&base).expect("unique fixture directory");
            let root = base.join("root");
            let staging = base.join("staging");
            fs::create_dir(&root).expect("fixture root");
            fs::create_dir_all(staging.join("7launcher/resources")).expect("fixture staging");
            fs::write(root.join("Run_fixture.exe"), OLD_EXE).expect("old exe");
            fs::write(root.join("WebView2Loader.dll"), OLD_DLL).expect("old dll");
            fs::write(root.join("launcher.ini"), b"unlisted config preserved").expect("config");
            fs::write(staging.join("Run_fixture.exe"), NEW_EXE).expect("new exe");
            fs::write(staging.join("WebView2Loader.dll"), NEW_DLL).expect("new dll");
            fs::write(staging.join("7launcher/resources/page.dat"), RESOURCE)
                .expect("new resource");
            Self {
                base,
                root,
                staging,
            }
        }
        fn context(&self) -> DirectContext {
            DirectContext::open(&self.root.join("Run_fixture.exe")).expect("direct context")
        }
        fn manifest(&self) -> VerifiedFileSet {
            let root = SigningKey::from_bytes(&[11; 32]);
            let release = SigningKey::from_bytes(&[22; 32]);
            let keyring = signed(
                json!({"authenticodeSignerThumbprints":[],
                "kind":"7launcher-maintenance-keyring-v1", "releaseKeys":[{"keyId":"fixture",
                    "publicKey":lower_hex(&release.verifying_key().to_bytes())}], "schema":1,"version":1}),
                &root,
                crate::KEYRING_SIGNING_DOMAIN,
            );
            let keyring = crate::verify_keyring_with_root(
                &keyring,
                KeyringAcceptance::default(),
                &root.verifying_key().to_bytes(),
            )
            .expect("fixture keyring signature");
            let files:Vec<_> = [("Run_fixture.exe",NEW_EXE),("WebView2Loader.dll",NEW_DLL),
                ("7launcher/resources/page.dat",RESOURCE)].iter().map(|(path,bytes)|
                json!({"path":path,"size":bytes.len(),"sha256":lower_hex(&crate::sha256(bytes))})).collect();
            let bytes = signed(
                json!({"files":files,"generation":1,"keyId":"fixture",
                "kind":"7launcher-file-set-v1","productId":"fixture-launcher","removeFiles":[],"schema":1}),
                &release,
                crate::FILE_SET_SIGNING_DOMAIN,
            );
            verify_file_set(
                &bytes,
                &keyring,
                FileSetAcceptance {
                    expected_product_id: "fixture-launcher",
                    previous: None,
                },
            )
            .expect("fixture manifest signature")
        }
        fn prepare(
            &self,
            context: &DirectContext,
            fault: Option<Arc<dyn MutationFaultInjector>>,
        ) -> Result<PreparedJob> {
            let manifest = self.manifest();
            validate_plan(&manifest, "Run_fixture.exe")?;
            let mut files = BTreeMap::new();
            for entry in &manifest.file_set().files {
                files.insert(
                    entry.path.clone(),
                    open_relative_file(
                        &self.staging,
                        &entry.path,
                        FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0,
                        false,
                        false,
                    )?
                    .expect("fixture payload"),
                );
            }
            let mut policy = context.policy(context.platform(files))?;
            if let Some(fault) = fault {
                policy = policy.with_fault_injector(fault);
            }
            prepare_file_set(&manifest, &context.root, &self.staging, policy)
        }
        fn assert_old(&self) {
            assert_eq!(
                fs::read(self.root.join("Run_fixture.exe")).expect("old exe exists"),
                OLD_EXE
            );
            assert_eq!(
                fs::read(self.root.join("WebView2Loader.dll")).expect("old dll exists"),
                OLD_DLL
            );
            assert!(!self.root.join("7launcher/resources/page.dat").exists());
            assert_eq!(
                fs::read(self.root.join("launcher.ini")).expect("config"),
                b"unlisted config preserved"
            );
        }
        fn assert_new(&self) {
            assert_eq!(
                fs::read(self.root.join("Run_fixture.exe")).expect("new exe exists"),
                NEW_EXE
            );
            assert_eq!(
                fs::read(self.root.join("WebView2Loader.dll")).expect("new dll exists"),
                NEW_DLL
            );
            assert_eq!(
                fs::read(self.root.join("7launcher/resources/page.dat")).expect("resource"),
                RESOURCE
            );
            assert_eq!(
                fs::read(self.root.join("launcher.ini")).expect("config"),
                b"unlisted config preserved"
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
    fn signed(mut value: Value, key: &SigningKey, domain: &[u8]) -> Vec<u8> {
        let payload = crate::canonical_json(&value).expect("fixture canonical bytes");
        let signature = key.sign(&crate::signing_message(domain, &payload));
        value
            .as_object_mut()
            .expect("fixture object")
            .insert("signature".into(), json!(lower_hex(&signature.to_bytes())));
        crate::canonical_json(&value).expect("fixture signed canonical bytes")
    }
    #[test]
    fn direct_atomic_receipt_replacement_keeps_one_complete_document() {
        let f = Fixture::new();
        let c = f.context();
        let relative = format!("{DIRECT_DIRECTORY}/accepted-release-v1.json");
        let path = c.directory.join("accepted-release-v1.json");
        replace_document(&c.root, &relative, b"first complete fixture document")
            .expect("first atomic receipt");
        assert_eq!(
            fs::read(&path).expect("first receipt"),
            b"first complete fixture document"
        );
        // Simulate a lost helper after its temporary receipt was written. The
        // accepted keyring and FileSet are still together in the old document.
        fs::write(
            path.with_file_name("accepted-release-v1.json.new"),
            b"incomplete new fixture",
        )
        .expect("interrupted receipt fixture");
        assert_eq!(
            fs::read(&path).expect("receipt survives lost helper"),
            b"first complete fixture document"
        );
        replace_document(&c.root, &relative, b"second complete fixture document")
            .expect("replace existing receipt");
        assert_eq!(
            fs::read(&path).expect("second receipt"),
            b"second complete fixture document"
        );
        assert!(!path.with_file_name("accepted-release-v1.json.new").exists());
        f.assert_old();
    }
    #[test]
    fn direct_native_multifile_commit_preserves_config_and_cleans_journal() {
        let f = Fixture::new();
        let c = f.context();
        let job = f.prepare(&c, None).expect("prepared group");
        commit_file_set(job).expect("atomic group commit");
        f.assert_new();
        c.recovery().expect("no leftover operation");
        assert!(!c.directory.join("jobs").exists());
    }
    #[test]
    fn direct_bad_companion_hash_is_rejected_before_mutating_any_target() {
        let f = Fixture::new();
        let c = f.context();
        fs::write(f.staging.join("WebView2Loader.dll"), b"tampered companion")
            .expect("bad payload");
        assert!(f.prepare(&c, None).is_err());
        f.assert_old();
        c.recovery().expect("discard clean prepare");
    }
    #[test]
    fn direct_locked_companion_refuses_prepare_and_keeps_all_old_files() {
        let f = Fixture::new();
        let c = f.context();
        let lock = open_absolute(
            &f.root.join("WebView2Loader.dll"),
            FILE_READ_DATA.0,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
        )
        .expect("external read lock without delete sharing");
        assert!(f.prepare(&c, None).is_err());
        f.assert_old();
        drop(lock);
        c.recovery().expect("safe recovery");
    }
    struct Crash {
        n: usize,
        calls: AtomicUsize,
    }
    impl MutationFaultInjector for Crash {
        fn checkpoint(&self, _event: &MutationEvent) -> Result<()> {
            if self.calls.fetch_add(1, Ordering::Relaxed) == self.n {
                panic!("simulated abrupt helper loss");
            }
            Ok(())
        }
    }
    #[test]
    fn direct_every_commit_boundary_retains_executable_and_recovers_complete_group() {
        // Three atomic replacements + cleanup, each Before/After. No production hook;
        // panic drops the updater exactly as an abruptly lost process loses its handles.
        for n in 0..8 {
            let f = Fixture::new();
            let c = f.context();
            let job = f
                .prepare(
                    &c,
                    Some(Arc::new(Crash {
                        n,
                        calls: AtomicUsize::new(0),
                    })),
                )
                .expect("prepared crash fixture");
            assert!(
                catch_unwind(AssertUnwindSafe(|| commit_file_set(job))).is_err(),
                "fault must fire at {n}"
            );
            assert!(
                f.root.join("Run_fixture.exe").is_file(),
                "launcher filename survived boundary {n}"
            );
            c.recovery().expect("recover interrupted direct operation");
            if n >= 6 {
                f.assert_new();
            } else {
                f.assert_old();
            }
            assert!(!c.directory.join("jobs").exists());
        }
    }
    struct RollbackCrash {
        n: usize,
        rollback: AtomicBool,
        calls: AtomicUsize,
    }
    impl MutationFaultInjector for RollbackCrash {
        fn checkpoint(&self, event: &MutationEvent) -> Result<()> {
            if event.kind == MutationKind::AtomicReplaceTarget
                && event.boundary == MutationBoundary::Before
                && event.path.as_deref() == Some("7launcher/resources/page.dat")
            {
                self.rollback.store(true, Ordering::Relaxed);
                return Err(error(
                    ErrorCode::TransactionIo,
                    "simulated third-file commit failure",
                ));
            }
            if self.rollback.load(Ordering::Relaxed)
                && self.calls.fetch_add(1, Ordering::Relaxed) == self.n
            {
                panic!("simulated abrupt loss during rollback");
            }
            Ok(())
        }
    }
    #[test]
    fn direct_every_rollback_boundary_retains_executable_and_resumes_old_group() {
        for n in 0..6 {
            let f = Fixture::new();
            let c = f.context();
            let fault = RollbackCrash {
                n,
                rollback: AtomicBool::new(false),
                calls: AtomicUsize::new(0),
            };
            let job = f
                .prepare(&c, Some(Arc::new(fault)))
                .expect("rollback fixture prepared");
            assert!(
                catch_unwind(AssertUnwindSafe(|| commit_file_set(job))).is_err(),
                "rollback fault fires at {n}"
            );
            assert!(
                f.root.join("Run_fixture.exe").is_file(),
                "EXE remains present during rollback {n}"
            );
            c.recovery().expect("resume interrupted atomic rollback");
            f.assert_old();
        }
    }
    #[test]
    fn direct_recovery_refuses_a_foreign_root_in_its_journal() {
        let f = Fixture::new();
        let c = f.context();
        let job = f.prepare(&c, None).expect("prepared fixture");
        let job_id = job.job_id().to_owned();
        drop(job);
        let journal = c.directory.join("jobs").join(job_id).join("journal.jsonl");
        let text = fs::read_to_string(&journal).expect("journal");
        let mut lines = text.lines();
        let mut header: Value =
            serde_json::from_str(lines.next().expect("header")).expect("header JSON");
        header["root"]["canonicalPath"] = json!(f.staging.to_str().expect("staging Unicode"));
        let modified = format!(
            "{}\n{}\n",
            serde_json::to_string(&header).expect("modified header"),
            lines.next().expect("state")
        );
        fs::write(journal, modified).expect("foreign journal fixture");
        assert!(c.recovery().is_err());
        f.assert_old();
    }
    #[test]
    fn direct_path_allowlist_rejects_traversal_reserved_and_executable_companions() {
        for p in [
            "../Run_fixture.exe",
            "/Run_fixture.exe",
            "C:/evil.dll",
            "a:b.dll",
            "con.dll",
            "7launcher/resources/evil.exe",
            "7launcher/tools/evil.dll",
            "OTHER.exe",
            "A/../B.dll",
        ] {
            assert!(!path_allowed(p, "Run_fixture.exe"), "must reject {p}");
        }
        for p in [
            "Run_fixture.exe",
            "WebView2Loader.dll",
            "7launcher/resources/page.dat",
        ] {
            assert!(path_allowed(p, "Run_fixture.exe"), "valid owned path {p}");
        }
    }
    #[test]
    fn direct_hardlinked_payload_is_rejected_before_prepare() {
        let f = Fixture::new();
        let c = f.context();
        fs::hard_link(
            f.staging.join("WebView2Loader.dll"),
            f.base.join("second-link.dll"),
        )
        .expect("hardlink fixture");
        assert!(f.prepare(&c, None).is_err());
        f.assert_old();
    }
    #[test]
    fn direct_root_junction_never_changes_the_outside_directory() {
        let f = Fixture::new();
        let c = f.context();
        fs::create_dir(f.root.join("7launcher")).expect("resource owner");
        let outside = f.base.join("outside");
        fs::create_dir(&outside).expect("outside");
        fs::write(outside.join("sentinel"), b"outside untouched").expect("outside sentinel");
        let status = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(f.root.join("7launcher").join("resources"))
            .arg(&outside)
            .output()
            .expect("junction tool");
        assert!(
            status.status.success(),
            "junction fixture is required for this test: {} {}",
            String::from_utf8_lossy(&status.stdout),
            String::from_utf8_lossy(&status.stderr)
        );
        assert!(f.prepare(&c, None).is_err());
        f.assert_old();
        assert_eq!(
            fs::read(outside.join("sentinel")).expect("outside sentinel"),
            b"outside untouched"
        );
        assert!(!outside.join("page.dat").exists());
    }
    #[test]
    #[ignore = "requires genuine production keyring in SE7EN_DIRECT_TEST_KEYRING"]
    fn direct_unsigned_helper_is_rejected_with_genuine_production_keyring() {
        let path = std::env::var_os("SE7EN_DIRECT_TEST_KEYRING")
            .expect("production keyring evidence is required");
        let f = Fixture::new();
        let c = f.context();
        let error = c
            .trust(Path::new(&path))
            .expect_err("unsigned test runner cannot mutate production update targets");
        assert_eq!(error.code(), ErrorCode::TrustSignature);
        f.assert_old();
    }
}
