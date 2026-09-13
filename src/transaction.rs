#![forbid(unsafe_code)]

use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ErrorCode, FileEntry, MAX_MANIFEST_BYTES, MaintenanceError, RegisteredRoot, Result,
    VerifiedFileSet, canonical_json, decode_lower_hex,
    file_set::validate_relative_path,
    parse_canonical,
    roots::{DirectoryIdentity, metadata_identity},
};

const JOURNAL_SCHEMA: u64 = 1;
const PRIVATE_JOBS_DIRECTORY: &str = "jobs";
const RESERVED_ROOT_DIRECTORY: &str = ".7launcher-maintenance";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalState {
    Prepared,
    Committing,
    Committed,
    RollingBack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum JournalAction {
    Replace,
    Remove,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetSnapshot {
    pub identity: DirectoryIdentity,
    pub last_write_time: u64,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalEntry {
    action: JournalAction,
    original: Option<TargetSnapshot>,
    path: String,
    prepared_index: Option<u32>,
    transaction_index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalHeader {
    entries: Vec<JournalEntry>,
    generation: u64,
    job_id: String,
    manifest_digest: String,
    root: RegisteredRoot,
    schema: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalStateRecord {
    state: JournalState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationBoundary {
    Before,
    After,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationKind {
    RenameTargetToBackup,
    RenamePreparedToTarget,
    DeleteTarget,
    RestoreBackup,
    CleanupJob,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationEvent {
    pub boundary: MutationBoundary,
    pub kind: MutationKind,
    pub path: Option<String>,
}

pub trait MutationFaultInjector: Send + Sync {
    fn checkpoint(&self, event: &MutationEvent) -> Result<()>;
}

#[derive(Default)]
struct NoFaultInjection;

impl MutationFaultInjector for NoFaultInjection {
    fn checkpoint(&self, _event: &MutationEvent) -> Result<()> {
        Ok(())
    }
}

pub trait TransactionPlatform: Send + Sync {
    fn verify_root_identity(&self, root: &RegisteredRoot) -> Result<()> {
        local_verify_root_identity(root)
    }

    fn root_is_missing(&self, root: &RegisteredRoot) -> bool {
        local_root_is_missing(root)
    }

    fn available_space(&self, _path: &Path) -> Result<u64> {
        Ok(u64::MAX)
    }

    fn same_volume(&self, _left: &Path, _right: &Path) -> Result<bool> {
        // Conservative until the Windows handle policy compares volume identities.
        Ok(true)
    }

    fn open_staging_payload(
        &self,
        staging_root: &Path,
        relative_path: &str,
    ) -> Result<Box<dyn Read + Send>> {
        local_open_staging_payload(staging_root, relative_path)
    }

    fn inspect_target(
        &self,
        root: &RegisteredRoot,
        relative_path: &str,
    ) -> Result<Option<TargetSnapshot>> {
        local_inspect_target(root, relative_path)
    }

    fn prepare_target_payload(
        &self,
        root: &RegisteredRoot,
        job_id: &str,
        index: u32,
        private_payload: &Path,
        expected: &FileEntry,
    ) -> Result<()> {
        local_prepare_target_payload(root, job_id, index, private_payload, expected)
    }

    fn rename_target_to_backup(
        &self,
        root: &RegisteredRoot,
        job_id: &str,
        index: u32,
        relative_path: &str,
        expected: TargetSnapshot,
    ) -> Result<()> {
        local_rename_target_to_backup(root, job_id, index, relative_path, expected)
    }

    fn rename_prepared_to_target(
        &self,
        root: &RegisteredRoot,
        job_id: &str,
        index: u32,
        relative_path: &str,
    ) -> Result<()> {
        local_rename_prepared_to_target(root, job_id, index, relative_path)
    }

    fn target_exists(&self, root: &RegisteredRoot, relative_path: &str) -> Result<bool> {
        Ok(self.inspect_target(root, relative_path)?.is_some())
    }

    fn backup_exists(&self, root: &RegisteredRoot, job_id: &str, index: u32) -> Result<bool> {
        local_backup_exists(root, job_id, index)
    }

    fn delete_target(&self, root: &RegisteredRoot, relative_path: &str) -> Result<()> {
        local_delete_target(root, relative_path)
    }

    fn restore_backup(
        &self,
        root: &RegisteredRoot,
        job_id: &str,
        index: u32,
        relative_path: &str,
    ) -> Result<()> {
        local_restore_backup(root, job_id, index, relative_path)
    }

    fn cleanup_job(
        &self,
        root: &RegisteredRoot,
        job_id: &str,
        private_job_directory: &Path,
    ) -> Result<()> {
        local_cleanup_job(root, job_id, private_job_directory)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LocalTransactionPlatform;

impl TransactionPlatform for LocalTransactionPlatform {}

#[derive(Clone)]
pub struct TransactionPolicy {
    data_directory: PathBuf,
    platform: Arc<dyn TransactionPlatform>,
    fault_injector: Arc<dyn MutationFaultInjector>,
}

impl fmt::Debug for TransactionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionPolicy")
            .field("data_directory", &self.data_directory)
            .finish_non_exhaustive()
    }
}

impl TransactionPolicy {
    pub fn local(data_directory: impl Into<PathBuf>) -> Result<Self> {
        Self::new(data_directory, Arc::new(LocalTransactionPlatform))
    }

    pub fn new(
        data_directory: impl Into<PathBuf>,
        platform: Arc<dyn TransactionPlatform>,
    ) -> Result<Self> {
        let data_directory = data_directory.into();
        if !data_directory.is_absolute() {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionState,
                "service data directory must be absolute",
            ));
        }
        fs::create_dir_all(&data_directory).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "service data directory cannot be created",
            )
        })?;
        let data_directory = fs::canonicalize(data_directory).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "service data directory cannot be canonicalized",
            )
        })?;
        Ok(Self {
            data_directory,
            platform,
            fault_injector: Arc::new(NoFaultInjection),
        })
    }

    #[must_use]
    pub fn with_fault_injector(mut self, injector: Arc<dyn MutationFaultInjector>) -> Self {
        self.fault_injector = injector;
        self
    }

    #[must_use]
    pub fn data_directory(&self) -> &Path {
        &self.data_directory
    }
}

#[derive(Debug)]
pub struct PreparedJob {
    header: JournalHeader,
    job_directory: PathBuf,
    journal_path: PathBuf,
    policy: TransactionPolicy,
}

impl PreparedJob {
    #[must_use]
    pub fn job_id(&self) -> &str {
        &self.header.job_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitResult {
    pub job_id: String,
    pub generation: u64,
    pub cleanup_pending: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveryResult {
    pub discarded_prepared_jobs: Vec<String>,
    pub rolled_back_jobs: Vec<String>,
    pub committed_jobs: Vec<String>,
}

pub fn prepare_file_set(
    manifest: &VerifiedFileSet,
    root: &RegisteredRoot,
    staging: &Path,
    policy: TransactionPolicy,
) -> Result<PreparedJob> {
    policy.platform.verify_root_identity(root)?;
    if manifest.file_set().product_id != root.product_id() {
        return Err(MaintenanceError::new(
            ErrorCode::ProductMismatch,
            "verified file set belongs to another registered product",
        ));
    }
    if !staging.is_absolute() {
        return Err(MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "staging directory must be absolute",
        ));
    }

    let declared_size = manifest
        .file_set()
        .files
        .iter()
        .try_fold(0_u64, |total, entry| total.checked_add(entry.size))
        .ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::InsufficientSpace,
                "declared payload size overflowed",
            )
        })?;
    ensure_available_space(&policy, root, declared_size)?;

    let job_id = format!(
        "{}-{}-{}",
        root.root_id(),
        manifest.file_set().generation,
        encode_hex(&manifest.digest())
    );
    let jobs_directory = policy.data_directory.join(PRIVATE_JOBS_DIRECTORY);
    fs::create_dir_all(&jobs_directory).map_err(transaction_io)?;
    let job_directory = jobs_directory.join(&job_id);
    fs::create_dir(&job_directory).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionConflict,
            "a transaction with this manifest already exists",
        )
    })?;
    let private_payload_directory = job_directory.join("payload");
    fs::create_dir(&private_payload_directory).map_err(transaction_io)?;

    let result = prepare_job_contents(
        manifest,
        root,
        staging,
        &policy,
        &job_id,
        &job_directory,
        &private_payload_directory,
    );
    match result {
        Ok((header, journal_path)) => Ok(PreparedJob {
            header,
            job_directory,
            journal_path,
            policy,
        }),
        Err(error) => {
            let _cleanup_result = policy.platform.cleanup_job(root, &job_id, &job_directory);
            Err(error)
        }
    }
}

fn prepare_job_contents(
    manifest: &VerifiedFileSet,
    root: &RegisteredRoot,
    staging: &Path,
    policy: &TransactionPolicy,
    job_id: &str,
    job_directory: &Path,
    private_payload_directory: &Path,
) -> Result<(JournalHeader, PathBuf)> {
    for (index, entry) in manifest.file_set().files.iter().enumerate() {
        let source = policy.platform.open_staging_payload(staging, &entry.path)?;
        let private_payload = private_payload_directory.join(index.to_string());
        copy_reader_verified(source, &private_payload, entry)?;
    }

    let mut entries = Vec::with_capacity(
        manifest.file_set().files.len() + manifest.file_set().remove_files.len(),
    );
    for (index, entry) in manifest.file_set().files.iter().enumerate() {
        let prepared_index = u32::try_from(index).map_err(|_| {
            MaintenanceError::new(ErrorCode::TransactionState, "prepared index overflowed")
        })?;
        entries.push(JournalEntry {
            action: JournalAction::Replace,
            original: policy.platform.inspect_target(root, &entry.path)?,
            path: entry.path.clone(),
            prepared_index: Some(prepared_index),
            transaction_index: prepared_index,
        });
    }
    for (remove_index, path) in manifest.file_set().remove_files.iter().enumerate() {
        let transaction_index = manifest
            .file_set()
            .files
            .len()
            .checked_add(remove_index)
            .and_then(|index| u32::try_from(index).ok())
            .ok_or_else(|| {
                MaintenanceError::new(ErrorCode::TransactionState, "transaction index overflowed")
            })?;
        entries.push(JournalEntry {
            action: JournalAction::Remove,
            original: policy.platform.inspect_target(root, path)?,
            path: path.clone(),
            prepared_index: None,
            transaction_index,
        });
    }

    let header = JournalHeader {
        entries,
        generation: manifest.file_set().generation,
        job_id: job_id.to_owned(),
        manifest_digest: encode_hex(&manifest.digest()),
        root: root.clone(),
        schema: JOURNAL_SCHEMA,
    };
    let journal_path = job_directory.join("journal.jsonl");
    write_new_journal(&journal_path, &header)?;

    for (index, entry) in manifest.file_set().files.iter().enumerate() {
        let prepared_index = u32::try_from(index).map_err(|_| {
            MaintenanceError::new(ErrorCode::TransactionState, "prepared index overflowed")
        })?;
        policy.platform.prepare_target_payload(
            root,
            job_id,
            prepared_index,
            &private_payload_directory.join(index.to_string()),
            entry,
        )?;
    }
    Ok((header, journal_path))
}

pub fn commit_file_set(prepared: PreparedJob) -> Result<CommitResult> {
    prepared
        .policy
        .platform
        .verify_root_identity(&prepared.header.root)?;
    verify_original_snapshots(&prepared)?;
    append_state(&prepared.journal_path, JournalState::Committing)?;

    if let Err(commit_error) = apply_entries(&prepared) {
        let _state_result = append_state(&prepared.journal_path, JournalState::RollingBack);
        if rollback_entries(&prepared).is_err() || cleanup_prepared_job(&prepared).is_err() {
            return Err(MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "commit failed and rollback must be resumed by recovery",
            ));
        }
        return Err(commit_error);
    }
    if append_state(&prepared.journal_path, JournalState::Committed).is_err() {
        let _state_result = append_state(&prepared.journal_path, JournalState::RollingBack);
        if rollback_entries(&prepared).is_err() || cleanup_prepared_job(&prepared).is_err() {
            return Err(MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "journal commit failed and rollback must be resumed by recovery",
            ));
        }
        return Err(MaintenanceError::new(
            ErrorCode::TransactionIo,
            "committed journal state could not be persisted",
        ));
    }

    let cleanup_pending = cleanup_prepared_job(&prepared).is_err();
    Ok(CommitResult {
        job_id: prepared.header.job_id,
        generation: prepared.header.generation,
        cleanup_pending,
    })
}

pub fn recover_incomplete(data_directory: &Path) -> Result<RecoveryResult> {
    let policy = TransactionPolicy::local(data_directory.to_path_buf())?;
    recover_incomplete_with_policy(policy)
}

pub fn recover_incomplete_with_policy(policy: TransactionPolicy) -> Result<RecoveryResult> {
    let jobs_directory = policy.data_directory.join(PRIVATE_JOBS_DIRECTORY);
    if !jobs_directory.exists() {
        return Ok(RecoveryResult::default());
    }
    let mut job_directories = fs::read_dir(&jobs_directory)
        .map_err(transaction_io)?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(transaction_io)?;
    job_directories.sort_by_key(fs::DirEntry::file_name);

    let mut result = RecoveryResult::default();
    for directory in job_directories {
        let file_type = directory.file_type().map_err(transaction_io)?;
        let directory_metadata = fs::symlink_metadata(directory.path()).map_err(transaction_io)?;
        if !file_type.is_dir()
            || file_type.is_symlink()
            || metadata_has_reparse_point(&directory_metadata)
        {
            return Err(MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "unexpected entry exists in the private jobs directory",
            ));
        }
        let job_directory = directory.path();
        let journal_path = job_directory.join("journal.jsonl");
        if !journal_path.exists() {
            fs::remove_dir_all(&job_directory).map_err(transaction_io)?;
            result
                .discarded_prepared_jobs
                .push(directory.file_name().to_string_lossy().into_owned());
            continue;
        }
        let (header, state) = read_journal(&journal_path)?;
        if directory.file_name().to_string_lossy() != header.job_id {
            return Err(MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "transaction directory does not match journal job ID",
            ));
        }
        let prepared = PreparedJob {
            header,
            job_directory,
            journal_path,
            policy: policy.clone(),
        };
        if let Err(identity_error) = policy.platform.verify_root_identity(&prepared.header.root) {
            if state == JournalState::Prepared
                && policy.platform.root_is_missing(&prepared.header.root)
            {
                cleanup_private_prepared_job(&prepared)?;
                result
                    .discarded_prepared_jobs
                    .push(prepared.header.job_id.clone());
                continue;
            }
            return Err(identity_error);
        }
        match state {
            JournalState::Prepared => {
                cleanup_prepared_job(&prepared)?;
                result
                    .discarded_prepared_jobs
                    .push(prepared.header.job_id.clone());
            }
            JournalState::Committing | JournalState::RollingBack => {
                if state == JournalState::Committing {
                    append_state(&prepared.journal_path, JournalState::RollingBack)?;
                }
                rollback_entries(&prepared)?;
                cleanup_prepared_job(&prepared)?;
                result.rolled_back_jobs.push(prepared.header.job_id.clone());
            }
            JournalState::Committed => {
                cleanup_prepared_job(&prepared)?;
                result.committed_jobs.push(prepared.header.job_id.clone());
            }
        }
    }
    Ok(result)
}

fn ensure_available_space(
    policy: &TransactionPolicy,
    root: &RegisteredRoot,
    required: u64,
) -> Result<()> {
    let same_volume = policy
        .platform
        .same_volume(&policy.data_directory, root.canonical_path())?;
    let private_required = if same_volume {
        required.checked_mul(2).ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::InsufficientSpace,
                "same-volume staging requirement overflowed",
            )
        })?
    } else {
        required
    };
    if policy.platform.available_space(&policy.data_directory)? < private_required
        || (!same_volume && policy.platform.available_space(root.canonical_path())? < required)
    {
        return Err(MaintenanceError::new(
            ErrorCode::InsufficientSpace,
            "private staging or registered root has insufficient free space",
        ));
    }
    Ok(())
}

fn verify_original_snapshots(prepared: &PreparedJob) -> Result<()> {
    for entry in &prepared.header.entries {
        let current = prepared
            .policy
            .platform
            .inspect_target(&prepared.header.root, &entry.path)?;
        if current != entry.original {
            return Err(MaintenanceError::new(
                ErrorCode::RootIdentity,
                "target identity changed between prepare and commit",
            ));
        }
    }
    Ok(())
}

fn apply_entries(prepared: &PreparedJob) -> Result<()> {
    for entry in &prepared.header.entries {
        if let Some(original) = entry.original {
            let index = entry.transaction_index;
            run_mutation(
                &prepared.policy,
                MutationKind::RenameTargetToBackup,
                Some(&entry.path),
                || {
                    prepared.policy.platform.rename_target_to_backup(
                        &prepared.header.root,
                        &prepared.header.job_id,
                        index,
                        &entry.path,
                        original,
                    )
                },
            )?;
        }
        if entry.action == JournalAction::Replace {
            let index = entry.prepared_index.ok_or_else(|| {
                MaintenanceError::new(
                    ErrorCode::TransactionState,
                    "replacement journal entry has no prepared index",
                )
            })?;
            run_mutation(
                &prepared.policy,
                MutationKind::RenamePreparedToTarget,
                Some(&entry.path),
                || {
                    prepared.policy.platform.rename_prepared_to_target(
                        &prepared.header.root,
                        &prepared.header.job_id,
                        index,
                        &entry.path,
                    )
                },
            )?;
        }
    }
    Ok(())
}

fn rollback_entries(prepared: &PreparedJob) -> Result<()> {
    prepared
        .policy
        .platform
        .verify_root_identity(&prepared.header.root)?;
    for entry in prepared.header.entries.iter().rev() {
        let index = entry.transaction_index;
        let backup_exists = entry.original.is_some()
            && prepared.policy.platform.backup_exists(
                &prepared.header.root,
                &prepared.header.job_id,
                index,
            )?;
        if backup_exists {
            if prepared
                .policy
                .platform
                .target_exists(&prepared.header.root, &entry.path)?
            {
                run_mutation(
                    &prepared.policy,
                    MutationKind::DeleteTarget,
                    Some(&entry.path),
                    || {
                        prepared
                            .policy
                            .platform
                            .delete_target(&prepared.header.root, &entry.path)
                    },
                )?;
            }
            run_mutation(
                &prepared.policy,
                MutationKind::RestoreBackup,
                Some(&entry.path),
                || {
                    prepared.policy.platform.restore_backup(
                        &prepared.header.root,
                        &prepared.header.job_id,
                        index,
                        &entry.path,
                    )
                },
            )?;
        } else if entry.original.is_none()
            && prepared
                .policy
                .platform
                .target_exists(&prepared.header.root, &entry.path)?
        {
            run_mutation(
                &prepared.policy,
                MutationKind::DeleteTarget,
                Some(&entry.path),
                || {
                    prepared
                        .policy
                        .platform
                        .delete_target(&prepared.header.root, &entry.path)
                },
            )?;
        }
    }
    Ok(())
}

fn cleanup_prepared_job(prepared: &PreparedJob) -> Result<()> {
    run_mutation(&prepared.policy, MutationKind::CleanupJob, None, || {
        prepared.policy.platform.cleanup_job(
            &prepared.header.root,
            &prepared.header.job_id,
            &prepared.job_directory,
        )
    })
}

fn cleanup_private_prepared_job(prepared: &PreparedJob) -> Result<()> {
    run_mutation(&prepared.policy, MutationKind::CleanupJob, None, || {
        if prepared.job_directory.exists() {
            validate_absolute_directory(&prepared.job_directory, ErrorCode::TransactionIo)?;
            fs::remove_dir_all(&prepared.job_directory).map_err(transaction_io)?;
        }
        Ok(())
    })
}

fn run_mutation(
    policy: &TransactionPolicy,
    kind: MutationKind,
    path: Option<&str>,
    operation: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let path = path.map(str::to_owned);
    policy.fault_injector.checkpoint(&MutationEvent {
        boundary: MutationBoundary::Before,
        kind,
        path: path.clone(),
    })?;
    operation()?;
    policy.fault_injector.checkpoint(&MutationEvent {
        boundary: MutationBoundary::After,
        kind,
        path,
    })
}

fn write_new_journal(path: &Path, header: &JournalHeader) -> Result<()> {
    let mut output = BufWriter::new(
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(transaction_io)?,
    );
    write_journal_line(&mut output, header)?;
    write_journal_line(
        &mut output,
        &JournalStateRecord {
            state: JournalState::Prepared,
        },
    )?;
    output.flush().map_err(transaction_io)?;
    output.get_ref().sync_all().map_err(transaction_io)
}

fn append_state(path: &Path, state: JournalState) -> Result<()> {
    let mut output = BufWriter::new(
        OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(transaction_io)?,
    );
    write_journal_line(&mut output, &JournalStateRecord { state })?;
    output.flush().map_err(transaction_io)?;
    output.get_ref().sync_all().map_err(transaction_io)
}

fn write_journal_line(output: &mut impl Write, value: &impl Serialize) -> Result<()> {
    let value = serde_json::to_value(value).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionState,
            "journal record cannot be encoded",
        )
    })?;
    output
        .write_all(&canonical_json(&value)?)
        .map_err(transaction_io)?;
    output.write_all(b"\n").map_err(transaction_io)
}

fn read_journal(path: &Path) -> Result<(JournalHeader, JournalState)> {
    let file = File::open(path).map_err(transaction_io)?;
    let mut bytes = Vec::with_capacity(MAX_MANIFEST_BYTES.min(64 * 1024));
    file.take((MAX_MANIFEST_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(transaction_io)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "transaction journal exceeds the bound",
        ));
    }
    let lines: Vec<&[u8]> = bytes.split(|byte| *byte == b'\n').collect();
    let header_bytes = lines
        .first()
        .copied()
        .filter(|line| !line.is_empty())
        .ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "transaction journal has no header",
            )
        })?;
    let header: JournalHeader = parse_canonical(header_bytes, MAX_MANIFEST_BYTES)?;
    validate_journal_header(&header)?;

    let mut state = None;
    for (index, line) in lines.iter().enumerate().skip(1) {
        if line.is_empty() {
            continue;
        }
        match parse_canonical::<JournalStateRecord>(line, 128) {
            Ok(record) => {
                validate_state_transition(state, record.state)?;
                state = Some(record.state);
            }
            Err(_) if index + 1 == lines.len() && !bytes.ends_with(b"\n") => break,
            Err(_) => {
                return Err(MaintenanceError::new(
                    ErrorCode::RecoveryIncomplete,
                    "transaction journal contains an invalid record",
                ));
            }
        }
    }
    let state = state.ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "journal has no durable state",
        )
    })?;
    Ok((header, state))
}

fn validate_journal_header(header: &JournalHeader) -> Result<()> {
    if header.schema != JOURNAL_SCHEMA
        || header.entries.is_empty()
        || !valid_internal_job_id(&header.job_id)
        || decode_lower_hex::<32>(&header.manifest_digest, ErrorCode::RecoveryIncomplete).is_err()
    {
        return Err(MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "transaction journal header is unsupported",
        ));
    }
    let mut paths = HashSet::with_capacity(header.entries.len());
    let mut transaction_indexes = HashSet::with_capacity(header.entries.len());
    let mut prepared_indexes = HashSet::new();
    for entry in &header.entries {
        validate_relative_path(&entry.path)?;
        if !paths.insert(entry.path.to_lowercase())
            || !transaction_indexes.insert(entry.transaction_index)
            || (entry.action == JournalAction::Replace && entry.prepared_index.is_none())
            || (entry.action == JournalAction::Remove && entry.prepared_index.is_some())
            || entry
                .prepared_index
                .is_some_and(|index| !prepared_indexes.insert(index))
        {
            return Err(MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "transaction journal entry is inconsistent",
            ));
        }
    }
    Ok(())
}

fn validate_state_transition(previous: Option<JournalState>, next: JournalState) -> Result<()> {
    let valid = matches!(
        (previous, next),
        (None, JournalState::Prepared)
            | (Some(JournalState::Prepared), JournalState::Committing)
            | (Some(JournalState::Committing), JournalState::Committed)
            | (Some(JournalState::Committing), JournalState::RollingBack)
    );
    if valid {
        Ok(())
    } else {
        Err(MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "transaction journal state transition is invalid",
        ))
    }
}

fn copy_reader_verified(
    mut source: Box<dyn Read + Send>,
    destination: &Path,
    expected: &FileEntry,
) -> Result<()> {
    let mut output = BufWriter::new(
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(transaction_io)?,
    );
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer).map_err(|_| {
            MaintenanceError::new(ErrorCode::StagingInvalid, "staging payload read failed")
        })?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            MaintenanceError::new(ErrorCode::StagingInvalid, "staging payload size overflowed")
        })?;
        if total > expected.size {
            return Err(MaintenanceError::new(
                ErrorCode::StagingInvalid,
                "staging payload is larger than the signed size",
            ));
        }
        hash.update(&buffer[..read]);
        output.write_all(&buffer[..read]).map_err(transaction_io)?;
    }
    if total != expected.size
        || hash.finalize().as_slice()
            != decode_lower_hex::<32>(&expected.sha256, ErrorCode::FileSetHash)?
    {
        return Err(MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "staging payload size or SHA-256 does not match the file set",
        ));
    }
    output.flush().map_err(transaction_io)?;
    output.get_ref().sync_all().map_err(transaction_io)
}

fn local_verify_root_identity(root: &RegisteredRoot) -> Result<()> {
    let canonical = fs::canonicalize(root.canonical_path()).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootIdentity,
            "registered root cannot be reopened",
        )
    })?;
    if canonical != root.canonical_path() {
        return Err(MaintenanceError::new(
            ErrorCode::RootIdentity,
            "registered root canonical path changed",
        ));
    }
    let metadata = fs::symlink_metadata(&canonical).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootIdentity,
            "registered root metadata is unavailable",
        )
    })?;
    if metadata.file_type().is_symlink()
        || metadata_has_reparse_point(&metadata)
        || metadata_identity(&metadata, ErrorCode::RootIdentity)? != root.identity()
    {
        return Err(MaintenanceError::new(
            ErrorCode::RootIdentity,
            "registered root identity or reparse status changed",
        ));
    }
    Ok(())
}

fn local_root_is_missing(root: &RegisteredRoot) -> bool {
    matches!(
        fs::symlink_metadata(root.canonical_path()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

fn local_open_staging_payload(
    staging_root: &Path,
    relative_path: &str,
) -> Result<Box<dyn Read + Send>> {
    validate_relative_path(relative_path)?;
    let canonical_staging = fs::canonicalize(staging_root).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "staging directory cannot be canonicalized",
        )
    })?;
    validate_absolute_directory(&canonical_staging, ErrorCode::StagingInvalid)?;
    let source_path =
        checked_descendant(&canonical_staging, relative_path, ErrorCode::StagingInvalid)?;
    let path_metadata = fs::symlink_metadata(&source_path).map_err(|_| {
        MaintenanceError::new(ErrorCode::StagingInvalid, "staging payload does not exist")
    })?;
    validate_regular_file_metadata(&path_metadata, ErrorCode::StagingInvalid)?;
    let file = File::open(&source_path).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "staging payload cannot be opened",
        )
    })?;
    let handle_metadata = file.metadata().map_err(|_| {
        MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "staging handle metadata is unavailable",
        )
    })?;
    if metadata_identity(&path_metadata, ErrorCode::StagingInvalid)?
        != metadata_identity(&handle_metadata, ErrorCode::StagingInvalid)?
    {
        return Err(MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "staging payload changed while opening",
        ));
    }
    Ok(Box::new(BufReader::new(file)))
}

fn local_inspect_target(
    root: &RegisteredRoot,
    relative_path: &str,
) -> Result<Option<TargetSnapshot>> {
    validate_relative_path(relative_path)?;
    let target = checked_descendant(
        root.canonical_path(),
        relative_path,
        ErrorCode::RootIdentity,
    )?;
    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(MaintenanceError::new(
                ErrorCode::RootIdentity,
                "target metadata cannot be inspected",
            ));
        }
    };
    validate_regular_file_metadata(&metadata, ErrorCode::RootIdentity)?;
    Ok(Some(TargetSnapshot {
        identity: metadata_identity(&metadata, ErrorCode::RootIdentity)?,
        last_write_time: metadata_last_write_time(&metadata),
        size: metadata.len(),
    }))
}

fn local_prepare_target_payload(
    root: &RegisteredRoot,
    job_id: &str,
    index: u32,
    private_payload: &Path,
    expected: &FileEntry,
) -> Result<()> {
    ensure_reserved_leaf_directory(root, job_id, "prepared")?;
    let destination = prepared_path(root, job_id, index);
    let source = File::open(private_payload).map_err(transaction_io)?;
    copy_reader_verified(Box::new(BufReader::new(source)), &destination, expected)
}

fn local_rename_target_to_backup(
    root: &RegisteredRoot,
    job_id: &str,
    index: u32,
    relative_path: &str,
    expected: TargetSnapshot,
) -> Result<()> {
    if local_inspect_target(root, relative_path)? != Some(expected) {
        return Err(MaintenanceError::new(
            ErrorCode::RootIdentity,
            "target identity changed before backup rename",
        ));
    }
    let target = root.canonical_path().join(relative_path.replace('/', "\\"));
    ensure_reserved_leaf_directory(root, job_id, "backup")?;
    let backup = backup_path(root, job_id, index);
    if backup.exists() {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionConflict,
            "transaction backup already exists",
        ));
    }
    fs::rename(target, backup).map_err(transaction_io)
}

fn local_rename_prepared_to_target(
    root: &RegisteredRoot,
    job_id: &str,
    index: u32,
    relative_path: &str,
) -> Result<()> {
    if local_inspect_target(root, relative_path)?.is_some() {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionConflict,
            "target exists before prepared rename",
        ));
    }
    let prepared = prepared_path(root, job_id, index);
    validate_regular_file_metadata(
        &fs::symlink_metadata(&prepared).map_err(transaction_io)?,
        ErrorCode::RootIdentity,
    )?;
    let target = root.canonical_path().join(relative_path.replace('/', "\\"));
    ensure_target_parent(root, relative_path)?;
    fs::rename(prepared, target).map_err(transaction_io)
}

fn local_backup_exists(root: &RegisteredRoot, job_id: &str, index: u32) -> Result<bool> {
    validate_reserved_job_directory(root, job_id)?;
    let backup = backup_path(root, job_id, index);
    match fs::symlink_metadata(backup) {
        Ok(metadata) => {
            validate_regular_file_metadata(&metadata, ErrorCode::RootIdentity)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(MaintenanceError::new(
            ErrorCode::TransactionIo,
            "transaction backup cannot be inspected",
        )),
    }
}

fn local_delete_target(root: &RegisteredRoot, relative_path: &str) -> Result<()> {
    if local_inspect_target(root, relative_path)?.is_none() {
        return Ok(());
    }
    let target = root.canonical_path().join(relative_path.replace('/', "\\"));
    match fs::remove_file(target) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(MaintenanceError::new(
            ErrorCode::TransactionIo,
            "transaction target delete failed",
        )),
    }
}

fn local_restore_backup(
    root: &RegisteredRoot,
    job_id: &str,
    index: u32,
    relative_path: &str,
) -> Result<()> {
    if local_inspect_target(root, relative_path)?.is_some() {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionConflict,
            "target exists before backup restore",
        ));
    }
    let backup = backup_path(root, job_id, index);
    validate_regular_file_metadata(
        &fs::symlink_metadata(&backup).map_err(transaction_io)?,
        ErrorCode::RootIdentity,
    )?;
    let target = root.canonical_path().join(relative_path.replace('/', "\\"));
    ensure_target_parent(root, relative_path)?;
    fs::rename(backup, target).map_err(transaction_io)
}

fn local_cleanup_job(
    root: &RegisteredRoot,
    job_id: &str,
    private_job_directory: &Path,
) -> Result<()> {
    let reserved_job = reserved_job_directory(root, job_id);
    if reserved_job.exists() {
        validate_reserved_job_directory(root, job_id)?;
        fs::remove_dir_all(&reserved_job).map_err(transaction_io)?;
    }
    if private_job_directory.exists() {
        validate_absolute_directory(private_job_directory, ErrorCode::TransactionIo)?;
        fs::remove_dir_all(private_job_directory).map_err(transaction_io)?;
    }
    Ok(())
}

fn validate_absolute_directory(path: &Path, code: ErrorCode) -> Result<()> {
    if !path.is_absolute() {
        return Err(MaintenanceError::new(
            code,
            "directory path must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| MaintenanceError::new(code, "directory metadata is unavailable"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata_has_reparse_point(&metadata)
    {
        return Err(MaintenanceError::new(
            code,
            "directory is not a safe non-reparse directory",
        ));
    }
    Ok(())
}

fn checked_descendant(root: &Path, relative_path: &str, code: ErrorCode) -> Result<PathBuf> {
    validate_relative_path(relative_path)?;
    let mut current = root.to_path_buf();
    for component in Path::new(relative_path).components() {
        let Component::Normal(component) = component else {
            return Err(MaintenanceError::new(
                code,
                "relative path contains a non-normal component",
            ));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata)
                if metadata.file_type().is_symlink() || metadata_has_reparse_point(&metadata) =>
            {
                return Err(MaintenanceError::new(
                    code,
                    "path traversal encountered a reparse point",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => {
                return Err(MaintenanceError::new(
                    code,
                    "path component metadata cannot be inspected",
                ));
            }
        }
    }
    Ok(root.join(relative_path.replace('/', "\\")))
}

fn validate_regular_file_metadata(metadata: &fs::Metadata, code: ErrorCode) -> Result<()> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata_has_reparse_point(metadata)
        || metadata_has_multiple_links(metadata)
    {
        return Err(MaintenanceError::new(
            code,
            "file is not a safe single-link regular file",
        ));
    }
    Ok(())
}

fn validate_reserved_job_directory(root: &RegisteredRoot, job_id: &str) -> Result<()> {
    if !valid_internal_job_id(job_id) {
        return Err(MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "transaction job ID is invalid",
        ));
    }
    let mut current = root.canonical_path().to_path_buf();
    for component in [RESERVED_ROOT_DIRECTORY, "jobs", job_id] {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata)
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata_has_reparse_point(&metadata) =>
            {
                return Err(MaintenanceError::new(
                    ErrorCode::RootIdentity,
                    "reserved transaction directory is not safe",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => {
                return Err(MaintenanceError::new(
                    ErrorCode::RootIdentity,
                    "reserved transaction directory cannot be inspected",
                ));
            }
        }
    }
    Ok(())
}

fn ensure_reserved_leaf_directory(
    root: &RegisteredRoot,
    job_id: &str,
    leaf: &str,
) -> Result<PathBuf> {
    if !valid_internal_job_id(job_id) || !matches!(leaf, "prepared" | "backup") {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionState,
            "reserved transaction path is invalid",
        ));
    }
    let mut current = root.canonical_path().to_path_buf();
    for component in [RESERVED_ROOT_DIRECTORY, "jobs", job_id, leaf] {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata)
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata_has_reparse_point(&metadata) =>
            {
                return Err(MaintenanceError::new(
                    ErrorCode::RootIdentity,
                    "reserved transaction path contains an unsafe component",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(transaction_io)?;
                let metadata = fs::symlink_metadata(&current).map_err(transaction_io)?;
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata_has_reparse_point(&metadata)
                {
                    return Err(MaintenanceError::new(
                        ErrorCode::RootIdentity,
                        "created transaction directory changed identity",
                    ));
                }
            }
            Err(_) => {
                return Err(MaintenanceError::new(
                    ErrorCode::RootIdentity,
                    "reserved transaction path cannot be inspected",
                ));
            }
        }
    }
    Ok(current)
}

fn ensure_target_parent(root: &RegisteredRoot, relative_path: &str) -> Result<PathBuf> {
    validate_relative_path(relative_path)?;
    let mut components: Vec<_> = Path::new(relative_path).components().collect();
    if components.pop().is_none() {
        return Err(MaintenanceError::new(
            ErrorCode::FileSetPath,
            "target path has no file component",
        ));
    }
    let mut current = root.canonical_path().to_path_buf();
    for component in components {
        let Component::Normal(component) = component else {
            return Err(MaintenanceError::new(
                ErrorCode::FileSetPath,
                "target parent contains a non-normal component",
            ));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata)
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata_has_reparse_point(&metadata) =>
            {
                return Err(MaintenanceError::new(
                    ErrorCode::RootIdentity,
                    "target parent contains an unsafe component",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(transaction_io)?;
            }
            Err(_) => {
                return Err(MaintenanceError::new(
                    ErrorCode::RootIdentity,
                    "target parent cannot be inspected",
                ));
            }
        }
    }
    Ok(current)
}

fn valid_internal_job_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn reserved_job_directory(root: &RegisteredRoot, job_id: &str) -> PathBuf {
    root.canonical_path()
        .join(RESERVED_ROOT_DIRECTORY)
        .join("jobs")
        .join(job_id)
}

fn prepared_path(root: &RegisteredRoot, job_id: &str, index: u32) -> PathBuf {
    reserved_job_directory(root, job_id)
        .join("prepared")
        .join(index.to_string())
}

fn backup_path(root: &RegisteredRoot, job_id: &str, index: u32) -> PathBuf {
    reserved_job_directory(root, job_id)
        .join("backup")
        .join(index.to_string())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn transaction_io(_error: std::io::Error) -> MaintenanceError {
    MaintenanceError::new(
        ErrorCode::TransactionIo,
        "transaction filesystem operation failed",
    )
}

#[cfg(windows)]
fn metadata_has_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn metadata_last_write_time(metadata: &fs::Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt;

    metadata.last_write_time()
}

#[cfg(not(windows))]
fn metadata_has_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn metadata_has_multiple_links(_metadata: &fs::Metadata) -> bool {
    // Stable std does not expose link count. The Windows service policy must override every local
    // filesystem operation and enforce link-count checks on the opened handle.
    false
}

#[cfg(unix)]
fn metadata_has_multiple_links(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.nlink() > 1
}

#[cfg(unix)]
fn metadata_last_write_time(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;

    let seconds = u64::try_from(metadata.mtime()).unwrap_or_default();
    let nanoseconds = u64::try_from(metadata.mtime_nsec()).unwrap_or_default();
    seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(nanoseconds)
}
