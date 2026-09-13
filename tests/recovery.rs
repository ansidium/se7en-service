use std::{
    fs,
    io::Read,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use seven_launcher_maintenance::{
    ErrorCode, FILE_SET_SIGNING_DOMAIN, FileSetAcceptance, KEYRING_SIGNING_DOMAIN,
    KeyringAcceptance, LocalTransactionPlatform, MaintenanceError, MutationEvent,
    MutationFaultInjector, MutationKind, RegisteredRoot, RootRegistry, TransactionPlatform,
    TransactionPolicy, VerifiedFileSet, canonical_json, commit_file_set, prepare_file_set,
    protocol::RootKind, recover_incomplete, recover_incomplete_with_policy, signing_message,
    verify_file_set, verify_keyring_with_root,
};
use sha2::{Digest, Sha256};

const ROOT_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const RELEASE_SEED: [u8; 32] = [0x42; 32];
const OWNER_SID: &str = "S-1-5-21-1000";

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

struct TestWorkspace {
    base: PathBuf,
    data: PathBuf,
    root: PathBuf,
    staging: PathBuf,
}

impl TestWorkspace {
    fn new(label: &str) -> Self {
        let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "7launcher-maintenance-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&base).expect("unique test directory");
        let data = base.join("data");
        let root = base.join("root");
        let staging = base.join("staging");
        for directory in [&data, &root, &staging] {
            fs::create_dir(directory).expect("test subdirectory");
        }
        Self {
            base,
            data,
            root,
            staging,
        }
    }

    fn registered_root(&self) -> RegisteredRoot {
        RegisteredRoot::from_verified_path(
            "sample-app-launcher",
            "sample-app",
            RootKind::Launcher,
            &self.root,
            OWNER_SID,
        )
        .expect("registered test root")
    }

    fn write_old_root(&self) {
        fs::create_dir_all(self.root.join("bin")).expect("root bin");
        fs::write(self.root.join("bin/a.bin"), b"old-a").expect("old a");
        fs::write(self.root.join("b.bin"), b"old-b").expect("old b");
        fs::write(self.root.join("obsolete.dll"), b"old-obsolete").expect("obsolete");
    }

    fn write_staging(&self) {
        fs::create_dir_all(self.staging.join("bin")).expect("staging bin");
        fs::write(self.staging.join("bin/a.bin"), b"new-a").expect("new a");
        fs::write(self.staging.join("b.bin"), b"new-b").expect("new b");
        fs::write(self.staging.join("new.bin"), b"brand-new").expect("new file");
    }

    fn assert_old_root(&self) {
        assert_eq!(
            fs::read(self.root.join("bin/a.bin")).expect("old a"),
            b"old-a"
        );
        assert_eq!(fs::read(self.root.join("b.bin")).expect("old b"), b"old-b");
        assert_eq!(
            fs::read(self.root.join("obsolete.dll")).expect("obsolete"),
            b"old-obsolete"
        );
        assert!(!self.root.join("new.bin").exists());
    }

    fn assert_new_root(&self) {
        assert_eq!(
            fs::read(self.root.join("bin/a.bin")).expect("new a"),
            b"new-a"
        );
        assert_eq!(fs::read(self.root.join("b.bin")).expect("new b"), b"new-b");
        assert_eq!(
            fs::read(self.root.join("new.bin")).expect("new file"),
            b"brand-new"
        );
        assert!(!self.root.join("obsolete.dll").exists());
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.base);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn sign_document(mut payload: Value, seed: [u8; 32], domain: &[u8]) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(&seed);
    let payload_bytes = canonical_json(&payload).expect("canonical test payload");
    let signature = signing_key.sign(&signing_message(domain, &payload_bytes));
    payload.as_object_mut().expect("object").insert(
        "signature".to_owned(),
        Value::String(hex(&signature.to_bytes())),
    );
    canonical_json(&payload).expect("canonical signed test document")
}

fn verified_file_set() -> VerifiedFileSet {
    let release_key = SigningKey::from_bytes(&RELEASE_SEED).verifying_key();
    let keyring_bytes = sign_document(
        json!({
            "authenticodeSignerThumbprints": [],
            "kind": "7launcher-maintenance-keyring-v1",
            "releaseKeys": [{"keyId": "release-2026", "publicKey": hex(&release_key.to_bytes())}],
            "schema": 1,
            "version": 1
        }),
        ROOT_SEED,
        KEYRING_SIGNING_DOMAIN,
    );
    let root_public_key = SigningKey::from_bytes(&ROOT_SEED)
        .verifying_key()
        .to_bytes();
    let keyring = verify_keyring_with_root(
        &keyring_bytes,
        KeyringAcceptance::default(),
        &root_public_key,
    )
    .expect("keyring");
    let file_set_bytes = sign_document(
        json!({
            "files": [
                {"path": "bin/a.bin", "sha256": sha256(b"new-a"), "size": 5},
                {"path": "b.bin", "sha256": sha256(b"new-b"), "size": 5},
                {"path": "new.bin", "sha256": sha256(b"brand-new"), "size": 9}
            ],
            "generation": 42,
            "keyId": "release-2026",
            "kind": "7launcher-file-set-v1",
            "productId": "sample-app",
            "removeFiles": ["obsolete.dll"],
            "schema": 1
        }),
        RELEASE_SEED,
        FILE_SET_SIGNING_DOMAIN,
    );
    verify_file_set(
        &file_set_bytes,
        &keyring,
        FileSetAcceptance {
            expected_product_id: "sample-app",
            previous: None,
        },
    )
    .expect("file set")
}

#[derive(Default)]
struct RecordingFaultInjector {
    events: Mutex<Vec<MutationEvent>>,
    panic_at: Option<usize>,
    sequence: AtomicUsize,
}

impl RecordingFaultInjector {
    fn new(panic_at: Option<usize>) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            panic_at,
            sequence: AtomicUsize::new(0),
        }
    }

    fn events(&self) -> Vec<MutationEvent> {
        self.events.lock().expect("events lock").clone()
    }
}

impl MutationFaultInjector for RecordingFaultInjector {
    fn checkpoint(&self, event: &MutationEvent) -> seven_launcher_maintenance::Result<()> {
        let index = self.sequence.fetch_add(1, Ordering::SeqCst);
        self.events.lock().expect("events lock").push(event.clone());
        assert_ne!(
            self.panic_at,
            Some(index),
            "simulated power loss at {index}"
        );
        Ok(())
    }
}

struct ErrorFaultInjector {
    fail_at: usize,
    sequence: AtomicUsize,
}

impl MutationFaultInjector for ErrorFaultInjector {
    fn checkpoint(&self, _event: &MutationEvent) -> seven_launcher_maintenance::Result<()> {
        let index = self.sequence.fetch_add(1, Ordering::SeqCst);
        if index == self.fail_at {
            Err(MaintenanceError::policy_rejection(ErrorCode::TransactionIo))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct NoSpacePlatform;

impl TransactionPlatform for NoSpacePlatform {
    fn available_space(&self, _path: &Path) -> seven_launcher_maintenance::Result<u64> {
        Ok(0)
    }
}

#[derive(Default)]
struct RejectStagingPlatform;

impl TransactionPlatform for RejectStagingPlatform {
    fn open_staging_payload(
        &self,
        _staging_root: &Path,
        _relative_path: &str,
    ) -> seven_launcher_maintenance::Result<Box<dyn Read + Send>> {
        Err(MaintenanceError::policy_rejection(
            ErrorCode::StagingInvalid,
        ))
    }
}

fn prepared_workspace(
    label: &str,
    injector: Arc<dyn MutationFaultInjector>,
) -> (
    TestWorkspace,
    TransactionPolicy,
    seven_launcher_maintenance::PreparedJob,
) {
    let workspace = TestWorkspace::new(label);
    workspace.write_old_root();
    workspace.write_staging();
    let root = workspace.registered_root();
    let policy = TransactionPolicy::local(&workspace.data)
        .expect("local policy")
        .with_fault_injector(injector);
    let prepared = prepare_file_set(
        &verified_file_set(),
        &root,
        &workspace.staging,
        policy.clone(),
    )
    .expect("prepared job");
    (workspace, policy, prepared)
}

#[test]
fn recovery_registry_resolves_only_owned_product_root_id() {
    let workspace = TestWorkspace::new("registry");
    let root = workspace.registered_root();
    let mut registry = RootRegistry::new();
    registry.register(root.clone()).expect("register root");
    let registry_path = workspace.data.join("roots-v1.json");
    registry.save(&registry_path).expect("save registry");
    let loaded = RootRegistry::load(&registry_path).expect("load registry");

    assert_eq!(
        loaded
            .resolve_job(root.root_id(), OWNER_SID, "sample-app")
            .expect("owned root")
            .canonical_path(),
        root.canonical_path()
    );
    assert_eq!(
        loaded
            .resolve_job(root.root_id(), "S-1-5-21-2000", "sample-app")
            .expect_err("other SID is rejected")
            .code(),
        ErrorCode::RootUnauthorized
    );
    assert_eq!(
        loaded
            .resolve_job(root.root_id(), OWNER_SID, "other-product")
            .expect_err("other product is rejected")
            .code(),
        ErrorCode::ProductMismatch
    );
}

#[test]
fn recovery_prepare_streams_and_rejects_bad_payload_or_policy_before_mutation() {
    let workspace = TestWorkspace::new("prepare-reject");
    workspace.write_old_root();
    workspace.write_staging();
    fs::write(workspace.staging.join("b.bin"), b"corrupt").expect("corrupt staging");
    let root = workspace.registered_root();

    let error = prepare_file_set(
        &verified_file_set(),
        &root,
        &workspace.staging,
        TransactionPolicy::local(&workspace.data).expect("local policy"),
    )
    .expect_err("corrupt staging is rejected");
    assert_eq!(error.code(), ErrorCode::StagingInvalid);
    workspace.assert_old_root();

    let no_space = TransactionPolicy::new(&workspace.data, Arc::new(NoSpacePlatform))
        .expect("no-space policy");
    assert_eq!(
        prepare_file_set(&verified_file_set(), &root, &workspace.staging, no_space)
            .expect_err("free-space gate runs before staging")
            .code(),
        ErrorCode::InsufficientSpace
    );

    let reject_staging = TransactionPolicy::new(&workspace.data, Arc::new(RejectStagingPlatform))
        .expect("reject-staging policy");
    assert_eq!(
        prepare_file_set(
            &verified_file_set(),
            &root,
            &workspace.staging,
            reject_staging,
        )
        .expect_err("platform hardening rejection is enforced")
        .code(),
        ErrorCode::StagingInvalid
    );
    workspace.assert_old_root();
}

#[test]
fn recovery_normal_commit_produces_exact_new_file_set() {
    let injector = Arc::new(RecordingFaultInjector::new(None));
    let (workspace, _policy, prepared) = prepared_workspace("commit", injector.clone());

    let result = commit_file_set(prepared).expect("commit succeeds");

    assert_eq!(result.generation, 42);
    assert!(!result.cleanup_pending);
    workspace.assert_new_root();
    let events = injector.events();
    assert!(
        events
            .iter()
            .any(|event| event.kind == MutationKind::RenameTargetToBackup)
    );
    assert!(
        events
            .iter()
            .any(|event| event.kind == MutationKind::RenamePreparedToTarget)
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == MutationKind::CleanupJob)
            .count(),
        2
    );
}

#[test]
fn recovery_regular_commit_error_rolls_back_before_returning() {
    let injector = Arc::new(ErrorFaultInjector {
        fail_at: 3,
        sequence: AtomicUsize::new(0),
    });
    let (workspace, _policy, prepared) = prepared_workspace("commit-error", injector);

    let error = commit_file_set(prepared).expect_err("injected I/O error is returned");

    assert_eq!(error.code(), ErrorCode::TransactionIo);
    workspace.assert_old_root();
    assert_eq!(
        recover_incomplete(&workspace.data).expect("nothing remains to recover"),
        seven_launcher_maintenance::RecoveryResult::default()
    );
}

#[test]
fn recovery_power_loss_before_and_after_every_commit_rename_or_delete_is_consistent() {
    let baseline_injector = Arc::new(RecordingFaultInjector::new(None));
    let (baseline_workspace, _policy, prepared) =
        prepared_workspace("fault-baseline", baseline_injector.clone());
    commit_file_set(prepared).expect("baseline commit");
    baseline_workspace.assert_new_root();
    let events = baseline_injector.events();
    assert!(!events.is_empty());

    for (fault_index, expected_event) in events.iter().enumerate() {
        let injector = Arc::new(RecordingFaultInjector::new(Some(fault_index)));
        let (workspace, _policy, prepared) =
            prepared_workspace(&format!("commit-fault-{fault_index}"), injector);
        let interrupted = catch_unwind(AssertUnwindSafe(|| commit_file_set(prepared)));
        assert!(
            interrupted.is_err(),
            "fault {fault_index} must interrupt commit"
        );

        let recovery = recover_incomplete(&workspace.data).expect("restart recovery");
        if expected_event.kind == MutationKind::CleanupJob {
            workspace.assert_new_root();
            assert!(
                recovery.committed_jobs.len() <= 1,
                "cleanup may already have removed the journal"
            );
        } else {
            workspace.assert_old_root();
            assert_eq!(recovery.rolled_back_jobs.len(), 1);
        }
    }
}

#[test]
fn recovery_power_loss_during_rollback_resumes_to_exact_old_file_set() {
    let success_injector = Arc::new(RecordingFaultInjector::new(None));
    let (success_workspace, _policy, prepared) =
        prepared_workspace("rollback-events", success_injector.clone());
    commit_file_set(prepared).expect("event discovery commit");
    let apply_events = success_injector.events();
    let crash_index = apply_events
        .iter()
        .rposition(|event| event.kind != MutationKind::CleanupJob)
        .expect("last apply event");
    success_workspace.assert_new_root();

    let crash_injector = Arc::new(RecordingFaultInjector::new(Some(crash_index)));
    let (event_workspace, _policy, prepared) =
        prepared_workspace("rollback-event-discovery", crash_injector);
    assert!(catch_unwind(AssertUnwindSafe(|| commit_file_set(prepared))).is_err());
    let rollback_recorder = Arc::new(RecordingFaultInjector::new(None));
    let recovery_policy =
        TransactionPolicy::new(&event_workspace.data, Arc::new(LocalTransactionPlatform))
            .expect("recovery policy")
            .with_fault_injector(rollback_recorder.clone());
    recover_incomplete_with_policy(recovery_policy).expect("discover rollback events");
    event_workspace.assert_old_root();
    let rollback_events = rollback_recorder.events();
    assert!(
        rollback_events
            .iter()
            .any(|event| event.kind == MutationKind::RestoreBackup)
    );
    assert!(
        rollback_events
            .iter()
            .any(|event| event.kind == MutationKind::DeleteTarget)
    );

    for rollback_fault_index in 0..rollback_events.len() {
        let apply_crash = Arc::new(RecordingFaultInjector::new(Some(crash_index)));
        let (workspace, _policy, prepared) = prepared_workspace(
            &format!("rollback-fault-{rollback_fault_index}"),
            apply_crash,
        );
        assert!(catch_unwind(AssertUnwindSafe(|| commit_file_set(prepared))).is_err());

        let rollback_crash = Arc::new(RecordingFaultInjector::new(Some(rollback_fault_index)));
        let recovery_policy =
            TransactionPolicy::new(&workspace.data, Arc::new(LocalTransactionPlatform))
                .expect("faulted recovery policy")
                .with_fault_injector(rollback_crash);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                recover_incomplete_with_policy(recovery_policy)
            }))
            .is_err(),
            "rollback fault {rollback_fault_index} must interrupt recovery"
        );

        recover_incomplete(&workspace.data).expect("second restart finishes rollback");
        workspace.assert_old_root();
    }
}

#[test]
fn recovery_target_identity_change_aborts_before_commit_mutation() {
    let injector = Arc::new(RecordingFaultInjector::new(None));
    let (workspace, _policy, prepared) = prepared_workspace("identity-change", injector.clone());
    fs::write(workspace.root.join("b.bin"), b"changed-size").expect("external change");

    let error = commit_file_set(prepared).expect_err("changed target is rejected");
    assert_eq!(error.code(), ErrorCode::RootIdentity);
    assert!(injector.events().is_empty());
    assert_eq!(
        fs::read(workspace.root.join("b.bin")).expect("external bytes remain"),
        b"changed-size"
    );
    recover_incomplete(&workspace.data).expect("prepared job cleanup");
}

#[test]
fn recovery_discards_prepared_job_when_registered_root_was_removed() {
    let injector = Arc::new(RecordingFaultInjector::new(None));
    let (workspace, _policy, prepared) =
        prepared_workspace("prepared-root-removed", injector.clone());
    let job_id = prepared.job_id().to_owned();
    drop(prepared);

    fs::remove_dir_all(&workspace.root).expect("remove registered root before restart");

    let recovery = recover_incomplete(&workspace.data)
        .expect("prepared transaction does not need the removed root for rollback");
    assert_eq!(recovery.discarded_prepared_jobs, vec![job_id]);
    assert!(recovery.rolled_back_jobs.is_empty());
    assert!(recovery.committed_jobs.is_empty());
    assert!(!workspace.root.exists());
    assert!(injector.events().is_empty());
}

#[test]
fn recovery_rejects_recreated_root_for_prepared_job() {
    let injector = Arc::new(RecordingFaultInjector::new(None));
    let (workspace, _policy, prepared) =
        prepared_workspace("prepared-root-recreated", injector.clone());
    let job_id = prepared.job_id().to_owned();
    drop(prepared);

    fs::remove_dir_all(&workspace.root).expect("remove registered root before restart");
    fs::create_dir(&workspace.root).expect("recreate different root at the same path");

    let error = recover_incomplete(&workspace.data).expect_err("replacement root must fail closed");
    assert_eq!(error.code(), ErrorCode::RootIdentity);
    assert!(workspace.data.join("jobs").join(job_id).exists());
    assert!(injector.events().is_empty());
}
