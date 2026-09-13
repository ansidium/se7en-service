use seven_launcher_maintenance::{
    ErrorCode,
    service_upgrade::{
        EnsureServiceOutcome, ServiceReleaseRecord, ServiceUpgradeJournal, ServiceUpgradePlatform,
        ServiceVersion, UpgradeDecision, UpgradePhase, decide_service_upgrade,
        decode_upgrade_journal, encode_upgrade_journal, execute_service_upgrade,
    },
};

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn service_version_is_strict_and_ordered() {
    let old = ServiceVersion::parse("1.2.3").expect("valid service version");
    let new = ServiceVersion::parse("1.3.0").expect("valid service version");
    assert!(old < new);
    assert_eq!(new.to_string(), "1.3.0");

    for invalid in ["", "1", "1.2", "1.2.3.4", "1.2.x", "01.2.3", "1.2.3-beta"] {
        assert!(ServiceVersion::parse(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn upgrade_decision_installs_keeps_and_advances_only_same_major() {
    let current = ServiceReleaseRecord::new("1.2.0", 10, digest(1)).unwrap();
    let same = ServiceReleaseRecord::new("1.2.0", 10, digest(1)).unwrap();
    let newer = ServiceReleaseRecord::new("1.3.0", 11, digest(2)).unwrap();

    assert_eq!(
        decide_service_upgrade(&same, None).unwrap(),
        UpgradeDecision::Install
    );
    assert_eq!(
        decide_service_upgrade(&same, Some(&current)).unwrap(),
        UpgradeDecision::KeepCompatible
    );
    assert_eq!(
        decide_service_upgrade(&newer, Some(&current)).unwrap(),
        UpgradeDecision::Upgrade
    );

    let downgrade = ServiceReleaseRecord::new("1.1.9", 9, digest(3)).unwrap();
    assert_eq!(
        decide_service_upgrade(&downgrade, Some(&current))
            .unwrap_err()
            .code(),
        ErrorCode::FileSetRollback
    );

    let cross_major = ServiceReleaseRecord::new("2.0.0", 12, digest(4)).unwrap();
    assert_eq!(
        decide_service_upgrade(&cross_major, Some(&current))
            .unwrap_err()
            .code(),
        ErrorCode::ProtocolVersion
    );
}

#[test]
fn upgrade_rejects_generation_or_digest_reuse() {
    let current = ServiceReleaseRecord::new("1.2.0", 10, digest(1)).unwrap();
    let reused_version_generation = ServiceReleaseRecord::new("1.2.0", 10, digest(2)).unwrap();
    let reused_generation = ServiceReleaseRecord::new("1.3.0", 10, digest(2)).unwrap();

    assert_eq!(
        decide_service_upgrade(&reused_version_generation, Some(&current))
            .unwrap_err()
            .code(),
        ErrorCode::GenerationConflict
    );
    assert_eq!(
        decide_service_upgrade(&reused_generation, Some(&current))
            .unwrap_err()
            .code(),
        ErrorCode::GenerationConflict
    );
}

#[test]
fn same_service_version_can_advance_internal_release_generation() {
    let installed = ServiceReleaseRecord::new("1.0.2", 2, digest(0x22)).unwrap();
    let candidate = ServiceReleaseRecord::new("1.0.2", 3, digest(0x33)).unwrap();
    assert_eq!(
        decide_service_upgrade(&candidate, Some(&installed)).expect("generation advances"),
        UpgradeDecision::Upgrade
    );
    assert!(decide_service_upgrade(&installed, Some(&candidate)).is_err());
}

#[test]
fn upgrade_journal_allows_only_forward_persisted_phases() {
    let candidate = ServiceReleaseRecord::new("1.3.0", 11, digest(2)).unwrap();
    let previous = ServiceReleaseRecord::new("1.2.0", 10, digest(1)).unwrap();
    let mut journal = ServiceUpgradeJournal::new(
        candidate,
        Some(previous),
        r#"\"C:\Program Files\7Launcher\Service\Se7enService.exe\" --service"#.to_owned(),
    )
    .unwrap();
    assert_eq!(journal.phase(), UpgradePhase::Staged);

    journal.advance(UpgradePhase::OldStopped).unwrap();
    journal.advance(UpgradePhase::ConfigSwitched).unwrap();
    journal.advance(UpgradePhase::Healthy).unwrap();
    assert_eq!(journal.phase(), UpgradePhase::Healthy);

    assert_eq!(
        journal
            .advance(UpgradePhase::ConfigSwitched)
            .unwrap_err()
            .code(),
        ErrorCode::TransactionState
    );
}

#[test]
fn upgrade_journal_roundtrip_is_canonical_and_strict() {
    let candidate = ServiceReleaseRecord::new("1.0.0", 1, digest(7)).unwrap();
    let journal = ServiceUpgradeJournal::new(
        candidate,
        None,
        r#"\"C:\Program Files\7Launcher\Service\Se7enService.exe\" --service"#.to_owned(),
    )
    .unwrap();
    let encoded = encode_upgrade_journal(&journal).unwrap();
    assert_eq!(decode_upgrade_journal(&encoded).unwrap(), journal);

    let mut noncanonical = b" \n".to_vec();
    noncanonical.extend_from_slice(&encoded);
    assert_eq!(
        decode_upgrade_journal(&noncanonical).unwrap_err().code(),
        ErrorCode::JsonNonCanonical
    );

    let unknown = String::from_utf8(encoded)
        .unwrap()
        .replacen("{", r#"{"unexpected":true,"#, 1);
    assert_eq!(
        decode_upgrade_journal(unknown.as_bytes())
            .unwrap_err()
            .code(),
        ErrorCode::JsonInvalid
    );
}

#[derive(Default)]
struct FakeUpgradePlatform {
    actions: Vec<&'static str>,
    busy: bool,
    health_fails: bool,
    saved_phases: Vec<UpgradePhase>,
}

impl ServiceUpgradePlatform for FakeUpgradePlatform {
    fn persist_journal(
        &mut self,
        journal: &ServiceUpgradeJournal,
    ) -> seven_launcher_maintenance::Result<()> {
        self.actions.push("persist");
        self.saved_phases.push(journal.phase());
        Ok(())
    }

    fn stop_service(&mut self) -> seven_launcher_maintenance::Result<()> {
        self.actions.push("stop");
        if self.busy {
            Err(
                seven_launcher_maintenance::MaintenanceError::policy_rejection(
                    ErrorCode::ServiceBusy,
                ),
            )
        } else {
            Ok(())
        }
    }

    fn activate_candidate(
        &mut self,
        _journal: &ServiceUpgradeJournal,
    ) -> seven_launcher_maintenance::Result<()> {
        self.actions.push("activate");
        Ok(())
    }

    fn verify_candidate_health(
        &mut self,
        _journal: &ServiceUpgradeJournal,
    ) -> seven_launcher_maintenance::Result<()> {
        self.actions.push("health");
        if self.health_fails {
            Err(
                seven_launcher_maintenance::MaintenanceError::policy_rejection(
                    ErrorCode::ProtocolVersion,
                ),
            )
        } else {
            Ok(())
        }
    }

    fn rollback_service(
        &mut self,
        _journal: &ServiceUpgradeJournal,
    ) -> seven_launcher_maintenance::Result<()> {
        self.actions.push("rollback");
        Ok(())
    }

    fn finalize_upgrade(
        &mut self,
        _journal: &ServiceUpgradeJournal,
    ) -> seven_launcher_maintenance::Result<()> {
        self.actions.push("finalize");
        Ok(())
    }

    fn clear_journal(&mut self) -> seven_launcher_maintenance::Result<()> {
        self.actions.push("clear");
        Ok(())
    }
}

fn upgrade_journal_with_previous() -> ServiceUpgradeJournal {
    ServiceUpgradeJournal::new(
        ServiceReleaseRecord::new("1.3.0", 11, digest(2)).unwrap(),
        Some(ServiceReleaseRecord::new("1.2.0", 10, digest(1)).unwrap()),
        "service --service".to_owned(),
    )
    .unwrap()
}

#[test]
fn coordinator_persists_every_phase_and_finalizes_upgrade() {
    let mut platform = FakeUpgradePlatform::default();
    let outcome = execute_service_upgrade(&mut platform, upgrade_journal_with_previous()).unwrap();
    assert_eq!(outcome, EnsureServiceOutcome::Upgraded);
    assert_eq!(
        platform.saved_phases,
        [
            UpgradePhase::Staged,
            UpgradePhase::OldStopped,
            UpgradePhase::ConfigSwitched,
            UpgradePhase::Healthy,
        ]
    );
    assert_eq!(
        platform.actions,
        [
            "persist", "stop", "persist", "activate", "persist", "health", "persist", "finalize",
            "clear",
        ]
    );
}

#[test]
fn coordinator_leaves_staged_journal_when_service_is_busy() {
    let mut platform = FakeUpgradePlatform {
        busy: true,
        ..FakeUpgradePlatform::default()
    };
    let error =
        execute_service_upgrade(&mut platform, upgrade_journal_with_previous()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ServiceBusy);
    assert_eq!(platform.saved_phases, [UpgradePhase::Staged]);
    assert_eq!(platform.actions, ["persist", "stop"]);
}

#[test]
fn coordinator_rolls_back_and_clears_journal_after_failed_health_check() {
    let mut platform = FakeUpgradePlatform {
        health_fails: true,
        ..FakeUpgradePlatform::default()
    };
    let error =
        execute_service_upgrade(&mut platform, upgrade_journal_with_previous()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProtocolVersion);
    assert_eq!(
        platform.actions,
        [
            "persist", "stop", "persist", "activate", "persist", "health", "rollback", "clear",
        ]
    );
    assert!(!platform.actions.contains(&"finalize"));
}

#[test]
fn coordinator_resumes_without_repeating_completed_external_phases() {
    let mut journal = upgrade_journal_with_previous();
    journal.advance(UpgradePhase::OldStopped).unwrap();
    journal.advance(UpgradePhase::ConfigSwitched).unwrap();
    let mut platform = FakeUpgradePlatform::default();
    execute_service_upgrade(&mut platform, journal).unwrap();
    assert_eq!(
        platform.actions,
        ["persist", "health", "persist", "finalize", "clear"]
    );
}
