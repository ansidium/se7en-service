#![forbid(unsafe_code)]

use std::{cmp::Ordering, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    ErrorCode, MAX_IPC_MESSAGE_BYTES, MaintenanceError, Result, canonical_json, decode_lower_hex,
    parse_canonical, protocol::PROTOCOL_MAJOR,
};

pub const SERVICE_BUNDLE_PRODUCT_ID: &str = "7launcher-maintenance";
pub const SERVICE_BINARY_NAME: &str = "Se7enService.exe";

const RELEASE_RECORD_KIND: &str = "7launcher-maintenance-service-release-v1";
const UPGRADE_JOURNAL_KIND: &str = "7launcher-maintenance-service-upgrade-v1";
const DOCUMENT_SCHEMA: u64 = 1;
const MAX_IMAGE_PATH_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServiceVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl ServiceVersion {
    pub fn parse(value: &str) -> Result<Self> {
        let mut components = value.split('.');
        let major = parse_version_component(components.next())?;
        let minor = parse_version_component(components.next())?;
        let patch = parse_version_component(components.next())?;
        if components.next().is_some() {
            return Err(invalid_version());
        }
        Ok(Self {
            major,
            minor,
            patch,
        })
    }

    #[must_use]
    pub const fn major(self) -> u64 {
        self.major
    }
}

impl fmt::Display for ServiceVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn parse_version_component(value: Option<&str>) -> Result<u64> {
    let value = value.ok_or_else(invalid_version)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid_version());
    }
    value.parse().map_err(|_| invalid_version())
}

const fn invalid_version() -> MaintenanceError {
    MaintenanceError::new(
        ErrorCode::ProtocolVersion,
        "service version must contain exactly three canonical numeric components",
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceReleaseRecord {
    digest: String,
    generation: u64,
    kind: String,
    schema: u64,
    service_version: String,
}

impl ServiceReleaseRecord {
    pub fn new(service_version: &str, generation: u64, digest: [u8; 32]) -> Result<Self> {
        let record = Self {
            digest: encode_lower_hex(&digest),
            generation,
            kind: RELEASE_RECORD_KIND.to_owned(),
            schema: DOCUMENT_SCHEMA,
            service_version: service_version.to_owned(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind != RELEASE_RECORD_KIND
            || self.schema != DOCUMENT_SCHEMA
            || self.generation == 0
        {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionState,
                "service release record kind, schema, or generation is invalid",
            ));
        }
        ServiceVersion::parse(&self.service_version)?;
        decode_lower_hex::<32>(&self.digest, ErrorCode::GenerationConflict)?;
        Ok(())
    }

    pub fn version(&self) -> Result<ServiceVersion> {
        ServiceVersion::parse(&self.service_version)
    }

    #[must_use]
    pub fn service_version(&self) -> &str {
        &self.service_version
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        decode_lower_hex::<32>(&self.digest, ErrorCode::GenerationConflict)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradeDecision {
    Install,
    KeepCompatible,
    Upgrade,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnsureServiceOutcome {
    Installed,
    Upgraded,
}

pub trait ServiceUpgradePlatform {
    fn persist_journal(&mut self, journal: &ServiceUpgradeJournal) -> Result<()>;
    fn stop_service(&mut self) -> Result<()>;
    fn activate_candidate(&mut self, journal: &ServiceUpgradeJournal) -> Result<()>;
    fn verify_candidate_health(&mut self, journal: &ServiceUpgradeJournal) -> Result<()>;
    fn rollback_service(&mut self, journal: &ServiceUpgradeJournal) -> Result<()>;
    fn finalize_upgrade(&mut self, journal: &ServiceUpgradeJournal) -> Result<()>;
    fn clear_journal(&mut self) -> Result<()>;
}

pub fn execute_service_upgrade(
    platform: &mut impl ServiceUpgradePlatform,
    mut journal: ServiceUpgradeJournal,
) -> Result<EnsureServiceOutcome> {
    journal.validate()?;
    platform.persist_journal(&journal)?;
    loop {
        match journal.phase() {
            UpgradePhase::Staged => {
                platform.stop_service()?;
                journal.advance(UpgradePhase::OldStopped)?;
                platform.persist_journal(&journal)?;
            }
            UpgradePhase::OldStopped => {
                platform.activate_candidate(&journal)?;
                journal.advance(UpgradePhase::ConfigSwitched)?;
                platform.persist_journal(&journal)?;
            }
            UpgradePhase::ConfigSwitched => {
                if let Err(health_error) = platform.verify_candidate_health(&journal) {
                    if platform.rollback_service(&journal).is_err() {
                        return Err(MaintenanceError::new(
                            ErrorCode::RecoveryIncomplete,
                            "candidate service failed health-check and rollback did not complete",
                        ));
                    }
                    platform.clear_journal().map_err(|_| {
                        MaintenanceError::new(
                            ErrorCode::RecoveryIncomplete,
                            "rolled-back service upgrade journal could not be cleared",
                        )
                    })?;
                    return Err(health_error);
                }
                journal.advance(UpgradePhase::Healthy)?;
                platform.persist_journal(&journal)?;
            }
            UpgradePhase::Healthy => {
                platform.finalize_upgrade(&journal)?;
                platform.clear_journal()?;
                return Ok(if journal.previous().is_some() {
                    EnsureServiceOutcome::Upgraded
                } else {
                    EnsureServiceOutcome::Installed
                });
            }
        }
    }
}

pub fn decide_service_upgrade(
    candidate: &ServiceReleaseRecord,
    installed: Option<&ServiceReleaseRecord>,
) -> Result<UpgradeDecision> {
    candidate.validate()?;
    let candidate_version = candidate.version()?;
    if candidate_version.major() != u64::from(PROTOCOL_MAJOR) {
        return Err(MaintenanceError::new(
            ErrorCode::ProtocolVersion,
            "candidate service major is incompatible with IPC v1",
        ));
    }
    let Some(installed) = installed else {
        return Ok(UpgradeDecision::Install);
    };
    installed.validate()?;
    let installed_version = installed.version()?;
    if installed_version.major() != candidate_version.major() {
        return Err(MaintenanceError::new(
            ErrorCode::ProtocolVersion,
            "cross-major maintenance service upgrade is forbidden",
        ));
    }
    match candidate_version.cmp(&installed_version) {
        Ordering::Less => Err(MaintenanceError::new(
            ErrorCode::FileSetRollback,
            "candidate maintenance service version is older than the installed version",
        )),
        Ordering::Equal => match candidate.generation.cmp(&installed.generation) {
            Ordering::Less => Err(MaintenanceError::new(
                ErrorCode::FileSetRollback,
                "candidate release generation is older than the installed generation",
            )),
            Ordering::Equal if candidate.digest == installed.digest => {
                Ok(UpgradeDecision::KeepCompatible)
            }
            Ordering::Equal => Err(MaintenanceError::new(
                ErrorCode::GenerationConflict,
                "one release generation cannot identify different service bytes",
            )),
            Ordering::Greater => Ok(UpgradeDecision::Upgrade),
        },
        Ordering::Greater => {
            if candidate.generation <= installed.generation {
                Err(MaintenanceError::new(
                    ErrorCode::GenerationConflict,
                    "newer maintenance service version must advance the release generation",
                ))
            } else {
                Ok(UpgradeDecision::Upgrade)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UpgradePhase {
    Staged,
    OldStopped,
    ConfigSwitched,
    Healthy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceUpgradeJournal {
    candidate: ServiceReleaseRecord,
    candidate_image_path: String,
    kind: String,
    phase: UpgradePhase,
    previous: Option<ServiceReleaseRecord>,
    schema: u64,
}

impl ServiceUpgradeJournal {
    pub fn new(
        candidate: ServiceReleaseRecord,
        previous: Option<ServiceReleaseRecord>,
        candidate_image_path: String,
    ) -> Result<Self> {
        let journal = Self {
            candidate,
            candidate_image_path,
            kind: UPGRADE_JOURNAL_KIND.to_owned(),
            phase: UpgradePhase::Staged,
            previous,
            schema: DOCUMENT_SCHEMA,
        };
        journal.validate()?;
        Ok(journal)
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind != UPGRADE_JOURNAL_KIND || self.schema != DOCUMENT_SCHEMA {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionState,
                "service upgrade journal kind or schema is invalid",
            ));
        }
        self.candidate.validate()?;
        if let Some(previous) = &self.previous {
            previous.validate()?;
        }
        validate_image_path(&self.candidate_image_path)?;
        Ok(())
    }

    pub fn advance(&mut self, next: UpgradePhase) -> Result<()> {
        let valid = matches!(
            (self.phase, next),
            (UpgradePhase::Staged, UpgradePhase::OldStopped)
                | (UpgradePhase::OldStopped, UpgradePhase::ConfigSwitched)
                | (UpgradePhase::ConfigSwitched, UpgradePhase::Healthy)
        );
        if !valid {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionState,
                "service upgrade journal transition is invalid",
            ));
        }
        self.phase = next;
        Ok(())
    }

    #[must_use]
    pub const fn phase(&self) -> UpgradePhase {
        self.phase
    }

    #[must_use]
    pub const fn candidate(&self) -> &ServiceReleaseRecord {
        &self.candidate
    }

    #[must_use]
    pub const fn previous(&self) -> Option<&ServiceReleaseRecord> {
        self.previous.as_ref()
    }

    #[must_use]
    pub fn candidate_image_path(&self) -> &str {
        &self.candidate_image_path
    }
}

pub fn encode_upgrade_journal(journal: &ServiceUpgradeJournal) -> Result<Vec<u8>> {
    journal.validate()?;
    canonical_json(&serde_json::to_value(journal).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::JsonInvalid,
            "service upgrade journal cannot be encoded",
        )
    })?)
}

pub fn decode_upgrade_journal(bytes: &[u8]) -> Result<ServiceUpgradeJournal> {
    let journal: ServiceUpgradeJournal = parse_canonical(bytes, MAX_IPC_MESSAGE_BYTES)?;
    journal.validate()?;
    Ok(journal)
}

pub fn encode_release_record(record: &ServiceReleaseRecord) -> Result<Vec<u8>> {
    record.validate()?;
    canonical_json(&serde_json::to_value(record).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::JsonInvalid,
            "service release record cannot be encoded",
        )
    })?)
}

pub fn decode_release_record(bytes: &[u8]) -> Result<ServiceReleaseRecord> {
    let record: ServiceReleaseRecord = parse_canonical(bytes, MAX_IPC_MESSAGE_BYTES)?;
    record.validate()?;
    Ok(record)
}

fn validate_image_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > MAX_IMAGE_PATH_BYTES || path.contains('\0') {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionState,
            "service ImagePath is empty, oversized, or contains NUL",
        ));
    }
    Ok(())
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
