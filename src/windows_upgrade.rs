#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    mem::{MaybeUninit, size_of},
    path::{Path, PathBuf},
    ptr, thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use windows::{
    Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_SERVICE_ALREADY_RUNNING,
            ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_DOES_NOT_EXIST,
            ERROR_SERVICE_NOT_ACTIVE, GetLastError, WIN32_ERROR,
        },
        Globalization::GetUserDefaultUILanguage,
        Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW,
            TOKEN_DUPLICATE, TOKEN_QUERY,
        },
        Storage::FileSystem::{
            DELETE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
            MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW,
        },
        System::{
            Registry::{
                HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY,
                REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ, RegCreateKeyExW,
                RegDeleteKeyExW, RegSetValueExW,
            },
            Services::{
                ChangeServiceConfigW, ControlService, DeleteService, OpenSCManagerW, OpenServiceW,
                QueryServiceConfigW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
                SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_STOP,
                SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL, SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
                SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS, StartServiceW,
            },
            Threading::{
                CreateMutexW, GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken,
                WaitForSingleObject,
            },
        },
        UI::{
            Shell::{
                SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
            },
            WindowsAndMessaging::{IDYES, MB_ICONQUESTION, MB_YESNO, MessageBoxW, SW_HIDE},
        },
    },
    core::{HRESULT, PCWSTR},
};

use crate::{
    ErrorCode, FileSetAcceptance, GenerationRecord, MAX_MANIFEST_BYTES, MaintenanceError, Result,
    service_upgrade::{
        EnsureServiceOutcome, SERVICE_BINARY_NAME, SERVICE_BUNDLE_PRODUCT_ID, ServiceReleaseRecord,
        ServiceUpgradeJournal, ServiceUpgradePlatform, UpgradeDecision, decide_service_upgrade,
        decode_release_record, decode_upgrade_journal, encode_release_record,
        encode_upgrade_journal, execute_service_upgrade,
    },
    verify_file_set,
};

use super::{
    KernelHandle, LocalSecurityDescriptor, RegistryKey, SERVICE_ACCOUNT, SERVICE_DISPLAY_NAME,
    SERVICE_NAME, ServiceHandle, call_shared_service, configure_system_service,
    create_system_service, delete_by_handle, install_verified_keyring_bytes, lock_parent_chain,
    open_absolute_directory, open_relative_file, provision_service_data_directory,
    read_service_file, recover_service_file_replacement, regular_file_snapshot,
    rename_handle_relative, replace_service_file, service_data_directory, token_is_administrator,
    token_is_elevated, verify_authenticode_signer, verify_candidate_keyring_bytes, wide_null,
};

const INSTALLER_MUTEX_NAME: &str = r"Global\SE7ENServiceInstaller-v1";
const RELEASE_RECORD_FILE: &str = "service-release-v1.json";
const UPGRADE_JOURNAL_FILE: &str = "service-upgrade-v1.json";
// These relative paths are canonical FileSet/open-relative identifiers. They deliberately use `/`.
// Absolute Windows filesystem and SCM paths must be built component-by-component below.
const MANAGED_SERVICE_RELATIVE_PATH: &str = "7Launcher/Service/Se7enService.exe";
const MANAGED_CANDIDATE_RELATIVE_PATH: &str = "7Launcher/Service/Se7enService.candidate.exe";
const MANAGED_PREVIOUS_RELATIVE_PATH: &str = "7Launcher/Service/Se7enService.previous.exe";
const PREVIOUS_MANAGED_SERVICE_RELATIVE_PATH: &str = "7Launcher/Se7enService.exe";
const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(300);
const START_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnsureServiceResult {
    Installed,
    Upgraded,
    Current,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoveServiceResult {
    Removed,
    Absent,
}

impl RemoveServiceResult {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::Absent => "absent",
        }
    }
}

impl EnsureServiceResult {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Upgraded => "upgraded",
            Self::Current => "current",
        }
    }
}

/// Installs or upgrades the one shared service from a local signed FileSet v1 bundle.
///
/// The caller must be an elevated administrator. The bundle contains exactly one fixed-name service
/// executable; no URL, command line, or arbitrary privileged operation is accepted.
pub fn ensure_system_service(
    bundle_root: &Path,
    manifest_path: &Path,
    keyring_path: &Path,
) -> Result<EnsureServiceResult> {
    require_elevated_installer()?;
    let _installer_mutex = acquire_installer_mutex()?;
    let outcome = install_system_service(bundle_root, manifest_path, keyring_path)?;
    // An explicit ensure also delivers manager-only recovery fixes when the verified service
    // release is already current. Keep the installer mutex until its independent uninstaller
    // and Programs and Features entry agree; the service binary is not rebuilt for this.
    let manager = install_uninstall_manager()?;
    write_uninstall_entry(&manager)?;
    Ok(outcome)
}

fn install_system_service(
    bundle_root: &Path,
    manifest_path: &Path,
    keyring_path: &Path,
) -> Result<EnsureServiceResult> {
    let manager = open_setup_manager()?;
    let service = open_setup_service(&manager)?;
    let _data_lock = if service.is_some() {
        open_absolute_directory(&service_data_directory()?, false)?
    } else {
        provision_installer_data_directory()?;
        open_absolute_directory(&service_data_directory()?, false)?
    };
    let data_directory = service_data_directory()?;
    let release_path = data_directory.join(RELEASE_RECORD_FILE);
    let journal_path = data_directory.join(UPGRADE_JOURNAL_FILE);
    let installed = load_release_record(&release_path)?;
    if service.is_some() && installed.is_none() {
        return Err(MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "pre-release service without a protected release record must be removed manually",
        ));
    }

    let keyring_bytes = read_service_file(keyring_path, MAX_MANIFEST_BYTES)?;
    let keyring = verify_candidate_keyring_bytes(&keyring_bytes)?;
    let manifest_bytes = read_service_file(manifest_path, MAX_MANIFEST_BYTES)?;
    let previous = installed
        .as_ref()
        .map(|record| {
            Ok(GenerationRecord {
                generation: record.generation(),
                digest: record.digest()?,
            })
        })
        .transpose()?;
    let manifest = verify_file_set(
        &manifest_bytes,
        &keyring,
        FileSetAcceptance {
            expected_product_id: SERVICE_BUNDLE_PRODUCT_ID,
            previous,
        },
    )?;
    let entry = validate_service_bundle(&manifest)?;
    let candidate = ServiceReleaseRecord::new(
        env!("CARGO_PKG_VERSION"),
        manifest.file_set().generation,
        manifest.digest(),
    )?;
    let decision = decide_service_upgrade(&candidate, installed.as_ref())?;
    let candidate_image_path = service_image_path(&managed_binary_path()?)?;

    let existing_journal = load_upgrade_journal(&journal_path)?;
    if let Some(journal) = existing_journal {
        if journal.candidate() != &candidate
            || (journal.previous() != installed.as_ref() && installed.as_ref() != Some(&candidate))
            || journal.candidate_image_path() != candidate_image_path
        {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionConflict,
                "another maintenance service upgrade journal is active",
            ));
        }
        let previous_binary_relative_path = journal
            .previous()
            .map(|_| {
                let service = service.as_ref().ok_or_else(|| {
                    MaintenanceError::new(
                        ErrorCode::RecoveryIncomplete,
                        "upgrade journal has a previous release but the SCM service is absent",
                    )
                })?;
                supported_previous_binary_relative_path(service, &candidate_image_path)
            })
            .transpose()?;
        let candidate_binary = stage_candidate_binary(bundle_root, entry, &keyring)?;
        let mut platform = WindowsUpgradePlatform::new(
            manager,
            service,
            previous_binary_relative_path,
            candidate_binary,
            keyring_bytes,
            release_path,
            journal_path,
        );
        return execute_service_upgrade(&mut platform, journal).map(map_upgrade_outcome);
    }

    match decision {
        UpgradeDecision::KeepCompatible => {
            let service = service.ok_or_else(|| {
                MaintenanceError::new(
                    ErrorCode::RecoveryIncomplete,
                    "service release record exists but the SCM service is absent; remove SE7EN Service from Programs and Features and retry",
                )
            })?;
            verify_managed_binary(entry, &keyring)?;
            ensure_expected_service_config(&service, &candidate_image_path)?;
            start_and_wait(&service, START_TIMEOUT)?;
            verify_running_service(candidate.service_version())?;
            install_verified_keyring_bytes(&keyring_bytes)?;
            Ok(EnsureServiceResult::Current)
        }
        UpgradeDecision::Install => {
            let candidate_binary = stage_candidate_binary(bundle_root, entry, &keyring)?;
            let journal =
                ServiceUpgradeJournal::new(candidate, None, candidate_image_path.clone())?;
            let mut platform = WindowsUpgradePlatform::new(
                manager,
                service,
                None,
                candidate_binary,
                keyring_bytes,
                release_path,
                journal_path,
            );
            execute_service_upgrade(&mut platform, journal).map(map_upgrade_outcome)
        }
        UpgradeDecision::Upgrade => {
            let previous = installed.ok_or_else(|| {
                MaintenanceError::new(
                    ErrorCode::RecoveryIncomplete,
                    "upgrade decision lost the installed service record",
                )
            })?;
            let service = service.ok_or_else(|| {
                MaintenanceError::new(
                    ErrorCode::RecoveryIncomplete,
                    "installed maintenance service is absent from SCM; remove SE7EN Service from Programs and Features and retry",
                )
            })?;
            let previous_binary_relative_path =
                supported_previous_binary_relative_path(&service, &candidate_image_path)?;
            let candidate_binary = stage_candidate_binary(bundle_root, entry, &keyring)?;
            let journal =
                ServiceUpgradeJournal::new(candidate, Some(previous), candidate_image_path)?;
            let mut platform = WindowsUpgradePlatform::new(
                manager,
                Some(service),
                Some(previous_binary_relative_path),
                candidate_binary,
                keyring_bytes,
                release_path,
                journal_path,
            );
            execute_service_upgrade(&mut platform, journal).map(map_upgrade_outcome)
        }
    }
}

/// Stops and removes the one fixed SCM service during an explicit component uninstall.
///
/// The caller must be an elevated administrator. The same installer mutex and bounded graceful
/// stop used by upgrades prevent removal during a commit or rollback. Game uninstallers never call
/// this function; only the independent SE7EN Service uninstaller does.
///
/// An SCM entry that is already gone -- an antivirus quarantine, a hand-deleted service directory,
/// a wrapper uninstall that stopped halfway -- still leaves the rest of the component behind, and
/// that goes all the same. The release record above all: a record without an SCM entry turns every
/// later `ensure-service` into `E_RECOVERY_INCOMPLETE`, and this uninstall is the only way out of
/// that state the user has.
pub fn remove_system_service() -> Result<RemoveServiceResult> {
    require_elevated_installer()?;
    let _installer_mutex = acquire_installer_mutex()?;
    let manager = open_setup_manager()?;
    let Some(service) = open_setup_service(&manager)? else {
        remove_component_leftovers()?;
        return Ok(RemoveServiceResult::Absent);
    };
    let expected_image_path = service_image_path(&managed_binary_path()?)?;
    supported_previous_binary_relative_path(&service, &expected_image_path)?;
    stop_and_wait(&service, DEFAULT_STOP_TIMEOUT)?;
    // SAFETY: the fixed-name service handle is owned by this elevated uninstaller and has DELETE
    // access. The service is stopped, so DeleteService only marks this exact SCM entry for removal;
    // the owned handle is closed when this function returns.
    unsafe { DeleteService(service.0) }.map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "maintenance service could not be deleted",
        )
    })?;
    remove_component_leftovers()?;
    Ok(RemoveServiceResult::Removed)
}

/// Removes everything the component owns besides its SCM entry: the Programs and Features entry,
/// the service images, the manager copy and the release record.
///
/// The service is stopped or absent by the time this runs, so the images delete outright, and
/// every step tolerates what is already gone.
fn remove_component_leftovers() -> Result<()> {
    delete_uninstall_entry()?;
    delete_managed_file(MANAGED_SERVICE_RELATIVE_PATH)?;
    delete_managed_file(MANAGED_CANDIDATE_RELATIVE_PATH)?;
    delete_managed_file(MANAGED_PREVIOUS_RELATIVE_PATH)?;
    remove_installed_manager();
    remove_service_release_record()
}

/// Removes the manager copy the uninstall entry points at.
///
/// Started from Programs and Features this is the running process, which Windows will not let
/// delete itself, so the fallback hands the file to the session manager to remove on the next
/// boot. Neither step is worth failing an otherwise complete uninstall over.
fn remove_installed_manager() {
    let Ok(directory) = service_install_directory() else {
        return;
    };
    let manager = directory.join(MANAGER_BINARY_NAME);
    match std::fs::remove_file(&manager) {
        Ok(()) => return,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(_) => {}
    }
    // The pending-delete list Windows keeps is addressed by path, so scheduling the canonical name
    // would delete whatever sits there at the next boot -- including a manager installed again in
    // the meantime, which would leave the uninstall entry pointing at nothing. Renaming first
    // (Windows allows renaming a running image) aims the pending delete at the old bytes and
    // leaves the canonical name free.
    let retired = directory.join(format!("{MANAGER_BINARY_NAME}.retired"));
    let _ = std::fs::remove_file(&retired);
    let doomed = if std::fs::rename(&manager, &retired).is_ok() {
        retired
    } else {
        manager
    };
    let path = wide_null(&doomed.to_string_lossy());
    // SAFETY: the NUL-terminated path stays live for this synchronous call, and a null destination
    // with MOVEFILE_DELAY_UNTIL_REBOOT is the documented way to ask for deletion at the next boot.
    let _ = unsafe { MoveFileExW(PCWSTR(path.as_ptr()), None, MOVEFILE_DELAY_UNTIL_REBOOT) };
}

/// Handles the Remove button of the service entry in Programs and Features.
///
/// Windows starts that entry's uninstall string without elevation, so the removal cannot run in
/// this process. The user is asked to confirm first -- the question the installer-owned uninstaller
/// used to ask -- and only then is this same executable restarted elevated to do the work. Returns
/// whether the service was actually removed; declining either prompt is a refusal, not a failure.
pub fn confirm_and_elevate_service_removal() -> Result<bool> {
    if !confirm_service_removal() {
        return Ok(false);
    }
    run_elevated_service_removal()
}

fn confirm_service_removal() -> bool {
    // SAFETY: the call takes no arguments and only reads the calling user's UI language.
    let language = unsafe { GetUserDefaultUILanguage() };
    let text = wide_null(if language & 0x3ff == 0x19 {
        "Удалить SE7EN Service с этого компьютера?"
    } else {
        "Remove SE7EN Service from this computer?"
    });
    let caption = wide_null(SERVICE_DISPLAY_NAME);
    // SAFETY: both strings are NUL-terminated and stay live for this synchronous modal call, and a
    // null owner window is valid.
    let answer = unsafe {
        MessageBoxW(
            None,
            PCWSTR(text.as_ptr()),
            PCWSTR(caption.as_ptr()),
            MB_YESNO | MB_ICONQUESTION,
        )
    };
    answer == IDYES
}

fn run_elevated_service_removal() -> Result<bool> {
    let executable = std::env::current_exe().map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionState,
            "the service executable path is unavailable",
        )
    })?;
    let executable = executable.to_str().ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::TransactionState,
            "the service executable path is not representable",
        )
    })?;
    let file = wide_null(executable);
    let verb = wide_null("runas");
    let parameters = wide_null("uninstall-service");
    let mut info = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(size_of::<SHELLEXECUTEINFOW>()).unwrap_or(u32::MAX),
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: every string stays live for this synchronous call and the structure carries its own
    // size. SEE_MASK_NOCLOSEPROCESS makes hProcess an owned handle on success.
    if unsafe { ShellExecuteExW(&mut info) }.is_err() {
        // A declined elevation prompt is the user refusing, not a failure to report.
        return Ok(false);
    }
    let process = KernelHandle::new(
        info.hProcess,
        ErrorCode::TransactionState,
        "elevated service removal did not start",
    )?;
    // SAFETY: the owned process handle stays valid for the wait.
    unsafe { WaitForSingleObject(process.raw(), INFINITE) };
    let mut code = 0_u32;
    // SAFETY: the owned handle is valid and the exit code is written into a live local.
    unsafe { GetExitCodeProcess(process.raw(), &mut code) }.map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionState,
            "elevated service removal did not report an exit code",
        )
    })?;
    if code == 0 {
        Ok(true)
    } else {
        Err(MaintenanceError::new(
            ErrorCode::TransactionIo,
            "elevated service removal failed",
        ))
    }
}

fn remove_service_release_record() -> Result<()> {
    let data_directory = service_data_directory()?;
    for file in [RELEASE_RECORD_FILE, UPGRADE_JOURNAL_FILE] {
        match std::fs::remove_file(data_directory.join(file)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "service release record could not be removed",
                ));
            }
        }
    }
    Ok(())
}

// The entry deliberately keeps the key the Inno wrapper used: a machine that installed the service
// through the wrapper ends up with this entry replaced in place, never with a second one beside a
// stale entry whose uninstaller no longer ships.
const UNINSTALL_SUBKEY: &str = concat!(
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
    "{846CF93F-AC92-4A47-9A4A-959B44C95CF4}_is1"
);
const UNINSTALL_DISPLAY_NAME: &str = "SE7EN Service";
const UNINSTALL_PUBLISHER: &str = "SE7EN Solutions";
const MANAGER_BINARY_NAME: &str = "Se7enServiceManager.exe";

fn service_install_directory() -> Result<PathBuf> {
    Ok(managed_program_files_root()?
        .join("7Launcher")
        .join("Service"))
}

fn uninstall_registry_result(result: WIN32_ERROR) -> Result<()> {
    if result.0 == 0 {
        Ok(())
    } else {
        Err(MaintenanceError::with_platform_status(
            ErrorCode::RegistryIo,
            "Programs and Features entry for the service cannot be written",
            result.0,
        ))
    }
}

fn set_uninstall_text(key: &RegistryKey, name: &str, value: &str) -> Result<()> {
    let name = wide_null(name);
    let data: Vec<u8> = value
        .encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    // SAFETY: the key handle, NUL-terminated name and exact byte slice stay live for this
    // synchronous call, and the bytes are the NUL-terminated UTF-16 that REG_SZ declares.
    let result =
        unsafe { RegSetValueExW(key.raw(), PCWSTR(name.as_ptr()), None, REG_SZ, Some(&data)) };
    uninstall_registry_result(result)
}

fn set_uninstall_flag(key: &RegistryKey, name: &str, value: u32) -> Result<()> {
    let name = wide_null(name);
    let data = value.to_le_bytes();
    // SAFETY: as above, with the exactly four little-endian bytes REG_DWORD declares.
    let result = unsafe {
        RegSetValueExW(
            key.raw(),
            PCWSTR(name.as_ptr()),
            None,
            REG_DWORD,
            Some(&data),
        )
    };
    uninstall_registry_result(result)
}

/// Keeps a copy of this manager beside the installed service.
///
/// The uninstall entry has to name an executable that outlives the game that offered the service,
/// and a manager sitting in a game folder does not. The service executable is deliberately not the
/// one named there: it is released and signed on its own cadence and stays untouched by this.
fn install_uninstall_manager() -> Result<PathBuf> {
    let source = std::env::current_exe().map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionState,
            "the manager executable path is unavailable",
        )
    })?;
    let directory = service_install_directory()?;
    let destination = directory.join(MANAGER_BINARY_NAME);
    if source == destination {
        return Ok(destination);
    }
    std::fs::create_dir_all(&directory).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "the installed service directory cannot be created",
        )
    })?;
    std::fs::copy(&source, &destination).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "the uninstall manager cannot be installed beside the service",
        )
    })?;
    Ok(destination)
}

/// Publishes the service as its own entry in Programs and Features.
///
/// The entry names the manager copy installed beside the service, which outlives any game
/// uninstall, so the Remove button keeps working after the game that offered the service is gone.
fn write_uninstall_entry(manager: &Path) -> Result<()> {
    let directory = service_install_directory()?;
    let image = directory.join(SERVICE_BINARY_NAME);
    let (Some(directory), Some(image), Some(manager)) =
        (directory.to_str(), image.to_str(), manager.to_str())
    else {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionState,
            "installed service path is not representable for the uninstall entry",
        ));
    };

    let subkey = wide_null(UNINSTALL_SUBKEY);
    let access = REG_SAM_FLAGS(KEY_SET_VALUE.0 | KEY_QUERY_VALUE.0 | KEY_WOW64_64KEY.0);
    let mut key = HKEY::default();
    // SAFETY: the predefined HKLM handle and the NUL-terminated fixed subkey are valid for the
    // synchronous call, no security descriptor is supplied, and the returned handle is owned by
    // RegistryKey. The 64-bit view is explicit because this manager is a 32-bit process.
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            access,
            None,
            &mut key,
            None,
        )
    };
    uninstall_registry_result(result)?;
    let key = RegistryKey::new(key)?;

    set_uninstall_text(&key, "DisplayName", UNINSTALL_DISPLAY_NAME)?;
    set_uninstall_text(&key, "DisplayVersion", env!("CARGO_PKG_VERSION"))?;
    set_uninstall_text(&key, "Publisher", UNINSTALL_PUBLISHER)?;
    set_uninstall_text(&key, "InstallLocation", directory)?;
    set_uninstall_text(&key, "DisplayIcon", image)?;
    // Programs and Features starts this without elevation, so the interactive form asks for
    // confirmation and then elevates itself. The quiet form expects an already elevated caller.
    set_uninstall_text(
        &key,
        "UninstallString",
        &format!("\"{manager}\" uninstall-service --interactive"),
    )?;
    set_uninstall_text(
        &key,
        "QuietUninstallString",
        &format!("\"{manager}\" uninstall-service"),
    )?;
    set_uninstall_flag(&key, "NoModify", 1)?;
    set_uninstall_flag(&key, "NoRepair", 1)
}

fn delete_uninstall_entry() -> Result<()> {
    let subkey = wide_null(UNINSTALL_SUBKEY);
    // SAFETY: the predefined HKLM handle and NUL-terminated fixed subkey are valid for the
    // synchronous call, which removes exactly this one leaf key from the 64-bit view.
    let result = unsafe {
        RegDeleteKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            KEY_WOW64_64KEY.0,
            None,
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    uninstall_registry_result(result)
}

/// What a verified service bundle proves, for the caller's diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceBundleEvidence {
    pub generation: u64,
    pub size: u64,
    pub sha256: String,
}

/// Verifies a shipped service bundle without changing anything on the machine.
///
/// The installer offers the service, and the launcher's settings page enables it, only when this
/// succeeds, so a bundle whose keyring, FileSet or executable does not verify is never offered in
/// the first place. The checks are the ones `ensure_system_service` repeats under elevation, which
/// is why a verified offer cannot turn into a rejected install for trust reasons. Nothing here
/// needs elevation: it only reads the three shipped files.
pub fn verify_service_bundle(
    bundle_root: &Path,
    manifest_path: &Path,
    keyring_path: &Path,
) -> Result<ServiceBundleEvidence> {
    if !bundle_root.is_absolute() {
        return Err(MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "service bundle root must be absolute",
        ));
    }
    let keyring_bytes = read_service_file(keyring_path, MAX_MANIFEST_BYTES)?;
    let keyring = verify_candidate_keyring_bytes(&keyring_bytes)?;
    let manifest_bytes = read_service_file(manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest = verify_file_set(
        &manifest_bytes,
        &keyring,
        FileSetAcceptance {
            expected_product_id: SERVICE_BUNDLE_PRODUCT_ID,
            previous: None,
        },
    )?;
    let entry = validate_service_bundle(&manifest)?;
    // The FileSet is pinned to the one fixed executable name, so this never opens a caller-chosen
    // path out of the bundle directory.
    let mut image = open_relative_file(
        bundle_root,
        SERVICE_BINARY_NAME,
        FILE_GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0,
        false,
        false,
    )?
    .ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "signed service bundle executable is absent",
        )
    })?;
    verify_bundle_file(&mut image, entry, &keyring)?;
    Ok(ServiceBundleEvidence {
        generation: manifest.file_set().generation,
        size: entry.size,
        sha256: entry.sha256.clone(),
    })
}

const fn map_upgrade_outcome(outcome: EnsureServiceOutcome) -> EnsureServiceResult {
    match outcome {
        EnsureServiceOutcome::Installed => EnsureServiceResult::Installed,
        EnsureServiceOutcome::Upgraded => EnsureServiceResult::Upgraded,
    }
}

struct WindowsUpgradePlatform {
    _manager: ServiceHandle,
    service: Option<ServiceHandle>,
    previous_binary_relative_path: Option<&'static str>,
    candidate_binary: PathBuf,
    keyring_bytes: Vec<u8>,
    release_path: PathBuf,
    journal_path: PathBuf,
    stop_timeout: Duration,
}

impl WindowsUpgradePlatform {
    fn new(
        manager: ServiceHandle,
        service: Option<ServiceHandle>,
        previous_binary_relative_path: Option<&'static str>,
        candidate_binary: PathBuf,
        keyring_bytes: Vec<u8>,
        release_path: PathBuf,
        journal_path: PathBuf,
    ) -> Self {
        Self {
            _manager: manager,
            service,
            previous_binary_relative_path,
            candidate_binary,
            keyring_bytes,
            release_path,
            journal_path,
            stop_timeout: DEFAULT_STOP_TIMEOUT,
        }
    }

    fn service(&self) -> Result<&ServiceHandle> {
        self.service.as_ref().ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "SCM service handle is unavailable during upgrade",
            )
        })
    }
}

impl ServiceUpgradePlatform for WindowsUpgradePlatform {
    fn persist_journal(&mut self, journal: &ServiceUpgradeJournal) -> Result<()> {
        recover_service_file_replacement(&self.journal_path)?;
        replace_service_file(&self.journal_path, &encode_upgrade_journal(journal)?)
    }

    fn stop_service(&mut self) -> Result<()> {
        if let Some(service) = &self.service {
            stop_and_wait(service, self.stop_timeout)?;
        }
        Ok(())
    }

    fn activate_candidate(&mut self, journal: &ServiceUpgradeJournal) -> Result<()> {
        if self.candidate_binary != managed_candidate_binary_path()? {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionState,
                "staged service candidate is outside the fixed managed path",
            ));
        }
        if journal.previous().is_some() != self.previous_binary_relative_path.is_some() {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionState,
                "service upgrade source path does not match the protected journal",
            ));
        }
        activate_staged_service_binary(self.previous_binary_relative_path)?;
        let live_binary = managed_binary_path()?;
        if self.service.is_none() {
            create_system_service(&live_binary)?;
            self.service = open_setup_service(&self._manager)?;
        }
        let service = self.service()?;
        let current = query_service_config(service)?;
        if current.image_path != journal.candidate_image_path() {
            change_service_image_path(service, journal.candidate_image_path())?;
        }
        configure_system_service(service)?;
        provision_service_data_directory()
    }

    fn verify_candidate_health(&mut self, journal: &ServiceUpgradeJournal) -> Result<()> {
        let service = self.service()?;
        let current = query_service_config(service)?;
        if current.image_path != journal.candidate_image_path() {
            stop_and_wait(service, self.stop_timeout)?;
            change_service_image_path(service, journal.candidate_image_path())?;
        }
        configure_system_service(service)?;
        start_and_wait(service, START_TIMEOUT)?;
        verify_running_service(journal.candidate().service_version())
    }

    fn rollback_service(&mut self, journal: &ServiceUpgradeJournal) -> Result<()> {
        if let Some(service) = &self.service {
            stop_and_wait(service, self.stop_timeout)?;
        }
        if let Some(previous) = journal.previous() {
            restore_previous_service_binary()?;
            let service = self.service()?;
            change_service_image_path(service, journal.candidate_image_path())?;
            configure_system_service(service)?;
            start_and_wait(service, START_TIMEOUT)?;
            verify_running_service(previous.service_version())
        } else {
            delete_managed_file(MANAGED_SERVICE_RELATIVE_PATH)?;
            delete_managed_file(MANAGED_CANDIDATE_RELATIVE_PATH)?;
            let service = self.service.take().ok_or_else(|| {
                MaintenanceError::new(
                    ErrorCode::RecoveryIncomplete,
                    "newly created service disappeared before rollback",
                )
            })?;
            // SAFETY: this elevated setup handle has DELETE access; the stopped service is marked for
            // deletion and the owned handle is closed immediately afterwards.
            unsafe { DeleteService(service.0) }.map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::RecoveryIncomplete,
                    "failed initial service could not be deleted",
                )
            })
        }
    }

    fn finalize_upgrade(&mut self, journal: &ServiceUpgradeJournal) -> Result<()> {
        install_verified_keyring_bytes(&self.keyring_bytes)?;
        recover_service_file_replacement(&self.release_path)?;
        replace_service_file(
            &self.release_path,
            &encode_release_record(journal.candidate())?,
        )?;
        delete_managed_file(MANAGED_PREVIOUS_RELATIVE_PATH)?;
        delete_managed_file(MANAGED_CANDIDATE_RELATIVE_PATH)
    }

    fn clear_journal(&mut self) -> Result<()> {
        recover_service_file_replacement(&self.journal_path)?;
        if self.journal_path.exists() {
            std::fs::remove_file(&self.journal_path).map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::RecoveryIncomplete,
                    "completed service upgrade journal could not be removed",
                )
            })?;
        }
        Ok(())
    }
}

fn require_elevated_installer() -> Result<()> {
    let mut token = windows::Win32::Foundation::HANDLE::default();
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle and `token` is a valid out pointer.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token,
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "installer process token cannot be opened",
        )
    })?;
    let token = KernelHandle::new(
        token,
        ErrorCode::RootUnauthorized,
        "installer process token is invalid",
    )?;
    if token_is_elevated(token.raw())? && token_is_administrator(token.raw())? {
        Ok(())
    } else {
        Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "service ensure operation requires an elevated administrator",
        ))
    }
}

fn acquire_installer_mutex() -> Result<KernelHandle> {
    let mut descriptor = LocalSecurityDescriptor::parse("D:P(A;;GA;;;SY)(A;;GA;;;BA)")?;
    let attributes = descriptor.attributes();
    let name = wide_null(INSTALLER_MUTEX_NAME);
    // SAFETY: security attributes and NUL-terminated name remain live for the synchronous call. The
    // returned handle is uniquely owned by KernelHandle.
    let handle = unsafe {
        CreateMutexW(
            Some(ptr::from_ref(&attributes)),
            true,
            PCWSTR(name.as_ptr()),
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::ServiceBusy,
            "maintenance installer mutex cannot be acquired",
        )
    })?;
    // SAFETY: GetLastError immediately observes the CreateMutexW result on this thread.
    let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let handle = KernelHandle::new(
        handle,
        ErrorCode::ServiceBusy,
        "maintenance installer mutex handle is invalid",
    )?;
    if already_exists {
        return Err(MaintenanceError::new(
            ErrorCode::ServiceBusy,
            "another maintenance installer is already active",
        ));
    }
    Ok(handle)
}

fn open_setup_manager() -> Result<ServiceHandle> {
    // SAFETY: null names select the local active SCM database and the returned handle is owned.
    unsafe {
        OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        )
    }
    .map(ServiceHandle)
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "elevated installer cannot open the service control manager",
        )
    })
}

fn open_setup_service(manager: &ServiceHandle) -> Result<Option<ServiceHandle>> {
    let name = wide_null(SERVICE_NAME);
    // SAFETY: manager and service name are valid; a returned handle is uniquely owned.
    match unsafe { OpenServiceW(manager.0, PCWSTR(name.as_ptr()), SERVICE_ALL_ACCESS) } {
        Ok(service) => Ok(Some(ServiceHandle(service))),
        Err(error) if error.code() == HRESULT::from_win32(ERROR_SERVICE_DOES_NOT_EXIST.0) => {
            Ok(None)
        }
        Err(_) => Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "elevated installer cannot open the existing maintenance service",
        )),
    }
}

fn provision_installer_data_directory() -> Result<()> {
    let program_data = std::env::var_os("ProgramData").ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::TransactionState,
            "ProgramData is unavailable to the installer",
        )
    })?;
    let program_data = PathBuf::from(program_data);
    if !program_data.is_absolute() {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionState,
            "ProgramData is not an absolute path",
        ));
    }
    let components = ["SE7EN".to_owned(), "Service".to_owned()];
    let Some((_locks, path)) = lock_parent_chain(&program_data, &components, true)? else {
        return Err(MaintenanceError::new(
            ErrorCode::RootIdentity,
            "protected installer data path cannot be created safely",
        ));
    };
    if path != service_data_directory()? {
        return Err(MaintenanceError::new(
            ErrorCode::RootIdentity,
            "protected installer data path is inconsistent",
        ));
    }
    let descriptor = LocalSecurityDescriptor::parse("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
    let path = wide_null(path.as_os_str().to_string_lossy().as_ref());
    let information = windows::Win32::Security::OBJECT_SECURITY_INFORMATION(
        DACL_SECURITY_INFORMATION.0 | PROTECTED_DACL_SECURITY_INFORMATION.0,
    );
    // SAFETY: the path and self-relative descriptor remain live through this synchronous DACL set.
    unsafe { SetFileSecurityW(PCWSTR(path.as_ptr()), information, descriptor.raw()) }
        .as_bool()
        .then_some(())
        .ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::RootUnauthorized,
                "installer data directory DACL could not be protected",
            )
        })
}

fn validate_service_bundle(manifest: &crate::VerifiedFileSet) -> Result<&crate::FileEntry> {
    let file_set = manifest.file_set();
    if file_set.files.len() != 1
        || !file_set.remove_files.is_empty()
        || file_set.files[0].path != SERVICE_BINARY_NAME
    {
        return Err(MaintenanceError::new(
            ErrorCode::ProductMismatch,
            "service bundle must contain only the fixed maintenance service executable",
        ));
    }
    Ok(&file_set.files[0])
}

fn stage_candidate_binary(
    bundle_root: &Path,
    entry: &crate::FileEntry,
    keyring: &crate::VerifiedKeyring,
) -> Result<PathBuf> {
    if !bundle_root.is_absolute() {
        return Err(MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "service bundle root must be absolute",
        ));
    }
    let mut source = open_relative_file(
        bundle_root,
        SERVICE_BINARY_NAME,
        FILE_GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0,
        false,
        false,
    )?
    .ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "signed service bundle executable is absent",
        )
    })?;
    verify_bundle_file(&mut source, entry, keyring)?;

    let program_files = managed_program_files_root()?;
    let relative = MANAGED_CANDIDATE_RELATIVE_PATH;
    if let Some(mut existing) = open_relative_file(
        &program_files,
        relative,
        FILE_GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0,
        false,
        true,
    )? {
        verify_bundle_file(&mut existing, entry, keyring)?;
        return Ok(managed_candidate_binary_path_at(&program_files));
    }

    let temporary_relative = format!("{relative}.new");
    if let Some(stale) = open_relative_file(
        &program_files,
        &temporary_relative,
        DELETE.0 | FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_READ_ATTRIBUTES.0,
        false,
        true,
    )? {
        delete_by_handle(&stale)?;
    }
    let mut destination = open_relative_file(
        &program_files,
        &temporary_relative,
        DELETE.0 | FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_READ_ATTRIBUTES.0,
        true,
        true,
    )?
    .ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "fixed-path service staging file could not be created",
        )
    })?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(service_upgrade_io)?;
    std::io::copy(&mut source, &mut destination).map_err(service_upgrade_io)?;
    destination.sync_all().map_err(service_upgrade_io)?;
    verify_bundle_file(&mut destination, entry, keyring)?;
    rename_handle_relative(&program_files, &destination, relative, true)?;
    Ok(managed_candidate_binary_path_at(&program_files))
}

fn verify_managed_binary(entry: &crate::FileEntry, keyring: &crate::VerifiedKeyring) -> Result<()> {
    let program_files = managed_program_files_root()?;
    let mut binary = open_relative_file(
        &program_files,
        MANAGED_SERVICE_RELATIVE_PATH,
        FILE_GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0,
        false,
        true,
    )?
    .ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "fixed managed service executable is absent",
        )
    })?;
    verify_bundle_file(&mut binary, entry, keyring)
}

fn activate_staged_service_binary(previous_relative_path: Option<&str>) -> Result<()> {
    let program_files = managed_program_files_root()?;
    activate_staged_service_binary_at(&program_files, previous_relative_path)
}

fn activate_staged_service_binary_at(
    program_files: &Path,
    previous_relative_path: Option<&str>,
) -> Result<()> {
    if let Some(relative) = previous_relative_path
        && relative != MANAGED_SERVICE_RELATIVE_PATH
        && relative != PREVIOUS_MANAGED_SERVICE_RELATIVE_PATH
    {
        return Err(MaintenanceError::new(
            ErrorCode::RootInvalid,
            "previous service executable is outside the supported managed paths",
        ));
    }
    let previous_exists = open_relative_file(
        program_files,
        MANAGED_PREVIOUS_RELATIVE_PATH,
        FILE_READ_ATTRIBUTES.0,
        false,
        true,
    )?
    .is_some();

    if let Some(previous_relative_path) = previous_relative_path.filter(|_| !previous_exists) {
        let live = open_relative_file(
            program_files,
            previous_relative_path,
            DELETE.0 | FILE_GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0,
            false,
            true,
        )?
        .ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "installed service executable is absent before upgrade",
            )
        })?;
        regular_file_snapshot(&live)?;
        rename_handle_relative(program_files, &live, MANAGED_PREVIOUS_RELATIVE_PATH, true)
            .map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "live service executable could not be retained for rollback",
                )
            })?;
    } else {
        delete_managed_file_at(program_files, MANAGED_SERVICE_RELATIVE_PATH)?;
    }

    let candidate = open_relative_file(
        program_files,
        MANAGED_CANDIDATE_RELATIVE_PATH,
        DELETE.0 | FILE_GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0,
        false,
        true,
    )?
    .ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "staged service candidate disappeared before activation",
        )
    })?;
    regular_file_snapshot(&candidate)?;
    rename_handle_relative(
        program_files,
        &candidate,
        MANAGED_SERVICE_RELATIVE_PATH,
        true,
    )
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "staged service executable could not be activated",
        )
    })
}

fn restore_previous_service_binary() -> Result<()> {
    let program_files = managed_program_files_root()?;
    restore_previous_service_binary_at(&program_files)
}

fn restore_previous_service_binary_at(program_files: &Path) -> Result<()> {
    delete_managed_file_at(program_files, MANAGED_SERVICE_RELATIVE_PATH)?;
    let previous = open_relative_file(
        program_files,
        MANAGED_PREVIOUS_RELATIVE_PATH,
        DELETE.0 | FILE_GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0,
        false,
        true,
    )?
    .ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "previous service executable is absent during rollback",
        )
    })?;
    regular_file_snapshot(&previous)?;
    rename_handle_relative(
        program_files,
        &previous,
        MANAGED_SERVICE_RELATIVE_PATH,
        true,
    )
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "previous service executable could not be restored",
        )
    })
}

fn delete_managed_file(relative: &str) -> Result<()> {
    let program_files = managed_program_files_root()?;
    delete_managed_file_at(&program_files, relative)
}

fn delete_managed_file_at(program_files: &Path, relative: &str) -> Result<()> {
    let Some(file) = open_relative_file(
        program_files,
        relative,
        DELETE.0 | FILE_GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0,
        false,
        true,
    )?
    else {
        return Ok(());
    };
    regular_file_snapshot(&file)?;
    delete_by_handle(&file)
}

fn verify_bundle_file(
    file: &mut File,
    entry: &crate::FileEntry,
    keyring: &crate::VerifiedKeyring,
) -> Result<()> {
    if regular_file_snapshot(file)?.size != entry.size {
        return Err(MaintenanceError::new(
            ErrorCode::FileSetHash,
            "service bundle executable size does not match FileSet v1",
        ));
    }
    let actual = hash_open_file(file)?;
    let expected = crate::decode_lower_hex::<32>(&entry.sha256, ErrorCode::FileSetHash)?;
    if actual != expected {
        return Err(MaintenanceError::new(
            ErrorCode::FileSetHash,
            "service bundle executable SHA-256 does not match FileSet v1",
        ));
    }
    verify_authenticode_signer(file, &keyring.keyring().authenticode_signer_thumbprints)
}

fn hash_open_file(file: &mut File) -> Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0)).map_err(service_upgrade_io)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(service_upgrade_io)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0)).map_err(service_upgrade_io)?;
    Ok(digest.finalize().into())
}

fn managed_program_files_root() -> Result<PathBuf> {
    let root = std::env::var_os("ProgramW6432")
        .or_else(|| std::env::var_os("ProgramFiles"))
        .ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::TransactionState,
                "Program Files is unavailable to the installer",
            )
        })?;
    let root = PathBuf::from(root);
    if !root.is_absolute() {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionState,
            "Program Files is not an absolute path",
        ));
    }
    Ok(root)
}

fn managed_binary_path() -> Result<PathBuf> {
    Ok(managed_binary_path_at(&managed_program_files_root()?))
}

fn managed_candidate_binary_path() -> Result<PathBuf> {
    Ok(managed_candidate_binary_path_at(
        &managed_program_files_root()?,
    ))
}

fn managed_binary_path_at(program_files: &Path) -> PathBuf {
    native_path_from_canonical_relative(program_files, MANAGED_SERVICE_RELATIVE_PATH)
}

fn managed_candidate_binary_path_at(program_files: &Path) -> PathBuf {
    native_path_from_canonical_relative(program_files, MANAGED_CANDIDATE_RELATIVE_PATH)
}

fn previous_managed_binary_path_at(program_files: &Path) -> PathBuf {
    native_path_from_canonical_relative(program_files, PREVIOUS_MANAGED_SERVICE_RELATIVE_PATH)
}

fn native_path_from_canonical_relative(root: &Path, relative: &str) -> PathBuf {
    relative
        .split('/')
        .fold(root.to_path_buf(), |path, component| path.join(component))
}

fn service_image_path(binary: &Path) -> Result<String> {
    let binary = binary.to_str().ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::RootInvalid,
            "managed service binary path must be Unicode",
        )
    })?;
    Ok(format!("\"{binary}\" --service"))
}

fn load_release_record(path: &Path) -> Result<Option<ServiceReleaseRecord>> {
    recover_service_file_replacement(path)?;
    if !path.exists() {
        return Ok(None);
    }
    decode_release_record(&read_service_file(path, crate::MAX_IPC_MESSAGE_BYTES)?).map(Some)
}

fn load_upgrade_journal(path: &Path) -> Result<Option<ServiceUpgradeJournal>> {
    recover_service_file_replacement(path)?;
    if !path.exists() {
        return Ok(None);
    }
    decode_upgrade_journal(&read_service_file(path, crate::MAX_IPC_MESSAGE_BYTES)?).map(Some)
}

struct QueriedServiceConfig {
    image_path: String,
}

fn query_service_config(service: &ServiceHandle) -> Result<QueriedServiceConfig> {
    let mut needed = 0_u32;
    // SAFETY: this sizing call deliberately provides no output buffer and writes only `needed`.
    let _ = unsafe { QueryServiceConfigW(service.0, None, 0, &mut needed) };
    if needed == 0 || needed > 64 * 1024 {
        return Err(MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "maintenance service configuration has an invalid size",
        ));
    }
    let words = usize::try_from(needed)
        .ok()
        .and_then(|bytes| bytes.checked_add(size_of::<usize>() - 1))
        .map(|bytes| bytes / size_of::<usize>())
        .ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "maintenance service configuration size overflowed",
            )
        })?;
    let mut storage = vec![0_usize; words];
    // SAFETY: storage is aligned and writable for `needed` bytes; SCM initializes a complete
    // QUERY_SERVICE_CONFIGW plus its trailing strings on success.
    unsafe {
        QueryServiceConfigW(
            service.0,
            Some(storage.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "maintenance service configuration cannot be queried",
        )
    })?;
    // SAFETY: the successful call initialized the aligned fixed header at storage start.
    let config = unsafe {
        &*storage
            .as_ptr()
            .cast::<windows::Win32::System::Services::QUERY_SERVICE_CONFIGW>()
    };
    if config.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || config.dwStartType != SERVICE_DEMAND_START
        || config.dwErrorControl != SERVICE_ERROR_NORMAL
    {
        return Err(MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "maintenance service type, start mode, or error policy drifted",
        ));
    }
    // SAFETY: both pointers refer to NUL-terminated strings inside the live SCM output buffer.
    let image_path = unsafe { config.lpBinaryPathName.to_string() }.map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "maintenance service ImagePath is invalid Unicode",
        )
    })?;
    // SAFETY: the account pointer refers to a NUL-terminated string inside the same live buffer.
    let account = unsafe { config.lpServiceStartName.to_string() }.map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "maintenance service account is invalid Unicode",
        )
    })?;
    if !account.eq_ignore_ascii_case(SERVICE_ACCOUNT) {
        return Err(MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "maintenance service account drifted from LocalSystem",
        ));
    }
    Ok(QueriedServiceConfig { image_path })
}

fn ensure_expected_service_config(service: &ServiceHandle, expected: &str) -> Result<()> {
    if query_service_config(service)?.image_path == expected {
        Ok(())
    } else {
        Err(MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "maintenance service ImagePath does not match its protected release record",
        ))
    }
}

fn supported_previous_binary_relative_path(
    service: &ServiceHandle,
    expected: &str,
) -> Result<&'static str> {
    let current = query_service_config(service)?.image_path;
    let program_files = managed_program_files_root()?;
    let known_mixed_current =
        service_image_path(&program_files.join(Path::new(MANAGED_SERVICE_RELATIVE_PATH)))?;
    let previous_native = service_image_path(&previous_managed_binary_path_at(&program_files))?;
    let previous_mixed =
        service_image_path(&program_files.join(Path::new(PREVIOUS_MANAGED_SERVICE_RELATIVE_PATH)))?;
    supported_previous_relative_path_for_image(
        &current,
        expected,
        &known_mixed_current,
        &previous_native,
        &previous_mixed,
    )
    .ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "maintenance service ImagePath is outside the current and supported previous paths",
        )
    })
}

fn supported_previous_relative_path_for_image(
    current: &str,
    expected: &str,
    known_mixed_current: &str,
    previous_native: &str,
    previous_mixed: &str,
) -> Option<&'static str> {
    if current == expected || current == known_mixed_current {
        Some(MANAGED_SERVICE_RELATIVE_PATH)
    } else if current == previous_native || current == previous_mixed {
        Some(PREVIOUS_MANAGED_SERVICE_RELATIVE_PATH)
    } else {
        None
    }
}

fn change_service_image_path(service: &ServiceHandle, image_path: &str) -> Result<()> {
    let image_path = wide_null(image_path);
    let account = wide_null(SERVICE_ACCOUNT);
    let display = wide_null(SERVICE_DISPLAY_NAME);
    // SAFETY: the service handle has setup rights and every supplied string is live/NUL-terminated.
    // Fixed service type/account/start policy are reasserted; no password or arbitrary arguments are
    // accepted.
    unsafe {
        ChangeServiceConfigW(
            service.0,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(image_path.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            PCWSTR::null(),
            PCWSTR(display.as_ptr()),
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "maintenance service ImagePath could not be switched",
        )
    })
}

fn query_service_status(service: &ServiceHandle) -> Result<SERVICE_STATUS_PROCESS> {
    let mut status = MaybeUninit::<SERVICE_STATUS_PROCESS>::uninit();
    let mut needed = 0_u32;
    // SAFETY: the byte slice exactly covers the aligned uninitialized output value and is
    // initialized in full by SC_STATUS_PROCESS_INFO on success.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            status.as_mut_ptr().cast::<u8>(),
            size_of::<SERVICE_STATUS_PROCESS>(),
        )
    };
    // SAFETY: output slice and needed pointer remain live through the synchronous query.
    unsafe { QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, Some(bytes), &mut needed) }
        .map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "maintenance service status cannot be queried",
            )
        })?;
    if usize::try_from(needed).ok() != Some(size_of::<SERVICE_STATUS_PROCESS>()) {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionState,
            "maintenance service status has an invalid size",
        ));
    }
    // SAFETY: the successful query initialized the full fixed-size status value.
    Ok(unsafe { status.assume_init() })
}

fn stop_and_wait(service: &ServiceHandle, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    loop {
        let status = query_service_status(service)?;
        if status.dwCurrentState == SERVICE_STOPPED {
            return Ok(());
        }
        if status.dwControlsAccepted & SERVICE_ACCEPT_STOP != 0 {
            let mut ignored = SERVICE_STATUS::default();
            // SAFETY: this setup handle has STOP rights and `ignored` is a valid output value.
            match unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut ignored) } {
                Ok(()) => {}
                Err(error)
                    if error.code() == HRESULT::from_win32(ERROR_SERVICE_CANNOT_ACCEPT_CTRL.0)
                        || error.code() == HRESULT::from_win32(ERROR_SERVICE_NOT_ACTIVE.0) => {}
                Err(_) => {
                    return Err(MaintenanceError::new(
                        ErrorCode::TransactionIo,
                        "maintenance service stop request failed",
                    ));
                }
            }
        }
        if started.elapsed() >= timeout {
            return Err(MaintenanceError::new(
                ErrorCode::ServiceBusy,
                "maintenance service is still committing or rolling back",
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn start_and_wait(service: &ServiceHandle, timeout: Duration) -> Result<()> {
    // SAFETY: this setup handle has START rights and no service arguments are supplied.
    match unsafe { StartServiceW(service.0, None) } {
        Ok(()) => {}
        Err(error) if error.code() == HRESULT::from_win32(ERROR_SERVICE_ALREADY_RUNNING.0) => {}
        Err(_) => {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionIo,
                "maintenance service could not be started",
            ));
        }
    }
    let started = Instant::now();
    loop {
        let status = query_service_status(service)?;
        if status.dwCurrentState == SERVICE_RUNNING {
            return Ok(());
        }
        if status.dwCurrentState == SERVICE_STOPPED || started.elapsed() >= timeout {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionIo,
                "maintenance service did not reach the running state",
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn verify_running_service(expected_version: &str) -> Result<()> {
    let response = call_shared_service(&crate::protocol::Request::GetStatus {
        protocol_major: crate::protocol::PROTOCOL_MAJOR,
    })?;
    if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true)
        || response
            .get("serviceVersion")
            .and_then(serde_json::Value::as_str)
            != Some(expected_version)
    {
        return Err(MaintenanceError::new(
            ErrorCode::ProtocolVersion,
            "running maintenance service version failed health-check",
        ));
    }
    let capabilities = response
        .get("capabilities")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::ProtocolVersion,
                "running maintenance service omitted capabilities",
            )
        })?;
    for required in ["file-set-v1", "registry-set-v1"] {
        if !capabilities
            .iter()
            .any(|value| value.as_str() == Some(required))
        {
            return Err(MaintenanceError::new(
                ErrorCode::ProtocolVersion,
                "running maintenance service lacks a required capability",
            ));
        }
    }
    Ok(())
}

fn service_upgrade_io(_error: std::io::Error) -> MaintenanceError {
    MaintenanceError::new(
        ErrorCode::TransactionIo,
        "maintenance service upgrade file operation failed",
    )
}

#[cfg(test)]
mod path_contract_tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "se7en-service-fixed-path-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temp root");
            Self(path)
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.0.join(Path::new(relative))
        }

        fn write(&self, relative: &str, bytes: &[u8]) {
            let path = self.path(relative);
            fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
            fs::write(path, bytes).expect("write fixture");
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn managed_service_binary_path_uses_canonical_file_set_separators() {
        let relative = super::MANAGED_SERVICE_RELATIVE_PATH;

        assert_eq!(relative, "7Launcher/Service/Se7enService.exe");
        assert_eq!(
            super::super::relative_components(relative).unwrap(),
            ["7Launcher", "Service", "Se7enService.exe"]
        );
        assert_eq!(
            super::PREVIOUS_MANAGED_SERVICE_RELATIVE_PATH,
            "7Launcher/Se7enService.exe"
        );
        assert!(!super::MANAGED_CANDIDATE_RELATIVE_PATH.contains("versions/"));
        assert!(!super::MANAGED_PREVIOUS_RELATIVE_PATH.contains("versions/"));
        let program_files = Path::new(r"C:\Program Files");
        assert_eq!(
            super::managed_binary_path_at(program_files),
            PathBuf::from(r"C:\Program Files\7Launcher\Service\Se7enService.exe")
        );
        assert_eq!(
            super::managed_candidate_binary_path_at(program_files),
            PathBuf::from(r"C:\Program Files\7Launcher\Service\Se7enService.candidate.exe")
        );
        assert_eq!(
            super::previous_managed_binary_path_at(program_files),
            PathBuf::from(r"C:\Program Files\7Launcher\Se7enService.exe")
        );
        assert_eq!(
            super::service_image_path(&super::managed_binary_path_at(program_files))
                .expect("native SCM image path"),
            r#""C:\Program Files\7Launcher\Service\Se7enService.exe" --service"#
        );
        let native = r#""C:\Program Files\7Launcher\Service\Se7enService.exe" --service"#;
        let mixed = r#""C:\Program Files\7Launcher/Service/Se7enService.exe" --service"#;
        let previous_native = r#""C:\Program Files\7Launcher\Se7enService.exe" --service"#;
        let previous_mixed = r#""C:\Program Files\7Launcher/Se7enService.exe" --service"#;
        assert_eq!(
            super::supported_previous_relative_path_for_image(
                mixed,
                native,
                mixed,
                previous_native,
                previous_mixed,
            ),
            Some(super::MANAGED_SERVICE_RELATIVE_PATH)
        );
        assert_eq!(
            super::supported_previous_relative_path_for_image(
                previous_mixed,
                native,
                mixed,
                previous_native,
                previous_mixed,
            ),
            Some(super::PREVIOUS_MANAGED_SERVICE_RELATIVE_PATH)
        );
        for erroneous in [
            r#""C:\Program Files\ExampleVendor\7Launcher\Se7enService.exe" --service"#,
            r#""C:\Program Files\ExampleVendor/7Launcher/Se7enService.exe" --service"#,
        ] {
            assert_eq!(
                super::supported_previous_relative_path_for_image(
                    erroneous,
                    native,
                    mixed,
                    previous_native,
                    previous_mixed,
                ),
                None
            );
        }
        assert_eq!(
            super::supported_previous_relative_path_for_image(
                r#""C:\Other\service.exe" --service"#,
                native,
                mixed,
                previous_native,
                previous_mixed,
            ),
            None
        );
    }

    #[test]
    fn fixed_path_install_and_upgrade_keep_at_most_one_rollback_binary() {
        let root = TemporaryDirectory::new();
        root.write(super::MANAGED_CANDIDATE_RELATIVE_PATH, b"first");
        super::activate_staged_service_binary_at(&root.0, None).expect("initial activation");
        let managed_directory = root.path("7Launcher/Service");
        let entries = fs::read_dir(&managed_directory)
            .expect("list managed directory")
            .map(|entry| entry.expect("directory entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            fs::read(root.path(super::MANAGED_SERVICE_RELATIVE_PATH))
                .unwrap_or_else(|error| panic!("live service: {error}; entries={entries:?}")),
            b"first"
        );
        assert!(!root.path(super::MANAGED_CANDIDATE_RELATIVE_PATH).exists());
        assert!(!root.path(super::MANAGED_PREVIOUS_RELATIVE_PATH).exists());

        root.write(super::MANAGED_CANDIDATE_RELATIVE_PATH, b"second");
        super::activate_staged_service_binary_at(
            &root.0,
            Some(super::MANAGED_SERVICE_RELATIVE_PATH),
        )
        .expect("upgrade activation");
        let entries = fs::read_dir(&managed_directory)
            .expect("list managed directory")
            .map(|entry| entry.expect("directory entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            fs::read(root.path(super::MANAGED_SERVICE_RELATIVE_PATH))
                .unwrap_or_else(|error| panic!("new live service: {error}; entries={entries:?}")),
            b"second"
        );
        assert_eq!(
            fs::read(root.path(super::MANAGED_PREVIOUS_RELATIVE_PATH))
                .expect("one rollback service"),
            b"first"
        );
        assert!(!root.path(super::MANAGED_CANDIDATE_RELATIVE_PATH).exists());
    }

    #[test]
    fn upgrade_migrates_the_previous_binary_from_the_old_7launcher_root() {
        let root = TemporaryDirectory::new();
        root.write(
            super::PREVIOUS_MANAGED_SERVICE_RELATIVE_PATH,
            b"version-1.0.1",
        );
        root.write(super::MANAGED_CANDIDATE_RELATIVE_PATH, b"version-1.0.2");

        super::activate_staged_service_binary_at(
            &root.0,
            Some(super::PREVIOUS_MANAGED_SERVICE_RELATIVE_PATH),
        )
        .expect("migrate previous service binary");

        assert_eq!(
            fs::read(root.path(super::MANAGED_SERVICE_RELATIVE_PATH)).expect("new live service"),
            b"version-1.0.2"
        );
        assert_eq!(
            fs::read(root.path(super::MANAGED_PREVIOUS_RELATIVE_PATH))
                .expect("previous rollback service"),
            b"version-1.0.1"
        );
        assert!(
            !root
                .path(super::PREVIOUS_MANAGED_SERVICE_RELATIVE_PATH)
                .exists()
        );
    }

    #[test]
    fn fixed_path_activation_is_repeatable_and_rollback_restores_previous_bytes() {
        let root = TemporaryDirectory::new();
        root.write(super::MANAGED_SERVICE_RELATIVE_PATH, b"new-before-crash");
        root.write(super::MANAGED_PREVIOUS_RELATIVE_PATH, b"old");
        root.write(super::MANAGED_CANDIDATE_RELATIVE_PATH, b"new-retry");

        super::activate_staged_service_binary_at(
            &root.0,
            Some(super::MANAGED_SERVICE_RELATIVE_PATH),
        )
        .expect("repeat activation");
        assert_eq!(
            fs::read(root.path(super::MANAGED_SERVICE_RELATIVE_PATH)).expect("retried live"),
            b"new-retry"
        );
        assert_eq!(
            fs::read(root.path(super::MANAGED_PREVIOUS_RELATIVE_PATH)).expect("old retained"),
            b"old"
        );

        super::restore_previous_service_binary_at(&root.0).expect("rollback");
        assert_eq!(
            fs::read(root.path(super::MANAGED_SERVICE_RELATIVE_PATH)).expect("restored live"),
            b"old"
        );
        assert!(!root.path(super::MANAGED_PREVIOUS_RELATIVE_PATH).exists());
    }

    #[test]
    fn upgrade_rejects_the_unsupported_vendor_directory() {
        let root = TemporaryDirectory::new();
        let erroneous_relative = "ExampleVendor/7Launcher/Se7enService.exe";
        root.write(erroneous_relative, b"erroneous-canary");
        root.write(super::MANAGED_CANDIDATE_RELATIVE_PATH, b"version-1.0.3");

        let error = super::activate_staged_service_binary_at(&root.0, Some(erroneous_relative))
            .expect_err("erroneous Rockstar path must be rejected");

        assert_eq!(error.code, super::ErrorCode::RootInvalid);
        assert_eq!(
            fs::read(root.path(erroneous_relative)).expect("rejected service is untouched"),
            b"erroneous-canary"
        );
        assert_eq!(
            fs::read(root.path(super::MANAGED_CANDIDATE_RELATIVE_PATH))
                .expect("candidate is untouched"),
            b"version-1.0.3"
        );
        assert!(!root.path(super::MANAGED_SERVICE_RELATIVE_PATH).exists());
        assert!(!root.path(super::MANAGED_PREVIOUS_RELATIVE_PATH).exists());
    }
}
