#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Windows-only security boundary for the maintenance service.
//!
//! Win32 FFI, raw handles, access-token inspection, service control, named-pipe setup, and
//! handle-based filesystem policy stay in this module. Every caller outside this module sees only
//! typed maintenance operations.

use std::{
    collections::BTreeMap,
    ffi::c_void,
    fs::{self, File},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    mem::{MaybeUninit, offset_of, size_of},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf},
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicPtr, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_MORE_DATA,
            ERROR_PATH_NOT_FOUND, ERROR_PIPE_CONNECTED, ERROR_SERVICE_ALREADY_RUNNING, HANDLE,
            HLOCAL, HWND, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GetSecurityInfo, NO_MULTIPLE_TRUSTEE,
            SDDL_REVISION_1, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetSecurityInfo,
            TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_TYPE, TRUSTEE_W,
        },
        Security::{
            ACL, AllocateAndInitializeSid, CheckTokenMembership,
            Cryptography::{
                CERT_CONTEXT, CERT_HASH_PROP_ID, CERT_SHA256_HASH_PROP_ID,
                CertGetCertificateContextProperty,
            },
            DACL_SECURITY_INFORMATION, DuplicateToken, FreeSid, GetTokenInformation,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
            SECURITY_ATTRIBUTES, SECURITY_NT_AUTHORITY, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            SecurityIdentification, SetFileSecurityW, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_TYPE,
            TOKEN_USER, TokenElevation, TokenImpersonation, TokenPrimary, TokenType, TokenUser,
            WinTrust::{
                WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
                WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
                WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
                WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_EXECUTE,
                WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
                WTHelperProvDataFromStateData, WinVerifyTrust,
            },
        },
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_DISPOSITION_FLAG_DELETE,
            FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_INFO_EX,
            FILE_DISPOSITION_INFO_EX_FLAGS, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_GENERIC_EXECUTE,
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
            FILE_READ_DATA, FILE_RENAME_INFO, FILE_RENAME_INFO_0, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_WRITE_DATA, FileAttributeTagInfo,
            FileBasicInfo, FileDispositionInfoEx, FileIdInfo, FileRenameInfo, FileStandardInfo,
            GetDiskFreeSpaceExW, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
            OPEN_EXISTING, PIPE_ACCESS_DUPLEX, READ_CONTROL, ReadFile, SetFileInformationByHandle,
            WRITE_DAC, WriteFile,
        },
        System::{
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
                ImpersonateNamedPipeClient, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_TYPE_MESSAGE, PIPE_WAIT, SetNamedPipeHandleState, TransactNamedPipe,
                WaitNamedPipeW,
            },
            Registry::{
                HKEY, HKEY_LOCAL_MACHINE, KEY_CREATE_SUB_KEY, KEY_QUERY_VALUE, KEY_SET_VALUE,
                KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_BINARY, REG_DWORD, REG_OPTION_NON_VOLATILE,
                REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW,
                RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
            },
            Services::{
                ChangeServiceConfig2W, CloseServiceHandle, CreateServiceW, OpenSCManagerW,
                OpenServiceW, RegisterServiceCtrlHandlerExW, SC_HANDLE, SC_MANAGER_CONNECT,
                SC_MANAGER_CREATE_SERVICE, SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS,
                SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONTROL_STOP,
                SERVICE_DEMAND_START, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL,
                SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_SID_INFO, SERVICE_START,
                SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
                SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
                SERVICE_WIN32_OWN_PROCESS, SetServiceObjectSecurity, SetServiceStatus,
                StartServiceCtrlDispatcherW, StartServiceW,
            },
            Threading::{
                CreateEventW, EVENT_MODIFY_STATE, GetCurrentThread, OpenEventW, OpenProcess,
                OpenThreadToken, PROCESS_SYNCHRONIZE, SetEvent, WaitForMultipleObjects,
                WaitForSingleObject,
            },
        },
    },
    core::{BOOL, HRESULT, PCWSTR, PWSTR},
};

use crate::{
    ErrorCode, GenerationRecord, MAX_IPC_MESSAGE_BYTES, MAX_MANIFEST_BYTES, MAX_REGISTRY_SET_BYTES,
    MaintenanceError, RegistrySetAcceptance, RegistryValue, RegistryView, Result, canonical_json,
    decode_lower_hex,
    file_set::FileEntry,
    parse_canonical,
    protocol::Request,
    registry_scopes::{RegisteredRegistryScope, RegistryScopeRegistry, validate_registry_subkey},
    roots::{DirectoryIdentity, RegisteredRoot, RootRegistry},
    transaction::{
        CommitResult, PreparedJob, TargetSnapshot, TransactionPlatform, TransactionPolicy,
        commit_file_set, prepare_file_set, recover_incomplete_with_policy,
    },
    trust::{KeyringAcceptance, VerifiedKeyring, verify_keyring},
    valid_identifier, valid_job_identifier, verify_file_set, verify_registry_set,
};

#[path = "windows_upgrade.rs"]
mod upgrade;
use sha2::{Digest, Sha256};
pub use upgrade::{
    EnsureServiceResult, RemoveServiceResult, ServiceBundleEvidence,
    confirm_and_elevate_service_removal, ensure_system_service, remove_system_service,
    verify_service_bundle,
};

/// Verifies the stable CDN service installer before the updater asks Windows to elevate it.
///
/// The manager and setup must both have valid Authenticode signatures from the same certificate.
/// The returned SHA-256 is diagnostic evidence; WinVerifyTrust verifies the signed file digest.
pub fn verify_service_setup_installer(path: &Path) -> Result<String> {
    if !path.is_absolute()
        || !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("se7en-service-setup.exe"))
    {
        return Err(MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "service setup path must be absolute and use the canonical file name",
        ));
    }

    let mut setup = open_absolute(
        path,
        FILE_GENERIC_READ.0,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "downloaded service setup cannot be opened without reparse traversal",
        )
    })?;
    ensure_safe_regular_file(&setup).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "downloaded service setup is not a regular non-reparse file",
        )
    })?;
    let digest = hash_trust_file(&mut setup)?;

    let manager_path = std::env::current_exe().map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TrustSignature,
            "service manager executable path is unavailable",
        )
    })?;
    let manager = File::open(manager_path).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TrustSignature,
            "service manager executable cannot be opened",
        )
    })?;
    let (manager_sha1, manager_sha256) = verified_authenticode_signer_thumbprints(&manager)?;
    verify_authenticode_signer(&setup, &[manager_sha1, manager_sha256])?;
    Ok(lower_hex(&digest))
}

fn hash_trust_file(file: &mut File) -> Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0)).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "downloaded service setup cannot be hashed",
        )
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "downloaded service setup cannot be hashed",
            )
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "downloaded service setup cannot be rewound after hashing",
        )
    })?;
    Ok(digest.finalize().into())
}

pub const SERVICE_NAME: &str = "SE7ENService";
pub const SERVICE_DISPLAY_NAME: &str = "SE7EN Service";
pub const SERVICE_DESCRIPTION: &str =
    "Provides secure privileged file maintenance for 7Launcher games and applications.";
pub const SERVICE_ACCOUNT: &str = "LocalSystem";
pub const PIPE_NAME: &str = r"\\.\pipe\SE7ENService-v1";

/// SYSTEM and Administrators have full control. Authenticated users may only start and query the
/// service (`RP`/`LC`); notably absent are stop, change-config, delete, write-DAC, and write-owner.
pub const SERVICE_DACL_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;LCRP;;;AU)";

/// The pipe is local-only in addition to `PIPE_REJECT_REMOTE_CLIENTS`. Authenticated users receive
/// only the specific client data/attribute/read-control/synchronize bits. The mask deliberately
/// excludes bit 0x4 (`FILE_CREATE_PIPE_INSTANCE`).
pub const PIPE_DACL_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00120183;;;AU)";
pub const PIPE_CLIENT_ACCESS_MASK: u32 = 0x0012_0183;
pub const FILE_CREATE_PIPE_INSTANCE_BIT: u32 = 0x0000_0004;

const PIPE_READY_TIMEOUT: Duration = Duration::from_secs(30);
const PIPE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const PIPE_READY_WAIT_SLICE: Duration = Duration::from_millis(250);
const PIPE_READY_RETRY_DELAY: Duration = Duration::from_millis(50);

const DOMAIN_ALIAS_RID_ADMINS_VALUE: u32 = 0x0000_0220;
const SECURITY_BUILTIN_DOMAIN_RID_VALUE: u32 = 0x0000_0020;
// Defined by winsvc.h but omitted from the metadata shipped with windows 0.62.
const SERVICE_SID_TYPE_NONE_VALUE: u32 = 0;
const SERVICE_IDLE_TIMEOUT_MS: u32 = 30_000;

struct KernelHandle(HANDLE);

impl KernelHandle {
    fn new(handle: HANDLE, code: ErrorCode, detail: &'static str) -> Result<Self> {
        if handle.is_invalid() {
            Err(MaintenanceError::new(code, detail))
        } else {
            Ok(Self(handle))
        }
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for KernelHandle {
    fn drop(&mut self) {
        // SAFETY: `KernelHandle` uniquely owns a non-pseudo HANDLE returned by Win32.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct RegistryKey(HKEY);

impl RegistryKey {
    fn new(handle: HKEY) -> Result<Self> {
        if handle.is_invalid() {
            Err(MaintenanceError::new(
                ErrorCode::RegistryIo,
                "registry key handle is invalid",
            ))
        } else {
            Ok(Self(handle))
        }
    }

    const fn raw(&self) -> HKEY {
        self.0
    }
}

impl Drop for RegistryKey {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: this wrapper owns the registry-key handle and closes it exactly once.
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: `ServiceHandle` uniquely owns the valid SCM/service handle.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl LocalSecurityDescriptor {
    fn parse(sddl: &str) -> Result<Self> {
        let wide = wide_null(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated and `descriptor` is a valid out pointer. The returned
        // descriptor is owned by LocalAlloc and released by this type's Drop implementation.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|_| {
            MaintenanceError::new(
                ErrorCode::RootUnauthorized,
                "security descriptor could not be constructed",
            )
        })?;
        Ok(Self(descriptor))
    }

    const fn raw(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }

    fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: BOOL(0),
        }
    }
}

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by
        // ConvertStringSecurityDescriptorToSecurityDescriptorW and is freed exactly once.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

/// Creates the one shared own-process service. This setup operation must be invoked by the signed
/// elevated installer; normal IPC clients never receive this capability.
pub fn create_system_service(executable: &Path) -> Result<()> {
    let executable = executable.to_str().ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::RootInvalid,
            "service executable path must be Unicode",
        )
    })?;
    let binary_path = wide_null(&format!("\"{executable}\" --service"));
    let service_name = wide_null(SERVICE_NAME);
    let display_name = wide_null(SERVICE_DISPLAY_NAME);
    let account = wide_null(SERVICE_ACCOUNT);

    // SAFETY: null machine/database names select the local active SCM database. The returned
    // handle is validated and then owned by ServiceHandle.
    let manager =
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CREATE_SERVICE) }
            .map(ServiceHandle)
            .map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::RootUnauthorized,
                    "service control manager cannot be opened for setup",
                )
            })?;

    // SAFETY: every string is live and NUL-terminated for the duration of the call. Null optional
    // values have the documented CreateServiceW meaning. LocalSystem has no password.
    let service = unsafe {
        CreateServiceW(
            manager.0,
            PCWSTR(service_name.as_ptr()),
            PCWSTR(display_name.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(binary_path.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            PCWSTR::null(),
        )
    }
    .map(ServiceHandle)
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "shared maintenance service could not be created",
        )
    })?;

    configure_system_service(&service)?;
    provision_service_data_directory()
}

fn configure_system_service(service: &ServiceHandle) -> Result<()> {
    let sid_info = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_NONE_VALUE,
    };
    // SAFETY: `sid_info` has the exact layout required by SERVICE_CONFIG_SERVICE_SID_INFO and is
    // live through the synchronous call.
    unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            Some(ptr::from_ref(&sid_info).cast()),
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "service SID mode could not be configured",
        )
    })?;

    let mut description_text = wide_null(SERVICE_DESCRIPTION);
    let description = SERVICE_DESCRIPTIONW {
        lpDescription: PWSTR(description_text.as_mut_ptr()),
    };
    // SAFETY: `description` has the exact layout required by SERVICE_CONFIG_DESCRIPTION and its
    // mutable NUL-terminated backing buffer remains live through the synchronous call.
    unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            Some(ptr::from_ref(&description).cast()),
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "maintenance service description could not be configured",
        )
    })?;

    let descriptor = LocalSecurityDescriptor::parse(SERVICE_DACL_SDDL)?;
    // SAFETY: the service handle and self-relative descriptor are valid for the synchronous call.
    unsafe { SetServiceObjectSecurity(service.0, DACL_SECURITY_INFORMATION, descriptor.raw()) }
        .map_err(|_| {
            MaintenanceError::new(
                ErrorCode::RootUnauthorized,
                "maintenance service DACL could not be configured",
            )
        })?;
    Ok(())
}

/// Installs a root-signed keyring into the protected service directory. Replacing it is allowed
/// only when the keyring contract accepts the current version/digest as its anti-rollback floor.
pub fn install_verified_keyring(source: &Path) -> Result<()> {
    let source_bytes = read_service_file(source, MAX_MANIFEST_BYTES)?;
    install_verified_keyring_bytes(&source_bytes)
}

fn verify_candidate_keyring_bytes(source_bytes: &[u8]) -> Result<VerifiedKeyring> {
    let destination = service_data_directory()?.join("keyring-v1.json");
    recover_service_file_replacement(&destination)?;
    let acceptance = if destination.exists() {
        let current_bytes = read_service_file(&destination, MAX_MANIFEST_BYTES)?;
        installed_keyring_acceptance(&current_bytes)?
    } else {
        KeyringAcceptance::default()
    };
    verify_keyring(source_bytes, acceptance)
}

fn installed_keyring_acceptance(bytes: &[u8]) -> Result<KeyringAcceptance> {
    let current = verify_keyring(bytes, KeyringAcceptance::default()).map_err(|error| {
        MaintenanceError::new(
            error.code(),
            "installed keyring is invalid; repair or uninstall the service before retrying",
        )
    })?;
    Ok(KeyringAcceptance {
        minimum_version: current.keyring().version,
        current_digest: Some(current.digest()),
    })
}

fn install_verified_keyring_bytes(source_bytes: &[u8]) -> Result<()> {
    verify_candidate_keyring_bytes(source_bytes)?;
    let destination = service_data_directory()?.join("keyring-v1.json");
    recover_service_file_replacement(&destination)?;
    replace_service_file(&destination, source_bytes)
}

/// Starts the shared service with only START/QUERY_STATUS rights. It never requests stop, config,
/// delete, or DACL rights from an ordinary client token.
pub fn start_shared_service() -> Result<()> {
    // SAFETY: null names select the local active SCM database; the returned handle is owned below.
    let manager = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
        .map(ServiceHandle)
        .map_err(|_| {
            MaintenanceError::new(
                ErrorCode::RootUnauthorized,
                "service control manager cannot be opened by the client",
            )
        })?;
    let name = wide_null(SERVICE_NAME);
    // SAFETY: the service name is NUL-terminated and the returned handle is owned below.
    let service = unsafe {
        OpenServiceW(
            manager.0,
            PCWSTR(name.as_ptr()),
            SERVICE_START | SERVICE_QUERY_STATUS,
        )
    }
    .map(ServiceHandle)
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::ProtocolVersion,
            "shared maintenance service is not installed",
        )
    })?;
    // SAFETY: the service handle has START rights and no service arguments are accepted.
    match unsafe { StartServiceW(service.0, None) } {
        Ok(()) => Ok(()),
        Err(error) if error.code() == HRESULT::from_win32(ERROR_SERVICE_ALREADY_RUNNING.0) => {
            Ok(())
        }
        Err(_) => Err(MaintenanceError::new(
            ErrorCode::TransactionIo,
            "shared maintenance service could not be started",
        )),
    }
}

/// Sends one typed IPC v1 request and returns one bounded JSON response.
pub fn call_shared_service(request: &Request) -> Result<serde_json::Value> {
    start_shared_service()?;
    let pipe_name = wide_null(PIPE_NAME);
    let pipe_path = Path::new(PIPE_NAME);
    let pipe = wait_for_pipe_ready_with(
        PIPE_READY_TIMEOUT,
        |wait_milliseconds| {
            // SAFETY: the pipe name is NUL-terminated and the wait slice is finite. WaitNamedPipeW
            // returns immediately while the service has reported Running but has not created its
            // first pipe instance, so the bounded outer retry is required.
            if !unsafe { WaitNamedPipeW(PCWSTR(pipe_name.as_ptr()), wait_milliseconds) }.as_bool() {
                return None;
            }
            // A successful wait does not reserve the instance. Retrying the open also covers the
            // documented race where another client opens or the service replaces that instance.
            open_absolute(
                pipe_path,
                PIPE_CLIENT_ACCESS_MASK,
                windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            )
            .ok()
        },
        thread::sleep,
    )
    .ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "shared maintenance pipe did not become ready",
        )
    })?;
    let encoded = serde_json::to_vec(request).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::ProtocolInvalid,
            "typed IPC request cannot be encoded",
        )
    })?;
    if encoded.len() > MAX_IPC_MESSAGE_BYTES {
        return Err(MaintenanceError::new(
            ErrorCode::ProtocolTooLarge,
            "typed IPC request exceeds the message bound",
        ));
    }
    let response = transact_pipe_message(raw_handle(&pipe), &encoded)?;
    let response: serde_json::Value = serde_json::from_slice(&response).map_err(|_| {
        MaintenanceError::new(ErrorCode::ProtocolInvalid, "IPC response is not JSON")
    })?;
    if response
        .get("protocolMajor")
        .and_then(serde_json::Value::as_u64)
        != Some(u64::from(crate::protocol::PROTOCOL_MAJOR))
    {
        return Err(MaintenanceError::new(
            ErrorCode::ProtocolVersion,
            "shared service returned an incompatible protocol major",
        ));
    }
    Ok(response)
}

fn transact_pipe_message(pipe: HANDLE, request: &[u8]) -> Result<Vec<u8>> {
    transact_pipe_message_with_timeout(pipe, request, PIPE_RESPONSE_TIMEOUT)
}

fn transact_pipe_message_with_timeout(
    pipe: HANDLE,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>> {
    let request_size = u32::try_from(request.len()).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::ProtocolTooLarge,
            "typed IPC request size overflowed",
        )
    })?;
    let response_capacity = u32::try_from(MAX_IPC_MESSAGE_BYTES).map_err(|_| {
        MaintenanceError::new(ErrorCode::ProtocolTooLarge, "IPC response bound overflowed")
    })?;
    let message_mode = PIPE_READMODE_MESSAGE;
    // SAFETY: this is a connected client-side named-pipe handle and the mode pointer remains live
    // for the synchronous call. The server created a duplex message-type pipe.
    unsafe { SetNamedPipeHandleState(pipe, Some(ptr::from_ref(&message_mode)), None, None) }
        .map_err(|_| {
            MaintenanceError::new(
                ErrorCode::ProtocolInvalid,
                "typed IPC pipe cannot enter message-read mode",
            )
        })?;

    let mut response = vec![0_u8; MAX_IPC_MESSAGE_BYTES];
    let mut read = 0_u32;
    let event = create_event(true, false)?;
    let mut overlapped = OVERLAPPED {
        hEvent: event.raw(),
        ..Default::default()
    };
    // SAFETY: the client pipe is overlapped and duplex message-type. All request/response buffers,
    // the event and OVERLAPPED stay alive until completion or cancellation is drained below.
    let completion = match unsafe {
        TransactNamedPipe(
            pipe,
            Some(request.as_ptr().cast()),
            request_size,
            Some(response.as_mut_ptr().cast()),
            response_capacity,
            &mut read,
            Some(&mut overlapped),
        )
    } {
        Ok(()) => {
            // SAFETY: this observes the byte count of the already completed live operation.
            unsafe { GetOverlappedResult(pipe, &overlapped, &mut read, false) }
        }
        Err(error) if error.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => {
            let milliseconds = timeout.as_millis().min(u128::from(u32::MAX - 1)) as u32;
            // SAFETY: the live event belongs exclusively to this pending operation.
            let wait = unsafe { WaitForSingleObject(event.raw(), milliseconds) };
            if wait != WAIT_OBJECT_0 {
                // SAFETY: cancellation addresses only this operation, and draining completion keeps
                // its buffers and OVERLAPPED alive even if completion raced the timeout.
                let _ = unsafe { CancelIoEx(pipe, Some(&overlapped)) };
                let _ = unsafe { GetOverlappedResult(pipe, &overlapped, &mut read, true) };
                return Err(MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    if wait == WAIT_TIMEOUT {
                        "typed IPC response timed out"
                    } else {
                        "typed IPC response wait failed"
                    },
                ));
            }
            // SAFETY: the event reported completion while its OVERLAPPED and buffers remain live.
            unsafe { GetOverlappedResult(pipe, &overlapped, &mut read, false) }
        }
        result => result,
    };
    match completion {
        Ok(()) => {}
        Err(error) if error.code() == HRESULT::from_win32(ERROR_MORE_DATA.0) => {
            return Err(MaintenanceError::new(
                ErrorCode::ProtocolTooLarge,
                "typed IPC response exceeds the message bound",
            ));
        }
        Err(_) => {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionIo,
                "typed IPC transaction did not return one bounded response",
            ));
        }
    }
    response.truncate(usize::try_from(read).map_err(|_| {
        MaintenanceError::new(ErrorCode::ProtocolTooLarge, "IPC response size overflowed")
    })?);
    Ok(response)
}

fn wait_for_pipe_ready_with<T>(
    timeout: Duration,
    mut try_open: impl FnMut(u32) -> Option<T>,
    mut sleep: impl FnMut(Duration),
) -> Option<T> {
    let started = Instant::now();
    loop {
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return None;
        }
        let remaining = timeout.saturating_sub(elapsed);
        let wait_slice = remaining.min(PIPE_READY_WAIT_SLICE);
        let wait_milliseconds = u32::try_from(wait_slice.as_millis())
            .unwrap_or(u32::MAX)
            .max(1);
        if let Some(pipe) = try_open(wait_milliseconds) {
            return Some(pipe);
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return None;
        }
        sleep(remaining.min(PIPE_READY_RETRY_DELAY));
    }
}

/// Holds the existing Launcher process identity across the helper readiness handshake. This handle
/// grants only SYNCHRONIZE; helper code receives no process-memory or injection rights.
pub struct LauncherProcess(KernelHandle);

impl LauncherProcess {
    pub fn open(process_id: u32) -> Result<Self> {
        // SAFETY: OpenProcess receives a concrete PID and only PROCESS_SYNCHRONIZE access. The
        // returned non-inheritable handle is uniquely owned by KernelHandle.
        let process =
            unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, process_id) }.map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::TransactionState,
                    "Launcher process cannot be opened for synchronization",
                )
            })?;
        KernelHandle::new(
            process,
            ErrorCode::TransactionState,
            "Launcher synchronization handle is invalid",
        )
        .map(Self)
    }

    /// Returns true after this exact process exits, or false when the finite wait expires.
    pub fn wait(&self, timeout: Duration) -> Result<bool> {
        let milliseconds = timeout.as_millis().min(u128::from(u32::MAX - 1)) as u32;
        // SAFETY: the process handle is waitable and remains live for the entire bounded wait.
        match unsafe { WaitForSingleObject(self.0.raw(), milliseconds) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(MaintenanceError::new(
                ErrorCode::TransactionState,
                "Launcher process synchronization failed",
            )),
        }
    }
}

/// Acknowledges that the helper has opened its Launcher synchronization handle. The Launcher owns
/// this existing event; the helper receives only the right to signal it and never creates one.
pub fn signal_launcher_ready(event_name: &str) -> Result<()> {
    if event_name.is_empty() || event_name.contains('\0') {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionState,
            "Launcher readiness event name is invalid",
        ));
    }
    let name = wide_null(event_name);
    // SAFETY: the name is NUL-terminated and the resulting handle is uniquely owned below.
    let event =
        unsafe { OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(name.as_ptr())) }.map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionState,
                "Launcher readiness event cannot be opened",
            )
        })?;
    let event = KernelHandle::new(
        event,
        ErrorCode::TransactionState,
        "Launcher readiness event handle is invalid",
    )?;
    // SAFETY: the live event handle grants EVENT_MODIFY_STATE and remains owned through the call.
    unsafe { SetEvent(event.raw()) }.map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionState,
            "Launcher readiness event cannot be signaled",
        )
    })
}

/// Compatibility entry point for callers that do not use the readiness handshake.
pub fn wait_for_process_exit(process_id: u32) -> Result<()> {
    let process = LauncherProcess::open(process_id)?;
    while !process.wait(Duration::from_secs(30))? {}
    Ok(())
}

fn provision_service_data_directory() -> Result<()> {
    let data_directory = service_data_directory()?;
    fs::create_dir_all(&data_directory).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "protected service data directory cannot be created",
        )
    })?;
    let descriptor = LocalSecurityDescriptor::parse("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
    let path = wide_null(data_directory.as_os_str().to_string_lossy().as_ref());
    let information = windows::Win32::Security::OBJECT_SECURITY_INFORMATION(
        DACL_SECURITY_INFORMATION.0 | PROTECTED_DACL_SECURITY_INFORMATION.0,
    );
    // SAFETY: the path is NUL-terminated and the parsed self-relative descriptor remains live for
    // this synchronous DACL update. The installer is required to be elevated.
    let applied = unsafe { SetFileSecurityW(PCWSTR(path.as_ptr()), information, descriptor.raw()) };
    if !applied.as_bool() {
        return Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "protected service data DACL cannot be applied",
        ));
    }
    Ok(())
}

/// Creates a single local message-mode server pipe with an explicit DACL. Remote clients are
/// rejected by the kernel before protocol decoding.
fn create_server_pipe() -> Result<KernelHandle> {
    let pipe_name = wide_null(PIPE_NAME);
    let mut descriptor = LocalSecurityDescriptor::parse(PIPE_DACL_SDDL)?;
    let attributes = descriptor.attributes();
    // SAFETY: the name is NUL-terminated, the security attributes and descriptor outlive the
    // synchronous call, and all buffer/count values are bounded constants.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(pipe_name.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            64 * 1024,
            30_000,
            Some(ptr::from_ref(&attributes)),
        )
    };
    KernelHandle::new(
        handle,
        ErrorCode::TransactionIo,
        "local maintenance pipe could not be created",
    )
}

struct ImpersonationGuard {
    active: bool,
}

impl ImpersonationGuard {
    fn begin(pipe: HANDLE) -> Result<Self> {
        // SAFETY: `pipe` is a connected server-side named-pipe handle owned by the service loop.
        unsafe { ImpersonateNamedPipeClient(pipe) }.map_err(|_| {
            MaintenanceError::new(
                ErrorCode::RootUnauthorized,
                "named-pipe caller could not be impersonated",
            )
        })?;
        Ok(Self { active: true })
    }

    fn revert(mut self) -> Result<()> {
        // SAFETY: the current service thread is impersonating because this guard is active.
        unsafe { RevertToSelf() }.map_err(|_| {
            MaintenanceError::new(
                ErrorCode::RootUnauthorized,
                "service could not revert from caller impersonation",
            )
        })?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: this is the final fail-safe for an active thread impersonation. Microsoft
            // requires process termination if RevertToSelf fails, because continuing privileged
            // execution under the client token is unsafe.
            if unsafe { RevertToSelf() }.is_err() {
                std::process::abort();
            }
        }
    }
}

fn caller_identity_from_connected_pipe(pipe: HANDLE) -> Result<CallerIdentity> {
    let guard = ImpersonationGuard::begin(pipe)?;
    let identity = current_thread_caller_identity();
    guard.revert()?;
    identity
}

fn current_thread_caller_identity() -> Result<CallerIdentity> {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentThread returns a pseudo-handle valid for this call and `token` is a valid
    // out pointer. The resulting real token handle is owned by KernelHandle.
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, false, &mut token) }.map_err(
        |_| {
            MaintenanceError::new(
                ErrorCode::RootUnauthorized,
                "impersonated caller token cannot be opened",
            )
        },
    )?;
    let token = KernelHandle::new(
        token,
        ErrorCode::RootUnauthorized,
        "impersonated caller token is invalid",
    )?;
    let sid = token_user_sid(token.raw())?;
    let elevated = token_is_elevated(token.raw())?;
    let administrator = token_is_administrator(token.raw())?;
    CallerIdentity::new(sid, elevated && administrator)
}

fn token_user_sid(token: HANDLE) -> Result<String> {
    let mut needed = 0_u32;
    // SAFETY: this first call deliberately supplies no buffer and obtains the required size.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed == 0 || needed > 64 * 1024 {
        return Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "caller token user information has an invalid size",
        ));
    }
    let word_count = usize::try_from(needed)
        .ok()
        .and_then(|bytes| bytes.checked_add(size_of::<usize>() - 1))
        .map(|bytes| bytes / size_of::<usize>())
        .ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::RootUnauthorized,
                "caller token user information size overflowed",
            )
        })?;
    let mut storage = vec![0_usize; word_count];
    // SAFETY: `storage` is suitably aligned, writable for at least `needed` bytes, and remains live
    // while the TOKEN_USER and embedded SID pointer are inspected.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(storage.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "caller token user information cannot be read",
        )
    })?;
    // SAFETY: GetTokenInformation initialized a complete, aligned TOKEN_USER at storage start.
    let token_user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let mut text = PWSTR::null();
    // SAFETY: the SID pointer refers into the live token buffer and `text` is a valid out pointer.
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut text) }.map_err(|_| {
        MaintenanceError::new(ErrorCode::RootUnauthorized, "caller SID cannot be encoded")
    })?;
    // SAFETY: ConvertSidToStringSidW returned a NUL-terminated LocalAlloc string.
    let result = unsafe { text.to_string() }.map_err(|_| {
        MaintenanceError::new(ErrorCode::RootUnauthorized, "caller SID string is invalid")
    });
    // SAFETY: `text` was allocated by ConvertSidToStringSidW and is freed exactly once.
    let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    result
}

fn token_is_elevated(token: HANDLE) -> Result<bool> {
    let mut elevation = MaybeUninit::<TOKEN_ELEVATION>::uninit();
    let mut returned = 0_u32;
    // SAFETY: `elevation` is a correctly sized/aligned out buffer and is initialized on success.
    unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(elevation.as_mut_ptr().cast()),
            u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(u32::MAX),
            &mut returned,
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "caller token elevation cannot be read",
        )
    })?;
    if returned != u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(u32::MAX) {
        return Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "caller token elevation has an invalid size",
        ));
    }
    // SAFETY: the successful call initialized the whole TOKEN_ELEVATION value.
    Ok(unsafe { elevation.assume_init() }.TokenIsElevated != 0)
}

fn token_is_administrator(token: HANDLE) -> Result<bool> {
    let token_type = token_type(token)?;
    let duplicated = if token_type == TokenPrimary {
        let mut duplicate = HANDLE::default();
        // SAFETY: the caller opened this primary token with TOKEN_DUPLICATE. SecurityIdentification
        // creates the least-privileged impersonation token sufficient for a membership query.
        unsafe { DuplicateToken(token, SecurityIdentification, &mut duplicate) }.map_err(|_| {
            MaintenanceError::new(
                ErrorCode::RootUnauthorized,
                "primary token cannot be duplicated for administrator membership",
            )
        })?;
        Some(KernelHandle::new(
            duplicate,
            ErrorCode::RootUnauthorized,
            "administrator membership token is invalid",
        )?)
    } else if token_type == TokenImpersonation {
        None
    } else {
        return Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "administrator membership token has an unsupported type",
        ));
    };
    let membership_token = duplicated.as_ref().map_or(token, KernelHandle::raw);

    let mut administrator_sid = PSID::default();
    // SAFETY: the authority and subauthority values form the well-known BUILTIN\Administrators
    // SID, and `administrator_sid` is a valid out pointer.
    unsafe {
        AllocateAndInitializeSid(
            &SECURITY_NT_AUTHORITY,
            2,
            SECURITY_BUILTIN_DOMAIN_RID_VALUE,
            DOMAIN_ALIAS_RID_ADMINS_VALUE,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut administrator_sid,
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "administrator SID cannot be constructed",
        )
    })?;
    let mut member = BOOL(0);
    // SAFETY: `membership_token` is an impersonation token and the allocated SID is valid for the
    // synchronous membership check.
    let result =
        unsafe { CheckTokenMembership(Some(membership_token), administrator_sid, &mut member) };
    // SAFETY: AllocateAndInitializeSid allocated this SID and it is freed exactly once.
    let _ = unsafe { FreeSid(administrator_sid) };
    result.map(|()| member.as_bool()).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "administrator membership cannot be checked",
        )
    })
}

fn token_type(token: HANDLE) -> Result<TOKEN_TYPE> {
    let mut token_type = MaybeUninit::<TOKEN_TYPE>::uninit();
    let expected = u32::try_from(size_of::<TOKEN_TYPE>()).unwrap_or(u32::MAX);
    let mut returned = 0_u32;
    // SAFETY: `token_type` is a correctly sized/aligned out buffer and is initialized on success.
    unsafe {
        GetTokenInformation(
            token,
            TokenType,
            Some(token_type.as_mut_ptr().cast()),
            expected,
            &mut returned,
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "administrator membership token type cannot be read",
        )
    })?;
    if returned != expected {
        return Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "administrator membership token type has an invalid size",
        ));
    }
    // SAFETY: the successful call initialized the whole TOKEN_TYPE value.
    Ok(unsafe { token_type.assume_init() })
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

/// Handle-based policy used by the real service. Staging files are opened while impersonating the
/// pipe caller, retained as handles, and never reopened by a privileged path string.
#[derive(Default)]
pub struct WindowsTransactionPlatform {
    staging_files: Mutex<BTreeMap<String, File>>,
    target_handles: Mutex<BTreeMap<String, File>>,
}

impl WindowsTransactionPlatform {
    fn with_staging_files(staging_files: BTreeMap<String, File>) -> Self {
        Self {
            staging_files: Mutex::new(staging_files),
            target_handles: Mutex::new(BTreeMap::new()),
        }
    }

    fn target_key(root: &RegisteredRoot, relative_path: &str) -> String {
        format!("{}\0{relative_path}", root.root_id())
    }

    fn verify_launcher_payloads(
        &self,
        entries: &[FileEntry],
        allowed_thumbprints: &[String],
    ) -> Result<()> {
        let files = self.staging_files.lock().map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionState,
                "staging handle map is poisoned",
            )
        })?;
        for entry in entries.iter().filter(|entry| {
            Path::new(&entry.path)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        }) {
            let file = files.get(&entry.path).ok_or_else(|| {
                MaintenanceError::new(
                    ErrorCode::StagingInvalid,
                    "launcher executable was not pre-opened as the caller",
                )
            })?;
            verify_authenticode_signer(file, allowed_thumbprints)?;
        }
        Ok(())
    }
}

fn verify_authenticode_signer(file: &File, allowed_thumbprints: &[String]) -> Result<()> {
    if allowed_thumbprints.is_empty() {
        return Err(MaintenanceError::new(
            ErrorCode::TrustSignature,
            "launcher executable signer allowlist is empty",
        ));
    }
    let (sha1, sha256) = verified_authenticode_signer_thumbprints(file)?;
    if signer_thumbprint_allowed(&sha1, &sha256, allowed_thumbprints) {
        Ok(())
    } else {
        Err(MaintenanceError::new(
            ErrorCode::TrustSignature,
            "executable signer is not in the signed allowlist",
        ))
    }
}

fn verified_authenticode_signer_thumbprints(file: &File) -> Result<(String, String)> {
    let final_path = final_path_owned(file)?;
    let final_path = final_path.to_str().ok_or_else(|| {
        MaintenanceError::new(ErrorCode::TrustSignature, "executable path is not Unicode")
    })?;
    let final_path = wide_null(final_path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: u32::try_from(size_of::<WINTRUST_FILE_INFO>()).unwrap_or_default(),
        pcwszFilePath: PCWSTR(final_path.as_ptr()),
        hFile: raw_handle(file),
        pgKnownSubject: ptr::null_mut(),
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: u32::try_from(size_of::<WINTRUST_DATA>()).unwrap_or_default(),
        pPolicyCallbackData: ptr::null_mut(),
        pSIPClientData: ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: ptr::from_mut(&mut file_info),
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: HANDLE::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: ptr::null_mut(),
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: the action, trust data, file info, path, and pre-opened file handle remain live for
    // both the VERIFY call and the matching CLOSE call below. UI and URL retrieval are disabled.
    let verification = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            ptr::from_mut(&mut trust_data).cast(),
        )
    };
    let result = if verification == 0 {
        authenticode_signer_thumbprints(&trust_data)
    } else {
        Err(MaintenanceError::new(
            ErrorCode::TrustSignature,
            "executable Authenticode verification failed",
        ))
    };
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: this closes exactly the state opened by the VERIFY call using the same live data.
    let _ = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            ptr::from_mut(&mut trust_data).cast(),
        )
    };
    result
}

fn authenticode_signer_thumbprints(trust_data: &WINTRUST_DATA) -> Result<(String, String)> {
    // SAFETY: a successful WinVerifyTrust VERIFY owns this state until the matching CLOSE call.
    let provider = unsafe { WTHelperProvDataFromStateData(trust_data.hWVTStateData) };
    if provider.is_null() {
        return Err(MaintenanceError::new(
            ErrorCode::TrustSignature,
            "Authenticode provider state is unavailable",
        ));
    }
    // SAFETY: provider is the live state returned above; index zero selects the primary signer.
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, false, 0) };
    if signer.is_null() {
        return Err(MaintenanceError::new(
            ErrorCode::TrustSignature,
            "Authenticode primary signer is unavailable",
        ));
    }
    // SAFETY: signer is live provider state; index zero selects its leaf signing certificate.
    let certificate = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    if certificate.is_null() {
        return Err(MaintenanceError::new(
            ErrorCode::TrustSignature,
            "Authenticode signing certificate is unavailable",
        ));
    }
    // SAFETY: certificate points into live WinVerifyTrust state through the matching CLOSE call.
    let context = unsafe { (*certificate).pCert };
    if context.is_null() {
        return Err(MaintenanceError::new(
            ErrorCode::TrustSignature,
            "Authenticode signing certificate context is unavailable",
        ));
    }
    let sha1 = certificate_thumbprint(context, CERT_HASH_PROP_ID, 20)?;
    let sha256 = certificate_thumbprint(context, CERT_SHA256_HASH_PROP_ID, 32)?;
    Ok((sha1, sha256))
}

fn certificate_thumbprint(
    context: *const CERT_CONTEXT,
    property: u32,
    expected_bytes: u32,
) -> Result<String> {
    let mut bytes = 0_u32;
    // SAFETY: context is a live leaf certificate and this sizing call writes only the byte count.
    unsafe { CertGetCertificateContextProperty(context, property, None, &mut bytes) }.map_err(
        |_| {
            MaintenanceError::new(
                ErrorCode::TrustSignature,
                "Authenticode certificate thumbprint size is unavailable",
            )
        },
    )?;
    if bytes != expected_bytes {
        return Err(MaintenanceError::new(
            ErrorCode::TrustSignature,
            "Authenticode certificate thumbprint size is invalid",
        ));
    }
    let mut value = vec![0_u8; usize::try_from(bytes).unwrap_or_default()];
    // SAFETY: the buffer has the exact size returned for this live certificate property.
    unsafe {
        CertGetCertificateContextProperty(
            context,
            property,
            Some(value.as_mut_ptr().cast()),
            &mut bytes,
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TrustSignature,
            "Authenticode certificate thumbprint cannot be read",
        )
    })?;
    Ok(lower_hex(&value))
}

fn signer_thumbprint_allowed(sha1: &str, sha256: &str, allowed: &[String]) -> bool {
    allowed
        .iter()
        .any(|thumbprint| thumbprint == sha1 || thumbprint == sha256)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

impl TransactionPlatform for WindowsTransactionPlatform {
    fn verify_root_identity(&self, root: &RegisteredRoot) -> Result<()> {
        let handle = open_absolute_directory(root.canonical_path(), false)?;
        if directory_identity(&handle)? != root.identity()
            || final_path_owned(&handle)? != root.canonical_path()
        {
            return Err(MaintenanceError::new(
                ErrorCode::RootIdentity,
                "registered root handle identity or canonical path changed",
            ));
        }
        Ok(())
    }

    fn root_is_missing(&self, root: &RegisteredRoot) -> bool {
        match open_absolute(
            root.canonical_path(),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        ) {
            Ok(_) => false,
            Err(error) => is_not_found(&error),
        }
    }

    fn available_space(&self, path: &Path) -> Result<u64> {
        let path = path.to_str().ok_or_else(|| {
            MaintenanceError::new(ErrorCode::InsufficientSpace, "volume path is not Unicode")
        })?;
        let path = wide_null(path);
        let mut available = 0_u64;
        // SAFETY: the path is NUL-terminated and `available` is a valid out pointer.
        unsafe { GetDiskFreeSpaceExW(PCWSTR(path.as_ptr()), Some(&mut available), None, None) }
            .map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::InsufficientSpace,
                    "available volume space cannot be queried",
                )
            })?;
        Ok(available)
    }

    fn same_volume(&self, left: &Path, right: &Path) -> Result<bool> {
        let left = open_absolute_directory(left, false)?;
        let right = open_absolute_directory(right, false)?;
        Ok(directory_identity(&left)?.volume_serial == directory_identity(&right)?.volume_serial)
    }

    fn open_staging_payload(
        &self,
        _staging_root: &Path,
        relative_path: &str,
    ) -> Result<Box<dyn Read + Send>> {
        let mut files = self.staging_files.lock().map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionState,
                "staging handle map is poisoned",
            )
        })?;
        let file = files.get_mut(relative_path).ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::StagingInvalid,
                "staging payload was not pre-opened as the caller",
            )
        })?;
        file.seek(SeekFrom::Start(0)).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::StagingInvalid,
                "staging payload handle cannot be rewound",
            )
        })?;
        let clone = file.try_clone().map_err(|_| {
            MaintenanceError::new(
                ErrorCode::StagingInvalid,
                "staging payload handle cannot be duplicated",
            )
        })?;
        Ok(Box::new(BufReader::new(clone)))
    }

    fn inspect_target(
        &self,
        root: &RegisteredRoot,
        relative_path: &str,
    ) -> Result<Option<TargetSnapshot>> {
        let key = Self::target_key(root, relative_path);
        let retained = self
            .target_handles
            .lock()
            .map_err(|_| {
                MaintenanceError::new(ErrorCode::TransactionState, "target handle map is poisoned")
            })?
            .remove(&key);
        // Keep using the prepare-time handle when one exists. It denies write/delete sharing, so
        // the commit reinspection observes the same filesystem object without reopening a path or
        // introducing a TOCTOU gap.
        let file = match retained {
            Some(file) => file,
            None => match open_relative_file(
                root.canonical_path(),
                relative_path,
                FILE_READ_ATTRIBUTES.0 | DELETE.0,
                false,
                false,
            )? {
                Some(file) => file,
                None => return Ok(None),
            },
        };
        let snapshot = regular_file_snapshot(&file)?;
        self.target_handles
            .lock()
            .map_err(|_| {
                MaintenanceError::new(ErrorCode::TransactionState, "target handle map is poisoned")
            })?
            .insert(key, file);
        Ok(Some(snapshot))
    }

    fn prepare_target_payload(
        &self,
        root: &RegisteredRoot,
        job_id: &str,
        index: u32,
        private_payload: &Path,
        expected: &FileEntry,
    ) -> Result<()> {
        let relative = prepared_relative_path(job_id, index);
        let mut destination = open_relative_file(
            root.canonical_path(),
            &relative,
            FILE_WRITE_DATA.0 | FILE_READ_ATTRIBUTES.0 | DELETE.0,
            true,
            true,
        )?
        .ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "same-volume prepared file could not be created",
            )
        })?;
        let mut source = File::open(private_payload).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "private prepared payload cannot be opened",
            )
        })?;
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = source.read(&mut buffer).map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "private prepared payload cannot be read",
                )
            })?;
            if read == 0 {
                break;
            }
            total = total.checked_add(read as u64).ok_or_else(|| {
                MaintenanceError::new(ErrorCode::TransactionIo, "prepared payload size overflowed")
            })?;
            digest.update(&buffer[..read]);
            destination.write_all(&buffer[..read]).map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "same-volume prepared payload cannot be written",
                )
            })?;
        }
        destination.sync_all().map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "same-volume prepared payload cannot be flushed",
            )
        })?;
        if total != expected.size
            || digest.finalize().as_slice()
                != decode_lower_hex::<32>(&expected.sha256, ErrorCode::FileSetHash)?
        {
            return Err(MaintenanceError::new(
                ErrorCode::FileSetHash,
                "same-volume prepared payload failed signed hash verification",
            ));
        }
        regular_file_snapshot(&destination)?;
        Ok(())
    }

    fn rename_target_to_backup(
        &self,
        root: &RegisteredRoot,
        job_id: &str,
        index: u32,
        relative_path: &str,
        expected: TargetSnapshot,
    ) -> Result<()> {
        let key = Self::target_key(root, relative_path);
        let file = self
            .target_handles
            .lock()
            .map_err(|_| {
                MaintenanceError::new(ErrorCode::TransactionState, "target handle map is poisoned")
            })?
            .remove(&key)
            .ok_or_else(|| {
                MaintenanceError::new(
                    ErrorCode::RootIdentity,
                    "target handle was not retained from inspection",
                )
            })?;
        if regular_file_snapshot(&file)? != expected {
            return Err(MaintenanceError::new(
                ErrorCode::RootIdentity,
                "target handle changed before backup rename",
            ));
        }
        rename_handle_relative(
            root.canonical_path(),
            &file,
            &backup_relative_path(job_id, index),
            true,
        )
    }

    fn rename_prepared_to_target(
        &self,
        root: &RegisteredRoot,
        job_id: &str,
        index: u32,
        relative_path: &str,
    ) -> Result<()> {
        if self.inspect_target(root, relative_path)?.is_some() {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionConflict,
                "target exists before prepared handle rename",
            ));
        }
        let prepared = open_relative_file(
            root.canonical_path(),
            &prepared_relative_path(job_id, index),
            FILE_READ_ATTRIBUTES.0 | DELETE.0,
            false,
            false,
        )?
        .ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "prepared handle is absent during commit",
            )
        })?;
        regular_file_snapshot(&prepared)?;
        rename_handle_relative(root.canonical_path(), &prepared, relative_path, true)
    }

    fn backup_exists(&self, root: &RegisteredRoot, job_id: &str, index: u32) -> Result<bool> {
        Ok(open_relative_file(
            root.canonical_path(),
            &backup_relative_path(job_id, index),
            FILE_READ_ATTRIBUTES.0,
            false,
            false,
        )?
        .map(|file| regular_file_snapshot(&file))
        .transpose()?
        .is_some())
    }

    fn delete_target(&self, root: &RegisteredRoot, relative_path: &str) -> Result<()> {
        let key = Self::target_key(root, relative_path);
        let retained = self
            .target_handles
            .lock()
            .map_err(|_| {
                MaintenanceError::new(ErrorCode::TransactionState, "target handle map is poisoned")
            })?
            .remove(&key);
        let file = match retained {
            Some(file) => file,
            None => {
                let Some(file) = open_relative_file(
                    root.canonical_path(),
                    relative_path,
                    FILE_READ_ATTRIBUTES.0 | DELETE.0,
                    false,
                    false,
                )?
                else {
                    return Ok(());
                };
                file
            }
        };
        regular_file_snapshot(&file)?;
        delete_by_handle(&file)
    }

    fn restore_backup(
        &self,
        root: &RegisteredRoot,
        job_id: &str,
        index: u32,
        relative_path: &str,
    ) -> Result<()> {
        if self.inspect_target(root, relative_path)?.is_some() {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionConflict,
                "target exists before backup handle restore",
            ));
        }
        let backup = open_relative_file(
            root.canonical_path(),
            &backup_relative_path(job_id, index),
            FILE_READ_ATTRIBUTES.0 | DELETE.0,
            false,
            false,
        )?
        .ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "backup handle is absent during rollback",
            )
        })?;
        regular_file_snapshot(&backup)?;
        rename_handle_relative(root.canonical_path(), &backup, relative_path, true)
    }

    fn cleanup_job(
        &self,
        root: &RegisteredRoot,
        job_id: &str,
        private_job_directory: &Path,
    ) -> Result<()> {
        cleanup_reserved_job(root.canonical_path(), job_id)?;
        if private_job_directory.exists() {
            fs::remove_dir_all(private_job_directory).map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "private service job directory cannot be removed",
                )
            })?;
        }
        Ok(())
    }
}

fn open_absolute_directory(path: &Path, delete_access: bool) -> Result<File> {
    let desired = FILE_READ_ATTRIBUTES.0 | if delete_access { DELETE.0 } else { 0 };
    let file = open_absolute(
        path,
        desired,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootIdentity,
            "directory handle cannot be opened without reparse traversal",
        )
    })?;
    ensure_safe_directory(&file)?;
    Ok(file)
}

fn open_relative_file(
    root: &Path,
    relative_path: &str,
    desired_access: u32,
    create_new: bool,
    create_parents: bool,
) -> Result<Option<File>> {
    let components = relative_components(relative_path)?;
    let (leaf, parents) = components.split_last().ok_or_else(|| {
        MaintenanceError::new(ErrorCode::FileSetPath, "relative file path is empty")
    })?;
    let Some((locks, parent_path)) = lock_parent_chain(root, parents, create_parents)? else {
        return Ok(None);
    };
    let leaf_path = parent_path.join(leaf);
    let disposition = if create_new {
        CREATE_NEW
    } else {
        OPEN_EXISTING
    };
    let opened = open_absolute(
        &leaf_path,
        desired_access,
        FILE_SHARE_READ,
        disposition,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
    );
    let file = match opened {
        Ok(file) => file,
        Err(error) if !create_new && is_not_found(&error) => return Ok(None),
        Err(_) => {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionIo,
                "file handle cannot be opened under the locked root",
            ));
        }
    };
    let _parent_locks = locks;
    ensure_safe_regular_file(&file)?;
    Ok(Some(file))
}

fn lock_parent_chain(
    root: &Path,
    parents: &[String],
    create_missing: bool,
) -> Result<Option<(Vec<File>, PathBuf)>> {
    let mut locks = vec![open_absolute_directory(root, false)?];
    let mut current = root.to_path_buf();
    for component in parents {
        current.push(component);
        let opened = open_absolute(
            &current,
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        );
        let directory = match opened {
            Ok(directory) => directory,
            Err(error) if create_missing && is_not_found(&error) => {
                fs::create_dir(&current).map_err(|_| {
                    MaintenanceError::new(
                        ErrorCode::TransactionIo,
                        "target parent directory cannot be created",
                    )
                })?;
                open_absolute(
                    &current,
                    FILE_READ_ATTRIBUTES.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                )
                .map_err(|_| {
                    MaintenanceError::new(
                        ErrorCode::RootIdentity,
                        "created target parent cannot be opened safely",
                    )
                })?
            }
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(_) => {
                return Err(MaintenanceError::new(
                    ErrorCode::RootIdentity,
                    "target parent cannot be opened safely",
                ));
            }
        };
        ensure_safe_directory(&directory)?;
        locks.push(directory);
    }
    Ok(Some((locks, current)))
}

fn open_absolute(
    path: &Path,
    desired_access: u32,
    share_mode: windows::Win32::Storage::FileSystem::FILE_SHARE_MODE,
    disposition: windows::Win32::Storage::FileSystem::FILE_CREATION_DISPOSITION,
    flags: windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
) -> std::result::Result<File, windows::core::Error> {
    let path = wide_null(path.as_os_str().to_string_lossy().as_ref());
    // SAFETY: the path is NUL-terminated. A successful, uniquely owned HANDLE is immediately
    // transferred to `File`, which closes it exactly once.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            desired_access,
            share_mode,
            None,
            disposition,
            flags,
            None,
        )
    }?;
    // SAFETY: CreateFileW returned a valid owned kernel handle and ownership moves to File.
    Ok(unsafe { File::from_raw_handle(handle.0) })
}

fn raw_handle(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle())
}

fn query_handle<T: Copy>(
    file: &File,
    class: windows::Win32::Storage::FileSystem::FILE_INFO_BY_HANDLE_CLASS,
) -> Result<T> {
    let mut output = MaybeUninit::<T>::uninit();
    // SAFETY: `output` is correctly sized/aligned and initialized in full by the selected fixed-
    // size information class on success.
    unsafe {
        GetFileInformationByHandleEx(
            raw_handle(file),
            class,
            output.as_mut_ptr().cast(),
            u32::try_from(size_of::<T>()).unwrap_or(u32::MAX),
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootIdentity,
            "filesystem identity information cannot be queried",
        )
    })?;
    // SAFETY: the successful Win32 call initialized the full fixed-size value.
    Ok(unsafe { output.assume_init() })
}

fn ensure_not_reparse(file: &File) -> Result<()> {
    let attributes: FILE_ATTRIBUTE_TAG_INFO = query_handle(file, FileAttributeTagInfo)?;
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(MaintenanceError::new(
            ErrorCode::RootIdentity,
            "opened filesystem object is a reparse point",
        ));
    }
    Ok(())
}

fn ensure_safe_directory(file: &File) -> Result<()> {
    ensure_not_reparse(file)?;
    let standard: FILE_STANDARD_INFO = query_handle(file, FileStandardInfo)?;
    if !standard.Directory || standard.DeletePending {
        return Err(MaintenanceError::new(
            ErrorCode::RootIdentity,
            "opened directory handle is not a stable directory",
        ));
    }
    Ok(())
}

fn ensure_safe_regular_file(file: &File) -> Result<()> {
    ensure_not_reparse(file)?;
    let standard: FILE_STANDARD_INFO = query_handle(file, FileStandardInfo)?;
    if standard.Directory || standard.DeletePending || standard.NumberOfLinks != 1 {
        return Err(MaintenanceError::new(
            ErrorCode::RootIdentity,
            "opened payload is not a stable single-link regular file",
        ));
    }
    Ok(())
}

fn directory_identity(file: &File) -> Result<DirectoryIdentity> {
    ensure_safe_directory(file)?;
    let id: FILE_ID_INFO = query_handle(file, FileIdInfo)?;
    Ok(DirectoryIdentity {
        volume_serial: id.VolumeSerialNumber,
        file_id: id.FileId.Identifier,
    })
}

fn regular_file_snapshot(file: &File) -> Result<TargetSnapshot> {
    ensure_safe_regular_file(file)?;
    let id: FILE_ID_INFO = query_handle(file, FileIdInfo)?;
    let standard: FILE_STANDARD_INFO = query_handle(file, FileStandardInfo)?;
    let basic: FILE_BASIC_INFO = query_handle(file, FileBasicInfo)?;
    Ok(TargetSnapshot {
        identity: DirectoryIdentity {
            volume_serial: id.VolumeSerialNumber,
            file_id: id.FileId.Identifier,
        },
        last_write_time: u64::try_from(basic.LastWriteTime).unwrap_or_default(),
        size: u64::try_from(standard.EndOfFile).unwrap_or_default(),
    })
}

fn final_path_owned(file: &File) -> Result<PathBuf> {
    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: the buffer is writable and the handle remains valid through the synchronous call.
    let length =
        unsafe { GetFinalPathNameByHandleW(raw_handle(file), &mut buffer, Default::default()) };
    let length = usize::try_from(length).map_err(|_| {
        MaintenanceError::new(ErrorCode::RootIdentity, "final path length overflowed")
    })?;
    if length == 0 || length >= buffer.len() {
        return Err(MaintenanceError::new(
            ErrorCode::RootIdentity,
            "canonical handle path cannot be obtained",
        ));
    }
    let text = String::from_utf16(&buffer[..length]).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootIdentity,
            "canonical handle path is invalid Unicode",
        )
    })?;
    Ok(PathBuf::from(text))
}

fn rename_handle_relative(
    root: &Path,
    file: &File,
    destination: &str,
    create_parents: bool,
) -> Result<()> {
    let components = relative_components(destination)?;
    let (leaf, parents) = components.split_last().ok_or_else(|| {
        MaintenanceError::new(ErrorCode::FileSetPath, "rename destination is empty")
    })?;
    let Some((locks, _parent_path)) = lock_parent_chain(root, parents, create_parents)? else {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionIo,
            "rename destination parent is unavailable",
        ));
    };
    let parent = locks.last().ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::TransactionState,
            "rename parent handle is unavailable",
        )
    })?;
    let destination_path = final_path_owned(parent)?.join(leaf);
    let name: Vec<u16> = destination_path.as_os_str().encode_wide().collect();
    let header = offset_of!(FILE_RENAME_INFO, FileName);
    let byte_length = name.len().checked_mul(size_of::<u16>()).ok_or_else(|| {
        MaintenanceError::new(ErrorCode::TransactionState, "rename path size overflowed")
    })?;
    // Some supported Windows builds consume the absolute legacy FileRenameInfo name as a
    // NUL-terminated UTF-16 string even though FileNameLength excludes the terminator. Keep the
    // documented byte length and provide one explicit zero word inside the submitted buffer.
    let total = header
        .checked_add(byte_length)
        .and_then(|bytes| bytes.checked_add(size_of::<u16>()))
        .ok_or_else(|| {
            MaintenanceError::new(ErrorCode::TransactionState, "rename buffer size overflowed")
        })?;
    let words = total
        .checked_add(size_of::<usize>() - 1)
        .map(|bytes| bytes / size_of::<usize>())
        .ok_or_else(|| {
            MaintenanceError::new(ErrorCode::TransactionState, "rename buffer size overflowed")
        })?;
    let byte_length_u32 = u32::try_from(byte_length).map_err(|_| {
        MaintenanceError::new(ErrorCode::TransactionState, "rename path size overflowed")
    })?;
    let total_u32 = u32::try_from(total).map_err(|_| {
        MaintenanceError::new(ErrorCode::TransactionState, "rename buffer size overflowed")
    })?;
    let mut storage = vec![0_usize; words];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `storage` is aligned for FILE_RENAME_INFO and has enough initialized backing bytes
    // for the fixed header, UTF-16 absolute destination, and an explicit trailing zero word. All
    // parent locks and storage remain live through SetFileInformationByHandle.
    unsafe {
        ptr::addr_of_mut!((*info).Anonymous).write(FILE_RENAME_INFO_0 { Flags: 0 });
        ptr::addr_of_mut!((*info).RootDirectory).write(HANDLE::default());
        ptr::addr_of_mut!((*info).FileNameLength).write(byte_length_u32);
        ptr::copy_nonoverlapping(
            name.as_ptr().cast::<u8>(),
            storage.as_mut_ptr().cast::<u8>().add(header),
            byte_length,
        );
        SetFileInformationByHandle(
            raw_handle(file),
            FileRenameInfo,
            storage.as_ptr().cast(),
            total_u32,
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "handle-based atomic rename failed",
        )
    })
}

fn delete_by_handle(file: &File) -> Result<()> {
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
            FILE_DISPOSITION_FLAG_DELETE.0 | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE.0,
        ),
    };
    // SAFETY: `disposition` has the exact fixed layout for FileDispositionInfoEx and both it and
    // the file handle remain valid for the synchronous call.
    unsafe {
        SetFileInformationByHandle(
            raw_handle(file),
            FileDispositionInfoEx,
            ptr::from_ref(&disposition).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO_EX>()).unwrap_or(u32::MAX),
        )
    }
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "handle-based file deletion failed",
        )
    })
}

fn cleanup_reserved_job(root: &Path, job_id: &str) -> Result<()> {
    for leaf in ["prepared", "backup"] {
        let relative = format!(".7launcher-maintenance/jobs/{job_id}/{leaf}");
        let directory_path = root.join(relative.replace('/', "\\"));
        let entries = match fs::read_dir(&directory_path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "reserved job directory cannot be enumerated",
                ));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "reserved job entry cannot be enumerated",
                )
            })?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(MaintenanceError::new(
                    ErrorCode::RootIdentity,
                    "reserved job contains an unexpected entry",
                ));
            }
            let item_relative = format!("{relative}/{name}");
            let Some(file) = open_relative_file(
                root,
                &item_relative,
                FILE_READ_ATTRIBUTES.0 | DELETE.0,
                false,
                false,
            )?
            else {
                continue;
            };
            regular_file_snapshot(&file)?;
            delete_by_handle(&file)?;
        }
        fs::remove_dir(&directory_path).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "reserved job leaf cannot be removed",
            )
        })?;
    }
    for relative in [
        format!(".7launcher-maintenance/jobs/{job_id}"),
        ".7launcher-maintenance/jobs".to_owned(),
        ".7launcher-maintenance".to_owned(),
    ] {
        let path = root.join(relative.replace('/', "\\"));
        match fs::remove_dir(path) {
            Ok(()) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(_) => {
                return Err(MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "reserved job parent cannot be removed",
                ));
            }
        }
    }
    Ok(())
}

fn relative_components(relative_path: &str) -> Result<Vec<String>> {
    if relative_path.is_empty()
        || relative_path.contains('\\')
        || relative_path.starts_with('/')
        || relative_path.ends_with('/')
    {
        return Err(MaintenanceError::new(
            ErrorCode::FileSetPath,
            "relative path is not normalized",
        ));
    }
    let mut components = Vec::new();
    for component in Path::new(relative_path).components() {
        let Component::Normal(component) = component else {
            return Err(MaintenanceError::new(
                ErrorCode::FileSetPath,
                "relative path contains traversal",
            ));
        };
        let component = component.to_str().ok_or_else(|| {
            MaintenanceError::new(ErrorCode::FileSetPath, "relative path is not Unicode")
        })?;
        if component.is_empty() || component == "." || component == ".." {
            return Err(MaintenanceError::new(
                ErrorCode::FileSetPath,
                "relative path contains an empty or dot component",
            ));
        }
        components.push(component.to_owned());
    }
    Ok(components)
}

fn prepared_relative_path(job_id: &str, index: u32) -> String {
    format!(".7launcher-maintenance/jobs/{job_id}/prepared/{index}")
}

fn backup_relative_path(job_id: &str, index: u32) -> String {
    format!(".7launcher-maintenance/jobs/{job_id}/backup/{index}")
}

fn is_not_found(error: &windows::core::Error) -> bool {
    error.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0)
        || error.code() == HRESULT::from_win32(ERROR_PATH_NOT_FOUND.0)
}

fn read_manifest_as_caller(
    pipe: HANDLE,
    manifest_path: &Path,
    maximum: usize,
) -> Result<(CallerIdentity, Vec<u8>)> {
    let guard = ImpersonationGuard::begin(pipe)?;
    let identity = current_thread_caller_identity()?;
    let file = open_absolute(
        manifest_path,
        FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "signed manifest cannot be opened as the pipe caller",
        )
    })?;
    ensure_safe_regular_file(&file)?;
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| {
            MaintenanceError::new(
                ErrorCode::StagingInvalid,
                "signed manifest cannot be read as the pipe caller",
            )
        })?;
    if bytes.len() > maximum {
        return Err(MaintenanceError::new(
            ErrorCode::ManifestTooLarge,
            "signed manifest exceeds the configured bound",
        ));
    }
    guard.revert()?;
    Ok((identity, bytes))
}

fn preopen_staging_as_caller(
    pipe: HANDLE,
    staging_root: &Path,
    entries: &[FileEntry],
) -> Result<(CallerIdentity, WindowsTransactionPlatform)> {
    let guard = ImpersonationGuard::begin(pipe)?;
    let identity = current_thread_caller_identity()?;
    let staging_handle = open_absolute_directory(staging_root, false).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::StagingInvalid,
            "staging root cannot be opened as the pipe caller",
        )
    })?;
    let canonical_staging = final_path_owned(&staging_handle)?;
    let mut files = BTreeMap::new();
    for entry in entries {
        let file = open_relative_file(
            &canonical_staging,
            &entry.path,
            FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0,
            false,
            false,
        )?
        .ok_or_else(|| {
            MaintenanceError::new(
                ErrorCode::StagingInvalid,
                "signed staging payload is absent",
            )
        })?;
        regular_file_snapshot(&file)?;
        files.insert(entry.path.clone(), file);
    }
    guard.revert()?;
    Ok((
        identity,
        WindowsTransactionPlatform::with_staging_files(files),
    ))
}

fn registered_root_as_caller(
    pipe: HANDLE,
    root_id: &str,
    product_id: &str,
    root_kind: crate::protocol::RootKind,
    path: &Path,
) -> Result<(CallerIdentity, RegisteredRoot)> {
    let guard = ImpersonationGuard::begin(pipe)?;
    let identity = current_thread_caller_identity()?;
    if !identity.is_elevated_administrator() {
        return Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "root registration requires an elevated administrator token",
        ));
    }
    let access = if root_is_shared_library(root_kind) {
        FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | WRITE_DAC.0
    } else {
        FILE_READ_ATTRIBUTES.0
    };
    let handle = open_absolute(
        path,
        access,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "elevated setup cannot open the registered root",
        )
    })?;
    ensure_safe_directory(&handle)?;
    if root_is_shared_library(root_kind) {
        grant_shared_library_user_access(&handle)?;
    }
    let canonical = final_path_owned(&handle)?;
    let canonical = canonical.to_str().ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::RootInvalid,
            "registered root path is not Unicode",
        )
    })?;
    let root = RegisteredRoot::from_canonical_identity(
        root_id,
        product_id,
        root_kind,
        canonical,
        directory_identity(&handle)?,
        identity.sid(),
    )?;
    guard.revert()?;
    Ok((identity, root))
}

const ROOT_MODIFY_ACCESS_MASK: u32 =
    FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | DELETE.0;
const BUILTIN_USERS_SID: &str = "S-1-5-32-545";

const fn root_is_shared_library(root_kind: crate::protocol::RootKind) -> bool {
    matches!(root_kind, crate::protocol::RootKind::Library)
}

struct LocalSid(PSID);

impl LocalSid {
    fn raw(&mut self) -> PSID {
        self.0
    }
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        // SAFETY: ConvertStringSidToSidW allocated this pointer with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
    }
}

fn string_sid(value: &str) -> Result<LocalSid> {
    let value = wide_null(value);
    let mut sid = PSID::default();
    // SAFETY: the input is NUL-terminated and `sid` is a valid output pointer.
    unsafe { ConvertStringSidToSidW(PCWSTR(value.as_ptr()), &mut sid) }.map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "registered root owner SID cannot be parsed",
        )
    })?;
    if sid.0.is_null() {
        return Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "registered root owner SID is empty",
        ));
    }
    Ok(LocalSid(sid))
}

fn root_modify_access_entry(sid: PSID, trustee_type: TRUSTEE_TYPE) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: ROOT_MODIFY_ACCESS_MASK,
        grfAccessMode: SET_ACCESS,
        grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: trustee_type,
            ptstrName: PWSTR(sid.0.cast()),
        },
    }
}

fn merge_root_access_entries(root: &File, entries: &[EXPLICIT_ACCESS_W]) -> Result<()> {
    let mut old_acl: *mut ACL = ptr::null_mut();
    let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the root handle has READ_CONTROL and all out pointers are valid. The returned
    // descriptor owns the old ACL storage until it is freed below.
    let result = unsafe {
        GetSecurityInfo(
            raw_handle(root),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old_acl),
            None,
            Some(&mut security_descriptor),
        )
    };
    if result.0 != 0 || security_descriptor.0.is_null() {
        return Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "registered root DACL cannot be read",
        ));
    }
    let descriptor = LocalSecurityDescriptor(security_descriptor);

    let mut new_acl: *mut ACL = ptr::null_mut();
    // SAFETY: entries, their SID pointers, and the old ACL remain live through this merge.
    let result = unsafe { SetEntriesInAclW(Some(entries), Some(old_acl), &mut new_acl) };
    if result.0 != 0 || new_acl.is_null() {
        return Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "maintenance service root ACE cannot be constructed",
        ));
    }
    // SAFETY: the root handle has WRITE_DAC and `new_acl` is a complete ACL returned above.
    let set_result = unsafe {
        SetSecurityInfo(
            raw_handle(root),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_acl),
            None,
        )
    };
    // SAFETY: SetEntriesInAclW allocated `new_acl` with LocalAlloc; it is freed exactly once.
    let _ = unsafe { LocalFree(Some(HLOCAL(new_acl.cast()))) };
    drop(descriptor);
    if set_result.0 != 0 {
        return Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "maintenance service root ACE cannot be applied",
        ));
    }
    Ok(())
}

fn grant_shared_library_user_access(root: &File) -> Result<()> {
    let mut users_sid = string_sid(BUILTIN_USERS_SID)?;
    merge_root_access_entries(
        root,
        &[root_modify_access_entry(
            users_sid.raw(),
            TRUSTEE_IS_WELL_KNOWN_GROUP,
        )],
    )
}

const REGISTRY_TRANSACTION_KIND: &str = "7launcher-registry-transaction-v1";
const REGISTRY_TRANSACTION_SCHEMA: u64 = 1;
const MAX_REGISTRY_VALUE_BYTES: usize = 64 * 1024;
const MAX_REGISTRY_SNAPSHOT_BYTES: usize = 1024 * 1024;
const MAX_REGISTRY_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum RegistryTransactionPhase {
    Prepared,
    Committed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredRegistryValue {
    data: Vec<u8>,
    value_type: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryTransactionValue {
    name: String,
    previous: Option<StoredRegistryValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryTransactionJournal {
    kind: String,
    phase: RegistryTransactionPhase,
    schema: u64,
    scope_id: String,
    subkey: String,
    values: Vec<RegistryTransactionValue>,
    view: RegistryView,
}

fn registry_view_access(view: RegistryView) -> u32 {
    match view {
        RegistryView::Registry32 => KEY_WOW64_32KEY.0,
        RegistryView::Registry64 => KEY_WOW64_64KEY.0,
    }
}

fn create_registry_scope_key(scope: &RegisteredRegistryScope) -> Result<RegistryKey> {
    let mut components = scope.subkey().split('\\').peekable();
    if components.next() != Some("SOFTWARE") {
        return Err(MaintenanceError::new(
            ErrorCode::RegistryScopeInvalid,
            "registry scope is outside HKLM SOFTWARE",
        ));
    }

    let software = wide_null("SOFTWARE");
    let mut parent = HKEY::default();
    let parent_access = REG_SAM_FLAGS(KEY_CREATE_SUB_KEY.0 | registry_view_access(scope.view()));
    // SAFETY: this runs only after caller authorization and RevertToSelf. The predefined HKLM
    // handle and NUL-terminated literal are valid for the synchronous call. The returned handle
    // is owned by RegistryKey.
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(software.as_ptr()),
            None,
            parent_access,
            &mut parent,
        )
    };
    if result.0 != 0 {
        return Err(MaintenanceError::with_platform_status(
            ErrorCode::RegistryScopeUnauthorized,
            "LocalSystem cannot open HKLM SOFTWARE for bounded scope creation",
            result.0,
        ));
    }
    let mut parent = RegistryKey::new(parent)?;

    while let Some(component) = components.next() {
        let final_component = components.peek().is_none();
        let access = if final_component {
            KEY_QUERY_VALUE.0 | KEY_SET_VALUE.0
        } else {
            KEY_CREATE_SUB_KEY.0
        };
        let access = REG_SAM_FLAGS(access | registry_view_access(scope.view()));
        let component = wide_null(component);
        let mut child = HKEY::default();
        // SAFETY: every component comes from the canonical, bounded registry-subkey validator.
        // Only one exact child is created per call. Intermediate handles receive CreateSubKey;
        // the final handle receives only the QueryValue + SetValue runtime rights. Default ACL
        // inheritance is preserved and no caller-supplied DACL or service-specific ACE is used.
        let result = unsafe {
            RegCreateKeyExW(
                parent.raw(),
                PCWSTR(component.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                access,
                None,
                &mut child,
                None,
            )
        };
        if result.0 != 0 {
            return Err(MaintenanceError::with_platform_status(
                ErrorCode::RegistryScopeUnauthorized,
                "LocalSystem cannot create or open a bounded HKLM registry-scope component",
                result.0,
            ));
        }
        let child = RegistryKey::new(child)?;
        if final_component {
            return Ok(child);
        }
        parent = child;
    }

    Err(MaintenanceError::new(
        ErrorCode::RegistryScopeInvalid,
        "registry scope has no child below HKLM SOFTWARE",
    ))
}

fn open_registry_scope_key(scope: &RegisteredRegistryScope) -> Result<RegistryKey> {
    let subkey = wide_null(scope.subkey());
    let access =
        REG_SAM_FLAGS(KEY_QUERY_VALUE.0 | KEY_SET_VALUE.0 | registry_view_access(scope.view()));
    let mut key = HKEY::default();
    // SAFETY: the HKLM pseudo-handle and NUL-terminated subkey remain live for the synchronous
    // call. The returned key is owned by RegistryKey.
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            None,
            access,
            &mut key,
        )
    };
    if result.0 != 0 {
        return Err(MaintenanceError::with_platform_status(
            ErrorCode::RegistryScopeInvalid,
            "registered HKLM scope cannot be opened by the service",
            result.0,
        ));
    }
    RegistryKey::new(key)
}

fn registered_registry_scope_as_caller(
    pipe: HANDLE,
    scope_id: &str,
    product_id: &str,
    view: RegistryView,
    subkey: &str,
    allowed_values: Vec<crate::AllowedRegistryValue>,
) -> Result<(CallerIdentity, RegisteredRegistryScope)> {
    let guard = ImpersonationGuard::begin(pipe)?;
    let identity = current_thread_caller_identity()?;
    if !identity.is_elevated_administrator() {
        return Err(MaintenanceError::new(
            ErrorCode::RegistryScopeUnauthorized,
            "registry-scope registration requires an elevated administrator token",
        ));
    }
    let scope = RegisteredRegistryScope::new(
        scope_id,
        product_id,
        view,
        subkey,
        allowed_values,
        identity.sid(),
    )?;
    guard.revert()?;
    drop(create_registry_scope_key(&scope)?);
    // Registration succeeds only after LocalSystem can reopen the exact key with the runtime
    // QueryValue + SetValue mask. The service never installs or broadens a registry DACL.
    drop(open_registry_scope_key(&scope)?);
    Ok((identity, scope))
}

fn registry_value_snapshot(key: &RegistryKey, name: &str) -> Result<Option<StoredRegistryValue>> {
    let name = wide_null(name);
    let mut value_type = REG_VALUE_TYPE::default();
    let mut size = 0_u32;
    // SAFETY: the registry key and NUL-terminated value name remain live; size/type are writable.
    let result = unsafe {
        RegQueryValueExW(
            key.raw(),
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut value_type),
            None,
            Some(&mut size),
        )
    };
    if result.0 == ERROR_FILE_NOT_FOUND.0 {
        return Ok(None);
    }
    if result.0 != 0 {
        return Err(MaintenanceError::new(
            ErrorCode::RegistryIo,
            "registry value metadata cannot be queried",
        ));
    }
    let size = usize::try_from(size).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RegistrySetLimit,
            "registry value size overflowed",
        )
    })?;
    if size > MAX_REGISTRY_VALUE_BYTES {
        return Err(MaintenanceError::new(
            ErrorCode::RegistrySetLimit,
            "existing registry value exceeds the rollback bound",
        ));
    }
    let mut data = vec![0_u8; size];
    let mut actual_size = u32::try_from(size).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RegistrySetLimit,
            "registry value size overflowed",
        )
    })?;
    // SAFETY: the optional data pointer refers to exactly actual_size writable bytes. The key and
    // value name remain live and the call updates only the supplied buffers.
    let result = unsafe {
        RegQueryValueExW(
            key.raw(),
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut value_type),
            if data.is_empty() {
                None
            } else {
                Some(data.as_mut_ptr())
            },
            Some(&mut actual_size),
        )
    };
    if result.0 != 0 {
        return Err(MaintenanceError::new(
            ErrorCode::RegistryIo,
            "registry value changed while it was being snapshotted",
        ));
    }
    let actual_size = usize::try_from(actual_size).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RegistrySetLimit,
            "registry value size overflowed",
        )
    })?;
    if actual_size > data.len() {
        return Err(MaintenanceError::new(
            ErrorCode::RegistryIo,
            "registry value expanded while it was being snapshotted",
        ));
    }
    data.truncate(actual_size);
    Ok(Some(StoredRegistryValue {
        data,
        value_type: value_type.0,
    }))
}

fn encoded_registry_value(value: &RegistryValue) -> Result<(REG_VALUE_TYPE, Vec<u8>)> {
    match value {
        RegistryValue::String { data, .. } => {
            let mut encoded = Vec::with_capacity((data.encode_utf16().count() + 1) * 2);
            for word in data.encode_utf16().chain(std::iter::once(0)) {
                encoded.extend_from_slice(&word.to_le_bytes());
            }
            Ok((REG_SZ, encoded))
        }
        RegistryValue::Dword { data, .. } => Ok((REG_DWORD, data.to_le_bytes().to_vec())),
        RegistryValue::Binary { data, .. } => Ok((
            REG_BINARY,
            crate::registry_set::decode_registry_binary(data)?,
        )),
    }
}

fn set_registry_value(key: &RegistryKey, value: &RegistryValue) -> Result<()> {
    let name = wide_null(value.name());
    let (value_type, data) = encoded_registry_value(value)?;
    // SAFETY: the key, NUL-terminated name, and exact immutable data slice remain live for the
    // synchronous call. The type matches the bounded RegistrySet variant.
    let result = unsafe {
        RegSetValueExW(
            key.raw(),
            PCWSTR(name.as_ptr()),
            None,
            value_type,
            Some(&data),
        )
    };
    if result.0 == 0 {
        Ok(())
    } else {
        Err(MaintenanceError::new(
            ErrorCode::RegistryIo,
            "registry value cannot be written",
        ))
    }
}

fn restore_registry_values(key: &RegistryKey, values: &[RegistryTransactionValue]) -> Result<()> {
    for value in values.iter().rev() {
        let name = wide_null(&value.name);
        let result = if let Some(previous) = &value.previous {
            // SAFETY: the key, name, and snapshotted bytes remain live. The original Win32 type is
            // restored verbatim from the protected transaction journal.
            unsafe {
                RegSetValueExW(
                    key.raw(),
                    PCWSTR(name.as_ptr()),
                    None,
                    REG_VALUE_TYPE(previous.value_type),
                    Some(&previous.data),
                )
            }
        } else {
            // SAFETY: the key and NUL-terminated name remain live for this synchronous delete.
            let result = unsafe { RegDeleteValueW(key.raw(), PCWSTR(name.as_ptr())) };
            if result.0 == ERROR_FILE_NOT_FOUND.0 {
                continue;
            }
            result
        };
        if result.0 != 0 {
            return Err(MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "registry transaction rollback did not complete",
            ));
        }
    }
    Ok(())
}

fn create_registry_transaction(
    scope: &RegisteredRegistryScope,
    values: &[RegistryValue],
) -> Result<(RegistryKey, RegistryTransactionJournal)> {
    let key = open_registry_scope_key(scope)?;
    let mut snapshots = Vec::with_capacity(values.len());
    let mut total_size = 0_usize;
    for value in values {
        let previous = registry_value_snapshot(&key, value.name())?;
        if let Some(previous) = &previous {
            total_size = total_size.checked_add(previous.data.len()).ok_or_else(|| {
                MaintenanceError::new(
                    ErrorCode::RegistrySetLimit,
                    "registry rollback snapshot size overflowed",
                )
            })?;
            if total_size > MAX_REGISTRY_SNAPSHOT_BYTES {
                return Err(MaintenanceError::new(
                    ErrorCode::RegistrySetLimit,
                    "registry rollback snapshots exceed the bound",
                ));
            }
        }
        snapshots.push(RegistryTransactionValue {
            name: value.name().to_owned(),
            previous,
        });
    }
    Ok((
        key,
        RegistryTransactionJournal {
            kind: REGISTRY_TRANSACTION_KIND.to_owned(),
            phase: RegistryTransactionPhase::Prepared,
            schema: REGISTRY_TRANSACTION_SCHEMA,
            scope_id: scope.scope_id().to_owned(),
            subkey: scope.subkey().to_owned(),
            values: snapshots,
            view: scope.view(),
        },
    ))
}

fn validate_registry_transaction(
    journal: &RegistryTransactionJournal,
    scopes: &RegistryScopeRegistry,
) -> Result<RegisteredRegistryScope> {
    if journal.kind != REGISTRY_TRANSACTION_KIND
        || journal.schema != REGISTRY_TRANSACTION_SCHEMA
        || journal.values.is_empty()
        || journal.values.len() > crate::MAX_REGISTRY_ENTRIES
    {
        return Err(MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "registry transaction journal schema or count is invalid",
        ));
    }
    validate_registry_subkey(&journal.subkey)?;
    let scope = scopes.resolve_registered(&journal.scope_id)?.clone();
    if scope.subkey() != journal.subkey || scope.view() != journal.view {
        return Err(MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "registry transaction no longer matches its registered scope",
        ));
    }
    let mut total_size = 0_usize;
    for value in &journal.values {
        if !scope
            .allowed_values()
            .iter()
            .any(|allowed| allowed.name.eq_ignore_ascii_case(&value.name))
        {
            return Err(MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "registry transaction contains an unregistered value",
            ));
        }
        if let Some(previous) = &value.previous {
            total_size = total_size.checked_add(previous.data.len()).ok_or_else(|| {
                MaintenanceError::new(
                    ErrorCode::RegistrySetLimit,
                    "registry rollback snapshot size overflowed",
                )
            })?;
            if previous.data.len() > MAX_REGISTRY_VALUE_BYTES
                || total_size > MAX_REGISTRY_SNAPSHOT_BYTES
            {
                return Err(MaintenanceError::new(
                    ErrorCode::RegistrySetLimit,
                    "registry rollback snapshots exceed the bound",
                ));
            }
        }
    }
    Ok(scope)
}

fn write_registry_transaction(path: &Path, journal: &RegistryTransactionJournal) -> Result<()> {
    let value = serde_json::to_value(journal).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "registry transaction journal cannot be encoded",
        )
    })?;
    let bytes = canonical_json(&value)?;
    if bytes.len() > MAX_REGISTRY_TRANSACTION_BYTES {
        return Err(MaintenanceError::new(
            ErrorCode::RegistrySetLimit,
            "registry transaction journal exceeds the bound",
        ));
    }
    replace_service_file(path, &bytes)
}

fn remove_registry_transaction(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "registry transaction journal cannot be removed",
            )
        })?;
    }
    Ok(())
}

fn recover_registry_transaction(path: &Path, scopes: &RegistryScopeRegistry) -> Result<()> {
    recover_service_file_replacement(path)?;
    if !path.exists() {
        return Ok(());
    }
    let bytes = read_bounded_file(path, MAX_REGISTRY_TRANSACTION_BYTES).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "registry transaction journal cannot be read",
        )
    })?;
    let journal: RegistryTransactionJournal =
        parse_canonical(&bytes, MAX_REGISTRY_TRANSACTION_BYTES)?;
    let scope = validate_registry_transaction(&journal, scopes)?;
    if journal.phase == RegistryTransactionPhase::Prepared {
        let key = open_registry_scope_key(&scope)?;
        restore_registry_values(&key, &journal.values)?;
    }
    remove_registry_transaction(path)
}

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static COMMITTING: AtomicBool = AtomicBool::new(false);
static STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static STOP_EVENT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static CURRENT_PIPE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

const GENERATION_REGISTRY_KIND: &str = "7launcher-maintenance-generations-v1";
const GENERATION_REGISTRY_SCHEMA: u64 = 1;
const MAX_GENERATION_REGISTRY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredGeneration {
    digest: String,
    generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationRegistryDocument {
    kind: String,
    roots: BTreeMap<String, StoredGeneration>,
    schema: u64,
}

#[derive(Clone, Default)]
struct GenerationRegistry {
    roots: BTreeMap<String, StoredGeneration>,
}

impl GenerationRegistry {
    fn load(path: &Path) -> Result<Self> {
        recover_service_file_replacement(path)?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = read_bounded_file(path, MAX_GENERATION_REGISTRY_BYTES).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionState,
                "generation registry cannot be read",
            )
        })?;
        let document: GenerationRegistryDocument =
            parse_canonical(&bytes, MAX_GENERATION_REGISTRY_BYTES)?;
        if document.kind != GENERATION_REGISTRY_KIND
            || document.schema != GENERATION_REGISTRY_SCHEMA
        {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionState,
                "generation registry schema is unsupported",
            ));
        }
        for (root_id, record) in &document.roots {
            if !valid_identifier(root_id)
                || record.generation == 0
                || decode_lower_hex::<32>(&record.digest, ErrorCode::GenerationConflict).is_err()
            {
                return Err(MaintenanceError::new(
                    ErrorCode::TransactionState,
                    "generation registry contains an invalid record",
                ));
            }
        }
        Ok(Self {
            roots: document.roots,
        })
    }

    fn previous(&self, root_id: &str) -> Result<Option<GenerationRecord>> {
        self.roots
            .get(root_id)
            .map(|record| {
                Ok(GenerationRecord {
                    generation: record.generation,
                    digest: decode_lower_hex::<32>(&record.digest, ErrorCode::GenerationConflict)?,
                })
            })
            .transpose()
    }

    fn accept(&mut self, root_id: &str, record: GenerationRecord) -> Result<()> {
        if !valid_identifier(root_id) || record.generation == 0 {
            return Err(MaintenanceError::new(
                ErrorCode::GenerationConflict,
                "accepted generation metadata is invalid",
            ));
        }
        if let Some(previous) = self.previous(root_id)?
            && (record.generation < previous.generation
                || (record.generation == previous.generation && record.digest != previous.digest))
        {
            return Err(MaintenanceError::new(
                ErrorCode::GenerationConflict,
                "accepted generation would roll back or conflict",
            ));
        }
        self.roots.insert(
            root_id.to_owned(),
            StoredGeneration {
                digest: encode_lower_hex(&record.digest),
                generation: record.generation,
            },
        );
        Ok(())
    }

    fn save(&self, path: &Path) -> Result<()> {
        let document = GenerationRegistryDocument {
            kind: GENERATION_REGISTRY_KIND.to_owned(),
            roots: self.roots.clone(),
            schema: GENERATION_REGISTRY_SCHEMA,
        };
        let value = serde_json::to_value(document).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionState,
                "generation registry cannot be encoded",
            )
        })?;
        let bytes = canonical_json(&value)?;
        if bytes.len() > MAX_GENERATION_REGISTRY_BYTES {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionState,
                "generation registry exceeds the bound",
            ));
        }
        replace_service_file(path, &bytes)
    }
}

enum ActiveJobState {
    Prepared(Box<PreparedJob>),
    Committing(Receiver<Result<CommitResult>>),
    Completed {
        cleanup_pending: bool,
        error: Option<ErrorCode>,
        generation: Option<u64>,
        state: &'static str,
    },
}

struct ActiveJob {
    job_id: String,
    owner_sid: String,
    state: ActiveJobState,
}

struct ServiceState {
    data_directory: PathBuf,
    generation_path: PathBuf,
    generations: GenerationRegistry,
    keyring_path: PathBuf,
    registry_path: PathBuf,
    roots: RootRegistry,
    registry_generation_path: PathBuf,
    registry_generations: GenerationRegistry,
    registry_scope_path: PathBuf,
    registry_scopes: RegistryScopeRegistry,
    registry_transaction_path: PathBuf,
    active_job: Option<ActiveJob>,
}

/// Enters the Windows Service Control Manager dispatcher. The service binary has no shell, network,
/// or generic command execution surface; all work arrives as a bounded typed IPC v1 request.
pub fn run_service_dispatcher() -> Result<()> {
    let mut service_name = wide_null(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(service_name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR::null(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: the dispatch table and service-name buffer remain live until the blocking dispatcher
    // returns, and the table has the required null terminator entry.
    unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }.map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "service control dispatcher could not be entered",
        )
    })
}

unsafe extern "system" fn service_main(_argument_count: u32, _arguments: *mut PWSTR) {
    let service_name = wide_null(SERVICE_NAME);
    // SAFETY: SCM invokes this callback for SERVICE_NAME, and the function pointer remains valid for
    // the process lifetime. No callback context is used.
    let status = unsafe {
        RegisterServiceCtrlHandlerExW(
            PCWSTR(service_name.as_ptr()),
            Some(service_control_handler),
            None,
        )
    };
    let Ok(status) = status else {
        return;
    };
    STATUS_HANDLE.store(status.0, Ordering::SeqCst);
    let _ = report_status(SERVICE_START_PENDING, false, 15_000);
    let result = service_loop();
    let exit_code = if result.is_ok() { 0 } else { 1 };
    let _ = report_status_with_exit(SERVICE_STOPPED, false, 0, exit_code);
    STATUS_HANDLE.store(ptr::null_mut(), Ordering::SeqCst);
}

unsafe extern "system" fn service_control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    if control == SERVICE_CONTROL_STOP {
        STOP_REQUESTED.store(true, Ordering::SeqCst);
        if !COMMITTING.load(Ordering::SeqCst) {
            let _ = report_status(SERVICE_STOP_PENDING, false, 30_000);
            let stop_event = STOP_EVENT.load(Ordering::SeqCst);
            if !stop_event.is_null() {
                // SAFETY: the service loop publishes a live event handle until it exits.
                let _ = unsafe { SetEvent(HANDLE(stop_event)) };
            }
            let pipe = CURRENT_PIPE.load(Ordering::SeqCst);
            if !pipe.is_null() {
                // SAFETY: the service loop publishes a live pipe handle; CancelIoEx is explicitly
                // safe to call from a different thread and only requests cancellation.
                let _ = unsafe { CancelIoEx(HANDLE(pipe), None) };
            }
        }
    }
    0
}

fn service_loop() -> Result<()> {
    STOP_REQUESTED.store(false, Ordering::SeqCst);
    COMMITTING.store(false, Ordering::SeqCst);
    let stop_event = create_event(true, false)?;
    STOP_EVENT.store(stop_event.raw().0, Ordering::SeqCst);

    let data_directory = service_data_directory()?;
    // Setup creates this directory with a protected DACL. The service never silently recreates a
    // missing directory with inherited permissions.
    let _data_handle = open_absolute_directory(&data_directory, false)?;
    let registry_path = data_directory.join("roots-v1.json");
    let roots = if registry_path.exists() {
        RootRegistry::load(&registry_path)?
    } else {
        RootRegistry::new()
    };
    let generation_path = data_directory.join("generations-v1.json");
    let mut generations = GenerationRegistry::load(&generation_path)?;
    let registry_scope_path = data_directory.join("registry-scopes-v1.json");
    let registry_scopes = if registry_scope_path.exists() {
        RegistryScopeRegistry::load(&registry_scope_path)?
    } else {
        RegistryScopeRegistry::new()
    };
    let registry_generation_path = data_directory.join("registry-generations-v1.json");
    let registry_generations = GenerationRegistry::load(&registry_generation_path)?;
    let registry_transaction_path = data_directory.join("registry-transaction-v1.json");
    recover_registry_transaction(&registry_transaction_path, &registry_scopes)?;
    let recovery_policy = TransactionPolicy::new(
        &data_directory,
        Arc::new(WindowsTransactionPlatform::default()),
    )?;
    let recovery = recover_incomplete_with_policy(recovery_policy)?;
    let mut recovered_generation = false;
    for job_id in recovery.committed_jobs {
        if let Some((root_id, record)) = generation_from_job_id(&job_id) {
            generations.accept(&root_id, record)?;
            recovered_generation = true;
        }
    }
    if recovered_generation {
        generations.save(&generation_path)?;
    }
    let mut state = ServiceState {
        generation_path,
        generations,
        keyring_path: data_directory.join("keyring-v1.json"),
        registry_path,
        data_directory,
        roots,
        registry_generation_path,
        registry_generations,
        registry_scope_path,
        registry_scopes,
        registry_transaction_path,
        active_job: None,
    };

    report_status(SERVICE_RUNNING, true, 0)?;
    while !STOP_REQUESTED.load(Ordering::SeqCst) {
        let pipe = create_server_pipe()?;
        CURRENT_PIPE.store(pipe.raw().0, Ordering::SeqCst);
        let connected = connect_pipe_or_stop(pipe.raw(), stop_event.raw())?;
        if !connected {
            CURRENT_PIPE.store(ptr::null_mut(), Ordering::SeqCst);
            if COMMITTING.load(Ordering::SeqCst) {
                continue;
            }
            break;
        }
        let response = match read_pipe_message(pipe.raw())
            .and_then(|bytes| crate::protocol::decode_request(&bytes))
            .and_then(|request| process_request(pipe.raw(), request, &mut state))
        {
            Ok(response) => response,
            Err(error) => maintenance_error_response(&error),
        };
        let encoded = serde_json::to_vec(&response).map_err(|_| {
            MaintenanceError::new(ErrorCode::ProtocolInvalid, "IPC response cannot be encoded")
        })?;
        if encoded.len() <= MAX_IPC_MESSAGE_BYTES {
            let _ = write_pipe_message(pipe.raw(), &encoded);
        }
        // SAFETY: this is a connected server pipe owned by the current loop iteration.
        let _ = unsafe { DisconnectNamedPipe(pipe.raw()) };
        CURRENT_PIPE.store(ptr::null_mut(), Ordering::SeqCst);
    }

    CURRENT_PIPE.store(ptr::null_mut(), Ordering::SeqCst);
    STOP_EVENT.store(ptr::null_mut(), Ordering::SeqCst);
    Ok(())
}

fn maintenance_error_response(error: &MaintenanceError) -> serde_json::Value {
    serde_json::json!({
        "detail": error.detail(),
        "error": error.code().as_str(),
        "ok": false,
        "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
        "win32Status": error.platform_status(),
    })
}

fn process_request(
    pipe: HANDLE,
    request: Request,
    state: &mut ServiceState,
) -> Result<serde_json::Value> {
    refresh_active_job(state);
    let caller = caller_identity_from_connected_pipe(pipe)?;
    let active_owner = state
        .active_job
        .as_ref()
        .map(|job| (job.job_id.as_str(), job.owner_sid.as_str()));
    let authorization = authorize_request(
        &request,
        &caller,
        &state.roots,
        &state.registry_scopes,
        active_owner,
    )?;
    match (request, authorization) {
        (Request::GetStatus { .. }, AuthorizedRequest::GetStatus) => Ok(serde_json::json!({
            "capabilities": [
                "file-set-v1",
                "registry-set-v1"
            ],
            "ok": true,
            "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
            "registeredRegistryScopeCount": state.registry_scopes.owned_scope_count(caller.sid()),
            "registeredRootCount": state.roots.accessible_root_count(caller.sid()),
            "serviceVersion": env!("CARGO_PKG_VERSION"),
        })),
        (Request::GetRootStatus { root_id, .. }, AuthorizedRequest::GetRootStatus { root }) => {
            Ok(serde_json::json!({
                "capabilities": [
                    "file-set-v1",
                    "registry-set-v1"
                ],
                "ok": true,
                "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
                "registeredRoot": {
                    "path": root.canonical_path(),
                    "productId": root.product_id(),
                    "rootId": root_id,
                    "rootKind": root.root_kind(),
                },
                "serviceVersion": env!("CARGO_PKG_VERSION"),
            }))
        }
        (
            Request::GetRegistryScopeStatus { scope_id, .. },
            AuthorizedRequest::GetRegistryScopeStatus { scope },
        ) => Ok(serde_json::json!({
            "capabilities": [
                "file-set-v1",
                "registry-set-v1"
            ],
            "ok": true,
            "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
            "registeredRegistryScope": {
                "allowedValues": scope.allowed_values(),
                "hive": "localMachine",
                "productId": scope.product_id(),
                "scopeId": scope_id,
                "subkey": scope.subkey(),
                "view": scope.view(),
            },
            "serviceVersion": env!("CARGO_PKG_VERSION"),
        })),
        (
            Request::RegisterRoot {
                root_id,
                product_id,
                root_kind,
                path,
                ..
            },
            AuthorizedRequest::RegisterRoot { owner_sid },
        ) => {
            let (verified_caller, root) = registered_root_as_caller(
                pipe,
                &root_id,
                &product_id,
                root_kind,
                Path::new(&path),
            )?;
            if verified_caller.sid() != owner_sid {
                return Err(MaintenanceError::new(
                    ErrorCode::RootUnauthorized,
                    "caller token changed during root registration",
                ));
            }
            let mut roots = state.roots.clone();
            roots.register(root)?;
            roots.save(&state.registry_path)?;
            state.roots = roots;
            Ok(serde_json::json!({
                "ok": true,
                "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
                "rootId": root_id,
            }))
        }
        (
            Request::UnregisterRoot { root_id, .. },
            AuthorizedRequest::UnregisterRoot {
                root_id: authorized_root_id,
            },
        ) => {
            if root_id != authorized_root_id {
                return Err(MaintenanceError::new(
                    ErrorCode::RootUnauthorized,
                    "authorized root ID changed",
                ));
            }
            let mut roots = state.roots.clone();
            roots.unregister(&root_id, caller.sid())?;
            roots.save(&state.registry_path)?;
            state.roots = roots;
            Ok(serde_json::json!({
                "ok": true,
                "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
                "rootId": root_id,
            }))
        }
        (
            Request::RegisterRegistryScope {
                scope_id,
                product_id,
                view,
                subkey,
                allowed_values,
                ..
            },
            AuthorizedRequest::RegisterRegistryScope { owner_sid },
        ) => {
            let (verified_caller, scope) = registered_registry_scope_as_caller(
                pipe,
                &scope_id,
                &product_id,
                view,
                &subkey,
                allowed_values,
            )?;
            if verified_caller.sid() != owner_sid {
                return Err(MaintenanceError::new(
                    ErrorCode::RegistryScopeUnauthorized,
                    "caller token changed during registry-scope registration",
                ));
            }
            let mut registry_scopes = state.registry_scopes.clone();
            registry_scopes.register(scope)?;
            registry_scopes.save(&state.registry_scope_path)?;
            state.registry_scopes = registry_scopes;
            Ok(serde_json::json!({
                "ok": true,
                "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
                "scopeId": scope_id,
            }))
        }
        (
            Request::UnregisterRegistryScope { scope_id, .. },
            AuthorizedRequest::UnregisterRegistryScope {
                scope_id: authorized_scope_id,
            },
        ) => {
            if scope_id != authorized_scope_id {
                return Err(MaintenanceError::new(
                    ErrorCode::RegistryScopeUnauthorized,
                    "authorized registry scope ID changed",
                ));
            }
            let mut registry_scopes = state.registry_scopes.clone();
            registry_scopes.unregister(&scope_id, caller.sid())?;
            registry_scopes.save(&state.registry_scope_path)?;
            state.registry_scopes = registry_scopes;
            Ok(serde_json::json!({
                "ok": true,
                "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
                "scopeId": scope_id,
            }))
        }
        (
            Request::ApplyRegistrySet { manifest_path, .. },
            AuthorizedRequest::ApplyRegistrySet { scope },
        ) => {
            if matches!(
                state.active_job.as_ref().map(|job| &job.state),
                Some(ActiveJobState::Completed { .. })
            ) {
                state.active_job = None;
            }
            if state.active_job.is_some() || STOP_REQUESTED.load(Ordering::SeqCst) {
                return Err(MaintenanceError::new(
                    ErrorCode::ServiceBusy,
                    "registry mutation cannot overlap another maintenance transaction",
                ));
            }
            let (manifest_caller, manifest_bytes) =
                read_manifest_as_caller(pipe, Path::new(&manifest_path), MAX_REGISTRY_SET_BYTES)?;
            if manifest_caller.sid() != caller.sid() {
                return Err(MaintenanceError::new(
                    ErrorCode::RegistryScopeUnauthorized,
                    "caller token changed while opening the registry manifest",
                ));
            }
            let keyring_bytes = read_service_file(&state.keyring_path, MAX_MANIFEST_BYTES)?;
            let keyring = verify_keyring(&keyring_bytes, KeyringAcceptance::default())?;
            let manifest = verify_registry_set(
                &manifest_bytes,
                &keyring,
                RegistrySetAcceptance {
                    allowed_values: scope.allowed_values(),
                    expected_product_id: scope.product_id(),
                    expected_scope_id: scope.scope_id(),
                    previous: state.registry_generations.previous(scope.scope_id())?,
                },
            )?;
            apply_registry_set_transaction(state, &scope, &manifest)
        }
        (
            Request::PrepareFileSet {
                manifest_path,
                staging_path,
                ..
            },
            AuthorizedRequest::PrepareFileSet { root },
        ) => {
            if matches!(
                state.active_job.as_ref().map(|job| &job.state),
                Some(ActiveJobState::Completed { .. })
            ) {
                state.active_job = None;
            }
            if state.active_job.is_some() {
                return Err(MaintenanceError::new(
                    ErrorCode::TransactionConflict,
                    "only one maintenance job may be active",
                ));
            }
            let (manifest_caller, manifest_bytes) =
                read_manifest_as_caller(pipe, Path::new(&manifest_path), MAX_MANIFEST_BYTES)?;
            if manifest_caller.sid() != caller.sid() {
                return Err(MaintenanceError::new(
                    ErrorCode::RootUnauthorized,
                    "caller token changed while opening the manifest",
                ));
            }
            let keyring_bytes = read_service_file(&state.keyring_path, MAX_MANIFEST_BYTES)?;
            let keyring = verify_keyring(&keyring_bytes, KeyringAcceptance::default())?;
            let manifest = verify_file_set(
                &manifest_bytes,
                &keyring,
                crate::FileSetAcceptance {
                    expected_product_id: root.product_id(),
                    previous: state.generations.previous(root.root_id())?,
                },
            )?;
            let (staging_caller, platform) = preopen_staging_as_caller(
                pipe,
                Path::new(&staging_path),
                &manifest.file_set().files,
            )?;
            if staging_caller.sid() != caller.sid() {
                return Err(MaintenanceError::new(
                    ErrorCode::RootUnauthorized,
                    "caller token changed while opening staging handles",
                ));
            }
            if root.root_kind() == crate::protocol::RootKind::Launcher {
                platform.verify_launcher_payloads(
                    &manifest.file_set().files,
                    &keyring.keyring().authenticode_signer_thumbprints,
                )?;
            }
            let policy = TransactionPolicy::new(&state.data_directory, Arc::new(platform))?;
            let prepared = prepare_file_set(&manifest, &root, Path::new(&staging_path), policy)?;
            let job_id = prepared.job_id().to_owned();
            state.generations.accept(
                root.root_id(),
                GenerationRecord {
                    generation: manifest.file_set().generation,
                    digest: manifest.digest(),
                },
            )?;
            state.generations.save(&state.generation_path)?;
            state.active_job = Some(ActiveJob {
                job_id: job_id.clone(),
                owner_sid: caller.sid().to_owned(),
                state: ActiveJobState::Prepared(Box::new(prepared)),
            });
            Ok(serde_json::json!({
                "jobId": job_id,
                "ok": true,
                "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
                "state": "prepared",
            }))
        }
        (
            Request::CommitJob { job_id, .. },
            AuthorizedRequest::CommitJob {
                job_id: authorized_job_id,
            },
        ) => {
            if job_id != authorized_job_id || STOP_REQUESTED.load(Ordering::SeqCst) {
                return Err(MaintenanceError::new(
                    ErrorCode::TransactionState,
                    "commit cannot start after a stop request",
                ));
            }
            let active = state.active_job.as_mut().ok_or_else(|| {
                MaintenanceError::new(
                    ErrorCode::TransactionState,
                    "maintenance job is no longer available",
                )
            })?;
            let placeholder = ActiveJobState::Completed {
                cleanup_pending: false,
                error: Some(ErrorCode::TransactionState),
                generation: None,
                state: "failed",
            };
            let previous_state = std::mem::replace(&mut active.state, placeholder);
            let ActiveJobState::Prepared(prepared) = previous_state else {
                active.state = previous_state;
                return Err(MaintenanceError::new(
                    ErrorCode::TransactionState,
                    "maintenance job is not prepared",
                ));
            };
            let (sender, receiver) = mpsc::sync_channel(1);
            let prepared_slot = Arc::new(Mutex::new(Some(prepared)));
            let worker_slot = Arc::clone(&prepared_slot);
            COMMITTING.store(true, Ordering::SeqCst);
            let _ = report_status(SERVICE_RUNNING, false, 0);
            let worker = std::thread::Builder::new()
                .name("7launcher-maintenance-commit".to_owned())
                .spawn(move || {
                    let _activity = CommitActivity;
                    let result = worker_slot
                        .lock()
                        .ok()
                        .and_then(|mut slot| slot.take())
                        .map(|prepared| commit_file_set(*prepared))
                        .unwrap_or_else(|| {
                            Err(MaintenanceError::new(
                                ErrorCode::RecoveryIncomplete,
                                "commit worker lost the prepared transaction",
                            ))
                        });
                    let _ = sender.send(result);
                });
            if worker.is_err() {
                COMMITTING.store(false, Ordering::SeqCst);
                let _ = report_status(SERVICE_RUNNING, true, 0);
                let prepared = prepared_slot
                    .lock()
                    .map_err(|_| {
                        MaintenanceError::new(
                            ErrorCode::RecoveryIncomplete,
                            "prepared transaction recovery lock was poisoned",
                        )
                    })?
                    .take()
                    .ok_or_else(|| {
                        MaintenanceError::new(
                            ErrorCode::RecoveryIncomplete,
                            "prepared transaction was lost before commit",
                        )
                    })?;
                active.state = ActiveJobState::Prepared(prepared);
                return Err(MaintenanceError::new(
                    ErrorCode::TransactionState,
                    "commit worker cannot be started",
                ));
            }
            active.state = ActiveJobState::Committing(receiver);
            Ok(serde_json::json!({
                "completedOperations": 0,
                "jobId": job_id,
                "ok": true,
                "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
                "state": "committing",
                "totalOperations": 1,
            }))
        }
        (
            Request::GetJobStatus { job_id, .. },
            AuthorizedRequest::GetJobStatus {
                job_id: authorized_job_id,
            },
        ) if job_id == authorized_job_id => job_status_response(state, &job_id),
        _ => Err(MaintenanceError::new(
            ErrorCode::ProtocolInvalid,
            "request and authorization decision did not match",
        )),
    }
}

fn apply_registry_set_transaction(
    state: &mut ServiceState,
    scope: &RegisteredRegistryScope,
    manifest: &crate::VerifiedRegistrySet,
) -> Result<serde_json::Value> {
    let (key, mut journal) = create_registry_transaction(scope, &manifest.registry_set().values)?;
    write_registry_transaction(&state.registry_transaction_path, &journal)?;

    COMMITTING.store(true, Ordering::SeqCst);
    let _activity = CommitActivity;
    for value in &manifest.registry_set().values {
        if let Err(error) = set_registry_value(&key, value) {
            if restore_registry_values(&key, &journal.values).is_err()
                || remove_registry_transaction(&state.registry_transaction_path).is_err()
            {
                return Err(MaintenanceError::new(
                    ErrorCode::RecoveryIncomplete,
                    "failed registry mutation could not be rolled back",
                ));
            }
            return Err(error);
        }
    }

    let previous_generations = state.registry_generations.clone();
    let record = GenerationRecord {
        generation: manifest.registry_set().generation,
        digest: manifest.digest(),
    };
    let generation_result = state
        .registry_generations
        .accept(scope.scope_id(), record)
        .and_then(|()| {
            state
                .registry_generations
                .save(&state.registry_generation_path)
        });
    if let Err(error) = generation_result {
        state.registry_generations = previous_generations;
        let generation_restored = state
            .registry_generations
            .save(&state.registry_generation_path)
            .is_ok();
        let values_restored = restore_registry_values(&key, &journal.values).is_ok();
        let journal_removed = remove_registry_transaction(&state.registry_transaction_path).is_ok();
        if generation_restored && values_restored && journal_removed {
            return Err(error);
        }
        return Err(MaintenanceError::new(
            ErrorCode::RecoveryIncomplete,
            "registry generation persistence could not be rolled back",
        ));
    }

    journal.phase = RegistryTransactionPhase::Committed;
    if write_registry_transaction(&state.registry_transaction_path, &journal).is_err() {
        state.registry_generations = previous_generations;
        let generation_restored = state
            .registry_generations
            .save(&state.registry_generation_path)
            .is_ok();
        let values_restored = restore_registry_values(&key, &journal.values).is_ok();
        let journal_removed = remove_registry_transaction(&state.registry_transaction_path).is_ok();
        if !(generation_restored && values_restored && journal_removed) {
            return Err(MaintenanceError::new(
                ErrorCode::RecoveryIncomplete,
                "registry commit marker failure could not be rolled back",
            ));
        }
        return Err(MaintenanceError::new(
            ErrorCode::RegistryIo,
            "registry commit marker cannot be persisted",
        ));
    }
    remove_registry_transaction(&state.registry_transaction_path)?;
    Ok(serde_json::json!({
        "appliedValues": manifest.registry_set().values.len(),
        "generation": manifest.registry_set().generation,
        "ok": true,
        "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
        "scopeId": scope.scope_id(),
        "state": "committed",
    }))
}

struct CommitActivity;

impl Drop for CommitActivity {
    fn drop(&mut self) {
        COMMITTING.store(false, Ordering::SeqCst);
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            let _ = report_status(SERVICE_STOP_PENDING, false, 30_000);
            let stop_event = STOP_EVENT.load(Ordering::SeqCst);
            if !stop_event.is_null() {
                // SAFETY: the service loop owns this event until the commit worker has finished.
                let _ = unsafe { SetEvent(HANDLE(stop_event)) };
            }
        } else {
            let _ = report_status(SERVICE_RUNNING, true, 0);
        }
    }
}

fn refresh_active_job(state: &mut ServiceState) {
    let Some(active) = state.active_job.as_mut() else {
        return;
    };
    let ActiveJobState::Committing(receiver) = &active.state else {
        return;
    };
    let completed = match receiver.try_recv() {
        Ok(Ok(result)) => Some(ActiveJobState::Completed {
            cleanup_pending: result.cleanup_pending,
            error: None,
            generation: Some(result.generation),
            state: "committed",
        }),
        Ok(Err(error)) => Some(ActiveJobState::Completed {
            cleanup_pending: false,
            error: Some(error.code()),
            generation: None,
            state: if error.code() == ErrorCode::RecoveryIncomplete {
                "failed"
            } else {
                "rolledBack"
            },
        }),
        Err(TryRecvError::Disconnected) => Some(ActiveJobState::Completed {
            cleanup_pending: false,
            error: Some(ErrorCode::RecoveryIncomplete),
            generation: None,
            state: "failed",
        }),
        Err(TryRecvError::Empty) => None,
    };
    if let Some(completed) = completed {
        active.state = completed;
    }
}

fn job_status_response(state: &mut ServiceState, job_id: &str) -> Result<serde_json::Value> {
    refresh_active_job(state);
    let active = state.active_job.as_ref().ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::TransactionState,
            "maintenance job is no longer available",
        )
    })?;
    let response = match &active.state {
        ActiveJobState::Prepared(_) => serde_json::json!({
            "completedOperations": 0,
            "jobId": job_id,
            "ok": true,
            "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
            "state": "prepared",
            "totalOperations": 1,
        }),
        ActiveJobState::Committing(_) => serde_json::json!({
            "completedOperations": 0,
            "jobId": job_id,
            "ok": true,
            "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
            "state": "committing",
            "totalOperations": 1,
        }),
        ActiveJobState::Completed {
            cleanup_pending,
            error,
            generation,
            state: job_state,
        } => serde_json::json!({
            "cleanupPending": cleanup_pending,
            "completedOperations": 1,
            "error": error.map(ErrorCode::as_str),
            "generation": generation,
            "jobId": job_id,
            "ok": true,
            "protocolMajor": crate::protocol::PROTOCOL_MAJOR,
            "state": job_state,
            "totalOperations": 1,
        }),
    };
    // Keep a terminal result readable if its IPC response is lost. The next PrepareFileSet or
    // ApplyRegistrySet already replaces a completed job, so this does not reserve the service.
    Ok(response)
}

fn create_event(manual_reset: bool, initial_state: bool) -> Result<KernelHandle> {
    // SAFETY: null security/name selects a private unnamed event; returned handle is uniquely owned.
    let handle = unsafe { CreateEventW(None, manual_reset, initial_state, PCWSTR::null()) }
        .map_err(|_| {
            MaintenanceError::new(ErrorCode::TransactionIo, "service event cannot be created")
        })?;
    KernelHandle::new(
        handle,
        ErrorCode::TransactionIo,
        "service event handle is invalid",
    )
}

fn connect_pipe_or_stop(pipe: HANDLE, stop_event: HANDLE) -> Result<bool> {
    let connect_event = create_event(true, false)?;
    let mut overlapped = OVERLAPPED {
        hEvent: connect_event.raw(),
        ..Default::default()
    };
    // SAFETY: the pipe was opened for overlapped I/O and `overlapped` plus its event remain live
    // until completion/cancellation is observed below.
    match unsafe { ConnectNamedPipe(pipe, Some(&mut overlapped)) } {
        Ok(()) => Ok(true),
        Err(error) if error.code() == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) => Ok(true),
        Err(error) if error.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => {
            // SAFETY: both handles are live waitable event handles for the whole call.
            let wait = unsafe {
                WaitForMultipleObjects(
                    &[connect_event.raw(), stop_event],
                    false,
                    SERVICE_IDLE_TIMEOUT_MS,
                )
            };
            if wait == WAIT_OBJECT_0 {
                let mut transferred = 0_u32;
                // SAFETY: the matching OVERLAPPED remains live and the event signaled completion.
                unsafe { GetOverlappedResult(pipe, &overlapped, &mut transferred, false) }
                    .map_err(|_| {
                        MaintenanceError::new(
                            ErrorCode::TransactionIo,
                            "named-pipe connection did not complete",
                        )
                    })?;
                Ok(true)
            } else if wait.0 == WAIT_OBJECT_0.0 + 1 || wait == WAIT_TIMEOUT {
                // SAFETY: cancellation targets this live connect operation and is observed before
                // `overlapped` leaves scope.
                let _ = unsafe { CancelIoEx(pipe, Some(&overlapped)) };
                let mut transferred = 0_u32;
                // SAFETY: waiting here drains completion/cancellation before stack storage drops.
                let _ = unsafe { GetOverlappedResult(pipe, &overlapped, &mut transferred, true) };
                Ok(false)
            } else {
                Err(MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "named-pipe connection wait failed",
                ))
            }
        }
        Err(_) => Err(MaintenanceError::new(
            ErrorCode::TransactionIo,
            "named-pipe connection failed",
        )),
    }
}

fn read_pipe_message(pipe: HANDLE) -> Result<Vec<u8>> {
    let event = create_event(true, false)?;
    let mut overlapped = OVERLAPPED {
        hEvent: event.raw(),
        ..Default::default()
    };
    let mut bytes = vec![0_u8; MAX_IPC_MESSAGE_BYTES];
    let mut transferred = 0_u32;
    // SAFETY: the pipe is connected and opened overlapped; buffer, count, OVERLAPPED, and event all
    // remain live until completion is observed.
    match unsafe {
        ReadFile(
            pipe,
            Some(&mut bytes),
            Some(&mut transferred),
            Some(&mut overlapped),
        )
    } {
        Ok(()) => {}
        Err(error) if error.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => {
            // SAFETY: this waits for the matching live OVERLAPPED before its storage is released.
            unsafe { GetOverlappedResult(pipe, &overlapped, &mut transferred, true) }.map_err(
                |_| {
                    MaintenanceError::new(
                        ErrorCode::ProtocolInvalid,
                        "IPC request read did not complete",
                    )
                },
            )?;
        }
        Err(_) => {
            return Err(MaintenanceError::new(
                ErrorCode::ProtocolInvalid,
                "IPC request could not be read as one bounded message",
            ));
        }
    }
    let transferred = usize::try_from(transferred).map_err(|_| {
        MaintenanceError::new(ErrorCode::ProtocolTooLarge, "IPC request size overflowed")
    })?;
    bytes.truncate(transferred);
    Ok(bytes)
}

fn write_pipe_message(pipe: HANDLE, bytes: &[u8]) -> Result<()> {
    let event = create_event(true, false)?;
    let mut overlapped = OVERLAPPED {
        hEvent: event.raw(),
        ..Default::default()
    };
    let mut transferred = 0_u32;
    // SAFETY: the pipe is connected and opened overlapped; the response bytes and OVERLAPPED remain
    // live until completion is observed.
    match unsafe {
        WriteFile(
            pipe,
            Some(bytes),
            Some(&mut transferred),
            Some(&mut overlapped),
        )
    } {
        Ok(()) => {}
        Err(error) if error.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => {
            // SAFETY: this waits for the matching live OVERLAPPED before its storage is released.
            unsafe { GetOverlappedResult(pipe, &overlapped, &mut transferred, true) }.map_err(
                |_| {
                    MaintenanceError::new(
                        ErrorCode::TransactionIo,
                        "IPC response write did not complete",
                    )
                },
            )?;
        }
        Err(_) => {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionIo,
                "IPC response could not be written",
            ));
        }
    }
    if usize::try_from(transferred).ok() != Some(bytes.len()) {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionIo,
            "IPC response write was incomplete",
        ));
    }
    Ok(())
}

fn report_status(
    state: SERVICE_STATUS_CURRENT_STATE,
    accept_stop: bool,
    wait_hint: u32,
) -> Result<()> {
    report_status_with_exit(state, accept_stop, wait_hint, 0)
}

fn report_status_with_exit(
    state: SERVICE_STATUS_CURRENT_STATE,
    accept_stop: bool,
    wait_hint: u32,
    exit_code: u32,
) -> Result<()> {
    let raw = STATUS_HANDLE.load(Ordering::SeqCst);
    if raw.is_null() {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionState,
            "service status handle is unavailable",
        ));
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if accept_stop { SERVICE_ACCEPT_STOP } else { 0 },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint,
    };
    // SAFETY: SCM supplied this status handle and the fixed status value lives through the call.
    unsafe { SetServiceStatus(SERVICE_STATUS_HANDLE(raw), &status) }.map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "service status could not be reported",
        )
    })
}

fn service_data_directory() -> Result<PathBuf> {
    let program_data = std::env::var_os("ProgramData").ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::TransactionState,
            "ProgramData is unavailable to the service",
        )
    })?;
    let path = PathBuf::from(program_data).join("SE7EN").join("Service");
    if !path.is_absolute() {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionState,
            "service data directory is not absolute",
        ));
    }
    Ok(path)
}

fn generation_from_job_id(job_id: &str) -> Option<(String, GenerationRecord)> {
    if !valid_job_identifier(job_id) {
        return None;
    }
    let mut parts = job_id.rsplitn(3, '-');
    let digest = parts.next()?;
    let generation = parts.next()?.parse::<u64>().ok()?;
    let root_id = parts.next()?;
    if generation == 0 || !valid_identifier(root_id) {
        return None;
    }
    let digest = decode_lower_hex::<32>(digest, ErrorCode::GenerationConflict).ok()?;
    Some((root_id.to_owned(), GenerationRecord { generation, digest }))
}

fn read_bounded_file(path: &Path, maximum: usize) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "service file exceeds its bound",
        ));
    }
    Ok(bytes)
}

fn replace_service_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("new");
    let backup = path.with_extension("bak");
    if temporary.exists() || backup.exists() {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionConflict,
            "stale protected replacement files require recovery",
        ));
    }
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "protected replacement cannot be created",
            )
        })?;
    output.write_all(bytes).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "protected replacement cannot be written",
        )
    })?;
    output.sync_all().map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            "protected replacement cannot be flushed",
        )
    })?;
    drop(output);
    if path.exists() {
        fs::rename(path, &backup).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "protected current file cannot be backed up",
            )
        })?;
    }
    if fs::rename(&temporary, path).is_err() {
        if backup.exists() {
            let _ = fs::rename(&backup, path);
        }
        return Err(MaintenanceError::new(
            ErrorCode::TransactionIo,
            "protected replacement cannot be activated",
        ));
    }
    if backup.exists() {
        fs::remove_file(backup).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "protected backup cannot be cleaned",
            )
        })?;
    }
    Ok(())
}

fn recover_service_file_replacement(path: &Path) -> Result<()> {
    let temporary = path.with_extension("new");
    let backup = path.with_extension("bak");
    match (path.exists(), temporary.exists(), backup.exists()) {
        (true, true, false) => fs::remove_file(temporary).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "stale protected replacement cannot be discarded",
            )
        })?,
        (false, true, true) => {
            fs::rename(&temporary, path).map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "protected replacement recovery cannot activate the new file",
                )
            })?;
            fs::remove_file(backup).map_err(|_| {
                MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "protected replacement recovery cannot remove the backup",
                )
            })?;
        }
        (true, false, true) => fs::remove_file(backup).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "protected replacement recovery cannot remove the backup",
            )
        })?,
        (false, false, true) => fs::rename(backup, path).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "protected replacement recovery cannot restore the backup",
            )
        })?,
        (false, true, false) => fs::rename(temporary, path).map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TransactionIo,
                "protected replacement recovery cannot activate the initial file",
            )
        })?,
        (true, true, true) => {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionState,
                "protected replacement state is ambiguous",
            ));
        }
        (true, false, false) | (false, false, false) => {}
    }
    Ok(())
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_service_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::TrustSignature,
            "protected service trust file cannot be opened",
        )
    })?;
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| {
            MaintenanceError::new(
                ErrorCode::TrustSignature,
                "protected service trust file cannot be read",
            )
        })?;
    if bytes.len() > maximum {
        return Err(MaintenanceError::new(
            ErrorCode::ManifestTooLarge,
            "protected service trust file exceeds the bound",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod rename_tests {
    use std::time::SystemTime;

    use super::*;

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn create() -> Self {
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "seven-maintenance-rename-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temp directory");
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn handle_rename_moves_into_the_locked_parent_directory() {
        let directory = TempDirectory::create();
        fs::write(directory.0.join("candidate.new"), b"candidate").expect("write candidate");
        let candidate = open_relative_file(
            &directory.0,
            "candidate.new",
            DELETE.0 | FILE_GENERIC_READ.0,
            false,
            false,
        )
        .expect("open candidate")
        .expect("candidate exists");

        let renamed =
            rename_handle_relative(&directory.0, &candidate, "nested/version/service.exe", true);
        renamed.expect("rename candidate by handle");
        let renamed_path = final_path_owned(&candidate).expect("read renamed handle path");
        drop(candidate);

        assert!(
            renamed_path.ends_with(Path::new("nested/version/service.exe")),
            "unexpected renamed path: {renamed_path:?}"
        );
        assert_eq!(
            fs::read(directory.0.join("nested/version/service.exe")).expect("read destination"),
            b"candidate"
        );
        assert!(!directory.0.join("candidate.new").exists());
    }
}

#[cfg(test)]
mod launcher_handoff_tests {
    use std::{
        io::Read,
        os::windows::process::CommandExt,
        process::{Command, Stdio},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::{
        CreateEventW, ErrorCode, KernelHandle, LauncherProcess, PCWSTR, WAIT_OBJECT_0,
        WAIT_TIMEOUT, WaitForSingleObject, signal_launcher_ready, wide_null,
    };

    #[test]
    fn launcher_process_wait_is_bounded_while_launcher_is_alive() {
        let process = LauncherProcess::open(std::process::id()).expect("current process");
        assert!(!process.wait(Duration::ZERO).unwrap());
        assert!(!process.wait(Duration::from_millis(1)).unwrap());
        assert!(LauncherProcess::open(0).is_err());
    }

    #[test]
    fn launcher_process_wait_keeps_the_original_handle_after_exit() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::launcher_handoff_tests::launcher_process_wait_child",
                "--nocapture",
            ])
            .env("SE7EN_LAUNCHER_PROCESS_WAIT_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .spawn()
            .expect("start isolated process-wait test child");
        let process = LauncherProcess::open(child.id()).expect("hold the existing process");
        assert!(!process.wait(Duration::ZERO).unwrap());
        // Closing only this child's stdin releases it; no user process or service is touched.
        drop(child.stdin.take());
        assert!(process.wait(Duration::from_secs(10)).unwrap());
        assert!(child.wait().unwrap().success());
        drop(child);
        assert!(process.wait(Duration::ZERO).unwrap());
    }

    #[test]
    fn launcher_process_wait_child() {
        if std::env::var("SE7EN_LAUNCHER_PROCESS_WAIT_CHILD").as_deref() == Ok("1") {
            let mut bytes = Vec::new();
            std::io::stdin().read_to_end(&mut bytes).unwrap();
            assert!(bytes.is_empty());
        }
    }

    #[test]
    fn launcher_ready_signals_only_an_existing_event() {
        let name = format!(
            "Local\\7Launcher-Readiness-Test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        assert!(signal_launcher_ready(&name).is_err());
        assert!(signal_launcher_ready("").is_err());
        assert!(signal_launcher_ready("Local\\invalid\0suffix").is_err());
        let wide_name = wide_null(&name);
        // SAFETY: the unique test event name is NUL-terminated and the handle is owned below.
        let event = unsafe { CreateEventW(None, true, false, PCWSTR(wide_name.as_ptr())) }
            .expect("create test readiness event");
        let event = KernelHandle::new(event, ErrorCode::TransactionState, "test event").unwrap();
        // SAFETY: this is a live waitable test event; the zero timeout cannot block.
        assert_eq!(unsafe { WaitForSingleObject(event.raw(), 0) }, WAIT_TIMEOUT);
        signal_launcher_ready(&name).expect("signal existing readiness event");
        // SAFETY: as above, the event remains owned until after this bounded wait.
        assert_eq!(
            unsafe { WaitForSingleObject(event.raw(), 0) },
            WAIT_OBJECT_0
        );
        drop(event);
        assert!(signal_launcher_ready(&name).is_err());
    }
}

#[cfg(test)]
mod token_membership_tests {
    use windows::Win32::{
        Foundation::HANDLE,
        Security::{TOKEN_DUPLICATE, TOKEN_QUERY},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    use super::{ErrorCode, KernelHandle, token_is_administrator};

    #[test]
    fn primary_process_token_can_be_checked_for_administrator_membership() {
        let mut token = HANDLE::default();
        // SAFETY: GetCurrentProcess returns a valid pseudo-handle and `token` is a valid out pointer.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut token,
            )
        }
        .expect("current process token");
        let token = KernelHandle::new(
            token,
            ErrorCode::RootUnauthorized,
            "test process token is invalid",
        )
        .expect("owned process token");

        assert!(token_is_administrator(token.raw()).is_ok());
    }
}

#[cfg(test)]
mod pipe_wait_tests {
    use std::{cell::Cell, time::Duration};

    use super::wait_for_pipe_ready_with;

    #[test]
    fn retries_when_service_is_running_before_the_pipe_exists() {
        let attempts = Cell::new(0_u32);
        let ready = wait_for_pipe_ready_with(
            Duration::from_secs(1),
            |_| {
                let attempt = attempts.get() + 1;
                attempts.set(attempt);
                (attempt == 3).then_some(())
            },
            |_| {},
        );

        assert_eq!(ready, Some(()));
        assert_eq!(attempts.get(), 3);
    }

    #[test]
    fn zero_timeout_does_not_probe_the_pipe() {
        let attempts = Cell::new(0_u32);
        let ready = wait_for_pipe_ready_with(
            Duration::ZERO,
            |_| {
                attempts.set(attempts.get() + 1);
                Some(())
            },
            |_| {},
        );

        assert_eq!(ready, None);
        assert_eq!(attempts.get(), 0);
    }
}

#[cfg(test)]
mod pipe_transaction_tests {
    use std::time::SystemTime;

    use super::*;

    #[test]
    fn client_receives_one_response_when_server_disconnects_immediately_after_write() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let pipe_name = format!(
            r"\\.\pipe\SE7ENService-transaction-test-{}-{nonce}",
            std::process::id()
        );
        let wide_name = wide_null(&pipe_name);
        // SAFETY: the unique pipe name is NUL-terminated and all sizes are bounded constants.
        let server = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide_name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                4096,
                4096,
                1000,
                None,
            )
        };
        let server = KernelHandle::new(
            server,
            ErrorCode::TransactionIo,
            "test server pipe is invalid",
        )
        .expect("create test server pipe");

        let client_name = pipe_name.clone();
        let client = thread::spawn(move || {
            let pipe = open_absolute(
                Path::new(&client_name),
                PIPE_CLIENT_ACCESS_MASK,
                windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            )
            .expect("open test client pipe");
            transact_pipe_message(raw_handle(&pipe), br#"{"request":true}"#)
                .expect("transact one bounded message")
        });

        // SAFETY: the server handle is a live synchronous named-pipe instance.
        match unsafe { ConnectNamedPipe(server.raw(), None) } {
            Ok(()) => {}
            Err(error) if error.code() == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) => {}
            Err(error) => panic!("connect test pipe: {error}"),
        }
        let mut request = [0_u8; 128];
        let mut request_size = 0_u32;
        // SAFETY: the connected synchronous pipe and output buffers remain live for the call.
        unsafe {
            ReadFile(
                server.raw(),
                Some(&mut request),
                Some(&mut request_size),
                None,
            )
        }
        .expect("read test request");
        assert_eq!(
            &request[..usize::try_from(request_size).expect("request size")],
            br#"{"request":true}"#
        );

        let response = br#"{"ok":true,"protocolMajor":1}"#;
        let mut written = 0_u32;
        // SAFETY: the connected synchronous pipe and input/count buffers remain live for the call.
        unsafe { WriteFile(server.raw(), Some(response), Some(&mut written), None) }
            .expect("write test response");
        assert_eq!(
            usize::try_from(written).expect("written size"),
            response.len()
        );
        // Reproduce the production server behavior that exposed the slow-system scheduling race.
        // SAFETY: this is the connected server pipe owned by this test.
        unsafe { DisconnectNamedPipe(server.raw()) }.expect("disconnect test server");

        assert_eq!(client.join().expect("client thread"), response);
    }

    #[test]
    fn client_cancels_an_unanswered_transaction_before_the_server_disconnects() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pipe_name = format!(
            r"\\.\pipe\SE7ENService-timeout-test-{}-{nonce}",
            std::process::id()
        );
        let wide_name = wide_null(&pipe_name);
        // SAFETY: this unique test pipe has bounded buffers and is owned below.
        let server = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide_name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                4096,
                4096,
                1000,
                None,
            )
        };
        let server = KernelHandle::new(server, ErrorCode::TransactionIo, "test timeout pipe")
            .expect("create timeout test pipe");
        let (sender, receiver) = mpsc::channel();
        let client = thread::spawn(move || {
            let pipe = open_absolute(
                Path::new(&pipe_name),
                PIPE_CLIENT_ACCESS_MASK,
                windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            )
            .expect("open timeout client pipe");
            let started = Instant::now();
            let result = transact_pipe_message_with_timeout(
                raw_handle(&pipe),
                br#"{"request":true}"#,
                Duration::from_millis(50),
            );
            sender.send((started.elapsed(), result)).unwrap();
        });
        // SAFETY: the server owns this synchronous pipe; the client may already have connected.
        match unsafe { ConnectNamedPipe(server.raw(), None) } {
            Ok(()) => {}
            Err(error) if error.code() == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) => {}
            Err(error) => panic!("connect timeout pipe: {error}"),
        }
        let mut request = [0_u8; 128];
        let mut request_size = 0;
        // SAFETY: request storage remains live through this synchronous read.
        unsafe {
            ReadFile(
                server.raw(),
                Some(&mut request),
                Some(&mut request_size),
                None,
            )
        }
        .expect("read the request that will remain unanswered");
        // The server deliberately stays connected. Completion must come from the client timeout,
        // not from a broken pipe. Disconnect before asserting so a regression cannot strand a thread.
        let completed = receiver.recv_timeout(Duration::from_secs(2));
        // SAFETY: this test owns the connected server pipe.
        let _ = unsafe { DisconnectNamedPipe(server.raw()) };
        client.join().expect("timeout client thread");
        let (elapsed, result) = completed.expect("client cancels without waiting for the server");
        let error = result.expect_err("an unanswered request must time out");
        assert_eq!(error.code(), ErrorCode::TransactionIo);
        assert_eq!(error.detail(), "typed IPC response timed out");
        assert!(elapsed < Duration::from_secs(2));
    }
}

#[cfg(test)]
mod root_acl_tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use windows::Win32::{
        Security::{
            Authorization::{GRANT_ACCESS, GetExplicitEntriesFromAclW},
            EqualSid,
        },
        Storage::FileSystem::WRITE_OWNER,
    };

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn create() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "7launcher-library-acl-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temporary library");
            Self(path)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn library_users_entry_is_inheritable_modify_without_acl_ownership_rights() {
        let directory = TemporaryDirectory::create();
        let root = open_absolute(
            &directory.0,
            READ_CONTROL.0 | WRITE_DAC.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
        .expect("open test library DACL");
        let mut users = string_sid("S-1-5-32-545").expect("construct BUILTIN Users SID");
        let users_raw = users.raw();
        let entry = root_modify_access_entry(users_raw, TRUSTEE_IS_WELL_KNOWN_GROUP);
        assert_eq!(entry.grfAccessMode, SET_ACCESS);
        merge_root_access_entries(&root, &[entry]).expect("apply test BUILTIN Users entry");

        let mut acl: *mut ACL = ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the root handle has READ_CONTROL and both output pointers remain live.
        let result = unsafe {
            GetSecurityInfo(
                raw_handle(&root),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut acl),
                None,
                Some(&mut descriptor),
            )
        };
        assert_eq!(result.0, 0, "read resulting DACL");
        let descriptor = LocalSecurityDescriptor(descriptor);
        let mut count = 0_u32;
        let mut entries = ptr::null_mut();
        // SAFETY: `acl` belongs to the live descriptor and the output pointers are valid.
        let result = unsafe { GetExplicitEntriesFromAclW(acl, &mut count, &mut entries) };
        assert_eq!(result.0, 0, "enumerate resulting DACL");
        assert!(!entries.is_null());
        // SAFETY: the API returned `count` contiguous entries allocated by LocalAlloc.
        let entries_slice = unsafe {
            std::slice::from_raw_parts(
                entries,
                usize::try_from(count).expect("ACL entry count fits usize"),
            )
        };
        let applied = entries_slice
            .iter()
            .find(|candidate| {
                let candidate_sid = PSID(candidate.Trustee.ptstrName.0.cast());
                // SAFETY: both pointers reference valid SIDs for this comparison.
                unsafe { EqualSid(candidate_sid, users_raw).is_ok() }
            })
            .expect("BUILTIN Users ACE exists");
        assert_eq!(applied.grfAccessPermissions, ROOT_MODIFY_ACCESS_MASK);
        assert_eq!(applied.grfAccessMode, GRANT_ACCESS);
        assert_eq!(applied.grfInheritance, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
        assert_eq!(applied.grfAccessPermissions & WRITE_DAC.0, 0);
        assert_eq!(applied.grfAccessPermissions & WRITE_OWNER.0, 0);
        // SAFETY: GetExplicitEntriesFromAclW allocated the entry array with LocalAlloc.
        let _ = unsafe { LocalFree(Some(HLOCAL(entries.cast()))) };
        drop(descriptor);
    }

    #[test]
    fn only_library_roots_are_machine_shared() {
        assert!(root_is_shared_library(crate::protocol::RootKind::Library));
        assert!(!root_is_shared_library(crate::protocol::RootKind::Launcher));
        assert!(!root_is_shared_library(crate::protocol::RootKind::Game));
    }
}

#[cfg(test)]
mod generation_tests {
    use super::*;
    use std::time::SystemTime;

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn create() -> Self {
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "seven-maintenance-generation-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temp directory");
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn generation_registry_persists_and_rejects_downgrade_or_conflict() {
        let directory = TempDirectory::create();
        let path = directory.0.join("generations-v1.json");
        let mut registry = GenerationRegistry::default();
        let accepted = GenerationRecord {
            generation: 7,
            digest: [0x42; 32],
        };
        registry
            .accept("launcher-sample-app", accepted)
            .expect("accept generation");
        registry.save(&path).expect("save generation registry");

        let mut loaded = GenerationRegistry::load(&path).expect("load generation registry");
        let previous = loaded
            .previous("launcher-sample-app")
            .unwrap()
            .expect("stored generation");
        assert_eq!(previous.generation, accepted.generation);
        assert_eq!(previous.digest, accepted.digest);
        loaded
            .accept("launcher-sample-app", accepted)
            .expect("same generation and digest is idempotent");
        assert!(
            loaded
                .accept(
                    "launcher-sample-app",
                    GenerationRecord {
                        generation: 6,
                        digest: [0x41; 32]
                    }
                )
                .is_err()
        );
        assert!(
            loaded
                .accept(
                    "launcher-sample-app",
                    GenerationRecord {
                        generation: 7,
                        digest: [0x43; 32]
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn committed_job_id_recovers_generation_from_the_right() {
        let digest = "ab".repeat(32);
        let (root_id, record) =
            generation_from_job_id(&format!("launcher-sample-app-9-{digest}")).expect("job ID");
        assert_eq!(root_id, "launcher-sample-app");
        assert_eq!(record.generation, 9);
        assert_eq!(record.digest, [0xab; 32]);
    }

    #[test]
    fn generation_registry_recovers_every_replace_boundary() {
        let old_document = GenerationRegistryDocument {
            kind: GENERATION_REGISTRY_KIND.to_owned(),
            roots: BTreeMap::from([(
                "launcher-sample-app".to_owned(),
                StoredGeneration {
                    digest: "41".repeat(32),
                    generation: 6,
                },
            )]),
            schema: GENERATION_REGISTRY_SCHEMA,
        };
        let new_document = GenerationRegistryDocument {
            kind: GENERATION_REGISTRY_KIND.to_owned(),
            roots: BTreeMap::from([(
                "launcher-sample-app".to_owned(),
                StoredGeneration {
                    digest: "42".repeat(32),
                    generation: 7,
                },
            )]),
            schema: GENERATION_REGISTRY_SCHEMA,
        };
        let old_bytes = canonical_json(&serde_json::to_value(old_document).unwrap()).unwrap();
        let new_bytes = canonical_json(&serde_json::to_value(new_document).unwrap()).unwrap();

        for (name, current, temporary, backup, expected_generation) in [
            ("before-backup", Some(&old_bytes), Some(&new_bytes), None, 6),
            (
                "before-activate",
                None,
                Some(&new_bytes),
                Some(&old_bytes),
                7,
            ),
            (
                "before-cleanup",
                Some(&new_bytes),
                None,
                Some(&old_bytes),
                7,
            ),
            ("restore-backup", None, None, Some(&old_bytes), 6),
            ("initial-create", None, Some(&new_bytes), None, 7),
        ] {
            let directory = TempDirectory::create();
            let path = directory.0.join(format!("{name}.json"));
            if let Some(bytes) = current {
                fs::write(&path, bytes).unwrap();
            }
            if let Some(bytes) = temporary {
                fs::write(path.with_extension("new"), bytes).unwrap();
            }
            if let Some(bytes) = backup {
                fs::write(path.with_extension("bak"), bytes).unwrap();
            }

            let recovered = GenerationRegistry::load(&path).unwrap();
            assert_eq!(
                recovered
                    .previous("launcher-sample-app")
                    .unwrap()
                    .unwrap()
                    .generation,
                expected_generation,
                "{name}"
            );
            assert!(!path.with_extension("new").exists(), "{name}");
            assert!(!path.with_extension("bak").exists(), "{name}");
        }
    }

    fn service_state_with_receiver(receiver: Receiver<Result<CommitResult>>) -> ServiceState {
        ServiceState {
            data_directory: PathBuf::new(),
            generation_path: PathBuf::new(),
            generations: GenerationRegistry::default(),
            keyring_path: PathBuf::new(),
            registry_path: PathBuf::new(),
            roots: RootRegistry::new(),
            registry_generation_path: PathBuf::new(),
            registry_generations: GenerationRegistry::default(),
            registry_scope_path: PathBuf::new(),
            registry_scopes: RegistryScopeRegistry::new(),
            registry_transaction_path: PathBuf::new(),
            active_job: Some(ActiveJob {
                job_id: "game-sample-app-7-digest".to_owned(),
                owner_sid: "S-1-5-21-1000".to_owned(),
                state: ActiveJobState::Committing(receiver),
            }),
        }
    }

    #[test]
    fn async_commit_status_repeats_success_after_a_lost_response() {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .send(Ok(CommitResult {
                cleanup_pending: false,
                generation: 7,
                job_id: "game-sample-app-7-digest".to_owned(),
            }))
            .unwrap();
        let mut state = service_state_with_receiver(receiver);
        let response = job_status_response(&mut state, "game-sample-app-7-digest").unwrap();
        assert_eq!(response["state"], "committed");
        assert_eq!(response["completedOperations"], 1);
        assert!(state.active_job.is_some());
        assert_eq!(
            job_status_response(&mut state, "game-sample-app-7-digest").unwrap(),
            response
        );
    }

    #[test]
    fn async_commit_status_reports_completed_rollback() {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .send(Err(MaintenanceError::policy_rejection(
                ErrorCode::TransactionIo,
            )))
            .unwrap();
        let mut state = service_state_with_receiver(receiver);
        let response = job_status_response(&mut state, "game-sample-app-7-digest").unwrap();
        assert_eq!(response["state"], "rolledBack");
        assert_eq!(response["error"], ErrorCode::TransactionIo.as_str());
        assert!(state.active_job.is_some());
        assert_eq!(
            job_status_response(&mut state, "game-sample-app-7-digest").unwrap(),
            response
        );
    }

    #[test]
    fn async_commit_status_never_reports_incomplete_recovery_as_rollback() {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .send(Err(MaintenanceError::policy_rejection(
                ErrorCode::RecoveryIncomplete,
            )))
            .unwrap();
        let mut state = service_state_with_receiver(receiver);
        let response = job_status_response(&mut state, "game-sample-app-7-digest").unwrap();
        assert_eq!(response["state"], "failed");
        assert_eq!(response["error"], ErrorCode::RecoveryIncomplete.as_str());
        assert_eq!(
            job_status_response(&mut state, "game-sample-app-7-digest").unwrap(),
            response
        );
    }

    #[test]
    fn async_commit_status_never_reports_a_lost_worker_as_rollback() {
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(sender);
        let mut state = service_state_with_receiver(receiver);
        let response = job_status_response(&mut state, "game-sample-app-7-digest").unwrap();
        assert_eq!(response["state"], "failed");
        assert_eq!(response["error"], ErrorCode::RecoveryIncomplete.as_str());
    }

    #[test]
    fn authenticode_allowlist_accepts_sha1_or_sha256_only() {
        let sha1 = "1".repeat(40);
        let sha256 = "2".repeat(64);
        assert!(signer_thumbprint_allowed(
            &sha1,
            &sha256,
            std::slice::from_ref(&sha1)
        ));
        assert!(signer_thumbprint_allowed(
            &sha1,
            &sha256,
            std::slice::from_ref(&sha256)
        ));
        assert!(!signer_thumbprint_allowed(
            &sha1,
            &sha256,
            &["3".repeat(64)]
        ));
    }

    #[test]
    fn invalid_installed_keyring_has_recovery_context() {
        let error = installed_keyring_acceptance(b"{}").unwrap_err();

        assert_eq!(error.code(), ErrorCode::JsonInvalid);
        assert!(error.to_string().contains("installed keyring is invalid"));
    }

    #[test]
    fn authenticode_gate_rejects_the_unsigned_test_binary() {
        let executable = std::env::current_exe().unwrap();
        let file = File::open(executable).unwrap();
        let error = verify_authenticode_signer(&file, &["1".repeat(40)]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::TrustSignature);
    }

    #[test]
    fn downloaded_service_setup_must_use_an_absolute_canonical_name() {
        let error =
            verify_service_setup_installer(Path::new("se7en-service-setup.exe")).unwrap_err();
        assert_eq!(error.code(), ErrorCode::StagingInvalid);
    }
}

#[cfg(test)]
mod registry_transaction_tests {
    use super::*;
    use crate::{AllowedRegistryValue, RegistryValueKind};

    fn scope() -> RegisteredRegistryScope {
        RegisteredRegistryScope::new(
            "sample-language",
            "sample-app",
            RegistryView::Registry32,
            r"SOFTWARE\ExampleVendor\SampleApp",
            vec![AllowedRegistryValue {
                name: "Language".to_owned(),
                value_type: RegistryValueKind::String,
            }],
            "S-1-5-21-1000",
        )
        .expect("valid registry scope")
    }

    #[test]
    fn registry_values_have_exact_win32_encodings() {
        let (value_type, bytes) = encoded_registry_value(&RegistryValue::String {
            name: "Language".to_owned(),
            data: "Русский".to_owned(),
        })
        .expect("valid REG_SZ encoding");
        assert_eq!(value_type, REG_SZ);
        let expected = "Русский"
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(bytes, expected);

        let (value_type, bytes) = encoded_registry_value(&RegistryValue::Dword {
            name: "Option".to_owned(),
            data: 0x1234_5678,
        })
        .expect("valid REG_DWORD encoding");
        assert_eq!(value_type, REG_DWORD);
        assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);

        let (value_type, bytes) = encoded_registry_value(&RegistryValue::Binary {
            name: "LanguageToken".to_owned(),
            data: "AQIDAA==".to_owned(),
        })
        .expect("valid REG_BINARY encoding");
        assert_eq!(value_type, REG_BINARY);
        assert_eq!(bytes, [1, 2, 3, 0]);
    }

    #[test]
    fn ipc_error_response_contains_bounded_diagnostic_status() {
        let response = maintenance_error_response(&MaintenanceError::with_platform_status(
            ErrorCode::RegistryScopeUnauthorized,
            "LocalSystem cannot create the bounded HKLM registry scope",
            5,
        ));

        assert_eq!(response["ok"], false);
        assert_eq!(response["error"], "E_REGISTRY_SCOPE_UNAUTHORIZED");
        assert_eq!(
            response["detail"],
            "LocalSystem cannot create the bounded HKLM registry scope"
        );
        assert_eq!(response["win32Status"], 5);
    }

    #[test]
    fn recovery_journal_is_bounded_and_matches_registered_scope() {
        let scope = scope();
        let mut scopes = RegistryScopeRegistry::new();
        scopes.register(scope.clone()).expect("register scope");
        let journal = RegistryTransactionJournal {
            kind: REGISTRY_TRANSACTION_KIND.to_owned(),
            phase: RegistryTransactionPhase::Prepared,
            schema: REGISTRY_TRANSACTION_SCHEMA,
            scope_id: scope.scope_id().to_owned(),
            subkey: scope.subkey().to_owned(),
            values: vec![RegistryTransactionValue {
                name: "Language".to_owned(),
                previous: Some(StoredRegistryValue {
                    data: b"old".to_vec(),
                    value_type: REG_SZ.0,
                }),
            }],
            view: scope.view(),
        };
        assert_eq!(
            validate_registry_transaction(&journal, &scopes)
                .expect("valid journal")
                .scope_id(),
            "sample-language"
        );

        let mut forged = journal;
        forged.values[0].name = "InstallPath".to_owned();
        assert_eq!(
            validate_registry_transaction(&forged, &scopes)
                .expect_err("journal cannot escape the registered allowlist")
                .code(),
            ErrorCode::RecoveryIncomplete
        );
    }
}

#[cfg(test)]
mod windows_transaction_e2e_tests {
    use std::time::SystemTime;

    use super::*;

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn create() -> Self {
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "seven-maintenance-windows-transaction-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temp directory");
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn retained_target_handle_survives_prepare_and_commit_reinspection() {
        let directory = TempDirectory::create();
        let root_path = directory.0.join("root");
        let private_payload = directory.0.join("payload.bin");
        fs::create_dir(&root_path).expect("create root");
        fs::write(root_path.join("obsolete.txt"), b"old").expect("write old target");
        fs::write(&private_payload, b"new").expect("write private payload");

        let root_handle = open_absolute_directory(&root_path, false).expect("open root");
        let canonical = final_path_owned(&root_handle).expect("canonical root");
        let root = RegisteredRoot::from_canonical_identity(
            "e2e-root",
            "e2e-product",
            crate::protocol::RootKind::Game,
            canonical.to_string_lossy(),
            directory_identity(&root_handle).expect("root identity"),
            "S-1-5-21-1000",
        )
        .expect("registered root");
        drop(root_handle);

        let platform = WindowsTransactionPlatform::default();
        platform
            .verify_root_identity(&root)
            .expect("initial root identity");
        assert_eq!(
            platform
                .inspect_target(&root, "nested/created.txt")
                .expect("inspect target below an absent parent"),
            None
        );
        let original = platform
            .inspect_target(&root, "obsolete.txt")
            .expect("initial target inspection")
            .expect("existing target");
        let expected = FileEntry {
            path: "managed.txt".to_owned(),
            sha256: encode_lower_hex(&crate::sha256(b"new")),
            size: 3,
        };
        platform
            .prepare_target_payload(&root, "e2e-job", 0, &private_payload, &expected)
            .expect("prepare same-volume payload");
        platform
            .prepare_target_payload(&root, "e2e-job", 2, &private_payload, &expected)
            .expect("prepare payload for an absent parent");
        platform
            .verify_root_identity(&root)
            .expect("commit root identity");
        assert_eq!(
            platform
                .inspect_target(&root, "obsolete.txt")
                .expect("commit target reinspection"),
            Some(original)
        );
        platform
            .rename_target_to_backup(&root, "e2e-job", 1, "obsolete.txt", original)
            .expect("rename retained target to backup");
        platform
            .rename_prepared_to_target(&root, "e2e-job", 0, "managed.txt")
            .expect("rename prepared payload to target");
        platform
            .rename_prepared_to_target(&root, "e2e-job", 2, "nested/created.txt")
            .expect("create missing target parent during rename");
        assert_eq!(fs::read(root_path.join("managed.txt")).unwrap(), b"new");
        assert_eq!(
            fs::read(root_path.join("nested/created.txt")).unwrap(),
            b"new"
        );
        platform
            .inspect_target(&root, "managed.txt")
            .expect("inspect created target")
            .expect("created target");
        platform
            .delete_target(&root, "managed.txt")
            .expect("delete retained target");
        platform
            .restore_backup(&root, "e2e-job", 1, "obsolete.txt")
            .expect("restore backup");
        assert_eq!(fs::read(root_path.join("obsolete.txt")).unwrap(), b"old");
        platform
            .cleanup_job(&root, "e2e-job", &directory.0.join("private-job"))
            .expect("clean reserved transaction state");
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallerIdentity {
    sid: String,
    elevated_administrator: bool,
}

impl CallerIdentity {
    pub fn new(sid: impl Into<String>, elevated_administrator: bool) -> Result<Self> {
        let sid = sid.into();
        if !valid_sid_text(&sid) {
            return Err(MaintenanceError::new(
                ErrorCode::RootUnauthorized,
                "caller token did not contain a bounded SID",
            ));
        }
        Ok(Self {
            sid,
            elevated_administrator,
        })
    }

    #[must_use]
    pub fn sid(&self) -> &str {
        &self.sid
    }

    #[must_use]
    pub const fn is_elevated_administrator(&self) -> bool {
        self.elevated_administrator
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizedRequest {
    GetStatus,
    GetRootStatus { root: RegisteredRoot },
    GetRegistryScopeStatus { scope: RegisteredRegistryScope },
    RegisterRoot { owner_sid: String },
    UnregisterRoot { root_id: String },
    RegisterRegistryScope { owner_sid: String },
    UnregisterRegistryScope { scope_id: String },
    ApplyRegistrySet { scope: RegisteredRegistryScope },
    PrepareFileSet { root: RegisteredRoot },
    CommitJob { job_id: String },
    GetJobStatus { job_id: String },
}

/// Authorizes an already decoded request. The optional active job is `(job_id, owner_sid)`.
/// Registration is never authorized from caller-supplied ownership data: it binds to the SID from
/// the impersonated elevated token.
pub fn authorize_request(
    request: &Request,
    caller: &CallerIdentity,
    roots: &RootRegistry,
    registry_scopes: &RegistryScopeRegistry,
    active_job: Option<(&str, &str)>,
) -> Result<AuthorizedRequest> {
    match request {
        Request::GetStatus { .. } => Ok(AuthorizedRequest::GetStatus),
        Request::GetRootStatus { root_id, .. } => {
            let root = roots.resolve_accessible(root_id, caller.sid())?.clone();
            Ok(AuthorizedRequest::GetRootStatus { root })
        }
        Request::GetRegistryScopeStatus { scope_id, .. } => {
            let scope = registry_scopes
                .resolve_owned(scope_id, caller.sid())?
                .clone();
            Ok(AuthorizedRequest::GetRegistryScopeStatus { scope })
        }
        Request::RegisterRoot { .. } => {
            require_elevated_administrator(caller)?;
            Ok(AuthorizedRequest::RegisterRoot {
                owner_sid: caller.sid.clone(),
            })
        }
        Request::UnregisterRoot { root_id, .. } => {
            require_elevated_administrator(caller)?;
            Ok(AuthorizedRequest::UnregisterRoot {
                root_id: root_id.clone(),
            })
        }
        Request::RegisterRegistryScope { .. } => {
            require_elevated_administrator(caller)?;
            Ok(AuthorizedRequest::RegisterRegistryScope {
                owner_sid: caller.sid.clone(),
            })
        }
        Request::UnregisterRegistryScope { scope_id, .. } => {
            require_elevated_administrator(caller)?;
            Ok(AuthorizedRequest::UnregisterRegistryScope {
                scope_id: scope_id.clone(),
            })
        }
        Request::ApplyRegistrySet { scope_id, .. } => {
            let scope = registry_scopes
                .resolve_owned(scope_id, caller.sid())?
                .clone();
            Ok(AuthorizedRequest::ApplyRegistrySet { scope })
        }
        Request::PrepareFileSet { root_id, .. } => {
            let root = roots.resolve_accessible(root_id, caller.sid())?.clone();
            Ok(AuthorizedRequest::PrepareFileSet { root })
        }
        Request::CommitJob { job_id, .. } => {
            authorize_owned_job(job_id, caller, active_job)?;
            Ok(AuthorizedRequest::CommitJob {
                job_id: job_id.clone(),
            })
        }
        Request::GetJobStatus { job_id, .. } => {
            authorize_owned_job(job_id, caller, active_job)?;
            Ok(AuthorizedRequest::GetJobStatus {
                job_id: job_id.clone(),
            })
        }
    }
}

fn require_elevated_administrator(caller: &CallerIdentity) -> Result<()> {
    if caller.is_elevated_administrator() {
        Ok(())
    } else {
        Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "setup operation requires an elevated administrator token",
        ))
    }
}

fn authorize_owned_job(
    requested_job_id: &str,
    caller: &CallerIdentity,
    active_job: Option<(&str, &str)>,
) -> Result<()> {
    match active_job {
        Some((job_id, owner_sid)) if job_id == requested_job_id && owner_sid == caller.sid() => {
            Ok(())
        }
        _ => Err(MaintenanceError::new(
            ErrorCode::RootUnauthorized,
            "job is absent or belongs to another caller",
        )),
    }
}

fn valid_sid_text(value: &str) -> bool {
    value.starts_with("S-1-")
        && value.len() <= 184
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
}
