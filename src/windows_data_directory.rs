#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Protected service data directory and the trusted system folders it is derived from.
//!
//! `%ProgramData%` lets every user create subdirectories, so `SE7EN\Service` may already exist
//! when an elevated installer or the LocalSystem service first looks for it. Both directories are
//! accepted only with an administrator owner and a DACL that gives other principals no way to
//! replace, rename, or write into the protected state. Paths come from the known-folder API and
//! HKLM, never from environment variables that a caller can change.

use std::{
    fs::File,
    mem::size_of,
    path::{Path, PathBuf},
    ptr,
};

use windows::{
    Win32::{
        Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree},
        Security::{
            ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT},
            DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl,
            GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, OBJECT_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            PSID, SE_DACL_PROTECTED, SetKernelObjectSecurity, TOKEN_QUERY,
        },
        Storage::FileSystem::{
            CreateDirectoryW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
            WRITE_DAC, WRITE_OWNER,
        },
        System::{
            Com::CoTaskMemFree,
            Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW},
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
        UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
    },
    core::{BOOL, HRESULT, PCWSTR, PWSTR},
};

use super::{
    KernelHandle, LocalSecurityDescriptor, final_path_owned, is_not_found, open_absolute,
    open_absolute_directory, raw_handle, token_is_administrator, token_is_elevated, token_user_sid,
    wide_null,
};
use crate::{ErrorCode, MaintenanceError, Result};

const DATA_PARENT_NAME: &str = "SE7EN";
const DATA_DIRECTORY_NAME: &str = "Service";

/// `SE7EN`: administrators own it; users may only list it.
const DATA_PARENT_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
/// `SE7EN\Service`: only SYSTEM and administrators have any access.
const DATA_DIRECTORY_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

const SYSTEM_SID: &str = "S-1-5-18";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const CREATOR_OWNER_SID: &str = "S-1-3-0";
const CREATOR_GROUP_SID: &str = "S-1-3-1";

const INHERIT_ONLY_ACE: u8 = 0x08;
/// Rights that let a principal rename, delete, re-ACL, or take over the directory itself, or move
/// its children away.
const TAKEOVER_RIGHTS: u32 = 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0200_0000 // MAXIMUM_ALLOWED
    | 0x1000_0000; // GENERIC_ALL
/// Rights that additionally let a principal add or change entries inside the protected state.
const WRITE_RIGHTS: u32 = TAKEOVER_RIGHTS
    | 0x0000_0002 // FILE_ADD_FILE / FILE_WRITE_DATA
    | 0x0000_0004 // FILE_ADD_SUBDIRECTORY / FILE_APPEND_DATA
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x4000_0000; // GENERIC_WRITE

/// Deny, audit, alarm, label, and other non-granting ACE types. Every other type is treated as a
/// grant so that an unknown ACE can only make the check stricter.
const NON_GRANTING_ACE_TYPES: [u8; 17] =
    [1, 2, 3, 6, 7, 8, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21];
/// ACE types whose SID immediately follows the header and access mask.
const SIMPLE_SID_ACE_TYPES: [u8; 3] = [0, 1, 9];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryRole {
    /// `SE7EN`: other principals may add siblings, but must not move `Service` away.
    Parent,
    /// `SE7EN\Service`: other principals must not write at all.
    Data,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AccessEntry {
    ace_type: u8,
    flags: u8,
    mask: u32,
    /// `None` for object ACEs, whose SID is never treated as trusted.
    sid: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectorySecurity {
    owner: String,
    dacl_protected: bool,
    /// `None` is a NULL DACL, which grants everyone full access.
    entries: Option<Vec<AccessEntry>>,
}

fn trusted_owner(sid: &str) -> bool {
    [SYSTEM_SID, ADMINISTRATORS_SID, TRUSTED_INSTALLER_SID].contains(&sid)
}

fn security_error(detail: &'static str) -> MaintenanceError {
    MaintenanceError::new(ErrorCode::RootUnauthorized, detail)
}

/// Accepts a directory only if non-administrators cannot take it over or write into it.
fn check_directory_security(security: &DirectorySecurity, role: DirectoryRole) -> Result<()> {
    if !trusted_owner(&security.owner) {
        return Err(security_error(
            "protected service data directory is owned by a non-administrator",
        ));
    }
    let Some(entries) = &security.entries else {
        return Err(security_error(
            "protected service data directory has a NULL DACL",
        ));
    };
    if role == DirectoryRole::Data && !security.dacl_protected {
        return Err(security_error(
            "protected service data directory inherits permissions from its parent",
        ));
    }
    let forbidden = match role {
        DirectoryRole::Parent => TAKEOVER_RIGHTS,
        DirectoryRole::Data => WRITE_RIGHTS,
    };
    for entry in entries {
        if NON_GRANTING_ACE_TYPES.contains(&entry.ace_type) {
            continue;
        }
        let inherit_only = entry.flags & INHERIT_ONLY_ACE != 0;
        // An inherit-only ACE on the parent never applies to the existing protected child.
        if role == DirectoryRole::Parent && inherit_only {
            continue;
        }
        let trusted = entry.sid.as_deref().is_some_and(|sid| {
            trusted_owner(sid)
                || (inherit_only && (sid == CREATOR_OWNER_SID || sid == CREATOR_GROUP_SID))
        });
        if !trusted && entry.mask & forbidden != 0 {
            return Err(security_error(
                "protected service data directory grants write access to a non-administrator",
            ));
        }
    }
    Ok(())
}

fn sid_text(sid: PSID) -> Result<String> {
    let mut text = PWSTR::null();
    // SAFETY: `sid` points into a live security descriptor or ACL that the caller keeps alive for
    // this synchronous call, and `text` is a valid out pointer.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }
        .map_err(|_| security_error("directory security SID cannot be encoded"))?;
    // SAFETY: ConvertSidToStringSidW returned a NUL-terminated LocalAlloc string.
    let result = unsafe { text.to_string() }
        .map_err(|_| security_error("directory security SID string is invalid"));
    // SAFETY: `text` was allocated by ConvertSidToStringSidW and is freed exactly once.
    let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    result
}

fn access_entries(dacl: *const ACL) -> Result<Vec<AccessEntry>> {
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` is a valid ACL inside a live security descriptor and `information` is a
    // correctly sized out buffer for AclSizeInformation.
    unsafe {
        GetAclInformation(
            dacl,
            ptr::from_mut(&mut information).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX),
            AclSizeInformation,
        )
    }
    .map_err(|_| security_error("directory DACL size cannot be read"))?;
    let mut entries = Vec::new();
    for index in 0..information.AceCount {
        let mut ace = ptr::null_mut();
        // SAFETY: `index` is below the ACL's ACE count and `ace` is a valid out pointer. The
        // returned pointer refers into the same live ACL.
        unsafe { GetAce(dacl, index, &mut ace) }
            .map_err(|_| security_error("directory DACL entry cannot be read"))?;
        let ace = ace.cast::<u8>().cast_const();
        // SAFETY: every ACE starts with ACE_HEADER; the ACL was validated by the security API.
        let header = unsafe { ptr::read_unaligned(ace.cast::<ACE_HEADER>()) };
        let size = usize::from(header.AceSize);
        if size < 8 {
            return Err(security_error("directory DACL entry is truncated"));
        }
        // SAFETY: the ACE is at least eight bytes long and its access mask follows the header.
        let mask = unsafe { ptr::read_unaligned(ace.add(4).cast::<u32>()) };
        let sid = if SIMPLE_SID_ACE_TYPES.contains(&header.AceType) {
            // The smallest valid SID has eight bytes.
            if size < 16 {
                return Err(security_error("directory DACL entry has no SID"));
            }
            // SAFETY: simple ACE types store their SID at offset eight, inside the ACE.
            Some(sid_text(PSID(unsafe { ace.add(8) }.cast_mut().cast()))?)
        } else {
            None
        };
        entries.push(AccessEntry {
            ace_type: header.AceType,
            flags: header.AceFlags,
            mask,
            sid,
        });
    }
    Ok(entries)
}

/// Reads the owner and DACL of a live security descriptor.
fn security_from_descriptor(descriptor: PSECURITY_DESCRIPTOR) -> Result<DirectorySecurity> {
    let mut owner = PSID::default();
    let mut defaulted = BOOL(0);
    // SAFETY: the descriptor is live and both out pointers are valid.
    unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) }
        .map_err(|_| security_error("directory owner cannot be read"))?;
    if owner.is_invalid() {
        return Err(security_error("directory has no owner"));
    }
    let owner = sid_text(owner)?;

    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: the descriptor is live and both out pointers are valid.
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
        .map_err(|_| security_error("directory security control cannot be read"))?;

    let mut present = BOOL(0);
    let mut dacl = ptr::null_mut::<ACL>();
    // SAFETY: the descriptor is live and all out pointers are valid. The DACL pointer refers into
    // the descriptor and is used only while the descriptor is alive.
    unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        .map_err(|_| security_error("directory DACL cannot be read"))?;
    let entries = if present.as_bool() && !dacl.is_null() {
        Some(access_entries(dacl)?)
    } else {
        None
    };
    Ok(DirectorySecurity {
        owner,
        dacl_protected: control & SE_DACL_PROTECTED.0 != 0,
        entries,
    })
}

fn directory_security(directory: &File) -> Result<DirectorySecurity> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the handle was opened with READ_CONTROL. Only the self-relative descriptor is
    // requested; it is LocalAlloc-owned and freed below after it has been read.
    let status = unsafe {
        GetSecurityInfo(
            raw_handle(directory),
            SE_FILE_OBJECT,
            OBJECT_SECURITY_INFORMATION(OWNER_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0),
            None,
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_invalid() {
        return Err(security_error("directory security cannot be read"));
    }
    let security = security_from_descriptor(descriptor);
    // SAFETY: GetSecurityInfo allocated the descriptor with LocalAlloc; it is freed exactly once.
    let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    security
}

/// `%ProgramData%` from the known-folder database, independent of the caller's environment.
pub(super) fn program_data_root() -> Result<PathBuf> {
    // SAFETY: the GUID is a static constant. On success the returned string is CoTaskMem-owned
    // and freed below exactly once.
    let text = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
        .map_err(|_| {
            MaintenanceError::new(ErrorCode::TransactionState, "ProgramData is unavailable")
        })?;
    // SAFETY: SHGetKnownFolderPath returned a NUL-terminated string.
    let path = unsafe { text.to_string() };
    // SAFETY: the string was allocated with CoTaskMemAlloc and is freed exactly once.
    unsafe { CoTaskMemFree(Some(text.0.cast_const().cast())) };
    absolute_system_folder(path.ok(), "ProgramData is not an absolute path")
}

/// The native `Program Files` folder from the 64-bit registry view.
pub(super) fn program_files_root() -> Result<PathBuf> {
    let subkey = wide_null(r"SOFTWARE\Microsoft\Windows\CurrentVersion");
    let value = wide_null("ProgramFilesDir");
    let mut buffer = vec![0_u16; 1024];
    let mut bytes = u32::try_from(buffer.len() * size_of::<u16>()).unwrap_or(u32::MAX);
    // SAFETY: the key and value names are NUL-terminated, and `buffer` is writable for `bytes`.
    // RRF_RT_REG_SZ makes RegGetValueW return a NUL-terminated string. On 32-bit Windows the
    // 64-bit view flag is ignored and the only view is native.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut bytes),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(MaintenanceError::new(
            ErrorCode::TransactionState,
            "Program Files is unavailable",
        ));
    }
    let length = buffer.iter().position(|unit| *unit == 0).unwrap_or(0);
    let path = String::from_utf16(&buffer[..length]).ok();
    absolute_system_folder(path, "Program Files is not an absolute path")
}

fn absolute_system_folder(path: Option<String>, detail: &'static str) -> Result<PathBuf> {
    let path = PathBuf::from(path.unwrap_or_default());
    if path.is_absolute() && path.parent().is_some() {
        Ok(path)
    } else {
        Err(MaintenanceError::new(ErrorCode::TransactionState, detail))
    }
}

pub(super) fn service_data_directory() -> Result<PathBuf> {
    Ok(program_data_root()?
        .join(DATA_PARENT_NAME)
        .join(DATA_DIRECTORY_NAME))
}

/// Open handles to `SE7EN` and `SE7EN\Service`. Neither handle shares delete access, so neither
/// directory can be renamed or replaced while this value is alive.
pub(super) struct ProtectedDataDirectory {
    _parent: File,
    _directory: File,
    path: PathBuf,
}

impl ProtectedDataDirectory {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

fn open_directory(
    path: &Path,
    modify_security: bool,
) -> std::result::Result<File, windows::core::Error> {
    let access = FILE_READ_ATTRIBUTES.0
        | READ_CONTROL.0
        | if modify_security {
            WRITE_DAC.0 | WRITE_OWNER.0
        } else {
            0
        };
    open_absolute(
        path,
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
}

fn open_existing_directory(path: &Path, modify_security: bool) -> Result<Option<File>> {
    match open_directory(path, modify_security) {
        Ok(directory) => {
            super::ensure_safe_directory(&directory)?;
            Ok(Some(directory))
        }
        Err(error) if is_not_found(&error) => Ok(None),
        Err(_) => Err(MaintenanceError::new(
            ErrorCode::RootIdentity,
            "protected service data directory cannot be opened safely",
        )),
    }
}

fn ensure_final_path(directory: &File, expected: &Path) -> Result<()> {
    let actual = final_path_owned(directory)?;
    let actual = actual.to_string_lossy();
    let actual = actual.strip_prefix(r"\\?\").unwrap_or(&actual);
    if actual.eq_ignore_ascii_case(&expected.to_string_lossy()) {
        Ok(())
    } else {
        Err(MaintenanceError::new(
            ErrorCode::RootIdentity,
            "protected service data directory resolved to a different location",
        ))
    }
}

/// Opens the existing directories and verifies their owner and DACL. Used by the LocalSystem
/// service before it reads any protected state and by the installer for an installed service.
pub(super) fn open_service_data_directory() -> Result<ProtectedDataDirectory> {
    let parent_path = program_data_root()?.join(DATA_PARENT_NAME);
    let path = parent_path.join(DATA_DIRECTORY_NAME);
    let missing = || {
        MaintenanceError::new(
            ErrorCode::TransactionState,
            "protected service data directory is missing",
        )
    };
    let parent = open_existing_directory(&parent_path, false)?.ok_or_else(missing)?;
    check_directory_security(&directory_security(&parent)?, DirectoryRole::Parent)?;
    let directory = open_existing_directory(&path, false)?.ok_or_else(missing)?;
    check_directory_security(&directory_security(&directory)?, DirectoryRole::Data)?;
    ensure_final_path(&directory, &path)?;
    Ok(ProtectedDataDirectory {
        _parent: parent,
        _directory: directory,
        path,
    })
}

/// Creates or hardens `SE7EN` and `SE7EN\Service`. Requires an elevated administrator.
///
/// A missing directory is created with an explicit administrator owner and protected DACL. An
/// existing directory is accepted only when an administrator owns it and no other principal can
/// take it over; its DACL is then reset to the protected form. A directory owned by the elevated
/// caller's own account is first given to `BUILTIN\Administrators`.
pub(super) fn provision_service_data_directory() -> Result<ProtectedDataDirectory> {
    let program_data = program_data_root()?;
    let _program_data = open_absolute_directory(&program_data, false)?;
    let parent_path = program_data.join(DATA_PARENT_NAME);
    let path = parent_path.join(DATA_DIRECTORY_NAME);
    let installer_sid = elevated_installer_sid()?;
    let parent = provision_directory(
        &parent_path,
        DATA_PARENT_SDDL,
        DirectoryRole::Parent,
        &installer_sid,
    )?;
    let directory = provision_directory(
        &path,
        DATA_DIRECTORY_SDDL,
        DirectoryRole::Data,
        &installer_sid,
    )?;
    ensure_final_path(&directory, &path)?;
    drop(directory);
    drop(parent);
    open_service_data_directory()
}

fn elevated_installer_sid() -> Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; `token` is a valid out pointer and the
    // returned token handle is owned by KernelHandle.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | windows::Win32::Security::TOKEN_DUPLICATE,
            &mut token,
        )
    }
    .map_err(|_| security_error("installer token cannot be opened"))?;
    let token = KernelHandle::new(
        token,
        ErrorCode::RootUnauthorized,
        "installer token is invalid",
    )?;
    if !token_is_elevated(token.raw())? || !token_is_administrator(token.raw())? {
        return Err(security_error(
            "protected service data directory requires an elevated administrator",
        ));
    }
    token_user_sid(token.raw())
}

fn provision_directory(
    path: &Path,
    sddl: &str,
    role: DirectoryRole,
    installer_sid: &str,
) -> Result<File> {
    let mut descriptor = LocalSecurityDescriptor::parse(sddl)?;
    if open_existing_directory(path, true)?.is_none() {
        let wide = wide_null(path.as_os_str().to_string_lossy().as_ref());
        let attributes = descriptor.attributes();
        // SAFETY: the path is NUL-terminated and the security attributes and descriptor outlive
        // this synchronous call. The descriptor sets an administrator owner and protected DACL.
        match unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&attributes)) } {
            Ok(()) => {}
            // Another process created it first; it is verified below like any existing directory.
            Err(error) if error.code() == HRESULT::from_win32(ERROR_ALREADY_EXISTS.0) => {}
            Err(_) => {
                return Err(MaintenanceError::new(
                    ErrorCode::TransactionIo,
                    "protected service data directory cannot be created",
                ));
            }
        }
    }
    let directory = open_existing_directory(path, true)?.ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::RootIdentity,
            "created service data directory cannot be opened",
        )
    })?;
    let mut security = directory_security(&directory)?;
    let mut information = DACL_SECURITY_INFORMATION.0 | PROTECTED_DACL_SECURITY_INFORMATION.0;
    if security.owner == installer_sid {
        // The "object creator" owner policy gives new objects to the administrator's account.
        security.owner = ADMINISTRATORS_SID.to_owned();
        information |= OWNER_SECURITY_INFORMATION.0;
    }
    check_directory_security(&security, role)?;
    // SAFETY: the handle was opened with WRITE_DAC and WRITE_OWNER, and the parsed descriptor is
    // live for this synchronous call. SetKernelObjectSecurity changes only this directory and does
    // not traverse or re-ACL existing children.
    unsafe {
        SetKernelObjectSecurity(
            raw_handle(&directory),
            OBJECT_SECURITY_INFORMATION(information),
            descriptor.raw(),
        )
    }
    .map_err(|_| security_error("protected service data directory DACL cannot be applied"))?;
    check_directory_security(&directory_security(&directory)?, role)?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    fn security(sddl: &str) -> DirectorySecurity {
        let descriptor = LocalSecurityDescriptor::parse(sddl).expect("valid test SDDL");
        security_from_descriptor(descriptor.raw()).expect("readable test descriptor")
    }

    fn data(sddl: &str) -> Result<()> {
        check_directory_security(&security(sddl), DirectoryRole::Data)
    }

    fn parent(sddl: &str) -> Result<()> {
        check_directory_security(&security(sddl), DirectoryRole::Parent)
    }

    #[test]
    fn installed_directories_are_accepted() {
        // Security of SE7EN and SE7EN\Service created by releases up to 1.0.2.
        data("O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").unwrap();
        parent(
            "O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)\
             (A;OICIID;0x1200a9;;;BU)(A;CIID;0x116;;;BU)",
        )
        .unwrap();
        data(DATA_DIRECTORY_SDDL).unwrap();
        parent(DATA_PARENT_SDDL).unwrap();
        data("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)").unwrap();
        data(&format!(
            "O:{TRUSTED_INSTALLER_SID}D:P(A;;FA;;;SY)(D;;FA;;;BU)"
        ))
        .unwrap();
    }

    #[test]
    fn user_owned_or_writable_directories_are_rejected() {
        let user = "S-1-5-21-1000000000-2000000000-3000000000-1001";
        let rejected = [
            // A user created the directory before the installer.
            format!("O:{user}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
            // Everyone has full access through a NULL DACL.
            "O:BAD:NO_ACCESS_CONTROL".to_owned(),
            // Users may add files or subdirectories.
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x2;;;BU)".to_owned(),
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x4;;;AU)".to_owned(),
            // Users may change the DACL of new children.
            format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICIIO;GA;;;{user})"),
            // The DACL follows the user-writable ProgramData parent.
            "O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)".to_owned(),
            // Generic rights are not expanded by the check.
            "O:BAD:P(A;;GW;;;WD)".to_owned(),
            "O:BAD:P(A;;GA;;;IU)".to_owned(),
        ];
        for sddl in rejected {
            let error = data(&sddl).expect_err(&sddl);
            assert_eq!(error.code(), ErrorCode::RootUnauthorized, "{sddl}");
        }
    }

    #[test]
    fn parent_rejects_rights_that_move_the_protected_child() {
        let user = "S-1-5-21-1000000000-2000000000-3000000000-1001";
        for sddl in [
            format!("O:{user}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
            "O:BAD:P(A;OICI;FA;;;SY)(A;CI;0x40;;;BU)".to_owned(),
            "O:BAD:P(A;OICI;FA;;;SY)(A;;0x10000;;;BU)".to_owned(),
            "O:BAD:P(A;OICI;FA;;;SY)(A;;WD;;;BU)".to_owned(),
            "O:BAD:P(A;OICI;FA;;;SY)(A;;WO;;;BU)".to_owned(),
            "O:BAD:NO_ACCESS_CONTROL".to_owned(),
        ] {
            assert!(parent(&sddl).is_err(), "{sddl}");
        }
        // Adding sibling directories does not affect SE7EN\Service.
        parent("O:BAD:(A;OICI;FA;;;SY)(A;CI;0x116;;;BU)(A;OICIIO;GA;;;CO)").unwrap();
    }

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn a_directory_created_by_the_test_user_is_not_trusted() {
        let path = env::temp_dir().join(format!(
            "se7en-data-directory-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let result = open_existing_directory(&path, false)
            .and_then(|directory| directory.ok_or_else(|| security_error("missing")))
            .and_then(|directory| directory_security(&directory))
            .and_then(|security| check_directory_security(&security, DirectoryRole::Data));
        fs::remove_dir(&path).unwrap();
        assert_eq!(result.unwrap_err().code(), ErrorCode::RootUnauthorized);
    }

    #[test]
    fn system_folders_do_not_come_from_the_environment() {
        let program_data = program_data_root().unwrap();
        let program_files = program_files_root().unwrap();
        assert!(program_data.is_dir(), "{}", program_data.display());
        assert!(program_files.is_dir(), "{}", program_files.display());
        assert_eq!(
            service_data_directory().unwrap(),
            program_data.join("SE7EN").join("Service")
        );
        if let Some(native) = env::var_os("ProgramW6432").or_else(|| env::var_os("ProgramFiles")) {
            assert!(program_files.as_os_str().eq_ignore_ascii_case(&native));
        }

        // A child process with a forged environment still resolves the real folders.
        let output = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::data_directory::tests::system_folders_child",
                "--nocapture",
            ])
            .env("SE7EN_SYSTEM_FOLDERS_CHILD", "1")
            .env("ProgramData", r"C:\Users\Public\Forged")
            .env("ProgramW6432", r"C:\Users\Public\Forged")
            .env("ProgramFiles", r"C:\Users\Public\Forged")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{stdout}");
        assert!(
            stdout.contains(&format!(
                "folders={}|{}",
                program_data.display(),
                program_files.display()
            )),
            "{stdout}"
        );
    }

    #[test]
    fn system_folders_child() {
        if env::var("SE7EN_SYSTEM_FOLDERS_CHILD").as_deref() == Ok("1") {
            println!(
                "folders={}|{}",
                program_data_root().unwrap().display(),
                program_files_root().unwrap().display()
            );
        }
    }
}
