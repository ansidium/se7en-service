#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::{
    AllowedRegistryValue, ErrorCode, MAX_IPC_MESSAGE_BYTES, MAX_PATH_BYTES, MaintenanceError,
    RegistryView, Result, registry_set::validate_allowed_registry_values, valid_identifier,
    valid_job_identifier,
};

pub const PROTOCOL_MAJOR: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RootKind {
    Launcher,
    Game,
    Library,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", deny_unknown_fields)]
pub enum Request {
    GetStatus {
        #[serde(rename = "protocolMajor")]
        protocol_major: u16,
    },
    GetRootStatus {
        #[serde(rename = "protocolMajor")]
        protocol_major: u16,
        #[serde(rename = "rootId")]
        root_id: String,
    },
    GetRegistryScopeStatus {
        #[serde(rename = "protocolMajor")]
        protocol_major: u16,
        #[serde(rename = "scopeId")]
        scope_id: String,
    },
    RegisterRoot {
        #[serde(rename = "protocolMajor")]
        protocol_major: u16,
        #[serde(rename = "rootId")]
        root_id: String,
        #[serde(rename = "productId")]
        product_id: String,
        #[serde(rename = "rootKind")]
        root_kind: RootKind,
        path: String,
    },
    UnregisterRoot {
        #[serde(rename = "protocolMajor")]
        protocol_major: u16,
        #[serde(rename = "rootId")]
        root_id: String,
    },
    RegisterRegistryScope {
        #[serde(rename = "protocolMajor")]
        protocol_major: u16,
        #[serde(rename = "scopeId")]
        scope_id: String,
        #[serde(rename = "productId")]
        product_id: String,
        view: RegistryView,
        subkey: String,
        #[serde(rename = "allowedValues")]
        allowed_values: Vec<AllowedRegistryValue>,
    },
    UnregisterRegistryScope {
        #[serde(rename = "protocolMajor")]
        protocol_major: u16,
        #[serde(rename = "scopeId")]
        scope_id: String,
    },
    ApplyRegistrySet {
        #[serde(rename = "protocolMajor")]
        protocol_major: u16,
        #[serde(rename = "scopeId")]
        scope_id: String,
        #[serde(rename = "manifestPath")]
        manifest_path: String,
    },
    PrepareFileSet {
        #[serde(rename = "protocolMajor")]
        protocol_major: u16,
        #[serde(rename = "rootId")]
        root_id: String,
        #[serde(rename = "manifestPath")]
        manifest_path: String,
        #[serde(rename = "stagingPath")]
        staging_path: String,
    },
    CommitJob {
        #[serde(rename = "protocolMajor")]
        protocol_major: u16,
        #[serde(rename = "jobId")]
        job_id: String,
    },
    GetJobStatus {
        #[serde(rename = "protocolMajor")]
        protocol_major: u16,
        #[serde(rename = "jobId")]
        job_id: String,
    },
}

impl Request {
    const fn protocol_major(&self) -> u16 {
        match self {
            Self::GetStatus { protocol_major }
            | Self::GetRootStatus { protocol_major, .. }
            | Self::GetRegistryScopeStatus { protocol_major, .. }
            | Self::RegisterRoot { protocol_major, .. }
            | Self::UnregisterRoot { protocol_major, .. }
            | Self::RegisterRegistryScope { protocol_major, .. }
            | Self::UnregisterRegistryScope { protocol_major, .. }
            | Self::ApplyRegistrySet { protocol_major, .. }
            | Self::PrepareFileSet { protocol_major, .. }
            | Self::CommitJob { protocol_major, .. }
            | Self::GetJobStatus { protocol_major, .. } => *protocol_major,
        }
    }
}

pub fn decode_request(bytes: &[u8]) -> Result<Request> {
    if bytes.len() > MAX_IPC_MESSAGE_BYTES {
        return Err(MaintenanceError::new(
            ErrorCode::ProtocolTooLarge,
            "IPC message exceeds 64 KiB",
        ));
    }
    let request: Request = serde_json::from_slice(bytes).map_err(|_| {
        MaintenanceError::new(
            ErrorCode::ProtocolInvalid,
            "IPC message is not a supported strict request",
        )
    })?;
    if request.protocol_major() != PROTOCOL_MAJOR {
        return Err(MaintenanceError::new(
            ErrorCode::ProtocolVersion,
            "IPC protocol major is unsupported",
        ));
    }
    validate_request(&request)?;
    Ok(request)
}

fn validate_request(request: &Request) -> Result<()> {
    match request {
        Request::GetStatus { .. } => Ok(()),
        Request::GetRootStatus { root_id, .. } => validate_id(root_id),
        Request::GetRegistryScopeStatus { scope_id, .. } => validate_id(scope_id),
        Request::RegisterRoot {
            root_id,
            product_id,
            path,
            ..
        } => {
            validate_id(root_id)?;
            validate_id(product_id)?;
            validate_client_path(path)?;
            Ok(())
        }
        Request::UnregisterRoot { root_id, .. } => validate_id(root_id),
        Request::RegisterRegistryScope {
            scope_id,
            product_id,
            subkey,
            allowed_values,
            ..
        } => {
            validate_id(scope_id)?;
            validate_id(product_id)?;
            validate_client_path(subkey)?;
            validate_allowed_registry_values(allowed_values)
        }
        Request::UnregisterRegistryScope { scope_id, .. } => validate_id(scope_id),
        Request::ApplyRegistrySet {
            scope_id,
            manifest_path,
            ..
        } => {
            validate_id(scope_id)?;
            validate_client_path(manifest_path)
        }
        Request::PrepareFileSet {
            root_id,
            manifest_path,
            staging_path,
            ..
        } => {
            validate_id(root_id)?;
            validate_client_path(manifest_path)?;
            validate_client_path(staging_path)
        }
        Request::CommitJob { job_id, .. } | Request::GetJobStatus { job_id, .. } => {
            validate_job_id(job_id)
        }
    }
}

fn validate_job_id(value: &str) -> Result<()> {
    if valid_job_identifier(value) {
        Ok(())
    } else {
        Err(MaintenanceError::new(
            ErrorCode::ProtocolInvalid,
            "IPC job identifier is invalid",
        ))
    }
}

fn validate_id(value: &str) -> Result<()> {
    if valid_identifier(value) {
        Ok(())
    } else {
        Err(MaintenanceError::new(
            ErrorCode::ProtocolInvalid,
            "IPC identifier is invalid",
        ))
    }
}

fn validate_client_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.chars().any(|character| character == '\0')
    {
        Err(MaintenanceError::new(
            ErrorCode::ProtocolInvalid,
            "IPC client path is invalid",
        ))
    } else {
        Ok(())
    }
}
