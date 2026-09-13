#![forbid(unsafe_code)]

#[cfg(windows)]
mod windows_client {
    use std::{
        ffi::OsString,
        fs::{self, File, OpenOptions},
        io::{self, BufReader, Write},
        path::{Component, Path, PathBuf},
        process::Command,
        thread,
        time::{Duration, Instant},
    };

    use seven_launcher_maintenance::{
        AllowedRegistryValue, MaintenanceError, RegistryValueKind, RegistryView,
        protocol::{Request, RootKind},
        service_upgrade::ServiceVersion,
        windows::{
            LauncherProcess, call_shared_service, confirm_and_elevate_service_removal,
            ensure_system_service, remove_system_service, signal_launcher_ready,
            verify_service_bundle, verify_service_setup_installer,
        },
    };

    const ENSURE_SERVICE_DIAGNOSTIC_FILE: &str = "SE7ENService-ensure-service.log";
    const SERVICE_SETUP_PACKAGE_NAME: &str = "se7en-service-setup.exe.lzma";
    const SERVICE_SETUP_NAME: &str = "se7en-service-setup.exe";
    const SERVICE_SETUP_TEMP_NAME: &str = "se7en-service-setup.exe.unpacking";
    const MAX_PACKED_SETUP_BYTES: u64 = 32 * 1024 * 1024;
    const MAX_UNPACKED_SETUP_BYTES: usize = 64 * 1024 * 1024;
    const MAX_LZMA_DICTIONARY_BYTES: usize = 64 * 1024 * 1024;

    struct BoundedWriter<W> {
        inner: W,
        written: usize,
        maximum: usize,
    }

    impl<W> BoundedWriter<W> {
        const fn new(inner: W, maximum: usize) -> Self {
            Self {
                inner,
                written: 0,
                maximum,
            }
        }

        fn into_parts(self) -> (W, usize) {
            (self.inner, self.written)
        }
    }

    impl<W: Write> Write for BoundedWriter<W> {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if buffer.len() > self.maximum.saturating_sub(self.written) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decompressed service setup exceeds the size limit",
                ));
            }
            let count = self.inner.write(buffer)?;
            self.written += count;
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    pub fn run() -> std::result::Result<(), String> {
        let mut arguments = std::env::args_os().skip(1);
        let command = required(&mut arguments, "command")?;
        let request = match command.to_str() {
            Some("status") => Some(Request::GetStatus { protocol_major: 1 }),
            Some("root-status") => {
                let root_id = required_text(&mut arguments, "root ID")?;
                ensure_finished(arguments)?;
                Some(Request::GetRootStatus {
                    protocol_major: 1,
                    root_id,
                })
            }
            Some("registry-scope-status") => {
                let scope_id = required_text(&mut arguments, "registry scope ID")?;
                ensure_finished(arguments)?;
                Some(Request::GetRegistryScopeStatus {
                    protocol_major: 1,
                    scope_id,
                })
            }
            Some("register-root") => {
                let root_id = required_text(&mut arguments, "root ID")?;
                let product_id = required_text(&mut arguments, "product ID")?;
                let root_kind = match required_text(&mut arguments, "root kind")?.as_str() {
                    "launcher" => RootKind::Launcher,
                    "game" => RootKind::Game,
                    "library" => RootKind::Library,
                    _ => return Err("root kind must be launcher, game, or library".to_owned()),
                };
                let path = required_path(&mut arguments, "root path")?;
                ensure_finished(arguments)?;
                Some(Request::RegisterRoot {
                    protocol_major: 1,
                    root_id,
                    product_id,
                    root_kind,
                    path: path_to_text(path)?,
                })
            }
            Some("unregister-root") => {
                let root_id = required_text(&mut arguments, "root ID")?;
                ensure_finished(arguments)?;
                Some(Request::UnregisterRoot {
                    protocol_major: 1,
                    root_id,
                })
            }
            Some("register-registry-scope") => {
                let scope_id = required_text(&mut arguments, "registry scope ID")?;
                let product_id = required_text(&mut arguments, "product ID")?;
                let view = match required_text(&mut arguments, "registry view")?.as_str() {
                    "registry32" => RegistryView::Registry32,
                    "registry64" => RegistryView::Registry64,
                    _ => return Err("registry view must be registry32 or registry64".to_owned()),
                };
                let subkey = required_text(&mut arguments, "HKLM SOFTWARE subkey")?;
                let mut allowed_values = Vec::new();
                while let Some(name) = arguments.next() {
                    let name = name
                        .into_string()
                        .map_err(|_| "registry value name must be Unicode".to_owned())?;
                    let value_type =
                        match required_text(&mut arguments, "registry value type")?.as_str() {
                            "string" => RegistryValueKind::String,
                            "dword" => RegistryValueKind::Dword,
                            "binary" => RegistryValueKind::Binary,
                            _ => {
                                return Err("registry value type must be string, dword, or binary"
                                    .to_owned());
                            }
                        };
                    allowed_values.push(AllowedRegistryValue { name, value_type });
                }
                if allowed_values.is_empty() {
                    return Err("registry scope requires at least one name/type pair".to_owned());
                }
                Some(Request::RegisterRegistryScope {
                    protocol_major: 1,
                    scope_id,
                    product_id,
                    view,
                    subkey,
                    allowed_values,
                })
            }
            Some("unregister-registry-scope") => {
                let scope_id = required_text(&mut arguments, "registry scope ID")?;
                ensure_finished(arguments)?;
                Some(Request::UnregisterRegistryScope {
                    protocol_major: 1,
                    scope_id,
                })
            }
            Some("apply-registry-set") => {
                let scope_id = required_text(&mut arguments, "registry scope ID")?;
                let manifest_path =
                    path_to_text(required_path(&mut arguments, "RegistrySet manifest path")?)?;
                ensure_finished(arguments)?;
                Some(Request::ApplyRegistrySet {
                    protocol_major: 1,
                    scope_id,
                    manifest_path,
                })
            }
            Some("prepare") => {
                let root_id = required_text(&mut arguments, "root ID")?;
                let manifest_path = path_to_text(required_path(&mut arguments, "manifest path")?)?;
                let staging_path = path_to_text(required_path(&mut arguments, "staging path")?)?;
                ensure_finished(arguments)?;
                Some(Request::PrepareFileSet {
                    protocol_major: 1,
                    root_id,
                    manifest_path,
                    staging_path,
                })
            }
            Some("commit") => {
                let job_id = required_text(&mut arguments, "job ID")?;
                ensure_finished(arguments)?;
                Some(Request::CommitJob {
                    protocol_major: 1,
                    job_id,
                })
            }
            Some("job-status") => {
                let job_id = required_text(&mut arguments, "job ID")?;
                ensure_finished(arguments)?;
                Some(Request::GetJobStatus {
                    protocol_major: 1,
                    job_id,
                })
            }
            Some("wait-commit-restart") => {
                let process_id = required_text(&mut arguments, "Launcher PID")?
                    .parse::<u32>()
                    .map_err(|_| "Launcher PID must be an unsigned integer".to_owned())?;
                let job_id = required_text(&mut arguments, "job ID")?;
                let restart = required_path(&mut arguments, "registered Launcher path")?;
                let ready_event = arguments
                    .next()
                    .map(|value| value.into_string())
                    .transpose()
                    .map_err(|_| "ready event must be Unicode".to_owned())?;
                ensure_finished(arguments)?;
                validate_restart_executable(&restart)?;
                let process = LauncherProcess::open(process_id).map_err(display_error)?;
                let status_request = Request::GetJobStatus {
                    protocol_major: 1,
                    job_id: job_id.clone(),
                };
                if call_checked(&status_request)?
                    .get("state")
                    .and_then(serde_json::Value::as_str)
                    != Some("prepared")
                {
                    return Err("maintenance job is not prepared for handoff".to_owned());
                }
                if let Some(event) = ready_event {
                    signal_launcher_ready(&event).map_err(display_error)?;
                }
                let shutdown_started = Instant::now();
                while !process
                    .wait(Duration::from_secs(5))
                    .map_err(display_error)?
                {
                    if shutdown_started.elapsed() >= Duration::from_secs(120) {
                        return Err("Launcher did not exit before the handoff deadline".to_owned());
                    }
                    // Keep the prepared job alive during a slow Launcher shutdown. No commit
                    // may be sent while its process handle is still unsignaled.
                    let _ = call_checked(&status_request);
                }
                // No Commit has been sent yet. If the service disappeared during shutdown,
                // the old Launcher is still the safe executable and may be reopened.
                let status = match call_checked(&status_request) {
                    Ok(status) => status,
                    Err(error) => {
                        restart_launcher(&restart)?;
                        return Err(format!(
                            "maintenance unavailable before commit; old Launcher restarted: {error}"
                        ));
                    }
                };
                let response = if status.get("state").and_then(serde_json::Value::as_str)
                    == Some("prepared")
                {
                    commit_after_launcher_exit(&job_id, call_checked)?
                } else {
                    wait_for_job_completion(&job_id, Ok(status), call_checked)?
                };
                // Restart the registered Launcher after either a completed commit or a completed
                // rollback, or a confirmed refusal before Commit started. An ambiguous or failed
                // recovery must never execute a possibly incomplete Launcher.
                restart_launcher(&restart)?;
                if response.get("state").and_then(serde_json::Value::as_str) != Some("committed") {
                    return Err(format!(
                        "maintenance update did not commit; original Launcher restarted: {}",
                        response
                            .get("error")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("E_TRANSACTION_STATE")
                    ));
                }
                print_response(&response)?;
                None
            }
            Some("ensure-service") => {
                let bundle_root = required_path(&mut arguments, "service bundle directory")?;
                let manifest = required_path(&mut arguments, "service FileSet manifest")?;
                let keyring = required_path(&mut arguments, "signed keyring")?;
                ensure_finished(arguments)?;
                let outcome = match ensure_system_service(&bundle_root, &manifest, &keyring) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        let diagnostic = display_error(error);
                        write_ensure_service_diagnostic(&bundle_root, &diagnostic);
                        return Err(diagnostic);
                    }
                };
                let response = format!(
                    r#"{{"ok":true,"protocolMajor":1,"serviceVersion":"{}","state":"{}"}}"#,
                    env!("CARGO_PKG_VERSION"),
                    outcome.as_str()
                );
                write_ensure_service_diagnostic(&bundle_root, &response);
                println!("{response}");
                None
            }
            Some("service-compatible") => {
                ensure_finished(arguments)?;
                let response = call_checked(&Request::GetStatus { protocol_major: 1 })?;
                ensure_service_compatible(&response)?;
                print_response(&response)?;
                None
            }
            Some("verify-service-setup") => {
                let setup = required_path(&mut arguments, "service setup path")?;
                ensure_finished(arguments)?;
                let sha256 = verify_service_setup_installer(&setup).map_err(display_error)?;
                println!(
                    r#"{{"ok":true,"serviceVersion":"{}","sha256":"{}"}}"#,
                    env!("CARGO_PKG_VERSION"),
                    sha256
                );
                None
            }
            Some("verify-service-bundle") => {
                let bundle_root = required_path(&mut arguments, "service bundle directory")?;
                let manifest = required_path(&mut arguments, "service FileSet manifest")?;
                let keyring = required_path(&mut arguments, "signed keyring")?;
                ensure_finished(arguments)?;
                let evidence = verify_service_bundle(&bundle_root, &manifest, &keyring)
                    .map_err(display_error)?;
                println!(
                    r#"{{"ok":true,"serviceVersion":"{}","generation":{},"size":{},"sha256":"{}"}}"#,
                    env!("CARGO_PKG_VERSION"),
                    evidence.generation,
                    evidence.size,
                    evidence.sha256
                );
                None
            }
            Some("unpack-service-setup") => {
                let package = required_path(&mut arguments, "service setup package path")?;
                let setup = required_path(&mut arguments, "service setup output path")?;
                ensure_finished(arguments)?;
                unpack_service_setup_package(&package, &setup)?;
                let sha256 = match verify_service_setup_installer(&setup) {
                    Ok(sha256) => sha256,
                    Err(error) => {
                        let _ = fs::remove_file(&setup);
                        return Err(display_error(error));
                    }
                };
                println!(
                    r#"{{"ok":true,"serviceVersion":"{}","sha256":"{}"}}"#,
                    env!("CARGO_PKG_VERSION"),
                    sha256
                );
                None
            }
            Some("uninstall-service") => {
                // Programs and Features starts the uninstall string without elevation, so that
                // form confirms with the user and restarts this manager elevated. Every other
                // caller -- the installer and the launcher -- is already elevated and silent.
                let modifier = arguments.next();
                let interactive = match modifier.as_deref() {
                    None => false,
                    Some(value) if value.to_str() == Some("--interactive") => true,
                    Some(_) => {
                        return Err("uninstall-service accepts only --interactive".to_owned());
                    }
                };
                ensure_finished(arguments)?;
                if interactive {
                    let removed = confirm_and_elevate_service_removal().map_err(display_error)?;
                    println!(
                        r#"{{"ok":true,"serviceVersion":"{}","state":"{}"}}"#,
                        env!("CARGO_PKG_VERSION"),
                        if removed { "removed" } else { "declined" }
                    );
                    return Ok(());
                }
                let outcome = remove_system_service().map_err(display_error)?;
                println!(
                    r#"{{"ok":true,"serviceVersion":"{}","state":"{}"}}"#,
                    env!("CARGO_PKG_VERSION"),
                    outcome.as_str()
                );
                None
            }
            _ => return Err(usage()),
        };
        if let Some(request) = request {
            let response = call_checked(&request)?;
            print_response(&response)?;
        }
        Ok(())
    }

    fn unpack_service_setup_package(
        package: &Path,
        setup: &Path,
    ) -> std::result::Result<(), String> {
        validate_service_setup_package_paths(package, setup)?;
        let metadata = fs::symlink_metadata(package)
            .map_err(|_| "service setup package does not exist".to_owned())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("service setup package is not a regular file".to_owned());
        }
        if metadata.len() == 0 || metadata.len() > MAX_PACKED_SETUP_BYTES {
            return Err("service setup package size is invalid".to_owned());
        }
        if fs::symlink_metadata(setup).is_ok() {
            return Err("service setup output already exists".to_owned());
        }

        let temporary = setup.with_file_name(SERVICE_SETUP_TEMP_NAME);
        if fs::symlink_metadata(&temporary).is_ok() {
            return Err("temporary service setup output already exists".to_owned());
        }
        let result = (|| {
            let input = File::open(package)
                .map_err(|_| "service setup package cannot be opened".to_owned())?;
            let output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|_| "temporary service setup output cannot be created".to_owned())?;
            let options = lzma_rs::decompress::Options {
                memlimit: Some(MAX_LZMA_DICTIONARY_BYTES),
                ..Default::default()
            };
            let mut input = BufReader::new(input);
            let mut output = BoundedWriter::new(output, MAX_UNPACKED_SETUP_BYTES);
            lzma_rs::lzma_decompress_with_options(&mut input, &mut output, &options)
                .map_err(|_| "service setup package is not valid LZMA data".to_owned())?;
            output
                .flush()
                .map_err(|_| "decompressed service setup cannot be flushed".to_owned())?;
            let (output, written) = output.into_parts();
            output
                .sync_all()
                .map_err(|_| "decompressed service setup cannot be synchronized".to_owned())?;
            drop(output);
            if written == 0 {
                return Err("decompressed service setup is empty".to_owned());
            }
            fs::rename(&temporary, setup)
                .map_err(|_| "decompressed service setup cannot be activated".to_owned())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn validate_service_setup_package_paths(
        package: &Path,
        setup: &Path,
    ) -> std::result::Result<(), String> {
        if !is_normalized_absolute_path(package) || !is_normalized_absolute_path(setup) {
            return Err("service setup package paths must be absolute and normalized".to_owned());
        }
        let package_name = package.file_name().and_then(|value| value.to_str());
        let setup_name = setup.file_name().and_then(|value| value.to_str());
        if !package_name.is_some_and(|value| value.eq_ignore_ascii_case(SERVICE_SETUP_PACKAGE_NAME))
            || !setup_name.is_some_and(|value| value.eq_ignore_ascii_case(SERVICE_SETUP_NAME))
            || package.parent() != setup.parent()
        {
            return Err("service setup package paths are not canonical".to_owned());
        }
        Ok(())
    }

    fn is_normalized_absolute_path(path: &Path) -> bool {
        let mut components = path.components();
        matches!(components.next(), Some(Component::Prefix(_)))
            && matches!(components.next(), Some(Component::RootDir))
            && components.all(|component| matches!(component, Component::Normal(_)))
    }

    fn call_checked(request: &Request) -> std::result::Result<serde_json::Value, String> {
        let response = call_shared_service(request).map_err(display_error)?;
        if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(format!(
                "maintenance service rejected the request: {}",
                service_rejection_diagnostic(&response)
            ));
        }
        Ok(response)
    }

    fn service_rejection_diagnostic(response: &serde_json::Value) -> String {
        let mut diagnostic = response
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("E_PROTOCOL_INVALID")
            .to_owned();
        if let Some(detail) = response
            .get("detail")
            .and_then(serde_json::Value::as_str)
            .filter(|detail| !detail.is_empty())
        {
            diagnostic.push_str(": ");
            diagnostic.push_str(detail);
        }
        if let Some(status) = response
            .get("win32Status")
            .and_then(serde_json::Value::as_u64)
        {
            diagnostic.push_str(&format!(" (Win32 status {status})"));
        }
        diagnostic
    }

    fn print_response(response: &serde_json::Value) -> std::result::Result<(), String> {
        println!(
            "{}",
            serde_json::to_string(response)
                .map_err(|_| "maintenance response cannot be printed".to_owned())?
        );
        Ok(())
    }

    fn ensure_service_compatible(response: &serde_json::Value) -> std::result::Result<(), String> {
        if response
            .get("protocolMajor")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
        {
            return Err("maintenance service protocol is incompatible".to_owned());
        }
        let installed = response
            .get("serviceVersion")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "maintenance service version is missing".to_owned())?;
        let installed = ServiceVersion::parse(installed).map_err(display_error)?;
        let required = ServiceVersion::parse(env!("CARGO_PKG_VERSION")).map_err(display_error)?;
        if installed < required {
            return Err("maintenance service install or upgrade is required".to_owned());
        }
        let capabilities = response
            .get("capabilities")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "maintenance service capabilities are missing".to_owned())?;
        for required in ["file-set-v1", "registry-set-v1"] {
            if !capabilities
                .iter()
                .any(|capability| capability.as_str() == Some(required))
            {
                return Err(format!(
                    "maintenance service capability is missing: {required}"
                ));
            }
        }
        Ok(())
    }

    fn restart_launcher(restart: &Path) -> std::result::Result<(), String> {
        Command::new(restart)
            .current_dir(
                restart
                    .parent()
                    .ok_or_else(|| "Launcher directory is missing".to_owned())?,
            )
            .spawn()
            .map_err(|_| "registered Launcher could not be restarted".to_owned())?;
        Ok(())
    }

    fn commit_after_launcher_exit(
        job_id: &str,
        mut call: impl FnMut(&Request) -> std::result::Result<serde_json::Value, String>,
    ) -> std::result::Result<serde_json::Value, String> {
        // A lost Commit response is ambiguous: inspect the job, never send Commit twice.
        let response = call(&Request::CommitJob {
            protocol_major: 1,
            job_id: job_id.to_owned(),
        });
        wait_for_job_completion(job_id, response, call)
    }

    fn wait_for_job_completion(
        job_id: &str,
        response: std::result::Result<serde_json::Value, String>,
        mut call: impl FnMut(&Request) -> std::result::Result<serde_json::Value, String>,
    ) -> std::result::Result<serde_json::Value, String> {
        let started = Instant::now();
        wait_for_job_completion_with(
            response,
            || {
                call(&Request::GetJobStatus {
                    protocol_major: 1,
                    job_id: job_id.to_owned(),
                })
            },
            || {
                if started.elapsed() >= Duration::from_secs(120) {
                    return false;
                }
                thread::sleep(Duration::from_millis(100));
                true
            },
        )
    }

    fn wait_for_job_completion_with(
        mut response: std::result::Result<serde_json::Value, String>,
        mut poll: impl FnMut() -> std::result::Result<serde_json::Value, String>,
        mut wait: impl FnMut() -> bool,
    ) -> std::result::Result<serde_json::Value, String> {
        let commit_response_failed = response.is_err();
        loop {
            if let Ok(value) = &response {
                // Older service builds labelled incomplete recovery as rolledBack. Check the
                // error as well as state before allowing either Launcher binary to execute.
                if value.get("error").and_then(serde_json::Value::as_str)
                    == Some("E_RECOVERY_INCOMPLETE")
                {
                    return Err(
                        "maintenance recovery is incomplete; Launcher restart withheld".to_owned(),
                    );
                }
                match value.get("state").and_then(serde_json::Value::as_str) {
                    Some("committed" | "rolledBack") => return response,
                    // The serialized service has explicitly confirmed that the failed Commit
                    // never left Prepared. It is safe to reopen the unchanged old executable.
                    Some("prepared") if commit_response_failed => return response,
                    Some("prepared" | "committing") => {}
                    Some("failed") => {
                        return Err("maintenance job failed; Launcher restart withheld".to_owned());
                    }
                    _ => return Err("maintenance service returned an invalid job state".to_owned()),
                }
            }
            if !wait() {
                return Err(format!(
                    "maintenance completion deadline exceeded; Launcher restart withheld: {}",
                    response
                        .err()
                        .unwrap_or_else(|| "job did not reach a safe terminal state".to_owned())
                ));
            }
            response = poll();
        }
    }

    fn validate_restart_executable(path: &PathBuf) -> std::result::Result<(), String> {
        if !path.is_absolute()
            || path.extension().and_then(|extension| extension.to_str()) != Some("exe")
        {
            return Err(
                "registered Launcher restart path must be an absolute .exe path".to_owned(),
            );
        }
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "registered Launcher restart path does not exist".to_owned())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("registered Launcher restart path is not a regular file".to_owned());
        }
        Ok(())
    }

    fn required(
        arguments: &mut impl Iterator<Item = OsString>,
        label: &str,
    ) -> std::result::Result<OsString, String> {
        arguments
            .next()
            .ok_or_else(|| format!("missing {label}\n{}", usage()))
    }

    fn required_text(
        arguments: &mut impl Iterator<Item = OsString>,
        label: &str,
    ) -> std::result::Result<String, String> {
        required(arguments, label)?
            .into_string()
            .map_err(|_| format!("{label} must be Unicode"))
    }

    fn required_path(
        arguments: &mut impl Iterator<Item = OsString>,
        label: &str,
    ) -> std::result::Result<PathBuf, String> {
        let path = PathBuf::from(required(arguments, label)?);
        if !path.is_absolute() {
            return Err(format!("{label} must be absolute"));
        }
        Ok(path)
    }

    fn ensure_finished(
        mut arguments: impl Iterator<Item = OsString>,
    ) -> std::result::Result<(), String> {
        if arguments.next().is_some() {
            Err(format!("unexpected extra argument\n{}", usage()))
        } else {
            Ok(())
        }
    }

    fn path_to_text(path: PathBuf) -> std::result::Result<String, String> {
        path.into_os_string()
            .into_string()
            .map_err(|_| "path must be Unicode".to_owned())
    }

    fn display_error(error: MaintenanceError) -> String {
        error.to_string()
    }

    fn write_ensure_service_diagnostic(bundle_root: &Path, message: &str) {
        // The elevated installer extracts this client into its private temporary bundle directory.
        // Diagnostics are best-effort and must never replace the authoritative operation result.
        let _ = std::fs::write(
            bundle_root.join(ENSURE_SERVICE_DIAGNOSTIC_FILE),
            message.as_bytes(),
        );
    }

    fn usage() -> String {
        "usage: Se7enServiceManager <status|root-status|registry-scope-status|register-root|unregister-root|register-registry-scope|unregister-registry-scope|apply-registry-set|prepare|commit|job-status|wait-commit-restart|ensure-service|service-compatible|unpack-service-setup|verify-service-setup|verify-service-bundle|uninstall-service> ...".to_owned()
    }

    #[cfg(test)]
    mod tests {
        use std::{
            fs,
            io::{BufReader, Cursor, Write},
            path::Path,
            sync::atomic::{AtomicU64, Ordering},
        };

        use serde_json::json;

        use super::{
            BoundedWriter, SERVICE_SETUP_NAME, SERVICE_SETUP_PACKAGE_NAME,
            commit_after_launcher_exit, ensure_service_compatible, service_rejection_diagnostic,
            unpack_service_setup_package, validate_service_setup_package_paths,
            wait_for_job_completion_with,
        };

        static NEXT_TEMPORARY_ID: AtomicU64 = AtomicU64::new(0);

        struct TemporaryDirectory(std::path::PathBuf);

        impl TemporaryDirectory {
            fn create() -> Self {
                let id = NEXT_TEMPORARY_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "se7en-service-package-test-{}-{id}",
                    std::process::id()
                ));
                fs::create_dir(&path).expect("create temporary directory");
                Self(path)
            }
        }

        impl Drop for TemporaryDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn status(version: &str) -> serde_json::Value {
            json!({
                "ok": true,
                "protocolMajor": 1,
                "serviceVersion": version,
                "capabilities": [
                    "file-set-v1",
                    "registry-set-v1"
                ]
            })
        }

        #[test]
        fn compatible_probe_accepts_current_and_newer_service() {
            assert!(ensure_service_compatible(&status(env!("CARGO_PKG_VERSION"))).is_ok());
            assert!(ensure_service_compatible(&status("1.99.0")).is_ok());
        }

        #[test]
        fn compatible_probe_requires_upgrade_for_older_service() {
            assert_eq!(
                ensure_service_compatible(&status("1.0.0")).unwrap_err(),
                "maintenance service install or upgrade is required"
            );
        }

        #[test]
        fn compatible_probe_rejects_missing_capability() {
            let mut response = status(env!("CARGO_PKG_VERSION"));
            response["capabilities"] = json!(["file-set-v1"]);
            assert_eq!(
                ensure_service_compatible(&response).unwrap_err(),
                "maintenance service capability is missing: registry-set-v1"
            );
        }

        #[test]
        fn service_rejection_diagnostic_accepts_old_and_extended_responses() {
            assert_eq!(
                service_rejection_diagnostic(&json!({"error": "E_PROTOCOL_INVALID"})),
                "E_PROTOCOL_INVALID"
            );
            assert_eq!(
                service_rejection_diagnostic(&json!({
                    "detail": "LocalSystem cannot create the bounded HKLM registry scope",
                    "error": "E_REGISTRY_SCOPE_UNAUTHORIZED",
                    "win32Status": 5
                })),
                "E_REGISTRY_SCOPE_UNAUTHORIZED: LocalSystem cannot create the bounded HKLM registry scope (Win32 status 5)"
            );
        }

        #[test]
        fn service_setup_package_round_trips_with_bounded_lzma_decoder() {
            let root = TemporaryDirectory::create();
            let package = root.0.join(SERVICE_SETUP_PACKAGE_NAME);
            let setup = root.0.join(SERVICE_SETUP_NAME);
            let original = b"signed setup fixture".repeat(1024);
            let mut encoded = Vec::new();
            lzma_rs::lzma_compress(&mut BufReader::new(Cursor::new(&original)), &mut encoded)
                .expect("compress fixture");
            fs::write(&package, encoded).expect("write fixture");

            unpack_service_setup_package(&package, &setup).expect("unpack fixture");
            assert_eq!(fs::read(setup).expect("read setup"), original);
        }

        #[test]
        fn service_setup_package_requires_canonical_same_directory_paths() {
            let package = Path::new(r"C:\Temp\se7en-service-setup.exe.lzma");
            assert!(
                validate_service_setup_package_paths(
                    package,
                    Path::new(r"C:\Other\se7en-service-setup.exe")
                )
                .is_err()
            );
            assert!(
                validate_service_setup_package_paths(
                    Path::new(r"C:\Temp\payload.lzma"),
                    Path::new(r"C:\Temp\se7en-service-setup.exe")
                )
                .is_err()
            );
            assert!(
                validate_service_setup_package_paths(
                    Path::new(r"C:\Temp\..\Other\se7en-service-setup.exe.lzma"),
                    Path::new(r"C:\Temp\..\Other\se7en-service-setup.exe")
                )
                .is_err()
            );
        }

        #[test]
        fn bounded_writer_rejects_excess_output() {
            let mut output = BoundedWriter::new(Vec::new(), 4);
            output.write_all(b"four").expect("within limit");
            assert!(output.write_all(b"!").is_err());
        }

        #[test]
        fn update_restarts_only_after_confirmed_commit_or_rollback() {
            for state in ["committed", "rolledBack"] {
                let response = json!({"state": state, "error": null});
                assert_eq!(
                    wait_for_job_completion_with(
                        Ok(response.clone()),
                        || panic!("terminal status must not poll"),
                        || false
                    )
                    .unwrap(),
                    response
                );
            }
            for response in [
                json!({"state": "failed", "error": "E_TRANSACTION_IO"}),
                json!({"state": "rolledBack", "error": "E_RECOVERY_INCOMPLETE"}),
                json!({"state": "committed", "error": "E_RECOVERY_INCOMPLETE"}),
                json!({"state": "unknown"}),
            ] {
                assert!(
                    wait_for_job_completion_with(
                        Ok(response),
                        || panic!("unsafe terminal status must not poll"),
                        || false
                    )
                    .is_err()
                );
            }
        }

        #[test]
        fn update_recovers_lost_commit_and_status_responses_without_second_commit() {
            use seven_launcher_maintenance::protocol::Request;
            let mut commits = 0;
            let mut polls = 0;
            let response = commit_after_launcher_exit("fixture", |request| match request {
                Request::CommitJob { .. } => {
                    commits += 1;
                    Err("lost commit response".to_owned())
                }
                Request::GetJobStatus { .. } => {
                    polls += 1;
                    if polls == 1 {
                        Err("lost status response".to_owned())
                    } else {
                        Ok(json!({"state": "committed"}))
                    }
                }
                _ => panic!("unexpected command"),
            })
            .unwrap();
            assert_eq!(response["state"], "committed");
            assert_eq!(commits, 1);
            assert_eq!(polls, 2);
        }

        #[test]
        fn update_confirmed_prepared_after_refused_commit_keeps_original_launcher_available() {
            let mut polls = 0;
            let response = wait_for_job_completion_with(
                Err("commit refused".to_owned()),
                || {
                    polls += 1;
                    Ok(json!({"state": "prepared"}))
                },
                || true,
            )
            .unwrap();
            assert_eq!(response["state"], "prepared");
            assert_eq!(polls, 1);
        }

        #[test]
        fn update_pending_and_unavailable_statuses_have_a_deadline() {
            for state in ["prepared", "committing"] {
                let mut polls = 0;
                let mut waits = 0;
                let result = wait_for_job_completion_with(
                    Ok(json!({"state": state})),
                    || {
                        polls += 1;
                        Err("service unavailable".to_owned())
                    },
                    || {
                        waits += 1;
                        waits <= 2
                    },
                );
                assert!(result.unwrap_err().contains("deadline exceeded"));
                assert_eq!(polls, 2);
            }
        }
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_client::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("7Launcher maintenance client is Windows-only");
    std::process::exit(2);
}
