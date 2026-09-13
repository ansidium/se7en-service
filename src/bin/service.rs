#![forbid(unsafe_code)]

#[cfg(windows)]
fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let command = arguments.next();
    let result = match command.as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("--service") if arguments.next().is_none() => {
            seven_launcher_maintenance::windows::run_service_dispatcher().map(|_| ())
        }
        Some("uninstall-service") if arguments.next().is_none() => {
            seven_launcher_maintenance::windows::remove_system_service().map(|_| ())
        }
        _ => {
            eprintln!(
                "SE7ENService must be started by the Windows Service Control Manager or its installer"
            );
            std::process::exit(2);
        }
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("SE7ENService is Windows-only");
    std::process::exit(2);
}
