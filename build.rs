#![forbid(unsafe_code)]

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo::rerun-if-env-changed=CARGO_CFG_TARGET_ENV");
    println!("cargo::rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    println!("cargo::rerun-if-env-changed=CARGO_CFG_TARGET_FEATURE");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=assets/service.ico");
    println!("cargo::rerun-if-changed=assets/app.manifest");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // Without the Visual C++ Redistributable a dynamic-CRT build does not start, and the
        // LocalSystem service would search PATH for the missing DLL.
        let static_crt = env::var("CARGO_CFG_TARGET_FEATURE")
            .is_ok_and(|features| features.split(',').any(|feature| feature == "crt-static"));
        if !static_crt {
            println!(
                "cargo::error=MSVC builds must link the CRT statically: keep .cargo/config.toml \
                 and do not override it with RUSTFLAGS, or add -C target-feature=+crt-static"
            );
            return;
        }
        println!("cargo::rustc-link-arg-bins=/Brepro");
        // LOAD_LIBRARY_SEARCH_SYSTEM32: non-KnownDLL imports such as wintrust.dll and
        // crypt32.dll load only from System32, never from the application directory.
        println!("cargo::rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        compile_windows_version_resources();
    }
}

fn compile_windows_version_resources() {
    let version = env::var("CARGO_PKG_VERSION").expect("Cargo package version is unavailable");
    let mut components = version.split('.');
    let major = parse_version_component(components.next(), "major");
    let minor = parse_version_component(components.next(), "minor");
    let patch = parse_version_component(components.next(), "patch");
    assert!(
        components.next().is_none(),
        "service version must be major.minor.patch"
    );

    let icon_path = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory is unavailable"),
    )
    .join("assets/service.ico")
    .canonicalize()
    .expect("7Launcher icon resource is unavailable")
    .to_string_lossy()
    .replace('\\', "/");
    let manifest_path = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory is unavailable"),
    )
    .join("assets/app.manifest")
    .canonicalize()
    .expect("application manifest is unavailable")
    .to_string_lossy()
    .replace('\\', "/");
    let resource = windows_version_resource(
        &icon_path,
        &manifest_path,
        &version,
        major,
        minor,
        patch,
        "Secure privileged maintenance component for 7Launcher games and applications.",
        "7Launcher Maintenance Service",
        "SE7ENService",
        "Se7enService.exe",
    );
    let resource_path = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is unavailable"))
        .join("se7en-service-version.rc");
    fs::write(&resource_path, resource).expect("service VERSIONINFO resource could not be written");
    embed_resource::compile_for(&resource_path, ["service"], embed_resource::NONE)
        .manifest_required()
        .expect("service VERSIONINFO resource could not be compiled");

    let manager_resource = windows_version_resource(
        &icon_path,
        &manifest_path,
        &version,
        major,
        minor,
        patch,
        "Installs, updates, and communicates with 7Launcher Maintenance Service.",
        "7Launcher Maintenance Service Manager",
        "Se7enServiceManager",
        "Se7enServiceManager.exe",
    );
    let manager_resource_path =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is unavailable"))
            .join("se7en-service-manager-version.rc");
    fs::write(&manager_resource_path, manager_resource)
        .expect("manager VERSIONINFO resource could not be written");
    embed_resource::compile_for(&manager_resource_path, ["client"], embed_resource::NONE)
        .manifest_required()
        .expect("manager VERSIONINFO resource could not be compiled");
}

#[allow(clippy::too_many_arguments)]
fn windows_version_resource(
    icon_path: &str,
    manifest_path: &str,
    version: &str,
    major: u16,
    minor: u16,
    patch: u16,
    comments: &str,
    description: &str,
    internal_name: &str,
    original_filename: &str,
) -> String {
    format!(
        r#"2 ICON "{icon_path}"
1 24 "{manifest_path}"

1 VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x00040004L
FILETYPE 0x00000001L
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName", "SE7EN Solutions\0"
            VALUE "Comments", "{comments}\0"
            VALUE "FileDescription", "{description}\0"
            VALUE "FileVersion", "{version}.0\0"
            VALUE "InternalName", "{internal_name}\0"
            VALUE "LegalCopyright", "Copyright (c) 2026 SE7EN Solutions. All rights reserved.\0"
            VALUE "OriginalFilename", "{original_filename}\0"
            VALUE "ProductName", "7Launcher Maintenance Service\0"
            VALUE "ProductVersion", "{version}.0\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
"#
    )
}

fn parse_version_component(component: Option<&str>, label: &str) -> u16 {
    component
        .unwrap_or_else(|| panic!("service version has no {label} component"))
        .parse::<u16>()
        .unwrap_or_else(|_| panic!("service version {label} component is invalid"))
}
