//! Checks the PE images of the service and manager.
//!
//! Both executables must start on a clean Windows installation without the Visual C++
//! Redistributable, so they must not import the dynamic CRT. Non-KnownDLL dependencies such as
//! `wintrust.dll` and `crypt32.dll` must load only from System32.

use std::{env, fs, path::Path};

const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u16 = 0x0800;
const MAX_IMPORTED_MODULES: usize = 512;

struct PeImage {
    bytes: Vec<u8>,
    pe32_plus: bool,
    data_directories: Vec<(u32, u32)>,
    sections: Vec<Section>,
}

struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_offset: u32,
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String> {
    bytes
        .get(offset..offset.checked_add(2).ok_or("offset overflow")?)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
        .ok_or_else(|| format!("u16 at {offset:#x} is outside the image"))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    bytes
        .get(offset..offset.checked_add(4).ok_or("offset overflow")?)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
        .ok_or_else(|| format!("u32 at {offset:#x} is outside the image"))
}

fn index(value: u32) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| "value does not fit usize".to_owned())
}

impl PeImage {
    fn read(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
        if bytes.get(..2) != Some(b"MZ") {
            return Err("missing MZ signature".to_owned());
        }
        let pe = index(u32_at(&bytes, 0x3c)?)?;
        if bytes.get(pe..pe + 4) != Some(b"PE\0\0") {
            return Err("missing PE signature".to_owned());
        }
        let coff = pe + 4;
        let section_count = usize::from(u16_at(&bytes, coff + 2)?);
        let optional_size = usize::from(u16_at(&bytes, coff + 16)?);
        let optional = coff + 20;
        let (pe32_plus, directory_count_offset) = match u16_at(&bytes, optional)? {
            0x10b => (false, 92),
            0x20b => (true, 108),
            magic => return Err(format!("unknown optional header magic {magic:#x}")),
        };
        let directory_count = index(u32_at(&bytes, optional + directory_count_offset)?)?.min(16);
        let directories = optional + directory_count_offset + 4;
        let data_directories = (0..directory_count)
            .map(|entry| {
                let offset = directories + entry * 8;
                Ok((u32_at(&bytes, offset)?, u32_at(&bytes, offset + 4)?))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let section_table = optional + optional_size;
        let sections = (0..section_count)
            .map(|entry| {
                let offset = section_table + entry * 40;
                Ok(Section {
                    virtual_size: u32_at(&bytes, offset + 8)?,
                    virtual_address: u32_at(&bytes, offset + 12)?,
                    raw_size: u32_at(&bytes, offset + 16)?,
                    raw_offset: u32_at(&bytes, offset + 20)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self {
            bytes,
            pe32_plus,
            data_directories,
            sections,
        })
    }

    fn directory(&self, entry: usize) -> Option<(u32, u32)> {
        self.data_directories
            .get(entry)
            .copied()
            .filter(|&(rva, size)| rva != 0 && size != 0)
    }

    fn offset(&self, rva: u32) -> Result<usize, String> {
        self.sections
            .iter()
            .find_map(|section| {
                let start = section.virtual_address;
                let length = section.virtual_size.max(section.raw_size);
                let delta = rva.checked_sub(start).filter(|delta| *delta < length)?;
                (delta < section.raw_size).then(|| section.raw_offset.checked_add(delta))?
            })
            .ok_or_else(|| format!("RVA {rva:#x} is not backed by file data"))
            .and_then(index)
    }

    fn ascii_at(&self, rva: u32) -> Result<String, String> {
        let start = self.offset(rva)?;
        let tail = self
            .bytes
            .get(start..)
            .ok_or("string is outside the image")?;
        let length = tail
            .iter()
            .take(260)
            .position(|byte| *byte == 0)
            .ok_or("module name is not terminated")?;
        String::from_utf8(tail[..length].to_vec()).map_err(|_| "module name is not ASCII".into())
    }

    /// Returns normal and delay-load module names in table order.
    fn imported_modules(&self) -> Result<Vec<String>, String> {
        let mut modules = Vec::new();
        for (entry, descriptor_size, name_offset) in [
            (IMAGE_DIRECTORY_ENTRY_IMPORT, 20, 12),
            (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 32, 4),
        ] {
            let Some((rva, _)) = self.directory(entry) else {
                continue;
            };
            let table = self.offset(rva)?;
            for descriptor in 0.. {
                if modules.len() >= MAX_IMPORTED_MODULES {
                    return Err("import table is unexpectedly large".to_owned());
                }
                let name_rva = u32_at(
                    &self.bytes,
                    table + descriptor * descriptor_size + name_offset,
                )?;
                if name_rva == 0 {
                    break;
                }
                modules.push(self.ascii_at(name_rva)?);
            }
        }
        Ok(modules)
    }

    /// `IMAGE_LOAD_CONFIG_DIRECTORY::DependentLoadFlags`, written by `/DEPENDENTLOADFLAG`.
    fn dependent_load_flags(&self) -> Result<u16, String> {
        let (rva, _) = self
            .directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
            .ok_or("image has no load configuration directory")?;
        let config = self.offset(rva)?;
        let field = if self.pe32_plus { 0x4e } else { 0x36 };
        let declared_size = index(u32_at(&self.bytes, config)?)?;
        if declared_size < field + 2 {
            return Err("load configuration has no DependentLoadFlags field".to_owned());
        }
        u16_at(&self.bytes, config + field)
    }
}

/// Dynamic Visual C++ runtime and Universal CRT modules.
fn is_dynamic_crt_module(module: &str) -> bool {
    let module = module.to_ascii_lowercase();
    [
        "vcruntime",
        "msvcp",
        "msvcr",
        "concrt",
        "ucrtbase",
        "api-ms-win-crt-",
    ]
    .iter()
    .any(|prefix| module.starts_with(prefix))
}

fn assert_standalone_image(path: &Path) {
    let image = PeImage::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let modules = image
        .imported_modules()
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    assert!(
        modules
            .iter()
            .any(|module| module.eq_ignore_ascii_case("kernel32.dll")),
        "{}: import table was not parsed: {modules:?}",
        path.display()
    );
    let crt: Vec<_> = modules
        .iter()
        .filter(|module| is_dynamic_crt_module(module))
        .collect();
    assert!(
        crt.is_empty(),
        "{} imports the dynamic CRT {crt:?}; build with -C target-feature=+crt-static",
        path.display()
    );
    let flags = image
        .dependent_load_flags()
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    assert_eq!(
        flags & LOAD_LIBRARY_SEARCH_SYSTEM32,
        LOAD_LIBRARY_SEARCH_SYSTEM32,
        "{}: dependent DLLs must load only from System32 (/DEPENDENTLOADFLAG:0x800)",
        path.display()
    );
}

#[test]
fn crt_module_names_are_recognized() {
    for module in [
        "VCRUNTIME140.dll",
        "vcruntime140_1.dll",
        "MSVCP140.dll",
        "msvcp140_atomic_wait.dll",
        "ucrtbase.dll",
        "api-ms-win-crt-runtime-l1-1-0.dll",
    ] {
        assert!(is_dynamic_crt_module(module), "{module}");
    }
    for module in [
        "kernel32.dll",
        "api-ms-win-core-synch-l1-2-0.dll",
        "wintrust.dll",
        "bcryptprimitives.dll",
    ] {
        assert!(!is_dynamic_crt_module(module), "{module}");
    }
}

#[test]
fn service_and_manager_run_without_the_visual_cpp_redistributable() {
    assert_standalone_image(Path::new(env!("CARGO_BIN_EXE_service")));
    assert_standalone_image(Path::new(env!("CARGO_BIN_EXE_client")));
}

#[test]
#[ignore = "CI and the release build supply SE7EN_RELEASE_BINARIES"]
fn release_binaries_from_environment_run_without_the_visual_cpp_redistributable() {
    let binaries = env::var_os("SE7EN_RELEASE_BINARIES")
        .expect("release check must set SE7EN_RELEASE_BINARIES to a PATH-style list");
    let paths: Vec<_> = env::split_paths(&binaries).collect();
    assert!(!paths.is_empty(), "SE7EN_RELEASE_BINARIES is empty");
    for path in paths {
        assert_standalone_image(&path);
    }
}
