use std::{env, fs, path::PathBuf};

use seven_launcher_maintenance::{
    FileSetAcceptance, KeyringAcceptance, verify_file_set, verify_keyring,
};
use sha2::{Digest, Sha256};

const SERVICE_PRODUCT_ID: &str = "7launcher-maintenance";
const SERVICE_BINARY_NAME: &str = "Se7enService.exe";

#[test]
#[ignore = "release build supplies SE7EN_RELEASE_BUNDLE_ROOT"]
fn production_bundle_from_environment_verifies_in_rust() {
    let bundle = PathBuf::from(
        env::var_os("SE7EN_RELEASE_BUNDLE_ROOT")
            .expect("release build must set SE7EN_RELEASE_BUNDLE_ROOT"),
    );
    let keyring_bytes = fs::read(bundle.join("keyring-v1.json")).expect("read keyring");
    let file_set_bytes = fs::read(bundle.join("file-set-v1.json")).expect("read FileSet");
    let service_bytes = fs::read(bundle.join(SERVICE_BINARY_NAME)).expect("read service");

    let keyring = verify_keyring(&keyring_bytes, KeyringAcceptance::default())
        .expect("Rust rejected the production keyring");
    let verified = verify_file_set(
        &file_set_bytes,
        &keyring,
        FileSetAcceptance {
            expected_product_id: SERVICE_PRODUCT_ID,
            previous: None,
        },
    )
    .expect("Rust rejected the production FileSet");
    let file_set = verified.file_set();

    assert!(file_set.generation > 0);
    assert!(file_set.remove_files.is_empty());
    assert_eq!(file_set.files.len(), 1);
    let entry = &file_set.files[0];
    assert_eq!(entry.path, SERVICE_BINARY_NAME);
    assert_eq!(entry.size, service_bytes.len() as u64);
    assert_eq!(entry.sha256, format!("{:x}", Sha256::digest(service_bytes)));
}
