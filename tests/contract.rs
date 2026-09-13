use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use seven_launcher_maintenance::{
    AllowedRegistryValue, ErrorCode, FILE_SET_SIGNING_DOMAIN, FileSetAcceptance, GenerationRecord,
    KEYRING_SIGNING_DOMAIN, KeyringAcceptance, MAX_REGISTRY_BINARY_BYTES,
    REGISTRY_SET_SIGNING_DOMAIN, RegistrySetAcceptance, RegistryValue, RegistryValueKind,
    canonical_json,
    protocol::{Request, RootKind, decode_request},
    signing_message, verify_file_set, verify_keyring_with_root, verify_registry_set,
};

const ROOT_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const RELEASE_SEED: [u8; 32] = [0x42; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sign_document(mut payload: Value, seed: [u8; 32], domain: &[u8]) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(&seed);
    let payload_bytes = canonical_json(&payload).expect("test payload is canonicalizable");
    let signature = signing_key.sign(&signing_message(domain, &payload_bytes));
    payload
        .as_object_mut()
        .expect("test payload is an object")
        .insert(
            "signature".to_owned(),
            Value::String(hex(&signature.to_bytes())),
        );
    canonical_json(&payload).expect("signed test document is canonicalizable")
}

fn keyring_payload(version: u64) -> Value {
    let release_key = SigningKey::from_bytes(&RELEASE_SEED).verifying_key();
    json!({
        "authenticodeSignerThumbprints": ["0123456789abcdef0123456789abcdef01234567"],
        "kind": "7launcher-maintenance-keyring-v1",
        "releaseKeys": [{"keyId": "release-2026", "publicKey": hex(&release_key.to_bytes())}],
        "schema": 1,
        "version": version
    })
}

fn file_set_payload(generation: u64, path: &str) -> Value {
    json!({
        "files": [{
            "path": path,
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size": 123
        }],
        "generation": generation,
        "keyId": "release-2026",
        "kind": "7launcher-file-set-v1",
        "productId": "sample-app",
        "removeFiles": ["obsolete.dll"],
        "schema": 1
    })
}

fn registry_set_payload(generation: u64, language: &str) -> Value {
    json!({
        "generation": generation,
        "keyId": "release-2026",
        "kind": "7launcher-registry-set-v1",
        "productId": "sample-app",
        "schema": 1,
        "scopeId": "sample-language",
        "values": [{"data": language, "name": "Language", "type": "string"}]
    })
}

fn registry_allowlist() -> Vec<AllowedRegistryValue> {
    vec![AllowedRegistryValue {
        name: "Language".to_owned(),
        value_type: RegistryValueKind::String,
    }]
}

fn verified_keyring() -> seven_launcher_maintenance::VerifiedKeyring {
    let bytes = sign_document(keyring_payload(1), ROOT_SEED, KEYRING_SIGNING_DOMAIN);
    let root_public_key = SigningKey::from_bytes(&ROOT_SEED)
        .verifying_key()
        .to_bytes();
    verify_keyring_with_root(&bytes, KeyringAcceptance::default(), &root_public_key)
        .expect("valid keyring")
}

#[test]
fn contract_accepts_only_canonical_signed_keyring_and_file_set() {
    let keyring = verified_keyring();
    let file_set_bytes = sign_document(
        file_set_payload(42, "Launcher.exe"),
        RELEASE_SEED,
        FILE_SET_SIGNING_DOMAIN,
    );
    let verified = verify_file_set(
        &file_set_bytes,
        &keyring,
        FileSetAcceptance {
            expected_product_id: "sample-app",
            previous: None,
        },
    )
    .expect("valid file set");

    assert_eq!(verified.file_set().generation, 42);
    assert_eq!(
        hex(&verified.digest()),
        "73ff7e072d44c094e5166299fd6b97e851e7c16b248ddc10c0e391ea90d18a32"
    );

    let mut non_canonical = file_set_bytes.clone();
    non_canonical.push(b'\n');
    assert_eq!(
        verify_file_set(
            &non_canonical,
            &keyring,
            FileSetAcceptance {
                expected_product_id: "sample-app",
                previous: None,
            },
        )
        .expect_err("trailing whitespace is not canonical")
        .code(),
        ErrorCode::JsonNonCanonical
    );
}

#[test]
fn contract_rejects_duplicate_and_unknown_fields() {
    let duplicate = br#"{"authenticodeSignerThumbprints":[],"kind":"7launcher-maintenance-keyring-v1","releaseKeys":[],"schema":1,"version":1,"version":1,"signature":"00"}"#;
    assert_eq!(
        verify_keyring_with_root(
            duplicate,
            KeyringAcceptance::default(),
            &SigningKey::from_bytes(&ROOT_SEED)
                .verifying_key()
                .to_bytes(),
        )
        .expect_err("duplicate fields fail closed")
        .code(),
        ErrorCode::JsonInvalid
    );

    let mut payload = keyring_payload(1);
    payload
        .as_object_mut()
        .expect("object")
        .insert("extension".to_owned(), json!(true));
    let unknown = sign_document(payload, ROOT_SEED, KEYRING_SIGNING_DOMAIN);
    assert_eq!(
        verify_keyring_with_root(
            &unknown,
            KeyringAcceptance::default(),
            &SigningKey::from_bytes(&ROOT_SEED)
                .verifying_key()
                .to_bytes(),
        )
        .expect_err("unknown fields fail closed")
        .code(),
        ErrorCode::JsonInvalid
    );
}

#[test]
fn contract_rejects_invalid_signature_and_old_keyring() {
    let mut bytes = sign_document(keyring_payload(1), ROOT_SEED, KEYRING_SIGNING_DOMAIN);
    let signature_digit = bytes
        .iter()
        .position(|byte| *byte == b'0')
        .expect("test signature contains a zero");
    bytes[signature_digit] = b'1';
    assert_eq!(
        verify_keyring_with_root(
            &bytes,
            KeyringAcceptance::default(),
            &SigningKey::from_bytes(&ROOT_SEED)
                .verifying_key()
                .to_bytes(),
        )
        .expect_err("tampering invalidates signature")
        .code(),
        ErrorCode::TrustSignature
    );

    let old = sign_document(keyring_payload(1), ROOT_SEED, KEYRING_SIGNING_DOMAIN);
    assert_eq!(
        verify_keyring_with_root(
            &old,
            KeyringAcceptance {
                minimum_version: 2,
                current_digest: None,
            },
            &SigningKey::from_bytes(&ROOT_SEED)
                .verifying_key()
                .to_bytes(),
        )
        .expect_err("keyring downgrade is rejected")
        .code(),
        ErrorCode::KeyringRollback
    );
}

#[test]
fn contract_rejects_generation_downgrade_and_same_generation_with_other_digest() {
    let keyring = verified_keyring();
    let current_bytes = sign_document(
        file_set_payload(42, "Launcher.exe"),
        RELEASE_SEED,
        FILE_SET_SIGNING_DOMAIN,
    );
    let current = verify_file_set(
        &current_bytes,
        &keyring,
        FileSetAcceptance {
            expected_product_id: "sample-app",
            previous: None,
        },
    )
    .expect("current file set");
    let previous = GenerationRecord {
        generation: 42,
        digest: current.digest(),
    };

    let downgrade = sign_document(
        file_set_payload(41, "Launcher.exe"),
        RELEASE_SEED,
        FILE_SET_SIGNING_DOMAIN,
    );
    assert_eq!(
        verify_file_set(
            &downgrade,
            &keyring,
            FileSetAcceptance {
                expected_product_id: "sample-app",
                previous: Some(previous),
            },
        )
        .expect_err("generation downgrade is rejected")
        .code(),
        ErrorCode::FileSetRollback
    );

    let conflict = sign_document(
        file_set_payload(42, "Other.exe"),
        RELEASE_SEED,
        FILE_SET_SIGNING_DOMAIN,
    );
    assert_eq!(
        verify_file_set(
            &conflict,
            &keyring,
            FileSetAcceptance {
                expected_product_id: "sample-app",
                previous: Some(previous),
            },
        )
        .expect_err("same generation needs the same digest")
        .code(),
        ErrorCode::GenerationConflict
    );

    verify_file_set(
        &current_bytes,
        &keyring,
        FileSetAcceptance {
            expected_product_id: "sample-app",
            previous: Some(previous),
        },
    )
    .expect("same generation and digest is an idempotent repair");
}

#[test]
fn contract_registry_set_is_signed_allowlisted_bounded_and_anti_rollback() {
    let keyring = verified_keyring();
    let allowed_values = registry_allowlist();
    let current_bytes = sign_document(
        registry_set_payload(7, "Russian"),
        RELEASE_SEED,
        REGISTRY_SET_SIGNING_DOMAIN,
    );
    let current = verify_registry_set(
        &current_bytes,
        &keyring,
        RegistrySetAcceptance {
            allowed_values: &allowed_values,
            expected_product_id: "sample-app",
            expected_scope_id: "sample-language",
            previous: None,
        },
    )
    .expect("valid registry set");
    assert_eq!(current.registry_set().generation, 7);

    let previous = GenerationRecord {
        generation: 7,
        digest: current.digest(),
    };
    verify_registry_set(
        &current_bytes,
        &keyring,
        RegistrySetAcceptance {
            allowed_values: &allowed_values,
            expected_product_id: "sample-app",
            expected_scope_id: "sample-language",
            previous: Some(previous),
        },
    )
    .expect("same generation and digest is idempotent");

    let downgrade = sign_document(
        registry_set_payload(6, "English"),
        RELEASE_SEED,
        REGISTRY_SET_SIGNING_DOMAIN,
    );
    assert_eq!(
        verify_registry_set(
            &downgrade,
            &keyring,
            RegistrySetAcceptance {
                allowed_values: &allowed_values,
                expected_product_id: "sample-app",
                expected_scope_id: "sample-language",
                previous: Some(previous),
            },
        )
        .expect_err("registry generation downgrade is rejected")
        .code(),
        ErrorCode::RegistrySetRollback
    );

    let conflict = sign_document(
        registry_set_payload(7, "English"),
        RELEASE_SEED,
        REGISTRY_SET_SIGNING_DOMAIN,
    );
    assert_eq!(
        verify_registry_set(
            &conflict,
            &keyring,
            RegistrySetAcceptance {
                allowed_values: &allowed_values,
                expected_product_id: "sample-app",
                expected_scope_id: "sample-language",
                previous: Some(previous),
            },
        )
        .expect_err("same registry generation with another digest is rejected")
        .code(),
        ErrorCode::GenerationConflict
    );

    let outside_allowlist = sign_document(
        json!({
            "generation": 8,
            "keyId": "release-2026",
            "kind": "7launcher-registry-set-v1",
            "productId": "sample-app",
            "schema": 1,
            "scopeId": "sample-language",
            "values": [{"data": 1, "name": "InstallPath", "type": "dword"}]
        }),
        RELEASE_SEED,
        REGISTRY_SET_SIGNING_DOMAIN,
    );
    assert_eq!(
        verify_registry_set(
            &outside_allowlist,
            &keyring,
            RegistrySetAcceptance {
                allowed_values: &allowed_values,
                expected_product_id: "sample-app",
                expected_scope_id: "sample-language",
                previous: None,
            },
        )
        .expect_err("unregistered value names and types fail closed")
        .code(),
        ErrorCode::RegistryScopeUnauthorized
    );
}

#[test]
fn contract_registry_set_accepts_only_allowlisted_canonical_binary() {
    let keyring = verified_keyring();
    let allowed_values = vec![AllowedRegistryValue {
        name: "LanguageToken".to_owned(),
        value_type: RegistryValueKind::Binary,
    }];
    let binary = sign_document(
        json!({
            "generation": 8,
            "keyId": "release-2026",
            "kind": "7launcher-registry-set-v1",
            "productId": "sample-app",
            "schema": 1,
            "scopeId": "sample-language",
            "values": [{"data": "AQIDAA==", "name": "LanguageToken", "type": "binary"}]
        }),
        RELEASE_SEED,
        REGISTRY_SET_SIGNING_DOMAIN,
    );
    let verified = verify_registry_set(
        &binary,
        &keyring,
        RegistrySetAcceptance {
            allowed_values: &allowed_values,
            expected_product_id: "sample-app",
            expected_scope_id: "sample-language",
            previous: None,
        },
    )
    .expect("canonical bounded binary registry value is accepted");
    assert!(matches!(
        &verified.registry_set().values[0],
        RegistryValue::Binary { data, .. } if data == "AQIDAA=="
    ));

    let malformed = sign_document(
        json!({
            "generation": 9,
            "keyId": "release-2026",
            "kind": "7launcher-registry-set-v1",
            "productId": "sample-app",
            "schema": 1,
            "scopeId": "sample-language",
            "values": [{"data": "not base64", "name": "LanguageToken", "type": "binary"}]
        }),
        RELEASE_SEED,
        REGISTRY_SET_SIGNING_DOMAIN,
    );
    assert_eq!(
        verify_registry_set(
            &malformed,
            &keyring,
            RegistrySetAcceptance {
                allowed_values: &allowed_values,
                expected_product_id: "sample-app",
                expected_scope_id: "sample-language",
                previous: None,
            },
        )
        .expect_err("malformed base64 fails closed before registry access")
        .code(),
        ErrorCode::JsonInvalid
    );

    let noncanonical = sign_document(
        json!({
            "generation": 10,
            "keyId": "release-2026",
            "kind": "7launcher-registry-set-v1",
            "productId": "sample-app",
            "schema": 1,
            "scopeId": "sample-language",
            "values": [{"data": "AB==", "name": "LanguageToken", "type": "binary"}]
        }),
        RELEASE_SEED,
        REGISTRY_SET_SIGNING_DOMAIN,
    );
    assert_eq!(
        verify_registry_set(
            &noncanonical,
            &keyring,
            RegistrySetAcceptance {
                allowed_values: &allowed_values,
                expected_product_id: "sample-app",
                expected_scope_id: "sample-language",
                previous: None,
            },
        )
        .expect_err("non-canonical base64 pad bits fail closed")
        .code(),
        ErrorCode::JsonInvalid
    );

    let oversized = sign_document(
        json!({
            "generation": 10,
            "keyId": "release-2026",
            "kind": "7launcher-registry-set-v1",
            "productId": "sample-app",
            "schema": 1,
            "scopeId": "sample-language",
            "values": [{
                "data": BASE64_STANDARD.encode(vec![0_u8; MAX_REGISTRY_BINARY_BYTES + 1]),
                "name": "LanguageToken",
                "type": "binary"
            }]
        }),
        RELEASE_SEED,
        REGISTRY_SET_SIGNING_DOMAIN,
    );
    assert_eq!(
        verify_registry_set(
            &oversized,
            &keyring,
            RegistrySetAcceptance {
                allowed_values: &allowed_values,
                expected_product_id: "sample-app",
                expected_scope_id: "sample-language",
                previous: None,
            },
        )
        .expect_err("oversized decoded binary fails before registry access")
        .code(),
        ErrorCode::RegistrySetLimit
    );

    let wrong_type_allowlist = vec![AllowedRegistryValue {
        name: "LanguageToken".to_owned(),
        value_type: RegistryValueKind::String,
    }];
    assert_eq!(
        verify_registry_set(
            &binary,
            &keyring,
            RegistrySetAcceptance {
                allowed_values: &wrong_type_allowlist,
                expected_product_id: "sample-app",
                expected_scope_id: "sample-language",
                previous: None,
            },
        )
        .expect_err("binary cannot bypass a string-only allowlist")
        .code(),
        ErrorCode::RegistryScopeUnauthorized
    );
}

#[test]
fn contract_rejects_traversal_and_oversized_input() {
    let keyring = verified_keyring();
    let traversal = sign_document(
        file_set_payload(43, "../outside.exe"),
        RELEASE_SEED,
        FILE_SET_SIGNING_DOMAIN,
    );
    assert_eq!(
        verify_file_set(
            &traversal,
            &keyring,
            FileSetAcceptance {
                expected_product_id: "sample-app",
                previous: None,
            },
        )
        .expect_err("traversal is rejected")
        .code(),
        ErrorCode::FileSetPath
    );

    let reserved = sign_document(
        file_set_payload(43, ".7launcher-maintenance/jobs/payload.bin"),
        RELEASE_SEED,
        FILE_SET_SIGNING_DOMAIN,
    );
    assert_eq!(
        verify_file_set(
            &reserved,
            &keyring,
            FileSetAcceptance {
                expected_product_id: "sample-app",
                previous: None,
            },
        )
        .expect_err("the internal transaction namespace is reserved")
        .code(),
        ErrorCode::FileSetPath
    );

    let oversized = vec![b' '; seven_launcher_maintenance::MAX_MANIFEST_BYTES + 1];
    assert_eq!(
        verify_keyring_with_root(
            &oversized,
            KeyringAcceptance::default(),
            &SigningKey::from_bytes(&ROOT_SEED)
                .verifying_key()
                .to_bytes(),
        )
        .expect_err("oversized document is rejected before parsing")
        .code(),
        ErrorCode::ManifestTooLarge
    );
}

#[test]
fn contract_ipc_v1_is_bounded_and_has_only_typed_commands() {
    let request = decode_request(br#"{"command":"GetStatus","protocolMajor":1}"#)
        .expect("GetStatus is supported");
    assert!(matches!(request, Request::GetStatus { .. }));

    let root_status =
        decode_request(br#"{"command":"GetRootStatus","protocolMajor":1,"rootId":"library-d"}"#)
            .expect("exact registered-root lookup is supported");
    assert!(matches!(root_status, Request::GetRootStatus { .. }));

    let registry_scope_status = decode_request(
        br#"{"command":"GetRegistryScopeStatus","protocolMajor":1,"scopeId":"sample-language"}"#,
    )
    .expect("exact registry-scope lookup is supported");
    assert!(matches!(
        registry_scope_status,
        Request::GetRegistryScopeStatus { .. }
    ));

    let library = decode_request(
        br#"{"command":"RegisterRoot","path":"D:\\7Launcher\\7Apps","productId":"7apps","protocolMajor":1,"rootId":"library-d","rootKind":"library"}"#,
    )
    .expect("library root is supported by the typed IPC v1 contract");
    assert!(matches!(
        library,
        Request::RegisterRoot {
            root_kind: RootKind::Library,
            ..
        }
    ));

    let registry_scope = decode_request(
        br#"{"allowedValues":[{"name":"Language","type":"string"}],"command":"RegisterRegistryScope","productId":"sample-app","protocolMajor":1,"scopeId":"sample-language","subkey":"SOFTWARE\\ExampleVendor\\SampleApp","view":"registry32"}"#,
    )
    .expect("bounded registry-scope registration is supported");
    assert!(matches!(
        registry_scope,
        Request::RegisterRegistryScope { .. }
    ));

    let unsupported = decode_request(br#"{"command":"Run","protocolMajor":1}"#)
        .expect_err("generic Run command must never be supported");
    assert_eq!(unsupported.code(), ErrorCode::ProtocolInvalid);

    let future = decode_request(br#"{"command":"GetStatus","protocolMajor":2}"#)
        .expect_err("unknown major versions fail closed");
    assert_eq!(future.code(), ErrorCode::ProtocolVersion);

    let oversized = vec![b' '; seven_launcher_maintenance::MAX_IPC_MESSAGE_BYTES + 1];
    assert_eq!(
        decode_request(&oversized)
            .expect_err("oversized IPC is rejected before parsing")
            .code(),
        ErrorCode::ProtocolTooLarge
    );
}

#[test]
fn contract_accepts_service_generated_job_ids() {
    let job_id = format!("launcher-sample-app-42-{}", "ab".repeat(32));
    let encoded = serde_json::to_vec(&json!({
        "command": "CommitJob",
        "jobId": job_id,
        "protocolMajor": 1
    }))
    .expect("request encodes");

    let request = decode_request(&encoded).expect("service-generated job ID must round-trip IPC");
    assert!(matches!(request, Request::CommitJob { .. }));

    let maximum_job_id = format!("{}-{}-{}", "a".repeat(64), u64::MAX, "ab".repeat(32));
    let encoded = serde_json::to_vec(&json!({
        "command": "GetJobStatus",
        "jobId": maximum_job_id,
        "protocolMajor": 1
    }))
    .expect("maximum request encodes");
    assert!(matches!(
        decode_request(&encoded).expect("maximum service-generated job ID is valid"),
        Request::GetJobStatus { .. }
    ));

    for invalid_job_id in [
        format!("launcher-sample-app-0-{}", "ab".repeat(32)),
        format!("launcher-sample-app-042-{}", "ab".repeat(32)),
        format!("launcher-sample-app-42-{}", "AB".repeat(32)),
        format!("{}-42-{}", "a".repeat(65), "ab".repeat(32)),
    ] {
        let encoded = serde_json::to_vec(&json!({
            "command": "GetJobStatus",
            "jobId": invalid_job_id,
            "protocolMajor": 1
        }))
        .expect("request encodes");
        assert_eq!(
            decode_request(&encoded)
                .expect_err("malformed job ID must fail closed")
                .code(),
            ErrorCode::ProtocolInvalid
        );
    }
}
