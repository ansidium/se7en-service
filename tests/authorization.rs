#![forbid(unsafe_code)]

#[cfg(windows)]
mod windows_authorization {
    use std::{fs, path::PathBuf, time::SystemTime};

    use seven_launcher_maintenance::{
        AllowedRegistryValue, RegisteredRegistryScope, RegisteredRoot, RegistryScopeRegistry,
        RegistryValueKind, RegistryView, RootRegistry,
        protocol::{Request, RootKind},
        windows::{
            AuthorizedRequest, CallerIdentity, FILE_CREATE_PIPE_INSTANCE_BIT,
            PIPE_CLIENT_ACCESS_MASK, authorize_request,
        },
    };

    const OWNER_SID: &str = "S-1-5-21-1000";
    const OTHER_SID: &str = "S-1-5-21-2000";

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn create(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "seven-maintenance-auth-{label}-{}-{nanos}",
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

    fn registry() -> (TempDirectory, RootRegistry) {
        let directory = TempDirectory::create("root");
        let root = RegisteredRoot::from_verified_path(
            "launcher-root",
            "sample-app",
            RootKind::Launcher,
            &directory.0,
            OWNER_SID,
        )
        .expect("registered root");
        let mut roots = RootRegistry::new();
        roots.register(root).expect("insert root");
        (directory, roots)
    }

    fn library_registry() -> (TempDirectory, RootRegistry) {
        let directory = TempDirectory::create("library");
        let root = RegisteredRoot::from_verified_path(
            "shared-library",
            "7apps",
            RootKind::Library,
            &directory.0,
            OWNER_SID,
        )
        .expect("registered library");
        let mut roots = RootRegistry::new();
        roots.register(root).expect("insert library");
        (directory, roots)
    }

    fn registry_scopes() -> RegistryScopeRegistry {
        let mut scopes = RegistryScopeRegistry::new();
        scopes
            .register(
                RegisteredRegistryScope::new(
                    "sample-language",
                    "sample-app",
                    RegistryView::Registry32,
                    r"SOFTWARE\ExampleVendor\SampleApp",
                    vec![AllowedRegistryValue {
                        name: "Language".to_owned(),
                        value_type: RegistryValueKind::String,
                    }],
                    OWNER_SID,
                )
                .expect("registered registry scope"),
            )
            .expect("insert registry scope");
        scopes
    }

    #[test]
    fn ordinary_user_cannot_register_or_unregister_roots() {
        let (_directory, roots) = registry();
        let scopes = RegistryScopeRegistry::new();
        let caller = CallerIdentity::new(OWNER_SID, false).expect("caller");
        let register = Request::RegisterRoot {
            protocol_major: 1,
            root_id: "new-root".to_owned(),
            product_id: "sample-app".to_owned(),
            root_kind: RootKind::Launcher,
            path: r"C:\Games\SampleApp".to_owned(),
        };
        let unregister = Request::UnregisterRoot {
            protocol_major: 1,
            root_id: "launcher-root".to_owned(),
        };

        assert!(authorize_request(&register, &caller, &roots, &scopes, None).is_err());
        assert!(authorize_request(&unregister, &caller, &roots, &scopes, None).is_err());
    }

    #[test]
    fn elevated_registration_binds_owner_to_token_sid() {
        let (_directory, roots) = registry();
        let scopes = RegistryScopeRegistry::new();
        let caller = CallerIdentity::new(OWNER_SID, true).expect("caller");
        let request = Request::RegisterRoot {
            protocol_major: 1,
            root_id: "library-d".to_owned(),
            product_id: "7apps".to_owned(),
            root_kind: RootKind::Library,
            path: r"D:\7Launcher\7Apps".to_owned(),
        };

        assert_eq!(
            authorize_request(&request, &caller, &roots, &scopes, None).expect("authorized"),
            AuthorizedRequest::RegisterRoot {
                owner_sid: OWNER_SID.to_owned()
            }
        );
    }

    #[test]
    fn prepare_is_limited_to_the_callers_registered_root() {
        let (_directory, roots) = registry();
        let scopes = RegistryScopeRegistry::new();
        let request = Request::PrepareFileSet {
            protocol_major: 1,
            root_id: "launcher-root".to_owned(),
            manifest_path: r"C:\Users\owner\manifest.json".to_owned(),
            staging_path: r"C:\Users\owner\staging".to_owned(),
        };
        let owner = CallerIdentity::new(OWNER_SID, false).expect("owner");
        let other = CallerIdentity::new(OTHER_SID, false).expect("other");

        assert!(matches!(
            authorize_request(&request, &owner, &roots, &scopes, None),
            Ok(AuthorizedRequest::PrepareFileSet { .. })
        ));
        assert!(authorize_request(&request, &other, &roots, &scopes, None).is_err());
    }

    #[test]
    fn commit_and_status_are_limited_to_job_owner() {
        let (_directory, roots) = registry();
        let scopes = RegistryScopeRegistry::new();
        let commit = Request::CommitJob {
            protocol_major: 1,
            job_id: "job-1".to_owned(),
        };
        let status = Request::GetJobStatus {
            protocol_major: 1,
            job_id: "job-1".to_owned(),
        };
        let owner = CallerIdentity::new(OWNER_SID, false).expect("owner");
        let other = CallerIdentity::new(OTHER_SID, false).expect("other");
        let active = Some(("job-1", OWNER_SID));

        assert!(authorize_request(&commit, &owner, &roots, &scopes, active).is_ok());
        assert!(authorize_request(&status, &owner, &roots, &scopes, active).is_ok());
        assert!(authorize_request(&commit, &other, &roots, &scopes, active).is_err());
        assert!(authorize_request(&status, &other, &roots, &scopes, active).is_err());
    }

    #[test]
    fn registry_apply_is_limited_to_the_scope_owner() {
        let (_directory, roots) = registry();
        let scopes = registry_scopes();
        let request = Request::ApplyRegistrySet {
            protocol_major: 1,
            scope_id: "sample-language".to_owned(),
            manifest_path: r"C:\Users\owner\registry-set-v1.json".to_owned(),
        };
        let owner = CallerIdentity::new(OWNER_SID, false).expect("owner");
        let other = CallerIdentity::new(OTHER_SID, false).expect("other");

        assert!(matches!(
            authorize_request(&request, &owner, &roots, &scopes, None),
            Ok(AuthorizedRequest::ApplyRegistrySet { .. })
        ));
        assert!(authorize_request(&request, &other, &roots, &scopes, None).is_err());
    }

    #[test]
    fn pipe_client_mask_excludes_create_pipe_instance() {
        assert_eq!(PIPE_CLIENT_ACCESS_MASK & FILE_CREATE_PIPE_INSTANCE_BIT, 0);
    }

    #[test]
    fn register_root_rejects_caller_supplied_owner_sid() {
        let bytes = br#"{"command":"RegisterRoot","ownerSid":"S-1-5-18","path":"C:\\Games\\SampleApp","productId":"sample-app","protocolMajor":1,"rootId":"launcher-root","rootKind":"launcher"}"#;
        assert!(seven_launcher_maintenance::protocol::decode_request(bytes).is_err());
    }

    #[test]
    fn exact_root_and_registry_scope_status_are_limited_to_the_owner() {
        let (_directory, roots) = registry();
        let scopes = registry_scopes();
        let owner = CallerIdentity::new(OWNER_SID, false).expect("owner");
        let other = CallerIdentity::new(OTHER_SID, false).expect("other");
        let root_status = Request::GetRootStatus {
            protocol_major: 1,
            root_id: "launcher-root".to_owned(),
        };
        let scope_status = Request::GetRegistryScopeStatus {
            protocol_major: 1,
            scope_id: "sample-language".to_owned(),
        };

        assert!(matches!(
            authorize_request(&root_status, &owner, &roots, &scopes, None),
            Ok(AuthorizedRequest::GetRootStatus { .. })
        ));
        assert!(authorize_request(&root_status, &other, &roots, &scopes, None).is_err());
        assert!(matches!(
            authorize_request(&scope_status, &owner, &roots, &scopes, None),
            Ok(AuthorizedRequest::GetRegistryScopeStatus { .. })
        ));
        assert!(authorize_request(&scope_status, &other, &roots, &scopes, None).is_err());
    }

    #[test]
    fn shared_library_status_and_prepare_are_available_to_another_local_user() {
        let (_directory, roots) = library_registry();
        let scopes = RegistryScopeRegistry::new();
        let other = CallerIdentity::new(OTHER_SID, false).expect("other");
        let root_status = Request::GetRootStatus {
            protocol_major: 1,
            root_id: "shared-library".to_owned(),
        };
        let prepare = Request::PrepareFileSet {
            protocol_major: 1,
            root_id: "shared-library".to_owned(),
            manifest_path: r"C:\Users\other\manifest.json".to_owned(),
            staging_path: r"C:\Users\other\staging".to_owned(),
        };

        assert!(matches!(
            authorize_request(&root_status, &other, &roots, &scopes, None),
            Ok(AuthorizedRequest::GetRootStatus { .. })
        ));
        assert!(matches!(
            authorize_request(&prepare, &other, &roots, &scopes, None),
            Ok(AuthorizedRequest::PrepareFileSet { .. })
        ));
        assert_eq!(roots.accessible_root_count(OTHER_SID), 1);
    }
}
