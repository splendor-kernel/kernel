use super::*;
use splendor_authority::secret_provider_test_support::{
    exercise_secret_provider_control, exercise_secret_provider_fetch,
    SecretProviderTestControlObservation, SecretProviderTestInvocation,
};
use splendor_types::{
    CanonicalTimestampV1, SecretDeliveryHandleId, SecretLeaseId, SecretProviderAuditId,
    SecretUseAttemptId, SecretUseClaimId,
};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use tempfile::TempDir;
use uuid::Uuid;

fn uuid(index: u128) -> Uuid {
    Uuid::from_u128(0x018f_0a1b_2c3d_4e5f_8a9b_3000_0000_0000 + index)
}

fn secret_id<T>(index: u128) -> T
where
    T: TryFrom<Uuid>,
    T::Error: fmt::Debug,
{
    T::try_from(uuid(index)).unwrap()
}

fn tenant(index: u128) -> TenantId {
    TenantId::from(uuid(index))
}

fn provider_id_for(index: u128) -> SecretProviderId {
    secret_id(index)
}

fn ref_id(index: u128) -> SecretRefId {
    secret_id(index)
}

fn version(value: &str) -> SecretProviderVersionRef {
    value.parse().unwrap()
}

fn timestamp() -> CanonicalTimestampV1 {
    "2026-07-26T12:00:00.000000Z".parse().unwrap()
}

fn invocation(
    provider_id: SecretProviderId,
    tenant_id: TenantId,
    secret_ref_id: SecretRefId,
    revision: u64,
    provider_version_ref: SecretProviderVersionRef,
    seed: u128,
) -> SecretProviderTestInvocation {
    SecretProviderTestInvocation::try_new(
        secret_id::<SecretProviderAuditId>(seed),
        provider_id,
        tenant_id,
        secret_ref_id,
        revision,
        provider_version_ref,
        secret_id::<SecretLeaseId>(seed + 1),
        secret_id::<SecretDeliveryHandleId>(seed + 2),
        secret_id::<SecretUseClaimId>(seed + 3),
        secret_id::<SecretUseAttemptId>(seed + 4),
        timestamp(),
    )
    .unwrap()
}

fn secure_root() -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let canonical = fs::canonicalize(directory.path()).unwrap();
    (directory, canonical)
}

fn write_secure(root: &Path, relative: &Path, bytes: &[u8]) {
    if let Some(parent) = relative
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        let mut current = root.to_path_buf();
        for component in parent.components() {
            let Component::Normal(name) = component else {
                panic!("test path must be relative and normal");
            };
            current.push(name);
            if !current.exists() {
                fs::create_dir(&current).unwrap();
            }
            fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let path = root.join(relative);
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn entry(
    tenant_id: TenantId,
    secret_ref_id: SecretRefId,
    revision: u64,
    provider_version_ref: SecretProviderVersionRef,
    relative_path: &str,
) -> LocalFileSecretProviderEntry {
    LocalFileSecretProviderEntry::new(
        tenant_id,
        secret_ref_id,
        revision,
        provider_version_ref,
        PathBuf::from(relative_path),
    )
}

fn configured_provider(
    root: PathBuf,
    provider: SecretProviderId,
    tenant_id: TenantId,
    secret_ref_id: SecretRefId,
    provider_version_ref: SecretProviderVersionRef,
    relative_path: &str,
) -> LocalFileSecretProvider {
    LocalFileSecretProvider::try_new(
        provider,
        LocalFileSecretProviderRuntimeMode::Test,
        root,
        vec![entry(
            tenant_id,
            secret_ref_id,
            1,
            provider_version_ref,
            relative_path,
        )],
    )
    .unwrap()
}

#[test]
fn exact_fetch_uses_real_authority_port_without_material_escape() {
    let (_directory, root) = secure_root();
    let relative = Path::new("nested/provider-material");
    let synthetic_canary = b"C03_LOCAL_FILE_SYMBOLIC_CANARY";
    write_secure(&root, relative, synthetic_canary);

    let provider_id = provider_id_for(1);
    let tenant_id = tenant(2);
    let secret_ref_id = ref_id(3);
    let provider_version = version("version-1");
    let provider = configured_provider(
        root,
        provider_id.clone(),
        tenant_id.clone(),
        secret_ref_id.clone(),
        provider_version.clone(),
        "nested/provider-material",
    );
    let request = invocation(
        provider_id.clone(),
        tenant_id.clone(),
        secret_ref_id.clone(),
        1,
        provider_version.clone(),
        10,
    );

    let observation = exercise_secret_provider_fetch(&provider, &request).unwrap();
    assert_eq!(observation.material_len(), synthetic_canary.len());
    assert_eq!(observation.audit().secret_provider_id(), &provider_id);
    assert_eq!(observation.audit().tenant_id(), &tenant_id);
    assert_eq!(observation.audit().secret_ref_id(), &secret_ref_id);
    assert_eq!(observation.audit().secret_ref_revision(), 1);
    assert_eq!(
        observation.audit().provider_version_ref(),
        &provider_version
    );
    assert_eq!(
        observation.audit().operation(),
        SecretProviderOperation::Fetch
    );
    assert_eq!(
        observation.audit().outcome(),
        SecretProviderOutcome::Succeeded
    );
    assert_eq!(provider.fetch_call_count(), 1);
    assert_eq!(
        format!("{observation:?}"),
        "SecretProviderTestFetchObservation(<redacted>)"
    );
    assert_eq!(
        format!("{request:?}"),
        "SecretProviderTestInvocation(<redacted>)"
    );
}

#[test]
fn exact_lookup_denies_wrong_provider_tenant_ref_revision_and_version() {
    let (_directory, root) = secure_root();
    write_secure(&root, Path::new("material"), b"synthetic");
    let provider_id = provider_id_for(30);
    let tenant_id = tenant(31);
    let secret_ref_id = ref_id(32);
    let provider_version = version("version-1");
    let provider = configured_provider(
        root,
        provider_id.clone(),
        tenant_id.clone(),
        secret_ref_id.clone(),
        provider_version.clone(),
        "material",
    );
    let requests = [
        invocation(
            provider_id_for(33),
            tenant_id.clone(),
            secret_ref_id.clone(),
            1,
            provider_version.clone(),
            40,
        ),
        invocation(
            provider_id.clone(),
            tenant(34),
            secret_ref_id.clone(),
            1,
            provider_version.clone(),
            50,
        ),
        invocation(
            provider_id.clone(),
            tenant_id.clone(),
            ref_id(35),
            1,
            provider_version.clone(),
            60,
        ),
        invocation(
            provider_id.clone(),
            tenant_id.clone(),
            secret_ref_id.clone(),
            2,
            provider_version.clone(),
            70,
        ),
        invocation(
            provider_id,
            tenant_id,
            secret_ref_id,
            1,
            version("version-2"),
            80,
        ),
    ];
    for request in requests {
        assert_eq!(
            exercise_secret_provider_fetch(&provider, &request)
                .unwrap_err()
                .code(),
            SecretProviderErrorCode::VersionNotAvailable
        );
    }
}

#[test]
fn construction_requires_explicit_local_mode_absolute_root_and_nonempty_map() {
    for mode in [
        LocalFileSecretProviderRuntimeMode::Resident,
        LocalFileSecretProviderRuntimeMode::Remote,
        LocalFileSecretProviderRuntimeMode::Fleet,
        LocalFileSecretProviderRuntimeMode::Production,
        LocalFileSecretProviderRuntimeMode::Unknown,
    ] {
        assert_eq!(
            LocalFileSecretProvider::try_new(
                provider_id_for(100),
                mode,
                PathBuf::from("implicit-root"),
                Vec::new(),
            )
            .unwrap_err(),
            LocalFileSecretProviderConfigError::UnsupportedRuntimeMode
        );
    }

    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(101),
            LocalFileSecretProviderRuntimeMode::Test,
            PathBuf::from("relative-root"),
            vec![entry(tenant(102), ref_id(103), 1, version("v1"), "file")],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::InvalidTrustedRoot
    );
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(104),
            LocalFileSecretProviderRuntimeMode::Test,
            PathBuf::from("/tmp/../tmp"),
            vec![entry(tenant(105), ref_id(106), 1, version("v1"), "file")],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::InvalidTrustedRoot
    );

    let (_directory, root) = secure_root();
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(107),
            LocalFileSecretProviderRuntimeMode::Test,
            root,
            Vec::new(),
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::InvalidCoordinates
    );

    for (invalid_tenant, invalid_revision) in [
        (TenantId::from(Uuid::nil()), 1),
        (tenant(108), 0),
        (tenant(109), MAX_SAFE_INTEGER + 1),
    ] {
        assert_eq!(
            SecretProviderTestInvocation::try_new(
                secret_id(110),
                provider_id_for(111),
                invalid_tenant,
                ref_id(112),
                invalid_revision,
                version("v1"),
                secret_id(113),
                secret_id(114),
                secret_id(115),
                secret_id(116),
                timestamp(),
            )
            .unwrap_err()
            .code(),
            SecretProviderErrorCode::IntegrityFailure
        );
    }
}

#[test]
fn local_development_mode_is_explicitly_supported() {
    let (_directory, root) = secure_root();
    write_secure(&root, Path::new("material"), b"synthetic");
    LocalFileSecretProvider::try_new(
        provider_id_for(120),
        LocalFileSecretProviderRuntimeMode::LocalDevelopment,
        root,
        vec![entry(
            tenant(121),
            ref_id(122),
            1,
            version("v1"),
            "material",
        )],
    )
    .unwrap();
}

#[test]
fn coordinates_paths_duplicates_and_capacity_fail_before_file_access() {
    let (_directory, root) = secure_root();
    for invalid in [
        "../outside",
        "/absolute",
        ".",
        "nested/../material",
        "nested//material",
        "nested/material/",
        "bad\0component",
    ] {
        assert_eq!(
            LocalFileSecretProvider::try_new(
                provider_id_for(130),
                LocalFileSecretProviderRuntimeMode::Test,
                root.clone(),
                vec![entry(tenant(131), ref_id(132), 1, version("v1"), invalid,)],
            )
            .unwrap_err(),
            LocalFileSecretProviderConfigError::InvalidRelativePath
        );
    }
    let overlong_component = "x".repeat(MAX_PATH_COMPONENT_BYTES + 1);
    let overdeep_path = std::iter::repeat_n("a", MAX_RELATIVE_PATH_COMPONENTS + 1)
        .collect::<Vec<_>>()
        .join("/");
    let overlong_path = std::iter::repeat_n("x".repeat(250), 17)
        .collect::<Vec<_>>()
        .join("/");
    for invalid in [overlong_component, overdeep_path, overlong_path] {
        assert_eq!(
            LocalFileSecretProvider::try_new(
                provider_id_for(130),
                LocalFileSecretProviderRuntimeMode::Test,
                root.clone(),
                vec![entry(tenant(131), ref_id(132), 1, version("v1"), &invalid,)],
            )
            .unwrap_err(),
            LocalFileSecretProviderConfigError::InvalidRelativePath
        );
    }
    for invalid_entry in [
        entry(
            TenantId::from(Uuid::nil()),
            ref_id(133),
            1,
            version("v1"),
            "missing-a",
        ),
        entry(tenant(134), ref_id(135), 0, version("v1"), "missing-b"),
        entry(
            tenant(136),
            ref_id(137),
            MAX_SAFE_INTEGER + 1,
            version("v1"),
            "missing-c",
        ),
    ] {
        assert_eq!(
            LocalFileSecretProvider::try_new(
                provider_id_for(138),
                LocalFileSecretProviderRuntimeMode::Test,
                root.clone(),
                vec![invalid_entry],
            )
            .unwrap_err(),
            LocalFileSecretProviderConfigError::InvalidCoordinates
        );
    }

    let duplicate = || entry(tenant(140), ref_id(141), 1, version("v1"), "missing");
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(142),
            LocalFileSecretProviderRuntimeMode::Test,
            root.clone(),
            vec![duplicate(), duplicate()],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::DuplicateCoordinates
    );
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(143),
            LocalFileSecretProviderRuntimeMode::Test,
            root.clone(),
            vec![
                entry(tenant(144), ref_id(145), 1, version("v1"), "missing"),
                entry(tenant(144), ref_id(146), 1, version("v1"), "missing"),
            ],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::AmbiguousPath
    );

    let over_capacity = (0..=MAX_CONFIGURED_ENTRIES)
        .map(|index| {
            entry(
                tenant(150),
                ref_id(1_000 + index as u128),
                1,
                version("v1"),
                &format!("missing-{index}"),
            )
        })
        .collect();
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(151),
            LocalFileSecretProviderRuntimeMode::Test,
            root,
            over_capacity,
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::CapacityExceeded
    );
}

#[test]
fn missing_symlink_nonregular_and_insecure_files_fail_closed() {
    let (_directory, root) = secure_root();
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(200),
            LocalFileSecretProviderRuntimeMode::Test,
            root.clone(),
            vec![entry(tenant(201), ref_id(202), 1, version("v1"), "missing")],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::PathUnavailable
    );

    write_secure(&root, Path::new("target"), b"synthetic");
    symlink("target", root.join("link")).unwrap();
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(203),
            LocalFileSecretProviderRuntimeMode::Test,
            root.clone(),
            vec![entry(tenant(204), ref_id(205), 1, version("v1"), "link")],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::FilesystemPolicyDenied
    );

    fs::create_dir(root.join("directory-entry")).unwrap();
    fs::set_permissions(
        root.join("directory-entry"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(206),
            LocalFileSecretProviderRuntimeMode::Test,
            root.clone(),
            vec![entry(
                tenant(207),
                ref_id(208),
                1,
                version("v1"),
                "directory-entry",
            )],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::FilesystemPolicyDenied
    );

    write_secure(&root, Path::new("insecure"), b"synthetic");
    fs::set_permissions(root.join("insecure"), fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(209),
            LocalFileSecretProviderRuntimeMode::Test,
            root,
            vec![entry(
                tenant(210),
                ref_id(211),
                1,
                version("v1"),
                "insecure",
            )],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::FilesystemPolicyDenied
    );
}

#[test]
fn root_intermediate_owner_and_hard_link_policies_are_enforced() {
    let (_directory, root) = secure_root();
    write_secure(&root, Path::new("linked"), b"synthetic");
    fs::hard_link(root.join("linked"), root.join("alias")).unwrap();
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(220),
            LocalFileSecretProviderRuntimeMode::Test,
            root.clone(),
            vec![entry(tenant(221), ref_id(222), 1, version("v1"), "linked")],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::FilesystemPolicyDenied
    );

    write_secure(&root, Path::new("nested/material"), b"synthetic");
    fs::set_permissions(root.join("nested"), fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(223),
            LocalFileSecretProviderRuntimeMode::Test,
            root.clone(),
            vec![entry(
                tenant(224),
                ref_id(225),
                1,
                version("v1"),
                "nested/material",
            )],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::FilesystemPolicyDenied
    );

    fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(226),
            LocalFileSecretProviderRuntimeMode::Test,
            root.clone(),
            vec![entry(tenant(227), ref_id(228), 1, version("v1"), "alias")],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::FilesystemPolicyDenied
    );

    let metadata = fs::metadata(root.join("alias")).unwrap();
    assert!(matches!(
        validate_secret_file_metadata(&metadata, effective_uid().wrapping_add(1)),
        Err(OpenFailure::PolicyDenied)
    ));

    let file = File::open(root.join("alias")).unwrap();
    assert!(matches!(
        fingerprint_for_open_file(&file, effective_uid()),
        Err(OpenFailure::PolicyDenied)
    ));

    let (_source_directory, source_root) = secure_root();
    write_secure(&source_root, Path::new("source"), b"synthetic");
    let source_file = File::open(source_root.join("source")).unwrap();
    let source_fingerprint = match fingerprint_for_open_file(&source_file, effective_uid()) {
        Ok(fingerprint) => fingerprint,
        Err(_) => panic!("secure source fingerprint must be available"),
    };
    let mut backing_sources = HashSet::new();
    assert_eq!(
        register_unique_backing_source(&mut backing_sources, &source_fingerprint),
        Ok(())
    );
    assert_eq!(
        register_unique_backing_source(&mut backing_sources, &source_fingerprint),
        Err(LocalFileSecretProviderConfigError::AmbiguousPath),
        "distinct configured paths may not alias one device/inode backing source"
    );
}

#[test]
fn symlinked_trusted_root_is_rejected() {
    let (parent, root) = secure_root();
    let actual = root.join("actual");
    fs::create_dir(&actual).unwrap();
    fs::set_permissions(&actual, fs::Permissions::from_mode(0o700)).unwrap();
    write_secure(&actual, Path::new("material"), b"synthetic");
    let linked = root.join("linked-root");
    symlink(&actual, &linked).unwrap();
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(230),
            LocalFileSecretProviderRuntimeMode::Test,
            linked,
            vec![entry(
                tenant(231),
                ref_id(232),
                1,
                version("v1"),
                "material"
            )],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::FilesystemPolicyDenied
    );
    drop(parent);
}

#[test]
fn empty_and_oversized_material_are_rejected() {
    let (_empty_directory, empty_root) = secure_root();
    write_secure(&empty_root, Path::new("empty"), b"");
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(240),
            LocalFileSecretProviderRuntimeMode::Test,
            empty_root,
            vec![entry(tenant(241), ref_id(242), 1, version("v1"), "empty")],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::InvalidMaterial
    );

    let (_large_directory, large_root) = secure_root();
    write_secure(
        &large_root,
        Path::new("large"),
        &vec![b'x'; MAX_MATERIAL_BYTES + 1],
    );
    assert_eq!(
        LocalFileSecretProvider::try_new(
            provider_id_for(243),
            LocalFileSecretProviderRuntimeMode::Test,
            large_root,
            vec![entry(tenant(244), ref_id(245), 1, version("v1"), "large")],
        )
        .unwrap_err(),
        LocalFileSecretProviderConfigError::InvalidMaterial
    );

    let (_maximum_directory, maximum_root) = secure_root();
    write_secure(
        &maximum_root,
        Path::new("maximum"),
        &vec![b'x'; MAX_MATERIAL_BYTES],
    );
    let maximum_provider_id = provider_id_for(246);
    let maximum_tenant = tenant(247);
    let maximum_ref = ref_id(248);
    let maximum_version = version("v1");
    let maximum_provider = configured_provider(
        maximum_root,
        maximum_provider_id.clone(),
        maximum_tenant.clone(),
        maximum_ref.clone(),
        maximum_version.clone(),
        "maximum",
    );
    let maximum_request = invocation(
        maximum_provider_id,
        maximum_tenant,
        maximum_ref,
        1,
        maximum_version,
        249,
    );
    assert_eq!(
        exercise_secret_provider_fetch(&maximum_provider, &maximum_request)
            .unwrap()
            .material_len(),
        MAX_MATERIAL_BYTES
    );
}

#[test]
fn changed_and_missing_registered_files_fail_on_fetch() {
    let (_changed_directory, changed_root) = secure_root();
    write_secure(&changed_root, Path::new("material"), b"original");
    let changed_provider_id = provider_id_for(250);
    let changed_tenant = tenant(251);
    let changed_ref = ref_id(252);
    let changed_version = version("v1");
    let changed_provider = configured_provider(
        changed_root.clone(),
        changed_provider_id.clone(),
        changed_tenant.clone(),
        changed_ref.clone(),
        changed_version.clone(),
        "material",
    );
    fs::write(changed_root.join("material"), b"replacement-material").unwrap();
    let changed_request = invocation(
        changed_provider_id,
        changed_tenant,
        changed_ref,
        1,
        changed_version,
        260,
    );
    assert_eq!(
        exercise_secret_provider_fetch(&changed_provider, &changed_request)
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::IntegrityFailure
    );
    assert_eq!(
        exercise_secret_provider_control(
            &changed_provider,
            &changed_request,
            SecretProviderOperation::Audit,
        )
        .unwrap_err()
        .code(),
        SecretProviderErrorCode::IntegrityFailure
    );
    match exercise_secret_provider_control(
        &changed_provider,
        &changed_request,
        SecretProviderOperation::ActiveProbe,
    )
    .unwrap()
    {
        SecretProviderTestControlObservation::Health(health) => assert!(!health.available()),
        SecretProviderTestControlObservation::Audit(_) => panic!("expected health evidence"),
    }

    let (_missing_directory, missing_root) = secure_root();
    write_secure(&missing_root, Path::new("material"), b"original");
    let missing_provider_id = provider_id_for(270);
    let missing_tenant = tenant(271);
    let missing_ref = ref_id(272);
    let missing_version = version("v1");
    let missing_provider = configured_provider(
        missing_root.clone(),
        missing_provider_id.clone(),
        missing_tenant.clone(),
        missing_ref.clone(),
        missing_version.clone(),
        "material",
    );
    fs::remove_file(missing_root.join("material")).unwrap();
    let missing_request = invocation(
        missing_provider_id,
        missing_tenant,
        missing_ref,
        1,
        missing_version,
        280,
    );
    assert_eq!(
        exercise_secret_provider_fetch(&missing_provider, &missing_request)
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::Unavailable
    );
}

#[test]
fn audit_health_outage_and_unsupported_controls_have_safe_semantics() {
    let (_directory, root) = secure_root();
    write_secure(&root, Path::new("material"), b"synthetic");
    let provider_id = provider_id_for(300);
    let tenant_id = tenant(301);
    let secret_ref_id = ref_id(302);
    let provider_version = version("v1");
    let provider = configured_provider(
        root.clone(),
        provider_id.clone(),
        tenant_id.clone(),
        secret_ref_id.clone(),
        provider_version.clone(),
        "material",
    );
    let request = invocation(
        provider_id.clone(),
        tenant_id,
        secret_ref_id,
        1,
        provider_version,
        310,
    );

    let audit_observation =
        exercise_secret_provider_control(&provider, &request, SecretProviderOperation::Audit)
            .unwrap();
    assert_eq!(
        format!("{audit_observation:?}"),
        "SecretProviderTestControlObservation(<redacted>)"
    );
    match audit_observation {
        SecretProviderTestControlObservation::Audit(audit) => {
            assert_eq!(audit.operation(), SecretProviderOperation::Audit);
            assert_eq!(audit.outcome(), SecretProviderOutcome::Succeeded);
        }
        SecretProviderTestControlObservation::Health(_) => panic!("expected audit evidence"),
    }
    match exercise_secret_provider_control(
        &provider,
        &request,
        SecretProviderOperation::ActiveProbe,
    )
    .unwrap()
    {
        SecretProviderTestControlObservation::Health(health) => assert!(health.available()),
        SecretProviderTestControlObservation::Audit(_) => panic!("expected health evidence"),
    }
    for operation in [
        SecretProviderOperation::Renew,
        SecretProviderOperation::Revoke,
    ] {
        assert_eq!(
            exercise_secret_provider_control(&provider, &request, operation)
                .unwrap_err()
                .code(),
            SecretProviderErrorCode::UnsupportedOperation
        );
    }
    assert!(root.join("material").is_file());
    assert!(exercise_secret_provider_fetch(&provider, &request).is_ok());

    provider.set_available(false);
    assert_eq!(
        exercise_secret_provider_fetch(&provider, &request)
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::Unavailable
    );
    match exercise_secret_provider_control(
        &provider,
        &request,
        SecretProviderOperation::ActiveProbe,
    )
    .unwrap()
    {
        SecretProviderTestControlObservation::Health(health) => assert!(!health.available()),
        SecretProviderTestControlObservation::Audit(_) => panic!("expected health evidence"),
    }
    assert_eq!(
        exercise_secret_provider_control(&provider, &request, SecretProviderOperation::Fetch)
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::IntegrityFailure
    );

    let wrong_provider_request = invocation(
        provider_id_for(320),
        tenant(301),
        ref_id(302),
        1,
        version("v1"),
        330,
    );
    assert_eq!(
        exercise_secret_provider_control(
            &provider,
            &wrong_provider_request,
            SecretProviderOperation::ActiveProbe,
        )
        .unwrap_err()
        .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
    assert_eq!(provider.control_call_count(), 6);
}

#[test]
fn poisoned_state_fails_fetch_and_health_closed() {
    let (_directory, root) = secure_root();
    write_secure(&root, Path::new("material"), b"synthetic");
    let provider_id = provider_id_for(350);
    let tenant_id = tenant(351);
    let secret_ref_id = ref_id(352);
    let provider_version = version("v1");
    let provider = configured_provider(
        root,
        provider_id.clone(),
        tenant_id.clone(),
        secret_ref_id.clone(),
        provider_version.clone(),
        "material",
    );
    let request = invocation(
        provider_id,
        tenant_id,
        secret_ref_id,
        1,
        provider_version,
        360,
    );
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _guard = provider.state.lock().unwrap();
        panic!("poison local-file provider state");
    }));
    assert_eq!(
        exercise_secret_provider_fetch(&provider, &request)
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::InternalFailure
    );
    assert_eq!(
        exercise_secret_provider_control(
            &provider,
            &request,
            SecretProviderOperation::ActiveProbe,
        )
        .unwrap_err()
        .code(),
        SecretProviderErrorCode::InternalFailure
    );
    provider.set_available(false);
}

#[test]
fn debug_and_error_surfaces_never_render_paths_coordinates_or_os_diagnostics() {
    let hostile = "HOSTILE_PATH_DIAGNOSTIC_CANARY";
    let (_directory, root) = secure_root();
    write_secure(&root, Path::new(hostile), b"synthetic");
    let provider_id = provider_id_for(400);
    let provider = configured_provider(
        root.clone(),
        provider_id.clone(),
        tenant(401),
        ref_id(402),
        version("v1"),
        hostile,
    );
    let rendered = format!("{provider:?}");
    assert_eq!(rendered, "LocalFileSecretProvider(<redacted>)");
    assert!(!rendered.contains(hostile));
    assert!(!rendered.contains(root.to_string_lossy().as_ref()));
    assert!(!rendered.contains(&provider_id.to_string()));

    let configured_entry = entry(tenant(403), ref_id(404), 1, version("v1"), hostile);
    assert_eq!(
        format!("{configured_entry:?}"),
        "LocalFileSecretProviderEntry(<redacted>)"
    );
    for error in [
        LocalFileSecretProviderConfigError::UnsupportedRuntimeMode,
        LocalFileSecretProviderConfigError::InvalidTrustedRoot,
        LocalFileSecretProviderConfigError::InvalidCoordinates,
        LocalFileSecretProviderConfigError::InvalidRelativePath,
        LocalFileSecretProviderConfigError::DuplicateCoordinates,
        LocalFileSecretProviderConfigError::AmbiguousPath,
        LocalFileSecretProviderConfigError::CapacityExceeded,
        LocalFileSecretProviderConfigError::PathUnavailable,
        LocalFileSecretProviderConfigError::FilesystemPolicyDenied,
        LocalFileSecretProviderConfigError::InvalidMaterial,
    ] {
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert_eq!(display, error.code());
        assert!(!display.contains(hostile));
        assert!(!debug.contains(hostile));
        assert!(!display.contains("os error"));
    }
}
