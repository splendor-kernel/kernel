use super::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use uuid::Uuid;

fn uuid(index: u128) -> Uuid {
    Uuid::from_u128(0x018f_0a1b_2c3d_4e5f_8a9b_1000_0000_0000 + index)
}

fn tenant(index: u128) -> TenantId {
    TenantId::from(uuid(index))
}

fn secret_id<T>(index: u128) -> T
where
    T: TryFrom<Uuid>,
    T::Error: fmt::Debug,
{
    T::try_from(uuid(index)).unwrap()
}

fn provider_id() -> SecretProviderId {
    secret_id(1)
}

fn ref_id() -> SecretRefId {
    secret_id(2)
}

fn version(value: &str) -> SecretProviderVersionRef {
    value.parse().unwrap()
}

fn coordinates<'a>(
    provider_id: &'a SecretProviderId,
    tenant_id: &'a TenantId,
    ref_id: &'a SecretRefId,
    version: &'a SecretProviderVersionRef,
) -> FetchCoordinates<'a> {
    FetchCoordinates {
        provider_id,
        tenant_id,
        secret_ref_id: ref_id,
        secret_ref_revision: 1,
        provider_version_ref: version,
    }
}

fn material(provider: &MemorySecretProvider, coordinates: FetchCoordinates<'_>) -> Vec<u8> {
    provider
        .with_entry(coordinates, |entry| Ok(entry.material.as_slice().to_vec()))
        .unwrap()
}

#[test]
fn construction_is_compile_gated_and_runtime_mode_restricted() {
    for mode in [
        MemorySecretProviderRuntimeMode::Resident,
        MemorySecretProviderRuntimeMode::Remote,
        MemorySecretProviderRuntimeMode::Fleet,
        MemorySecretProviderRuntimeMode::Production,
        MemorySecretProviderRuntimeMode::Unknown,
    ] {
        assert_eq!(
            MemorySecretProvider::try_new(provider_id(), mode).unwrap_err(),
            MemorySecretProviderConfigError::UnsupportedRuntimeMode
        );
    }
    MemorySecretProvider::try_new(provider_id(), MemorySecretProviderRuntimeMode::Test).unwrap();
    MemorySecretProvider::try_new(
        provider_id(),
        MemorySecretProviderRuntimeMode::LocalDevelopment,
    )
    .unwrap();
    assert_eq!(
        MemorySecretProvider::try_new_with_capacity(
            provider_id(),
            MemorySecretProviderRuntimeMode::Test,
            0,
        )
        .unwrap_err(),
        MemorySecretProviderConfigError::CapacityExceeded
    );
}

#[test]
fn provider_port_registration_is_passive_and_resolves_nothing() {
    let provider = Arc::new(
        MemorySecretProvider::try_new(provider_id(), MemorySecretProviderRuntimeMode::Test)
            .unwrap(),
    );
    provider
        .insert_synthetic(
            tenant(1),
            ref_id(),
            1,
            version("version-1"),
            b"synthetic".to_vec(),
        )
        .unwrap();
    let port: Arc<dyn SecretProvider> = provider.clone();
    assert_eq!(port.provider_id(), &provider_id());
    assert_eq!(provider.fetch_call_count(), 0);
    assert_eq!(provider.control_call_count(), 0);
}

#[test]
fn exact_lookup_denies_wrong_provider_tenant_ref_revision_and_version() {
    let provider_id = provider_id();
    let tenant_id = tenant(1);
    let ref_id = ref_id();
    let current_version = version("version-1");
    let provider =
        MemorySecretProvider::try_new(provider_id.clone(), MemorySecretProviderRuntimeMode::Test)
            .unwrap();
    provider
        .insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            current_version.clone(),
            b"exact".to_vec(),
        )
        .unwrap();
    assert_eq!(
        material(
            &provider,
            coordinates(&provider_id, &tenant_id, &ref_id, &current_version)
        ),
        b"exact"
    );

    let wrong_provider = secret_id(99);
    let wrong_ref = secret_id(98);
    for coordinate in [
        coordinates(&wrong_provider, &tenant_id, &ref_id, &current_version),
        coordinates(&provider_id, &tenant(2), &ref_id, &current_version),
        coordinates(&provider_id, &tenant_id, &wrong_ref, &current_version),
        coordinates(&provider_id, &tenant_id, &ref_id, &version("version-2")),
    ] {
        assert_eq!(
            provider
                .with_entry(coordinate, |_| Ok(()))
                .unwrap_err()
                .code(),
            SecretProviderErrorCode::VersionNotAvailable
        );
    }
    assert_eq!(
        provider
            .with_entry(
                FetchCoordinates {
                    provider_id: &provider_id,
                    tenant_id: &tenant_id,
                    secret_ref_id: &ref_id,
                    secret_ref_revision: 2,
                    provider_version_ref: &current_version,
                },
                |_| Ok(()),
            )
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
}

#[test]
fn outage_rotation_and_revocation_erase_old_entries() {
    let provider_id = provider_id();
    let tenant_id = tenant(1);
    let ref_id = ref_id();
    let old = version("version-1");
    let new = version("version-2");
    let provider =
        MemorySecretProvider::try_new(provider_id.clone(), MemorySecretProviderRuntimeMode::Test)
            .unwrap();
    provider
        .insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            old.clone(),
            b"old-material".to_vec(),
        )
        .unwrap();
    provider.set_available(false);
    assert_eq!(
        provider
            .with_entry(
                coordinates(&provider_id, &tenant_id, &ref_id, &old),
                |_| Ok(()),
            )
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::Unavailable
    );
    provider.set_available(true);
    provider
        .rotate_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            &old,
            new.clone(),
            b"new-material".to_vec(),
        )
        .unwrap();
    assert_eq!(
        provider
            .with_entry(
                coordinates(&provider_id, &tenant_id, &ref_id, &old),
                |_| Ok(()),
            )
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
    assert_eq!(
        material(
            &provider,
            coordinates(&provider_id, &tenant_id, &ref_id, &new)
        ),
        b"new-material"
    );
    provider
        .erase_coordinates(coordinates(&provider_id, &tenant_id, &ref_id, &new))
        .unwrap();
    assert_eq!(
        provider
            .with_entry(
                coordinates(&provider_id, &tenant_id, &ref_id, &new),
                |_| Ok(()),
            )
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
}

#[test]
fn finite_entry_capacity_and_invalid_material_fail_without_candidate_echo() {
    let provider = MemorySecretProvider::try_new_with_capacity(
        provider_id(),
        MemorySecretProviderRuntimeMode::Test,
        1,
    )
    .unwrap();
    provider
        .insert_synthetic(
            tenant(1),
            ref_id(),
            1,
            version("version-1"),
            b"first".to_vec(),
        )
        .unwrap();
    assert_eq!(
        provider
            .insert_synthetic(
                tenant(2),
                secret_id(20),
                1,
                version("version-1"),
                b"PRIVATE_SECRET_CANARY".to_vec(),
            )
            .unwrap_err(),
        MemorySecretProviderConfigError::CapacityExceeded
    );
    let invalid =
        MemorySecretProvider::try_new(secret_id(21), MemorySecretProviderRuntimeMode::Test)
            .unwrap();
    let error = invalid
        .insert_synthetic(tenant(1), ref_id(), 1, version("version-1"), Vec::new())
        .unwrap_err();
    assert_eq!(error, MemorySecretProviderConfigError::InvalidMaterial);
    assert!(!format!("{error:?}").contains("PRIVATE_SECRET_CANARY"));
}

#[test]
fn duplicate_rotation_and_poisoned_state_fail_closed() {
    let provider =
        MemorySecretProvider::try_new(provider_id(), MemorySecretProviderRuntimeMode::Test)
            .unwrap();
    provider
        .insert_synthetic(
            tenant(1),
            ref_id(),
            1,
            version("version-1"),
            b"first".to_vec(),
        )
        .unwrap();
    assert_eq!(
        provider
            .insert_synthetic(
                tenant(1),
                ref_id(),
                1,
                version("version-1"),
                b"duplicate".to_vec(),
            )
            .unwrap_err(),
        MemorySecretProviderConfigError::DuplicateEntry
    );
    assert_eq!(
        provider
            .rotate_synthetic(
                tenant(1),
                ref_id(),
                1,
                &version("missing"),
                version("version-2"),
                b"new".to_vec(),
            )
            .unwrap_err(),
        MemorySecretProviderConfigError::EntryNotAvailable
    );

    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _guard = provider.state.lock().unwrap();
        panic!("poison test lock");
    }));
    assert_eq!(
        provider
            .insert_synthetic(
                tenant(2),
                secret_id(30),
                1,
                version("version-1"),
                b"after-poison".to_vec(),
            )
            .unwrap_err(),
        MemorySecretProviderConfigError::StateUnavailable
    );
}

#[test]
fn debug_and_errors_are_redacted_and_trait_object_is_real() {
    let provider = Arc::new(
        MemorySecretProvider::try_new(provider_id(), MemorySecretProviderRuntimeMode::Test)
            .unwrap(),
    );
    let rendered = format!("{provider:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("material"));
    let port: Arc<dyn SecretProvider> = provider;
    assert_eq!(port.provider_id(), &provider_id());
    for error in [
        MemorySecretProviderConfigError::UnsupportedRuntimeMode,
        MemorySecretProviderConfigError::InvalidCoordinates,
        MemorySecretProviderConfigError::InvalidMaterial,
        MemorySecretProviderConfigError::DuplicateEntry,
        MemorySecretProviderConfigError::EntryNotAvailable,
        MemorySecretProviderConfigError::CapacityExceeded,
        MemorySecretProviderConfigError::StateUnavailable,
    ] {
        assert_eq!(error.to_string(), error.code());
    }
}

#[test]
fn private_provider_helpers_cover_health_erasure_and_fixed_failures() {
    assert_eq!(
        MemorySecretProvider::try_new_with_capacity(
            provider_id(),
            MemorySecretProviderRuntimeMode::Test,
            MAX_CONFIGURED_ENTRIES + 1,
        )
        .unwrap_err(),
        MemorySecretProviderConfigError::CapacityExceeded
    );

    let provider_id = provider_id();
    let tenant_id = tenant(1);
    let ref_id = ref_id();
    let current_version = version("version-1");
    let provider =
        MemorySecretProvider::try_new(provider_id.clone(), MemorySecretProviderRuntimeMode::Test)
            .unwrap();
    for result in [
        provider.insert_synthetic(
            TenantId::from(Uuid::nil()),
            ref_id.clone(),
            1,
            current_version.clone(),
            b"private".to_vec(),
        ),
        provider.insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            0,
            current_version.clone(),
            b"private".to_vec(),
        ),
        provider.insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            MAX_SAFE_INTEGER + 1,
            current_version.clone(),
            b"private".to_vec(),
        ),
    ] {
        assert_eq!(
            result.unwrap_err(),
            MemorySecretProviderConfigError::InvalidCoordinates
        );
    }
    assert_eq!(
        provider
            .insert_synthetic(
                tenant_id.clone(),
                ref_id.clone(),
                1,
                current_version.clone(),
                vec![0; MAX_MATERIAL_BYTES + 1],
            )
            .unwrap_err(),
        MemorySecretProviderConfigError::InvalidMaterial
    );
    provider
        .insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            current_version.clone(),
            b"private".to_vec(),
        )
        .unwrap();
    provider
        .insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            version("version-2"),
            b"replacement".to_vec(),
        )
        .unwrap();
    assert_eq!(
        provider
            .rotate_synthetic(
                tenant_id.clone(),
                ref_id.clone(),
                1,
                &current_version,
                version("version-2"),
                b"duplicate".to_vec(),
            )
            .unwrap_err(),
        MemorySecretProviderConfigError::DuplicateEntry
    );

    let observed_at: CanonicalTimestampV1 = "2026-07-24T12:00:00.000000Z".parse().unwrap();
    let health = provider.health_scoped(&provider_id, &observed_at).unwrap();
    assert_eq!(health.secret_provider_id(), &provider_id);
    assert!(health.available());
    assert_eq!(health.observed_at(), &observed_at);
    assert_eq!(
        health.schema_version(),
        splendor_authority::PROCESS_LOCAL_SECRET_PROVIDER_HEALTH_EVIDENCE_SCHEMA_V1
    );
    assert_eq!(provider.control_call_count(), 1);
    let wrong_provider = secret_id(900);
    assert_eq!(
        provider
            .health_scoped(&wrong_provider, &observed_at)
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
    assert_eq!(
        provider
            .erase_coordinates(coordinates(
                &wrong_provider,
                &tenant_id,
                &ref_id,
                &current_version,
            ))
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
    assert_eq!(
        provider
            .with_entry(
                coordinates(&provider_id, &tenant_id, &ref_id, &current_version),
                |_| Err::<(), _>(provider_error(SecretProviderErrorCode::RateLimited)),
            )
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::RateLimited
    );

    provider.set_available(false);
    let health = provider.health_scoped(&provider_id, &observed_at).unwrap();
    assert!(!health.available());
    assert_eq!(
        provider
            .erase_coordinates(coordinates(
                &provider_id,
                &tenant_id,
                &ref_id,
                &current_version,
            ))
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::Unavailable
    );
    provider.set_available(true);
    provider
        .erase_coordinates(coordinates(
            &provider_id,
            &tenant_id,
            &ref_id,
            &current_version,
        ))
        .unwrap();
    assert_eq!(
        provider
            .erase_coordinates(coordinates(
                &provider_id,
                &tenant_id,
                &ref_id,
                &current_version,
            ))
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
}

#[test]
fn poisoned_private_provider_helpers_fail_closed() {
    let provider_id = provider_id();
    let tenant_id = tenant(1);
    let ref_id = ref_id();
    let current_version = version("version-1");
    let provider =
        MemorySecretProvider::try_new(provider_id.clone(), MemorySecretProviderRuntimeMode::Test)
            .unwrap();
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _guard = provider.state.lock().unwrap();
        panic!("poison private helper lock");
    }));
    assert_eq!(
        provider
            .with_entry(
                coordinates(&provider_id, &tenant_id, &ref_id, &current_version),
                |_| Ok(()),
            )
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::InternalFailure
    );
    assert_eq!(
        provider
            .erase_coordinates(coordinates(
                &provider_id,
                &tenant_id,
                &ref_id,
                &current_version,
            ))
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::InternalFailure
    );
    let observed_at: CanonicalTimestampV1 = "2026-07-24T12:00:00.000000Z".parse().unwrap();
    assert_eq!(
        provider
            .health_scoped(&provider_id, &observed_at)
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::InternalFailure
    );
    provider.set_available(false);
}
