use super::*;
use splendor_authority::{InMemorySecretBrokerEventSink, ProcessLocalSecretBroker};
use splendor_types::{
    DriverCredentialDestinationDigest, DriverOperationRef, DriverTrustedSendProfileV1,
    SecretClassification, SecretCredentialAuthorizationV2, SecretCredentialSlotId,
    SecretDeliveryExposureProfile, SecretDeliveryMethod, SecretLeasePolicy, SecretOfflineBehavior,
    SecretRefV2,
};
use std::sync::Arc;
use uuid::Uuid;

const CANARY: &str = "PRIVATE_SECRET_CANARY_684f";

fn uuid(index: u128) -> Uuid {
    Uuid::from_u128(0x018f_0a1b_2c3d_4e5f_8a9b_0000_0000_0000 + index)
}

fn provider_id() -> SecretProviderId {
    SecretProviderId::try_from(uuid(1)).unwrap()
}

fn tenant(index: u128) -> TenantId {
    TenantId::from(uuid(index))
}

fn secret_ref(index: u128) -> SecretRefId {
    SecretRefId::try_from(uuid(index)).unwrap()
}

fn coordinates<'a>(
    provider_id: &'a SecretProviderId,
    tenant_id: &'a TenantId,
    secret_ref_id: &'a SecretRefId,
    version: &'a SecretProviderVersionRef,
) -> FetchCoordinates<'a> {
    FetchCoordinates {
        provider_id,
        tenant_id,
        secret_ref_id,
        secret_ref_revision: 1,
        provider_version_ref: version,
    }
}

fn audit_coordinates<'a>(
    audit_id: &'a SecretProviderAuditId,
    provider_id: &'a SecretProviderId,
    tenant_id: &'a TenantId,
    secret_ref_id: &'a SecretRefId,
    version: &'a SecretProviderVersionRef,
    observed_at: &'a CanonicalTimestampV1,
) -> AuditCoordinates<'a> {
    AuditCoordinates {
        provider_audit_id: audit_id,
        provider_id,
        tenant_id,
        secret_ref_id,
        secret_ref_revision: 1,
        provider_version_ref: version,
        observed_at,
    }
}

fn configured_secret_ref(provider_id: SecretProviderId) -> SecretRefV2 {
    let credential_slot_id = SecretCredentialSlotId::try_from(uuid(5)).unwrap();
    let destination_digest: DriverCredentialDestinationDigest =
        "blake3:1111111111111111111111111111111111111111111111111111111111111111"
            .parse()
            .unwrap();
    let authorization = SecretCredentialAuthorizationV2::try_new(
        DriverOperationRef {
            driver: "http".to_string(),
            operation: "fetch".to_string(),
            schema_version: "splendor.driver.operation.v1".to_string(),
        },
        1,
        credential_slot_id,
        "splendor.driver.destination.http.v1",
        SecretDeliveryExposureProfile::MaterialExposed,
        DriverTrustedSendProfileV1::not_applicable(),
        vec![destination_digest],
    )
    .unwrap();
    SecretRefV2::try_new(
        secret_ref(3),
        1,
        tenant(2),
        provider_id,
        "test",
        "http-credential",
        "version-1".parse().unwrap(),
        SecretClassification::AuthenticationCredential,
        vec![authorization],
        vec![SecretDeliveryMethod::InheritedFd],
        SecretLeasePolicy::try_new(300, 600, 1, true, 0).unwrap(),
        SecretOfflineBehavior::Deny,
        "2026-07-24T11:00:00.000000Z",
        None,
    )
    .unwrap()
}

#[test]
fn construction_is_explicitly_test_or_local_dev_only() {
    for allowed in [
        MemorySecretProviderRuntimeMode::Test,
        MemorySecretProviderRuntimeMode::LocalDevelopment,
    ] {
        assert!(MemorySecretProvider::try_new(provider_id(), allowed).is_ok());
    }
    for denied in [
        MemorySecretProviderRuntimeMode::Resident,
        MemorySecretProviderRuntimeMode::Remote,
        MemorySecretProviderRuntimeMode::Fleet,
        MemorySecretProviderRuntimeMode::Production,
        MemorySecretProviderRuntimeMode::Unknown,
    ] {
        assert_eq!(
            MemorySecretProvider::try_new(provider_id(), denied).unwrap_err(),
            MemorySecretProviderConfigError::UnsupportedRuntimeMode
        );
    }
}

#[test]
fn real_broker_composition_registers_memory_provider_without_resolving_material() {
    let provider_id = provider_id();
    let provider = Arc::new(
        MemorySecretProvider::try_new(provider_id.clone(), MemorySecretProviderRuntimeMode::Test)
            .unwrap(),
    );
    provider
        .insert_synthetic(
            tenant(2),
            secret_ref(3),
            1,
            "version-1".parse().unwrap(),
            CANARY.as_bytes().to_vec(),
        )
        .unwrap();
    let provider_port: Arc<dyn SecretProvider> = provider.clone();
    let broker = ProcessLocalSecretBroker::try_new(
        vec![configured_secret_ref(provider_id)],
        vec![provider_port],
        Arc::new(InMemorySecretBrokerEventSink::new()),
    )
    .unwrap();

    assert_eq!(broker.registered_provider_count(), 1);
    assert!(broker.replay().unwrap().leases.is_empty());
    assert_eq!(provider.fetch_call_count(), 0);
    assert_eq!(provider.control_call_count(), 0);
}

#[test]
fn exact_lookup_enforces_tenant_ref_revision_and_version() {
    let provider_id = provider_id();
    let provider =
        MemorySecretProvider::try_new(provider_id.clone(), MemorySecretProviderRuntimeMode::Test)
            .unwrap();
    let tenant_id = tenant(2);
    let ref_id = secret_ref(3);
    let version: SecretProviderVersionRef = "version-1".parse().unwrap();
    provider
        .insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            version.clone(),
            CANARY.as_bytes().to_vec(),
        )
        .unwrap();

    let material = provider
        .fetch_coordinates(coordinates(&provider_id, &tenant_id, &ref_id, &version))
        .unwrap();
    material.expose_borrowed(|bytes| assert_eq!(bytes, CANARY.as_bytes()));
    assert!(!format!("{material:?}").contains(CANARY));
    assert!(!format!("{provider:?}").contains(CANARY));

    let wrong_version: SecretProviderVersionRef = "version-2".parse().unwrap();
    assert_eq!(
        provider
            .fetch_coordinates(coordinates(
                &provider_id,
                &tenant_id,
                &ref_id,
                &wrong_version,
            ))
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
    assert_eq!(
        provider
            .fetch_coordinates(coordinates(&provider_id, &tenant(99), &ref_id, &version,))
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
    assert_eq!(
        provider
            .fetch_coordinates(FetchCoordinates {
                provider_id: &provider_id,
                tenant_id: &tenant_id,
                secret_ref_id: &ref_id,
                secret_ref_revision: 2,
                provider_version_ref: &version,
            })
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
}

#[test]
fn outage_revocation_and_rotation_are_deterministic_and_redacted() {
    let provider_id = provider_id();
    let provider =
        MemorySecretProvider::try_new(provider_id.clone(), MemorySecretProviderRuntimeMode::Test)
            .unwrap();
    let tenant_id = tenant(2);
    let ref_id = secret_ref(3);
    let old_version: SecretProviderVersionRef = "version-1".parse().unwrap();
    let new_version: SecretProviderVersionRef = "version-2".parse().unwrap();
    provider
        .insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            old_version.clone(),
            CANARY.as_bytes().to_vec(),
        )
        .unwrap();

    provider.set_available(false);
    let outage = provider
        .fetch_coordinates(coordinates(&provider_id, &tenant_id, &ref_id, &old_version))
        .unwrap_err();
    assert_eq!(outage.code(), SecretProviderErrorCode::Unavailable);
    assert!(!outage.to_string().contains(CANARY));
    provider.set_available(true);

    provider
        .rotate_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            &old_version,
            new_version.clone(),
            b"rotated-canary".to_vec(),
        )
        .unwrap();
    assert_eq!(
        provider
            .fetch_coordinates(coordinates(&provider_id, &tenant_id, &ref_id, &old_version,))
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::Revoked
    );
    let rotated = provider
        .fetch_coordinates(coordinates(&provider_id, &tenant_id, &ref_id, &new_version))
        .unwrap();
    rotated.expose_borrowed(|bytes| assert_eq!(bytes, b"rotated-canary"));
}

#[test]
fn config_errors_do_not_echo_material_and_trait_object_is_real() {
    let provider = MemorySecretProvider::try_new(
        provider_id(),
        MemorySecretProviderRuntimeMode::LocalDevelopment,
    )
    .unwrap();
    let port: &dyn SecretProvider = &provider;
    assert_eq!(port.provider_id(), &provider_id());
    assert_eq!(
        provider.insert_synthetic(
            tenant(2),
            secret_ref(3),
            0,
            "version-1".parse().unwrap(),
            CANARY.as_bytes().to_vec(),
        ),
        Err(MemorySecretProviderConfigError::InvalidCoordinates)
    );
    assert_eq!(
        provider.insert_synthetic(
            TenantId::from(Uuid::nil()),
            secret_ref(3),
            1,
            "version-1".parse().unwrap(),
            CANARY.as_bytes().to_vec(),
        ),
        Err(MemorySecretProviderConfigError::InvalidCoordinates)
    );
    let error = provider
        .insert_synthetic(
            tenant(2),
            secret_ref(3),
            1,
            "version-1".parse().unwrap(),
            Vec::new(),
        )
        .unwrap_err();
    assert_eq!(error, MemorySecretProviderConfigError::InvalidMaterial);
    assert!(!error.to_string().contains(CANARY));
    assert_eq!(provider.fetch_call_count(), 0);
    assert_eq!(provider.control_call_count(), 0);

    for error in [
        MemorySecretProviderConfigError::UnsupportedRuntimeMode,
        MemorySecretProviderConfigError::InvalidCoordinates,
        MemorySecretProviderConfigError::InvalidMaterial,
        MemorySecretProviderConfigError::DuplicateEntry,
        MemorySecretProviderConfigError::EntryNotAvailable,
        MemorySecretProviderConfigError::StateUnavailable,
    ] {
        assert_eq!(error.to_string(), error.code());
        assert!(!error.code().contains(CANARY));
    }
}

#[test]
fn scoped_provider_operations_cover_fetch_controls_health_and_failures() {
    let provider_id = provider_id();
    let provider =
        MemorySecretProvider::try_new(provider_id.clone(), MemorySecretProviderRuntimeMode::Test)
            .unwrap();
    let tenant_id = tenant(2);
    let ref_id = secret_ref(3);
    let version: SecretProviderVersionRef = "version-1".parse().unwrap();
    let audit_id = SecretProviderAuditId::try_from(uuid(4)).unwrap();
    let observed_at: CanonicalTimestampV1 = "2026-07-24T12:00:00.000000Z".parse().unwrap();
    provider
        .insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            version.clone(),
            CANARY.as_bytes().to_vec(),
        )
        .unwrap();
    assert_eq!(
        provider.insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            version.clone(),
            CANARY.as_bytes().to_vec(),
        ),
        Err(MemorySecretProviderConfigError::DuplicateEntry)
    );

    let fetched = provider
        .fetch_scoped(
            coordinates(&provider_id, &tenant_id, &ref_id, &version),
            audit_coordinates(
                &audit_id,
                &provider_id,
                &tenant_id,
                &ref_id,
                &version,
                &observed_at,
            ),
        )
        .unwrap();
    let (material, audit) = fetched.into_parts();
    material.expose_borrowed(|bytes| assert_eq!(bytes, CANARY.as_bytes()));
    assert_eq!(audit.operation(), SecretProviderOperation::Fetch);
    assert_eq!(provider.fetch_call_count(), 1);
    let nil_tenant = TenantId::from(Uuid::nil());
    assert_eq!(
        provider
            .fetch_scoped(
                coordinates(&provider_id, &tenant_id, &ref_id, &version),
                audit_coordinates(
                    &audit_id,
                    &provider_id,
                    &nil_tenant,
                    &ref_id,
                    &version,
                    &observed_at,
                ),
            )
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::IntegrityFailure
    );
    assert_eq!(
        provider
            .fetch_coordinates(coordinates(
                &SecretProviderId::try_from(uuid(98)).unwrap(),
                &tenant_id,
                &ref_id,
                &version,
            ))
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
    assert_eq!(provider.fetch_call_count(), 2);

    for operation in [
        SecretProviderOperation::Renew,
        SecretProviderOperation::Audit,
    ] {
        let evidence = provider
            .inspect_control_scoped(
                coordinates(&provider_id, &tenant_id, &ref_id, &version),
                audit_coordinates(
                    &audit_id,
                    &provider_id,
                    &tenant_id,
                    &ref_id,
                    &version,
                    &observed_at,
                ),
                operation,
            )
            .unwrap();
        assert_eq!(evidence.operation(), operation);
        assert_eq!(evidence.outcome(), SecretProviderOutcome::Succeeded);
    }
    let health = provider.health_scoped(&provider_id, &observed_at).unwrap();
    assert!(health.available());
    assert_eq!(health.secret_provider_id(), &provider_id);
    assert_eq!(
        provider
            .health_scoped(&SecretProviderId::try_from(uuid(99)).unwrap(), &observed_at)
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
    assert_eq!(
        provider
            .revoke_scoped(
                coordinates(
                    &SecretProviderId::try_from(uuid(97)).unwrap(),
                    &tenant_id,
                    &ref_id,
                    &version,
                ),
                audit_coordinates(
                    &audit_id,
                    &provider_id,
                    &tenant_id,
                    &ref_id,
                    &version,
                    &observed_at,
                ),
            )
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );

    provider.set_available(false);
    assert_eq!(
        provider
            .inspect_control_scoped(
                coordinates(&provider_id, &tenant_id, &ref_id, &version),
                audit_coordinates(
                    &audit_id,
                    &provider_id,
                    &tenant_id,
                    &ref_id,
                    &version,
                    &observed_at,
                ),
                SecretProviderOperation::Audit,
            )
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::Unavailable
    );
    let unavailable_health = provider.health_scoped(&provider_id, &observed_at).unwrap();
    assert!(!unavailable_health.available());
    assert_eq!(
        provider
            .revoke_scoped(
                coordinates(&provider_id, &tenant_id, &ref_id, &version),
                audit_coordinates(
                    &audit_id,
                    &provider_id,
                    &tenant_id,
                    &ref_id,
                    &version,
                    &observed_at,
                ),
            )
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::Unavailable
    );
    provider.set_available(true);

    let revoke = provider
        .revoke_scoped(
            coordinates(&provider_id, &tenant_id, &ref_id, &version),
            audit_coordinates(
                &audit_id,
                &provider_id,
                &tenant_id,
                &ref_id,
                &version,
                &observed_at,
            ),
        )
        .unwrap();
    assert_eq!(revoke.operation(), SecretProviderOperation::Revoke);
    assert_eq!(
        provider
            .fetch_scoped(
                coordinates(&provider_id, &tenant_id, &ref_id, &version),
                audit_coordinates(
                    &audit_id,
                    &provider_id,
                    &tenant_id,
                    &ref_id,
                    &version,
                    &observed_at,
                ),
            )
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::Revoked
    );
    assert_eq!(provider.control_call_count(), 9);

    let missing_version: SecretProviderVersionRef = "missing".parse().unwrap();
    assert_eq!(
        provider
            .revoke_scoped(
                coordinates(&provider_id, &tenant_id, &ref_id, &missing_version),
                audit_coordinates(
                    &audit_id,
                    &provider_id,
                    &tenant_id,
                    &ref_id,
                    &missing_version,
                    &observed_at,
                ),
            )
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::VersionNotAvailable
    );
}

#[test]
fn mutation_failures_and_poisoned_state_are_closed() {
    let provider_id = provider_id();
    let provider = MemorySecretProvider::try_new(
        provider_id.clone(),
        MemorySecretProviderRuntimeMode::LocalDevelopment,
    )
    .unwrap();
    let tenant_id = tenant(2);
    let ref_id = secret_ref(3);
    let old_version: SecretProviderVersionRef = "version-1".parse().unwrap();
    let new_version: SecretProviderVersionRef = "version-2".parse().unwrap();
    assert_eq!(
        provider.rotate_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            &old_version,
            new_version.clone(),
            CANARY.as_bytes().to_vec(),
        ),
        Err(MemorySecretProviderConfigError::EntryNotAvailable)
    );
    provider
        .insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            old_version.clone(),
            CANARY.as_bytes().to_vec(),
        )
        .unwrap();
    provider
        .insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            new_version.clone(),
            CANARY.as_bytes().to_vec(),
        )
        .unwrap();
    assert_eq!(
        provider.rotate_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            &old_version,
            new_version,
            CANARY.as_bytes().to_vec(),
        ),
        Err(MemorySecretProviderConfigError::DuplicateEntry)
    );
    assert_eq!(
        provider.rotate_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            0,
            &old_version,
            "version-3".parse().unwrap(),
            CANARY.as_bytes().to_vec(),
        ),
        Err(MemorySecretProviderConfigError::InvalidCoordinates)
    );
    assert_eq!(
        provider.rotate_synthetic(
            TenantId::from(Uuid::nil()),
            ref_id.clone(),
            1,
            &old_version,
            "version-3".parse().unwrap(),
            CANARY.as_bytes().to_vec(),
        ),
        Err(MemorySecretProviderConfigError::InvalidCoordinates)
    );
    assert_eq!(
        provider.rotate_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            &old_version,
            "version-3".parse().unwrap(),
            Vec::new(),
        ),
        Err(MemorySecretProviderConfigError::InvalidMaterial)
    );

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = provider.state.lock().unwrap();
        panic!("poison memory provider state for fail-closed test");
    }));
    assert_eq!(
        provider.insert_synthetic(
            tenant_id.clone(),
            ref_id.clone(),
            1,
            "version-4".parse().unwrap(),
            CANARY.as_bytes().to_vec(),
        ),
        Err(MemorySecretProviderConfigError::StateUnavailable)
    );
    let observed_at: CanonicalTimestampV1 = "2026-07-24T12:00:00.000000Z".parse().unwrap();
    assert_eq!(
        provider
            .health_scoped(&provider_id, &observed_at)
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::InternalFailure
    );
}
