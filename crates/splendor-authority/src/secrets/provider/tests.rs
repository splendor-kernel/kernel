use super::*;
use splendor_types::{HashAlgorithm, SecretIdParseError};
use uuid::Uuid;

fn uuid(index: u128) -> Uuid {
    Uuid::from_u128(0x018f_0a1b_2c3d_4e5f_8a9b_2000_0000_0000 + index)
}

fn secret_id<T>(index: u128) -> T
where
    T: TryFrom<Uuid, Error = SecretIdParseError>,
{
    T::try_from(uuid(index)).unwrap()
}

fn timestamp() -> CanonicalTimestampV1 {
    "2026-07-24T12:00:00.000000Z".parse().unwrap()
}

fn fetch_request(index: u128) -> SecretProviderFetchRequest {
    SecretProviderFetchRequest {
        provider_audit_id: secret_id(index),
        secret_provider_id: secret_id(index + 1),
        tenant_id: TenantId::from(uuid(index + 2)),
        secret_ref_id: secret_id(index + 3),
        secret_ref_revision: 1,
        provider_version_ref: "version-1".parse().unwrap(),
        secret_lease_id: secret_id(index + 4),
        delivery_handle_id: secret_id(index + 5),
        secret_use_claim_id: secret_id(index + 6),
        secret_use_attempt_id: secret_id(index + 7),
        requested_at: timestamp(),
    }
}

fn control_request(index: u128, with_lease: bool) -> SecretProviderControlRequest {
    SecretProviderControlRequest {
        provider_audit_id: secret_id(index),
        secret_provider_id: secret_id(index + 1),
        tenant_id: TenantId::from(uuid(index + 2)),
        secret_ref_id: secret_id(index + 3),
        secret_ref_revision: 1,
        provider_version_ref: "version-1".parse().unwrap(),
        secret_lease_id: with_lease.then(|| secret_id(index + 4)),
        requested_at: timestamp(),
    }
}

#[test]
fn fetch_request_audit_and_material_result_are_exactly_bound() {
    let request = fetch_request(1);
    assert_eq!(request.provider_audit_id(), &secret_id(1));
    assert_eq!(request.secret_provider_id(), &secret_id(2));
    assert_eq!(request.tenant_id(), &TenantId::from(uuid(3)));
    assert_eq!(request.secret_ref_id(), &secret_id(4));
    assert_eq!(request.secret_ref_revision(), 1);
    assert_eq!(request.provider_version_ref().as_str(), "version-1");
    assert_eq!(request.secret_lease_id(), &secret_id(5));
    assert_eq!(request.delivery_handle_id(), &secret_id(6));
    assert_eq!(request.secret_use_claim_id(), &secret_id(7));
    assert_eq!(request.secret_use_attempt_id(), &secret_id(8));
    assert_eq!(request.requested_at(), &timestamp());
    assert_eq!(
        format!("{request:?}"),
        "SecretProviderFetchRequest(<redacted>)"
    );

    let audit = SecretProviderAuditEvidence::for_fetch_request(
        &request,
        SecretProviderOutcome::Succeeded,
        EffectCertainty::Known,
        timestamp(),
    )
    .unwrap();
    assert_eq!(audit.provider_audit_id(), request.provider_audit_id());
    assert_eq!(audit.secret_provider_id(), request.secret_provider_id());
    assert_eq!(audit.tenant_id(), request.tenant_id());
    assert_eq!(audit.secret_ref_id(), request.secret_ref_id());
    assert_eq!(audit.secret_ref_revision(), 1);
    assert_eq!(audit.provider_version_ref(), request.provider_version_ref());
    assert_eq!(audit.operation(), SecretProviderOperation::Fetch);
    assert_eq!(audit.outcome(), SecretProviderOutcome::Succeeded);
    assert_eq!(audit.effect_certainty(), EffectCertainty::Known);
    assert_eq!(audit.observed_at(), &timestamp());
    assert_eq!(
        audit.schema_version(),
        SECRET_PROVIDER_AUDIT_EVIDENCE_SCHEMA_LOCAL_V1
    );
    assert_eq!(
        audit.request_binding_digest().algorithm,
        HashAlgorithm::Blake3
    );
    let encoded = serde_json::to_value(&audit).unwrap();
    assert_eq!(
        encoded["schema_version"],
        SECRET_PROVIDER_AUDIT_EVIDENCE_SCHEMA_LOCAL_V1
    );

    let result = SecretProviderFetchResult::try_new(&request, b"private".to_vec(), audit).unwrap();
    assert_eq!(result.material_len(), 7);
    assert_eq!(
        result.audit().provider_audit_id(),
        request.provider_audit_id()
    );
    assert_eq!(
        format!("{:?}", result.material),
        "SecretMaterial(<redacted>)"
    );
    assert_eq!(
        format!("{result:?}"),
        "SecretProviderFetchResult(<redacted>)"
    );

    let denied_audit = SecretProviderAuditEvidence::for_fetch_request(
        &request,
        SecretProviderOutcome::Denied,
        EffectCertainty::Known,
        timestamp(),
    )
    .unwrap();
    assert_eq!(
        SecretProviderFetchResult::try_new(&request, b"private".to_vec(), denied_audit)
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::IntegrityFailure
    );
    let successful_audit = SecretProviderAuditEvidence::for_fetch_request(
        &request,
        SecretProviderOutcome::Succeeded,
        EffectCertainty::Known,
        timestamp(),
    )
    .unwrap();
    assert_eq!(
        SecretProviderFetchResult::try_new(
            &request,
            vec![0; MAX_SECRET_MATERIAL_BYTES + 1],
            successful_audit,
        )
        .unwrap_err()
        .code(),
        SecretProviderErrorCode::IntegrityFailure
    );
}

#[test]
fn audit_evidence_rejects_incoherent_coordinates_and_certainty() {
    let request = fetch_request(20);
    for (outcome, certainty) in [
        (SecretProviderOutcome::Succeeded, EffectCertainty::Uncertain),
        (
            SecretProviderOutcome::EffectUncertain,
            EffectCertainty::Known,
        ),
    ] {
        assert_eq!(
            SecretProviderAuditEvidence::for_fetch_request(
                &request,
                outcome,
                certainty,
                timestamp(),
            )
            .unwrap_err()
            .code(),
            SecretProviderErrorCode::IntegrityFailure
        );
    }

    let mut nil_tenant = fetch_request(30);
    nil_tenant.tenant_id = TenantId::from(Uuid::nil());
    assert_eq!(
        SecretProviderAuditEvidence::for_fetch_request(
            &nil_tenant,
            SecretProviderOutcome::Denied,
            EffectCertainty::Known,
            timestamp(),
        )
        .unwrap_err()
        .code(),
        SecretProviderErrorCode::IntegrityFailure
    );
    let mut invalid_revision = fetch_request(40);
    invalid_revision.secret_ref_revision = 0;
    assert_eq!(
        SecretProviderAuditEvidence::for_fetch_request(
            &invalid_revision,
            SecretProviderOutcome::Denied,
            EffectCertainty::Known,
            timestamp(),
        )
        .unwrap_err()
        .code(),
        SecretProviderErrorCode::IntegrityFailure
    );
}

#[test]
fn control_requests_bind_operation_and_cover_safe_getters() {
    let with_lease = control_request(50, true);
    assert_eq!(with_lease.provider_audit_id(), &secret_id(50));
    assert_eq!(with_lease.secret_provider_id(), &secret_id(51));
    assert_eq!(with_lease.tenant_id(), &TenantId::from(uuid(52)));
    assert_eq!(with_lease.secret_ref_id(), &secret_id(53));
    assert_eq!(with_lease.secret_ref_revision(), 1);
    assert_eq!(with_lease.provider_version_ref().as_str(), "version-1");
    assert_eq!(with_lease.secret_lease_id(), Some(&secret_id(54)));
    assert_eq!(with_lease.requested_at(), &timestamp());
    assert_eq!(
        format!("{with_lease:?}"),
        "SecretProviderControlRequest(<redacted>)"
    );
    assert!(control_request(60, false).secret_lease_id().is_none());

    let mut digests = Vec::new();
    for operation in [
        SecretProviderOperation::Renew,
        SecretProviderOperation::Revoke,
        SecretProviderOperation::Audit,
        SecretProviderOperation::ActiveProbe,
    ] {
        let audit = SecretProviderAuditEvidence::for_control_request(
            &with_lease,
            operation,
            SecretProviderOutcome::Succeeded,
            EffectCertainty::Known,
            timestamp(),
        )
        .unwrap();
        assert_eq!(audit.operation(), operation);
        assert_eq!(audit.outcome(), SecretProviderOutcome::Succeeded);
        digests.push(audit.request_binding_digest().clone());
    }
    assert!(digests.windows(2).all(|pair| pair[0] != pair[1]));
    assert_eq!(
        SecretProviderAuditEvidence::for_control_request(
            &with_lease,
            SecretProviderOperation::Fetch,
            SecretProviderOutcome::Succeeded,
            EffectCertainty::Known,
            timestamp(),
        )
        .unwrap_err()
        .code(),
        SecretProviderErrorCode::IntegrityFailure
    );

    let uncertain = SecretProviderAuditEvidence::for_control_request(
        &with_lease,
        SecretProviderOperation::Revoke,
        SecretProviderOutcome::EffectUncertain,
        EffectCertainty::Uncertain,
        timestamp(),
    )
    .unwrap();
    assert_eq!(uncertain.outcome(), SecretProviderOutcome::EffectUncertain);
}

#[test]
fn health_and_closed_error_vocabulary_are_serializable_and_redacted() {
    let provider_id: SecretProviderId = secret_id(80);
    let health = SecretProviderHealthEvidence::new(provider_id.clone(), false, timestamp());
    assert_eq!(
        health.schema_version(),
        SECRET_PROVIDER_HEALTH_EVIDENCE_SCHEMA_LOCAL_V1
    );
    assert_eq!(health.secret_provider_id(), &provider_id);
    assert!(!health.available());
    assert_eq!(health.observed_at(), &timestamp());
    let encoded = serde_json::to_value(&health).unwrap();
    assert_eq!(
        encoded["schema_version"],
        SECRET_PROVIDER_HEALTH_EVIDENCE_SCHEMA_LOCAL_V1
    );

    for (code, text) in [
        (SecretProviderErrorCode::Unavailable, "unavailable"),
        (
            SecretProviderErrorCode::TimeoutBeforeSend,
            "timeout_before_send",
        ),
        (SecretProviderErrorCode::RateLimited, "rate_limited"),
        (
            SecretProviderErrorCode::VersionNotAvailable,
            "version_not_available",
        ),
        (SecretProviderErrorCode::Revoked, "revoked"),
        (
            SecretProviderErrorCode::IntegrityFailure,
            "integrity_failure",
        ),
        (
            SecretProviderErrorCode::UnsupportedProviderVersion,
            "unsupported_provider_version",
        ),
        (
            SecretProviderErrorCode::UnsupportedOperation,
            "unsupported_operation",
        ),
        (SecretProviderErrorCode::EffectUncertain, "effect_uncertain"),
        (SecretProviderErrorCode::InternalFailure, "internal_failure"),
    ] {
        let error = SecretProviderError::new(code);
        assert_eq!(code.as_str(), text);
        assert_eq!(error.code(), code);
        assert_eq!(error.to_string(), text);
        assert_eq!(format!("{error:?}"), text);
    }

    for operation in [
        SecretProviderOperation::Fetch,
        SecretProviderOperation::Renew,
        SecretProviderOperation::Revoke,
        SecretProviderOperation::Audit,
        SecretProviderOperation::ActiveProbe,
    ] {
        assert!(serde_json::to_string(&operation).unwrap().starts_with('"'));
    }
    for outcome in [
        SecretProviderOutcome::Succeeded,
        SecretProviderOutcome::Denied,
        SecretProviderOutcome::Unavailable,
        SecretProviderOutcome::Failed,
        SecretProviderOutcome::EffectUncertain,
    ] {
        assert!(serde_json::to_string(&outcome).unwrap().starts_with('"'));
    }
}
