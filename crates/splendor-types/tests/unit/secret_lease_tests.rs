use super::*;
use crate::{
    DriverOperationRef, DriverTrustedSendProfileV1, SecretDeliveryControlKind,
    SecretDeliveryMethod, SecretPurpose, SecretUseIntent, SECRET_USE_REQUIREMENT_SCHEMA_V1,
};

const TENANT_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001";
const PRINCIPAL_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4002";
const WORKLOAD_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4003";
const NODE_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4004";
const INSTANCE_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4005";
const AUDIENCE_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4006";
const SECRET_REF_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4007";
const SLOT_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4008";
const REQUEST_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4009";
const LEASE_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4010";
const HANDLE_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4011";
const EVENT_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4012";
const CLAIM_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4013";
const ATTEMPT_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4014";
const PROVIDER_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4015";
const DESTINATION_DIGEST: &str =
    "blake3:1111111111111111111111111111111111111111111111111111111111111111";

fn binding() -> SecretLeaseUseBinding {
    SecretLeaseUseBinding::try_new(
        TENANT_ID.parse().unwrap(),
        PRINCIPAL_ID.parse().unwrap(),
        WORKLOAD_ID.parse().unwrap(),
        DriverOperationRef {
            driver: "http".to_string(),
            operation: "fetch".to_string(),
            schema_version: "splendor.driver.operation.v1".to_string(),
        },
        7,
        SLOT_ID.parse().unwrap(),
        "splendor.driver.destination.http.v1",
        DESTINATION_DIGEST.parse().unwrap(),
        SecretDeliveryExposureProfile::TrustedInjection,
        DriverTrustedSendProfileV1::try_trusted_injection(
            1,
            vec![SecretDeliveryControlKind::TrustedInjectionBoundary],
        )
        .unwrap(),
        NODE_ID.parse().unwrap(),
        INSTANCE_ID.parse().unwrap(),
        AUDIENCE_ID.parse().unwrap(),
        SECRET_REF_ID.parse().unwrap(),
        3,
        PROVIDER_ID.parse().unwrap(),
        "version-3".parse().unwrap(),
        SecretUseIntent::Authenticate,
        SecretPurpose::ExternalServiceAccess,
    )
    .unwrap()
}

fn requirement() -> SecretUseRequirement {
    SecretUseRequirement::try_new(
        SECRET_REF_ID.parse().unwrap(),
        SLOT_ID.parse().unwrap(),
        SecretUseIntent::Authenticate,
        SecretPurpose::ExternalServiceAccess,
        vec![SecretDeliveryMethod::InheritedFd],
        300,
        2,
        true,
    )
    .unwrap()
}

fn request() -> SecretLeaseRequest {
    SecretLeaseRequest::try_new(
        REQUEST_ID.parse().unwrap(),
        binding(),
        requirement(),
        "2026-07-24T12:00:00.000000Z".parse().unwrap(),
        "2026-07-24T12:05:00.000000Z".parse().unwrap(),
        "2026-07-24T12:00:00.000000Z".parse().unwrap(),
    )
    .unwrap()
}

#[test]
fn request_is_closed_ref_only_and_preserves_the_bound_requirement() {
    let request = request();
    assert_eq!(
        request.bound_use_requirement().schema_version(),
        SECRET_USE_REQUIREMENT_SCHEMA_V1
    );
    let encoded = serde_json::to_string(&request).unwrap();
    assert!(encoded.contains(SECRET_LEASE_REQUEST_SCHEMA_V1));
    assert!(encoded.contains(SECRET_LEASE_USE_BINDING_SCHEMA_V1));
    for forbidden in [
        "PRIVATE_SECRET_CANARY",
        "password",
        "provider_response",
        "provider_locator",
        "secret_material",
        "bearer",
    ] {
        assert!(!encoded.contains(forbidden));
    }
    assert_eq!(format!("{request:?}"), "secret_lease_request");
    assert_eq!(
        format!("{:?}", request.use_binding()),
        "secret_lease_use_binding"
    );
}

#[test]
fn request_rejects_mismatched_requirement_and_invalid_windows() {
    let mismatched = SecretUseRequirement::try_new(
        "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4999".parse().unwrap(),
        SLOT_ID.parse().unwrap(),
        SecretUseIntent::Authenticate,
        SecretPurpose::ExternalServiceAccess,
        vec![SecretDeliveryMethod::InheritedFd],
        300,
        1,
        true,
    )
    .unwrap();
    assert_eq!(
        SecretLeaseRequest::try_new(
            REQUEST_ID.parse().unwrap(),
            binding(),
            mismatched,
            "2026-07-24T12:00:00.000000Z".parse().unwrap(),
            "2026-07-24T12:05:00.000000Z".parse().unwrap(),
            "2026-07-24T12:00:00.000000Z".parse().unwrap(),
        ),
        Err(SecretLeaseContractError::RequirementBindingMismatch)
    );
    assert_eq!(
        SecretLeaseRequest::try_new(
            REQUEST_ID.parse().unwrap(),
            binding(),
            requirement(),
            "2026-07-24T12:05:00.000000Z".parse().unwrap(),
            "2026-07-24T12:05:00.000000Z".parse().unwrap(),
            "2026-07-24T12:00:00.000000Z".parse().unwrap(),
        ),
        Err(SecretLeaseContractError::InvalidTimeWindow)
    );
    let duration_limited = SecretUseRequirement::try_new(
        SECRET_REF_ID.parse().unwrap(),
        SLOT_ID.parse().unwrap(),
        SecretUseIntent::Authenticate,
        SecretPurpose::ExternalServiceAccess,
        vec![SecretDeliveryMethod::InheritedFd],
        299,
        1,
        true,
    )
    .unwrap();
    assert_eq!(
        SecretLeaseRequest::try_new(
            REQUEST_ID.parse().unwrap(),
            binding(),
            duration_limited,
            "2026-07-24T12:00:00.000000Z".parse().unwrap(),
            "2026-07-24T12:05:00.000000Z".parse().unwrap(),
            "2026-07-24T12:00:00.000000Z".parse().unwrap(),
        ),
        Err(SecretLeaseContractError::RequestedDurationExceeded)
    );
}

#[test]
fn snapshot_and_access_evidence_serialize_only_safe_coordinates() {
    let snapshot = SecretLeaseSnapshot::try_new(
        LEASE_ID.parse().unwrap(),
        REQUEST_ID.parse().unwrap(),
        HANDLE_ID.parse().unwrap(),
        binding(),
        SecretDeliveryMethod::InheritedFd,
        SecretLeaseStatus::Active,
        "2026-07-24T12:00:00.000000Z".parse().unwrap(),
        "2026-07-24T12:05:00.000000Z".parse().unwrap(),
        "2026-07-24T12:00:00.000000Z".parse().unwrap(),
        "2026-07-24T13:00:00.000000Z".parse().unwrap(),
        2,
        1,
        1,
        "2026-07-24T12:00:00.000000Z".parse().unwrap(),
        None,
        EVENT_ID.parse().unwrap(),
    )
    .unwrap();
    let event = SecretAccessEvidence::try_new(
        EVENT_ID.parse().unwrap(),
        ProcessLocalSecretBrokerCommandId::UseAttempt(ATTEMPT_ID.parse().unwrap()),
        SecretAccessEvidenceKind::UseClaimed,
        SecretAccessEvidenceOutcome::Succeeded,
        binding(),
        Some(LEASE_ID.parse().unwrap()),
        Some(HANDLE_ID.parse().unwrap()),
        Some(CLAIM_ID.parse().unwrap()),
        1,
        2,
        1,
        None,
        "2026-07-24T12:01:00.000000Z".parse().unwrap(),
    )
    .unwrap();

    let encoded = serde_json::to_string(&(snapshot, event)).unwrap();
    assert!(encoded.contains(SECRET_LEASE_SNAPSHOT_SCHEMA_V1));
    assert!(encoded.contains(SECRET_ACCESS_EVIDENCE_SCHEMA_V1));
    assert!(!encoded.contains("PRIVATE_SECRET_CANARY"));
    assert!(!encoded.contains("material"));
    assert!(!encoded.contains("locator"));
}

#[test]
fn errors_are_fixed_and_do_not_echo_candidates() {
    let error = SecretLeaseUseBinding::try_new(
        TenantId::from(uuid::Uuid::nil()),
        PRINCIPAL_ID.parse().unwrap(),
        WORKLOAD_ID.parse().unwrap(),
        DriverOperationRef {
            driver: "http".to_string(),
            operation: "fetch".to_string(),
            schema_version: "splendor.driver.operation.v1".to_string(),
        },
        1,
        SLOT_ID.parse().unwrap(),
        "splendor.driver.destination.http.v1",
        DESTINATION_DIGEST.parse().unwrap(),
        SecretDeliveryExposureProfile::TrustedInjection,
        DriverTrustedSendProfileV1::try_trusted_injection(
            1,
            vec![SecretDeliveryControlKind::TrustedInjectionBoundary],
        )
        .unwrap(),
        NODE_ID.parse().unwrap(),
        INSTANCE_ID.parse().unwrap(),
        AUDIENCE_ID.parse().unwrap(),
        SECRET_REF_ID.parse().unwrap(),
        1,
        PROVIDER_ID.parse().unwrap(),
        "PRIVATE_SECRET_CANARY".parse().unwrap(),
        SecretUseIntent::Authenticate,
        SecretPurpose::ExternalServiceAccess,
    )
    .unwrap_err();
    assert_eq!(error, SecretLeaseContractError::InvalidTenantId);
    assert_eq!(error.to_string(), "invalid_tenant_id");
    assert!(!error.to_string().contains("PRIVATE_SECRET_CANARY"));
}

#[test]
fn binding_getters_and_each_checked_boundary_are_covered() {
    let value = binding();
    assert_eq!(value.schema_version(), SECRET_LEASE_USE_BINDING_SCHEMA_V1);
    assert_eq!(value.tenant_id().to_string(), TENANT_ID);
    assert_eq!(value.principal_id().to_string(), PRINCIPAL_ID);
    assert_eq!(value.workload_id().to_string(), WORKLOAD_ID);
    assert_eq!(value.driver_operation().operation, "fetch");
    assert_eq!(value.driver_declaration_revision(), 7);
    assert_eq!(value.credential_slot_id().to_string(), SLOT_ID);
    assert_eq!(
        value.destination_schema(),
        "splendor.driver.destination.http.v1"
    );
    assert_eq!(value.destination_digest().to_string(), DESTINATION_DIGEST);
    assert_eq!(
        value.delivery_exposure_profile(),
        SecretDeliveryExposureProfile::TrustedInjection
    );
    assert_eq!(value.node_id().to_string(), NODE_ID);
    assert_eq!(value.instance_id().to_string(), INSTANCE_ID);
    assert_eq!(value.audience_id().to_string(), AUDIENCE_ID);
    assert_eq!(value.secret_ref_id().to_string(), SECRET_REF_ID);
    assert_eq!(value.secret_ref_revision(), 3);
    assert_eq!(value.secret_provider_id().to_string(), PROVIDER_ID);
    assert_eq!(value.provider_version_ref().as_str(), "version-3");
    assert_eq!(
        value.trusted_send_profile().max_credential_bearing_sends(),
        Some(1)
    );
    assert_eq!(value.intent(), SecretUseIntent::Authenticate);
    assert_eq!(value.purpose(), SecretPurpose::ExternalServiceAccess);
    assert_eq!(
        serde_json::to_value(&value).unwrap()["driver_declaration_revision"],
        7
    );

    let make = |tenant_id: TenantId,
                principal_id: PrincipalId,
                workload_id: WorkloadId,
                operation: DriverOperationRef,
                driver_revision: u64,
                destination_schema: &str,
                node_id: NodeId,
                instance_id: InstanceId,
                ref_revision: u64| {
        SecretLeaseUseBinding::try_new(
            tenant_id,
            principal_id,
            workload_id,
            operation,
            driver_revision,
            SLOT_ID.parse().unwrap(),
            destination_schema,
            DESTINATION_DIGEST.parse().unwrap(),
            SecretDeliveryExposureProfile::TrustedInjection,
            DriverTrustedSendProfileV1::try_trusted_injection(
                1,
                vec![SecretDeliveryControlKind::TrustedInjectionBoundary],
            )
            .unwrap(),
            node_id,
            instance_id,
            AUDIENCE_ID.parse().unwrap(),
            SECRET_REF_ID.parse().unwrap(),
            ref_revision,
            PROVIDER_ID.parse().unwrap(),
            "version-3".parse().unwrap(),
            SecretUseIntent::Authenticate,
            SecretPurpose::ExternalServiceAccess,
        )
    };
    let valid_operation = || DriverOperationRef {
        driver: "http".to_string(),
        operation: "fetch".to_string(),
        schema_version: "splendor.driver.operation.v1".to_string(),
    };
    let valid_args = || {
        (
            TENANT_ID.parse().unwrap(),
            PRINCIPAL_ID.parse().unwrap(),
            WORKLOAD_ID.parse().unwrap(),
            NODE_ID.parse().unwrap(),
            INSTANCE_ID.parse().unwrap(),
        )
    };
    let (_, principal_id, workload_id, node_id, instance_id) = valid_args();
    assert_eq!(
        make(
            TenantId::from(uuid::Uuid::nil()),
            principal_id,
            workload_id,
            valid_operation(),
            1,
            "splendor.driver.destination.http.v1",
            node_id,
            instance_id,
            1,
        ),
        Err(SecretLeaseContractError::InvalidTenantId)
    );
    let (tenant_id, _, workload_id, node_id, instance_id) = valid_args();
    assert_eq!(
        make(
            tenant_id,
            PrincipalId::from(uuid::Uuid::nil()),
            workload_id,
            valid_operation(),
            1,
            "splendor.driver.destination.http.v1",
            node_id,
            instance_id,
            1,
        ),
        Err(SecretLeaseContractError::InvalidPrincipalId)
    );
    let (tenant_id, principal_id, _, node_id, instance_id) = valid_args();
    assert_eq!(
        make(
            tenant_id,
            principal_id,
            WorkloadId::from(uuid::Uuid::nil()),
            valid_operation(),
            1,
            "splendor.driver.destination.http.v1",
            node_id,
            instance_id,
            1,
        ),
        Err(SecretLeaseContractError::InvalidWorkloadId)
    );
    let (tenant_id, principal_id, workload_id, _, instance_id) = valid_args();
    assert_eq!(
        make(
            tenant_id,
            principal_id,
            workload_id,
            valid_operation(),
            1,
            "splendor.driver.destination.http.v1",
            NodeId::from(uuid::Uuid::nil()),
            instance_id,
            1,
        ),
        Err(SecretLeaseContractError::InvalidNodeId)
    );
    let (tenant_id, principal_id, workload_id, node_id, _) = valid_args();
    assert_eq!(
        make(
            tenant_id,
            principal_id,
            workload_id,
            valid_operation(),
            1,
            "splendor.driver.destination.http.v1",
            node_id,
            InstanceId::from(uuid::Uuid::nil()),
            1,
        ),
        Err(SecretLeaseContractError::InvalidInstanceId)
    );
    for (operation, revision, schema, ref_revision, expected) in [
        (
            DriverOperationRef {
                driver: String::new(),
                operation: "fetch".to_string(),
                schema_version: "splendor.driver.operation.v1".to_string(),
            },
            1,
            "splendor.driver.destination.http.v1",
            1,
            SecretLeaseContractError::InvalidDriverOperation,
        ),
        (
            valid_operation(),
            0,
            "splendor.driver.destination.http.v1",
            1,
            SecretLeaseContractError::InvalidDriverDeclarationRevision,
        ),
        (
            valid_operation(),
            1,
            "invalid",
            1,
            SecretLeaseContractError::InvalidDestinationSchema,
        ),
        (
            valid_operation(),
            1,
            "splendor.driver.destination.http.v1",
            0,
            SecretLeaseContractError::InvalidSecretRefRevision,
        ),
    ] {
        let (tenant_id, principal_id, workload_id, node_id, instance_id) = valid_args();
        assert_eq!(
            make(
                tenant_id,
                principal_id,
                workload_id,
                operation,
                revision,
                schema,
                node_id,
                instance_id,
                ref_revision,
            ),
            Err(expected)
        );
    }

    assert_eq!(
        SecretLeaseUseBinding::try_new(
            TENANT_ID.parse().unwrap(),
            PRINCIPAL_ID.parse().unwrap(),
            WORKLOAD_ID.parse().unwrap(),
            valid_operation(),
            1,
            SLOT_ID.parse().unwrap(),
            "splendor.driver.destination.http.v1",
            DESTINATION_DIGEST.parse().unwrap(),
            SecretDeliveryExposureProfile::TrustedInjection,
            DriverTrustedSendProfileV1::not_applicable(),
            NODE_ID.parse().unwrap(),
            INSTANCE_ID.parse().unwrap(),
            AUDIENCE_ID.parse().unwrap(),
            SECRET_REF_ID.parse().unwrap(),
            1,
            PROVIDER_ID.parse().unwrap(),
            "version-3".parse().unwrap(),
            SecretUseIntent::Authenticate,
            SecretPurpose::ExternalServiceAccess,
        ),
        Err(SecretLeaseContractError::InvalidTrustedSendProfile)
    );
}

#[test]
fn request_snapshot_and_evidence_getters_and_invalid_shapes_are_covered() {
    let request = request();
    assert_eq!(request.schema_version(), SECRET_LEASE_REQUEST_SCHEMA_V1);
    assert_eq!(request.secret_lease_request_id().to_string(), REQUEST_ID);
    assert_eq!(request.use_binding(), &binding());
    assert_eq!(request.starts_at().as_str(), "2026-07-24T12:00:00.000000Z");
    assert_eq!(request.expires_at().as_str(), "2026-07-24T12:05:00.000000Z");
    assert_eq!(
        request.requested_at().as_str(),
        "2026-07-24T12:00:00.000000Z"
    );

    let make_snapshot = |status,
                         max_uses,
                         uses_claimed,
                         revocation_generation,
                         issued_at: &str,
                         renewed_from_lease_id| {
        SecretLeaseSnapshot::try_new(
            LEASE_ID.parse().unwrap(),
            REQUEST_ID.parse().unwrap(),
            HANDLE_ID.parse().unwrap(),
            binding(),
            SecretDeliveryMethod::InheritedFd,
            status,
            "2026-07-24T12:00:00.000000Z".parse().unwrap(),
            "2026-07-24T12:05:00.000000Z".parse().unwrap(),
            "2026-07-24T12:00:00.000000Z".parse().unwrap(),
            "2026-07-24T13:00:00.000000Z".parse().unwrap(),
            max_uses,
            uses_claimed,
            revocation_generation,
            issued_at.parse().unwrap(),
            renewed_from_lease_id,
            EVENT_ID.parse().unwrap(),
        )
    };
    let snapshot = make_snapshot(
        SecretLeaseStatus::Active,
        2,
        1,
        1,
        "2026-07-24T12:00:00.000000Z",
        None,
    )
    .unwrap();
    assert_eq!(snapshot.schema_version(), SECRET_LEASE_SNAPSHOT_SCHEMA_V1);
    assert_eq!(snapshot.secret_lease_id().to_string(), LEASE_ID);
    assert_eq!(snapshot.secret_lease_request_id().to_string(), REQUEST_ID);
    assert_eq!(snapshot.delivery_handle_id().to_string(), HANDLE_ID);
    assert_eq!(snapshot.use_binding(), &binding());
    assert_eq!(
        snapshot.selected_delivery_method(),
        SecretDeliveryMethod::InheritedFd
    );
    assert_eq!(snapshot.status(), SecretLeaseStatus::Active);
    assert_eq!(snapshot.starts_at().as_str(), "2026-07-24T12:00:00.000000Z");
    assert_eq!(
        snapshot.expires_at().as_str(),
        "2026-07-24T12:05:00.000000Z"
    );
    assert_eq!(
        snapshot.continuous_lifetime_started_at().as_str(),
        "2026-07-24T12:00:00.000000Z"
    );
    assert_eq!(
        snapshot.max_continuous_expires_at().as_str(),
        "2026-07-24T13:00:00.000000Z"
    );
    assert_eq!(snapshot.max_uses(), 2);
    assert_eq!(snapshot.uses_claimed(), 1);
    assert_eq!(snapshot.revocation_generation(), 1);
    assert_eq!(snapshot.issued_at().as_str(), "2026-07-24T12:00:00.000000Z");
    assert_eq!(snapshot.renewed_from_lease_id(), None);
    assert_eq!(snapshot.last_event_id().to_string(), EVENT_ID);
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap()["continuous_lifetime_started_at"],
        "2026-07-24T12:00:00.000000Z"
    );

    assert_eq!(
        make_snapshot(
            SecretLeaseStatus::Active,
            1,
            1,
            1,
            "2026-07-24T12:00:00.000000Z",
            None
        ),
        Err(SecretLeaseContractError::InvalidUseCounter)
    );
    assert_eq!(
        make_snapshot(
            SecretLeaseStatus::Active,
            0,
            0,
            1,
            "2026-07-24T12:00:00.000000Z",
            None
        ),
        Err(SecretLeaseContractError::InvalidUseCounter)
    );
    assert_eq!(
        make_snapshot(
            SecretLeaseStatus::Exhausted,
            2,
            1,
            1,
            "2026-07-24T12:00:00.000000Z",
            None
        ),
        Err(SecretLeaseContractError::InvalidUseCounter)
    );
    assert_eq!(
        make_snapshot(
            SecretLeaseStatus::Active,
            2,
            1,
            0,
            "2026-07-24T12:00:00.000000Z",
            None
        ),
        Err(SecretLeaseContractError::InvalidRevocationGeneration)
    );
    assert_eq!(
        make_snapshot(
            SecretLeaseStatus::Active,
            2,
            1,
            1,
            "2026-07-24T12:00:00.000000Z",
            Some(LEASE_ID.parse().unwrap())
        ),
        Err(SecretLeaseContractError::InvalidRenewalLineage)
    );
    assert_eq!(
        make_snapshot(
            SecretLeaseStatus::Active,
            2,
            1,
            1,
            "2026-07-24T12:00:00.000001Z",
            None
        ),
        Err(SecretLeaseContractError::InvalidTimeWindow)
    );
    let renewed = make_snapshot(
        SecretLeaseStatus::Active,
        2,
        1,
        1,
        "2026-07-24T12:00:00.000000Z",
        Some("018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4998".parse().unwrap()),
    )
    .unwrap();
    assert!(serde_json::to_string(&renewed)
        .unwrap()
        .contains("renewed_from_lease_id"));

    let make_event =
        |kind, outcome, claim_id, denial_code, max_uses, uses_claimed, revocation_generation| {
            let command_id = if matches!(
                kind,
                SecretAccessEvidenceKind::UseClaimed | SecretAccessEvidenceKind::UseDenied
            ) {
                ProcessLocalSecretBrokerCommandId::UseAttempt(ATTEMPT_ID.parse().unwrap())
            } else {
                ProcessLocalSecretBrokerCommandId::LeaseRequest(REQUEST_ID.parse().unwrap())
            };
            SecretAccessEvidence::try_new(
                EVENT_ID.parse().unwrap(),
                command_id,
                kind,
                outcome,
                binding(),
                Some(LEASE_ID.parse().unwrap()),
                Some(HANDLE_ID.parse().unwrap()),
                claim_id,
                uses_claimed,
                max_uses,
                revocation_generation,
                denial_code,
                "2026-07-24T12:01:00.000000Z".parse().unwrap(),
            )
        };
    let event = make_event(
        SecretAccessEvidenceKind::UseClaimed,
        SecretAccessEvidenceOutcome::Succeeded,
        Some(CLAIM_ID.parse().unwrap()),
        None,
        2,
        1,
        1,
    )
    .unwrap();
    assert_eq!(event.schema_version(), SECRET_ACCESS_EVIDENCE_SCHEMA_V1);
    assert_eq!(event.secret_access_event_id().to_string(), EVENT_ID);
    assert_eq!(
        event.command_id(),
        &ProcessLocalSecretBrokerCommandId::UseAttempt(ATTEMPT_ID.parse().unwrap())
    );
    assert_eq!(event.kind(), SecretAccessEvidenceKind::UseClaimed);
    assert_eq!(event.outcome(), SecretAccessEvidenceOutcome::Succeeded);
    assert_eq!(event.use_binding(), &binding());
    assert_eq!(event.secret_lease_id().unwrap().to_string(), LEASE_ID);
    assert_eq!(event.delivery_handle_id().unwrap().to_string(), HANDLE_ID);
    assert_eq!(event.secret_use_claim_id().unwrap().to_string(), CLAIM_ID);
    assert_eq!(event.uses_claimed(), 1);
    assert_eq!(event.max_uses(), 2);
    assert_eq!(event.revocation_generation(), 1);
    assert_eq!(event.denial_code(), None);
    assert_eq!(event.occurred_at().as_str(), "2026-07-24T12:01:00.000000Z");
    let denied = make_event(
        SecretAccessEvidenceKind::LeaseDenied,
        SecretAccessEvidenceOutcome::Denied,
        None,
        Some(SecretAccessDenialCode::AuthorityDenied),
        2,
        0,
        1,
    )
    .unwrap();
    assert!(serde_json::to_string(&denied)
        .unwrap()
        .contains("authority_denied"));
    let sparse_denial = SecretAccessEvidence::try_new(
        "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4601".parse().unwrap(),
        ProcessLocalSecretBrokerCommandId::LeaseRequest(REQUEST_ID.parse().unwrap()),
        SecretAccessEvidenceKind::LeaseDenied,
        SecretAccessEvidenceOutcome::Denied,
        binding(),
        None,
        None,
        None,
        0,
        1,
        1,
        Some(SecretAccessDenialCode::SecretNotAvailable),
        "2026-07-24T12:01:00.000000Z".parse().unwrap(),
    )
    .unwrap();
    let sparse_json = serde_json::to_value(&sparse_denial).unwrap();
    assert!(sparse_json.get("delivery_handle_id").is_none());
    assert!(sparse_json.get("secret_lease_id").is_none());

    for (invalid, expected) in [
        (
            make_event(
                SecretAccessEvidenceKind::LeaseDenied,
                SecretAccessEvidenceOutcome::Denied,
                None,
                None,
                1,
                0,
                1,
            ),
            SecretLeaseContractError::InvalidEvidenceShape,
        ),
        (
            make_event(
                SecretAccessEvidenceKind::LeaseIssued,
                SecretAccessEvidenceOutcome::Denied,
                None,
                Some(SecretAccessDenialCode::AuthorityDenied),
                1,
                0,
                1,
            ),
            SecretLeaseContractError::InvalidEvidenceShape,
        ),
        (
            make_event(
                SecretAccessEvidenceKind::UseClaimed,
                SecretAccessEvidenceOutcome::Succeeded,
                None,
                None,
                1,
                0,
                1,
            ),
            SecretLeaseContractError::InvalidEvidenceShape,
        ),
        (
            make_event(
                SecretAccessEvidenceKind::LeaseIssued,
                SecretAccessEvidenceOutcome::Succeeded,
                None,
                None,
                0,
                0,
                1,
            ),
            SecretLeaseContractError::InvalidUseCounter,
        ),
        (
            make_event(
                SecretAccessEvidenceKind::LeaseIssued,
                SecretAccessEvidenceOutcome::Succeeded,
                None,
                None,
                1,
                0,
                0,
            ),
            SecretLeaseContractError::InvalidUseCounter,
        ),
    ] {
        assert_eq!(invalid, Err(expected));
    }
}

#[test]
fn every_contract_error_has_a_fixed_code() {
    for error in [
        SecretLeaseContractError::InvalidTenantId,
        SecretLeaseContractError::InvalidPrincipalId,
        SecretLeaseContractError::InvalidWorkloadId,
        SecretLeaseContractError::InvalidNodeId,
        SecretLeaseContractError::InvalidInstanceId,
        SecretLeaseContractError::InvalidDriverOperation,
        SecretLeaseContractError::InvalidDriverDeclarationRevision,
        SecretLeaseContractError::InvalidDestinationSchema,
        SecretLeaseContractError::InvalidTrustedSendProfile,
        SecretLeaseContractError::InvalidSecretRefRevision,
        SecretLeaseContractError::RequirementBindingMismatch,
        SecretLeaseContractError::InvalidTimeWindow,
        SecretLeaseContractError::RequestedDurationExceeded,
        SecretLeaseContractError::InvalidUseCounter,
        SecretLeaseContractError::InvalidRevocationGeneration,
        SecretLeaseContractError::InvalidRenewalLineage,
        SecretLeaseContractError::InvalidEvidenceShape,
    ] {
        assert_eq!(error.to_string(), error.code());
        assert!(!error.code().is_empty());
    }
}
