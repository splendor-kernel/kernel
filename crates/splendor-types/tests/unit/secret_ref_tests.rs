use super::*;
use serde_json::{json, Value};

const AUTHORIZATION_FIXTURE: &[u8] =
    include_bytes!("../fixtures/secrets/v2/authorization-v2-same-revision.json");
const REF_FIXTURE: &[u8] =
    include_bytes!("../fixtures/secrets/v2/secret-ref-v2-same-revision.json");
const HISTORICAL_FIXTURE: &[u8] =
    include_bytes!("../fixtures/secrets/v2/historical-secret-ref-v1.json");
const MAXIMUM_AUTHORIZATION_FIXTURE: &[u8] =
    include_bytes!("../fixtures/secrets/v2/authorization-v2-legal-maximum.json");
const MAXIMUM_REF_FIXTURE: &[u8] =
    include_bytes!("../fixtures/secrets/v2/secret-ref-v2-legal-maximum.json");

#[test]
fn canonical_fixture_family_hashes_are_pinned() {
    for (name, fixture, expected_len, expected_blake3) in [
        (
            "authorization-v2-same-revision",
            AUTHORIZATION_FIXTURE,
            673,
            "0ad457b86c8039cfbacfd4e2d785c985656c45fef86ccddbfe5de8c969618060",
        ),
        (
            "secret-ref-v2-same-revision",
            REF_FIXTURE,
            1_347,
            "8bf4eb0d822ca320ae1731b76d13caeb024291b1fadd1f5ec49aa5fefdd90139",
        ),
        (
            "historical-secret-ref-v1",
            HISTORICAL_FIXTURE,
            1_315,
            "da5bf26d3fd9d9424387a1c1d301c3bf42c1aea5bdffd7fc6c852c3f28f302af",
        ),
        (
            "authorization-v2-legal-maximum",
            MAXIMUM_AUTHORIZATION_FIXTURE,
            2_237,
            "6576988eddba3e8368783447a58ae48739a5c67779019aac247a2cd03ef5f49d",
        ),
        (
            "secret-ref-v2-legal-maximum",
            MAXIMUM_REF_FIXTURE,
            37_041,
            "af2f77f6e7b0f87c2ba845a095b3ef391934409d21da485e041c18bfc8625f19",
        ),
    ] {
        assert_eq!(fixture.len(), expected_len, "{name} byte length changed");
        assert_eq!(
            blake3::hash(fixture).to_hex().as_str(),
            expected_blake3,
            "{name} BLAKE3 changed"
        );
    }
}

fn fixture_bytes(input: &'static [u8]) -> &'static [u8] {
    input.strip_suffix(b"\n").unwrap_or(input)
}

fn authorization() -> SecretCredentialAuthorizationV2 {
    SecretCredentialAuthorizationV2::from_json_slice(fixture_bytes(AUTHORIZATION_FIXTURE))
        .expect("canonical authorization")
}

fn secret_ref() -> SecretRefV2 {
    SecretRefV2::from_json_slice(fixture_bytes(REF_FIXTURE)).expect("canonical ref")
}

fn authorization_value() -> Value {
    serde_json::from_slice(fixture_bytes(AUTHORIZATION_FIXTURE)).unwrap()
}

fn ref_value() -> Value {
    serde_json::from_slice(fixture_bytes(REF_FIXTURE)).unwrap()
}

fn authorization_code(value: &Value) -> SecretCredentialAuthorizationV2ErrorCode {
    SecretCredentialAuthorizationV2::from_json_slice(&serde_json::to_vec(value).unwrap())
        .expect_err("authorization must reject")
        .code()
}

fn ref_code(value: &Value) -> SecretRefV2ErrorCode {
    SecretRefV2::from_json_slice(&serde_json::to_vec(value).unwrap())
        .expect_err("ref must reject")
        .code()
}

fn assert_authorization_shape_rejection(input: &[u8]) {
    assert_eq!(
        SecretCredentialAuthorizationV2::from_json_slice(input)
            .unwrap_err()
            .code(),
        SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape
    );
}

fn assert_ref_ingress_shape_rejection(input: &[u8]) {
    assert_eq!(
        SecretRefV2::from_json_slice(input).unwrap_err().code(),
        SecretRefV2ErrorCode::InvalidContractShape
    );
    assert_eq!(
        HistoricalSecretRefV1::from_json_slice(input).unwrap_err(),
        HistoricalSecretRefV1Error::InvalidHistoricalSecretRef
    );
}

fn operation(driver: &str, operation: &str) -> DriverOperationRef {
    DriverOperationRef {
        driver: driver.to_owned(),
        operation: operation.to_owned(),
        schema_version: crate::DRIVER_OPERATION_SCHEMA_V1.to_owned(),
    }
}

fn trusted_profile(limit: u8) -> DriverTrustedSendProfileV1 {
    DriverTrustedSendProfileV1::try_trusted_injection(
        limit,
        vec![
            SecretDeliveryControlKind::TrustedInjectionBoundary,
            SecretDeliveryControlKind::DestinationNetworkEgress,
        ],
    )
    .expect("trusted profile")
}

fn digest(fill: u8) -> DriverCredentialDestinationDigest {
    format!("blake3:{}", format!("{fill:02x}").repeat(32))
        .parse()
        .expect("digest")
}

fn sink(
    slot: SecretCredentialSlotId,
    classifications: Vec<SecretClassification>,
    intents: Vec<SecretUseIntent>,
    destination: &str,
    exposure: SecretDeliveryExposureProfile,
    profile: DriverTrustedSendProfileV1,
) -> crate::DriverOperationCredentialSinkV1 {
    crate::DriverOperationCredentialSinkV1::try_new(
        slot,
        classifications,
        intents,
        destination,
        exposure,
        profile,
    )
    .expect("sink")
}

fn declaration(
    operation: DriverOperationRef,
    revision: u64,
    sinks: Vec<crate::DriverOperationCredentialSinkV1>,
) -> DriverOperationCredentialSinksV1 {
    DriverOperationCredentialSinksV1::try_new(operation, revision, sinks).expect("declaration")
}

#[test]
fn canonical_v2_fixtures_parse_serialize_and_expose_only_validated_values() {
    let authorization = authorization();
    assert_eq!(
        serde_json::to_vec(&authorization).unwrap(),
        fixture_bytes(AUTHORIZATION_FIXTURE)
    );
    assert!(!AUTHORIZATION_FIXTURE.ends_with(b"\n"));
    assert!(!REF_FIXTURE.ends_with(b"\n"));
    assert!(!HISTORICAL_FIXTURE.ends_with(b"\n"));
    assert_eq!(
        authorization.schema_version(),
        SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V2
    );
    assert_eq!(authorization.driver_declaration_revision(), 7);
    assert_eq!(
        authorization.driver_operation(),
        &operation("example_driver", "example_operation")
    );
    assert_eq!(
        authorization.credential_slot_id().to_string(),
        "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001"
    );
    assert_eq!(
        authorization.destination_schema(),
        "example.driver.https_destination.v1"
    );
    assert_eq!(
        authorization.delivery_exposure_profile(),
        SecretDeliveryExposureProfile::TrustedInjection
    );
    assert_eq!(authorization.trusted_send_profile(), &trusted_profile(1));
    assert_eq!(authorization.approved_destination_digests().len(), 1);
    assert_eq!(
        format!("{authorization:?}"),
        "secret_credential_authorization_v2"
    );

    let secret_ref = secret_ref();
    assert_eq!(
        serde_json::to_vec(&secret_ref).unwrap(),
        fixture_bytes(REF_FIXTURE)
    );
    assert_eq!(secret_ref.schema_version(), SECRET_REF_SCHEMA_V2);
    assert_eq!(
        secret_ref.secret_ref_id().to_string(),
        "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5001"
    );
    assert_eq!(secret_ref.secret_ref_revision(), 2);
    assert_eq!(
        secret_ref.tenant_id().to_string(),
        "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5002"
    );
    assert_eq!(
        secret_ref.secret_provider_id().to_string(),
        "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5003"
    );
    assert_eq!(secret_ref.provider_namespace(), "example");
    assert_eq!(secret_ref.logical_name(), "billing_api");
    assert_eq!(secret_ref.provider_version_ref().as_str(), "release-007");
    assert_eq!(
        secret_ref.classification(),
        SecretClassification::AuthenticationCredential
    );
    assert_eq!(secret_ref.allowed_credential_bindings(), [authorization]);
    assert_eq!(
        secret_ref.allowed_delivery_methods(),
        [SecretDeliveryMethod::InheritedFd]
    );
    assert_eq!(secret_ref.lease_policy().max_lease_duration_seconds(), 300);
    assert_eq!(secret_ref.offline_behavior(), SecretOfflineBehavior::Deny);
    assert_eq!(secret_ref.created_at(), "2026-07-19T00:00:00.000000Z");
    assert_eq!(secret_ref.disabled_at(), None);
    assert_eq!(format!("{secret_ref:?}"), "secret_ref_v2");
}

#[test]
fn checked_constructors_apply_the_same_semantic_rules_and_set_ordering() {
    let base = authorization();
    let constructed = SecretCredentialAuthorizationV2::try_new(
        base.driver_operation().clone(),
        7,
        base.credential_slot_id(),
        base.destination_schema(),
        base.delivery_exposure_profile(),
        base.trusted_send_profile().clone(),
        vec![digest(2), digest(1)],
    )
    .expect("authorization constructor");
    assert_eq!(
        constructed.approved_destination_digests(),
        [digest(1), digest(2)]
    );
    let second_slot = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4002"
        .parse()
        .expect("second slot");
    let second_authorization = SecretCredentialAuthorizationV2::try_new(
        base.driver_operation().clone(),
        7,
        second_slot,
        base.destination_schema(),
        base.delivery_exposure_profile(),
        base.trusted_send_profile().clone(),
        vec![digest(1), digest(2)],
    )
    .expect("second authorization");

    let source = secret_ref();
    let constructed_ref = SecretRefV2::try_new(
        source.secret_ref_id().clone(),
        3,
        source.tenant_id().clone(),
        source.secret_provider_id().clone(),
        "example",
        "billing_api",
        SecretProviderVersionRef::try_new("release-008").unwrap(),
        source.classification(),
        vec![second_authorization, constructed],
        vec![
            SecretDeliveryMethod::TmpfsFile,
            SecretDeliveryMethod::InheritedFd,
        ],
        *source.lease_policy(),
        source.offline_behavior(),
        "2026-07-19T00:00:00.000000Z",
        Some("2026-07-19T00:00:00.000001Z".to_owned()),
    )
    .expect("ref constructor");
    assert_eq!(
        constructed_ref.allowed_delivery_methods(),
        [
            SecretDeliveryMethod::InheritedFd,
            SecretDeliveryMethod::TmpfsFile
        ]
    );
    assert_eq!(
        constructed_ref
            .allowed_credential_bindings()
            .iter()
            .map(SecretCredentialAuthorizationV2::credential_slot_id)
            .collect::<Vec<_>>(),
        vec![base.credential_slot_id(), second_slot]
    );
    assert_eq!(
        constructed_ref.disabled_at(),
        Some("2026-07-19T00:00:00.000001Z")
    );
}

#[test]
fn checked_constructors_reject_every_untyped_semantic_failure() {
    let base = authorization();
    let make_authorization =
        |operation: DriverOperationRef,
         revision: u64,
         destination: &str,
         exposure: SecretDeliveryExposureProfile,
         profile: DriverTrustedSendProfileV1,
         digests: Vec<DriverCredentialDestinationDigest>| {
            SecretCredentialAuthorizationV2::try_new(
                operation,
                revision,
                base.credential_slot_id(),
                destination,
                exposure,
                profile,
                digests,
            )
        };
    for (candidate, expected) in [
        (
            make_authorization(
                operation("", "example_operation"),
                7,
                base.destination_schema(),
                base.delivery_exposure_profile(),
                base.trusted_send_profile().clone(),
                vec![digest(1)],
            ),
            SecretCredentialAuthorizationV2ErrorCode::InvalidDriverOperation,
        ),
        (
            make_authorization(
                base.driver_operation().clone(),
                0,
                base.destination_schema(),
                base.delivery_exposure_profile(),
                base.trusted_send_profile().clone(),
                vec![digest(1)],
            ),
            SecretCredentialAuthorizationV2ErrorCode::InvalidDriverDeclarationRevision,
        ),
        (
            make_authorization(
                base.driver_operation().clone(),
                7,
                "invalid",
                base.delivery_exposure_profile(),
                base.trusted_send_profile().clone(),
                vec![digest(1)],
            ),
            SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationSchema,
        ),
        (
            make_authorization(
                base.driver_operation().clone(),
                7,
                base.destination_schema(),
                SecretDeliveryExposureProfile::MaterialExposed,
                base.trusted_send_profile().clone(),
                vec![digest(1)],
            ),
            SecretCredentialAuthorizationV2ErrorCode::InvalidExposureProfileBinding,
        ),
        (
            make_authorization(
                base.driver_operation().clone(),
                7,
                base.destination_schema(),
                base.delivery_exposure_profile(),
                base.trusted_send_profile().clone(),
                vec![],
            ),
            SecretCredentialAuthorizationV2ErrorCode::EmptyApprovedDestinationDigests,
        ),
        (
            make_authorization(
                base.driver_operation().clone(),
                7,
                base.destination_schema(),
                base.delivery_exposure_profile(),
                base.trusted_send_profile().clone(),
                (0..17).map(digest).collect(),
            ),
            SecretCredentialAuthorizationV2ErrorCode::TooManyApprovedDestinationDigests,
        ),
        (
            make_authorization(
                base.driver_operation().clone(),
                7,
                base.destination_schema(),
                base.delivery_exposure_profile(),
                base.trusted_send_profile().clone(),
                vec![digest(1), digest(1)],
            ),
            SecretCredentialAuthorizationV2ErrorCode::DuplicateDestinationDigest,
        ),
    ] {
        assert_eq!(candidate.unwrap_err().code(), expected);
    }

    for destination in ["", "no_version", "é.v1", &"a".repeat(129)] {
        assert_eq!(
            make_authorization(
                base.driver_operation().clone(),
                7,
                destination,
                base.delivery_exposure_profile(),
                base.trusted_send_profile().clone(),
                vec![digest(1)],
            )
            .unwrap_err()
            .code(),
            SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationSchema
        );
    }

    let source = secret_ref();
    let make_ref = |revision: u64,
                    tenant_id: TenantId,
                    namespace: &str,
                    name: &str,
                    bindings: Vec<SecretCredentialAuthorizationV2>,
                    methods: Vec<SecretDeliveryMethod>,
                    created_at: &str,
                    disabled_at: Option<String>| {
        SecretRefV2::try_new(
            source.secret_ref_id().clone(),
            revision,
            tenant_id,
            source.secret_provider_id().clone(),
            namespace,
            name,
            source.provider_version_ref().clone(),
            source.classification(),
            bindings,
            methods,
            *source.lease_policy(),
            source.offline_behavior(),
            created_at,
            disabled_at,
        )
    };
    for (candidate, expected) in [
        (
            make_ref(
                0,
                source.tenant_id().clone(),
                "example",
                "billing_api",
                vec![base.clone()],
                vec![SecretDeliveryMethod::InheritedFd],
                source.created_at(),
                None,
            ),
            SecretRefV2ErrorCode::InvalidSecretRefRevision,
        ),
        (
            make_ref(
                2,
                uuid::Uuid::nil().into(),
                "example",
                "billing_api",
                vec![base.clone()],
                vec![SecretDeliveryMethod::InheritedFd],
                source.created_at(),
                None,
            ),
            SecretRefV2ErrorCode::InvalidTenantId,
        ),
        (
            make_ref(
                2,
                source.tenant_id().clone(),
                "",
                "billing_api",
                vec![base.clone()],
                vec![SecretDeliveryMethod::InheritedFd],
                source.created_at(),
                None,
            ),
            SecretRefV2ErrorCode::InvalidProviderNamespace,
        ),
        (
            make_ref(
                2,
                source.tenant_id().clone(),
                "example",
                "",
                vec![base.clone()],
                vec![SecretDeliveryMethod::InheritedFd],
                source.created_at(),
                None,
            ),
            SecretRefV2ErrorCode::InvalidLogicalName,
        ),
        (
            make_ref(
                2,
                source.tenant_id().clone(),
                "example",
                "billing_api",
                vec![],
                vec![SecretDeliveryMethod::InheritedFd],
                source.created_at(),
                None,
            ),
            SecretRefV2ErrorCode::EmptyCredentialAuthorizations,
        ),
        (
            make_ref(
                2,
                source.tenant_id().clone(),
                "example",
                "billing_api",
                vec![base.clone(); 17],
                vec![SecretDeliveryMethod::InheritedFd],
                source.created_at(),
                None,
            ),
            SecretRefV2ErrorCode::TooManyCredentialAuthorizations,
        ),
        (
            make_ref(
                2,
                source.tenant_id().clone(),
                "example",
                "billing_api",
                vec![base.clone(), base.clone()],
                vec![SecretDeliveryMethod::InheritedFd],
                source.created_at(),
                None,
            ),
            SecretRefV2ErrorCode::DuplicateCredentialAuthorizationCoordinate,
        ),
        (
            make_ref(
                2,
                source.tenant_id().clone(),
                "example",
                "billing_api",
                vec![base.clone()],
                vec![SecretDeliveryMethod::EnvironmentVariable],
                source.created_at(),
                None,
            ),
            SecretRefV2ErrorCode::InvalidDeliveryMethods,
        ),
        (
            make_ref(
                2,
                source.tenant_id().clone(),
                "example",
                "billing_api",
                vec![base.clone()],
                vec![SecretDeliveryMethod::InheritedFd],
                "invalid",
                None,
            ),
            SecretRefV2ErrorCode::InvalidCreatedAt,
        ),
        (
            make_ref(
                2,
                source.tenant_id().clone(),
                "example",
                "billing_api",
                vec![base],
                vec![SecretDeliveryMethod::InheritedFd],
                source.created_at(),
                Some("2026-07-18T23:59:59.999999Z".to_owned()),
            ),
            SecretRefV2ErrorCode::InvalidDisabledAt,
        ),
    ] {
        assert_eq!(candidate.unwrap_err().code(), expected);
    }
}

#[test]
fn exact_errors_are_code_only_source_free_and_serializable() {
    let authorization_codes = [
        SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape,
        SecretCredentialAuthorizationV2ErrorCode::InvalidSchemaVersion,
        SecretCredentialAuthorizationV2ErrorCode::InvalidDriverOperation,
        SecretCredentialAuthorizationV2ErrorCode::InvalidDriverDeclarationRevision,
        SecretCredentialAuthorizationV2ErrorCode::InvalidCredentialSlot,
        SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationSchema,
        SecretCredentialAuthorizationV2ErrorCode::InvalidExposureProfileBinding,
        SecretCredentialAuthorizationV2ErrorCode::InvalidTrustedSendProfile,
        SecretCredentialAuthorizationV2ErrorCode::EmptyApprovedDestinationDigests,
        SecretCredentialAuthorizationV2ErrorCode::TooManyApprovedDestinationDigests,
        SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationDigest,
        SecretCredentialAuthorizationV2ErrorCode::DuplicateDestinationDigest,
    ];
    for code in authorization_codes {
        let error = authorization_error(code);
        assert_eq!(error.to_string(), code.as_str());
        assert_eq!(format!("{error:?}"), code.as_str());
        assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{code}\""));
        assert_eq!(format!("{code:?}"), code.as_str());
        assert_eq!(
            serde_json::to_string(&error).unwrap(),
            format!(r#"{{"code":"{code}"}}"#)
        );
        assert!(std::error::Error::source(&error).is_none());
    }

    let ref_codes = [
        SecretRefV2ErrorCode::InvalidContractShape,
        SecretRefV2ErrorCode::InvalidSchemaVersion,
        SecretRefV2ErrorCode::InvalidDriverOperation,
        SecretRefV2ErrorCode::InvalidDriverDeclarationRevision,
        SecretRefV2ErrorCode::InvalidCredentialSlot,
        SecretRefV2ErrorCode::InvalidDestinationSchema,
        SecretRefV2ErrorCode::InvalidExposureProfileBinding,
        SecretRefV2ErrorCode::InvalidTrustedSendProfile,
        SecretRefV2ErrorCode::EmptyApprovedDestinationDigests,
        SecretRefV2ErrorCode::TooManyApprovedDestinationDigests,
        SecretRefV2ErrorCode::InvalidDestinationDigest,
        SecretRefV2ErrorCode::DuplicateDestinationDigest,
        SecretRefV2ErrorCode::InvalidSecretRefId,
        SecretRefV2ErrorCode::InvalidSecretRefRevision,
        SecretRefV2ErrorCode::InvalidTenantId,
        SecretRefV2ErrorCode::InvalidSecretProviderId,
        SecretRefV2ErrorCode::InvalidProviderNamespace,
        SecretRefV2ErrorCode::InvalidLogicalName,
        SecretRefV2ErrorCode::InvalidProviderVersionRef,
        SecretRefV2ErrorCode::InvalidClassification,
        SecretRefV2ErrorCode::EmptyCredentialAuthorizations,
        SecretRefV2ErrorCode::TooManyCredentialAuthorizations,
        SecretRefV2ErrorCode::DuplicateCredentialAuthorizationCoordinate,
        SecretRefV2ErrorCode::InvalidDeliveryMethods,
        SecretRefV2ErrorCode::InvalidLeasePolicy,
        SecretRefV2ErrorCode::InvalidOfflineBehavior,
        SecretRefV2ErrorCode::InvalidCreatedAt,
        SecretRefV2ErrorCode::InvalidDisabledAt,
    ];
    assert_eq!(ref_codes.len(), 28);
    for code in ref_codes {
        let error = ref_error(code);
        assert_eq!(error.to_string(), code.as_str());
        assert_eq!(format!("{error:?}"), code.as_str());
        assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{code}\""));
        assert_eq!(format!("{code:?}"), code.as_str());
        assert_eq!(
            serde_json::to_string(&error).unwrap(),
            format!(r#"{{"code":"{code}"}}"#)
        );
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn authorization_parser_enforces_exact_shape_stages_and_profile_precedence() {
    assert_eq!(
        SecretCredentialAuthorizationV2::from_json_slice(b"[]")
            .unwrap_err()
            .code(),
        SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape
    );
    let duplicate = fixture_bytes(AUTHORIZATION_FIXTURE)
        .strip_suffix(b"}")
        .unwrap()
        .iter()
        .copied()
        .chain(
            b",\"schema_version\":\"splendor.secret.credential_authorization.v2\"}"
                .iter()
                .copied(),
        )
        .collect::<Vec<_>>();
    assert_eq!(
        SecretCredentialAuthorizationV2::from_json_slice(&duplicate)
            .unwrap_err()
            .code(),
        SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape
    );

    let mut candidate = authorization_value();
    candidate["unknown"] = json!("PRIVATE_UNKNOWN_CANARY");
    assert_eq!(
        authorization_code(&candidate),
        SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape
    );

    for (field, bad, expected) in [
        (
            "schema_version",
            Value::Null,
            SecretCredentialAuthorizationV2ErrorCode::InvalidSchemaVersion,
        ),
        (
            "driver_operation",
            Value::Null,
            SecretCredentialAuthorizationV2ErrorCode::InvalidDriverOperation,
        ),
        (
            "driver_declaration_revision",
            Value::Null,
            SecretCredentialAuthorizationV2ErrorCode::InvalidDriverDeclarationRevision,
        ),
        (
            "credential_slot_id",
            Value::Null,
            SecretCredentialAuthorizationV2ErrorCode::InvalidCredentialSlot,
        ),
        (
            "destination_schema",
            Value::Null,
            SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationSchema,
        ),
        (
            "delivery_exposure_profile",
            Value::Null,
            SecretCredentialAuthorizationV2ErrorCode::InvalidExposureProfileBinding,
        ),
        (
            "trusted_send_profile",
            Value::Null,
            SecretCredentialAuthorizationV2ErrorCode::InvalidTrustedSendProfile,
        ),
        (
            "approved_destination_digests",
            Value::Null,
            SecretCredentialAuthorizationV2ErrorCode::EmptyApprovedDestinationDigests,
        ),
    ] {
        for remove in [true, false] {
            let mut candidate = authorization_value();
            if remove {
                candidate.as_object_mut().unwrap().remove(field);
            } else {
                candidate[field] = bad.clone();
            }
            assert_eq!(authorization_code(&candidate), expected, "field {field}");
        }
    }

    for (field, bad, expected) in [
        (
            "schema_version",
            json!(7),
            SecretCredentialAuthorizationV2ErrorCode::InvalidSchemaVersion,
        ),
        (
            "driver_operation",
            json!("example_driver.example_operation"),
            SecretCredentialAuthorizationV2ErrorCode::InvalidDriverOperation,
        ),
        (
            "driver_declaration_revision",
            json!(true),
            SecretCredentialAuthorizationV2ErrorCode::InvalidDriverDeclarationRevision,
        ),
        (
            "credential_slot_id",
            json!(7),
            SecretCredentialAuthorizationV2ErrorCode::InvalidCredentialSlot,
        ),
        (
            "destination_schema",
            json!(7),
            SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationSchema,
        ),
        (
            "delivery_exposure_profile",
            json!(7),
            SecretCredentialAuthorizationV2ErrorCode::InvalidExposureProfileBinding,
        ),
        (
            "trusted_send_profile",
            json!("trusted_injection"),
            SecretCredentialAuthorizationV2ErrorCode::InvalidTrustedSendProfile,
        ),
        (
            "approved_destination_digests",
            json!("blake3"),
            SecretCredentialAuthorizationV2ErrorCode::EmptyApprovedDestinationDigests,
        ),
    ] {
        let mut candidate = authorization_value();
        candidate[field] = bad;
        assert_eq!(authorization_code(&candidate), expected, "field {field}");
    }

    let mut bad_operation = authorization_value();
    bad_operation["driver_operation"]["extra"] = json!(true);
    assert_eq!(
        authorization_code(&bad_operation),
        SecretCredentialAuthorizationV2ErrorCode::InvalidDriverOperation
    );

    let mut stage_eight = authorization_value();
    stage_eight["delivery_exposure_profile"] = json!("PRIVATE_EXPOSURE_CANARY");
    stage_eight["trusted_send_profile"] = json!({"kind":"PRIVATE_PROFILE_CANARY"});
    assert_eq!(
        authorization_code(&stage_eight),
        SecretCredentialAuthorizationV2ErrorCode::InvalidExposureProfileBinding
    );

    let mut stage_nine = authorization_value();
    stage_nine["trusted_send_profile"] = json!({"kind":"PRIVATE_PROFILE_CANARY"});
    assert_eq!(
        authorization_code(&stage_nine),
        SecretCredentialAuthorizationV2ErrorCode::InvalidTrustedSendProfile
    );

    let mut stage_ten = authorization_value();
    stage_ten["delivery_exposure_profile"] = json!("material_exposed");
    assert_eq!(
        authorization_code(&stage_ten),
        SecretCredentialAuthorizationV2ErrorCode::InvalidExposureProfileBinding
    );

    for profile in [
        json!({"kind":"trusted_injection","max_credential_bearing_sends":0,"applicable_delivery_controls":["trusted_injection_boundary"]}),
        json!({"kind":"trusted_injection","max_credential_bearing_sends":1,"applicable_delivery_controls":[]}),
        json!({"kind":"trusted_injection","max_credential_bearing_sends":1,"applicable_delivery_controls":["core_dump"]}),
        json!({"kind":"trusted_injection","max_credential_bearing_sends":1,"applicable_delivery_controls":["trusted_injection_boundary","trusted_injection_boundary"]}),
        json!({"kind":"not_applicable","payload":true}),
    ] {
        let mut candidate = authorization_value();
        candidate["trusted_send_profile"] = profile;
        assert_eq!(
            authorization_code(&candidate),
            SecretCredentialAuthorizationV2ErrorCode::InvalidTrustedSendProfile
        );
    }
}

#[test]
fn strict_private_wire_rejects_all_json_kinds_at_the_owning_stage() {
    for input in [
        b"true".as_slice(),
        b"-1".as_slice(),
        b"1".as_slice(),
        b"1.5".as_slice(),
        br#""PRIVATE_TOP_LEVEL_CANARY""#,
        b"null".as_slice(),
        b"[]".as_slice(),
    ] {
        assert_authorization_shape_rejection(input);
        assert_ref_ingress_shape_rejection(input);
    }

    let wrong_kinds = vec![
        json!(true),
        json!(-1),
        json!(1),
        json!(1.5),
        json!("PRIVATE_WIRE_CANARY"),
        Value::Null,
        json!([]),
        json!({}),
    ];
    for value in wrong_kinds {
        let mut operation = authorization_value();
        operation["driver_operation"] = value.clone();
        assert_eq!(
            authorization_code(&operation),
            SecretCredentialAuthorizationV2ErrorCode::InvalidDriverOperation
        );

        let mut profile = authorization_value();
        profile["trusted_send_profile"] = value.clone();
        let profile_error = SecretCredentialAuthorizationV2::from_json_slice(
            &serde_json::to_vec(&profile).unwrap(),
        )
        .unwrap_err();
        assert_eq!(
            profile_error.code(),
            SecretCredentialAuthorizationV2ErrorCode::InvalidTrustedSendProfile
        );
        assert!(!profile_error.to_string().contains("PRIVATE"));

        let mut digests = authorization_value();
        digests["approved_destination_digests"] = value.clone();
        assert_eq!(
            authorization_code(&digests),
            SecretCredentialAuthorizationV2ErrorCode::EmptyApprovedDestinationDigests
        );

        let mut bindings = ref_value();
        bindings["allowed_credential_bindings"] = value.clone();
        assert_eq!(
            ref_code(&bindings),
            SecretRefV2ErrorCode::EmptyCredentialAuthorizations
        );

        let mut methods = ref_value();
        methods["allowed_delivery_methods"] = value.clone();
        assert_eq!(
            ref_code(&methods),
            SecretRefV2ErrorCode::InvalidDeliveryMethods
        );

        let mut lease = ref_value();
        lease["lease_policy"] = value;
        assert_eq!(ref_code(&lease), SecretRefV2ErrorCode::InvalidLeasePolicy);
    }

    for value in [json!([]), json!({})] {
        let mut authorization = authorization_value();
        authorization["schema_version"] = value;
        assert_eq!(
            authorization_code(&authorization),
            SecretCredentialAuthorizationV2ErrorCode::InvalidSchemaVersion
        );
    }
}

#[test]
fn authorization_integer_digest_and_set_boundaries_fail_closed() {
    for accepted in [1_u64, MAX_SAFE_INTEGER] {
        let mut candidate = authorization_value();
        candidate["driver_declaration_revision"] = json!(accepted);
        assert_eq!(
            SecretCredentialAuthorizationV2::from_json_slice(
                &serde_json::to_vec(&candidate).unwrap()
            )
            .unwrap()
            .driver_declaration_revision(),
            accepted
        );
    }
    for raw in [
        "0",
        "-1",
        "1.0",
        "1e0",
        "9007199254740992",
        "18446744073709551616",
        "\"7\"",
    ] {
        let input = String::from_utf8(fixture_bytes(AUTHORIZATION_FIXTURE).to_vec())
            .unwrap()
            .replace(
                "\"driver_declaration_revision\":7",
                &format!("\"driver_declaration_revision\":{raw}"),
            );
        assert_eq!(
            SecretCredentialAuthorizationV2::from_json_slice(input.as_bytes())
                .unwrap_err()
                .code(),
            SecretCredentialAuthorizationV2ErrorCode::InvalidDriverDeclarationRevision
        );
    }
    let leading_zero = String::from_utf8(fixture_bytes(AUTHORIZATION_FIXTURE).to_vec())
        .unwrap()
        .replace(
            "\"driver_declaration_revision\":7",
            "\"driver_declaration_revision\":07",
        );
    assert_eq!(
        SecretCredentialAuthorizationV2::from_json_slice(leading_zero.as_bytes())
            .unwrap_err()
            .code(),
        SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape
    );
    let integer_overflow = String::from_utf8(fixture_bytes(AUTHORIZATION_FIXTURE).to_vec())
        .unwrap()
        .replace(
            "\"driver_declaration_revision\":7",
            "\"driver_declaration_revision\":340282366920938463463374607431768211456",
        );
    assert_eq!(
        SecretCredentialAuthorizationV2::from_json_slice(integer_overflow.as_bytes())
            .unwrap_err()
            .code(),
        SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape
    );

    let mut empty = authorization_value();
    empty["approved_destination_digests"] = json!([]);
    assert_eq!(
        authorization_code(&empty),
        SecretCredentialAuthorizationV2ErrorCode::EmptyApprovedDestinationDigests
    );
    let mut too_many = authorization_value();
    too_many["approved_destination_digests"] = Value::Array(
        (0..17)
            .map(|index| json!(digest(index).to_string()))
            .collect(),
    );
    assert_eq!(
        authorization_code(&too_many),
        SecretCredentialAuthorizationV2ErrorCode::TooManyApprovedDestinationDigests
    );
    let mut invalid = authorization_value();
    invalid["approved_destination_digests"] = json!(["PRIVATE_DIGEST_CANARY"]);
    assert_eq!(
        authorization_code(&invalid),
        SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationDigest
    );
    let mut duplicate = authorization_value();
    duplicate["approved_destination_digests"] =
        json!([digest(1).to_string(), digest(1).to_string()]);
    assert_eq!(
        authorization_code(&duplicate),
        SecretCredentialAuthorizationV2ErrorCode::DuplicateDestinationDigest
    );
    let mut permutation = authorization_value();
    permutation["approved_destination_digests"] =
        json!([digest(2).to_string(), digest(1).to_string()]);
    let parsed = SecretCredentialAuthorizationV2::from_json_slice(
        &serde_json::to_vec(&permutation).unwrap(),
    )
    .unwrap();
    assert_eq!(
        parsed.approved_destination_digests(),
        [digest(1), digest(2)]
    );
}

#[test]
fn ref_parser_enforces_all_named_stages_in_order() {
    assert_eq!(
        SecretRefV2::from_json_slice(b"null").unwrap_err().code(),
        SecretRefV2ErrorCode::InvalidContractShape
    );
    let duplicate = fixture_bytes(REF_FIXTURE)
        .strip_suffix(b"}")
        .unwrap()
        .iter()
        .copied()
        .chain(
            b",\"schema_version\":\"splendor.secret.ref.v2\"}"
                .iter()
                .copied(),
        )
        .collect::<Vec<_>>();
    assert_eq!(
        SecretRefV2::from_json_slice(&duplicate).unwrap_err().code(),
        SecretRefV2ErrorCode::InvalidContractShape
    );

    let mut unknown = ref_value();
    unknown["PRIVATE_REF_KEY_CANARY"] = json!("PRIVATE_REF_VALUE_CANARY");
    assert_eq!(
        ref_code(&unknown),
        SecretRefV2ErrorCode::InvalidContractShape
    );

    for (field, expected) in [
        ("schema_version", SecretRefV2ErrorCode::InvalidSchemaVersion),
        ("secret_ref_id", SecretRefV2ErrorCode::InvalidSecretRefId),
        (
            "secret_ref_revision",
            SecretRefV2ErrorCode::InvalidSecretRefRevision,
        ),
        ("tenant_id", SecretRefV2ErrorCode::InvalidTenantId),
        (
            "secret_provider_id",
            SecretRefV2ErrorCode::InvalidSecretProviderId,
        ),
        (
            "provider_namespace",
            SecretRefV2ErrorCode::InvalidProviderNamespace,
        ),
        ("logical_name", SecretRefV2ErrorCode::InvalidLogicalName),
        (
            "provider_version_ref",
            SecretRefV2ErrorCode::InvalidProviderVersionRef,
        ),
        (
            "classification",
            SecretRefV2ErrorCode::InvalidClassification,
        ),
        (
            "allowed_credential_bindings",
            SecretRefV2ErrorCode::EmptyCredentialAuthorizations,
        ),
        (
            "allowed_delivery_methods",
            SecretRefV2ErrorCode::InvalidDeliveryMethods,
        ),
        ("lease_policy", SecretRefV2ErrorCode::InvalidLeasePolicy),
        (
            "offline_behavior",
            SecretRefV2ErrorCode::InvalidOfflineBehavior,
        ),
        ("created_at", SecretRefV2ErrorCode::InvalidCreatedAt),
    ] {
        for remove in [true, false] {
            let mut candidate = ref_value();
            if remove {
                candidate.as_object_mut().unwrap().remove(field);
            } else {
                candidate[field] = Value::Null;
            }
            assert_eq!(ref_code(&candidate), expected, "field {field}");
        }
    }

    for (field, expected) in [
        ("schema_version", SecretRefV2ErrorCode::InvalidSchemaVersion),
        ("secret_ref_id", SecretRefV2ErrorCode::InvalidSecretRefId),
        (
            "secret_ref_revision",
            SecretRefV2ErrorCode::InvalidSecretRefRevision,
        ),
        ("tenant_id", SecretRefV2ErrorCode::InvalidTenantId),
        (
            "secret_provider_id",
            SecretRefV2ErrorCode::InvalidSecretProviderId,
        ),
        (
            "provider_namespace",
            SecretRefV2ErrorCode::InvalidProviderNamespace,
        ),
        ("logical_name", SecretRefV2ErrorCode::InvalidLogicalName),
        (
            "provider_version_ref",
            SecretRefV2ErrorCode::InvalidProviderVersionRef,
        ),
        (
            "classification",
            SecretRefV2ErrorCode::InvalidClassification,
        ),
        (
            "allowed_credential_bindings",
            SecretRefV2ErrorCode::EmptyCredentialAuthorizations,
        ),
        (
            "allowed_delivery_methods",
            SecretRefV2ErrorCode::InvalidDeliveryMethods,
        ),
        ("lease_policy", SecretRefV2ErrorCode::InvalidLeasePolicy),
        (
            "offline_behavior",
            SecretRefV2ErrorCode::InvalidOfflineBehavior,
        ),
        ("created_at", SecretRefV2ErrorCode::InvalidCreatedAt),
    ] {
        let mut candidate = ref_value();
        candidate[field] = json!(true);
        assert_eq!(ref_code(&candidate), expected, "field {field}");
    }

    let mut disabled_null = ref_value();
    disabled_null["disabled_at"] = Value::Null;
    assert_eq!(
        ref_code(&disabled_null),
        SecretRefV2ErrorCode::InvalidDisabledAt
    );
    let mut disabled_wrong_kind = ref_value();
    disabled_wrong_kind["disabled_at"] = json!(true);
    assert_eq!(
        ref_code(&disabled_wrong_kind),
        SecretRefV2ErrorCode::InvalidDisabledAt
    );
    let mut disabled_before = ref_value();
    disabled_before["disabled_at"] = json!("2026-07-18T23:59:59.999999Z");
    assert_eq!(
        ref_code(&disabled_before),
        SecretRefV2ErrorCode::InvalidDisabledAt
    );
    let mut nested = ref_value();
    nested["allowed_credential_bindings"][0]["driver_operation"] = Value::Null;
    assert_eq!(
        ref_code(&nested),
        SecretRefV2ErrorCode::InvalidDriverOperation
    );

    let mut nested_cases = Vec::new();
    let mut invalid_shape = authorization_value();
    invalid_shape["unknown"] = json!(true);
    nested_cases.push((invalid_shape, SecretRefV2ErrorCode::InvalidContractShape));
    for (field, value, expected) in [
        (
            "schema_version",
            Value::Null,
            SecretRefV2ErrorCode::InvalidSchemaVersion,
        ),
        (
            "driver_operation",
            Value::Null,
            SecretRefV2ErrorCode::InvalidDriverOperation,
        ),
        (
            "driver_declaration_revision",
            Value::Null,
            SecretRefV2ErrorCode::InvalidDriverDeclarationRevision,
        ),
        (
            "credential_slot_id",
            Value::Null,
            SecretRefV2ErrorCode::InvalidCredentialSlot,
        ),
        (
            "destination_schema",
            Value::Null,
            SecretRefV2ErrorCode::InvalidDestinationSchema,
        ),
        (
            "delivery_exposure_profile",
            Value::Null,
            SecretRefV2ErrorCode::InvalidExposureProfileBinding,
        ),
        (
            "trusted_send_profile",
            Value::Null,
            SecretRefV2ErrorCode::InvalidTrustedSendProfile,
        ),
        (
            "approved_destination_digests",
            Value::Null,
            SecretRefV2ErrorCode::EmptyApprovedDestinationDigests,
        ),
        (
            "approved_destination_digests",
            Value::Array(
                (0..17)
                    .map(|index| json!(digest(index).to_string()))
                    .collect(),
            ),
            SecretRefV2ErrorCode::TooManyApprovedDestinationDigests,
        ),
        (
            "approved_destination_digests",
            json!(["PRIVATE_DIGEST_CANARY"]),
            SecretRefV2ErrorCode::InvalidDestinationDigest,
        ),
        (
            "approved_destination_digests",
            json!([digest(1).to_string(), digest(1).to_string()]),
            SecretRefV2ErrorCode::DuplicateDestinationDigest,
        ),
    ] {
        let mut candidate = authorization_value();
        candidate[field] = value;
        nested_cases.push((candidate, expected));
    }
    for (authorization, expected) in nested_cases {
        let mut candidate = ref_value();
        candidate["allowed_credential_bindings"] = json!([authorization]);
        assert_eq!(ref_code(&candidate), expected);
    }
}

#[test]
fn ref_sets_duplicate_coordinates_delivery_and_timestamps_are_exact() {
    let base = authorization_value();
    for second_digests in [
        base["approved_destination_digests"].clone(),
        json!([digest(1).to_string(), digest(2).to_string()]),
        json!([digest(2).to_string()]),
    ] {
        let mut second = base.clone();
        second["approved_destination_digests"] = second_digests;
        let mut candidate = ref_value();
        candidate["allowed_credential_bindings"] = json!([base.clone(), second]);
        candidate["allowed_delivery_methods"] = Value::Null;
        assert_eq!(
            ref_code(&candidate),
            SecretRefV2ErrorCode::DuplicateCredentialAuthorizationCoordinate,
            "duplicate coordinate must precede delivery validation"
        );
    }

    let mut too_many = ref_value();
    too_many["allowed_credential_bindings"] = Value::Array(
        (0..17)
            .map(|index| {
                let mut value = base.clone();
                value["credential_slot_id"] =
                    json!(format!("018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f{index:04x}"));
                value
            })
            .collect(),
    );
    assert_eq!(
        ref_code(&too_many),
        SecretRefV2ErrorCode::TooManyCredentialAuthorizations
    );

    for methods in [
        json!([]),
        json!(["environment_variable"]),
        json!(["inherited_fd", "inherited_fd"]),
        json!(["PRIVATE_METHOD_CANARY"]),
        json!([
            "inherited_fd",
            "tmpfs_file",
            "one_shot_local_socket",
            "orchestrator_projected_secret",
            "environment_variable",
            "inherited_fd"
        ]),
    ] {
        let mut candidate = ref_value();
        candidate["allowed_delivery_methods"] = methods;
        assert_eq!(
            ref_code(&candidate),
            SecretRefV2ErrorCode::InvalidDeliveryMethods
        );
    }

    for timestamp in [
        "2026-02-29T00:00:00.000000Z",
        "2026-13-01T00:00:00.000000Z",
        "2026-07-19T24:00:00.000000Z",
        "2026-07-19T00:00:60.000000Z",
        "2026-07-19T00:00:00Z",
        "2026-07-19T00:00:00.000000+00:00",
    ] {
        let mut candidate = ref_value();
        candidate["created_at"] = json!(timestamp);
        assert_eq!(ref_code(&candidate), SecretRefV2ErrorCode::InvalidCreatedAt);
    }
    let mut valid_leap = ref_value();
    valid_leap["created_at"] = json!("2028-02-29T23:59:59.999999Z");
    assert!(SecretRefV2::from_json_slice(&serde_json::to_vec(&valid_leap).unwrap()).is_ok());

    let mut material_exposed = authorization_value();
    material_exposed["delivery_exposure_profile"] = json!("material_exposed");
    material_exposed["trusted_send_profile"] = json!({"kind":"not_applicable"});
    assert!(SecretCredentialAuthorizationV2::from_json_slice(
        &serde_json::to_vec(&material_exposed).unwrap()
    )
    .is_ok());

    let mut unknown_control = authorization_value();
    unknown_control["trusted_send_profile"]["applicable_delivery_controls"] =
        json!(["trusted_injection_boundary", "PRIVATE_CONTROL_CANARY"]);
    assert_eq!(
        authorization_code(&unknown_control),
        SecretCredentialAuthorizationV2ErrorCode::InvalidTrustedSendProfile
    );

    for (field, value, expected) in [
        (
            "classification",
            json!("PRIVATE_CLASSIFICATION_CANARY"),
            SecretRefV2ErrorCode::InvalidClassification,
        ),
        (
            "offline_behavior",
            json!("PRIVATE_OFFLINE_CANARY"),
            SecretRefV2ErrorCode::InvalidOfflineBehavior,
        ),
    ] {
        let mut candidate = ref_value();
        candidate[field] = value;
        assert_eq!(ref_code(&candidate), expected);
    }
}

#[test]
fn ref_integer_tokens_and_closed_lease_policy_fail_at_exact_stages() {
    for accepted in [1_u64, MAX_SAFE_INTEGER] {
        let raw = String::from_utf8(fixture_bytes(REF_FIXTURE).to_vec())
            .unwrap()
            .replace(
                "\"secret_ref_revision\":2",
                &format!("\"secret_ref_revision\":{accepted}"),
            );
        assert_eq!(
            SecretRefV2::from_json_slice(raw.as_bytes())
                .unwrap()
                .secret_ref_revision(),
            accepted
        );
    }
    for raw_value in [
        "0",
        "-1",
        "1.0",
        "1e0",
        "9007199254740992",
        "18446744073709551616",
        "\"2\"",
    ] {
        let raw = String::from_utf8(fixture_bytes(REF_FIXTURE).to_vec())
            .unwrap()
            .replace(
                "\"secret_ref_revision\":2",
                &format!("\"secret_ref_revision\":{raw_value}"),
            );
        assert_eq!(
            SecretRefV2::from_json_slice(raw.as_bytes())
                .unwrap_err()
                .code(),
            SecretRefV2ErrorCode::InvalidSecretRefRevision,
            "revision token {raw_value}"
        );
    }
    let integer_overflow = String::from_utf8(fixture_bytes(REF_FIXTURE).to_vec())
        .unwrap()
        .replace(
            "\"secret_ref_revision\":2",
            "\"secret_ref_revision\":340282366920938463463374607431768211456",
        );
    assert_eq!(
        SecretRefV2::from_json_slice(integer_overflow.as_bytes())
            .unwrap_err()
            .code(),
        SecretRefV2ErrorCode::InvalidContractShape
    );

    for (field, value) in [
        ("max_lease_duration_seconds", json!(0)),
        ("max_continuous_lifetime_seconds", json!(0)),
        ("max_uses", json!(0)),
        ("clock_skew_tolerance_seconds", json!(31)),
        ("renewable", json!("false")),
    ] {
        let mut candidate = ref_value();
        candidate["lease_policy"][field] = value;
        assert_eq!(
            ref_code(&candidate),
            SecretRefV2ErrorCode::InvalidLeasePolicy,
            "lease field {field}"
        );
    }
    let mut relationship = ref_value();
    relationship["lease_policy"]["max_continuous_lifetime_seconds"] = json!(299);
    assert_eq!(
        ref_code(&relationship),
        SecretRefV2ErrorCode::InvalidLeasePolicy
    );
    let mut unknown = ref_value();
    unknown["lease_policy"]["PRIVATE_LEASE_CANARY"] = json!(true);
    assert_eq!(ref_code(&unknown), SecretRefV2ErrorCode::InvalidLeasePolicy);
    let mut missing = ref_value();
    missing["lease_policy"]
        .as_object_mut()
        .unwrap()
        .remove("max_uses");
    assert_eq!(ref_code(&missing), SecretRefV2ErrorCode::InvalidLeasePolicy);
}

fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut value = String::new();
    value.extend(std::iter::repeat_n('[', depth));
    value.push_str("null");
    value.extend(std::iter::repeat_n(']', depth));
    value.into_bytes()
}

fn member_document(count: usize) -> Vec<u8> {
    let fields = (0..count)
        .map(|index| format!(r#""k{index}":null"#))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{fields}}}").into_bytes()
}

fn auth_token_document(last_is_array: bool) -> Vec<u8> {
    let mut fields = (0..31)
        .map(|index| format!(r#""k{index}":[0]"#))
        .collect::<Vec<_>>();
    fields.push(if last_is_array {
        r#""last":[]"#.to_owned()
    } else {
        r#""last":0"#.to_owned()
    });
    format!("{{{}}}", fields.join(",")).into_bytes()
}

fn ref_token_document(array_values: usize) -> Vec<u8> {
    let mut values = (0..384)
        .map(|index| {
            if index < array_values {
                format!(r#"{{"k{index}":[]}}"#)
            } else {
                format!(r#"{{"k{index}":0}}"#)
            }
        })
        .collect::<Vec<_>>();
    values.extend((0..128).map(|_| "null".to_owned()));
    format!("[{}]", values.join(",")).into_bytes()
}

#[test]
fn bounded_ingress_enforces_every_authorization_cap_and_cap_plus_one() {
    let canonical = fixture_bytes(AUTHORIZATION_FIXTURE);
    let mut raw_cap = canonical.to_vec();
    raw_cap.resize(AUTHORIZATION_INGRESS_BUDGET.bytes, b' ');
    assert!(SecretCredentialAuthorizationV2::from_json_slice(&raw_cap).is_ok());
    raw_cap.push(b' ');
    assert_eq!(
        SecretCredentialAuthorizationV2::from_json_slice(&raw_cap)
            .unwrap_err()
            .code(),
        SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape
    );

    assert_eq!(
        preflight_json(
            &nested_arrays(AUTHORIZATION_INGRESS_BUDGET.depth),
            AUTHORIZATION_INGRESS_BUDGET
        )
        .unwrap()
        .depth,
        AUTHORIZATION_INGRESS_BUDGET.depth
    );
    assert!(preflight_json(
        &nested_arrays(AUTHORIZATION_INGRESS_BUDGET.depth + 1),
        AUTHORIZATION_INGRESS_BUDGET
    )
    .is_err());

    assert_eq!(
        preflight_json(&auth_token_document(false), AUTHORIZATION_INGRESS_BUDGET)
            .unwrap()
            .tokens,
        AUTHORIZATION_INGRESS_BUDGET.tokens
    );
    assert!(preflight_json(&auth_token_document(true), AUTHORIZATION_INGRESS_BUDGET).is_err());

    assert_eq!(
        preflight_json(
            &member_document(AUTHORIZATION_INGRESS_BUDGET.members),
            AUTHORIZATION_INGRESS_BUDGET
        )
        .unwrap()
        .members,
        AUTHORIZATION_INGRESS_BUDGET.members
    );
    assert!(preflight_json(
        &member_document(AUTHORIZATION_INGRESS_BUDGET.members + 1),
        AUTHORIZATION_INGRESS_BUDGET
    )
    .is_err());

    let elements = |count: usize| format!("[{}]", vec!["null"; count].join(",")).into_bytes();
    assert_eq!(
        preflight_json(
            &elements(AUTHORIZATION_INGRESS_BUDGET.elements),
            AUTHORIZATION_INGRESS_BUDGET
        )
        .unwrap()
        .elements,
        AUTHORIZATION_INGRESS_BUDGET.elements
    );
    assert!(preflight_json(
        &elements(AUTHORIZATION_INGRESS_BUDGET.elements + 1),
        AUTHORIZATION_INGRESS_BUDGET
    )
    .is_err());

    let string = |length: usize| serde_json::to_vec(&"x".repeat(length)).unwrap();
    assert!(preflight_json(
        &string(AUTHORIZATION_INGRESS_BUDGET.string_bytes),
        AUTHORIZATION_INGRESS_BUDGET
    )
    .is_ok());
    assert!(preflight_json(
        &string(AUTHORIZATION_INGRESS_BUDGET.string_bytes + 1),
        AUTHORIZATION_INGRESS_BUDGET
    )
    .is_err());
    let name_at_cap = format!(r#"{{"{}":null}}"#, "x".repeat(256));
    let name_over_cap = format!(r#"{{"{}":null}}"#, "x".repeat(257));
    assert!(preflight_json(name_at_cap.as_bytes(), AUTHORIZATION_INGRESS_BUDGET).is_ok());
    assert!(preflight_json(name_over_cap.as_bytes(), AUTHORIZATION_INGRESS_BUDGET).is_err());
    let escaped_at_cap = format!(r#""{}""#, r"\u0061".repeat(256));
    let escaped_over_cap = format!(r#""{}""#, r"\u0061".repeat(257));
    assert!(preflight_json(escaped_at_cap.as_bytes(), AUTHORIZATION_INGRESS_BUDGET).is_ok());
    assert!(preflight_json(escaped_over_cap.as_bytes(), AUTHORIZATION_INGRESS_BUDGET).is_err());
    for input in [
        nested_arrays(AUTHORIZATION_INGRESS_BUDGET.depth + 1),
        auth_token_document(true),
        member_document(AUTHORIZATION_INGRESS_BUDGET.members + 1),
        elements(AUTHORIZATION_INGRESS_BUDGET.elements + 1),
        string(AUTHORIZATION_INGRESS_BUDGET.string_bytes + 1),
        name_over_cap.into_bytes(),
        escaped_over_cap.into_bytes(),
    ] {
        assert_authorization_shape_rejection(&input);
    }
}

#[test]
fn bounded_ingress_enforces_every_ref_cap_and_cap_plus_one() {
    let canonical = fixture_bytes(REF_FIXTURE);
    let mut raw_cap = canonical.to_vec();
    raw_cap.resize(REF_INGRESS_BUDGET.bytes, b' ');
    assert!(SecretRefV2::from_json_slice(&raw_cap).is_ok());
    let mut historical_raw_cap = fixture_bytes(HISTORICAL_FIXTURE).to_vec();
    historical_raw_cap.resize(REF_INGRESS_BUDGET.bytes, b' ');
    assert!(HistoricalSecretRefV1::from_json_slice(&historical_raw_cap).is_ok());
    raw_cap.push(b' ');
    assert_ref_ingress_shape_rejection(&raw_cap);

    assert_eq!(
        preflight_json(&nested_arrays(REF_INGRESS_BUDGET.depth), REF_INGRESS_BUDGET)
            .unwrap()
            .depth,
        REF_INGRESS_BUDGET.depth
    );
    assert!(preflight_json(
        &nested_arrays(REF_INGRESS_BUDGET.depth + 1),
        REF_INGRESS_BUDGET
    )
    .is_err());
    assert_eq!(
        preflight_json(&ref_token_document(382), REF_INGRESS_BUDGET)
            .unwrap()
            .tokens,
        REF_INGRESS_BUDGET.tokens
    );
    assert!(preflight_json(&ref_token_document(383), REF_INGRESS_BUDGET).is_err());
    assert_eq!(
        preflight_json(
            &member_document(REF_INGRESS_BUDGET.members),
            REF_INGRESS_BUDGET
        )
        .unwrap()
        .members,
        REF_INGRESS_BUDGET.members
    );
    assert!(preflight_json(
        &member_document(REF_INGRESS_BUDGET.members + 1),
        REF_INGRESS_BUDGET
    )
    .is_err());
    let elements = |count: usize| format!("[{}]", vec!["null"; count].join(",")).into_bytes();
    assert_eq!(
        preflight_json(&elements(REF_INGRESS_BUDGET.elements), REF_INGRESS_BUDGET)
            .unwrap()
            .elements,
        REF_INGRESS_BUDGET.elements
    );
    assert!(preflight_json(
        &elements(REF_INGRESS_BUDGET.elements + 1),
        REF_INGRESS_BUDGET
    )
    .is_err());
    let exact_string = serde_json::to_vec(&"x".repeat(REF_INGRESS_BUDGET.string_bytes)).unwrap();
    let long_string = serde_json::to_vec(&"x".repeat(REF_INGRESS_BUDGET.string_bytes + 1)).unwrap();
    assert!(preflight_json(&exact_string, REF_INGRESS_BUDGET).is_ok());
    assert!(preflight_json(&long_string, REF_INGRESS_BUDGET).is_err());
    let escaped_at_cap = format!(r#""{}""#, r"\u0061".repeat(256));
    let escaped_over_cap = format!(r#""{}""#, r"\u0061".repeat(257));
    assert!(preflight_json(escaped_at_cap.as_bytes(), REF_INGRESS_BUDGET).is_ok());
    assert!(preflight_json(escaped_over_cap.as_bytes(), REF_INGRESS_BUDGET).is_err());
    for input in [
        nested_arrays(REF_INGRESS_BUDGET.depth + 1),
        ref_token_document(383),
        member_document(REF_INGRESS_BUDGET.members + 1),
        elements(REF_INGRESS_BUDGET.elements + 1),
        long_string,
        escaped_over_cap.into_bytes(),
    ] {
        assert_ref_ingress_shape_rejection(&input);
    }
}

#[test]
fn bounded_ingress_rejects_malformed_utf8_escapes_duplicates_and_bombs() {
    for input in [
        b"\xff\xfe".as_slice(),
        br#"{"schema_version":"\uD800"}"#,
        b"{".as_slice(),
    ] {
        assert_eq!(
            SecretCredentialAuthorizationV2::from_json_slice(input)
                .unwrap_err()
                .code(),
            SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape
        );
        assert_eq!(
            SecretRefV2::from_json_slice(input).unwrap_err().code(),
            SecretRefV2ErrorCode::InvalidContractShape
        );
        assert_eq!(
            HistoricalSecretRefV1::from_json_slice(input).unwrap_err(),
            HistoricalSecretRefV1Error::InvalidHistoricalSecretRef
        );
    }
    let nested_duplicate = br#"{"x":{"PRIVATE_DUPLICATE_CANARY":1,"PRIVATE_DUPLICATE_CANARY":2}}"#;
    assert!(preflight_json(nested_duplicate, AUTHORIZATION_INGRESS_BUDGET).is_err());
    assert_authorization_shape_rejection(nested_duplicate);
    assert_ref_ingress_shape_rejection(nested_duplicate);
    let whitespace_bomb = [
        fixture_bytes(AUTHORIZATION_FIXTURE),
        &vec![b' '; AUTHORIZATION_INGRESS_BUDGET.bytes],
    ]
    .concat();
    assert_eq!(
        SecretCredentialAuthorizationV2::from_json_slice(&whitespace_bomb)
            .unwrap_err()
            .code(),
        SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape
    );
    let escape_bomb = format!(r#"{{"schema_version":"{}"}}"#, r"\u0061".repeat(2_000));
    assert!(escape_bomb.len() > AUTHORIZATION_INGRESS_BUDGET.bytes);
    assert_eq!(
        SecretCredentialAuthorizationV2::from_json_slice(escape_bomb.as_bytes())
            .unwrap_err()
            .code(),
        SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape
    );
}

fn maximum_authorization_value(index: usize) -> Value {
    let controls = [
        "alternate_mount_egress",
        "child_inheritance",
        "child_process_egress",
        "core_dump",
        "destination_network_egress",
        "filesystem_sink_egress",
        "generic_cache",
        "trusted_injection_boundary",
    ];
    json!({
        "schema_version": SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V2,
        "driver_operation": {
            "driver": "d".repeat(128),
            "operation": "o".repeat(128),
            "schema_version": crate::DRIVER_OPERATION_SCHEMA_V1,
        },
        "driver_declaration_revision": MAX_SAFE_INTEGER,
        "credential_slot_id": format!("018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f{:04x}", index + 1),
        "destination_schema": format!("{}.v1", "d".repeat(125)),
        "delivery_exposure_profile": "trusted_injection",
        "trusted_send_profile": {
            "kind": "trusted_injection",
            "max_credential_bearing_sends": 8,
            "applicable_delivery_controls": controls,
        },
        "approved_destination_digests": (0..16)
            .map(|digest_index| digest(u8::try_from(digest_index).unwrap()).to_string())
            .collect::<Vec<_>>(),
    })
}

fn maximum_ref_value() -> Value {
    json!({
        "schema_version": SECRET_REF_SCHEMA_V2,
        "secret_ref_id": "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f6001",
        "secret_ref_revision": MAX_SAFE_INTEGER,
        "tenant_id": "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f6002",
        "secret_provider_id": "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f6003",
        "provider_namespace": "n".repeat(128),
        "logical_name": "l".repeat(128),
        "provider_version_ref": "v".repeat(128),
        "classification": "opaque_secret",
        "allowed_credential_bindings": (0..16).map(maximum_authorization_value).collect::<Vec<_>>(),
        "allowed_delivery_methods": [
            "tmpfs_file",
            "environment_variable",
            "orchestrator_projected_secret",
            "inherited_fd",
            "one_shot_local_socket",
        ],
        "lease_policy": {
            "max_lease_duration_seconds": MAX_SAFE_INTEGER,
            "max_continuous_lifetime_seconds": MAX_SAFE_INTEGER,
            "max_uses": MAX_SAFE_INTEGER,
            "renewable": true,
            "clock_skew_tolerance_seconds": 30,
        },
        "offline_behavior": "continue_existing_until_expiry",
        "created_at": "9999-12-31T23:59:59.999998Z",
        "disabled_at": "9999-12-31T23:59:59.999999Z",
    })
}

#[test]
fn independently_generated_legal_maxima_fit_every_budget_and_round_trip_canonically() {
    assert!(!MAXIMUM_AUTHORIZATION_FIXTURE.ends_with(b"\n"));
    assert!(!MAXIMUM_REF_FIXTURE.ends_with(b"\n"));
    let authorization_wire = serde_json::to_vec(&maximum_authorization_value(0)).unwrap();
    let authorization_stats =
        preflight_json(&authorization_wire, AUTHORIZATION_INGRESS_BUDGET).unwrap();
    assert_eq!(
        authorization_stats,
        IngressStats {
            depth: 3,
            tokens: 58,
            members: 14,
            elements: 24,
        }
    );
    let authorization =
        SecretCredentialAuthorizationV2::from_json_slice(&authorization_wire).unwrap();
    let authorization_canonical = serde_json::to_vec(&authorization).unwrap();
    assert_eq!(authorization_canonical.len(), 2_237);
    assert_eq!(
        blake3::hash(&authorization_canonical).to_hex().as_str(),
        "6576988eddba3e8368783447a58ae48739a5c67779019aac247a2cd03ef5f49d"
    );
    assert_eq!(authorization_canonical, MAXIMUM_AUTHORIZATION_FIXTURE);
    assert_eq!(
        SecretCredentialAuthorizationV2::from_json_slice(MAXIMUM_AUTHORIZATION_FIXTURE).unwrap(),
        authorization
    );

    let ref_wire = serde_json::to_vec(&maximum_ref_value()).unwrap();
    let ref_stats = preflight_json(&ref_wire, REF_INGRESS_BUDGET).unwrap();
    assert_eq!(
        ref_stats,
        IngressStats {
            depth: 5,
            tokens: 978,
            members: 244,
            elements: 405,
        }
    );
    let parsed_ref = SecretRefV2::from_json_slice(&ref_wire).unwrap();
    let ref_canonical = serde_json::to_vec(&parsed_ref).unwrap();
    assert_eq!(ref_canonical.len(), 37_041);
    assert_eq!(
        blake3::hash(&ref_canonical).to_hex().as_str(),
        "af2f77f6e7b0f87c2ba845a095b3ef391934409d21da485e041c18bfc8625f19"
    );
    assert_eq!(ref_canonical, MAXIMUM_REF_FIXTURE);
    assert_eq!(
        SecretRefV2::from_json_slice(MAXIMUM_REF_FIXTURE).unwrap(),
        parsed_ref
    );
}

#[test]
fn pure_comparison_matches_and_returns_all_eight_first_mismatches() {
    let authorization = authorization();
    let base_sink = sink(
        authorization.credential_slot_id(),
        vec![SecretClassification::AuthenticationCredential],
        vec![SecretUseIntent::Authenticate],
        authorization.destination_schema(),
        SecretDeliveryExposureProfile::TrustedInjection,
        trusted_profile(1),
    );
    let matching = declaration(
        operation("example_driver", "example_operation"),
        7,
        vec![base_sink],
    );
    assert_eq!(
        compare_secret_credential_authorization_v2(
            &authorization,
            &SecretClassification::AuthenticationCredential,
            &SecretUseIntent::Authenticate,
            &matching,
        ),
        SecretCredentialDeclarationComparisonV2::Matched
    );

    let other_slot: SecretCredentialSlotId =
        "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4002".parse().unwrap();
    let cases = [
        (
            declaration(
                operation("other_driver", "example_operation"),
                7,
                vec![sink(
                    authorization.credential_slot_id(),
                    vec![SecretClassification::AuthenticationCredential],
                    vec![SecretUseIntent::Authenticate],
                    authorization.destination_schema(),
                    SecretDeliveryExposureProfile::TrustedInjection,
                    trusted_profile(1),
                )],
            ),
            SecretClassification::AuthenticationCredential,
            SecretUseIntent::Authenticate,
            SecretCredentialDeclarationMismatchCodeV2::DriverOperationMismatch,
        ),
        (
            declaration(
                operation("example_driver", "example_operation"),
                8,
                vec![sink(
                    authorization.credential_slot_id(),
                    vec![SecretClassification::AuthenticationCredential],
                    vec![SecretUseIntent::Authenticate],
                    authorization.destination_schema(),
                    SecretDeliveryExposureProfile::TrustedInjection,
                    trusted_profile(1),
                )],
            ),
            SecretClassification::AuthenticationCredential,
            SecretUseIntent::Authenticate,
            SecretCredentialDeclarationMismatchCodeV2::DriverDeclarationRevisionMismatch,
        ),
        (
            declaration(
                operation("example_driver", "example_operation"),
                7,
                vec![sink(
                    other_slot,
                    vec![SecretClassification::AuthenticationCredential],
                    vec![SecretUseIntent::Authenticate],
                    authorization.destination_schema(),
                    SecretDeliveryExposureProfile::TrustedInjection,
                    trusted_profile(1),
                )],
            ),
            SecretClassification::AuthenticationCredential,
            SecretUseIntent::Authenticate,
            SecretCredentialDeclarationMismatchCodeV2::CredentialSlotNotDeclared,
        ),
        (
            declaration(
                operation("example_driver", "example_operation"),
                7,
                vec![sink(
                    authorization.credential_slot_id(),
                    vec![SecretClassification::AuthenticationCredential],
                    vec![SecretUseIntent::Authenticate],
                    "example.driver.other_destination.v1",
                    SecretDeliveryExposureProfile::TrustedInjection,
                    trusted_profile(1),
                )],
            ),
            SecretClassification::AuthenticationCredential,
            SecretUseIntent::Authenticate,
            SecretCredentialDeclarationMismatchCodeV2::DestinationSchemaMismatch,
        ),
        (
            declaration(
                operation("example_driver", "example_operation"),
                7,
                vec![sink(
                    authorization.credential_slot_id(),
                    vec![SecretClassification::AuthenticationCredential],
                    vec![SecretUseIntent::Authenticate],
                    authorization.destination_schema(),
                    SecretDeliveryExposureProfile::MaterialExposed,
                    DriverTrustedSendProfileV1::not_applicable(),
                )],
            ),
            SecretClassification::AuthenticationCredential,
            SecretUseIntent::Authenticate,
            SecretCredentialDeclarationMismatchCodeV2::DeliveryExposureProfileMismatch,
        ),
        (
            declaration(
                operation("example_driver", "example_operation"),
                7,
                vec![sink(
                    authorization.credential_slot_id(),
                    vec![SecretClassification::AuthenticationCredential],
                    vec![SecretUseIntent::Authenticate],
                    authorization.destination_schema(),
                    SecretDeliveryExposureProfile::TrustedInjection,
                    trusted_profile(2),
                )],
            ),
            SecretClassification::AuthenticationCredential,
            SecretUseIntent::Authenticate,
            SecretCredentialDeclarationMismatchCodeV2::TrustedSendProfileMismatch,
        ),
        (
            declaration(
                operation("example_driver", "example_operation"),
                7,
                vec![sink(
                    authorization.credential_slot_id(),
                    vec![SecretClassification::SigningMaterial],
                    vec![SecretUseIntent::Authenticate],
                    authorization.destination_schema(),
                    SecretDeliveryExposureProfile::TrustedInjection,
                    trusted_profile(1),
                )],
            ),
            SecretClassification::AuthenticationCredential,
            SecretUseIntent::Authenticate,
            SecretCredentialDeclarationMismatchCodeV2::SecretClassificationNotAllowed,
        ),
        (
            declaration(
                operation("example_driver", "example_operation"),
                7,
                vec![sink(
                    authorization.credential_slot_id(),
                    vec![SecretClassification::AuthenticationCredential],
                    vec![SecretUseIntent::Sign],
                    authorization.destination_schema(),
                    SecretDeliveryExposureProfile::TrustedInjection,
                    trusted_profile(1),
                )],
            ),
            SecretClassification::AuthenticationCredential,
            SecretUseIntent::Authenticate,
            SecretCredentialDeclarationMismatchCodeV2::SecretUseIntentNotAllowed,
        ),
    ];
    for (declaration, classification, intent, expected) in cases {
        let result = compare_secret_credential_authorization_v2(
            &authorization,
            &classification,
            &intent,
            &declaration,
        );
        assert_eq!(
            result,
            SecretCredentialDeclarationComparisonV2::Denied(expected)
        );
        assert_eq!(result.to_string(), expected.as_str());
        assert_eq!(format!("{result:?}"), expected.as_str());
        assert_eq!(format!("{expected:?}"), expected.as_str());
    }
    assert_eq!(
        SecretCredentialDeclarationComparisonV2::Matched.to_string(),
        "matched"
    );
    assert_eq!(
        format!("{:?}", SecretCredentialDeclarationComparisonV2::Matched),
        "matched"
    );
}

#[test]
fn historical_v1_is_deterministic_digest_bound_ordinal_stable_and_live_denied() {
    let historical =
        HistoricalSecretRefV1::from_json_slice(fixture_bytes(HISTORICAL_FIXTURE)).unwrap();
    assert_eq!(
        serde_json::to_vec(&historical).unwrap(),
        fixture_bytes(HISTORICAL_FIXTURE)
    );
    assert_eq!(
        historical.canonical_bytes(),
        fixture_bytes(HISTORICAL_FIXTURE)
    );
    assert_eq!(historical.credential_authorizations().len(), 1);
    let entry = &historical.credential_authorizations()[0];
    assert_eq!(historical.schema_version(), HISTORICAL_SECRET_REF_SCHEMA_V1);
    assert_eq!(
        historical.secret_ref_id().to_string(),
        "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5001"
    );
    assert_eq!(historical.secret_ref_revision(), 1);
    assert_eq!(
        historical.tenant_id().to_string(),
        "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5002"
    );
    assert_eq!(
        historical.secret_provider_id().to_string(),
        "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5003"
    );
    assert_eq!(historical.provider_namespace(), "example");
    assert_eq!(historical.logical_name(), "billing_api");
    assert_eq!(historical.provider_version_ref().as_str(), "release-007");
    assert_eq!(
        historical.classification(),
        SecretClassification::AuthenticationCredential
    );
    assert_eq!(
        historical.allowed_delivery_methods(),
        [SecretDeliveryMethod::InheritedFd]
    );
    assert_eq!(historical.lease_policy().max_lease_duration_seconds(), 300);
    assert_eq!(historical.offline_behavior(), SecretOfflineBehavior::Deny);
    assert_eq!(historical.created_at(), "2026-07-19T00:00:00.000000Z");
    assert_eq!(historical.disabled_at(), None);
    assert_eq!(
        entry.schema_version(),
        HISTORICAL_SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V1
    );
    assert_eq!(
        entry.driver_operation(),
        &operation("example_driver", "example_operation")
    );
    assert_eq!(
        entry.credential_slot_id().to_string(),
        "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001"
    );
    assert_eq!(
        entry.destination_schema(),
        "example.driver.https_destination.v1"
    );
    assert_eq!(
        entry.delivery_exposure_profile(),
        SecretDeliveryExposureProfile::TrustedInjection
    );
    assert_eq!(entry.trusted_send_profile(), &trusted_profile(1));
    assert_eq!(
        entry.approved_destination_digests()[0].to_string(),
        "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    assert_eq!(entry.source_entry_ordinal(), 0);
    assert_eq!(
        serde_json::to_vec(entry).unwrap(),
        entry.canonical_entry_bytes()
    );
    assert_eq!(
        entry.source_entry_digest(),
        "blake3:325869750e5aff11fb8e1d4d521cafb1e82f77388df41c21aafea83121b91bd3"
    );
    assert_eq!(
        historical.source_ref_digest(),
        "blake3:f44ff11756463a95e3d19276288df817e027cd43f47805ddcae8c3d53fed95ff"
    );
    assert_eq!(
        historical.live_denial(),
        HistoricalSecretRefV1LiveDenial::HistoricalRevisionlessAuthorizationLiveDenied
    );
    assert_eq!(
        historical.live_denial().to_string(),
        "historical_revisionless_authorization_live_denied"
    );
    assert_eq!(
        format!("{:?}", historical.live_denial()),
        "historical_revisionless_authorization_live_denied"
    );
    assert_eq!(format!("{historical:?}"), "historical_secret_ref_v1");
    assert_eq!(
        format!("{entry:?}"),
        "historical_secret_credential_authorization_v1"
    );

    let mut first_input: Value = serde_json::from_slice(fixture_bytes(HISTORICAL_FIXTURE)).unwrap();
    let first_entry = first_input["allowed_credential_bindings"][0].clone();
    let mut second_entry = first_entry.clone();
    second_entry["credential_slot_id"] = json!("018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4002");
    second_entry["approved_destination_digests"] = json!([digest(2).to_string()]);
    first_input["allowed_credential_bindings"] = json!([second_entry.clone(), first_entry.clone()]);
    let mut second_input = first_input.clone();
    second_input["allowed_credential_bindings"] = json!([first_entry, second_entry]);
    let first =
        HistoricalSecretRefV1::from_json_slice(&serde_json::to_vec(&first_input).unwrap()).unwrap();
    let second =
        HistoricalSecretRefV1::from_json_slice(&serde_json::to_vec(&second_input).unwrap())
            .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.source_ref_digest(), second.source_ref_digest());
    assert_eq!(
        first
            .credential_authorizations()
            .iter()
            .map(HistoricalSecretCredentialAuthorizationV1::source_entry_ordinal)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );

    let mut disabled_input: Value =
        serde_json::from_slice(fixture_bytes(HISTORICAL_FIXTURE)).unwrap();
    disabled_input["disabled_at"] = json!("2026-07-19T00:00:00.000001Z");
    let disabled =
        HistoricalSecretRefV1::from_json_slice(&serde_json::to_vec(&disabled_input).unwrap())
            .unwrap();
    assert_eq!(disabled.disabled_at(), Some("2026-07-19T00:00:00.000001Z"));
}

#[test]
fn historical_v1_rejects_every_non_frozen_or_duplicate_shape_without_reflection() {
    for mutate in [
        ("schema_version", json!("splendor.secret.ref.v2")),
        ("secret_ref_revision", json!(0)),
        ("tenant_id", json!("PRIVATE_TENANT_CANARY")),
        ("allowed_credential_bindings", json!([])),
        ("allowed_delivery_methods", json!(["environment_variable"])),
        ("created_at", json!("PRIVATE_TIME_CANARY")),
    ] {
        let mut candidate: Value =
            serde_json::from_slice(fixture_bytes(HISTORICAL_FIXTURE)).unwrap();
        candidate[mutate.0] = mutate.1;
        let error =
            HistoricalSecretRefV1::from_json_slice(&serde_json::to_vec(&candidate).unwrap())
                .unwrap_err();
        assert_eq!(
            error,
            HistoricalSecretRefV1Error::InvalidHistoricalSecretRef
        );
        assert_eq!(error.to_string(), "invalid_historical_secret_ref");
        assert_eq!(format!("{error:?}"), "invalid_historical_secret_ref");
        assert!(std::error::Error::source(&error).is_none());
        assert!(!error.to_string().contains("PRIVATE"));
    }

    for field in [
        "schema_version",
        "secret_ref_id",
        "secret_ref_revision",
        "tenant_id",
        "secret_provider_id",
        "provider_namespace",
        "logical_name",
        "provider_version_ref",
        "classification",
        "allowed_credential_bindings",
        "allowed_delivery_methods",
        "lease_policy",
        "offline_behavior",
        "created_at",
        "disabled_at",
    ] {
        let mut candidate: Value =
            serde_json::from_slice(fixture_bytes(HISTORICAL_FIXTURE)).unwrap();
        candidate[field] = Value::Null;
        assert_eq!(
            HistoricalSecretRefV1::from_json_slice(&serde_json::to_vec(&candidate).unwrap())
                .unwrap_err(),
            HistoricalSecretRefV1Error::InvalidHistoricalSecretRef,
            "field {field}"
        );
    }

    for field in [
        "schema_version",
        "driver_operation",
        "credential_slot_id",
        "destination_schema",
        "delivery_exposure_profile",
        "trusted_send_profile",
        "approved_destination_digests",
    ] {
        let mut candidate: Value =
            serde_json::from_slice(fixture_bytes(HISTORICAL_FIXTURE)).unwrap();
        candidate["allowed_credential_bindings"][0][field] = Value::Null;
        assert_eq!(
            HistoricalSecretRefV1::from_json_slice(&serde_json::to_vec(&candidate).unwrap())
                .unwrap_err(),
            HistoricalSecretRefV1Error::InvalidHistoricalSecretRef,
            "nested field {field}"
        );
    }

    let mut unknown: Value = serde_json::from_slice(fixture_bytes(HISTORICAL_FIXTURE)).unwrap();
    unknown["PRIVATE_HISTORICAL_CANARY"] = json!(true);
    assert_eq!(
        HistoricalSecretRefV1::from_json_slice(&serde_json::to_vec(&unknown).unwrap()).unwrap_err(),
        HistoricalSecretRefV1Error::InvalidHistoricalSecretRef
    );

    let mut revision_smuggling: Value =
        serde_json::from_slice(fixture_bytes(HISTORICAL_FIXTURE)).unwrap();
    revision_smuggling["allowed_credential_bindings"][0]["driver_declaration_revision"] = json!(7);
    assert_eq!(
        HistoricalSecretRefV1::from_json_slice(&serde_json::to_vec(&revision_smuggling).unwrap())
            .unwrap_err(),
        HistoricalSecretRefV1Error::InvalidHistoricalSecretRef
    );

    let mut duplicate: Value = serde_json::from_slice(fixture_bytes(HISTORICAL_FIXTURE)).unwrap();
    let entry = duplicate["allowed_credential_bindings"][0].clone();
    let mut same_coordinate = entry.clone();
    same_coordinate["approved_destination_digests"] = json!([digest(2).to_string()]);
    duplicate["allowed_credential_bindings"] = json!([entry, same_coordinate]);
    assert_eq!(
        HistoricalSecretRefV1::from_json_slice(&serde_json::to_vec(&duplicate).unwrap())
            .unwrap_err(),
        HistoricalSecretRefV1Error::InvalidHistoricalSecretRef
    );
}

#[test]
fn secret_ref_wire_grammar_remains_delegated_to_owner_codecs() {
    // Rust visibility enforces that these seams stay crate-private. This narrow
    // source guard additionally prevents the containing C03 parser from quietly
    // reintroducing Driver/C03 wire vocabularies beside those owner seams.
    let source = include_str!("../../src/secret_ref.rs");
    for required_owner_seam in [
        "DriverOperationRefWireV1",
        "DriverTrustedSendProfileWireV1",
        "is_driver_destination_schema_v1",
        ".matches_exposure(",
        "SecretClassification::from_wire_spelling",
        "SecretDeliveryExposureProfile::from_wire_spelling",
        "SecretOfflineBehavior::from_wire_spelling",
        "SecretDeliveryMethod::from_wire_spelling",
    ] {
        assert!(
            source.contains(required_owner_seam),
            "secret_ref.rs must consume the owner codec/spelling seam `{required_owner_seam}`"
        );
    }

    for copied_owner_grammar in [
        "struct DriverOperationWire",
        "struct TrustedSendProfileWire",
        "fn is_destination_schema",
        "fn profile_matches_exposure",
        "fn parse_delivery_control",
        "\"driver\" =>",
        "\"operation\" =>",
        "\"applicable_delivery_controls\" =>",
        "\"max_credential_bearing_sends\" =>",
        "\"trusted_injection\"",
        "\"not_applicable\"",
        "\"authentication_credential\"",
        "\"signing_material\"",
        "\"encryption_material\"",
        "\"private_configuration\"",
        "\"opaque_secret\"",
        "\"continue_existing_until_expiry\"",
        "\"inherited_fd\"",
        "\"tmpfs_file\"",
        "\"one_shot_local_socket\"",
        "\"orchestrator_projected_secret\"",
        "\"environment_variable\"",
        "\"trusted_injection_boundary\"",
        "\"destination_network_egress\"",
    ] {
        assert!(
            !source.contains(copied_owner_grammar),
            "secret_ref.rs copied owner wire grammar `{copied_owner_grammar}`; reuse driver.rs/secrets.rs instead"
        );
    }
}
