use super::*;
use crate::{
    SecretClassification, SecretDeliveryControlKind, SecretDeliveryExposureProfile, SecretUseIntent,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::error::Error;
use uuid::Uuid;

const SLOT_1: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001";
const SLOT_2: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4002";
const CANONICAL_DECLARATION: &str = r#"{"credential_sinks":[{"allowed_classifications":["authentication_credential"],"allowed_intents":["authenticate"],"credential_slot_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001","delivery_exposure_profile":"trusted_injection","destination_schema":"example.driver.https_destination.v1","trusted_send_profile":{"applicable_delivery_controls":["destination_network_egress","trusted_injection_boundary"],"kind":"trusted_injection","max_credential_bearing_sends":1}},{"allowed_classifications":["signing_material"],"allowed_intents":["sign"],"credential_slot_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4002","delivery_exposure_profile":"material_exposed","destination_schema":"example.driver.signing_destination.v1","trusted_send_profile":{"kind":"not_applicable"}}],"driver_declaration_revision":1,"driver_operation":{"driver":"example_driver","operation":"example_operation","schema_version":"splendor.driver.operation.v1"},"schema_version":"splendor.driver.operation_credential_sinks.v1"}"#;

fn operation() -> DriverOperationRef {
    DriverOperationRef {
        driver: "example_driver".to_owned(),
        operation: "example_operation".to_owned(),
        schema_version: DRIVER_OPERATION_SCHEMA_V1.to_owned(),
    }
}

fn trusted_profile() -> DriverTrustedSendProfileV1 {
    DriverTrustedSendProfileV1::try_trusted_injection(
        1,
        vec![
            SecretDeliveryControlKind::TrustedInjectionBoundary,
            SecretDeliveryControlKind::DestinationNetworkEgress,
        ],
    )
    .expect("trusted profile")
}

fn trusted_sink() -> DriverOperationCredentialSinkV1 {
    DriverOperationCredentialSinkV1::try_new(
        SLOT_1.parse().expect("slot"),
        vec![SecretClassification::AuthenticationCredential],
        vec![SecretUseIntent::Authenticate],
        "example.driver.https_destination.v1",
        SecretDeliveryExposureProfile::TrustedInjection,
        trusted_profile(),
    )
    .expect("trusted sink")
}

fn exposed_sink() -> DriverOperationCredentialSinkV1 {
    DriverOperationCredentialSinkV1::try_new(
        SLOT_2.parse().expect("slot"),
        vec![SecretClassification::SigningMaterial],
        vec![SecretUseIntent::Sign],
        "example.driver.signing_destination.v1",
        SecretDeliveryExposureProfile::MaterialExposed,
        DriverTrustedSendProfileV1::not_applicable(),
    )
    .expect("exposed sink")
}

fn assert_fixed_string_deserializer<T>(valid: &str, expected: T)
where
    T: DeserializeOwned + PartialEq + std::fmt::Debug,
{
    assert_eq!(serde_json::from_str::<T>(valid).expect("valid"), expected);
}

fn assert_all_non_string_deserializers_reject<T>(expected: &str)
where
    T: DeserializeOwned + std::fmt::Debug,
{
    use serde::de::value::{
        BoolDeserializer, BorrowedBytesDeserializer, BytesDeserializer, CharDeserializer,
        Error as ValueError, F64Deserializer, I128Deserializer, I64Deserializer, MapDeserializer,
        SeqDeserializer, U128Deserializer, U64Deserializer, UnitDeserializer,
    };

    fn assert_fixed<T, E>(result: Result<T, E>, expected: &str)
    where
        T: std::fmt::Debug,
        E: std::fmt::Display,
    {
        assert_eq!(
            result.expect_err("non-string form must reject").to_string(),
            expected
        );
    }

    assert_fixed(
        T::deserialize(BoolDeserializer::<ValueError>::new(true)),
        expected,
    );
    assert_fixed(
        T::deserialize(I64Deserializer::<ValueError>::new(-1)),
        expected,
    );
    assert_fixed(
        T::deserialize(U64Deserializer::<ValueError>::new(1)),
        expected,
    );
    assert_fixed(
        T::deserialize(I128Deserializer::<ValueError>::new(i128::MIN)),
        expected,
    );
    assert_fixed(
        T::deserialize(U128Deserializer::<ValueError>::new(u128::MAX)),
        expected,
    );
    assert_fixed(
        T::deserialize(F64Deserializer::<ValueError>::new(1.5)),
        expected,
    );
    assert_fixed(
        T::deserialize(CharDeserializer::<ValueError>::new('x')),
        expected,
    );
    assert_fixed(
        T::deserialize(UnitDeserializer::<ValueError>::new()),
        expected,
    );
    assert_fixed(
        T::deserialize(SeqDeserializer::<_, ValueError>::new(
            Vec::<u8>::new().into_iter(),
        )),
        expected,
    );
    assert_fixed(
        T::deserialize(MapDeserializer::<_, ValueError>::new(
            Vec::<(String, String)>::new().into_iter(),
        )),
        expected,
    );
    assert_fixed(
        T::deserialize(BorrowedBytesDeserializer::<ValueError>::new(b"private")),
        expected,
    );
    assert_fixed(
        T::deserialize(BytesDeserializer::<ValueError>::new(b"private")),
        expected,
    );
}

#[test]
fn operation_validator_is_strict_without_changing_standalone_serde() {
    validate_driver_operation_ref_v1(&operation()).expect("canonical operation");
    for bad in [
        DriverOperationRef {
            driver: "Example".to_owned(),
            ..operation()
        },
        DriverOperationRef {
            operation: "*".to_owned(),
            ..operation()
        },
        DriverOperationRef {
            schema_version: "legacy.driver.operation.v0".to_owned(),
            ..operation()
        },
    ] {
        let error = validate_driver_operation_ref_v1(&bad).expect_err("must reject");
        assert_eq!(error.to_string(), INVALID_OPERATION);
        assert_eq!(format!("{error:?}"), INVALID_OPERATION);
        assert!(error.source().is_none());
    }

    let historical =
        r#"{"driver":"Example","operation":"*","schema_version":"legacy.driver.operation.v0"}"#;
    let standalone: DriverOperationRef =
        serde_json::from_str(historical).expect("standalone compatibility remains permissive");
    assert_eq!(serde_json::to_string(&standalone).unwrap(), historical);
}

#[test]
fn slot_id_is_nominal_canonical_non_nil_and_non_reflecting() {
    let slot: SecretCredentialSlotId = SLOT_1.parse().expect("canonical slot");
    assert_eq!(slot.to_string(), SLOT_1);
    assert_eq!(format!("{slot:?}"), SLOT_1);
    assert_eq!(
        serde_json::to_string(&slot).unwrap(),
        format!("\"{SLOT_1}\"")
    );
    assert_fixed_string_deserializer(&format!("\"{SLOT_1}\""), slot);
    assert_eq!(
        SecretCredentialSlotId::deserialize(serde::de::value::StringDeserializer::<
            serde::de::value::Error,
        >::new(SLOT_1.to_owned(),),)
        .expect("owned slot string"),
        slot
    );
    assert_eq!(
        SecretCredentialSlotId::try_from(slot.as_uuid()).unwrap(),
        slot
    );
    assert!(slot < SLOT_2.parse().unwrap());

    for invalid in [
        SLOT_1.to_ascii_uppercase(),
        SLOT_1.replace('-', ""),
        format!("{{{SLOT_1}}}"),
        format!("urn:uuid:{SLOT_1}"),
        format!(" {SLOT_1}"),
        "PRIVATE_SLOT_SENTINEL".to_owned(),
    ] {
        let error = invalid
            .parse::<SecretCredentialSlotId>()
            .expect_err("invalid form");
        assert_eq!(error.to_string(), INVALID_SLOT);
        assert!(!error.to_string().contains(&invalid));
    }
    assert_eq!(
        SecretCredentialSlotId::try_from(Uuid::nil()).unwrap_err(),
        SecretCredentialSlotIdError::Nil
    );
    assert_eq!(
        SecretCredentialSlotIdError::Nil.to_string(),
        "nil_secret_credential_slot_id"
    );
    for invalid_json in ["null", "true", "1", "[]", "{}"] {
        let error = serde_json::from_str::<SecretCredentialSlotId>(invalid_json)
            .expect_err("non-string rejects")
            .to_string();
        assert!(error.starts_with(INVALID_SLOT));
        assert!(error.len() <= 120);
    }
    let char_error = SecretCredentialSlotId::deserialize(serde::de::value::CharDeserializer::<
        serde::de::value::Error,
    >::new('x'))
    .unwrap_err()
    .to_string();
    assert_eq!(char_error, INVALID_SLOT);
    assert_all_non_string_deserializers_reject::<SecretCredentialSlotId>(INVALID_SLOT);
}

#[test]
fn destination_digest_is_exact_and_golden_is_independent() {
    let schema = "example.driver.https_destination.v1";
    let projection =
        br#"{"account":"acct_001","origin":"https://api.example.test:443","service":"billing"}"#;
    let mut domain = Vec::new();
    domain.extend_from_slice(schema.as_bytes());
    domain.push(0);
    domain.extend_from_slice(projection);
    let expected = format!("blake3:{}", blake3::hash(&domain).to_hex());
    assert_eq!(
        expected,
        "blake3:1497bbb0f248532c3d621c641ef0687986120982e07d7d8c96908d74a1af4540"
    );
    let digest: DriverCredentialDestinationDigest = expected.parse().expect("digest");
    assert_eq!(expected.len(), 71);
    assert_eq!(digest.to_string(), expected);
    assert_eq!(format!("{digest:?}"), expected);
    assert_eq!(
        serde_json::to_string(&digest).unwrap(),
        format!("\"{expected}\"")
    );
    assert_eq!(
        serde_json::from_str::<DriverCredentialDestinationDigest>(&format!("\"{expected}\""))
            .unwrap(),
        digest
    );
    assert_eq!(
        DriverCredentialDestinationDigest::deserialize(serde::de::value::StringDeserializer::<
            serde::de::value::Error,
        >::new(expected.clone()),)
        .expect("owned digest string"),
        digest
    );
    assert_eq!(digest.as_bytes(), blake3::hash(&domain).as_bytes());
    let mut changed_schema_domain = b"example.driver.changed_destination.v1\0".to_vec();
    changed_schema_domain.extend_from_slice(projection);
    assert_ne!(
        blake3::hash(&changed_schema_domain).as_bytes(),
        digest.as_bytes()
    );
    let mut changed_projection_domain = schema.as_bytes().to_vec();
    changed_projection_domain.push(0);
    changed_projection_domain.extend_from_slice(
        br#"{"account":"acct_002","origin":"https://api.example.test:443","service":"billing"}"#,
    );
    assert_ne!(
        blake3::hash(&changed_projection_domain).as_bytes(),
        digest.as_bytes()
    );

    for invalid in [
        expected.to_ascii_uppercase(),
        expected.trim_start_matches("blake3:").to_owned(),
        expected.replacen("blake3:", "sha256:", 1),
        format!("{expected}0"),
        "PRIVATE_DIGEST_SENTINEL".to_owned(),
    ] {
        let error = invalid
            .parse::<DriverCredentialDestinationDigest>()
            .expect_err("invalid digest");
        assert_eq!(error.to_string(), INVALID_DIGEST);
        assert!(!error.to_string().contains(&invalid));
    }
    assert_all_non_string_deserializers_reject::<DriverCredentialDestinationDigest>(INVALID_DIGEST);
}

#[test]
fn contract_errors_are_exact_code_only_values() {
    let codes = [
        DriverCredentialSinkContractErrorCode::InvalidContractShape,
        DriverCredentialSinkContractErrorCode::InvalidSchemaVersion,
        DriverCredentialSinkContractErrorCode::InvalidDriverOperation,
        DriverCredentialSinkContractErrorCode::InvalidDeclarationRevision,
        DriverCredentialSinkContractErrorCode::InvalidCredentialSlot,
        DriverCredentialSinkContractErrorCode::EmptyCredentialSinks,
        DriverCredentialSinkContractErrorCode::TooManyCredentialSinks,
        DriverCredentialSinkContractErrorCode::DuplicateCredentialSlot,
        DriverCredentialSinkContractErrorCode::InvalidClassificationSet,
        DriverCredentialSinkContractErrorCode::InvalidIntentSet,
        DriverCredentialSinkContractErrorCode::InvalidDestinationSchema,
        DriverCredentialSinkContractErrorCode::MissingTrustedSendProfile,
        DriverCredentialSinkContractErrorCode::ExposureProfileMismatch,
        DriverCredentialSinkContractErrorCode::InvalidSendLimit,
        DriverCredentialSinkContractErrorCode::InvalidControlSet,
        DriverCredentialSinkContractErrorCode::TrustedInjectionBoundaryRequired,
        DriverCredentialSinkContractErrorCode::NotApplicablePayloadForbidden,
        DriverCredentialSinkContractErrorCode::InvalidDestinationProjection,
        DriverCredentialSinkContractErrorCode::DestinationDigestMismatch,
    ];
    assert_eq!(codes.len(), 19);
    for code in codes {
        assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{code}\""));
        let error = DriverCredentialSinkContractError::new(code);
        assert_eq!(error.to_string(), code.as_str());
        assert_eq!(format!("{error:?}"), code.as_str());
        assert_eq!(
            serde_json::to_string(&error).unwrap(),
            format!(r#"{{"code":"{code}"}}"#)
        );
        assert!(error.source().is_none());
    }
}

#[test]
fn checked_profiles_and_sinks_enforce_bounds_and_normalize_sets() {
    assert_eq!(trusted_profile().kind(), "trusted_injection");
    assert_eq!(trusted_profile().max_credential_bearing_sends(), Some(1));
    assert_eq!(
        DriverTrustedSendProfileV1::not_applicable().kind(),
        "not_applicable"
    );
    assert_eq!(
        DriverTrustedSendProfileV1::not_applicable().max_credential_bearing_sends(),
        None
    );
    assert!(DriverTrustedSendProfileV1::not_applicable()
        .applicable_delivery_controls()
        .is_empty());
    for limit in [0, 9] {
        assert_eq!(
            DriverTrustedSendProfileV1::try_trusted_injection(
                limit,
                vec![SecretDeliveryControlKind::TrustedInjectionBoundary]
            )
            .unwrap_err()
            .code(),
            DriverCredentialSinkContractErrorCode::InvalidSendLimit
        );
    }
    assert_eq!(
        DriverTrustedSendProfileV1::try_trusted_injection(
            1,
            vec![SecretDeliveryControlKind::CoreDump]
        )
        .unwrap_err()
        .code(),
        DriverCredentialSinkContractErrorCode::TrustedInjectionBoundaryRequired
    );
    assert_eq!(
        DriverTrustedSendProfileV1::try_trusted_injection(
            1,
            vec![
                SecretDeliveryControlKind::TrustedInjectionBoundary,
                SecretDeliveryControlKind::TrustedInjectionBoundary,
            ]
        )
        .unwrap_err()
        .code(),
        DriverCredentialSinkContractErrorCode::InvalidControlSet
    );
    let control_inventory = [
        SecretDeliveryControlKind::TrustedInjectionBoundary,
        SecretDeliveryControlKind::PtraceDebug,
        SecretDeliveryControlKind::ProxyEgress,
        SecretDeliveryControlKind::OutputCapture,
        SecretDeliveryControlKind::IpcEgress,
        SecretDeliveryControlKind::GenericCache,
        SecretDeliveryControlKind::CoreDump,
        SecretDeliveryControlKind::ChildInheritance,
    ];
    let mut maximum_profile = None;
    for limit in 1_u8..=8 {
        let profile = DriverTrustedSendProfileV1::try_trusted_injection(
            limit,
            control_inventory[..usize::from(limit)].to_vec(),
        )
        .expect("every accepted send limit and control count");
        assert_eq!(profile.max_credential_bearing_sends(), Some(limit));
        assert_eq!(
            profile.applicable_delivery_controls().len(),
            usize::from(limit)
        );
        if limit == 8 {
            maximum_profile = Some(profile);
        }
    }
    let maximum_profile = maximum_profile.expect("eight-control profile");
    assert_eq!(maximum_profile.applicable_delivery_controls().len(), 8);
    assert_eq!(
        serde_json::to_string(&maximum_profile).unwrap(),
        r#"{"applicable_delivery_controls":["child_inheritance","core_dump","generic_cache","ipc_egress","output_capture","proxy_egress","ptrace_debug","trusted_injection_boundary"],"kind":"trusted_injection","max_credential_bearing_sends":8}"#
    );

    assert_eq!(
        DriverOperationCredentialSinkV1::try_new(
            SLOT_1.parse().unwrap(),
            vec![],
            vec![SecretUseIntent::Authenticate],
            "example.driver.destination.v1",
            SecretDeliveryExposureProfile::TrustedInjection,
            trusted_profile(),
        )
        .unwrap_err()
        .code(),
        DriverCredentialSinkContractErrorCode::InvalidClassificationSet
    );
    assert_eq!(
        DriverOperationCredentialSinkV1::try_new(
            SLOT_1.parse().unwrap(),
            vec![SecretClassification::AuthenticationCredential],
            vec![],
            "example.driver.destination.v1",
            SecretDeliveryExposureProfile::TrustedInjection,
            trusted_profile(),
        )
        .unwrap_err()
        .code(),
        DriverCredentialSinkContractErrorCode::InvalidIntentSet
    );

    let sink = DriverOperationCredentialSinkV1::try_new(
        SLOT_1.parse().unwrap(),
        vec![
            SecretClassification::SigningMaterial,
            SecretClassification::AuthenticationCredential,
        ],
        vec![SecretUseIntent::Sign, SecretUseIntent::Authenticate],
        "example.driver.destination.v1",
        SecretDeliveryExposureProfile::TrustedInjection,
        trusted_profile(),
    )
    .unwrap();
    assert_eq!(
        sink.allowed_classifications(),
        &[
            SecretClassification::AuthenticationCredential,
            SecretClassification::SigningMaterial
        ]
    );
    assert_eq!(
        sink.allowed_intents(),
        &[SecretUseIntent::Authenticate, SecretUseIntent::Sign]
    );
    assert_eq!(sink.destination_schema(), "example.driver.destination.v1");
    assert_eq!(
        sink.delivery_exposure_profile(),
        SecretDeliveryExposureProfile::TrustedInjection
    );
    assert_eq!(sink.trusted_send_profile().kind(), "trusted_injection");

    assert_eq!(
        DriverOperationCredentialSinkV1::try_new(
            SLOT_1.parse().unwrap(),
            vec![SecretClassification::AuthenticationCredential],
            vec![SecretUseIntent::Authenticate],
            "network",
            SecretDeliveryExposureProfile::TrustedInjection,
            trusted_profile(),
        )
        .unwrap_err()
        .code(),
        DriverCredentialSinkContractErrorCode::InvalidDestinationSchema
    );
    assert_eq!(
        DriverOperationCredentialSinkV1::try_new(
            SLOT_1.parse().unwrap(),
            vec![SecretClassification::AuthenticationCredential],
            vec![SecretUseIntent::Authenticate],
            "example.driver.destination.v1",
            SecretDeliveryExposureProfile::MaterialExposed,
            trusted_profile(),
        )
        .unwrap_err()
        .code(),
        DriverCredentialSinkContractErrorCode::ExposureProfileMismatch
    );
}

#[test]
fn declaration_serialization_is_the_pinned_canonical_example() {
    let declaration = DriverOperationCredentialSinksV1::try_new(
        operation(),
        1,
        vec![exposed_sink(), trusted_sink()],
    )
    .expect("declaration");
    assert_eq!(
        declaration.schema_version(),
        DRIVER_OPERATION_CREDENTIAL_SINKS_SCHEMA_V1
    );
    assert_eq!(declaration.driver_operation(), &operation());
    assert_eq!(declaration.driver_declaration_revision(), 1);
    assert_eq!(declaration.credential_sinks().len(), 2);
    assert_eq!(
        declaration.credential_sinks()[0]
            .credential_slot_id()
            .to_string(),
        SLOT_1
    );
    let actual = serde_json::to_string(&declaration).unwrap();
    assert_eq!(actual, CANONICAL_DECLARATION);
    assert_eq!(actual.len(), 975);
}

#[test]
fn declaration_constructor_rejects_operation_revision_count_and_duplicate_slots() {
    assert_eq!(
        DriverOperationCredentialSinksV1::try_new(
            DriverOperationRef {
                schema_version: "legacy".to_owned(),
                ..operation()
            },
            1,
            vec![trusted_sink()]
        )
        .unwrap_err()
        .code(),
        DriverCredentialSinkContractErrorCode::InvalidDriverOperation
    );
    for revision in [0, 9_007_199_254_740_992] {
        assert_eq!(
            DriverOperationCredentialSinksV1::try_new(operation(), revision, vec![trusted_sink()])
                .unwrap_err()
                .code(),
            DriverCredentialSinkContractErrorCode::InvalidDeclarationRevision
        );
    }
    assert_eq!(
        DriverOperationCredentialSinksV1::try_new(operation(), 1, vec![])
            .unwrap_err()
            .code(),
        DriverCredentialSinkContractErrorCode::EmptyCredentialSinks
    );
    assert_eq!(
        DriverOperationCredentialSinksV1::try_new(
            operation(),
            1,
            vec![trusted_sink(), trusted_sink()]
        )
        .unwrap_err()
        .code(),
        DriverCredentialSinkContractErrorCode::DuplicateCredentialSlot
    );
    let too_many = (1_u128..=17)
        .map(|slot| {
            DriverOperationCredentialSinkV1::try_new(
                SecretCredentialSlotId::try_from(Uuid::from_u128(slot)).unwrap(),
                vec![SecretClassification::AuthenticationCredential],
                vec![SecretUseIntent::Authenticate],
                "example.driver.destination.v1",
                SecretDeliveryExposureProfile::TrustedInjection,
                trusted_profile(),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        DriverOperationCredentialSinksV1::try_new(operation(), 1, too_many)
            .unwrap_err()
            .code(),
        DriverCredentialSinkContractErrorCode::TooManyCredentialSinks
    );
}

#[test]
fn lexical_and_typed_maximum_boundaries_are_exact() {
    let max_name_operation = DriverOperationRef {
        driver: "a".repeat(128),
        operation: "a".repeat(128),
        schema_version: DRIVER_OPERATION_SCHEMA_V1.to_owned(),
    };
    validate_driver_operation_ref_v1(&max_name_operation).expect("128-byte names");
    for invalid_name in ["a".repeat(129), "A".repeat(128), "é".to_owned()] {
        let invalid = DriverOperationRef {
            driver: invalid_name,
            ..operation()
        };
        assert_eq!(
            validate_driver_operation_ref_v1(&invalid).unwrap_err(),
            DriverOperationRefV1ValidationError::Invalid
        );
    }

    let maximum = maximum_declaration();
    assert_eq!(maximum.driver_declaration_revision(), 9_007_199_254_740_991);
    assert_eq!(maximum.credential_sinks().len(), 16);
    assert_eq!(maximum.driver_operation().driver.len(), 128);
    for sink in maximum.credential_sinks() {
        assert_eq!(sink.allowed_classifications().len(), 5);
        assert_eq!(sink.allowed_intents().len(), 6);
        assert_eq!(sink.destination_schema().len(), 128);
        assert_eq!(
            sink.trusted_send_profile()
                .applicable_delivery_controls()
                .len(),
            8
        );
    }

    assert_eq!(
        DriverOperationCredentialSinkV1::try_new(
            SLOT_1.parse().unwrap(),
            vec![SecretClassification::AuthenticationCredential],
            vec![SecretUseIntent::Authenticate],
            format!("{}.v1", "a".repeat(126)),
            SecretDeliveryExposureProfile::TrustedInjection,
            trusted_profile(),
        )
        .unwrap_err()
        .code(),
        DriverCredentialSinkContractErrorCode::InvalidDestinationSchema
    );
}

fn fixture_value() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../fixtures/driver/operation-credential-sinks-v1.json"
    ))
    .expect("driver fixture")
}

fn parse_value(
    value: &serde_json::Value,
) -> Result<DriverOperationCredentialSinksV1, DriverCredentialSinkContractError> {
    DriverOperationCredentialSinksV1::from_json_slice(
        &serde_json::to_vec(value).expect("fixture value serializes"),
    )
}

fn assert_value_error(value: &serde_json::Value, expected: DriverCredentialSinkContractErrorCode) {
    let error = parse_value(value).expect_err("value must reject");
    assert_eq!(error.code(), expected);
    assert_eq!(error.to_string(), expected.as_str());
    assert_eq!(format!("{error:?}"), expected.as_str());
    assert!(error.source().is_none());
    assert_eq!(
        serde_json::to_string(&error).unwrap(),
        format!(r#"{{"code":"{}"}}"#, expected.as_str())
    );
}

#[test]
fn bounded_ingress_round_trips_fixture_to_canonical_bytes() {
    let fixture = include_bytes!("../fixtures/driver/operation-credential-sinks-v1.json");
    assert_eq!(fixture.len(), 975);
    assert_eq!(fixture.as_slice(), CANONICAL_DECLARATION.as_bytes());
    let declaration = DriverOperationCredentialSinksV1::from_json_slice(fixture)
        .expect("strict fixture must parse");
    assert_eq!(
        serde_json::to_string(&declaration).unwrap(),
        CANONICAL_DECLARATION
    );
    assert_eq!(
        DriverOperationCredentialSinksV1::from_json_slice(CANONICAL_DECLARATION.as_bytes())
            .unwrap(),
        declaration
    );
}

#[test]
fn ingress_top_level_precedence_and_operation_shape_are_exact() {
    for raw in [
        b"null".as_slice(),
        b"[]".as_slice(),
        b"{".as_slice(),
        br#"{"schema_version":"x","schema_version":"y"}"#,
        &[0xff],
    ] {
        assert_eq!(
            DriverOperationCredentialSinksV1::from_json_slice(raw)
                .expect_err("shape must reject")
                .code(),
            DriverCredentialSinkContractErrorCode::InvalidContractShape
        );
    }

    let mut value = fixture_value();
    value["unknown"] = serde_json::json!("PRIVATE_UNKNOWN_SENTINEL");
    value["schema_version"] = serde_json::json!(null);
    assert_value_error(
        &value,
        DriverCredentialSinkContractErrorCode::InvalidContractShape,
    );

    for schema in [
        serde_json::Value::Null,
        serde_json::json!(1),
        serde_json::json!("wrong"),
    ] {
        let mut value = fixture_value();
        value["schema_version"] = schema;
        value["driver_operation"] = serde_json::Value::Null;
        assert_value_error(
            &value,
            DriverCredentialSinkContractErrorCode::InvalidSchemaVersion,
        );
    }
    let mut missing_schema = fixture_value();
    missing_schema
        .as_object_mut()
        .unwrap()
        .remove("schema_version");
    assert_value_error(
        &missing_schema,
        DriverCredentialSinkContractErrorCode::InvalidSchemaVersion,
    );

    for operation_value in [
        serde_json::Value::Null,
        serde_json::json!("driver"),
        serde_json::json!(true),
        serde_json::json!(-1),
        serde_json::json!(1),
        serde_json::json!(1.5),
        serde_json::json!([]),
        serde_json::json!({"driver":"example_driver","operation":"example_operation"}),
        serde_json::json!({"driver":"Example","operation":"example_operation","schema_version":DRIVER_OPERATION_SCHEMA_V1}),
        serde_json::json!({"driver":"example_driver","operation":"*","schema_version":DRIVER_OPERATION_SCHEMA_V1}),
        serde_json::json!({"driver":"example_driver","operation":"example_operation","schema_version":DRIVER_OPERATION_SCHEMA_V1,"side":"field"}),
    ] {
        let mut value = fixture_value();
        value["driver_operation"] = operation_value;
        value["driver_declaration_revision"] = serde_json::json!(0);
        assert_value_error(
            &value,
            DriverCredentialSinkContractErrorCode::InvalidDriverOperation,
        );
    }
}

#[test]
fn ingress_revision_and_sink_count_codes_are_exact() {
    for revision in [
        serde_json::Value::Null,
        serde_json::json!("1"),
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(1.0),
        serde_json::json!(9_007_199_254_740_992_u64),
    ] {
        let mut value = fixture_value();
        value["driver_declaration_revision"] = revision;
        value["credential_sinks"] = serde_json::Value::Null;
        assert_value_error(
            &value,
            DriverCredentialSinkContractErrorCode::InvalidDeclarationRevision,
        );
    }
    let mut missing = fixture_value();
    missing
        .as_object_mut()
        .unwrap()
        .remove("driver_declaration_revision");
    assert_value_error(
        &missing,
        DriverCredentialSinkContractErrorCode::InvalidDeclarationRevision,
    );

    for sinks in [serde_json::Value::Null, serde_json::json!({})] {
        let mut value = fixture_value();
        value["credential_sinks"] = sinks;
        assert_value_error(
            &value,
            DriverCredentialSinkContractErrorCode::InvalidContractShape,
        );
    }
    let mut missing_sinks = fixture_value();
    missing_sinks
        .as_object_mut()
        .unwrap()
        .remove("credential_sinks");
    assert_value_error(
        &missing_sinks,
        DriverCredentialSinkContractErrorCode::InvalidContractShape,
    );
    let mut empty = fixture_value();
    empty["credential_sinks"] = serde_json::json!([]);
    assert_value_error(
        &empty,
        DriverCredentialSinkContractErrorCode::EmptyCredentialSinks,
    );
    let mut too_many = fixture_value();
    let sink = too_many["credential_sinks"][0].clone();
    too_many["credential_sinks"] = serde_json::Value::Array(vec![sink; 17]);
    assert_value_error(
        &too_many,
        DriverCredentialSinkContractErrorCode::TooManyCredentialSinks,
    );
}

#[test]
fn ingress_sink_field_precedence_and_set_denials_are_exact() {
    let mut non_object_sink = fixture_value();
    non_object_sink["credential_sinks"][0] = serde_json::Value::Null;
    assert_value_error(
        &non_object_sink,
        DriverCredentialSinkContractErrorCode::InvalidContractShape,
    );

    let mut invalid_slot = fixture_value();
    invalid_slot["credential_sinks"][0]["credential_slot_id"] =
        serde_json::json!(SLOT_1.to_ascii_uppercase());
    assert_value_error(
        &invalid_slot,
        DriverCredentialSinkContractErrorCode::InvalidCredentialSlot,
    );

    let cases = [
        (
            "credential_slot_id",
            DriverCredentialSinkContractErrorCode::InvalidCredentialSlot,
        ),
        (
            "allowed_classifications",
            DriverCredentialSinkContractErrorCode::InvalidClassificationSet,
        ),
        (
            "allowed_intents",
            DriverCredentialSinkContractErrorCode::InvalidIntentSet,
        ),
        (
            "destination_schema",
            DriverCredentialSinkContractErrorCode::InvalidDestinationSchema,
        ),
    ];
    for (field, code) in cases {
        for replacement in [serde_json::Value::Null, serde_json::json!({})] {
            let mut value = fixture_value();
            value["credential_sinks"][0][field] = replacement;
            assert_value_error(&value, code);
        }
        let mut missing = fixture_value();
        missing["credential_sinks"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert_value_error(&missing, code);
    }

    let mut unknown = fixture_value();
    unknown["credential_sinks"][0]["credential"] = serde_json::json!("PRIVATE_SECRET");
    unknown["credential_sinks"][0]["credential_slot_id"] = serde_json::Value::Null;
    assert_value_error(
        &unknown,
        DriverCredentialSinkContractErrorCode::InvalidContractShape,
    );

    for classifications in [
        serde_json::json!([]),
        serde_json::json!(["authentication_credential", "authentication_credential"]),
        serde_json::json!(["unknown"]),
        serde_json::json!([
            "authentication_credential",
            "signing_material",
            "encryption_material",
            "private_configuration",
            "opaque_secret",
            "authentication_credential"
        ]),
    ] {
        let mut value = fixture_value();
        value["credential_sinks"][0]["allowed_classifications"] = classifications;
        assert_value_error(
            &value,
            DriverCredentialSinkContractErrorCode::InvalidClassificationSet,
        );
    }
    for intents in [
        serde_json::json!([]),
        serde_json::json!(["authenticate", "authenticate"]),
        serde_json::json!(["unknown"]),
        serde_json::json!([
            "authenticate",
            "sign",
            "encrypt",
            "decrypt",
            "derive_session",
            "bootstrap_transport",
            "authenticate"
        ]),
    ] {
        let mut value = fixture_value();
        value["credential_sinks"][0]["allowed_intents"] = intents;
        assert_value_error(
            &value,
            DriverCredentialSinkContractErrorCode::InvalidIntentSet,
        );
    }
    for destination in [
        "network",
        "Example.destination.v1",
        "example.!destination.v1",
        "example.destination.v0",
        "example.destination",
        "",
    ] {
        let mut value = fixture_value();
        value["credential_sinks"][0]["destination_schema"] = serde_json::json!(destination);
        assert_value_error(
            &value,
            DriverCredentialSinkContractErrorCode::InvalidDestinationSchema,
        );
    }
}

#[test]
fn ingress_profile_precedence_and_denials_are_exact() {
    let mut non_object_profile = fixture_value();
    non_object_profile["credential_sinks"][0]["trusted_send_profile"] =
        serde_json::json!("trusted_injection");
    assert_value_error(
        &non_object_profile,
        DriverCredentialSinkContractErrorCode::ExposureProfileMismatch,
    );

    for missing_or_null in [true, false] {
        let mut value = fixture_value();
        if missing_or_null {
            value["credential_sinks"][0]
                .as_object_mut()
                .unwrap()
                .remove("trusted_send_profile");
        } else {
            value["credential_sinks"][0]["trusted_send_profile"] = serde_json::Value::Null;
        }
        value["credential_sinks"][0]["delivery_exposure_profile"] = serde_json::json!("wrong");
        assert_value_error(
            &value,
            DriverCredentialSinkContractErrorCode::MissingTrustedSendProfile,
        );
    }
    for (exposure, profile) in [
        (
            serde_json::Value::Null,
            serde_json::json!({"kind":"trusted_injection"}),
        ),
        (
            serde_json::json!("wrong"),
            serde_json::json!({"kind":"trusted_injection"}),
        ),
        (
            serde_json::json!("trusted_injection"),
            serde_json::json!({}),
        ),
        (
            serde_json::json!("trusted_injection"),
            serde_json::json!({"kind":"not_applicable"}),
        ),
        (
            serde_json::json!("material_exposed"),
            serde_json::json!({"kind":"trusted_injection"}),
        ),
    ] {
        let mut value = fixture_value();
        value["credential_sinks"][0]["delivery_exposure_profile"] = exposure;
        value["credential_sinks"][0]["trusted_send_profile"] = profile;
        assert_value_error(
            &value,
            DriverCredentialSinkContractErrorCode::ExposureProfileMismatch,
        );
    }

    let mut extra = fixture_value();
    extra["credential_sinks"][0]["trusted_send_profile"]["extra"] = serde_json::json!(true);
    extra["credential_sinks"][0]["trusted_send_profile"]["max_credential_bearing_sends"] =
        serde_json::json!(0);
    assert_value_error(
        &extra,
        DriverCredentialSinkContractErrorCode::InvalidContractShape,
    );
    for limit in [
        serde_json::Value::Null,
        serde_json::json!("1"),
        serde_json::json!(0),
        serde_json::json!(9),
    ] {
        let mut value = fixture_value();
        value["credential_sinks"][0]["trusted_send_profile"]["max_credential_bearing_sends"] =
            limit;
        value["credential_sinks"][0]["trusted_send_profile"]
            .as_object_mut()
            .unwrap()
            .remove("applicable_delivery_controls");
        assert_value_error(
            &value,
            DriverCredentialSinkContractErrorCode::InvalidSendLimit,
        );
    }
    for controls in [
        serde_json::Value::Null,
        serde_json::json!([]),
        serde_json::json!(["unknown"]),
        serde_json::json!(["trusted_injection_boundary", "trusted_injection_boundary"]),
        serde_json::json!([
            "core_dump",
            "ptrace_debug",
            "child_inheritance",
            "output_capture",
            "swap_page_dump",
            "generic_cache",
            "orchestrator_projection",
            "trusted_injection_boundary",
            "ipc_egress"
        ]),
    ] {
        let mut value = fixture_value();
        value["credential_sinks"][0]["trusted_send_profile"]["applicable_delivery_controls"] =
            controls;
        assert_value_error(
            &value,
            DriverCredentialSinkContractErrorCode::InvalidControlSet,
        );
    }
    let mut no_boundary = fixture_value();
    no_boundary["credential_sinks"][0]["trusted_send_profile"]["applicable_delivery_controls"] =
        serde_json::json!(["destination_network_egress"]);
    assert_value_error(
        &no_boundary,
        DriverCredentialSinkContractErrorCode::TrustedInjectionBoundaryRequired,
    );
    let mut not_applicable_payload = fixture_value();
    not_applicable_payload["credential_sinks"][1]["trusted_send_profile"]["payload"] =
        serde_json::json!("PRIVATE_PAYLOAD");
    assert_value_error(
        &not_applicable_payload,
        DriverCredentialSinkContractErrorCode::NotApplicablePayloadForbidden,
    );
}

#[test]
fn ingress_duplicate_slot_is_checked_after_entry_validation_and_sets_canonicalize() {
    let mut duplicate = fixture_value();
    duplicate["credential_sinks"][1]["credential_slot_id"] = serde_json::json!(SLOT_1);
    duplicate["credential_sinks"][1]["allowed_classifications"] = serde_json::json!([]);
    assert_value_error(
        &duplicate,
        DriverCredentialSinkContractErrorCode::InvalidClassificationSet,
    );
    duplicate["credential_sinks"][1]["allowed_classifications"] =
        serde_json::json!(["signing_material"]);
    assert_value_error(
        &duplicate,
        DriverCredentialSinkContractErrorCode::DuplicateCredentialSlot,
    );

    let mut permuted = fixture_value();
    permuted["credential_sinks"]
        .as_array_mut()
        .unwrap()
        .reverse();
    permuted["credential_sinks"][1]["trusted_send_profile"]["applicable_delivery_controls"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let parsed = parse_value(&permuted).unwrap();
    assert_eq!(
        serde_json::to_string(&parsed).unwrap(),
        CANONICAL_DECLARATION
    );
}

fn nested_arrays(depth: usize) -> serde_json::Value {
    let mut value = serde_json::Value::Null;
    for _ in 0..depth {
        value = serde_json::Value::Array(vec![value]);
    }
    value
}

fn token_limit_value(plus_one: bool) -> serde_json::Value {
    let mut values = Vec::with_capacity(192);
    for index in 0..192 {
        let value = match index {
            0 => nested_empty_arrays(29),
            1 => nested_empty_arrays(2),
            2 if plus_one => serde_json::json!([null]),
            _ => serde_json::json!([]),
        };
        values.push(serde_json::json!({"a": value}));
    }
    serde_json::Value::Array(values)
}

fn nested_empty_arrays(extra_wrappers: usize) -> serde_json::Value {
    let mut value = serde_json::json!([]);
    for _ in 0..extra_wrappers {
        value = serde_json::Value::Array(vec![value]);
    }
    value
}

#[test]
fn preflight_enforces_each_exact_resource_ceiling() {
    assert_eq!(
        preflight_declaration(&serde_json::to_vec(&nested_arrays(32)).unwrap())
            .unwrap()
            .depth,
        32
    );
    assert!(preflight_declaration(&serde_json::to_vec(&nested_arrays(33)).unwrap()).is_err());

    let exact_tokens = serde_json::to_vec(&token_limit_value(false)).unwrap();
    assert_eq!(preflight_declaration(&exact_tokens).unwrap().tokens, 1_024);
    let too_many_tokens = serde_json::to_vec(&token_limit_value(true)).unwrap();
    assert!(preflight_declaration(&too_many_tokens).is_err());

    let exact_members = serde_json::Value::Object(
        (0..192)
            .map(|index| (format!("m{index}"), serde_json::Value::Null))
            .collect(),
    );
    assert_eq!(
        preflight_declaration(&serde_json::to_vec(&exact_members).unwrap())
            .unwrap()
            .members,
        192
    );
    let too_many_members = serde_json::Value::Object(
        (0..193)
            .map(|index| (format!("m{index}"), serde_json::Value::Null))
            .collect(),
    );
    assert!(preflight_declaration(&serde_json::to_vec(&too_many_members).unwrap()).is_err());

    let exact_elements = serde_json::json!(vec![serde_json::Value::Null; 384]);
    assert_eq!(
        preflight_declaration(&serde_json::to_vec(&exact_elements).unwrap())
            .unwrap()
            .elements,
        384
    );
    let too_many_elements = serde_json::json!(vec![serde_json::Value::Null; 385]);
    assert!(preflight_declaration(&serde_json::to_vec(&too_many_elements).unwrap()).is_err());

    assert!(preflight_declaration(&serde_json::to_vec(&"a".repeat(256)).unwrap()).is_ok());
    assert!(preflight_declaration(&serde_json::to_vec(&"a".repeat(257)).unwrap()).is_err());
    let exact_name = serde_json::Value::Object(
        [("a".repeat(256), serde_json::Value::Null)]
            .into_iter()
            .collect(),
    );
    assert!(preflight_declaration(&serde_json::to_vec(&exact_name).unwrap()).is_ok());
    let too_long_name = serde_json::Value::Object(
        [("a".repeat(257), serde_json::Value::Null)]
            .into_iter()
            .collect(),
    );
    assert!(preflight_declaration(&serde_json::to_vec(&too_long_name).unwrap()).is_err());
    let exact_escaped = format!("\"{}\"", "\\u0061".repeat(256));
    assert!(preflight_declaration(exact_escaped.as_bytes()).is_ok());
    let too_many_escaped = format!("\"{}\"", "\\u0061".repeat(257));
    assert!(preflight_declaration(too_many_escaped.as_bytes()).is_err());
    for malformed in [
        br#""\uD800""#.as_slice(),
        br#""\x41""#.as_slice(),
        b"1e9999".as_slice(),
        b"99999999999999999999999999999999999999999999999999".as_slice(),
    ] {
        assert!(preflight_declaration(malformed).is_err());
    }

    let mut exact_body = CANONICAL_DECLARATION.as_bytes().to_vec();
    exact_body.resize(32_768, b' ');
    DriverOperationCredentialSinksV1::from_json_slice(&exact_body).expect("32 KiB body");
    exact_body.push(b' ');
    assert_eq!(
        DriverOperationCredentialSinksV1::from_json_slice(&exact_body)
            .unwrap_err()
            .code(),
        DriverCredentialSinkContractErrorCode::InvalidContractShape
    );
}

#[test]
fn preflight_rejects_duplicate_names_and_never_reflects_canaries() {
    let raw = br#"{"schema_version":"splendor.driver.operation_credential_sinks.v1","driver_operation":{"driver":"PRIVATE_DRIVER_SENTINEL","driver":"other","operation":"x","schema_version":"splendor.driver.operation.v1"},"driver_declaration_revision":1,"credential_sinks":[]}"#;
    let error = DriverOperationCredentialSinksV1::from_json_slice(raw).unwrap_err();
    assert_eq!(
        error.code(),
        DriverCredentialSinkContractErrorCode::InvalidContractShape
    );
    let visible = format!(
        "{error} {error:?} {}",
        serde_json::to_string(&error).unwrap()
    );
    assert!(!visible.contains("PRIVATE_DRIVER_SENTINEL"));
    assert!(!visible.contains("other"));
    assert!(error.source().is_none());
}

fn maximum_declaration() -> DriverOperationCredentialSinksV1 {
    let classifications = vec![
        SecretClassification::AuthenticationCredential,
        SecretClassification::SigningMaterial,
        SecretClassification::EncryptionMaterial,
        SecretClassification::PrivateConfiguration,
        SecretClassification::OpaqueSecret,
    ];
    let intents = vec![
        SecretUseIntent::Authenticate,
        SecretUseIntent::Sign,
        SecretUseIntent::Encrypt,
        SecretUseIntent::Decrypt,
        SecretUseIntent::DeriveSession,
        SecretUseIntent::BootstrapTransport,
    ];
    let controls = vec![
        SecretDeliveryControlKind::ChildInheritance,
        SecretDeliveryControlKind::OrchestratorProjection,
        SecretDeliveryControlKind::TrustedInjectionBoundary,
        SecretDeliveryControlKind::DestinationNetworkEgress,
        SecretDeliveryControlKind::FilesystemSinkEgress,
        SecretDeliveryControlKind::ChildProcessEgress,
        SecretDeliveryControlKind::AlternateMountEgress,
        SecretDeliveryControlKind::SwapPageDump,
    ];
    let destination_schema = format!("{}.v1", "a".repeat(125));
    let sinks = (1_u128..=16)
        .map(|slot| {
            DriverOperationCredentialSinkV1::try_new(
                SecretCredentialSlotId::try_from(Uuid::from_u128(slot)).unwrap(),
                classifications.clone(),
                intents.clone(),
                destination_schema.clone(),
                SecretDeliveryExposureProfile::TrustedInjection,
                DriverTrustedSendProfileV1::try_trusted_injection(8, controls.clone()).unwrap(),
            )
            .unwrap()
        })
        .collect();
    DriverOperationCredentialSinksV1::try_new(
        DriverOperationRef {
            driver: "a".repeat(128),
            operation: "a".repeat(128),
            schema_version: DRIVER_OPERATION_SCHEMA_V1.to_owned(),
        },
        9_007_199_254_740_991,
        sinks,
    )
    .unwrap()
}

#[test]
fn legal_maximum_fixture_pins_all_independent_counts() {
    let bytes = serde_json::to_vec(&maximum_declaration()).unwrap();
    let stats = preflight_declaration(&bytes).unwrap();
    assert_eq!(bytes.len(), 13_478);
    assert_eq!(stats.depth, 5);
    assert_eq!(stats.tokens, 706);
    assert_eq!(stats.members, 151);
    assert_eq!(stats.elements, 320);
    let parsed = DriverOperationCredentialSinksV1::from_json_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&parsed).unwrap(), bytes);
}
