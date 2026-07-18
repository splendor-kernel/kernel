use super::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};
use std::io::{self, Read};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../fixtures/secrets/v1a/preplacement-primitives.json"
    ))
    .expect("pre-placement primitive fixture must be valid JSON")
}

fn assert_closed_enum<T>(expected: &[(T, &str)])
where
    T: Copy + DeserializeOwned + Ord + PartialEq + Serialize + std::fmt::Debug,
{
    for (variant, spelling) in expected {
        let encoded = serde_json::to_string(variant).expect("enum must serialize");
        assert_eq!(encoded, format!("\"{spelling}\""));
        assert_eq!(
            serde_json::from_str::<T>(&encoded).expect("exact enum value must deserialize"),
            *variant
        );

        let case_changed = format!("\"{}\"", spelling.to_ascii_uppercase());
        let case_error = serde_json::from_str::<T>(&case_changed)
            .expect_err("case-changed enum value must reject")
            .to_string();
        assert!(case_error.starts_with(CLOSED_SECRET_ENUM_ERROR));
        assert!(!case_error.contains(&spelling.to_ascii_uppercase()));

        let tagged_object = format!(r#"{{"{spelling}":null}}"#);
        let tagged_error = serde_json::from_str::<T>(&tagged_object)
            .expect_err("externally tagged enum object must reject")
            .to_string();
        assert!(
            tagged_error.starts_with(CLOSED_SECRET_ENUM_ERROR),
            "unexpected tagged-object error: {tagged_error}"
        );
        assert!(
            !tagged_error.contains(spelling),
            "tagged-object error must not reflect: {spelling}"
        );
    }

    const SENSITIVE_SENTINEL: &str = "PRIVATE_ENUM_SENTINEL_DO_NOT_REFLECT";
    for invalid in [
        format!("\"{SENSITIVE_SENTINEL}\""),
        "null".to_owned(),
        "true".to_owned(),
        "987654321".to_owned(),
        "17.5".to_owned(),
        format!(r#"{{"{SENSITIVE_SENTINEL}":null}}"#),
        format!(r#"["{SENSITIVE_SENTINEL}"]"#),
    ] {
        let error = serde_json::from_str::<T>(&invalid)
            .expect_err("unknown or non-string enum form must reject")
            .to_string();
        assert!(error.starts_with(CLOSED_SECRET_ENUM_ERROR));
        assert!(error.len() <= 120, "enum errors must remain bounded");
        assert!(!error.contains(SENSITIVE_SENTINEL));
    }

    let mut ordered_variants = expected
        .iter()
        .map(|(variant, _)| *variant)
        .collect::<Vec<_>>();
    ordered_variants.sort();
    let ordered_spellings = ordered_variants
        .iter()
        .map(|variant| {
            serde_json::to_value(variant)
                .expect("ordered enum must serialize")
                .as_str()
                .expect("ordered enum must serialize as a string")
                .to_owned()
        })
        .collect::<Vec<_>>();
    let mut expected_ascii_order = expected
        .iter()
        .map(|(_, spelling)| (*spelling).to_owned())
        .collect::<Vec<_>>();
    expected_ascii_order.sort();
    assert_eq!(ordered_spellings, expected_ascii_order);
}

#[test]
fn closed_secret_enums_have_exact_v1_wire_values() {
    assert_closed_enum(&[
        (
            SecretClassification::AuthenticationCredential,
            "authentication_credential",
        ),
        (SecretClassification::SigningMaterial, "signing_material"),
        (
            SecretClassification::EncryptionMaterial,
            "encryption_material",
        ),
        (
            SecretClassification::PrivateConfiguration,
            "private_configuration",
        ),
        (SecretClassification::OpaqueSecret, "opaque_secret"),
    ]);
    assert_closed_enum(&[
        (SecretDeliveryMethod::InheritedFd, "inherited_fd"),
        (SecretDeliveryMethod::TmpfsFile, "tmpfs_file"),
        (
            SecretDeliveryMethod::OneShotLocalSocket,
            "one_shot_local_socket",
        ),
        (
            SecretDeliveryMethod::OrchestratorProjectedSecret,
            "orchestrator_projected_secret",
        ),
        (
            SecretDeliveryMethod::EnvironmentVariable,
            "environment_variable",
        ),
    ]);
    assert_closed_enum(&[
        (SecretUseIntent::Authenticate, "authenticate"),
        (SecretUseIntent::Sign, "sign"),
        (SecretUseIntent::Encrypt, "encrypt"),
        (SecretUseIntent::Decrypt, "decrypt"),
        (SecretUseIntent::DeriveSession, "derive_session"),
        (SecretUseIntent::BootstrapTransport, "bootstrap_transport"),
    ]);
    assert_closed_enum(&[
        (
            SecretPurpose::ExternalServiceAccess,
            "external_service_access",
        ),
        (SecretPurpose::DataSourceAccess, "data_source_access"),
        (SecretPurpose::ArtifactStoreAccess, "artifact_store_access"),
        (SecretPurpose::ModelProviderAccess, "model_provider_access"),
        (SecretPurpose::OrchestratorAccess, "orchestrator_access"),
        (SecretPurpose::DeviceServiceAccess, "device_service_access"),
        (
            SecretPurpose::CryptographicOperation,
            "cryptographic_operation",
        ),
    ]);
    assert_closed_enum(&[
        (SecretOfflineBehavior::Deny, "deny"),
        (
            SecretOfflineBehavior::ContinueExistingUntilExpiry,
            "continue_existing_until_expiry",
        ),
    ]);
    assert_closed_enum(&[
        (
            SecretDeliveryExposureProfile::TrustedInjection,
            "trusted_injection",
        ),
        (
            SecretDeliveryExposureProfile::MaterialExposed,
            "material_exposed",
        ),
    ]);

    assert_eq!(
        serde_json::to_string(&SecretDeliveryMethod::EnvironmentVariable)
            .expect("compatibility vocabulary serializes"),
        "\"environment_variable\""
    );
}

#[test]
fn enum_fixture_pins_the_exact_closed_inventories() {
    let fixture = fixture();
    let enums = fixture["enums"]
        .as_object()
        .expect("fixture enums must be an object");
    let expected_names = [
        "SecretClassification",
        "SecretDeliveryExposureProfile",
        "SecretDeliveryMethod",
        "SecretOfflineBehavior",
        "SecretPurpose",
        "SecretUseIntent",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(
        enums.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        expected_names
    );

    let expected_lengths = [
        ("SecretClassification", 5),
        ("SecretDeliveryMethod", 5),
        ("SecretUseIntent", 6),
        ("SecretPurpose", 7),
        ("SecretOfflineBehavior", 2),
        ("SecretDeliveryExposureProfile", 2),
    ];
    for (name, length) in expected_lengths {
        assert_eq!(
            enums[name]
                .as_array()
                .expect("enum inventory must be an array")
                .len(),
            length
        );
    }
    assert_eq!(
        enums["SecretClassification"],
        json!([
            "authentication_credential",
            "signing_material",
            "encryption_material",
            "private_configuration",
            "opaque_secret"
        ])
    );
    assert_eq!(
        enums["SecretDeliveryMethod"],
        json!([
            "inherited_fd",
            "tmpfs_file",
            "one_shot_local_socket",
            "orchestrator_projected_secret",
            "environment_variable"
        ])
    );
    assert_eq!(
        enums["SecretUseIntent"],
        json!([
            "authenticate",
            "sign",
            "encrypt",
            "decrypt",
            "derive_session",
            "bootstrap_transport"
        ])
    );
    assert_eq!(
        enums["SecretPurpose"],
        json!([
            "external_service_access",
            "data_source_access",
            "artifact_store_access",
            "model_provider_access",
            "orchestrator_access",
            "device_service_access",
            "cryptographic_operation"
        ])
    );
    assert_eq!(
        enums["SecretOfflineBehavior"],
        json!(["deny", "continue_existing_until_expiry"])
    );
    assert_eq!(
        enums["SecretDeliveryExposureProfile"],
        json!(["trusted_injection", "material_exposed"])
    );
}

#[test]
fn provider_version_ref_accepts_only_bounded_opaque_non_locator_text() {
    let fixture = fixture();
    let minimum = fixture["version_ref"]["minimum"]
        .as_str()
        .expect("minimum fixture text");
    let maximum = fixture["version_ref"]["maximum"]
        .as_str()
        .expect("maximum fixture text");
    assert_eq!(minimum.len(), 1);
    assert_eq!(maximum.len(), 128);

    let minimum_ref = SecretProviderVersionRef::try_new(minimum).expect("minimum must validate");
    let maximum_ref: SecretProviderVersionRef = maximum.parse().expect("maximum must validate");
    assert_eq!(minimum_ref.as_str(), minimum);
    assert_eq!(minimum_ref.to_string(), minimum);
    assert_eq!(maximum_ref.as_str(), maximum);
    assert_eq!(
        SecretProviderVersionRef::try_from(maximum.to_owned()).expect("TryFrom must validate"),
        maximum_ref
    );
    assert_eq!(
        serde_json::from_str::<SecretProviderVersionRef>(
            &serde_json::to_string(&maximum_ref).expect("serialize maximum")
        )
        .expect("strict string round trip"),
        maximum_ref
    );

    let ordered_first = SecretProviderVersionRef::try_new("release-001").expect("valid ref");
    let ordered_second = SecretProviderVersionRef::try_new("release-002").expect("valid ref");
    assert!(ordered_first < ordered_second);
    let mut unique = HashSet::new();
    unique.insert(ordered_first.clone());
    unique.insert(ordered_first);
    assert_eq!(unique.len(), 1);

    assert_eq!(
        SecretProviderVersionRef::try_new(""),
        Err(SecretProviderVersionRefError::Empty)
    );
    assert_eq!(
        SecretProviderVersionRef::try_new("x".repeat(129)),
        Err(SecretProviderVersionRefError::TooLong { max_bytes: 128 })
    );

    for byte in 0_u8..=0x20 {
        let candidate = String::from_utf8(vec![byte]).expect("ASCII control byte");
        assert_eq!(
            SecretProviderVersionRef::try_new(candidate),
            Err(SecretProviderVersionRefError::NonPrintableAscii)
        );
    }
    assert_eq!(
        SecretProviderVersionRef::try_new(String::from("\u{7f}")),
        Err(SecretProviderVersionRefError::NonPrintableAscii)
    );
    for candidate in ["révision", "版本", "release💠"] {
        assert_eq!(
            SecretProviderVersionRef::try_new(candidate),
            Err(SecretProviderVersionRefError::NonPrintableAscii)
        );
    }
    for delimiter in ['/', '\\', '?', '#', ':'] {
        let candidate = format!("release{delimiter}001");
        assert_eq!(
            SecretProviderVersionRef::try_new(candidate),
            Err(SecretProviderVersionRefError::ForbiddenLocatorDelimiter)
        );
    }
    for candidate in [
        "https://provider.example/version",
        "vault/path/version",
        "vault\\path\\version",
        "version?account=private",
        "version#fragment",
        "scheme:opaque",
    ] {
        assert_eq!(
            SecretProviderVersionRef::try_new(candidate),
            Err(SecretProviderVersionRefError::ForbiddenLocatorDelimiter)
        );
    }
}

#[test]
fn provider_version_ref_serde_and_errors_are_strict_bounded_and_non_echoing() {
    let oversized = format!("PRIVATE-CANDIDATE-{}", "z".repeat(256));
    let direct_error = SecretProviderVersionRef::try_new(&oversized)
        .expect_err("oversized reference must reject")
        .to_string();
    assert!(direct_error.len() <= 80);
    assert!(!direct_error.contains(&oversized));

    let encoded = serde_json::to_string(&oversized).expect("candidate JSON");
    let serde_error = serde_json::from_str::<SecretProviderVersionRef>(&encoded)
        .expect_err("oversized reference JSON must reject")
        .to_string();
    assert!(serde_error.starts_with(PROVIDER_VERSION_REF_SERDE_ERROR));
    assert!(serde_error.len() <= 120);
    assert!(!serde_error.contains(&oversized));

    for (raw, candidate) in [
        ("\"\"", ""),
        (
            "\"release/PRIVATE_PROVIDER_SENTINEL\"",
            "PRIVATE_PROVIDER_SENTINEL",
        ),
        ("\"révision\"", "révision"),
        ("null", "null"),
        ("true", "true"),
        ("4242424242", "4242424242"),
        ("17.5", "17.5"),
        ("{}", "{}"),
        ("[]", "[]"),
        ("\"PRIVATE_PROVIDER_SENTINEL", "PRIVATE_PROVIDER_SENTINEL"),
    ] {
        let error = serde_json::from_str::<SecretProviderVersionRef>(raw)
            .expect_err("invalid reference JSON must reject")
            .to_string();
        assert!(error.starts_with(PROVIDER_VERSION_REF_SERDE_ERROR));
        assert!(error.len() <= 120);
        if !candidate.is_empty() {
            assert!(!error.contains(candidate));
        }
    }
}

#[test]
fn provider_version_ref_validates_borrowed_input_before_allocating_and_retains_owned_input() {
    let oversized = "z".repeat(1_000_000);
    assert_eq!(
        oversized.parse::<SecretProviderVersionRef>(),
        Err(SecretProviderVersionRefError::TooLong { max_bytes: 128 })
    );
    assert_eq!(
        SecretProviderVersionRef::try_new(oversized.as_str()),
        Err(SecretProviderVersionRefError::TooLong { max_bytes: 128 })
    );

    let owned = String::from("release-003");
    let allocation = owned.as_ptr();
    let version = SecretProviderVersionRef::try_from(owned).expect("owned input must validate");
    assert_eq!(version.as_str().as_ptr(), allocation);
}

fn valid_policy() -> SecretLeasePolicy {
    SecretLeasePolicy::try_new(300, 3600, 10, true, 5).expect("valid policy")
}

fn valid_policy_value() -> Value {
    json!({
        "max_lease_duration_seconds": 300,
        "max_continuous_lifetime_seconds": 3600,
        "max_uses": 10,
        "renewable": true,
        "clock_skew_tolerance_seconds": 5
    })
}

#[test]
fn lease_policy_is_valid_by_construction_at_all_boundaries() {
    let minimum = SecretLeasePolicy::try_new(1, 1, 1, false, 0).expect("minimum policy");
    assert_eq!(minimum.max_lease_duration_seconds(), 1);
    assert_eq!(minimum.max_continuous_lifetime_seconds(), 1);
    assert_eq!(minimum.max_uses(), 1);
    assert!(!minimum.renewable());
    assert_eq!(minimum.clock_skew_tolerance_seconds(), 0);

    let maximum = SecretLeasePolicy::try_new(
        MAX_SAFE_INTEGER,
        MAX_SAFE_INTEGER,
        MAX_SAFE_INTEGER,
        true,
        30,
    )
    .expect("maximum policy");
    assert_eq!(maximum.max_lease_duration_seconds(), MAX_SAFE_INTEGER);
    assert_eq!(maximum.max_continuous_lifetime_seconds(), MAX_SAFE_INTEGER);
    assert_eq!(maximum.max_uses(), MAX_SAFE_INTEGER);
    assert!(maximum.renewable());
    assert_eq!(maximum.clock_skew_tolerance_seconds(), 30);

    assert_eq!(
        SecretLeasePolicy::try_from(SecretLeasePolicyInput {
            max_lease_duration_seconds: 300,
            max_continuous_lifetime_seconds: 3600,
            max_uses: 10,
            renewable: true,
            clock_skew_tolerance_seconds: 5,
        })
        .expect("closed input validation"),
        valid_policy()
    );

    let serialized = serde_json::to_string(&valid_policy()).expect("policy serialization");
    assert_eq!(
        serialized,
        "{\"clock_skew_tolerance_seconds\":5,\"max_continuous_lifetime_seconds\":3600,\"max_lease_duration_seconds\":300,\"max_uses\":10,\"renewable\":true}"
    );
    assert_eq!(
        serde_json::from_str::<SecretLeasePolicy>(&serialized).expect("policy round trip"),
        valid_policy()
    );
}

#[test]
fn lease_policy_checked_construction_rejects_every_invalid_range_and_relationship() {
    let cases = [
        (
            SecretLeasePolicy::try_new(0, 1, 1, false, 0),
            SecretLeasePolicyError::MaxLeaseDurationOutOfRange,
        ),
        (
            SecretLeasePolicy::try_new(MAX_SAFE_INTEGER + 1, MAX_SAFE_INTEGER + 1, 1, false, 0),
            SecretLeasePolicyError::MaxLeaseDurationOutOfRange,
        ),
        (
            SecretLeasePolicy::try_new(1, 0, 1, false, 0),
            SecretLeasePolicyError::MaxContinuousLifetimeOutOfRange,
        ),
        (
            SecretLeasePolicy::try_new(1, MAX_SAFE_INTEGER + 1, 1, false, 0),
            SecretLeasePolicyError::MaxContinuousLifetimeOutOfRange,
        ),
        (
            SecretLeasePolicy::try_new(1, 1, 0, false, 0),
            SecretLeasePolicyError::MaxUsesOutOfRange,
        ),
        (
            SecretLeasePolicy::try_new(1, 1, MAX_SAFE_INTEGER + 1, false, 0),
            SecretLeasePolicyError::MaxUsesOutOfRange,
        ),
        (
            SecretLeasePolicy::try_new(2, 1, 1, false, 0),
            SecretLeasePolicyError::ContinuousLifetimeLessThanLeaseDuration,
        ),
        (
            SecretLeasePolicy::try_new(1, 1, 1, false, 31),
            SecretLeasePolicyError::ClockSkewToleranceOutOfRange,
        ),
    ];
    for (actual, expected) in cases {
        assert_eq!(actual, Err(expected));
        let message = expected.to_string();
        assert!(message.len() <= 96);
    }
}

fn assert_policy_rejects(raw: &str) -> String {
    let error = serde_json::from_str::<SecretLeasePolicy>(raw)
        .expect_err("invalid policy must reject")
        .to_string();
    assert!(error.len() <= 160, "policy errors must remain bounded");
    error
}

struct OneByteReader<'a> {
    input: &'a [u8],
    consumed: usize,
}

impl Read for OneByteReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.consumed == self.input.len() {
            return Ok(0);
        }
        buffer[0] = self.input[self.consumed];
        self.consumed += 1;
        Ok(1)
    }
}

#[test]
fn lease_policy_serde_rejects_missing_duplicate_unknown_and_malformed_objects() {
    let field_names = [
        "max_lease_duration_seconds",
        "max_continuous_lifetime_seconds",
        "max_uses",
        "renewable",
        "clock_skew_tolerance_seconds",
    ];
    for field in field_names {
        let mut candidate = valid_policy_value();
        candidate
            .as_object_mut()
            .expect("policy candidate object")
            .remove(field);
        assert_policy_rejects(&candidate.to_string());
    }

    let duplicate_cases = [
        r#"{"max_lease_duration_seconds":300,"max_lease_duration_seconds":301,"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_continuous_lifetime_seconds":3601,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":10,"max_uses":11,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":true,"renewable":false,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5,"clock_skew_tolerance_seconds":6}"#,
    ];
    for raw in duplicate_cases {
        let error = assert_policy_rejects(raw);
        assert!(error.contains("duplicate field"));
    }

    let unknown = r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5,"VERY_SENSITIVE_UNKNOWN_FIELD":"PRIVATE_POLICY_CANDIDATE"}"#;
    let unknown_error = assert_policy_rejects(unknown);
    assert!(!unknown_error.contains("VERY_SENSITIVE_UNKNOWN_FIELD"));
    assert!(!unknown_error.contains("PRIVATE_POLICY_CANDIDATE"));

    let malformed_unknown = r#"{"VERY_SENSITIVE_UNKNOWN_FIELD":"#;
    let malformed_unknown_error = assert_policy_rejects(malformed_unknown);
    assert!(malformed_unknown_error.contains("contains an unknown field"));
    assert!(!malformed_unknown_error.contains("EOF"));

    let oversized_unknown = format!(
        r#"{{"VERY_SENSITIVE_UNKNOWN_FIELD":"{}"}}"#,
        "PRIVATE_POLICY_VALUE_SENTINEL".repeat(40_000)
    );
    let mut reader = OneByteReader {
        input: oversized_unknown.as_bytes(),
        consumed: 0,
    };
    let mut deserializer = serde_json::Deserializer::from_reader(&mut reader);
    let oversized_unknown_error = SecretLeasePolicy::deserialize(&mut deserializer)
        .expect_err("unknown field must reject before its oversized value")
        .to_string();
    assert!(oversized_unknown_error.contains("contains an unknown field"));
    assert!(!oversized_unknown_error.contains("PRIVATE_POLICY_VALUE_SENTINEL"));
    assert!(
        reader.consumed < 128,
        "unknown policy value was consumed before denial: {} bytes",
        reader.consumed
    );

    assert_policy_rejects(r#"{"max_lease_duration_seconds":300"#);
    for raw in [
        "null",
        "true",
        "17",
        "17.5",
        "\"PRIVATE_POLICY_CANDIDATE\"",
        "[]",
    ] {
        let error = assert_policy_rejects(raw);
        assert!(!error.contains("PRIVATE_POLICY_CANDIDATE"));
    }
}

#[test]
fn lease_policy_serde_rejects_null_wrong_type_coercion_and_invalid_values() {
    let field_names = [
        "max_lease_duration_seconds",
        "max_continuous_lifetime_seconds",
        "max_uses",
        "renewable",
        "clock_skew_tolerance_seconds",
    ];
    for field in field_names {
        let mut candidate = valid_policy_value();
        candidate
            .as_object_mut()
            .expect("policy candidate object")
            .insert(field.to_string(), Value::Null);
        assert_policy_rejects(&candidate.to_string());
    }

    let wrong_type_cases = [
        r#"{"max_lease_duration_seconds":"PRIVATE_POLICY_CANDIDATE","max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":[],"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":{},"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":1,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":false}"#,
    ];
    for raw in wrong_type_cases {
        let error = assert_policy_rejects(raw);
        assert!(!error.contains("PRIVATE_POLICY_CANDIDATE"));
    }

    let invalid_value_cases = [
        r#"{"max_lease_duration_seconds":-1,"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":0,"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":9007199254740992,"max_continuous_lifetime_seconds":9007199254740992,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":-1,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":0,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":9007199254740992,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":-1,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":0,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":9007199254740992,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":299,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":-1}"#,
        r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":31}"#,
    ];
    for raw in invalid_value_cases {
        assert_policy_rejects(raw);
    }
}

#[test]
fn lease_policy_scalar_fields_reject_coercion_with_fixed_non_reflecting_errors() {
    const SENSITIVE_SENTINEL: &str = "PRIVATE_POLICY_SCALAR_SENTINEL";

    for value in [
        "-1",
        "1.0",
        "1e0",
        "\"PRIVATE_POLICY_SCALAR_SENTINEL\"",
        "true",
        "null",
        "[]",
        r#"{"PRIVATE_POLICY_SCALAR_SENTINEL":1}"#,
        "18446744073709551616",
    ] {
        let raw = format!(
            r#"{{"max_lease_duration_seconds":{value},"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}}"#
        );
        let error = assert_policy_rejects(&raw);
        assert!(error.starts_with(LEASE_POLICY_INTEGER_TYPE_ERROR));
        assert!(!error.contains(SENSITIVE_SENTINEL));
    }

    for value in [
        "-1",
        "1.0",
        "1e0",
        "\"PRIVATE_POLICY_SCALAR_SENTINEL\"",
        "1",
        "null",
        "[]",
        r#"{"PRIVATE_POLICY_SCALAR_SENTINEL":true}"#,
    ] {
        let raw = format!(
            r#"{{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":{value},"clock_skew_tolerance_seconds":5}}"#
        );
        let error = assert_policy_rejects(&raw);
        assert!(error.starts_with(LEASE_POLICY_RENEWABLE_TYPE_ERROR));
        assert!(!error.contains(SENSITIVE_SENTINEL));
    }

    for (raw, expected_error) in [
        (
            r#"{"max_lease_duration_seconds":9007199254740992,"max_continuous_lifetime_seconds":9007199254740992,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
            SecretLeasePolicyError::MaxLeaseDurationOutOfRange,
        ),
        (
            r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":9007199254740992,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
            SecretLeasePolicyError::MaxContinuousLifetimeOutOfRange,
        ),
        (
            r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":9007199254740992,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
            SecretLeasePolicyError::MaxUsesOutOfRange,
        ),
        (
            r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":3600,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":31}"#,
            SecretLeasePolicyError::ClockSkewToleranceOutOfRange,
        ),
        (
            r#"{"max_lease_duration_seconds":300,"max_continuous_lifetime_seconds":299,"max_uses":10,"renewable":true,"clock_skew_tolerance_seconds":5}"#,
            SecretLeasePolicyError::ContinuousLifetimeLessThanLeaseDuration,
        ),
    ] {
        let error = assert_policy_rejects(raw);
        assert!(error.starts_with(&expected_error.to_string()));
    }
}

#[test]
fn lease_policy_rejects_non_json_serde_scalar_and_byte_forms_without_reflection() {
    use serde::de::value::{
        BytesDeserializer, CharDeserializer, Error as ValueError, I128Deserializer,
        I64Deserializer, StringDeserializer, U128Deserializer,
    };

    const SENSITIVE_SENTINEL: &str = "PRIVATE_POLICY_SERDE_SENTINEL";
    let assert_rejected = |result: Result<SecretLeasePolicy, ValueError>| {
        let error = result
            .expect_err("non-object serde form must reject")
            .to_string();
        assert_eq!(error, "secret lease policy must be an object");
        assert!(!error.contains(SENSITIVE_SENTINEL));
    };

    assert_rejected(SecretLeasePolicy::deserialize(I64Deserializer::new(-1)));
    assert_rejected(SecretLeasePolicy::deserialize(I128Deserializer::new(-1)));
    assert_rejected(SecretLeasePolicy::deserialize(U128Deserializer::new(
        u128::MAX,
    )));
    assert_rejected(SecretLeasePolicy::deserialize(CharDeserializer::new('x')));
    assert_rejected(SecretLeasePolicy::deserialize(StringDeserializer::new(
        SENSITIVE_SENTINEL.to_owned(),
    )));
    assert_rejected(SecretLeasePolicy::deserialize(BytesDeserializer::new(
        SENSITIVE_SENTINEL.as_bytes(),
    )));
}

fn restricted_policy_canonical_bytes(value: &Value) -> Vec<u8> {
    let object = value
        .as_object()
        .expect("restricted canonical fixture must be an object");
    let mut fields = object.iter().collect::<Vec<_>>();
    fields.sort_by(|left, right| left.0.cmp(right.0));

    let mut canonical = String::from("{");
    for (index, (key, field_value)) in fields.into_iter().enumerate() {
        if index > 0 {
            canonical.push(',');
        }
        canonical.push_str(&serde_json::to_string(key).expect("ASCII key serialization"));
        canonical.push(':');
        match field_value {
            Value::Bool(value) => canonical.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => {
                let value = value
                    .as_u64()
                    .expect("restricted canonical number must be unsigned");
                assert!(value <= MAX_SAFE_INTEGER);
                canonical.push_str(&value.to_string());
            }
            _ => panic!("restricted policy canonicalizer accepts only booleans and integers"),
        }
    }
    canonical.push('}');
    canonical.into_bytes()
}

#[test]
fn fixture_pins_boundaries_and_restricted_rfc8785_policy_bytes() {
    let fixture = fixture();
    let policy_value = &fixture["policy"];
    let policy: SecretLeasePolicy =
        serde_json::from_value(policy_value.clone()).expect("fixture policy must validate");
    assert_eq!(policy, valid_policy());

    let expected = fixture["policy_rfc8785"]
        .as_str()
        .expect("fixture canonical text")
        .as_bytes();
    assert_eq!(restricted_policy_canonical_bytes(policy_value), expected);
    assert_eq!(
        serde_json::to_vec(&policy).expect("serialize policy"),
        expected
    );
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn assert_no_secret_payload_keys(value: &Value) {
    const FORBIDDEN: &[&str] = &[
        "value",
        "secretvalue",
        "material",
        "secretmaterial",
        "bytes",
        "rawbytes",
        "locator",
        "providerlocator",
        "providerrequest",
        "rawerror",
        "token",
        "accesstoken",
        "password",
        "apikey",
        "credential",
        "credentialvalue",
    ];
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized = normalized_key(key);
                assert!(
                    !FORBIDDEN.contains(&normalized.as_str()),
                    "forbidden secret payload key: {key}"
                );
                assert_no_secret_payload_keys(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                assert_no_secret_payload_keys(child);
            }
        }
        _ => {}
    }
}

#[test]
fn implemented_values_and_fixture_objects_have_no_secret_payload_keys() {
    let implemented = [
        serde_json::to_value([
            SecretClassification::AuthenticationCredential,
            SecretClassification::SigningMaterial,
            SecretClassification::EncryptionMaterial,
            SecretClassification::PrivateConfiguration,
            SecretClassification::OpaqueSecret,
        ])
        .expect("classification serialization"),
        serde_json::to_value([
            SecretDeliveryMethod::InheritedFd,
            SecretDeliveryMethod::TmpfsFile,
            SecretDeliveryMethod::OneShotLocalSocket,
            SecretDeliveryMethod::OrchestratorProjectedSecret,
            SecretDeliveryMethod::EnvironmentVariable,
        ])
        .expect("delivery method serialization"),
        serde_json::to_value([
            SecretUseIntent::Authenticate,
            SecretUseIntent::Sign,
            SecretUseIntent::Encrypt,
            SecretUseIntent::Decrypt,
            SecretUseIntent::DeriveSession,
            SecretUseIntent::BootstrapTransport,
        ])
        .expect("intent serialization"),
        serde_json::to_value([
            SecretPurpose::ExternalServiceAccess,
            SecretPurpose::DataSourceAccess,
            SecretPurpose::ArtifactStoreAccess,
            SecretPurpose::ModelProviderAccess,
            SecretPurpose::OrchestratorAccess,
            SecretPurpose::DeviceServiceAccess,
            SecretPurpose::CryptographicOperation,
        ])
        .expect("purpose serialization"),
        serde_json::to_value([
            SecretOfflineBehavior::Deny,
            SecretOfflineBehavior::ContinueExistingUntilExpiry,
        ])
        .expect("offline behavior serialization"),
        serde_json::to_value([
            SecretDeliveryExposureProfile::TrustedInjection,
            SecretDeliveryExposureProfile::MaterialExposed,
        ])
        .expect("exposure profile serialization"),
        serde_json::to_value(SecretProviderVersionRef::try_new("release-001").expect("valid ref"))
            .expect("version ref serialization"),
        serde_json::to_value(valid_policy()).expect("policy serialization"),
    ];
    for value in &implemented {
        assert_no_secret_payload_keys(value);
    }

    let fixture = fixture();
    assert_no_secret_payload_keys(&fixture);
    let canonical_policy: Value = serde_json::from_str(
        fixture["policy_rfc8785"]
            .as_str()
            .expect("fixture canonical policy"),
    )
    .expect("canonical policy must be JSON");
    assert_no_secret_payload_keys(&canonical_policy);
}
