use super::*;
use std::error::Error;

const DECLARATION_FIXTURE: &[u8] =
    include_bytes!("../fixtures/driver/operation-credential-sinks-v1.json");
const EXPECTED_DECLARATION_DIGEST: &str =
    "blake3:f18d117f253c367f79de0ca2c546088580cc47e53f49ce177ed10022d39ecdb6";

#[test]
fn schema_ids_accept_exact_boundaries_and_serialize_deterministically() {
    for value in [
        "a.v1".to_owned(),
        "splendor.driver.operation_credential_sinks.v1".to_owned(),
        format!("{}.v1", "a".repeat(125)),
        "a.v1.v2".to_owned(),
    ] {
        let parsed = CanonicalSchemaIdV1::parse(&value).expect("canonical schema ID");
        assert_eq!(parsed.as_str(), value);
        assert_eq!(
            serde_json::to_string(&parsed).expect("serialize"),
            format!("\"{value}\"")
        );
        assert_eq!(
            value.parse::<CanonicalSchemaIdV1>().expect("FromStr"),
            parsed
        );
        assert_eq!(
            CanonicalSchemaIdV1::try_new(value).expect("checked constructor"),
            parsed
        );
    }

    for value in [
        ".v1", "A.v1", "1a.v1", "a", "a.v0", "a.v01", "a.v-1", "a.V1", "a.v1 ", "é.v1",
    ] {
        assert_eq!(
            CanonicalSchemaIdV1::parse(value).expect_err("noncanonical schema ID"),
            FoundationGrammarError::InvalidContractVersion
        );
    }
    assert_eq!(
        CanonicalSchemaIdV1::parse("").expect_err("empty schema ID"),
        FoundationGrammarError::InvalidContractVersion
    );
    assert_eq!(
        CanonicalSchemaIdV1::parse(&format!("{}.v1", "a".repeat(126))).expect_err("schema maximum"),
        FoundationGrammarError::InvalidContractBound
    );
}

#[test]
fn labels_and_foundation_codes_are_exact_distinct_profiles() {
    for value in ["a".to_owned(), "a0._-z".to_owned(), "a".repeat(128)] {
        let label = CanonicalLabelV1::parse(&value).expect("canonical label");
        let code = FoundationGrammarCodeV1::parse(&value).expect("canonical code");
        assert_eq!(label.as_str(), value);
        assert_eq!(code.as_str(), value);
        assert_eq!(
            serde_json::to_string(&label).expect("label JSON"),
            format!("\"{value}\"")
        );
        assert_eq!(
            serde_json::to_string(&code).expect("code JSON"),
            format!("\"{value}\"")
        );
        assert_eq!(
            CanonicalLabelV1::try_new(value.clone()).expect("checked label constructor"),
            label
        );
        assert_eq!(
            FoundationGrammarCodeV1::try_new(value).expect("checked code constructor"),
            code
        );
    }

    for value in ["", "A", "0a", ".a", "a/b", "a b", "a\n", "é", "aé", "a\0b"] {
        assert_eq!(
            CanonicalLabelV1::parse(value).expect_err("noncanonical label"),
            FoundationGrammarError::InvalidContractShape
        );
        assert_eq!(
            FoundationGrammarCodeV1::parse(value).expect_err("noncanonical code"),
            FoundationGrammarError::InvalidContractShape
        );
    }
    let over_bound = "a".repeat(129);
    assert_eq!(
        CanonicalLabelV1::parse(&over_bound).expect_err("label bound"),
        FoundationGrammarError::InvalidContractBound
    );
    assert_eq!(
        FoundationGrammarCodeV1::parse(&over_bound).expect_err("code bound"),
        FoundationGrammarError::InvalidContractBound
    );
}

#[test]
fn timestamps_enforce_calendar_utc_and_microsecond_form() {
    for value in [
        "0001-01-01T00:00:00.000000Z",
        "2000-02-29T23:59:59.999999Z",
        "9999-12-31T23:59:59.999999Z",
    ] {
        let timestamp = CanonicalTimestampV1::parse(value).expect("canonical timestamp");
        assert_eq!(timestamp.as_str(), value);
        assert_eq!(
            serde_json::to_string(&timestamp).expect("timestamp JSON"),
            format!("\"{value}\"")
        );
        assert_eq!(
            value.parse::<CanonicalTimestampV1>().expect("FromStr"),
            timestamp
        );
        assert_eq!(
            CanonicalTimestampV1::try_new(value.to_owned()).expect("checked constructor"),
            timestamp
        );
    }

    for value in [
        "0000-01-01T00:00:00.000000Z",
        "10000-01-01T00:00:00.000000Z",
        "1900-02-29T00:00:00.000000Z",
        "2000-02-30T00:00:00.000000Z",
        "2000-01-00T00:00:00.000000Z",
        "2000-04-31T00:00:00.000000Z",
        "2100-02-29T00:00:00.000000Z",
        "2000-00-01T00:00:00.000000Z",
        "2000-13-01T00:00:00.000000Z",
        "2000-01-01T24:00:00.000000Z",
        "2000-01-01T00:60:00.000000Z",
        "2000-01-01T00:00:60.000000Z",
        "2000-01-01T00:00:00.000000z",
        "2000-01-01T00:00:00.000000+00:00",
        "2000-01-01T00:00:00Z",
        "2000-01-01T00:00:00.00000Z",
        "2000-01-01T00:00:00.0000000Z",
        " 2000-01-01T00:00:00.000000Z",
        "2000-01-01 00:00:00.000000Z",
    ] {
        assert_eq!(
            CanonicalTimestampV1::parse(value).expect_err("noncanonical timestamp"),
            FoundationGrammarError::InvalidContractTimestamp
        );
    }

    assert!(
        CanonicalTimestampV1::parse("2000-01-01T00:00:00.000001Z").expect("earlier")
            < CanonicalTimestampV1::parse("2000-01-01T00:00:00.000002Z").expect("later")
    );
}

macro_rules! assert_zero_inclusive_integer_profile {
    ($type:ty) => {{
        for (token, expected) in [
            ("0", 0_u64),
            ("1", 1),
            ("9007199254740991", 9_007_199_254_740_991),
        ] {
            let value = <$type>::parse(token).expect("canonical integer");
            assert_eq!(value.get(), expected);
            assert_eq!(serde_json::to_string(&value).expect("integer JSON"), token);
            assert_eq!(token.parse::<$type>().expect("FromStr"), value);
        }
        for token in [
            "",
            "-0",
            "-1",
            "-9007199254740991",
            "-1.0",
            "-1e0",
            "+0",
            "+1",
            "00",
            "01",
            "1.0",
            "1e0",
            "1E0",
            "9007199254740992",
            "18446744073709551616",
            " 1",
            "1 ",
        ] {
            assert_eq!(
                <$type>::parse(token).expect_err("noncanonical integer"),
                FoundationGrammarError::InvalidContractInteger
            );
        }
        assert_eq!(
            <$type>::try_new(9_007_199_254_740_992).expect_err("over safe range"),
            FoundationGrammarError::InvalidContractInteger
        );
    }};
}

#[test]
fn zero_inclusive_integer_profiles_validate_original_tokens_and_ranges() {
    assert_zero_inclusive_integer_profile!(CanonicalCountV1);
    assert_zero_inclusive_integer_profile!(CanonicalOrdinalV1);
    assert_zero_inclusive_integer_profile!(CanonicalSequenceV1);
}

#[test]
fn integer_parsers_reject_very_large_tokens_without_reflection() {
    static VERY_LARGE_DIGITS: [u8; 4096] = [b'9'; 4096];
    let candidate = std::str::from_utf8(&VERY_LARGE_DIGITS).expect("ASCII digits");
    for error in [
        CanonicalCountV1::parse(candidate).expect_err("large count"),
        CanonicalOrdinalV1::parse(candidate).expect_err("large ordinal"),
        CanonicalSequenceV1::parse(candidate).expect_err("large sequence"),
        CanonicalPositiveRevisionV1::parse(candidate).expect_err("large revision"),
    ] {
        assert_eq!(error, FoundationGrammarError::InvalidContractInteger);
        assert_eq!(error.to_string(), "invalid_contract_integer");
        assert_eq!(format!("{error:?}"), "invalid_contract_integer");
        assert!(error.source().is_none());
    }
}

#[test]
fn positive_revision_validates_original_tokens_and_range() {
    for (token, expected) in [("1", 1_u64), ("9007199254740991", 9_007_199_254_740_991)] {
        let value = CanonicalPositiveRevisionV1::parse(token).expect("positive revision");
        assert_eq!(value.get(), expected);
        assert_eq!(serde_json::to_string(&value).expect("revision JSON"), token);
    }
    for token in [
        "",
        "0",
        "-0",
        "-1",
        "-9007199254740991",
        "-1.0",
        "-1e0",
        "+0",
        "+1",
        "00",
        "01",
        "1.0",
        "1e0",
        "1E0",
        "9007199254740992",
        "18446744073709551616",
    ] {
        assert_eq!(
            CanonicalPositiveRevisionV1::parse(token).expect_err("noncanonical revision"),
            FoundationGrammarError::InvalidContractInteger
        );
    }
    for value in [0, 9_007_199_254_740_992] {
        assert_eq!(
            CanonicalPositiveRevisionV1::try_new(value).expect_err("invalid revision"),
            FoundationGrammarError::InvalidContractInteger
        );
    }
}

#[test]
fn grammar_errors_are_closed_code_only_and_non_reflecting() {
    let cases = [
        (
            FoundationGrammarError::InvalidContractShape,
            "invalid_contract_shape",
        ),
        (
            FoundationGrammarError::InvalidContractVersion,
            "invalid_contract_version",
        ),
        (
            FoundationGrammarError::InvalidContractIdentity,
            "invalid_contract_identity",
        ),
        (
            FoundationGrammarError::InvalidContractTimestamp,
            "invalid_contract_timestamp",
        ),
        (
            FoundationGrammarError::InvalidContractInteger,
            "invalid_contract_integer",
        ),
        (
            FoundationGrammarError::InvalidContractDigest,
            "invalid_contract_digest",
        ),
        (
            FoundationGrammarError::InvalidContractSignature,
            "invalid_contract_signature",
        ),
        (
            FoundationGrammarError::InvalidContractBound,
            "invalid_contract_bound",
        ),
        (
            FoundationGrammarError::InvalidContractBinding,
            "invalid_contract_binding",
        ),
    ];
    assert_eq!(cases.len(), 9);
    for (error, code) in cases {
        assert_eq!(error.as_str(), code);
        assert_eq!(error.to_string(), code);
        assert_eq!(format!("{error:?}"), code);
        assert!(error.source().is_none());
    }

    let candidate = "PRIVATE_FOUNDATION_CANDIDATE";
    for error in [
        CanonicalLabelV1::parse(candidate).expect_err("candidate rejects"),
        CanonicalTimestampV1::parse(candidate).expect_err("candidate rejects"),
        CanonicalCountV1::parse(candidate).expect_err("candidate rejects"),
        RegistryDeclarationDigest::parse(candidate).expect_err("candidate rejects"),
    ] {
        assert!(!error.to_string().contains(candidate));
        assert!(!format!("{error:?}").contains(candidate));
        assert!(error.source().is_none());
    }
}

#[test]
fn registry_declaration_digest_pins_existing_rfc0013_bytes_and_domain() {
    let declaration = DriverOperationCredentialSinksV1::from_json_slice(DECLARATION_FIXTURE)
        .expect("existing RFC 0013 fixture");
    assert_eq!(
        serde_json::to_vec(&declaration).expect("existing declaration serialization"),
        DECLARATION_FIXTURE
    );

    let digest = RegistryDeclarationDigest::try_from(&declaration).expect("declaration digest");
    assert_eq!(
        serde_json::to_string(&digest).expect("digest JSON"),
        format!("\"{EXPECTED_DECLARATION_DIGEST}\"")
    );
    assert_eq!(
        RegistryDeclarationDigest::parse(EXPECTED_DECLARATION_DIGEST)
            .expect("hard-coded digest vector"),
        digest
    );
    assert_eq!(
        format!("{digest:?}"),
        "RegistryDeclarationDigest(<redacted>)"
    );

    let mut independent = blake3::Hasher::new();
    independent.update(b"splendor.driver.operation_credential_sinks.v1");
    independent.update(&[0]);
    independent.update(DECLARATION_FIXTURE);
    assert_eq!(
        format!("blake3:{}", independent.finalize().to_hex()),
        EXPECTED_DECLARATION_DIGEST
    );

    let mut changed_bytes = DECLARATION_FIXTURE.to_vec();
    let revision_marker = b"\"driver_declaration_revision\":1";
    let revision_offset = changed_bytes
        .windows(revision_marker.len())
        .position(|window| window == revision_marker)
        .expect("fixture revision marker")
        + revision_marker.len()
        - 1;
    changed_bytes[revision_offset] = b'2';
    assert_eq!(
        changed_bytes
            .iter()
            .zip(DECLARATION_FIXTURE)
            .filter(|(left, right)| left != right)
            .count(),
        1
    );
    let changed_declaration = DriverOperationCredentialSinksV1::from_json_slice(&changed_bytes)
        .expect("one-byte mutation remains a valid declaration");
    assert_eq!(
        serde_json::to_vec(&changed_declaration).expect("changed declaration serialization"),
        changed_bytes
    );
    let changed_digest = RegistryDeclarationDigest::try_from(&changed_declaration)
        .expect("changed declaration digest");
    assert_ne!(changed_digest, digest);

    let mut independent_changed_declaration = blake3::Hasher::new();
    independent_changed_declaration.update(b"splendor.driver.operation_credential_sinks.v1");
    independent_changed_declaration.update(&[0]);
    independent_changed_declaration.update(&changed_bytes);
    let independent_changed_wire = format!(
        "blake3:{}",
        independent_changed_declaration.finalize().to_hex()
    );
    assert_eq!(
        RegistryDeclarationDigest::parse(&independent_changed_wire)
            .expect("independent changed declaration digest"),
        changed_digest
    );

    let mut domain_mutation = blake3::Hasher::new();
    domain_mutation.update(b"splendor.driver.operation_credential_sinks.v2");
    domain_mutation.update(&[0]);
    domain_mutation.update(DECLARATION_FIXTURE);
    assert_ne!(
        format!("blake3:{}", domain_mutation.finalize().to_hex()),
        EXPECTED_DECLARATION_DIGEST
    );
}

#[test]
fn registry_declaration_digest_wire_is_strict() {
    let valid = format!("blake3:{}", "0".repeat(64));
    let digest = RegistryDeclarationDigest::parse(&valid).expect("exact digest wire");
    assert_eq!(
        serde_json::to_string(&digest).expect("digest JSON"),
        format!("\"{valid}\"")
    );
    for invalid in [
        "",
        &"0".repeat(64),
        &format!("sha256:{}", "0".repeat(64)),
        &format!("BLAKE3:{}", "0".repeat(64)),
        &format!("blake3:{}", "0".repeat(63)),
        &format!("blake3:{}", "0".repeat(65)),
        &format!("blake3:{}A", "0".repeat(63)),
        &format!(" blake3:{}", "0".repeat(64)),
        &format!("blake3:{} ", "0".repeat(64)),
    ] {
        assert_eq!(
            RegistryDeclarationDigest::parse(invalid).expect_err("noncanonical digest"),
            FoundationGrammarError::InvalidContractDigest
        );
    }
}
