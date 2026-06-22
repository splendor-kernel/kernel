use super::*;

fn fixture_catalog() -> SecurityInvariantCatalog {
    serde_json::from_str(include_str!(
        "../../../../docs/rules/v2/security/security-invariants.json"
    ))
    .expect("fixture should deserialize")
}

#[test]
fn valid_security_invariant_fixture_passes_validation() {
    let catalog = fixture_catalog();

    validate_security_invariant_catalog(&catalog).expect("security invariant fixture validates");
}

#[test]
fn missing_gold_mapping_fails_validation() {
    let mut catalog = fixture_catalog();
    catalog.invariants.retain(|record| record.gold_id != "G89");

    let error = validate_security_invariant_catalog(&catalog).expect_err("missing G89 fails");

    assert_eq!(
        error,
        SecurityInvariantValidationError::MissingGoldMappings {
            gold_ids: vec!["G89"]
        }
    );
}

#[test]
fn prompt_only_boundary_fails_validation() {
    let mut catalog = fixture_catalog();
    let g80 = catalog
        .invariants
        .iter_mut()
        .find(|record| record.gold_id == "G80")
        .expect("G80 fixture exists");
    g80.trust_boundary.prompt_only = true;

    let error = validate_security_invariant_catalog(&catalog).expect_err("prompt-only fails");

    assert_eq!(
        error,
        SecurityInvariantValidationError::PromptOnlyBoundary {
            gold_id: "G80".to_string()
        }
    );
}

#[test]
fn prompt_only_false_with_prompt_wording_still_fails_validation() {
    let mut catalog = fixture_catalog();
    let g80 = catalog
        .invariants
        .iter_mut()
        .find(|record| record.gold_id == "G80")
        .expect("G80 fixture exists");
    g80.trust_boundary.prompt_only = false;
    g80.trust_boundary.enforced_by = vec![
        "prompt instruction".to_string(),
        "system prompt".to_string(),
        "LLM instruction".to_string(),
    ];

    let error = validate_security_invariant_catalog(&catalog).expect_err("prompt wording fails");

    assert_eq!(
        error,
        SecurityInvariantValidationError::PromptOnlyBoundary {
            gold_id: "G80".to_string()
        }
    );
}

#[test]
fn skipped_mandatory_case_fails_validation() {
    let mut catalog = fixture_catalog();
    let g87 = catalog
        .invariants
        .iter_mut()
        .find(|record| record.gold_id == "G87")
        .expect("G87 fixture exists");
    g87.maturity_gate.case_status = SecurityCaseStatus::Skipped;

    let error = validate_security_invariant_catalog(&catalog).expect_err("skipped mandatory fails");

    assert_eq!(
        error,
        SecurityInvariantValidationError::SkippedMandatoryCase {
            gold_id: "G87".to_string()
        }
    );
}

#[test]
fn exercised_case_requires_executable_gold_evidence() {
    let mut catalog = fixture_catalog();
    let g86 = catalog
        .invariants
        .iter_mut()
        .find(|record| record.gold_id == "G86")
        .expect("G86 fixture exists");
    g86.maturity_gate.case_status = SecurityCaseStatus::Exercised;
    g86.maturity_gate.executable_gold_evidence = None;

    let error = validate_security_invariant_catalog(&catalog)
        .expect_err("exercised without evidence fails");

    assert_eq!(
        error,
        SecurityInvariantValidationError::MissingExecutableGoldEvidence {
            gold_id: "G86".to_string()
        }
    );
}

#[test]
fn explicit_allowed_crypto_algorithm_labels_pass_validation() {
    let mut catalog = fixture_catalog();
    catalog.crypto_agility.allowed_signature_algorithms =
        vec!["ed25519".to_string(), "ecdsa-p256-sha256".to_string()];

    validate_security_invariant_catalog(&catalog)
        .expect("only explicit allowed signature algorithms pass");
}

#[test]
fn unsupported_or_unsafe_crypto_algorithm_labels_fail_validation() {
    for algorithm in [
        "none",
        "md5",
        "rsa_md5",
        "plain",
        "rsa_sha1",
        "sha1",
        "dsa_sha1",
        "ecdsa_p192_sha256",
        "rsa_pkcs1_sha1",
        "rsa_pss_sha256",
        " ",
    ] {
        let mut catalog = fixture_catalog();
        catalog.crypto_agility.allowed_signature_algorithms = vec![algorithm.to_string()];

        let error = validate_security_invariant_catalog(&catalog)
            .expect_err("unsafe or unsupported crypto algorithm fails");

        if algorithm.trim().is_empty() {
            assert_eq!(
                error,
                SecurityInvariantValidationError::MissingCryptoAgility {
                    field: "allowed_signature_algorithms"
                }
            );
        } else {
            assert_eq!(
                error,
                SecurityInvariantValidationError::UnsafeCryptoAlgorithm {
                    algorithm: algorithm.to_string()
                }
            );
        }
    }
}

#[test]
fn missing_event_evidence_or_containment_links_fail_validation() {
    let mut catalog = fixture_catalog();
    let g82 = catalog
        .invariants
        .iter_mut()
        .find(|record| record.gold_id == "G82")
        .expect("G82 fixture exists");
    g82.enforcement.required_events.clear();

    let error = validate_security_invariant_catalog(&catalog).expect_err("required events fail");

    assert_eq!(
        error,
        SecurityInvariantValidationError::MissingEnforcementMapping {
            gold_id: "G82".to_string(),
            field: "required_events"
        }
    );
}

#[test]
fn threat_ids_reject_authority_shaped_or_invalid_text() {
    let error = SecurityThreatId::try_new("Threat.G80").expect_err("uppercase is invalid");

    assert_eq!(
        error,
        SecurityThreatIdError::InvalidCharacter { character: 'T' }
    );
}
