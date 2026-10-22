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

#[test]
fn threat_id_serialization_and_length_validation_are_stable() {
    assert_eq!(
        SecurityThreatId::try_new(" ").expect_err("empty id fails"),
        SecurityThreatIdError::Empty
    );
    let too_long = "a".repeat(97);
    assert_eq!(
        SecurityThreatId::try_new(too_long).expect_err("long id fails"),
        SecurityThreatIdError::TooLong { max: 96 }
    );

    let threat_id = SecurityThreatId::try_new("threat.g80_injection").expect("valid id");
    assert_eq!(threat_id.as_str(), "threat.g80_injection");
    assert_eq!(threat_id.to_string(), "threat.g80_injection");
    let encoded = serde_json::to_string(&threat_id).expect("serialize threat id");
    assert_eq!(encoded, "\"threat.g80_injection\"");
    let decoded: SecurityThreatId = serde_json::from_str(&encoded).expect("deserialize threat id");
    let decoded_string: String = decoded.into();
    assert_eq!(decoded_string, "threat.g80_injection");
}

#[test]
fn catalog_header_plane_and_duplicate_failures_are_explicit() {
    let mut bad_schema = fixture_catalog();
    bad_schema.schema_version = "splendor.security_invariants.v2".to_string();
    assert!(matches!(
        validate_security_invariant_catalog(&bad_schema),
        Err(SecurityInvariantValidationError::UnsupportedSchemaVersion { found, .. })
            if found == "splendor.security_invariants.v2"
    ));

    let mut bad_scope = fixture_catalog();
    bad_scope.evidence_scope = "gold_pass".to_string();
    assert!(matches!(
        validate_security_invariant_catalog(&bad_scope),
        Err(SecurityInvariantValidationError::UnsupportedEvidenceScope { found, .. })
            if found == "gold_pass"
    ));

    let mut missing_non_claim = fixture_catalog();
    missing_non_claim
        .non_claims
        .retain(|claim| claim != "no_gold_harness_pass");
    assert!(matches!(
        validate_security_invariant_catalog(&missing_non_claim),
        Err(SecurityInvariantValidationError::MissingNonClaims { missing })
            if missing == vec!["no_gold_harness_pass"]
    ));

    let mut duplicate = fixture_catalog();
    duplicate.invariants[1].gold_id = "G80".to_string();
    assert!(matches!(
        validate_security_invariant_catalog(&duplicate),
        Err(SecurityInvariantValidationError::DuplicateGoldMapping { gold_id }) if gold_id == "G80"
    ));

    let mut missing_planes = fixture_catalog();
    for record in &mut missing_planes.invariants {
        record.primary_plane = SecurityPlane::IdentityAuthority;
        record.related_planes.clear();
    }
    assert!(matches!(
        validate_security_invariant_catalog(&missing_planes),
        Err(SecurityInvariantValidationError::MissingSecurityPlanes { planes })
            if planes.contains(&"driver_boundary")
    ));
}

#[test]
fn crypto_agility_required_fields_fail_closed() {
    let mut empty_algorithms = fixture_catalog();
    empty_algorithms
        .crypto_agility
        .allowed_signature_algorithms
        .clear();
    assert!(matches!(
        validate_security_invariant_catalog(&empty_algorithms),
        Err(SecurityInvariantValidationError::MissingCryptoAgility {
            field: "allowed_signature_algorithms"
        })
    ));

    let mut rotation_missing = fixture_catalog();
    rotation_missing
        .crypto_agility
        .key_rotation
        .rotation_required = false;
    assert!(matches!(
        validate_security_invariant_catalog(&rotation_missing),
        Err(SecurityInvariantValidationError::MissingCryptoAgility {
            field: "key_rotation.rotation_required"
        })
    ));

    let mut revocation_missing = fixture_catalog();
    revocation_missing
        .crypto_agility
        .key_rotation
        .revocation_path_required = false;
    assert!(matches!(
        validate_security_invariant_catalog(&revocation_missing),
        Err(SecurityInvariantValidationError::MissingCryptoAgility {
            field: "key_rotation.revocation_path_required"
        })
    ));

    let mut response_missing = fixture_catalog();
    response_missing
        .crypto_agility
        .key_rotation
        .compromise_response
        .clear();
    assert!(matches!(
        validate_security_invariant_catalog(&response_missing),
        Err(SecurityInvariantValidationError::MissingCryptoAgility {
            field: "key_rotation.compromise_response"
        })
    ));

    let mut attestation_missing = fixture_catalog();
    attestation_missing
        .crypto_agility
        .node_attestation_extension_points
        .clear();
    assert!(matches!(
        validate_security_invariant_catalog(&attestation_missing),
        Err(SecurityInvariantValidationError::MissingCryptoAgility {
            field: "node_attestation_extension_points"
        })
    ));

    let mut assumptions_missing = fixture_catalog();
    assumptions_missing
        .crypto_agility
        .non_cryptographic_safety_assumptions
        .clear();
    assert!(matches!(
        validate_security_invariant_catalog(&assumptions_missing),
        Err(SecurityInvariantValidationError::MissingCryptoAgility {
            field: "non_cryptographic_safety_assumptions"
        })
    ));
}

#[test]
fn record_enforcement_and_evidence_failures_are_explicit() {
    let mut empty_asset = fixture_catalog();
    empty_asset.invariants[0].assets.clear();
    assert!(matches!(
        validate_security_invariant_catalog(&empty_asset),
        Err(SecurityInvariantValidationError::EmptyField { gold_id, field })
            if gold_id == "G80" && field == "assets"
    ));

    let mut prompt_component = fixture_catalog();
    prompt_component.invariants[0]
        .enforcement
        .enforcing_component = "system prompt".to_string();
    assert!(matches!(
        validate_security_invariant_catalog(&prompt_component),
        Err(SecurityInvariantValidationError::PromptOnlyBoundary { gold_id }) if gold_id == "G80"
    ));

    let mut missing_component = fixture_catalog();
    missing_component.invariants[0]
        .enforcement
        .enforcing_component
        .clear();
    assert!(matches!(
        validate_security_invariant_catalog(&missing_component),
        Err(SecurityInvariantValidationError::MissingEnforcementMapping { gold_id, field })
            if gold_id == "G80" && field == "enforcing_component"
    ));

    let mut missing_evidence = fixture_catalog();
    missing_evidence.invariants[0]
        .enforcement
        .evidence_links
        .clear();
    assert!(matches!(
        validate_security_invariant_catalog(&missing_evidence),
        Err(SecurityInvariantValidationError::MissingEnforcementMapping { gold_id, field })
            if gold_id == "G80" && field == "evidence_links"
    ));

    let mut missing_containment = fixture_catalog();
    missing_containment.invariants[0]
        .enforcement
        .containment_actions
        .clear();
    assert!(matches!(
        validate_security_invariant_catalog(&missing_containment),
        Err(SecurityInvariantValidationError::MissingEnforcementMapping { gold_id, field })
            if gold_id == "G80" && field == "containment_actions"
    ));

    let mut empty_evidence_field = fixture_catalog();
    let g86 = empty_evidence_field
        .invariants
        .iter_mut()
        .find(|record| record.gold_id == "G86")
        .expect("G86 exists");
    g86.maturity_gate.case_status = SecurityCaseStatus::Exercised;
    g86.maturity_gate.executable_gold_evidence = Some(ExecutableGoldEvidence {
        harness_id: "".to_string(),
        report_ref: "artifact:report".to_string(),
        executed_at: "2026-06-22T13:00:00Z".to_string(),
        evidence_assertions: vec!["denial evidence retained".to_string()],
    });
    assert!(matches!(
        validate_security_invariant_catalog(&empty_evidence_field),
        Err(SecurityInvariantValidationError::EmptyField { gold_id, field })
            if gold_id == "G86" && field == "executable_gold_evidence.harness_id"
    ));
}

#[test]
fn review_checklist_rejects_empty_items() {
    let mut catalog = fixture_catalog();
    catalog.security_review_checklist[0]
        .required_evidence
        .clear();
    assert_eq!(
        validate_security_invariant_catalog(&catalog),
        Err(SecurityInvariantValidationError::MissingSecurityReviewChecklist)
    );
}
