use super::*;
use crate::{RunId, TraceEventId, WorkOrderValidationError};

#[test]
fn category_retry_and_effect_labels_cover_required_fnd004_set() {
    let categories = [
        (ErrorCategory::InvalidInput, "invalid_input"),
        (ErrorCategory::IncompatibleSchema, "incompatible_schema"),
        (ErrorCategory::Unauthenticated, "unauthenticated"),
        (ErrorCategory::Unauthorized, "unauthorized"),
        (ErrorCategory::Revoked, "revoked"),
        (ErrorCategory::Expired, "expired"),
        (ErrorCategory::QuotaExceeded, "quota_exceeded"),
        (ErrorCategory::Unavailable, "unavailable"),
        (ErrorCategory::Conflict, "conflict"),
        (ErrorCategory::StaleHead, "stale_head"),
        (ErrorCategory::Unsafe, "unsafe"),
        (ErrorCategory::Uncertain, "uncertain"),
        (ErrorCategory::ProtectedDataDenial, "protected_data_denial"),
        (ErrorCategory::IntegrityFailure, "integrity_failure"),
        (ErrorCategory::Timeout, "timeout"),
        (ErrorCategory::Cancellation, "cancellation"),
        (ErrorCategory::Preemption, "preemption"),
        (ErrorCategory::WorkerFailure, "worker_failure"),
        (ErrorCategory::DriverFailure, "driver_failure"),
        (ErrorCategory::PostconditionFailure, "postcondition_failure"),
        (
            ErrorCategory::InternalInvariantViolation,
            "internal_invariant_violation",
        ),
    ];

    for (category, label) in categories {
        assert_eq!(category.as_str(), label);
        let encoded = serde_json::to_value(category).expect("serialize category");
        assert_eq!(encoded.as_str(), Some(label));
        let decoded: ErrorCategory = serde_json::from_value(encoded).expect("decode category");
        assert_eq!(decoded, category);
    }

    assert_eq!(RetryClass::NotRetryable.as_str(), "not_retryable");
    assert_eq!(
        RetryClass::RetryWithSameIdempotencyKey.as_str(),
        "retry_with_same_idempotency_key"
    );
    assert_eq!(
        RetryClass::RetryWithNewAuthorization.as_str(),
        "retry_with_new_authorization"
    );
    assert_eq!(EffectCertainty::None.as_str(), "none");
    assert_eq!(EffectCertainty::Known.as_str(), "known");
    assert_eq!(EffectCertainty::Uncertain.as_str(), "uncertain");
}

#[test]
fn reason_codes_are_exact_validated_and_round_trip() {
    let code = ReasonCode::try_new("expired_work_order").expect("valid code");
    assert_eq!(code.as_str(), "expired_work_order");
    let encoded = serde_json::to_string(&code).expect("serialize reason code");
    assert_eq!(encoded, "\"expired_work_order\"");
    let decoded: ReasonCode = serde_json::from_str(&encoded).expect("decode reason code");
    assert_eq!(decoded, code);

    assert!(matches!(
        ReasonCode::try_new(""),
        Err(ReasonCodeError::Empty)
    ));
    assert!(matches!(
        ReasonCode::try_new("human prose is not a stable code"),
        Err(ReasonCodeError::InvalidCharacter { character: ' ' })
    ));
    assert!(serde_json::from_str::<ReasonCode>("\"BadCode\"").is_err());
}

#[test]
fn taxonomy_carries_optional_causal_event_and_sanitized_provider_detail() {
    let run_id = RunId::new();
    let event_id = TraceEventId::from_run_sequence(&run_id, 42);
    let taxonomy = ErrorTaxonomy::unknown_provider_failure(
        "OpenAI Provider",
        Some("HTTP 500\nAuthorization: Bearer secret-token"),
    )
    .with_causal_event(event_id.clone());

    assert_eq!(taxonomy.category, ErrorCategory::DriverFailure);
    assert_eq!(
        taxonomy.reason_code.as_str(),
        UNKNOWN_PROVIDER_FAILURE_REASON
    );
    assert_eq!(taxonomy.retry_class, RetryClass::NotRetryable);
    assert_eq!(taxonomy.effect_certainty, EffectCertainty::Uncertain);
    assert_eq!(taxonomy.causal_event_id.as_ref(), Some(&event_id));
    let detail = taxonomy.provider_detail.as_ref().expect("provider detail");
    assert_eq!(detail.provider(), "openai_provider");
    assert_eq!(detail.safe_summary(), Some("[redacted]"));

    let encoded = serde_json::to_value(&taxonomy).expect("serialize taxonomy");
    assert_eq!(encoded["category"].as_str(), Some("driver_failure"));
    assert_eq!(encoded["retry_class"].as_str(), Some("not_retryable"));
    assert_eq!(encoded["effect_certainty"].as_str(), Some("uncertain"));
    assert_eq!(
        encoded["provider_detail"]["safe_summary"].as_str(),
        Some("[redacted]")
    );
    let rendered = encoded.to_string();
    assert!(!rendered.contains("secret-token"));
    assert!(!rendered.contains("Bearer"));
}

#[test]
fn provider_detail_deserialization_is_sanitized_before_reserialization() {
    let taxonomy: ErrorTaxonomy = serde_json::from_value(serde_json::json!({
        "category": "driver_failure",
        "reason_code": UNKNOWN_PROVIDER_FAILURE_REASON,
        "retry_class": "not_retryable",
        "effect_certainty": "uncertain",
        "provider_detail": {
            "provider": "Provider With Spaces",
            "provider_code": "HTTP 500",
            "safe_summary": "password=top-secret"
        }
    }))
    .expect("taxonomy decodes");

    let detail = taxonomy.provider_detail.as_ref().expect("provider detail");
    assert_eq!(detail.provider(), "provider_with_spaces");
    assert_eq!(detail.provider_code(), Some("http_500"));
    assert_eq!(detail.safe_summary(), Some("[redacted]"));
    let rendered = serde_json::to_string(&taxonomy).expect("taxonomy reserializes");
    assert!(!rendered.contains("top-secret"));
    assert!(!rendered.contains("password"));
}

#[test]
fn unknown_adapter_failure_defaults_to_uncertain_non_retryable() {
    let taxonomy = ErrorTaxonomy::unknown_adapter_failure(
        "Robot Driver / v2",
        Some("opaque provider timeout"),
    );

    assert_eq!(taxonomy.category, ErrorCategory::DriverFailure);
    assert_eq!(
        taxonomy.reason_code.as_str(),
        UNKNOWN_ADAPTER_FAILURE_REASON
    );
    assert_eq!(taxonomy.retry_class, RetryClass::NotRetryable);
    assert_eq!(taxonomy.effect_certainty, EffectCertainty::Uncertain);
    assert_eq!(
        taxonomy
            .provider_detail
            .as_ref()
            .map(ProviderDetail::provider),
        Some("robot_driver___v2")
    );
    assert_eq!(
        taxonomy
            .provider_detail
            .as_ref()
            .and_then(ProviderDetail::safe_summary),
        Some("opaque provider timeout")
    );
}

#[test]
fn work_order_validation_errors_map_to_exact_taxonomy_semantics() {
    for (error, category, reason, retry) in [
        (
            WorkOrderValidationError::Unsigned,
            ErrorCategory::Unauthenticated,
            "unsigned_work_order",
            RetryClass::RetryWithNewAuthorization,
        ),
        (
            WorkOrderValidationError::UnknownKey {
                key_id: "old".to_string(),
            },
            ErrorCategory::Unauthenticated,
            "unknown_signature_key",
            RetryClass::RetryWithNewAuthorization,
        ),
        (
            WorkOrderValidationError::BadSignature,
            ErrorCategory::IntegrityFailure,
            "bad_signature",
            RetryClass::RetryWithNewAuthorization,
        ),
        (
            WorkOrderValidationError::Expired,
            ErrorCategory::Expired,
            "expired_work_order",
            RetryClass::RetryWithNewAuthorization,
        ),
        (
            WorkOrderValidationError::Revoked {
                reason: "operator".to_string(),
            },
            ErrorCategory::Revoked,
            "revoked_work_order",
            RetryClass::RetryWithNewAuthorization,
        ),
        (
            WorkOrderValidationError::Incompatible {
                reason: "tenant_mismatch".to_string(),
            },
            ErrorCategory::Unauthorized,
            "work_order_tenant_mismatch",
            RetryClass::RetryWithNewAuthorization,
        ),
    ] {
        let taxonomy = error.taxonomy();
        assert_eq!(taxonomy.category, category, "{reason} category");
        assert_eq!(taxonomy.reason_code.as_str(), reason);
        assert_eq!(taxonomy.retry_class, retry, "{reason} retry");
        assert_eq!(taxonomy.effect_certainty, EffectCertainty::None);
        assert!(taxonomy.provider_detail.is_none());
    }
}

#[test]
fn malformed_work_order_reasons_keep_exact_classified_codes() {
    for (reason, category, code, retry) in [
        (
            "unsupported_schema_version:splendor.work_order.v0",
            ErrorCategory::IncompatibleSchema,
            "unsupported_work_order_schema_version",
            RetryClass::NotRetryable,
        ),
        (
            "empty_objective",
            ErrorCategory::InvalidInput,
            "work_order_empty_objective",
            RetryClass::NotRetryable,
        ),
        (
            "cloud_helper_robotics_adapter_authority_denied",
            ErrorCategory::Unsafe,
            "cloud_helper_robotics_adapter_authority_denied",
            RetryClass::RetryWithNewAuthorization,
        ),
        (
            "cloud_helper_physical_action_authority_denied",
            ErrorCategory::Unsafe,
            "cloud_helper_physical_action_authority_denied",
            RetryClass::RetryWithNewAuthorization,
        ),
    ] {
        let taxonomy = WorkOrderValidationError::Malformed {
            reason: reason.to_string(),
        }
        .taxonomy();
        assert_eq!(taxonomy.category, category, "{reason} category");
        assert_eq!(taxonomy.reason_code.as_str(), code);
        assert_eq!(taxonomy.retry_class, retry, "{reason} retry");
        assert_eq!(taxonomy.effect_certainty, EffectCertainty::None);
    }
}
