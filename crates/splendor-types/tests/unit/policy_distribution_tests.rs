use super::*;
use serde::Serialize;
use time::{Duration, OffsetDateTime};

const KEY_ID: &str = "policy-test-key";
const SECRET: &[u8] = b"policy-test-secret";

fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::parse(
        "2026-07-12T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .expect("fixed policy validation time")
}

fn keyring() -> PolicyBundleKeyring {
    let mut keyring = PolicyBundleKeyring::new();
    keyring
        .insert_shared_secret(KEY_ID, SECRET)
        .expect("insert key");
    keyring
}

fn bundle() -> PolicyBundle {
    let now = fixed_now();
    PolicyBundle {
        schema_version: POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
        policy_bundle_id: PolicyBundleId::try_new("pol_test").expect("policy bundle id"),
        version: "2026.05.29".to_string(),
        tenant_id: TenantId::parse("10000000-0000-4000-8000-000000000001")
            .expect("fixed tenant id"),
        agent_id: None,
        issued_at: now - Duration::minutes(1),
        expires_at: now + Duration::hours(1),
        revocation: RevocationStatus::Active,
        degraded_mode: PolicyDegradedMode {
            allow_low_risk_cached: true,
            disconnected_low_risk_actions: vec!["read_battery".to_string()],
            disconnected_high_risk_actions: vec!["move_to_waypoint".to_string()],
            high_risk_disconnected_behavior: OfflineHighRiskBehavior::NeedsLocalIntervention,
        },
    }
}

fn context(bundle: &PolicyBundle) -> PolicyBundleValidationContext {
    PolicyBundleValidationContext {
        tenant_id: bundle.tenant_id.clone(),
        agent_id: bundle.agent_id.clone(),
        now: fixed_now(),
    }
}

#[test]
fn signed_policy_bundle_validates_and_preserves_trace_metadata() {
    let bundle = bundle();
    let envelope = PolicyBundleEnvelope::signed_with_shared_secret(bundle.clone(), KEY_ID, SECRET)
        .expect("signed policy bundle");

    let validated = validate_policy_bundle(&envelope, &context(&bundle), &keyring())
        .expect("validated policy bundle");

    assert_eq!(validated.bundle().policy_bundle_id.as_str(), "pol_test");
    let trace = PolicyBundleTraceContext::from(validated.bundle());
    assert_eq!(trace.policy_bundle_id.as_str(), "pol_test");
    assert_eq!(trace.version, "2026.05.29");
    assert!(trace.degraded_mode.allow_low_risk_cached);
    assert_eq!(
        trace.degraded_mode.disconnected_low_risk_actions,
        vec!["read_battery"]
    );
}

#[test]
fn policy_bundle_identity_and_keyring_inputs_validate_fail_closed() {
    assert_eq!(
        PolicyBundleId::try_new("   "),
        Err(PolicyBundleIdError::Empty)
    );

    let id = PolicyBundleId::try_new("pol_owned").expect("policy bundle id");
    let raw: String = id.into();
    assert_eq!(raw, "pol_owned");

    let mut keyring = PolicyBundleKeyring::new();
    let error = keyring
        .insert_shared_secret(" ", SECRET)
        .expect_err("empty key id denied");
    assert_eq!(error.reason_code(), "malformed_policy_bundle");

    let error = keyring
        .insert_shared_secret(KEY_ID, b"")
        .expect_err("empty shared secret denied");
    assert_eq!(error.reason_code(), "malformed_policy_bundle");

    let error = PolicyBundleEnvelope::signed_with_shared_secret(bundle(), KEY_ID, b"")
        .expect_err("empty signing secret denied");
    assert_eq!(error.reason_code(), "malformed_policy_bundle");
}

#[test]
fn unsigned_or_bad_signature_policy_bundle_fails_closed() {
    let bundle = bundle();
    let unsigned = PolicyBundleEnvelope {
        bundle: bundle.clone(),
        signature: None,
    };

    let error = validate_policy_bundle(&unsigned, &context(&bundle), &keyring())
        .expect_err("unsigned bundle denied");
    assert_eq!(error.reason_code(), "unsigned_policy_bundle");

    let mut signed =
        PolicyBundleEnvelope::signed_with_shared_secret(bundle.clone(), KEY_ID, SECRET)
            .expect("signed policy bundle");
    signed.signature.as_mut().expect("signature").signature = "bad".to_string();
    let error = validate_policy_bundle(&signed, &context(&bundle), &keyring())
        .expect_err("bad signature denied");
    assert_eq!(error.reason_code(), "bad_policy_signature");

    let mut empty_key =
        PolicyBundleEnvelope::signed_with_shared_secret(bundle.clone(), KEY_ID, SECRET)
            .expect("signed policy bundle");
    empty_key.signature.as_mut().expect("signature").key_id = " ".to_string();
    let error = validate_policy_bundle(&empty_key, &context(&bundle), &keyring())
        .expect_err("empty signature key denied");
    assert_eq!(error.reason_code(), "unsigned_policy_bundle");

    let mut empty_signature =
        PolicyBundleEnvelope::signed_with_shared_secret(bundle.clone(), KEY_ID, SECRET)
            .expect("signed policy bundle");
    empty_signature
        .signature
        .as_mut()
        .expect("signature")
        .signature = " ".to_string();
    let error = validate_policy_bundle(&empty_signature, &context(&bundle), &keyring())
        .expect_err("empty signature denied");
    assert_eq!(error.reason_code(), "unsigned_policy_bundle");

    let mut unknown_key =
        PolicyBundleEnvelope::signed_with_shared_secret(bundle.clone(), KEY_ID, SECRET)
            .expect("signed policy bundle");
    unknown_key.signature.as_mut().expect("signature").key_id = "unknown-policy-key".to_string();
    let error = validate_policy_bundle(&unknown_key, &context(&bundle), &keyring())
        .expect_err("unknown key denied");
    assert_eq!(error.reason_code(), "unknown_policy_signature_key");
}

#[test]
fn malformed_policy_bundle_shape_branches_fail_closed() {
    let mut malformed = bundle();
    malformed.schema_version = "splendor.policy_bundle.v0".to_string();
    let envelope = PolicyBundleEnvelope {
        bundle: malformed.clone(),
        signature: None,
    };
    let error = validate_policy_bundle(&envelope, &context(&malformed), &keyring())
        .expect_err("malformed bundle denied before signature trust");
    assert_eq!(error.reason_code(), "malformed_policy_bundle");

    let mut malformed = bundle();
    malformed.policy_bundle_id = PolicyBundleId("   ".to_string());
    let envelope = PolicyBundleEnvelope {
        bundle: malformed.clone(),
        signature: None,
    };
    let error = validate_policy_bundle(&envelope, &context(&malformed), &keyring())
        .expect_err("empty policy id denied before signature trust");
    assert_eq!(error.reason_code(), "malformed_policy_bundle");

    let mut malformed = bundle();
    malformed.version = " ".to_string();
    let envelope = PolicyBundleEnvelope {
        bundle: malformed.clone(),
        signature: None,
    };
    let error = validate_policy_bundle(&envelope, &context(&malformed), &keyring())
        .expect_err("empty policy version denied before signature trust");
    assert_eq!(error.reason_code(), "malformed_policy_bundle");

    let mut malformed = bundle();
    malformed.expires_at = malformed.issued_at;
    let envelope = PolicyBundleEnvelope {
        bundle: malformed.clone(),
        signature: None,
    };
    let error = validate_policy_bundle(&envelope, &context(&malformed), &keyring())
        .expect_err("non-increasing TTL denied before signature trust");
    assert_eq!(error.reason_code(), "malformed_policy_bundle");
}

#[test]
fn expired_revoked_and_wrong_scope_policy_bundles_fail_closed() {
    let mut expired = bundle();
    expired.issued_at = fixed_now() - Duration::hours(2);
    expired.expires_at = fixed_now() - Duration::hours(1);
    let envelope = PolicyBundleEnvelope::signed_with_shared_secret(expired.clone(), KEY_ID, SECRET)
        .expect("signed expired policy bundle");
    let error = validate_policy_bundle(&envelope, &context(&expired), &keyring())
        .expect_err("expired bundle denied");
    assert_eq!(error.reason_code(), "expired_policy_bundle");

    let mut revoked = bundle();
    revoked.revocation = RevocationStatus::Revoked {
        reason: "operator revoked".to_string(),
    };
    let envelope = PolicyBundleEnvelope::signed_with_shared_secret(revoked.clone(), KEY_ID, SECRET)
        .expect("signed revoked policy bundle");
    let error = validate_policy_bundle(&envelope, &context(&revoked), &keyring())
        .expect_err("revoked bundle denied");
    assert_eq!(error.reason_code(), "revoked_policy_bundle");

    let wrong_context = PolicyBundleValidationContext {
        tenant_id: TenantId::parse("10000000-0000-4000-8000-000000000009")
            .expect("fixed wrong tenant id"),
        agent_id: None,
        now: fixed_now(),
    };
    let good = bundle();
    let envelope = PolicyBundleEnvelope::signed_with_shared_secret(good.clone(), KEY_ID, SECRET)
        .expect("signed policy bundle");
    let error = validate_policy_bundle(&envelope, &wrong_context, &keyring())
        .expect_err("wrong tenant denied");
    assert_eq!(error.reason_code(), "incompatible_policy_bundle");

    let mut agent_scoped = bundle();
    let agent_id = AgentId::parse("20000000-0000-4000-8000-000000000002").expect("fixed agent id");
    agent_scoped.agent_id = Some(agent_id.clone());

    let tenant_only_context = PolicyBundleValidationContext {
        tenant_id: agent_scoped.tenant_id.clone(),
        agent_id: None,
        now: fixed_now(),
    };
    let envelope =
        PolicyBundleEnvelope::signed_with_shared_secret(agent_scoped.clone(), KEY_ID, SECRET)
            .expect("signed agent-scoped policy bundle");
    let error = validate_policy_bundle(&envelope, &tenant_only_context, &keyring())
        .expect_err("agent-scoped bundle needs an agent context");
    assert_eq!(error.reason_code(), "incompatible_policy_bundle");

    let wrong_agent_context = PolicyBundleValidationContext {
        tenant_id: agent_scoped.tenant_id.clone(),
        agent_id: Some(
            AgentId::parse("20000000-0000-4000-8000-000000000009").expect("fixed wrong agent id"),
        ),
        now: fixed_now(),
    };
    let envelope =
        PolicyBundleEnvelope::signed_with_shared_secret(agent_scoped.clone(), KEY_ID, SECRET)
            .expect("signed agent-scoped policy bundle");
    let error = validate_policy_bundle(&envelope, &wrong_agent_context, &keyring())
        .expect_err("wrong agent denied");
    assert_eq!(error.reason_code(), "incompatible_policy_bundle");

    let matching_agent_context = PolicyBundleValidationContext {
        tenant_id: agent_scoped.tenant_id.clone(),
        agent_id: Some(agent_id),
        now: fixed_now(),
    };
    validate_policy_bundle(&envelope, &matching_agent_context, &keyring())
        .expect("matching agent-scoped bundle is accepted");
}

#[test]
fn policy_bundle_serde_defaults_are_stable_and_trace_safe() {
    let mut value = serde_json::to_value(bundle()).expect("bundle json");
    let object = value.as_object_mut().expect("bundle object");
    object.remove("schema_version");
    object.remove("agent_id");
    object.remove("revocation");
    object.remove("degraded_mode");

    let decoded: PolicyBundle = serde_json::from_value(value).expect("defaulted bundle");

    assert_eq!(decoded.schema_version, POLICY_BUNDLE_SCHEMA_VERSION);
    assert_eq!(decoded.agent_id, None);
    assert_eq!(decoded.revocation, RevocationStatus::Active);
    assert!(!decoded.degraded_mode.allow_low_risk_cached);
    assert!(decoded
        .degraded_mode
        .disconnected_low_risk_actions
        .is_empty());
    assert!(decoded
        .degraded_mode
        .disconnected_high_risk_actions
        .is_empty());
    assert_eq!(
        decoded.degraded_mode.high_risk_disconnected_behavior,
        OfflineHighRiskBehavior::Deny
    );

    let envelope = PolicyBundleEnvelope::signed_with_shared_secret(decoded.clone(), KEY_ID, SECRET)
        .expect("signed defaulted bundle");
    let validated = validate_policy_bundle(&envelope, &context(&decoded), &keyring())
        .expect("validated defaulted bundle");
    assert_eq!(validated.into_policy_bundle(), decoded);
}

#[test]
fn policy_distribution_exact_family_versions_fail_closed_independent_of_audit_version() {
    let current = bundle();
    let current_envelope =
        PolicyBundleEnvelope::signed_with_shared_secret(current.clone(), KEY_ID, SECRET)
            .expect("current v1 policy signs");
    validate_policy_bundle(&current_envelope, &context(&current), &keyring())
        .expect("current exact-family v1 policy validates");

    for unsupported in ["splendor.policy_bundle.v0", "splendor.policy_bundle.v2"] {
        let mut raw = serde_json::to_value(&current_envelope).expect("policy envelope json");
        raw["schema_version"] = serde_json::json!(unsupported);
        let envelope: PolicyBundleEnvelope =
            serde_json::from_value(raw).expect("unsupported raw policy remains parseable");
        let error = validate_policy_bundle(&envelope, &context(&envelope.bundle), &keyring())
            .expect_err("unsupported exact-family policy must not validate");
        assert_eq!(error.reason_code(), "malformed_policy_bundle");
        assert_eq!(
            error,
            PolicyBundleValidationError::Malformed {
                reason: format!("unsupported_schema_version:{unsupported}"),
            }
        );
    }

    let mut audit_label_only = current;
    audit_label_only.version = "splendor.policy_bundle.v0".to_string();
    let envelope =
        PolicyBundleEnvelope::signed_with_shared_secret(audit_label_only.clone(), KEY_ID, SECRET)
            .expect("audit version label does not select a schema");
    validate_policy_bundle(&envelope, &context(&audit_label_only), &keyring())
        .expect("schema compatibility uses schema_version, not version audit text");
}

#[test]
fn policy_distribution_future_issued_policy_uses_strict_fixed_clock_boundary() {
    let now = fixed_now();
    let mut boundary = bundle();
    boundary.issued_at = now;
    boundary.expires_at = now + Duration::hours(1);
    let envelope =
        PolicyBundleEnvelope::signed_with_shared_secret(boundary.clone(), KEY_ID, SECRET)
            .expect("boundary policy signs");
    validate_policy_bundle(
        &envelope,
        &PolicyBundleValidationContext {
            tenant_id: boundary.tenant_id.clone(),
            agent_id: boundary.agent_id.clone(),
            now,
        },
        &keyring(),
    )
    .expect("issued_at equal to validation time is allowed");

    let mut future = boundary;
    future.issued_at = now + Duration::nanoseconds(1);
    let envelope = PolicyBundleEnvelope::signed_with_shared_secret(future.clone(), KEY_ID, SECRET)
        .expect("future policy signs before receiver validation");
    let error = validate_policy_bundle(
        &envelope,
        &PolicyBundleValidationContext {
            tenant_id: future.tenant_id.clone(),
            agent_id: future.agent_id.clone(),
            now,
        },
        &keyring(),
    )
    .expect_err("any positive issuance skew must fail closed");
    assert_eq!(error, PolicyBundleValidationError::FutureIssued);
    assert_eq!(error.reason_code(), "future_issued_policy_bundle");
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct HistoricalPolicyDegradedModeV004 {
    allow_low_risk_cached: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct HistoricalPolicyBundleV004<'a> {
    schema_version: &'a str,
    policy_bundle_id: &'a PolicyBundleId,
    version: &'a str,
    tenant_id: &'a TenantId,
    agent_id: &'a Option<AgentId>,
    #[serde(with = "time::serde::rfc3339")]
    issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    revocation: &'a RevocationStatus,
    degraded_mode: HistoricalPolicyDegradedModeV004,
}

#[test]
fn policy_distribution_historical_v004_shaped_v1_signature_is_not_currently_compatible() {
    let bundle = bundle();
    let historical = HistoricalPolicyBundleV004 {
        schema_version: POLICY_BUNDLE_SCHEMA_VERSION,
        policy_bundle_id: &bundle.policy_bundle_id,
        version: &bundle.version,
        tenant_id: &bundle.tenant_id,
        agent_id: &bundle.agent_id,
        issued_at: bundle.issued_at,
        expires_at: bundle.expires_at,
        revocation: &bundle.revocation,
        degraded_mode: HistoricalPolicyDegradedModeV004 {
            allow_low_risk_cached: bundle.degraded_mode.allow_low_risk_cached,
        },
    };
    let historical_payload = serde_json::to_vec(&historical).expect("historical payload");
    let key = blake3::hash(SECRET);
    let signature = blake3::keyed_hash(key.as_bytes(), &historical_payload)
        .to_hex()
        .to_string();
    let mut raw = serde_json::to_value(&historical).expect("historical policy json");
    raw.as_object_mut()
        .expect("historical policy object")
        .insert(
            "signature".to_string(),
            serde_json::json!({"key_id": KEY_ID, "signature": signature}),
        );
    let envelope: PolicyBundleEnvelope =
        serde_json::from_value(raw).expect("historical v1 shape decodes with current defaults");

    assert!(envelope
        .bundle
        .degraded_mode
        .disconnected_low_risk_actions
        .is_empty());
    let error = validate_policy_bundle(&envelope, &context(&envelope.bundle), &keyring())
        .expect_err("current normalization changes the historical signed payload");
    assert_eq!(error, PolicyBundleValidationError::BadSignature);
    assert_eq!(error.reason_code(), "bad_policy_signature");
}
