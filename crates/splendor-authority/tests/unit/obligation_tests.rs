use super::*;
use crate::capability::unchecked_validated_grant_for_tests;
use crate::{evaluate_capability_request, gateway_action_operation};
use splendor_types::{
    AuthorityBudgetScope, AuthorityDecision, AuthorityDecisionId, AuthorityDecisionStatus,
    AuthorityObligation, AuthorityObligationKind, AuthorityObligationReceipt, CapabilityGrant,
    CapabilityGrantId, CapabilityGrantValidation, CapabilityGrantValidationKind, CapabilityRequest,
    CapabilityScope, PrincipalId, RevocationStatus, RunId, TenantId,
    AUTHORITY_DECISION_SCHEMA_VERSION, AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION,
    AUTHORITY_OBLIGATION_SCHEMA_VERSION, CAPABILITY_GRANT_SCHEMA_VERSION,
    CAPABILITY_REQUEST_SCHEMA_VERSION,
};
use time::OffsetDateTime;

const GRANT_DIGEST: &str =
    "blake3:4444444444444444444444444444444444444444444444444444444444444444";
const EVIDENCE_DIGEST: &str =
    "blake3:5555555555555555555555555555555555555555555555555555555555555555";

fn scope(tenant_id: TenantId, run_id: RunId) -> CapabilityScope {
    CapabilityScope {
        tenant_ids: Some(vec![tenant_id]),
        run_ids: Some(vec![run_id]),
        audiences: Some(vec!["daemon:local".to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(2),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn grant(subject: PrincipalId, scope: CapabilityScope, now: OffsetDateTime) -> CapabilityGrant {
    CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: CapabilityGrantId::new(),
        issuer: PrincipalId::new(),
        subject,
        parent_grant_ids: Vec::new(),
        operations: vec![gateway_action_operation("artifact.publish")],
        scope,
        not_before: now - time::Duration::minutes(1),
        expires_at: now + time::Duration::minutes(30),
        revocation_ref: Some("revocation:obligation-test".to_string()),
        revocation: RevocationStatus::Active,
        obligations: Vec::new(),
        max_delegation_depth: 0,
        validation: Some(CapabilityGrantValidation {
            validation_kind: CapabilityGrantValidationKind::LocallyValidated,
            algorithm: "local-obligation-test-v1".to_string(),
            key_id: None,
            digest: GRANT_DIGEST.to_string(),
            signature: None,
        }),
        metadata: Default::default(),
    }
}

fn request(subject: PrincipalId, scope: CapabilityScope, now: OffsetDateTime) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject,
        operation: gateway_action_operation("artifact.publish"),
        scope,
        requested_at: now,
        metadata: Default::default(),
    }
}

fn obligation(kind: AuthorityObligationKind) -> AuthorityObligation {
    AuthorityObligation {
        schema_version: AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string(),
        obligation_id: splendor_types::AuthorityObligationId::new(),
        kind,
        description: "satisfy authority-owned obligation".to_string(),
        parameters: Default::default(),
    }
}

fn conditional_decision(now: OffsetDateTime) -> AuthorityDecision {
    let subject = PrincipalId::new();
    let tenant_id = TenantId::new();
    let run_id = RunId::new();
    let scope = scope(tenant_id, run_id);
    let mut grant = grant(subject.clone(), scope.clone(), now);
    grant.obligations = vec![obligation(AuthorityObligationKind::ApprovalRequired)];
    let request = request(subject, scope, now);

    evaluate_capability_request(&[unchecked_validated_grant_for_tests(grant)], &request, now)
}

fn receipt_for(decision: &AuthorityDecision, now: OffsetDateTime) -> AuthorityObligationReceipt {
    let obligation = decision
        .obligations
        .first()
        .expect("conditional decision obligation");
    AuthorityObligationReceipt {
        schema_version: AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION.to_string(),
        obligation_id: obligation.obligation_id.clone(),
        kind: obligation.kind,
        subject: decision.request.subject.clone(),
        authority_decision_id: decision.decision_id.clone(),
        canonical_request_digest: canonical_authority_request_digest(&decision.request)
            .expect("request digest"),
        evidence_digest: EVIDENCE_DIGEST.to_string(),
        evidence_ref: Some("approval-evidence:obligation-test".to_string()),
        issued_at: now - time::Duration::seconds(1),
        expires_at: now + time::Duration::minutes(10),
        revocation: RevocationStatus::Active,
        approval_id: None,
        approval_trace_event_id: None,
    }
}

fn assert_denied_with(
    decision: &AuthorityDecision,
    receipts: &[AuthorityObligationReceipt],
    now: OffsetDateTime,
    reason: &str,
) {
    let verification = verify_obligation_receipts(decision, receipts, now);
    assert!(!verification.allowed, "verification unexpectedly allowed");
    assert!(
        verification.reasons.contains(&reason.to_string()),
        "expected {reason}, got {:?}",
        verification.reasons
    );
}

#[test]
fn obligation_receipt_verification_accepts_exact_matching_receipt() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    assert_eq!(decision.status, AuthorityDecisionStatus::Conditional);
    assert_eq!(decision.reasons, vec!["capability_conditional"]);
    let receipt = receipt_for(&decision, now);

    let verification = verify_obligation_receipts(&decision, &[receipt], now);

    assert!(verification.allowed);
    assert!(verification.reasons.is_empty());
    assert_eq!(
        verification.satisfied_obligation_ids,
        vec![decision.obligations[0].obligation_id.clone()]
    );
}

#[test]
fn obligation_receipt_verification_fails_closed_for_missing_and_mismatched_receipts() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let matching = receipt_for(&decision, now);

    assert_denied_with(&decision, &[], now, "missing_obligation_receipt");

    let mut wrong_obligation = matching.clone();
    wrong_obligation.obligation_id = splendor_types::AuthorityObligationId::new();
    assert_denied_with(
        &decision,
        &[wrong_obligation],
        now,
        "obligation_receipt_id_mismatch",
    );

    let mut wrong_decision = matching.clone();
    wrong_decision.authority_decision_id = AuthorityDecisionId::new();
    assert_denied_with(
        &decision,
        &[wrong_decision],
        now,
        "obligation_receipt_decision_mismatch",
    );

    let mut wrong_subject = matching.clone();
    wrong_subject.subject = PrincipalId::new();
    assert_denied_with(
        &decision,
        &[wrong_subject],
        now,
        "obligation_receipt_subject_mismatch",
    );

    let mut wrong_kind = matching;
    wrong_kind.kind = AuthorityObligationKind::HumanReview;
    assert_denied_with(
        &decision,
        &[wrong_kind],
        now,
        "obligation_receipt_kind_mismatch",
    );
}

#[test]
fn obligation_receipt_verification_rejects_stale_revoked_and_malformed_receipts() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let matching = receipt_for(&decision, now);

    let mut expired = matching.clone();
    expired.expires_at = now - time::Duration::seconds(1);
    assert_denied_with(&decision, &[expired], now, "obligation_receipt_expired");

    let mut revoked = matching.clone();
    revoked.revocation = RevocationStatus::Revoked {
        reason: "approval_withdrawn".to_string(),
    };
    assert_denied_with(&decision, &[revoked], now, "obligation_receipt_revoked");

    let mut malformed_evidence = matching.clone();
    malformed_evidence.evidence_digest = "approved".to_string();
    assert_denied_with(
        &decision,
        &[malformed_evidence],
        now,
        "obligation_receipt_evidence_digest_malformed",
    );

    let mut unsupported_schema = matching;
    unsupported_schema.schema_version = "splendor.authority.obligation_receipt.v0".to_string();
    assert_denied_with(
        &decision,
        &[unsupported_schema],
        now,
        "obligation_receipt_schema_unsupported",
    );
}

#[test]
fn obligation_receipt_request_digest_changes_when_scope_or_params_change() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let mut receipt = receipt_for(&decision, now);
    let mut changed_request = decision.request.clone();
    changed_request.scope.budget.max_actions_per_tick = Some(1);
    changed_request.metadata.insert(
        "params_digest".to_string(),
        serde_json::json!(
            "blake3:6666666666666666666666666666666666666666666666666666666666666666"
        ),
    );

    receipt.canonical_request_digest =
        canonical_authority_request_digest(&changed_request).expect("changed digest");

    assert_denied_with(
        &decision,
        &[receipt],
        now,
        "obligation_receipt_request_digest_mismatch",
    );
}

#[test]
fn obligation_receipt_verification_denies_non_conditional_decisions() {
    let now = OffsetDateTime::now_utc();
    let subject = PrincipalId::new();
    let tenant_id = TenantId::new();
    let run_id = RunId::new();
    let scope = scope(tenant_id, run_id);
    let decision = AuthorityDecision {
        schema_version: AUTHORITY_DECISION_SCHEMA_VERSION.to_string(),
        decision_id: AuthorityDecisionId::new(),
        request: request(subject, scope, now),
        status: AuthorityDecisionStatus::Allowed,
        reasons: vec!["capability_allowed".to_string()],
        matched_grant_ids: Vec::new(),
        obligations: Vec::new(),
        decided_at: now,
    };

    let verification = verify_obligation_receipts(&decision, &[], now);

    assert!(!verification.allowed);
    assert_eq!(verification.reasons, vec!["decision_not_conditional"]);
}
