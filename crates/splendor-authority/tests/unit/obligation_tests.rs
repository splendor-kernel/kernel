use super::*;
use crate::capability::unchecked_validated_grant_for_tests;
use crate::{evaluate_capability_request, gateway_action_operation};
use splendor_types::{
    AuthorityBudgetScope, AuthorityDecision, AuthorityDecisionId, AuthorityDecisionStatus,
    AuthorityObligation, AuthorityObligationKind, AuthorityObligationReceipt,
    AuthorityObligationReceiptId, AuthorityObligationReceiptValidation,
    AuthorityObligationReceiptValidationKind, CapabilityGrant, CapabilityGrantId,
    CapabilityGrantValidation, CapabilityGrantValidationKind, CapabilityRequest, CapabilityScope,
    PrincipalId, RevocationStatus, RunId, TenantId, AUTHORITY_DECISION_SCHEMA_VERSION,
    AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION, AUTHORITY_OBLIGATION_SCHEMA_VERSION,
    CAPABILITY_GRANT_SCHEMA_VERSION, CAPABILITY_REQUEST_SCHEMA_VERSION,
};
use time::OffsetDateTime;

const GRANT_DIGEST: &str =
    "blake3:4444444444444444444444444444444444444444444444444444444444444444";
const EVIDENCE_DIGEST: &str =
    "blake3:5555555555555555555555555555555555555555555555555555555555555555";
const PLACEHOLDER_DIGEST: &str =
    "blake3:0000000000000000000000000000000000000000000000000000000000000000";
const RECEIPT_AUDIENCE: &str = "daemon:local";
const RECEIPT_KEY_ID: &str = "receipt-key-1";
const RECEIPT_SECRET: &str = "receipt-secret-owned-by-service";
const RECEIPT_REVOCATION_REF: &str = "revocation:receipt-obligation-test";

fn scope(tenant_id: TenantId, run_id: RunId) -> CapabilityScope {
    CapabilityScope {
        tenant_ids: Some(vec![tenant_id]),
        run_ids: Some(vec![run_id]),
        audiences: Some(vec![RECEIPT_AUDIENCE.to_string()]),
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

fn validation_context(
    issuer: PrincipalId,
    now: OffsetDateTime,
) -> AuthorityObligationReceiptValidationContext {
    AuthorityObligationReceiptValidationContext::new(
        issuer,
        RECEIPT_AUDIENCE,
        RECEIPT_KEY_ID,
        RECEIPT_SECRET,
        RECEIPT_REVOCATION_REF,
        now,
    )
}

fn unsigned_receipt_for(
    decision: &AuthorityDecision,
    issuer: PrincipalId,
    now: OffsetDateTime,
) -> AuthorityObligationReceipt {
    let obligation = decision
        .obligations
        .first()
        .expect("conditional decision obligation");
    AuthorityObligationReceipt {
        schema_version: AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: AuthorityObligationReceiptId::new(),
        issuer,
        audience: RECEIPT_AUDIENCE.to_string(),
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
        revocation_ref: RECEIPT_REVOCATION_REF.to_string(),
        approval_id: None,
        approval_trace_event_id: None,
        validation: AuthorityObligationReceiptValidation {
            validation_kind: AuthorityObligationReceiptValidationKind::LocalSignature,
            algorithm: LOCAL_RECEIPT_VALIDATION_ALGORITHM.to_string(),
            key_id: RECEIPT_KEY_ID.to_string(),
            digest: PLACEHOLDER_DIGEST.to_string(),
            signature: PLACEHOLDER_DIGEST.to_string(),
        },
    }
}

fn sign_receipt(
    mut receipt: AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> AuthorityObligationReceipt {
    receipt.validation.digest =
        obligation_receipt_validation_digest(&receipt).expect("receipt digest");
    receipt.validation.signature =
        local_obligation_receipt_signature(&receipt, context).expect("receipt signature");
    receipt
}

fn validated_receipt_for(
    decision: &AuthorityDecision,
    issuer: PrincipalId,
    now: OffsetDateTime,
) -> ValidatedAuthorityObligationReceipt {
    let context = validation_context(issuer.clone(), now);
    validate_authority_obligation_receipt(
        sign_receipt(unsigned_receipt_for(decision, issuer, now), &context),
        &context,
    )
    .expect("validated receipt")
}

fn validate_signed(
    receipt: AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> ValidatedAuthorityObligationReceipt {
    validate_authority_obligation_receipt(sign_receipt(receipt, context), context)
        .expect("validated receipt")
}

fn assert_denied_with(
    decision: &AuthorityDecision,
    receipts: &[ValidatedAuthorityObligationReceipt],
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

fn assert_validation_denied(
    receipt: AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
    reason: &str,
) {
    let error = validate_authority_obligation_receipt(receipt, context)
        .expect_err("receipt validation should fail");
    assert_eq!(error.reason_code(), reason);
}

#[test]
fn obligation_receipt_validation_context_debug_redacts_secret() {
    let now = OffsetDateTime::now_utc();
    let context = validation_context(PrincipalId::new(), now);

    let rendered = format!("{context:?}");

    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains(RECEIPT_SECRET));
}

#[test]
fn obligation_receipt_verification_accepts_exact_matching_validated_receipt() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    assert_eq!(decision.status, AuthorityDecisionStatus::Conditional);
    assert_eq!(decision.reasons, vec!["capability_conditional"]);
    let issuer = PrincipalId::new();
    let receipt = validated_receipt_for(&decision, issuer, now);

    let verification = verify_obligation_receipts(&decision, &[receipt], now);

    assert!(verification.allowed);
    assert!(verification.reasons.is_empty());
    assert_eq!(
        verification.satisfied_obligation_ids,
        vec![decision.obligations[0].obligation_id.clone()]
    );
}

#[test]
fn raw_or_forged_obligation_receipts_do_not_validate_as_trusted() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let raw = unsigned_receipt_for(&decision, issuer.clone(), now);

    assert_validation_denied(
        raw.clone(),
        &context,
        "obligation_receipt_validation_digest_mismatch",
    );

    let forged_context = AuthorityObligationReceiptValidationContext::new(
        issuer,
        RECEIPT_AUDIENCE,
        RECEIPT_KEY_ID,
        "requester-supplied-secret",
        RECEIPT_REVOCATION_REF,
        now,
    );
    let forged = sign_receipt(raw, &forged_context);

    assert_validation_denied(forged, &context, "obligation_receipt_signature_mismatch");
}

#[test]
fn obligation_receipt_validation_rejects_wrong_issuer_audience_key_and_signature() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);

    let wrong_issuer_receipt = sign_receipt(
        unsigned_receipt_for(&decision, PrincipalId::new(), now),
        &context,
    );
    assert_validation_denied(
        wrong_issuer_receipt,
        &context,
        "obligation_receipt_issuer_mismatch",
    );

    let mut wrong_audience = unsigned_receipt_for(&decision, issuer.clone(), now);
    wrong_audience.audience = "daemon:other".to_string();
    let wrong_audience = sign_receipt(wrong_audience, &context);
    assert_validation_denied(
        wrong_audience,
        &context,
        "obligation_receipt_audience_mismatch",
    );

    let mut wrong_key = unsigned_receipt_for(&decision, issuer.clone(), now);
    wrong_key.validation.key_id = "receipt-key-2".to_string();
    let wrong_key = sign_receipt(wrong_key, &context);
    assert_validation_denied(wrong_key, &context, "obligation_receipt_key_mismatch");

    let mut wrong_signature = sign_receipt(unsigned_receipt_for(&decision, issuer, now), &context);
    wrong_signature.validation.signature = EVIDENCE_DIGEST.to_string();
    assert_validation_denied(
        wrong_signature,
        &context,
        "obligation_receipt_signature_mismatch",
    );
}

#[test]
fn obligation_receipt_verification_rejects_duplicate_and_extra_receipts() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let matching = validated_receipt_for(&decision, issuer.clone(), now);
    let duplicate_same_receipt = matching.clone();

    assert_denied_with(
        &decision,
        &[matching.clone(), duplicate_same_receipt],
        now,
        "duplicate_obligation_receipt_id",
    );
    assert_denied_with(
        &decision,
        &[matching.clone(), matching.clone()],
        now,
        "duplicate_obligation_receipt_obligation_id",
    );

    let mut duplicate_obligation = unsigned_receipt_for(&decision, issuer.clone(), now);
    duplicate_obligation.receipt_id = AuthorityObligationReceiptId::new();
    let duplicate_obligation = validate_signed(duplicate_obligation, &context);
    assert_denied_with(
        &decision,
        &[matching.clone(), duplicate_obligation],
        now,
        "duplicate_obligation_receipt_obligation_id",
    );

    let mut extra = unsigned_receipt_for(&decision, issuer, now);
    extra.receipt_id = AuthorityObligationReceiptId::new();
    extra.obligation_id = splendor_types::AuthorityObligationId::new();
    let extra = validate_signed(extra, &context);
    assert_denied_with(
        &decision,
        &[matching, extra],
        now,
        "extra_obligation_receipt",
    );
}

#[test]
fn obligation_receipt_verification_fails_closed_for_missing_and_mismatched_receipts() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let matching = unsigned_receipt_for(&decision, issuer.clone(), now);

    assert_denied_with(&decision, &[], now, "missing_obligation_receipt");

    let mut wrong_obligation = matching.clone();
    wrong_obligation.obligation_id = splendor_types::AuthorityObligationId::new();
    let wrong_obligation = validate_signed(wrong_obligation, &context);
    assert_denied_with(
        &decision,
        &[wrong_obligation],
        now,
        "obligation_receipt_id_mismatch",
    );

    let mut wrong_decision = matching.clone();
    wrong_decision.authority_decision_id = AuthorityDecisionId::new();
    let wrong_decision = validate_signed(wrong_decision, &context);
    assert_denied_with(
        &decision,
        &[wrong_decision],
        now,
        "obligation_receipt_decision_mismatch",
    );

    let mut wrong_subject = matching.clone();
    wrong_subject.subject = PrincipalId::new();
    let wrong_subject = validate_signed(wrong_subject, &context);
    assert_denied_with(
        &decision,
        &[wrong_subject],
        now,
        "obligation_receipt_subject_mismatch",
    );

    let mut wrong_kind = matching;
    wrong_kind.kind = AuthorityObligationKind::HumanReview;
    let wrong_kind = validate_signed(wrong_kind, &context);
    assert_denied_with(
        &decision,
        &[wrong_kind],
        now,
        "obligation_receipt_kind_mismatch",
    );
}

#[test]
fn obligation_receipt_validation_rejects_stale_revoked_and_malformed_receipts() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let matching = unsigned_receipt_for(&decision, issuer.clone(), now);

    let mut expired = matching.clone();
    expired.expires_at = now - time::Duration::seconds(1);
    let expired = sign_receipt(expired, &context);
    assert_validation_denied(expired, &context, "obligation_receipt_expired");

    let mut revoked = matching.clone();
    revoked.revocation = RevocationStatus::Revoked {
        reason: "approval_withdrawn".to_string(),
    };
    let revoked = sign_receipt(revoked, &context);
    assert_validation_denied(revoked, &context, "obligation_receipt_revoked");

    let mut wrong_revocation_ref = matching.clone();
    wrong_revocation_ref.revocation_ref = "revocation:other".to_string();
    let wrong_revocation_ref = sign_receipt(wrong_revocation_ref, &context);
    assert_validation_denied(
        wrong_revocation_ref,
        &context,
        "obligation_receipt_revocation_ref_mismatch",
    );

    let mut malformed_evidence = matching.clone();
    malformed_evidence.evidence_digest = "approved".to_string();
    let malformed_evidence = sign_receipt(malformed_evidence, &context);
    assert_validation_denied(
        malformed_evidence,
        &context,
        "obligation_receipt_evidence_digest_malformed",
    );

    let mut unsupported_schema = matching;
    unsupported_schema.schema_version = "splendor.authority.obligation_receipt.v0".to_string();
    let unsupported_schema = sign_receipt(unsupported_schema, &context);
    assert_validation_denied(
        unsupported_schema,
        &context,
        "obligation_receipt_schema_unsupported",
    );
}

#[test]
fn obligation_receipt_verification_rechecks_expiry_after_validation() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let mut receipt = unsigned_receipt_for(&decision, issuer, now);
    receipt.expires_at = now + time::Duration::seconds(1);
    let receipt = validate_signed(receipt, &context);

    assert_denied_with(
        &decision,
        &[receipt],
        now + time::Duration::seconds(2),
        "obligation_receipt_expired",
    );
}

#[test]
fn obligation_receipt_request_digest_changes_when_scope_or_params_change() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let mut receipt = unsigned_receipt_for(&decision, issuer, now);
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
    let receipt = validate_signed(receipt, &context);

    assert_denied_with(
        &decision,
        &[receipt],
        now,
        "obligation_receipt_request_digest_mismatch",
    );
}

#[test]
fn obligation_receipt_verification_rejects_duplicate_decision_obligations() {
    let now = OffsetDateTime::now_utc();
    let mut decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let receipt = validated_receipt_for(&decision, issuer, now);
    decision.obligations.push(decision.obligations[0].clone());

    assert_denied_with(
        &decision,
        &[receipt],
        now,
        "duplicate_authority_obligation_id",
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
