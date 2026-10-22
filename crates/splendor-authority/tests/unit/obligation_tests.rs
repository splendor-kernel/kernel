use super::*;
use crate::capability::unchecked_validated_grant_for_tests;
use crate::{
    compatibility_permission_operation, evaluate_capability_request, gateway_action_operation,
};
use splendor_types::{
    Action, ActionId, AgentId, ApprovalActionScope, ApprovalChallenge, ApprovalPolicy,
    AuthorityBudgetScope, AuthorityDecision, AuthorityDecisionId, AuthorityDecisionStatus,
    AuthorityObligation, AuthorityObligationKind, AuthorityObligationReceipt,
    AuthorityObligationReceiptId, AuthorityObligationReceiptValidation,
    AuthorityObligationReceiptValidationKind, CapabilityGrant, CapabilityGrantId,
    CapabilityGrantValidation, CapabilityGrantValidationKind, CapabilityRequest, CapabilityScope,
    PrincipalId, RevocationStatus, RunId, SideEffectClass, TenantId, TraceEventId,
    APPROVAL_CHALLENGE_SCHEMA_VERSION, AUTHORITY_DECISION_SCHEMA_VERSION,
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

#[derive(Debug)]
struct ScriptedReceiptClock {
    observations: std::sync::Mutex<std::collections::VecDeque<Option<OffsetDateTime>>>,
}

impl ScriptedReceiptClock {
    fn new(observations: impl IntoIterator<Item = Option<OffsetDateTime>>) -> Self {
        Self {
            observations: std::sync::Mutex::new(observations.into_iter().collect()),
        }
    }
}

impl AuthorityObligationReceiptClock for ScriptedReceiptClock {
    fn now_utc(&self) -> Option<OffsetDateTime> {
        self.observations.lock().ok()?.pop_front().flatten()
    }
}

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
    AuthorityObligationReceiptValidationContext::trusted_local(
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

fn approval_inputs(
    now: OffsetDateTime,
) -> (
    AuthorityDecision,
    ApprovalPolicy,
    TenantId,
    AgentId,
    RunId,
    ActionId,
    Action,
) {
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let action_id = ActionId::new();
    let subject = PrincipalId::new();
    let request_scope = scope(tenant_id.clone(), run_id.clone());
    let decision = evaluate_capability_request(
        &[unchecked_validated_grant_for_tests(grant(
            subject.clone(),
            request_scope.clone(),
            now,
        ))],
        &request(subject, request_scope, now),
        now,
    );
    let mut policy = ApprovalPolicy::new(
        "approval-policy-unit",
        tenant_id.clone(),
        "unit approval required",
    );
    policy.agent_id = Some(agent_id.clone());
    policy.action_name = Some("artifact.publish".to_string());
    policy.adapter = Some("artifact-store".to_string());
    let action = Action {
        name: "artifact.publish".to_string(),
        params: serde_json::json!({"artifact_ref": "artifact:unit"}),
        side_effect_class: SideEffectClass::External,
        cost_estimate: None,
        required_permissions: vec!["artifact.publish".to_string()],
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    };
    (
        decision, policy, tenant_id, agent_id, run_id, action_id, action,
    )
}

fn apply_approval_for_test(
    decision: AuthorityDecision,
    policies: &[ApprovalPolicy],
    action_scope: ApprovalActionScope<'_>,
    now: OffsetDateTime,
    digest: &str,
    audience: &str,
    authority_expires_at: OffsetDateTime,
) -> AuthorityDecision {
    apply_approval_policy_obligation(
        decision,
        policies,
        ApprovalObligationContext {
            action_scope,
            gateway_action_request_digest: digest,
            receipt_audience: audience,
            authority_expires_at,
            action_requested_at: now,
            now,
        },
    )
}

fn approval_scope_for_test<'a>(
    tenant_id: &'a TenantId,
    agent_id: &'a AgentId,
    run_id: &'a RunId,
    action_id: &'a ActionId,
    action: &'a Action,
) -> ApprovalActionScope<'a> {
    ApprovalActionScope {
        tenant_id,
        agent_id,
        run_id,
        action_id,
        action,
        adapter: Some("artifact-store"),
    }
}

#[test]
fn obligation_receipt_validation_context_debug_redacts_secret() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);

    let rendered = format!("{context:?}");

    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains(RECEIPT_SECRET));
    assert_eq!(context.issuer(), &issuer);
    assert_eq!(context.audience(), RECEIPT_AUDIENCE);
    assert_eq!(context.key_id(), RECEIPT_KEY_ID);
    assert_eq!(context.revocation_ref(), RECEIPT_REVOCATION_REF);
    assert_eq!(context.now(), now);
    assert_eq!(
        context.at_time(now + time::Duration::seconds(1)).now(),
        now + time::Duration::seconds(1)
    );
}

#[test]
fn obligation_receipt_internal_rechecks_cover_every_fail_closed_fact() {
    let now = OffsetDateTime::now_utc();
    let mut decision = conditional_decision(now);
    decision.request.scope.audiences = None;
    let expected_request_digest =
        canonical_authority_request_digest(&decision.request).expect("request digest");
    let mut receipt = unsigned_receipt_for(&decision, PrincipalId::new(), now);
    receipt.schema_version = "splendor.authority_obligation_receipt.v0".to_string();
    receipt.subject = PrincipalId::new();
    receipt.authority_decision_id = AuthorityDecisionId::new();
    receipt.canonical_request_digest = "malformed".to_string();
    receipt.evidence_digest = "malformed".to_string();
    receipt.evidence_ref = Some("unsafe:*".to_string());
    receipt.issued_at = now + time::Duration::minutes(1);
    receipt.expires_at = now - time::Duration::minutes(1);
    receipt.revocation = RevocationStatus::Revoked {
        reason: "unit revocation".to_string(),
    };
    let mut reasons = Vec::new();
    validate_receipt_against_decision(
        &receipt,
        &decision,
        &expected_request_digest,
        now,
        &mut reasons,
    );
    for expected in [
        "obligation_receipt_schema_unsupported",
        "obligation_receipt_subject_mismatch",
        "obligation_receipt_decision_mismatch",
        "obligation_receipt_audience_mismatch",
        "obligation_receipt_request_digest_malformed",
        "obligation_receipt_evidence_digest_malformed",
        "obligation_receipt_evidence_ref_malformed",
        "obligation_receipt_not_yet_valid",
        "obligation_receipt_expired",
        "obligation_receipt_revoked",
    ] {
        assert!(
            reasons.contains(&expected.to_string()),
            "missing {expected}"
        );
    }

    let receipt_id = AuthorityObligationReceiptId::new();
    let permit = AuthorityObligationEffectPermit {
        receipt_ids: vec![receipt_id.clone()],
    };
    assert_eq!(permit.receipt_ids(), &[receipt_id]);
    assert_eq!(
        ObligationReceiptError::RequestDigestUnavailable {
            reason: "unit".to_string(),
        }
        .reason_code(),
        "request_digest_unavailable"
    );
    assert_eq!(
        ObligationReceiptError::ReceiptValidationDigestUnavailable {
            reason: "unit".to_string(),
        }
        .reason_code(),
        "obligation_receipt_validation_digest_unavailable"
    );
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

    let forged_context = AuthorityObligationReceiptValidationContext::trusted_local(
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

    let mut future = matching.clone();
    future.issued_at = now + time::Duration::seconds(1);
    future.expires_at = now + time::Duration::minutes(1);
    assert_validation_denied(
        sign_receipt(future, &context),
        &context,
        "obligation_receipt_not_yet_valid",
    );

    let mut unsafe_reference = matching.clone();
    unsafe_reference.evidence_ref = Some("approval-evidence:*".to_string());
    assert_validation_denied(
        sign_receipt(unsafe_reference, &context),
        &context,
        "obligation_receipt_evidence_ref_malformed",
    );

    let mut wrong_algorithm = matching.clone();
    wrong_algorithm.validation.algorithm = "unsupported".to_string();
    assert_validation_denied(
        sign_receipt(wrong_algorithm, &context),
        &context,
        "obligation_receipt_algorithm_mismatch",
    );

    let mut malformed_token = matching.clone();
    malformed_token.audience = " invalid ".to_string();
    assert_validation_denied(
        sign_receipt(malformed_token, &context),
        &context,
        "obligation_receipt_token_malformed",
    );

    let malformed_context = AuthorityObligationReceiptValidationContext::trusted_local(
        issuer.clone(),
        RECEIPT_AUDIENCE,
        RECEIPT_KEY_ID,
        RECEIPT_SECRET,
        " invalid ",
        now,
    );
    assert_validation_denied(
        sign_receipt(matching.clone(), &context),
        &malformed_context,
        "obligation_receipt_token_malformed",
    );

    let mut malformed_key = sign_receipt(matching.clone(), &context);
    malformed_key.validation.key_id = " invalid ".to_string();
    assert_validation_denied(
        malformed_key,
        &context,
        "obligation_receipt_token_malformed",
    );

    let mut malformed_validation_digest = sign_receipt(matching.clone(), &context);
    malformed_validation_digest.validation.digest = "invalid".to_string();
    assert_validation_denied(
        malformed_validation_digest,
        &context,
        "obligation_receipt_validation_digest_malformed",
    );

    let mut malformed_signature = sign_receipt(matching.clone(), &context);
    malformed_signature.validation.signature = "invalid".to_string();
    assert_validation_denied(
        malformed_signature,
        &context,
        "obligation_receipt_signature_malformed",
    );

    let mut wildcard_digest = matching.clone();
    wildcard_digest.canonical_request_digest = format!("blake3:{}", "*".repeat(64));
    assert_validation_denied(
        sign_receipt(wildcard_digest, &context),
        &context,
        "obligation_receipt_request_digest_malformed",
    );

    let unavailable_context = AuthorityObligationReceiptValidationContext::trusted_local(
        issuer,
        RECEIPT_AUDIENCE,
        RECEIPT_KEY_ID,
        "",
        RECEIPT_REVOCATION_REF,
        now,
    );
    assert_validation_denied(
        sign_receipt(matching.clone(), &unavailable_context),
        &unavailable_context,
        "obligation_receipt_validation_secret_unavailable",
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
fn caller_time_inversion_does_not_create_receipt_ledger_clock_rollback() {
    let now = OffsetDateTime::now_utc();
    let first_decision = conditional_decision(now);
    let second_decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let first_receipt = sign_receipt(
        unsigned_receipt_for(&first_decision, issuer.clone(), now),
        &context,
    );
    let second_receipt = sign_receipt(
        unsigned_receipt_for(&second_decision, issuer, now),
        &context,
    );
    let ledger = InMemoryAuthorityObligationReceiptLedger::with_clock(std::sync::Arc::new(
        ScriptedReceiptClock::new([
            Some(now + time::Duration::seconds(1)),
            Some(now + time::Duration::seconds(2)),
        ]),
    ));

    ledger
        .validate_receipts(
            std::slice::from_ref(&first_receipt),
            &context,
            now + time::Duration::hours(1),
        )
        .expect("first authentic receipt validates");
    ledger
        .validate_receipts(
            std::slice::from_ref(&second_receipt),
            &context,
            now - time::Duration::hours(1),
        )
        .expect("inverted legacy caller time is non-authoritative");
}

#[test]
fn local_receipt_ledger_rejects_real_clock_rollback_without_terminal_mutation() {
    let now = OffsetDateTime::now_utc();
    let first_decision = conditional_decision(now);
    let second_decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let first_receipt = sign_receipt(
        unsigned_receipt_for(&first_decision, issuer.clone(), now),
        &context,
    );
    let second_receipt = sign_receipt(
        unsigned_receipt_for(&second_decision, issuer, now),
        &context,
    );
    let forward = now + time::Duration::seconds(2);
    let ledger = InMemoryAuthorityObligationReceiptLedger::with_clock(std::sync::Arc::new(
        ScriptedReceiptClock::new([
            Some(forward),
            Some(now + time::Duration::seconds(1)),
            Some(now + time::Duration::seconds(3)),
        ]),
    ));

    ledger
        .validate_receipts(std::slice::from_ref(&first_receipt), &context, now)
        .expect("forward trusted-clock observation");
    let rollback = ledger
        .revoke_receipt(&second_receipt, &context, now)
        .expect_err("actual trusted-clock rollback denied");
    assert_eq!(
        rollback.reason_code(),
        "authority_obligation_receipt_clock_rollback"
    );
    {
        let state = ledger.state.lock().expect("ledger state");
        assert_eq!(state.max_observed_time, Some(forward));
        assert!(state.receipt_terminal_states.is_empty());
        assert!(state.semantic_terminal_states.is_empty());
        assert!(state.expired_receipts.is_empty());
    }
    ledger
        .claim_receipts(std::slice::from_ref(&second_receipt), &context, now)
        .expect("rollback attempt did not revoke or claim receipt");
}

#[test]
fn local_receipt_ledger_latches_expiry_across_real_clock_rollback() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let receipt = sign_receipt(unsigned_receipt_for(&decision, issuer, now), &context);
    let ledger = InMemoryAuthorityObligationReceiptLedger::with_clock(std::sync::Arc::new(
        ScriptedReceiptClock::new([Some(receipt.expires_at), Some(now)]),
    ));

    let expiry = ledger
        .validate_receipts(std::slice::from_ref(&receipt), &context, now)
        .expect_err("expiry denied");
    assert_eq!(expiry.reason_code(), "obligation_receipt_expired");
    let rolled_back_after_expiry = ledger
        .claim_receipts(&[receipt], &context, now)
        .expect_err("latched expiry denied");
    assert_eq!(
        rolled_back_after_expiry.reason_code(),
        "obligation_receipt_expired"
    );
}

#[test]
fn unavailable_receipt_ledger_clock_fails_closed_without_mutation() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let receipt = sign_receipt(unsigned_receipt_for(&decision, issuer, now), &context);
    let ledger = InMemoryAuthorityObligationReceiptLedger::with_clock(std::sync::Arc::new(
        ScriptedReceiptClock::new([None]),
    ));

    let error = ledger
        .claim_receipts(std::slice::from_ref(&receipt), &context, now)
        .expect_err("missing trusted time fails closed");

    assert_eq!(
        error.reason_code(),
        "authority_obligation_receipt_replay_state_unavailable"
    );
    assert!(error.is_unavailable());
    let state = ledger.state.lock().expect("ledger state");
    assert!(state.max_observed_time.is_none());
    assert!(state.receipt_terminal_states.is_empty());
    assert!(state.semantic_terminal_states.is_empty());
    assert!(state.expired_receipts.is_empty());
}

#[test]
fn receipt_revocation_and_claim_share_one_terminal_ledger_state() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let receipt = sign_receipt(unsigned_receipt_for(&decision, issuer, now), &context);

    let revoked_first = InMemoryAuthorityObligationReceiptLedger::default();
    assert_eq!(
        revoked_first
            .revoke_receipt(&receipt, &context, now)
            .expect("first revoke"),
        AuthorityObligationReceiptRevocationOutcome::Revoked
    );
    assert_eq!(
        revoked_first
            .revoke_receipt(&receipt, &context, now)
            .expect("duplicate revoke"),
        AuthorityObligationReceiptRevocationOutcome::AlreadyRevoked
    );
    assert_eq!(
        revoked_first
            .claim_receipts(std::slice::from_ref(&receipt), &context, now)
            .expect_err("revoked receipt cannot be claimed")
            .reason_code(),
        "authority_obligation_receipt_revoked"
    );

    let claimed_first = InMemoryAuthorityObligationReceiptLedger::default();
    claimed_first
        .claim_receipts(std::slice::from_ref(&receipt), &context, now)
        .expect("first claim");
    assert_eq!(
        claimed_first
            .revoke_receipt(&receipt, &context, now)
            .expect("late revoke has known result"),
        AuthorityObligationReceiptRevocationOutcome::AlreadyClaimed
    );
}

#[derive(Debug)]
struct LedgerWithoutRevocation;

impl AuthorityObligationReceiptLedger for LedgerWithoutRevocation {
    fn validate_receipts(
        &self,
        _receipts: &[AuthorityObligationReceipt],
        _context: &AuthorityObligationReceiptValidationContext,
        _now: OffsetDateTime,
    ) -> Result<Vec<ValidatedAuthorityObligationReceipt>, ObligationReceiptLedgerError> {
        Err(ObligationReceiptLedgerError::Unavailable)
    }

    fn claim_receipts(
        &self,
        _receipts: &[AuthorityObligationReceipt],
        _context: &AuthorityObligationReceiptValidationContext,
        _now: OffsetDateTime,
    ) -> Result<AuthorityObligationEffectPermit, ObligationReceiptLedgerError> {
        Err(ObligationReceiptLedgerError::Unavailable)
    }
}

#[test]
fn receipt_ledger_without_revocation_support_fails_closed() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let receipt = sign_receipt(unsigned_receipt_for(&decision, issuer, now), &context);

    let error = LedgerWithoutRevocation
        .revoke_receipt(&receipt, &context, now)
        .expect_err("unsupported revocation cannot report success");

    assert_eq!(
        error.reason_code(),
        "authority_obligation_receipt_replay_state_unavailable"
    );
    assert!(error.is_unavailable());
}

#[test]
fn semantic_duplicate_claim_is_atomic_and_corrupt_terminal_state_fails_closed() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let receipt = sign_receipt(
        unsigned_receipt_for(&decision, issuer.clone(), now),
        &context,
    );
    let mut semantic_reissue = receipt.clone();
    semantic_reissue.receipt_id = AuthorityObligationReceiptId::new();
    let semantic_reissue = sign_receipt(semantic_reissue, &context);
    let ledger = InMemoryAuthorityObligationReceiptLedger::default();

    let duplicate = ledger
        .claim_receipts(&[receipt.clone(), semantic_reissue], &context, now)
        .expect_err("one request cannot claim the same semantic approval twice");
    assert_eq!(
        duplicate.reason_code(),
        "authority_obligation_receipt_replayed"
    );
    ledger
        .claim_receipts(std::slice::from_ref(&receipt), &context, now)
        .expect("duplicate-set rejection does not partially claim");

    let corrupt = InMemoryAuthorityObligationReceiptLedger::default();
    let semantic_key =
        authority_obligation_receipt_semantic_claim_key(&receipt).expect("semantic receipt key");
    {
        let mut state = corrupt.state.lock().expect("ledger state");
        state.receipt_terminal_states.insert(
            receipt.receipt_id.to_string(),
            ReceiptTerminalState::Claimed,
        );
        state
            .semantic_terminal_states
            .insert(semantic_key, ReceiptTerminalState::Revoked);
    }
    let error = corrupt
        .revoke_receipt(&receipt, &context, now)
        .expect_err("conflicting authority tombstones fail closed");
    assert_eq!(
        error.reason_code(),
        "authority_obligation_receipt_replay_state_unavailable"
    );
}

#[test]
fn semantic_reissue_inherits_revocation_and_wrong_target_does_not_poison_receipt() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let receipt = sign_receipt(
        unsigned_receipt_for(&decision, issuer.clone(), now),
        &context,
    );
    let mut reissue = receipt.clone();
    reissue.receipt_id = AuthorityObligationReceiptId::new();
    let reissue = sign_receipt(reissue, &context);
    let ledger = InMemoryAuthorityObligationReceiptLedger::default();

    let wrong_target = AuthorityObligationReceiptValidationContext::trusted_local(
        issuer,
        "daemon:wrong-target",
        RECEIPT_KEY_ID,
        RECEIPT_SECRET,
        RECEIPT_REVOCATION_REF,
        now,
    );
    assert!(matches!(
        ledger.revoke_receipt(&receipt, &wrong_target, now),
        Err(ObligationReceiptLedgerError::Validation(_))
    ));
    ledger
        .validate_receipts(std::slice::from_ref(&receipt), &context, now)
        .expect("wrong-target rejection did not poison the valid receipt");

    assert_eq!(
        ledger
            .revoke_receipt(&receipt, &context, now)
            .expect("valid target revoke"),
        AuthorityObligationReceiptRevocationOutcome::Revoked
    );
    assert_eq!(
        ledger
            .revoke_receipt(&reissue, &context, now)
            .expect("semantic duplicate revoke"),
        AuthorityObligationReceiptRevocationOutcome::AlreadyRevoked
    );
    assert_eq!(
        ledger
            .claim_receipts(std::slice::from_ref(&reissue), &context, now)
            .expect_err("semantic reissue remains revoked")
            .reason_code(),
        "authority_obligation_receipt_revoked"
    );
}

#[test]
fn forged_expired_same_id_receipts_cannot_poison_a_later_valid_receipt() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer, now);
    let valid = sign_receipt(
        unsigned_receipt_for(&decision, context.issuer().clone(), now),
        &context,
    );
    let ledger = InMemoryAuthorityObligationReceiptLedger::default();

    let mut bad_signature = valid.clone();
    bad_signature.expires_at = now - time::Duration::seconds(1);
    bad_signature = sign_receipt(bad_signature, &context);
    bad_signature.validation.signature = format!("blake3:{}", "0".repeat(64));
    let error = ledger
        .validate_receipts(std::slice::from_ref(&bad_signature), &context, now)
        .expect_err("forged expired receipt rejected before expiry latch");
    assert_eq!(error.reason_code(), "obligation_receipt_signature_mismatch");

    let mut wrong_audience = valid.clone();
    wrong_audience.audience = "daemon:wrong-target".to_string();
    wrong_audience.expires_at = now - time::Duration::seconds(1);
    wrong_audience = sign_receipt(wrong_audience, &context);
    let error = ledger
        .validate_receipts(std::slice::from_ref(&wrong_audience), &context, now)
        .expect_err("wrong-audience expired receipt rejected before expiry latch");
    assert_eq!(error.reason_code(), "obligation_receipt_audience_mismatch");

    ledger
        .claim_receipts(std::slice::from_ref(&valid), &context, now)
        .expect("the authentic same-ID receipt remains claimable");
}

#[test]
fn failed_receipt_set_authentication_claims_nothing() {
    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer, now);
    let first = sign_receipt(
        unsigned_receipt_for(&decision, context.issuer().clone(), now),
        &context,
    );
    let mut forged_second = first.clone();
    forged_second.receipt_id = AuthorityObligationReceiptId::new();
    forged_second = sign_receipt(forged_second, &context);
    forged_second.validation.signature = format!("blake3:{}", "f".repeat(64));
    let ledger = InMemoryAuthorityObligationReceiptLedger::default();

    let error = ledger
        .claim_receipts(&[first.clone(), forged_second], &context, now)
        .expect_err("one forged member rejects the complete set");
    assert_eq!(error.reason_code(), "obligation_receipt_signature_mismatch");
    ledger
        .claim_receipts(std::slice::from_ref(&first), &context, now)
        .expect("failed set validation did not partially claim the valid member");
}

#[test]
fn concurrent_receipt_claim_and_revoke_have_exactly_one_winner() {
    use std::sync::{Arc, Barrier};

    let now = OffsetDateTime::now_utc();
    let decision = conditional_decision(now);
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let receipt = sign_receipt(unsigned_receipt_for(&decision, issuer, now), &context);
    let ledger = Arc::new(InMemoryAuthorityObligationReceiptLedger::with_clock(
        Arc::new(ScriptedReceiptClock::new([
            Some(now + time::Duration::seconds(1)),
            Some(now + time::Duration::seconds(2)),
        ])),
    ));
    let barrier = Arc::new(Barrier::new(2));

    let claim = {
        let ledger = Arc::clone(&ledger);
        let barrier = Arc::clone(&barrier);
        let context = context.clone();
        let receipt = receipt.clone();
        std::thread::spawn(move || {
            barrier.wait();
            ledger.claim_receipts(&[receipt], &context, now)
        })
    };
    let revoke = {
        let ledger = Arc::clone(&ledger);
        let barrier = Arc::clone(&barrier);
        let context = context.clone();
        let receipt = receipt.clone();
        std::thread::spawn(move || {
            barrier.wait();
            ledger.revoke_receipt(&receipt, &context, now)
        })
    };

    let claim = claim.join().expect("claim thread");
    let revoke = revoke.join().expect("revoke thread");
    match (claim, revoke) {
        (Ok(_), Ok(AuthorityObligationReceiptRevocationOutcome::AlreadyClaimed)) => {}
        (
            Err(ObligationReceiptLedgerError::Revoked),
            Ok(AuthorityObligationReceiptRevocationOutcome::Revoked),
        ) => {}
        other => panic!("claim/revoke produced inconsistent winners: {other:?}"),
    }
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

    let mut missing_obligations = decision;
    missing_obligations.status = AuthorityDecisionStatus::Conditional;
    let verification = verify_obligation_receipts(&missing_obligations, &[], now);
    assert_eq!(
        verification.reasons,
        vec!["conditional_decision_missing_obligations"]
    );
}

#[test]
fn approval_receipt_requires_exact_identity_and_trace_evidence() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let context = validation_context(issuer.clone(), now);
    let expected_approval_id = ApprovalId::new();

    let mut malformed_identity = conditional_decision(now);
    malformed_identity.obligations[0].parameters.insert(
        APPROVAL_OBLIGATION_APPROVAL_ID.to_string(),
        serde_json::Value::String("not-an-approval-id".to_string()),
    );
    let mut receipt = unsigned_receipt_for(&malformed_identity, issuer.clone(), now);
    receipt.approval_id = Some(expected_approval_id.clone());
    receipt.approval_trace_event_id = Some(TraceEventId::new());
    let receipt = validate_signed(receipt, &context);
    assert_denied_with(
        &malformed_identity,
        &[receipt],
        now,
        "approval_obligation_identity_missing",
    );

    let mut mismatched_identity = conditional_decision(now);
    mismatched_identity.obligations[0].parameters.insert(
        APPROVAL_OBLIGATION_APPROVAL_ID.to_string(),
        serde_json::Value::String(expected_approval_id.to_string()),
    );
    let mut receipt = unsigned_receipt_for(&mismatched_identity, issuer.clone(), now);
    receipt.approval_id = Some(ApprovalId::new());
    receipt.approval_trace_event_id = Some(TraceEventId::new());
    let receipt = validate_signed(receipt, &context);
    assert_denied_with(
        &mismatched_identity,
        &[receipt],
        now,
        "obligation_receipt_approval_id_mismatch",
    );

    let mut missing_trace = unsigned_receipt_for(&mismatched_identity, issuer, now);
    missing_trace.approval_id = Some(expected_approval_id);
    let missing_trace = validate_signed(missing_trace, &context);
    assert_denied_with(
        &mismatched_identity,
        &[missing_trace],
        now,
        "obligation_receipt_approval_trace_missing",
    );
}

#[test]
fn local_approval_receipt_config_and_challenge_fail_closed_boundaries_are_covered() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let secret = "0123456789abcdef0123456789abcdef";
    let config = LocalAuthorityObligationReceiptConfig::trusted_local(
        issuer.clone(),
        "daemon",
        RECEIPT_KEY_ID,
        secret,
        RECEIPT_REVOCATION_REF,
    )
    .expect("trusted local approval receipt config");
    let rendered = format!("{config:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains(secret));
    let nil_instance = splendor_types::InstanceId::parse("00000000-0000-0000-0000-000000000000")
        .expect("nil instance parses for validation");
    assert_eq!(
        config
            .for_resident_instance(&nil_instance)
            .expect_err("nil resident target rejected")
            .reason_code(),
        "obligation_receipt_resident_instance_invalid"
    );

    let nil_issuer = PrincipalId::parse("00000000-0000-0000-0000-000000000000")
        .expect("nil principal parses for validation");
    for error in [
        LocalAuthorityObligationReceiptConfig::trusted_local(
            nil_issuer,
            "daemon",
            RECEIPT_KEY_ID,
            secret,
            RECEIPT_REVOCATION_REF,
        )
        .expect_err("nil issuer rejected"),
        LocalAuthorityObligationReceiptConfig::trusted_local(
            issuer.clone(),
            " invalid ",
            RECEIPT_KEY_ID,
            secret,
            RECEIPT_REVOCATION_REF,
        )
        .expect_err("invalid audience rejected"),
        LocalAuthorityObligationReceiptConfig::trusted_local(
            issuer.clone(),
            "daemon",
            " invalid ",
            secret,
            RECEIPT_REVOCATION_REF,
        )
        .expect_err("invalid key rejected"),
        LocalAuthorityObligationReceiptConfig::trusted_local(
            issuer.clone(),
            "daemon",
            RECEIPT_KEY_ID,
            "too-short",
            RECEIPT_REVOCATION_REF,
        )
        .expect_err("short secret rejected"),
        LocalAuthorityObligationReceiptConfig::trusted_local(
            issuer.clone(),
            "daemon",
            RECEIPT_KEY_ID,
            secret,
            " invalid ",
        )
        .expect_err("invalid revocation ref rejected"),
    ] {
        assert!(!error.reason_code().is_empty());
    }

    let (decision, policy, tenant_id, agent_id, run_id, action_id, action) = approval_inputs(now);
    let conditional = apply_approval_for_test(
        decision,
        &[policy],
        approval_scope_for_test(&tenant_id, &agent_id, &run_id, &action_id, &action),
        now,
        &format!("blake3:{}", "6".repeat(64)),
        &config.audience_for_run(&run_id),
        now + time::Duration::minutes(10),
    );
    let approval_id = ApprovalId::parse(
        conditional.obligations[0].parameters[APPROVAL_OBLIGATION_APPROVAL_ID]
            .as_str()
            .expect("approval parameter"),
    )
    .expect("approval id");
    let challenge = ApprovalChallenge {
        schema_version: APPROVAL_CHALLENGE_SCHEMA_VERSION.to_string(),
        approval_id,
        tenant_id,
        agent_id,
        run_id: run_id.clone(),
        action_id,
        action_name: action.name,
        adapter: "artifact-store".to_string(),
        policy_id: "approval-policy-unit".to_string(),
        risk_level: None,
        subject: conditional.request.subject.clone(),
        authority_decision_id: conditional.decision_id.clone(),
        obligation_id: conditional.obligations[0].obligation_id.clone(),
        receipt_audience: config.audience_for_run(&run_id),
        canonical_request_digest: canonical_authority_request_digest(&conditional.request)
            .expect("canonical request digest"),
        gateway_action_request_digest: format!("blake3:{}", "6".repeat(64)),
        physical_action_resource_coordinate: None,
        authority_decision_digest: format!("blake3:{}", "7".repeat(64)),
        requested_at: now,
        expires_at: now + time::Duration::minutes(5),
    };
    config
        .validate_approval_challenge(&challenge, now)
        .expect("valid challenge");
    let trace_id = TraceEventId::new();
    let receipt = config
        .issue_approval_receipt(&challenge, trace_id.clone(), now)
        .expect("approval receipt");
    assert_eq!(receipt.approval_trace_event_id, Some(trace_id));

    for (mut invalid, reason) in [
        (
            ApprovalChallenge {
                schema_version: "splendor.approval_challenge.v0".to_string(),
                ..challenge.clone()
            },
            "approval_challenge_schema_unsupported",
        ),
        (
            ApprovalChallenge {
                action_name: " ".to_string(),
                ..challenge.clone()
            },
            "approval_challenge_scope_invalid",
        ),
        (
            ApprovalChallenge {
                canonical_request_digest: "invalid".to_string(),
                ..challenge.clone()
            },
            "approval_challenge_digest_malformed",
        ),
        (
            ApprovalChallenge {
                expires_at: now,
                ..challenge.clone()
            },
            "approval_challenge_expired_or_future",
        ),
    ] {
        let error = config
            .validate_approval_challenge(&invalid, now)
            .expect_err("invalid challenge rejected");
        assert_eq!(error.reason_code(), reason);
        invalid.schema_version = APPROVAL_CHALLENGE_SCHEMA_VERSION.to_string();
    }

    let mut nil_challenge = challenge;
    nil_challenge.approval_id =
        ApprovalId::parse("00000000-0000-0000-0000-000000000000").expect("nil approval id");
    assert_eq!(
        config
            .validate_approval_challenge(&nil_challenge, now)
            .expect_err("nil challenge rejected")
            .reason_code(),
        "approval_challenge_identity_invalid"
    );
}

#[test]
fn approval_policy_obligation_branch_matrix_remains_fail_closed() {
    let now = OffsetDateTime::now_utc();
    let digest = format!("blake3:{}", "8".repeat(64));
    let (decision, mut policy, tenant_id, agent_id, run_id, action_id, action) =
        approval_inputs(now);

    let mut wrong_operation = decision.clone();
    wrong_operation.request.operation = compatibility_permission_operation("artifact.publish");
    assert_eq!(
        apply_approval_for_test(
            wrong_operation.clone(),
            std::slice::from_ref(&policy),
            approval_scope_for_test(&tenant_id, &agent_id, &run_id, &action_id, &action),
            now,
            &digest,
            RECEIPT_AUDIENCE,
            now + time::Duration::minutes(10),
        ),
        wrong_operation
    );

    let mut unmatched = policy.clone();
    unmatched.tenant_id = TenantId::new();
    assert_eq!(
        apply_approval_for_test(
            decision.clone(),
            &[unmatched],
            approval_scope_for_test(&tenant_id, &agent_id, &run_id, &action_id, &action),
            now,
            &digest,
            RECEIPT_AUDIENCE,
            now + time::Duration::minutes(10),
        )
        .status,
        AuthorityDecisionStatus::Allowed
    );

    policy.risk_level = Some("high".to_string());
    policy.expires_at = Some(now + time::Duration::minutes(5));
    let conditional = apply_approval_for_test(
        decision.clone(),
        std::slice::from_ref(&policy),
        approval_scope_for_test(&tenant_id, &agent_id, &run_id, &action_id, &action),
        now,
        &digest,
        RECEIPT_AUDIENCE,
        now + time::Duration::minutes(10),
    );
    assert_eq!(conditional.status, AuthorityDecisionStatus::Conditional);
    assert_eq!(
        conditional.obligations[0].parameters[APPROVAL_OBLIGATION_RISK_LEVEL],
        "high"
    );

    for (candidate, mut candidate_policy, candidate_digest, audience, reason) in [
        (
            decision.clone(),
            ApprovalPolicy {
                schema_version: "splendor.approval_policy.v0".to_string(),
                ..policy.clone()
            },
            digest.as_str(),
            RECEIPT_AUDIENCE,
            "approval_policy_schema_unsupported",
        ),
        (
            decision.clone(),
            ApprovalPolicy {
                expires_at: Some(now),
                ..policy.clone()
            },
            digest.as_str(),
            RECEIPT_AUDIENCE,
            "approval_policy_expired",
        ),
        (
            {
                let mut conflicted = decision.clone();
                conflicted
                    .obligations
                    .push(obligation(AuthorityObligationKind::HumanReview));
                conflicted
            },
            policy.clone(),
            digest.as_str(),
            RECEIPT_AUDIENCE,
            "approval_obligation_conflict",
        ),
        (
            decision.clone(),
            policy.clone(),
            " ",
            RECEIPT_AUDIENCE,
            "approval_challenge_binding_unavailable",
        ),
    ] {
        candidate_policy.agent_id = Some(agent_id.clone());
        let result = apply_approval_for_test(
            candidate,
            &[candidate_policy],
            approval_scope_for_test(&tenant_id, &agent_id, &run_id, &action_id, &action),
            now,
            candidate_digest,
            audience,
            now + time::Duration::minutes(10),
        );
        assert_eq!(result.status, AuthorityDecisionStatus::NeedsIntervention);
        assert_eq!(result.reasons, vec![reason]);
    }

    let expired_authority = apply_approval_for_test(
        decision,
        &[policy],
        approval_scope_for_test(&tenant_id, &agent_id, &run_id, &action_id, &action),
        now,
        &digest,
        RECEIPT_AUDIENCE,
        now,
    );
    assert_eq!(
        expired_authority.status,
        AuthorityDecisionStatus::NeedsIntervention
    );
    assert_eq!(expired_authority.reasons, vec!["approval_policy_expired"]);
}
