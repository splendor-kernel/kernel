//! AUTH-004a obligation receipt verification.
//!
//! This module validates authority obligation receipts with a trusted local
//! owning-service context before matching them to a conditional authority
//! decision. Raw `AuthorityObligationReceipt` values remain behavior-free
//! contracts and cannot satisfy obligations directly. The paired bounded gateway
//! slice can invoke these helpers before adapter execution, but this module still
//! does not implement a human approval workflow, MFA provider, gate engine,
//! durable evidence store, production PKI, or external revocation service.

use serde::Serialize;
use splendor_types::{
    ActionId, ApprovalActionScope, ApprovalChallenge, ApprovalId, ApprovalPolicy,
    AuthorityDecision, AuthorityDecisionId, AuthorityDecisionStatus, AuthorityObligation,
    AuthorityObligationId, AuthorityObligationKind, AuthorityObligationReceipt,
    AuthorityObligationReceiptId, AuthorityObligationReceiptValidation,
    AuthorityObligationReceiptValidationKind, AuthorityOperationNamespace, AuthorityResourceKind,
    AuthorityVerb, CapabilityRequest, ContentHash, InstanceId, PrincipalId, RevocationStatus,
    RunId, TraceEventId, APPROVAL_CHALLENGE_SCHEMA_VERSION, APPROVAL_POLICY_SCHEMA_VERSION,
    AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION, AUTHORITY_OBLIGATION_SCHEMA_VERSION,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

const LOCAL_RECEIPT_VALIDATION_ALGORITHM: &str = "local-obligation-receipt-v1";

/// Exact parameter names carried by an authority-owned approval obligation.
pub const APPROVAL_OBLIGATION_APPROVAL_ID: &str = "approval_id";
pub const APPROVAL_OBLIGATION_POLICY_ID: &str = "policy_id";
pub const APPROVAL_OBLIGATION_RISK_LEVEL: &str = "risk_level";
pub const APPROVAL_OBLIGATION_RECEIPT_AUDIENCE: &str = "receipt_audience";
pub const APPROVAL_OBLIGATION_EXPIRES_AT: &str = "expires_at";
pub const APPROVAL_OBLIGATION_ACTION_ID: &str = "action_id";
pub const APPROVAL_OBLIGATION_ACTION_NAME: &str = "action_name";
pub const APPROVAL_OBLIGATION_ADAPTER: &str = "adapter";
pub const APPROVAL_OBLIGATION_ACTION_DIGEST: &str = "gateway_action_request_digest";

/// Trusted process configuration shared by the local approval receipt issuer
/// and the daemon-side receipt validator.
///
/// This value is never a request contract. Its debug representation redacts the
/// local validation secret, and the request/receipt wire shapes cannot construct
/// a trusted instance.
#[derive(Clone, Eq, PartialEq)]
pub struct LocalAuthorityObligationReceiptConfig {
    issuer: PrincipalId,
    audience_prefix: String,
    key_id: String,
    validation_secret: String,
    revocation_ref: String,
}

impl LocalAuthorityObligationReceiptConfig {
    /// Builds bounded local trusted receipt configuration.
    pub fn trusted_local(
        issuer: PrincipalId,
        audience_prefix: impl Into<String>,
        key_id: impl Into<String>,
        validation_secret: impl Into<String>,
        revocation_ref: impl Into<String>,
    ) -> Result<Self, ObligationReceiptError> {
        let config = Self {
            issuer,
            audience_prefix: audience_prefix.into(),
            key_id: key_id.into(),
            validation_secret: validation_secret.into(),
            revocation_ref: revocation_ref.into(),
        };
        if config.issuer.is_nil() {
            return Err(validation_error("obligation_receipt_issuer_invalid"));
        }
        validate_token(
            "obligation_receipt_config.audience_prefix",
            &config.audience_prefix,
        )?;
        validate_token("obligation_receipt_config.key_id", &config.key_id)?;
        validate_token(
            "obligation_receipt_config.revocation_ref",
            &config.revocation_ref,
        )?;
        if config.validation_secret.trim().len() < 32
            || config.validation_secret.trim() != config.validation_secret
            || config.validation_secret.contains('*')
        {
            return Err(validation_error(
                "obligation_receipt_validation_secret_unavailable",
            ));
        }
        Ok(config)
    }

    /// Derives the trusted exact receipt audience for one run.
    pub fn audience_for_run(&self, run_id: &RunId) -> String {
        format!("{}:{run_id}", self.audience_prefix)
    }

    /// Returns trusted configuration pinned to one exact resident instance.
    ///
    /// The input is process-owned startup/registry identity, never a request
    /// field. The resulting run audience is exactly the RFC 0011 v2 shape.
    pub fn for_resident_instance(
        &self,
        instance_id: &InstanceId,
    ) -> Result<Self, ObligationReceiptError> {
        if instance_id.is_nil() {
            return Err(validation_error(
                "obligation_receipt_resident_instance_invalid",
            ));
        }
        let mut resident = self.clone();
        resident.audience_prefix =
            format!("splendor.daemon.approval_receipt.v2:instance:{instance_id}:run");
        Ok(resident)
    }

    /// Builds a validator context for one exact run audience and trusted time.
    pub fn validation_context_for_run(
        &self,
        run_id: &RunId,
        now: OffsetDateTime,
    ) -> AuthorityObligationReceiptValidationContext {
        AuthorityObligationReceiptValidationContext::trusted_local(
            self.issuer.clone(),
            self.audience_for_run(run_id),
            self.key_id.clone(),
            self.validation_secret.clone(),
            self.revocation_ref.clone(),
            now,
        )
    }

    /// Issues one local receipt for an exact, previously recorded challenge.
    pub fn issue_approval_receipt(
        &self,
        challenge: &ApprovalChallenge,
        approval_trace_event_id: TraceEventId,
        issued_at: OffsetDateTime,
    ) -> Result<AuthorityObligationReceipt, ObligationReceiptError> {
        validate_approval_challenge_for_issuance(challenge, self, issued_at)?;
        let evidence_bytes = serde_json::to_vec(&(
            "splendor.approval_receipt_evidence.v1",
            challenge,
            &approval_trace_event_id,
        ))
        .map_err(
            |error| ObligationReceiptError::ReceiptValidationDigestUnavailable {
                reason: error.to_string(),
            },
        )?;
        let receipt = AuthorityObligationReceipt {
            schema_version: AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_id: AuthorityObligationReceiptId::new(),
            issuer: self.issuer.clone(),
            audience: challenge.receipt_audience.clone(),
            obligation_id: challenge.obligation_id.clone(),
            kind: AuthorityObligationKind::ApprovalRequired,
            subject: challenge.subject.clone(),
            authority_decision_id: challenge.authority_decision_id.clone(),
            canonical_request_digest: challenge.canonical_request_digest.clone(),
            evidence_digest: ContentHash::blake3(evidence_bytes).to_string(),
            evidence_ref: Some(format!("approval-trace:{approval_trace_event_id}")),
            issued_at,
            expires_at: challenge.expires_at,
            revocation: RevocationStatus::Active,
            revocation_ref: self.revocation_ref.clone(),
            approval_id: Some(challenge.approval_id.clone()),
            approval_trace_event_id: Some(approval_trace_event_id),
            validation: AuthorityObligationReceiptValidation {
                validation_kind: AuthorityObligationReceiptValidationKind::LocalSignature,
                algorithm: LOCAL_RECEIPT_VALIDATION_ALGORITHM.to_string(),
                key_id: self.key_id.clone(),
                digest: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                signature:
                    "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
            },
        };
        issue_local_authority_obligation_receipt(
            receipt,
            &self.validation_context_for_run(&challenge.run_id, issued_at),
        )
    }

    /// Validates that a behavior-free challenge is exact and issuable under this
    /// trusted process configuration at `now` without issuing a receipt.
    pub fn validate_approval_challenge(
        &self,
        challenge: &ApprovalChallenge,
        now: OffsetDateTime,
    ) -> Result<(), ObligationReceiptError> {
        validate_approval_challenge_for_issuance(challenge, self, now)
    }
}

impl fmt::Debug for LocalAuthorityObligationReceiptConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalAuthorityObligationReceiptConfig")
            .field("issuer", &self.issuer)
            .field("audience_prefix", &self.audience_prefix)
            .field("key_id", &self.key_id)
            .field("validation_secret", &"<redacted>")
            .field("revocation_ref", &self.revocation_ref)
            .finish()
    }
}

/// Migrates a matching legacy approval policy into one exact authority-owned
/// `ApprovalRequired` obligation on an already allowed action decision.
///
/// The current capability decision remains the permission source. This helper
/// never turns a denied/uncertain decision into allow, and a conflicting existing
/// obligation fails closed instead of merging approval into a bypass bundle.
#[derive(Clone, Copy, Debug)]
pub struct ApprovalObligationContext<'a> {
    /// Exact action scope evaluated by the approval policy.
    pub action_scope: ApprovalActionScope<'a>,
    /// Canonical digest of the full gateway action request and effective adapter.
    pub gateway_action_request_digest: &'a str,
    /// Trusted audience required on the resulting receipt.
    pub receipt_audience: &'a str,
    /// Expiry of the live authority that the obligation may not outlive.
    pub authority_expires_at: OffsetDateTime,
    /// Original action request time preserved across the exact retry.
    pub action_requested_at: OffsetDateTime,
    /// Current trusted authority evaluation time.
    pub now: OffsetDateTime,
}

/// Applies a matching approval policy using one explicit exact-action binding.
pub fn apply_approval_policy_obligation(
    mut decision: AuthorityDecision,
    policies: &[ApprovalPolicy],
    context: ApprovalObligationContext<'_>,
) -> AuthorityDecision {
    let ApprovalObligationContext {
        action_scope,
        gateway_action_request_digest,
        receipt_audience,
        authority_expires_at,
        action_requested_at,
        now,
    } = context;
    if decision.request.operation.namespace != AuthorityOperationNamespace::Gateway
        || decision.request.operation.resource_kind != AuthorityResourceKind::Action
        || decision.request.operation.verb != AuthorityVerb::Invoke
    {
        return decision;
    }

    let matching = policies
        .iter()
        .filter(|policy| policy.matches_action(&action_scope, now))
        .collect::<Vec<_>>();
    let Some(policy) = matching.first().copied() else {
        return decision;
    };
    if matching
        .iter()
        .any(|policy| policy.schema_version != APPROVAL_POLICY_SCHEMA_VERSION)
    {
        return approval_policy_intervention(decision, "approval_policy_schema_unsupported");
    }
    if matching.iter().any(|policy| {
        policy.is_expired(now)
            || policy
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
    }) {
        return approval_policy_intervention(decision, "approval_policy_expired");
    }
    if decision.status != AuthorityDecisionStatus::Allowed || !decision.obligations.is_empty() {
        return approval_policy_intervention(decision, "approval_obligation_conflict");
    }
    if gateway_action_request_digest.trim().is_empty()
        || receipt_audience.trim().is_empty()
        || receipt_audience.contains('*')
    {
        return approval_policy_intervention(decision, "approval_challenge_binding_unavailable");
    }

    let expires_at = policy
        .expires_at
        .map_or(authority_expires_at, |policy_expiry| {
            policy_expiry.min(authority_expires_at)
        });
    if expires_at <= now {
        return approval_policy_intervention(decision, "approval_policy_expired");
    }
    let expires_at_text = match expires_at.format(&Rfc3339) {
        Ok(value) => value,
        Err(_) => {
            return approval_policy_intervention(decision, "approval_challenge_binding_unavailable")
        }
    };
    let identity_payload = ApprovalChallengeIdentityPayload {
        schema_version: APPROVAL_CHALLENGE_SCHEMA_VERSION,
        policy,
        subject: &decision.request.subject,
        operation: &decision.request.operation,
        scope: &decision.request.scope,
        action_id: action_scope.action_id,
        action_name: &action_scope.action.name,
        adapter: action_scope.adapter,
        gateway_action_request_digest,
        receipt_audience,
        action_requested_at,
        expires_at,
    };
    let identity_bytes = match serde_json::to_vec(&identity_payload) {
        Ok(bytes) => bytes,
        Err(_) => {
            return approval_policy_intervention(decision, "approval_challenge_binding_unavailable")
        }
    };
    let approval_id = ApprovalId::from(deterministic_uuid("approval", &identity_bytes));
    let obligation_id =
        AuthorityObligationId::from(deterministic_uuid("approval-obligation", &identity_bytes));
    decision.decision_id =
        AuthorityDecisionId::from(deterministic_uuid("approval-decision", &identity_bytes));
    decision.request.requested_at = action_requested_at;

    let mut parameters = BTreeMap::new();
    parameters.insert(
        APPROVAL_OBLIGATION_APPROVAL_ID.to_string(),
        serde_json::Value::String(approval_id.to_string()),
    );
    parameters.insert(
        APPROVAL_OBLIGATION_POLICY_ID.to_string(),
        serde_json::Value::String(policy.policy_id.clone()),
    );
    if let Some(risk_level) = policy.risk_level.clone() {
        parameters.insert(
            APPROVAL_OBLIGATION_RISK_LEVEL.to_string(),
            serde_json::Value::String(risk_level),
        );
    }
    parameters.insert(
        APPROVAL_OBLIGATION_RECEIPT_AUDIENCE.to_string(),
        serde_json::Value::String(receipt_audience.to_string()),
    );
    parameters.insert(
        APPROVAL_OBLIGATION_EXPIRES_AT.to_string(),
        serde_json::Value::String(expires_at_text),
    );
    parameters.insert(
        APPROVAL_OBLIGATION_ACTION_ID.to_string(),
        serde_json::Value::String(action_scope.action_id.to_string()),
    );
    parameters.insert(
        APPROVAL_OBLIGATION_ACTION_NAME.to_string(),
        serde_json::Value::String(action_scope.action.name.clone()),
    );
    parameters.insert(
        APPROVAL_OBLIGATION_ADAPTER.to_string(),
        serde_json::Value::String(action_scope.adapter.unwrap_or_default().to_string()),
    );
    parameters.insert(
        APPROVAL_OBLIGATION_ACTION_DIGEST.to_string(),
        serde_json::Value::String(gateway_action_request_digest.to_string()),
    );
    decision.status = AuthorityDecisionStatus::Conditional;
    decision.reasons = vec![
        "capability_conditional".to_string(),
        "approval_required".to_string(),
    ];
    decision.obligations = vec![AuthorityObligation {
        schema_version: AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string(),
        obligation_id,
        kind: AuthorityObligationKind::ApprovalRequired,
        description: "exact approval obligation required before effect".to_string(),
        parameters,
    }];
    decision
}

#[derive(Serialize)]
struct ApprovalChallengeIdentityPayload<'a> {
    schema_version: &'static str,
    policy: &'a ApprovalPolicy,
    subject: &'a PrincipalId,
    operation: &'a splendor_types::AuthorityOperation,
    scope: &'a splendor_types::CapabilityScope,
    action_id: &'a ActionId,
    action_name: &'a str,
    adapter: Option<&'a str>,
    gateway_action_request_digest: &'a str,
    receipt_audience: &'a str,
    #[serde(with = "time::serde::rfc3339")]
    action_requested_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

fn deterministic_uuid(domain: &str, payload: &[u8]) -> Uuid {
    let namespace = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"splendor.auth-004c.approval.v1");
    let mut name = Vec::with_capacity(domain.len() + payload.len() + 16);
    name.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    name.extend_from_slice(domain.as_bytes());
    name.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    name.extend_from_slice(payload);
    Uuid::new_v5(&namespace, &name)
}

fn approval_policy_intervention(
    mut decision: AuthorityDecision,
    reason: &'static str,
) -> AuthorityDecision {
    decision.status = AuthorityDecisionStatus::NeedsIntervention;
    decision.reasons = vec![reason.to_string()];
    decision.obligations.clear();
    decision
}

fn validate_approval_challenge_for_issuance(
    challenge: &ApprovalChallenge,
    config: &LocalAuthorityObligationReceiptConfig,
    issued_at: OffsetDateTime,
) -> Result<(), ObligationReceiptError> {
    if challenge.schema_version != APPROVAL_CHALLENGE_SCHEMA_VERSION {
        return Err(validation_error("approval_challenge_schema_unsupported"));
    }
    if challenge.approval_id.is_nil()
        || challenge.tenant_id.is_nil()
        || challenge.agent_id.is_nil()
        || challenge.run_id.is_nil()
        || challenge.action_id.is_nil()
        || challenge.subject.is_nil()
        || challenge.authority_decision_id.is_nil()
        || challenge.obligation_id.is_nil()
    {
        return Err(validation_error("approval_challenge_identity_invalid"));
    }
    if challenge.action_name.trim().is_empty()
        || challenge.adapter.trim().is_empty()
        || challenge.policy_id.trim().is_empty()
        || challenge.receipt_audience != config.audience_for_run(&challenge.run_id)
    {
        return Err(validation_error("approval_challenge_scope_invalid"));
    }
    for digest in [
        &challenge.canonical_request_digest,
        &challenge.gateway_action_request_digest,
        &challenge.authority_decision_digest,
    ] {
        validate_supported_digest("approval_challenge_digest_malformed", digest)?;
    }
    if challenge.expires_at <= issued_at || challenge.requested_at > issued_at {
        return Err(validation_error("approval_challenge_expired_or_future"));
    }
    Ok(())
}

/// Trusted owning-service context required to validate behavior-free receipt
/// contracts before matching them to a conditional authority decision.
///
/// The validation secret is local deterministic test material for this bounded
/// slice, not production PKI/IAM. Callers must provide this context from the
/// owning receipt service, not from the requester trying to satisfy obligations.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorityObligationReceiptValidationContext {
    issuer: PrincipalId,
    audience: String,
    key_id: String,
    validation_secret: String,
    revocation_ref: String,
    now: OffsetDateTime,
}

impl AuthorityObligationReceiptValidationContext {
    /// Builds trusted local validation context for the receipt owning service.
    ///
    /// This constructor is a configuration seam for the authority-owned receipt
    /// service or a local gateway composition root. It must not be populated from
    /// requester payloads; a caller that supplies its own issuer/secret tuple is
    /// not trusted authority. Future production integrations should replace this
    /// deterministic local context with PKI/IAM-backed validation while keeping
    /// the gateway input behavior-free.
    pub fn trusted_local(
        issuer: PrincipalId,
        audience: impl Into<String>,
        key_id: impl Into<String>,
        validation_secret: impl Into<String>,
        revocation_ref: impl Into<String>,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            issuer,
            audience: audience.into(),
            key_id: key_id.into(),
            validation_secret: validation_secret.into(),
            revocation_ref: revocation_ref.into(),
            now,
        }
    }

    /// Owning-service issuer expected on receipts validated by this context.
    pub fn issuer(&self) -> &PrincipalId {
        &self.issuer
    }

    /// Audience binding expected on receipts validated by this context.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Key identifier expected on local receipt validation material.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Revocation source coordinate expected on receipts validated by this context.
    pub fn revocation_ref(&self) -> &str {
        &self.revocation_ref
    }

    /// Validation time used for expiry/not-before/revocation checks.
    pub fn now(&self) -> OffsetDateTime {
        self.now
    }

    /// Returns a copy of this context with a different validation time.
    pub fn at_time(&self, now: OffsetDateTime) -> Self {
        Self {
            now,
            ..self.clone()
        }
    }
}

impl fmt::Debug for AuthorityObligationReceiptValidationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityObligationReceiptValidationContext")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("key_id", &self.key_id)
            .field("validation_secret", &"<redacted>")
            .field("revocation_ref", &self.revocation_ref)
            .field("now", &self.now)
            .finish()
    }
}

/// Locally validated authority obligation receipt accepted by final receipt
/// matching.
///
/// Raw receipt contracts are intentionally not accepted by
/// `verify_obligation_receipts`; only this wrapper can be passed after trusted
/// owning-service validation succeeds.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedAuthorityObligationReceipt {
    receipt: AuthorityObligationReceipt,
    trust: ValidatedReceiptTrust,
}

/// Authority-owned one-use receipt state used by gateway verifiers.
///
/// Implementations own both trusted-time observation and the linearized claim.
/// Validation and claim must fail closed when that state is unavailable.
pub trait AuthorityObligationReceiptLedger: Send + Sync {
    /// Validates receipts at a monotonic trusted time without consuming them.
    ///
    /// `now` is retained for source compatibility. The built-in ledger does not
    /// trust it: after acquiring its state lock, it samples its authority-owned
    /// UTC clock and uses only that observation for time-sensitive decisions.
    fn validate_receipts(
        &self,
        receipts: &[AuthorityObligationReceipt],
        context: &AuthorityObligationReceiptValidationContext,
        now: OffsetDateTime,
    ) -> Result<Vec<ValidatedAuthorityObligationReceipt>, ObligationReceiptLedgerError>;

    /// Atomically revalidates and permanently claims each receipt exactly once.
    /// This claim is the effect linearization point.
    ///
    /// `now` is a legacy compatibility input and is non-authoritative for the
    /// built-in ledger, which samples its own UTC clock while holding its lock.
    fn claim_receipts(
        &self,
        receipts: &[AuthorityObligationReceipt],
        context: &AuthorityObligationReceiptValidationContext,
        now: OffsetDateTime,
    ) -> Result<AuthorityObligationEffectPermit, ObligationReceiptLedgerError>;

    /// Atomically validates and revokes one receipt against a concurrent claim.
    ///
    /// `now` is a legacy compatibility input and is non-authoritative for the
    /// built-in ledger, which samples its own UTC clock while holding its lock.
    fn revoke_receipt(
        &self,
        receipt: &AuthorityObligationReceipt,
        context: &AuthorityObligationReceiptValidationContext,
        now: OffsetDateTime,
    ) -> Result<AuthorityObligationReceiptRevocationOutcome, ObligationReceiptLedgerError> {
        let _ = (receipt, context, now);
        Err(ObligationReceiptLedgerError::Unavailable)
    }
}

/// Known terminal result of atomically revoking one obligation receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityObligationReceiptRevocationOutcome {
    /// This operation wrote the terminal revocation tombstones.
    Revoked,
    /// Exact or semantic revocation had already won.
    AlreadyRevoked,
    /// The gateway claim had already won, so revocation is too late.
    AlreadyClaimed,
}

/// Owned proof that exact obligation receipts were valid and claimed once.
///
/// Expiry after this value is returned does not cancel the already-linearized
/// in-flight effect. The gateway retains this permit through evidence append and
/// adapter execution. A claim is intentionally not released on drop.
#[derive(Debug)]
pub struct AuthorityObligationEffectPermit {
    receipt_ids: Vec<AuthorityObligationReceiptId>,
}

impl AuthorityObligationEffectPermit {
    /// Receipt identities atomically burned by this permit.
    pub fn receipt_ids(&self) -> &[AuthorityObligationReceiptId] {
        &self.receipt_ids
    }
}

/// Authority-owned UTC time source for process-local receipt state.
///
/// Implementations return `None` when trusted time cannot be observed. The
/// built-in ledger maps that uncertainty to an unavailable, fail-closed result.
/// Production construction uses the system UTC clock; injection exists so tests
/// can deterministically exercise rollback and expiry.
pub trait AuthorityObligationReceiptClock: Send + Sync {
    /// Returns one trusted UTC wall-clock observation, or `None` if unavailable.
    fn now_utc(&self) -> Option<OffsetDateTime>;
}

#[derive(Debug)]
struct SystemAuthorityObligationReceiptClock;

impl AuthorityObligationReceiptClock for SystemAuthorityObligationReceiptClock {
    fn now_utc(&self) -> Option<OffsetDateTime> {
        Some(OffsetDateTime::now_utc())
    }
}

/// Process-local authority-owned receipt ledger.
///
/// Clones of a verifier should receive the same `Arc` of this ledger. This
/// implementation is suitable only for current process-local runs; it does not
/// claim restart durability. Its legacy method-level `now` arguments are ignored;
/// trusted UTC is sampled only after the state mutex is acquired so scheduler
/// inversion cannot appear as clock rollback.
pub struct InMemoryAuthorityObligationReceiptLedger {
    state: Mutex<InMemoryAuthorityObligationReceiptState>,
    clock: Arc<dyn AuthorityObligationReceiptClock>,
}

impl InMemoryAuthorityObligationReceiptLedger {
    /// Builds a process-local ledger with an injectable authority-owned UTC clock.
    ///
    /// This additive seam is intended for deterministic tests. Production code
    /// should use `Default`, which owns the system UTC clock.
    pub fn with_clock(clock: Arc<dyn AuthorityObligationReceiptClock>) -> Self {
        Self {
            state: Mutex::new(InMemoryAuthorityObligationReceiptState::default()),
            clock,
        }
    }

    fn lock_state_and_observe_time(
        &self,
    ) -> Result<
        (
            std::sync::MutexGuard<'_, InMemoryAuthorityObligationReceiptState>,
            OffsetDateTime,
        ),
        ObligationReceiptLedgerError,
    > {
        let state = self
            .state
            .lock()
            .map_err(|_| ObligationReceiptLedgerError::Unavailable)?;
        let observed_now = self
            .clock
            .now_utc()
            .ok_or(ObligationReceiptLedgerError::Unavailable)?;
        Ok((state, observed_now))
    }
}

impl Default for InMemoryAuthorityObligationReceiptLedger {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemAuthorityObligationReceiptClock))
    }
}

impl fmt::Debug for InMemoryAuthorityObligationReceiptLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryAuthorityObligationReceiptLedger")
            .field("state", &self.state)
            .field("clock", &"<authority-owned UTC clock>")
            .finish()
    }
}

#[derive(Debug, Default)]
struct InMemoryAuthorityObligationReceiptState {
    max_observed_time: Option<OffsetDateTime>,
    receipt_terminal_states: HashMap<String, ReceiptTerminalState>,
    semantic_terminal_states: HashMap<String, ReceiptTerminalState>,
    expired_receipts: HashSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptTerminalState {
    Claimed,
    Revoked,
}

impl AuthorityObligationReceiptLedger for InMemoryAuthorityObligationReceiptLedger {
    fn validate_receipts(
        &self,
        receipts: &[AuthorityObligationReceipt],
        context: &AuthorityObligationReceiptValidationContext,
        _now: OffsetDateTime,
    ) -> Result<Vec<ValidatedAuthorityObligationReceipt>, ObligationReceiptLedgerError> {
        let (mut state, observed_now) = self.lock_state_and_observe_time()?;
        validate_receipts_at_monotonic_time(&mut state, receipts, context, observed_now)
    }

    fn claim_receipts(
        &self,
        receipts: &[AuthorityObligationReceipt],
        context: &AuthorityObligationReceiptValidationContext,
        _now: OffsetDateTime,
    ) -> Result<AuthorityObligationEffectPermit, ObligationReceiptLedgerError> {
        let (mut state, observed_now) = self.lock_state_and_observe_time()?;
        validate_receipts_at_monotonic_time(&mut state, receipts, context, observed_now)?;
        let semantic_claims = receipts
            .iter()
            .map(authority_obligation_receipt_semantic_claim_key)
            .collect::<Result<Vec<_>, _>>()?;
        if semantic_claims.iter().collect::<HashSet<_>>().len() != semantic_claims.len() {
            return Err(ObligationReceiptLedgerError::Replayed);
        }
        for (receipt, semantic_claim) in receipts.iter().zip(&semantic_claims) {
            match terminal_state_for_coordinates(&state, receipt, semantic_claim)? {
                Some(ReceiptTerminalState::Claimed) => {
                    tombstone_receipt_coordinates(
                        &mut state,
                        receipt,
                        semantic_claim,
                        ReceiptTerminalState::Claimed,
                    );
                    return Err(ObligationReceiptLedgerError::Replayed);
                }
                Some(ReceiptTerminalState::Revoked) => {
                    tombstone_receipt_coordinates(
                        &mut state,
                        receipt,
                        semantic_claim,
                        ReceiptTerminalState::Revoked,
                    );
                    return Err(ObligationReceiptLedgerError::Revoked);
                }
                None => {}
            }
        }
        for (receipt, semantic_claim) in receipts.iter().zip(&semantic_claims) {
            tombstone_receipt_coordinates(
                &mut state,
                receipt,
                semantic_claim,
                ReceiptTerminalState::Claimed,
            );
        }
        Ok(AuthorityObligationEffectPermit {
            receipt_ids: receipts
                .iter()
                .map(|receipt| receipt.receipt_id.clone())
                .collect(),
        })
    }

    fn revoke_receipt(
        &self,
        receipt: &AuthorityObligationReceipt,
        context: &AuthorityObligationReceiptValidationContext,
        _now: OffsetDateTime,
    ) -> Result<AuthorityObligationReceiptRevocationOutcome, ObligationReceiptLedgerError> {
        let (mut state, observed_now) = self.lock_state_and_observe_time()?;
        validate_receipts_at_monotonic_time(
            &mut state,
            std::slice::from_ref(receipt),
            context,
            observed_now,
        )?;
        let semantic_claim = authority_obligation_receipt_semantic_claim_key(receipt)?;
        match terminal_state_for_coordinates(&state, receipt, &semantic_claim)? {
            Some(ReceiptTerminalState::Revoked) => {
                tombstone_receipt_coordinates(
                    &mut state,
                    receipt,
                    &semantic_claim,
                    ReceiptTerminalState::Revoked,
                );
                Ok(AuthorityObligationReceiptRevocationOutcome::AlreadyRevoked)
            }
            Some(ReceiptTerminalState::Claimed) => {
                tombstone_receipt_coordinates(
                    &mut state,
                    receipt,
                    &semantic_claim,
                    ReceiptTerminalState::Claimed,
                );
                Ok(AuthorityObligationReceiptRevocationOutcome::AlreadyClaimed)
            }
            None => {
                tombstone_receipt_coordinates(
                    &mut state,
                    receipt,
                    &semantic_claim,
                    ReceiptTerminalState::Revoked,
                );
                Ok(AuthorityObligationReceiptRevocationOutcome::Revoked)
            }
        }
    }
}

fn terminal_state_for_coordinates(
    state: &InMemoryAuthorityObligationReceiptState,
    receipt: &AuthorityObligationReceipt,
    semantic_claim: &str,
) -> Result<Option<ReceiptTerminalState>, ObligationReceiptLedgerError> {
    let receipt_state = state
        .receipt_terminal_states
        .get(&receipt.receipt_id.to_string())
        .copied();
    let semantic_state = state.semantic_terminal_states.get(semantic_claim).copied();
    match (receipt_state, semantic_state) {
        (Some(left), Some(right)) if left != right => {
            Err(ObligationReceiptLedgerError::Unavailable)
        }
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn tombstone_receipt_coordinates(
    state: &mut InMemoryAuthorityObligationReceiptState,
    receipt: &AuthorityObligationReceipt,
    semantic_claim: &str,
    terminal: ReceiptTerminalState,
) {
    state
        .receipt_terminal_states
        .insert(receipt.receipt_id.to_string(), terminal);
    state
        .semantic_terminal_states
        .insert(semantic_claim.to_string(), terminal);
}

fn authority_obligation_receipt_semantic_claim_key(
    receipt: &AuthorityObligationReceipt,
) -> Result<String, ObligationReceiptLedgerError> {
    let bytes = serde_json::to_vec(&(
        "splendor.authority_obligation_receipt.semantic_claim.v1",
        &receipt.issuer,
        &receipt.audience,
        &receipt.subject,
        &receipt.authority_decision_id,
        &receipt.obligation_id,
        &receipt.kind,
        &receipt.canonical_request_digest,
        &receipt.approval_id,
    ))
    .map_err(|_| ObligationReceiptLedgerError::ClaimKeyUnavailable)?;
    Ok(ContentHash::blake3(bytes).to_string())
}

fn validate_receipts_at_monotonic_time(
    state: &mut InMemoryAuthorityObligationReceiptState,
    receipts: &[AuthorityObligationReceipt],
    context: &AuthorityObligationReceiptValidationContext,
    now: OffsetDateTime,
) -> Result<Vec<ValidatedAuthorityObligationReceipt>, ObligationReceiptLedgerError> {
    let previous = state.max_observed_time;
    let effective_now = previous.map_or(now, |observed| observed.max(now));

    // Authenticate and context-bind the complete set before mutating any
    // trusted-time, expiry, claim, or revocation state. In particular, an
    // attacker cannot submit an expired forged receipt under a valid receipt ID
    // to latch that ID as expired before its signature or audience is checked.
    let validated = receipts
        .iter()
        .cloned()
        .map(|receipt| {
            authenticate_authority_obligation_receipt(receipt, &context.at_time(effective_now))
                .map_err(ObligationReceiptLedgerError::Validation)
        })
        .collect::<Result<Vec<_>, _>>()?;

    if receipts.iter().any(|receipt| {
        state
            .expired_receipts
            .contains(&receipt.receipt_id.to_string())
    }) {
        return Err(ObligationReceiptLedgerError::Expired);
    }
    if previous.is_some_and(|observed| now < observed) {
        return Err(ObligationReceiptLedgerError::ClockRollback);
    }

    state.max_observed_time = Some(effective_now);
    for receipt in receipts {
        if effective_now >= receipt.expires_at {
            state
                .expired_receipts
                .insert(receipt.receipt_id.to_string());
        }
    }
    if receipts.iter().any(|receipt| {
        state
            .expired_receipts
            .contains(&receipt.receipt_id.to_string())
    }) {
        return Err(ObligationReceiptLedgerError::Expired);
    }

    for receipt in receipts {
        validate_receipt_lifecycle(receipt, &context.at_time(effective_now))
            .map_err(ObligationReceiptLedgerError::Validation)?;
    }
    Ok(validated)
}

/// Stable fail-closed errors from authority-owned receipt state.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ObligationReceiptLedgerError {
    /// Trusted one-use or time state could not be read.
    #[error("authority obligation receipt ledger unavailable")]
    Unavailable,
    /// Trusted wall-clock observation moved backwards.
    #[error("authority obligation receipt clock rollback")]
    ClockRollback,
    /// Receipt expiry was observed and latched.
    #[error("authority obligation receipt expired")]
    Expired,
    /// A receipt was already claimed.
    #[error("authority obligation receipt replayed")]
    Replayed,
    /// A receipt or semantic equivalent was revoked before claim.
    #[error("authority obligation receipt revoked")]
    Revoked,
    /// Stable semantic claim coordinates could not be serialized.
    #[error("authority obligation receipt semantic claim key unavailable")]
    ClaimKeyUnavailable,
    /// Trusted receipt validation failed.
    #[error("authority obligation receipt validation failed: {0}")]
    Validation(ObligationReceiptError),
}

impl ObligationReceiptLedgerError {
    /// Stable normalized reason code used at the gateway boundary.
    pub fn reason_code(&self) -> String {
        match self {
            Self::Unavailable => {
                "authority_obligation_receipt_replay_state_unavailable".to_string()
            }
            Self::ClockRollback => "authority_obligation_receipt_clock_rollback".to_string(),
            Self::Expired => "obligation_receipt_expired".to_string(),
            Self::Replayed => "authority_obligation_receipt_replayed".to_string(),
            Self::Revoked => "authority_obligation_receipt_revoked".to_string(),
            Self::ClaimKeyUnavailable => {
                "authority_obligation_receipt_claim_key_unavailable".to_string()
            }
            Self::Validation(error) => error.reason_code(),
        }
    }

    /// Whether this failure represents unavailable verifier/ledger state.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable | Self::ClaimKeyUnavailable)
            || matches!(self, Self::Validation(error) if error.reason_code() == "obligation_receipt_validation_secret_unavailable")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValidatedReceiptTrust {
    LocalSignature,
}

impl ValidatedAuthorityObligationReceipt {
    /// Returns the underlying behavior-free receipt contract for inspection.
    pub fn receipt(&self) -> &AuthorityObligationReceipt {
        &self.receipt
    }
}

/// Result of verifying validated obligation receipts against one conditional
/// decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObligationReceiptVerification {
    /// True only when every obligation on the decision has one exact validated
    /// matching receipt and no duplicates/extras are present.
    pub allowed: bool,
    /// Stable reason codes. Empty when `allowed` is true.
    pub reasons: Vec<String>,
    /// Obligation IDs satisfied by exact matching receipts.
    pub satisfied_obligation_ids: Vec<AuthorityObligationId>,
}

impl ObligationReceiptVerification {
    fn allow(satisfied_obligation_ids: Vec<AuthorityObligationId>) -> Self {
        Self {
            allowed: true,
            reasons: Vec::new(),
            satisfied_obligation_ids,
        }
    }

    fn deny(reasons: Vec<String>, satisfied_obligation_ids: Vec<AuthorityObligationId>) -> Self {
        Self {
            allowed: false,
            reasons,
            satisfied_obligation_ids,
        }
    }
}

/// Computes the deterministic digest receipts must bind to for this exact
/// authority request. Callers must keep secrets out of `CapabilityRequest`
/// metadata; the helper emits only a content hash and never returns serialized
/// request bytes.
pub fn canonical_authority_request_digest(
    request: &CapabilityRequest,
) -> Result<String, ObligationReceiptError> {
    let bytes = serde_json::to_vec(request).map_err(|error| {
        ObligationReceiptError::RequestDigestUnavailable {
            reason: error.to_string(),
        }
    })?;
    Ok(ContentHash::blake3(bytes).to_string())
}

/// Validates a behavior-free receipt using trusted local owning-service context.
///
/// This is a deterministic local validation seam for tests and bounded AUTH-004a
/// evidence. It proves the caller cannot satisfy obligations with raw
/// self-asserted receipt fields, but it does not claim production PKI, external
/// revocation introspection, approval workflow execution, or gateway wiring.
pub fn validate_authority_obligation_receipt(
    receipt: AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> Result<ValidatedAuthorityObligationReceipt, ObligationReceiptError> {
    let validated = authenticate_authority_obligation_receipt(receipt, context)?;
    validate_receipt_lifecycle(validated.receipt(), context)?;
    Ok(validated)
}

fn authenticate_authority_obligation_receipt(
    receipt: AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> Result<ValidatedAuthorityObligationReceipt, ObligationReceiptError> {
    validate_receipt_authenticated_shape(&receipt, context)?;
    let expected_digest = obligation_receipt_validation_digest(&receipt)?;
    if receipt.validation.digest != expected_digest {
        return Err(validation_error(
            "obligation_receipt_validation_digest_mismatch",
        ));
    }
    let expected_signature = local_obligation_receipt_signature(&receipt, context)?;
    if receipt.validation.signature != expected_signature {
        return Err(validation_error("obligation_receipt_signature_mismatch"));
    }

    Ok(ValidatedAuthorityObligationReceipt {
        receipt,
        trust: ValidatedReceiptTrust::LocalSignature,
    })
}

/// Adds deterministic local validation material to a raw receipt contract.
///
/// This helper models the authority-owned receipt service issuing local evidence
/// after an obligation has been satisfied. It is intentionally a bounded local
/// seam for tests and embedded gateway configuration; it is not production PKI,
/// does not perform an approval/MFA/gate workflow, and must not be called with a
/// context derived from requester payloads.
pub fn issue_local_authority_obligation_receipt(
    mut receipt: AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> Result<AuthorityObligationReceipt, ObligationReceiptError> {
    receipt.validation.digest = obligation_receipt_validation_digest(&receipt)?;
    receipt.validation.signature = local_obligation_receipt_signature(&receipt, context)?;
    Ok(receipt)
}

/// Verifies that validated receipts satisfy every obligation carried by a
/// conditional decision. Any uncertainty fails closed with stable reason codes.
pub fn verify_obligation_receipts(
    decision: &AuthorityDecision,
    receipts: &[ValidatedAuthorityObligationReceipt],
    now: OffsetDateTime,
) -> ObligationReceiptVerification {
    if decision.status != AuthorityDecisionStatus::Conditional {
        return ObligationReceiptVerification::deny(
            vec!["decision_not_conditional".to_string()],
            Vec::new(),
        );
    }
    if decision.obligations.is_empty() {
        return ObligationReceiptVerification::deny(
            vec!["conditional_decision_missing_obligations".to_string()],
            Vec::new(),
        );
    }

    let mut reasons = Vec::new();
    reject_duplicate_decision_obligations(decision, &mut reasons);

    let expected_request_digest = match canonical_authority_request_digest(&decision.request) {
        Ok(digest) => digest,
        Err(error) => {
            return ObligationReceiptVerification::deny(vec![error.reason_code()], Vec::new());
        }
    };

    let raw_receipts = receipts
        .iter()
        .map(ValidatedAuthorityObligationReceipt::receipt)
        .collect::<Vec<_>>();
    reject_duplicate_and_extra_receipts(decision, &raw_receipts, &mut reasons);

    let mut satisfied = Vec::new();
    for obligation in &decision.obligations {
        let matching = raw_receipts
            .iter()
            .filter(|receipt| receipt.obligation_id == obligation.obligation_id)
            .copied()
            .collect::<Vec<_>>();
        let Some(receipt) = matching.first().copied() else {
            push_unique(
                &mut reasons,
                if raw_receipts.is_empty() {
                    "missing_obligation_receipt"
                } else {
                    "obligation_receipt_id_mismatch"
                },
            );
            continue;
        };

        let mut receipt_reasons = Vec::new();
        validate_receipt_against_decision(
            receipt,
            decision,
            &expected_request_digest,
            now,
            &mut receipt_reasons,
        );
        if receipt.kind != obligation.kind {
            push_unique(&mut receipt_reasons, "obligation_receipt_kind_mismatch");
        }
        if obligation.kind == AuthorityObligationKind::ApprovalRequired
            && obligation
                .parameters
                .contains_key(APPROVAL_OBLIGATION_APPROVAL_ID)
        {
            let expected_approval_id = obligation
                .parameters
                .get(APPROVAL_OBLIGATION_APPROVAL_ID)
                .and_then(serde_json::Value::as_str)
                .and_then(|value| ApprovalId::parse(value).ok());
            match (expected_approval_id.as_ref(), receipt.approval_id.as_ref()) {
                (Some(expected), Some(actual)) if expected == actual => {}
                (None, _) => {
                    push_unique(&mut receipt_reasons, "approval_obligation_identity_missing")
                }
                _ => push_unique(
                    &mut receipt_reasons,
                    "obligation_receipt_approval_id_mismatch",
                ),
            }
            if receipt.approval_trace_event_id.is_none() {
                push_unique(
                    &mut receipt_reasons,
                    "obligation_receipt_approval_trace_missing",
                );
            }
        }
        if receipt_reasons.is_empty() {
            satisfied.push(obligation.obligation_id.clone());
        } else {
            for reason in receipt_reasons {
                push_unique_string(&mut reasons, reason);
            }
        }
    }

    if reasons.is_empty()
        && satisfied.len() == decision.obligations.len()
        && raw_receipts.len() == decision.obligations.len()
    {
        ObligationReceiptVerification::allow(satisfied)
    } else {
        ObligationReceiptVerification::deny(reasons, satisfied)
    }
}

fn validate_receipt_authenticated_shape(
    receipt: &AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> Result<(), ObligationReceiptError> {
    if receipt.schema_version != AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION {
        return Err(validation_error("obligation_receipt_schema_unsupported"));
    }
    if receipt.receipt_id.is_nil() {
        return Err(validation_error("obligation_receipt_id_invalid"));
    }
    if receipt.issuer.is_nil() {
        return Err(validation_error("obligation_receipt_issuer_invalid"));
    }
    if receipt.issuer != context.issuer {
        return Err(validation_error("obligation_receipt_issuer_mismatch"));
    }
    validate_token("obligation_receipt.audience", &receipt.audience)?;
    validate_token("obligation_receipt_context.audience", &context.audience)?;
    if receipt.audience != context.audience {
        return Err(validation_error("obligation_receipt_audience_mismatch"));
    }
    if receipt.obligation_id.is_nil() {
        return Err(validation_error("obligation_receipt_obligation_id_invalid"));
    }
    if receipt.subject.is_nil() {
        return Err(validation_error("obligation_receipt_subject_invalid"));
    }
    if receipt.authority_decision_id.is_nil() {
        return Err(validation_error("obligation_receipt_decision_id_invalid"));
    }
    validate_supported_digest(
        "obligation_receipt_request_digest_malformed",
        &receipt.canonical_request_digest,
    )?;
    validate_supported_digest(
        "obligation_receipt_evidence_digest_malformed",
        &receipt.evidence_digest,
    )?;
    if receipt
        .evidence_ref
        .as_deref()
        .is_some_and(|value| !is_safe_reference(value))
    {
        return Err(validation_error(
            "obligation_receipt_evidence_ref_malformed",
        ));
    }
    validate_token("obligation_receipt.revocation_ref", &receipt.revocation_ref)?;
    validate_token(
        "obligation_receipt_context.revocation_ref",
        &context.revocation_ref,
    )?;
    if receipt.revocation_ref != context.revocation_ref {
        return Err(validation_error(
            "obligation_receipt_revocation_ref_mismatch",
        ));
    }
    if receipt.validation.validation_kind
        != AuthorityObligationReceiptValidationKind::LocalSignature
    {
        return Err(validation_error(
            "obligation_receipt_validation_kind_unsupported",
        ));
    }
    if receipt.validation.algorithm != LOCAL_RECEIPT_VALIDATION_ALGORITHM {
        return Err(validation_error("obligation_receipt_algorithm_mismatch"));
    }
    validate_token(
        "obligation_receipt.validation.key_id",
        &receipt.validation.key_id,
    )?;
    validate_token("obligation_receipt_context.key_id", &context.key_id)?;
    if receipt.validation.key_id != context.key_id {
        return Err(validation_error("obligation_receipt_key_mismatch"));
    }
    validate_supported_digest(
        "obligation_receipt_validation_digest_malformed",
        &receipt.validation.digest,
    )?;
    validate_supported_digest(
        "obligation_receipt_signature_malformed",
        &receipt.validation.signature,
    )?;
    if context.validation_secret.trim().is_empty() || context.validation_secret.contains('*') {
        return Err(validation_error(
            "obligation_receipt_validation_secret_unavailable",
        ));
    }
    Ok(())
}

fn validate_receipt_lifecycle(
    receipt: &AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> Result<(), ObligationReceiptError> {
    if context.now < receipt.issued_at {
        return Err(validation_error("obligation_receipt_not_yet_valid"));
    }
    if context.now >= receipt.expires_at {
        return Err(validation_error("obligation_receipt_expired"));
    }
    if matches!(receipt.revocation, RevocationStatus::Revoked { .. }) {
        return Err(validation_error("obligation_receipt_revoked"));
    }
    Ok(())
}

fn reject_duplicate_decision_obligations(decision: &AuthorityDecision, reasons: &mut Vec<String>) {
    for (index, obligation) in decision.obligations.iter().enumerate() {
        if decision
            .obligations
            .iter()
            .skip(index + 1)
            .any(|candidate| candidate.obligation_id == obligation.obligation_id)
        {
            push_unique(reasons, "duplicate_authority_obligation_id");
        }
    }
}

fn reject_duplicate_and_extra_receipts(
    decision: &AuthorityDecision,
    receipts: &[&AuthorityObligationReceipt],
    reasons: &mut Vec<String>,
) {
    for (index, receipt) in receipts.iter().enumerate() {
        if receipts
            .iter()
            .skip(index + 1)
            .any(|candidate| candidate.receipt_id == receipt.receipt_id)
        {
            push_unique(reasons, "duplicate_obligation_receipt_id");
        }
        if receipts
            .iter()
            .skip(index + 1)
            .any(|candidate| candidate.obligation_id == receipt.obligation_id)
        {
            push_unique(reasons, "duplicate_obligation_receipt_obligation_id");
        }
        if !decision
            .obligations
            .iter()
            .any(|obligation| obligation.obligation_id == receipt.obligation_id)
        {
            push_unique(reasons, "extra_obligation_receipt");
        }
    }
}

fn validate_receipt_against_decision(
    receipt: &AuthorityObligationReceipt,
    decision: &AuthorityDecision,
    expected_request_digest: &str,
    now: OffsetDateTime,
    reasons: &mut Vec<String>,
) {
    if receipt.schema_version != AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION {
        push_unique(reasons, "obligation_receipt_schema_unsupported");
    }
    if receipt.subject != decision.request.subject {
        push_unique(reasons, "obligation_receipt_subject_mismatch");
    }
    if receipt.authority_decision_id != decision.decision_id {
        push_unique(reasons, "obligation_receipt_decision_mismatch");
    }
    if !decision
        .request
        .scope
        .audiences
        .as_ref()
        .is_some_and(|audiences| {
            audiences
                .iter()
                .any(|audience| audience == &receipt.audience)
        })
    {
        push_unique(reasons, "obligation_receipt_audience_mismatch");
    }
    if !is_supported_digest(&receipt.canonical_request_digest) {
        push_unique(reasons, "obligation_receipt_request_digest_malformed");
    } else if receipt.canonical_request_digest != expected_request_digest {
        push_unique(reasons, "obligation_receipt_request_digest_mismatch");
    }
    if !is_supported_digest(&receipt.evidence_digest) {
        push_unique(reasons, "obligation_receipt_evidence_digest_malformed");
    }
    if receipt
        .evidence_ref
        .as_deref()
        .is_some_and(|value| !is_safe_reference(value))
    {
        push_unique(reasons, "obligation_receipt_evidence_ref_malformed");
    }
    if now < receipt.issued_at {
        push_unique(reasons, "obligation_receipt_not_yet_valid");
    }
    if now >= receipt.expires_at {
        push_unique(reasons, "obligation_receipt_expired");
    }
    if matches!(receipt.revocation, RevocationStatus::Revoked { .. }) {
        push_unique(reasons, "obligation_receipt_revoked");
    }
}

fn local_obligation_receipt_signature(
    receipt: &AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> Result<String, ObligationReceiptError> {
    let payload_digest = obligation_receipt_validation_digest(receipt)?;
    let signature_material = format!(
        "{}:{}:{}:{}",
        LOCAL_RECEIPT_VALIDATION_ALGORITHM,
        context.key_id,
        context.validation_secret,
        payload_digest
    );
    Ok(ContentHash::blake3(signature_material.as_bytes()).to_string())
}

fn obligation_receipt_validation_digest(
    receipt: &AuthorityObligationReceipt,
) -> Result<String, ObligationReceiptError> {
    let payload = ReceiptValidationPayload {
        schema_version: &receipt.schema_version,
        receipt_id: &receipt.receipt_id,
        issuer: &receipt.issuer,
        audience: &receipt.audience,
        obligation_id: &receipt.obligation_id,
        kind: receipt.kind,
        subject: &receipt.subject,
        authority_decision_id: &receipt.authority_decision_id,
        canonical_request_digest: &receipt.canonical_request_digest,
        evidence_digest: &receipt.evidence_digest,
        evidence_ref: receipt.evidence_ref.as_deref(),
        issued_at: receipt.issued_at,
        expires_at: receipt.expires_at,
        revocation: &receipt.revocation,
        revocation_ref: &receipt.revocation_ref,
        approval_id: receipt.approval_id.as_ref(),
        approval_trace_event_id: receipt.approval_trace_event_id.as_ref(),
    };
    let bytes = serde_json::to_vec(&payload).map_err(|error| {
        ObligationReceiptError::ReceiptValidationDigestUnavailable {
            reason: error.to_string(),
        }
    })?;
    Ok(ContentHash::blake3(bytes).to_string())
}

#[derive(Serialize)]
struct ReceiptValidationPayload<'a> {
    schema_version: &'a str,
    receipt_id: &'a AuthorityObligationReceiptId,
    issuer: &'a PrincipalId,
    audience: &'a str,
    obligation_id: &'a AuthorityObligationId,
    kind: splendor_types::AuthorityObligationKind,
    subject: &'a PrincipalId,
    authority_decision_id: &'a splendor_types::AuthorityDecisionId,
    canonical_request_digest: &'a str,
    evidence_digest: &'a str,
    evidence_ref: Option<&'a str>,
    #[serde(with = "time::serde::rfc3339")]
    issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    revocation: &'a RevocationStatus,
    revocation_ref: &'a str,
    approval_id: Option<&'a splendor_types::ApprovalId>,
    approval_trace_event_id: Option<&'a splendor_types::TraceEventId>,
}

fn validate_supported_digest(
    reason: &'static str,
    value: &str,
) -> Result<(), ObligationReceiptError> {
    if is_supported_digest(value) {
        Ok(())
    } else {
        Err(validation_error(reason))
    }
}

fn is_supported_digest(value: &str) -> bool {
    if value.trim() != value || value.contains('*') {
        return false;
    }
    let Some((algorithm, digest)) = value.split_once(':') else {
        return false;
    };
    matches!(algorithm, "blake3" | "sha256")
        && digest.len() == 64
        && digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn validate_token(_field: &'static str, value: &str) -> Result<(), ObligationReceiptError> {
    if value.trim().is_empty() || value.trim() != value || value.contains('*') {
        return Err(validation_error("obligation_receipt_token_malformed"));
    }
    Ok(())
}

fn is_safe_reference(value: &str) -> bool {
    !value.trim().is_empty() && value.trim() == value && !value.contains('*')
}

fn validation_error(reason: &'static str) -> ObligationReceiptError {
    ObligationReceiptError::ReceiptValidationFailed { reason }
}

fn push_unique(reasons: &mut Vec<String>, reason: &'static str) {
    if !reasons.iter().any(|existing| existing == reason) {
        reasons.push(reason.to_string());
    }
}

fn push_unique_string(reasons: &mut Vec<String>, reason: String) {
    if !reasons.iter().any(|existing| existing == &reason) {
        reasons.push(reason);
    }
}

/// Errors while preparing or validating deterministic obligation receipt
/// evidence.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ObligationReceiptError {
    /// Authority request serialization failed before hashing.
    #[error("authority request digest unavailable: {reason}")]
    RequestDigestUnavailable {
        /// Stable error detail for debugging without request bytes.
        reason: String,
    },
    /// Receipt canonical validation digest could not be prepared.
    #[error("obligation receipt validation digest unavailable: {reason}")]
    ReceiptValidationDigestUnavailable {
        /// Stable error detail for debugging without receipt bytes.
        reason: String,
    },
    /// Receipt validation failed closed with a stable reason.
    #[error("obligation receipt validation failed: {reason}")]
    ReceiptValidationFailed {
        /// Stable reason code.
        reason: &'static str,
    },
}

impl ObligationReceiptError {
    /// Stable reason code for fail-closed decisions and tests.
    pub fn reason_code(&self) -> String {
        match self {
            Self::RequestDigestUnavailable { .. } => "request_digest_unavailable".to_string(),
            Self::ReceiptValidationDigestUnavailable { .. } => {
                "obligation_receipt_validation_digest_unavailable".to_string()
            }
            Self::ReceiptValidationFailed { reason } => (*reason).to_string(),
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/obligation_tests.rs"]
mod tests;
