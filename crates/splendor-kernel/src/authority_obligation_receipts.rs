//! Opaque kernel composition facade for local authority-obligation receipts.
//!
//! Authority owns receipt issuance and validation semantics, while the kernel
//! owns composition for daemon consumers. Request payloads cannot construct the
//! trusted configuration or its process-local one-use ledger.

use splendor_gateway::{
    ActionRequest, AuthorityObligationVerification, AuthorityObligationVerifier,
    LocalAuthorityObligationVerifier,
};
use splendor_types::{
    ApprovalChallenge, AuthorityObligationReceipt, AuthorityObligationReceiptId, InstanceId,
    PrincipalId, RunId, TraceEventId,
};
use std::fmt;
use std::sync::Arc;
use time::OffsetDateTime;

/// Opaque trusted process configuration for local obligation receipts.
///
/// This facade intentionally exposes only the behavior needed by process
/// composition. Authority validation contexts, ledgers, and errors remain
/// private to the kernel composition boundary.
#[derive(Clone)]
pub struct LocalAuthorityObligationReceiptConfig {
    inner: splendor_authority::LocalAuthorityObligationReceiptConfig,
}

impl LocalAuthorityObligationReceiptConfig {
    /// Builds bounded local trusted receipt configuration.
    pub fn trusted_local(
        issuer: PrincipalId,
        audience_prefix: impl Into<String>,
        key_id: impl Into<String>,
        validation_secret: impl Into<String>,
        revocation_ref: impl Into<String>,
    ) -> Result<Self, AuthorityObligationReceiptFacadeError> {
        splendor_authority::LocalAuthorityObligationReceiptConfig::trusted_local(
            issuer,
            audience_prefix,
            key_id,
            validation_secret,
            revocation_ref,
        )
        .map(|inner| Self { inner })
        .map_err(AuthorityObligationReceiptFacadeError::from_authority)
    }

    /// Derives the exact trusted receipt audience for one run.
    pub fn audience_for_run(&self, run_id: &RunId) -> String {
        self.inner.audience_for_run(run_id)
    }

    /// Pins receipt audiences to one trusted resident startup identity.
    pub fn for_resident_instance(
        &self,
        instance_id: &InstanceId,
    ) -> Result<Self, AuthorityObligationReceiptFacadeError> {
        self.inner
            .for_resident_instance(instance_id)
            .map(|inner| Self { inner })
            .map_err(AuthorityObligationReceiptFacadeError::from_authority)
    }

    /// Validates an exact behavior-free approval challenge without issuing.
    pub fn validate_approval_challenge(
        &self,
        challenge: &ApprovalChallenge,
        now: OffsetDateTime,
    ) -> Result<(), AuthorityObligationReceiptFacadeError> {
        self.inner
            .validate_approval_challenge(challenge, now)
            .map_err(AuthorityObligationReceiptFacadeError::from_authority)
    }

    /// Issues one local receipt for an exact, previously recorded challenge.
    pub fn issue_approval_receipt(
        &self,
        challenge: &ApprovalChallenge,
        approval_trace_event_id: TraceEventId,
        issued_at: OffsetDateTime,
    ) -> Result<AuthorityObligationReceipt, AuthorityObligationReceiptFacadeError> {
        self.inner
            .issue_approval_receipt(challenge, approval_trace_event_id, issued_at)
            .map_err(AuthorityObligationReceiptFacadeError::from_authority)
    }

    /// Composes one verifier and one process-local one-use ledger for a run.
    ///
    /// Call this exactly once when admitting a run, then share clones of the
    /// returned `Arc` across every gateway composition for that run.
    pub fn verifier_for_run(
        &self,
        run_id: &RunId,
        now: OffsetDateTime,
    ) -> Arc<AuthorityObligationReceiptVerifier> {
        let ledger =
            Arc::new(splendor_authority::InMemoryAuthorityObligationReceiptLedger::default());
        let context = self.inner.validation_context_for_run(run_id, now);
        Arc::new(AuthorityObligationReceiptVerifier {
            inner: LocalAuthorityObligationVerifier::new(context.clone(), ledger.clone()),
            context,
            ledger,
        })
    }
}

impl fmt::Debug for LocalAuthorityObligationReceiptConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalAuthorityObligationReceiptConfig")
            .field("configuration", &"<opaque>")
            .finish()
    }
}

/// Opaque verifier composed with exactly one authority-owned receipt ledger.
pub struct AuthorityObligationReceiptVerifier {
    inner: LocalAuthorityObligationVerifier,
    context: splendor_authority::AuthorityObligationReceiptValidationContext,
    ledger: Arc<splendor_authority::InMemoryAuthorityObligationReceiptLedger>,
}

/// Known atomic receipt-revocation outcome returned through the opaque facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityObligationReceiptRevocation {
    /// Revocation won the race and wrote both tombstones.
    Revoked,
    /// Revocation had already won for this exact or semantic receipt.
    AlreadyRevoked,
    /// Gateway claim had already won, so revocation is too late.
    AlreadyClaimed,
}

impl AuthorityObligationReceiptVerifier {
    /// Validates and atomically revokes one exact path-bound receipt using the
    /// same authority-owned ledger shared by gateway claims for this run.
    pub fn revoke_receipt(
        &self,
        expected_receipt_id: &AuthorityObligationReceiptId,
        receipt: &AuthorityObligationReceipt,
        now: OffsetDateTime,
    ) -> Result<AuthorityObligationReceiptRevocation, AuthorityObligationReceiptFacadeError> {
        if &receipt.receipt_id != expected_receipt_id {
            return Err(AuthorityObligationReceiptFacadeError {
                reason_code: "authority_obligation_receipt_id_mismatch".to_string(),
            });
        }
        use splendor_authority::AuthorityObligationReceiptLedger as _;
        self.ledger
            .revoke_receipt(receipt, &self.context, now)
            .map(|outcome| match outcome {
                splendor_authority::AuthorityObligationReceiptRevocationOutcome::Revoked => {
                    AuthorityObligationReceiptRevocation::Revoked
                }
                splendor_authority::AuthorityObligationReceiptRevocationOutcome::AlreadyRevoked => {
                    AuthorityObligationReceiptRevocation::AlreadyRevoked
                }
                splendor_authority::AuthorityObligationReceiptRevocationOutcome::AlreadyClaimed => {
                    AuthorityObligationReceiptRevocation::AlreadyClaimed
                }
            })
            .map_err(AuthorityObligationReceiptFacadeError::from_ledger)
    }
}

impl fmt::Debug for AuthorityObligationReceiptVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityObligationReceiptVerifier")
            .finish_non_exhaustive()
    }
}

impl AuthorityObligationVerifier for AuthorityObligationReceiptVerifier {
    fn verify_obligations(
        &self,
        action: &ActionRequest,
        adapter: Option<&str>,
        now: OffsetDateTime,
    ) -> AuthorityObligationVerification {
        self.inner.verify_obligations(action, adapter, now)
    }

    fn claim_verified_receipts(
        &self,
        receipts: &[AuthorityObligationReceipt],
        now: OffsetDateTime,
    ) -> AuthorityObligationVerification {
        self.inner.claim_verified_receipts(receipts, now)
    }
}

/// Stable facade error that reveals only a machine-readable reason code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityObligationReceiptFacadeError {
    reason_code: String,
}

impl AuthorityObligationReceiptFacadeError {
    fn from_authority(error: splendor_authority::ObligationReceiptError) -> Self {
        Self {
            reason_code: error.reason_code(),
        }
    }

    fn from_ledger(error: splendor_authority::ObligationReceiptLedgerError) -> Self {
        Self {
            reason_code: error.reason_code(),
        }
    }

    /// Stable fail-closed reason code.
    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }
}

impl fmt::Display for AuthorityObligationReceiptFacadeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.reason_code)
    }
}

impl std::error::Error for AuthorityObligationReceiptFacadeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use splendor_types::{
        Action, ActionId, AgentId, ApprovalId, AuthorityDecisionId, AuthorityObligationId,
        QuotaUsage, SideEffectClass, TenantId, APPROVAL_CHALLENGE_SCHEMA_VERSION,
    };
    use time::Duration;

    fn config() -> LocalAuthorityObligationReceiptConfig {
        LocalAuthorityObligationReceiptConfig::trusted_local(
            PrincipalId::new(),
            "splendor.daemon.run",
            "approval-receipt-local-key",
            "splendor-local-approval-receipt-secret-v1",
            "local-approval-receipts",
        )
        .expect("receipt config")
    }

    fn challenge(
        config: &LocalAuthorityObligationReceiptConfig,
        run_id: RunId,
        now: OffsetDateTime,
    ) -> ApprovalChallenge {
        ApprovalChallenge {
            schema_version: APPROVAL_CHALLENGE_SCHEMA_VERSION.to_string(),
            approval_id: ApprovalId::new(),
            tenant_id: TenantId::new(),
            agent_id: AgentId::new(),
            run_id: run_id.clone(),
            action_id: ActionId::new(),
            action_name: "artifact.publish".to_string(),
            adapter: "artifact-store".to_string(),
            policy_id: "approval-policy".to_string(),
            risk_level: Some("high".to_string()),
            subject: PrincipalId::new(),
            authority_decision_id: AuthorityDecisionId::new(),
            obligation_id: AuthorityObligationId::new(),
            receipt_audience: config.audience_for_run(&run_id),
            canonical_request_digest: format!("blake3:{}", "1".repeat(64)),
            gateway_action_request_digest: format!("blake3:{}", "2".repeat(64)),
            physical_action_resource_coordinate: None,
            authority_decision_digest: format!("blake3:{}", "3".repeat(64)),
            requested_at: now - Duration::seconds(1),
            expires_at: now + Duration::minutes(5),
        }
    }

    #[test]
    fn facade_exposes_stable_reason_code_without_authority_error() {
        let error = LocalAuthorityObligationReceiptConfig::trusted_local(
            PrincipalId::new(),
            "splendor.daemon.run",
            "approval-receipt-local-key",
            "short",
            "local-approval-receipts",
        )
        .expect_err("short secret must fail closed");

        assert_eq!(
            error.reason_code(),
            "obligation_receipt_validation_secret_unavailable"
        );
        assert_eq!(error.to_string(), error.reason_code());
    }

    #[test]
    fn facade_debug_output_keeps_trusted_configuration_opaque() {
        let now = OffsetDateTime::now_utc();
        let run_id = RunId::new();
        let config = config();

        assert_eq!(
            format!("{config:?}"),
            "LocalAuthorityObligationReceiptConfig { configuration: \"<opaque>\" }"
        );
        assert_eq!(
            format!("{:?}", config.verifier_for_run(&run_id, now)),
            "AuthorityObligationReceiptVerifier { .. }"
        );
    }

    #[test]
    fn facade_preserves_challenge_validation_and_issuance_failures() {
        let now = OffsetDateTime::now_utc();
        let run_id = RunId::new();
        let config = config();
        let valid_challenge = challenge(&config, run_id, now);

        let mut wrong_audience = valid_challenge.clone();
        wrong_audience.receipt_audience = "splendor.daemon.run:wrong-run".to_string();
        assert_eq!(
            config
                .validate_approval_challenge(&wrong_audience, now)
                .expect_err("wrong audience must fail closed")
                .reason_code(),
            "approval_challenge_scope_invalid"
        );

        let mut expired = valid_challenge;
        expired.expires_at = now;
        assert_eq!(
            config
                .issue_approval_receipt(&expired, TraceEventId::new(), now)
                .expect_err("expired challenge must not issue a receipt")
                .reason_code(),
            "approval_challenge_expired_or_future"
        );
    }

    #[test]
    fn facade_verifier_delegates_non_obligation_paths() {
        let now = OffsetDateTime::now_utc();
        let run_id = RunId::new();
        let verifier = config().verifier_for_run(&run_id, now);
        let action = ActionRequest {
            action_id: ActionId::new(),
            tenant_id: TenantId::new(),
            agent_id: AgentId::new(),
            run_id,
            tick_id: None,
            action: Action {
                name: "artifact.publish".to_string(),
                params: serde_json::json!({"artifact_id": "artifact-1"}),
                side_effect_class: SideEffectClass::External,
                cost_estimate: None,
                required_permissions: vec!["artifact.publish".to_string()],
                preconditions: Vec::new(),
                postconditions: Vec::new(),
            },
            adapter: Some("artifact-store".to_string()),
            quota_usage: QuotaUsage::single_action(),
            satisfied_preconditions: Vec::new(),
            requested_at: now,
            physical_action_resource_coordinate: None,
            approval_evidence: None,
            authority_obligation_evidence: None,
            authority_obligation_receipts: Vec::new(),
        };

        assert!(matches!(
            verifier.verify_obligations(&action, action.adapter.as_deref(), now),
            AuthorityObligationVerification::NotRequired
        ));
        assert!(matches!(
            verifier.claim_verified_receipts(&[], now),
            AuthorityObligationVerification::NotRequired
        ));
    }

    #[test]
    fn one_run_verifier_arc_shares_one_use_ledger_across_gateway_compositions() {
        let now = OffsetDateTime::now_utc();
        let run_id = RunId::new();
        let config = config();
        let challenge = challenge(&config, run_id.clone(), now);
        config
            .validate_approval_challenge(&challenge, now)
            .expect("challenge valid");
        let receipt = config
            .issue_approval_receipt(&challenge, TraceEventId::new(), now)
            .expect("receipt issued");

        let verifier = config.verifier_for_run(&run_id, now);
        let normal_gateway: Arc<dyn AuthorityObligationVerifier> = verifier.clone();
        let physical_gateway: Arc<dyn AuthorityObligationVerifier> = verifier;

        assert!(matches!(
            normal_gateway.claim_verified_receipts(std::slice::from_ref(&receipt), now),
            AuthorityObligationVerification::Permitted { .. }
        ));
        let replay = physical_gateway
            .claim_verified_receipts(std::slice::from_ref(&receipt), now + Duration::seconds(1));
        let AuthorityObligationVerification::Denied(result) = replay else {
            panic!("shared ledger must reject replay");
        };
        assert!(result
            .reasons
            .contains(&"authority_obligation_receipt_replayed".to_string()));
    }

    #[test]
    fn facade_revocation_reports_too_late_after_shared_ledger_claim() {
        let now = OffsetDateTime::now_utc();
        let run_id = RunId::new();
        let config = config();
        let challenge = challenge(&config, run_id.clone(), now);
        let receipt = config
            .issue_approval_receipt(&challenge, TraceEventId::new(), now)
            .expect("receipt");
        let verifier = config.verifier_for_run(&run_id, now);

        assert!(matches!(
            verifier.claim_verified_receipts(std::slice::from_ref(&receipt), now),
            AuthorityObligationVerification::Permitted { .. }
        ));
        assert_eq!(
            verifier
                .revoke_receipt(&receipt.receipt_id, &receipt, now)
                .expect("known late revocation"),
            AuthorityObligationReceiptRevocation::AlreadyClaimed
        );
    }

    #[test]
    fn facade_revocation_rejects_path_receipt_identity_mismatch_without_tombstone() {
        let now = OffsetDateTime::now_utc();
        let run_id = RunId::new();
        let config = config();
        let challenge = challenge(&config, run_id.clone(), now);
        let receipt = config
            .issue_approval_receipt(&challenge, TraceEventId::new(), now)
            .expect("receipt");
        let verifier = config.verifier_for_run(&run_id, now);

        let error = verifier
            .revoke_receipt(&AuthorityObligationReceiptId::new(), &receipt, now)
            .expect_err("path-bound receipt identity mismatch rejected");
        assert_eq!(
            error.reason_code(),
            "authority_obligation_receipt_id_mismatch"
        );
        assert_eq!(
            verifier
                .revoke_receipt(&receipt.receipt_id, &receipt, now)
                .expect("mismatch did not poison exact receipt"),
            AuthorityObligationReceiptRevocation::Revoked
        );
    }
}
