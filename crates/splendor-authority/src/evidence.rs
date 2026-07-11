//! Bounded AUTH-006a authority decision evidence and explainability.
//!
//! These records are local, deterministic inspection artifacts. They are never
//! authority and cannot satisfy a capability, verifier, obligation, approval, or
//! gateway. The module deliberately records digests and typed summaries instead
//! of request scopes, request/grant metadata, signatures, key identifiers,
//! credentials, obligation descriptions, or obligation parameters.

use crate::{
    evaluate_cached_capability_request, evaluate_capability_request, AuthorityConnectivity,
    AuthorityGrantCache, CachedAuthorityGrant, OfflineAuthorityPolicy, RevocationSnapshot,
    ValidatedCapabilityGrant,
};
use serde::{Deserialize, Serialize};
use splendor_types::{
    AuthorityDecision, AuthorityDecisionId, AuthorityDecisionStatus, AuthorityObligationId,
    AuthorityObligationKind, AuthorityOperation, AuthorityOperationNamespace,
    AuthorityResourceKind, AuthorityVerb, CapabilityGrantId, CapabilityGrantValidationKind,
    CapabilityRequest, CapabilityScope, ContentHash, PrincipalId, RevocationStatus,
    AUTHORITY_DECISION_SCHEMA_VERSION, AUTHORITY_OPERATION_SCHEMA_VERSION,
    CAPABILITY_GRANT_SCHEMA_VERSION,
};
use std::collections::BTreeSet;
use thiserror::Error;
use time::OffsetDateTime;

/// Local schema identifier for bounded authority decision evidence.
pub const AUTHORITY_DECISION_EVIDENCE_SCHEMA_VERSION: &str =
    "splendor.authority.decision_evidence.local.v1";

/// How much evaluator context was available when evidence was recorded.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityEvidenceCompleteness {
    /// Only an already-produced decision was available.
    DecisionOnly,
    /// The validated grants supplied to the normal evaluator were available.
    GrantEvaluation,
    /// Cached grants and cache/snapshot freshness facts were available.
    CachedEvaluation,
}

/// Facts that the current local evaluator did not provide.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityEvidenceMissingFact {
    /// Validated grant inputs were not supplied with an existing decision.
    SuppliedGrants,
    /// Cache and revocation-snapshot freshness were not supplied.
    CacheFreshness,
    /// No versioned policy reference exists in the current evaluator contract.
    PolicyRefs,
    /// No separate data-use decision references exist in the current evaluator contract.
    DataUseRefs,
    /// Exact request/scope/metadata binding requires a future keyed evidence service.
    ExactRequestBinding,
    /// Exact concrete operation-name binding is withheld without keyed redaction.
    ProtectedOperationBinding,
}

/// Sensitive or free-form fields intentionally excluded from evidence records.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityEvidenceWithheldField {
    /// Raw request scope coordinates are withheld without an exact request digest.
    RequestScopeValues,
    /// Arbitrary request and grant metadata is never copied into evidence.
    RawMetadata,
    /// Signatures, key IDs/material, and validation algorithms are never copied.
    ValidationSecretsAndKeys,
    /// Free-form obligation descriptions and parameters are never copied.
    ObligationDetails,
    /// Concrete operation names are omitted from tenant/operator redacted views.
    RedactedOperationName,
}

/// Stable high-level explanation categories.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityExplanationCategory {
    /// Explicit successful authority match.
    Allowed,
    /// Identity, schema, shape, validation, or subject failure.
    IdentityValidation,
    /// Operation, audience, or scope mismatch.
    Scope,
    /// Grant or revocation-snapshot revocation result.
    Revocation,
    /// Expiry, not-before, or other time-window result.
    ExpiryTime,
    /// Quota or budget constraint.
    QuotaBudget,
    /// Data-purpose or data-use constraint.
    DataUse,
    /// Conditional authority, obligation, approval, intervention, or gate result.
    ObligationsGate,
    /// Cache, snapshot, connectivity, or offline freshness result.
    CacheFreshness,
    /// Provider/verifier uncertainty or an otherwise unknown stable reason.
    ProviderUnknown,
}

/// One deterministic branch in the authority explanation tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityExplanationBranch {
    /// Category represented by this branch.
    pub category: AuthorityExplanationCategory,
    /// Sorted, de-duplicated stable reason codes in the category.
    pub reason_codes: Vec<String>,
}

/// Deterministic explanation tree grouped by stable categories.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityDecisionExplanation {
    /// Branches sorted by category.
    pub branches: Vec<AuthorityExplanationBranch>,
}

/// Safe reference to one validated grant revision supplied to an evaluator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityGrantEvidence {
    /// Evaluated grant identity.
    pub grant_id: CapabilityGrantId,
    /// Whether the resulting decision identified this grant as matched.
    pub matched: bool,
    /// Validation kind, without algorithm, key ID, signature, or key material.
    pub validation_kind: CapabilityGrantValidationKind,
    /// Domain-separated digest of the validation token; the raw token is never copied.
    pub validation_token_digest: String,
    /// Restricted digest over safe/canonical grant revision facts.
    pub revision_digest: String,
}

/// Tenant/operator grant projection without restricted revision/token digests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RedactedAuthorityGrantEvidence {
    /// Supplied grant identity.
    pub grant_id: CapabilityGrantId,
    /// Whether the decision identified this grant as matched.
    pub matched: bool,
    /// Validation kind only; validation tokens/material are withheld.
    pub validation_kind: CapabilityGrantValidationKind,
}

/// Safe obligation identity/kind projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityObligationEvidence {
    /// Obligation identity.
    pub obligation_id: AuthorityObligationId,
    /// Typed obligation kind.
    pub kind: AuthorityObligationKind,
}

/// Cache or snapshot freshness classification at the decision timestamp.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityFreshnessStatus {
    /// Required cache/snapshot input was absent.
    Missing,
    /// Input was live within its configured window.
    Fresh,
    /// Input exceeded its configured freshness window.
    Stale,
    /// Input claimed a refresh/install time after the decision time.
    FutureDated,
    /// A cache entry or wrapped grant was expired.
    Expired,
}

/// Freshness evidence for one cached validated grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityCacheEntryEvidence {
    /// Cached grant identity.
    pub grant_id: CapabilityGrantId,
    /// Local cache installation time.
    #[serde(with = "time::serde::rfc3339")]
    pub cached_at: OffsetDateTime,
    /// Local cache expiry, which cannot extend grant expiry.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Freshness against `max_cache_staleness` at decision time.
    pub cache_freshness: AuthorityFreshnessStatus,
    /// Disconnected TTL freshness, absent in connected mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_ttl_freshness: Option<AuthorityFreshnessStatus>,
    /// Effective freshness after cache, grant expiry, and offline TTL checks.
    pub effective_freshness: AuthorityFreshnessStatus,
}

/// Freshness evidence for the revocation snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityRevocationSnapshotEvidence {
    /// Snapshot refresh time, absent when no snapshot was supplied.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub refreshed_at: Option<OffsetDateTime>,
    /// Snapshot expiry, absent when no snapshot was supplied.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// Freshness result at decision time.
    pub freshness: AuthorityFreshnessStatus,
}

/// Cache/snapshot facts available to the bounded cached evaluator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityCachedEvaluationEvidence {
    /// Explicit connected/disconnected evaluator mode.
    pub connectivity: AuthorityConnectivityEvidence,
    /// True when no cached grant existed.
    pub cache_missing: bool,
    /// Per-entry freshness facts sorted by grant identity.
    pub cache_entries: Vec<AuthorityCacheEntryEvidence>,
    /// Revocation snapshot freshness without raw revocation records or refs.
    pub revocation_snapshot: AuthorityRevocationSnapshotEvidence,
}

/// Serializable connectivity projection for evidence only.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityConnectivityEvidence {
    /// Connected evaluation mode.
    Connected,
    /// Explicit safe-degraded disconnected evaluation mode.
    Disconnected,
}

/// Safe source decision schema classification. Raw caller schema strings are never copied.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityDecisionSchemaEvidence {
    /// Source decision used the canonical authority decision schema.
    Canonical,
    /// Source decision schema was not canonical; its raw value is withheld.
    Invalid,
}

impl From<AuthorityConnectivity> for AuthorityConnectivityEvidence {
    fn from(value: AuthorityConnectivity) -> Self {
        match value {
            AuthorityConnectivity::Connected => Self::Connected,
            AuthorityConnectivity::Disconnected => Self::Disconnected,
        }
    }
}

/// Restricted local authority decision evidence.
///
/// This record intentionally excludes every raw credential, signature, key
/// identifier/material, metadata value, request scope value, concrete operation
/// name, protected-eval identifier, and free-form obligation detail.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityDecisionEvidence {
    /// Local evidence schema version.
    pub schema_version: String,
    /// Explicit completeness of this evidence projection.
    pub completeness: AuthorityEvidenceCompleteness,
    /// Original decision identity.
    pub decision_id: AuthorityDecisionId,
    /// Safe classification of the source decision schema.
    pub decision_schema: AuthorityDecisionSchemaEvidence,
    /// Original decision status.
    pub status: AuthorityDecisionStatus,
    /// Original decision timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub decided_at: OffsetDateTime,
    /// Request subject identity.
    pub subject: PrincipalId,
    /// Requested typed operation classification without caller schema/name strings.
    pub operation: RedactedAuthorityOperation,
    /// Deterministic domain-separated digest over only the safe recorded fact set.
    pub decision_digest: String,
    /// Sorted, de-duplicated stable reason codes.
    pub reason_codes: Vec<String>,
    /// Deterministic explanation branches.
    pub explanation: AuthorityDecisionExplanation,
    /// Validated grant inputs supplied to an evaluator wrapper. `matched` is the
    /// only traversal outcome asserted per grant; input order/short-circuit path
    /// is not fabricated by this bounded evidence model.
    pub supplied_grants: Vec<AuthorityGrantEvidence>,
    /// Matched grant identities from the decision, sorted deterministically.
    pub matched_grant_ids: Vec<CapabilityGrantId>,
    /// Obligation identity/kind only; descriptions/parameters are never copied.
    pub obligations: Vec<AuthorityObligationEvidence>,
    /// Cache/snapshot facts only for cached evaluation wrappers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_evaluation: Option<AuthorityCachedEvaluationEvidence>,
    /// Facts not supplied by current contracts.
    pub missing_facts: Vec<AuthorityEvidenceMissingFact>,
    /// Fields deliberately withheld from this evidence model.
    pub withheld_fields: Vec<AuthorityEvidenceWithheldField>,
}

/// Typed operation summary safe for tenant/operator views.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RedactedAuthorityOperation {
    /// Canonical operation schema marker, never the caller-provided value.
    pub schema_version: String,
    /// Typed namespace.
    pub namespace: AuthorityOperationNamespace,
    /// Typed resource kind.
    pub resource_kind: AuthorityResourceKind,
    /// Typed verb.
    pub verb: AuthorityVerb,
    /// Whether the source operation schema matched the canonical marker.
    pub source_schema_valid: bool,
    /// Whether a concrete operation name was present and withheld.
    pub concrete_name_withheld: bool,
    /// Whether a caller-provided resource schema was present and withheld.
    pub resource_schema_withheld: bool,
}

/// Deterministic tenant/operator evidence view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RedactedAuthorityDecisionEvidence {
    /// Same evidence schema as the restricted record.
    pub schema_version: String,
    /// Same explicit completeness classification.
    pub completeness: AuthorityEvidenceCompleteness,
    /// Preserved decision identity.
    pub decision_id: AuthorityDecisionId,
    /// Preserved safe source schema classification.
    pub decision_schema: AuthorityDecisionSchemaEvidence,
    /// Preserved decision status.
    pub status: AuthorityDecisionStatus,
    /// Preserved decision timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub decided_at: OffsetDateTime,
    /// Preserved subject identity.
    pub subject: PrincipalId,
    /// Typed operation shape without its concrete optional name.
    pub operation: RedactedAuthorityOperation,
    /// Preserved decision/evidence digest.
    pub decision_digest: String,
    /// Preserved stable reason codes.
    pub reason_codes: Vec<String>,
    /// Preserved explanation shape.
    pub explanation: AuthorityDecisionExplanation,
    /// Preserved grant identity/outcome without restricted token/revision digests.
    pub supplied_grants: Vec<RedactedAuthorityGrantEvidence>,
    /// Preserved matched grant identities.
    pub matched_grant_ids: Vec<CapabilityGrantId>,
    /// Preserved obligation identity/kind only.
    pub obligations: Vec<AuthorityObligationEvidence>,
    /// Preserved bounded freshness facts.
    pub cached_evaluation: Option<AuthorityCachedEvaluationEvidence>,
    /// Preserved missing-fact declarations.
    pub missing_facts: Vec<AuthorityEvidenceMissingFact>,
    /// Preserved/extended withheld-field declarations.
    pub withheld_fields: Vec<AuthorityEvidenceWithheldField>,
}

impl AuthorityDecisionEvidence {
    /// Produces a deterministic tenant/operator view without raw operation names.
    pub fn redacted(&self) -> Result<RedactedAuthorityDecisionEvidence, AuthorityEvidenceError> {
        Ok(RedactedAuthorityDecisionEvidence {
            schema_version: self.schema_version.clone(),
            completeness: self.completeness,
            decision_id: self.decision_id.clone(),
            decision_schema: self.decision_schema,
            status: self.status,
            decided_at: self.decided_at,
            subject: self.subject.clone(),
            operation: self.operation.clone(),
            decision_digest: self.decision_digest.clone(),
            reason_codes: self.reason_codes.clone(),
            explanation: self.explanation.clone(),
            supplied_grants: self
                .supplied_grants
                .iter()
                .map(|grant| RedactedAuthorityGrantEvidence {
                    grant_id: grant.grant_id.clone(),
                    matched: grant.matched,
                    validation_kind: grant.validation_kind,
                })
                .collect(),
            matched_grant_ids: self.matched_grant_ids.clone(),
            obligations: self.obligations.clone(),
            cached_evaluation: self.cached_evaluation.clone(),
            missing_facts: self.missing_facts.clone(),
            withheld_fields: self.withheld_fields.clone(),
        })
    }
}

/// A decision plus evidence produced through the normal validated-grant evaluator.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorityDecisionWithEvidence {
    /// Unchanged evaluator decision.
    pub decision: AuthorityDecision,
    /// Non-authorizing local evidence for that decision.
    pub evidence: AuthorityDecisionEvidence,
}

/// Records a decision-only projection without fabricating grant/cache/policy facts.
pub fn authority_decision_evidence(
    decision: &AuthorityDecision,
) -> Result<AuthorityDecisionEvidence, AuthorityEvidenceError> {
    build_evidence(
        decision,
        AuthorityEvidenceCompleteness::DecisionOnly,
        Vec::new(),
        None,
    )
}

/// Runs the existing validated-grant evaluator unchanged and records the supplied
/// grant revision facts. If evidence construction fails, this evidence-required
/// wrapper returns an error rather than fabricating evidence or authority.
pub fn evaluate_capability_request_with_evidence(
    grants: &[ValidatedCapabilityGrant],
    request: &CapabilityRequest,
    now: OffsetDateTime,
) -> Result<AuthorityDecisionWithEvidence, AuthorityEvidenceError> {
    let decision = evaluate_capability_request(grants, request, now);
    let grant_evidence = grants
        .iter()
        .map(|grant| grant_evidence(grant, &decision))
        .collect::<Result<Vec<_>, _>>()?;
    let evidence = build_evidence(
        &decision,
        AuthorityEvidenceCompleteness::GrantEvaluation,
        grant_evidence,
        None,
    )?;
    Ok(AuthorityDecisionWithEvidence { decision, evidence })
}

/// Runs the existing cached/offline evaluator unchanged and records only the
/// cache/snapshot facts already available to that call. Stale/future/missing data
/// remains evidence of denial or uncertainty and never becomes authority.
pub fn evaluate_cached_capability_request_with_evidence(
    cache: &AuthorityGrantCache,
    revocations: Option<&RevocationSnapshot>,
    policy: &OfflineAuthorityPolicy,
    request: &CapabilityRequest,
    now: OffsetDateTime,
) -> Result<AuthorityDecisionWithEvidence, AuthorityEvidenceError> {
    let decision = evaluate_cached_capability_request(cache, revocations, policy, request, now);
    let grant_evidence = cache
        .cached_grants()
        .iter()
        .map(|cached| grant_evidence(cached.grant(), &decision))
        .collect::<Result<Vec<_>, _>>()?;
    let cached_evaluation = Some(cached_evaluation_evidence(cache, revocations, policy, now));
    let evidence = build_evidence(
        &decision,
        AuthorityEvidenceCompleteness::CachedEvaluation,
        grant_evidence,
        cached_evaluation,
    )?;
    Ok(AuthorityDecisionWithEvidence { decision, evidence })
}

/// Stable labels for inspect-only evidence comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityEvidenceComparisonLabel {
    /// Already-recorded historical evidence.
    Historical,
    /// Already-recorded current evidence.
    Current,
    /// Already-recorded counterfactual/simulated evidence.
    Counterfactual,
}

/// Inspect-only comparison between two already-recorded evidence records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityEvidenceComparison {
    /// Label for the left record.
    pub left_label: AuthorityEvidenceComparisonLabel,
    /// Label for the right record.
    pub right_label: AuthorityEvidenceComparisonLabel,
    /// Left evidence digest.
    pub left_decision_digest: String,
    /// Right evidence digest.
    pub right_decision_digest: String,
    /// Whether decision status changed.
    pub status_changed: bool,
    /// Whether the recorded decision/evidence digest changed.
    pub decision_digest_changed: bool,
    /// Whether restricted supplied-grant revision facts changed.
    pub grant_revision_changed: bool,
    /// Sorted reason codes only on the left.
    pub removed_reason_codes: Vec<String>,
    /// Sorted reason codes only on the right.
    pub added_reason_codes: Vec<String>,
}

/// Compares two recorded evidence objects without policy evaluation, secret
/// resolution, revocation lookup, gateway/adapter calls, or history mutation.
pub fn compare_authority_evidence(
    left_label: AuthorityEvidenceComparisonLabel,
    left: &AuthorityDecisionEvidence,
    right_label: AuthorityEvidenceComparisonLabel,
    right: &AuthorityDecisionEvidence,
) -> AuthorityEvidenceComparison {
    let left_reasons = left.reason_codes.iter().cloned().collect::<BTreeSet<_>>();
    let right_reasons = right.reason_codes.iter().cloned().collect::<BTreeSet<_>>();
    AuthorityEvidenceComparison {
        left_label,
        right_label,
        left_decision_digest: left.decision_digest.clone(),
        right_decision_digest: right.decision_digest.clone(),
        status_changed: left.status != right.status,
        decision_digest_changed: left.decision_digest != right.decision_digest,
        grant_revision_changed: restricted_grant_revision_facts(left)
            != restricted_grant_revision_facts(right),
        removed_reason_codes: left_reasons.difference(&right_reasons).cloned().collect(),
        added_reason_codes: right_reasons.difference(&left_reasons).cloned().collect(),
    }
}

fn restricted_grant_revision_facts(
    evidence: &AuthorityDecisionEvidence,
) -> Vec<(String, String, String)> {
    evidence
        .supplied_grants
        .iter()
        .map(|grant| {
            (
                grant.grant_id.to_string(),
                grant.validation_token_digest.clone(),
                grant.revision_digest.clone(),
            )
        })
        .collect()
}

/// Maps one stable reason code to a deterministic explanation category.
pub fn authority_reason_category(reason: &str) -> AuthorityExplanationCategory {
    normalize_authority_reason(reason).category
}

/// Normalizes any evaluator/requester reason into a bounded static code.
pub fn normalize_authority_reason_code(reason: &str) -> &'static str {
    normalize_authority_reason(reason).code
}

#[derive(Clone, Copy)]
struct NormalizedAuthorityReason {
    code: &'static str,
    category: AuthorityExplanationCategory,
}

fn normalized(
    code: &'static str,
    category: AuthorityExplanationCategory,
) -> NormalizedAuthorityReason {
    NormalizedAuthorityReason { code, category }
}

fn normalize_authority_reason(reason: &str) -> NormalizedAuthorityReason {
    use AuthorityExplanationCategory as Category;

    if reason.len() > 256 || reason.chars().any(char::is_control) {
        return normalized("authority_reason_unknown", Category::ProviderUnknown);
    }

    match reason {
        "capability_allowed" | "authority_allowed" => {
            normalized("capability_allowed", Category::Allowed)
        }
        "capability_conditional" => normalized("capability_conditional", Category::ObligationsGate),
        "missing_capability_grant" => {
            normalized("missing_capability_grant", Category::IdentityValidation)
        }
        "capability_denied" => normalized("capability_denied", Category::ProviderUnknown),
        "metadata_reserved_authority_key" => normalized(
            "metadata_reserved_authority_key",
            Category::IdentityValidation,
        ),
        "subject_mismatch" => normalized("subject_mismatch", Category::IdentityValidation),
        "grant_not_yet_valid" => normalized("grant_not_yet_valid", Category::ExpiryTime),
        "expired_grant" => normalized("expired_grant", Category::ExpiryTime),
        "revoked_grant" | "authority_grant_revoked" => {
            normalized("authority_grant_revoked", Category::Revocation)
        }
        "operation_not_granted" => normalized("operation_not_granted", Category::Scope),
        "data_purpose_missing_for_operation" => {
            normalized("data_use_scope_mismatch", Category::DataUse)
        }
        "authority_cache_missing" => {
            normalized("authority_cache_missing", Category::CacheFreshness)
        }
        "authority_cache_expired" => {
            normalized("authority_cache_expired", Category::CacheFreshness)
        }
        "authority_cache_stale" => normalized("authority_cache_stale", Category::CacheFreshness),
        "authority_cache_future_dated" => {
            normalized("authority_cache_future_dated", Category::CacheFreshness)
        }
        "authority_revocation_snapshot_missing" => normalized(
            "authority_revocation_snapshot_missing",
            Category::CacheFreshness,
        ),
        "authority_revocation_snapshot_stale" => normalized(
            "authority_revocation_snapshot_stale",
            Category::CacheFreshness,
        ),
        "authority_revocation_snapshot_future_dated" => normalized(
            "authority_revocation_snapshot_future_dated",
            Category::CacheFreshness,
        ),
        "authority_revocation_ref_mismatch" => {
            normalized("authority_revocation_ref_mismatch", Category::Revocation)
        }
        "authority_offline_ttl_expired" => {
            normalized("authority_offline_ttl_expired", Category::CacheFreshness)
        }
        "authority_offline_unsupported_operation" => normalized(
            "authority_offline_unsupported_operation",
            Category::ObligationsGate,
        ),
        "authority_offline_high_risk_denied" => normalized(
            "authority_offline_high_risk_denied",
            Category::ObligationsGate,
        ),
        "authority_offline_high_risk_needs_intervention" => normalized(
            "authority_offline_high_risk_needs_intervention",
            Category::ObligationsGate,
        ),
        "authority_scope_mismatch" => normalized("authority_scope_mismatch", Category::Scope),
        _ => normalize_prefixed_authority_reason(reason),
    }
}

fn normalize_prefixed_authority_reason(reason: &str) -> NormalizedAuthorityReason {
    use AuthorityExplanationCategory as Category;

    if matches!(
        reason,
        "invalid_schema:capability_request.schema_version"
            | "invalid_schema:capability_grant.schema_version"
            | "invalid_schema:authority_operation.schema_version"
            | "invalid_schema:capability_scope.schema_version"
            | "invalid_schema:authority_obligation.schema_version"
    ) {
        normalized("invalid_schema", Category::IdentityValidation)
    } else if matches!(
        reason,
        "invalid_identity:subject"
            | "invalid_identity:grant_id"
            | "invalid_identity:issuer"
            | "invalid_identity:obligation_id"
    ) {
        normalized("invalid_identity", Category::IdentityValidation)
    } else if matches!(
        reason,
        "invalid_operation:missing_operations"
            | "invalid_operation:operation_tuple_not_allowed"
            | "invalid_operation:operation_name_required"
            | "invalid_operation:operation_name_not_allowed_for_typed_tuple"
    ) {
        normalized("invalid_operation", Category::IdentityValidation)
    } else if reason
        .strip_prefix("invalid_token:")
        .is_some_and(is_evaluator_token_field)
    {
        normalized("invalid_token", Category::IdentityValidation)
    } else if matches!(
        reason,
        "invalid_validation:verified_work_order_grant_requires_signed_validation"
            | "invalid_validation:missing_grant_validation"
            | "invalid_validation:signed_grant_verifier_unavailable"
            | "invalid_validation:verified_signed_grant_missing_key_id"
            | "invalid_validation:verified_grant_requires_signed_validation"
    ) {
        normalized("invalid_validation", Category::IdentityValidation)
    } else if let Some(category) = invalid_scope_reason_category(reason) {
        normalized("invalid_scope", category)
    } else if reason
        .strip_prefix("empty_intersection:")
        .is_some_and(is_evaluator_scope_dimension)
        || is_evaluator_narrowing_reason(reason)
    {
        normalized("scope_not_granted", Category::Scope)
    } else if matches!(
        reason,
        "time.not_before_missing_from_request"
            | "time.not_before_not_granted"
            | "time.not_before_precedes_grant"
            | "time.expires_at_missing_from_request"
            | "time.expires_at_not_granted"
            | "time.expires_at_exceeds_grant"
    ) {
        normalized("time_scope_mismatch", Category::ExpiryTime)
    } else if is_evaluator_budget_reason(reason) {
        normalized("budget_scope_mismatch", Category::QuotaBudget)
    } else if is_evaluator_set_reason(reason, "data_purposes") {
        normalized("data_use_scope_mismatch", Category::DataUse)
    } else if EVALUATOR_SET_DIMENSIONS
        .iter()
        .any(|dimension| is_evaluator_set_reason(reason, dimension))
    {
        normalized("scope_not_granted", Category::Scope)
    } else {
        normalized("authority_reason_unknown", Category::ProviderUnknown)
    }
}

const EVALUATOR_SET_DIMENSIONS: &[&str] = &[
    "tenant_ids",
    "fleet_ids",
    "agent_ids",
    "run_ids",
    "workload_ids",
    "device_ids",
    "artifact_ids",
    "state_partition_ids",
    "driver_operations",
    "audience",
    "network.egress_schemes",
    "network.egress_hosts",
    "locality.regions",
    "locality.zones",
    "locality.data_localities",
];

const EVALUATOR_BUDGET_DIMENSIONS: &[&str] = &[
    "budget.max_actions_per_tick",
    "budget.max_action_duration_ms",
    "budget.max_filesystem_read_bytes",
    "budget.max_filesystem_write_bytes",
    "budget.max_network_read_bytes",
    "budget.max_network_write_bytes",
    "budget.max_http_requests_per_minute",
];

fn is_evaluator_set_reason(reason: &str, dimension: &str) -> bool {
    reason.strip_prefix(dimension).is_some_and(|suffix| {
        matches!(
            suffix,
            "_missing_from_request" | "_not_granted" | "_exceeds_grant"
        )
    })
}

fn is_evaluator_budget_reason(reason: &str) -> bool {
    EVALUATOR_BUDGET_DIMENSIONS
        .iter()
        .any(|dimension| is_evaluator_set_reason(reason, dimension))
}

fn is_evaluator_budget_dimension(dimension: &str) -> bool {
    EVALUATOR_BUDGET_DIMENSIONS.contains(&dimension)
}

fn is_evaluator_token_field(field: &str) -> bool {
    matches!(
        field,
        "revocation_ref"
            | "grant_validation.algorithm"
            | "grant_validation.digest"
            | "grant_validation.key_id"
            | "grant_validation.signature"
            | "authority_operation.resource_schema_version"
            | "authority_operation.name"
            | "driver_operations.driver"
            | "driver_operations.operation"
            | "driver_operations.schema_version"
            | "audiences"
            | "network.egress_schemes"
            | "network.egress_hosts"
            | "locality.regions"
            | "locality.zones"
            | "locality.data_localities"
            | "obligation.description"
    )
}

fn invalid_scope_reason_category(reason: &str) -> Option<AuthorityExplanationCategory> {
    use AuthorityExplanationCategory as Category;

    let body = reason.strip_prefix("invalid_scope:")?;
    let (dimension, cause) = body.rsplit_once(':')?;
    if !is_evaluator_invalid_scope_dimension(dimension) || !is_evaluator_scope_cause(cause) {
        return None;
    }
    if cause == "nil_identity" {
        Some(Category::IdentityValidation)
    } else if dimension == "time"
        || dimension.ends_with(".time")
        || matches!(
            cause,
            "scope_time_expired"
                | "scope_time_not_yet_valid"
                | "not_before_must_precede_expires_at"
                | "grant_not_before_must_precede_expires_at"
        )
    {
        Some(Category::ExpiryTime)
    } else if cause == "data_purpose_missing_for_operation" {
        Some(Category::DataUse)
    } else {
        Some(Category::Scope)
    }
}

fn is_evaluator_invalid_scope_dimension(dimension: &str) -> bool {
    matches!(
        dimension,
        "tenant_ids"
            | "fleet_ids"
            | "agent_ids"
            | "run_ids"
            | "workload_ids"
            | "device_ids"
            | "artifact_ids"
            | "state_partition_ids"
            | "data_purposes"
            | "driver_operations"
            | "audiences"
            | "network.egress_schemes"
            | "network.egress_hosts"
            | "locality.regions"
            | "locality.zones"
            | "locality.data_localities"
            | "time"
            | "obligations"
            | "capability_request.scope"
            | "capability_grant.scope"
            | "capability_request.scope.time"
            | "capability_grant.scope.time"
    )
}

fn is_evaluator_scope_cause(cause: &str) -> bool {
    matches!(
        cause,
        "nil_identity"
            | "empty_scope_set"
            | "grant_not_before_must_precede_expires_at"
            | "duplicate_obligation_id"
            | "missing_audience_binding"
            | "missing_bounded_dimension"
            | "missing_tenant_or_fleet_binding"
            | "scope_time_not_yet_valid"
            | "scope_time_expired"
            | "data_purpose_missing_for_operation"
            | "network_egress_scope_required"
            | "device_scope_required"
            | "artifact_scope_required"
            | "state_partition_scope_required"
            | "driver_operation_scope_required"
            | "workload_or_run_scope_required"
            | "agent_scope_required"
            | "not_before_must_precede_expires_at"
    )
}

fn is_evaluator_scope_dimension(dimension: &str) -> bool {
    dimension == "data_purposes"
        || dimension == "time"
        || matches!(dimension, "time.not_before" | "time.expires_at")
        || is_evaluator_budget_dimension(dimension)
        || EVALUATOR_SET_DIMENSIONS.contains(&dimension)
        || matches!(
            dimension,
            "operations" | "obligations" | "parent_grant_ids" | "issuer" | "max_delegation_depth"
        )
}

fn is_evaluator_narrowing_reason(reason: &str) -> bool {
    let Some(body) = reason.strip_prefix("narrowing_violation:") else {
        return false;
    };
    let Some((dimension, cause)) = body.rsplit_once(':') else {
        return false;
    };
    is_evaluator_scope_dimension(dimension)
        && matches!(
            cause,
            "missing_parent_grant_id"
                | "child_issuer_not_parent_subject"
                | "parent_delegation_depth_exhausted"
                | "child_delegation_depth_broadened"
                | "child_time_window_broadened"
                | "child_operation_not_in_parent"
                | "child_dropped_parent_obligation"
                | "child_removed_parent_constraint"
                | "child_value_not_in_parent"
                | "child_removed_budget_limit"
                | "child_budget_limit_increased"
                | "child_removed_not_before"
                | "child_removed_expires_at"
                | "child_started_earlier"
                | "child_expires_later"
        )
}

fn build_evidence(
    decision: &AuthorityDecision,
    completeness: AuthorityEvidenceCompleteness,
    mut supplied_grants: Vec<AuthorityGrantEvidence>,
    cached_evaluation: Option<AuthorityCachedEvaluationEvidence>,
) -> Result<AuthorityDecisionEvidence, AuthorityEvidenceError> {
    if decision.decision_id.is_nil() {
        return Err(AuthorityEvidenceError::InvalidDecisionIdentity {
            field: "decision_id",
        });
    }
    if decision.request.subject.is_nil() {
        return Err(AuthorityEvidenceError::InvalidDecisionIdentity { field: "subject" });
    }
    supplied_grants
        .sort_by_key(|grant| (grant.grant_id.to_string(), grant.revision_digest.clone()));

    let mut reason_codes = decision
        .reasons
        .iter()
        .map(|reason| normalize_authority_reason_code(reason).to_string())
        .collect::<Vec<_>>();
    reason_codes.sort();
    reason_codes.dedup();
    let explanation = explanation(&decision.reasons);

    let mut matched_grant_ids = decision.matched_grant_ids.clone();
    matched_grant_ids.sort_by_key(ToString::to_string);
    let mut obligations = decision
        .obligations
        .iter()
        .map(|obligation| AuthorityObligationEvidence {
            obligation_id: obligation.obligation_id.clone(),
            kind: obligation.kind,
        })
        .collect::<Vec<_>>();
    obligations.sort_by_key(|obligation| obligation.obligation_id.to_string());

    let mut missing_facts = vec![
        AuthorityEvidenceMissingFact::PolicyRefs,
        AuthorityEvidenceMissingFact::DataUseRefs,
        AuthorityEvidenceMissingFact::ExactRequestBinding,
        AuthorityEvidenceMissingFact::ProtectedOperationBinding,
    ];
    match completeness {
        AuthorityEvidenceCompleteness::DecisionOnly => {
            missing_facts.push(AuthorityEvidenceMissingFact::SuppliedGrants);
            missing_facts.push(AuthorityEvidenceMissingFact::CacheFreshness);
        }
        AuthorityEvidenceCompleteness::GrantEvaluation => {
            missing_facts.push(AuthorityEvidenceMissingFact::CacheFreshness);
        }
        AuthorityEvidenceCompleteness::CachedEvaluation => {}
    }
    missing_facts.sort();
    missing_facts.dedup();
    let withheld_fields = vec![
        AuthorityEvidenceWithheldField::RequestScopeValues,
        AuthorityEvidenceWithheldField::RawMetadata,
        AuthorityEvidenceWithheldField::ValidationSecretsAndKeys,
        AuthorityEvidenceWithheldField::ObligationDetails,
        AuthorityEvidenceWithheldField::RedactedOperationName,
    ];

    let mut evidence = AuthorityDecisionEvidence {
        schema_version: AUTHORITY_DECISION_EVIDENCE_SCHEMA_VERSION.to_string(),
        completeness,
        decision_id: decision.decision_id.clone(),
        decision_schema: if decision.schema_version == AUTHORITY_DECISION_SCHEMA_VERSION {
            AuthorityDecisionSchemaEvidence::Canonical
        } else {
            AuthorityDecisionSchemaEvidence::Invalid
        },
        status: decision.status,
        decided_at: decision.decided_at,
        subject: decision.request.subject.clone(),
        operation: redacted_operation(&decision.request.operation)?,
        decision_digest: String::new(),
        reason_codes,
        explanation,
        supplied_grants,
        matched_grant_ids,
        obligations,
        cached_evaluation,
        missing_facts,
        withheld_fields,
    };
    evidence.decision_digest = digest_serializable(
        "decision-safe-facts-v1",
        "authority_decision_evidence_digest_unavailable",
        &AuthorityDecisionDigestPayload::from(&evidence),
    )?;
    Ok(evidence)
}

fn explanation(raw_reasons: &[String]) -> AuthorityDecisionExplanation {
    let mut branches = Vec::<AuthorityExplanationBranch>::new();
    for reason in raw_reasons {
        let normalized_reason = normalize_authority_reason(reason);
        let category = normalized_reason.category;
        let reason = normalized_reason.code.to_string();
        if let Some(branch) = branches
            .iter_mut()
            .find(|branch| branch.category == category)
        {
            if !branch.reason_codes.contains(&reason) {
                branch.reason_codes.push(reason);
                branch.reason_codes.sort();
            }
        } else {
            branches.push(AuthorityExplanationBranch {
                category,
                reason_codes: vec![reason],
            });
        }
    }
    branches.sort_by_key(|branch| branch.category);
    AuthorityDecisionExplanation { branches }
}

fn grant_evidence(
    validated: &ValidatedCapabilityGrant,
    decision: &AuthorityDecision,
) -> Result<AuthorityGrantEvidence, AuthorityEvidenceError> {
    let grant = validated.grant();
    let validation = grant.validation.as_ref().ok_or(
        AuthorityEvidenceError::GrantValidationDigestUnavailable {
            grant_id: grant.grant_id.clone(),
        },
    )?;
    let normalized_validation_token = normalize_digest_token(&validation.digest);
    let validation_token_digest = domain_hash_bytes(
        "validation-token-v1",
        normalized_validation_token.as_bytes(),
    );
    let mut parent_grant_ids = grant.parent_grant_ids.clone();
    parent_grant_ids.sort_by_key(ToString::to_string);
    parent_grant_ids.dedup();
    let mut obligations = grant
        .obligations
        .iter()
        .map(|obligation| AuthorityObligationEvidence {
            obligation_id: obligation.obligation_id.clone(),
            kind: obligation.kind,
        })
        .collect::<Vec<_>>();
    obligations.sort_by_key(|obligation| obligation.obligation_id.to_string());
    obligations.dedup();
    let canonical_scope = canonical_scope(&grant.scope);
    let mut operation_fact_digests = grant
        .operations
        .iter()
        .map(|operation| {
            let safe_operation = redacted_operation(operation)?;
            digest_serializable(
                "operation-fact-v1",
                "authority_operation_fact_digest_unavailable",
                &safe_operation,
            )
        })
        .collect::<Result<Vec<_>, AuthorityEvidenceError>>()?;
    operation_fact_digests.sort();
    operation_fact_digests.dedup();
    let revision = AuthorityGrantRevisionDigestPayload {
        grant_schema_valid: grant.schema_version == CAPABILITY_GRANT_SCHEMA_VERSION,
        grant_id: &grant.grant_id,
        issuer: &grant.issuer,
        subject: &grant.subject,
        parent_grant_ids: &parent_grant_ids,
        operation_fact_digests: &operation_fact_digests,
        scope: &canonical_scope,
        not_before: grant.not_before,
        expires_at: grant.expires_at,
        revocation_ref: grant.revocation_ref.as_deref(),
        revocation_state: match &grant.revocation {
            RevocationStatus::Active => "active",
            RevocationStatus::Revoked { .. } => "revoked",
        },
        obligations: &obligations,
        max_delegation_depth: grant.max_delegation_depth,
        validation_kind: validation.validation_kind,
        validation_token_digest: &validation_token_digest,
    };
    let revision_digest = digest_serializable(
        "grant-revision-v1",
        "authority_grant_revision_digest_unavailable",
        &revision,
    )?;
    Ok(AuthorityGrantEvidence {
        grant_id: grant.grant_id.clone(),
        matched: decision
            .matched_grant_ids
            .iter()
            .any(|grant_id| grant_id == &grant.grant_id),
        validation_kind: validation.validation_kind,
        validation_token_digest,
        revision_digest,
    })
}

fn cached_evaluation_evidence(
    cache: &AuthorityGrantCache,
    revocations: Option<&RevocationSnapshot>,
    policy: &OfflineAuthorityPolicy,
    now: OffsetDateTime,
) -> AuthorityCachedEvaluationEvidence {
    let mut cache_entries = cache
        .cached_grants()
        .iter()
        .map(|cached| cache_entry_evidence(cached, policy, now))
        .collect::<Vec<_>>();
    cache_entries.sort_by_key(|entry| entry.grant_id.to_string());
    let revocation_snapshot = match revocations {
        None => AuthorityRevocationSnapshotEvidence {
            refreshed_at: None,
            expires_at: None,
            freshness: AuthorityFreshnessStatus::Missing,
        },
        Some(snapshot) => AuthorityRevocationSnapshotEvidence {
            refreshed_at: Some(snapshot.refreshed_at()),
            expires_at: Some(snapshot.expires_at()),
            freshness: if now < snapshot.refreshed_at() {
                AuthorityFreshnessStatus::FutureDated
            } else if now >= snapshot.expires_at() {
                AuthorityFreshnessStatus::Stale
            } else {
                AuthorityFreshnessStatus::Fresh
            },
        },
    };
    AuthorityCachedEvaluationEvidence {
        connectivity: policy.connectivity().into(),
        cache_missing: cache.is_empty(),
        cache_entries,
        revocation_snapshot,
    }
}

fn cache_entry_evidence(
    cached: &CachedAuthorityGrant,
    policy: &OfflineAuthorityPolicy,
    now: OffsetDateTime,
) -> AuthorityCacheEntryEvidence {
    let cache_freshness = if cached.cached_at() > now {
        AuthorityFreshnessStatus::FutureDated
    } else if now >= cached.expires_at() || now >= cached.grant().grant().expires_at {
        AuthorityFreshnessStatus::Expired
    } else if cached
        .cached_at()
        .checked_add(policy.max_cache_staleness())
        .is_none_or(|fresh_until| now >= fresh_until)
    {
        AuthorityFreshnessStatus::Stale
    } else {
        AuthorityFreshnessStatus::Fresh
    };
    let offline_ttl_freshness = (policy.connectivity() == AuthorityConnectivity::Disconnected)
        .then(|| {
            if cached.cached_at() > now {
                AuthorityFreshnessStatus::FutureDated
            } else if cached
                .cached_at()
                .checked_add(policy.offline_grant_ttl())
                .is_none_or(|offline_until| now >= offline_until)
            {
                AuthorityFreshnessStatus::Expired
            } else {
                AuthorityFreshnessStatus::Fresh
            }
        });
    let effective_freshness = match (cache_freshness, offline_ttl_freshness) {
        (AuthorityFreshnessStatus::FutureDated, _)
        | (_, Some(AuthorityFreshnessStatus::FutureDated)) => AuthorityFreshnessStatus::FutureDated,
        (AuthorityFreshnessStatus::Expired, _) | (_, Some(AuthorityFreshnessStatus::Expired)) => {
            AuthorityFreshnessStatus::Expired
        }
        (AuthorityFreshnessStatus::Stale, _) => AuthorityFreshnessStatus::Stale,
        _ => AuthorityFreshnessStatus::Fresh,
    };
    AuthorityCacheEntryEvidence {
        grant_id: cached.grant().grant().grant_id.clone(),
        cached_at: cached.cached_at(),
        expires_at: cached.expires_at(),
        cache_freshness,
        offline_ttl_freshness,
        effective_freshness,
    }
}

fn digest_serializable<T: Serialize>(
    domain: &'static str,
    reason: &'static str,
    value: &T,
) -> Result<String, AuthorityEvidenceError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| AuthorityEvidenceError::DigestUnavailable { reason })?;
    Ok(domain_hash_bytes(domain, &bytes))
}

fn domain_hash_bytes(domain: &str, bytes: &[u8]) -> String {
    let mut material = Vec::with_capacity(domain.len() + bytes.len() + 64);
    material.extend_from_slice(b"splendor.authority.evidence.local.v1\0");
    material.extend_from_slice(domain.as_bytes());
    material.push(0);
    material.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    material.extend_from_slice(bytes);
    ContentHash::blake3(material).to_string()
}

fn redacted_operation(
    operation: &AuthorityOperation,
) -> Result<RedactedAuthorityOperation, AuthorityEvidenceError> {
    Ok(RedactedAuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: operation.namespace,
        resource_kind: operation.resource_kind,
        verb: operation.verb,
        source_schema_valid: operation.schema_version == AUTHORITY_OPERATION_SCHEMA_VERSION,
        concrete_name_withheld: operation.name.is_some(),
        resource_schema_withheld: operation.resource_schema_version.is_some(),
    })
}

fn normalize_digest_token(value: &str) -> String {
    let Some((algorithm, digest)) = value.split_once(':') else {
        return value.to_string();
    };
    let algorithm = algorithm.to_ascii_lowercase();
    if matches!(algorithm.as_str(), "blake3" | "sha256")
        && digest.len() == 64
        && digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        format!("{algorithm}:{}", digest.to_ascii_lowercase())
    } else {
        value.to_string()
    }
}

fn canonical_scope(scope: &CapabilityScope) -> CapabilityScope {
    let mut canonical = scope.clone();
    canonical.schema_version = splendor_types::CAPABILITY_SCOPE_SCHEMA_VERSION.to_string();
    canonicalize_display_vec(&mut canonical.tenant_ids);
    canonicalize_display_vec(&mut canonical.fleet_ids);
    canonicalize_display_vec(&mut canonical.agent_ids);
    canonicalize_display_vec(&mut canonical.run_ids);
    canonicalize_display_vec(&mut canonical.workload_ids);
    canonicalize_display_vec(&mut canonical.device_ids);
    canonicalize_ord_vec(&mut canonical.data_purposes);
    canonicalize_display_vec(&mut canonical.artifact_ids);
    canonicalize_display_vec(&mut canonical.state_partition_ids);
    canonicalize_ord_vec(&mut canonical.driver_operations);
    canonicalize_ord_vec(&mut canonical.audiences);
    canonicalize_ord_vec(&mut canonical.network.egress_schemes);
    canonicalize_ord_vec(&mut canonical.network.egress_hosts);
    canonicalize_ord_vec(&mut canonical.locality.regions);
    canonicalize_ord_vec(&mut canonical.locality.zones);
    canonicalize_ord_vec(&mut canonical.locality.data_localities);
    canonical
}

fn canonicalize_display_vec<T: ToString>(values: &mut Option<Vec<T>>) {
    if let Some(values) = values {
        values.sort_by_key(ToString::to_string);
        values.dedup_by(|left, right| left.to_string() == right.to_string());
    }
}

fn canonicalize_ord_vec<T: Ord>(values: &mut Option<Vec<T>>) {
    if let Some(values) = values {
        values.sort();
        values.dedup();
    }
}

#[derive(Serialize)]
struct AuthorityGrantRevisionDigestPayload<'a> {
    grant_schema_valid: bool,
    grant_id: &'a CapabilityGrantId,
    issuer: &'a PrincipalId,
    subject: &'a PrincipalId,
    parent_grant_ids: &'a [CapabilityGrantId],
    operation_fact_digests: &'a [String],
    scope: &'a CapabilityScope,
    #[serde(with = "time::serde::rfc3339")]
    not_before: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    revocation_ref: Option<&'a str>,
    revocation_state: &'static str,
    obligations: &'a [AuthorityObligationEvidence],
    max_delegation_depth: u32,
    validation_kind: CapabilityGrantValidationKind,
    validation_token_digest: &'a str,
}

#[derive(Serialize)]
struct AuthorityDecisionDigestPayload<'a> {
    schema_version: &'a str,
    completeness: AuthorityEvidenceCompleteness,
    decision_id: &'a AuthorityDecisionId,
    decision_schema: AuthorityDecisionSchemaEvidence,
    status: AuthorityDecisionStatus,
    #[serde(with = "time::serde::rfc3339")]
    decided_at: OffsetDateTime,
    subject: &'a PrincipalId,
    operation: &'a RedactedAuthorityOperation,
    reason_codes: &'a [String],
    supplied_grants: Vec<RedactedAuthorityGrantEvidence>,
    matched_grant_ids: &'a [CapabilityGrantId],
    obligations: &'a [AuthorityObligationEvidence],
    cached_evaluation: &'a Option<AuthorityCachedEvaluationEvidence>,
    missing_facts: &'a [AuthorityEvidenceMissingFact],
    withheld_fields: &'a [AuthorityEvidenceWithheldField],
}

impl<'a> From<&'a AuthorityDecisionEvidence> for AuthorityDecisionDigestPayload<'a> {
    fn from(value: &'a AuthorityDecisionEvidence) -> Self {
        Self {
            schema_version: &value.schema_version,
            completeness: value.completeness,
            decision_id: &value.decision_id,
            decision_schema: value.decision_schema,
            status: value.status,
            decided_at: value.decided_at,
            subject: &value.subject,
            operation: &value.operation,
            reason_codes: &value.reason_codes,
            supplied_grants: value
                .supplied_grants
                .iter()
                .map(|grant| RedactedAuthorityGrantEvidence {
                    grant_id: grant.grant_id.clone(),
                    matched: grant.matched,
                    validation_kind: grant.validation_kind,
                })
                .collect(),
            matched_grant_ids: &value.matched_grant_ids,
            obligations: &value.obligations,
            cached_evaluation: &value.cached_evaluation,
            missing_facts: &value.missing_facts,
            withheld_fields: &value.withheld_fields,
        }
    }
}

/// Evidence construction errors. Callers requiring evidence must fail closed or
/// record the stable unavailable reason; they must never fabricate a replacement.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthorityEvidenceError {
    /// A required decision identity was invalid.
    #[error("authority evidence decision identity invalid: {field}")]
    InvalidDecisionIdentity {
        /// Invalid field name only; no payload value is included.
        field: &'static str,
    },
    /// A validated grant lacked a safe immutable validation digest.
    #[error("authority evidence grant validation digest unavailable: {grant_id}")]
    GrantValidationDigestUnavailable {
        /// Safe grant identity.
        grant_id: CapabilityGrantId,
    },
    /// A deterministic digest could not be produced.
    #[error("authority evidence digest unavailable: {reason}")]
    DigestUnavailable {
        /// Stable reason code without serialized payload details.
        reason: &'static str,
    },
}

impl AuthorityEvidenceError {
    /// Stable reason code for fail-closed callers and unavailable artifacts.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidDecisionIdentity { .. } => "authority_evidence_decision_identity_invalid",
            Self::GrantValidationDigestUnavailable { .. } => {
                "authority_evidence_grant_validation_digest_unavailable"
            }
            Self::DigestUnavailable { reason } => reason,
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/evidence_tests.rs"]
mod tests;
