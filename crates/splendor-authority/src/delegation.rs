//! AUTH-003a local authority-owned delegation foundation.
//!
//! This module builds a behavior-free `DelegationGrant` contract and a trusted
//! `ValidatedCapabilityGrant` child from an already validated parent grant. It is
//! intentionally not wired into `splendor-kernel` local delegation, gateway
//! verification, daemon APIs, trace formats, or adapter execution. Messages,
//! metadata, task payloads, principal existence, ownership, and model output do
//! not authorize delegation here; only a parent `ValidatedCapabilityGrant` can be
//! narrowed into a child grant.

use crate::capability::validate_local_profile_grant;
use crate::{
    ensure_child_grant_narrows, evaluate_capability_request, AuthorityEvaluationError,
    ValidatedCapabilityGrant,
};
use splendor_types::{
    AgentId, AuthorityDecisionStatus, AuthorityObligation, AuthorityOperation,
    AuthorityOperationNamespace, AuthorityResourceKind, AuthorityVerb, CapabilityGrant,
    CapabilityGrantId, CapabilityGrantValidation, CapabilityGrantValidationKind, CapabilityRequest,
    CapabilityScope, DelegationGrant, DelegationResultContract, DelegationRoleProfile,
    MessageSchemaVersion, PrincipalId, RevocationStatus, RunId, CAPABILITY_GRANT_SCHEMA_VERSION,
    CAPABILITY_REQUEST_SCHEMA_VERSION, DELEGATION_GRANT_SCHEMA_VERSION,
    DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION,
};
use thiserror::Error;
use time::OffsetDateTime;

const DELEGATION_CHILD_GRANT_ALGORITHM: &str = "local-delegation-child-grant-v1";

/// Typed request to mint one child capability grant from a validated parent.
#[derive(Clone, Debug, PartialEq)]
pub struct DelegationChildGrantRequest {
    /// Parent grant edge the child must narrow from. Missing/wrong edges fail closed.
    pub parent_grant_id: Option<CapabilityGrantId>,
    /// Principal issuing the child grant; must equal the parent grant subject.
    pub issuer: PrincipalId,
    /// Explicit child subject/principal receiving the grant.
    pub child_subject: Option<PrincipalId>,
    /// Grant ID to assign to the child capability grant.
    pub child_grant_id: CapabilityGrantId,
    /// Parent run that requested delegated work.
    pub parent_run_id: RunId,
    /// Parent agent that requested delegated work.
    pub parent_agent_id: AgentId,
    /// Child run receiving delegated work.
    pub child_run_id: RunId,
    /// Child agent receiving delegated work.
    pub child_agent_id: AgentId,
    /// Scoped delegated objective.
    pub objective: String,
    /// Child role/profile.
    pub role_profile: DelegationRoleProfile,
    /// Operations the child grant may authorize.
    pub operations: Vec<AuthorityOperation>,
    /// Scope the child grant may authorize.
    pub scope: CapabilityScope,
    /// Message schemas the child may emit for this delegation.
    pub allowed_message_schemas: Vec<String>,
    /// Message recipients the child may target for this delegation.
    pub allowed_recipient_agent_ids: Vec<AgentId>,
    /// Required terminal result contract.
    pub result_contract: DelegationResultContract,
    /// Child grant not-before timestamp.
    pub not_before: OffsetDateTime,
    /// Child grant expiry timestamp.
    pub expires_at: OffsetDateTime,
    /// Remaining child delegation depth.
    pub max_delegation_depth: u32,
    /// Maximum child grants allowed for this parent edge.
    pub max_fan_out: u32,
    /// Local validation digest for the child grant evidence slice.
    pub validation_digest: String,
}

/// Runtime context supplied by the authority owner when issuing a delegation.
#[derive(Clone, Debug, PartialEq)]
pub struct DelegationValidationContext {
    /// Decision time used for parent expiry/revocation checks.
    pub now: OffsetDateTime,
    /// Audience that must appear in the child scope.
    pub audience: String,
    /// Subject/principal expected for the target child.
    pub expected_child_subject: PrincipalId,
    /// Authority-owned fan-out limit for the parent edge.
    pub parent_fan_out_limit: u32,
    /// Number of children already issued for this parent edge.
    pub current_parent_fan_out: u32,
}

/// Successful delegated child grant construction.
#[derive(Clone, Debug, PartialEq)]
pub struct DelegationChildGrant {
    delegation_grant: DelegationGrant,
    child_grant: ValidatedCapabilityGrant,
}

impl DelegationChildGrant {
    /// Behavior-free delegation edge for evidence/storage.
    pub fn delegation_grant(&self) -> &DelegationGrant {
        &self.delegation_grant
    }

    /// Authority-owned validated child grant for later evaluator calls.
    pub(crate) fn child_grant(&self) -> &ValidatedCapabilityGrant {
        &self.child_grant
    }

    /// Consumes the result and returns the validated child grant.
    #[cfg(test)]
    pub(crate) fn into_child_grant(self) -> ValidatedCapabilityGrant {
        self.child_grant
    }
}

/// Fail-closed AUTH-003a delegation construction errors.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum DelegationGrantError {
    /// Request did not explicitly reference the parent grant edge.
    #[error("delegation request is missing the parent grant edge")]
    MissingParentEdge,
    /// Request issuer was not the parent grant subject.
    #[error("delegation issuer is not the parent grant subject")]
    IssuerNotParentSubject,
    /// Child subject was absent or nil.
    #[error("delegation child subject is required")]
    ChildSubjectMissing,
    /// Child subject did not match authority context.
    #[error("delegation child subject does not match authority context")]
    ChildSubjectWrong,
    /// Operation set attempted to broaden parent authority.
    #[error("delegation operation set is overbroad: {reason}")]
    OverbroadOperation { reason: String },
    /// Scope attempted to broaden parent authority.
    #[error("delegation scope is overbroad: {reason}")]
    OverbroadScope { reason: String },
    /// Audience binding attempted to broaden or bypass parent authority.
    #[error("delegation audience is overbroad: {reason}")]
    OverbroadAudience { reason: String },
    /// Time window attempted to broaden parent authority.
    #[error("delegation time window is overbroad: {reason}")]
    OverbroadTime { reason: String },
    /// Budget attempted to broaden parent authority.
    #[error("delegation budget is overbroad: {reason}")]
    OverbroadBudget { reason: String },
    /// Child delegation depth attempted to broaden parent authority.
    #[error("delegation depth is overbroad")]
    OverbroadDepth,
    /// Parent grant has no remaining delegation depth.
    #[error("parent delegation depth is exhausted")]
    DelegationDepthExhausted,
    /// Parent fan-out cap was reached.
    #[error("delegation fan-out cap exceeded")]
    FanOutExceeded,
    /// Requested fan-out cap attempted to broaden the authority-owned cap.
    #[error("delegation fan-out cap is overbroad")]
    OverbroadFanOut,
    /// No allowed message schema was provided.
    #[error("delegation requires at least one allowed message schema")]
    MissingMessageSchema,
    /// An allowed message schema was malformed.
    #[error("delegation message schema is invalid: {schema}")]
    BadMessageSchema { schema: String },
    /// No allowed message recipient was provided.
    #[error("delegation requires at least one allowed message recipient")]
    MissingMessageRecipient,
    /// An allowed message recipient was malformed.
    #[error("delegation message recipient is invalid")]
    BadMessageRecipient,
    /// Objective was blank.
    #[error("delegation objective is required")]
    MissingObjective,
    /// Result contract was malformed.
    #[error("delegation result contract is invalid: {reason}")]
    BadResultContract { reason: String },
    /// Parent grant was revoked.
    #[error("parent grant is revoked")]
    ParentRevoked,
    /// Parent grant was expired at decision time.
    #[error("parent grant is expired")]
    ParentExpired,
    /// Parent grant is not valid yet at decision time.
    #[error("parent grant is not yet valid")]
    ParentNotYetValid,
    /// Immediate delegated routing cannot start before the requested child window.
    #[error("child grant is not yet valid")]
    ChildNotYetValid,
    /// Critic/evaluator roles tried to carry actuation or external-effect authority.
    #[error("critic/evaluator delegation cannot carry external-effect operations")]
    CriticEvaluatorExternalEffectOperation,
    /// A delegation identity field was nil or inconsistent.
    #[error("delegation identity is invalid: {field}")]
    InvalidIdentity { field: &'static str },
    /// Child grant construction failed after explicit checks.
    #[error("child grant is invalid: {reason_code}")]
    ChildGrantInvalid { reason_code: String },
    /// Parent grant failed evaluator validation for a reason not otherwise mapped.
    #[error("parent grant is invalid: {reason_code}")]
    ParentGrantInvalid { reason_code: String },
    /// Parent authority matched but carries unsatisfied obligations.
    #[error("parent authority obligations are unsatisfied")]
    ParentObligationsUnsatisfied,
}

impl DelegationGrantError {
    /// Stable reason code suitable for tests, traces, and audit records.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::MissingParentEdge => "missing_parent_edge",
            Self::IssuerNotParentSubject => "issuer_not_parent_subject",
            Self::ChildSubjectMissing => "child_subject_missing",
            Self::ChildSubjectWrong => "child_subject_wrong",
            Self::OverbroadOperation { .. } => "overbroad_operation",
            Self::OverbroadScope { .. } => "overbroad_scope",
            Self::OverbroadAudience { .. } => "overbroad_audience",
            Self::OverbroadTime { .. } => "overbroad_time",
            Self::OverbroadBudget { .. } => "overbroad_budget",
            Self::OverbroadDepth => "overbroad_delegation_depth",
            Self::DelegationDepthExhausted => "delegation_depth_exhausted",
            Self::FanOutExceeded => "fan_out_exceeded",
            Self::OverbroadFanOut => "overbroad_fan_out",
            Self::MissingMessageSchema => "missing_message_schema",
            Self::BadMessageSchema { .. } => "bad_message_schema",
            Self::MissingMessageRecipient => "missing_message_recipient",
            Self::BadMessageRecipient => "bad_message_recipient",
            Self::MissingObjective => "missing_objective",
            Self::BadResultContract { .. } => "bad_result_contract",
            Self::ParentRevoked => "parent_revoked",
            Self::ParentExpired => "parent_expired",
            Self::ParentNotYetValid => "parent_not_yet_valid",
            Self::ChildNotYetValid => "child_grant_not_yet_valid",
            Self::CriticEvaluatorExternalEffectOperation => {
                "critic_evaluator_external_effect_operation"
            }
            Self::InvalidIdentity { .. } => "invalid_delegation_identity",
            Self::ChildGrantInvalid { .. } => "child_grant_invalid",
            Self::ParentGrantInvalid { .. } => "parent_grant_invalid",
            Self::ParentObligationsUnsatisfied => "parent_obligations_unsatisfied",
        }
    }
}

/// Builds and validates one delegated child grant from a validated parent grant.
pub fn issue_delegation_child_grant(
    parent: &ValidatedCapabilityGrant,
    request: DelegationChildGrantRequest,
    context: DelegationValidationContext,
) -> Result<DelegationChildGrant, DelegationGrantError> {
    validate_parent_edge(parent, &request)?;
    validate_parent_liveness(parent, context.now)?;
    validate_request_shape(&request, &context)?;
    validate_message_contracts(&request)?;
    validate_result_contract(&request.result_contract)?;
    validate_role_operations(request.role_profile, &request.operations)?;

    let child_subject = request
        .child_subject
        .clone()
        .ok_or(DelegationGrantError::ChildSubjectMissing)?;
    let parent_grant_id = request
        .parent_grant_id
        .clone()
        .ok_or(DelegationGrantError::MissingParentEdge)?;
    let raw_child_grant = build_raw_child_grant(
        &request,
        &child_subject,
        &parent_grant_id,
        &parent.grant().obligations,
    );

    ensure_child_grant_narrows(parent.grant(), &raw_child_grant).map_err(map_narrowing_error)?;
    ensure_parent_authorizes_child(parent, &raw_child_grant, context.now)?;

    let child_grant = validate_local_profile_grant(raw_child_grant.clone()).map_err(|error| {
        DelegationGrantError::ChildGrantInvalid {
            reason_code: error.reason_code(),
        }
    })?;
    let mut delegation_grant = DelegationGrant {
        schema_version: DELEGATION_GRANT_SCHEMA_VERSION.to_string(),
        binding_digest: String::new(),
        parent_grant_id,
        parent_run_id: request.parent_run_id,
        parent_agent_id: request.parent_agent_id,
        child_run_id: request.child_run_id,
        child_agent_id: request.child_agent_id,
        objective: request.objective,
        role_profile: request.role_profile,
        allowed_message_schemas: request.allowed_message_schemas,
        allowed_recipient_agent_ids: request.allowed_recipient_agent_ids,
        result_contract: request.result_contract,
        budget: raw_child_grant.scope.budget,
        not_before: raw_child_grant.not_before,
        expires_at: raw_child_grant.expires_at,
        remaining_delegation_depth: raw_child_grant.max_delegation_depth,
        max_fan_out: request.max_fan_out,
        cleanup_obligations: splendor_types::DelegationCleanupObligations::default(),
        child_capability_grant: raw_child_grant,
    };
    delegation_grant.binding_digest = delegation_edge_binding_digest(&delegation_grant)
        .map_err(|reason_code| DelegationGrantError::ChildGrantInvalid { reason_code })?;

    Ok(DelegationChildGrant {
        delegation_grant,
        child_grant,
    })
}

/// Canonical digest over every semantic delegation-edge field except the digest
/// itself. This binds replay evidence against field-by-field substitution.
pub fn delegation_edge_binding_digest(edge: &DelegationGrant) -> Result<String, String> {
    let mut canonical = edge.clone();
    canonical.binding_digest.clear();
    let bytes =
        serde_json::to_vec(&canonical).map_err(|_| "edge_digest_unavailable".to_string())?;
    Ok(splendor_types::ContentHash::blake3(bytes).to_string())
}

fn validate_parent_edge(
    parent: &ValidatedCapabilityGrant,
    request: &DelegationChildGrantRequest,
) -> Result<(), DelegationGrantError> {
    match &request.parent_grant_id {
        Some(parent_grant_id) if parent_grant_id == &parent.grant().grant_id => {}
        _ => return Err(DelegationGrantError::MissingParentEdge),
    }
    if request.issuer != parent.grant().subject {
        return Err(DelegationGrantError::IssuerNotParentSubject);
    }
    Ok(())
}

fn validate_parent_liveness(
    parent: &ValidatedCapabilityGrant,
    now: OffsetDateTime,
) -> Result<(), DelegationGrantError> {
    let grant = parent.grant();
    if now < grant.not_before {
        return Err(DelegationGrantError::ParentNotYetValid);
    }
    if now >= grant.expires_at {
        return Err(DelegationGrantError::ParentExpired);
    }
    if let RevocationStatus::Revoked { .. } = &grant.revocation {
        return Err(DelegationGrantError::ParentRevoked);
    }
    if grant.max_delegation_depth == 0 {
        return Err(DelegationGrantError::DelegationDepthExhausted);
    }
    Ok(())
}

fn validate_request_shape(
    request: &DelegationChildGrantRequest,
    context: &DelegationValidationContext,
) -> Result<(), DelegationGrantError> {
    if request.child_grant_id.is_nil() {
        return Err(DelegationGrantError::InvalidIdentity {
            field: "child_grant_id",
        });
    }
    if request.parent_run_id.is_nil() {
        return Err(DelegationGrantError::InvalidIdentity {
            field: "parent_run_id",
        });
    }
    if request.child_run_id.is_nil() || request.child_run_id == request.parent_run_id {
        return Err(DelegationGrantError::InvalidIdentity {
            field: "child_run_id",
        });
    }
    if request.parent_agent_id.is_nil() {
        return Err(DelegationGrantError::InvalidIdentity {
            field: "parent_agent_id",
        });
    }
    if request.child_agent_id.is_nil() || request.child_agent_id == request.parent_agent_id {
        return Err(DelegationGrantError::InvalidIdentity {
            field: "child_agent_id",
        });
    }
    let child_subject = request
        .child_subject
        .as_ref()
        .ok_or(DelegationGrantError::ChildSubjectMissing)?;
    if child_subject.is_nil() {
        return Err(DelegationGrantError::ChildSubjectMissing);
    }
    if context.expected_child_subject.is_nil() || child_subject != &context.expected_child_subject {
        return Err(DelegationGrantError::ChildSubjectWrong);
    }
    if request.objective.trim().is_empty() {
        return Err(DelegationGrantError::MissingObjective);
    }
    validate_token("audience", &context.audience).map_err(|reason| {
        DelegationGrantError::OverbroadAudience {
            reason: reason.to_string(),
        }
    })?;
    if !scope_contains_agent_run(
        &request.scope,
        &request.child_agent_id,
        &request.child_run_id,
    ) {
        return Err(DelegationGrantError::OverbroadScope {
            reason: "child_scope_must_include_child_agent_and_run".to_string(),
        });
    }
    if !string_set_contains(&request.scope.audiences, &context.audience) {
        return Err(DelegationGrantError::OverbroadAudience {
            reason: "child_scope_missing_context_audience".to_string(),
        });
    }
    if request.not_before >= request.expires_at {
        return Err(DelegationGrantError::OverbroadTime {
            reason: "child_not_before_must_precede_expires_at".to_string(),
        });
    }
    if context.now < request.not_before {
        return Err(DelegationGrantError::ChildNotYetValid);
    }
    if request.max_fan_out == 0 || request.max_fan_out > context.parent_fan_out_limit {
        return Err(DelegationGrantError::OverbroadFanOut);
    }
    if context.current_parent_fan_out >= context.parent_fan_out_limit
        || context.current_parent_fan_out >= request.max_fan_out
    {
        return Err(DelegationGrantError::FanOutExceeded);
    }
    validate_token("validation_digest", &request.validation_digest).map_err(|reason| {
        DelegationGrantError::ChildGrantInvalid {
            reason_code: reason.to_string(),
        }
    })?;
    Ok(())
}

fn validate_message_contracts(
    request: &DelegationChildGrantRequest,
) -> Result<(), DelegationGrantError> {
    if request.allowed_message_schemas.is_empty() {
        return Err(DelegationGrantError::MissingMessageSchema);
    }
    for schema in &request.allowed_message_schemas {
        if validate_versioned_schema(schema).is_err() || !schema.starts_with("splendor.message.") {
            return Err(DelegationGrantError::BadMessageSchema {
                schema: schema.clone(),
            });
        }
    }
    if request.allowed_recipient_agent_ids.is_empty() {
        return Err(DelegationGrantError::MissingMessageRecipient);
    }
    if request
        .allowed_recipient_agent_ids
        .iter()
        .any(AgentId::is_nil)
    {
        return Err(DelegationGrantError::BadMessageRecipient);
    }
    Ok(())
}

fn validate_result_contract(
    contract: &DelegationResultContract,
) -> Result<(), DelegationGrantError> {
    if contract.schema_version != DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION {
        return Err(DelegationGrantError::BadResultContract {
            reason: "invalid_result_contract_schema".to_string(),
        });
    }
    validate_versioned_schema(&contract.result_schema).map_err(|reason| {
        DelegationGrantError::BadResultContract {
            reason: reason.to_string(),
        }
    })?;
    if contract.result_schema != splendor_types::TASK_RESPONSE_SCHEMA {
        return Err(DelegationGrantError::BadResultContract {
            reason: "unsupported_result_schema".to_string(),
        });
    }
    if contract.max_result_bytes == Some(0) {
        return Err(DelegationGrantError::BadResultContract {
            reason: "max_result_bytes_must_be_positive".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn validate_role_operations(
    role: DelegationRoleProfile,
    operations: &[AuthorityOperation],
) -> Result<(), DelegationGrantError> {
    if matches!(
        role,
        DelegationRoleProfile::Critic | DelegationRoleProfile::Evaluator
    ) && operations.iter().any(is_external_effect_operation)
    {
        return Err(DelegationGrantError::CriticEvaluatorExternalEffectOperation);
    }
    Ok(())
}

fn build_raw_child_grant(
    request: &DelegationChildGrantRequest,
    child_subject: &PrincipalId,
    parent_grant_id: &CapabilityGrantId,
    parent_obligations: &[AuthorityObligation],
) -> CapabilityGrant {
    CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: request.child_grant_id.clone(),
        issuer: request.issuer.clone(),
        subject: child_subject.clone(),
        parent_grant_ids: vec![parent_grant_id.clone()],
        operations: request.operations.clone(),
        scope: request.scope.clone(),
        not_before: request.not_before,
        expires_at: request.expires_at,
        revocation_ref: Some(format!("delegation:{parent_grant_id}")),
        revocation: RevocationStatus::Active,
        obligations: parent_obligations.to_vec(),
        max_delegation_depth: request.max_delegation_depth,
        validation: Some(CapabilityGrantValidation {
            validation_kind: CapabilityGrantValidationKind::LocallyValidated,
            algorithm: DELEGATION_CHILD_GRANT_ALGORITHM.to_string(),
            key_id: None,
            digest: request.validation_digest.clone(),
            signature: None,
        }),
        metadata: Default::default(),
    }
}

fn ensure_parent_authorizes_child(
    parent: &ValidatedCapabilityGrant,
    child: &CapabilityGrant,
    now: OffsetDateTime,
) -> Result<(), DelegationGrantError> {
    for operation in &child.operations {
        let request = CapabilityRequest {
            schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
            subject: parent.grant().subject.clone(),
            operation: operation.clone(),
            scope: child.scope.clone(),
            requested_at: now,
            metadata: Default::default(),
        };
        let decision = evaluate_capability_request(std::slice::from_ref(parent), &request, now);
        match decision.status {
            AuthorityDecisionStatus::Allowed => {}
            AuthorityDecisionStatus::Conditional => {
                return Err(DelegationGrantError::ParentObligationsUnsatisfied);
            }
            _ => return Err(map_parent_denial(&decision.reasons)),
        }
    }
    Ok(())
}

fn map_parent_denial(reasons: &[String]) -> DelegationGrantError {
    for reason in reasons {
        if reason == "revoked_grant" {
            return DelegationGrantError::ParentRevoked;
        }
        if reason == "expired_grant" || reason.contains("scope_time_expired") {
            return DelegationGrantError::ParentExpired;
        }
        if reason == "grant_not_yet_valid" || reason.contains("scope_time_not_yet_valid") {
            return DelegationGrantError::ParentNotYetValid;
        }
        if reason == "operation_not_granted" {
            return DelegationGrantError::OverbroadOperation {
                reason: reason.clone(),
            };
        }
        if reason.contains("audience") {
            return DelegationGrantError::OverbroadAudience {
                reason: reason.clone(),
            };
        }
        if reason.starts_with("time.") || reason.contains("scope.time") {
            return DelegationGrantError::OverbroadTime {
                reason: reason.clone(),
            };
        }
        if reason.starts_with("budget.") {
            return DelegationGrantError::OverbroadBudget {
                reason: reason.clone(),
            };
        }
        if reason.contains("not_granted") || reason.contains("missing_from_request") {
            return DelegationGrantError::OverbroadScope {
                reason: reason.clone(),
            };
        }
    }
    DelegationGrantError::ParentGrantInvalid {
        reason_code: reasons
            .first()
            .cloned()
            .unwrap_or_else(|| "parent_capability_denied".to_string()),
    }
}

fn map_narrowing_error(error: AuthorityEvaluationError) -> DelegationGrantError {
    match error {
        AuthorityEvaluationError::NarrowingViolation { dimension, reason } => match dimension {
            "parent_grant_ids" => DelegationGrantError::MissingParentEdge,
            "issuer" => DelegationGrantError::IssuerNotParentSubject,
            "max_delegation_depth" if reason == "parent_delegation_depth_exhausted" => {
                DelegationGrantError::DelegationDepthExhausted
            }
            "max_delegation_depth" => DelegationGrantError::OverbroadDepth,
            "operations" => DelegationGrantError::OverbroadOperation {
                reason: reason.to_string(),
            },
            "audiences" => DelegationGrantError::OverbroadAudience {
                reason: reason.to_string(),
            },
            dimension if dimension.starts_with("time") => DelegationGrantError::OverbroadTime {
                reason: reason.to_string(),
            },
            dimension if dimension.starts_with("budget") => DelegationGrantError::OverbroadBudget {
                reason: reason.to_string(),
            },
            _ => DelegationGrantError::OverbroadScope {
                reason: format!("{dimension}:{reason}"),
            },
        },
        other => DelegationGrantError::ChildGrantInvalid {
            reason_code: other.reason_code(),
        },
    }
}

fn validate_versioned_schema(schema: &str) -> Result<(), &'static str> {
    validate_token("schema", schema)?;
    MessageSchemaVersion::from_schema(schema).map_err(|_| "invalid_schema_version")?;
    Ok(())
}

fn validate_token(_field: &'static str, value: &str) -> Result<(), &'static str> {
    if value.trim().is_empty() || value.trim() != value || value.contains('*') {
        return Err("invalid_token");
    }
    Ok(())
}

fn scope_contains_agent_run(scope: &CapabilityScope, agent_id: &AgentId, run_id: &RunId) -> bool {
    scope
        .agent_ids
        .as_ref()
        .is_some_and(|agent_ids| agent_ids.iter().any(|candidate| candidate == agent_id))
        && scope
            .run_ids
            .as_ref()
            .is_some_and(|run_ids| run_ids.iter().any(|candidate| candidate == run_id))
}

fn string_set_contains(values: &Option<Vec<String>>, expected: &str) -> bool {
    values
        .as_ref()
        .is_some_and(|values| values.iter().any(|value| value == expected))
}

fn is_external_effect_operation(operation: &AuthorityOperation) -> bool {
    match operation.namespace {
        AuthorityOperationNamespace::Gateway
        | AuthorityOperationNamespace::Driver
        | AuthorityOperationNamespace::Network
        | AuthorityOperationNamespace::Compatibility => true,
        AuthorityOperationNamespace::Device => operation.verb == AuthorityVerb::Actuate,
        AuthorityOperationNamespace::Artifact => matches!(
            operation.verb,
            AuthorityVerb::Write | AuthorityVerb::Publish | AuthorityVerb::Activate
        ),
        AuthorityOperationNamespace::State => operation.verb == AuthorityVerb::Write,
        AuthorityOperationNamespace::Workload => {
            matches!(operation.verb, AuthorityVerb::Admit | AuthorityVerb::Invoke)
        }
        AuthorityOperationNamespace::Change => operation.verb == AuthorityVerb::Activate,
        AuthorityOperationNamespace::Agent => {
            operation.resource_kind == AuthorityResourceKind::Agent
                && matches!(
                    operation.verb,
                    AuthorityVerb::Invoke | AuthorityVerb::Delegate
                )
        }
        AuthorityOperationNamespace::Data => operation.verb == AuthorityVerb::Publish,
    }
}

#[cfg(test)]
#[path = "../tests/unit/delegation_tests.rs"]
pub(crate) mod tests;
