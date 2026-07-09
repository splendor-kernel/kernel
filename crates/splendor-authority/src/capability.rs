//! AUTH-001 capability grammar evaluation and narrowing.
//!
//! This module is a bounded local evidence slice. It evaluates typed capability
//! grants, computes deterministic scope intersections, and checks that child
//! grants never broaden parent authority. The public evaluator accepts only
//! `ValidatedCapabilityGrant` values produced by trusted local profile builders;
//! raw external `CapabilityGrant` payloads are behavior-free contracts, not
//! authority. This module does not issue production grants, replace signed work
//! orders, integrate with the gateway, call stores, or execute side effects.
//!
//! Each evaluation call authorizes exactly one `AuthorityOperation`. Callers that
//! mediate composite privileged effects must evaluate every required operation
//! before gateway/driver execution. For example, an allowed gateway action does
//! not authorize its adapter, compatibility permission, data purpose, or driver
//! operation unless those operations are separately requested and allowed.

use splendor_types::{
    validate_extension_map, AgentId, AuthorityBudgetScope, AuthorityDecision, AuthorityDecisionId,
    AuthorityDecisionStatus, AuthorityObligation, AuthorityOperation, AuthorityOperationNamespace,
    AuthorityResourceKind, AuthorityTimeScope, AuthorityVerb, CapabilityGrant, CapabilityGrantId,
    CapabilityGrantValidation, CapabilityGrantValidationKind, CapabilityRequest, CapabilityScope,
    DataPurpose, DelegatedAuthority, DriverOperationRef, LocalityScope, NetworkScope, PrincipalId,
    RevocationStatus, RunId, TenantId, WorkOrder, WorkOrderQuotaPolicy,
    AUTHORITY_DECISION_SCHEMA_VERSION, AUTHORITY_OBLIGATION_SCHEMA_VERSION,
    AUTHORITY_OPERATION_SCHEMA_VERSION, CAPABILITY_GRANT_SCHEMA_VERSION,
    CAPABILITY_REQUEST_SCHEMA_VERSION, CAPABILITY_SCOPE_SCHEMA_VERSION,
};
use thiserror::Error;
use time::OffsetDateTime;

/// Context supplied by compatibility profile builders.
#[derive(Clone, Debug)]
pub struct CompatibilityGrantContext {
    /// Grant identity to assign.
    pub grant_id: CapabilityGrantId,
    /// Principal issuing the compatibility grant.
    pub issuer: PrincipalId,
    /// Principal receiving the compatibility grant.
    pub subject: PrincipalId,
    /// Audience binding for the local daemon/runtime path.
    pub audience: String,
    /// Validation digest for the local evidence slice.
    pub validation_digest: String,
    /// Remaining child-delegation depth.
    pub max_delegation_depth: u32,
    /// Parent grant references, when this grant is delegated.
    pub parent_grant_ids: Vec<CapabilityGrantId>,
}

/// Scope coordinates supplied by legacy allowlist compatibility paths.
#[derive(Clone, Debug)]
pub struct LegacyScopeProfile {
    /// Tenant boundary for the grant.
    pub tenant_id: TenantId,
    /// Agent boundary for the grant.
    pub agent_id: AgentId,
    /// Optional run boundary.
    pub run_id: Option<RunId>,
    /// Optional quota/budget narrowing.
    pub quotas: AuthorityBudgetScope,
}

/// Locally validated capability grant accepted by the bounded evaluator.
///
/// Raw `CapabilityGrant` remains a behavior-free public contract in
/// `splendor-types`. The evaluator intentionally consumes only this authority
/// crate wrapper so external grant payloads are not treated as authority unless a
/// trusted local builder has validated their shape and profile constraints.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedCapabilityGrant {
    grant: CapabilityGrant,
    trust: ValidatedGrantTrust,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValidatedGrantTrust {
    LocalProfile,
    VerifiedSigned,
}

impl ValidatedCapabilityGrant {
    /// Returns the underlying behavior-free grant contract for inspection.
    pub fn grant(&self) -> &CapabilityGrant {
        &self.grant
    }
}

/// Evaluates a request against zero or more grants and returns an explicit
/// fail-closed authority decision. The first matching grant allows the request
/// only when it carries no obligations; matching grants with obligations return
/// `Conditional`;
/// invalid, expired, revoked, wrong-subject, wrong-audience, or overbroad grants
/// are treated as denial evidence rather than skipped into an implicit allow.
///
/// This function checks one operation at a time. Composite effects must require
/// separate successful decisions for each action, adapter, permission,
/// data-purpose, driver, or other operation needed for that effect.
pub fn evaluate_capability_request(
    grants: &[ValidatedCapabilityGrant],
    request: &CapabilityRequest,
    now: OffsetDateTime,
) -> AuthorityDecision {
    if let Err(error) = validate_request_shape(request, now) {
        return denied_decision(request.clone(), now, vec![error.reason_code()]);
    }

    if grants.is_empty() {
        return denied_decision(
            request.clone(),
            now,
            vec!["missing_capability_grant".to_string()],
        );
    }

    let mut denial_reasons = Vec::new();
    for validated_grant in grants {
        let grant = validated_grant.grant();
        match grant_allows_request(validated_grant, request, now) {
            Ok(()) => {
                let (status, reason) = if grant.obligations.is_empty() {
                    (AuthorityDecisionStatus::Allowed, "capability_allowed")
                } else {
                    (
                        AuthorityDecisionStatus::Conditional,
                        "capability_conditional",
                    )
                };
                return AuthorityDecision {
                    schema_version: AUTHORITY_DECISION_SCHEMA_VERSION.to_string(),
                    decision_id: AuthorityDecisionId::new(),
                    request: request.clone(),
                    status,
                    reasons: vec![reason.to_string()],
                    matched_grant_ids: vec![grant.grant_id.clone()],
                    obligations: grant.obligations.clone(),
                    decided_at: now,
                };
            }
            Err(errors) => {
                for error in errors {
                    push_unique(&mut denial_reasons, error.reason_code());
                }
            }
        }
    }

    if denial_reasons.is_empty() {
        denial_reasons.push("capability_denied".to_string());
    }
    denied_decision(request.clone(), now, denial_reasons)
}

/// Computes a deterministic intersection of two capability scopes. `None` means
/// a dimension is absent from that scope for intersection purposes; it is not a
/// string wildcard and does not bypass evaluation checks.
pub fn intersect_capability_scopes(
    left: &CapabilityScope,
    right: &CapabilityScope,
) -> Result<CapabilityScope, AuthorityEvaluationError> {
    validate_scope_shape(left)?;
    validate_scope_shape(right)?;

    Ok(CapabilityScope {
        schema_version: CAPABILITY_SCOPE_SCHEMA_VERSION.to_string(),
        tenant_ids: intersect_optional_set("tenant_ids", &left.tenant_ids, &right.tenant_ids)?,
        fleet_ids: intersect_optional_set("fleet_ids", &left.fleet_ids, &right.fleet_ids)?,
        agent_ids: intersect_optional_set("agent_ids", &left.agent_ids, &right.agent_ids)?,
        run_ids: intersect_optional_set("run_ids", &left.run_ids, &right.run_ids)?,
        workload_ids: intersect_optional_set(
            "workload_ids",
            &left.workload_ids,
            &right.workload_ids,
        )?,
        device_ids: intersect_optional_set("device_ids", &left.device_ids, &right.device_ids)?,
        data_purposes: intersect_optional_set(
            "data_purposes",
            &left.data_purposes,
            &right.data_purposes,
        )?,
        artifact_ids: intersect_optional_set(
            "artifact_ids",
            &left.artifact_ids,
            &right.artifact_ids,
        )?,
        state_partition_ids: intersect_optional_set(
            "state_partition_ids",
            &left.state_partition_ids,
            &right.state_partition_ids,
        )?,
        driver_operations: intersect_optional_set(
            "driver_operations",
            &left.driver_operations,
            &right.driver_operations,
        )?,
        audiences: intersect_optional_set("audiences", &left.audiences, &right.audiences)?,
        time: intersect_time_scope(&left.time, &right.time)?,
        budget: intersect_budget_scope(&left.budget, &right.budget),
        network: NetworkScope {
            egress_schemes: intersect_optional_set(
                "network.egress_schemes",
                &left.network.egress_schemes,
                &right.network.egress_schemes,
            )?,
            egress_hosts: intersect_optional_set(
                "network.egress_hosts",
                &left.network.egress_hosts,
                &right.network.egress_hosts,
            )?,
        },
        locality: LocalityScope {
            regions: intersect_optional_set(
                "locality.regions",
                &left.locality.regions,
                &right.locality.regions,
            )?,
            zones: intersect_optional_set(
                "locality.zones",
                &left.locality.zones,
                &right.locality.zones,
            )?,
            data_localities: intersect_optional_set(
                "locality.data_localities",
                &left.locality.data_localities,
                &right.locality.data_localities,
            )?,
        },
    })
}

/// Verifies that `child` is a valid narrower grant under `parent` and returns the
/// effective intersected scope. The check is strict: child grants cannot drop
/// parent constraints, add operations, extend time, increase budget, change
/// issuer lineage, or remove parent obligations.
pub fn ensure_child_grant_narrows(
    parent: &CapabilityGrant,
    child: &CapabilityGrant,
) -> Result<CapabilityScope, AuthorityEvaluationError> {
    validate_grant_shape(parent)?;
    validate_grant_shape(child)?;

    if !child
        .parent_grant_ids
        .iter()
        .any(|grant_id| grant_id == &parent.grant_id)
    {
        return Err(narrowing_violation(
            "parent_grant_ids",
            "missing_parent_grant_id",
        ));
    }
    if child.issuer != parent.subject {
        return Err(narrowing_violation(
            "issuer",
            "child_issuer_not_parent_subject",
        ));
    }
    if parent.max_delegation_depth == 0 {
        return Err(narrowing_violation(
            "max_delegation_depth",
            "parent_delegation_depth_exhausted",
        ));
    }
    if child.max_delegation_depth > parent.max_delegation_depth - 1 {
        return Err(narrowing_violation(
            "max_delegation_depth",
            "child_delegation_depth_broadened",
        ));
    }
    if child.not_before < parent.not_before || child.expires_at > parent.expires_at {
        return Err(narrowing_violation("time", "child_time_window_broadened"));
    }
    ensure_operations_subset(&parent.operations, &child.operations)?;
    ensure_obligations_preserved(&parent.obligations, &child.obligations)?;
    ensure_scope_narrows(&parent.scope, &child.scope)?;

    intersect_capability_scopes(&parent.scope, &child.scope)
}

/// Builds a local compatibility grant from a signed/validated work order's
/// existing action, adapter, permission, quota, tenant, agent, run, expiry, and
/// revocation fields. This is a profile builder only; it does not validate the
/// work-order signature or admit a run.
pub fn grant_from_work_order(
    context: CompatibilityGrantContext,
    work_order: &WorkOrder,
) -> Result<ValidatedCapabilityGrant, AuthorityEvaluationError> {
    let scope = CapabilityScope {
        tenant_ids: Some(vec![work_order.tenant_id.clone()]),
        agent_ids: Some(vec![work_order.agent_id.clone()]),
        run_ids: work_order.run_id.clone().map(|run_id| vec![run_id]),
        audiences: Some(vec![context.audience.clone()]),
        budget: budget_from_work_order_quotas(&work_order.quotas),
        locality: LocalityScope {
            data_localities: work_order
                .placement
                .data_locality
                .as_ref()
                .map(|locality| vec![locality.clone()]),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut grant = raw_grant_from_legacy_allowlists(
        context,
        LegacyScopeProfile {
            tenant_id: work_order.tenant_id.clone(),
            agent_id: work_order.agent_id.clone(),
            run_id: work_order.run_id.clone(),
            quotas: scope.budget,
        },
        &work_order.allowed_actions,
        &work_order.allowed_adapters,
        &work_order.allowed_permissions,
        work_order.issued_at,
        work_order.expires_at,
        work_order.revocation.clone(),
        Some(format!("work_order:{}", work_order.work_order_id.as_str())),
    );
    grant.scope.locality.data_localities = scope.locality.data_localities;
    validate_local_profile_grant(grant)
}

pub(crate) fn grant_from_verified_signed_work_order(
    context: CompatibilityGrantContext,
    work_order: &WorkOrder,
    validation: CapabilityGrantValidation,
) -> Result<ValidatedCapabilityGrant, AuthorityEvaluationError> {
    if validation.validation_kind != CapabilityGrantValidationKind::Signed {
        return Err(AuthorityEvaluationError::InvalidValidation {
            reason: "verified_work_order_grant_requires_signed_validation".to_string(),
        });
    }

    let mut grant = raw_grant_from_legacy_allowlists(
        context,
        LegacyScopeProfile {
            tenant_id: work_order.tenant_id.clone(),
            agent_id: work_order.agent_id.clone(),
            run_id: work_order.run_id.clone(),
            quotas: budget_from_work_order_quotas(&work_order.quotas),
        },
        &work_order.allowed_actions,
        &work_order.allowed_adapters,
        &work_order.allowed_permissions,
        work_order.issued_at,
        work_order.expires_at,
        work_order.revocation.clone(),
        Some(format!("work_order:{}", work_order.work_order_id.as_str())),
    );
    grant.scope.locality.data_localities = work_order
        .placement
        .data_locality
        .as_ref()
        .map(|locality| vec![locality.clone()]);
    grant.validation = Some(validation);
    validate_verified_signed_grant(grant)
}

/// Builds a local compatibility grant from existing delegated authority. This is
/// a profile builder only; local delegation routing and gateway enforcement remain
/// separate runtime checks until future integration work is explicitly wired.
pub fn grant_from_delegated_authority(
    context: CompatibilityGrantContext,
    scope_profile: LegacyScopeProfile,
    authority: &DelegatedAuthority,
    not_before: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<ValidatedCapabilityGrant, AuthorityEvaluationError> {
    grant_from_legacy_allowlists(
        context,
        scope_profile,
        &authority.allowed_actions,
        &authority.allowed_adapters,
        &authority.allowed_permissions,
        not_before,
        expires_at,
        RevocationStatus::Active,
        None,
    )
}

/// Builds a local compatibility grant from legacy allowlist fields. Kernel code
/// can pass current tenant-policy fields through this profile without adding a
/// reverse dependency from `splendor-authority` to `splendor-kernel`.
#[allow(clippy::too_many_arguments)]
pub fn grant_from_legacy_allowlists(
    context: CompatibilityGrantContext,
    scope_profile: LegacyScopeProfile,
    allowed_actions: &[String],
    allowed_adapters: &[String],
    allowed_permissions: &[String],
    not_before: OffsetDateTime,
    expires_at: OffsetDateTime,
    revocation: RevocationStatus,
    revocation_ref: Option<String>,
) -> Result<ValidatedCapabilityGrant, AuthorityEvaluationError> {
    validate_local_profile_grant(raw_grant_from_legacy_allowlists(
        context,
        scope_profile,
        allowed_actions,
        allowed_adapters,
        allowed_permissions,
        not_before,
        expires_at,
        revocation,
        revocation_ref,
    ))
}

#[allow(clippy::too_many_arguments)]
fn raw_grant_from_legacy_allowlists(
    context: CompatibilityGrantContext,
    scope_profile: LegacyScopeProfile,
    allowed_actions: &[String],
    allowed_adapters: &[String],
    allowed_permissions: &[String],
    not_before: OffsetDateTime,
    expires_at: OffsetDateTime,
    revocation: RevocationStatus,
    revocation_ref: Option<String>,
) -> CapabilityGrant {
    let scope = CapabilityScope {
        tenant_ids: Some(vec![scope_profile.tenant_id]),
        agent_ids: Some(vec![scope_profile.agent_id]),
        run_ids: scope_profile.run_id.map(|run_id| vec![run_id]),
        audiences: Some(vec![context.audience]),
        budget: scope_profile.quotas,
        ..Default::default()
    };

    let mut operations = Vec::new();
    operations.extend(
        allowed_actions
            .iter()
            .cloned()
            .map(gateway_action_operation),
    );
    operations.extend(
        allowed_adapters
            .iter()
            .cloned()
            .map(gateway_adapter_operation),
    );
    operations.extend(
        allowed_permissions
            .iter()
            .cloned()
            .map(compatibility_permission_operation),
    );

    CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: context.grant_id,
        issuer: context.issuer,
        subject: context.subject,
        parent_grant_ids: context.parent_grant_ids,
        operations,
        scope,
        not_before,
        expires_at,
        revocation_ref,
        revocation,
        obligations: Vec::new(),
        max_delegation_depth: context.max_delegation_depth,
        validation: Some(CapabilityGrantValidation {
            validation_kind: CapabilityGrantValidationKind::LocallyValidated,
            algorithm: "local-compatibility-profile-v1".to_string(),
            key_id: None,
            digest: context.validation_digest,
            signature: None,
        }),
        metadata: Default::default(),
    }
}

pub(crate) fn validate_local_profile_grant(
    grant: CapabilityGrant,
) -> Result<ValidatedCapabilityGrant, AuthorityEvaluationError> {
    validate_grant_shape_with_trust(&grant, ValidatedGrantTrust::LocalProfile)?;
    for operation in &grant.operations {
        validate_authorization_scope_binding("capability_grant.scope", &grant.scope, operation)?;
    }
    Ok(ValidatedCapabilityGrant {
        grant,
        trust: ValidatedGrantTrust::LocalProfile,
    })
}

#[cfg(test)]
pub(crate) fn unchecked_validated_grant_for_tests(
    grant: CapabilityGrant,
) -> ValidatedCapabilityGrant {
    ValidatedCapabilityGrant {
        grant,
        trust: ValidatedGrantTrust::LocalProfile,
    }
}

fn validate_verified_signed_grant(
    grant: CapabilityGrant,
) -> Result<ValidatedCapabilityGrant, AuthorityEvaluationError> {
    validate_grant_shape_with_trust(&grant, ValidatedGrantTrust::VerifiedSigned)?;
    for operation in &grant.operations {
        validate_authorization_scope_binding("capability_grant.scope", &grant.scope, operation)?;
    }
    Ok(ValidatedCapabilityGrant {
        grant,
        trust: ValidatedGrantTrust::VerifiedSigned,
    })
}

/// Builds a typed 0.1-compatible gateway action operation.
pub fn gateway_action_operation(name: impl Into<String>) -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Gateway,
        resource_kind: AuthorityResourceKind::Action,
        verb: AuthorityVerb::Invoke,
        name: Some(name.into()),
        resource_schema_version: Some("splendor.action.v1".to_string()),
    }
}

/// Builds a typed 0.1-compatible adapter-use operation.
pub fn gateway_adapter_operation(name: impl Into<String>) -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Gateway,
        resource_kind: AuthorityResourceKind::Adapter,
        verb: AuthorityVerb::Use,
        name: Some(name.into()),
        resource_schema_version: Some("splendor.adapter.v1".to_string()),
    }
}

/// Builds a typed 0.1-compatible permission-token operation.
pub fn compatibility_permission_operation(name: impl Into<String>) -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Compatibility,
        resource_kind: AuthorityResourceKind::Permission,
        verb: AuthorityVerb::Use,
        name: Some(name.into()),
        resource_schema_version: Some("splendor.permission.v1".to_string()),
    }
}

/// Builds a typed workload admission operation used by AUTH-002 issuance bridges.
pub fn workload_admit_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Workload,
        resource_kind: AuthorityResourceKind::Workload,
        verb: AuthorityVerb::Admit,
        name: None,
        resource_schema_version: Some("splendor.workload.v1".to_string()),
    }
}

fn grant_allows_request(
    validated_grant: &ValidatedCapabilityGrant,
    request: &CapabilityRequest,
    now: OffsetDateTime,
) -> Result<(), Vec<AuthorityEvaluationError>> {
    let mut errors = Vec::new();
    let grant = validated_grant.grant();

    if let Err(error) = validate_grant_shape_with_trust(grant, validated_grant.trust) {
        errors.push(error);
        return Err(errors);
    }
    for operation in &grant.operations {
        if let Err(error) =
            validate_authorization_scope_binding("capability_grant.scope", &grant.scope, operation)
        {
            errors.push(error);
        }
    }
    if let Err(error) =
        validate_authorization_time("capability_grant.scope.time", &grant.scope.time, now)
    {
        errors.push(error);
    }
    if grant.subject != request.subject {
        errors.push(AuthorityEvaluationError::SubjectMismatch {
            grant_id: grant.grant_id.clone(),
        });
    }
    if now < grant.not_before {
        errors.push(AuthorityEvaluationError::GrantNotYetValid {
            grant_id: grant.grant_id.clone(),
        });
    }
    if now >= grant.expires_at {
        errors.push(AuthorityEvaluationError::ExpiredGrant {
            grant_id: grant.grant_id.clone(),
        });
    }
    if let RevocationStatus::Revoked { reason } = &grant.revocation {
        errors.push(AuthorityEvaluationError::RevokedGrant {
            grant_id: grant.grant_id.clone(),
            reason: reason.clone(),
        });
    }
    if !grant
        .operations
        .iter()
        .any(|operation| operation == &request.operation)
    {
        errors.push(AuthorityEvaluationError::OperationNotGranted {
            operation: operation_label(&request.operation),
        });
    }

    let mut scope_reasons = Vec::new();
    scope_contains_request(&grant.scope, &request.scope, &mut scope_reasons);
    if let Some(required_purpose) = required_data_purpose(&request.operation) {
        match &request.scope.data_purposes {
            Some(purposes) if purposes.contains(&required_purpose) => {}
            _ => scope_reasons.push("data_purpose_missing_for_operation".to_string()),
        }
    }
    for reason in scope_reasons {
        errors.push(AuthorityEvaluationError::ScopeNotGranted { reason });
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_request_shape(
    request: &CapabilityRequest,
    now: OffsetDateTime,
) -> Result<(), AuthorityEvaluationError> {
    if request.schema_version != CAPABILITY_REQUEST_SCHEMA_VERSION {
        return Err(schema_error(
            "capability_request.schema_version",
            CAPABILITY_REQUEST_SCHEMA_VERSION,
            &request.schema_version,
        ));
    }
    if request.subject.is_nil() {
        return Err(AuthorityEvaluationError::InvalidIdentity { field: "subject" });
    }
    validate_operation_shape(&request.operation)?;
    validate_scope_shape(&request.scope)?;
    validate_authorization_scope_binding(
        "capability_request.scope",
        &request.scope,
        &request.operation,
    )?;
    validate_authorization_time("capability_request.scope.time", &request.scope.time, now)?;
    validate_extension_map(&request.metadata, "capability_request.metadata")?;
    Ok(())
}

fn validate_grant_shape(grant: &CapabilityGrant) -> Result<(), AuthorityEvaluationError> {
    validate_grant_shape_with_trust(grant, ValidatedGrantTrust::LocalProfile)
}

fn validate_grant_shape_with_trust(
    grant: &CapabilityGrant,
    trust: ValidatedGrantTrust,
) -> Result<(), AuthorityEvaluationError> {
    if grant.schema_version != CAPABILITY_GRANT_SCHEMA_VERSION {
        return Err(schema_error(
            "capability_grant.schema_version",
            CAPABILITY_GRANT_SCHEMA_VERSION,
            &grant.schema_version,
        ));
    }
    if grant.grant_id.is_nil() {
        return Err(AuthorityEvaluationError::InvalidIdentity { field: "grant_id" });
    }
    if grant.issuer.is_nil() {
        return Err(AuthorityEvaluationError::InvalidIdentity { field: "issuer" });
    }
    if grant.subject.is_nil() {
        return Err(AuthorityEvaluationError::InvalidIdentity { field: "subject" });
    }
    if grant.operations.is_empty() {
        return Err(AuthorityEvaluationError::InvalidOperation {
            reason: "missing_operations".to_string(),
        });
    }
    for operation in &grant.operations {
        validate_operation_shape(operation)?;
    }
    validate_scope_shape(&grant.scope)?;
    if grant.not_before >= grant.expires_at {
        return Err(AuthorityEvaluationError::InvalidScope {
            dimension: "time",
            reason: "grant_not_before_must_precede_expires_at".to_string(),
        });
    }
    validate_optional_token("revocation_ref", grant.revocation_ref.as_deref())?;
    validate_grant_validation(grant.validation.as_ref(), trust)?;
    validate_extension_map(&grant.metadata, "capability_grant.metadata")?;
    for (index, obligation) in grant.obligations.iter().enumerate() {
        validate_obligation(obligation)?;
        if grant
            .obligations
            .iter()
            .skip(index + 1)
            .any(|candidate| candidate.obligation_id == obligation.obligation_id)
        {
            return Err(AuthorityEvaluationError::InvalidScope {
                dimension: "obligations",
                reason: "duplicate_obligation_id".to_string(),
            });
        }
    }
    Ok(())
}

fn validate_grant_validation(
    validation: Option<&CapabilityGrantValidation>,
    trust: ValidatedGrantTrust,
) -> Result<(), AuthorityEvaluationError> {
    let validation = validation.ok_or_else(|| AuthorityEvaluationError::InvalidValidation {
        reason: "missing_grant_validation".to_string(),
    })?;
    validate_token("grant_validation.algorithm", &validation.algorithm)?;
    validate_token("grant_validation.digest", &validation.digest)?;
    validate_optional_token("grant_validation.key_id", validation.key_id.as_deref())?;
    validate_optional_token(
        "grant_validation.signature",
        validation.signature.as_deref(),
    )?;
    if validation.validation_kind == CapabilityGrantValidationKind::Signed {
        if trust != ValidatedGrantTrust::VerifiedSigned {
            return Err(AuthorityEvaluationError::InvalidValidation {
                reason: "signed_grant_verifier_unavailable".to_string(),
            });
        }
        if validation.key_id.is_none() {
            return Err(AuthorityEvaluationError::InvalidValidation {
                reason: "verified_signed_grant_missing_key_id".to_string(),
            });
        }
        return Ok(());
    }
    if trust == ValidatedGrantTrust::VerifiedSigned {
        return Err(AuthorityEvaluationError::InvalidValidation {
            reason: "verified_grant_requires_signed_validation".to_string(),
        });
    }
    Ok(())
}

fn validate_operation_shape(
    operation: &AuthorityOperation,
) -> Result<(), AuthorityEvaluationError> {
    if operation.schema_version != AUTHORITY_OPERATION_SCHEMA_VERSION {
        return Err(schema_error(
            "authority_operation.schema_version",
            AUTHORITY_OPERATION_SCHEMA_VERSION,
            &operation.schema_version,
        ));
    }
    validate_optional_token(
        "authority_operation.resource_schema_version",
        operation.resource_schema_version.as_deref(),
    )?;

    let requires_name = matches!(
        (operation.namespace, operation.resource_kind, operation.verb,),
        (
            AuthorityOperationNamespace::Gateway,
            AuthorityResourceKind::Action,
            AuthorityVerb::Invoke,
        ) | (
            AuthorityOperationNamespace::Gateway,
            AuthorityResourceKind::Adapter,
            AuthorityVerb::Use,
        ) | (
            AuthorityOperationNamespace::Compatibility,
            AuthorityResourceKind::Permission,
            AuthorityVerb::Use,
        ) | (
            AuthorityOperationNamespace::Driver,
            AuthorityResourceKind::DriverOperation,
            AuthorityVerb::Invoke,
        )
    );
    let tuple_allowed = matches!(
        (operation.namespace, operation.resource_kind, operation.verb,),
        (
            AuthorityOperationNamespace::Gateway,
            AuthorityResourceKind::Action,
            AuthorityVerb::Invoke,
        ) | (
            AuthorityOperationNamespace::Gateway,
            AuthorityResourceKind::Adapter,
            AuthorityVerb::Use,
        ) | (
            AuthorityOperationNamespace::Compatibility,
            AuthorityResourceKind::Permission,
            AuthorityVerb::Use,
        ) | (
            AuthorityOperationNamespace::Data,
            AuthorityResourceKind::Data,
            AuthorityVerb::Read
                | AuthorityVerb::Train
                | AuthorityVerb::Evaluate
                | AuthorityVerb::Publish,
        ) | (
            AuthorityOperationNamespace::Artifact,
            AuthorityResourceKind::Artifact,
            AuthorityVerb::Read | AuthorityVerb::Write | AuthorityVerb::Publish,
        ) | (
            AuthorityOperationNamespace::State,
            AuthorityResourceKind::StatePartition,
            AuthorityVerb::Read | AuthorityVerb::Write,
        ) | (
            AuthorityOperationNamespace::Driver,
            AuthorityResourceKind::DriverOperation,
            AuthorityVerb::Invoke,
        ) | (
            AuthorityOperationNamespace::Network,
            AuthorityResourceKind::Network,
            AuthorityVerb::Egress,
        ) | (
            AuthorityOperationNamespace::Device,
            AuthorityResourceKind::Device,
            AuthorityVerb::Read | AuthorityVerb::Actuate,
        ) | (
            AuthorityOperationNamespace::Agent,
            AuthorityResourceKind::Agent,
            AuthorityVerb::Invoke | AuthorityVerb::Delegate,
        ) | (
            AuthorityOperationNamespace::Workload,
            AuthorityResourceKind::Workload,
            AuthorityVerb::Admit | AuthorityVerb::Invoke,
        ) | (
            AuthorityOperationNamespace::Change,
            AuthorityResourceKind::Change,
            AuthorityVerb::Propose | AuthorityVerb::Activate,
        )
    );
    if !tuple_allowed {
        return Err(AuthorityEvaluationError::InvalidOperation {
            reason: "operation_tuple_not_allowed".to_string(),
        });
    }
    match (requires_name, operation.name.as_deref()) {
        (true, Some(name)) => validate_token("authority_operation.name", name),
        (true, None) => Err(AuthorityEvaluationError::InvalidOperation {
            reason: "operation_name_required".to_string(),
        }),
        (false, Some(_)) => Err(AuthorityEvaluationError::InvalidOperation {
            reason: "operation_name_not_allowed_for_typed_tuple".to_string(),
        }),
        (false, None) => Ok(()),
    }
}

fn validate_scope_shape(scope: &CapabilityScope) -> Result<(), AuthorityEvaluationError> {
    if scope.schema_version != CAPABILITY_SCOPE_SCHEMA_VERSION {
        return Err(schema_error(
            "capability_scope.schema_version",
            CAPABILITY_SCOPE_SCHEMA_VERSION,
            &scope.schema_version,
        ));
    }
    validate_identity_set("tenant_ids", scope.tenant_ids.as_ref(), TenantId::is_nil)?;
    validate_identity_set("fleet_ids", scope.fleet_ids.as_ref(), |value| {
        value.is_nil()
    })?;
    validate_identity_set("agent_ids", scope.agent_ids.as_ref(), AgentId::is_nil)?;
    validate_identity_set("run_ids", scope.run_ids.as_ref(), RunId::is_nil)?;
    validate_identity_set("workload_ids", scope.workload_ids.as_ref(), |value| {
        value.is_nil()
    })?;
    validate_identity_set("device_ids", scope.device_ids.as_ref(), |value| {
        value.is_nil()
    })?;
    validate_identity_set("artifact_ids", scope.artifact_ids.as_ref(), |value| {
        value.is_nil()
    })?;
    validate_identity_set(
        "state_partition_ids",
        scope.state_partition_ids.as_ref(),
        |value| value.is_nil(),
    )?;
    validate_non_empty_set("data_purposes", scope.data_purposes.as_ref())?;
    validate_driver_operation_refs(scope.driver_operations.as_ref())?;
    validate_string_set("audiences", scope.audiences.as_ref())?;
    validate_time_scope(&scope.time)?;
    validate_string_set(
        "network.egress_schemes",
        scope.network.egress_schemes.as_ref(),
    )?;
    validate_string_set("network.egress_hosts", scope.network.egress_hosts.as_ref())?;
    validate_string_set("locality.regions", scope.locality.regions.as_ref())?;
    validate_string_set("locality.zones", scope.locality.zones.as_ref())?;
    validate_string_set(
        "locality.data_localities",
        scope.locality.data_localities.as_ref(),
    )?;
    Ok(())
}

fn validate_authorization_scope_binding(
    dimension: &'static str,
    scope: &CapabilityScope,
    operation: &AuthorityOperation,
) -> Result<(), AuthorityEvaluationError> {
    if scope
        .audiences
        .as_ref()
        .is_none_or(|values| values.is_empty())
    {
        return Err(AuthorityEvaluationError::InvalidScope {
            dimension,
            reason: "missing_audience_binding".to_string(),
        });
    }
    if !has_concrete_authorization_dimension(scope) {
        return Err(AuthorityEvaluationError::InvalidScope {
            dimension,
            reason: "missing_bounded_dimension".to_string(),
        });
    }
    if !has_scope_values(&scope.tenant_ids) && !has_scope_values(&scope.fleet_ids) {
        return Err(AuthorityEvaluationError::InvalidScope {
            dimension,
            reason: "missing_tenant_or_fleet_binding".to_string(),
        });
    }
    validate_operation_specific_scope(dimension, scope, operation)?;
    Ok(())
}

fn validate_authorization_time(
    dimension: &'static str,
    scope: &AuthorityTimeScope,
    now: OffsetDateTime,
) -> Result<(), AuthorityEvaluationError> {
    if matches!(scope.not_before, Some(not_before) if now < not_before) {
        return Err(AuthorityEvaluationError::InvalidScope {
            dimension,
            reason: "scope_time_not_yet_valid".to_string(),
        });
    }
    if matches!(scope.expires_at, Some(expires_at) if now >= expires_at) {
        return Err(AuthorityEvaluationError::InvalidScope {
            dimension,
            reason: "scope_time_expired".to_string(),
        });
    }
    Ok(())
}

fn validate_operation_specific_scope(
    dimension: &'static str,
    scope: &CapabilityScope,
    operation: &AuthorityOperation,
) -> Result<(), AuthorityEvaluationError> {
    let reason = match operation.namespace {
        AuthorityOperationNamespace::Data => required_data_purpose(operation).and_then(|purpose| {
            (!scope
                .data_purposes
                .as_ref()
                .is_some_and(|purposes| purposes.contains(&purpose)))
            .then_some("data_purpose_missing_for_operation")
        }),
        AuthorityOperationNamespace::Network => (!has_scope_values(&scope.network.egress_schemes)
            || !has_scope_values(&scope.network.egress_hosts))
        .then_some("network_egress_scope_required"),
        AuthorityOperationNamespace::Device => {
            (!has_scope_values(&scope.device_ids)).then_some("device_scope_required")
        }
        AuthorityOperationNamespace::Artifact => {
            (!has_scope_values(&scope.artifact_ids)).then_some("artifact_scope_required")
        }
        AuthorityOperationNamespace::State => (!has_scope_values(&scope.state_partition_ids))
            .then_some("state_partition_scope_required"),
        AuthorityOperationNamespace::Driver => (!has_scope_values(&scope.driver_operations))
            .then_some("driver_operation_scope_required"),
        AuthorityOperationNamespace::Workload => (!has_scope_values(&scope.workload_ids)
            && !has_scope_values(&scope.run_ids))
        .then_some("workload_or_run_scope_required"),
        AuthorityOperationNamespace::Agent => {
            (!has_scope_values(&scope.agent_ids)).then_some("agent_scope_required")
        }
        AuthorityOperationNamespace::Gateway
        | AuthorityOperationNamespace::Compatibility
        | AuthorityOperationNamespace::Change => None,
    };
    if let Some(reason) = reason {
        return Err(AuthorityEvaluationError::InvalidScope {
            dimension,
            reason: reason.to_string(),
        });
    }
    Ok(())
}

fn has_concrete_authorization_dimension(scope: &CapabilityScope) -> bool {
    has_scope_values(&scope.tenant_ids)
        || has_scope_values(&scope.fleet_ids)
        || has_scope_values(&scope.agent_ids)
        || has_scope_values(&scope.run_ids)
        || has_scope_values(&scope.workload_ids)
        || has_scope_values(&scope.device_ids)
        || has_scope_values(&scope.data_purposes)
        || has_scope_values(&scope.artifact_ids)
        || has_scope_values(&scope.state_partition_ids)
        || has_scope_values(&scope.driver_operations)
        || has_scope_values(&scope.network.egress_schemes)
        || has_scope_values(&scope.network.egress_hosts)
        || has_scope_values(&scope.locality.regions)
        || has_scope_values(&scope.locality.zones)
        || has_scope_values(&scope.locality.data_localities)
}

fn has_scope_values<T>(values: &Option<Vec<T>>) -> bool {
    values.as_ref().is_some_and(|values| !values.is_empty())
}

fn validate_identity_set<T>(
    dimension: &'static str,
    values: Option<&Vec<T>>,
    is_nil: impl Fn(&T) -> bool,
) -> Result<(), AuthorityEvaluationError> {
    validate_non_empty_set(dimension, values)?;
    if let Some(values) = values {
        if values.iter().any(is_nil) {
            return Err(AuthorityEvaluationError::InvalidScope {
                dimension,
                reason: "nil_identity".to_string(),
            });
        }
    }
    Ok(())
}

fn validate_non_empty_set<T>(
    dimension: &'static str,
    values: Option<&Vec<T>>,
) -> Result<(), AuthorityEvaluationError> {
    if values.is_some_and(Vec::is_empty) {
        return Err(AuthorityEvaluationError::InvalidScope {
            dimension,
            reason: "empty_scope_set".to_string(),
        });
    }
    Ok(())
}

fn validate_driver_operation_refs(
    refs: Option<&Vec<DriverOperationRef>>,
) -> Result<(), AuthorityEvaluationError> {
    validate_non_empty_set("driver_operations", refs)?;
    if let Some(refs) = refs {
        for reference in refs {
            validate_token("driver_operations.driver", &reference.driver)?;
            validate_token("driver_operations.operation", &reference.operation)?;
            validate_token(
                "driver_operations.schema_version",
                &reference.schema_version,
            )?;
        }
    }
    Ok(())
}

fn validate_string_set(
    dimension: &'static str,
    values: Option<&Vec<String>>,
) -> Result<(), AuthorityEvaluationError> {
    validate_non_empty_set(dimension, values)?;
    if let Some(values) = values {
        for value in values {
            validate_token(dimension, value)?;
        }
    }
    Ok(())
}

fn validate_time_scope(scope: &AuthorityTimeScope) -> Result<(), AuthorityEvaluationError> {
    if matches!((scope.not_before, scope.expires_at), (Some(start), Some(end)) if start >= end) {
        return Err(AuthorityEvaluationError::InvalidScope {
            dimension: "time",
            reason: "not_before_must_precede_expires_at".to_string(),
        });
    }
    Ok(())
}

fn validate_obligation(obligation: &AuthorityObligation) -> Result<(), AuthorityEvaluationError> {
    if obligation.schema_version != AUTHORITY_OBLIGATION_SCHEMA_VERSION {
        return Err(schema_error(
            "authority_obligation.schema_version",
            AUTHORITY_OBLIGATION_SCHEMA_VERSION,
            &obligation.schema_version,
        ));
    }
    if obligation.obligation_id.is_nil() {
        return Err(AuthorityEvaluationError::InvalidIdentity {
            field: "obligation_id",
        });
    }
    validate_token("obligation.description", &obligation.description)?;
    validate_extension_map(&obligation.parameters, "authority_obligation.parameters")?;
    Ok(())
}

fn validate_token(field: &'static str, value: &str) -> Result<(), AuthorityEvaluationError> {
    if value.trim().is_empty() || value.trim() != value || value.contains('*') {
        return Err(AuthorityEvaluationError::InvalidToken {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_optional_token(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), AuthorityEvaluationError> {
    if let Some(value) = value {
        validate_token(field, value)?;
    }
    Ok(())
}

fn scope_contains_request(
    grant: &CapabilityScope,
    request: &CapabilityScope,
    reasons: &mut Vec<String>,
) {
    contains_requested_set(
        "tenant_ids",
        &grant.tenant_ids,
        &request.tenant_ids,
        reasons,
    );
    contains_requested_set("fleet_ids", &grant.fleet_ids, &request.fleet_ids, reasons);
    contains_requested_set("agent_ids", &grant.agent_ids, &request.agent_ids, reasons);
    contains_requested_set("run_ids", &grant.run_ids, &request.run_ids, reasons);
    contains_requested_set(
        "workload_ids",
        &grant.workload_ids,
        &request.workload_ids,
        reasons,
    );
    contains_requested_set(
        "device_ids",
        &grant.device_ids,
        &request.device_ids,
        reasons,
    );
    contains_requested_set(
        "data_purposes",
        &grant.data_purposes,
        &request.data_purposes,
        reasons,
    );
    contains_requested_set(
        "artifact_ids",
        &grant.artifact_ids,
        &request.artifact_ids,
        reasons,
    );
    contains_requested_set(
        "state_partition_ids",
        &grant.state_partition_ids,
        &request.state_partition_ids,
        reasons,
    );
    contains_requested_set(
        "driver_operations",
        &grant.driver_operations,
        &request.driver_operations,
        reasons,
    );
    contains_requested_set("audience", &grant.audiences, &request.audiences, reasons);
    time_contains_request(&grant.time, &request.time, reasons);
    budget_contains_request(&grant.budget, &request.budget, reasons);
    contains_requested_set(
        "network.egress_schemes",
        &grant.network.egress_schemes,
        &request.network.egress_schemes,
        reasons,
    );
    contains_requested_set(
        "network.egress_hosts",
        &grant.network.egress_hosts,
        &request.network.egress_hosts,
        reasons,
    );
    contains_requested_set(
        "locality.regions",
        &grant.locality.regions,
        &request.locality.regions,
        reasons,
    );
    contains_requested_set(
        "locality.zones",
        &grant.locality.zones,
        &request.locality.zones,
        reasons,
    );
    contains_requested_set(
        "locality.data_localities",
        &grant.locality.data_localities,
        &request.locality.data_localities,
        reasons,
    );
}

fn time_contains_request(
    grant: &AuthorityTimeScope,
    request: &AuthorityTimeScope,
    reasons: &mut Vec<String>,
) {
    match (grant.not_before, request.not_before) {
        (Some(_), None) => reasons.push("time.not_before_missing_from_request".to_string()),
        (None, Some(_)) => reasons.push("time.not_before_not_granted".to_string()),
        (Some(granted), Some(requested)) if requested < granted => {
            reasons.push("time.not_before_precedes_grant".to_string());
        }
        _ => {}
    }
    match (grant.expires_at, request.expires_at) {
        (Some(_), None) => reasons.push("time.expires_at_missing_from_request".to_string()),
        (None, Some(_)) => reasons.push("time.expires_at_not_granted".to_string()),
        (Some(granted), Some(requested)) if requested > granted => {
            reasons.push("time.expires_at_exceeds_grant".to_string());
        }
        _ => {}
    }
}

fn contains_requested_set<T: PartialEq>(
    dimension: &str,
    granted: &Option<Vec<T>>,
    requested: &Option<Vec<T>>,
    reasons: &mut Vec<String>,
) {
    match (granted, requested) {
        (Some(_), None) => reasons.push(format!("{dimension}_missing_from_request")),
        (None, Some(_)) => reasons.push(format!("{dimension}_not_granted")),
        (Some(granted), Some(requested)) => {
            if !requested
                .iter()
                .all(|item| granted.iter().any(|grant| grant == item))
            {
                reasons.push(format!("{dimension}_not_granted"));
            }
        }
        (None, None) => {}
    }
}

fn budget_contains_request(
    grant: &AuthorityBudgetScope,
    request: &AuthorityBudgetScope,
    reasons: &mut Vec<String>,
) {
    budget_limit_contains(
        "budget.max_actions_per_tick",
        grant.max_actions_per_tick,
        request.max_actions_per_tick,
        reasons,
    );
    budget_limit_contains(
        "budget.max_action_duration_ms",
        grant.max_action_duration_ms,
        request.max_action_duration_ms,
        reasons,
    );
    budget_limit_contains(
        "budget.max_filesystem_read_bytes",
        grant.max_filesystem_read_bytes,
        request.max_filesystem_read_bytes,
        reasons,
    );
    budget_limit_contains(
        "budget.max_filesystem_write_bytes",
        grant.max_filesystem_write_bytes,
        request.max_filesystem_write_bytes,
        reasons,
    );
    budget_limit_contains(
        "budget.max_network_read_bytes",
        grant.max_network_read_bytes,
        request.max_network_read_bytes,
        reasons,
    );
    budget_limit_contains(
        "budget.max_network_write_bytes",
        grant.max_network_write_bytes,
        request.max_network_write_bytes,
        reasons,
    );
    budget_limit_contains(
        "budget.max_http_requests_per_minute",
        grant.max_http_requests_per_minute,
        request.max_http_requests_per_minute,
        reasons,
    );
}

fn budget_limit_contains<T: Ord>(
    dimension: &str,
    granted: Option<T>,
    requested: Option<T>,
    reasons: &mut Vec<String>,
) {
    match (granted, requested) {
        (Some(_), None) => reasons.push(format!("{dimension}_missing_from_request")),
        (None, Some(_)) => reasons.push(format!("{dimension}_not_granted")),
        (Some(granted), Some(requested)) if requested > granted => {
            reasons.push(format!("{dimension}_exceeds_grant"));
        }
        _ => {}
    }
}

fn ensure_operations_subset(
    parent: &[AuthorityOperation],
    child: &[AuthorityOperation],
) -> Result<(), AuthorityEvaluationError> {
    for operation in child {
        if !parent
            .iter()
            .any(|parent_operation| parent_operation == operation)
        {
            return Err(narrowing_violation(
                "operations",
                "child_operation_not_in_parent",
            ));
        }
    }
    Ok(())
}

fn ensure_obligations_preserved(
    parent: &[AuthorityObligation],
    child: &[AuthorityObligation],
) -> Result<(), AuthorityEvaluationError> {
    for obligation in parent {
        if !child.iter().any(|candidate| candidate == obligation) {
            return Err(narrowing_violation(
                "obligations",
                "child_dropped_parent_obligation",
            ));
        }
    }
    Ok(())
}

fn ensure_scope_narrows(
    parent: &CapabilityScope,
    child: &CapabilityScope,
) -> Result<(), AuthorityEvaluationError> {
    ensure_set_narrows("tenant_ids", &parent.tenant_ids, &child.tenant_ids)?;
    ensure_set_narrows("fleet_ids", &parent.fleet_ids, &child.fleet_ids)?;
    ensure_set_narrows("agent_ids", &parent.agent_ids, &child.agent_ids)?;
    ensure_set_narrows("run_ids", &parent.run_ids, &child.run_ids)?;
    ensure_set_narrows("workload_ids", &parent.workload_ids, &child.workload_ids)?;
    ensure_set_narrows("device_ids", &parent.device_ids, &child.device_ids)?;
    ensure_set_narrows("data_purposes", &parent.data_purposes, &child.data_purposes)?;
    ensure_set_narrows("artifact_ids", &parent.artifact_ids, &child.artifact_ids)?;
    ensure_set_narrows(
        "state_partition_ids",
        &parent.state_partition_ids,
        &child.state_partition_ids,
    )?;
    ensure_set_narrows(
        "driver_operations",
        &parent.driver_operations,
        &child.driver_operations,
    )?;
    ensure_set_narrows("audiences", &parent.audiences, &child.audiences)?;
    ensure_budget_narrows(&parent.budget, &child.budget)?;
    ensure_time_narrows(&parent.time, &child.time)?;
    ensure_set_narrows(
        "network.egress_schemes",
        &parent.network.egress_schemes,
        &child.network.egress_schemes,
    )?;
    ensure_set_narrows(
        "network.egress_hosts",
        &parent.network.egress_hosts,
        &child.network.egress_hosts,
    )?;
    ensure_set_narrows(
        "locality.regions",
        &parent.locality.regions,
        &child.locality.regions,
    )?;
    ensure_set_narrows(
        "locality.zones",
        &parent.locality.zones,
        &child.locality.zones,
    )?;
    ensure_set_narrows(
        "locality.data_localities",
        &parent.locality.data_localities,
        &child.locality.data_localities,
    )?;
    Ok(())
}

fn ensure_set_narrows<T: PartialEq>(
    dimension: &'static str,
    parent: &Option<Vec<T>>,
    child: &Option<Vec<T>>,
) -> Result<(), AuthorityEvaluationError> {
    if let Some(parent_values) = parent {
        let Some(child_values) = child else {
            return Err(narrowing_violation(
                dimension,
                "child_removed_parent_constraint",
            ));
        };
        if !child_values.iter().all(|child_value| {
            parent_values
                .iter()
                .any(|parent_value| parent_value == child_value)
        }) {
            return Err(narrowing_violation(dimension, "child_value_not_in_parent"));
        }
    }
    Ok(())
}

fn ensure_budget_narrows(
    parent: &AuthorityBudgetScope,
    child: &AuthorityBudgetScope,
) -> Result<(), AuthorityEvaluationError> {
    ensure_budget_limit_narrows(
        "budget.max_actions_per_tick",
        parent.max_actions_per_tick,
        child.max_actions_per_tick,
    )?;
    ensure_budget_limit_narrows(
        "budget.max_action_duration_ms",
        parent.max_action_duration_ms,
        child.max_action_duration_ms,
    )?;
    ensure_budget_limit_narrows(
        "budget.max_filesystem_read_bytes",
        parent.max_filesystem_read_bytes,
        child.max_filesystem_read_bytes,
    )?;
    ensure_budget_limit_narrows(
        "budget.max_filesystem_write_bytes",
        parent.max_filesystem_write_bytes,
        child.max_filesystem_write_bytes,
    )?;
    ensure_budget_limit_narrows(
        "budget.max_network_read_bytes",
        parent.max_network_read_bytes,
        child.max_network_read_bytes,
    )?;
    ensure_budget_limit_narrows(
        "budget.max_network_write_bytes",
        parent.max_network_write_bytes,
        child.max_network_write_bytes,
    )?;
    ensure_budget_limit_narrows(
        "budget.max_http_requests_per_minute",
        parent.max_http_requests_per_minute,
        child.max_http_requests_per_minute,
    )?;
    Ok(())
}

fn ensure_budget_limit_narrows<T: Ord>(
    dimension: &'static str,
    parent: Option<T>,
    child: Option<T>,
) -> Result<(), AuthorityEvaluationError> {
    match (parent, child) {
        (Some(_), None) => Err(narrowing_violation(dimension, "child_removed_budget_limit")),
        (Some(parent), Some(child)) if child > parent => Err(narrowing_violation(
            dimension,
            "child_budget_limit_increased",
        )),
        _ => Ok(()),
    }
}

fn ensure_time_narrows(
    parent: &AuthorityTimeScope,
    child: &AuthorityTimeScope,
) -> Result<(), AuthorityEvaluationError> {
    if matches!((parent.not_before, child.not_before), (Some(_), None)) {
        return Err(narrowing_violation(
            "time.not_before",
            "child_removed_not_before",
        ));
    }
    if matches!((parent.expires_at, child.expires_at), (Some(_), None)) {
        return Err(narrowing_violation(
            "time.expires_at",
            "child_removed_expires_at",
        ));
    }
    if matches!((parent.not_before, child.not_before), (Some(parent), Some(child)) if child < parent)
    {
        return Err(narrowing_violation(
            "time.not_before",
            "child_started_earlier",
        ));
    }
    if matches!((parent.expires_at, child.expires_at), (Some(parent), Some(child)) if child > parent)
    {
        return Err(narrowing_violation(
            "time.expires_at",
            "child_expires_later",
        ));
    }
    Ok(())
}

fn intersect_optional_set<T: Clone + PartialEq>(
    dimension: &'static str,
    left: &Option<Vec<T>>,
    right: &Option<Vec<T>>,
) -> Result<Option<Vec<T>>, AuthorityEvaluationError> {
    match (left, right) {
        (Some(left), Some(right)) => {
            let intersection = left
                .iter()
                .filter(|value| right.iter().any(|candidate| candidate == *value))
                .cloned()
                .collect::<Vec<_>>();
            if intersection.is_empty() {
                Err(AuthorityEvaluationError::EmptyIntersection { dimension })
            } else {
                Ok(Some(intersection))
            }
        }
        (Some(left), None) => Ok(Some(left.clone())),
        (None, Some(right)) => Ok(Some(right.clone())),
        (None, None) => Ok(None),
    }
}

fn intersect_time_scope(
    left: &AuthorityTimeScope,
    right: &AuthorityTimeScope,
) -> Result<AuthorityTimeScope, AuthorityEvaluationError> {
    let not_before = max_optional(left.not_before, right.not_before);
    let expires_at = min_optional(left.expires_at, right.expires_at);
    if matches!((not_before, expires_at), (Some(start), Some(end)) if start >= end) {
        return Err(AuthorityEvaluationError::EmptyIntersection { dimension: "time" });
    }
    Ok(AuthorityTimeScope {
        not_before,
        expires_at,
    })
}

fn intersect_budget_scope(
    left: &AuthorityBudgetScope,
    right: &AuthorityBudgetScope,
) -> AuthorityBudgetScope {
    AuthorityBudgetScope {
        max_actions_per_tick: min_optional(left.max_actions_per_tick, right.max_actions_per_tick),
        max_action_duration_ms: min_optional(
            left.max_action_duration_ms,
            right.max_action_duration_ms,
        ),
        max_filesystem_read_bytes: min_optional(
            left.max_filesystem_read_bytes,
            right.max_filesystem_read_bytes,
        ),
        max_filesystem_write_bytes: min_optional(
            left.max_filesystem_write_bytes,
            right.max_filesystem_write_bytes,
        ),
        max_network_read_bytes: min_optional(
            left.max_network_read_bytes,
            right.max_network_read_bytes,
        ),
        max_network_write_bytes: min_optional(
            left.max_network_write_bytes,
            right.max_network_write_bytes,
        ),
        max_http_requests_per_minute: min_optional(
            left.max_http_requests_per_minute,
            right.max_http_requests_per_minute,
        ),
    }
}

pub(crate) fn budget_from_work_order_quotas(quotas: &WorkOrderQuotaPolicy) -> AuthorityBudgetScope {
    AuthorityBudgetScope {
        max_actions_per_tick: quotas.max_actions_per_tick,
        max_action_duration_ms: quotas.max_action_duration_ms,
        max_filesystem_read_bytes: quotas.max_filesystem_read_bytes,
        max_filesystem_write_bytes: quotas.max_filesystem_write_bytes,
        max_network_read_bytes: quotas.max_network_read_bytes,
        max_network_write_bytes: quotas.max_network_write_bytes,
        max_http_requests_per_minute: quotas.max_http_requests_per_minute,
    }
}

fn min_optional<T: Ord + Copy>(left: Option<T>, right: Option<T>) -> Option<T> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn max_optional<T: Ord + Copy>(left: Option<T>, right: Option<T>) -> Option<T> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn required_data_purpose(operation: &AuthorityOperation) -> Option<DataPurpose> {
    if operation.namespace != AuthorityOperationNamespace::Data {
        return None;
    }
    match operation.verb {
        AuthorityVerb::Read => Some(DataPurpose::Read),
        AuthorityVerb::Train => Some(DataPurpose::TrainingUse),
        AuthorityVerb::Evaluate => Some(DataPurpose::EvaluationUse),
        AuthorityVerb::Publish => Some(DataPurpose::Publication),
        _ => None,
    }
}

fn operation_label(operation: &AuthorityOperation) -> String {
    operation.name.clone().unwrap_or_else(|| {
        format!(
            "{:?}.{:?}.{:?}",
            operation.namespace, operation.resource_kind, operation.verb
        )
    })
}

fn denied_decision(
    request: CapabilityRequest,
    now: OffsetDateTime,
    reasons: Vec<String>,
) -> AuthorityDecision {
    AuthorityDecision {
        schema_version: AUTHORITY_DECISION_SCHEMA_VERSION.to_string(),
        decision_id: AuthorityDecisionId::new(),
        request,
        status: AuthorityDecisionStatus::Denied,
        reasons,
        matched_grant_ids: Vec::new(),
        obligations: Vec::new(),
        decided_at: now,
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn schema_error(
    field: &'static str,
    expected: &'static str,
    actual: &str,
) -> AuthorityEvaluationError {
    AuthorityEvaluationError::InvalidSchema {
        field,
        expected,
        actual: actual.to_string(),
    }
}

fn narrowing_violation(dimension: &'static str, reason: &'static str) -> AuthorityEvaluationError {
    AuthorityEvaluationError::NarrowingViolation { dimension, reason }
}

/// Fail-closed authority evaluation and narrowing errors.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthorityEvaluationError {
    /// A schema version was unsupported.
    #[error("invalid schema for {field}: expected {expected}, found {actual}")]
    InvalidSchema {
        /// Field carrying the schema version.
        field: &'static str,
        /// Expected schema value.
        expected: &'static str,
        /// Actual schema value.
        actual: String,
    },
    /// A required identity was nil.
    #[error("invalid identity field {field}")]
    InvalidIdentity { field: &'static str },
    /// A scope dimension was malformed.
    #[error("invalid scope dimension {dimension}: {reason}")]
    InvalidScope {
        /// Scope dimension.
        dimension: &'static str,
        /// Stable failure reason.
        reason: String,
    },
    /// An operation tuple or token was malformed.
    #[error("invalid operation: {reason}")]
    InvalidOperation { reason: String },
    /// A string token used a blank value, surrounding whitespace, or wildcard.
    #[error("invalid token in {field}: {value}")]
    InvalidToken { field: &'static str, value: String },
    /// A grant was missing local validation/signature evidence.
    #[error("invalid grant validation: {reason}")]
    InvalidValidation { reason: String },
    /// Non-authorizing metadata tried to use reserved authority keys.
    #[error("metadata rejected: {0}")]
    Metadata(#[from] splendor_types::ExtensionValidationError),
    /// Grant subject did not match request subject.
    #[error("grant subject does not match request subject: {grant_id}")]
    SubjectMismatch { grant_id: CapabilityGrantId },
    /// Grant is not yet valid.
    #[error("grant is not yet valid: {grant_id}")]
    GrantNotYetValid { grant_id: CapabilityGrantId },
    /// Grant is expired.
    #[error("grant is expired: {grant_id}")]
    ExpiredGrant { grant_id: CapabilityGrantId },
    /// Grant has been revoked.
    #[error("grant has been revoked: {grant_id}: {reason}")]
    RevokedGrant {
        /// Grant ID.
        grant_id: CapabilityGrantId,
        /// Revocation reason.
        reason: String,
    },
    /// Requested operation was absent from the grant.
    #[error("operation is not granted: {operation}")]
    OperationNotGranted { operation: String },
    /// Requested scope was not contained in the grant.
    #[error("scope not granted: {reason}")]
    ScopeNotGranted { reason: String },
    /// Two scopes have no deterministic intersection for a dimension.
    #[error("empty scope intersection for {dimension}")]
    EmptyIntersection { dimension: &'static str },
    /// A child grant broadened or failed to preserve a parent dimension.
    #[error("child grant broadened {dimension}: {reason}")]
    NarrowingViolation {
        /// Dimension that broadened.
        dimension: &'static str,
        /// Stable failure reason.
        reason: &'static str,
    },
}

impl AuthorityEvaluationError {
    /// Stable reason code for authority decisions and tests.
    pub fn reason_code(&self) -> String {
        match self {
            Self::InvalidSchema { field, .. } => format!("invalid_schema:{field}"),
            Self::InvalidIdentity { field } => format!("invalid_identity:{field}"),
            Self::InvalidScope { dimension, reason } => {
                format!("invalid_scope:{dimension}:{reason}")
            }
            Self::InvalidOperation { reason } => format!("invalid_operation:{reason}"),
            Self::InvalidToken { field, .. } => format!("invalid_token:{field}"),
            Self::InvalidValidation { reason } => format!("invalid_validation:{reason}"),
            Self::Metadata(_) => "metadata_reserved_authority_key".to_string(),
            Self::SubjectMismatch { .. } => "subject_mismatch".to_string(),
            Self::GrantNotYetValid { .. } => "grant_not_yet_valid".to_string(),
            Self::ExpiredGrant { .. } => "expired_grant".to_string(),
            Self::RevokedGrant { .. } => "revoked_grant".to_string(),
            Self::OperationNotGranted { .. } => "operation_not_granted".to_string(),
            Self::ScopeNotGranted { reason } => reason.clone(),
            Self::EmptyIntersection { dimension } => format!("empty_intersection:{dimension}"),
            Self::NarrowingViolation { dimension, reason } => {
                format!("narrowing_violation:{dimension}:{reason}")
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/capability_tests.rs"]
mod tests;
