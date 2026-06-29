//! AUTH-002a signed work-order to validated capability grant bridge.
//!
//! This module is intentionally bounded: it validates an already signed
//! `WorkOrderEnvelope`, checks issuer/subject principal records, evaluates the
//! issuer's workload-admission authority, and returns a verified signed
//! `ValidatedCapabilityGrant` over the work-order allowlists. It does not change
//! work-order schemas, daemon APIs, gateway wiring, fleet/node behavior, or raw
//! signed grant evaluation.

use crate::capability::{
    budget_from_work_order_quotas, grant_from_verified_signed_work_order, workload_admit_operation,
};
use crate::{evaluate_capability_request, CompatibilityGrantContext, ValidatedCapabilityGrant};
use splendor_types::{
    validate_work_order, AuthorityDecision, AuthorityDecisionStatus, AuthorityTimeScope,
    CapabilityGrantId, CapabilityGrantValidation, CapabilityGrantValidationKind, CapabilityRequest,
    CapabilityScope, LocalityScope, Principal, PrincipalBinding, PrincipalStatus, TenantId,
    ValidatedWorkOrder, WorkOrder, WorkOrderEnvelope, WorkOrderKeyring, WorkOrderValidationContext,
    WorkOrderValidationError, CAPABILITY_REQUEST_SCHEMA_VERSION,
};
use thiserror::Error;

const WORK_ORDER_GRANT_VALIDATION_ALGORITHM: &str = "work-order-signed-grant-bridge-v1";

/// Command for issuing a validated capability grant from a signed work order.
pub struct WorkOrderGrantIssuance<'a> {
    /// Signed work-order envelope to validate before any authority grant is built.
    pub envelope: &'a WorkOrderEnvelope,
    /// Runtime validation context for tenant, agent, run, placement, and time.
    pub validation_context: &'a WorkOrderValidationContext,
    /// Verification keys used by the work-order signature validator.
    pub keyring: &'a WorkOrderKeyring,
    /// Active issuer principal record that owns or is bound to the work-order tenant.
    pub issuer: &'a Principal,
    /// Active subject principal record that is bound to the work-order agent.
    pub subject: &'a Principal,
    /// Existing issuer grants used to authorize workload admission.
    pub issuer_grants: &'a [ValidatedCapabilityGrant],
    /// Audience binding for both the issuer decision and issued grant.
    pub audience: String,
    /// Grant ID assigned to the issued work-order capability grant.
    pub issued_grant_id: CapabilityGrantId,
}

/// Successful AUTH-002a issuance evidence.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkOrderGrantIssuanceResult {
    validated_work_order: ValidatedWorkOrder,
    issuer_decision: AuthorityDecision,
    issued_grant: ValidatedCapabilityGrant,
}

impl WorkOrderGrantIssuanceResult {
    /// Returns the signed and context-validated work order.
    pub fn validated_work_order(&self) -> &ValidatedWorkOrder {
        &self.validated_work_order
    }

    /// Returns the issuer workload-admission decision used as issuance evidence.
    pub fn issuer_decision(&self) -> &AuthorityDecision {
        &self.issuer_decision
    }

    /// Returns the issued validated capability grant.
    pub fn issued_grant(&self) -> &ValidatedCapabilityGrant {
        &self.issued_grant
    }

    /// Consumes the result and returns the issued validated capability grant.
    pub fn into_issued_grant(self) -> ValidatedCapabilityGrant {
        self.issued_grant
    }
}

/// Fail-closed AUTH-002a issuance errors. Error text carries stable reason codes
/// and intentionally omits shared secrets and detached signature values.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum WorkOrderGrantIssuanceError {
    /// Work-order validation failed before principal or authority evaluation.
    #[error("work-order validation failed: {reason_code}")]
    WorkOrderValidation {
        /// Sanitized work-order validation reason.
        reason_code: &'static str,
    },
    /// Issuer principal is not active for privileged issuance.
    #[error("issuer principal is not active: {status:?}")]
    InactiveIssuer {
        /// Current issuer principal status.
        status: PrincipalStatus,
    },
    /// Subject principal is not active for privileged use.
    #[error("subject principal is not active: {status:?}")]
    InactiveSubject {
        /// Current subject principal status.
        status: PrincipalStatus,
    },
    /// Issuer is not bound to the work-order tenant.
    #[error("issuer principal is not tenant-bound to the work order")]
    IssuerTenantBindingMismatch,
    /// Issuer proof records do not bind the validated work-order signing key.
    #[error("issuer principal is not bound to the work-order signing key")]
    IssuerSignatureBindingMismatch,
    /// Subject is not bound to the work-order agent.
    #[error("subject principal is not bound to the work-order agent")]
    SubjectAgentBindingMismatch,
    /// Subject is not bound to the work-order tenant.
    #[error("subject principal is not tenant-bound to the work order")]
    SubjectTenantBindingMismatch,
    /// Issuer did not have authority to admit this workload scope.
    #[error("issuer workload-admission authority denied")]
    IssuerAuthorityDenied {
        /// Denial evidence from the capability evaluator.
        decision: Box<AuthorityDecision>,
    },
    /// Building the issued grant failed after issuer authorization.
    #[error("capability grant build failed: {reason_code}")]
    GrantBuildFailed {
        /// Sanitized grant-build reason.
        reason_code: String,
    },
}

impl WorkOrderGrantIssuanceError {
    /// Stable reason code suitable for tests, traces, and audit records.
    pub fn reason_code(&self) -> &str {
        match self {
            Self::WorkOrderValidation { reason_code } => reason_code,
            Self::InactiveIssuer { status } => principal_status_reason(*status, "issuer"),
            Self::InactiveSubject { status } => principal_status_reason(*status, "subject"),
            Self::IssuerTenantBindingMismatch => "issuer_tenant_binding_mismatch",
            Self::IssuerSignatureBindingMismatch => "issuer_signature_binding_mismatch",
            Self::SubjectAgentBindingMismatch => "subject_agent_binding_mismatch",
            Self::SubjectTenantBindingMismatch => "subject_tenant_binding_mismatch",
            Self::IssuerAuthorityDenied { .. } => "issuer_authority_denied",
            Self::GrantBuildFailed { reason_code } => reason_code.as_str(),
        }
    }
}

/// Issues a verified signed capability grant for a validated work order's
/// existing action, adapter, permission, quota, tenant, agent, run, expiry, and
/// locality scope.
pub fn issue_work_order_capability_grant(
    request: WorkOrderGrantIssuance<'_>,
) -> Result<WorkOrderGrantIssuanceResult, WorkOrderGrantIssuanceError> {
    let validated_work_order = validate_work_order(
        request.envelope,
        request.validation_context,
        request.keyring,
    )
    .map_err(work_order_validation_error)?;
    let work_order = validated_work_order.work_order();

    require_active_issuer(request.issuer)?;
    require_active_subject(request.subject)?;
    require_issuer_tenant_binding(request.issuer, &work_order.tenant_id)?;
    require_issuer_signature_binding(request.issuer, request.envelope, &request.audience)?;
    require_subject_work_order_binding(request.subject, work_order)?;

    let issuer_request = CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject: request.issuer.principal_id.clone(),
        operation: workload_admit_operation(),
        scope: workload_admit_scope(work_order, &request.audience),
        requested_at: request.validation_context.now,
        metadata: Default::default(),
    };
    let issuer_decision = evaluate_capability_request(
        request.issuer_grants,
        &issuer_request,
        request.validation_context.now,
    );
    if issuer_decision.status != AuthorityDecisionStatus::Allowed {
        return Err(WorkOrderGrantIssuanceError::IssuerAuthorityDenied {
            decision: Box::new(issuer_decision),
        });
    }

    let grant_validation = CapabilityGrantValidation {
        validation_kind: CapabilityGrantValidationKind::Signed,
        algorithm: WORK_ORDER_GRANT_VALIDATION_ALGORITHM.to_string(),
        key_id: request
            .envelope
            .signature
            .as_ref()
            .map(|signature| signature.key_id.clone()),
        digest: format!("work_order:{}", work_order.work_order_id.as_str()),
        signature: None,
    };
    let issued_grant = grant_from_verified_signed_work_order(
        CompatibilityGrantContext {
            grant_id: request.issued_grant_id,
            issuer: request.issuer.principal_id.clone(),
            subject: request.subject.principal_id.clone(),
            audience: request.audience,
            validation_digest: grant_validation.digest.clone(),
            max_delegation_depth: 0,
            parent_grant_ids: Vec::new(),
        },
        work_order,
        grant_validation,
    )
    .map_err(|error| WorkOrderGrantIssuanceError::GrantBuildFailed {
        reason_code: error.reason_code(),
    })?;

    Ok(WorkOrderGrantIssuanceResult {
        validated_work_order,
        issuer_decision,
        issued_grant,
    })
}

fn work_order_validation_error(error: WorkOrderValidationError) -> WorkOrderGrantIssuanceError {
    WorkOrderGrantIssuanceError::WorkOrderValidation {
        reason_code: error.reason_code(),
    }
}

fn require_active_issuer(principal: &Principal) -> Result<(), WorkOrderGrantIssuanceError> {
    if principal.status != PrincipalStatus::Active {
        return Err(WorkOrderGrantIssuanceError::InactiveIssuer {
            status: principal.status,
        });
    }
    Ok(())
}

fn require_active_subject(principal: &Principal) -> Result<(), WorkOrderGrantIssuanceError> {
    if principal.status != PrincipalStatus::Active {
        return Err(WorkOrderGrantIssuanceError::InactiveSubject {
            status: principal.status,
        });
    }
    Ok(())
}

fn require_issuer_tenant_binding(
    issuer: &Principal,
    tenant_id: &TenantId,
) -> Result<(), WorkOrderGrantIssuanceError> {
    if issuer.owner_tenant_id.as_ref() == Some(tenant_id)
        || issuer.bindings.iter().any(|binding| {
            matches!(binding, PrincipalBinding::Tenant { tenant_id: bound } if bound == tenant_id)
        })
    {
        return Ok(());
    }
    Err(WorkOrderGrantIssuanceError::IssuerTenantBindingMismatch)
}

fn require_issuer_signature_binding(
    issuer: &Principal,
    envelope: &WorkOrderEnvelope,
    audience: &str,
) -> Result<(), WorkOrderGrantIssuanceError> {
    let Some(signature) = &envelope.signature else {
        return Err(WorkOrderGrantIssuanceError::IssuerSignatureBindingMismatch);
    };
    if issuer.proof_refs.iter().any(|proof| {
        proof.proof_kind == "work_order_signing_key"
            && proof.audience.as_deref() == Some(audience)
            && proof
                .key_id
                .as_deref()
                .is_some_and(|key_id| key_id == signature.key_id)
    }) {
        return Ok(());
    }
    Err(WorkOrderGrantIssuanceError::IssuerSignatureBindingMismatch)
}

fn require_subject_work_order_binding(
    subject: &Principal,
    work_order: &WorkOrder,
) -> Result<(), WorkOrderGrantIssuanceError> {
    let agent_bound = subject.bindings.iter().any(|binding| {
        matches!(binding, PrincipalBinding::Agent { agent_id } if agent_id == &work_order.agent_id)
    });
    if !agent_bound {
        return Err(WorkOrderGrantIssuanceError::SubjectAgentBindingMismatch);
    }
    let tenant_bound = subject.owner_tenant_id.as_ref() == Some(&work_order.tenant_id)
        || subject.bindings.iter().any(|binding| {
            matches!(binding, PrincipalBinding::Tenant { tenant_id } if tenant_id == &work_order.tenant_id)
        });
    if !tenant_bound {
        return Err(WorkOrderGrantIssuanceError::SubjectTenantBindingMismatch);
    }
    Ok(())
}

fn workload_admit_scope(work_order: &WorkOrder, audience: &str) -> CapabilityScope {
    CapabilityScope {
        tenant_ids: Some(vec![work_order.tenant_id.clone()]),
        agent_ids: Some(vec![work_order.agent_id.clone()]),
        run_ids: work_order.run_id.clone().map(|run_id| vec![run_id]),
        audiences: Some(vec![audience.to_string()]),
        time: AuthorityTimeScope {
            not_before: Some(work_order.issued_at),
            expires_at: Some(work_order.expires_at),
        },
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
    }
}

fn principal_status_reason(status: PrincipalStatus, role: &str) -> &'static str {
    match (role, status) {
        ("issuer", PrincipalStatus::Pending) => "pending_issuer_principal",
        ("issuer", PrincipalStatus::Suspended) => "suspended_issuer_principal",
        ("issuer", PrincipalStatus::Revoked) => "revoked_issuer_principal",
        ("subject", PrincipalStatus::Pending) => "pending_subject_principal",
        ("subject", PrincipalStatus::Suspended) => "suspended_subject_principal",
        ("subject", PrincipalStatus::Revoked) => "revoked_subject_principal",
        ("issuer", PrincipalStatus::Active) => "active_issuer_principal",
        ("subject", PrincipalStatus::Active) => "active_subject_principal",
        _ => "principal_not_active",
    }
}

#[cfg(test)]
#[path = "../tests/unit/issuance_tests.rs"]
mod tests;
