//! External governance adapter contracts for scoped control-plane integration.
//!
//! Sprint 0.04-S6 keeps external product integrations at the boundary. These
//! schemas describe how a Harmony-compatible or generic control plane can bridge
//! signed work orders, approval decisions, and artifact references into Splendor
//! runtime primitives without receiving runtime enforcement authority or
//! bypassing the Action Gateway.

use crate::{
    schema_extensions, ApprovalDenial, ApprovalGrant, ApprovalId, ApprovalStatus,
    GovernanceExtensions, GovernanceIssuer, GovernanceScope, GovernanceTraceLink,
    GovernanceValidationError, RunId, StateNodeId, TraceEventId, WorkOrderEnvelope,
    WorkOrderValidationError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

/// Schema version for external governance adapter contracts introduced in 0.04-S6.
pub const EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION: &str =
    "splendor.external_governance_adapter.v1";

/// Schema version for trace-linked artifact references introduced in 0.04-S6.
pub const GOVERNED_ARTIFACT_REF_SCHEMA_VERSION: &str = "splendor.governed_artifact_ref.v1";

/// Product/control-plane reference that is non-authoritative inside Splendor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExternalGovernanceReference {
    /// External control-plane name such as `harmony` or `customer_console`.
    pub provider: String,
    /// Provider-local reference ID for the work order, approval, artifact, or signal.
    pub reference_id: String,
    /// Optional provider endpoint or route that produced the reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

impl ExternalGovernanceReference {
    /// Creates and validates a non-authoritative external reference.
    pub fn new(
        provider: impl Into<String>,
        reference_id: impl Into<String>,
        endpoint: Option<String>,
    ) -> Result<Self, ExternalGovernanceAdapterError> {
        let reference = Self {
            provider: provider.into(),
            reference_id: reference_id.into(),
            endpoint,
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Validates that the reference carries attribution but not authority.
    pub fn validate(&self) -> Result<(), ExternalGovernanceAdapterError> {
        validate_non_blank("external_ref.provider", &self.provider)?;
        validate_non_blank("external_ref.reference_id", &self.reference_id)?;
        if let Some(endpoint) = &self.endpoint {
            validate_endpoint("external_ref.endpoint", endpoint)?;
        }
        Ok(())
    }
}

/// Minimal provider endpoint map. Endpoint names may be renamed by a thin mapper;
/// the Splendor runtime contract stays the same.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExternalGovernanceEndpoints {
    /// Fetch or receive a signed, scoped work order.
    pub work_orders: String,
    /// Optional external path that submits action requests back to Splendor's gateway.
    pub action_gateway: String,
    /// Receive approval grants or denials.
    pub approvals: String,
    /// Export trace events or summaries to the external control plane.
    pub traces: String,
    /// Export state commit references to the external control plane.
    pub state_commits: String,
    /// Export trace-linked artifact references.
    pub artifact_refs: String,
}

impl ExternalGovernanceEndpoints {
    /// Harmony-compatible endpoint names from the Splendor development model.
    pub fn harmony_compatible() -> Self {
        Self {
            work_orders: "/splendor/work-orders/{work_order_id}".to_string(),
            action_gateway: "/splendor/action-gateway".to_string(),
            approvals: "/splendor/approvals".to_string(),
            traces: "/splendor/traces".to_string(),
            state_commits: "/splendor/state-commits".to_string(),
            artifact_refs: "/splendor/artifacts".to_string(),
        }
    }

    /// Validates endpoint strings without binding Splendor to one product's route names.
    pub fn validate(&self) -> Result<(), ExternalGovernanceAdapterError> {
        validate_endpoint("endpoints.work_orders", &self.work_orders)?;
        validate_endpoint("endpoints.action_gateway", &self.action_gateway)?;
        validate_endpoint("endpoints.approvals", &self.approvals)?;
        validate_endpoint("endpoints.traces", &self.traces)?;
        validate_endpoint("endpoints.state_commits", &self.state_commits)?;
        validate_endpoint("endpoints.artifact_refs", &self.artifact_refs)
    }
}

/// External governance adapter contract that remains provider-neutral.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExternalGovernanceAdapterContract {
    /// Schema version for compatibility and replay interpretation.
    #[serde(default = "default_external_governance_schema")]
    pub schema_version: String,
    /// External provider/control-plane label.
    pub provider: String,
    /// Provider endpoint map.
    pub endpoints: ExternalGovernanceEndpoints,
}

impl ExternalGovernanceAdapterContract {
    /// Creates a Harmony-compatible contract without making Harmony a kernel dependency.
    pub fn harmony_compatible() -> Result<Self, ExternalGovernanceAdapterError> {
        Self::new("harmony", ExternalGovernanceEndpoints::harmony_compatible())
    }

    /// Creates a provider-neutral contract with renamed endpoints.
    pub fn new(
        provider: impl Into<String>,
        endpoints: ExternalGovernanceEndpoints,
    ) -> Result<Self, ExternalGovernanceAdapterError> {
        let contract = Self {
            schema_version: default_external_governance_schema(),
            provider: provider.into(),
            endpoints,
        };
        contract.validate()?;
        Ok(contract)
    }

    /// Validates contract shape. It does not authorize actions or runs.
    pub fn validate(&self) -> Result<(), ExternalGovernanceAdapterError> {
        validate_external_schema(&self.schema_version)?;
        validate_non_blank("provider", &self.provider)?;
        self.endpoints.validate()
    }
}

/// Scoped signed work-order bridge accepted from an external control plane.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExternalGovernanceWorkOrderBridge {
    /// Schema version for compatibility and replay interpretation.
    #[serde(default = "default_external_governance_schema")]
    pub schema_version: String,
    /// External product reference for audit/debugging only.
    pub external_ref: ExternalGovernanceReference,
    /// Signed scoped Splendor work order. The runtime still performs full validation.
    pub work_order: WorkOrderEnvelope,
    /// Issuer/source attribution for trace and audit.
    pub issuer: GovernanceIssuer,
    /// Trace event that received or accepted the bridge.
    pub trace: GovernanceTraceLink,
    /// Non-authoritative external metadata. Credential-like fields are rejected.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub context: GovernanceExtensions,
}

impl ExternalGovernanceWorkOrderBridge {
    /// Creates a bridge after rejecting unsigned work orders and broad credentials.
    pub fn new(
        external_ref: ExternalGovernanceReference,
        work_order: WorkOrderEnvelope,
        issuer: GovernanceIssuer,
        trace: GovernanceTraceLink,
        context: GovernanceExtensions,
    ) -> Result<Self, ExternalGovernanceAdapterError> {
        let bridge = Self {
            schema_version: default_external_governance_schema(),
            external_ref,
            work_order,
            issuer,
            trace,
            context,
        };
        bridge.validate()?;
        Ok(bridge)
    }

    /// Validates bridge shape. Signature verification and revocation checks remain
    /// the receiver runtime's work-order validation responsibility.
    pub fn validate(&self) -> Result<(), ExternalGovernanceAdapterError> {
        validate_external_schema(&self.schema_version)?;
        self.external_ref.validate()?;
        self.issuer.validate()?;
        self.trace.validate()?;
        reject_authoritative_metadata(&self.context, "context")?;
        self.work_order.work_order.signing_payload_bytes()?;
        let signature = self
            .work_order
            .signature
            .as_ref()
            .ok_or(ExternalGovernanceAdapterError::UnsignedWorkOrder)?;
        validate_non_blank("work_order.signature.key_id", &signature.key_id)
            .map_err(|_| ExternalGovernanceAdapterError::UnsignedWorkOrder)?;
        validate_non_blank("work_order.signature.signature", &signature.signature)
            .map_err(|_| ExternalGovernanceAdapterError::UnsignedWorkOrder)?;
        Ok(())
    }
}

/// External approval decision that maps to Splendor approval governance objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalApprovalDecisionKind {
    /// External control plane granted approval for the explicit scope.
    Granted,
    /// External control plane denied approval for the explicit scope.
    Denied,
}

/// Approval decision received through an external governance adapter.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExternalApprovalDecision {
    /// Schema version for compatibility and replay interpretation.
    #[serde(default = "default_external_governance_schema")]
    pub schema_version: String,
    /// Non-authoritative product/control-plane reference.
    pub external_ref: ExternalGovernanceReference,
    /// Approval identity distinct from action/run/trace/message IDs.
    pub approval_id: ApprovalId,
    /// Explicit governance scope authorized or denied by the control plane.
    pub scope: GovernanceScope,
    /// Grant or denial decision.
    pub decision: ExternalApprovalDecisionKind,
    /// Decision creation timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Decision expiry. Explicit even for denial so replay can bound the signal.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Reason supplied by the external approver/control plane.
    pub reason: String,
    /// External issuer/source attribution.
    pub issuer: GovernanceIssuer,
    /// Causal trace linkage for the approval request or adapter intake.
    pub trace: GovernanceTraceLink,
    /// Non-authoritative metadata. Credential-like fields are rejected.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub extensions: GovernanceExtensions,
}

impl ExternalApprovalDecision {
    /// Validates and maps an external decision into a Splendor governance object.
    pub fn into_mapping(self) -> Result<ExternalApprovalMapping, ExternalGovernanceAdapterError> {
        self.validate()?;
        let mut extensions = self.extensions.clone();
        extensions.insert(
            "external_ref".to_string(),
            serde_json::to_value(&self.external_ref).map_err(|error| {
                ExternalGovernanceAdapterError::Serialization {
                    reason: error.to_string(),
                }
            })?,
        );
        match self.decision {
            ExternalApprovalDecisionKind::Granted => {
                let approval = ApprovalGrant::new(
                    self.approval_id,
                    self.scope,
                    self.created_at,
                    Some(self.expires_at),
                    self.reason,
                    self.issuer,
                    self.trace,
                    extensions,
                )?;
                Ok(ExternalApprovalMapping::Grant { approval })
            }
            ExternalApprovalDecisionKind::Denied => {
                let mut approval = ApprovalDenial::new(
                    self.approval_id,
                    self.scope,
                    self.created_at,
                    self.reason,
                    self.issuer,
                    self.trace,
                    extensions,
                )?;
                approval.expires_at = Some(self.expires_at);
                approval.validate()?;
                Ok(ExternalApprovalMapping::Denial { approval })
            }
        }
    }

    /// Validates external decision shape before any grant/denial is trusted.
    pub fn validate(&self) -> Result<(), ExternalGovernanceAdapterError> {
        validate_external_schema(&self.schema_version)?;
        self.external_ref.validate()?;
        self.scope.validate()?;
        validate_non_blank("reason", &self.reason)?;
        if self.expires_at <= self.created_at {
            return Err(ExternalGovernanceAdapterError::InvalidExpiry);
        }
        if self.decision == ExternalApprovalDecisionKind::Granted
            && !matches!(self.scope, GovernanceScope::Action { .. })
        {
            return Err(ExternalGovernanceAdapterError::BroadApprovalGrantScope {
                scope: governance_scope_label(&self.scope),
            });
        }
        self.issuer.validate()?;
        self.trace.validate()?;
        validate_scope_trace_run_match(&self.scope, &self.trace)?;
        reject_authoritative_metadata(&self.extensions, "extensions")
    }
}

/// Fail-closed record for an external adapter failure.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExternalGovernanceAdapterFailure {
    /// Schema version for compatibility and replay interpretation.
    #[serde(default = "default_external_governance_schema")]
    pub schema_version: String,
    /// Non-authoritative product/control-plane reference.
    pub external_ref: ExternalGovernanceReference,
    /// Scope that the failed decision would have affected.
    pub scope: GovernanceScope,
    /// Failure timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// Sanitized failure reason.
    pub reason: String,
    /// Adapter/service issuer attribution.
    pub issuer: GovernanceIssuer,
    /// Causal trace linkage for the failed adapter call or intake.
    pub trace: GovernanceTraceLink,
}

impl ExternalGovernanceAdapterFailure {
    /// Creates a validated fail-closed adapter failure.
    pub fn new(
        external_ref: ExternalGovernanceReference,
        scope: GovernanceScope,
        occurred_at: OffsetDateTime,
        reason: impl Into<String>,
        issuer: GovernanceIssuer,
        trace: GovernanceTraceLink,
    ) -> Result<Self, ExternalGovernanceAdapterError> {
        let failure = Self {
            schema_version: default_external_governance_schema(),
            external_ref,
            scope,
            occurred_at,
            reason: reason.into(),
            issuer,
            trace,
        };
        failure.validate()?;
        Ok(failure)
    }

    /// Converts failure into a non-authorizing mapping.
    pub fn into_mapping(self) -> ExternalApprovalMapping {
        ExternalApprovalMapping::AdapterFailure { failure: self }
    }

    /// Validates failure shape.
    pub fn validate(&self) -> Result<(), ExternalGovernanceAdapterError> {
        validate_external_schema(&self.schema_version)?;
        self.external_ref.validate()?;
        self.scope.validate()?;
        validate_non_blank("reason", &self.reason)?;
        self.issuer.validate()?;
        self.trace.validate()?;
        validate_scope_trace_run_match(&self.scope, &self.trace)?;
        Ok(())
    }
}

/// Result of mapping an external approval adapter response into Splendor objects.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mapping", rename_all = "snake_case")]
pub enum ExternalApprovalMapping {
    /// External grant mapped to a first-class `ApprovalGrant` object.
    Grant { approval: ApprovalGrant },
    /// External denial mapped to a first-class `ApprovalDenial` object.
    Denial { approval: ApprovalDenial },
    /// Adapter failure. This never grants approval and never executes an action.
    AdapterFailure {
        failure: ExternalGovernanceAdapterFailure,
    },
}

impl ExternalApprovalMapping {
    /// Returns true only for explicit approval grants. The Action Gateway must
    /// still verify the mapped object before any adapter can execute.
    pub fn contains_approval_grant(&self) -> bool {
        matches!(self, Self::Grant { .. })
    }
}

/// Inclusive trace range for an externally visible artifact reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExternalTraceRange {
    /// First trace event included in the artifact provenance range.
    pub start_trace_event_id: TraceEventId,
    /// Last trace event included in the artifact provenance range.
    pub end_trace_event_id: TraceEventId,
}

impl ExternalTraceRange {
    /// Creates and validates a trace range.
    pub fn new(
        start_trace_event_id: TraceEventId,
        end_trace_event_id: TraceEventId,
    ) -> Result<Self, ExternalGovernanceAdapterError> {
        let range = Self {
            start_trace_event_id,
            end_trace_event_id,
        };
        range.validate()?;
        Ok(range)
    }

    /// Validates non-nil trace identities.
    pub fn validate(&self) -> Result<(), ExternalGovernanceAdapterError> {
        validate_trace_id(
            "trace_range.start_trace_event_id",
            &self.start_trace_event_id,
        )?;
        validate_trace_id("trace_range.end_trace_event_id", &self.end_trace_event_id)
    }
}

/// Trace-linked artifact reference exported to an external control plane.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GovernedArtifactRef {
    /// Schema version for compatibility and replay interpretation.
    #[serde(default = "default_governed_artifact_schema")]
    pub schema_version: String,
    /// Artifact identity in the external or local artifact store namespace.
    pub artifact_id: String,
    /// Optional artifact version label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Source data or artifact references used to build this artifact.
    pub source_refs: Vec<String>,
    /// Splendor run that produced or published the artifact reference.
    pub run_id: RunId,
    /// State graph node linked to the artifact-producing transition.
    pub state_node_id: StateNodeId,
    /// Trace range proving the artifact lifecycle.
    pub trace_range: ExternalTraceRange,
    /// Current approval lifecycle state relevant to publication/export.
    pub approval_state: ApprovalStatus,
    /// Optional approval object associated with the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
    /// Optional product/control-plane reference for the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<ExternalGovernanceReference>,
    /// Explicit export targets, if any. Empty means not exported.
    #[serde(default)]
    pub export_targets: Vec<String>,
}

impl GovernedArtifactRef {
    /// Validates a trace-linked artifact reference.
    pub fn validate(&self) -> Result<(), ExternalGovernanceAdapterError> {
        if self.schema_version != GOVERNED_ARTIFACT_REF_SCHEMA_VERSION {
            return Err(ExternalGovernanceAdapterError::UnsupportedSchema {
                schema: self.schema_version.clone(),
            });
        }
        validate_non_blank("artifact_id", &self.artifact_id)?;
        if let Some(version) = &self.version {
            validate_non_blank("version", version)?;
        }
        validate_non_empty_list("source_refs", &self.source_refs)?;
        self.trace_range.validate()?;
        if matches!(
            self.approval_state,
            ApprovalStatus::Granted
                | ApprovalStatus::Denied
                | ApprovalStatus::Expired
                | ApprovalStatus::Revoked
        ) && self.approval_id.is_none()
        {
            return Err(ExternalGovernanceAdapterError::Missing {
                field: "approval_id",
            });
        }
        if let Some(external_ref) = &self.external_ref {
            external_ref.validate()?;
        }
        validate_no_blank_items("export_targets", &self.export_targets)?;
        Ok(())
    }
}

/// Fail-closed validation errors for external governance adapter contracts.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExternalGovernanceAdapterError {
    /// Schema version is not supported by this compatibility line.
    #[error("unsupported external governance schema version: {schema}")]
    UnsupportedSchema { schema: String },
    /// A required field was missing or blank.
    #[error("{field} is required")]
    Missing { field: &'static str },
    /// Endpoint fields must be local route paths.
    #[error("invalid endpoint {field}: {value}")]
    InvalidEndpoint { field: &'static str, value: String },
    /// External metadata attempted to carry broad credentials or authority.
    #[error("external governance metadata cannot carry credentials or authority: {field}")]
    BroadCredentialSupplied { field: String },
    /// Work-order bridge omitted detached signature metadata.
    #[error("external governance work-order bridge requires a signed work order")]
    UnsignedWorkOrder,
    /// Expiry must be after creation.
    #[error("expires_at must be after created_at")]
    InvalidExpiry,
    /// External approval grants must not use broad governance scopes.
    #[error("external approval grants require action scope, found {scope}")]
    BroadApprovalGrantScope { scope: &'static str },
    /// Trace event identity was nil.
    #[error("{field} must not be nil")]
    InvalidTraceId { field: &'static str },
    /// JSON serialization failed for a trace/replay-safe payload.
    #[error("external governance serialization failed: {reason}")]
    Serialization { reason: String },
    /// Governance object validation failed.
    #[error(transparent)]
    Governance(#[from] GovernanceValidationError),
    /// Work-order shape validation failed.
    #[error(transparent)]
    WorkOrder(#[from] WorkOrderValidationError),
}

fn default_external_governance_schema() -> String {
    EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION.to_string()
}

fn default_governed_artifact_schema() -> String {
    GOVERNED_ARTIFACT_REF_SCHEMA_VERSION.to_string()
}

fn validate_external_schema(schema_version: &str) -> Result<(), ExternalGovernanceAdapterError> {
    if schema_version == EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(ExternalGovernanceAdapterError::UnsupportedSchema {
            schema: schema_version.to_string(),
        })
    }
}

fn validate_non_blank(
    field: &'static str,
    value: &str,
) -> Result<(), ExternalGovernanceAdapterError> {
    if value.trim().is_empty() || value.trim() != value {
        Err(ExternalGovernanceAdapterError::Missing { field })
    } else {
        Ok(())
    }
}

fn validate_endpoint(
    field: &'static str,
    value: &str,
) -> Result<(), ExternalGovernanceAdapterError> {
    validate_non_blank(field, value)?;
    let invalid_route = !value.starts_with('/')
        || value.starts_with("//")
        || value.contains("//")
        || value.contains('\\')
        || value.contains("://")
        || value.split('/').any(|segment| segment == "..")
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace());
    if invalid_route {
        return Err(ExternalGovernanceAdapterError::InvalidEndpoint {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_trace_id(
    field: &'static str,
    value: &TraceEventId,
) -> Result<(), ExternalGovernanceAdapterError> {
    if value.is_nil() {
        Err(ExternalGovernanceAdapterError::InvalidTraceId { field })
    } else {
        Ok(())
    }
}

fn governance_scope_label(scope: &GovernanceScope) -> &'static str {
    match scope {
        GovernanceScope::Global => "global",
        GovernanceScope::Fleet { .. } => "fleet",
        GovernanceScope::Node { .. } => "node",
        GovernanceScope::Instance { .. } => "instance",
        GovernanceScope::Tenant { .. } => "tenant",
        GovernanceScope::Agent { .. } => "agent",
        GovernanceScope::Run { .. } => "run",
        GovernanceScope::Action { .. } => "action",
        GovernanceScope::Adapter { .. } => "adapter",
    }
}

fn validate_scope_trace_run_match(
    scope: &GovernanceScope,
    trace: &GovernanceTraceLink,
) -> Result<(), ExternalGovernanceAdapterError> {
    if let (Some(scope_run_id), Some(trace_run_id)) = (scope.run_id(), trace.run_id.as_ref()) {
        if scope_run_id != trace_run_id {
            return Err(ExternalGovernanceAdapterError::Governance(
                GovernanceValidationError::RunScopeMismatch {
                    expected: scope_run_id.to_string(),
                    actual: trace_run_id.to_string(),
                },
            ));
        }
    }
    Ok(())
}

fn validate_non_empty_list(
    field: &'static str,
    values: &[String],
) -> Result<(), ExternalGovernanceAdapterError> {
    if values.is_empty() {
        return Err(ExternalGovernanceAdapterError::Missing { field });
    }
    validate_no_blank_items(field, values)
}

fn validate_no_blank_items(
    field: &'static str,
    values: &[String],
) -> Result<(), ExternalGovernanceAdapterError> {
    for value in values {
        if value.trim().is_empty() || value.trim() != value {
            return Err(ExternalGovernanceAdapterError::Missing { field });
        }
    }
    Ok(())
}

fn reject_authoritative_metadata(
    values: &GovernanceExtensions,
    field: &str,
) -> Result<(), ExternalGovernanceAdapterError> {
    schema_extensions::validate_extension_map(values, field).map_err(|error| {
        ExternalGovernanceAdapterError::BroadCredentialSupplied { field: error.path }
    })
}

#[cfg(test)]
#[path = "../tests/unit/external_governance_tests.rs"]
mod tests;
