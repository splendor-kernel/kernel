//! Behavior-free authority and capability contracts.
//!
//! These records define the typed AUTH-001 grammar used by the authority service
//! evidence slice. They are serializable contracts only: evaluation, narrowing,
//! expiry, revocation, and wildcard rejection live in `splendor-authority`.

use crate::{
    AgentId, ApprovalId, ArtifactId, AuthorityDecisionId, AuthorityObligationId,
    AuthorityRevocationId, CapabilityGrantId, DeviceId, FleetId, PrincipalId, RevocationStatus,
    RunId, StatePartitionId, TenantId, TraceEventId, WorkloadId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// Canonical schema identifier for typed authority operations.
pub const AUTHORITY_OPERATION_SCHEMA_VERSION: &str = "splendor.authority.operation.v1";
/// Canonical schema identifier for composable capability scopes.
pub const CAPABILITY_SCOPE_SCHEMA_VERSION: &str = "splendor.authority.scope.v1";
/// Canonical schema identifier for local capability grants.
pub const CAPABILITY_GRANT_SCHEMA_VERSION: &str = "splendor.authority.capability_grant.v1";
/// Canonical schema identifier for authority requests.
pub const CAPABILITY_REQUEST_SCHEMA_VERSION: &str = "splendor.authority.capability_request.v1";
/// Canonical schema identifier for authority decisions.
pub const AUTHORITY_DECISION_SCHEMA_VERSION: &str = "splendor.authority.decision.v1";
/// Canonical schema identifier for authority obligations.
pub const AUTHORITY_OBLIGATION_SCHEMA_VERSION: &str = "splendor.authority.obligation.v1";
/// Canonical schema identifier for authority obligation receipts.
pub const AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION: &str =
    "splendor.authority.obligation_receipt.v1";
/// Canonical schema identifier for authority revocation records.
pub const REVOCATION_RECORD_SCHEMA_VERSION: &str = "splendor.authority.revocation_record.v1";
/// Canonical schema identifier for behavior-free delegation grants.
pub const DELEGATION_GRANT_SCHEMA_VERSION: &str = "splendor.authority.delegation_grant.v1";
/// Canonical schema identifier for behavior-free delegation chains.
pub const DELEGATION_CHAIN_SCHEMA_VERSION: &str = "splendor.authority.delegation_chain.v1";
/// Canonical schema identifier for delegated child result contracts.
pub const DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION: &str =
    "splendor.authority.delegation_result_contract.v1";

/// Namespace that owns a typed operation verb.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityOperationNamespace {
    /// Agent runtime and delegation operations.
    Agent,
    /// Workload admission or execution-boundary operations.
    Workload,
    /// 0.1-compatible gateway action/adaptor operations.
    Gateway,
    /// Data access and data-use operations.
    Data,
    /// Artifact registry/read/write/publication operations.
    Artifact,
    /// State partition read/write operations.
    State,
    /// Driver invocation operations.
    Driver,
    /// Network egress operations.
    Network,
    /// Physical or edge device operations.
    Device,
    /// Change/governance activation operations.
    Change,
    /// Compatibility permission-token profile.
    Compatibility,
}

/// Resource class an authority operation is bound to.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityResourceKind {
    /// Agent identity or delegated agent work.
    Agent,
    /// Workload boundary.
    Workload,
    /// 0.1-compatible gateway action name.
    Action,
    /// 0.1-compatible adapter identifier.
    Adapter,
    /// 0.1-compatible permission token.
    Permission,
    /// Data resource or dataset-purpose boundary.
    Data,
    /// Artifact resource.
    Artifact,
    /// Explicit state partition.
    StatePartition,
    /// Versioned driver operation.
    DriverOperation,
    /// Network egress boundary.
    Network,
    /// Physical or edge device boundary.
    Device,
    /// Change/governance resource.
    Change,
}

/// Typed operation verb. Data-read, training-use, eval-use, and publication are
/// deliberately separate verbs rather than one merged permission.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityVerb {
    /// Invoke an action, agent, workload, or driver.
    Invoke,
    /// Use a compatibility adapter or permission token.
    Use,
    /// Read protected data, artifacts, state, or device summaries.
    Read,
    /// Write artifacts or state partitions.
    Write,
    /// Publish an artifact or data product.
    Publish,
    /// Use data for training.
    Train,
    /// Use data for evaluation.
    Evaluate,
    /// Admit a workload before execution.
    Admit,
    /// Delegate bounded work to another agent.
    Delegate,
    /// Perform network egress.
    Egress,
    /// Request a bounded high-level physical/device action.
    Actuate,
    /// Propose a governed change.
    Propose,
    /// Activate a governed change after gates.
    Activate,
}

/// Namespaced typed operation bound to a resource kind and schema version.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct AuthorityOperation {
    /// Operation schema version.
    pub schema_version: String,
    /// Namespace that owns the operation.
    pub namespace: AuthorityOperationNamespace,
    /// Resource kind this verb may target.
    pub resource_kind: AuthorityResourceKind,
    /// Typed operation verb.
    pub verb: AuthorityVerb,
    /// Optional concrete action/adapter/permission/driver token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional target resource schema version, such as a driver operation schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_schema_version: Option<String>,
}

/// Independent data-purpose axis. Read, training, evaluation, and publication
/// remain separate so one purpose cannot imply another.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataPurpose {
    /// Read or inspect source data.
    Read,
    /// Use data as training input.
    TrainingUse,
    /// Use data as evaluation or protected holdout input.
    EvaluationUse,
    /// Publish or export data-derived output.
    Publication,
}

/// Versioned driver operation coordinate inside a capability scope.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DriverOperationRef {
    /// Driver identifier.
    pub driver: String,
    /// Driver-declared operation identifier.
    pub operation: String,
    /// Driver operation schema version.
    pub schema_version: String,
}

/// Optional temporal scope for authority intersections.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityTimeScope {
    /// Earliest valid operation time.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub not_before: Option<OffsetDateTime>,
    /// Latest valid operation time.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

/// Budget and quota dimensions that can be intersected or narrowed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityBudgetScope {
    /// Maximum actions allowed per tick.
    #[serde(default)]
    pub max_actions_per_tick: Option<u32>,
    /// Maximum duration in milliseconds for a single operation.
    #[serde(default)]
    pub max_action_duration_ms: Option<u64>,
    /// Maximum filesystem read bytes.
    #[serde(default)]
    pub max_filesystem_read_bytes: Option<u64>,
    /// Maximum filesystem write bytes.
    #[serde(default)]
    pub max_filesystem_write_bytes: Option<u64>,
    /// Maximum network read bytes.
    #[serde(default)]
    pub max_network_read_bytes: Option<u64>,
    /// Maximum network write bytes.
    #[serde(default)]
    pub max_network_write_bytes: Option<u64>,
    /// Maximum HTTP requests per minute.
    #[serde(default)]
    pub max_http_requests_per_minute: Option<u32>,
}

/// Network authority dimensions. Concrete strings are validated by
/// `splendor-authority`; there is no string wildcard variant in this contract.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkScope {
    /// Allowed egress schemes, when network egress is in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_schemes: Option<Vec<String>>,
    /// Allowed egress hosts, when network egress is in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_hosts: Option<Vec<String>>,
}

/// Locality authority dimensions for data, workload, and node placement.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LocalityScope {
    /// Allowed regions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regions: Option<Vec<String>>,
    /// Allowed zones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zones: Option<Vec<String>>,
    /// Allowed data-locality labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_localities: Option<Vec<String>>,
}

/// Composable scope dimensions for authority grants and requests.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityScope {
    /// Scope schema version.
    pub schema_version: String,
    /// Tenant boundaries in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_ids: Option<Vec<TenantId>>,
    /// Fleet boundaries in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_ids: Option<Vec<FleetId>>,
    /// Agent identities in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_ids: Option<Vec<AgentId>>,
    /// Run identities in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_ids: Option<Vec<RunId>>,
    /// Workload identities in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_ids: Option<Vec<WorkloadId>>,
    /// Device identities in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_ids: Option<Vec<DeviceId>>,
    /// Data-use purposes in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_purposes: Option<Vec<DataPurpose>>,
    /// Artifact identities in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_ids: Option<Vec<ArtifactId>>,
    /// State partition identities in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_partition_ids: Option<Vec<StatePartitionId>>,
    /// Driver operations in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_operations: Option<Vec<DriverOperationRef>>,
    /// Audience bindings in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audiences: Option<Vec<String>>,
    /// Temporal scope used by deterministic intersection.
    #[serde(default)]
    pub time: AuthorityTimeScope,
    /// Budget dimensions used by deterministic intersection.
    #[serde(default)]
    pub budget: AuthorityBudgetScope,
    /// Network dimensions.
    #[serde(default)]
    pub network: NetworkScope,
    /// Locality dimensions.
    #[serde(default)]
    pub locality: LocalityScope,
}

impl Default for CapabilityScope {
    fn default() -> Self {
        Self {
            schema_version: CAPABILITY_SCOPE_SCHEMA_VERSION.to_string(),
            tenant_ids: None,
            fleet_ids: None,
            agent_ids: None,
            run_ids: None,
            workload_ids: None,
            device_ids: None,
            data_purposes: None,
            artifact_ids: None,
            state_partition_ids: None,
            driver_operations: None,
            audiences: None,
            time: AuthorityTimeScope::default(),
            budget: AuthorityBudgetScope::default(),
            network: NetworkScope::default(),
            locality: LocalityScope::default(),
        }
    }
}

/// Explicit proof that a grant has been signed or locally validated before
/// authority evaluation. This does not implement PKI or product IAM.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityGrantValidation {
    /// Validation mode for this bounded slice.
    pub validation_kind: CapabilityGrantValidationKind,
    /// Signing or validation algorithm label.
    pub algorithm: String,
    /// Optional key identifier for signed grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Digest over the canonical grant payload or validation evidence.
    pub digest: String,
    /// Detached signature for signed grants, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Capability grant validation mode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityGrantValidationKind {
    /// A detached signature is present and should be verified by a future issuer path.
    Signed,
    /// A local test/compatibility builder validated the grant shape before use.
    LocallyValidated,
}

/// Explicit obligation returned with a conditional authority decision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorityObligation {
    /// Obligation schema version.
    #[serde(default = "authority_obligation_schema_version")]
    pub schema_version: String,
    /// Distinct obligation identity.
    pub obligation_id: AuthorityObligationId,
    /// Obligation kind.
    pub kind: AuthorityObligationKind,
    /// Human-readable obligation detail for audit/debugging.
    pub description: String,
    /// Non-authorizing structured parameters.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, serde_json::Value>,
}

/// Obligation kind. Full approval/intervention workflow semantics remain future AUTH-004 work.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityObligationKind {
    /// Approval evidence is required before a later effect stage.
    ApprovalRequired,
    /// Stronger caller authentication or assurance, such as MFA, is required.
    MfaAssurance,
    /// Operation must run in a dedicated isolation boundary.
    DedicatedIsolation,
    /// Network egress must be denied for the obligated operation.
    NetworkDeny,
    /// A human review/adjudication step must complete.
    HumanReview,
    /// An independent evaluator must assess the result or proposal.
    IndependentEvaluator,
    /// A local safety verifier must approve the bounded action.
    LocalSafetyVerifier,
    /// A postcondition verifier must run after the operation.
    PostconditionCheck,
    /// A maximum blast-radius bound must be enforced.
    MaximumBlastRadius,
    /// Redaction must occur before output or evidence publication.
    RedactionRequired,
    /// Operation must stay in local-only execution.
    LocalOnly,
    /// Operation must use simulation/non-live execution.
    SimulationOnly,
    /// Additional evidence must be recorded.
    EvidenceRequired,
}

/// Behavior-free receipt proving an owning service completed one authority
/// obligation for one exact authority decision/request digest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorityObligationReceipt {
    /// Receipt schema version.
    pub schema_version: String,
    /// Obligation satisfied by this receipt.
    pub obligation_id: AuthorityObligationId,
    /// Obligation kind satisfied by this receipt.
    pub kind: AuthorityObligationKind,
    /// Subject principal bound to the original authority decision.
    pub subject: PrincipalId,
    /// Original authority decision this receipt satisfies.
    pub authority_decision_id: AuthorityDecisionId,
    /// Deterministic digest of the exact canonical authority request.
    pub canonical_request_digest: String,
    /// Digest of owning-service evidence for the satisfied obligation.
    pub evidence_digest: String,
    /// Optional opaque evidence reference. This is a reference, not authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    /// Receipt issuance time.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    /// Receipt expiry time.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Current revocation state supplied by the owning service/revocation path.
    pub revocation: RevocationStatus,
    /// Optional approval identity for approval-backed obligations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
    /// Optional trace event for approval/request evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_trace_event_id: Option<TraceEventId>,
}

/// Immutable capability grant contract for this local AUTH-001 slice.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// Grant schema version.
    pub schema_version: String,
    /// Distinct grant identity.
    pub grant_id: CapabilityGrantId,
    /// Principal that issued this grant.
    pub issuer: PrincipalId,
    /// Principal receiving this grant.
    pub subject: PrincipalId,
    /// Parent grants this grant narrows from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_grant_ids: Vec<CapabilityGrantId>,
    /// Operations authorized by this grant.
    pub operations: Vec<AuthorityOperation>,
    /// Scope dimensions authorized by this grant.
    pub scope: CapabilityScope,
    /// Earliest time the grant may be used.
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    /// Latest time the grant may be used.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Optional revocation lookup coordinate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_ref: Option<String>,
    /// Current revocation status supplied by the revocation path.
    pub revocation: RevocationStatus,
    /// Obligations carried forward with successful decisions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<AuthorityObligation>,
    /// Maximum remaining child-grant delegation depth.
    pub max_delegation_depth: u32,
    /// Signed or locally validated evidence for this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<CapabilityGrantValidation>,
    /// Non-authorizing metadata only.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// Role/profile requested for a delegated child agent or workload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationRoleProfile {
    /// Long-lived child agent with bounded delegated authority.
    Persistent,
    /// Short-lived child run for a bounded objective.
    Ephemeral,
    /// Event-triggered child agent/run.
    Trigger,
    /// Critic child that may evaluate or comment but must not receive actuation authority.
    Critic,
    /// Evaluator child that may assess results but must not receive actuation authority.
    Evaluator,
    /// Actuator-like child whose side effects remain gateway mediated.
    Actuator,
    /// Named specialist child with explicit scoped authority.
    Specialist,
}

/// Behavior-free contract describing the expected output from a delegated child.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationResultContract {
    /// Result-contract schema version.
    pub schema_version: String,
    /// Versioned schema the child must use for its terminal result/response.
    pub result_schema: String,
    /// Whether the parent expects a response message/result.
    pub requires_response: bool,
    /// Optional upper bound for inline result bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_result_bytes: Option<u64>,
}

/// Behavior-free delegation edge that embeds the narrowed child capability grant.
///
/// This record is a serializable contract only. Authority validation, parent-edge
/// checks, fan-out/depth enforcement, message-schema validation, expiry checks,
/// role restrictions, and child grant wrapping live in `splendor-authority`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationGrant {
    /// Delegation-grant schema version.
    pub schema_version: String,
    /// Parent capability grant that the child grant narrows from.
    pub parent_grant_id: CapabilityGrantId,
    /// Parent run that requested delegated work.
    pub parent_run_id: RunId,
    /// Parent agent that requested delegated work.
    pub parent_agent_id: AgentId,
    /// Child run created for the delegated objective.
    pub child_run_id: RunId,
    /// Child agent receiving the delegated objective.
    pub child_agent_id: AgentId,
    /// Scoped objective for the child.
    pub objective: String,
    /// Child role/profile.
    pub role_profile: DelegationRoleProfile,
    /// Message payload schemas the child may send for this delegation.
    pub allowed_message_schemas: Vec<String>,
    /// Agent recipients the child may message for this delegation.
    pub allowed_recipient_agent_ids: Vec<AgentId>,
    /// Expected terminal result contract.
    pub result_contract: DelegationResultContract,
    /// Delegation-level budget cap, mirrored into the child capability scope.
    pub budget: AuthorityBudgetScope,
    /// Earliest time the delegation edge may be used.
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    /// Latest time the delegation edge may be used.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Remaining child-grant delegation depth after this edge.
    pub remaining_delegation_depth: u32,
    /// Maximum children this parent edge may fan out to.
    pub max_fan_out: u32,
    /// Embedded behavior-free child capability grant.
    pub child_capability_grant: CapabilityGrant,
}

/// Behavior-free ordered delegation chain evidence container.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationChain {
    /// Delegation-chain schema version.
    pub schema_version: String,
    /// Root capability grant for the chain.
    pub root_grant_id: CapabilityGrantId,
    /// Ordered delegation edges from root toward the current child.
    pub grants: Vec<DelegationGrant>,
    /// Maximum allowed chain depth for the recorded chain evidence.
    pub max_depth: u32,
}

/// Authority evaluation request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityRequest {
    /// Request schema version.
    pub schema_version: String,
    /// Principal requesting the operation.
    pub subject: PrincipalId,
    /// Requested operation.
    pub operation: AuthorityOperation,
    /// Requested scope.
    pub scope: CapabilityScope,
    /// Request timestamp used for audit and replay interpretation.
    #[serde(with = "time::serde::rfc3339")]
    pub requested_at: OffsetDateTime,
    /// Non-authorizing request metadata only.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// Authority decision status.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityDecisionStatus {
    /// Request is allowed with no unsatisfied authority obligations.
    Allowed,
    /// Request is denied fail-closed.
    Denied,
    /// Request matched authority but cannot execute until obligations are satisfied.
    Conditional,
    /// Request cannot proceed without approval. Full workflow remains AUTH-004.
    NeedsApproval,
    /// Request cannot proceed without operator/runtime intervention.
    NeedsIntervention,
}

/// Deterministic authority decision record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorityDecision {
    /// Decision schema version.
    pub schema_version: String,
    /// Distinct decision identity.
    pub decision_id: AuthorityDecisionId,
    /// Original request being evaluated.
    pub request: CapabilityRequest,
    /// Decision status.
    pub status: AuthorityDecisionStatus,
    /// Stable reason codes for allow/deny/explain paths.
    pub reasons: Vec<String>,
    /// Grants that matched the request, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_grant_ids: Vec<CapabilityGrantId>,
    /// Obligations returned by the matching grant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<AuthorityObligation>,
    /// Decision timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub decided_at: OffsetDateTime,
}

fn authority_obligation_schema_version() -> String {
    AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string()
}

/// Revocation record for a capability grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// Revocation record schema version.
    pub schema_version: String,
    /// Distinct revocation record identity.
    pub revocation_id: AuthorityRevocationId,
    /// Grant affected by this revocation record.
    pub grant_id: CapabilityGrantId,
    /// Optional external revocation-list/introspection reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_ref: Option<String>,
    /// Current revocation status.
    pub status: RevocationStatus,
    /// When revocation was recorded, if known.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

#[cfg(test)]
#[path = "../tests/unit/authority_tests.rs"]
mod tests;
