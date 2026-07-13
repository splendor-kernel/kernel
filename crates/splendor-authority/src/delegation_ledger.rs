//! Authority-owned local delegation chain and reservation ledger.
//!
//! The ledger is the single mutation owner for local delegation edges, fan-out,
//! aggregate child budgets, and reservation lifecycle. Kernel routing composes
//! this owner; caller-provided counters and message payloads are never authority.

use crate::{
    ensure_child_grant_narrows, issue_delegation_child_grant, DelegationChildGrant,
    DelegationChildGrantRequest, DelegationGrantError, DelegationValidationContext,
    ValidatedCapabilityGrant,
};
use splendor_types::{
    AgentId, AuthorityBudgetScope, AuthorityDecisionStatus, CapabilityGrant, CapabilityGrantId,
    CapabilityRequest, DelegationChain, DelegationCleanupObligations, DelegationLedgerEvidence,
    DelegationReservationStatus, PrincipalId, QuotaUsage, RunId, TenantId,
    CAPABILITY_REQUEST_SCHEMA_VERSION, DELEGATION_CHAIN_SCHEMA_VERSION,
};
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use thiserror::Error;
use time::OffsetDateTime;

/// Immutable local authority-owned fan-out cap for every root/child edge.
pub const LOCAL_DELEGATION_FAN_OUT_LIMIT: u32 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EdgeStatus {
    Reserved,
    Active,
    ConsumedAfterRoutingFailure,
    Cleaned,
    Revoked,
}

impl EdgeStatus {
    fn accounts(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Active | Self::ConsumedAfterRoutingFailure
        )
    }
}

#[derive(Clone)]
struct LedgerNode {
    grant: ValidatedCapabilityGrant,
    chain: DelegationChain,
    parent_grant_id: Option<CapabilityGrantId>,
    parent_fan_out_limit: u32,
    budget: AuthorityBudgetScope,
    status: EdgeStatus,
    runtime_binding: Option<RuntimeBinding>,
    handle_token: CapabilityGrantId,
    own_tick_usage: HashMap<u64, QuotaUsage>,
    subtree_tick_usage: HashMap<u64, QuotaUsage>,
    own_http_usage: HashMap<i64, u32>,
    subtree_http_usage: HashMap<i64, u32>,
    in_flight_effects: u64,
    allowed_child_bindings: Vec<(AgentId, RunId)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeBinding {
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
}

#[derive(Default)]
struct LedgerState {
    nodes: HashMap<CapabilityGrantId, LedgerNode>,
}

#[derive(Default)]
struct LedgerShared {
    state: Mutex<LedgerState>,
    quiescent: Condvar,
}

/// Opaque atomic reservation returned before the kernel attempts routing.
#[derive(Clone, Debug)]
pub struct DelegationReservation {
    issued: DelegationChildGrant,
    evidence: DelegationLedgerEvidence,
}

impl DelegationReservation {
    /// Authority-issued immutable child edge and validated grant.
    pub fn delegation_grant(&self) -> &splendor_types::DelegationGrant {
        self.issued.delegation_grant()
    }

    /// Replay-safe evidence for the reserved state.
    pub fn evidence(&self) -> &DelegationLedgerEvidence {
        &self.evidence
    }

    fn child_grant_id(&self) -> &CapabilityGrantId {
        &self.issued.child_grant().grant().grant_id
    }
}

/// Opaque authority-owned identity used by a run to create a narrower child.
///
/// The handle cannot be constructed from a grant ID, message, run ID, or raw
/// capability payload. Every use is re-bound to the owning ledger and current
/// node lifecycle before delegation is reserved.
#[derive(Clone)]
pub struct DelegationCallerHandle {
    state: Arc<LedgerShared>,
    grant_id: CapabilityGrantId,
    token: CapabilityGrantId,
}

impl std::fmt::Debug for DelegationCallerHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegationCallerHandle")
            .field("grant_id", &self.grant_id)
            .field("authority", &"<opaque>")
            .finish()
    }
}

impl DelegationCallerHandle {
    /// Non-authorizing grant reference for action/message correlation.
    pub fn grant_id(&self) -> &CapabilityGrantId {
        &self.grant_id
    }

    /// Returns an opaque live runtime authority view for this exact run binding.
    pub fn runtime_authority(&self) -> DelegatedRuntimeAuthorityHandle {
        DelegatedRuntimeAuthorityHandle {
            state: Arc::clone(&self.state),
            grant_id: self.grant_id.clone(),
            token: self.token.clone(),
        }
    }

    /// Compares opaque authority ownership without exposing validation material.
    pub fn is_same_authority(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
            && self.grant_id == other.grant_id
            && self.token == other.token
    }

    /// Trusted admission compatibility check. The supplied wrapper never
    /// becomes live authority; it must equal the ledger-owned binding exactly.
    pub fn matches_validated_grant(&self, grant: &ValidatedCapabilityGrant) -> bool {
        self.state.state.lock().ok().is_some_and(|state| {
            state
                .nodes
                .get(&self.grant_id)
                .is_some_and(|node| node.handle_token == self.token && node.grant == *grant)
        })
    }

    /// Returns bounded defaults for constructing a narrower child request. This
    /// is configuration only; every value is revalidated from live ledger state.
    pub fn child_request_defaults(
        &self,
    ) -> Result<DelegationChildRequestDefaults, DelegationLedgerError> {
        let state = self
            .state
            .state
            .lock()
            .map_err(|_| DelegationLedgerError::StorageUnavailable)?;
        let node = state
            .nodes
            .get(&self.grant_id)
            .ok_or(DelegationLedgerError::ParentGrantMissing)?;
        if node.handle_token != self.token || node.status != EdgeStatus::Active {
            return Err(DelegationLedgerError::ParentGrantMismatch);
        }
        Ok(DelegationChildRequestDefaults {
            budget: node.budget,
            not_before: node.grant.grant().not_before,
            expires_at: node.grant.grant().expires_at,
            max_delegation_depth: node.grant.grant().max_delegation_depth.saturating_sub(1),
        })
    }
}

/// Non-authorizing defaults projected from a live parent handle.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DelegationChildRequestDefaults {
    pub budget: AuthorityBudgetScope,
    pub not_before: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub max_delegation_depth: u32,
}

/// Opaque authority-owned live child runtime authority.
#[derive(Clone)]
pub struct DelegatedRuntimeAuthorityHandle {
    state: Arc<LedgerShared>,
    grant_id: CapabilityGrantId,
    token: CapabilityGrantId,
}

impl std::fmt::Debug for DelegatedRuntimeAuthorityHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedRuntimeAuthorityHandle")
            .field("grant_id", &self.grant_id)
            .field("authority", &"<opaque>")
            .finish()
    }
}

impl DelegatedRuntimeAuthorityHandle {
    /// Non-authorizing grant reference required on delegated action proposals.
    pub fn grant_id(&self) -> &CapabilityGrantId {
        &self.grant_id
    }

    /// Atomically performs final live authorization and reserves cumulative
    /// authority-owned usage before the gateway can be entered.
    pub fn authorize_action(
        &self,
        request: DelegatedActionAuthorizationRequest,
    ) -> Result<DelegatedActionPermit, DelegatedActionAuthorizationError> {
        let mut state = self
            .state
            .state
            .lock()
            .map_err(|_| DelegatedActionAuthorizationError::AuthorityUnavailable)?;
        authorize_live_action(&mut state, &self.grant_id, &self.token, request)?;
        let lineage = grant_lineage(&state, &self.grant_id)?;
        for id in &lineage {
            let node = state
                .nodes
                .get_mut(id)
                .ok_or(DelegatedActionAuthorizationError::InvalidHandle)?;
            node.in_flight_effects = node.in_flight_effects.saturating_add(1);
        }
        Ok(DelegatedActionPermit {
            state: Arc::clone(&self.state),
            grant_id: self.grant_id.clone(),
            lineage,
        })
    }
}

/// Exact final delegated-action authorization request.
#[derive(Clone, Debug)]
pub struct DelegatedActionAuthorizationRequest {
    pub supplied_grant_id: Option<CapabilityGrantId>,
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub run_id: RunId,
    pub tick_id: u64,
    pub operations: Vec<splendor_types::AuthorityOperation>,
    pub usage_estimate: QuotaUsage,
    pub now: OffsetDateTime,
}

/// Linearization permit proving final live delegated authorization occurred.
pub struct DelegatedActionPermit {
    state: Arc<LedgerShared>,
    grant_id: CapabilityGrantId,
    lineage: Vec<CapabilityGrantId>,
}

impl std::fmt::Debug for DelegatedActionPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedActionPermit")
            .field("grant_id", &self.grant_id)
            .field("authority", &"<opaque>")
            .finish()
    }
}

impl DelegatedActionPermit {
    pub fn grant_id(&self) -> &CapabilityGrantId {
        &self.grant_id
    }
}

impl Drop for DelegatedActionPermit {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.state.lock() else {
            return;
        };
        for id in &self.lineage {
            if let Some(node) = state.nodes.get_mut(id) {
                node.in_flight_effects = node.in_flight_effects.saturating_sub(1);
            }
        }
        self.state.quiescent.notify_all();
    }
}

/// Stable fail-closed delegated-action authorization failures.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum DelegatedActionAuthorizationError {
    #[error("delegated authority is unavailable")]
    AuthorityUnavailable,
    #[error("delegated authority handle is invalid")]
    InvalidHandle,
    #[error("delegated capability grant reference does not match")]
    GrantReferenceMismatch,
    #[error("delegated runtime identity does not match")]
    RuntimeBindingMismatch,
    #[error("delegated authority is no longer active")]
    AuthorityInactive,
    #[error("delegated authority is not yet valid")]
    NotYetValid,
    #[error("delegated authority is expired")]
    Expired,
    #[error("delegated authority is revoked")]
    Revoked,
    #[error("delegated operation is denied: {reason}")]
    OperationDenied { reason: String },
    #[error("delegated cumulative budget is exceeded: {dimension}")]
    BudgetExceeded { dimension: &'static str },
    #[error("delegated retained executable budget is exceeded: {dimension}")]
    RetainedBudgetExceeded { dimension: &'static str },
}

impl DelegatedActionAuthorizationError {
    pub fn reason_code(&self) -> String {
        match self {
            Self::AuthorityUnavailable => "delegated_authority_unavailable".to_string(),
            Self::InvalidHandle => "delegated_authority_handle_invalid".to_string(),
            Self::GrantReferenceMismatch => "delegated_capability_grant_ref_mismatch".to_string(),
            Self::RuntimeBindingMismatch => "delegated_runtime_binding_mismatch".to_string(),
            Self::AuthorityInactive => "delegated_authority_inactive".to_string(),
            Self::NotYetValid => "delegated_authority_not_yet_valid".to_string(),
            Self::Expired => "delegated_authority_expired".to_string(),
            Self::Revoked => "delegated_authority_revoked".to_string(),
            Self::OperationDenied { reason } => reason.clone(),
            Self::BudgetExceeded { dimension } => {
                format!("delegated_cumulative_budget_exceeded_{dimension}")
            }
            Self::RetainedBudgetExceeded { dimension } => {
                format!("delegated_retained_budget_exceeded_{dimension}")
            }
        }
    }
}

/// Successful committed child authority, containing handles rather than a
/// requester-visible validated grant clone.
#[derive(Debug)]
pub struct CommittedDelegation {
    pub evidence: DelegationLedgerEvidence,
    pub caller: DelegationCallerHandle,
    pub runtime_authority: DelegatedRuntimeAuthorityHandle,
}

/// Deterministic chain validation failure naming the first failing edge.
#[derive(Clone, Debug, Error, PartialEq)]
#[error("delegation chain edge {edge_index} is invalid: {reason}")]
pub struct DelegationChainValidationError {
    /// Zero-based edge index from root to leaf.
    pub edge_index: usize,
    /// Stable failure reason for that exact edge.
    pub reason: String,
}

/// Fail-closed authority ledger errors.
#[derive(Debug, Error)]
pub enum DelegationLedgerError {
    /// Ledger storage is unavailable.
    #[error("delegation authority ledger is unavailable")]
    StorageUnavailable,
    /// A root grant ID was already registered with different immutable content.
    #[error("delegation root grant conflicts with its immutable ledger binding")]
    RootGrantConflict,
    /// Parent grant is not registered in this ledger.
    #[error("delegation parent grant is not registered")]
    ParentGrantMissing,
    /// Supplied parent differs from the immutable ledger grant.
    #[error("delegation parent grant differs from its immutable ledger binding")]
    ParentGrantMismatch,
    /// Child ID is already present in the ledger.
    #[error("delegation child grant ID already exists in the authority ledger")]
    ChildGrantCollision,
    /// Authority issuance denied the requested child edge.
    #[error(transparent)]
    Issuance(#[from] DelegationGrantError),
    /// Existing or proposed complete chain is invalid.
    #[error(transparent)]
    Chain(#[from] DelegationChainValidationError),
    /// Aggregate sibling budget exceeds the parent subtree allocation.
    #[error("delegation aggregate budget exceeds parent dimension {dimension}")]
    AggregateBudgetExceeded { dimension: &'static str },
    /// Child role attempted to broaden the parent edge role.
    #[error("delegation child role broadens the parent role")]
    RoleEscalation,
    /// Reservation is absent or no longer in the expected lifecycle state.
    #[error("delegation reservation is not active")]
    ReservationNotActive,
    /// Parent cleanup was attempted while descendant allocations remain active.
    #[error("delegation cleanup requires descendants to finish first")]
    ActiveDescendants,
    /// Requested child agent/run pair was not an exact authority-owned binding.
    #[error("delegation child agent/run binding is not allowed")]
    ChildRuntimeBindingDenied,
}

impl DelegationLedgerError {
    /// Stable reason suitable for trace/replay evidence.
    pub fn reason_code(&self) -> String {
        match self {
            Self::StorageUnavailable => "delegation_ledger_unavailable".to_string(),
            Self::RootGrantConflict => "delegation_root_grant_conflict".to_string(),
            Self::ParentGrantMissing => "delegation_parent_grant_missing".to_string(),
            Self::ParentGrantMismatch => "delegation_parent_grant_mismatch".to_string(),
            Self::ChildGrantCollision => "child_capability_grant_id_collision".to_string(),
            Self::Issuance(error) => error.reason_code().to_string(),
            Self::Chain(error) => format!(
                "delegation_chain_edge_{}_{}",
                error.edge_index, error.reason
            ),
            Self::AggregateBudgetExceeded { dimension } => {
                format!("aggregate_budget_exceeded_{dimension}")
            }
            Self::RoleEscalation => "delegation_role_escalation".to_string(),
            Self::ReservationNotActive => "delegation_reservation_not_active".to_string(),
            Self::ActiveDescendants => "delegation_active_descendants".to_string(),
            Self::ChildRuntimeBindingDenied => {
                "delegation_child_runtime_binding_denied".to_string()
            }
        }
    }
}

/// In-memory authority owner for local delegation validity and accounting.
pub struct InMemoryDelegationAuthorityLedger {
    state: Arc<LedgerShared>,
}

impl Default for InMemoryDelegationAuthorityLedger {
    fn default() -> Self {
        Self {
            state: Arc::new(LedgerShared::default()),
        }
    }
}

impl std::fmt::Debug for InMemoryDelegationAuthorityLedger {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InMemoryDelegationAuthorityLedger")
            .field("state", &"<redacted authority ledger>")
            .finish()
    }
}

impl InMemoryDelegationAuthorityLedger {
    /// Creates an empty local authority ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one immutable validated root grant. Exact retries are idempotent.
    #[cfg(test)]
    pub fn register_root(
        &self,
        root: &ValidatedCapabilityGrant,
    ) -> Result<DelegationCallerHandle, DelegationLedgerError> {
        self.register_root_with_binding(root, None, exact_scope_bindings(root.grant())?)
    }

    /// Registers one root with the exact runtime binding used for nested calls
    /// and final action authorization.
    pub fn register_root_runtime(
        &self,
        root: &ValidatedCapabilityGrant,
        tenant_id: TenantId,
        agent_id: AgentId,
        run_id: RunId,
    ) -> Result<DelegationCallerHandle, DelegationLedgerError> {
        let bindings = exact_scope_bindings(root.grant())?;
        self.register_root_with_binding(
            root,
            Some(RuntimeBinding {
                tenant_id,
                agent_id,
                run_id,
            }),
            bindings,
        )
    }

    /// Registers a root with explicit exact child agent/run bindings for a
    /// multi-valued compatibility scope. The two scope lists are never treated
    /// as a Cartesian authorization surface.
    pub fn register_root_runtime_with_child_bindings(
        &self,
        root: &ValidatedCapabilityGrant,
        tenant_id: TenantId,
        agent_id: AgentId,
        run_id: RunId,
        child_bindings: Vec<(AgentId, RunId)>,
    ) -> Result<DelegationCallerHandle, DelegationLedgerError> {
        validate_explicit_child_bindings(root.grant(), &child_bindings)?;
        self.register_root_with_binding(
            root,
            Some(RuntimeBinding {
                tenant_id,
                agent_id,
                run_id,
            }),
            child_bindings,
        )
    }

    fn register_root_with_binding(
        &self,
        root: &ValidatedCapabilityGrant,
        runtime_binding: Option<RuntimeBinding>,
        allowed_child_bindings: Vec<(AgentId, RunId)>,
    ) -> Result<DelegationCallerHandle, DelegationLedgerError> {
        let mut state = self.lock()?;
        let id = root.grant().grant_id.clone();
        if let Some(existing) = state.nodes.get(&id) {
            return if existing.parent_grant_id.is_none()
                && existing.grant == *root
                && existing.runtime_binding == runtime_binding
                && existing.allowed_child_bindings == allowed_child_bindings
            {
                Ok(handle_for_node(&self.state, &id, existing))
            } else {
                Err(DelegationLedgerError::RootGrantConflict)
            };
        }
        let handle_token = CapabilityGrantId::new();
        state.nodes.insert(
            id.clone(),
            LedgerNode {
                grant: root.clone(),
                chain: DelegationChain {
                    schema_version: DELEGATION_CHAIN_SCHEMA_VERSION.to_string(),
                    root_grant_id: id.clone(),
                    grants: Vec::new(),
                    max_depth: root.grant().max_delegation_depth,
                },
                parent_grant_id: None,
                parent_fan_out_limit: LOCAL_DELEGATION_FAN_OUT_LIMIT,
                budget: root.grant().scope.budget,
                status: EdgeStatus::Active,
                runtime_binding,
                handle_token: handle_token.clone(),
                own_tick_usage: HashMap::new(),
                subtree_tick_usage: HashMap::new(),
                own_http_usage: HashMap::new(),
                subtree_http_usage: HashMap::new(),
                in_flight_effects: 0,
                allowed_child_bindings,
            },
        );
        Ok(DelegationCallerHandle {
            state: Arc::clone(&self.state),
            grant_id: id,
            token: handle_token,
        })
    }

    /// Atomically validates, issues, chain-checks, and reserves one child edge.
    pub fn reserve_child(
        &self,
        parent: &DelegationCallerHandle,
        mut request: DelegationChildGrantRequest,
        now: OffsetDateTime,
        audience: String,
        expected_child_subject: PrincipalId,
    ) -> Result<DelegationReservation, DelegationLedgerError> {
        let mut state = self.lock()?;
        if !Arc::ptr_eq(&self.state, &parent.state) {
            return Err(DelegationLedgerError::ParentGrantMismatch);
        }
        let parent_id = parent.grant_id.clone();
        let parent_node = state
            .nodes
            .get(&parent_id)
            .cloned()
            .ok_or(DelegationLedgerError::ParentGrantMissing)?;
        if parent_node.handle_token != parent.token || parent_node.status != EdgeStatus::Active {
            return Err(DelegationLedgerError::ParentGrantMismatch);
        }
        validate_delegation_chain(parent_node.chain_root(&state)?, &parent_node.chain)?;
        if state.nodes.contains_key(&request.child_grant_id) {
            return Err(DelegationLedgerError::ChildGrantCollision);
        }
        if let Some(parent_edge) = parent_node.chain.grants.last() {
            if !role_narrows(parent_edge.role_profile, request.role_profile) {
                return Err(DelegationLedgerError::RoleEscalation);
            }
        }

        let parent_binding = parent_runtime_binding(&parent_node, &request)?;
        if !parent_node
            .allowed_child_bindings
            .contains(&(request.child_agent_id.clone(), request.child_run_id.clone()))
        {
            return Err(DelegationLedgerError::ChildRuntimeBindingDenied);
        }
        request.parent_grant_id = Some(parent_id.clone());
        request.issuer = parent_node.grant.grant().subject.clone();
        request.parent_run_id = parent_binding.run_id.clone();
        request.parent_agent_id = parent_binding.agent_id.clone();
        let requested_budget = request.scope.budget;
        request.scope = parent_node.grant.grant().scope.clone();
        request.scope.tenant_ids = Some(vec![parent_binding.tenant_id.clone()]);
        request.scope.budget = requested_budget;

        let current_fan_out = state
            .nodes
            .values()
            .filter(|node| {
                node.parent_grant_id.as_ref() == Some(&parent_id) && node.status.accounts()
            })
            .count() as u32;

        // Fan-out is authority-owned. A compatibility caller field cannot raise,
        // lower, or otherwise become the effective limit.
        request.max_fan_out = parent_node.parent_fan_out_limit;
        let issued = issue_delegation_child_grant(
            &parent_node.grant,
            request,
            DelegationValidationContext {
                now,
                audience,
                expected_child_subject,
                parent_fan_out_limit: parent_node.parent_fan_out_limit,
                current_parent_fan_out: current_fan_out,
            },
        )?;

        ensure_aggregate_budget_available(
            &state,
            &parent_id,
            &parent_node.budget,
            &issued.delegation_grant().budget,
        )?;

        let mut chain = parent_node.chain.clone();
        chain.grants.push(issued.delegation_grant().clone());
        validate_delegation_chain(parent_node.chain_root(&state)?, &chain)?;

        let child_id = issued.child_grant().grant().grant_id.clone();
        let runtime_binding = Some(RuntimeBinding {
            tenant_id: issued
                .child_grant()
                .grant()
                .scope
                .tenant_ids
                .as_ref()
                .and_then(|ids| ids.first())
                .cloned()
                .ok_or(DelegationLedgerError::ParentGrantMismatch)?,
            agent_id: issued.delegation_grant().child_agent_id.clone(),
            run_id: issued.delegation_grant().child_run_id.clone(),
        });
        let handle_token = CapabilityGrantId::new();
        let allowed_child_bindings = parent_node
            .allowed_child_bindings
            .iter()
            .filter(|binding| {
                binding.0 != issued.delegation_grant().child_agent_id
                    || binding.1 != issued.delegation_grant().child_run_id
            })
            .cloned()
            .collect();
        let budget = issued.delegation_grant().budget;
        let evidence = DelegationLedgerEvidence {
            chain: chain.clone(),
            budget,
            parent_fan_out_limit: parent_node.parent_fan_out_limit,
            status: DelegationReservationStatus::Reserved,
            reason: None,
        };
        state.nodes.insert(
            child_id,
            LedgerNode {
                grant: issued.child_grant().clone(),
                chain,
                parent_grant_id: Some(parent_id),
                parent_fan_out_limit: LOCAL_DELEGATION_FAN_OUT_LIMIT,
                budget,
                status: EdgeStatus::Reserved,
                runtime_binding,
                handle_token,
                own_tick_usage: HashMap::new(),
                subtree_tick_usage: HashMap::new(),
                own_http_usage: HashMap::new(),
                subtree_http_usage: HashMap::new(),
                in_flight_effects: 0,
                allowed_child_bindings,
            },
        );
        Ok(DelegationReservation { issued, evidence })
    }

    /// Commits a reservation after routing and child start both succeed.
    pub fn commit(
        &self,
        reservation: &DelegationReservation,
    ) -> Result<CommittedDelegation, DelegationLedgerError> {
        let evidence = self.transition(
            reservation,
            EdgeStatus::Active,
            DelegationReservationStatus::Committed,
            None,
        )?;
        let state = self.lock()?;
        let node = state
            .nodes
            .get(reservation.child_grant_id())
            .ok_or(DelegationLedgerError::ReservationNotActive)?;
        let caller = handle_for_node(&self.state, reservation.child_grant_id(), node);
        Ok(CommittedDelegation {
            evidence,
            runtime_authority: caller.runtime_authority(),
            caller,
        })
    }

    /// Releases a reservation only when routing produced no effect.
    pub fn release(
        &self,
        reservation: &DelegationReservation,
        reason: impl Into<String>,
    ) -> Result<DelegationLedgerEvidence, DelegationLedgerError> {
        let reason = reason.into();
        let mut state = self.lock()?;
        let node = state
            .nodes
            .get(reservation.child_grant_id())
            .ok_or(DelegationLedgerError::ReservationNotActive)?;
        if node.status != EdgeStatus::Reserved {
            return Err(DelegationLedgerError::ReservationNotActive);
        }
        state.nodes.remove(reservation.child_grant_id());
        Ok(evidence_with_status(
            reservation.evidence(),
            DelegationReservationStatus::Released,
            Some(reason),
        ))
    }

    /// Consumes a reservation fail-safe when routing may already have occurred.
    pub fn consume_after_routing_failure(
        &self,
        reservation: &DelegationReservation,
        reason: impl Into<String>,
    ) -> Result<DelegationLedgerEvidence, DelegationLedgerError> {
        let mut state = self.lock()?;
        let node = state
            .nodes
            .get_mut(reservation.child_grant_id())
            .ok_or(DelegationLedgerError::ReservationNotActive)?;
        if !matches!(node.status, EdgeStatus::Reserved | EdgeStatus::Active) {
            return Err(DelegationLedgerError::ReservationNotActive);
        }
        node.status = EdgeStatus::ConsumedAfterRoutingFailure;
        Ok(node.evidence(
            DelegationReservationStatus::ConsumedAfterRoutingFailure,
            Some(reason.into()),
        ))
    }

    /// Releases an active edge's allocation after terminal child cleanup.
    pub fn cleanup(
        &self,
        grant_id: &CapabilityGrantId,
        reason: impl Into<String>,
    ) -> Result<DelegationLedgerEvidence, DelegationLedgerError> {
        let mut state = self.lock()?;
        if state.nodes.values().any(|candidate| {
            candidate.parent_grant_id.as_ref() == Some(grant_id) && candidate.status.accounts()
        }) {
            return Err(DelegationLedgerError::ActiveDescendants);
        }
        {
            let node = state
                .nodes
                .get_mut(grant_id)
                .ok_or(DelegationLedgerError::ParentGrantMissing)?;
            if !matches!(
                node.status,
                EdgeStatus::Active | EdgeStatus::ConsumedAfterRoutingFailure
            ) {
                return Err(DelegationLedgerError::ReservationNotActive);
            }
            // Closing admission is the linearization point. Existing permits
            // remain valid until their gateway/adapter call leaves the boundary.
            node.status = EdgeStatus::Cleaned;
        }
        while state
            .nodes
            .get(grant_id)
            .is_some_and(|node| node.in_flight_effects != 0)
        {
            state = self
                .state
                .quiescent
                .wait(state)
                .map_err(|_| DelegationLedgerError::StorageUnavailable)?;
        }
        Ok(state
            .nodes
            .get(grant_id)
            .ok_or(DelegationLedgerError::ParentGrantMissing)?
            .evidence(DelegationReservationStatus::Cleaned, Some(reason.into())))
    }

    /// Reclaims a just-cleaned edge fail-safe when cleanup trace persistence fails.
    pub fn retain_after_cleanup_trace_failure(
        &self,
        grant_id: &CapabilityGrantId,
        reason: impl Into<String>,
    ) -> Result<DelegationLedgerEvidence, DelegationLedgerError> {
        let mut state = self.lock()?;
        let node = state
            .nodes
            .get_mut(grant_id)
            .ok_or(DelegationLedgerError::ParentGrantMissing)?;
        if node.status != EdgeStatus::Cleaned {
            return Err(DelegationLedgerError::ReservationNotActive);
        }
        node.status = EdgeStatus::ConsumedAfterRoutingFailure;
        Ok(node.evidence(
            DelegationReservationStatus::ConsumedAfterRoutingFailure,
            Some(reason.into()),
        ))
    }

    /// Revokes an edge and every descendant, returning deterministic root-first evidence.
    pub fn revoke_subtree(
        &self,
        grant_id: &CapabilityGrantId,
        reason: impl Into<String>,
    ) -> Result<Vec<DelegationLedgerEvidence>, DelegationLedgerError> {
        let reason = reason.into();
        let mut state = self.lock()?;
        if !state.nodes.contains_key(grant_id) {
            return Err(DelegationLedgerError::ParentGrantMissing);
        }
        let mut ids = state
            .nodes
            .iter()
            .filter(|(id, node)| {
                *id == grant_id
                    || node
                        .chain
                        .grants
                        .iter()
                        .any(|edge| &edge.parent_grant_id == grant_id)
            })
            .map(|(id, node)| (node.chain.grants.len(), id.clone()))
            .collect::<Vec<_>>();
        ids.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.to_string().cmp(&right.1.to_string()))
        });
        for (_, id) in &ids {
            if let Some(node) = state.nodes.get_mut(id) {
                node.status = EdgeStatus::Revoked;
            }
        }
        while ids.iter().any(|(_, id)| {
            state
                .nodes
                .get(id)
                .is_some_and(|node| node.in_flight_effects != 0)
        }) {
            state = self
                .state
                .quiescent
                .wait(state)
                .map_err(|_| DelegationLedgerError::StorageUnavailable)?;
        }
        let evidence = ids
            .into_iter()
            .filter_map(|(_, id)| state.nodes.get(&id))
            .map(|node| node.evidence(DelegationReservationStatus::Revoked, Some(reason.clone())))
            .collect();
        Ok(evidence)
    }

    /// Returns the complete immutable chain for one registered grant.
    pub fn chain(
        &self,
        grant_id: &CapabilityGrantId,
    ) -> Result<DelegationChain, DelegationLedgerError> {
        self.lock()?
            .nodes
            .get(grant_id)
            .map(|node| node.chain.clone())
            .ok_or(DelegationLedgerError::ParentGrantMissing)
    }

    fn transition(
        &self,
        reservation: &DelegationReservation,
        next: EdgeStatus,
        status: DelegationReservationStatus,
        reason: Option<String>,
    ) -> Result<DelegationLedgerEvidence, DelegationLedgerError> {
        let mut state = self.lock()?;
        let node = state
            .nodes
            .get_mut(reservation.child_grant_id())
            .ok_or(DelegationLedgerError::ReservationNotActive)?;
        if node.status != EdgeStatus::Reserved {
            return Err(DelegationLedgerError::ReservationNotActive);
        }
        node.status = next;
        Ok(node.evidence(status, reason))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, LedgerState>, DelegationLedgerError> {
        self.state
            .state
            .lock()
            .map_err(|_| DelegationLedgerError::StorageUnavailable)
    }

    #[cfg(test)]
    fn caller_for_test(
        &self,
        grant_id: &CapabilityGrantId,
    ) -> Result<DelegationCallerHandle, DelegationLedgerError> {
        let state = self.lock()?;
        let node = state
            .nodes
            .get(grant_id)
            .ok_or(DelegationLedgerError::ParentGrantMissing)?;
        Ok(handle_for_node(&self.state, grant_id, node))
    }
}

impl LedgerNode {
    fn chain_root<'a>(
        &self,
        state: &'a LedgerState,
    ) -> Result<&'a ValidatedCapabilityGrant, DelegationLedgerError> {
        state
            .nodes
            .get(&self.chain.root_grant_id)
            .map(|node| &node.grant)
            .ok_or(DelegationLedgerError::ParentGrantMissing)
    }

    fn evidence(
        &self,
        status: DelegationReservationStatus,
        reason: Option<String>,
    ) -> DelegationLedgerEvidence {
        DelegationLedgerEvidence {
            chain: self.chain.clone(),
            budget: self.budget,
            parent_fan_out_limit: self.parent_fan_out_limit,
            status,
            reason,
        }
    }
}

fn handle_for_node(
    state: &Arc<LedgerShared>,
    grant_id: &CapabilityGrantId,
    node: &LedgerNode,
) -> DelegationCallerHandle {
    DelegationCallerHandle {
        state: Arc::clone(state),
        grant_id: grant_id.clone(),
        token: node.handle_token.clone(),
    }
}

fn parent_runtime_binding(
    node: &LedgerNode,
    request: &DelegationChildGrantRequest,
) -> Result<RuntimeBinding, DelegationLedgerError> {
    if let Some(binding) = node.runtime_binding.clone() {
        return Ok(binding);
    }
    #[cfg(test)]
    {
        let tenant_id = node
            .grant
            .grant()
            .scope
            .tenant_ids
            .as_ref()
            .and_then(|ids| ids.first())
            .cloned()
            .ok_or(DelegationLedgerError::ParentGrantMismatch)?;
        Ok(RuntimeBinding {
            tenant_id,
            agent_id: request.parent_agent_id.clone(),
            run_id: request.parent_run_id.clone(),
        })
    }
    #[cfg(not(test))]
    {
        let _ = request;
        Err(DelegationLedgerError::ParentGrantMismatch)
    }
}

fn exact_scope_bindings(
    grant: &CapabilityGrant,
) -> Result<Vec<(AgentId, RunId)>, DelegationLedgerError> {
    let agents = grant
        .scope
        .agent_ids
        .as_ref()
        .ok_or(DelegationLedgerError::ChildRuntimeBindingDenied)?;
    let runs = grant
        .scope
        .run_ids
        .as_ref()
        .ok_or(DelegationLedgerError::ChildRuntimeBindingDenied)?;
    if agents.len() != 1 || runs.len() != 1 {
        return Err(DelegationLedgerError::ChildRuntimeBindingDenied);
    }
    Ok(vec![(agents[0].clone(), runs[0].clone())])
}

fn validate_explicit_child_bindings(
    grant: &CapabilityGrant,
    bindings: &[(AgentId, RunId)],
) -> Result<(), DelegationLedgerError> {
    let agents = grant
        .scope
        .agent_ids
        .as_ref()
        .ok_or(DelegationLedgerError::ChildRuntimeBindingDenied)?;
    let runs = grant
        .scope
        .run_ids
        .as_ref()
        .ok_or(DelegationLedgerError::ChildRuntimeBindingDenied)?;
    if bindings.is_empty() {
        return Err(DelegationLedgerError::ChildRuntimeBindingDenied);
    }
    let mut seen = std::collections::HashSet::new();
    for (agent_id, run_id) in bindings {
        if agent_id.is_nil()
            || run_id.is_nil()
            || !agents.contains(agent_id)
            || !runs.contains(run_id)
            || !seen.insert((agent_id.clone(), run_id.clone()))
        {
            return Err(DelegationLedgerError::ChildRuntimeBindingDenied);
        }
    }
    Ok(())
}

fn authorize_live_action(
    state: &mut LedgerState,
    grant_id: &CapabilityGrantId,
    token: &CapabilityGrantId,
    request: DelegatedActionAuthorizationRequest,
) -> Result<(), DelegatedActionAuthorizationError> {
    let node = state
        .nodes
        .get(grant_id)
        .cloned()
        .ok_or(DelegatedActionAuthorizationError::InvalidHandle)?;
    if &node.handle_token != token {
        return Err(DelegatedActionAuthorizationError::InvalidHandle);
    }
    if request.supplied_grant_id.as_ref() != Some(grant_id) {
        return Err(DelegatedActionAuthorizationError::GrantReferenceMismatch);
    }
    if node.status != EdgeStatus::Active {
        return Err(DelegatedActionAuthorizationError::AuthorityInactive);
    }
    let binding = node
        .runtime_binding
        .as_ref()
        .ok_or(DelegatedActionAuthorizationError::RuntimeBindingMismatch)?;
    if binding.tenant_id != request.tenant_id
        || binding.agent_id != request.agent_id
        || binding.run_id != request.run_id
    {
        return Err(DelegatedActionAuthorizationError::RuntimeBindingMismatch);
    }
    if request.now < node.grant.grant().not_before {
        return Err(DelegatedActionAuthorizationError::NotYetValid);
    }
    if request.now >= node.grant.grant().expires_at {
        return Err(DelegatedActionAuthorizationError::Expired);
    }
    if matches!(
        node.grant.grant().revocation,
        splendor_types::RevocationStatus::Revoked { .. }
    ) {
        return Err(DelegatedActionAuthorizationError::Revoked);
    }

    let mut exact_scope = node.grant.grant().scope.clone();
    exact_scope.tenant_ids = Some(vec![request.tenant_id.clone()]);
    exact_scope.agent_ids = Some(vec![request.agent_id.clone()]);
    exact_scope.run_ids = Some(vec![request.run_id.clone()]);
    // Scope containment is checked against the immutable reserved budget. Live
    // usage is enforced separately below by the cumulative authority ledger.
    exact_scope.budget = node.budget;
    for operation in &request.operations {
        let decision = crate::evaluate_capability_request(
            std::slice::from_ref(&node.grant),
            &CapabilityRequest {
                schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
                subject: node.grant.grant().subject.clone(),
                operation: operation.clone(),
                scope: exact_scope.clone(),
                requested_at: request.now,
                metadata: Default::default(),
            },
            request.now,
        );
        if decision.status != AuthorityDecisionStatus::Allowed {
            return Err(DelegatedActionAuthorizationError::OperationDenied {
                reason: decision
                    .reasons
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "delegated_operation_denied".to_string()),
            });
        }
    }

    let retained = retained_executable_budget(state, grant_id, node.budget)?;
    let usage = conservative_usage(retained, request.usage_estimate);
    let mut tick_usage = usage;
    tick_usage.http_requests = 0;
    let minute_bucket = request.now.unix_timestamp().div_euclid(60);
    let own_current = node
        .own_tick_usage
        .get(&request.tick_id)
        .copied()
        .unwrap_or_default();
    ensure_usage_fits(own_current, tick_usage, without_http_limit(retained)).map_err(|error| {
        match error {
            DelegatedActionAuthorizationError::BudgetExceeded { dimension } => {
                DelegatedActionAuthorizationError::RetainedBudgetExceeded { dimension }
            }
            other => other,
        }
    })?;
    ensure_http_fits(
        node.own_http_usage
            .get(&minute_bucket)
            .copied()
            .unwrap_or_default(),
        usage.http_requests,
        retained.max_http_requests_per_minute,
    )
    .map_err(|error| match error {
        DelegatedActionAuthorizationError::BudgetExceeded { dimension } => {
            DelegatedActionAuthorizationError::RetainedBudgetExceeded { dimension }
        }
        other => other,
    })?;

    let lineage = grant_lineage(state, grant_id)?;
    for ancestor_id in &lineage {
        let ancestor = state
            .nodes
            .get(ancestor_id)
            .ok_or(DelegatedActionAuthorizationError::InvalidHandle)?;
        if ancestor.status != EdgeStatus::Active {
            return Err(DelegatedActionAuthorizationError::AuthorityInactive);
        }
        let subtree_current = ancestor
            .subtree_tick_usage
            .get(&request.tick_id)
            .copied()
            .unwrap_or_default();
        ensure_usage_fits(
            subtree_current,
            tick_usage,
            without_http_limit(ancestor.budget),
        )?;
        ensure_http_fits(
            ancestor
                .subtree_http_usage
                .get(&minute_bucket)
                .copied()
                .unwrap_or_default(),
            usage.http_requests,
            ancestor.budget.max_http_requests_per_minute,
        )?;
    }

    let node = state
        .nodes
        .get_mut(grant_id)
        .ok_or(DelegatedActionAuthorizationError::InvalidHandle)?;
    node.own_tick_usage
        .entry(request.tick_id)
        .or_default()
        .accumulate(tick_usage);
    prune_http_windows(&mut node.own_http_usage, minute_bucket);
    let own_http = node
        .own_http_usage
        .get(&minute_bucket)
        .copied()
        .unwrap_or_default()
        .saturating_add(usage.http_requests);
    node.own_http_usage.insert(minute_bucket, own_http);
    for ancestor_id in lineage {
        let ancestor = state
            .nodes
            .get_mut(&ancestor_id)
            .ok_or(DelegatedActionAuthorizationError::InvalidHandle)?;
        ancestor
            .subtree_tick_usage
            .entry(request.tick_id)
            .or_default()
            .accumulate(tick_usage);
        prune_http_windows(&mut ancestor.subtree_http_usage, minute_bucket);
        let subtree_http = ancestor
            .subtree_http_usage
            .get(&minute_bucket)
            .copied()
            .unwrap_or_default()
            .saturating_add(usage.http_requests);
        ancestor
            .subtree_http_usage
            .insert(minute_bucket, subtree_http);
    }
    Ok(())
}

fn grant_lineage(
    state: &LedgerState,
    grant_id: &CapabilityGrantId,
) -> Result<Vec<CapabilityGrantId>, DelegatedActionAuthorizationError> {
    let mut lineage = vec![grant_id.clone()];
    let mut cursor = state
        .nodes
        .get(grant_id)
        .ok_or(DelegatedActionAuthorizationError::InvalidHandle)?
        .parent_grant_id
        .clone();
    while let Some(parent_id) = cursor {
        let parent = state
            .nodes
            .get(&parent_id)
            .ok_or(DelegatedActionAuthorizationError::InvalidHandle)?;
        lineage.push(parent_id.clone());
        cursor = parent.parent_grant_id.clone();
    }
    Ok(lineage)
}

fn retained_executable_budget(
    state: &LedgerState,
    grant_id: &CapabilityGrantId,
    budget: AuthorityBudgetScope,
) -> Result<AuthorityBudgetScope, DelegatedActionAuthorizationError> {
    let children = state
        .nodes
        .values()
        .filter(|node| node.parent_grant_id.as_ref() == Some(grant_id) && node.status.accounts());
    let mut reserved = zero_budget_like(budget);
    for child in children {
        reserved = add_budget(reserved, child.budget)?;
    }
    Ok(subtract_budget(budget, reserved))
}

fn zero_budget_like(budget: AuthorityBudgetScope) -> AuthorityBudgetScope {
    AuthorityBudgetScope {
        max_actions_per_tick: budget.max_actions_per_tick.map(|_| 0),
        max_action_duration_ms: budget.max_action_duration_ms.map(|_| 0),
        max_filesystem_read_bytes: budget.max_filesystem_read_bytes.map(|_| 0),
        max_filesystem_write_bytes: budget.max_filesystem_write_bytes.map(|_| 0),
        max_network_read_bytes: budget.max_network_read_bytes.map(|_| 0),
        max_network_write_bytes: budget.max_network_write_bytes.map(|_| 0),
        max_http_requests_per_minute: budget.max_http_requests_per_minute.map(|_| 0),
    }
}

fn add_budget(
    left: AuthorityBudgetScope,
    right: AuthorityBudgetScope,
) -> Result<AuthorityBudgetScope, DelegatedActionAuthorizationError> {
    macro_rules! add {
        ($field:ident, $dimension:literal) => {
            match (left.$field, right.$field) {
                (Some(a), Some(b)) => Some(a.checked_add(b).ok_or(
                    DelegatedActionAuthorizationError::BudgetExceeded {
                        dimension: $dimension,
                    },
                )?),
                (None, None) => None,
                _ => {
                    return Err(DelegatedActionAuthorizationError::BudgetExceeded {
                        dimension: $dimension,
                    })
                }
            }
        };
    }
    Ok(AuthorityBudgetScope {
        max_actions_per_tick: add!(max_actions_per_tick, "max_actions_per_tick"),
        max_action_duration_ms: add!(max_action_duration_ms, "max_action_duration_ms"),
        max_filesystem_read_bytes: add!(max_filesystem_read_bytes, "max_filesystem_read_bytes"),
        max_filesystem_write_bytes: add!(max_filesystem_write_bytes, "max_filesystem_write_bytes"),
        max_network_read_bytes: add!(max_network_read_bytes, "max_network_read_bytes"),
        max_network_write_bytes: add!(max_network_write_bytes, "max_network_write_bytes"),
        max_http_requests_per_minute: add!(
            max_http_requests_per_minute,
            "max_http_requests_per_minute"
        ),
    })
}

fn subtract_budget(
    limit: AuthorityBudgetScope,
    reserved: AuthorityBudgetScope,
) -> AuthorityBudgetScope {
    macro_rules! subtract {
        ($field:ident) => {
            match (limit.$field, reserved.$field) {
                (Some(limit), Some(reserved)) => Some(limit.saturating_sub(reserved)),
                (Some(limit), None) => Some(limit),
                (None, _) => None,
            }
        };
    }
    AuthorityBudgetScope {
        max_actions_per_tick: subtract!(max_actions_per_tick),
        max_action_duration_ms: subtract!(max_action_duration_ms),
        max_filesystem_read_bytes: subtract!(max_filesystem_read_bytes),
        max_filesystem_write_bytes: subtract!(max_filesystem_write_bytes),
        max_network_read_bytes: subtract!(max_network_read_bytes),
        max_network_write_bytes: subtract!(max_network_write_bytes),
        max_http_requests_per_minute: subtract!(max_http_requests_per_minute),
    }
}

fn conservative_usage(limits: AuthorityBudgetScope, estimate: QuotaUsage) -> QuotaUsage {
    QuotaUsage {
        // One admitted proposal is always one action. Every other unmeasured
        // dimension reserves the trusted grant maximum, never a smaller value
        // supplied by policy/user space.
        actions: 1,
        action_duration_ms: conservative_u64(
            estimate.action_duration_ms,
            limits.max_action_duration_ms,
        ),
        filesystem_read_bytes: conservative_u64(
            estimate.filesystem_read_bytes,
            limits.max_filesystem_read_bytes,
        ),
        filesystem_write_bytes: conservative_u64(
            estimate.filesystem_write_bytes,
            limits.max_filesystem_write_bytes,
        ),
        network_read_bytes: conservative_u64(
            estimate.network_read_bytes,
            limits.max_network_read_bytes,
        ),
        network_write_bytes: conservative_u64(
            estimate.network_write_bytes,
            limits.max_network_write_bytes,
        ),
        http_requests: conservative_u32(
            estimate.http_requests,
            limits.max_http_requests_per_minute,
        ),
    }
}

fn conservative_u64(estimate: u64, limit: Option<u64>) -> u64 {
    limit.unwrap_or(estimate)
}

fn conservative_u32(estimate: u32, limit: Option<u32>) -> u32 {
    limit.unwrap_or(estimate)
}

fn without_http_limit(mut limit: AuthorityBudgetScope) -> AuthorityBudgetScope {
    limit.max_http_requests_per_minute = None;
    limit
}

fn ensure_http_fits(
    current: u32,
    additional: u32,
    limit: Option<u32>,
) -> Result<(), DelegatedActionAuthorizationError> {
    if limit.is_some_and(|limit| {
        current
            .checked_add(additional)
            .is_none_or(|value| value > limit)
    }) {
        return Err(DelegatedActionAuthorizationError::BudgetExceeded {
            dimension: "max_http_requests_per_minute",
        });
    }
    Ok(())
}

fn prune_http_windows(windows: &mut HashMap<i64, u32>, current: i64) {
    windows.retain(|bucket, _| *bucket >= current);
}

fn ensure_usage_fits(
    current: QuotaUsage,
    additional: QuotaUsage,
    limit: AuthorityBudgetScope,
) -> Result<(), DelegatedActionAuthorizationError> {
    macro_rules! check {
        ($usage:ident, $limit:ident, $dimension:literal) => {
            if let Some(limit) = limit.$limit {
                if current
                    .$usage
                    .checked_add(additional.$usage)
                    .is_none_or(|value| value > limit)
                {
                    return Err(DelegatedActionAuthorizationError::BudgetExceeded {
                        dimension: $dimension,
                    });
                }
            }
        };
    }
    check!(actions, max_actions_per_tick, "max_actions_per_tick");
    check!(
        action_duration_ms,
        max_action_duration_ms,
        "max_action_duration_ms"
    );
    check!(
        filesystem_read_bytes,
        max_filesystem_read_bytes,
        "max_filesystem_read_bytes"
    );
    check!(
        filesystem_write_bytes,
        max_filesystem_write_bytes,
        "max_filesystem_write_bytes"
    );
    check!(
        network_read_bytes,
        max_network_read_bytes,
        "max_network_read_bytes"
    );
    check!(
        network_write_bytes,
        max_network_write_bytes,
        "max_network_write_bytes"
    );
    check!(
        http_requests,
        max_http_requests_per_minute,
        "max_http_requests_per_minute"
    );
    Ok(())
}

fn evidence_with_status(
    evidence: &DelegationLedgerEvidence,
    status: DelegationReservationStatus,
    reason: Option<String>,
) -> DelegationLedgerEvidence {
    let mut evidence = evidence.clone();
    evidence.status = status;
    evidence.reason = reason;
    evidence
}

/// Validates every immutable edge in order and identifies the first failure.
pub fn validate_delegation_chain(
    root: &ValidatedCapabilityGrant,
    chain: &DelegationChain,
) -> Result<(), DelegationChainValidationError> {
    if chain.schema_version != DELEGATION_CHAIN_SCHEMA_VERSION {
        return Err(chain_error(0, "invalid_chain_schema"));
    }
    if chain.root_grant_id != root.grant().grant_id {
        return Err(chain_error(0, "root_grant_mismatch"));
    }
    if chain.max_depth != root.grant().max_delegation_depth {
        return Err(chain_error(0, "root_depth_mismatch"));
    }
    if chain.grants.len() > chain.max_depth as usize {
        return Err(chain_error(
            chain.max_depth as usize,
            "chain_depth_exceeded",
        ));
    }

    let mut parent: &CapabilityGrant = root.grant();
    let mut previous_edge: Option<&splendor_types::DelegationGrant> = None;
    for (index, edge) in chain.grants.iter().enumerate() {
        let child = &edge.child_capability_grant;
        if edge.schema_version != splendor_types::DELEGATION_GRANT_SCHEMA_VERSION {
            return Err(chain_error(index, "invalid_edge_schema"));
        }
        if !matches!(
            crate::delegation::delegation_edge_binding_digest(edge),
            Ok(digest) if digest == edge.binding_digest
        ) {
            return Err(chain_error(index, "edge_binding_digest_mismatch"));
        }
        if edge.parent_run_id.is_nil()
            || edge.child_run_id.is_nil()
            || edge.parent_run_id == edge.child_run_id
            || edge.parent_agent_id.is_nil()
            || edge.child_agent_id.is_nil()
            || edge.parent_agent_id == edge.child_agent_id
        {
            return Err(chain_error(index, "runtime_identity_invalid"));
        }
        if edge.objective.trim().is_empty() || edge.objective.trim() != edge.objective {
            return Err(chain_error(index, "objective_invalid"));
        }
        if edge.allowed_message_schemas.is_empty()
            || has_duplicates(&edge.allowed_message_schemas)
            || edge.allowed_message_schemas.iter().any(|schema| {
                !schema.starts_with("splendor.message.")
                    || splendor_types::MessageSchemaVersion::from_schema(schema).is_err()
            })
        {
            return Err(chain_error(index, "message_schema_contract_invalid"));
        }
        if edge.allowed_recipient_agent_ids.is_empty()
            || edge.allowed_recipient_agent_ids.iter().any(AgentId::is_nil)
            || has_duplicates(&edge.allowed_recipient_agent_ids)
        {
            return Err(chain_error(index, "message_recipient_contract_invalid"));
        }
        if edge.result_contract.schema_version
            != splendor_types::DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION
            || splendor_types::MessageSchemaVersion::from_schema(
                &edge.result_contract.result_schema,
            )
            .is_err()
            || edge.result_contract.result_schema != splendor_types::TASK_RESPONSE_SCHEMA
            || edge.result_contract.max_result_bytes == Some(0)
        {
            return Err(chain_error(index, "result_contract_invalid"));
        }
        if edge.parent_grant_id != parent.grant_id
            || child.parent_grant_ids.as_slice() != [parent.grant_id.clone()]
        {
            return Err(chain_error(index, "parent_child_grant_ref_mismatch"));
        }
        if let Some(previous) = previous_edge {
            if edge.parent_run_id != previous.child_run_id
                || edge.parent_agent_id != previous.child_agent_id
            {
                return Err(chain_error(index, "parent_child_runtime_ref_mismatch"));
            }
            if !role_narrows(previous.role_profile, edge.role_profile) {
                return Err(chain_error(index, "role_escalation"));
            }
        }
        if edge.budget != child.scope.budget
            || edge.not_before != child.not_before
            || edge.expires_at != child.expires_at
            || edge.remaining_delegation_depth != child.max_delegation_depth
        {
            return Err(chain_error(index, "edge_child_grant_projection_mismatch"));
        }
        if child.issuer != parent.subject || child.subject.is_nil() {
            return Err(chain_error(index, "principal_binding_mismatch"));
        }
        if edge.not_before >= edge.expires_at {
            return Err(chain_error(index, "edge_time_window_invalid"));
        }
        if !child
            .scope
            .agent_ids
            .as_ref()
            .is_some_and(|ids| ids.contains(&edge.child_agent_id))
            || !child
                .scope
                .run_ids
                .as_ref()
                .is_some_and(|ids| ids.contains(&edge.child_run_id))
        {
            return Err(chain_error(index, "child_scope_identity_mismatch"));
        }
        if edge.max_fan_out != LOCAL_DELEGATION_FAN_OUT_LIMIT {
            return Err(chain_error(index, "fan_out_not_authority_owned"));
        }
        if edge.cleanup_obligations != DelegationCleanupObligations::default() {
            return Err(chain_error(index, "cleanup_obligations_weakened"));
        }
        if child.max_delegation_depth >= parent.max_delegation_depth {
            return Err(chain_error(index, "delegation_depth_not_monotonic"));
        }
        ensure_child_grant_narrows(parent, child)
            .map_err(|error| chain_error(index, &format!("narrowing_{}", error.reason_code())))?;
        crate::delegation::validate_role_operations(edge.role_profile, &child.operations)
            .map_err(|error| chain_error(index, error.reason_code()))?;
        parent = child;
        previous_edge = Some(edge);
    }
    Ok(())
}

fn has_duplicates<T: Eq + std::hash::Hash>(values: &[T]) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(values.len());
    values.iter().any(|value| !seen.insert(value))
}

fn chain_error(index: usize, reason: &str) -> DelegationChainValidationError {
    DelegationChainValidationError {
        edge_index: index,
        reason: reason.to_string(),
    }
}

fn role_narrows(
    parent: splendor_types::DelegationRoleProfile,
    child: splendor_types::DelegationRoleProfile,
) -> bool {
    use splendor_types::DelegationRoleProfile::*;
    match parent {
        Persistent => true,
        Specialist => matches!(child, Specialist | Ephemeral | Trigger | Critic | Evaluator),
        Trigger => matches!(child, Trigger | Ephemeral | Critic | Evaluator),
        Ephemeral => matches!(child, Ephemeral | Critic | Evaluator),
        Actuator => matches!(child, Actuator | Critic | Evaluator),
        Evaluator => matches!(child, Evaluator | Critic),
        Critic => child == Critic,
    }
}

fn ensure_aggregate_budget_available(
    state: &LedgerState,
    parent_id: &CapabilityGrantId,
    limit: &AuthorityBudgetScope,
    requested: &AuthorityBudgetScope,
) -> Result<(), DelegationLedgerError> {
    let budgets = state
        .nodes
        .values()
        .filter(|node| node.parent_grant_id.as_ref() == Some(parent_id) && node.status.accounts())
        .map(|node| node.budget)
        .collect::<Vec<_>>();

    check_u32(
        "max_actions_per_tick",
        limit.max_actions_per_tick,
        requested.max_actions_per_tick,
        budgets.iter().map(|budget| budget.max_actions_per_tick),
    )?;
    check_u64(
        "max_action_duration_ms",
        limit.max_action_duration_ms,
        requested.max_action_duration_ms,
        budgets.iter().map(|budget| budget.max_action_duration_ms),
    )?;
    check_u64(
        "max_filesystem_read_bytes",
        limit.max_filesystem_read_bytes,
        requested.max_filesystem_read_bytes,
        budgets
            .iter()
            .map(|budget| budget.max_filesystem_read_bytes),
    )?;
    check_u64(
        "max_filesystem_write_bytes",
        limit.max_filesystem_write_bytes,
        requested.max_filesystem_write_bytes,
        budgets
            .iter()
            .map(|budget| budget.max_filesystem_write_bytes),
    )?;
    check_u64(
        "max_network_read_bytes",
        limit.max_network_read_bytes,
        requested.max_network_read_bytes,
        budgets.iter().map(|budget| budget.max_network_read_bytes),
    )?;
    check_u64(
        "max_network_write_bytes",
        limit.max_network_write_bytes,
        requested.max_network_write_bytes,
        budgets.iter().map(|budget| budget.max_network_write_bytes),
    )?;
    check_u32(
        "max_http_requests_per_minute",
        limit.max_http_requests_per_minute,
        requested.max_http_requests_per_minute,
        budgets
            .iter()
            .map(|budget| budget.max_http_requests_per_minute),
    )?;
    Ok(())
}

fn check_u32(
    dimension: &'static str,
    limit: Option<u32>,
    requested: Option<u32>,
    existing: impl Iterator<Item = Option<u32>>,
) -> Result<(), DelegationLedgerError> {
    check_sum(
        dimension,
        limit.map(u128::from),
        requested.map(u128::from),
        existing.map(|value| value.map(u128::from)),
    )
}

fn check_u64(
    dimension: &'static str,
    limit: Option<u64>,
    requested: Option<u64>,
    existing: impl Iterator<Item = Option<u64>>,
) -> Result<(), DelegationLedgerError> {
    check_sum(
        dimension,
        limit.map(u128::from),
        requested.map(u128::from),
        existing.map(|value| value.map(u128::from)),
    )
}

fn check_sum(
    dimension: &'static str,
    limit: Option<u128>,
    requested: Option<u128>,
    existing: impl Iterator<Item = Option<u128>>,
) -> Result<(), DelegationLedgerError> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let Some(requested) = requested else {
        return Err(DelegationLedgerError::AggregateBudgetExceeded { dimension });
    };
    let used = existing
        .flatten()
        .try_fold(0_u128, u128::checked_add)
        .ok_or(DelegationLedgerError::AggregateBudgetExceeded { dimension })?;
    if used
        .checked_add(requested)
        .is_none_or(|total| total > limit)
    {
        return Err(DelegationLedgerError::AggregateBudgetExceeded { dimension });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::unchecked_validated_grant_for_tests;
    use crate::delegation::tests::{parent_grant, request_for, Fixture};
    use splendor_types::{DelegationRoleProfile, RunId};

    fn reserve(
        ledger: &InMemoryDelegationAuthorityLedger,
        fixture: &Fixture,
        parent: &ValidatedCapabilityGrant,
        mut request: DelegationChildGrantRequest,
    ) -> Result<DelegationReservation, DelegationLedgerError> {
        request.max_fan_out = u32::MAX;
        let caller = ledger.caller_for_test(&parent.grant().grant_id)?;
        ledger.reserve_child(
            &caller,
            request,
            fixture.now,
            fixture.audience.clone(),
            fixture.child_subject.clone(),
        )
    }

    #[test]
    fn ledger_lifecycle_is_atomic_immutable_and_fail_safe() {
        let fixture = Fixture::new();
        let root = parent_grant(&fixture);
        let ledger = InMemoryDelegationAuthorityLedger::new();
        assert!(format!("{ledger:?}").contains("redacted authority ledger"));
        ledger.register_root(&root).expect("root registered");
        ledger.register_root(&root).expect("exact retry");

        let first = reserve(&ledger, &fixture, &root, request_for(&fixture, &root))
            .expect("first reserved");
        assert_eq!(
            first.evidence().parent_fan_out_limit,
            LOCAL_DELEGATION_FAN_OUT_LIMIT
        );
        let committed = ledger.commit(&first).expect("first committed");
        assert_eq!(
            committed.evidence.status,
            DelegationReservationStatus::Committed
        );
        assert!(matches!(
            ledger.commit(&first),
            Err(DelegationLedgerError::ReservationNotActive)
        ));
        assert_eq!(
            ledger
                .chain(first.child_grant_id())
                .expect("stored chain")
                .grants
                .len(),
            1
        );
        let cleaned = ledger
            .cleanup(first.child_grant_id(), "complete")
            .expect("cleanup");
        assert_eq!(cleaned.status, DelegationReservationStatus::Cleaned);
        let retained = ledger
            .retain_after_cleanup_trace_failure(first.child_grant_id(), "trace_failed")
            .expect("cleanup failure retained");
        assert_eq!(
            retained.status,
            DelegationReservationStatus::ConsumedAfterRoutingFailure
        );

        let mut second_request = request_for(&fixture, &root);
        second_request.child_grant_id = CapabilityGrantId::new();
        let second = reserve(&ledger, &fixture, &root, second_request).expect("second reserved");
        let released = ledger.release(&second, "routing_failed").expect("released");
        assert_eq!(released.status, DelegationReservationStatus::Released);
        assert!(matches!(
            ledger.chain(second.child_grant_id()),
            Err(DelegationLedgerError::ParentGrantMissing)
        ));

        let mut third_request = request_for(&fixture, &root);
        third_request.child_grant_id = CapabilityGrantId::new();
        let third = reserve(&ledger, &fixture, &root, third_request).expect("third reserved");
        let consumed = ledger
            .consume_after_routing_failure(&third, "start_failed")
            .expect("consumed fail-safe");
        assert_eq!(
            consumed.status,
            DelegationReservationStatus::ConsumedAfterRoutingFailure
        );
        let revoked = ledger
            .revoke_subtree(&root.grant().grant_id, "root_revoked")
            .expect("root subtree revoked");
        assert_eq!(revoked.len(), 3);
        assert!(revoked
            .iter()
            .all(|evidence| evidence.status == DelegationReservationStatus::Revoked));
    }

    #[test]
    fn ledger_errors_have_stable_reason_codes_and_role_cannot_escalate() {
        let reasons = vec![
            DelegationLedgerError::StorageUnavailable.reason_code(),
            DelegationLedgerError::RootGrantConflict.reason_code(),
            DelegationLedgerError::ParentGrantMissing.reason_code(),
            DelegationLedgerError::ParentGrantMismatch.reason_code(),
            DelegationLedgerError::ChildGrantCollision.reason_code(),
            DelegationLedgerError::Issuance(DelegationGrantError::MissingParentEdge).reason_code(),
            DelegationLedgerError::Chain(DelegationChainValidationError {
                edge_index: 2,
                reason: "scope".to_string(),
            })
            .reason_code(),
            DelegationLedgerError::AggregateBudgetExceeded {
                dimension: "network",
            }
            .reason_code(),
            DelegationLedgerError::RoleEscalation.reason_code(),
            DelegationLedgerError::ReservationNotActive.reason_code(),
            DelegationLedgerError::ActiveDescendants.reason_code(),
        ];
        assert_eq!(reasons.len(), 11);
        assert!(reasons.iter().all(|reason| !reason.is_empty()));

        let fixture = Fixture::new();
        let root = parent_grant(&fixture);
        let ledger = InMemoryDelegationAuthorityLedger::new();
        ledger.register_root(&root).expect("root");
        let first =
            reserve(&ledger, &fixture, &root, request_for(&fixture, &root)).expect("first child");
        let committed = ledger.commit(&first).expect("active child");

        let child_grant = unchecked_validated_grant_for_tests(
            first.delegation_grant().child_capability_grant.clone(),
        );
        let mut nested = request_for(&fixture, &child_grant);
        nested.parent_grant_id = Some(first.child_grant_id().clone());
        nested.issuer = child_grant.grant().subject.clone();
        nested.parent_run_id = fixture.child_run_id.clone();
        nested.parent_agent_id = fixture.child_agent_id.clone();
        nested.child_run_id = RunId::new();
        nested.role_profile = DelegationRoleProfile::Actuator;
        assert!(matches!(
            ledger.reserve_child(
                &committed.caller,
                nested,
                fixture.now,
                fixture.audience.clone(),
                fixture.child_subject.clone(),
            ),
            Err(DelegationLedgerError::RoleEscalation)
        ));
        assert!(matches!(
            ledger.cleanup(&root.grant().grant_id, "invalid_root_cleanup"),
            Err(DelegationLedgerError::ActiveDescendants)
        ));
    }

    #[test]
    fn complete_chain_validation_reports_first_mutated_edge() {
        let fixture = Fixture::new();
        let root = parent_grant(&fixture);
        let ledger = InMemoryDelegationAuthorityLedger::new();
        ledger.register_root(&root).expect("root");
        let reservation =
            reserve(&ledger, &fixture, &root, request_for(&fixture, &root)).expect("reservation");
        let baseline = reservation.evidence().chain.clone();
        validate_delegation_chain(&root, &baseline).expect("baseline");

        let mut cases = Vec::new();
        let mut chain = baseline.clone();
        chain.schema_version = "splendor.authority.delegation_chain.v1".to_string();
        cases.push((chain, "invalid_chain_schema"));
        let mut chain = baseline.clone();
        chain.root_grant_id = CapabilityGrantId::new();
        cases.push((chain, "root_grant_mismatch"));
        let mut chain = baseline.clone();
        chain.max_depth += 1;
        cases.push((chain, "root_depth_mismatch"));
        let mut chain = baseline.clone();
        chain.grants[0].parent_grant_id = CapabilityGrantId::new();
        chain.grants[0].binding_digest =
            crate::delegation_edge_binding_digest(&chain.grants[0]).expect("digest");
        cases.push((chain, "parent_child_grant_ref_mismatch"));
        let mut chain = baseline.clone();
        chain.grants[0].budget.max_actions_per_tick = Some(1);
        chain.grants[0].binding_digest =
            crate::delegation_edge_binding_digest(&chain.grants[0]).expect("digest");
        cases.push((chain, "edge_child_grant_projection_mismatch"));
        let mut chain = baseline.clone();
        chain.grants[0].child_agent_id = splendor_types::AgentId::new();
        chain.grants[0].binding_digest =
            crate::delegation_edge_binding_digest(&chain.grants[0]).expect("digest");
        cases.push((chain, "child_scope_identity_mismatch"));
        let mut chain = baseline.clone();
        chain.grants[0].max_fan_out = 1;
        chain.grants[0].binding_digest =
            crate::delegation_edge_binding_digest(&chain.grants[0]).expect("digest");
        cases.push((chain, "fan_out_not_authority_owned"));
        let mut chain = baseline.clone();
        chain.grants[0].cleanup_obligations.cancel_descendants = false;
        chain.grants[0].binding_digest =
            crate::delegation_edge_binding_digest(&chain.grants[0]).expect("digest");
        cases.push((chain, "cleanup_obligations_weakened"));
        let mut chain = baseline.clone();
        chain.grants[0].remaining_delegation_depth = root.grant().max_delegation_depth;
        chain.grants[0].child_capability_grant.max_delegation_depth =
            root.grant().max_delegation_depth;
        chain.grants[0].binding_digest =
            crate::delegation_edge_binding_digest(&chain.grants[0]).expect("digest");
        cases.push((chain, "delegation_depth_not_monotonic"));
        let mut chain = baseline.clone();
        chain
            .grants
            .extend([baseline.grants[0].clone(), baseline.grants[0].clone()]);
        cases.push((chain, "chain_depth_exceeded"));

        for (chain, reason) in cases {
            let error = validate_delegation_chain(&root, &chain).expect_err(reason);
            assert_eq!(
                error.edge_index,
                if reason == "chain_depth_exceeded" {
                    2
                } else {
                    0
                }
            );
            assert_eq!(error.reason, reason);
        }
    }

    #[test]
    fn every_budget_component_is_aggregated() {
        for dimension in 0..7 {
            let fixture = Fixture::new();
            let mut raw_root = parent_grant(&fixture).grant().clone();
            raw_root.scope.budget = budget_for_dimension(dimension, 10);
            let root = unchecked_validated_grant_for_tests(raw_root);
            let ledger = InMemoryDelegationAuthorityLedger::new();
            ledger.register_root(&root).expect("root");

            let mut first_request = request_for(&fixture, &root);
            first_request.scope.budget = budget_for_dimension(dimension, 6);
            let first = reserve(&ledger, &fixture, &root, first_request).expect("first");
            ledger.commit(&first).expect("commit first");

            let mut second_request = request_for(&fixture, &root);
            second_request.child_grant_id = CapabilityGrantId::new();
            second_request.scope.budget = budget_for_dimension(dimension, 5);
            assert!(matches!(
                reserve(&ledger, &fixture, &root, second_request),
                Err(DelegationLedgerError::AggregateBudgetExceeded { .. })
            ));
        }
    }

    #[test]
    fn ledger_rejects_conflicts_collisions_and_invalid_lifecycle_transitions() {
        let fixture = Fixture::new();
        let root = parent_grant(&fixture);
        let ledger = InMemoryDelegationAuthorityLedger::new();
        ledger.register_root(&root).expect("root");

        let mut conflicting_root = root.grant().clone();
        conflicting_root.scope.budget.max_actions_per_tick = Some(1);
        assert!(matches!(
            ledger.register_root(&unchecked_validated_grant_for_tests(
                conflicting_root.clone()
            )),
            Err(DelegationLedgerError::RootGrantConflict)
        ));
        let stale_clone_attempt = reserve(
            &ledger,
            &fixture,
            &unchecked_validated_grant_for_tests(conflicting_root),
            request_for(&fixture, &root),
        )
        .expect("opaque handle derives the immutable ledger parent");
        ledger
            .release(&stale_clone_attempt, "test_release")
            .expect("released");

        let request = request_for(&fixture, &root);
        let reservation = reserve(&ledger, &fixture, &root, request.clone()).expect("reserved");
        assert!(matches!(
            reserve(&ledger, &fixture, &root, request),
            Err(DelegationLedgerError::ChildGrantCollision)
        ));
        ledger.commit(&reservation).expect("committed");
        assert!(matches!(
            ledger.release(&reservation, "too late"),
            Err(DelegationLedgerError::ReservationNotActive)
        ));
        ledger
            .cleanup(reservation.child_grant_id(), "complete")
            .expect("cleaned");
        assert!(matches!(
            ledger.consume_after_routing_failure(&reservation, "too late"),
            Err(DelegationLedgerError::ReservationNotActive)
        ));
        assert!(matches!(
            ledger.cleanup(reservation.child_grant_id(), "duplicate"),
            Err(DelegationLedgerError::ReservationNotActive)
        ));

        let mut active_request = request_for(&fixture, &root);
        active_request.child_grant_id = CapabilityGrantId::new();
        let active = reserve(&ledger, &fixture, &root, active_request).expect("active reserved");
        ledger.commit(&active).expect("active committed");
        assert!(matches!(
            ledger.retain_after_cleanup_trace_failure(active.child_grant_id(), "not cleaned"),
            Err(DelegationLedgerError::ReservationNotActive)
        ));
        assert!(matches!(
            ledger.revoke_subtree(&CapabilityGrantId::new(), "unknown"),
            Err(DelegationLedgerError::ParentGrantMissing)
        ));
    }

    #[test]
    fn role_narrowing_and_budget_overflow_checks_are_fail_closed() {
        use DelegationRoleProfile::*;

        assert!(role_narrows(Persistent, Actuator));
        assert!(role_narrows(Specialist, Trigger));
        assert!(role_narrows(Trigger, Critic));
        assert!(role_narrows(Ephemeral, Evaluator));
        assert!(role_narrows(Actuator, Critic));
        assert!(role_narrows(Evaluator, Critic));
        assert!(role_narrows(Critic, Critic));
        assert!(!role_narrows(Critic, Actuator));

        assert!(matches!(
            check_sum("missing", Some(1), None, std::iter::empty()),
            Err(DelegationLedgerError::AggregateBudgetExceeded {
                dimension: "missing"
            })
        ));
        assert!(matches!(
            check_sum(
                "overflow",
                Some(u128::MAX),
                Some(0),
                [Some(u128::MAX), Some(1)].into_iter(),
            ),
            Err(DelegationLedgerError::AggregateBudgetExceeded {
                dimension: "overflow"
            })
        ));
    }

    #[test]
    fn live_child_handle_enforces_exact_binding_cumulative_tick_usage_and_cleanup() {
        let fixture = Fixture::new();
        let root = parent_grant(&fixture);
        let ledger = InMemoryDelegationAuthorityLedger::new();
        let root_caller = ledger
            .register_root_runtime(
                &root,
                fixture.tenant_id.clone(),
                fixture.parent_agent_id.clone(),
                fixture.parent_run_id.clone(),
            )
            .expect("root handle");
        let mut request = request_for(&fixture, &root);
        request.scope.budget.max_actions_per_tick = Some(1);
        request.scope.budget.max_action_duration_ms = Some(10);
        let reservation = ledger
            .reserve_child(
                &root_caller,
                request,
                fixture.now,
                fixture.audience.clone(),
                fixture.child_subject.clone(),
            )
            .expect("child reserved");
        let grant_id = reservation.child_grant_id().clone();
        let operation = reservation
            .delegation_grant()
            .child_capability_grant
            .operations[0]
            .clone();
        let committed = ledger.commit(&reservation).expect("child committed");
        let authorize = |tick_id| DelegatedActionAuthorizationRequest {
            supplied_grant_id: Some(grant_id.clone()),
            tenant_id: fixture.tenant_id.clone(),
            agent_id: fixture.child_agent_id.clone(),
            run_id: fixture.child_run_id.clone(),
            tick_id,
            operations: vec![operation.clone()],
            usage_estimate: QuotaUsage {
                actions: 1,
                action_duration_ms: 1,
                ..QuotaUsage::default()
            },
            now: fixture.now,
        };

        committed
            .runtime_authority
            .authorize_action(authorize(7))
            .expect("first action reserved");
        assert!(matches!(
            committed.runtime_authority.authorize_action(authorize(7)),
            Err(DelegatedActionAuthorizationError::RetainedBudgetExceeded {
                dimension: "max_actions_per_tick"
            })
        ));
        committed
            .runtime_authority
            .authorize_action(authorize(8))
            .expect("new tick has fresh usage");
        ledger.cleanup(&grant_id, "complete").expect("cleanup");
        assert!(matches!(
            committed.runtime_authority.authorize_action(authorize(9)),
            Err(DelegatedActionAuthorizationError::AuthorityInactive)
        ));
    }

    #[test]
    fn opaque_handles_and_live_action_denials_cover_fail_closed_boundaries() {
        let fixture = Fixture::new();
        let root = parent_grant(&fixture);
        let ledger = InMemoryDelegationAuthorityLedger::new();
        let root_caller = ledger
            .register_root_runtime(
                &root,
                fixture.tenant_id.clone(),
                fixture.parent_agent_id.clone(),
                fixture.parent_run_id.clone(),
            )
            .expect("root handle");
        assert!(format!("{root_caller:?}").contains("<opaque>"));
        assert_eq!(root_caller.grant_id(), &root.grant().grant_id);
        assert_eq!(
            root_caller
                .child_request_defaults()
                .expect("defaults")
                .expires_at,
            root.grant().expires_at
        );
        let root_runtime = root_caller.runtime_authority();
        assert!(format!("{root_runtime:?}").contains("<opaque>"));
        assert_eq!(root_runtime.grant_id(), root_caller.grant_id());

        let reservation = ledger
            .reserve_child(
                &root_caller,
                request_for(&fixture, &root),
                fixture.now,
                fixture.audience.clone(),
                fixture.child_subject.clone(),
            )
            .expect("child reserved");
        let grant_id = reservation.child_grant_id().clone();
        let operation = reservation
            .delegation_grant()
            .child_capability_grant
            .operations[0]
            .clone();
        let committed = ledger.commit(&reservation).expect("child committed");
        let request = |now, tick_id| DelegatedActionAuthorizationRequest {
            supplied_grant_id: Some(grant_id.clone()),
            tenant_id: fixture.tenant_id.clone(),
            agent_id: fixture.child_agent_id.clone(),
            run_id: fixture.child_run_id.clone(),
            tick_id,
            operations: vec![operation.clone()],
            usage_estimate: QuotaUsage {
                actions: 1,
                action_duration_ms: 1,
                ..QuotaUsage::default()
            },
            now,
        };
        let permit = committed
            .runtime_authority
            .authorize_action(request(fixture.now, 1))
            .expect("permit");
        assert!(format!("{permit:?}").contains("<opaque>"));
        assert_eq!(permit.grant_id(), &grant_id);

        let mut wrong_runtime = request(fixture.now, 2);
        wrong_runtime.run_id = RunId::new();
        assert!(matches!(
            committed.runtime_authority.authorize_action(wrong_runtime),
            Err(DelegatedActionAuthorizationError::RuntimeBindingMismatch)
        ));
        assert!(matches!(
            committed.runtime_authority.authorize_action(request(
                reservation.delegation_grant().not_before - time::Duration::seconds(1),
                3,
            )),
            Err(DelegatedActionAuthorizationError::NotYetValid)
        ));
        assert!(matches!(
            committed
                .runtime_authority
                .authorize_action(request(reservation.delegation_grant().expires_at, 4,)),
            Err(DelegatedActionAuthorizationError::Expired)
        ));
        let mut wrong_operation = request(fixture.now, 5);
        wrong_operation.operations = vec![crate::gateway_action_operation("not.granted")];
        assert!(matches!(
            committed
                .runtime_authority
                .authorize_action(wrong_operation),
            Err(DelegatedActionAuthorizationError::OperationDenied { .. })
        ));
        let invalid_handle = DelegatedRuntimeAuthorityHandle {
            state: Arc::clone(&ledger.state),
            grant_id: grant_id.clone(),
            token: CapabilityGrantId::new(),
        };
        assert!(matches!(
            invalid_handle.authorize_action(request(fixture.now, 6)),
            Err(DelegatedActionAuthorizationError::InvalidHandle)
        ));
        {
            let mut state = ledger.lock().expect("state");
            let node = state.nodes.get_mut(&grant_id).expect("child node");
            let mut raw = node.grant.grant().clone();
            raw.revocation = splendor_types::RevocationStatus::Revoked {
                reason: "test".to_string(),
            };
            node.grant = unchecked_validated_grant_for_tests(raw);
        }
        assert!(matches!(
            committed
                .runtime_authority
                .authorize_action(request(fixture.now, 7)),
            Err(DelegatedActionAuthorizationError::Revoked)
        ));
        {
            let mut state = ledger.lock().expect("state");
            let node = state.nodes.get_mut(&grant_id).expect("child node");
            let mut raw = node.grant.grant().clone();
            raw.revocation = splendor_types::RevocationStatus::Active;
            node.grant = unchecked_validated_grant_for_tests(raw);
            state
                .nodes
                .get_mut(root_caller.grant_id())
                .expect("root node")
                .status = EdgeStatus::Revoked;
        }
        assert!(matches!(
            committed
                .runtime_authority
                .authorize_action(request(fixture.now, 8)),
            Err(DelegatedActionAuthorizationError::AuthorityInactive)
        ));
        assert_eq!(conservative_u64(3, Some(10)), 10);
        assert_eq!(conservative_u32(2, Some(10)), 10);

        let reason_codes = [
            DelegatedActionAuthorizationError::AuthorityUnavailable.reason_code(),
            DelegatedActionAuthorizationError::InvalidHandle.reason_code(),
            DelegatedActionAuthorizationError::GrantReferenceMismatch.reason_code(),
            DelegatedActionAuthorizationError::RuntimeBindingMismatch.reason_code(),
            DelegatedActionAuthorizationError::AuthorityInactive.reason_code(),
            DelegatedActionAuthorizationError::NotYetValid.reason_code(),
            DelegatedActionAuthorizationError::Expired.reason_code(),
            DelegatedActionAuthorizationError::Revoked.reason_code(),
            DelegatedActionAuthorizationError::OperationDenied {
                reason: "operation_not_granted".to_string(),
            }
            .reason_code(),
            DelegatedActionAuthorizationError::BudgetExceeded {
                dimension: "actions",
            }
            .reason_code(),
            DelegatedActionAuthorizationError::RetainedBudgetExceeded {
                dimension: "actions",
            }
            .reason_code(),
        ];
        assert!(reason_codes.iter().all(|reason| !reason.is_empty()));

        let foreign_ledger = InMemoryDelegationAuthorityLedger::new();
        let foreign = foreign_ledger.register_root(&root).expect("foreign root");
        assert!(matches!(
            ledger.reserve_child(
                &foreign,
                request_for(&fixture, &root),
                fixture.now,
                fixture.audience.clone(),
                fixture.child_subject.clone(),
            ),
            Err(DelegationLedgerError::ParentGrantMismatch)
        ));
        let inactive = InMemoryDelegationAuthorityLedger::new();
        let inactive_caller = inactive.register_root(&root).expect("inactive root");
        inactive
            .cleanup(inactive_caller.grant_id(), "test")
            .expect("root cleanup");
        assert!(matches!(
            inactive_caller.child_request_defaults(),
            Err(DelegationLedgerError::ParentGrantMismatch)
        ));
        assert!(matches!(
            inactive.reserve_child(
                &inactive_caller,
                request_for(&fixture, &root),
                fixture.now,
                fixture.audience.clone(),
                fixture.child_subject.clone(),
            ),
            Err(DelegationLedgerError::ParentGrantMismatch)
        ));
    }

    #[test]
    fn exact_root_bindings_and_chain_shapes_reject_ambiguous_inputs() {
        let fixture = Fixture::new();
        let root = parent_grant(&fixture);
        let ledger = InMemoryDelegationAuthorityLedger::new();
        assert!(matches!(
            ledger.register_root_runtime_with_child_bindings(
                &root,
                fixture.tenant_id.clone(),
                fixture.parent_agent_id.clone(),
                fixture.parent_run_id.clone(),
                Vec::new(),
            ),
            Err(DelegationLedgerError::ChildRuntimeBindingDenied)
        ));
        assert!(matches!(
            ledger.register_root_runtime_with_child_bindings(
                &root,
                fixture.tenant_id.clone(),
                fixture.parent_agent_id.clone(),
                fixture.parent_run_id.clone(),
                vec![(AgentId::new(), RunId::new())],
            ),
            Err(DelegationLedgerError::ChildRuntimeBindingDenied)
        ));
        assert!(matches!(
            ledger.register_root_runtime_with_child_bindings(
                &root,
                fixture.tenant_id.clone(),
                fixture.parent_agent_id.clone(),
                fixture.parent_run_id.clone(),
                vec![
                    (fixture.child_agent_id.clone(), fixture.child_run_id.clone()),
                    (fixture.child_agent_id.clone(), fixture.child_run_id.clone()),
                ],
            ),
            Err(DelegationLedgerError::ChildRuntimeBindingDenied)
        ));
        let mut multi = root.grant().clone();
        multi
            .scope
            .agent_ids
            .as_mut()
            .expect("agents")
            .push(AgentId::new());
        multi
            .scope
            .run_ids
            .as_mut()
            .expect("runs")
            .push(RunId::new());
        assert!(matches!(
            ledger.register_root_runtime(
                &unchecked_validated_grant_for_tests(multi),
                fixture.tenant_id.clone(),
                fixture.parent_agent_id.clone(),
                fixture.parent_run_id.clone(),
            ),
            Err(DelegationLedgerError::ChildRuntimeBindingDenied)
        ));

        ledger.register_root(&root).expect("root");
        let reservation =
            reserve(&ledger, &fixture, &root, request_for(&fixture, &root)).expect("edge");
        let baseline = reservation.evidence().chain.clone();
        let mut cases = Vec::new();
        macro_rules! invalid_edge {
            ($reason:literal, $body:expr) => {{
                let mut chain = baseline.clone();
                $body(&mut chain.grants[0]);
                chain.grants[0].binding_digest =
                    crate::delegation_edge_binding_digest(&chain.grants[0]).expect("digest");
                cases.push((chain, $reason));
            }};
        }
        invalid_edge!(
            "invalid_edge_schema",
            |edge: &mut splendor_types::DelegationGrant| {
                edge.schema_version = "splendor.authority.delegation_grant.v1".to_string()
            }
        );
        invalid_edge!(
            "runtime_identity_invalid",
            |edge: &mut splendor_types::DelegationGrant| {
                edge.parent_run_id = edge.child_run_id.clone()
            }
        );
        invalid_edge!(
            "objective_invalid",
            |edge: &mut splendor_types::DelegationGrant| {
                edge.objective = " invalid ".to_string()
            }
        );
        invalid_edge!(
            "message_schema_contract_invalid",
            |edge: &mut splendor_types::DelegationGrant| { edge.allowed_message_schemas.clear() }
        );
        invalid_edge!(
            "message_recipient_contract_invalid",
            |edge: &mut splendor_types::DelegationGrant| {
                edge.allowed_recipient_agent_ids.clear()
            }
        );
        invalid_edge!(
            "result_contract_invalid",
            |edge: &mut splendor_types::DelegationGrant| {
                edge.result_contract.max_result_bytes = Some(0)
            }
        );
        invalid_edge!(
            "principal_binding_mismatch",
            |edge: &mut splendor_types::DelegationGrant| {
                edge.child_capability_grant.issuer = PrincipalId::new()
            }
        );
        invalid_edge!(
            "edge_time_window_invalid",
            |edge: &mut splendor_types::DelegationGrant| {
                edge.not_before = edge.expires_at;
                edge.child_capability_grant.not_before = edge.expires_at;
            }
        );
        for (chain, expected) in cases {
            assert_eq!(
                validate_delegation_chain(&root, &chain)
                    .expect_err("invalid chain")
                    .reason,
                expected
            );
        }
    }

    #[test]
    fn exact_edge_binding_digest_rejects_every_semantic_field_mutation() {
        let fixture = Fixture::new();
        let root = parent_grant(&fixture);
        let ledger = InMemoryDelegationAuthorityLedger::new();
        ledger.register_root(&root).expect("root");
        let reservation =
            reserve(&ledger, &fixture, &root, request_for(&fixture, &root)).expect("edge");
        let baseline = reservation.evidence().chain.clone();
        let mut cases = Vec::new();
        macro_rules! mutated {
            ($body:expr) => {{
                let mut chain = baseline.clone();
                $body(&mut chain.grants[0]);
                cases.push(chain);
            }};
        }
        mutated!(|edge: &mut splendor_types::DelegationGrant| edge.objective.push_str(" changed"));
        mutated!(|edge: &mut splendor_types::DelegationGrant| edge.parent_run_id = RunId::new());
        mutated!(|edge: &mut splendor_types::DelegationGrant| edge.child_run_id = RunId::new());
        mutated!(
            |edge: &mut splendor_types::DelegationGrant| edge.parent_agent_id = AgentId::new()
        );
        mutated!(|edge: &mut splendor_types::DelegationGrant| edge.child_agent_id = AgentId::new());
        mutated!(|edge: &mut splendor_types::DelegationGrant| edge
            .allowed_message_schemas
            .push("splendor.message.note.v1".to_string()));
        mutated!(|edge: &mut splendor_types::DelegationGrant| edge
            .allowed_recipient_agent_ids
            .push(AgentId::new()));
        mutated!(|edge: &mut splendor_types::DelegationGrant| edge
            .result_contract
            .requires_response = false);
        mutated!(
            |edge: &mut splendor_types::DelegationGrant| edge.role_profile =
                DelegationRoleProfile::Critic
        );
        mutated!(|edge: &mut splendor_types::DelegationGrant| edge
            .cleanup_obligations
            .cancel_descendants = false);
        mutated!(|edge: &mut splendor_types::DelegationGrant| edge
            .child_capability_grant
            .operations
            .clear());
        mutated!(
            |edge: &mut splendor_types::DelegationGrant| edge.expires_at +=
                time::Duration::seconds(1)
        );
        mutated!(
            |edge: &mut splendor_types::DelegationGrant| edge.remaining_delegation_depth =
                edge.remaining_delegation_depth.saturating_add(1)
        );
        mutated!(
            |edge: &mut splendor_types::DelegationGrant| edge.max_fan_out =
                edge.max_fan_out.saturating_sub(1)
        );
        mutated!(
            |edge: &mut splendor_types::DelegationGrant| edge.budget.max_actions_per_tick = Some(1)
        );

        for chain in cases {
            let error = validate_delegation_chain(&root, &chain).expect_err("mutation denied");
            assert_eq!(error.edge_index, 0);
            assert_eq!(error.reason, "edge_binding_digest_mismatch");
        }
    }

    #[test]
    fn default_trace_summary_redacts_complete_authority_parameters() {
        let fixture = Fixture::new();
        let root = parent_grant(&fixture);
        let ledger = InMemoryDelegationAuthorityLedger::new();
        ledger.register_root(&root).expect("root");
        let reservation =
            reserve(&ledger, &fixture, &root, request_for(&fixture, &root)).expect("edge");
        let mut evidence = reservation.evidence().clone();
        evidence.budget = AuthorityBudgetScope {
            max_actions_per_tick: Some(1),
            max_action_duration_ms: Some(1),
            max_filesystem_read_bytes: Some(1),
            max_filesystem_write_bytes: Some(1),
            max_network_read_bytes: Some(1),
            max_network_write_bytes: Some(1),
            max_http_requests_per_minute: Some(1),
        };
        let summary = evidence.redacted_trace_summary();
        assert_eq!(summary.reserved_budget_dimensions.len(), 7);
        let json = serde_json::to_string(&summary).expect("summary");
        assert!(json.contains("chain_digest"));
        assert!(json.contains("child_grant_id"));
        for forbidden in [
            "child_capability_grant",
            "allowed_message_schemas",
            "allowed_recipient_agent_ids",
            "cleanup_obligations",
            "result_contract",
            "objective",
        ] {
            assert!(
                !json.contains(forbidden),
                "redacted summary leaked {forbidden}"
            );
        }
    }

    fn budget_for_dimension(dimension: usize, value: u64) -> AuthorityBudgetScope {
        let mut budget = AuthorityBudgetScope::default();
        match dimension {
            0 => budget.max_actions_per_tick = Some(value as u32),
            1 => budget.max_action_duration_ms = Some(value),
            2 => budget.max_filesystem_read_bytes = Some(value),
            3 => budget.max_filesystem_write_bytes = Some(value),
            4 => budget.max_network_read_bytes = Some(value),
            5 => budget.max_network_write_bytes = Some(value),
            6 => budget.max_http_requests_per_minute = Some(value as u32),
            _ => unreachable!(),
        }
        budget
    }
}
