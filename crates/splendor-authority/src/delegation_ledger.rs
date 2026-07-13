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
    AuthorityBudgetScope, CapabilityGrant, CapabilityGrantId, DelegationChain,
    DelegationCleanupObligations, DelegationLedgerEvidence, DelegationReservationStatus,
    PrincipalId, DELEGATION_CHAIN_SCHEMA_VERSION,
};
use std::collections::HashMap;
use std::sync::Mutex;
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
}

#[derive(Default)]
struct LedgerState {
    nodes: HashMap<CapabilityGrantId, LedgerNode>,
}

/// Opaque atomic reservation returned before the kernel attempts routing.
#[derive(Clone, Debug)]
pub struct DelegationReservation {
    issued: DelegationChildGrant,
    evidence: DelegationLedgerEvidence,
}

impl DelegationReservation {
    /// Authority-issued immutable child edge and validated grant.
    pub fn issued(&self) -> &DelegationChildGrant {
        &self.issued
    }

    /// Replay-safe evidence for the reserved state.
    pub fn evidence(&self) -> &DelegationLedgerEvidence {
        &self.evidence
    }

    fn child_grant_id(&self) -> &CapabilityGrantId {
        &self.issued.child_grant().grant().grant_id
    }
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
        }
    }
}

/// In-memory authority owner for local delegation validity and accounting.
#[derive(Default)]
pub struct InMemoryDelegationAuthorityLedger {
    state: Mutex<LedgerState>,
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
    pub fn register_root(
        &self,
        root: &ValidatedCapabilityGrant,
    ) -> Result<(), DelegationLedgerError> {
        let mut state = self.lock()?;
        let id = root.grant().grant_id.clone();
        if let Some(existing) = state.nodes.get(&id) {
            return if existing.parent_grant_id.is_none() && existing.grant == *root {
                Ok(())
            } else {
                Err(DelegationLedgerError::RootGrantConflict)
            };
        }
        state.nodes.insert(
            id.clone(),
            LedgerNode {
                grant: root.clone(),
                chain: DelegationChain {
                    schema_version: DELEGATION_CHAIN_SCHEMA_VERSION.to_string(),
                    root_grant_id: id,
                    grants: Vec::new(),
                    max_depth: root.grant().max_delegation_depth,
                },
                parent_grant_id: None,
                parent_fan_out_limit: LOCAL_DELEGATION_FAN_OUT_LIMIT,
                budget: root.grant().scope.budget,
                status: EdgeStatus::Active,
            },
        );
        Ok(())
    }

    /// Atomically validates, issues, chain-checks, and reserves one child edge.
    pub fn reserve_child(
        &self,
        parent: &ValidatedCapabilityGrant,
        mut request: DelegationChildGrantRequest,
        now: OffsetDateTime,
        audience: String,
        expected_child_subject: PrincipalId,
    ) -> Result<DelegationReservation, DelegationLedgerError> {
        let mut state = self.lock()?;
        let parent_id = parent.grant().grant_id.clone();
        let parent_node = state
            .nodes
            .get(&parent_id)
            .cloned()
            .ok_or(DelegationLedgerError::ParentGrantMissing)?;
        if parent_node.grant != *parent {
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
            parent,
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
            },
        );
        Ok(DelegationReservation { issued, evidence })
    }

    /// Commits a reservation after routing and child start both succeed.
    pub fn commit(
        &self,
        reservation: &DelegationReservation,
    ) -> Result<DelegationLedgerEvidence, DelegationLedgerError> {
        self.transition(
            reservation,
            EdgeStatus::Active,
            DelegationReservationStatus::Committed,
            None,
        )
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
        node.status = EdgeStatus::Cleaned;
        Ok(node.evidence(DelegationReservationStatus::Cleaned, Some(reason.into())))
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
        let root_revoked = state
            .nodes
            .get(grant_id)
            .is_some_and(|node| node.parent_grant_id.is_none());
        let mut ids = state
            .nodes
            .iter()
            .filter(|(_, node)| {
                node.parent_grant_id.is_some()
                    && (root_revoked
                        || node
                            .chain
                            .grants
                            .iter()
                            .any(|edge| &edge.child_capability_grant.grant_id == grant_id))
            })
            .map(|(id, node)| (node.chain.grants.len(), id.clone()))
            .collect::<Vec<_>>();
        ids.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.to_string().cmp(&right.1.to_string()))
        });
        let mut evidence = Vec::new();
        for (_, id) in ids {
            if let Some(node) = state.nodes.get_mut(&id) {
                node.status = EdgeStatus::Revoked;
                evidence.push(
                    node.evidence(DelegationReservationStatus::Revoked, Some(reason.clone())),
                );
            }
        }
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
            .lock()
            .map_err(|_| DelegationLedgerError::StorageUnavailable)
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
        ledger.reserve_child(
            parent,
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
        assert_eq!(committed.status, DelegationReservationStatus::Committed);
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
        assert_eq!(revoked.len(), 2);
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
        ledger.commit(&first).expect("active child");

        let mut nested = request_for(&fixture, first.issued().child_grant());
        nested.parent_grant_id = Some(first.child_grant_id().clone());
        nested.issuer = first.issued().child_grant().grant().subject.clone();
        nested.parent_run_id = fixture.child_run_id.clone();
        nested.parent_agent_id = fixture.child_agent_id.clone();
        nested.child_run_id = RunId::new();
        nested.role_profile = DelegationRoleProfile::Actuator;
        assert!(matches!(
            reserve(&ledger, &fixture, first.issued().child_grant(), nested),
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
        chain.schema_version = "splendor.authority.delegation_chain.v2".to_string();
        cases.push((chain, "invalid_chain_schema"));
        let mut chain = baseline.clone();
        chain.root_grant_id = CapabilityGrantId::new();
        cases.push((chain, "root_grant_mismatch"));
        let mut chain = baseline.clone();
        chain.max_depth += 1;
        cases.push((chain, "root_depth_mismatch"));
        let mut chain = baseline.clone();
        chain.grants[0].parent_grant_id = CapabilityGrantId::new();
        cases.push((chain, "parent_child_grant_ref_mismatch"));
        let mut chain = baseline.clone();
        chain.grants[0].budget.max_actions_per_tick = Some(1);
        cases.push((chain, "edge_child_grant_projection_mismatch"));
        let mut chain = baseline.clone();
        chain.grants[0].child_agent_id = splendor_types::AgentId::new();
        cases.push((chain, "child_scope_identity_mismatch"));
        let mut chain = baseline.clone();
        chain.grants[0].max_fan_out = 1;
        cases.push((chain, "fan_out_not_authority_owned"));
        let mut chain = baseline.clone();
        chain.grants[0].cleanup_obligations.cancel_descendants = false;
        cases.push((chain, "cleanup_obligations_weakened"));
        let mut chain = baseline.clone();
        chain.grants[0].remaining_delegation_depth = root.grant().max_delegation_depth;
        chain.grants[0].child_capability_grant.max_delegation_depth =
            root.grant().max_delegation_depth;
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
        assert!(matches!(
            reserve(
                &ledger,
                &fixture,
                &unchecked_validated_grant_for_tests(conflicting_root),
                request_for(&fixture, &root),
            ),
            Err(DelegationLedgerError::ParentGrantMismatch)
        ));

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
