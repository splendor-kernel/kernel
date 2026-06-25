//! Principal identity registry contracts.
//!
//! These records are behavior-free kernel contracts for the Principal Registry.
//! They identify principals, typed compatibility bindings, proof references, and
//! immutable lifecycle events. They do not grant authority and they do not carry
//! raw credential material.

use crate::{
    AgentId, FleetId, IdentityEventId, InstanceId, NodeId, PrincipalId, PrincipalProofRefId, RunId,
    TenantId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// Actor class represented by a registry principal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// Tenant boundary represented for attribution and migration.
    Tenant,
    /// Human user, operator, annotator, approver, or reviewer.
    Human,
    /// Daemon client, CLI, sidecar, control plane, or integration principal.
    Service,
    /// Splendor agent identity.
    Agent,
    /// Running Splendor runtime process/instance.
    RuntimeInstance,
    /// Physical, virtual, or logical host.
    Node,
    /// Robot, drone, humanoid, sensor package, actuator boundary, or edge device.
    PhysicalDevice,
    /// Governance or approval authority source.
    GovernanceAuthority,
    /// External identity or attestation provider reference.
    ExternalProvider,
    /// Workload or execution-boundary identity used for attribution.
    Workload,
}

/// Current lifecycle status of a principal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalStatus {
    /// Registered but not yet active for privileged use.
    Pending,
    /// Eligible to be considered by authority decisions; not authority by itself.
    Active,
    /// Temporarily blocked from new privileged use.
    Suspended,
    /// Terminally invalid for new privileged use.
    Revoked,
}

/// Monotonic optimistic-concurrency coordinate for principal history.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityRevision(u64);

impl IdentityRevision {
    /// First immutable history revision created by registration.
    pub const fn initial() -> Self {
        Self(1)
    }

    /// Creates an explicit identity revision value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the next monotonic revision.
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Returns the numeric revision value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Typed compatibility binding from a principal to an existing Splendor identity
/// coordinate or external provider subject.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrincipalBinding {
    /// Tenant compatibility and attribution binding.
    Tenant { tenant_id: TenantId },
    /// Fleet ownership or attribution binding.
    Fleet { fleet_id: FleetId },
    /// Node host identity binding.
    Node { node_id: NodeId },
    /// Runtime process identity binding.
    Instance { instance_id: InstanceId },
    /// Agent identity binding.
    Agent { agent_id: AgentId },
    /// Run attribution and migration-query coordinate only.
    Run { run_id: RunId },
    /// Canonical provider/issuer/subject/audience tuple.
    ExternalSubject {
        /// Provider namespace, such as `oidc`, `mtls`, or a local verifier name.
        provider: String,
        /// Issuer or trust anchor reference.
        issuer: String,
        /// Provider subject identifier.
        subject: String,
        /// Intended daemon, instance, fleet, node, or manager audience.
        audience: String,
    },
}

/// Redacted reference to proof evidence bound to a principal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrincipalProofRef {
    /// Stable proof-reference identity within a principal.
    pub proof_ref_id: PrincipalProofRefId,
    /// Provider-neutral proof kind, for example `oidc_subject` or `mtls_subject`.
    pub proof_kind: String,
    /// Provider namespace, where applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Issuer or trust anchor reference, where applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Provider subject reference, never a bearer credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Intended audience, where applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Key or credential identifier, never key bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Digest over canonical proof descriptor/evidence, excluding secret bytes.
    pub proof_digest: String,
    /// Hash algorithm/version for `proof_digest`.
    pub digest_algorithm: String,
    /// Redacted evidence references only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
}

/// Optional human-facing display fields for a principal.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrincipalDisplay {
    /// Human-facing display label only; never a stable principal key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Human-facing description only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Principal contract record. A principal identifies an actor and lifecycle
/// state; it does not grant permission, work-order scope, data use, approval, or
/// gateway authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Principal {
    /// Distinct principal identity.
    pub principal_id: PrincipalId,
    /// Principal kind.
    pub kind: PrincipalKind,
    /// Current principal lifecycle status.
    pub status: PrincipalStatus,
    /// Current revision of this principal.
    pub revision: IdentityRevision,
    /// Tenant owner coordinate, where applicable; not a permission grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_tenant_id: Option<TenantId>,
    /// Fleet owner coordinate, where applicable; not a permission grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_fleet_id: Option<FleetId>,
    /// Non-authorizing bindings to existing typed IDs or external subjects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<PrincipalBinding>,
    /// Redacted proof references. No raw credentials belong here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof_refs: Vec<PrincipalProofRef>,
    /// Display-only fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<PrincipalDisplay>,
    /// Non-authorizing metadata, subject to reserved-key rejection by lifecycle owners.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Last mutation timestamp.
    pub updated_at: OffsetDateTime,
    /// Replacement principal, when supersession is recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<PrincipalId>,
}

/// Principal lifecycle event kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum IdentityLifecycleEventKind {
    /// Principal history created.
    #[serde(rename = "principal.registered")]
    Registered,
    /// Principal activated from an allowed state.
    #[serde(rename = "principal.activated")]
    Activated,
    /// Principal suspended.
    #[serde(rename = "principal.suspended")]
    Suspended,
    /// Principal terminally revoked.
    #[serde(rename = "principal.revoked")]
    Revoked,
    /// Principal proof binding rotated.
    #[serde(rename = "principal.proof_rotated")]
    ProofRotated,
    /// Principal linked to a replacement principal.
    #[serde(rename = "principal.superseded")]
    Superseded,
}

/// Immutable identity lifecycle event record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdentityLifecycleEvent {
    /// Distinct lifecycle event identity.
    pub identity_event_id: IdentityEventId,
    /// Principal affected by the event.
    pub principal_id: PrincipalId,
    /// Revision before the transition, absent for registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_revision: Option<IdentityRevision>,
    /// Revision after the transition.
    pub new_revision: IdentityRevision,
    /// Event kind.
    pub event_kind: IdentityLifecycleEventKind,
    /// Previous status where applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_status: Option<PrincipalStatus>,
    /// New status where applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_status: Option<PrincipalStatus>,
    /// Principal that requested or approved the mutation, where available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_principal_id: Option<PrincipalId>,
    /// Structured reason code for the transition.
    pub reason_code: String,
    /// Digest of proof changes when present; never raw proof material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_digest: Option<String>,
    /// Redacted evidence references only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    /// Logical occurrence timestamp.
    pub occurred_at: OffsetDateTime,
    /// Persistence timestamp.
    pub recorded_at: OffsetDateTime,
}

#[cfg(test)]
#[path = "../tests/unit/identity_tests.rs"]
mod tests;
