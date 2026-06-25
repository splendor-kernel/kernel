//! Principal Registry lifecycle decisions.
//!
//! This module owns IDR-001 lifecycle legality only. Existence or status of a
//! principal is never treated as capability, work-order authority, approval, or
//! gateway permission.

use splendor_store::{IdentityHistoryRecord, PrincipalRegistryStore, PrincipalRegistryStoreError};
use splendor_types::{
    validate_extension_map, FleetId, IdentityEventId, IdentityLifecycleEvent,
    IdentityLifecycleEventKind, IdentityRevision, Principal, PrincipalBinding, PrincipalDisplay,
    PrincipalId, PrincipalKind, PrincipalProofRef, PrincipalStatus, TenantId,
};
use std::collections::BTreeMap;
use thiserror::Error;
use time::OffsetDateTime;

const ALLOWED_PROOF_DIGEST_ALGORITHMS: &[&str] = &["blake3", "sha256", "sha512"];
const ALLOWED_EVIDENCE_REF_PREFIXES: &[&str] = &[
    "artifact:",
    "event:",
    "evidence:",
    "receipt:",
    "trace:",
    "verifier_receipt:",
];
const CREDENTIAL_MATERIAL_MARKERS: &[&str] = &[
    "access_token",
    "api_key",
    "apikey",
    "authorization:",
    "bearer",
    "cookie",
    "credential",
    "gho_",
    "ghp_",
    "github_pat",
    "jwt",
    "oauth",
    "password",
    "private_key",
    "secret",
    "session",
    "sk_",
    "token",
    "xoxb",
    "xoxp",
    "-----begin",
];

/// Input for registering a principal. Registration always creates a pending
/// principal revision in this slice.
#[derive(Clone, Debug)]
pub struct RegisterPrincipal {
    /// Distinct principal ID to register.
    pub principal_id: PrincipalId,
    /// Kind of principal being registered.
    pub kind: PrincipalKind,
    /// Tenant owner coordinate, where applicable; not a permission grant.
    pub owner_tenant_id: Option<TenantId>,
    /// Fleet owner coordinate, where applicable; not a permission grant.
    pub owner_fleet_id: Option<FleetId>,
    /// Non-authorizing bindings.
    pub bindings: Vec<PrincipalBinding>,
    /// Redacted proof references.
    pub proof_refs: Vec<PrincipalProofRef>,
    /// Display-only fields.
    pub display: Option<PrincipalDisplay>,
    /// Non-authorizing metadata subject to reserved-key rejection.
    pub metadata: BTreeMap<String, serde_json::Value>,
    /// Request timestamp used for created/updated/event times.
    pub requested_at: OffsetDateTime,
    /// Structured reason code recorded in lifecycle history.
    pub reason_code: String,
    /// Optional actor attribution.
    pub actor_principal_id: Option<PrincipalId>,
}

/// Result of an accepted Principal Registry mutation.
#[derive(Clone, Debug, PartialEq)]
pub struct IdentityMutation {
    /// Principal snapshot after the accepted mutation.
    pub principal: Principal,
    /// Immutable lifecycle event produced by the mutation.
    pub event: IdentityLifecycleEvent,
}

/// Principal Registry lifecycle service over a storage-only registry seam.
pub struct IdentityRegistry<S> {
    store: S,
}

impl<S> IdentityRegistry<S>
where
    S: PrincipalRegistryStore,
{
    /// Creates a lifecycle registry using the given storage seam.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Returns a shared reference to the underlying storage seam.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Registers a new principal in `pending` status.
    pub fn register(
        &self,
        command: RegisterPrincipal,
    ) -> Result<IdentityMutation, IdentityRegistryError> {
        validate_principal_id(&command.principal_id)?;
        validate_owner_ids(
            command.owner_tenant_id.as_ref(),
            command.owner_fleet_id.as_ref(),
        )?;
        validate_bindings(&command.bindings)?;
        validate_proofs(&command.proof_refs)?;
        validate_optional_actor_principal_id(command.actor_principal_id.as_ref())?;
        validate_display(command.display.as_ref())?;
        validate_reason_code(&command.reason_code)?;
        validate_extension_map(&command.metadata, "principal.metadata")?;
        validate_metadata_values(&command.metadata)?;

        let principal = Principal {
            principal_id: command.principal_id.clone(),
            kind: command.kind,
            status: PrincipalStatus::Pending,
            revision: IdentityRevision::initial(),
            owner_tenant_id: command.owner_tenant_id,
            owner_fleet_id: command.owner_fleet_id,
            bindings: command.bindings,
            proof_refs: command.proof_refs,
            display: command.display,
            metadata: command.metadata,
            created_at: command.requested_at,
            updated_at: command.requested_at,
            superseded_by: None,
        };
        let event = lifecycle_event(LifecycleEventInput {
            principal_id: principal.principal_id.clone(),
            previous_revision: None,
            new_revision: principal.revision,
            event_kind: IdentityLifecycleEventKind::Registered,
            previous_status: None,
            new_status: Some(principal.status),
            actor_principal_id: command.actor_principal_id,
            reason_code: command.reason_code,
            proof_digest: None,
            evidence_refs: Vec::new(),
            occurred_at: command.requested_at,
        });
        self.store
            .create_principal(principal.clone(), event.clone())?;
        Ok(IdentityMutation { principal, event })
    }

    /// Activates a pending or suspended principal after expected-revision CAS.
    pub fn activate(
        &self,
        principal_id: &PrincipalId,
        expected_revision: IdentityRevision,
        reason_code: impl Into<String>,
    ) -> Result<IdentityMutation, IdentityRegistryError> {
        self.transition_status(
            principal_id,
            expected_revision,
            PrincipalStatus::Active,
            IdentityLifecycleEventKind::Activated,
            reason_code.into(),
        )
    }

    /// Suspends an active principal after expected-revision CAS.
    pub fn suspend(
        &self,
        principal_id: &PrincipalId,
        expected_revision: IdentityRevision,
        reason_code: impl Into<String>,
    ) -> Result<IdentityMutation, IdentityRegistryError> {
        self.transition_status(
            principal_id,
            expected_revision,
            PrincipalStatus::Suspended,
            IdentityLifecycleEventKind::Suspended,
            reason_code.into(),
        )
    }

    /// Revokes a pending, active, or suspended principal after expected-revision CAS.
    pub fn revoke(
        &self,
        principal_id: &PrincipalId,
        expected_revision: IdentityRevision,
        reason_code: impl Into<String>,
    ) -> Result<IdentityMutation, IdentityRegistryError> {
        self.transition_status(
            principal_id,
            expected_revision,
            PrincipalStatus::Revoked,
            IdentityLifecycleEventKind::Revoked,
            reason_code.into(),
        )
    }

    /// Rotates proof evidence for a non-revoked principal. The event records only
    /// proof digest and evidence references, never raw credential material.
    pub fn rotate_proof(
        &self,
        principal_id: &PrincipalId,
        expected_revision: IdentityRevision,
        new_proof_ref: PrincipalProofRef,
        reason_code: impl Into<String>,
    ) -> Result<IdentityMutation, IdentityRegistryError> {
        let reason_code = reason_code.into();
        validate_reason_code(&reason_code)?;
        validate_proofs(std::slice::from_ref(&new_proof_ref))?;
        let current = self.load_expected(principal_id, expected_revision)?;
        if current.status == PrincipalStatus::Revoked {
            return Err(IdentityRegistryError::RevokedPrincipal {
                principal_id: principal_id.clone(),
            });
        }

        let now = OffsetDateTime::now_utc();
        let previous_revision = current.revision;
        let proof_digest = new_proof_ref.proof_digest.clone();
        let evidence_refs = new_proof_ref.evidence_refs.clone();
        let mut next = current.clone();
        next.revision = previous_revision.next();
        next.updated_at = now;
        next.proof_refs.push(new_proof_ref);
        let event = lifecycle_event(LifecycleEventInput {
            principal_id: next.principal_id.clone(),
            previous_revision: Some(previous_revision),
            new_revision: next.revision,
            event_kind: IdentityLifecycleEventKind::ProofRotated,
            previous_status: Some(current.status),
            new_status: Some(next.status),
            actor_principal_id: None,
            reason_code,
            proof_digest: Some(proof_digest),
            evidence_refs,
            occurred_at: now,
        });
        self.store
            .compare_and_swap_revision(next.clone(), expected_revision, event.clone())?;
        Ok(IdentityMutation {
            principal: next,
            event,
        })
    }

    /// Records supersession by another principal without rewriting attribution.
    pub fn supersede(
        &self,
        principal_id: &PrincipalId,
        expected_revision: IdentityRevision,
        superseded_by: PrincipalId,
        reason_code: impl Into<String>,
    ) -> Result<IdentityMutation, IdentityRegistryError> {
        let reason_code = reason_code.into();
        validate_reason_code(&reason_code)?;
        validate_principal_id(&superseded_by)?;
        let current = self.load_expected(principal_id, expected_revision)?;
        if current.status == PrincipalStatus::Revoked {
            return Err(IdentityRegistryError::RevokedPrincipal {
                principal_id: principal_id.clone(),
            });
        }
        let now = OffsetDateTime::now_utc();
        let previous_revision = current.revision;
        let mut next = current.clone();
        next.revision = previous_revision.next();
        next.updated_at = now;
        next.superseded_by = Some(superseded_by);
        let event = lifecycle_event(LifecycleEventInput {
            principal_id: next.principal_id.clone(),
            previous_revision: Some(previous_revision),
            new_revision: next.revision,
            event_kind: IdentityLifecycleEventKind::Superseded,
            previous_status: Some(current.status),
            new_status: Some(next.status),
            actor_principal_id: None,
            reason_code,
            proof_digest: None,
            evidence_refs: Vec::new(),
            occurred_at: now,
        });
        self.store
            .compare_and_swap_revision(next.clone(), expected_revision, event.clone())?;
        Ok(IdentityMutation {
            principal: next,
            event,
        })
    }

    /// Loads current principal state.
    pub fn current(&self, principal_id: &PrincipalId) -> Result<Principal, IdentityRegistryError> {
        validate_principal_id(principal_id)?;
        Ok(self.store.current_principal(principal_id)?)
    }

    /// Loads immutable principal history.
    pub fn history(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<IdentityHistoryRecord>, IdentityRegistryError> {
        validate_principal_id(principal_id)?;
        Ok(self.store.history(principal_id)?)
    }

    fn transition_status(
        &self,
        principal_id: &PrincipalId,
        expected_revision: IdentityRevision,
        next_status: PrincipalStatus,
        event_kind: IdentityLifecycleEventKind,
        reason_code: String,
    ) -> Result<IdentityMutation, IdentityRegistryError> {
        validate_reason_code(&reason_code)?;
        let current = self.load_expected(principal_id, expected_revision)?;
        if !is_allowed_transition(current.status, next_status) {
            return Err(IdentityRegistryError::InvalidLifecycleTransition {
                principal_id: principal_id.clone(),
                from: current.status,
                to: next_status,
            });
        }
        if next_status == PrincipalStatus::Active && current.proof_refs.is_empty() {
            return Err(IdentityRegistryError::InvalidProofRef {
                field: "proof_refs",
            });
        }
        let now = OffsetDateTime::now_utc();
        let previous_revision = current.revision;
        let mut next = current.clone();
        next.status = next_status;
        next.revision = previous_revision.next();
        next.updated_at = now;
        let event = lifecycle_event(LifecycleEventInput {
            principal_id: next.principal_id.clone(),
            previous_revision: Some(previous_revision),
            new_revision: next.revision,
            event_kind,
            previous_status: Some(current.status),
            new_status: Some(next.status),
            actor_principal_id: None,
            reason_code,
            proof_digest: None,
            evidence_refs: Vec::new(),
            occurred_at: now,
        });
        self.store
            .compare_and_swap_revision(next.clone(), expected_revision, event.clone())?;
        Ok(IdentityMutation {
            principal: next,
            event,
        })
    }

    fn load_expected(
        &self,
        principal_id: &PrincipalId,
        expected_revision: IdentityRevision,
    ) -> Result<Principal, IdentityRegistryError> {
        validate_principal_id(principal_id)?;
        let principal = self.store.current_principal(principal_id)?;
        if principal.revision != expected_revision {
            return Err(IdentityRegistryError::RevisionConflict {
                principal_id: principal_id.clone(),
                expected: expected_revision,
                actual: principal.revision,
            });
        }
        Ok(principal)
    }
}

fn validate_principal_id(principal_id: &PrincipalId) -> Result<(), IdentityRegistryError> {
    if principal_id.is_nil() {
        return Err(IdentityRegistryError::InvalidPrincipalId);
    }
    Ok(())
}

fn validate_optional_actor_principal_id(
    actor_principal_id: Option<&PrincipalId>,
) -> Result<(), IdentityRegistryError> {
    if actor_principal_id.is_some_and(PrincipalId::is_nil) {
        return Err(IdentityRegistryError::InvalidActorPrincipalId);
    }
    Ok(())
}

fn validate_owner_ids(
    owner_tenant_id: Option<&TenantId>,
    owner_fleet_id: Option<&FleetId>,
) -> Result<(), IdentityRegistryError> {
    if owner_tenant_id.is_some_and(TenantId::is_nil) {
        return Err(IdentityRegistryError::InvalidBinding {
            field: "owner_tenant_id",
        });
    }
    if owner_fleet_id.is_some_and(FleetId::is_nil) {
        return Err(IdentityRegistryError::InvalidBinding {
            field: "owner_fleet_id",
        });
    }
    Ok(())
}

fn validate_display(display: Option<&PrincipalDisplay>) -> Result<(), IdentityRegistryError> {
    if let Some(display) = display {
        validate_optional_non_credential_text(
            "display.display_name",
            display.display_name.as_deref(),
        )?;
        validate_optional_non_credential_text(
            "display.description",
            display.description.as_deref(),
        )?;
    }
    Ok(())
}

fn validate_reason_code(value: &str) -> Result<(), IdentityRegistryError> {
    validate_non_credential_text("reason_code", value)
}

fn validate_optional_non_credential_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), IdentityRegistryError> {
    if let Some(value) = value {
        validate_non_credential_text(field, value)?;
    }
    Ok(())
}

fn validate_non_credential_text(
    field: &'static str,
    value: &str,
) -> Result<(), IdentityRegistryError> {
    if value.trim().is_empty() || value.trim() != value || contains_credential_material(value) {
        return Err(IdentityRegistryError::CredentialMaterial { field });
    }
    Ok(())
}

fn validate_metadata_values(
    metadata: &BTreeMap<String, serde_json::Value>,
) -> Result<(), IdentityRegistryError> {
    for value in metadata.values() {
        validate_metadata_value(value)?;
    }
    Ok(())
}

fn validate_metadata_value(value: &serde_json::Value) -> Result<(), IdentityRegistryError> {
    match value {
        serde_json::Value::String(value) if contains_credential_material(value) => {
            Err(IdentityRegistryError::CredentialMaterial {
                field: "principal.metadata",
            })
        }
        serde_json::Value::Array(values) => {
            for child in values {
                validate_metadata_value(child)?;
            }
            Ok(())
        }
        serde_json::Value::Object(values) => {
            for child in values.values() {
                validate_metadata_value(child)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_bindings(bindings: &[PrincipalBinding]) -> Result<(), IdentityRegistryError> {
    for binding in bindings {
        match binding {
            PrincipalBinding::Tenant { tenant_id } if tenant_id.is_nil() => {
                return Err(IdentityRegistryError::InvalidBinding { field: "tenant_id" });
            }
            PrincipalBinding::Fleet { fleet_id } if fleet_id.is_nil() => {
                return Err(IdentityRegistryError::InvalidBinding { field: "fleet_id" });
            }
            PrincipalBinding::Node { node_id } if node_id.is_nil() => {
                return Err(IdentityRegistryError::InvalidBinding { field: "node_id" });
            }
            PrincipalBinding::Instance { instance_id } if instance_id.is_nil() => {
                return Err(IdentityRegistryError::InvalidBinding {
                    field: "instance_id",
                });
            }
            PrincipalBinding::Agent { agent_id } if agent_id.is_nil() => {
                return Err(IdentityRegistryError::InvalidBinding { field: "agent_id" });
            }
            PrincipalBinding::Run { run_id } if run_id.is_nil() => {
                return Err(IdentityRegistryError::InvalidBinding { field: "run_id" });
            }
            PrincipalBinding::ExternalSubject {
                provider,
                issuer,
                subject,
                audience,
            } => {
                validate_external_subject_part("provider", provider)?;
                validate_external_subject_part("issuer", issuer)?;
                validate_external_subject_part("subject", subject)?;
                validate_external_subject_part("audience", audience)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_external_subject_part(
    field: &'static str,
    value: &str,
) -> Result<(), IdentityRegistryError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(IdentityRegistryError::InvalidExternalSubject { field });
    }
    Ok(())
}

fn validate_proofs(proof_refs: &[PrincipalProofRef]) -> Result<(), IdentityRegistryError> {
    for proof in proof_refs {
        if proof.proof_ref_id.is_nil() {
            return Err(IdentityRegistryError::InvalidProofRef {
                field: "proof_ref_id",
            });
        }
        validate_safe_proof_descriptor("proof_kind", &proof.proof_kind)?;
        validate_optional_safe_proof_descriptor("provider", proof.provider.as_deref())?;
        validate_optional_safe_proof_descriptor("issuer", proof.issuer.as_deref())?;
        validate_optional_safe_proof_descriptor("subject", proof.subject.as_deref())?;
        validate_optional_safe_proof_descriptor("audience", proof.audience.as_deref())?;
        validate_optional_safe_proof_descriptor("key_id", proof.key_id.as_deref())?;
        let digest_algorithm = validate_digest_algorithm(&proof.digest_algorithm)?;
        validate_proof_digest(&digest_algorithm, &proof.proof_digest)?;
        for evidence_ref in &proof.evidence_refs {
            validate_evidence_ref(evidence_ref)?;
        }
    }
    Ok(())
}

fn validate_optional_safe_proof_descriptor(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), IdentityRegistryError> {
    if let Some(value) = value {
        validate_safe_proof_descriptor(field, value)?;
    }
    Ok(())
}

fn validate_safe_proof_descriptor(
    field: &'static str,
    value: &str,
) -> Result<(), IdentityRegistryError> {
    if value.trim().is_empty() || value.trim() != value || contains_credential_material(value) {
        return Err(IdentityRegistryError::InvalidProofRef { field });
    }
    Ok(())
}

fn validate_digest_algorithm(value: &str) -> Result<String, IdentityRegistryError> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized != value || !ALLOWED_PROOF_DIGEST_ALGORITHMS.contains(&normalized.as_str()) {
        return Err(IdentityRegistryError::InvalidProofRef {
            field: "digest_algorithm",
        });
    }
    Ok(normalized)
}

fn validate_proof_digest(digest_algorithm: &str, value: &str) -> Result<(), IdentityRegistryError> {
    if value.trim().is_empty() || value.trim() != value || contains_credential_material(value) {
        return Err(IdentityRegistryError::InvalidProofRef {
            field: "proof_digest",
        });
    }

    let expected_prefix = format!("{digest_algorithm}:");
    let digest = value.strip_prefix(&expected_prefix).unwrap_or(value);
    let expected_len = match digest_algorithm {
        "blake3" | "sha256" => 64,
        "sha512" => 128,
        _ => {
            return Err(IdentityRegistryError::InvalidProofRef {
                field: "digest_algorithm",
            })
        }
    };
    if digest.len() != expected_len
        || !digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(IdentityRegistryError::InvalidProofRef {
            field: "proof_digest",
        });
    }
    Ok(())
}

fn validate_evidence_ref(value: &str) -> Result<(), IdentityRegistryError> {
    if value.trim().is_empty() || value.trim() != value || contains_credential_material(value) {
        return Err(IdentityRegistryError::InvalidProofRef {
            field: "evidence_refs",
        });
    }
    let Some(body) = ALLOWED_EVIDENCE_REF_PREFIXES
        .iter()
        .find_map(|prefix| value.strip_prefix(prefix))
    else {
        return Err(IdentityRegistryError::InvalidProofRef {
            field: "evidence_refs",
        });
    };

    if body.is_empty()
        || contains_credential_material(body)
        || !body.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, ':' | '_' | '-' | '/')
        })
    {
        return Err(IdentityRegistryError::InvalidProofRef {
            field: "evidence_refs",
        });
    }
    Ok(())
}

fn contains_credential_material(value: &str) -> bool {
    let normalized = value
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(' ', "_");
    CREDENTIAL_MATERIAL_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
        || looks_like_jwt(value)
}

fn looks_like_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.chars().all(|character| {
                    character.is_ascii_alphanumeric() || character == '-' || character == '_'
                })
        })
}

fn is_allowed_transition(from: PrincipalStatus, to: PrincipalStatus) -> bool {
    matches!(
        (from, to),
        (PrincipalStatus::Pending, PrincipalStatus::Active)
            | (PrincipalStatus::Pending, PrincipalStatus::Revoked)
            | (PrincipalStatus::Active, PrincipalStatus::Suspended)
            | (PrincipalStatus::Active, PrincipalStatus::Revoked)
            | (PrincipalStatus::Suspended, PrincipalStatus::Active)
            | (PrincipalStatus::Suspended, PrincipalStatus::Revoked)
    )
}

struct LifecycleEventInput {
    principal_id: PrincipalId,
    previous_revision: Option<IdentityRevision>,
    new_revision: IdentityRevision,
    event_kind: IdentityLifecycleEventKind,
    previous_status: Option<PrincipalStatus>,
    new_status: Option<PrincipalStatus>,
    actor_principal_id: Option<PrincipalId>,
    reason_code: String,
    proof_digest: Option<String>,
    evidence_refs: Vec<String>,
    occurred_at: OffsetDateTime,
}

fn lifecycle_event(input: LifecycleEventInput) -> IdentityLifecycleEvent {
    IdentityLifecycleEvent {
        identity_event_id: IdentityEventId::new(),
        principal_id: input.principal_id,
        previous_revision: input.previous_revision,
        new_revision: input.new_revision,
        event_kind: input.event_kind,
        previous_status: input.previous_status,
        new_status: input.new_status,
        actor_principal_id: input.actor_principal_id,
        reason_code: input.reason_code,
        proof_digest: input.proof_digest,
        evidence_refs: input.evidence_refs,
        occurred_at: input.occurred_at,
        recorded_at: OffsetDateTime::now_utc(),
    }
}

/// Identity lifecycle decision failures.
#[derive(Debug, Error)]
pub enum IdentityRegistryError {
    /// Nil principal IDs cannot be registered, queried, or mutated.
    #[error("principal_id must not be nil")]
    InvalidPrincipalId,
    /// Nil actor principal IDs cannot be recorded into lifecycle events.
    #[error("actor_principal_id must not be nil")]
    InvalidActorPrincipalId,
    /// A typed binding ID was nil or malformed.
    #[error("invalid principal binding field {field}")]
    InvalidBinding { field: &'static str },
    /// External subject tuple was missing a canonical part.
    #[error("invalid external subject field {field}")]
    InvalidExternalSubject { field: &'static str },
    /// Proof reference was missing a redacted identifier or digest field.
    #[error("invalid proof reference field {field}")]
    InvalidProofRef { field: &'static str },
    /// Credential-like material was supplied in a principal field that is persisted in records or lifecycle events.
    #[error("credential-like material is not allowed in principal field {field}")]
    CredentialMaterial { field: &'static str },
    /// The requested lifecycle transition is not legal.
    #[error("invalid principal lifecycle transition for {principal_id}: {from:?} -> {to:?}")]
    InvalidLifecycleTransition {
        principal_id: PrincipalId,
        from: PrincipalStatus,
        to: PrincipalStatus,
    },
    /// Revoked principals are terminal and cannot be resurrected or rotated.
    #[error("revoked principal is terminal: {principal_id}")]
    RevokedPrincipal { principal_id: PrincipalId },
    /// Expected revision was stale before mutation.
    #[error("principal {principal_id} revision conflict: expected {expected:?}, found {actual:?}")]
    RevisionConflict {
        principal_id: PrincipalId,
        expected: IdentityRevision,
        actual: IdentityRevision,
    },
    /// Metadata included reserved authority, credential, gateway, verifier, or similar keys.
    #[error("principal metadata rejected: {0}")]
    Metadata(#[from] splendor_types::ExtensionValidationError),
    /// Underlying storage-only CAS/history failure.
    #[error("principal registry store error: {0}")]
    Store(#[from] PrincipalRegistryStoreError),
}

#[cfg(test)]
#[path = "../tests/unit/identity_tests.rs"]
mod tests;
