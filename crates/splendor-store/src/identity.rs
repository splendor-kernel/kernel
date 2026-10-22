//! Storage-only Principal Registry history and current-pointer CAS.
//!
//! This first implementation is intentionally in-memory. It preserves immutable
//! revision history, one current pointer per principal, duplicate external
//! subject detection, and compare-and-swap semantics. Lifecycle legality remains
//! owned by `splendor-authority`.

use splendor_types::{
    FleetId, IdentityLifecycleEvent, IdentityRevision, Principal, PrincipalBinding, PrincipalId,
    TenantId,
};
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;

/// Immutable history record for one principal revision.
#[derive(Clone, Debug, PartialEq)]
pub struct IdentityHistoryRecord {
    /// Principal snapshot after the recorded mutation.
    pub principal: Principal,
    /// Immutable lifecycle event recorded for the mutation.
    pub event: IdentityLifecycleEvent,
}

/// Storage seam for Principal Registry current pointers and immutable history.
pub trait PrincipalRegistryStore: Send + Sync {
    /// Creates a new principal history and current pointer.
    fn create_principal(
        &self,
        principal: Principal,
        event: IdentityLifecycleEvent,
    ) -> Result<(), PrincipalRegistryStoreError>;

    /// Loads the current principal pointer.
    fn current_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Principal, PrincipalRegistryStoreError>;

    /// Appends a new immutable revision and moves the current pointer only when
    /// the stored current revision matches `expected_revision`.
    fn compare_and_swap_revision(
        &self,
        principal: Principal,
        expected_revision: IdentityRevision,
        event: IdentityLifecycleEvent,
    ) -> Result<(), PrincipalRegistryStoreError>;

    /// Returns immutable revision history for a principal.
    fn history(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<IdentityHistoryRecord>, PrincipalRegistryStoreError>;

    /// Returns current principals that exactly match a typed binding.
    ///
    /// This is a storage-only read: it does not decide lifecycle legality or
    /// authority. External subject provider/issuer/audience matching is
    /// canonicalized while subject matching remains exact.
    fn principals_by_binding(
        &self,
        binding: &PrincipalBinding,
    ) -> Result<Vec<Principal>, PrincipalRegistryStoreError>;

    /// Returns current principals owned by the tenant coordinate in deterministic
    /// order. This is an identity fact read only, not an authorization decision.
    fn principals_by_owner_tenant(
        &self,
        owner_tenant_id: &TenantId,
    ) -> Result<Vec<Principal>, PrincipalRegistryStoreError>;

    /// Returns current principals owned by the fleet coordinate in deterministic
    /// order. This is an identity fact read only, not an authorization decision.
    fn principals_by_owner_fleet(
        &self,
        owner_fleet_id: &FleetId,
    ) -> Result<Vec<Principal>, PrincipalRegistryStoreError>;
}

/// In-memory identity registry store for local contract evidence and tests.
#[derive(Default)]
pub struct InMemoryPrincipalRegistryStore {
    inner: Mutex<PrincipalRegistryState>,
}

#[derive(Default)]
struct PrincipalRegistryState {
    current: HashMap<PrincipalId, Principal>,
    history: HashMap<PrincipalId, Vec<IdentityHistoryRecord>>,
    external_subject_index: HashMap<ExternalSubjectIndexKey, PrincipalId>,
}

impl PrincipalRegistryStore for InMemoryPrincipalRegistryStore {
    fn create_principal(
        &self,
        principal: Principal,
        event: IdentityLifecycleEvent,
    ) -> Result<(), PrincipalRegistryStoreError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| PrincipalRegistryStoreError::Poisoned)?;
        if state.current.contains_key(&principal.principal_id) {
            return Err(PrincipalRegistryStoreError::PrincipalAlreadyExists {
                principal_id: principal.principal_id,
            });
        }
        ensure_event_matches(&principal, &event)?;
        let external_keys = external_subject_keys(&principal);
        state.ensure_external_subjects_available(&principal.principal_id, &external_keys)?;

        for key in external_keys {
            state
                .external_subject_index
                .insert(key, principal.principal_id.clone());
        }
        state.history.insert(
            principal.principal_id.clone(),
            vec![IdentityHistoryRecord {
                principal: principal.clone(),
                event,
            }],
        );
        state
            .current
            .insert(principal.principal_id.clone(), principal);
        Ok(())
    }

    fn current_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Principal, PrincipalRegistryStoreError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| PrincipalRegistryStoreError::Poisoned)?;
        state.current.get(principal_id).cloned().ok_or_else(|| {
            PrincipalRegistryStoreError::PrincipalNotFound {
                principal_id: principal_id.clone(),
            }
        })
    }

    fn compare_and_swap_revision(
        &self,
        principal: Principal,
        expected_revision: IdentityRevision,
        event: IdentityLifecycleEvent,
    ) -> Result<(), PrincipalRegistryStoreError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| PrincipalRegistryStoreError::Poisoned)?;
        let current = state.current.get(&principal.principal_id).ok_or_else(|| {
            PrincipalRegistryStoreError::PrincipalNotFound {
                principal_id: principal.principal_id.clone(),
            }
        })?;
        if current.revision != expected_revision {
            return Err(PrincipalRegistryStoreError::RevisionConflict {
                principal_id: principal.principal_id,
                expected: expected_revision,
                actual: current.revision,
            });
        }
        ensure_event_matches(&principal, &event)?;
        let external_keys = external_subject_keys(&principal);
        state.ensure_external_subjects_available(&principal.principal_id, &external_keys)?;

        let current_external_keys = external_subject_keys(current);
        for key in current_external_keys {
            state.external_subject_index.remove(&key);
        }
        for key in external_keys {
            state
                .external_subject_index
                .insert(key, principal.principal_id.clone());
        }
        state
            .history
            .entry(principal.principal_id.clone())
            .or_default()
            .push(IdentityHistoryRecord {
                principal: principal.clone(),
                event,
            });
        state
            .current
            .insert(principal.principal_id.clone(), principal);
        Ok(())
    }

    fn history(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<IdentityHistoryRecord>, PrincipalRegistryStoreError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| PrincipalRegistryStoreError::Poisoned)?;
        state.history.get(principal_id).cloned().ok_or_else(|| {
            PrincipalRegistryStoreError::PrincipalNotFound {
                principal_id: principal_id.clone(),
            }
        })
    }

    fn principals_by_binding(
        &self,
        binding: &PrincipalBinding,
    ) -> Result<Vec<Principal>, PrincipalRegistryStoreError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| PrincipalRegistryStoreError::Poisoned)?;
        let mut matches: Vec<Principal> = state
            .current
            .values()
            .filter(|principal| {
                principal
                    .bindings
                    .iter()
                    .any(|candidate| binding_matches(candidate, binding))
            })
            .cloned()
            .collect();
        sort_principals(&mut matches);
        Ok(matches)
    }

    fn principals_by_owner_tenant(
        &self,
        owner_tenant_id: &TenantId,
    ) -> Result<Vec<Principal>, PrincipalRegistryStoreError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| PrincipalRegistryStoreError::Poisoned)?;
        let mut matches: Vec<Principal> = state
            .current
            .values()
            .filter(|principal| principal.owner_tenant_id.as_ref() == Some(owner_tenant_id))
            .cloned()
            .collect();
        sort_principals(&mut matches);
        Ok(matches)
    }

    fn principals_by_owner_fleet(
        &self,
        owner_fleet_id: &FleetId,
    ) -> Result<Vec<Principal>, PrincipalRegistryStoreError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| PrincipalRegistryStoreError::Poisoned)?;
        let mut matches: Vec<Principal> = state
            .current
            .values()
            .filter(|principal| principal.owner_fleet_id.as_ref() == Some(owner_fleet_id))
            .cloned()
            .collect();
        sort_principals(&mut matches);
        Ok(matches)
    }
}

fn sort_principals(principals: &mut [Principal]) {
    principals.sort_by_key(|principal| principal.principal_id.to_string());
}

fn binding_matches(candidate: &PrincipalBinding, query: &PrincipalBinding) -> bool {
    match (candidate, query) {
        (
            PrincipalBinding::Tenant { tenant_id: left },
            PrincipalBinding::Tenant { tenant_id: right },
        ) => left == right,
        (
            PrincipalBinding::Fleet { fleet_id: left },
            PrincipalBinding::Fleet { fleet_id: right },
        ) => left == right,
        (PrincipalBinding::Node { node_id: left }, PrincipalBinding::Node { node_id: right }) => {
            left == right
        }
        (
            PrincipalBinding::Instance { instance_id: left },
            PrincipalBinding::Instance { instance_id: right },
        ) => left == right,
        (
            PrincipalBinding::Agent { agent_id: left },
            PrincipalBinding::Agent { agent_id: right },
        ) => left == right,
        (PrincipalBinding::Run { run_id: left }, PrincipalBinding::Run { run_id: right }) => {
            left == right
        }
        (
            PrincipalBinding::ExternalSubject {
                provider: left_provider,
                issuer: left_issuer,
                subject: left_subject,
                audience: left_audience,
            },
            PrincipalBinding::ExternalSubject {
                provider: right_provider,
                issuer: right_issuer,
                subject: right_subject,
                audience: right_audience,
            },
        ) => {
            ExternalSubjectIndexKey::new(left_provider, left_issuer, left_subject, left_audience)
                == ExternalSubjectIndexKey::new(
                    right_provider,
                    right_issuer,
                    right_subject,
                    right_audience,
                )
        }
        _ => false,
    }
}

impl PrincipalRegistryState {
    fn ensure_external_subjects_available(
        &self,
        principal_id: &PrincipalId,
        keys: &[ExternalSubjectIndexKey],
    ) -> Result<(), PrincipalRegistryStoreError> {
        for key in keys {
            if let Some(existing_principal_id) = self.external_subject_index.get(key) {
                if existing_principal_id != principal_id {
                    return Err(
                        PrincipalRegistryStoreError::DuplicateExternalSubjectBinding {
                            existing_principal_id: existing_principal_id.clone(),
                        },
                    );
                }
            }
        }
        Ok(())
    }
}

fn ensure_event_matches(
    principal: &Principal,
    event: &IdentityLifecycleEvent,
) -> Result<(), PrincipalRegistryStoreError> {
    if event.principal_id != principal.principal_id {
        return Err(PrincipalRegistryStoreError::EventPrincipalMismatch {
            principal_id: principal.principal_id.clone(),
            event_principal_id: event.principal_id.clone(),
        });
    }
    if event.new_revision != principal.revision {
        return Err(PrincipalRegistryStoreError::EventRevisionMismatch {
            principal_id: principal.principal_id.clone(),
            principal_revision: principal.revision,
            event_revision: event.new_revision,
        });
    }
    Ok(())
}

fn external_subject_keys(principal: &Principal) -> Vec<ExternalSubjectIndexKey> {
    principal
        .bindings
        .iter()
        .filter_map(|binding| match binding {
            PrincipalBinding::ExternalSubject {
                provider,
                issuer,
                subject,
                audience,
            } => Some(ExternalSubjectIndexKey::new(
                provider, issuer, subject, audience,
            )),
            _ => None,
        })
        .collect()
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ExternalSubjectIndexKey {
    provider: String,
    issuer: String,
    subject: String,
    audience: String,
}

impl ExternalSubjectIndexKey {
    fn new(provider: &str, issuer: &str, subject: &str, audience: &str) -> Self {
        Self {
            provider: provider.trim().to_ascii_lowercase(),
            issuer: issuer.trim().to_ascii_lowercase(),
            subject: subject.to_string(),
            audience: audience.trim().to_ascii_lowercase(),
        }
    }
}

/// Storage-only failures for principal registry persistence.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum PrincipalRegistryStoreError {
    /// The backing mutex was poisoned.
    #[error("principal registry store mutex was poisoned")]
    Poisoned,
    /// Current pointer already exists.
    #[error("principal already exists: {principal_id}")]
    PrincipalAlreadyExists { principal_id: PrincipalId },
    /// Current pointer was not found.
    #[error("principal was not found: {principal_id}")]
    PrincipalNotFound { principal_id: PrincipalId },
    /// Store compare-and-swap revision mismatch.
    #[error("principal {principal_id} revision conflict: expected {expected:?}, found {actual:?}")]
    RevisionConflict {
        principal_id: PrincipalId,
        expected: IdentityRevision,
        actual: IdentityRevision,
    },
    /// Another principal already owns the same canonical external subject tuple.
    #[error("duplicate external subject binding for existing principal: {existing_principal_id}")]
    DuplicateExternalSubjectBinding { existing_principal_id: PrincipalId },
    /// Lifecycle event principal ID differs from the stored principal snapshot.
    #[error("identity lifecycle event principal mismatch for {principal_id}; event had {event_principal_id}")]
    EventPrincipalMismatch {
        principal_id: PrincipalId,
        event_principal_id: PrincipalId,
    },
    /// Lifecycle event revision differs from the stored principal snapshot.
    #[error("identity lifecycle event revision mismatch for {principal_id}")]
    EventRevisionMismatch {
        principal_id: PrincipalId,
        principal_revision: IdentityRevision,
        event_revision: IdentityRevision,
    },
}

#[cfg(test)]
#[path = "../tests/unit/identity_tests.rs"]
mod tests;
