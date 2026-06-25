//! Storage-only Principal Registry history and current-pointer CAS.
//!
//! This first implementation is intentionally in-memory. It preserves immutable
//! revision history, one current pointer per principal, duplicate external
//! subject detection, and compare-and-swap semantics. Lifecycle legality remains
//! owned by `splendor-authority`.

use splendor_types::{
    IdentityLifecycleEvent, IdentityRevision, Principal, PrincipalBinding, PrincipalId,
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
                            provider: key.provider.clone(),
                            issuer: key.issuer.clone(),
                            subject: key.subject.clone(),
                            audience: key.audience.clone(),
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
            subject: subject.trim().to_string(),
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
    #[error("duplicate external subject binding for provider={provider} issuer={issuer} subject={subject} audience={audience}")]
    DuplicateExternalSubjectBinding {
        provider: String,
        issuer: String,
        subject: String,
        audience: String,
        existing_principal_id: PrincipalId,
    },
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
