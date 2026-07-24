//! Deterministic in-memory Secret Provider for tests and explicit local use.
//!
//! The provider opens no listener, has no environment fallback, and cannot be
//! constructed in resident, remote, fleet, production, or unknown mode. Its
//! `SecretProvider` request types have no public constructors, so this adapter
//! does not expose an independent material-resolution API.

use splendor_authority::{
    SecretMaterial, SecretProvider, SecretProviderAuditEvidence, SecretProviderControlRequest,
    SecretProviderError, SecretProviderErrorCode, SecretProviderFetchRequest,
    SecretProviderFetchResult, SecretProviderHealthEvidence, SecretProviderOperation,
    SecretProviderOutcome,
};
use splendor_types::{
    CanonicalTimestampV1, EffectCertainty, SecretProviderAuditId, SecretProviderId,
    SecretProviderVersionRef, SecretRefId, TenantId,
};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use zeroize::Zeroizing;

const MAX_MATERIAL_BYTES: usize = 65_536;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Explicit runtime modes accepted or rejected by the test/dev provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemorySecretProviderRuntimeMode {
    Test,
    LocalDevelopment,
    Resident,
    Remote,
    Fleet,
    Production,
    Unknown,
}

/// Fixed adapter configuration failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemorySecretProviderConfigError {
    UnsupportedRuntimeMode,
    InvalidCoordinates,
    InvalidMaterial,
    DuplicateEntry,
    EntryNotAvailable,
    StateUnavailable,
}

impl MemorySecretProviderConfigError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedRuntimeMode => "memory_secret_provider_runtime_mode_unsupported",
            Self::InvalidCoordinates => "memory_secret_provider_coordinates_invalid",
            Self::InvalidMaterial => "memory_secret_provider_material_invalid",
            Self::DuplicateEntry => "memory_secret_provider_entry_duplicate",
            Self::EntryNotAvailable => "memory_secret_provider_entry_not_available",
            Self::StateUnavailable => "memory_secret_provider_state_unavailable",
        }
    }
}

impl fmt::Display for MemorySecretProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for MemorySecretProviderConfigError {}

/// Test/dev-only deterministic provider implementation.
pub struct MemorySecretProvider {
    provider_id: SecretProviderId,
    state: Mutex<MemoryProviderState>,
    fetch_calls: AtomicU64,
    control_calls: AtomicU64,
}

#[derive(Default)]
struct MemoryProviderState {
    available: bool,
    entries: HashMap<MemoryEntryKey, MemoryEntry>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct MemoryEntryKey {
    tenant_id: TenantId,
    secret_ref_id: SecretRefId,
    secret_ref_revision: u64,
    provider_version_ref: SecretProviderVersionRef,
}

struct MemoryEntry {
    material: Zeroizing<Vec<u8>>,
    revoked: bool,
}

struct FetchCoordinates<'a> {
    provider_id: &'a SecretProviderId,
    tenant_id: &'a TenantId,
    secret_ref_id: &'a SecretRefId,
    secret_ref_revision: u64,
    provider_version_ref: &'a SecretProviderVersionRef,
}

struct AuditCoordinates<'a> {
    provider_audit_id: &'a SecretProviderAuditId,
    provider_id: &'a SecretProviderId,
    tenant_id: &'a TenantId,
    secret_ref_id: &'a SecretRefId,
    secret_ref_revision: u64,
    provider_version_ref: &'a SecretProviderVersionRef,
    observed_at: &'a CanonicalTimestampV1,
}

impl MemorySecretProvider {
    /// Constructs only in explicit test or local-development mode.
    pub fn try_new(
        provider_id: SecretProviderId,
        mode: MemorySecretProviderRuntimeMode,
    ) -> Result<Self, MemorySecretProviderConfigError> {
        if !matches!(
            mode,
            MemorySecretProviderRuntimeMode::Test
                | MemorySecretProviderRuntimeMode::LocalDevelopment
        ) {
            return Err(MemorySecretProviderConfigError::UnsupportedRuntimeMode);
        }
        Ok(Self {
            provider_id,
            state: Mutex::new(MemoryProviderState {
                available: true,
                entries: HashMap::new(),
            }),
            fetch_calls: AtomicU64::new(0),
            control_calls: AtomicU64::new(0),
        })
    }

    /// Installs one exact synthetic test/dev material version. This is startup
    /// configuration, not a workload or policy resolution API.
    pub fn insert_synthetic(
        &self,
        tenant_id: TenantId,
        secret_ref_id: SecretRefId,
        secret_ref_revision: u64,
        provider_version_ref: SecretProviderVersionRef,
        material: Vec<u8>,
    ) -> Result<(), MemorySecretProviderConfigError> {
        validate_tenant(&tenant_id)?;
        validate_revision(secret_ref_revision)?;
        validate_material(&material)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| MemorySecretProviderConfigError::StateUnavailable)?;
        let key = MemoryEntryKey {
            tenant_id,
            secret_ref_id,
            secret_ref_revision,
            provider_version_ref,
        };
        if state.entries.contains_key(&key) {
            return Err(MemorySecretProviderConfigError::DuplicateEntry);
        }
        state.entries.insert(
            key,
            MemoryEntry {
                material: Zeroizing::new(material),
                revoked: false,
            },
        );
        Ok(())
    }

    /// Rotates to a new exact version and marks the old provider entry revoked.
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_synthetic(
        &self,
        tenant_id: TenantId,
        secret_ref_id: SecretRefId,
        secret_ref_revision: u64,
        old_provider_version_ref: &SecretProviderVersionRef,
        new_provider_version_ref: SecretProviderVersionRef,
        material: Vec<u8>,
    ) -> Result<(), MemorySecretProviderConfigError> {
        validate_tenant(&tenant_id)?;
        validate_revision(secret_ref_revision)?;
        validate_material(&material)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| MemorySecretProviderConfigError::StateUnavailable)?;
        let old_key = MemoryEntryKey {
            tenant_id: tenant_id.clone(),
            secret_ref_id: secret_ref_id.clone(),
            secret_ref_revision,
            provider_version_ref: old_provider_version_ref.clone(),
        };
        let new_key = MemoryEntryKey {
            tenant_id,
            secret_ref_id,
            secret_ref_revision,
            provider_version_ref: new_provider_version_ref,
        };
        if state.entries.contains_key(&new_key) {
            return Err(MemorySecretProviderConfigError::DuplicateEntry);
        }
        let old = state
            .entries
            .get_mut(&old_key)
            .ok_or(MemorySecretProviderConfigError::EntryNotAvailable)?;
        old.revoked = true;
        state.entries.insert(
            new_key,
            MemoryEntry {
                material: Zeroizing::new(material),
                revoked: false,
            },
        );
        Ok(())
    }

    /// Enables deterministic outage injection.
    pub fn set_available(&self, available: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.available = available;
        }
    }

    /// Number of provider fetch-port calls.
    pub fn fetch_call_count(&self) -> u64 {
        self.fetch_calls.load(Ordering::SeqCst)
    }

    /// Number of non-fetch provider control calls.
    pub fn control_call_count(&self) -> u64 {
        self.control_calls.load(Ordering::SeqCst)
    }

    fn fetch_coordinates(
        &self,
        coordinates: FetchCoordinates<'_>,
    ) -> Result<SecretMaterial, SecretProviderError> {
        self.with_entry(coordinates, |entry| {
            SecretMaterial::try_new(entry.material.as_slice().to_vec())
        })
    }

    fn fetch_scoped(
        &self,
        coordinates: FetchCoordinates<'_>,
        audit: AuditCoordinates<'_>,
    ) -> Result<SecretProviderFetchResult, SecretProviderError> {
        self.fetch_calls.fetch_add(1, Ordering::SeqCst);
        let material = self.fetch_coordinates(coordinates)?;
        let audit = audit_evidence(
            audit,
            SecretProviderOperation::Fetch,
            SecretProviderOutcome::Succeeded,
            EffectCertainty::Known,
        )?;
        SecretProviderFetchResult::try_new(material, audit)
    }

    fn with_entry<R>(
        &self,
        coordinates: FetchCoordinates<'_>,
        inspect: impl FnOnce(&MemoryEntry) -> Result<R, SecretProviderError>,
    ) -> Result<R, SecretProviderError> {
        if coordinates.provider_id != &self.provider_id {
            return Err(provider_error(SecretProviderErrorCode::VersionNotAvailable));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| provider_error(SecretProviderErrorCode::InternalFailure))?;
        if !state.available {
            return Err(provider_error(SecretProviderErrorCode::Unavailable));
        }
        let key = MemoryEntryKey {
            tenant_id: coordinates.tenant_id.clone(),
            secret_ref_id: coordinates.secret_ref_id.clone(),
            secret_ref_revision: coordinates.secret_ref_revision,
            provider_version_ref: coordinates.provider_version_ref.clone(),
        };
        let entry = state
            .entries
            .get(&key)
            .ok_or_else(|| provider_error(SecretProviderErrorCode::VersionNotAvailable))?;
        if entry.revoked {
            return Err(provider_error(SecretProviderErrorCode::Revoked));
        }
        inspect(entry)
    }

    fn inspect_control_scoped(
        &self,
        coordinates: FetchCoordinates<'_>,
        audit: AuditCoordinates<'_>,
        operation: SecretProviderOperation,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.control_calls.fetch_add(1, Ordering::SeqCst);
        self.with_entry(coordinates, |_| Ok(()))?;
        audit_evidence(
            audit,
            operation,
            SecretProviderOutcome::Succeeded,
            EffectCertainty::Known,
        )
    }

    fn revoke_scoped(
        &self,
        coordinates: FetchCoordinates<'_>,
        audit: AuditCoordinates<'_>,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.control_calls.fetch_add(1, Ordering::SeqCst);
        if coordinates.provider_id != &self.provider_id {
            return Err(provider_error(SecretProviderErrorCode::VersionNotAvailable));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| provider_error(SecretProviderErrorCode::InternalFailure))?;
        if !state.available {
            return Err(provider_error(SecretProviderErrorCode::Unavailable));
        }
        let key = MemoryEntryKey {
            tenant_id: coordinates.tenant_id.clone(),
            secret_ref_id: coordinates.secret_ref_id.clone(),
            secret_ref_revision: coordinates.secret_ref_revision,
            provider_version_ref: coordinates.provider_version_ref.clone(),
        };
        let entry = state
            .entries
            .get_mut(&key)
            .ok_or_else(|| provider_error(SecretProviderErrorCode::VersionNotAvailable))?;
        entry.revoked = true;
        audit_evidence(
            audit,
            SecretProviderOperation::Revoke,
            SecretProviderOutcome::Succeeded,
            EffectCertainty::Known,
        )
    }

    fn health_scoped(
        &self,
        provider_id: &SecretProviderId,
        observed_at: &CanonicalTimestampV1,
    ) -> Result<SecretProviderHealthEvidence, SecretProviderError> {
        self.control_calls.fetch_add(1, Ordering::SeqCst);
        if provider_id != &self.provider_id {
            return Err(provider_error(SecretProviderErrorCode::VersionNotAvailable));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| provider_error(SecretProviderErrorCode::InternalFailure))?;
        Ok(SecretProviderHealthEvidence::new(
            self.provider_id.clone(),
            state.available,
            observed_at.clone(),
        ))
    }
}

impl fmt::Debug for MemorySecretProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemorySecretProvider")
            .field("provider_id", &self.provider_id)
            .field("state", &"<redacted>")
            .finish()
    }
}

impl SecretProvider for MemorySecretProvider {
    fn provider_id(&self) -> &SecretProviderId {
        &self.provider_id
    }

    fn fetch(
        &self,
        request: &SecretProviderFetchRequest,
    ) -> Result<SecretProviderFetchResult, SecretProviderError> {
        self.fetch_scoped(fetch_coordinates(request), audit_coordinates(request))
    }

    fn renew(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.inspect_control_scoped(
            control_coordinates(request),
            control_audit_coordinates(request),
            SecretProviderOperation::Renew,
        )
    }

    fn revoke(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.revoke_scoped(
            control_coordinates(request),
            control_audit_coordinates(request),
        )
    }

    fn audit(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.inspect_control_scoped(
            control_coordinates(request),
            control_audit_coordinates(request),
            SecretProviderOperation::Audit,
        )
    }

    fn health(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderHealthEvidence, SecretProviderError> {
        self.health_scoped(request.secret_provider_id(), request.requested_at())
    }
}

fn validate_material(material: &[u8]) -> Result<(), MemorySecretProviderConfigError> {
    if material.is_empty() || material.len() > MAX_MATERIAL_BYTES {
        Err(MemorySecretProviderConfigError::InvalidMaterial)
    } else {
        Ok(())
    }
}

fn validate_revision(secret_ref_revision: u64) -> Result<(), MemorySecretProviderConfigError> {
    if (1..=MAX_SAFE_INTEGER).contains(&secret_ref_revision) {
        Ok(())
    } else {
        Err(MemorySecretProviderConfigError::InvalidCoordinates)
    }
}

fn validate_tenant(tenant_id: &TenantId) -> Result<(), MemorySecretProviderConfigError> {
    if tenant_id.is_nil() {
        Err(MemorySecretProviderConfigError::InvalidCoordinates)
    } else {
        Ok(())
    }
}

fn provider_error(code: SecretProviderErrorCode) -> SecretProviderError {
    SecretProviderError::new(code)
}

fn fetch_coordinates(request: &SecretProviderFetchRequest) -> FetchCoordinates<'_> {
    FetchCoordinates {
        provider_id: request.secret_provider_id(),
        tenant_id: request.tenant_id(),
        secret_ref_id: request.secret_ref_id(),
        secret_ref_revision: request.secret_ref_revision(),
        provider_version_ref: request.provider_version_ref(),
    }
}

fn audit_coordinates(request: &SecretProviderFetchRequest) -> AuditCoordinates<'_> {
    AuditCoordinates {
        provider_audit_id: request.provider_audit_id(),
        provider_id: request.secret_provider_id(),
        tenant_id: request.tenant_id(),
        secret_ref_id: request.secret_ref_id(),
        secret_ref_revision: request.secret_ref_revision(),
        provider_version_ref: request.provider_version_ref(),
        observed_at: request.requested_at(),
    }
}

fn control_coordinates(request: &SecretProviderControlRequest) -> FetchCoordinates<'_> {
    FetchCoordinates {
        provider_id: request.secret_provider_id(),
        tenant_id: request.tenant_id(),
        secret_ref_id: request.secret_ref_id(),
        secret_ref_revision: request.secret_ref_revision(),
        provider_version_ref: request.provider_version_ref(),
    }
}

fn control_audit_coordinates(request: &SecretProviderControlRequest) -> AuditCoordinates<'_> {
    AuditCoordinates {
        provider_audit_id: request.provider_audit_id(),
        provider_id: request.secret_provider_id(),
        tenant_id: request.tenant_id(),
        secret_ref_id: request.secret_ref_id(),
        secret_ref_revision: request.secret_ref_revision(),
        provider_version_ref: request.provider_version_ref(),
        observed_at: request.requested_at(),
    }
}

fn audit_evidence(
    coordinates: AuditCoordinates<'_>,
    operation: SecretProviderOperation,
    outcome: SecretProviderOutcome,
    effect_certainty: EffectCertainty,
) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
    SecretProviderAuditEvidence::try_new(
        coordinates.provider_audit_id.clone(),
        coordinates.provider_id.clone(),
        coordinates.tenant_id.clone(),
        coordinates.secret_ref_id.clone(),
        coordinates.secret_ref_revision,
        coordinates.provider_version_ref.clone(),
        operation,
        outcome,
        effect_certainty,
        coordinates.observed_at.clone(),
    )
}

#[cfg(test)]
#[path = "../tests/unit/memory_provider_tests.rs"]
mod tests;
