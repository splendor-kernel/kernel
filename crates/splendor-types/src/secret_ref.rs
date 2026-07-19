//! Behavior-free revision-bound secret-reference contracts.
//!
//! These values are closed declarations only. Parsing, constructing,
//! serializing, or comparing them never grants authority, resolves a provider,
//! issues a lease, invokes a driver, or performs I/O.

use crate::{
    validate_driver_operation_ref_v1, DriverCredentialDestinationDigest,
    DriverOperationCredentialSinksV1, DriverOperationRef, DriverTrustedSendProfileV1,
    SecretClassification, SecretCredentialSlotId, SecretDeliveryControlKind,
    SecretDeliveryExposureProfile, SecretDeliveryMethod, SecretLeasePolicy, SecretOfflineBehavior,
    SecretProviderId, SecretProviderVersionRef, SecretRefId, SecretUseIntent, TenantId,
};
use serde::de::{DeserializeSeed, Error as DeError, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;

/// Exact schema for a revision-bearing credential authorization.
pub const SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V2: &str =
    "splendor.secret.credential_authorization.v2";

/// Exact schema for a revision-bearing secret reference.
pub const SECRET_REF_SCHEMA_V2: &str = "splendor.secret.ref.v2";

const HISTORICAL_SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V1: &str =
    "splendor.secret.credential_authorization.v1";
const HISTORICAL_SECRET_REF_SCHEMA_V1: &str = "splendor.secret.ref.v1";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_AUTHORIZATIONS: usize = 16;
const MAX_DESTINATION_DIGESTS: usize = 16;
const MAX_DELIVERY_METHODS: usize = 5;
const MAX_LABEL_BYTES: usize = 128;

const AUTHORIZATION_INGRESS_BUDGET: IngressBudget = IngressBudget {
    bytes: 8_192,
    depth: 8,
    tokens: 128,
    members: 32,
    elements: 32,
    string_bytes: 256,
};

const REF_INGRESS_BUDGET: IngressBudget = IngressBudget {
    bytes: 65_536,
    depth: 12,
    tokens: 2_048,
    members: 384,
    elements: 512,
    string_bytes: 256,
};

/// Closed, revision-bearing credential authorization declaration.
///
/// This value is not authority. It intentionally implements `Serialize` but
/// not generic `Deserialize`; untrusted bytes must use the bounded parser.
///
/// ```compile_fail
/// use splendor_types::SecretCredentialAuthorizationV2;
/// let _: SecretCredentialAuthorizationV2 = serde_json::from_slice(b"{}").unwrap();
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct SecretCredentialAuthorizationV2 {
    driver_operation: DriverOperationRef,
    driver_declaration_revision: u64,
    credential_slot_id: SecretCredentialSlotId,
    destination_schema: String,
    delivery_exposure_profile: SecretDeliveryExposureProfile,
    trusted_send_profile: DriverTrustedSendProfileV1,
    approved_destination_digests: Vec<DriverCredentialDestinationDigest>,
}

impl SecretCredentialAuthorizationV2 {
    /// Parses one untrusted authorization through the exact bounded v2 ingress.
    pub fn from_json_slice(input: &[u8]) -> Result<Self, SecretCredentialAuthorizationV2Error> {
        preflight_json(input, AUTHORIZATION_INGRESS_BUDGET).map_err(|_| {
            authorization_error(SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape)
        })?;
        let wire: AuthorizationWire = serde_json::from_slice(input).map_err(|_| {
            authorization_error(SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape)
        })?;
        parse_authorization_wire(wire)
    }

    /// Constructs one validated declaration from already typed owner values.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        driver_operation: DriverOperationRef,
        driver_declaration_revision: u64,
        credential_slot_id: SecretCredentialSlotId,
        destination_schema: impl Into<String>,
        delivery_exposure_profile: SecretDeliveryExposureProfile,
        trusted_send_profile: DriverTrustedSendProfileV1,
        mut approved_destination_digests: Vec<DriverCredentialDestinationDigest>,
    ) -> Result<Self, SecretCredentialAuthorizationV2Error> {
        validate_driver_operation_ref_v1(&driver_operation).map_err(|_| {
            authorization_error(SecretCredentialAuthorizationV2ErrorCode::InvalidDriverOperation)
        })?;
        if !(1..=MAX_SAFE_INTEGER).contains(&driver_declaration_revision) {
            return Err(authorization_error(
                SecretCredentialAuthorizationV2ErrorCode::InvalidDriverDeclarationRevision,
            ));
        }
        let destination_schema = destination_schema.into();
        if !is_destination_schema(&destination_schema) {
            return Err(authorization_error(
                SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationSchema,
            ));
        }
        if !profile_matches_exposure(&trusted_send_profile, delivery_exposure_profile) {
            return Err(authorization_error(
                SecretCredentialAuthorizationV2ErrorCode::InvalidExposureProfileBinding,
            ));
        }
        if approved_destination_digests.is_empty() {
            return Err(authorization_error(
                SecretCredentialAuthorizationV2ErrorCode::EmptyApprovedDestinationDigests,
            ));
        }
        if approved_destination_digests.len() > MAX_DESTINATION_DIGESTS {
            return Err(authorization_error(
                SecretCredentialAuthorizationV2ErrorCode::TooManyApprovedDestinationDigests,
            ));
        }
        if has_duplicates(&approved_destination_digests) {
            return Err(authorization_error(
                SecretCredentialAuthorizationV2ErrorCode::DuplicateDestinationDigest,
            ));
        }
        approved_destination_digests.sort();
        Ok(Self {
            driver_operation,
            driver_declaration_revision,
            credential_slot_id,
            destination_schema,
            delivery_exposure_profile,
            trusted_send_profile,
            approved_destination_digests,
        })
    }

    /// Returns the exact v2 schema version.
    pub const fn schema_version(&self) -> &'static str {
        SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V2
    }

    /// Returns the exact canonical driver operation.
    pub const fn driver_operation(&self) -> &DriverOperationRef {
        &self.driver_operation
    }

    /// Returns the positive declaration revision.
    pub const fn driver_declaration_revision(&self) -> u64 {
        self.driver_declaration_revision
    }

    /// Returns the driver-owned nominal credential slot.
    pub const fn credential_slot_id(&self) -> SecretCredentialSlotId {
        self.credential_slot_id
    }

    /// Returns the exact version-bearing destination schema.
    pub fn destination_schema(&self) -> &str {
        &self.destination_schema
    }

    /// Returns the declared exposure profile.
    pub const fn delivery_exposure_profile(&self) -> SecretDeliveryExposureProfile {
        self.delivery_exposure_profile
    }

    /// Returns the exact owner-defined trusted-send profile.
    pub const fn trusted_send_profile(&self) -> &DriverTrustedSendProfileV1 {
        &self.trusted_send_profile
    }

    /// Returns the normalized approved destination-digest set.
    pub fn approved_destination_digests(&self) -> &[DriverCredentialDestinationDigest] {
        &self.approved_destination_digests
    }

    fn has_same_binding_key(&self, other: &Self) -> bool {
        self.driver_operation == other.driver_operation
            && self.driver_declaration_revision == other.driver_declaration_revision
            && self.credential_slot_id == other.credential_slot_id
            && self.destination_schema == other.destination_schema
            && self.delivery_exposure_profile == other.delivery_exposure_profile
            && self.trusted_send_profile == other.trusted_send_profile
    }
}

impl fmt::Debug for SecretCredentialAuthorizationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret_credential_authorization_v2")
    }
}

impl Serialize for SecretCredentialAuthorizationV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretCredentialAuthorizationV2", 8)?;
        state.serialize_field(
            "approved_destination_digests",
            &self.approved_destination_digests,
        )?;
        state.serialize_field("credential_slot_id", &self.credential_slot_id)?;
        state.serialize_field("delivery_exposure_profile", &self.delivery_exposure_profile)?;
        state.serialize_field("destination_schema", &self.destination_schema)?;
        state.serialize_field(
            "driver_declaration_revision",
            &self.driver_declaration_revision,
        )?;
        state.serialize_field("driver_operation", &self.driver_operation)?;
        state.serialize_field("schema_version", SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V2)?;
        state.serialize_field("trusted_send_profile", &self.trusted_send_profile)?;
        state.end()
    }
}

/// Closed authorization-grammar error codes.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum SecretCredentialAuthorizationV2ErrorCode {
    InvalidContractShape,
    InvalidSchemaVersion,
    InvalidDriverOperation,
    InvalidDriverDeclarationRevision,
    InvalidCredentialSlot,
    InvalidDestinationSchema,
    InvalidExposureProfileBinding,
    InvalidTrustedSendProfile,
    EmptyApprovedDestinationDigests,
    TooManyApprovedDestinationDigests,
    InvalidDestinationDigest,
    DuplicateDestinationDigest,
}

impl SecretCredentialAuthorizationV2ErrorCode {
    /// Returns the exact fixed snake-case code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidContractShape => "invalid_contract_shape",
            Self::InvalidSchemaVersion => "invalid_schema_version",
            Self::InvalidDriverOperation => "invalid_driver_operation",
            Self::InvalidDriverDeclarationRevision => "invalid_driver_declaration_revision",
            Self::InvalidCredentialSlot => "invalid_credential_slot",
            Self::InvalidDestinationSchema => "invalid_destination_schema",
            Self::InvalidExposureProfileBinding => "invalid_exposure_profile_binding",
            Self::InvalidTrustedSendProfile => "invalid_trusted_send_profile",
            Self::EmptyApprovedDestinationDigests => "empty_approved_destination_digests",
            Self::TooManyApprovedDestinationDigests => "too_many_approved_destination_digests",
            Self::InvalidDestinationDigest => "invalid_destination_digest",
            Self::DuplicateDestinationDigest => "duplicate_destination_digest",
        }
    }
}

impl fmt::Display for SecretCredentialAuthorizationV2ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for SecretCredentialAuthorizationV2ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Serialize for SecretCredentialAuthorizationV2ErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// One fixed, non-reflecting authorization-grammar error.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SecretCredentialAuthorizationV2Error {
    code: SecretCredentialAuthorizationV2ErrorCode,
}

impl SecretCredentialAuthorizationV2Error {
    /// Returns the exact fixed code.
    pub const fn code(&self) -> SecretCredentialAuthorizationV2ErrorCode {
        self.code
    }
}

impl fmt::Display for SecretCredentialAuthorizationV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.code, formatter)
    }
}

impl fmt::Debug for SecretCredentialAuthorizationV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for SecretCredentialAuthorizationV2Error {}

impl Serialize for SecretCredentialAuthorizationV2Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretCredentialAuthorizationV2Error", 1)?;
        state.serialize_field("code", &self.code)?;
        state.end()
    }
}

/// Closed, revision-bearing secret reference declaration.
///
/// Parsing or possessing this value does not authorize secret use. The type has
/// no generic `Deserialize` implementation.
///
/// ```compile_fail
/// use splendor_types::SecretRefV2;
/// let _: SecretRefV2 = serde_json::from_slice(b"{}").unwrap();
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct SecretRefV2 {
    secret_ref_id: SecretRefId,
    secret_ref_revision: u64,
    tenant_id: TenantId,
    secret_provider_id: SecretProviderId,
    provider_namespace: String,
    logical_name: String,
    provider_version_ref: SecretProviderVersionRef,
    classification: SecretClassification,
    allowed_credential_bindings: Vec<SecretCredentialAuthorizationV2>,
    allowed_delivery_methods: Vec<SecretDeliveryMethod>,
    lease_policy: SecretLeasePolicy,
    offline_behavior: SecretOfflineBehavior,
    created_at: String,
    disabled_at: Option<String>,
}

impl SecretRefV2 {
    /// Parses one untrusted ref through the exact bounded v2 ingress.
    pub fn from_json_slice(input: &[u8]) -> Result<Self, SecretRefV2Error> {
        preflight_json(input, REF_INGRESS_BUDGET)
            .map_err(|_| ref_error(SecretRefV2ErrorCode::InvalidContractShape))?;
        let wire: SecretRefWire = serde_json::from_slice(input)
            .map_err(|_| ref_error(SecretRefV2ErrorCode::InvalidContractShape))?;
        parse_secret_ref_v2_wire(wire)
    }

    /// Constructs one validated ref from already typed owner values.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        secret_ref_id: SecretRefId,
        secret_ref_revision: u64,
        tenant_id: TenantId,
        secret_provider_id: SecretProviderId,
        provider_namespace: impl Into<String>,
        logical_name: impl Into<String>,
        provider_version_ref: SecretProviderVersionRef,
        classification: SecretClassification,
        mut allowed_credential_bindings: Vec<SecretCredentialAuthorizationV2>,
        mut allowed_delivery_methods: Vec<SecretDeliveryMethod>,
        lease_policy: SecretLeasePolicy,
        offline_behavior: SecretOfflineBehavior,
        created_at: impl Into<String>,
        disabled_at: Option<String>,
    ) -> Result<Self, SecretRefV2Error> {
        if !(1..=MAX_SAFE_INTEGER).contains(&secret_ref_revision) {
            return Err(ref_error(SecretRefV2ErrorCode::InvalidSecretRefRevision));
        }
        if tenant_id.is_nil() {
            return Err(ref_error(SecretRefV2ErrorCode::InvalidTenantId));
        }
        let provider_namespace = provider_namespace.into();
        if !is_canonical_label(&provider_namespace) {
            return Err(ref_error(SecretRefV2ErrorCode::InvalidProviderNamespace));
        }
        let logical_name = logical_name.into();
        if !is_canonical_label(&logical_name) {
            return Err(ref_error(SecretRefV2ErrorCode::InvalidLogicalName));
        }
        if allowed_credential_bindings.is_empty() {
            return Err(ref_error(
                SecretRefV2ErrorCode::EmptyCredentialAuthorizations,
            ));
        }
        if allowed_credential_bindings.len() > MAX_AUTHORIZATIONS {
            return Err(ref_error(
                SecretRefV2ErrorCode::TooManyCredentialAuthorizations,
            ));
        }
        for index in 0..allowed_credential_bindings.len() {
            if allowed_credential_bindings[..index]
                .iter()
                .any(|prior| prior.has_same_binding_key(&allowed_credential_bindings[index]))
            {
                return Err(ref_error(
                    SecretRefV2ErrorCode::DuplicateCredentialAuthorizationCoordinate,
                ));
            }
        }
        validate_delivery_methods(&allowed_delivery_methods)?;
        let created_at = created_at.into();
        if !is_exact_timestamp(&created_at) {
            return Err(ref_error(SecretRefV2ErrorCode::InvalidCreatedAt));
        }
        if let Some(disabled_at) = &disabled_at {
            if !is_exact_timestamp(disabled_at) || disabled_at < &created_at {
                return Err(ref_error(SecretRefV2ErrorCode::InvalidDisabledAt));
            }
        }
        sort_by_canonical_bytes(&mut allowed_credential_bindings)
            .map_err(|_| ref_error(SecretRefV2ErrorCode::InvalidContractShape))?;
        allowed_delivery_methods.sort_by_key(|method| delivery_method_wire(*method));
        Ok(Self {
            secret_ref_id,
            secret_ref_revision,
            tenant_id,
            secret_provider_id,
            provider_namespace,
            logical_name,
            provider_version_ref,
            classification,
            allowed_credential_bindings,
            allowed_delivery_methods,
            lease_policy,
            offline_behavior,
            created_at,
            disabled_at,
        })
    }

    /// Returns the exact v2 schema version.
    pub const fn schema_version(&self) -> &'static str {
        SECRET_REF_SCHEMA_V2
    }

    pub const fn secret_ref_id(&self) -> &SecretRefId {
        &self.secret_ref_id
    }

    pub const fn secret_ref_revision(&self) -> u64 {
        self.secret_ref_revision
    }

    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub const fn secret_provider_id(&self) -> &SecretProviderId {
        &self.secret_provider_id
    }

    pub fn provider_namespace(&self) -> &str {
        &self.provider_namespace
    }

    pub fn logical_name(&self) -> &str {
        &self.logical_name
    }

    pub const fn provider_version_ref(&self) -> &SecretProviderVersionRef {
        &self.provider_version_ref
    }

    pub const fn classification(&self) -> SecretClassification {
        self.classification
    }

    pub fn allowed_credential_bindings(&self) -> &[SecretCredentialAuthorizationV2] {
        &self.allowed_credential_bindings
    }

    pub fn allowed_delivery_methods(&self) -> &[SecretDeliveryMethod] {
        &self.allowed_delivery_methods
    }

    pub const fn lease_policy(&self) -> &SecretLeasePolicy {
        &self.lease_policy
    }

    pub const fn offline_behavior(&self) -> SecretOfflineBehavior {
        self.offline_behavior
    }

    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    pub fn disabled_at(&self) -> Option<&str> {
        self.disabled_at.as_deref()
    }
}

impl fmt::Debug for SecretRefV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret_ref_v2")
    }
}

impl Serialize for SecretRefV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_ref_fields(
            serializer,
            "SecretRefV2",
            SECRET_REF_SCHEMA_V2,
            &self.secret_ref_id,
            self.secret_ref_revision,
            &self.tenant_id,
            &self.secret_provider_id,
            &self.provider_namespace,
            &self.logical_name,
            &self.provider_version_ref,
            self.classification,
            &self.allowed_credential_bindings,
            &self.allowed_delivery_methods,
            &self.lease_policy,
            self.offline_behavior,
            &self.created_at,
            self.disabled_at.as_deref(),
        )
    }
}

/// Closed secret-ref grammar error codes.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum SecretRefV2ErrorCode {
    InvalidContractShape,
    InvalidSchemaVersion,
    InvalidDriverOperation,
    InvalidDriverDeclarationRevision,
    InvalidCredentialSlot,
    InvalidDestinationSchema,
    InvalidExposureProfileBinding,
    InvalidTrustedSendProfile,
    EmptyApprovedDestinationDigests,
    TooManyApprovedDestinationDigests,
    InvalidDestinationDigest,
    DuplicateDestinationDigest,
    InvalidSecretRefId,
    InvalidSecretRefRevision,
    InvalidTenantId,
    InvalidSecretProviderId,
    InvalidProviderNamespace,
    InvalidLogicalName,
    InvalidProviderVersionRef,
    InvalidClassification,
    EmptyCredentialAuthorizations,
    TooManyCredentialAuthorizations,
    DuplicateCredentialAuthorizationCoordinate,
    InvalidDeliveryMethods,
    InvalidLeasePolicy,
    InvalidOfflineBehavior,
    InvalidCreatedAt,
    InvalidDisabledAt,
}

impl SecretRefV2ErrorCode {
    /// Returns the exact fixed snake-case code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidContractShape => "invalid_contract_shape",
            Self::InvalidSchemaVersion => "invalid_schema_version",
            Self::InvalidDriverOperation => "invalid_driver_operation",
            Self::InvalidDriverDeclarationRevision => "invalid_driver_declaration_revision",
            Self::InvalidCredentialSlot => "invalid_credential_slot",
            Self::InvalidDestinationSchema => "invalid_destination_schema",
            Self::InvalidExposureProfileBinding => "invalid_exposure_profile_binding",
            Self::InvalidTrustedSendProfile => "invalid_trusted_send_profile",
            Self::EmptyApprovedDestinationDigests => "empty_approved_destination_digests",
            Self::TooManyApprovedDestinationDigests => "too_many_approved_destination_digests",
            Self::InvalidDestinationDigest => "invalid_destination_digest",
            Self::DuplicateDestinationDigest => "duplicate_destination_digest",
            Self::InvalidSecretRefId => "invalid_secret_ref_id",
            Self::InvalidSecretRefRevision => "invalid_secret_ref_revision",
            Self::InvalidTenantId => "invalid_tenant_id",
            Self::InvalidSecretProviderId => "invalid_secret_provider_id",
            Self::InvalidProviderNamespace => "invalid_provider_namespace",
            Self::InvalidLogicalName => "invalid_logical_name",
            Self::InvalidProviderVersionRef => "invalid_provider_version_ref",
            Self::InvalidClassification => "invalid_classification",
            Self::EmptyCredentialAuthorizations => "empty_credential_authorizations",
            Self::TooManyCredentialAuthorizations => "too_many_credential_authorizations",
            Self::DuplicateCredentialAuthorizationCoordinate => {
                "duplicate_credential_authorization_coordinate"
            }
            Self::InvalidDeliveryMethods => "invalid_delivery_methods",
            Self::InvalidLeasePolicy => "invalid_lease_policy",
            Self::InvalidOfflineBehavior => "invalid_offline_behavior",
            Self::InvalidCreatedAt => "invalid_created_at",
            Self::InvalidDisabledAt => "invalid_disabled_at",
        }
    }
}

impl fmt::Display for SecretRefV2ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for SecretRefV2ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Serialize for SecretRefV2ErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// One fixed, non-reflecting secret-ref grammar error.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SecretRefV2Error {
    code: SecretRefV2ErrorCode,
}

impl SecretRefV2Error {
    /// Returns the exact fixed code.
    pub const fn code(&self) -> SecretRefV2ErrorCode {
        self.code
    }
}

impl fmt::Display for SecretRefV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.code, formatter)
    }
}

impl fmt::Debug for SecretRefV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for SecretRefV2Error {}

impl Serialize for SecretRefV2Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretRefV2Error", 1)?;
        state.serialize_field("code", &self.code)?;
        state.end()
    }
}

/// Closed historical revision-less credential authorization view.
///
/// It is serializable for deterministic audit/replay inspection but cannot be
/// generically deserialized or converted into the live v2 type.
///
/// ```compile_fail
/// use splendor_types::{HistoricalSecretCredentialAuthorizationV1, SecretCredentialAuthorizationV2};
/// fn make_live(value: HistoricalSecretCredentialAuthorizationV1) -> SecretCredentialAuthorizationV2 {
///     value.into()
/// }
/// ```
///
/// ```compile_fail
/// use splendor_types::HistoricalSecretCredentialAuthorizationV1;
/// let _: HistoricalSecretCredentialAuthorizationV1 = serde_json::from_slice(b"{}").unwrap();
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct HistoricalSecretCredentialAuthorizationV1 {
    driver_operation: DriverOperationRef,
    credential_slot_id: SecretCredentialSlotId,
    destination_schema: String,
    delivery_exposure_profile: SecretDeliveryExposureProfile,
    trusted_send_profile: DriverTrustedSendProfileV1,
    approved_destination_digests: Vec<DriverCredentialDestinationDigest>,
    source_entry_ordinal: usize,
    canonical_entry_bytes: Vec<u8>,
    source_entry_digest: String,
}

impl HistoricalSecretCredentialAuthorizationV1 {
    pub const fn schema_version(&self) -> &'static str {
        HISTORICAL_SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V1
    }

    pub const fn driver_operation(&self) -> &DriverOperationRef {
        &self.driver_operation
    }

    pub const fn credential_slot_id(&self) -> SecretCredentialSlotId {
        self.credential_slot_id
    }

    pub fn destination_schema(&self) -> &str {
        &self.destination_schema
    }

    pub const fn delivery_exposure_profile(&self) -> SecretDeliveryExposureProfile {
        self.delivery_exposure_profile
    }

    pub const fn trusted_send_profile(&self) -> &DriverTrustedSendProfileV1 {
        &self.trusted_send_profile
    }

    pub fn approved_destination_digests(&self) -> &[DriverCredentialDestinationDigest] {
        &self.approved_destination_digests
    }

    /// Returns the zero-based ordinal after canonical entry ordering.
    pub const fn source_entry_ordinal(&self) -> usize {
        self.source_entry_ordinal
    }

    /// Returns the exact canonical historical entry bytes.
    pub fn canonical_entry_bytes(&self) -> &[u8] {
        &self.canonical_entry_bytes
    }

    /// Returns the exact domain-separated BLAKE3 entry digest.
    pub fn source_entry_digest(&self) -> &str {
        &self.source_entry_digest
    }

    fn has_same_binding_key(&self, other: &Self) -> bool {
        self.driver_operation == other.driver_operation
            && self.credential_slot_id == other.credential_slot_id
            && self.destination_schema == other.destination_schema
            && self.delivery_exposure_profile == other.delivery_exposure_profile
            && self.trusted_send_profile == other.trusted_send_profile
    }
}

impl fmt::Debug for HistoricalSecretCredentialAuthorizationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("historical_secret_credential_authorization_v1")
    }
}

impl Serialize for HistoricalSecretCredentialAuthorizationV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state =
            serializer.serialize_struct("HistoricalSecretCredentialAuthorizationV1", 7)?;
        state.serialize_field(
            "approved_destination_digests",
            &self.approved_destination_digests,
        )?;
        state.serialize_field("credential_slot_id", &self.credential_slot_id)?;
        state.serialize_field("delivery_exposure_profile", &self.delivery_exposure_profile)?;
        state.serialize_field("destination_schema", &self.destination_schema)?;
        state.serialize_field("driver_operation", &self.driver_operation)?;
        state.serialize_field(
            "schema_version",
            HISTORICAL_SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V1,
        )?;
        state.serialize_field("trusted_send_profile", &self.trusted_send_profile)?;
        state.end()
    }
}

/// Closed historical v1 secret-ref view.
///
/// ```compile_fail
/// use splendor_types::HistoricalSecretRefV1;
/// let _: HistoricalSecretRefV1 = serde_json::from_slice(b"{}").unwrap();
/// ```
///
/// ```compile_fail
/// use splendor_types::{HistoricalSecretRefV1, SecretRefV2};
/// fn make_live(value: HistoricalSecretRefV1) -> SecretRefV2 {
///     value.into()
/// }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct HistoricalSecretRefV1 {
    secret_ref_id: SecretRefId,
    secret_ref_revision: u64,
    tenant_id: TenantId,
    secret_provider_id: SecretProviderId,
    provider_namespace: String,
    logical_name: String,
    provider_version_ref: SecretProviderVersionRef,
    classification: SecretClassification,
    credential_authorizations: Vec<HistoricalSecretCredentialAuthorizationV1>,
    allowed_delivery_methods: Vec<SecretDeliveryMethod>,
    lease_policy: SecretLeasePolicy,
    offline_behavior: SecretOfflineBehavior,
    created_at: String,
    disabled_at: Option<String>,
    canonical_bytes: Vec<u8>,
    source_ref_digest: String,
}

impl HistoricalSecretRefV1 {
    /// Parses one frozen historical v1 ref through the v2 ref ingress budget.
    pub fn from_json_slice(input: &[u8]) -> Result<Self, HistoricalSecretRefV1Error> {
        let parsed = (|| {
            preflight_json(input, REF_INGRESS_BUDGET).map_err(|_| ())?;
            let wire: SecretRefWire = serde_json::from_slice(input).map_err(|_| ())?;
            parse_historical_ref_wire(wire)
        })();
        parsed.map_err(|_| HistoricalSecretRefV1Error::InvalidHistoricalSecretRef)
    }

    pub const fn schema_version(&self) -> &'static str {
        HISTORICAL_SECRET_REF_SCHEMA_V1
    }

    pub const fn secret_ref_id(&self) -> &SecretRefId {
        &self.secret_ref_id
    }

    pub const fn secret_ref_revision(&self) -> u64 {
        self.secret_ref_revision
    }

    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub const fn secret_provider_id(&self) -> &SecretProviderId {
        &self.secret_provider_id
    }

    pub fn provider_namespace(&self) -> &str {
        &self.provider_namespace
    }

    pub fn logical_name(&self) -> &str {
        &self.logical_name
    }

    pub const fn provider_version_ref(&self) -> &SecretProviderVersionRef {
        &self.provider_version_ref
    }

    pub const fn classification(&self) -> SecretClassification {
        self.classification
    }

    /// Returns the canonical historical authorization entries.
    pub fn credential_authorizations(&self) -> &[HistoricalSecretCredentialAuthorizationV1] {
        &self.credential_authorizations
    }

    pub fn allowed_delivery_methods(&self) -> &[SecretDeliveryMethod] {
        &self.allowed_delivery_methods
    }

    pub const fn lease_policy(&self) -> &SecretLeasePolicy {
        &self.lease_policy
    }

    pub const fn offline_behavior(&self) -> SecretOfflineBehavior {
        self.offline_behavior
    }

    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    pub fn disabled_at(&self) -> Option<&str> {
        self.disabled_at.as_deref()
    }

    /// Returns the complete canonical historical-ref bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the exact domain-separated BLAKE3 source-ref digest.
    pub fn source_ref_digest(&self) -> &str {
        &self.source_ref_digest
    }

    /// Always returns the fieldless denial for revision-less live use.
    pub const fn live_denial(&self) -> HistoricalSecretRefV1LiveDenial {
        HistoricalSecretRefV1LiveDenial::HistoricalRevisionlessAuthorizationLiveDenied
    }
}

impl fmt::Debug for HistoricalSecretRefV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("historical_secret_ref_v1")
    }
}

impl Serialize for HistoricalSecretRefV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_ref_fields(
            serializer,
            "HistoricalSecretRefV1",
            HISTORICAL_SECRET_REF_SCHEMA_V1,
            &self.secret_ref_id,
            self.secret_ref_revision,
            &self.tenant_id,
            &self.secret_provider_id,
            &self.provider_namespace,
            &self.logical_name,
            &self.provider_version_ref,
            self.classification,
            &self.credential_authorizations,
            &self.allowed_delivery_methods,
            &self.lease_policy,
            self.offline_behavior,
            &self.created_at,
            self.disabled_at.as_deref(),
        )
    }
}

/// Sole fixed historical-v1 parser error.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum HistoricalSecretRefV1Error {
    InvalidHistoricalSecretRef,
}

impl fmt::Display for HistoricalSecretRefV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid_historical_secret_ref")
    }
}

impl fmt::Debug for HistoricalSecretRefV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for HistoricalSecretRefV1Error {}

/// Fieldless denial for every attempt to treat revision-less history as live.
///
/// Historical denials are internal closed results, not serializable evidence.
///
/// ```compile_fail
/// use splendor_types::HistoricalSecretRefV1LiveDenial;
/// let value = HistoricalSecretRefV1LiveDenial::HistoricalRevisionlessAuthorizationLiveDenied;
/// let _ = serde_json::to_string(&value).unwrap();
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum HistoricalSecretRefV1LiveDenial {
    HistoricalRevisionlessAuthorizationLiveDenied,
}

impl fmt::Display for HistoricalSecretRefV1LiveDenial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("historical_revisionless_authorization_live_denied")
    }
}

impl fmt::Debug for HistoricalSecretRefV1LiveDenial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// Purely compares a validated authorization to one supplied declaration.
///
/// This function performs no lookup, current-state selection, authority
/// decision, persistence, migration, provider access, or I/O.
pub fn compare_secret_credential_authorization_v2(
    authorization: &SecretCredentialAuthorizationV2,
    ref_classification: &SecretClassification,
    requirement_intent: &SecretUseIntent,
    declaration: &DriverOperationCredentialSinksV1,
) -> SecretCredentialDeclarationComparisonV2 {
    use SecretCredentialDeclarationMismatchCodeV2 as Mismatch;

    if authorization.driver_operation() != declaration.driver_operation() {
        return SecretCredentialDeclarationComparisonV2::Denied(Mismatch::DriverOperationMismatch);
    }
    if authorization.driver_declaration_revision() != declaration.driver_declaration_revision() {
        return SecretCredentialDeclarationComparisonV2::Denied(
            Mismatch::DriverDeclarationRevisionMismatch,
        );
    }
    let Some(sink) = declaration
        .credential_sinks()
        .iter()
        .find(|sink| sink.credential_slot_id() == authorization.credential_slot_id())
    else {
        return SecretCredentialDeclarationComparisonV2::Denied(
            Mismatch::CredentialSlotNotDeclared,
        );
    };
    if authorization.destination_schema() != sink.destination_schema() {
        return SecretCredentialDeclarationComparisonV2::Denied(
            Mismatch::DestinationSchemaMismatch,
        );
    }
    if authorization.delivery_exposure_profile() != sink.delivery_exposure_profile() {
        return SecretCredentialDeclarationComparisonV2::Denied(
            Mismatch::DeliveryExposureProfileMismatch,
        );
    }
    if authorization.trusted_send_profile() != sink.trusted_send_profile() {
        return SecretCredentialDeclarationComparisonV2::Denied(
            Mismatch::TrustedSendProfileMismatch,
        );
    }
    if !sink.allowed_classifications().contains(ref_classification) {
        return SecretCredentialDeclarationComparisonV2::Denied(
            Mismatch::SecretClassificationNotAllowed,
        );
    }
    if !sink.allowed_intents().contains(requirement_intent) {
        return SecretCredentialDeclarationComparisonV2::Denied(
            Mismatch::SecretUseIntentNotAllowed,
        );
    }
    SecretCredentialDeclarationComparisonV2::Matched
}

/// Closed behavior-free declaration comparison result.
///
/// A match is not authority, proof, evidence, a decision, permit, lease, or
/// cache value. The result is deliberately non-serializable.
///
/// ```compile_fail
/// use splendor_types::SecretCredentialDeclarationComparisonV2;
/// let value = SecretCredentialDeclarationComparisonV2::Matched;
/// let _ = serde_json::to_string(&value).unwrap();
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum SecretCredentialDeclarationComparisonV2 {
    Matched,
    Denied(SecretCredentialDeclarationMismatchCodeV2),
}

impl fmt::Display for SecretCredentialDeclarationComparisonV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Matched => formatter.write_str("matched"),
            Self::Denied(code) => fmt::Display::fmt(code, formatter),
        }
    }
}

impl fmt::Debug for SecretCredentialDeclarationComparisonV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// Closed, code-only declaration/context mismatch taxonomy.
///
/// Mismatch codes are deliberately non-serializable.
///
/// ```compile_fail
/// use splendor_types::SecretCredentialDeclarationMismatchCodeV2;
/// let value = SecretCredentialDeclarationMismatchCodeV2::DriverOperationMismatch;
/// let _ = serde_json::to_string(&value).unwrap();
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum SecretCredentialDeclarationMismatchCodeV2 {
    DriverOperationMismatch,
    DriverDeclarationRevisionMismatch,
    CredentialSlotNotDeclared,
    DestinationSchemaMismatch,
    DeliveryExposureProfileMismatch,
    TrustedSendProfileMismatch,
    SecretClassificationNotAllowed,
    SecretUseIntentNotAllowed,
}

impl SecretCredentialDeclarationMismatchCodeV2 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DriverOperationMismatch => "driver_operation_mismatch",
            Self::DriverDeclarationRevisionMismatch => "driver_declaration_revision_mismatch",
            Self::CredentialSlotNotDeclared => "credential_slot_not_declared",
            Self::DestinationSchemaMismatch => "destination_schema_mismatch",
            Self::DeliveryExposureProfileMismatch => "delivery_exposure_profile_mismatch",
            Self::TrustedSendProfileMismatch => "trusted_send_profile_mismatch",
            Self::SecretClassificationNotAllowed => "secret_classification_not_allowed",
            Self::SecretUseIntentNotAllowed => "secret_use_intent_not_allowed",
        }
    }
}

impl fmt::Display for SecretCredentialDeclarationMismatchCodeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for SecretCredentialDeclarationMismatchCodeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

enum WireScalar {
    String(String),
    Unsigned(u64),
    Bool(bool),
    Other,
}

impl WireScalar {
    fn into_string(self) -> Option<String> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    fn into_u64(self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(value),
            _ => None,
        }
    }

    fn into_bool(self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(value),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for WireScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(WireScalarVisitor)
    }
}

struct WireScalarVisitor;

impl<'de> Visitor<'de> for WireScalarVisitor {
    type Value = WireScalar;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one private secret-reference wire scalar")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(WireScalar::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(u64::try_from(value)
            .map(WireScalar::Unsigned)
            .unwrap_or(WireScalar::Other))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(WireScalar::Unsigned(value))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(WireScalar::Other)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(WireScalar::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(WireScalar::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(WireScalar::Other)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(WireScalar::Other)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(WireScalar::Other)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_entry::<String, IgnoredAny>()?.is_some() {}
        Ok(WireScalar::Other)
    }
}

enum WireArray<T> {
    Values(Vec<T>),
    Invalid,
}

impl<'de, T> Deserialize<'de> for WireArray<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(WireArrayVisitor(std::marker::PhantomData))
    }
}

struct WireArrayVisitor<T>(std::marker::PhantomData<T>);

impl<'de, T> Visitor<'de> for WireArrayVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = WireArray<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one private secret-reference wire array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<T>()? {
            values.push(value);
        }
        Ok(WireArray::Values(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_entry::<String, IgnoredAny>()?.is_some() {}
        Ok(WireArray::Invalid)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(WireArray::Invalid)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(WireArray::Invalid)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(WireArray::Invalid)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(WireArray::Invalid)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(WireArray::Invalid)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(WireArray::Invalid)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(WireArray::Invalid)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(WireArray::Invalid)
    }
}

macro_rules! read_wire_field {
    ($map:ident, $wire:ident.$field:ident, $type:ty, $invalid_wire:ident.invalid_shape) => {
        if $wire.$field.is_some() {
            $invalid_wire.invalid_shape = true;
            $map.next_value::<IgnoredAny>()?;
        } else {
            $wire.$field = Some($map.next_value::<$type>()?);
        }
    };
}

macro_rules! invalid_wire_scalar_visits {
    ($invalid:expr) => {
        fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
            Ok($invalid)
        }

        fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
            Ok($invalid)
        }

        fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
            Ok($invalid)
        }

        fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
            Ok($invalid)
        }

        fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
            Ok($invalid)
        }

        fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
            Ok($invalid)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok($invalid)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok($invalid)
        }
    };
}

#[derive(Default)]
struct DriverOperationWire {
    driver: Option<WireScalar>,
    operation: Option<WireScalar>,
    schema_version: Option<WireScalar>,
    invalid_shape: bool,
}

impl DriverOperationWire {
    fn invalid() -> Self {
        Self {
            invalid_shape: true,
            ..Self::default()
        }
    }
}

impl<'de> Deserialize<'de> for DriverOperationWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DriverOperationWireVisitor)
    }
}

struct DriverOperationWireVisitor;

impl<'de> Visitor<'de> for DriverOperationWireVisitor {
    type Value = DriverOperationWire;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the private driver-operation wire object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut wire = DriverOperationWire::default();
        while let Some(name) = map.next_key::<String>()? {
            match name.as_str() {
                "driver" => read_wire_field!(map, wire.driver, WireScalar, wire.invalid_shape),
                "operation" => {
                    read_wire_field!(map, wire.operation, WireScalar, wire.invalid_shape)
                }
                "schema_version" => {
                    read_wire_field!(map, wire.schema_version, WireScalar, wire.invalid_shape)
                }
                _ => {
                    wire.invalid_shape = true;
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(wire)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(DriverOperationWire::invalid())
    }

    invalid_wire_scalar_visits!(DriverOperationWire::invalid());
}

#[derive(Default)]
struct TrustedSendProfileWire {
    applicable_delivery_controls: Option<WireArray<WireScalar>>,
    kind: Option<WireScalar>,
    max_credential_bearing_sends: Option<WireScalar>,
    invalid_shape: bool,
}

impl TrustedSendProfileWire {
    fn invalid() -> Self {
        Self {
            invalid_shape: true,
            ..Self::default()
        }
    }
}

impl<'de> Deserialize<'de> for TrustedSendProfileWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(TrustedSendProfileWireVisitor)
    }
}

struct TrustedSendProfileWireVisitor;

impl<'de> Visitor<'de> for TrustedSendProfileWireVisitor {
    type Value = TrustedSendProfileWire;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the private trusted-send-profile wire object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut wire = TrustedSendProfileWire::default();
        while let Some(name) = map.next_key::<String>()? {
            match name.as_str() {
                "applicable_delivery_controls" => read_wire_field!(
                    map,
                    wire.applicable_delivery_controls,
                    WireArray<WireScalar>,
                    wire.invalid_shape
                ),
                "kind" => read_wire_field!(map, wire.kind, WireScalar, wire.invalid_shape),
                "max_credential_bearing_sends" => read_wire_field!(
                    map,
                    wire.max_credential_bearing_sends,
                    WireScalar,
                    wire.invalid_shape
                ),
                _ => {
                    wire.invalid_shape = true;
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(wire)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(TrustedSendProfileWire::invalid())
    }

    invalid_wire_scalar_visits!(TrustedSendProfileWire::invalid());
}

#[derive(Default)]
struct LeasePolicyWire {
    clock_skew_tolerance_seconds: Option<WireScalar>,
    max_continuous_lifetime_seconds: Option<WireScalar>,
    max_lease_duration_seconds: Option<WireScalar>,
    max_uses: Option<WireScalar>,
    renewable: Option<WireScalar>,
    invalid_shape: bool,
}

impl LeasePolicyWire {
    fn invalid() -> Self {
        Self {
            invalid_shape: true,
            ..Self::default()
        }
    }
}

impl<'de> Deserialize<'de> for LeasePolicyWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(LeasePolicyWireVisitor)
    }
}

struct LeasePolicyWireVisitor;

impl<'de> Visitor<'de> for LeasePolicyWireVisitor {
    type Value = LeasePolicyWire;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the private lease-policy wire object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut wire = LeasePolicyWire::default();
        while let Some(name) = map.next_key::<String>()? {
            match name.as_str() {
                "clock_skew_tolerance_seconds" => read_wire_field!(
                    map,
                    wire.clock_skew_tolerance_seconds,
                    WireScalar,
                    wire.invalid_shape
                ),
                "max_continuous_lifetime_seconds" => read_wire_field!(
                    map,
                    wire.max_continuous_lifetime_seconds,
                    WireScalar,
                    wire.invalid_shape
                ),
                "max_lease_duration_seconds" => read_wire_field!(
                    map,
                    wire.max_lease_duration_seconds,
                    WireScalar,
                    wire.invalid_shape
                ),
                "max_uses" => {
                    read_wire_field!(map, wire.max_uses, WireScalar, wire.invalid_shape)
                }
                "renewable" => {
                    read_wire_field!(map, wire.renewable, WireScalar, wire.invalid_shape)
                }
                _ => {
                    wire.invalid_shape = true;
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(wire)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(LeasePolicyWire::invalid())
    }

    invalid_wire_scalar_visits!(LeasePolicyWire::invalid());
}

#[derive(Default)]
struct AuthorizationWire {
    approved_destination_digests: Option<WireArray<WireScalar>>,
    credential_slot_id: Option<WireScalar>,
    delivery_exposure_profile: Option<WireScalar>,
    destination_schema: Option<WireScalar>,
    driver_declaration_revision: Option<WireScalar>,
    driver_operation: Option<DriverOperationWire>,
    schema_version: Option<WireScalar>,
    trusted_send_profile: Option<TrustedSendProfileWire>,
    invalid_shape: bool,
}

impl AuthorizationWire {
    fn invalid() -> Self {
        Self {
            invalid_shape: true,
            ..Self::default()
        }
    }
}

impl<'de> Deserialize<'de> for AuthorizationWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(AuthorizationWireVisitor)
    }
}

struct AuthorizationWireVisitor;

impl<'de> Visitor<'de> for AuthorizationWireVisitor {
    type Value = AuthorizationWire;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the private credential-authorization wire object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut wire = AuthorizationWire::default();
        while let Some(name) = map.next_key::<String>()? {
            match name.as_str() {
                "approved_destination_digests" => read_wire_field!(
                    map,
                    wire.approved_destination_digests,
                    WireArray<WireScalar>,
                    wire.invalid_shape
                ),
                "credential_slot_id" => {
                    read_wire_field!(map, wire.credential_slot_id, WireScalar, wire.invalid_shape)
                }
                "delivery_exposure_profile" => read_wire_field!(
                    map,
                    wire.delivery_exposure_profile,
                    WireScalar,
                    wire.invalid_shape
                ),
                "destination_schema" => {
                    read_wire_field!(map, wire.destination_schema, WireScalar, wire.invalid_shape)
                }
                "driver_declaration_revision" => read_wire_field!(
                    map,
                    wire.driver_declaration_revision,
                    WireScalar,
                    wire.invalid_shape
                ),
                "driver_operation" => read_wire_field!(
                    map,
                    wire.driver_operation,
                    DriverOperationWire,
                    wire.invalid_shape
                ),
                "schema_version" => {
                    read_wire_field!(map, wire.schema_version, WireScalar, wire.invalid_shape)
                }
                "trusted_send_profile" => read_wire_field!(
                    map,
                    wire.trusted_send_profile,
                    TrustedSendProfileWire,
                    wire.invalid_shape
                ),
                _ => {
                    wire.invalid_shape = true;
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(wire)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(AuthorizationWire::invalid())
    }

    invalid_wire_scalar_visits!(AuthorizationWire::invalid());
}

#[derive(Default)]
struct SecretRefWire {
    allowed_credential_bindings: Option<WireArray<AuthorizationWire>>,
    allowed_delivery_methods: Option<WireArray<WireScalar>>,
    classification: Option<WireScalar>,
    created_at: Option<WireScalar>,
    disabled_at: Option<WireScalar>,
    lease_policy: Option<LeasePolicyWire>,
    logical_name: Option<WireScalar>,
    offline_behavior: Option<WireScalar>,
    provider_namespace: Option<WireScalar>,
    provider_version_ref: Option<WireScalar>,
    schema_version: Option<WireScalar>,
    secret_provider_id: Option<WireScalar>,
    secret_ref_id: Option<WireScalar>,
    secret_ref_revision: Option<WireScalar>,
    tenant_id: Option<WireScalar>,
    invalid_shape: bool,
}

impl SecretRefWire {
    fn invalid() -> Self {
        Self {
            invalid_shape: true,
            ..Self::default()
        }
    }
}

impl<'de> Deserialize<'de> for SecretRefWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SecretRefWireVisitor)
    }
}

struct SecretRefWireVisitor;

impl<'de> Visitor<'de> for SecretRefWireVisitor {
    type Value = SecretRefWire;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the private secret-reference wire object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut wire = SecretRefWire::default();
        while let Some(name) = map.next_key::<String>()? {
            match name.as_str() {
                "allowed_credential_bindings" => read_wire_field!(
                    map,
                    wire.allowed_credential_bindings,
                    WireArray<AuthorizationWire>,
                    wire.invalid_shape
                ),
                "allowed_delivery_methods" => read_wire_field!(
                    map,
                    wire.allowed_delivery_methods,
                    WireArray<WireScalar>,
                    wire.invalid_shape
                ),
                "classification" => {
                    read_wire_field!(map, wire.classification, WireScalar, wire.invalid_shape)
                }
                "created_at" => {
                    read_wire_field!(map, wire.created_at, WireScalar, wire.invalid_shape)
                }
                "disabled_at" => {
                    read_wire_field!(map, wire.disabled_at, WireScalar, wire.invalid_shape)
                }
                "lease_policy" => {
                    read_wire_field!(map, wire.lease_policy, LeasePolicyWire, wire.invalid_shape)
                }
                "logical_name" => {
                    read_wire_field!(map, wire.logical_name, WireScalar, wire.invalid_shape)
                }
                "offline_behavior" => {
                    read_wire_field!(map, wire.offline_behavior, WireScalar, wire.invalid_shape)
                }
                "provider_namespace" => {
                    read_wire_field!(map, wire.provider_namespace, WireScalar, wire.invalid_shape)
                }
                "provider_version_ref" => read_wire_field!(
                    map,
                    wire.provider_version_ref,
                    WireScalar,
                    wire.invalid_shape
                ),
                "schema_version" => {
                    read_wire_field!(map, wire.schema_version, WireScalar, wire.invalid_shape)
                }
                "secret_provider_id" => {
                    read_wire_field!(map, wire.secret_provider_id, WireScalar, wire.invalid_shape)
                }
                "secret_ref_id" => {
                    read_wire_field!(map, wire.secret_ref_id, WireScalar, wire.invalid_shape)
                }
                "secret_ref_revision" => read_wire_field!(
                    map,
                    wire.secret_ref_revision,
                    WireScalar,
                    wire.invalid_shape
                ),
                "tenant_id" => {
                    read_wire_field!(map, wire.tenant_id, WireScalar, wire.invalid_shape)
                }
                _ => {
                    wire.invalid_shape = true;
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(wire)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(SecretRefWire::invalid())
    }

    invalid_wire_scalar_visits!(SecretRefWire::invalid());
}

fn parse_authorization_wire(
    wire: AuthorizationWire,
) -> Result<SecretCredentialAuthorizationV2, SecretCredentialAuthorizationV2Error> {
    if wire.invalid_shape {
        return Err(authorization_error(
            SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape,
        ));
    }
    if wire
        .schema_version
        .and_then(WireScalar::into_string)
        .as_deref()
        != Some(SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V2)
    {
        return Err(authorization_error(
            SecretCredentialAuthorizationV2ErrorCode::InvalidSchemaVersion,
        ));
    }
    let operation = parse_driver_operation(wire.driver_operation).map_err(|_| {
        authorization_error(SecretCredentialAuthorizationV2ErrorCode::InvalidDriverOperation)
    })?;
    let revision =
        parse_positive_safe_integer(wire.driver_declaration_revision).ok_or_else(|| {
            authorization_error(
                SecretCredentialAuthorizationV2ErrorCode::InvalidDriverDeclarationRevision,
            )
        })?;
    let credential_slot_id = wire
        .credential_slot_id
        .and_then(WireScalar::into_string)
        .ok_or_else(|| {
            authorization_error(SecretCredentialAuthorizationV2ErrorCode::InvalidCredentialSlot)
        })?
        .parse()
        .map_err(|_| {
            authorization_error(SecretCredentialAuthorizationV2ErrorCode::InvalidCredentialSlot)
        })?;
    let destination_schema = wire
        .destination_schema
        .and_then(WireScalar::into_string)
        .filter(|value| is_destination_schema(value))
        .ok_or_else(|| {
            authorization_error(SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationSchema)
        })?;
    let exposure = parse_exposure(wire.delivery_exposure_profile).ok_or_else(|| {
        authorization_error(SecretCredentialAuthorizationV2ErrorCode::InvalidExposureProfileBinding)
    })?;
    let profile = parse_trusted_send_profile(wire.trusted_send_profile).map_err(|_| {
        authorization_error(SecretCredentialAuthorizationV2ErrorCode::InvalidTrustedSendProfile)
    })?;
    if !profile_matches_exposure(&profile, exposure) {
        return Err(authorization_error(
            SecretCredentialAuthorizationV2ErrorCode::InvalidExposureProfileBinding,
        ));
    }
    let digests = parse_destination_digests(wire.approved_destination_digests)?;
    SecretCredentialAuthorizationV2::try_new(
        operation,
        revision,
        credential_slot_id,
        destination_schema,
        exposure,
        profile,
        digests,
    )
}

fn parse_secret_ref_v2_wire(wire: SecretRefWire) -> Result<SecretRefV2, SecretRefV2Error> {
    if wire.invalid_shape {
        return Err(ref_error(SecretRefV2ErrorCode::InvalidContractShape));
    }
    if wire
        .schema_version
        .and_then(WireScalar::into_string)
        .as_deref()
        != Some(SECRET_REF_SCHEMA_V2)
    {
        return Err(ref_error(SecretRefV2ErrorCode::InvalidSchemaVersion));
    }
    let secret_ref_id = parse_secret_ref_id(wire.secret_ref_id)?;
    let secret_ref_revision = parse_positive_safe_integer(wire.secret_ref_revision)
        .ok_or_else(|| ref_error(SecretRefV2ErrorCode::InvalidSecretRefRevision))?;
    let tenant_id = parse_tenant_id(wire.tenant_id)?;
    let secret_provider_id = parse_secret_provider_id(wire.secret_provider_id)?;
    let provider_namespace = parse_label(
        wire.provider_namespace,
        SecretRefV2ErrorCode::InvalidProviderNamespace,
    )?;
    let logical_name = parse_label(wire.logical_name, SecretRefV2ErrorCode::InvalidLogicalName)?;
    let provider_version_ref = wire
        .provider_version_ref
        .and_then(WireScalar::into_string)
        .ok_or_else(|| ref_error(SecretRefV2ErrorCode::InvalidProviderVersionRef))
        .and_then(|value| {
            SecretProviderVersionRef::try_new(value)
                .map_err(|_| ref_error(SecretRefV2ErrorCode::InvalidProviderVersionRef))
        })?;
    let classification = parse_classification(wire.classification)
        .ok_or_else(|| ref_error(SecretRefV2ErrorCode::InvalidClassification))?;
    let authorizations = match wire.allowed_credential_bindings {
        Some(WireArray::Values(values)) => values,
        Some(WireArray::Invalid) | None => {
            return Err(ref_error(
                SecretRefV2ErrorCode::EmptyCredentialAuthorizations,
            ));
        }
    };
    if authorizations.is_empty() {
        return Err(ref_error(
            SecretRefV2ErrorCode::EmptyCredentialAuthorizations,
        ));
    }
    if authorizations.len() > MAX_AUTHORIZATIONS {
        return Err(ref_error(
            SecretRefV2ErrorCode::TooManyCredentialAuthorizations,
        ));
    }
    let mut parsed_authorizations = Vec::with_capacity(authorizations.len());
    for authorization in authorizations {
        parsed_authorizations.push(
            parse_authorization_wire(authorization)
                .map_err(SecretRefV2Error::from_authorization)?,
        );
    }
    for index in 0..parsed_authorizations.len() {
        if parsed_authorizations[..index]
            .iter()
            .any(|prior| prior.has_same_binding_key(&parsed_authorizations[index]))
        {
            return Err(ref_error(
                SecretRefV2ErrorCode::DuplicateCredentialAuthorizationCoordinate,
            ));
        }
    }
    let delivery_methods = parse_delivery_methods(wire.allowed_delivery_methods)?;
    let lease_policy = parse_lease_policy(wire.lease_policy)
        .ok_or_else(|| ref_error(SecretRefV2ErrorCode::InvalidLeasePolicy))?;
    let offline_behavior = parse_offline_behavior(wire.offline_behavior)
        .ok_or_else(|| ref_error(SecretRefV2ErrorCode::InvalidOfflineBehavior))?;
    let created_at = wire
        .created_at
        .and_then(WireScalar::into_string)
        .filter(|value| is_exact_timestamp(value))
        .ok_or_else(|| ref_error(SecretRefV2ErrorCode::InvalidCreatedAt))?;
    let disabled_at = match wire.disabled_at {
        None => None,
        Some(value) => Some(
            value
                .into_string()
                .filter(|value| is_exact_timestamp(value) && value >= &created_at)
                .ok_or_else(|| ref_error(SecretRefV2ErrorCode::InvalidDisabledAt))?,
        ),
    };
    SecretRefV2::try_new(
        secret_ref_id,
        secret_ref_revision,
        tenant_id,
        secret_provider_id,
        provider_namespace,
        logical_name,
        provider_version_ref,
        classification,
        parsed_authorizations,
        delivery_methods,
        lease_policy,
        offline_behavior,
        created_at,
        disabled_at,
    )
}

impl SecretRefV2Error {
    fn from_authorization(error: SecretCredentialAuthorizationV2Error) -> Self {
        let code = match error.code() {
            SecretCredentialAuthorizationV2ErrorCode::InvalidContractShape => {
                SecretRefV2ErrorCode::InvalidContractShape
            }
            SecretCredentialAuthorizationV2ErrorCode::InvalidSchemaVersion => {
                SecretRefV2ErrorCode::InvalidSchemaVersion
            }
            SecretCredentialAuthorizationV2ErrorCode::InvalidDriverOperation => {
                SecretRefV2ErrorCode::InvalidDriverOperation
            }
            SecretCredentialAuthorizationV2ErrorCode::InvalidDriverDeclarationRevision => {
                SecretRefV2ErrorCode::InvalidDriverDeclarationRevision
            }
            SecretCredentialAuthorizationV2ErrorCode::InvalidCredentialSlot => {
                SecretRefV2ErrorCode::InvalidCredentialSlot
            }
            SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationSchema => {
                SecretRefV2ErrorCode::InvalidDestinationSchema
            }
            SecretCredentialAuthorizationV2ErrorCode::InvalidExposureProfileBinding => {
                SecretRefV2ErrorCode::InvalidExposureProfileBinding
            }
            SecretCredentialAuthorizationV2ErrorCode::InvalidTrustedSendProfile => {
                SecretRefV2ErrorCode::InvalidTrustedSendProfile
            }
            SecretCredentialAuthorizationV2ErrorCode::EmptyApprovedDestinationDigests => {
                SecretRefV2ErrorCode::EmptyApprovedDestinationDigests
            }
            SecretCredentialAuthorizationV2ErrorCode::TooManyApprovedDestinationDigests => {
                SecretRefV2ErrorCode::TooManyApprovedDestinationDigests
            }
            SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationDigest => {
                SecretRefV2ErrorCode::InvalidDestinationDigest
            }
            SecretCredentialAuthorizationV2ErrorCode::DuplicateDestinationDigest => {
                SecretRefV2ErrorCode::DuplicateDestinationDigest
            }
        };
        ref_error(code)
    }
}

fn parse_historical_ref_wire(wire: SecretRefWire) -> Result<HistoricalSecretRefV1, ()> {
    if wire.invalid_shape
        || wire
            .schema_version
            .and_then(WireScalar::into_string)
            .as_deref()
            != Some(HISTORICAL_SECRET_REF_SCHEMA_V1)
    {
        return Err(());
    }
    let secret_ref_id = parse_secret_ref_id(wire.secret_ref_id).map_err(|_| ())?;
    let secret_ref_revision = parse_positive_safe_integer(wire.secret_ref_revision).ok_or(())?;
    let tenant_id = parse_tenant_id(wire.tenant_id).map_err(|_| ())?;
    let secret_provider_id = parse_secret_provider_id(wire.secret_provider_id).map_err(|_| ())?;
    let provider_namespace = wire
        .provider_namespace
        .and_then(WireScalar::into_string)
        .filter(|value| is_canonical_label(value))
        .ok_or(())?;
    let logical_name = wire
        .logical_name
        .and_then(WireScalar::into_string)
        .filter(|value| is_canonical_label(value))
        .ok_or(())?;
    let provider_version_ref = wire
        .provider_version_ref
        .and_then(WireScalar::into_string)
        .ok_or(())
        .and_then(|value| SecretProviderVersionRef::try_new(value).map_err(|_| ()))?;
    let classification = parse_classification(wire.classification).ok_or(())?;
    let authorization_values = match wire.allowed_credential_bindings {
        Some(WireArray::Values(values)) => values,
        Some(WireArray::Invalid) | None => return Err(()),
    };
    if authorization_values.is_empty() || authorization_values.len() > MAX_AUTHORIZATIONS {
        return Err(());
    }
    let mut credential_authorizations = authorization_values
        .into_iter()
        .map(parse_historical_authorization_wire)
        .collect::<Result<Vec<_>, _>>()?;
    for index in 0..credential_authorizations.len() {
        if credential_authorizations[..index]
            .iter()
            .any(|prior| prior.has_same_binding_key(&credential_authorizations[index]))
        {
            return Err(());
        }
    }
    let mut allowed_delivery_methods =
        parse_delivery_methods(wire.allowed_delivery_methods).map_err(|_| ())?;
    let lease_policy = parse_lease_policy(wire.lease_policy).ok_or(())?;
    let offline_behavior = parse_offline_behavior(wire.offline_behavior).ok_or(())?;
    let created_at = wire
        .created_at
        .and_then(WireScalar::into_string)
        .filter(|value| is_exact_timestamp(value))
        .ok_or(())?;
    let disabled_at = match wire.disabled_at {
        None => None,
        Some(value) => Some(
            value
                .into_string()
                .filter(|value| is_exact_timestamp(value) && value >= &created_at)
                .ok_or(())?,
        ),
    };
    credential_authorizations
        .sort_by(|left, right| left.canonical_entry_bytes.cmp(&right.canonical_entry_bytes));
    for (ordinal, authorization) in credential_authorizations.iter_mut().enumerate() {
        authorization.source_entry_ordinal = ordinal;
    }
    allowed_delivery_methods.sort_by_key(|method| delivery_method_wire(*method));
    let mut historical = HistoricalSecretRefV1 {
        secret_ref_id,
        secret_ref_revision,
        tenant_id,
        secret_provider_id,
        provider_namespace,
        logical_name,
        provider_version_ref,
        classification,
        credential_authorizations,
        allowed_delivery_methods,
        lease_policy,
        offline_behavior,
        created_at,
        disabled_at,
        canonical_bytes: Vec::new(),
        source_ref_digest: String::new(),
    };
    historical.canonical_bytes = serde_json::to_vec(&historical).map_err(|_| ())?;
    historical.source_ref_digest =
        domain_digest(HISTORICAL_SECRET_REF_SCHEMA_V1, &historical.canonical_bytes);
    Ok(historical)
}

fn parse_historical_authorization_wire(
    wire: AuthorizationWire,
) -> Result<HistoricalSecretCredentialAuthorizationV1, ()> {
    if wire.invalid_shape
        || wire.driver_declaration_revision.is_some()
        || wire
            .schema_version
            .and_then(WireScalar::into_string)
            .as_deref()
            != Some(HISTORICAL_SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V1)
    {
        return Err(());
    }
    let driver_operation = parse_driver_operation(wire.driver_operation)?;
    let credential_slot_id = wire
        .credential_slot_id
        .and_then(WireScalar::into_string)
        .ok_or(())?
        .parse()
        .map_err(|_| ())?;
    let destination_schema = wire
        .destination_schema
        .and_then(WireScalar::into_string)
        .filter(|value| is_destination_schema(value))
        .ok_or(())?;
    let delivery_exposure_profile = parse_exposure(wire.delivery_exposure_profile).ok_or(())?;
    let trusted_send_profile = parse_trusted_send_profile(wire.trusted_send_profile)?;
    if !profile_matches_exposure(&trusted_send_profile, delivery_exposure_profile) {
        return Err(());
    }
    let approved_destination_digests =
        parse_destination_digests(wire.approved_destination_digests).map_err(|_| ())?;
    let mut historical = HistoricalSecretCredentialAuthorizationV1 {
        driver_operation,
        credential_slot_id,
        destination_schema,
        delivery_exposure_profile,
        trusted_send_profile,
        approved_destination_digests,
        source_entry_ordinal: 0,
        canonical_entry_bytes: Vec::new(),
        source_entry_digest: String::new(),
    };
    historical.canonical_entry_bytes = serde_json::to_vec(&historical).map_err(|_| ())?;
    historical.source_entry_digest = domain_digest(
        HISTORICAL_SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V1,
        &historical.canonical_entry_bytes,
    );
    Ok(historical)
}

fn parse_driver_operation(value: Option<DriverOperationWire>) -> Result<DriverOperationRef, ()> {
    let value = value.ok_or(())?;
    if value.invalid_shape {
        return Err(());
    }
    let operation = DriverOperationRef {
        driver: value.driver.and_then(WireScalar::into_string).ok_or(())?,
        operation: value
            .operation
            .and_then(WireScalar::into_string)
            .ok_or(())?,
        schema_version: value
            .schema_version
            .and_then(WireScalar::into_string)
            .ok_or(())?,
    };
    validate_driver_operation_ref_v1(&operation).map_err(|_| ())?;
    Ok(operation)
}

fn parse_trusted_send_profile(
    value: Option<TrustedSendProfileWire>,
) -> Result<DriverTrustedSendProfileV1, ()> {
    let value = value.ok_or(())?;
    if value.invalid_shape {
        return Err(());
    }
    match value.kind.and_then(WireScalar::into_string).as_deref() {
        Some("trusted_injection") => {
            let limit = value
                .max_credential_bearing_sends
                .and_then(WireScalar::into_u64)
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(())?;
            let controls = match value.applicable_delivery_controls {
                Some(WireArray::Values(values)) => values,
                Some(WireArray::Invalid) | None => return Err(()),
            };
            let mut parsed = Vec::with_capacity(controls.len());
            for control in controls {
                parsed.push(parse_delivery_control(control).ok_or(())?);
            }
            DriverTrustedSendProfileV1::try_trusted_injection(limit, parsed).map_err(|_| ())
        }
        Some("not_applicable") => {
            if value.applicable_delivery_controls.is_some()
                || value.max_credential_bearing_sends.is_some()
            {
                return Err(());
            }
            Ok(DriverTrustedSendProfileV1::not_applicable())
        }
        _ => Err(()),
    }
}

fn parse_destination_digests(
    value: Option<WireArray<WireScalar>>,
) -> Result<Vec<DriverCredentialDestinationDigest>, SecretCredentialAuthorizationV2Error> {
    let values = match value {
        Some(WireArray::Values(values)) => values,
        Some(WireArray::Invalid) | None => {
            return Err(authorization_error(
                SecretCredentialAuthorizationV2ErrorCode::EmptyApprovedDestinationDigests,
            ));
        }
    };
    if values.is_empty() {
        return Err(authorization_error(
            SecretCredentialAuthorizationV2ErrorCode::EmptyApprovedDestinationDigests,
        ));
    }
    if values.len() > MAX_DESTINATION_DIGESTS {
        return Err(authorization_error(
            SecretCredentialAuthorizationV2ErrorCode::TooManyApprovedDestinationDigests,
        ));
    }
    let mut digests = Vec::with_capacity(values.len());
    for value in values {
        let digest = value
            .into_string()
            .ok_or_else(|| {
                authorization_error(
                    SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationDigest,
                )
            })?
            .parse()
            .map_err(|_| {
                authorization_error(
                    SecretCredentialAuthorizationV2ErrorCode::InvalidDestinationDigest,
                )
            })?;
        digests.push(digest);
    }
    if has_duplicates(&digests) {
        return Err(authorization_error(
            SecretCredentialAuthorizationV2ErrorCode::DuplicateDestinationDigest,
        ));
    }
    digests.sort();
    Ok(digests)
}

fn parse_delivery_methods(
    value: Option<WireArray<WireScalar>>,
) -> Result<Vec<SecretDeliveryMethod>, SecretRefV2Error> {
    let values = match value {
        Some(WireArray::Values(values)) => values,
        Some(WireArray::Invalid) | None => {
            return Err(ref_error(SecretRefV2ErrorCode::InvalidDeliveryMethods));
        }
    };
    let mut methods = Vec::with_capacity(values.len());
    for value in values {
        methods.push(
            parse_delivery_method(value)
                .ok_or_else(|| ref_error(SecretRefV2ErrorCode::InvalidDeliveryMethods))?,
        );
    }
    validate_delivery_methods(&methods)?;
    Ok(methods)
}

fn validate_delivery_methods(methods: &[SecretDeliveryMethod]) -> Result<(), SecretRefV2Error> {
    if methods.is_empty()
        || methods.len() > MAX_DELIVERY_METHODS
        || has_duplicates(methods)
        || (methods.len() == 1 && methods[0] == SecretDeliveryMethod::EnvironmentVariable)
    {
        return Err(ref_error(SecretRefV2ErrorCode::InvalidDeliveryMethods));
    }
    Ok(())
}

fn parse_secret_ref_id(value: Option<WireScalar>) -> Result<SecretRefId, SecretRefV2Error> {
    value
        .and_then(WireScalar::into_string)
        .ok_or_else(|| ref_error(SecretRefV2ErrorCode::InvalidSecretRefId))?
        .parse()
        .map_err(|_| ref_error(SecretRefV2ErrorCode::InvalidSecretRefId))
}

fn parse_secret_provider_id(
    value: Option<WireScalar>,
) -> Result<SecretProviderId, SecretRefV2Error> {
    value
        .and_then(WireScalar::into_string)
        .ok_or_else(|| ref_error(SecretRefV2ErrorCode::InvalidSecretProviderId))?
        .parse()
        .map_err(|_| ref_error(SecretRefV2ErrorCode::InvalidSecretProviderId))
}

fn parse_tenant_id(value: Option<WireScalar>) -> Result<TenantId, SecretRefV2Error> {
    let text = value
        .and_then(WireScalar::into_string)
        .ok_or_else(|| ref_error(SecretRefV2ErrorCode::InvalidTenantId))?;
    let parsed: TenantId = text
        .parse()
        .map_err(|_| ref_error(SecretRefV2ErrorCode::InvalidTenantId))?;
    if parsed.is_nil() || parsed.to_string() != text {
        return Err(ref_error(SecretRefV2ErrorCode::InvalidTenantId));
    }
    Ok(parsed)
}

fn parse_label(
    value: Option<WireScalar>,
    code: SecretRefV2ErrorCode,
) -> Result<String, SecretRefV2Error> {
    value
        .and_then(WireScalar::into_string)
        .filter(|value| is_canonical_label(value))
        .ok_or_else(|| ref_error(code))
}

fn parse_positive_safe_integer(value: Option<WireScalar>) -> Option<u64> {
    value
        .and_then(WireScalar::into_u64)
        .filter(|value| (1..=MAX_SAFE_INTEGER).contains(value))
}

fn parse_classification(value: Option<WireScalar>) -> Option<SecretClassification> {
    match value.and_then(WireScalar::into_string)?.as_str() {
        "authentication_credential" => Some(SecretClassification::AuthenticationCredential),
        "signing_material" => Some(SecretClassification::SigningMaterial),
        "encryption_material" => Some(SecretClassification::EncryptionMaterial),
        "private_configuration" => Some(SecretClassification::PrivateConfiguration),
        "opaque_secret" => Some(SecretClassification::OpaqueSecret),
        _ => None,
    }
}

fn parse_exposure(value: Option<WireScalar>) -> Option<SecretDeliveryExposureProfile> {
    match value.and_then(WireScalar::into_string)?.as_str() {
        "trusted_injection" => Some(SecretDeliveryExposureProfile::TrustedInjection),
        "material_exposed" => Some(SecretDeliveryExposureProfile::MaterialExposed),
        _ => None,
    }
}

fn parse_offline_behavior(value: Option<WireScalar>) -> Option<SecretOfflineBehavior> {
    match value.and_then(WireScalar::into_string)?.as_str() {
        "deny" => Some(SecretOfflineBehavior::Deny),
        "continue_existing_until_expiry" => {
            Some(SecretOfflineBehavior::ContinueExistingUntilExpiry)
        }
        _ => None,
    }
}

fn parse_delivery_method(value: WireScalar) -> Option<SecretDeliveryMethod> {
    match value.into_string()?.as_str() {
        "inherited_fd" => Some(SecretDeliveryMethod::InheritedFd),
        "tmpfs_file" => Some(SecretDeliveryMethod::TmpfsFile),
        "one_shot_local_socket" => Some(SecretDeliveryMethod::OneShotLocalSocket),
        "orchestrator_projected_secret" => Some(SecretDeliveryMethod::OrchestratorProjectedSecret),
        "environment_variable" => Some(SecretDeliveryMethod::EnvironmentVariable),
        _ => None,
    }
}

fn parse_delivery_control(value: WireScalar) -> Option<SecretDeliveryControlKind> {
    match value.into_string()?.as_str() {
        "core_dump" => Some(SecretDeliveryControlKind::CoreDump),
        "ptrace_debug" => Some(SecretDeliveryControlKind::PtraceDebug),
        "child_inheritance" => Some(SecretDeliveryControlKind::ChildInheritance),
        "output_capture" => Some(SecretDeliveryControlKind::OutputCapture),
        "swap_page_dump" => Some(SecretDeliveryControlKind::SwapPageDump),
        "generic_cache" => Some(SecretDeliveryControlKind::GenericCache),
        "orchestrator_projection" => Some(SecretDeliveryControlKind::OrchestratorProjection),
        "trusted_injection_boundary" => Some(SecretDeliveryControlKind::TrustedInjectionBoundary),
        "destination_network_egress" => Some(SecretDeliveryControlKind::DestinationNetworkEgress),
        "filesystem_sink_egress" => Some(SecretDeliveryControlKind::FilesystemSinkEgress),
        "ipc_egress" => Some(SecretDeliveryControlKind::IpcEgress),
        "child_process_egress" => Some(SecretDeliveryControlKind::ChildProcessEgress),
        "proxy_egress" => Some(SecretDeliveryControlKind::ProxyEgress),
        "alternate_mount_egress" => Some(SecretDeliveryControlKind::AlternateMountEgress),
        _ => None,
    }
}

fn parse_lease_policy(value: Option<LeasePolicyWire>) -> Option<SecretLeasePolicy> {
    let value = value?;
    if value.invalid_shape {
        return None;
    }
    SecretLeasePolicy::try_new(
        value.max_lease_duration_seconds?.into_u64()?,
        value.max_continuous_lifetime_seconds?.into_u64()?,
        value.max_uses?.into_u64()?,
        value.renewable?.into_bool()?,
        value.clock_skew_tolerance_seconds?.into_u64()?,
    )
    .ok()
}

fn profile_matches_exposure(
    profile: &DriverTrustedSendProfileV1,
    exposure: SecretDeliveryExposureProfile,
) -> bool {
    matches!(
        (profile.kind(), exposure),
        (
            "trusted_injection",
            SecretDeliveryExposureProfile::TrustedInjection
        ) | (
            "not_applicable",
            SecretDeliveryExposureProfile::MaterialExposed
        )
    )
}

fn delivery_method_wire(method: SecretDeliveryMethod) -> &'static str {
    match method {
        SecretDeliveryMethod::InheritedFd => "inherited_fd",
        SecretDeliveryMethod::TmpfsFile => "tmpfs_file",
        SecretDeliveryMethod::OneShotLocalSocket => "one_shot_local_socket",
        SecretDeliveryMethod::OrchestratorProjectedSecret => "orchestrator_projected_secret",
        SecretDeliveryMethod::EnvironmentVariable => "environment_variable",
    }
}

fn has_duplicates<T: Eq + std::hash::Hash>(values: &[T]) -> bool {
    let mut seen = HashSet::with_capacity(values.len());
    values.iter().any(|value| !seen.insert(value))
}

fn sort_by_canonical_bytes<T: Serialize>(values: &mut Vec<T>) -> Result<(), serde_json::Error> {
    let mut keyed = values
        .drain(..)
        .map(|value| serde_json::to_vec(&value).map(|bytes| (bytes, value)))
        .collect::<Result<Vec<_>, _>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    values.extend(keyed.into_iter().map(|(_, value)| value));
    Ok(())
}

fn is_canonical_label(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_LABEL_BYTES
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_destination_schema(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_LABEL_BYTES || !value.is_ascii() {
        return false;
    }
    let Some((prefix, version)) = value.rsplit_once(".v") else {
        return false;
    };
    is_canonical_label(prefix)
        && !version.is_empty()
        && version.as_bytes()[0].is_ascii_digit()
        && version.as_bytes()[0] != b'0'
        && version.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_exact_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 27
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[26] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 26) && !byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| -> u32 {
        bytes[range]
            .iter()
            .fold(0, |value, byte| value * 10 + u32::from(byte - b'0'))
    };
    let year = number(0..4) as i32;
    let month = number(5..7) as u8;
    let day = number(8..10) as u8;
    let hour = number(11..13) as u8;
    let minute = number(14..16) as u8;
    let second = number(17..19) as u8;
    let microsecond = number(20..26);
    let Ok(month) = time::Month::try_from(month) else {
        return false;
    };
    time::Date::from_calendar_date(year, month, day).is_ok()
        && time::Time::from_hms_micro(hour, minute, second, microsecond).is_ok()
}

fn domain_digest(domain: &str, canonical: &[u8]) -> String {
    let mut input = Vec::with_capacity(domain.len() + 1 + canonical.len());
    input.extend_from_slice(domain.as_bytes());
    input.push(0);
    input.extend_from_slice(canonical);
    format!("blake3:{}", blake3::hash(&input).to_hex())
}

#[allow(clippy::too_many_arguments)]
fn serialize_ref_fields<S, A>(
    serializer: S,
    name: &'static str,
    schema: &'static str,
    secret_ref_id: &SecretRefId,
    secret_ref_revision: u64,
    tenant_id: &TenantId,
    secret_provider_id: &SecretProviderId,
    provider_namespace: &str,
    logical_name: &str,
    provider_version_ref: &SecretProviderVersionRef,
    classification: SecretClassification,
    allowed_credential_bindings: &[A],
    allowed_delivery_methods: &[SecretDeliveryMethod],
    lease_policy: &SecretLeasePolicy,
    offline_behavior: SecretOfflineBehavior,
    created_at: &str,
    disabled_at: Option<&str>,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    A: Serialize,
{
    let field_count = if disabled_at.is_some() { 15 } else { 14 };
    let mut state = serializer.serialize_struct(name, field_count)?;
    state.serialize_field("allowed_credential_bindings", allowed_credential_bindings)?;
    state.serialize_field("allowed_delivery_methods", allowed_delivery_methods)?;
    state.serialize_field("classification", &classification)?;
    state.serialize_field("created_at", created_at)?;
    if let Some(disabled_at) = disabled_at {
        state.serialize_field("disabled_at", disabled_at)?;
    }
    state.serialize_field("lease_policy", lease_policy)?;
    state.serialize_field("logical_name", logical_name)?;
    state.serialize_field("offline_behavior", &offline_behavior)?;
    state.serialize_field("provider_namespace", provider_namespace)?;
    state.serialize_field("provider_version_ref", provider_version_ref)?;
    state.serialize_field("schema_version", schema)?;
    state.serialize_field("secret_provider_id", secret_provider_id)?;
    state.serialize_field("secret_ref_id", secret_ref_id)?;
    state.serialize_field("secret_ref_revision", &secret_ref_revision)?;
    state.serialize_field("tenant_id", tenant_id)?;
    state.end()
}

fn authorization_error(
    code: SecretCredentialAuthorizationV2ErrorCode,
) -> SecretCredentialAuthorizationV2Error {
    SecretCredentialAuthorizationV2Error { code }
}

fn ref_error(code: SecretRefV2ErrorCode) -> SecretRefV2Error {
    SecretRefV2Error { code }
}

#[derive(Clone, Copy)]
struct IngressBudget {
    bytes: usize,
    depth: usize,
    tokens: usize,
    members: usize,
    elements: usize,
    string_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct IngressStats {
    depth: usize,
    tokens: usize,
    members: usize,
    elements: usize,
}

fn preflight_json(input: &[u8], budget: IngressBudget) -> Result<IngressStats, ()> {
    if input.len() > budget.bytes {
        return Err(());
    }
    validate_numeric_tokens(input)?;
    let mut scanner = PreflightScanner {
        budget,
        stats: IngressStats::default(),
    };
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    PreflightSeed {
        scanner: &mut scanner,
        depth: 1,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| ())?;
    deserializer.end().map_err(|_| ())?;
    Ok(scanner.stats)
}

fn validate_numeric_tokens(input: &[u8]) -> Result<(), ()> {
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < input.len() {
        let byte = input[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < input.len()
                && matches!(input[index], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
            {
                index += 1;
            }
            let token = std::str::from_utf8(&input[start..index]).map_err(|_| ())?;
            if token.contains(['.', 'e', 'E']) {
                let parsed = token.parse::<f64>().map_err(|_| ())?;
                if !parsed.is_finite() {
                    return Err(());
                }
            } else if token.starts_with('-') {
                token.parse::<i128>().map_err(|_| ())?;
            } else {
                token.parse::<u128>().map_err(|_| ())?;
            }
            continue;
        }
        index += 1;
    }
    Ok(())
}

struct PreflightScanner {
    budget: IngressBudget,
    stats: IngressStats,
}

impl PreflightScanner {
    fn reject(&mut self) -> PreflightError {
        PreflightError
    }

    fn add_tokens(&mut self, count: usize) -> Result<(), PreflightError> {
        self.stats.tokens = self
            .stats
            .tokens
            .checked_add(count)
            .ok_or_else(|| self.reject())?;
        if self.stats.tokens > self.budget.tokens {
            return Err(self.reject());
        }
        Ok(())
    }

    fn enter_container(&mut self, depth: usize) -> Result<(), PreflightError> {
        if depth > self.budget.depth {
            return Err(self.reject());
        }
        self.stats.depth = self.stats.depth.max(depth);
        self.add_tokens(2)
    }

    fn add_member(&mut self, name: &str) -> Result<(), PreflightError> {
        self.check_string(name)?;
        self.stats.members = self
            .stats
            .members
            .checked_add(1)
            .ok_or_else(|| self.reject())?;
        if self.stats.members > self.budget.members {
            return Err(self.reject());
        }
        self.add_tokens(1)
    }

    fn add_element(&mut self) -> Result<(), PreflightError> {
        self.stats.elements = self
            .stats
            .elements
            .checked_add(1)
            .ok_or_else(|| self.reject())?;
        if self.stats.elements > self.budget.elements {
            return Err(self.reject());
        }
        Ok(())
    }

    fn check_string(&mut self, value: &str) -> Result<(), PreflightError> {
        if value.len() > self.budget.string_bytes {
            return Err(self.reject());
        }
        Ok(())
    }

    fn add_scalar(&mut self) -> Result<(), PreflightError> {
        self.add_tokens(1)
    }
}

#[derive(Clone, Copy, Debug)]
struct PreflightError;

impl fmt::Display for PreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid_contract_shape")
    }
}

impl Error for PreflightError {}

struct PreflightSeed<'a> {
    scanner: &'a mut PreflightScanner,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for PreflightSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PreflightVisitor {
            scanner: self.scanner,
            depth: self.depth,
        })
    }
}

struct PreflightVisitor<'a> {
    scanner: &'a mut PreflightScanner,
    depth: usize,
}

impl<'de> Visitor<'de> for PreflightVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded secret-reference JSON")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.scanner.add_scalar().map_err(E::custom)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.scanner.add_scalar().map_err(E::custom)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.scanner.add_scalar().map_err(E::custom)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.scanner.add_scalar().map_err(E::custom)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.scanner.check_string(value).map_err(E::custom)?;
        self.scanner.add_scalar().map_err(E::custom)
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_str(&value)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.scanner.add_scalar().map_err(E::custom)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.scanner.add_scalar().map_err(E::custom)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.scanner
            .enter_container(self.depth)
            .map_err(A::Error::custom)?;
        while sequence
            .next_element_seed(PreflightSeed {
                scanner: self.scanner,
                depth: self.depth + 1,
            })?
            .is_some()
        {
            self.scanner.add_element().map_err(A::Error::custom)?;
        }
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        self.scanner
            .enter_container(self.depth)
            .map_err(A::Error::custom)?;
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            self.scanner.add_member(&name).map_err(A::Error::custom)?;
            if !names.insert(name) {
                return Err(A::Error::custom(self.scanner.reject()));
            }
            map.next_value_seed(PreflightSeed {
                scanner: self.scanner,
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/unit/secret_ref_tests.rs"]
mod tests;
