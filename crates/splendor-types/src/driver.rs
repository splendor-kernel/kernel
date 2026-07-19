//! Behavior-free Driver Registry credential-sink contracts.
//!
//! These values describe an operation's declared credential slots. They grant
//! no authority and perform no registry, projection, credential, or I/O work.
//! Untrusted serialized declarations must enter through bounded
//! [`DriverOperationCredentialSinksV1::from_json_slice`]; typed constructors are
//! for already typed owner code and are not a byte-ingress substitute.

use crate::{
    DriverOperationRef, SecretClassification, SecretDeliveryControlKind,
    SecretDeliveryExposureProfile, SecretUseIntent,
};
use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Canonical v1 schema used by declaration-bound driver operation references.
pub const DRIVER_OPERATION_SCHEMA_V1: &str = "splendor.driver.operation.v1";

/// Canonical v1 operation credential-sink declaration schema.
pub const DRIVER_OPERATION_CREDENTIAL_SINKS_SCHEMA_V1: &str =
    "splendor.driver.operation_credential_sinks.v1";

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_NAME_BYTES: usize = 128;
const MAX_DESTINATION_SCHEMA_BYTES: usize = 128;
const MAX_CREDENTIAL_SINKS: usize = 16;
const MAX_CLASSIFICATIONS: usize = 5;
const MAX_INTENTS: usize = 6;
const MAX_DELIVERY_CONTROLS: usize = 8;
const MAX_INGRESS_BYTES: usize = 32_768;
const MAX_INGRESS_DEPTH: usize = 32;
const MAX_INGRESS_TOKENS: usize = 1_024;
const MAX_INGRESS_MEMBERS: usize = 192;
const MAX_INGRESS_ELEMENTS: usize = 384;
const MAX_INGRESS_STRING_BYTES: usize = 256;
const INVALID_OPERATION: &str = "invalid_driver_operation";
const INVALID_SLOT: &str = "invalid_secret_credential_slot_id";
const NIL_SLOT: &str = "nil_secret_credential_slot_id";
const INVALID_DIGEST: &str = "invalid_driver_credential_destination_digest";

/// Validates the existing standalone operation reference for use at the strict
/// Driver Registry v1 declaration boundary.
pub fn validate_driver_operation_ref_v1(
    value: &DriverOperationRef,
) -> Result<(), DriverOperationRefV1ValidationError> {
    if value.schema_version != DRIVER_OPERATION_SCHEMA_V1
        || !is_canonical_name(&value.driver)
        || !is_canonical_name(&value.operation)
    {
        return Err(DriverOperationRefV1ValidationError::Invalid);
    }
    Ok(())
}

fn is_canonical_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_NAME_BYTES || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..].iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    })
}

/// Fixed, non-reflecting operation-reference validation error.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum DriverOperationRefV1ValidationError {
    /// The operation reference is not the exact canonical v1 form.
    Invalid,
}

impl fmt::Display for DriverOperationRefV1ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(INVALID_OPERATION)
    }
}

impl fmt::Debug for DriverOperationRefV1ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(INVALID_OPERATION)
    }
}

impl Error for DriverOperationRefV1ValidationError {}

/// Nominal identity for one credential slot declared by a driver operation.
///
/// This identity is not interchangeable with any C03 secret identity:
///
/// ```compile_fail
/// use splendor_types::{SecretCredentialSlotId, SecretRefId};
/// let slot: SecretCredentialSlotId =
///     "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001".parse().unwrap();
/// let _: SecretRefId = slot;
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SecretCredentialSlotId(Uuid);

impl SecretCredentialSlotId {
    /// Parses one exact lowercase hyphenated, non-nil UUID.
    pub fn parse(value: &str) -> Result<Self, SecretCredentialSlotIdError> {
        if value.len() != 36 || !value.is_ascii() {
            return Err(SecretCredentialSlotIdError::InvalidFormat);
        }
        let parsed =
            Uuid::parse_str(value).map_err(|_| SecretCredentialSlotIdError::InvalidFormat)?;
        if parsed.hyphenated().to_string() != value {
            return Err(SecretCredentialSlotIdError::InvalidFormat);
        }
        Self::try_from(parsed)
    }

    /// Returns the validated UUID value.
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl TryFrom<Uuid> for SecretCredentialSlotId {
    type Error = SecretCredentialSlotIdError;

    fn try_from(value: Uuid) -> Result<Self, Self::Error> {
        if value.is_nil() {
            return Err(SecretCredentialSlotIdError::Nil);
        }
        Ok(Self(value))
    }
}

impl FromStr for SecretCredentialSlotId {
    type Err = SecretCredentialSlotIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for SecretCredentialSlotId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0.hyphenated())
    }
}

impl fmt::Debug for SecretCredentialSlotId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Ord for SecretCredentialSlotId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl PartialOrd for SecretCredentialSlotId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for SecretCredentialSlotId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SecretCredentialSlotId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SecretCredentialSlotIdVisitor)
    }
}

struct SecretCredentialSlotIdVisitor;

impl<'de> Visitor<'de> for SecretCredentialSlotIdVisitor {
    type Value = SecretCredentialSlotId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(INVALID_SLOT)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        SecretCredentialSlotId::parse(value).map_err(|error| E::custom(error.to_string()))
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

    fn visit_char<E>(self, _value: char) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_SLOT))
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_SLOT))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_SLOT))
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_SLOT))
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_SLOT))
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_SLOT))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_SLOT))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_SLOT))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_SLOT))
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        Err(A::Error::custom(INVALID_SLOT))
    }

    fn visit_map<A>(self, _map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        Err(A::Error::custom(INVALID_SLOT))
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_SLOT))
    }

    fn visit_byte_buf<E>(self, _value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_SLOT))
    }
}

/// Fixed, non-reflecting credential-slot parse error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecretCredentialSlotIdError {
    /// The candidate is not exact canonical UUID text.
    InvalidFormat,
    /// The candidate is the nil UUID.
    Nil,
}

impl fmt::Display for SecretCredentialSlotIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFormat => INVALID_SLOT,
            Self::Nil => NIL_SLOT,
        })
    }
}

impl Error for SecretCredentialSlotIdError {}

/// Exact BLAKE3 destination equality binding.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DriverCredentialDestinationDigest([u8; 32]);

impl DriverCredentialDestinationDigest {
    /// Parses `blake3:` followed by exactly 64 lowercase hexadecimal digits.
    pub fn parse(value: &str) -> Result<Self, DriverCredentialDestinationDigestError> {
        let bytes = value.as_bytes();
        if bytes.len() != 71 || !bytes.starts_with(b"blake3:") {
            return Err(DriverCredentialDestinationDigestError::InvalidFormat);
        }
        let mut digest = [0_u8; 32];
        for (index, pair) in bytes[7..].chunks_exact(2).enumerate() {
            let high = decode_lower_hex(pair[0])
                .ok_or(DriverCredentialDestinationDigestError::InvalidFormat)?;
            let low = decode_lower_hex(pair[1])
                .ok_or(DriverCredentialDestinationDigestError::InvalidFormat)?;
            digest[index] = (high << 4) | low;
        }
        Ok(Self(digest))
    }

    /// Returns the validated BLAKE3 output bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn decode_lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl FromStr for DriverCredentialDestinationDigest {
    type Err = DriverCredentialDestinationDigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for DriverCredentialDestinationDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("blake3:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for DriverCredentialDestinationDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Serialize for DriverCredentialDestinationDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DriverCredentialDestinationDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DriverCredentialDestinationDigestVisitor)
    }
}

struct DriverCredentialDestinationDigestVisitor;

impl<'de> Visitor<'de> for DriverCredentialDestinationDigestVisitor {
    type Value = DriverCredentialDestinationDigest;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(INVALID_DIGEST)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        DriverCredentialDestinationDigest::parse(value).map_err(|_| E::custom(INVALID_DIGEST))
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

    fn visit_char<E>(self, _value: char) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_DIGEST))
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_DIGEST))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_DIGEST))
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_DIGEST))
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_DIGEST))
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_DIGEST))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_DIGEST))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_DIGEST))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_DIGEST))
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        Err(A::Error::custom(INVALID_DIGEST))
    }

    fn visit_map<A>(self, _map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        Err(A::Error::custom(INVALID_DIGEST))
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_DIGEST))
    }

    fn visit_byte_buf<E>(self, _value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(INVALID_DIGEST))
    }
}

/// Fixed, non-reflecting destination-digest parse error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DriverCredentialDestinationDigestError {
    /// The candidate is not the exact BLAKE3 wire representation.
    InvalidFormat,
}

impl fmt::Display for DriverCredentialDestinationDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(INVALID_DIGEST)
    }
}

impl Error for DriverCredentialDestinationDigestError {}

/// Closed declaration/projection validation result codes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DriverCredentialSinkContractErrorCode {
    InvalidContractShape,
    InvalidSchemaVersion,
    InvalidDriverOperation,
    InvalidDeclarationRevision,
    InvalidCredentialSlot,
    EmptyCredentialSinks,
    TooManyCredentialSinks,
    DuplicateCredentialSlot,
    InvalidClassificationSet,
    InvalidIntentSet,
    InvalidDestinationSchema,
    MissingTrustedSendProfile,
    ExposureProfileMismatch,
    InvalidSendLimit,
    InvalidControlSet,
    TrustedInjectionBoundaryRequired,
    NotApplicablePayloadForbidden,
    InvalidDestinationProjection,
    DestinationDigestMismatch,
}

impl DriverCredentialSinkContractErrorCode {
    /// Returns the exact public snake-case code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidContractShape => "invalid_contract_shape",
            Self::InvalidSchemaVersion => "invalid_schema_version",
            Self::InvalidDriverOperation => "invalid_driver_operation",
            Self::InvalidDeclarationRevision => "invalid_declaration_revision",
            Self::InvalidCredentialSlot => "invalid_credential_slot",
            Self::EmptyCredentialSinks => "empty_credential_sinks",
            Self::TooManyCredentialSinks => "too_many_credential_sinks",
            Self::DuplicateCredentialSlot => "duplicate_credential_slot",
            Self::InvalidClassificationSet => "invalid_classification_set",
            Self::InvalidIntentSet => "invalid_intent_set",
            Self::InvalidDestinationSchema => "invalid_destination_schema",
            Self::MissingTrustedSendProfile => "missing_trusted_send_profile",
            Self::ExposureProfileMismatch => "exposure_profile_mismatch",
            Self::InvalidSendLimit => "invalid_send_limit",
            Self::InvalidControlSet => "invalid_control_set",
            Self::TrustedInjectionBoundaryRequired => "trusted_injection_boundary_required",
            Self::NotApplicablePayloadForbidden => "not_applicable_payload_forbidden",
            Self::InvalidDestinationProjection => "invalid_destination_projection",
            Self::DestinationDigestMismatch => "destination_digest_mismatch",
        }
    }
}

impl fmt::Display for DriverCredentialSinkContractErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for DriverCredentialSinkContractErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// Code-only, non-reflecting declaration/projection validation error.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct DriverCredentialSinkContractError {
    code: DriverCredentialSinkContractErrorCode,
}

impl DriverCredentialSinkContractError {
    fn new(code: DriverCredentialSinkContractErrorCode) -> Self {
        Self { code }
    }

    /// Returns the fixed validation code.
    pub const fn code(&self) -> DriverCredentialSinkContractErrorCode {
        self.code
    }
}

impl fmt::Display for DriverCredentialSinkContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl fmt::Debug for DriverCredentialSinkContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl Error for DriverCredentialSinkContractError {}

impl Serialize for DriverCredentialSinkContractError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DriverCredentialSinkContractError", 1)?;
        state.serialize_field("code", &self.code)?;
        state.end()
    }
}

/// Closed, validated trusted-send declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverTrustedSendProfileV1 {
    profile: DriverTrustedSendProfileKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DriverTrustedSendProfileKind {
    TrustedInjection {
        max_credential_bearing_sends: u8,
        applicable_delivery_controls: Vec<SecretDeliveryControlKind>,
    },
    NotApplicable,
}

impl DriverTrustedSendProfileV1 {
    /// Constructs a validated trusted-injection profile.
    pub fn try_trusted_injection(
        max_credential_bearing_sends: u8,
        mut applicable_delivery_controls: Vec<SecretDeliveryControlKind>,
    ) -> Result<Self, DriverCredentialSinkContractError> {
        if !(1..=8).contains(&max_credential_bearing_sends) {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::InvalidSendLimit,
            ));
        }
        if applicable_delivery_controls.is_empty()
            || applicable_delivery_controls.len() > MAX_DELIVERY_CONTROLS
            || has_duplicates(&applicable_delivery_controls)
        {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::InvalidControlSet,
            ));
        }
        if !applicable_delivery_controls
            .contains(&SecretDeliveryControlKind::TrustedInjectionBoundary)
        {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::TrustedInjectionBoundaryRequired,
            ));
        }
        applicable_delivery_controls.sort_by_key(|value| delivery_control_wire(*value));
        Ok(Self {
            profile: DriverTrustedSendProfileKind::TrustedInjection {
                max_credential_bearing_sends,
                applicable_delivery_controls,
            },
        })
    }

    /// Constructs the fieldless material-exposure profile.
    pub const fn not_applicable() -> Self {
        Self {
            profile: DriverTrustedSendProfileKind::NotApplicable,
        }
    }

    /// Returns the exact profile tag.
    pub const fn kind(&self) -> &'static str {
        match self.profile {
            DriverTrustedSendProfileKind::TrustedInjection { .. } => "trusted_injection",
            DriverTrustedSendProfileKind::NotApplicable => "not_applicable",
        }
    }

    /// Returns the bounded send limit for trusted injection.
    pub const fn max_credential_bearing_sends(&self) -> Option<u8> {
        match self.profile {
            DriverTrustedSendProfileKind::TrustedInjection {
                max_credential_bearing_sends,
                ..
            } => Some(max_credential_bearing_sends),
            DriverTrustedSendProfileKind::NotApplicable => None,
        }
    }

    /// Returns the normalized controls for trusted injection.
    pub fn applicable_delivery_controls(&self) -> &[SecretDeliveryControlKind] {
        match &self.profile {
            DriverTrustedSendProfileKind::TrustedInjection {
                applicable_delivery_controls,
                ..
            } => applicable_delivery_controls,
            DriverTrustedSendProfileKind::NotApplicable => &[],
        }
    }

    fn matches_exposure(&self, exposure: SecretDeliveryExposureProfile) -> bool {
        matches!(
            (&self.profile, exposure),
            (
                DriverTrustedSendProfileKind::TrustedInjection { .. },
                SecretDeliveryExposureProfile::TrustedInjection
            ) | (
                DriverTrustedSendProfileKind::NotApplicable,
                SecretDeliveryExposureProfile::MaterialExposed
            )
        )
    }
}

impl Serialize for DriverTrustedSendProfileV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.profile {
            DriverTrustedSendProfileKind::TrustedInjection {
                max_credential_bearing_sends,
                applicable_delivery_controls,
            } => {
                let mut state = serializer.serialize_struct("DriverTrustedSendProfileV1", 3)?;
                state.serialize_field(
                    "applicable_delivery_controls",
                    applicable_delivery_controls,
                )?;
                state.serialize_field("kind", "trusted_injection")?;
                state.serialize_field(
                    "max_credential_bearing_sends",
                    max_credential_bearing_sends,
                )?;
                state.end()
            }
            DriverTrustedSendProfileKind::NotApplicable => {
                let mut state = serializer.serialize_struct("DriverTrustedSendProfileV1", 1)?;
                state.serialize_field("kind", "not_applicable")?;
                state.end()
            }
        }
    }
}

/// One validated credential sink in an operation declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverOperationCredentialSinkV1 {
    credential_slot_id: SecretCredentialSlotId,
    allowed_classifications: Vec<SecretClassification>,
    allowed_intents: Vec<SecretUseIntent>,
    destination_schema: String,
    delivery_exposure_profile: SecretDeliveryExposureProfile,
    trusted_send_profile: DriverTrustedSendProfileV1,
}

impl DriverOperationCredentialSinkV1 {
    /// Constructs one validated sink entry from already typed values.
    pub fn try_new(
        credential_slot_id: SecretCredentialSlotId,
        mut allowed_classifications: Vec<SecretClassification>,
        mut allowed_intents: Vec<SecretUseIntent>,
        destination_schema: impl Into<String>,
        delivery_exposure_profile: SecretDeliveryExposureProfile,
        trusted_send_profile: DriverTrustedSendProfileV1,
    ) -> Result<Self, DriverCredentialSinkContractError> {
        if allowed_classifications.is_empty()
            || allowed_classifications.len() > MAX_CLASSIFICATIONS
            || has_duplicates(&allowed_classifications)
        {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::InvalidClassificationSet,
            ));
        }
        if allowed_intents.is_empty()
            || allowed_intents.len() > MAX_INTENTS
            || has_duplicates(&allowed_intents)
        {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::InvalidIntentSet,
            ));
        }
        let destination_schema = destination_schema.into();
        if !is_destination_schema(&destination_schema) {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::InvalidDestinationSchema,
            ));
        }
        if !trusted_send_profile.matches_exposure(delivery_exposure_profile) {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::ExposureProfileMismatch,
            ));
        }
        allowed_classifications.sort_by_key(|value| classification_wire(*value));
        allowed_intents.sort_by_key(|value| intent_wire(*value));
        Ok(Self {
            credential_slot_id,
            allowed_classifications,
            allowed_intents,
            destination_schema,
            delivery_exposure_profile,
            trusted_send_profile,
        })
    }

    pub const fn credential_slot_id(&self) -> SecretCredentialSlotId {
        self.credential_slot_id
    }

    pub fn allowed_classifications(&self) -> &[SecretClassification] {
        &self.allowed_classifications
    }

    pub fn allowed_intents(&self) -> &[SecretUseIntent] {
        &self.allowed_intents
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
}

impl Serialize for DriverOperationCredentialSinkV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DriverOperationCredentialSinkV1", 6)?;
        state.serialize_field("allowed_classifications", &self.allowed_classifications)?;
        state.serialize_field("allowed_intents", &self.allowed_intents)?;
        state.serialize_field("credential_slot_id", &self.credential_slot_id)?;
        state.serialize_field("delivery_exposure_profile", &self.delivery_exposure_profile)?;
        state.serialize_field("destination_schema", &self.destination_schema)?;
        state.serialize_field("trusted_send_profile", &self.trusted_send_profile)?;
        state.end()
    }
}

/// Validated, canonical operation-level credential-sink declaration.
///
/// This type intentionally does not implement `Deserialize`:
///
/// ```compile_fail
/// use splendor_types::DriverOperationCredentialSinksV1;
/// let _: DriverOperationCredentialSinksV1 = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverOperationCredentialSinksV1 {
    driver_operation: DriverOperationRef,
    driver_declaration_revision: u64,
    credential_sinks: Vec<DriverOperationCredentialSinkV1>,
}

impl DriverOperationCredentialSinksV1 {
    /// Parses one untrusted declaration through the exact bounded v1 ingress.
    pub fn from_json_slice(input: &[u8]) -> Result<Self, DriverCredentialSinkContractError> {
        struct DriverOperationRefWireV1(Option<DriverOperationRef>);

        struct DriverOperationRefWireV1Visitor;

        impl<'de> Visitor<'de> for DriverOperationRefWireV1Visitor {
            type Value = DriverOperationRefWireV1;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(INVALID_OPERATION)
            }

            fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(DriverOperationRefWireV1(None))
            }

            fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(DriverOperationRefWireV1(None))
            }

            fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(DriverOperationRefWireV1(None))
            }

            fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(DriverOperationRefWireV1(None))
            }

            fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(DriverOperationRefWireV1(None))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                while sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(DriverOperationRefWireV1(None))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut driver = None;
                let mut operation = None;
                let mut schema_version = None;
                let mut invalid = false;
                while let Some(name) = map.next_key::<String>()? {
                    let value = map.next_value::<serde_json::Value>()?;
                    let target = match name.as_str() {
                        "driver" => &mut driver,
                        "operation" => &mut operation,
                        "schema_version" => &mut schema_version,
                        _ => {
                            invalid = true;
                            continue;
                        }
                    };
                    if target.is_some() {
                        invalid = true;
                    }
                    *target = value.as_str().map(str::to_owned);
                    if target.is_none() {
                        invalid = true;
                    }
                }
                let operation = match (invalid, driver, operation, schema_version) {
                    (false, Some(driver), Some(operation), Some(schema_version)) => {
                        Some(DriverOperationRef {
                            driver,
                            operation,
                            schema_version,
                        })
                    }
                    _ => None,
                };
                Ok(DriverOperationRefWireV1(operation))
            }
        }

        impl<'de> Deserialize<'de> for DriverOperationRefWireV1 {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_any(DriverOperationRefWireV1Visitor)
            }
        }

        #[derive(Deserialize)]
        struct DriverOperationCredentialSinksWireV1 {
            schema_version: Option<serde_json::Value>,
            driver_operation: Option<DriverOperationRefWireV1>,
            driver_declaration_revision: Option<serde_json::Value>,
            credential_sinks: Option<serde_json::Value>,
            #[serde(flatten)]
            unknown_fields: std::collections::BTreeMap<String, serde_json::Value>,
        }

        preflight_declaration(input).map_err(|_| {
            contract_error(DriverCredentialSinkContractErrorCode::InvalidContractShape)
        })?;
        let wire: DriverOperationCredentialSinksWireV1 =
            serde_json::from_slice(input).map_err(|_| {
                contract_error(DriverCredentialSinkContractErrorCode::InvalidContractShape)
            })?;
        parse_declaration_wire(
            !wire.unknown_fields.is_empty(),
            wire.schema_version,
            wire.driver_operation.and_then(|operation| operation.0),
            wire.driver_declaration_revision,
            wire.credential_sinks,
        )
    }

    /// Constructs a canonical declaration from already typed values.
    pub fn try_new(
        driver_operation: DriverOperationRef,
        driver_declaration_revision: u64,
        mut credential_sinks: Vec<DriverOperationCredentialSinkV1>,
    ) -> Result<Self, DriverCredentialSinkContractError> {
        validate_driver_operation_ref_v1(&driver_operation).map_err(|_| {
            contract_error(DriverCredentialSinkContractErrorCode::InvalidDriverOperation)
        })?;
        if !(1..=MAX_SAFE_INTEGER).contains(&driver_declaration_revision) {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::InvalidDeclarationRevision,
            ));
        }
        if credential_sinks.is_empty() {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::EmptyCredentialSinks,
            ));
        }
        if credential_sinks.len() > MAX_CREDENTIAL_SINKS {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::TooManyCredentialSinks,
            ));
        }
        let mut slots = HashSet::with_capacity(credential_sinks.len());
        if credential_sinks
            .iter()
            .any(|sink| !slots.insert(sink.credential_slot_id))
        {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::DuplicateCredentialSlot,
            ));
        }
        credential_sinks.sort_by_key(|sink| sink.credential_slot_id);
        Ok(Self {
            driver_operation,
            driver_declaration_revision,
            credential_sinks,
        })
    }

    pub const fn schema_version(&self) -> &'static str {
        DRIVER_OPERATION_CREDENTIAL_SINKS_SCHEMA_V1
    }

    pub const fn driver_operation(&self) -> &DriverOperationRef {
        &self.driver_operation
    }

    pub const fn driver_declaration_revision(&self) -> u64 {
        self.driver_declaration_revision
    }

    pub fn credential_sinks(&self) -> &[DriverOperationCredentialSinkV1] {
        &self.credential_sinks
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct IngressStats {
    depth: usize,
    tokens: usize,
    members: usize,
    elements: usize,
}

#[derive(Default)]
struct PreflightScanner {
    stats: IngressStats,
}

fn preflight_declaration(input: &[u8]) -> Result<IngressStats, ()> {
    if input.len() > MAX_INGRESS_BYTES {
        return Err(());
    }
    validate_numeric_tokens(input)?;
    let mut scanner = PreflightScanner::default();
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

impl PreflightScanner {
    fn add_tokens(&mut self, count: usize) -> Result<(), PreflightError> {
        self.stats.tokens = self.stats.tokens.checked_add(count).ok_or(PreflightError)?;
        if self.stats.tokens > MAX_INGRESS_TOKENS {
            return Err(PreflightError);
        }
        Ok(())
    }

    fn enter_container(&mut self, depth: usize) -> Result<(), PreflightError> {
        if depth > MAX_INGRESS_DEPTH {
            return Err(PreflightError);
        }
        self.stats.depth = self.stats.depth.max(depth);
        self.add_tokens(2)
    }

    fn add_member(&mut self, name: &str) -> Result<(), PreflightError> {
        if name.len() > MAX_INGRESS_STRING_BYTES {
            return Err(PreflightError);
        }
        self.stats.members = self.stats.members.checked_add(1).ok_or(PreflightError)?;
        if self.stats.members > MAX_INGRESS_MEMBERS {
            return Err(PreflightError);
        }
        self.add_tokens(1)
    }

    fn add_element(&mut self) -> Result<(), PreflightError> {
        self.stats.elements = self.stats.elements.checked_add(1).ok_or(PreflightError)?;
        if self.stats.elements > MAX_INGRESS_ELEMENTS {
            return Err(PreflightError);
        }
        Ok(())
    }

    fn add_scalar(&mut self) -> Result<(), PreflightError> {
        self.add_tokens(1)
    }

    fn add_string(&mut self, value: &str) -> Result<(), PreflightError> {
        if value.len() > MAX_INGRESS_STRING_BYTES {
            return Err(PreflightError);
        }
        self.add_scalar()
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
        formatter.write_str("bounded JSON")
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

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.scanner.add_scalar().map_err(E::custom)
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E>
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
        self.scanner.add_string(value).map_err(E::custom)
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
                return Err(A::Error::custom(PreflightError));
            }
            map.next_value_seed(PreflightSeed {
                scanner: self.scanner,
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

fn parse_declaration_wire(
    has_unknown_fields: bool,
    schema_version: Option<serde_json::Value>,
    driver_operation: Option<DriverOperationRef>,
    driver_declaration_revision: Option<serde_json::Value>,
    credential_sinks: Option<serde_json::Value>,
) -> Result<DriverOperationCredentialSinksV1, DriverCredentialSinkContractError> {
    if has_unknown_fields {
        return Err(contract_error(
            DriverCredentialSinkContractErrorCode::InvalidContractShape,
        ));
    }

    match schema_version.as_ref().and_then(serde_json::Value::as_str) {
        Some(DRIVER_OPERATION_CREDENTIAL_SINKS_SCHEMA_V1) => {}
        _ => {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::InvalidSchemaVersion,
            ));
        }
    }

    let operation = driver_operation.ok_or_else(|| {
        contract_error(DriverCredentialSinkContractErrorCode::InvalidDriverOperation)
    })?;
    validate_driver_operation_ref_v1(&operation).map_err(|_| {
        contract_error(DriverCredentialSinkContractErrorCode::InvalidDriverOperation)
    })?;

    let revision = driver_declaration_revision
        .as_ref()
        .and_then(serde_json::Value::as_u64)
        .filter(|value| (1..=MAX_SAFE_INTEGER).contains(value))
        .ok_or_else(|| {
            contract_error(DriverCredentialSinkContractErrorCode::InvalidDeclarationRevision)
        })?;

    let sink_values = credential_sinks
        .as_ref()
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            contract_error(DriverCredentialSinkContractErrorCode::InvalidContractShape)
        })?;
    if sink_values.is_empty() {
        return Err(contract_error(
            DriverCredentialSinkContractErrorCode::EmptyCredentialSinks,
        ));
    }
    if sink_values.len() > MAX_CREDENTIAL_SINKS {
        return Err(contract_error(
            DriverCredentialSinkContractErrorCode::TooManyCredentialSinks,
        ));
    }
    let mut sinks = Vec::with_capacity(sink_values.len());
    for value in sink_values {
        sinks.push(parse_sink_value(value)?);
    }
    DriverOperationCredentialSinksV1::try_new(operation, revision, sinks)
}

fn parse_sink_value(
    value: &serde_json::Value,
) -> Result<DriverOperationCredentialSinkV1, DriverCredentialSinkContractError> {
    let object = value.as_object().ok_or_else(|| {
        contract_error(DriverCredentialSinkContractErrorCode::InvalidContractShape)
    })?;
    if !has_only_fields(
        object,
        &[
            "credential_slot_id",
            "allowed_classifications",
            "allowed_intents",
            "destination_schema",
            "delivery_exposure_profile",
            "trusted_send_profile",
        ],
    ) {
        return Err(contract_error(
            DriverCredentialSinkContractErrorCode::InvalidContractShape,
        ));
    }

    let slot = object
        .get("credential_slot_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            contract_error(DriverCredentialSinkContractErrorCode::InvalidCredentialSlot)
        })?
        .parse()
        .map_err(|_| {
            contract_error(DriverCredentialSinkContractErrorCode::InvalidCredentialSlot)
        })?;
    let classifications = parse_classifications(object.get("allowed_classifications"))?;
    let intents = parse_intents(object.get("allowed_intents"))?;
    let destination_schema = object
        .get("destination_schema")
        .and_then(serde_json::Value::as_str)
        .filter(|value| is_destination_schema(value))
        .ok_or_else(|| {
            contract_error(DriverCredentialSinkContractErrorCode::InvalidDestinationSchema)
        })?;

    let profile_value = object.get("trusted_send_profile").ok_or_else(|| {
        contract_error(DriverCredentialSinkContractErrorCode::MissingTrustedSendProfile)
    })?;
    if profile_value.is_null() {
        return Err(contract_error(
            DriverCredentialSinkContractErrorCode::MissingTrustedSendProfile,
        ));
    }
    let exposure = parse_exposure(object.get("delivery_exposure_profile"))?;
    let profile_object = profile_value.as_object().ok_or_else(|| {
        contract_error(DriverCredentialSinkContractErrorCode::ExposureProfileMismatch)
    })?;
    let profile_kind = profile_object
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            contract_error(DriverCredentialSinkContractErrorCode::ExposureProfileMismatch)
        })?;
    let profile = match (exposure, profile_kind) {
        (SecretDeliveryExposureProfile::TrustedInjection, "trusted_injection") => {
            parse_trusted_injection_profile(profile_object)?
        }
        (SecretDeliveryExposureProfile::MaterialExposed, "not_applicable") => {
            if profile_object.len() != 1 {
                return Err(contract_error(
                    DriverCredentialSinkContractErrorCode::NotApplicablePayloadForbidden,
                ));
            }
            DriverTrustedSendProfileV1::not_applicable()
        }
        _ => {
            return Err(contract_error(
                DriverCredentialSinkContractErrorCode::ExposureProfileMismatch,
            ));
        }
    };

    DriverOperationCredentialSinkV1::try_new(
        slot,
        classifications,
        intents,
        destination_schema,
        exposure,
        profile,
    )
}

fn parse_classifications(
    value: Option<&serde_json::Value>,
) -> Result<Vec<SecretClassification>, DriverCredentialSinkContractError> {
    let values = value.and_then(serde_json::Value::as_array).ok_or_else(|| {
        contract_error(DriverCredentialSinkContractErrorCode::InvalidClassificationSet)
    })?;
    if values.is_empty() || values.len() > MAX_CLASSIFICATIONS {
        return Err(contract_error(
            DriverCredentialSinkContractErrorCode::InvalidClassificationSet,
        ));
    }
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let parsed_value = match value.as_str() {
            Some("authentication_credential") => SecretClassification::AuthenticationCredential,
            Some("signing_material") => SecretClassification::SigningMaterial,
            Some("encryption_material") => SecretClassification::EncryptionMaterial,
            Some("private_configuration") => SecretClassification::PrivateConfiguration,
            Some("opaque_secret") => SecretClassification::OpaqueSecret,
            _ => {
                return Err(contract_error(
                    DriverCredentialSinkContractErrorCode::InvalidClassificationSet,
                ));
            }
        };
        parsed.push(parsed_value);
    }
    if has_duplicates(&parsed) {
        return Err(contract_error(
            DriverCredentialSinkContractErrorCode::InvalidClassificationSet,
        ));
    }
    Ok(parsed)
}

fn parse_intents(
    value: Option<&serde_json::Value>,
) -> Result<Vec<SecretUseIntent>, DriverCredentialSinkContractError> {
    let values = value
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| contract_error(DriverCredentialSinkContractErrorCode::InvalidIntentSet))?;
    if values.is_empty() || values.len() > MAX_INTENTS {
        return Err(contract_error(
            DriverCredentialSinkContractErrorCode::InvalidIntentSet,
        ));
    }
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let parsed_value = match value.as_str() {
            Some("authenticate") => SecretUseIntent::Authenticate,
            Some("sign") => SecretUseIntent::Sign,
            Some("encrypt") => SecretUseIntent::Encrypt,
            Some("decrypt") => SecretUseIntent::Decrypt,
            Some("derive_session") => SecretUseIntent::DeriveSession,
            Some("bootstrap_transport") => SecretUseIntent::BootstrapTransport,
            _ => {
                return Err(contract_error(
                    DriverCredentialSinkContractErrorCode::InvalidIntentSet,
                ));
            }
        };
        parsed.push(parsed_value);
    }
    if has_duplicates(&parsed) {
        return Err(contract_error(
            DriverCredentialSinkContractErrorCode::InvalidIntentSet,
        ));
    }
    Ok(parsed)
}

fn parse_exposure(
    value: Option<&serde_json::Value>,
) -> Result<SecretDeliveryExposureProfile, DriverCredentialSinkContractError> {
    match value.and_then(serde_json::Value::as_str) {
        Some("trusted_injection") => Ok(SecretDeliveryExposureProfile::TrustedInjection),
        Some("material_exposed") => Ok(SecretDeliveryExposureProfile::MaterialExposed),
        _ => Err(contract_error(
            DriverCredentialSinkContractErrorCode::ExposureProfileMismatch,
        )),
    }
}

fn parse_trusted_injection_profile(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<DriverTrustedSendProfileV1, DriverCredentialSinkContractError> {
    if !has_only_fields(
        object,
        &[
            "kind",
            "max_credential_bearing_sends",
            "applicable_delivery_controls",
        ],
    ) {
        return Err(contract_error(
            DriverCredentialSinkContractErrorCode::InvalidContractShape,
        ));
    }
    let send_limit = object
        .get("max_credential_bearing_sends")
        .and_then(serde_json::Value::as_u64)
        .filter(|value| (1..=8).contains(value))
        .ok_or_else(|| contract_error(DriverCredentialSinkContractErrorCode::InvalidSendLimit))?
        as u8;
    let controls = parse_controls(object.get("applicable_delivery_controls"))?;
    DriverTrustedSendProfileV1::try_trusted_injection(send_limit, controls)
}

fn parse_controls(
    value: Option<&serde_json::Value>,
) -> Result<Vec<SecretDeliveryControlKind>, DriverCredentialSinkContractError> {
    let values = value
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| contract_error(DriverCredentialSinkContractErrorCode::InvalidControlSet))?;
    if values.is_empty() || values.len() > MAX_DELIVERY_CONTROLS {
        return Err(contract_error(
            DriverCredentialSinkContractErrorCode::InvalidControlSet,
        ));
    }
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let parsed_value = match value.as_str() {
            Some("core_dump") => SecretDeliveryControlKind::CoreDump,
            Some("ptrace_debug") => SecretDeliveryControlKind::PtraceDebug,
            Some("child_inheritance") => SecretDeliveryControlKind::ChildInheritance,
            Some("output_capture") => SecretDeliveryControlKind::OutputCapture,
            Some("swap_page_dump") => SecretDeliveryControlKind::SwapPageDump,
            Some("generic_cache") => SecretDeliveryControlKind::GenericCache,
            Some("orchestrator_projection") => SecretDeliveryControlKind::OrchestratorProjection,
            Some("trusted_injection_boundary") => {
                SecretDeliveryControlKind::TrustedInjectionBoundary
            }
            Some("destination_network_egress") => {
                SecretDeliveryControlKind::DestinationNetworkEgress
            }
            Some("filesystem_sink_egress") => SecretDeliveryControlKind::FilesystemSinkEgress,
            Some("ipc_egress") => SecretDeliveryControlKind::IpcEgress,
            Some("child_process_egress") => SecretDeliveryControlKind::ChildProcessEgress,
            Some("proxy_egress") => SecretDeliveryControlKind::ProxyEgress,
            Some("alternate_mount_egress") => SecretDeliveryControlKind::AlternateMountEgress,
            _ => {
                return Err(contract_error(
                    DriverCredentialSinkContractErrorCode::InvalidControlSet,
                ));
            }
        };
        parsed.push(parsed_value);
    }
    if has_duplicates(&parsed) {
        return Err(contract_error(
            DriverCredentialSinkContractErrorCode::InvalidControlSet,
        ));
    }
    Ok(parsed)
}

fn has_only_fields(object: &serde_json::Map<String, serde_json::Value>, allowed: &[&str]) -> bool {
    object.keys().all(|key| allowed.contains(&key.as_str()))
}

impl Serialize for DriverOperationCredentialSinksV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DriverOperationCredentialSinksV1", 4)?;
        state.serialize_field("credential_sinks", &self.credential_sinks)?;
        state.serialize_field(
            "driver_declaration_revision",
            &self.driver_declaration_revision,
        )?;
        state.serialize_field("driver_operation", &self.driver_operation)?;
        state.serialize_field(
            "schema_version",
            DRIVER_OPERATION_CREDENTIAL_SINKS_SCHEMA_V1,
        )?;
        state.end()
    }
}

fn contract_error(
    code: DriverCredentialSinkContractErrorCode,
) -> DriverCredentialSinkContractError {
    DriverCredentialSinkContractError::new(code)
}

fn has_duplicates<T>(values: &[T]) -> bool
where
    T: Copy + Eq + std::hash::Hash,
{
    let mut seen = HashSet::with_capacity(values.len());
    values.iter().any(|value| !seen.insert(*value))
}

fn is_destination_schema(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_DESTINATION_SCHEMA_BYTES
        || !bytes.is_ascii()
        || !bytes[0].is_ascii_lowercase()
    {
        return false;
    }
    let Some(version_separator) = value.rfind(".v") else {
        return false;
    };
    let (name, version_with_prefix) = value.split_at(version_separator);
    if name.is_empty()
        || !name.as_bytes().iter().enumerate().all(|(index, byte)| {
            (index == 0 && byte.is_ascii_lowercase())
                || (index > 0
                    && (byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')))
        })
    {
        return false;
    }
    let version = &version_with_prefix[2..];
    !version.is_empty()
        && version.as_bytes()[0].is_ascii_digit()
        && version.as_bytes()[0] != b'0'
        && version.bytes().all(|byte| byte.is_ascii_digit())
}

fn classification_wire(value: SecretClassification) -> &'static str {
    match value {
        SecretClassification::AuthenticationCredential => "authentication_credential",
        SecretClassification::SigningMaterial => "signing_material",
        SecretClassification::EncryptionMaterial => "encryption_material",
        SecretClassification::PrivateConfiguration => "private_configuration",
        SecretClassification::OpaqueSecret => "opaque_secret",
    }
}

fn intent_wire(value: SecretUseIntent) -> &'static str {
    match value {
        SecretUseIntent::Authenticate => "authenticate",
        SecretUseIntent::Sign => "sign",
        SecretUseIntent::Encrypt => "encrypt",
        SecretUseIntent::Decrypt => "decrypt",
        SecretUseIntent::DeriveSession => "derive_session",
        SecretUseIntent::BootstrapTransport => "bootstrap_transport",
    }
}

fn delivery_control_wire(value: SecretDeliveryControlKind) -> &'static str {
    match value {
        SecretDeliveryControlKind::CoreDump => "core_dump",
        SecretDeliveryControlKind::PtraceDebug => "ptrace_debug",
        SecretDeliveryControlKind::ChildInheritance => "child_inheritance",
        SecretDeliveryControlKind::OutputCapture => "output_capture",
        SecretDeliveryControlKind::SwapPageDump => "swap_page_dump",
        SecretDeliveryControlKind::GenericCache => "generic_cache",
        SecretDeliveryControlKind::OrchestratorProjection => "orchestrator_projection",
        SecretDeliveryControlKind::TrustedInjectionBoundary => "trusted_injection_boundary",
        SecretDeliveryControlKind::DestinationNetworkEgress => "destination_network_egress",
        SecretDeliveryControlKind::FilesystemSinkEgress => "filesystem_sink_egress",
        SecretDeliveryControlKind::IpcEgress => "ipc_egress",
        SecretDeliveryControlKind::ChildProcessEgress => "child_process_egress",
        SecretDeliveryControlKind::ProxyEgress => "proxy_egress",
        SecretDeliveryControlKind::AlternateMountEgress => "alternate_mount_egress",
    }
}

#[cfg(test)]
#[path = "../tests/unit/driver_tests.rs"]
mod tests;
