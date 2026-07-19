//! Behavior-free secret-use requirement contract.
//!
//! A requirement names an opaque secret reference and one driver-owned
//! credential slot. It is a proposal only: it grants no authority, resolves no
//! provider, creates no lease, and performs no delivery or I/O.

use crate::{
    SecretCredentialSlotId, SecretDeliveryMethod, SecretPurpose, SecretRefId, SecretUseIntent,
};
use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::error::Error;
use std::fmt;

/// Exact schema version for the behavior-free v1 secret-use requirement.
pub const SECRET_USE_REQUIREMENT_SCHEMA_V1: &str = "splendor.secret.use_requirement.v1";

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_DELIVERY_METHODS: usize = 5;

/// Closed, valid-by-construction request to use one opaque secret reference.
///
/// This value is not authority and contains no material, provider locator,
/// destination, target, authority decision, lease, or delivery handle.
/// Preference order is preserved exactly and duplicate methods are rejected.
///
/// Fields are private and default construction is unavailable:
///
/// ```compile_fail
/// use splendor_types::SecretUseRequirement;
///
/// let _ = SecretUseRequirement::default();
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SecretUseRequirement {
    secret_ref_id: SecretRefId,
    credential_slot_id: SecretCredentialSlotId,
    intent: SecretUseIntent,
    purpose: SecretPurpose,
    delivery_methods: Vec<SecretDeliveryMethod>,
    requested_duration_seconds: u64,
    requested_max_uses: u64,
    required: bool,
}

impl SecretUseRequirement {
    /// Constructs one validated, non-authorizing secret-use requirement.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        secret_ref_id: SecretRefId,
        credential_slot_id: SecretCredentialSlotId,
        intent: SecretUseIntent,
        purpose: SecretPurpose,
        delivery_methods: Vec<SecretDeliveryMethod>,
        requested_duration_seconds: u64,
        requested_max_uses: u64,
        required: bool,
    ) -> Result<Self, SecretUseRequirementError> {
        if delivery_methods.is_empty() {
            return Err(SecretUseRequirementError::EmptyDeliveryMethods);
        }
        if delivery_methods.len() > MAX_DELIVERY_METHODS {
            return Err(SecretUseRequirementError::TooManyDeliveryMethods);
        }
        if delivery_methods
            .iter()
            .enumerate()
            .any(|(index, method)| delivery_methods[..index].contains(method))
        {
            return Err(SecretUseRequirementError::DuplicateDeliveryMethod);
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&requested_duration_seconds) {
            return Err(SecretUseRequirementError::InvalidRequestedDuration);
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&requested_max_uses) {
            return Err(SecretUseRequirementError::InvalidRequestedMaxUses);
        }
        if !required {
            return Err(SecretUseRequirementError::RequiredMustBeTrue);
        }

        Ok(Self {
            secret_ref_id,
            credential_slot_id,
            intent,
            purpose,
            delivery_methods,
            requested_duration_seconds,
            requested_max_uses,
            required,
        })
    }

    /// Returns the exact v1 schema version.
    pub const fn schema_version(&self) -> &'static str {
        SECRET_USE_REQUIREMENT_SCHEMA_V1
    }

    /// Returns the opaque logical secret-reference identity.
    pub const fn secret_ref_id(&self) -> &SecretRefId {
        &self.secret_ref_id
    }

    /// Returns the exact driver-owned credential-slot identity.
    pub const fn credential_slot_id(&self) -> SecretCredentialSlotId {
        self.credential_slot_id
    }

    /// Returns the requested closed use intent.
    pub const fn intent(&self) -> SecretUseIntent {
        self.intent
    }

    /// Returns the requested closed purpose.
    pub const fn purpose(&self) -> SecretPurpose {
        self.purpose
    }

    /// Returns delivery methods in exact preference order.
    pub fn delivery_methods(&self) -> &[SecretDeliveryMethod] {
        &self.delivery_methods
    }

    /// Returns the positive requested duration in seconds.
    pub const fn requested_duration_seconds(&self) -> u64 {
        self.requested_duration_seconds
    }

    /// Returns the positive requested maximum use count.
    pub const fn requested_max_uses(&self) -> u64 {
        self.requested_max_uses
    }

    /// Returns the required marker, which is always true in v1.
    pub const fn required(&self) -> bool {
        self.required
    }
}

impl Serialize for SecretUseRequirement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretUseRequirement", 9)?;
        state.serialize_field("credential_slot_id", &self.credential_slot_id)?;
        state.serialize_field("delivery_methods", &self.delivery_methods)?;
        state.serialize_field("intent", &self.intent)?;
        state.serialize_field("purpose", &self.purpose)?;
        state.serialize_field(
            "requested_duration_seconds",
            &self.requested_duration_seconds,
        )?;
        state.serialize_field("requested_max_uses", &self.requested_max_uses)?;
        state.serialize_field("required", &self.required)?;
        state.serialize_field("schema_version", SECRET_USE_REQUIREMENT_SCHEMA_V1)?;
        state.serialize_field("secret_ref_id", &self.secret_ref_id)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SecretUseRequirement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SecretUseRequirementVisitor)
    }
}

/// Fixed, non-reflecting validation failures for a secret-use requirement.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum SecretUseRequirementError {
    /// The top-level value was not the exact closed object form.
    InvalidContractShape,
    /// At least one required member was absent.
    MissingRequiredField,
    /// A member appeared more than once.
    DuplicateField,
    /// A member outside the closed v1 schema appeared.
    UnknownField,
    /// The schema version was absent from the exact v1 value space.
    InvalidSchemaVersion,
    /// The secret-reference identity was malformed, noncanonical, or nil.
    InvalidSecretRefId,
    /// The credential-slot identity was malformed, noncanonical, or nil.
    InvalidCredentialSlotId,
    /// The intent was not an exact closed string value.
    InvalidIntent,
    /// The purpose was not an exact closed string value.
    InvalidPurpose,
    /// The delivery-method member was not an array.
    InvalidDeliveryMethods,
    /// One delivery method was not an exact closed string value.
    InvalidDeliveryMethod,
    /// The ordered delivery preference list was empty.
    EmptyDeliveryMethods,
    /// The ordered delivery preference list exceeded five entries.
    TooManyDeliveryMethods,
    /// The ordered delivery preference list contained a duplicate.
    DuplicateDeliveryMethod,
    /// The requested duration was not a positive safe JSON integer.
    InvalidRequestedDuration,
    /// The requested maximum uses was not a positive safe JSON integer.
    InvalidRequestedMaxUses,
    /// The required member was not a boolean.
    InvalidRequired,
    /// The required member was false; v1 supports required use only.
    RequiredMustBeTrue,
}

impl SecretUseRequirementError {
    /// Returns the exact fixed snake-case validation code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidContractShape => "invalid_contract_shape",
            Self::MissingRequiredField => "missing_required_field",
            Self::DuplicateField => "duplicate_field",
            Self::UnknownField => "unknown_field",
            Self::InvalidSchemaVersion => "invalid_schema_version",
            Self::InvalidSecretRefId => "invalid_secret_ref_id",
            Self::InvalidCredentialSlotId => "invalid_credential_slot_id",
            Self::InvalidIntent => "invalid_intent",
            Self::InvalidPurpose => "invalid_purpose",
            Self::InvalidDeliveryMethods => "invalid_delivery_methods",
            Self::InvalidDeliveryMethod => "invalid_delivery_method",
            Self::EmptyDeliveryMethods => "empty_delivery_methods",
            Self::TooManyDeliveryMethods => "too_many_delivery_methods",
            Self::DuplicateDeliveryMethod => "duplicate_delivery_method",
            Self::InvalidRequestedDuration => "invalid_requested_duration_seconds",
            Self::InvalidRequestedMaxUses => "invalid_requested_max_uses",
            Self::InvalidRequired => "invalid_required",
            Self::RequiredMustBeTrue => "required_must_be_true",
        }
    }
}

impl fmt::Display for SecretUseRequirementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for SecretUseRequirementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for SecretUseRequirementError {}

enum SecretUseRequirementField {
    CredentialSlotId,
    DeliveryMethods,
    Intent,
    Purpose,
    RequestedDurationSeconds,
    RequestedMaxUses,
    Required,
    SchemaVersion,
    SecretRefId,
    Unknown,
}

struct SecretUseRequirementFieldVisitor;

impl<'de> Visitor<'de> for SecretUseRequirementFieldVisitor {
    type Value = SecretUseRequirementField;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a secret-use requirement field")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(match value {
            "credential_slot_id" => SecretUseRequirementField::CredentialSlotId,
            "delivery_methods" => SecretUseRequirementField::DeliveryMethods,
            "intent" => SecretUseRequirementField::Intent,
            "purpose" => SecretUseRequirementField::Purpose,
            "requested_duration_seconds" => SecretUseRequirementField::RequestedDurationSeconds,
            "requested_max_uses" => SecretUseRequirementField::RequestedMaxUses,
            "required" => SecretUseRequirementField::Required,
            "schema_version" => SecretUseRequirementField::SchemaVersion,
            "secret_ref_id" => SecretUseRequirementField::SecretRefId,
            _ => SecretUseRequirementField::Unknown,
        })
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
        Ok(SecretUseRequirementField::Unknown)
    }
}

impl<'de> Deserialize<'de> for SecretUseRequirementField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_identifier(SecretUseRequirementFieldVisitor)
    }
}

struct SecretUseRequirementVisitor;

impl<'de> Visitor<'de> for SecretUseRequirementVisitor {
    type Value = SecretUseRequirement;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SecretUseRequirementError::InvalidContractShape.code())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut credential_slot_id = None;
        let mut delivery_methods = None;
        let mut intent = None;
        let mut purpose = None;
        let mut requested_duration_seconds = None;
        let mut requested_max_uses = None;
        let mut required = None;
        let mut schema_version = None;
        let mut secret_ref_id = None;

        while let Some(field) = map.next_key::<SecretUseRequirementField>()? {
            match field {
                SecretUseRequirementField::CredentialSlotId => {
                    reject_duplicate::<A::Error>(credential_slot_id.is_some())?;
                    credential_slot_id = Some(map.next_value::<CredentialSlotIdInput>()?.0);
                }
                SecretUseRequirementField::DeliveryMethods => {
                    reject_duplicate::<A::Error>(delivery_methods.is_some())?;
                    delivery_methods = Some(map.next_value::<DeliveryMethodsInput>()?.0);
                }
                SecretUseRequirementField::Intent => {
                    reject_duplicate::<A::Error>(intent.is_some())?;
                    intent = Some(map.next_value::<IntentInput>()?.0);
                }
                SecretUseRequirementField::Purpose => {
                    reject_duplicate::<A::Error>(purpose.is_some())?;
                    purpose = Some(map.next_value::<PurposeInput>()?.0);
                }
                SecretUseRequirementField::RequestedDurationSeconds => {
                    reject_duplicate::<A::Error>(requested_duration_seconds.is_some())?;
                    requested_duration_seconds =
                        Some(map.next_value::<RequestedDurationInput>()?.0);
                }
                SecretUseRequirementField::RequestedMaxUses => {
                    reject_duplicate::<A::Error>(requested_max_uses.is_some())?;
                    requested_max_uses = Some(map.next_value::<RequestedMaxUsesInput>()?.0);
                }
                SecretUseRequirementField::Required => {
                    reject_duplicate::<A::Error>(required.is_some())?;
                    required = Some(map.next_value::<RequiredInput>()?.0);
                }
                SecretUseRequirementField::SchemaVersion => {
                    reject_duplicate::<A::Error>(schema_version.is_some())?;
                    map.next_value::<SchemaVersionInput>()?;
                    schema_version = Some(());
                }
                SecretUseRequirementField::SecretRefId => {
                    reject_duplicate::<A::Error>(secret_ref_id.is_some())?;
                    secret_ref_id = Some(map.next_value::<SecretRefIdInput>()?.0);
                }
                SecretUseRequirementField::Unknown => {
                    return Err(A::Error::custom(SecretUseRequirementError::UnknownField));
                }
            }
        }

        let missing = || A::Error::custom(SecretUseRequirementError::MissingRequiredField);
        schema_version.ok_or_else(missing)?;
        SecretUseRequirement::try_new(
            secret_ref_id.ok_or_else(missing)?,
            credential_slot_id.ok_or_else(missing)?,
            intent.ok_or_else(missing)?,
            purpose.ok_or_else(missing)?,
            delivery_methods.ok_or_else(missing)?,
            requested_duration_seconds.ok_or_else(missing)?,
            requested_max_uses.ok_or_else(missing)?,
            required.ok_or_else(missing)?,
        )
        .map_err(A::Error::custom)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_char<E>(self, _value: char) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_byte_buf<E>(self, _value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_contract_shape()
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        invalid_contract_shape()
    }
}

fn reject_duplicate<E>(duplicate: bool) -> Result<(), E>
where
    E: DeError,
{
    if duplicate {
        Err(E::custom(SecretUseRequirementError::DuplicateField))
    } else {
        Ok(())
    }
}

fn invalid_contract_shape<T, E>() -> Result<T, E>
where
    E: DeError,
{
    Err(E::custom(SecretUseRequirementError::InvalidContractShape))
}

struct SchemaVersionInput;

impl<'de> Deserialize<'de> for SchemaVersionInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_str(SchemaVersionVisitor)
            .map_err(|_| D::Error::custom(SecretUseRequirementError::InvalidSchemaVersion))
    }
}

struct SchemaVersionVisitor;

impl<'de> Visitor<'de> for SchemaVersionVisitor {
    type Value = SchemaVersionInput;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SecretUseRequirementError::InvalidSchemaVersion.code())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        if value == SECRET_USE_REQUIREMENT_SCHEMA_V1 {
            Ok(SchemaVersionInput)
        } else {
            Err(E::custom(SecretUseRequirementError::InvalidSchemaVersion))
        }
    }
}

struct SecretRefIdInput(SecretRefId);

impl<'de> Deserialize<'de> for SecretRefIdInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SecretRefId::deserialize(deserializer)
            .map(Self)
            .map_err(|_| D::Error::custom(SecretUseRequirementError::InvalidSecretRefId))
    }
}

struct CredentialSlotIdInput(SecretCredentialSlotId);

impl<'de> Deserialize<'de> for CredentialSlotIdInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SecretCredentialSlotId::deserialize(deserializer)
            .map(Self)
            .map_err(|_| D::Error::custom(SecretUseRequirementError::InvalidCredentialSlotId))
    }
}

struct IntentInput(SecretUseIntent);

impl<'de> Deserialize<'de> for IntentInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SecretUseIntent::deserialize(deserializer)
            .map(Self)
            .map_err(|_| D::Error::custom(SecretUseRequirementError::InvalidIntent))
    }
}

struct PurposeInput(SecretPurpose);

impl<'de> Deserialize<'de> for PurposeInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SecretPurpose::deserialize(deserializer)
            .map(Self)
            .map_err(|_| D::Error::custom(SecretUseRequirementError::InvalidPurpose))
    }
}

struct DeliveryMethodInput(SecretDeliveryMethod);

impl<'de> Deserialize<'de> for DeliveryMethodInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SecretDeliveryMethod::deserialize(deserializer)
            .map(Self)
            .map_err(|_| D::Error::custom(SecretUseRequirementError::InvalidDeliveryMethod))
    }
}

struct DeliveryMethodsInput(Vec<SecretDeliveryMethod>);

impl<'de> Deserialize<'de> for DeliveryMethodsInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DeliveryMethodsVisitor)
    }
}

struct DeliveryMethodsVisitor;

impl<'de> Visitor<'de> for DeliveryMethodsVisitor {
    type Value = DeliveryMethodsInput;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SecretUseRequirementError::InvalidDeliveryMethods.code())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut methods = Vec::with_capacity(MAX_DELIVERY_METHODS);
        while let Some(method) = sequence.next_element::<DeliveryMethodInput>()? {
            if methods.len() == MAX_DELIVERY_METHODS {
                return Err(A::Error::custom(
                    SecretUseRequirementError::TooManyDeliveryMethods,
                ));
            }
            methods.push(method.0);
        }
        Ok(DeliveryMethodsInput(methods))
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_char<E>(self, _value: char) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_byte_buf<E>(self, _value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        invalid_delivery_methods()
    }

    fn visit_map<A>(self, _map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        invalid_delivery_methods()
    }
}

fn invalid_delivery_methods<T, E>() -> Result<T, E>
where
    E: DeError,
{
    Err(E::custom(SecretUseRequirementError::InvalidDeliveryMethods))
}

struct RequestedDurationInput(u64);

impl<'de> Deserialize<'de> for RequestedDurationInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_u64(U64Visitor)
            .map(Self)
            .map_err(|_| D::Error::custom(SecretUseRequirementError::InvalidRequestedDuration))
    }
}

struct RequestedMaxUsesInput(u64);

impl<'de> Deserialize<'de> for RequestedMaxUsesInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_u64(U64Visitor)
            .map(Self)
            .map_err(|_| D::Error::custom(SecretUseRequirementError::InvalidRequestedMaxUses))
    }
}

struct U64Visitor;

impl<'de> Visitor<'de> for U64Visitor {
    type Value = u64;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an unsigned integer")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(value)
    }
}

struct RequiredInput(bool);

impl<'de> Deserialize<'de> for RequiredInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_bool(BoolVisitor)
            .map(Self)
            .map_err(|_| D::Error::custom(SecretUseRequirementError::InvalidRequired))
    }
}

struct BoolVisitor;

impl<'de> Visitor<'de> for BoolVisitor {
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a boolean")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(value)
    }
}
