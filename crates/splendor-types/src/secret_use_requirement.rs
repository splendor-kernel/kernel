//! Behavior-free secret-use requirement contract.
//!
//! A requirement names an opaque secret reference and one driver-owned
//! credential slot. It is a proposal only: it grants no authority, resolves no
//! provider, creates no lease, and performs no delivery or I/O. Untrusted,
//! imported, persisted, and rehydrated bytes must enter through
//! [`SecretUseRequirement::from_json_slice`].

use crate::{
    SecretCredentialSlotId, SecretDeliveryMethod, SecretPurpose, SecretRefId, SecretUseIntent,
};
use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;

/// Exact schema version for the behavior-free v1 secret-use requirement.
pub const SECRET_USE_REQUIREMENT_SCHEMA_V1: &str = "splendor.secret.use_requirement.v1";

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_DELIVERY_METHODS: usize = 5;

// These ingress limits are intentionally specific to the closed nine-field v1
// requirement. The maximum legal value has one root object, one five-element
// array, nine members, 26 decoder tokens, and 36-byte UUID strings. The raw cap
// leaves bounded room for harmless JSON whitespace and equivalent escapes.
const MAX_INGRESS_BYTES: usize = 1_024;
const MAX_INGRESS_DEPTH: usize = 2;
const MAX_INGRESS_TOKENS: usize = 26;
const MAX_INGRESS_MEMBERS: usize = 9;
const MAX_INGRESS_ELEMENTS: usize = 5;
const MAX_INGRESS_STRING_BYTES: usize = 36;

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
///
/// The validated type intentionally implements `Serialize` but not
/// `Deserialize`; bytes must use the bounded owner parser:
///
/// ```compile_fail
/// use splendor_types::SecretUseRequirement;
///
/// let _: SecretUseRequirement = serde_json::from_slice(b"{}").unwrap();
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
    /// Parses one untrusted requirement through the exact bounded v1 ingress.
    pub fn from_json_slice(input: &[u8]) -> Result<Self, SecretUseRequirementError> {
        #[derive(Default)]
        struct WireValue(Option<serde_json::Value>);

        impl<'de> Deserialize<'de> for WireValue {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                serde_json::Value::deserialize(deserializer).map(|value| Self(Some(value)))
            }
        }

        #[derive(Deserialize)]
        struct SecretUseRequirementWire {
            #[serde(default)]
            credential_slot_id: WireValue,
            #[serde(default)]
            delivery_methods: WireValue,
            #[serde(default)]
            intent: WireValue,
            #[serde(default)]
            purpose: WireValue,
            #[serde(default)]
            requested_duration_seconds: WireValue,
            #[serde(default)]
            requested_max_uses: WireValue,
            #[serde(default)]
            required: WireValue,
            #[serde(default)]
            schema_version: WireValue,
            #[serde(default)]
            secret_ref_id: WireValue,
            #[serde(flatten)]
            unknown_fields: BTreeMap<String, serde_json::Value>,
        }

        preflight_requirement(input)?;
        let wire: SecretUseRequirementWire = serde_json::from_slice(input)
            .map_err(|_| SecretUseRequirementError::InvalidContractShape)?;
        parse_wire(
            wire.credential_slot_id.0,
            wire.delivery_methods.0,
            wire.intent.0,
            wire.purpose.0,
            wire.requested_duration_seconds.0,
            wire.requested_max_uses.0,
            wire.required.0,
            wire.schema_version.0,
            wire.secret_ref_id.0,
            !wire.unknown_fields.is_empty(),
        )
    }

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

/// Fixed, non-reflecting validation failures for a secret-use requirement.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum SecretUseRequirementError {
    /// The input exceeded a general ingress budget or parsing failed before a
    /// recognized root-field error stage could be attributed.
    InvalidContractShape,
    /// At least one required member was absent.
    MissingRequiredField,
    /// A member appeared more than once at an object depth.
    DuplicateField,
    /// A member outside the closed v1 root schema appeared.
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

#[allow(clippy::too_many_arguments)]
fn parse_wire(
    credential_slot_id: Option<serde_json::Value>,
    delivery_methods: Option<serde_json::Value>,
    intent: Option<serde_json::Value>,
    purpose: Option<serde_json::Value>,
    requested_duration_seconds: Option<serde_json::Value>,
    requested_max_uses: Option<serde_json::Value>,
    required: Option<serde_json::Value>,
    schema_version: Option<serde_json::Value>,
    secret_ref_id: Option<serde_json::Value>,
    has_unknown_fields: bool,
) -> Result<SecretUseRequirement, SecretUseRequirementError> {
    if has_unknown_fields {
        return Err(SecretUseRequirementError::UnknownField);
    }
    let (
        Some(credential_slot_id),
        Some(delivery_methods),
        Some(intent),
        Some(purpose),
        Some(requested_duration_seconds),
        Some(requested_max_uses),
        Some(required),
        Some(schema_version),
        Some(secret_ref_id),
    ) = (
        credential_slot_id,
        delivery_methods,
        intent,
        purpose,
        requested_duration_seconds,
        requested_max_uses,
        required,
        schema_version,
        secret_ref_id,
    )
    else {
        return Err(SecretUseRequirementError::MissingRequiredField);
    };

    if schema_version.as_str() != Some(SECRET_USE_REQUIREMENT_SCHEMA_V1) {
        return Err(SecretUseRequirementError::InvalidSchemaVersion);
    }
    let secret_ref_id = secret_ref_id
        .as_str()
        .ok_or(SecretUseRequirementError::InvalidSecretRefId)?
        .parse()
        .map_err(|_| SecretUseRequirementError::InvalidSecretRefId)?;
    let credential_slot_id = credential_slot_id
        .as_str()
        .ok_or(SecretUseRequirementError::InvalidCredentialSlotId)?
        .parse()
        .map_err(|_| SecretUseRequirementError::InvalidCredentialSlotId)?;
    let intent = parse_intent(&intent)?;
    let purpose = parse_purpose(&purpose)?;
    let delivery_methods = parse_delivery_methods(delivery_methods)?;
    let requested_duration_seconds = requested_duration_seconds
        .as_u64()
        .ok_or(SecretUseRequirementError::InvalidRequestedDuration)?;
    let requested_max_uses = requested_max_uses
        .as_u64()
        .ok_or(SecretUseRequirementError::InvalidRequestedMaxUses)?;
    let required = required
        .as_bool()
        .ok_or(SecretUseRequirementError::InvalidRequired)?;

    SecretUseRequirement::try_new(
        secret_ref_id,
        credential_slot_id,
        intent,
        purpose,
        delivery_methods,
        requested_duration_seconds,
        requested_max_uses,
        required,
    )
}

fn parse_intent(value: &serde_json::Value) -> Result<SecretUseIntent, SecretUseRequirementError> {
    value
        .as_str()
        .and_then(SecretUseIntent::from_wire_spelling)
        .ok_or(SecretUseRequirementError::InvalidIntent)
}

fn parse_purpose(value: &serde_json::Value) -> Result<SecretPurpose, SecretUseRequirementError> {
    value
        .as_str()
        .and_then(SecretPurpose::from_wire_spelling)
        .ok_or(SecretUseRequirementError::InvalidPurpose)
}

fn parse_delivery_methods(
    value: serde_json::Value,
) -> Result<Vec<SecretDeliveryMethod>, SecretUseRequirementError> {
    let serde_json::Value::Array(values) = value else {
        return Err(SecretUseRequirementError::InvalidDeliveryMethods);
    };
    let mut methods = Vec::with_capacity(values.len());
    for value in values {
        let method = value
            .as_str()
            .and_then(SecretDeliveryMethod::from_wire_spelling)
            .ok_or(SecretUseRequirementError::InvalidDeliveryMethod)?;
        methods.push(method);
    }
    Ok(methods)
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
    failure: Option<SecretUseRequirementError>,
    pending_parser_error: Option<SecretUseRequirementError>,
}

fn preflight_requirement(input: &[u8]) -> Result<IngressStats, SecretUseRequirementError> {
    if input.len() > MAX_INGRESS_BYTES {
        return Err(SecretUseRequirementError::InvalidContractShape);
    }
    let mut scanner = PreflightScanner::default();
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let result = PreflightSeed {
        scanner: &mut scanner,
        depth: 1,
    }
    .deserialize(&mut deserializer);
    if result.is_err() {
        return Err(scanner
            .failure
            .or(scanner.pending_parser_error)
            .unwrap_or(SecretUseRequirementError::InvalidContractShape));
    }
    deserializer
        .end()
        .map_err(|_| SecretUseRequirementError::InvalidContractShape)?;
    Ok(scanner.stats)
}

impl PreflightScanner {
    fn reject(&mut self, error: SecretUseRequirementError) -> PreflightError {
        self.failure.get_or_insert(error);
        PreflightError
    }

    fn add_tokens(&mut self, count: usize) -> Result<(), PreflightError> {
        self.stats.tokens = self
            .stats
            .tokens
            .checked_add(count)
            .ok_or_else(|| self.reject(SecretUseRequirementError::InvalidContractShape))?;
        if self.stats.tokens > MAX_INGRESS_TOKENS {
            return Err(self.reject(SecretUseRequirementError::InvalidContractShape));
        }
        Ok(())
    }

    fn enter_container(&mut self, depth: usize) -> Result<(), PreflightError> {
        if depth > MAX_INGRESS_DEPTH {
            return Err(self.reject(SecretUseRequirementError::InvalidContractShape));
        }
        self.stats.depth = self.stats.depth.max(depth);
        self.add_tokens(2)
    }

    fn check_string(&mut self, value: &str) -> Result<(), PreflightError> {
        if value.len() > MAX_INGRESS_STRING_BYTES {
            return Err(self.reject(SecretUseRequirementError::InvalidContractShape));
        }
        Ok(())
    }

    fn add_member(&mut self) -> Result<(), PreflightError> {
        self.stats.members = self
            .stats
            .members
            .checked_add(1)
            .ok_or_else(|| self.reject(SecretUseRequirementError::InvalidContractShape))?;
        if self.stats.members > MAX_INGRESS_MEMBERS {
            return Err(self.reject(SecretUseRequirementError::InvalidContractShape));
        }
        self.add_tokens(1)
    }

    fn add_element(&mut self) -> Result<(), PreflightError> {
        self.stats.elements = self
            .stats
            .elements
            .checked_add(1)
            .ok_or_else(|| self.reject(SecretUseRequirementError::InvalidContractShape))?;
        if self.stats.elements > MAX_INGRESS_ELEMENTS {
            return Err(self.reject(SecretUseRequirementError::TooManyDeliveryMethods));
        }
        Ok(())
    }

    fn add_scalar(&mut self) -> Result<(), PreflightError> {
        self.add_tokens(1)
    }

    fn add_string(&mut self, value: &str) -> Result<(), PreflightError> {
        self.check_string(value)?;
        self.add_scalar()
    }
}

#[derive(Clone, Copy, Debug)]
struct PreflightError;

impl fmt::Display for PreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SecretUseRequirementError::InvalidContractShape.code())
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
        formatter.write_str("bounded secret-use requirement JSON")
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
            let parser_error = if self.depth == 1 {
                root_field_error(&name).ok_or_else(|| {
                    A::Error::custom(self.scanner.reject(SecretUseRequirementError::UnknownField))
                })?
            } else {
                SecretUseRequirementError::InvalidContractShape
            };
            self.scanner.check_string(&name).map_err(A::Error::custom)?;
            if !names.insert(name.clone()) {
                let error = self
                    .scanner
                    .reject(SecretUseRequirementError::DuplicateField);
                return Err(A::Error::custom(error));
            }
            self.scanner.add_member().map_err(A::Error::custom)?;
            if self.depth == 1 {
                self.scanner.pending_parser_error = Some(parser_error);
            }
            map.next_value_seed(PreflightSeed {
                scanner: self.scanner,
                depth: self.depth + 1,
            })?;
            if self.depth == 1 {
                self.scanner.pending_parser_error = None;
            }
        }
        Ok(())
    }
}

fn root_field_error(name: &str) -> Option<SecretUseRequirementError> {
    match name {
        "credential_slot_id" => Some(SecretUseRequirementError::InvalidCredentialSlotId),
        "delivery_methods" => Some(SecretUseRequirementError::InvalidDeliveryMethods),
        "intent" => Some(SecretUseRequirementError::InvalidIntent),
        "purpose" => Some(SecretUseRequirementError::InvalidPurpose),
        "requested_duration_seconds" => Some(SecretUseRequirementError::InvalidRequestedDuration),
        "requested_max_uses" => Some(SecretUseRequirementError::InvalidRequestedMaxUses),
        "required" => Some(SecretUseRequirementError::InvalidRequired),
        "schema_version" => Some(SecretUseRequirementError::InvalidSchemaVersion),
        "secret_ref_id" => Some(SecretUseRequirementError::InvalidSecretRefId),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_REF_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001";
    const CREDENTIAL_SLOT_ID: &str = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4101";

    fn legal_maximum() -> SecretUseRequirement {
        SecretUseRequirement::try_new(
            SECRET_REF_ID.parse().expect("secret ref"),
            CREDENTIAL_SLOT_ID.parse().expect("credential slot"),
            SecretUseIntent::BootstrapTransport,
            SecretPurpose::CryptographicOperation,
            vec![
                SecretDeliveryMethod::InheritedFd,
                SecretDeliveryMethod::TmpfsFile,
                SecretDeliveryMethod::OneShotLocalSocket,
                SecretDeliveryMethod::OrchestratorProjectedSecret,
                SecretDeliveryMethod::EnvironmentVariable,
            ],
            MAX_SAFE_INTEGER,
            MAX_SAFE_INTEGER,
            true,
        )
        .expect("legal maximum")
    }

    #[test]
    fn bounded_ingress_accepts_the_generated_legal_maximum_and_exact_raw_cap() {
        let maximum = legal_maximum();
        let canonical = serde_json::to_vec(&maximum).expect("maximum serialization");
        assert_eq!(canonical.len(), 465, "generated legal maximum changed");
        assert!(canonical.len() < MAX_INGRESS_BYTES);
        assert_eq!(
            preflight_requirement(&canonical),
            Ok(IngressStats {
                depth: MAX_INGRESS_DEPTH,
                tokens: MAX_INGRESS_TOKENS,
                members: MAX_INGRESS_MEMBERS,
                elements: MAX_INGRESS_ELEMENTS,
            })
        );
        assert_eq!(
            SecretUseRequirement::from_json_slice(&canonical),
            Ok(maximum.clone())
        );

        let mut exact_raw_cap = canonical;
        exact_raw_cap.resize(MAX_INGRESS_BYTES, b' ');
        assert_eq!(
            SecretUseRequirement::from_json_slice(&exact_raw_cap),
            Ok(maximum)
        );
    }

    #[test]
    fn bounded_ingress_rejects_each_cap_plus_one() {
        let canonical = serde_json::to_vec(&legal_maximum()).unwrap();
        let mut raw_cap_plus_one = canonical;
        raw_cap_plus_one.resize(MAX_INGRESS_BYTES + 1, b' ');
        assert_eq!(
            SecretUseRequirement::from_json_slice(&raw_cap_plus_one),
            Err(SecretUseRequirementError::InvalidContractShape)
        );

        let depth_cap_plus_one = br#"{"required":[[]]}"#;
        assert_eq!(
            preflight_requirement(depth_cap_plus_one),
            Err(SecretUseRequirementError::InvalidContractShape)
        );
        assert_eq!(
            SecretUseRequirement::from_json_slice(depth_cap_plus_one),
            Err(SecretUseRequirementError::InvalidContractShape)
        );

        let token_cap_plus_one = br#"{"credential_slot_id":[],"delivery_methods":[],"intent":[],"purpose":[],"requested_duration_seconds":[],"requested_max_uses":[],"required":[],"schema_version":[],"secret_ref_id":[]}"#;
        assert_eq!(
            preflight_requirement(token_cap_plus_one),
            Err(SecretUseRequirementError::InvalidContractShape)
        );
        assert_eq!(
            SecretUseRequirement::from_json_slice(token_cap_plus_one),
            Err(SecretUseRequirementError::InvalidContractShape)
        );

        let member_cap_plus_one = br#"{"required":{"a":null,"b":null,"c":null,"d":null,"e":null,"f":null,"g":null,"h":null,"i":null}}"#;
        assert_eq!(
            preflight_requirement(member_cap_plus_one),
            Err(SecretUseRequirementError::InvalidContractShape)
        );
        assert_eq!(
            SecretUseRequirement::from_json_slice(member_cap_plus_one),
            Err(SecretUseRequirementError::InvalidContractShape)
        );

        let element_cap_plus_one = br#"{"delivery_methods":[null,null,null,null,null,null]}"#;
        assert_eq!(
            preflight_requirement(element_cap_plus_one),
            Err(SecretUseRequirementError::TooManyDeliveryMethods)
        );
        assert_eq!(
            SecretUseRequirement::from_json_slice(element_cap_plus_one),
            Err(SecretUseRequirementError::TooManyDeliveryMethods)
        );

        let overlong = "x".repeat(MAX_INGRESS_STRING_BYTES + 1);
        let string_cap_plus_one = format!(r#"{{"required":"{overlong}"}}"#);
        assert_eq!(
            preflight_requirement(string_cap_plus_one.as_bytes()),
            Err(SecretUseRequirementError::InvalidContractShape)
        );
        assert_eq!(
            SecretUseRequirement::from_json_slice(string_cap_plus_one.as_bytes()),
            Err(SecretUseRequirementError::InvalidContractShape)
        );
        let name_cap_plus_one = format!(r#"{{"required":{{"{overlong}":true}}}}"#);
        assert_eq!(
            preflight_requirement(name_cap_plus_one.as_bytes()),
            Err(SecretUseRequirementError::InvalidContractShape)
        );
        assert_eq!(
            SecretUseRequirement::from_json_slice(name_cap_plus_one.as_bytes()),
            Err(SecretUseRequirementError::InvalidContractShape)
        );
    }

    #[test]
    fn bounded_ingress_handles_whitespace_escapes_duplicates_and_malformed_json() {
        let canonical = serde_json::to_string(&legal_maximum()).unwrap();
        let escaped = canonical.replacen("splendor", r"\u0073plendor", 1);
        assert_eq!(
            SecretUseRequirement::from_json_slice(escaped.as_bytes()),
            Ok(legal_maximum())
        );

        let whitespace_bomb = format!("{}{}", canonical, " ".repeat(MAX_INGRESS_BYTES));
        assert_eq!(
            SecretUseRequirement::from_json_slice(whitespace_bomb.as_bytes()),
            Err(SecretUseRequirementError::InvalidContractShape)
        );
        let escape_bomb = format!(
            r#"{{"required":"{}"}}"#,
            r"\u0061".repeat(MAX_INGRESS_BYTES / 6)
        );
        assert!(escape_bomb.len() > MAX_INGRESS_BYTES);
        assert_eq!(
            SecretUseRequirement::from_json_slice(escape_bomb.as_bytes()),
            Err(SecretUseRequirementError::InvalidContractShape)
        );

        assert_eq!(
            SecretUseRequirement::from_json_slice(
                br#"{"required":{"nested":true,"nested":false}}"#
            ),
            Err(SecretUseRequirementError::DuplicateField)
        );
        for (malformed, expected) in [
            (
                b"{".as_slice(),
                SecretUseRequirementError::InvalidContractShape,
            ),
            (
                br#"{123:true}"#,
                SecretUseRequirementError::InvalidContractShape,
            ),
            (
                br#"{"required":"unterminated}"#,
                SecretUseRequirementError::InvalidRequired,
            ),
            (
                &[0xff, 0xfe],
                SecretUseRequirementError::InvalidContractShape,
            ),
        ] {
            let error = SecretUseRequirement::from_json_slice(malformed)
                .expect_err("malformed JSON must reject");
            assert_eq!(error, expected);
        }
    }

    #[test]
    fn ingress_errors_have_fixed_source_free_canary_safe_bytes() {
        const KEY_CANARY: &str = "PRIVATE_KEY_CANARY";
        const VALUE_CANARY: &str = "PRIVATE_VALUE_CANARY";
        let raw = format!(r#"{{"{KEY_CANARY}":"{VALUE_CANARY}"}}"#);
        let error = SecretUseRequirement::from_json_slice(raw.as_bytes())
            .expect_err("unknown canary field must reject");
        assert_eq!(error, SecretUseRequirementError::UnknownField);
        assert_eq!(error.to_string(), error.code());
        assert_eq!(format!("{error:?}"), error.code());
        assert!(!error.to_string().contains(KEY_CANARY));
        assert!(!error.to_string().contains(VALUE_CANARY));
        assert!(std::error::Error::source(&error).is_none());

        let numeric_key = SecretUseRequirement::from_json_slice(br#"{9876543210:true}"#)
            .expect_err("a non-string JSON key must reject");
        assert_eq!(numeric_key, SecretUseRequirementError::InvalidContractShape);
        assert_eq!(numeric_key.to_string(), "invalid_contract_shape");
        assert!(!numeric_key.to_string().contains("9876543210"));
    }
}
