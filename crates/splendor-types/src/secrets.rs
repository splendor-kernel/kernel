//! Behavior-free C03 secret reference and lease-policy grammar.
//!
//! These values describe closed pre-placement contracts only. They do not
//! authorize secret access, resolve provider locations, create leases, or
//! perform delivery.

use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;
use thiserror::Error;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_PROVIDER_VERSION_REF_BYTES: usize = 128;
const CLOSED_SECRET_ENUM_ERROR: &str = "secret enum must be an exact lowercase snake-case string";

trait ClosedSecretEnum: Copy {
    fn wire_spelling(self) -> &'static str;
    fn from_wire_spelling(value: &str) -> Option<Self>;
}

struct ClosedSecretEnumVisitor<T>(PhantomData<T>);

impl<T> ClosedSecretEnumVisitor<T> {
    const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<'de, T> Visitor<'de> for ClosedSecretEnumVisitor<T>
where
    T: ClosedSecretEnum,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(CLOSED_SECRET_ENUM_ERROR)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        T::from_wire_spelling(value).ok_or_else(|| E::custom(CLOSED_SECRET_ENUM_ERROR))
    }
}

macro_rules! define_closed_secret_enum {
    (
        $(#[$enum_meta:meta])*
        pub enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $wire_spelling:literal
            ),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl ClosedSecretEnum for $name {
            fn wire_spelling(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire_spelling,)+
                }
            }

            fn from_wire_spelling(value: &str) -> Option<Self> {
                match value {
                    $($wire_spelling => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.wire_spelling())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer
                    .deserialize_str(ClosedSecretEnumVisitor::<Self>::new())
                    .map_err(|_| D::Error::custom(CLOSED_SECRET_ENUM_ERROR))
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> Ordering {
                self.wire_spelling().cmp(other.wire_spelling())
            }
        }

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }
    };
}

define_closed_secret_enum! {
/// Classification of secret material referenced by a future secret record.
pub enum SecretClassification {
    /// Material used to authenticate to a protected service.
    AuthenticationCredential => "authentication_credential",
    /// Material used to create cryptographic signatures.
    SigningMaterial => "signing_material",
    /// Material used for encryption or decryption.
    EncryptionMaterial => "encryption_material",
    /// Configuration that must remain private.
    PrivateConfiguration => "private_configuration",
    /// Secret material without a more specific v1 classification.
    OpaqueSecret => "opaque_secret",
}
}

define_closed_secret_enum! {
/// Closed delivery vocabulary for a future secret-use requirement.
pub enum SecretDeliveryMethod {
    /// Delivery through a pre-opened inherited file descriptor.
    InheritedFd => "inherited_fd",
    /// Delivery through a bounded file on a memory-backed filesystem.
    TmpfsFile => "tmpfs_file",
    /// Delivery through a one-shot local socket.
    OneShotLocalSocket => "one_shot_local_socket",
    /// Delivery through an orchestrator-managed projected secret.
    OrchestratorProjectedSecret => "orchestrator_projected_secret",
    /// Compatibility vocabulary only; this variant grants no permission.
    EnvironmentVariable => "environment_variable",
}
}

define_closed_secret_enum! {
/// Intended operation for a future secret use.
pub enum SecretUseIntent {
    /// Authenticate to a service or resource.
    Authenticate => "authenticate",
    /// Sign data.
    Sign => "sign",
    /// Encrypt data.
    Encrypt => "encrypt",
    /// Decrypt data.
    Decrypt => "decrypt",
    /// Derive bounded session material.
    DeriveSession => "derive_session",
    /// Bootstrap a protected transport.
    BootstrapTransport => "bootstrap_transport",
}
}

define_closed_secret_enum! {
/// Closed purpose vocabulary for a future secret use.
pub enum SecretPurpose {
    /// Access an external service.
    ExternalServiceAccess => "external_service_access",
    /// Access a governed data source.
    DataSourceAccess => "data_source_access",
    /// Access an artifact store.
    ArtifactStoreAccess => "artifact_store_access",
    /// Access a model provider.
    ModelProviderAccess => "model_provider_access",
    /// Access an orchestrator service.
    OrchestratorAccess => "orchestrator_access",
    /// Access a device-local service.
    DeviceServiceAccess => "device_service_access",
    /// Perform a cryptographic operation.
    CryptographicOperation => "cryptographic_operation",
}
}

define_closed_secret_enum! {
/// Offline behavior allowed by a future secret reference.
pub enum SecretOfflineBehavior {
    /// Deny secret use while the required authority path is unavailable.
    Deny => "deny",
    /// Existing uses may continue only until their already-established expiry.
    ContinueExistingUntilExpiry => "continue_existing_until_expiry",
}
}

define_closed_secret_enum! {
/// Exposure profile declared by a future driver-owned credential sink.
pub enum SecretDeliveryExposureProfile {
    /// The driver provides a trusted injection boundary.
    TrustedInjection => "trusted_injection",
    /// Secret material becomes exposed to the target process boundary.
    MaterialExposed => "material_exposed",
}
}

/// Opaque immutable provider version reference.
///
/// The value is deliberately not a provider locator. It cannot contain URI,
/// path, query, fragment, or scheme delimiters and has no resolution helpers.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretProviderVersionRef(String);

impl SecretProviderVersionRef {
    /// Creates a provider version reference after strict non-locator validation.
    pub fn try_new(value: impl AsRef<str>) -> Result<Self, SecretProviderVersionRefError> {
        let value = value.as_ref();
        validate_provider_version_ref(value)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the validated opaque reference text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SecretProviderVersionRef {
    type Error = SecretProviderVersionRefError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_provider_version_ref(&value)?;
        Ok(Self(value))
    }
}

impl FromStr for SecretProviderVersionRef {
    type Err = SecretProviderVersionRefError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_new(value)
    }
}

impl fmt::Display for SecretProviderVersionRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for SecretProviderVersionRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretProviderVersionRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SecretProviderVersionRefVisitor)
    }
}

/// Provider version reference validation failure.
///
/// Variants contain only fixed bounds/categories and never retain rejected text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretProviderVersionRefError {
    /// Empty provider version references are invalid.
    #[error("secret provider version reference must not be empty")]
    Empty,
    /// The reference exceeded the fixed byte bound.
    #[error("secret provider version reference exceeds {max_bytes} bytes")]
    TooLong {
        /// Maximum accepted UTF-8 byte length.
        max_bytes: usize,
    },
    /// The reference contained a byte outside printable non-space ASCII.
    #[error("secret provider version reference must use printable non-space ASCII")]
    NonPrintableAscii,
    /// The reference contained a URI/path/query/fragment delimiter.
    #[error("secret provider version reference contains a forbidden locator delimiter")]
    ForbiddenLocatorDelimiter,
}

fn validate_provider_version_ref(value: &str) -> Result<(), SecretProviderVersionRefError> {
    if value.is_empty() {
        return Err(SecretProviderVersionRefError::Empty);
    }
    if value.len() > MAX_PROVIDER_VERSION_REF_BYTES {
        return Err(SecretProviderVersionRefError::TooLong {
            max_bytes: MAX_PROVIDER_VERSION_REF_BYTES,
        });
    }
    if value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
        return Err(SecretProviderVersionRefError::NonPrintableAscii);
    }
    if value
        .bytes()
        .any(|byte| matches!(byte, b'/' | b'\\' | b'?' | b'#' | b':'))
    {
        return Err(SecretProviderVersionRefError::ForbiddenLocatorDelimiter);
    }
    Ok(())
}

struct SecretProviderVersionRefVisitor;

impl<'de> Visitor<'de> for SecretProviderVersionRefVisitor {
    type Value = SecretProviderVersionRef;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a validated opaque secret provider version reference string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        SecretProviderVersionRef::try_new(value).map_err(E::custom)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        SecretProviderVersionRef::try_from(value).map_err(E::custom)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret provider version reference must be a string",
        ))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret provider version reference must be a string",
        ))
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret provider version reference must be a string",
        ))
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret provider version reference must be a string",
        ))
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret provider version reference must be a string",
        ))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret provider version reference must be a string",
        ))
    }

    fn visit_char<E>(self, _value: char) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret provider version reference must be a string",
        ))
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret provider version reference must be a string",
        ))
    }

    fn visit_byte_buf<E>(self, _value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret provider version reference must be a string",
        ))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret provider version reference must be a string",
        ))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret provider version reference must be a string",
        ))
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        Err(A::Error::custom(
            "secret provider version reference must be a string",
        ))
    }

    fn visit_map<A>(self, _map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        Err(A::Error::custom(
            "secret provider version reference must be a string",
        ))
    }
}

/// Finite lease bounds carried by a future secret reference.
///
/// This value is behavior-free and does not issue, renew, or authorize a lease.
/// Its private fields and checked deserialization keep public values valid by
/// construction.
///
/// Direct field construction and default/unbounded policy construction are not
/// available:
///
/// ```compile_fail
/// use splendor_types::SecretLeasePolicy;
///
/// let _ = SecretLeasePolicy {
///     max_lease_duration_seconds: 1,
///     max_continuous_lifetime_seconds: 1,
///     max_uses: 1,
///     renewable: false,
///     clock_skew_tolerance_seconds: 0,
/// };
/// ```
///
/// ```compile_fail
/// use splendor_types::SecretLeasePolicy;
///
/// let _ = SecretLeasePolicy::default();
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecretLeasePolicy {
    max_lease_duration_seconds: u64,
    max_continuous_lifetime_seconds: u64,
    max_uses: u64,
    renewable: bool,
    clock_skew_tolerance_seconds: u64,
}

impl SecretLeasePolicy {
    /// Creates a finite validated lease policy.
    pub fn try_new(
        max_lease_duration_seconds: u64,
        max_continuous_lifetime_seconds: u64,
        max_uses: u64,
        renewable: bool,
        clock_skew_tolerance_seconds: u64,
    ) -> Result<Self, SecretLeasePolicyError> {
        if !(1..=MAX_SAFE_INTEGER).contains(&max_lease_duration_seconds) {
            return Err(SecretLeasePolicyError::MaxLeaseDurationOutOfRange);
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&max_continuous_lifetime_seconds) {
            return Err(SecretLeasePolicyError::MaxContinuousLifetimeOutOfRange);
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&max_uses) {
            return Err(SecretLeasePolicyError::MaxUsesOutOfRange);
        }
        if clock_skew_tolerance_seconds > 30 {
            return Err(SecretLeasePolicyError::ClockSkewToleranceOutOfRange);
        }
        if max_continuous_lifetime_seconds < max_lease_duration_seconds {
            return Err(SecretLeasePolicyError::ContinuousLifetimeLessThanLeaseDuration);
        }
        Ok(Self {
            max_lease_duration_seconds,
            max_continuous_lifetime_seconds,
            max_uses,
            renewable,
            clock_skew_tolerance_seconds,
        })
    }

    /// Returns the maximum duration of one lease in seconds.
    pub fn max_lease_duration_seconds(&self) -> u64 {
        self.max_lease_duration_seconds
    }

    /// Returns the maximum continuous lifetime across renewals in seconds.
    pub fn max_continuous_lifetime_seconds(&self) -> u64 {
        self.max_continuous_lifetime_seconds
    }

    /// Returns the maximum number of uses allowed by the policy.
    pub fn max_uses(&self) -> u64 {
        self.max_uses
    }

    /// Returns whether the future lease policy permits renewal.
    pub fn renewable(&self) -> bool {
        self.renewable
    }

    /// Returns the bounded clock-skew tolerance in seconds.
    ///
    /// This value does not create post-expiry grace.
    pub fn clock_skew_tolerance_seconds(&self) -> u64 {
        self.clock_skew_tolerance_seconds
    }
}

struct SecretLeasePolicyInput {
    max_lease_duration_seconds: u64,
    max_continuous_lifetime_seconds: u64,
    max_uses: u64,
    renewable: bool,
    clock_skew_tolerance_seconds: u64,
}

impl TryFrom<SecretLeasePolicyInput> for SecretLeasePolicy {
    type Error = SecretLeasePolicyError;

    fn try_from(value: SecretLeasePolicyInput) -> Result<Self, Self::Error> {
        Self::try_new(
            value.max_lease_duration_seconds,
            value.max_continuous_lifetime_seconds,
            value.max_uses,
            value.renewable,
            value.clock_skew_tolerance_seconds,
        )
    }
}

impl Serialize for SecretLeasePolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretLeasePolicy", 5)?;
        state.serialize_field(
            "clock_skew_tolerance_seconds",
            &self.clock_skew_tolerance_seconds,
        )?;
        state.serialize_field(
            "max_continuous_lifetime_seconds",
            &self.max_continuous_lifetime_seconds,
        )?;
        state.serialize_field(
            "max_lease_duration_seconds",
            &self.max_lease_duration_seconds,
        )?;
        state.serialize_field("max_uses", &self.max_uses)?;
        state.serialize_field("renewable", &self.renewable)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SecretLeasePolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SecretLeasePolicyVisitor)
    }
}

/// Lease-policy range or relationship validation failure.
///
/// Errors intentionally omit candidate policy values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretLeasePolicyError {
    /// The single-lease duration was not a positive safe JSON integer.
    #[error("max_lease_duration_seconds must be in 1..=9007199254740991")]
    MaxLeaseDurationOutOfRange,
    /// The continuous lifetime was not a positive safe JSON integer.
    #[error("max_continuous_lifetime_seconds must be in 1..=9007199254740991")]
    MaxContinuousLifetimeOutOfRange,
    /// The maximum use count was not a positive safe JSON integer.
    #[error("max_uses must be in 1..=9007199254740991")]
    MaxUsesOutOfRange,
    /// Continuous lifetime was shorter than a single lease duration.
    #[error("max_continuous_lifetime_seconds must not be less than max_lease_duration_seconds")]
    ContinuousLifetimeLessThanLeaseDuration,
    /// Clock-skew tolerance exceeded the closed zero-to-thirty-second range.
    #[error("clock_skew_tolerance_seconds must be in 0..=30")]
    ClockSkewToleranceOutOfRange,
}

enum SecretLeasePolicyField {
    ClockSkewToleranceSeconds,
    MaxContinuousLifetimeSeconds,
    MaxLeaseDurationSeconds,
    MaxUses,
    Renewable,
    Unknown,
}

struct SecretLeasePolicyFieldVisitor;

impl<'de> Visitor<'de> for SecretLeasePolicyFieldVisitor {
    type Value = SecretLeasePolicyField;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a secret lease policy field")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(match value {
            "clock_skew_tolerance_seconds" => SecretLeasePolicyField::ClockSkewToleranceSeconds,
            "max_continuous_lifetime_seconds" => {
                SecretLeasePolicyField::MaxContinuousLifetimeSeconds
            }
            "max_lease_duration_seconds" => SecretLeasePolicyField::MaxLeaseDurationSeconds,
            "max_uses" => SecretLeasePolicyField::MaxUses,
            "renewable" => SecretLeasePolicyField::Renewable,
            _ => SecretLeasePolicyField::Unknown,
        })
    }
}

impl<'de> Deserialize<'de> for SecretLeasePolicyField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_identifier(SecretLeasePolicyFieldVisitor)
    }
}

struct SecretLeasePolicyVisitor;

impl<'de> Visitor<'de> for SecretLeasePolicyVisitor {
    type Value = SecretLeasePolicy;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a closed five-field secret lease policy object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut clock_skew_tolerance_seconds = None;
        let mut max_continuous_lifetime_seconds = None;
        let mut max_lease_duration_seconds = None;
        let mut max_uses = None;
        let mut renewable = None;

        while let Some(field) = map.next_key::<SecretLeasePolicyField>()? {
            match field {
                SecretLeasePolicyField::ClockSkewToleranceSeconds => {
                    if clock_skew_tolerance_seconds.is_some() {
                        return Err(A::Error::custom(
                            "secret lease policy has a duplicate field",
                        ));
                    }
                    clock_skew_tolerance_seconds = Some(map.next_value::<NoEchoU64>()?.0);
                }
                SecretLeasePolicyField::MaxContinuousLifetimeSeconds => {
                    if max_continuous_lifetime_seconds.is_some() {
                        return Err(A::Error::custom(
                            "secret lease policy has a duplicate field",
                        ));
                    }
                    max_continuous_lifetime_seconds = Some(map.next_value::<NoEchoU64>()?.0);
                }
                SecretLeasePolicyField::MaxLeaseDurationSeconds => {
                    if max_lease_duration_seconds.is_some() {
                        return Err(A::Error::custom(
                            "secret lease policy has a duplicate field",
                        ));
                    }
                    max_lease_duration_seconds = Some(map.next_value::<NoEchoU64>()?.0);
                }
                SecretLeasePolicyField::MaxUses => {
                    if max_uses.is_some() {
                        return Err(A::Error::custom(
                            "secret lease policy has a duplicate field",
                        ));
                    }
                    max_uses = Some(map.next_value::<NoEchoU64>()?.0);
                }
                SecretLeasePolicyField::Renewable => {
                    if renewable.is_some() {
                        return Err(A::Error::custom(
                            "secret lease policy has a duplicate field",
                        ));
                    }
                    renewable = Some(map.next_value::<NoEchoBool>()?.0);
                }
                SecretLeasePolicyField::Unknown => {
                    return Err(A::Error::custom(
                        "secret lease policy contains an unknown field",
                    ));
                }
            }
        }

        let clock_skew_tolerance_seconds = clock_skew_tolerance_seconds
            .ok_or_else(|| A::Error::custom("secret lease policy is missing a required field"))?;
        let max_continuous_lifetime_seconds = max_continuous_lifetime_seconds
            .ok_or_else(|| A::Error::custom("secret lease policy is missing a required field"))?;
        let max_lease_duration_seconds = max_lease_duration_seconds
            .ok_or_else(|| A::Error::custom("secret lease policy is missing a required field"))?;
        let max_uses = max_uses
            .ok_or_else(|| A::Error::custom("secret lease policy is missing a required field"))?;
        let renewable = renewable
            .ok_or_else(|| A::Error::custom("secret lease policy is missing a required field"))?;

        SecretLeasePolicy::try_from(SecretLeasePolicyInput {
            max_lease_duration_seconds,
            max_continuous_lifetime_seconds,
            max_uses,
            renewable,
            clock_skew_tolerance_seconds,
        })
        .map_err(A::Error::custom)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_char<E>(self, _value: char) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_byte_buf<E>(self, _value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("secret lease policy must be an object"))
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        Err(A::Error::custom("secret lease policy must be an object"))
    }
}

struct NoEchoU64(u64);

impl<'de> Deserialize<'de> for NoEchoU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoEchoU64Visitor)
    }
}

struct NoEchoU64Visitor;

impl<'de> Visitor<'de> for NoEchoU64Visitor {
    type Value = NoEchoU64;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an unsigned integer")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(NoEchoU64(value))
    }

    fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        u64::try_from(value)
            .map(NoEchoU64)
            .map_err(|_| E::custom("secret lease policy integer field is out of range"))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        u64::try_from(value)
            .map(NoEchoU64)
            .map_err(|_| E::custom("secret lease policy integer field is out of range"))
    }

    fn visit_i128<E>(self, value: i128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        u64::try_from(value)
            .map(NoEchoU64)
            .map_err(|_| E::custom("secret lease policy integer field is out of range"))
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy integer field has invalid type",
        ))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy integer field has invalid type",
        ))
    }

    fn visit_char<E>(self, _value: char) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy integer field has invalid type",
        ))
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy integer field has invalid type",
        ))
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy integer field has invalid type",
        ))
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy integer field has invalid type",
        ))
    }

    fn visit_byte_buf<E>(self, _value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy integer field has invalid type",
        ))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy integer field has invalid type",
        ))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy integer field has invalid type",
        ))
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        Err(A::Error::custom(
            "secret lease policy integer field has invalid type",
        ))
    }

    fn visit_map<A>(self, _map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        Err(A::Error::custom(
            "secret lease policy integer field has invalid type",
        ))
    }
}

struct NoEchoBool(bool);

impl<'de> Deserialize<'de> for NoEchoBool {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoEchoBoolVisitor)
    }
}

struct NoEchoBoolVisitor;

impl<'de> Visitor<'de> for NoEchoBoolVisitor {
    type Value = NoEchoBool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a boolean")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(NoEchoBool(value))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_char<E>(self, _value: char) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_byte_buf<E>(self, _value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        Err(A::Error::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }

    fn visit_map<A>(self, _map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        Err(A::Error::custom(
            "secret lease policy renewable field has invalid type",
        ))
    }
}

#[cfg(test)]
#[path = "../tests/unit/secrets_tests.rs"]
mod tests;
