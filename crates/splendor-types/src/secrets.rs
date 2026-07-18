//! Behavior-free C03 secret reference and lease-policy grammar.
//!
//! These values describe closed pre-placement contracts only. They do not
//! authorize secret access, resolve provider locations, create leases, or
//! perform delivery.

use serde::de::{Error as DeError, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_PROVIDER_VERSION_REF_BYTES: usize = 128;

/// Classification of secret material referenced by a future secret record.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretClassification {
    /// Material used to authenticate to a protected service.
    AuthenticationCredential,
    /// Material used to create cryptographic signatures.
    SigningMaterial,
    /// Material used for encryption or decryption.
    EncryptionMaterial,
    /// Configuration that must remain private.
    PrivateConfiguration,
    /// Secret material without a more specific v1 classification.
    OpaqueSecret,
}

/// Closed delivery vocabulary for a future secret-use requirement.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretDeliveryMethod {
    /// Delivery through a pre-opened inherited file descriptor.
    InheritedFd,
    /// Delivery through a bounded file on a memory-backed filesystem.
    TmpfsFile,
    /// Delivery through a one-shot local socket.
    OneShotLocalSocket,
    /// Delivery through an orchestrator-managed projected secret.
    OrchestratorProjectedSecret,
    /// Compatibility vocabulary only; this variant grants no permission.
    EnvironmentVariable,
}

/// Intended operation for a future secret use.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretUseIntent {
    /// Authenticate to a service or resource.
    Authenticate,
    /// Sign data.
    Sign,
    /// Encrypt data.
    Encrypt,
    /// Decrypt data.
    Decrypt,
    /// Derive bounded session material.
    DeriveSession,
    /// Bootstrap a protected transport.
    BootstrapTransport,
}

/// Closed purpose vocabulary for a future secret use.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretPurpose {
    /// Access an external service.
    ExternalServiceAccess,
    /// Access a governed data source.
    DataSourceAccess,
    /// Access an artifact store.
    ArtifactStoreAccess,
    /// Access a model provider.
    ModelProviderAccess,
    /// Access an orchestrator service.
    OrchestratorAccess,
    /// Access a device-local service.
    DeviceServiceAccess,
    /// Perform a cryptographic operation.
    CryptographicOperation,
}

/// Offline behavior allowed by a future secret reference.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretOfflineBehavior {
    /// Deny secret use while the required authority path is unavailable.
    Deny,
    /// Existing uses may continue only until their already-established expiry.
    ContinueExistingUntilExpiry,
}

/// Exposure profile declared by a future driver-owned credential sink.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretDeliveryExposureProfile {
    /// The driver provides a trusted injection boundary.
    TrustedInjection,
    /// Secret material becomes exposed to the target process boundary.
    MaterialExposed,
}

/// Opaque immutable provider version reference.
///
/// The value is deliberately not a provider locator. It cannot contain URI,
/// path, query, fragment, or scheme delimiters and has no resolution helpers.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretProviderVersionRef(String);

impl SecretProviderVersionRef {
    /// Creates a provider version reference after strict non-locator validation.
    pub fn try_new(value: impl Into<String>) -> Result<Self, SecretProviderVersionRefError> {
        let value = value.into();
        validate_provider_version_ref(&value)?;
        Ok(Self(value))
    }

    /// Returns the validated opaque reference text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SecretProviderVersionRef {
    type Error = SecretProviderVersionRefError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
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
        SecretProviderVersionRef::try_new(value).map_err(E::custom)
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
                    let _: IgnoredAny = map.next_value()?;
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
