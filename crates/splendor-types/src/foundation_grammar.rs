//! Behavior-free C03 foundation lexical and declaration-digest primitives.
//!
//! These values validate and serialize exact wire spellings. They perform no
//! owner lookup, grant no authority, and create no Registry record or state.

use crate::DriverOperationCredentialSinksV1;
use serde::{Serialize, Serializer};
use std::error::Error;
use std::fmt;
use std::str::FromStr;

const MAX_LEXICAL_BYTES: usize = 128;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const REGISTRY_DECLARATION_DIGEST_DOMAIN: &[u8] = b"splendor.driver.operation_credential_sinks.v1";

/// Closed, code-only failure for the RFC 0018 foundation grammar.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum FoundationGrammarError {
    InvalidContractShape,
    InvalidContractVersion,
    InvalidContractIdentity,
    InvalidContractTimestamp,
    InvalidContractInteger,
    InvalidContractDigest,
    InvalidContractSignature,
    InvalidContractBound,
    InvalidContractBinding,
}

impl FoundationGrammarError {
    /// Returns the exact fixed RFC 0018 error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidContractShape => "invalid_contract_shape",
            Self::InvalidContractVersion => "invalid_contract_version",
            Self::InvalidContractIdentity => "invalid_contract_identity",
            Self::InvalidContractTimestamp => "invalid_contract_timestamp",
            Self::InvalidContractInteger => "invalid_contract_integer",
            Self::InvalidContractDigest => "invalid_contract_digest",
            Self::InvalidContractSignature => "invalid_contract_signature",
            Self::InvalidContractBound => "invalid_contract_bound",
            Self::InvalidContractBinding => "invalid_contract_binding",
        }
    }
}

impl fmt::Display for FoundationGrammarError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for FoundationGrammarError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for FoundationGrammarError {}

/// An ASCII schema identifier in the exact RFC 0018 v1 lexical profile.
///
/// Validated scalars intentionally have no generic deserialization bypass:
///
/// ```compile_fail
/// use splendor_types::CanonicalSchemaIdV1;
/// let _: CanonicalSchemaIdV1 = serde_json::from_str("\"example.schema.v1\"").unwrap();
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalSchemaIdV1(String);

impl CanonicalSchemaIdV1 {
    /// Constructs a checked schema identifier without normalization.
    pub fn try_new(value: String) -> Result<Self, FoundationGrammarError> {
        validate_schema_id(&value)?;
        Ok(Self(value))
    }

    /// Parses a checked schema identifier without normalization.
    pub fn parse(value: &str) -> Result<Self, FoundationGrammarError> {
        validate_schema_id(value)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact validated wire spelling.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for CanonicalSchemaIdV1 {
    type Err = FoundationGrammarError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for CanonicalSchemaIdV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

/// An ASCII security-sensitive label in the exact RFC 0018 v1 profile.
///
/// ```compile_fail
/// use splendor_types::CanonicalLabelV1;
/// let _: CanonicalLabelV1 = serde_json::from_str("\"example\"").unwrap();
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalLabelV1(String);

impl CanonicalLabelV1 {
    /// Constructs a checked label without normalization.
    pub fn try_new(value: String) -> Result<Self, FoundationGrammarError> {
        validate_label(&value)?;
        Ok(Self(value))
    }

    /// Parses a checked label without normalization.
    pub fn parse(value: &str) -> Result<Self, FoundationGrammarError> {
        validate_label(value)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact validated wire spelling.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for CanonicalLabelV1 {
    type Err = FoundationGrammarError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for CanonicalLabelV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

/// A distinct C03 foundation code in the exact RFC 0018 v1 profile.
///
/// It is deliberately not interchangeable with [`CanonicalLabelV1`]:
///
/// ```compile_fail
/// use splendor_types::{CanonicalLabelV1, FoundationGrammarCodeV1};
/// let label = CanonicalLabelV1::parse("example").unwrap();
/// let _: FoundationGrammarCodeV1 = label;
/// ```
///
/// ```compile_fail
/// use splendor_types::FoundationGrammarCodeV1;
/// let _: FoundationGrammarCodeV1 = serde_json::from_str("\"example\"").unwrap();
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FoundationGrammarCodeV1(String);

impl FoundationGrammarCodeV1 {
    /// Constructs a checked code without normalization.
    pub fn try_new(value: String) -> Result<Self, FoundationGrammarError> {
        validate_label(&value)?;
        Ok(Self(value))
    }

    /// Parses a checked code without normalization.
    pub fn parse(value: &str) -> Result<Self, FoundationGrammarError> {
        validate_label(value)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact validated wire spelling.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for FoundationGrammarCodeV1 {
    type Err = FoundationGrammarError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for FoundationGrammarCodeV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

fn validate_lexical_maximum(value: &str) -> Result<(), FoundationGrammarError> {
    if value.len() > MAX_LEXICAL_BYTES {
        return Err(FoundationGrammarError::InvalidContractBound);
    }
    Ok(())
}

fn validate_label(value: &str) -> Result<(), FoundationGrammarError> {
    validate_lexical_maximum(value)?;
    if !is_canonical_label(value) {
        return Err(FoundationGrammarError::InvalidContractShape);
    }
    Ok(())
}

fn validate_schema_id(value: &str) -> Result<(), FoundationGrammarError> {
    validate_lexical_maximum(value)?;
    if !is_canonical_schema_id(value) {
        return Err(FoundationGrammarError::InvalidContractVersion);
    }
    Ok(())
}

fn is_canonical_label(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(byte) if byte.is_ascii_lowercase())
        && bytes.get(1..).is_some_and(|remaining| {
            remaining.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        })
}

fn is_canonical_schema_id(value: &str) -> bool {
    let Some((name, version)) = value.rsplit_once(".v") else {
        return false;
    };
    is_canonical_label(name)
        && !version.is_empty()
        && matches!(version.as_bytes()[0], b'1'..=b'9')
        && version.bytes().all(|byte| byte.is_ascii_digit())
}

/// An exact UTC timestamp with mandatory microsecond precision.
///
/// ```compile_fail
/// use splendor_types::CanonicalTimestampV1;
/// let _: CanonicalTimestampV1 =
///     serde_json::from_str("\"2000-01-01T00:00:00.000000Z\"").unwrap();
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalTimestampV1(String);

impl CanonicalTimestampV1 {
    /// Constructs a checked timestamp without rounding or normalization.
    pub fn try_new(value: String) -> Result<Self, FoundationGrammarError> {
        validate_timestamp(&value)?;
        Ok(Self(value))
    }

    /// Parses a checked timestamp without rounding or normalization.
    pub fn parse(value: &str) -> Result<Self, FoundationGrammarError> {
        validate_timestamp(value)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact validated wire spelling.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_timestamp(value: &str) -> Result<(), FoundationGrammarError> {
    if !is_canonical_timestamp(value) {
        return Err(FoundationGrammarError::InvalidContractTimestamp);
    }
    Ok(())
}

impl FromStr for CanonicalTimestampV1 {
    type Err = FoundationGrammarError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for CanonicalTimestampV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

fn is_canonical_timestamp(value: &str) -> bool {
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
    if year == 0 {
        return false;
    }
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

macro_rules! canonical_zero_inclusive_integer {
    ($name:ident) => {
        #[doc = concat!(
                    "A canonical zero-inclusive safe JSON integer.\n\n",
                    "```compile_fail\n",
                    "use splendor_types::", stringify!($name), ";\n",
                    "let _: ", stringify!($name), " = serde_json::from_str(\"0\").unwrap();\n",
                    "```"
                )]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            /// Constructs a checked safe integer.
            pub const fn try_new(value: u64) -> Result<Self, FoundationGrammarError> {
                if value > MAX_SAFE_INTEGER {
                    return Err(FoundationGrammarError::InvalidContractInteger);
                }
                Ok(Self(value))
            }

            /// Parses the exact original decimal token before numeric conversion.
            pub fn parse(value: &str) -> Result<Self, FoundationGrammarError> {
                let parsed = parse_canonical_integer_token(value, true)?;
                Self::try_new(parsed)
            }

            /// Returns the validated integer.
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl FromStr for $name {
            type Err = FoundationGrammarError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_u64(self.0)
            }
        }
    };
}

canonical_zero_inclusive_integer!(CanonicalCountV1);
canonical_zero_inclusive_integer!(CanonicalOrdinalV1);
canonical_zero_inclusive_integer!(CanonicalSequenceV1);

/// A canonical positive revision in the safe JSON integer range.
///
/// ```compile_fail
/// use splendor_types::CanonicalPositiveRevisionV1;
/// let _: CanonicalPositiveRevisionV1 = serde_json::from_str("1").unwrap();
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalPositiveRevisionV1(u64);

impl CanonicalPositiveRevisionV1 {
    /// Constructs a checked positive safe integer.
    pub const fn try_new(value: u64) -> Result<Self, FoundationGrammarError> {
        if value == 0 || value > MAX_SAFE_INTEGER {
            return Err(FoundationGrammarError::InvalidContractInteger);
        }
        Ok(Self(value))
    }

    /// Parses the exact original decimal token before numeric conversion.
    pub fn parse(value: &str) -> Result<Self, FoundationGrammarError> {
        let parsed = parse_canonical_integer_token(value, false)?;
        Self::try_new(parsed)
    }

    /// Returns the validated integer.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl FromStr for CanonicalPositiveRevisionV1 {
    type Err = FoundationGrammarError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for CanonicalPositiveRevisionV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

fn parse_canonical_integer_token(
    value: &str,
    zero_allowed: bool,
) -> Result<u64, FoundationGrammarError> {
    if value.is_empty() || value.len() > 16 {
        return Err(FoundationGrammarError::InvalidContractInteger);
    }
    let bytes = value.as_bytes();
    let canonical = if value == "0" {
        zero_allowed
    } else {
        matches!(bytes.first(), Some(b'1'..=b'9')) && bytes[1..].iter().all(u8::is_ascii_digit)
    };
    if !canonical {
        return Err(FoundationGrammarError::InvalidContractInteger);
    }
    value
        .parse::<u64>()
        .map_err(|_| FoundationGrammarError::InvalidContractInteger)
}

/// Registry-owned digest over an exact validated RFC 0013 declaration.
///
/// The digest has no generic deserialization, byte/domain constructor,
/// `ContentHash` conversion, or full-value formatting surface:
///
/// ```compile_fail
/// use splendor_types::RegistryDeclarationDigest;
/// let _: RegistryDeclarationDigest = serde_json::from_str("\"blake3:00\"").unwrap();
/// ```
///
/// ```compile_fail
/// use splendor_types::{ContentHash, RegistryDeclarationDigest};
/// let _: RegistryDeclarationDigest = ContentHash::blake3(b"candidate").into();
/// ```
///
/// ```compile_fail
/// use splendor_types::RegistryDeclarationDigest;
/// let _: RegistryDeclarationDigest = [0_u8; 32].into();
/// ```
///
/// ```compile_fail
/// use splendor_types::RegistryDeclarationDigest;
/// let digest = RegistryDeclarationDigest::parse(
///     "blake3:0000000000000000000000000000000000000000000000000000000000000000",
/// ).unwrap();
/// let _ = format!("{digest}");
/// ```
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegistryDeclarationDigest([u8; 32]);

impl RegistryDeclarationDigest {
    /// Parses exactly `blake3:` plus 64 lowercase hexadecimal digits.
    pub fn parse(value: &str) -> Result<Self, FoundationGrammarError> {
        let bytes = value.as_bytes();
        if bytes.len() != 71 || !bytes.starts_with(b"blake3:") {
            return Err(FoundationGrammarError::InvalidContractDigest);
        }
        let mut digest = [0_u8; 32];
        for (index, pair) in bytes[7..].chunks_exact(2).enumerate() {
            let high =
                decode_lower_hex(pair[0]).ok_or(FoundationGrammarError::InvalidContractDigest)?;
            let low =
                decode_lower_hex(pair[1]).ok_or(FoundationGrammarError::InvalidContractDigest)?;
            digest[index] = (high << 4) | low;
        }
        Ok(Self(digest))
    }

    fn wire_string(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut wire = String::with_capacity(71);
        wire.push_str("blake3:");
        for byte in self.0 {
            wire.push(char::from(HEX[usize::from(byte >> 4)]));
            wire.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        wire
    }
}

impl TryFrom<&DriverOperationCredentialSinksV1> for RegistryDeclarationDigest {
    type Error = FoundationGrammarError;

    fn try_from(declaration: &DriverOperationCredentialSinksV1) -> Result<Self, Self::Error> {
        let canonical = serde_json::to_vec(declaration)
            .map_err(|_| FoundationGrammarError::InvalidContractShape)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(REGISTRY_DECLARATION_DIGEST_DOMAIN);
        hasher.update(&[0]);
        hasher.update(&canonical);
        Ok(Self(*hasher.finalize().as_bytes()))
    }
}

impl FromStr for RegistryDeclarationDigest {
    type Err = FoundationGrammarError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Debug for RegistryDeclarationDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistryDeclarationDigest(<redacted>)")
    }
}

impl Serialize for RegistryDeclarationDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.wire_string())
    }
}

fn decode_lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../tests/unit/foundation_grammar_tests.rs"]
mod tests;
