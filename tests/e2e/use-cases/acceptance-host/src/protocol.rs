use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::{digest, hmac};
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Number, Value};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Read as _;
use std::path::Path;

pub(crate) const PROFILE_DIGEST_DOMAIN: &[u8] = b"splendor.acceptance.profile_set.v3\0";
pub(crate) const OPERATION_DIGEST_DOMAIN: &str = "splendor.acceptance.operation_profile.v3";
pub(crate) const REQUEST_BODY_DIGEST_DOMAIN: &str = "splendor.acceptance.request_body.v3";
pub(crate) const REQUEST_SIGNATURE_DOMAIN: &[u8] = b"splendor.acceptance.request_hmac.v3\0";
pub(crate) const IDEMPOTENCY_DOMAIN: &str = "splendor.acceptance.idempotency.v3";
pub(crate) const SEMANTIC_DOMAIN: &str = "splendor.acceptance.semantic.v3";
pub(crate) const EFFECT_DOMAIN: &str = "splendor.acceptance.effect.v3";
pub(crate) const STATE_DOMAIN: &str = "splendor.acceptance.domain_state.v3";
pub(crate) const OUTPUT_DOMAIN: &[u8] = b"splendor.acceptance.output.v3\0";
pub(crate) const RECEIPT_ID_DOMAIN: &str = "splendor.acceptance.receipt_id.v3";
pub(crate) const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"splendor.acceptance.receipt_signature.v3\0";

#[derive(Clone, Copy)]
pub(crate) struct JsonLimits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_fields: usize,
    pub max_array_items: usize,
    pub max_string_bytes: usize,
}

#[derive(Debug)]
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private-v3 canonical JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let signed = i64::try_from(value).map_err(|_| E::custom("integer_out_of_range"))?;
        Ok(StrictValue(Value::Number(Number::from(signed))))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("floating_point_not_supported"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate_object_key"));
            }
            let value = object.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values.into_iter().collect())))
    }
}

pub(crate) fn parse_json(
    bytes: &[u8],
    limits: JsonLimits,
    require_canonical: bool,
) -> Result<Value, String> {
    if bytes.is_empty() || bytes.len() > limits.max_bytes {
        return Err("json_size_invalid".to_string());
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|_| "invalid_private_v3_json".to_string())?
        .0;
    deserializer
        .end()
        .map_err(|_| "invalid_private_v3_json".to_string())?;
    validate_value(&value, limits)?;
    if require_canonical && canonical_json(&value, limits)? != bytes {
        return Err("json_not_canonical".to_string());
    }
    Ok(value)
}

pub(crate) fn canonical_json(value: &Value, limits: JsonLimits) -> Result<Vec<u8>, String> {
    validate_value(value, limits)?;
    serde_json::to_vec(value).map_err(|_| "canonical_json_failed".to_string())
}

pub(crate) fn validate_value(value: &Value, limits: JsonLimits) -> Result<(), String> {
    fn visit(
        value: &Value,
        limits: JsonLimits,
        depth: usize,
        fields: &mut usize,
    ) -> Result<(), String> {
        if depth > limits.max_depth {
            return Err("json_depth_exceeded".to_string());
        }
        match value {
            Value::Null | Value::Bool(_) => Ok(()),
            Value::Number(number) => {
                if number.as_i64().is_none() {
                    Err("integer_out_of_range".to_string())
                } else {
                    Ok(())
                }
            }
            Value::String(value) => {
                if value.len() > limits.max_string_bytes
                    || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
                {
                    Err("json_string_not_printable_ascii".to_string())
                } else {
                    Ok(())
                }
            }
            Value::Array(values) => {
                if values.len() > limits.max_array_items {
                    return Err("json_array_items_exceeded".to_string());
                }
                for value in values {
                    visit(value, limits, depth + 1, fields)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                *fields = fields
                    .checked_add(values.len())
                    .ok_or_else(|| "json_fields_exceeded".to_string())?;
                if *fields > limits.max_fields {
                    return Err("json_fields_exceeded".to_string());
                }
                for (key, value) in values {
                    visit(&Value::String(key.clone()), limits, depth + 1, fields)?;
                    visit(value, limits, depth + 1, fields)?;
                }
                Ok(())
            }
        }
    }

    let mut fields = 0;
    visit(value, limits, 1, &mut fields)
}

pub(crate) fn sha256_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let mut input = Vec::with_capacity(domain.len() + bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(bytes);
    format!(
        "sha256:{}",
        hex(digest::digest(&digest::SHA256, &input).as_ref())
    )
}

pub(crate) fn sha256_value(domain: &str, value: &Value) -> Result<String, String> {
    let mut prefix = domain.as_bytes().to_vec();
    prefix.push(0);
    Ok(sha256_bytes(
        &prefix,
        &canonical_json(
            value,
            JsonLimits {
                max_bytes: 262_144,
                max_depth: 16,
                max_fields: 1024,
                max_array_items: 256,
                max_string_bytes: 2048,
            },
        )?,
    ))
}

pub(crate) fn request_mac(key: &[u8], key_id: &str, body: &[u8]) -> Result<String, String> {
    if key.len() != 32 || !printable_token(key_id, 128) {
        return Err("request_key_invalid".to_string());
    }
    let mut frame =
        Vec::with_capacity(REQUEST_SIGNATURE_DOMAIN.len() + key_id.len() + body.len() + 1);
    frame.extend_from_slice(REQUEST_SIGNATURE_DOMAIN);
    frame.extend_from_slice(key_id.as_bytes());
    frame.push(0);
    frame.extend_from_slice(body);
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    Ok(URL_SAFE_NO_PAD.encode(hmac::sign(&key, &frame).as_ref()))
}

pub(crate) fn decode_b64(value: &str, expected: Option<usize>) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("base64url_not_canonical".to_string());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| "base64url_invalid".to_string())?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value
        || expected.is_some_and(|expected| decoded.len() != expected)
    {
        return Err("base64url_not_canonical".to_string());
    }
    Ok(decoded)
}

pub(crate) fn printable_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

pub(crate) fn read_secure_file(
    path: &Path,
    maximum: usize,
    owner_only: bool,
) -> Result<Vec<u8>, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "secure_file_parent_invalid".to_string())?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| "secure_file_parent_unavailable".to_string())?;
    let before =
        std::fs::symlink_metadata(path).map_err(|_| "secure_file_unavailable".to_string())?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.len() == 0
        || before.len() > maximum as u64
    {
        return Err("secure_file_metadata_invalid".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if parent_metadata.uid() != unsafe { libc::geteuid() }
            || parent_metadata.permissions().mode() & 0o022 != 0
            || before.nlink() != 1
            || before.uid() != unsafe { libc::geteuid() }
            || (owner_only && before.permissions().mode() & 0o077 != 0)
            || (!owner_only && before.permissions().mode() & 0o022 != 0)
        {
            return Err("secure_file_ownership_invalid".to_string());
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|_| "secure_file_open_failed".to_string())?;
    let opened = file
        .metadata()
        .map_err(|_| "secure_file_metadata_unavailable".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if opened.dev() != before.dev() || opened.ino() != before.ino() || opened.nlink() != 1 {
            return Err("secure_file_changed".to_string());
        }
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "secure_file_read_failed".to_string())?;
    if bytes.len() != opened.len() as usize || bytes.len() > maximum {
        return Err("secure_file_size_invalid".to_string());
    }
    Ok(bytes)
}

pub(crate) fn object_fields(value: &Value) -> Option<std::collections::BTreeSet<&str>> {
    value
        .as_object()
        .map(|object| object.keys().map(String::as_str).collect())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
