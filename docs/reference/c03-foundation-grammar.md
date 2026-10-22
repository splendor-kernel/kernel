# C03 Foundation Grammar — RFC 0018 Slice 1A

## Status and purpose

This is an **additive experimental and incomplete** `FND-001` slice in
`splendor-types`. It implements reusable behavior-free lexical values and the
one declaration digest fully authorized by accepted RFC 0018. It does not
complete `FND-001`, C03, the Driver Registry, or `G00`; `G00` remains
`not_exercised`.

## Implemented Rust APIs

- `CanonicalSchemaIdV1`: `1..=128` ASCII bytes matching
  `^[a-z][a-z0-9._-]*\.v[1-9][0-9]*$`.
- `CanonicalLabelV1` and the distinct, non-convertible
  `FoundationGrammarCodeV1`: `1..=128` ASCII bytes matching
  `^[a-z][a-z0-9._-]*$`.
- `CanonicalTimestampV1`: exact calendar-valid
  `YYYY-MM-DDTHH:MM:SS.ffffffZ`, including years `0001..=9999` and no leap
  seconds, offsets, alternate precision, or normalization.
- `CanonicalCountV1`, `CanonicalOrdinalV1`, and `CanonicalSequenceV1`: exact
  original token `0|[1-9][0-9]*` in `0..=9007199254740991`.
- `CanonicalPositiveRevisionV1`: exact original token `[1-9][0-9]*` in
  `1..=9007199254740991`.
- `FoundationGrammarError`: the nine closed RFC 0018 codes. `Display`, `Debug`,
  and `Error::source` expose no rejected input or parser detail.
- `RegistryDeclarationDigest`: strict `blake3:` plus 64 lowercase hex digits.
  `TryFrom<&DriverOperationCredentialSinksV1>` hashes unkeyed BLAKE3-256 over
  `UTF8("splendor.driver.operation_credential_sinks.v1") || 0x00 ||` the exact
  existing compact RFC 0013 declaration serialization. Its `Debug` is redacted;
  it has no `Display`, generic `Deserialize`, generic domain/byte constructor,
  or `ContentHash` conversion.

All scalar fields are private and valid by construction. Checked constructors
and strict `parse`/`FromStr` preserve original lexical form; deterministic
`Serialize` emits only the validated canonical scalar. No type trims, case
folds, normalizes, pads, rounds, coerces, defaults, or generically deserializes.

`CanonicalSchemaIdV1` proves lexical form only. It does not register or
authorize a schema. A privileged consumer compares the complete value with one
exact registered schema constant; it never splits or extracts a version,
negotiates a nearby version, infers registration, or falls back to another
schema. For example, `a.v1.v2` is lexically valid because `a.v1` is a valid base
and `.v2` is the final version suffix, but it is semantically unusable unless
`a.v1.v2` itself is exactly registered for that boundary.

## Lifecycle, authority, state, and replay

These values only validate, compare, serialize, or hash in memory. A valid
value grants no identity, authority, admission, activation, currentness,
durability, lookup, read, secret, Gateway, driver, or side-effect permission.
The slice performs no I/O, persistence, state mutation, trace emission, owner
decision, or replay execution. Replay may inspect serialized values but gains no
live authority from them.

## Failures and security

Malformed values fail closed with one fixed `FoundationGrammarError` code.
Errors retain no candidate, path, field, source error, digest, or retry detail.
`RegistryDeclarationDigest` is an integrity/equality binding, not a signature,
credential, redaction mechanism, lookup key, or authorization token. Hashing is
not redaction; callers must keep restricted digests out of generic logs,
metrics, traces, errors, and unauthorized views.

Parsing an arbitrary digest wire proves syntax only. It establishes neither an
RFC 0013 declaration binding nor authority. A binding consumer recomputes
`RegistryDeclarationDigest` from the exact validated
`DriverOperationCredentialSinksV1` declaration and compares that nominal value;
it does not trust a caller-supplied digest string by possession or shape.

## Compatibility and reserved surfaces

This slice is additive and changes no existing 0.1 or RFC 0012–0014 public type,
serde behavior, canonical bytes, digest domain, state format, trace contract, or
runtime behavior. The RFC 0013 declaration remains serialized only by its
existing ordinary compact `Serialize` implementation.

Not implemented here: reserved Event/State/Evidence/Registry/Authority IDs or
enums; any reserved record schema or parser; owner attestation; collection
helpers; ingress-budget scanners or record budget assignments; any other digest;
generated Python/TypeScript/OpenAPI/JSON Schema surfaces; owner services; Store,
daemon, SDK, CLI, Gateway, runtime, migration, or C03 wiring. Those remain
blocked on their accepted owner-specific annexes and compatibility contracts.
