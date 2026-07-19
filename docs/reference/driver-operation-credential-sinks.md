# Driver Operation Credential-Sink Contract

## Status

**Additive experimental 0.2/v2 behavior-free contract; incomplete Driver
Registry implementation.**

The implemented surface is the first dependency-safe slice of `DRREG-001` and
accepted [RFC 0013](../rfc/0013-driver-operation-credential-sink-contract.md).
It defines checked Rust values and strict declaration parsing only. It does not
implement a `DriverManifest`, registration, admission, resolution, projection
execution, Gateway invocation, C03 credential authorization, a provider/node
path, daemon/SDK/generated contracts, feature activation, issue closure, or
`G07`/`G08` evidence.

## Purpose and ownership

The Driver Registry owns a nominal `SecretCredentialSlotId` and a closed
operation-level `DriverOperationCredentialSinksV1` declaration. The declaration
states what one driver operation claims it can receive; it is not authority,
control attestation, an approved destination set, or permission to fetch or use
a credential.

C03 continues to own secret classification, intent, delivery exposure and
delivery-control vocabulary. The Driver Registry contract imports those types.
It reuses the existing `DriverOperationRef` unchanged and validates it only at
new strict declaration boundaries.

## Public Rust contract

The crate exports:

- `DRIVER_OPERATION_SCHEMA_V1` and
  `DRIVER_OPERATION_CREDENTIAL_SINKS_SCHEMA_V1`;
- `validate_driver_operation_ref_v1`, which returns unit and creates no wrapper
  or proof identity;
- `SecretCredentialSlotId`;
- `DriverOperationCredentialSinksV1` and
  `DriverOperationCredentialSinkV1`;
- `DriverTrustedSendProfileV1`;
- `DriverCredentialDestinationDigest`; and
- fixed non-reflecting ID, digest, operation and contract error types.

Fields are private and checked constructors/getters expose only validated
values. `DriverOperationCredentialSinksV1` implements `Serialize` but not
`Deserialize`. Untrusted, imported, persisted or rehydrated declaration bytes
must use `DriverOperationCredentialSinksV1::from_json_slice`.

## Declaration schema

Schema: `splendor.driver.operation_credential_sinks.v1`.

Each declaration binds one exact canonical v1 `DriverOperationRef`, one positive
safe-integer declaration revision and 1–16 unique credential slots. Each slot
has non-empty unique supported classifications and intents, one versioned
destination-schema identifier, one delivery exposure profile and the matching
trusted-send profile.

Trusted injection requires a send limit of 1–8 and 1–8 unique delivery-control
kinds including `trusted_injection_boundary`. Material exposure accepts only the
fieldless `{"kind":"not_applicable"}` profile. These values describe a
capability; they do not prove that a runtime control is applied.

Semantic sets are sorted deterministically. Ordinary compact serialization of a
validated declaration is its RFC 8785-compatible canonical byte form. Existing
standalone `DriverOperationRef` serialization and permissive historical reads
remain unchanged.

## Bounded ingress and failures

Before generic value construction, `from_json_slice` enforces:

| Resource | Maximum |
| --- | ---: |
| Raw encoded JSON | 32,768 bytes |
| Container depth | 32 |
| Decoder tokens | 1,024 |
| Object members | 192 |
| Array elements | 384 |
| Decoded member-name/string bytes | 256 |

The preflight rejects malformed UTF-8/escapes, overflowing number tokens,
duplicate names at every object depth and every cap excess. Strict field
validation then follows RFC 0013's deterministic precedence. Public failures
contain one fixed code only; rejected bodies, keys, values, parser details,
locations and source chains are not retained or reflected.

## Destination digest

`DriverCredentialDestinationDigest` is exactly `blake3:` plus 64 lowercase hex
characters. A later admitted destination projection is bound as unkeyed
BLAKE3-256 over:

```text
UTF8(destination_schema) || 0x00 || RFC8785_JCS(validated_projection)
```

The digest is an equality binding, not a signature, credential, permission,
redaction substitute or complete cache key. This slice provides no public
projection type and executes no projection.

## State, trace, replay and side effects

Construction, parsing and serialization perform no external I/O, state commit,
trace emission, provider access, driver call or Gateway action. Replay may
inspect and serialize these values but cannot execute a projection or side
effect. All future credential use remains separately authorized and Gateway
mediated.

## Minimal example

```rust
use splendor_types::DriverOperationCredentialSinksV1;

let input = include_bytes!(
    "../../crates/splendor-types/tests/fixtures/driver/operation-credential-sinks-v1.json"
);
let declaration = DriverOperationCredentialSinksV1::from_json_slice(input)?;
let canonical = serde_json::to_vec(&declaration)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Compatibility and next gates

This contract is additive and experimental and changes no stable 0.1 type or
wire form. Future changes to its schema, error meanings or canonical bytes need
compatible versioning or an accepted RFC amendment.

Before C03 credential authorization or `SecretRef` consumption, a separately
accepted C03 revision-bearing RFC 0012 amendment/versioned successor remains
mandatory. Registry admission/lifecycle, authenticated publisher/artifact
binding, projection schema validation, capability-empty projection isolation,
final-use revision fencing and live authorization are separate blocking owner
contracts.
