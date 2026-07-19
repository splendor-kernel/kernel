# RFC 0013 - Driver Operation Credential-Sink Contract

## Status and Binding

**Status:** Accepted planning contract

**Accepted:** 2026-07-18

**Accepted proposal SHA-256:**
`f1fd1fa7558811a6794c720d495c15bef42c101e971494de02b572707c4d27b1`

**Compatibility line:** Additive experimental 0.2/v2 owner contract over the
stable 0.1 `DriverOperationRef` representation

**Component:** `splendor.driver-registry`

**Sprint:** `V2-DB-1 - Driver Registry And Gateway`

**Catalog task:** narrow prerequisite slice of `DRREG-001` / issue #331

**Functional requirements:** primary `FR-0.2-04`; constrains `FR-0.2-02`;
`FR-0.2-08` remains future evidence only

**Primitive strengthened:** driver operation contract and secret credential-sink
declaration

This RFC normatively depends on the accepted planning contract in
[RFC 0012](0012-secret-broker-contract.md), especially its canonical driver
operation identity, nominal credential slot, credential-sink, destination
projection, trusted-send, ownership, compatibility, and implementation-order
rules. RFC 0012 remains authoritative for C03 semantics. This RFC supplies only
the Driver Registry-owned wire and validation details that RFC 0012 delegates to
that owner. It does not weaken, replace, or reinterpret any C03 rule.

Accepted RFC 0012 has one explicit downstream gap: its exact
`splendor.secret.credential_authorization.v1` entry does not carry
`driver_declaration_revision`, although its later safe destination binding does.
This RFC does not patch that C03-owned schema. The separately accepted C03
revision-bearing authorization prerequisite below must close the gap before C03
credential authorization or a `SecretRef` consumes this contract.

This RFC is an accepted planning contract. Acceptance is docs-only: it does not
implement a schema, change runtime behavior, authorize credential use, add a
registry service, close #331 or #245, or make `G07` or `G08` pass. It authorizes
only the dependency-safe implementation sequence and evidence gates below.

## Decision

The Driver Registry owns one nominal credential-slot identity and one additive,
operation-level declaration:

- `SecretCredentialSlotId` is a strict non-nil UUID newtype owned by the Driver
  Registry contract surface in `splendor-types`.
- `DriverOperationCredentialSinksV1` is a closed declaration with schema
  `splendor.driver.operation_credential_sinks.v1`.
- Each declaration identifies one existing `DriverOperationRef`, one positive
  declaration revision, and one bounded semantic set of credential sinks.
- Each sink declares only the classifications and intents it can accept, one
  destination projection schema, one exposure profile, and the matching closed
  trusted-send profile.
- The Driver Registry owns the closed destination projection contract and
  `DriverCredentialDestinationDigest` representation. The complete validated
  projection remains private.
- C03 owns `SecretDeliveryControlKind`, credential authorization, approved
  destination digest sets, safe destination binding records, leases, and the
  decision to permit or deny credential use.

The declaration is capability metadata only. It grants no permission, carries
no approved destination digest, and cannot substitute for caller identity, a
work order, capability, data-use grant, policy, approval, quota, lease, Gateway
verification, or C03 authorization. A driver cannot authorize itself by
publishing this declaration.

This is deliberately a pre-manifest seam. It does not define `DriverManifest`,
`DriverOperation`, registration, resolution, invocation, or a registry runtime.

## C03 Revision-Bearing Authorization Prerequisite

Acceptance of this RFC may authorize the first behavior-free #331 owner types
and, after the nominal slot export exists, a separately owned behavior-free C03
`SecretUseRequirement` slot grammar. Neither step authorizes a credential or
consumes `SecretRef.allowed_credential_bindings`.

Before any complete C03 credential authorization, `SecretRef` construction or
revision, authority intersection, lease path, cache, or live credential use
consumes the #331 contract, C03 must separately accept an amendment to RFC 0012
or a versioned C03-owned successor that:

- adds a positive `driver_declaration_revision` to the exact credential-
  authorization coordinate;
- requires a fresh `SecretRef` revision and fresh authority whenever an
  authorized driver declaration revision changes;
- defines historical migration and read/deny behavior: revision-less historical
  records remain readable for audit/replay, may migrate only when the exact
  declaration revision is proven, and otherwise deny live use without inferring
  latest, active, or numerically matching state; and
- pins positive same-revision fixtures and cross-revision denial fixtures across
  canonical Rust bytes and every generated or persisted surface it introduces.

This prerequisite remains C03/Authority-owned. #331 must not add a shadow C03
field, hidden side table, broker translation, inferred revision, or weaker
cross-revision semantics. None of those can satisfy or bypass the separately
accepted C03 contract.

## Ownership and Authority Boundary

One concept has one owner.

| Owner | Owns in this contract | Must not own through this contract |
| --- | --- | --- |
| `splendor-types` Driver Registry contract module | Behavior-free ID, declaration, profile, digest value type, exact constants, bounded strict parsing, reusable operation validation, deterministic canonical serialization | Registry I/O, projection execution, C03 authorization, provider behavior, Gateway execution |
| Driver Registry in `splendor-gateway` | Future admission of declarations and immutable association of an operation revision with its closed projection schema | Credential grants, approved destination sets, leases, provider access, driver self-authorization |
| C03 / Authority | `SecretDeliveryControlKind`, secret classifications/intents/exposure vocabulary, the separately amended revision-bearing credential authorization, approved destination digests, destination binding, lease/use lifecycle | Driver operation identity, credential-slot identity, driver projection schema, driver declaration mutation, or a #331-owned authorization shadow |
| Driver implementation | Future pure projection definition from validated action parameters and trusted registered resource bindings, admitted only under the deferred isolation contract below | Request-provided destination overrides, authority decisions, credentials in manifests, ambient capabilities, alternate effect paths |
| Gateway | Future invocation of an admitted projection only through the deferred capability-empty executor and C03 path after required validation and verification | A second credential path, in-process or ambient-authority projection execution, pre-verification provider I/O, broker-side translation of driver operation identity |
| Caller, SDK, daemon, work order, action parameters | May name a C03 secret-use requirement only where a later accepted C03 surface permits it | Supplying a projection, destination digest, trusted destination override, provider locator, credential, or declaration |

The first implementation slice is behavior-free `splendor-types` work. It
creates no mutable owner, performs no I/O, and has no Gateway or registry
behavior.

## Public Contract Surface

The first implementation plan may expose only these additive experimental Rust
symbols from `splendor-types`:

| Symbol | Contract |
| --- | --- |
| `DRIVER_OPERATION_SCHEMA_V1` | Exact value `splendor.driver.operation.v1`; used by declaration-boundary validation without changing standalone `DriverOperationRef`. |
| `DRIVER_OPERATION_CREDENTIAL_SINKS_SCHEMA_V1` | Exact value `splendor.driver.operation_credential_sinks.v1`. |
| `validate_driver_operation_ref_v1` | Reusable Driver Registry-owned canonical-v1 validator over the existing `DriverOperationRef`; returns unit and creates no wrapper or proof identity. |
| `SecretCredentialSlotId` | Nominal strict non-nil UUID identity. |
| `DriverOperationCredentialSinksV1` | Closed operation-level declaration. |
| `DriverOperationCredentialSinksV1::from_json_slice` | Sole owner-provided untrusted byte parser; enforces the complete ingress budget before strict construction. |
| `DriverOperationCredentialSinkV1` | Closed entry type used only by the declaration. |
| `DriverTrustedSendProfileV1` | Closed tagged union for trusted injection or not-applicable material exposure. |
| `DriverCredentialDestinationDigest` | Exact BLAKE3 destination digest value type. |
| `DriverOperationRefV1ValidationError` | Sole fixed non-reflecting error from `validate_driver_operation_ref_v1`. |
| `SecretCredentialSlotIdError` | Fixed non-reflecting slot parse error. |
| `DriverCredentialDestinationDigestError` | Fixed non-reflecting digest parse error. |
| `DriverCredentialSinkContractError` | Typed declaration/projection validation error containing exactly one fixed code. |
| `DriverCredentialSinkContractErrorCode` | Closed non-reflecting validation code enum. |

Fields are private and are constructed only through checked constructors or the
bounded private wire inputs inside `from_json_slice`.
`DriverOperationCredentialSinksV1` implements `Serialize`, does not implement
`Deserialize`, and exposes no public generic deserialization route. Imported,
external, persisted, and rehydrated bytes can produce the final validated type
only through `from_json_slice`; private wire input types are not exported and
deserialize only inside that function. Getters expose validated values. No
`Default`, unchecked constructor, arbitrary `serde_json::Value`, map, metadata,
or `extensions` field is part of the public contract.

## `SecretCredentialSlotId`

`SecretCredentialSlotId` is a distinct nominal newtype backed by a UUID. It is
not interchangeable with any C03 ID, action ID, invocation ID, secret ref ID,
delivery handle ID, or string alias.

| Property | Exact rule |
| --- | --- |
| Wire form | JSON string containing exactly 36 ASCII bytes in lowercase hyphenated UUID form: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. |
| Parse rule | Parse as a UUID and require that formatting it as lowercase hyphenated text reproduces the input byte-for-byte. |
| Nil | `00000000-0000-0000-0000-000000000000` is invalid. |
| UUID version/variant | Any non-nil UUID accepted by the UUID parser is valid; this RFC does not assign a version or allocator. |
| Ordering | Lexicographic ordering of the UUID's 16 network-order bytes. |
| Construction | Checked parse, `FromStr`, strict serde, and checked `TryFrom<Uuid>` only. |
| Forbidden APIs | No `Default`, `From<Uuid>`, unchecked byte/UUID constructor, random allocator, string alias, or normalization helper. |
| Serialization | Always the exact lowercase hyphenated form. |

Uppercase, compact, braced, URN, whitespace-padded, malformed, nil, null,
numeric, boolean, array, and object forms reject. The fixed parse errors are
`SecretCredentialSlotIdError::InvalidFormat` and
`SecretCredentialSlotIdError::Nil`; their display strings are respectively
`invalid_secret_credential_slot_id` and `nil_secret_credential_slot_id`. Errors
must not retain or print the rejected candidate.

## `DriverOperationCredentialSinksV1`

### Exact schema

Schema constant:

```text
splendor.driver.operation_credential_sinks.v1
```

The top-level value is a closed JSON object with exactly four required,
non-null fields.

| Field | JSON type | Exact rule |
| --- | --- | --- |
| `schema_version` | string | Exactly `splendor.driver.operation_credential_sinks.v1`. |
| `driver_operation` | object | Exact existing three-field `DriverOperationRef` form and declaration-boundary validation defined below. |
| `driver_declaration_revision` | integer | Decimal JSON integer token matching `^[1-9][0-9]*$` and numerically in `1..=9007199254740991`; no zero, sign, leading zero, fraction, exponent, string coercion, or default. |
| `credential_sinks` | array | Semantic set of `1..=16` closed sink entries. |

Unknown fields, missing fields, duplicate JSON members, null, aliases, defaults,
and extensions reject.

### Exact sink entry

Each `credential_sinks` member is a closed object with exactly six required,
non-null fields.

| Field | JSON type | Exact rule |
| --- | --- | --- |
| `credential_slot_id` | string | One valid `SecretCredentialSlotId`; unique within the declaration. |
| `allowed_classifications` | array of strings | Semantic set of `1..=5` unique imported `SecretClassification` values. |
| `allowed_intents` | array of strings | Semantic set of `1..=6` unique imported `SecretUseIntent` values. |
| `destination_schema` | string | `1..=128` ASCII bytes and the exact grammar below. |
| `delivery_exposure_profile` | string | One imported `SecretDeliveryExposureProfile`. |
| `trusted_send_profile` | object | Exact profile corresponding to `delivery_exposure_profile`. |

The word `allowed` means only that the driver declares support. It is not an
authority allowlist. C03 must separately intersect the exact operation, slot,
classification, intent, destination schema/digest, exposure profile, and
trusted-send profile with current authority.

`destination_schema` must match this anchored ASCII grammar:

```regex
^[a-z][a-z0-9._-]*\.v[1-9][0-9]*$
```

There is no case folding, Unicode normalization, alias, wildcard, unversioned
name, trailing separator, or whitespace form. Values such as `network`,
`authorization_header`, `connection_auth`, or an operation-class label are not
complete destination schemas and must not be admitted merely because they match
the lexical grammar. Registry admission must also require the driver-owned
closed projection contract described below.

### Imported C03 vocabulary

This RFC imports, and does not redefine, these exact C03 enums from RFC 0012:

| Type | Imported values / use |
| --- | --- |
| `SecretClassification` | The five RFC 0012 values; entry set bound is therefore `1..=5`. |
| `SecretUseIntent` | The six RFC 0012 values; entry set bound is therefore `1..=6`. |
| `SecretDeliveryExposureProfile` | `trusted_injection`, `material_exposed`. |
| `SecretDeliveryControlKind` | The closed RFC 0012 control vocabulary; used only by trusted injection and bounded here to `1..=8` entries. |

`SecretDeliveryControlKind` is C03-owned and is not currently implemented. A
separate behavior-free #245 prerequisite must implement and export the exact RFC
0012 enum before the Driver Registry contract implementation starts. #331 must
import that type. It must not define, alias, copy, shadow, or translate a Driver
Registry-owned replacement.

### Closed trusted-send profiles

`trusted_send_profile` is a closed internally tagged union.

For `delivery_exposure_profile = "trusted_injection"`, the exact object is:

```json
{
  "kind": "trusted_injection",
  "max_credential_bearing_sends": 1,
  "applicable_delivery_controls": [
    "trusted_injection_boundary"
  ]
}
```

Rules:

- the object has exactly the three fields shown;
- `max_credential_bearing_sends` is a decimal JSON integer token matching
  `^[1-8]$`;
- `applicable_delivery_controls` is a semantic set of `1..=8` unique imported
  `SecretDeliveryControlKind` values;
- the set must contain `trusted_injection_boundary`;
- duplicate controls reject before sorting;
- presence of the declaration does not prove that a runtime control was
  applied; later C03 delivery-control attestation remains required.

For `delivery_exposure_profile = "material_exposed"`, the exact object is:

```json
{"kind":"not_applicable"}
```

No send limit, control list, payload, extension, or alternate not-applicable
spelling is permitted. `trusted_injection` paired with `not_applicable`, or
`material_exposed` paired with `trusted_injection`, rejects.

### Complete valid example

```json
{
  "schema_version": "splendor.driver.operation_credential_sinks.v1",
  "driver_operation": {
    "driver": "example_driver",
    "operation": "example_operation",
    "schema_version": "splendor.driver.operation.v1"
  },
  "driver_declaration_revision": 1,
  "credential_sinks": [
    {
      "credential_slot_id": "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001",
      "allowed_classifications": ["authentication_credential"],
      "allowed_intents": ["authenticate"],
      "destination_schema": "example.driver.https_destination.v1",
      "delivery_exposure_profile": "trusted_injection",
      "trusted_send_profile": {
        "kind": "trusted_injection",
        "max_credential_bearing_sends": 1,
        "applicable_delivery_controls": [
          "destination_network_egress",
          "trusted_injection_boundary"
        ]
      }
    },
    {
      "credential_slot_id": "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4002",
      "allowed_classifications": ["signing_material"],
      "allowed_intents": ["sign"],
      "destination_schema": "example.driver.signing_destination.v1",
      "delivery_exposure_profile": "material_exposed",
      "trusted_send_profile": {"kind": "not_applicable"}
    }
  ]
}
```

The example declares two capabilities. It authorizes neither secret, contains no
destination instance or digest, and triggers no projection, provider, Gateway,
or target operation.

## Declaration Canonicalization

Strict validation runs before canonicalization. Duplicate members and duplicate
semantic-set values reject; canonicalization never silently repairs them.

| Value | Canonical order |
| --- | --- |
| `credential_sinks` | Ascending `SecretCredentialSlotId` 16-byte network order. |
| `allowed_classifications` | Ascending exact ASCII enum spelling. |
| `allowed_intents` | Ascending exact ASCII enum spelling. |
| `applicable_delivery_controls` | Ascending exact ASCII enum spelling. |
| Object members | RFC 8785 JSON Canonicalization Scheme (JCS). |

After the set arrays are normalized, canonical declaration bytes are RFC 8785
JCS bytes for the complete closed declaration. No declaration digest is defined
by this RFC. Input array permutations of the same valid sets serialize to the
same bytes. A duplicate, changed value, changed revision, changed operation, or
changed profile is not the same declaration.

The ordinary `Serialize` implementation for a validated
`DriverOperationCredentialSinksV1` emits every object member in exact RFC 8785
order and every semantic set in the normalized order above. Therefore compact
`serde_json::to_vec(&declaration)` is the canonical-byte API and must equal the
pinned fixture byte-for-byte. There is no second canonical serializer whose
output may diverge from ordinary compact serialization. Pretty-printed or other
formatter output is not canonical declaration bytes.

The valid example above canonicalizes to this exact single-line JSON, with no
BOM, leading/trailing whitespace, or trailing newline:

```json
{"credential_sinks":[{"allowed_classifications":["authentication_credential"],"allowed_intents":["authenticate"],"credential_slot_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001","delivery_exposure_profile":"trusted_injection","destination_schema":"example.driver.https_destination.v1","trusted_send_profile":{"applicable_delivery_controls":["destination_network_egress","trusted_injection_boundary"],"kind":"trusted_injection","max_credential_bearing_sends":1}},{"allowed_classifications":["signing_material"],"allowed_intents":["sign"],"credential_slot_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4002","delivery_exposure_profile":"material_exposed","destination_schema":"example.driver.signing_destination.v1","trusted_send_profile":{"kind":"not_applicable"}}],"driver_declaration_revision":1,"driver_operation":{"driver":"example_driver","operation":"example_operation","schema_version":"splendor.driver.operation.v1"},"schema_version":"splendor.driver.operation_credential_sinks.v1"}
```

## `DriverOperationRef` Compatibility

The first implementation slice must reuse the existing public
`DriverOperationRef` unchanged. The exact nested declaration form is:

```json
{
  "driver": "example_driver",
  "operation": "example_operation",
  "schema_version": "splendor.driver.operation.v1"
}
```

At the `DriverOperationCredentialSinksV1` checked-construction or
`from_json_slice` boundary, the owner must validate all of the following before
returning the declaration:

- the nested object has exactly the three required non-null string fields shown;
- `schema_version` is exactly `splendor.driver.operation.v1`;
- `driver` and `operation` are each `1..=128` ASCII bytes matching
  `^[a-z][a-z0-9._-]*$`;
- duplicate, missing, unknown, side, operation-semantics, display, alias,
  stringified-JSON, case-folded, and wildcard forms reject.

The owner validation function has this exact semantic signature:

```rust
pub fn validate_driver_operation_ref_v1(
    value: &DriverOperationRef,
) -> Result<(), DriverOperationRefV1ValidationError>;
```

It validates the exact schema constant and both canonical names above. Success
returns `()` only. `DriverOperationRefV1ValidationError` has exactly one
fieldless variant, `Invalid`, displayed and debugged only as
`invalid_driver_operation`; it retains no field, candidate, parser error, or
source chain. The function does not construct or return a validated wrapper,
marker, token, proof, digest, or second identity.

This scoped strict boundary is the required 0.1 compatibility strategy:

- do not make existing `DriverOperationRef` fields private;
- do not change its derived standalone serde behavior or wire bytes;
- do not change existing authority records, equality, ordering, or hashes;
- do not introduce a wrapper, shadow operation type, second operation
  coordinate, or C03 translation;
- do not admit an unvalidated operation ref from this declaration into C03.

The private wire deserializer inside `from_json_slice` must validate the nested
map with a custom visitor, reject side fields before constructing the existing
`DriverOperationRef`, and then call `validate_driver_operation_ref_v1`. It must
not add a public or private retained operation DTO/wrapper as a second type.
Checked Rust construction calls the same function before retaining the existing
type.

Every new privileged Driver Registry or C03 schema, constructor, deserializer,
persistence insertion, lookup/hash projection, authority intersection, and
dispatch boundary that receives a `DriverOperationRef` must use an exact nested
map parser plus `validate_driver_operation_ref_v1`, or consume the exact
canonical operation from an already admitted declaration lookup. A runtime
lookup is not permission to accept a fresh permissive standalone value. C03 must
not duplicate the grammar, retain a proof wrapper, or create another operation
coordinate.

Existing standalone documents with historical schema spellings remain readable
under their existing type behavior, but they are not valid inputs to this new
declaration. A future global hardening of `DriverOperationRef` requires separate
compatibility evidence and an accepted RFC/amendment if it changes public source,
wire, persisted, or hash behavior. C03 must never translate incompatible values
at its boundary.

## Driver-Owned Destination Projection Contract

Each admitted `destination_schema` identifies one immutable, driver-owned closed
projection schema for the exact `(driver_operation, driver_declaration_revision,
credential_slot_id)` tuple. A declaration revision must change if projection
semantics change. Reusing a revision with changed fields, derivation, bounds, or
canonicalization is forbidden.

The declaration contains only the schema identifier. It contains no projection,
destination instance, endpoint, digest, projection function, or approved digest
set.

A conforming destination projection schema must satisfy all global rules below
and must further pin its own complete field table and lexical/semantic rules.

| Projection property | Global v1 rule |
| --- | --- |
| Root | Non-empty JSON object only. |
| Closure | Every object is closed; unknown members and arbitrary maps reject. No `extensions` or metadata field. |
| Field names | Exact schema-declared names, each `1..=64` ASCII bytes matching `^[a-z][a-z0-9_]*$`. |
| Presence | Every field is explicitly required or optional in the owner schema. Missing required fields reject; absent optional fields remain absent. Null is always forbidden. |
| Value kinds | Only schema-declared booleans, integers, strings, closed objects, and bounded arrays. No floating-point number, binary value, tagged arbitrary JSON, or coercion. |
| Integers | Decimal JSON integer token only, with no exponent, fraction, plus sign, or leading zero except the token `0`; each owner field declares a narrower range within `-9007199254740991..=9007199254740991`. |
| Strings | Each owner field declares a narrower non-zero UTF-8 byte bound no greater than 1024 and an exact lexical/enum grammar. Values are compared byte-for-byte; no Unicode normalization or case folding occurs. Secret material is forbidden. |
| Arrays | Length `1..=16`; element type is exact. The owner marks each array as ordered or a semantic set and defines its duplicate rejection and canonical sort key. |
| Nesting | Maximum object/array nesting depth 4, with the root object at depth 1. |
| Members | At most 64 object members across the complete projection. |
| Canonical size | RFC 8785 JCS bytes for the complete projection must be `1..=16384` bytes. |

An owner schema may narrow these bounds or omit value kinds it does not need. It
may not loosen them. Origin, account, service, cluster, database, namespace,
repository, model endpoint, device, device-local service, or cryptographic
resource fields must be typed and bounded by that schema rather than hidden in a
generic label or map.

As required by RFC 0012, a future admitted projection function derives the
complete projection only after action-schema validation and only from validated
action parameters plus trusted registered resource bindings. Request JSON cannot
supply or override the projection, digest, origin, account, cluster, database,
namespace, repository, endpoint, device, service, or projection function.
Missing support, ambiguity, unregistered schema, or disagreement fails before
lease issuance, provider I/O, node control, or adapter/driver entry.

The complete result is the private `ValidatedCredentialDestination` described by
RFC 0012. It is not a new public serialized type in this RFC and is not part of
the first behavior-free implementation slice.

### Deferred projection execution gate

This RFC does not authorize any projection implementation to execute. Projection
execution is blocked until a later separately accepted runtime/conformance
contract defines and proves a Gateway-owned, capability-empty isolation boundary.
That later contract must require the projector to be pure, total, deterministic,
secret-free, non-I/O, non-resolving, and independent of clock, randomness, global
mutable state, and invocation history. It must expose only the validated action
parameters and immutable trusted resource-binding values required by the admitted
schema. Environment variables, keyrings, credentials, network, filesystem,
process creation, dynamic loading, provider clients, nodes, drivers, daemon
services, and host syscalls are unavailable.

The following values are policy maxima, not a complete executable accounting
model. The later Gateway/Sandbox isolation contract must mechanically enforce
them per invocation:

| Projector resource | Maximum |
| --- | ---: |
| CPU time | 10 milliseconds |
| Elapsed time | 25 milliseconds |
| Total working memory, including copied input and output | 1,048,576 bytes |
| Stack | 65,536 bytes |
| Call depth | 32 |
| Canonical projection output | 16,384 bytes, as already required above |

Before executable boundary tests or any projector admission, that later contract
must define a deterministic, platform-independent accounting and conformance
model for CPU clock or deterministic fuel, elapsed time, guest allocator and
runtime overhead, working memory, stack and call depth, every copied input and
output, raw and canonical output, isolation startup and IPC, timeout/kill
initiation, post-kill quiescence, and cleanup. An unavailable counter, ambiguous
charge, unsupported platform guarantee, or uncertain kill denies before lease,
provider access, driver entry, or externally emitted bytes. It never selects a
looser counter, host-dependent tolerance, in-process fallback, alternate
projector, or retry.

The projector may run only in an isolation domain without ambient daemon,
Gateway, driver, or tenant capabilities; in-process invocation in a credentialed
Gateway or driver process is non-conforming. Panic, trap, timeout, CPU, memory,
stack, depth, output, nondeterminism, unavailable isolation, or attempted
capability use returns `invalid_destination_projection` and fails closed. It
causes zero lease issuance and zero provider, node, driver, network, filesystem,
process, or other externally emitted bytes or effects. No fallback projector or
retry under a different implementation is inferred. A later contract may tighten
these ceilings; loosening one requires an accepted amendment to this RFC.

Only after that accounting model is accepted may the later conformance gate make
the numeric ceilings executable and exercise purity, capability denial, every
exact ceiling and ceiling-plus-one, panic/trap, hang/timeout/kill, recursion,
allocation pressure, copied input/output, startup/IPC, and repeated-input
determinism. Static fixtures or test-only projection logic in the behavior-free
slice do not satisfy this gate.

### Deferred revision admission and selection gate

Before any declaration or projector can be registered or selected, a later
accepted Driver Registry contract must enforce all of the following:

- under DRREG-002/ART-004 and Authority-owned registrar scope, authenticate the
  publisher and registrar and verify their authority for the exact operation,
  tenant, and installation scope;
- bind the declaration and projection fingerprint to immutable manifest,
  implementation artifact, and projector artifact digests, trusted conformance
  evidence, installation scope, tenant scope, and current revocation state;
  operation squatting, self-asserted conformance, or projector/implementation
  code swap under unchanged coordinates denies admission and selection;
- admission is keyed by exact canonical `(driver_operation,
  driver_declaration_revision)` and binds canonical declaration bytes plus an
  immutable projection-contract fingerprint;
- an exact duplicate is idempotent, while the same key with changed declaration
  bytes or projection fingerprint conflicts and cannot overwrite;
- lifecycle state distinguishes at least `active`, `stale`, and `revoked`; only
  the exact `active` revision may enter a new live normalization, projection, or
  lease path;
- stale and revoked revisions remain readable for historical replay/explanation
  but deny live selection and use;
- Driver Registry lifecycle transitions use owner-controlled CAS and a monotonic
  lifecycle generation; an `active -> stale|revoked` transition fences every
  older generation, and a revoked revision cannot be reactivated or overwritten
  under the same revision;
- every live path pins the explicit declaration revision and observed lifecycle
  generation through normalization, projection, lease, final permit, delivery,
  and use;
- the later Registry/C03/Gateway contracts define CAS race winners and recheck
  the exact revision/generation as active immediately before provider access or
  each credential-bearing use. No old-generation use may begin after a stale or
  revoked transition commits; already-issued leases are denied or fenced from
  further use and receive explicit historical/cleanup handling; and
- no `latest`, newest-number, alias, last-writer-wins, fallback, or presence-only
  inference selects or revives a revision.

This gate is a blocking prerequisite, not lifecycle behavior implemented by this
RFC's first slice.

## `DriverCredentialDestinationDigest`

`DriverCredentialDestinationDigest` is a closed value type with this exact wire
form:

```text
blake3:<64 lowercase hexadecimal characters>
```

The wire string is exactly 71 ASCII bytes. Uppercase hex, omitted prefix,
alternate algorithm, wrong width, whitespace, null, and non-string forms reject.
The type has no `Default`, aliases, algorithm field, or unchecked string
constructor. Its sole parse error is
`DriverCredentialDestinationDigestError::InvalidFormat`, displayed as
`invalid_driver_credential_destination_digest`, without candidate reflection.

For a validated projection `P` and its exact `destination_schema` string `S`,
the digest domain and algorithm are exactly:

```text
canonical_projection = RFC8785_JCS(P)
digest_input = UTF8(S) || 0x00 || canonical_projection
digest_bytes = BLAKE3-256(digest_input)
wire = "blake3:" || lowercase_hex(digest_bytes)
```

`BLAKE3-256` means the unkeyed BLAKE3 hash with its standard 32-byte output. No
length prefix, newline, BOM, surrounding JSON string, declaration bytes,
operation, revision, slot, exposure profile, trusted-send profile, credential,
or endpoint side channel is added to `digest_input`. The schema plus zero-byte
prefix is the domain separator required by RFC 0012's prefix/JCS/BLAKE3 rule.

For example, this complete validated projection:

```json
{"account":"acct_001","origin":"https://api.example.test:443","service":"billing"}
```

under `example.driver.https_destination.v1` hashes the ASCII schema bytes, one
zero byte, and exactly the single-line JCS bytes shown. The implementation
fixture must pin the resulting 32 bytes and 71-byte wire form rather than rely on
this RFC text as executable evidence.

The digest is a destination equality binding, not a signature, MAC, credential,
permission, or secrecy mechanism. The declaration never contains one. C03 owns
approved digest sets and the actual safe binding/authorization comparison.

The digest is never a standalone authority, cache, lookup, deduplication, or
approval key. The tuple `(driver_operation, driver_declaration_revision,
credential_slot_id, destination_schema, destination_digest,
delivery_exposure_profile, trusted_send_profile)` is only the complete
destination-binding subkey. It is never a complete authorization or cache key.
The same digest under a different operation, revision, slot, exposure profile,
or trusted-send profile does not authorize and must deny before lease or effect.

After the separately accepted C03 amendment exists, every authorizing comparison
and authorization-sensitive C03 cache must bind that destination subkey together
with the exact tenant, `SecretRefId` and positive ref revision, classification,
intent, purpose, current authority/policy/revocation generations, execution
audience, and lease identity/revision/generation coordinates, plus any stricter
caller or work-order binding required by RFC 0012. Missing, stale, cross-tenant,
cross-ref, cross-classification, cross-intent, cross-purpose, cross-generation,
wrong-audience, or wrong-lease reuse denies. #331 cannot make this representable
with a shadow field, side table, or broker translation.

Destination digests may appear only in access-controlled C03 binding records and
restricted trace/evidence records that already carry the complete destination
subkey and applicable C03 authority coordinates. Because a closed projection can
be low entropy, a digest must not appear in generic or public logs, metrics,
errors, trace/evidence projections, discovery responses, unauthorized responses,
or digest-only caches. It must not be used as a redaction substitute or exposed
to confirm candidate destinations.

## Untrusted Declaration Ingress Budget

Every untrusted byte ingress for
`splendor.driver.operation_credential_sinks.v1` must apply this exact budget
before generic JSON decoding or declaration construction:

| Resource | Exact v1 maximum |
| --- | ---: |
| Raw encoded JSON body | 32,768 bytes |
| Decoder container nesting depth | 32, with the root container at depth 1 |
| Decoder tokens | 1,024 |
| Object members across the document | 192 |
| Array elements across the document | 384 |
| Decoded UTF-8 bytes in any member-name or string-value token | 256 |

A decoder token is one object/array open, one object/array close, one member
name, or one scalar value; commas and colons are not separate tokens. Object
member and array-element totals count duplicates and unknown structures before
they are rejected. String limits apply after JSON escape decoding. Malformed
UTF-8, invalid escapes, integer-token overflow, and every budget excess return
only `invalid_contract_shape`.

The limits cover the legal semantic maximum without relying on attacker input.
With 16 trusted-injection sinks, all five classifications, all six intents, the
longest eight imported controls including `trusted_injection_boundary`, 128-byte
driver/operation/destination-schema values, and the maximum revision, the exact
legal maxima are depth 5, 706 decoder tokens, 151 object members, 320 array
elements, and 13,478 compact canonical bytes. The 32-KiB wire ceiling therefore
also permits bounded whitespace or escape expansion but does not make unlimited
alternate encodings valid. The first implementation fixture must independently
construct this maximum declaration and pin all five calculated values.

The owner parser has this exact semantic signature:

```rust
pub fn from_json_slice(
    input: &[u8],
) -> Result<DriverOperationCredentialSinksV1, DriverCredentialSinkContractError>;
```

It must reject an input length above 32,768 before tokenization and run one
bounded preflight scanner before strict private-wire serde construction. The
final validated type has `Serialize` but no `Deserialize` implementation; generic
`serde_json::from_slice::<DriverOperationCredentialSinksV1>` is therefore not an
available bypass. A streaming body or reader layer must read at most 32,769
bytes, reject as soon as the extra byte is observed, and must not pass an
over-bound prefix to a generic decoder. The same token, depth, member, element,
and string limits apply in every daemon, registry, fixture, import, and
persistence-rehydration path; no endpoint may substitute a larger body-parser
default or deserialize a private wire input outside `from_json_slice`.

Rejected raw bytes and decoded candidates are ephemeral. They must not be
persisted, traced, measured as labeled metric values, body/debug logged, attached
to audit records, included in public errors, or retained in an error source
chain. Parsers drop their bounded buffers on failure. `Display`, `Debug`, serde
custom errors, transport mappings, metrics, and audit summaries expose only the
fixed code; no line, column, key, value, prefix, body, or nested parser text is
public.

## Validation Precedence

Validation is deterministic and fail closed. Implementations must not return a
later, more specific result after an earlier stage fails.

### Declaration validation

| Order | Check | Fixed failure code |
| ---: | --- | --- |
| 1 | For byte ingress, enforce every resource cap above; then require valid JSON, no duplicate member names at any depth, and a top-level object | `invalid_contract_shape` |
| 2 | Reject top-level members outside the exact four-name vocabulary; deliberately defer every required field's absence, null, and kind to its named stage below | `invalid_contract_shape` |
| 3 | Declaration `schema_version` is present, non-null, a string, and the exact constant | `invalid_schema_version` |
| 4 | Declaration-boundary `DriverOperationRef` is present, non-null, an object with its exact fields/string kinds, and passes `validate_driver_operation_ref_v1` | `invalid_driver_operation` |
| 5 | `driver_declaration_revision` is present, non-null, and an exact decimal integer token within its bound | `invalid_declaration_revision` |
| 6 | `credential_sinks` is present, non-null, an array, and within cardinality | `invalid_contract_shape`, `empty_credential_sinks`, or `too_many_credential_sinks` respectively |
| 7 | Each entry in original input order using the exact sub-order below | Entry-specific code below |
| 8 | Duplicate slot IDs across otherwise valid entries | `duplicate_credential_slot` |
| 9 | Sort all validated semantic sets using the canonical rules | Cannot fail; a duplicate was rejected earlier |

Entry sub-order and failures are exact:

| Order | Check | Fixed failure code |
| ---: | --- | --- |
| 7.0 | Entry is an object and has no member outside the exact six-name vocabulary; deliberately defer every recognized field's absence, null, and kind to its named stage | `invalid_contract_shape` |
| 7.1 | Slot is present/non-null and satisfies the strict UUID grammar and non-nil rule | `invalid_credential_slot` |
| 7.2 | Classifications are present/non-null and satisfy array kind, cardinality, imported values, and uniqueness | `invalid_classification_set` |
| 7.3 | Intents are present/non-null and satisfy array kind, cardinality, imported values, and uniqueness | `invalid_intent_set` |
| 7.4 | Destination schema is present/non-null and satisfies string kind, ASCII length, and grammar | `invalid_destination_schema` |
| 7.5 | `trusted_send_profile` missing or null | `missing_trusted_send_profile` |
| 7.6 | Exposure is present/non-null and an exact string enum; profile is an object with a present/non-null exact string `kind`; exposure and kind pair correctly | `exposure_profile_mismatch` |
| 7.7 | For `trusted_injection`, reject members outside `kind`, `max_credential_bearing_sends`, and `applicable_delivery_controls`; validate send-limit presence/null/kind/range while deliberately deferring control-list presence/null/content to 7.8 | `invalid_contract_shape` for extra members; otherwise `invalid_send_limit` |
| 7.8 | `trusted_injection` controls are present/non-null and satisfy array kind, cardinality, imported values, and uniqueness | `invalid_control_set` |
| 7.9 | Required control membership | `trusted_injection_boundary_required` |
| 7.10 | `not_applicable` has no member other than `kind` | `not_applicable_payload_forbidden` |

A wrong field-specific scalar, object, or array-element kind is assigned at that
field's stated step: schema uses `invalid_schema_version`; operation uses
`invalid_driver_operation`; revision uses `invalid_declaration_revision`; slot
uses `invalid_credential_slot`; classification and intent use their set codes;
destination schema uses `invalid_destination_schema`; exposure/profile uses
`exposure_profile_mismatch`; send limit uses `invalid_send_limit`; and controls
use `invalid_control_set`. All entries are semantically checked in input order
before the cross-entry duplicate-slot check. Set duplicates reject during their
entry check, before sorting.

### Destination projection and digest validation

This precedence specifies future conformance and C03 consumption. It does not
add projection execution to the first implementation slice.

| Order | Check | Fixed failure code |
| ---: | --- | --- |
| 1 | Exact admitted operation, explicit active declaration revision, slot, destination schema, and immutable projection fingerprint exist; stale/revoked/presence-only/latest resolution denies | `invalid_destination_projection` |
| 2 | Action schema was validated and only trusted registered resource bindings are used | `invalid_destination_projection` |
| 3 | Projection root, closure, fields, values, per-field bounds, array semantics, global depth/member/size bounds | `invalid_destination_projection` |
| 4 | RFC 8785 JCS succeeds on the already validated projection | `invalid_destination_projection` |
| 5 | Supplied binding digest has exact `DriverCredentialDestinationDigest` form, equals the recomputed digest, and is compared only inside the complete destination-binding subkey and, after the C03 amendment, its full current authorization coordinates | `destination_digest_mismatch` |

Projection errors collapse to one non-reflecting code. They must not reveal the
candidate destination, registered destination set, account, endpoint, resource,
or which trusted binding disagreed.

## Fixed Error Taxonomy

`DriverCredentialSinkContractErrorCode` is closed to these exact snake-case
values:

| Code | Meaning |
| --- | --- |
| `invalid_contract_shape` | Ingress-budget, malformed JSON/UTF-8, duplicate-member, non-object, unknown/extra-member, or container-shape failure assigned above. |
| `invalid_schema_version` | Declaration schema is absent, null, non-string, or not the exact constant. |
| `invalid_driver_operation` | Nested operation is absent, null, wrong-shaped, or fails owner canonical-v1 validation. |
| `invalid_declaration_revision` | Revision is absent, null, not an exact integer token, or outside the positive safe-integer range. |
| `invalid_credential_slot` | Slot is absent, null, wrong-typed, malformed, noncanonical, or nil. |
| `empty_credential_sinks` | No sink entry is present. |
| `too_many_credential_sinks` | More than 16 entries are present. |
| `duplicate_credential_slot` | Two otherwise valid entries use the same slot. |
| `invalid_classification_set` | Classification set is absent, null, wrong-typed, empty, over-bound, duplicate, or contains an unknown value. |
| `invalid_intent_set` | Intent set is absent, null, wrong-typed, empty, over-bound, duplicate, or contains an unknown value. |
| `invalid_destination_schema` | Destination schema is absent, null, wrong-typed, non-ASCII, out of bounds, unversioned, or lexically invalid. |
| `missing_trusted_send_profile` | Required profile is absent or null. |
| `exposure_profile_mismatch` | Exposure or profile kind is absent, null, wrong-typed, unknown, or the pair is incompatible. |
| `invalid_send_limit` | Trusted-injection send limit is absent, null, non-integer, zero, or greater than eight. |
| `invalid_control_set` | Trusted-injection controls are absent, null, wrong-typed, empty, over-bound, duplicate, or unknown. |
| `trusted_injection_boundary_required` | The valid control set omits `trusted_injection_boundary`. |
| `not_applicable_payload_forbidden` | A not-applicable profile contains any payload or extra member. |
| `invalid_destination_projection` | Registered projection support, trusted derivation, closed shape, bounds, or JCS validation failed. |
| `destination_digest_mismatch` | Digest form or exact recomputed destination binding does not match. |

`DriverCredentialSinkContractError` contains exactly:

- `code: DriverCredentialSinkContractErrorCode`.

Its serialized form, when required, is the exact one-member object
`{"code":"<snake_case_code>"}`. There is no sink index, field identifier,
line/column, arbitrary message, or optional context. Input-order evaluation and
the precedence tables determine the code, but the failing entry is never exposed.

The error must not include an arbitrary message, rejected value, unknown key,
operation candidate, slot candidate, projection, destination, expected digest,
actual digest, provider request/error, credential, or nested parser error that
reflects input. The typed error's `Display`, `Debug`, semantic serde custom-message
component, and transport mapping expose only the fixed code. `Error::source` is
absent. Generated-language mappings preserve the same one-code shape.

## Security Properties

- The declaration contains no secret bytes, secret-derived hash, provider
  credential, provider request, raw provider error, locator, endpoint instance,
  destination instance, digest allowlist, runtime handle, permit, token, or
  authority decision.
- A slot ID is an index into later typed delivery, not a bearer capability.
- A declaration, projection schema, or destination digest is never authority.
- Trusted injection is a declared capability and send bound, not evidence that a
  runtime boundary or control was applied. C03's exact control attestation and
  Gateway verifier path remain mandatory.
- Material exposure does not become safe because it is declared. RFC 0012's
  NODE/SBX isolation, suppression, cleanup, containment, and publication rules
  remain mandatory and outside this RFC.
- Destination projection uses validated parameters and trusted registered
  bindings only. Caller-provided destination overrides and alternate projection
  functions are forbidden.
- Untrusted declaration bytes are capped and scanned before generic decoding;
  rejected bodies, values, parser details, and source chains are never retained
  or exported.
- Projection execution remains prohibited until the separately accepted
  capability-empty isolation/resource contract and conformance gate pass. A
  projector cannot use ambient credentials or become a second effect path.
- BLAKE3 provides deterministic equality/integrity binding, not authenticity or
  secrecy. Low-entropy destination digests can be enumeration-sensitive and
  must not be treated as a redaction substitute or enter generic/public
  observability. Digest-only comparison or caching is forbidden; the complete
  operation/revision/slot/schema/digest/exposure/profile destination subkey and
  all current C03 tenant/ref/authority/audience/lease coordinates are required.
- Only an explicitly active, exact declaration revision may enter a future live
  path. Stale, revoked, ambiguous, inferred-latest, overwritten, lifecycle-
  generation-mismatched, or final-use-raced state denies and fences outstanding
  leases from further use.
- Unknown, ambiguous, unsupported, over-bound, or unavailable validation state
  denies before lease issuance, provider I/O, node control, or driver entry.
- No side effect is introduced. Future credential use remains behind the current
  Action Gateway and every required verifier.

## Compatibility, Migration, and Rollback

This contract is additive and experimental. It does not modify a stable 0.1 wire
schema. The first implementation must preserve:

- standalone `DriverOperationRef` source construction, serde acceptance, wire
  bytes, equality, ordering, Authority use, and persisted/hash behavior;
- stable 0.1 `Action`, `ActionCandidate`, `ActionRequest`, `ActionOutcome`, trace,
  state, replay, work-order, adapter, and Gateway behavior;
- all existing Rust/Python/TypeScript/OpenAPI surfaces unless a later accepted
  implementation explicitly versions them.

Migration into the first implementation is opt-in: a driver operation adopts
the new declaration only by constructing the new exact v1 object. Historical
adapter registrations and standalone operation refs are not auto-converted,
wrapped, translated, or inferred. No existing manifest exists to migrate.

Once a declaration revision is admitted or referenced by a C03 record, changing
its slots, classifications, intents, destination schema, projection semantics,
exposure profile, or trusted-send profile requires a new positive
`driver_declaration_revision`. A changed schema shape requires a new schema
version or accepted RFC amendment; it must not reuse v1 bytes with changed
meaning.

The required C03 amendment owns migration of revision-less RFC 0012 credential-
authorization records. #331 neither rewrites nor annotates them. Such records may
remain readable for historical audit/replay, but live migration or use requires
proof of the exact declaration revision and a fresh `SecretRef` revision; absent
that proof they deny without latest/active inference or compatibility fallback.

Rollback may remove the additive experimental module, exports, and fixtures only
before they appear in a release and before any external or released source,
wire, generated, persisted, or runtime consumer exists. Once any such consumer
exists, the symbols and exact bytes must remain readable and may only be
deprecated under an explicit compatible migration. Persisted v1 declarations or
C03 bindings require permanent historical read/deny support unless an accepted
migration preserves their exact coordinate and authority history. Rollback must
not reinterpret bytes, break a released downstream crate, silently fall back to
an old adapter path, or delete authority history.

## Implementation and Test Sequence

Acceptance authorizes implementation only in this dependency-safe order:

1. Land a separate #245 behavior-free prerequisite that implements RFC 0012's
   exact C03-owned `SecretDeliveryControlKind`, its closed serde, ordering, and
   negative tests. It adds no broker or delivery behavior.
2. Add only `crates/splendor-types/src/driver.rs` and root exports for the public
   contract surface listed above. Import the existing `DriverOperationRef` and
   C03-owned enums. Do not edit `DriverOperationRef` or add a shadow type.
3. Add the reusable unit-returning `validate_driver_operation_ref_v1`, bounded
   preflight scanner and `from_json_slice`, strict private serde inputs, custom
   nested-operation visitor, checked constructors, exact ordinary canonical
   `Serialize`, canonical getters, and code-only non-reflecting errors. The final
   validated declaration does not implement `Deserialize`; private wire inputs
   exist only inside `from_json_slice`. No operation wrapper/proof, registry,
   projection validator or projector, Gateway, adapter, daemon, SDK, generated,
   provider, or I/O code belongs in this slice.
4. Add focused unit tests plus one canonical fixture under
   `crates/splendor-types/tests/fixtures/driver/`. Add a narrow owner reference
   document and user-visible changelog note that identify the contract as
   additive experimental and behavior-free.
5. Run independent architecture/compatibility and security review. Prove stable
   0.1 and current C03 tests remain unchanged. Do not claim `G07`, `G08`, issue
   closure, or feature activation.
6. After acceptance and availability of the #331 nominal slot export, a
   separately owned C03 behavior-free slice may add only the
   `SecretUseRequirement` slot grammar. It grants no authority and does not
   construct or consume `SecretRef.allowed_credential_bindings`.
7. Before C03 implements or consumes credential authorization, approved digest
   sets, `SecretRef.allowed_credential_bindings`, authority intersection, leases,
   caches, or live credential use, the separately accepted C03-owned RFC 0012
   amendment or versioned successor above must add the positive declaration
   revision, fresh-ref-revision rule, historical migration/read-deny behavior,
   and cross-revision fixtures. No #331 shadow field, hidden side table, broker
   translation, inferred revision, or weaker comparison can satisfy this gate.
8. A later separately accepted concrete projection-schema/admission contract must
   define a production pure schema validator, immutable projection fingerprint,
   authenticated publisher/registrar and artifact/code binding, and fenced
   active/stale/revoked revision admission before the full projection denial
   matrix can run. Test-only validation is not evidence.
9. Projection execution remains blocked until the separate accepted
   capability-empty isolation/resource contract defines the complete accounting
   model and its conformance gate passes. Neither acceptance nor implementation
   of this RFC authorizes projector code.
10. Only after the C03 amendment and every applicable deferred gate may a later
    separately owned C03 slice import these accepted exports to complete
    credential authorization and destination binding. Gateway live ingress,
    DGW-003 handles, providers, nodes, and gold remain later work.

The contract test matrix must include:

| Area | Required fixtures/assertions |
| --- | --- |
| Slot ID | Exact valid round trip and ordering; uppercase, compact, braced, URN, padded, malformed, nil, null, scalar/object/array denial; nominal compile-time non-interchangeability; no candidate reflection. |
| Declaration shape | Exact positive round trip; missing, duplicate member, unknown, null, alias, default, map, metadata, extension, wildcard, credential, endpoint, destination override, and extra side-field denial. |
| Untrusted ingress | Pin the exact 13,478-byte legal-maximum fixture and its 5/706/151/320 depth/token/member/element counts; test 32,768 bytes and 32,769 denial, whitespace/escape bombs, depth 32/33, tokens 1,024/1,025, members 192/193, elements 384/385, strings 256/257, malformed UTF-8, duplicate bombs, and canary absence from `Display`, `Debug`, sources, logs, traces, metrics, audit, and persistence. Compile/API assertions prove the final validated declaration implements `Serialize`, does not implement `Deserialize`, exposes no public generic deserialization route, and sends every imported/rehydrated byte path through `from_json_slice`. Later ingress surfaces repeat retention tests before activation. |
| Operation compatibility | Exact nested three-field object accepted; every bad schema/name/side-field rejected by the nested parser and reusable validator at every new privileged owner boundary; validator returns unit only; standalone historical `DriverOperationRef` source/serde/bytes/hashes unchanged; no proof/wrapper identity exists. |
| Bounds | Revision 1/max and zero/max+1; sinks 1/16 and 0/17; classification 1/5 and 0/6; intent 1/6 and 0/7; destination schema byte/grammar boundaries. |
| Sets | Every representative permutation canonicalizes identically; duplicate slot/classification/intent/control rejects before sorting. |
| Profiles | Both exact positive forms; send limits 1..8; zero/nine; control counts 1..8; duplicate/unknown controls; missing boundary; missing/null/mismatched profile; payload on not-applicable. |
| Canonical declaration | Every semantic-set permutation gives identical ordinary compact `serde_json::to_vec` bytes; the complete example equals the pinned JCS fixture exactly; no alternate canonical API diverges. |
| Registry admission | Deferred to DRREG-002/ART-004 and Authority owner contracts. Wrong publisher/registrar authority, tenant or installation scope, unsigned/tampered/revoked manifest or implementation/projector artifact, untrusted/self-attested conformance, operation squatting, and projector/code swap under unchanged coordinates all deny before selection. |
| Projection contract | Deferred to the first separately accepted concrete projection-schema/admission slice. It must test production pure validation for unknown/null/type/depth/member/array/string/integer/JCS-size failures and trusted-vs-request source distinction before registration. No test-only validator satisfies this row. |
| Projector isolation | Deferred blocking runtime gate. Before exact boundaries are executable, pin the platform-independent clock/fuel, allocator/runtime/stack, copied input/output, raw/canonical output, startup/IPC, timeout/kill/quiescence, and cleanup accounting model. Then test no host capabilities or ambient authority, every exact ceiling and plus one, panic/trap/hang/nondeterminism, zero external bytes/effects, uncertainty denial, and no fallback before first invocation. |
| Revision lifecycle | Deferred blocking registry/C03/Gateway gate. Exact duplicate is idempotent; changed declaration/fingerprint/artifact conflicts; lifecycle generation is monotonic and CAS-fenced; stale/revoked deny; historical read is non-live; no inferred latest or last-writer behavior; races at normalization/projection/lease/final permit/provider access/use have one defined winner; final-use active recheck and outstanding-lease fencing prevent old-generation use. |
| C03 revision authorization | Deferred blocking C03 amendment gate. Positive declaration revision is present in the C03 authorization coordinate; a changed declaration revision requires a fresh `SecretRef` revision and authority; revision-less history is readable but live-denied unless exactly provable; same-revision positive and cross-revision denial canonical/migration fixtures are pinned. |
| Digest | First slice pins exact domain bytes, zero separator, JCS bytes, independently reproduced 32-byte BLAKE3 golden, lowercase wire form, wrong prefix/case/width/algorithm, changed schema, and changed projection. Later C03/Gateway tests prove cross-operation/revision/slot/exposure/profile reuse denies; the destination subkey cannot serve as the full cache key; cross-tenant/ref/classification/intent/purpose/authority-policy-revocation-generation/audience/lease reuse denies; digest-only lookup cannot allow; and restricted visibility excludes generic/public logs, metrics, errors, traces, discovery, and unauthorized responses. |
| Errors | Every reachable declaration code and precedence conflict; exact code-only shape; missing profile and missing controls each have one fixed stage; no index, field, line/column, rejected/expected value, destination, digest, parser source, or provider text. Projection/runtime codes are exercised only when their production seams exist. |
| Compatibility | `cargo test -p splendor-types`, relevant `splendor-authority` tests, stable baseline/conformance, dependency policy, and unchanged stable bytes/hashes. |

The first behavior-free slice runs `Slot ID`, `Declaration shape`, `Untrusted
ingress`, `Operation compatibility`, `Bounds`, `Sets`, `Profiles`, `Canonical
declaration`, the first-slice part of `Digest`, `Errors`, and `Compatibility`.
It uses one static closed projection only to pin canonical digest-domain bytes
and an independently reproduced golden. `Projection contract`, `Projector
isolation`, `Registry admission`, `Revision lifecycle`, `C03 revision
authorization`, and live digest authorization or visibility enforcement remain
explicit later blocking gates. The behavior-free slice must not add test-only
production substitutes or claim those rows.

## Trace, State, Replay, and Runtime Impact

The first implementation is behavior-free:

| Surface | Impact |
| --- | --- |
| Gateway/adapter | None. No registration, invocation, verifier, or effect path changes. |
| Trace/evidence | None. Parsing or constructing a value emits no event. |
| State/store | None. No state node, head, record, table, or migration is added. |
| Replay | Values may be inspected or round-tripped only. No projection, provider, driver, network, filesystem, node, or target is invoked. |
| Daemon/API/SDK/generated | None. No endpoint or generated surface is added. |
| Gold/conformance status | `G07` and `G08` remain `specified_not_implemented` / `not_exercised`. |

Future C03 runtime adoption may begin only after the separately accepted
revision-bearing C03 amendment and must follow RFC 0012's trace, state, replay,
pre-persistence, publication, and no-repeat-effect rules. This RFC creates no
alternate semantics for those surfaces.

## Non-Goals

This RFC does not define or implement:

- the full `DriverManifest`, full `DriverOperation`, or full `DRREG-001`;
- registry service, registration, installation, admission, lookup, compatibility
  resolution, selection, lifecycle, revocation, capability API, or conformance
  service;
- projection execution, live destination binding, action normalization,
  credential ingress, provider access, node delivery, cleanup, or containment;
- the C03-owned RFC 0012 amendment/versioned successor, credential authorization,
  approved destination digest sets, `SecretRef` records/leases, or any C03
  lifecycle record; a separately owned behavior-free `SecretUseRequirement` slot
  grammar may proceed after acceptance but is not implemented by #331;
- `SecretDeliveryControlKind` in the Driver Registry; it remains the explicit
  C03-owned #245 prerequisite;
- a #331-owned C03 declaration-revision field, authorization side table, broker
  translation, revision inference, or compatibility fallback around the required
  C03 amendment;
- a wrapper or shadow operation type, changed standalone `DriverOperationRef`,
  broker translation, alias migration, or C03-owned operation coordinate;
- arbitrary maps, extensions, wildcard destinations, provider credentials,
  mutable endpoints, request destination overrides, raw provider requests/errors,
  secret material, material-derived hashes, permits, or runtime handles;
- DGW-003 invocation handles, a new Gateway path, verifier changes, adapter
  behavior, side effects, daemon endpoints, SDKs, generated contracts, Python,
  TypeScript, or OpenAPI;
- trace events, state records, persistence migrations, replay execution, feature
  activation, issue closure, RFC acceptance, PR creation, or release changes;
- `G07`, `G08`, or any other gold/conformance pass claim.

## Acceptance Gate

This RFC moved from Proposed only after:

- architecture/compatibility review confirms one-owner direction and standalone
  `DriverOperationRef` preservation, reusable owner validation, and no wrapper,
  proof identity, C03 translation, shadow authorization field, or side table;
- security review confirms the declaration is non-authorizing, contains no
  secret/destination authority, bounds untrusted ingress, blocks projector
  execution on the later isolation/accounting gate, requires final-use revision
  fencing and publisher/artifact binding in their later owner contracts, and
  preserves all RFC 0012 denial boundaries;
- contract review confirms every field, bound, enum import, set/order rule,
  canonical byte rule, digest domain, validation precedence, error, migration,
  rollback, revision/digest rule, test, and non-goal is internally consistent;
- reviewers confirm the separate C03-owned `SecretDeliveryControlKind`
  prerequisite; and
- reviewers confirm that complete C03 credential authorization and `SecretRef`
  consumption remain blocked on a separately accepted C03-owned revision-bearing
  RFC 0012 amendment/versioned successor with fresh-ref-revision,
  migration/read-deny, and cross-revision fixture rules, while no implementation,
  gold, or issue-completion claim is made.

Acceptance would authorize only the dependency-safe first behavior-free #331
slice and allow the separately owned non-authorizing `SecretUseRequirement` slot
grammar described above. It would not authorize C03 credential authorization or
`SecretRef` consumption, projection admission or execution, runtime behavior, or
completion of any task or gold case.
