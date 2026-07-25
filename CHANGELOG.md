# Changelog

## Unreleased — 0.2/v2 foundation partial evidence

### Added

- **status/incomplete:** added a Gateway-owned, always-on, bounded
  pre-persistence raw-credential ingress denial across direct
  `VerifiedActionGateway` calls, kernel policy candidates, daemon configured-run
  admission, direct/physical action handlers, and Gateway policy/trace-durability
  wrappers. Normalized credential coordinates, nested map/list content,
  URL/userinfo/path/query, quoted/spaced connection/environment assignments,
  structured cloud/device aliases, closed selector-plus-material coordinate
  objects for credential aliases (while preserving generic/non-ASCII labels),
  decoded colon-bearing Basic, short Bearer, provider-specific realistically
  bounded token forms, PEM, embedded/encoded generic secret refs,
  credential-bearing object keys, raw receipt metadata, physical/operator
  envelope strings, and complete device-profile envelopes are covered. URL/form
  parsing handles once-decoded URL authorities, paths, bare query names and
  values, bounded nested URLs, standalone form bodies, encoded non-URL spans
  adjacent to URLs, valid token prefixes before alphabet-overlapping punctuation,
  structurally separated numeric host ports, and plus-as-space values with one
  decode per layer;
  ordinary literal-percent forms, embedded URLs, generic schema descriptors, and
  provider-like resource names remain accepted. Every inspected raw or decoded
  string rejects BOM and ambiguous NUL/control encodings. Every top-level numeric
  `params.bytes` body additionally
  requires unambiguous UTF-8 regardless of action label or adapter routing;
  UTF-16, invalid UTF-8, malformed parsed coordinates, and
  depth/node/string/byte overflow all return only
  `raw_credential_input_denied`. Denied traces retain action identity/order but
  use one constant action projection; raw input is excluded from constraints,
  delegated authority, request fingerprints/idempotency, action traces, physical
  safety evidence, device profile/status/audit records, operator records,
  feedback, adapters/simulators, and
  inspect-only replay. Complete-token grammar preserves ordinary Basic prose and
  provider-looking resource paths. Existing wire schemas, trace variants, and
  `ActionStatus` remain unchanged. Ordinary non-byte and bounded UTF-8 byte
  actions remain compatible; generic top-level binary/ambiguous `params.bytes`
  now fail closed until an owner-versioned ingress profile exists.
  This is only a denial slice of `SECR-004`/`SECR-006`: it adds no typed secret
  delivery, broker/provider Gateway session, operation-specific
  `CredentialIngressProfile`, exhaustive entropy/encoded/split detection,
  repository scanner, quarantine/incident workflow, issue closure, or gold pass.
- **status/incomplete:** added the first process-local C03 Secret Broker owner
  slice for `SECR-001`, with bounded `SECR-003` renewal/revocation and
  `SECR-005` provider-port progress. Additive ref-safe contracts are exported
  only under `ProcessLocal*` names and bind exact tenant, principal, workload,
  Driver declaration/slot/destination/trusted-send profile, placement, audience,
  ref/provider version, intent, and purpose coordinates. The incomplete broker
  lifecycle, constructors, handles/claims, clocks/IDs, limits, mutation errors,
  inspection, and replay are crate-private; there is no callable production
  lease API or complete live permit. The internal one-tenant prototype performs
  current authenticated Authority/capability/revocation checks before
  SecretRef/current-Driver, command, or handle lookup; derives command and
  request partitions only from trusted tenant/principal/workload plus command
  kind/nominal ID; and keeps placement/binding coordinates in explicit semantic
  equality while excluding only lease-request `requested_at`. Historical
  non-authorizing receipts are integrity-bound to their exact command/event and
  retain/recreate no capability nonce. Fixed provider audit/health and memory
  provider `Debug` output exposes no provider/ref/tenant/version/digest/time
  coordinates. A live opaque capability is available only to the first
  successful application.
  Hidden hit/miss/conflict/cross-scope cases share `secret_not_available`.
  `environment_variable` is never selected, renewal uses broker-observed current
  time as its immediate cutover, and every valid clock observation latches a
  monotonic high-water across later failures. Production compilation uses only
  fixed local system clock/random-ID sources; custom synchronous sources and
  narrowed limits are test-only. Bounded owner-local evidence and lifecycle
  state otherwise commit atomically without an external callback, and elapsed
  leases do not retain active-admission capacity. Provider fetch results validate
  an exact request/audit digest, retain bytes only in zeroizing
  request-borrowed `!Send`/`!Sync` storage, and expose no material escape.
  `splendor-adapter-secrets-memory` is `publish = false`, requires the explicit
  `memory-secret-provider` feature outside tests, enforces finite exact-version
  storage, and erases rotated/revoked entries. This slice remains process-local
  and non-restart-durable; it does not invoke a provider from the broker, return
  material, add Gateway/node delivery, persistence, daemon/API/SDK/generated
  surfaces, production providers, issue closure, or gold evidence. Its reduced
  records use explicit `*.local.v1` schemas rather than claiming RFC 0012's
  complete durable wire records; `G07` and `G08` remain `not_exercised`.
- **status/incomplete:** added RFC 0018 Slice 1A's additive experimental,
  behavior-free C03 foundation lexical Rust primitives and the sole accepted
  `RegistryDeclarationDigest` construction over unchanged RFC 0013 declaration
  bytes. Exact schema/label/code, UTC microsecond timestamp, safe-integer,
  code-only error, and redacted digest contracts use checked construction,
  strict parsing, and deterministic serialization without generic
  deserialization or normalization. This partial `FND-001` slice adds no
  reserved IDs/enums/records, budgets, attestations, other digests, generated
  surfaces, owner/runtime/persistence behavior, issue closure, or gold evidence;
  `G00` remains `not_exercised`, and existing 0.1 and RFC 0012–0014 behavior and
  bytes remain unchanged.
- **status/incomplete:** added RFC 0014's additive behavior-free
  `SecretCredentialAuthorizationV2` and `SecretRefV2` Rust contracts in
  `splendor-types`, with checked construction, deterministic canonical
  serialization, fixed non-reflecting errors, strict duplicate-aware bounded
  byte parsers, an exact pure Driver declaration/classification/intent
  comparison, and closed historical-v1 read/deny views with stable source-entry
  ordinals and domain-separated digests. Canonical minimal, accepted historical,
  and independently generated legal-maximum fixtures pin set ordering, exact
  bytes, and ingress bounds. Validated v2 and historical records implement
  `Serialize` but not generic `Deserialize`; comparison and historical-denial
  results are non-serializable. This slice grants no authority and adds no
  lookup, current-head selection, migration execution, persistence, cache,
  provider, lease, material delivery, Gateway/runtime behavior,
  daemon/API/SDK/generated surface, issue closure, feature activation, or gold
  evidence. RFC 0012 v1 bytes remain historical-only, and RFC 0013 Driver-owned
  operation, slot, declaration, trusted-send, and digest contracts remain
  unchanged.
- **status/incomplete:** added the additive experimental, behavior-free
  `SecretUseRequirement` v1 Rust contract in `splendor-types`. Private fields,
  checked construction, a sole duplicate-aware bounded `from_json_slice` byte
  ingress, fixed non-reflecting source-free error codes, and a canonical fixture
  enforce the exact schema, opaque `SecretRefId`, imported
  Driver Registry-owned `SecretCredentialSlotId`, closed intent/purpose, one-to-
  five unique ordered delivery preferences, positive safe-JSON-integer duration
  and use limits, and `required: true`. The validated type implements `Serialize`
  but not public generic `Deserialize`; its exact ingress caps raw bytes, depth,
  tokens, members, elements, and decoded name/string bytes before private wire
  decoding. The contract contains no material,
  provider locator, destination, target, authority, lease, handle, fallback, or
  environment name. It grants no authority and adds no `SecretRef`, credential
  authorization, provider, broker, Gateway, runtime, daemon/API/SDK/generated
  surface, scanner, side effect, issue closure, or `G08` evidence. Stable 0.1,
  existing C03 pre-placement, and Driver Registry contract bytes are unchanged.
- **status/incomplete:** added the first behavior-free `DRREG-001` credential-
  sink contract in `splendor-types`: strict canonical driver-operation
  validation over the unchanged `DriverOperationRef`, nominal
  `SecretCredentialSlotId`, checked operation sink/trusted-send declarations,
  exact destination-digest and code-only error types, deterministic canonical
  serialization, and a bounded duplicate-aware `from_json_slice` ingress. The
  public declaration implements `Serialize` but not `Deserialize`; malformed,
  unknown, duplicate, null, over-bound, noncanonical and profile-mismatched
  inputs fail closed without candidate reflection. This additive experimental
  slice grants no authority and adds no manifest registry, admission, projection
  execution, Gateway/provider/node behavior, C03 credential authorization,
  daemon/API/SDK/generated surface, feature activation, issue closure, or
  `G07`/`G08` pass.
- **status/incomplete:** added exactly 40 behavior-free C03 V1a nominal secret
  UUID identity types plus seven closed enums (six owner-independent
  pre-placement enums and the C03-owned `SecretDeliveryControlKind` trusted-send
  control vocabulary), a strict opaque non-locator `SecretProviderVersionRef`,
  and a closed valid-by-construction `SecretLeasePolicy`. IDs retain checked
  non-nil construction, strict lowercase hyphenated wire forms, canonical
  serialization, bounded non-echoing errors, and byte-order-compatible ordering.
  Pre-placement primitives reject unknown,
  malformed, duplicate, null, wrong-type, out-of-range, locator-like, and unsafe
  integer forms without adding authority or runtime behavior. This partial slice
  adds no complete `SecretRef`, lease record/lifecycle,
  provider port, broker, Gateway/daemon/API/SDK/generated surface, scanner,
  feature activation, issue closure, or gold pass. The new control vocabulary
  grants no authority and adds no broker, delivery, driver, registry, or runtime
  behavior. The owner-defined `SecretCredentialSlotId` and behavior-free exact
  credential-sink/trusted-send/destination contracts are now imported
  prerequisites; complete revision-bearing C03 authorization remains separately
  blocked. Stable 0.1 behavior and bytes remain unchanged.
- Hardened physical/edge resident boundaries without changing intervention or
  trace-record schemas. Operator intervention evidence is now checked against
  the authoritative tenant, agent, run, node, action, granted status, and expiry,
  preventing caller-extended grants and cross-device reuse. Device reconnect
  trace sync now requires the dedicated mutating scope
  `splendor.device.trace_sync`, rejects empty/non-zero-start/gapped/cross-run
  batches, and recomputes every event hash before acknowledging any record.
  Exact valid full-batch retries remain revalidated and accepted; this local
  endpoint does not claim central persistence or exactly-once delivery.
- Corrected resident state-handoff import to fail closed before store, state-head,
  or run-trace mutation. Caller bearer authentication, endpoint scope, and the
  exact signed target work order remain required but cannot authenticate the v0
  handoff source or prove the caller-carried source trace exists. Resident import
  now returns `503 state_handoff_proof_unavailable` with `needs_intervention`;
  valid exact-profile unknown-run imports receive the same response instead of a
  run-existence oracle. Denials record only bounded redacted resident security
  audit facts and no run trace; successful import remains experimental loopback
  `local_dev` compatibility.
  Signed source manifests, source event/evidence verification, and durable replay
  remain downstream STA-005/EVT-005/EVID-005 work. Gold was not exercised.
- Hardened the bounded non-gold, production-local AUTH-003 delegation slice:
  the Authority Service now stores and validates immutable ordered chains,
  atomically reserves authority-owned fan-out and component-wise subtree budgets,
  supports exact-grant nested children, binds every child action to its issued
  grant, propagates cancellation/revocation, enforces cleanup obligations, and
  records reservation release/fail-safe consumption for inspect-only replay.
  Runtime callers now receive opaque live caller/child handles rather than
  validated grants; child actions recheck lifecycle, exact grant/run/agent
  binding, and cumulative per-tick budget, then retain a final permit through
  gateway entry. Exact semantic edge digests reject chain mutation, and exact
  agent/run bindings reject Cartesian identity recombination. Explicit rooted
  runtime edges prevent a direct child from delegating to a root sibling while
  preserving assigned nested descendants. Delegated action expiry and HTTP
  minute windows use maximum-observed authority service time, so rollback cannot
  reactivate a grant or old quota bucket. Cleanup and subtree revocation close
  admission before a bounded typed quiescence wait rather than waiting forever.
  A child cleanup timeout now terminally fails the manager-owned child lifecycle,
  emits structured parent/child replay evidence, and rejects completion retry
  after the earlier permit drops. Trusted runtime trees reject root identity reuse
  in descendant scope, and nested role escalation names the exact failing edge.
  Legacy
  `DelegatedAuthority` is narrowing-only. Live task requests, delegation
  edge/chain contracts, and redacted ledger trace summaries are v2; task v1 is
  replay/migration-only and full authority parameters remain ledger-owned.
  Remote Message Service/Agent Controller
  adoption and G18/G70/G71 remain deferred/not exercised; no gold was run.
- Integrated current daemon run admission/effects with one opaque live C02 grant
  admitted only from the verified signed-work-order wrapper. Scheduler, direct,
  and run-bound physical gateway paths now evaluate typed action/adapter/
  permission operations, fail closed on live expiry/revocation, persist redacted
  authority allow evidence before adapter execution, and expose inspect-only
  replay summaries. Gold evidence remains `not_exercised`.
- Corrected the bounded AUTH-004 approval path so raw `ApprovalEvidence` is
  compatibility/replay data and can never authorize an effect. Approval-required
  outcomes now expose an exact non-authorizing challenge; the local manager can
  immutably record that challenge and issue one trusted approval-obligation
  receipt, and waiting runs progress only by retrying the exact action through
  `/actions`. Receipt-bearing or raw-evidence lifecycle resumes do not tick,
  while an exact receipt-free `/actions` retry can now carry a raw denial through
  the policy verifier to terminal trace/replay evidence without adapter execution.
  Changed action bindings fail closed, one-use and semantic-reissue replay are
  denied, and trace failure cannot produce a second adapter effect. Physical
  approval digests now bind the exact server-derived node under a separate v2
  digest domain while nonphysical v1 bytes remain unchanged. Granted receipt
  revocation is sent to the exact resident over validated TLS and commits at the
  manager only after a typed known acknowledgement; claim/revoke races are atomic
  and uncertainty blocks dispatch. Receipt trust and replay/revocation state
  remain process-local; no production PKI, restart-durable ledger, full AUTH-004,
  or gold completion is claimed. Rust process composition obtains receipt
  configuration and the single per-run shared verifier/ledger through the opaque
  `splendor-kernel` facade, removing the daemon's normal `splendor-authority`
  dependency. OpenAPI and TypeScript expose the additive closed revocation and
  physical challenge contracts.
- Closed the remaining local manager approval signing oracle: approval request,
  grant, deny, and revoke now require a fresh one-use Ed25519 caller bearer bound
  to the exact central-manager audience, configured fleet, and
  `splendor.approvals.manage` scope. Approval trust now binds the exact caller
  subject, must use a key distinct from outbound resident dispatch, permits an
  exactly matching optional/null risk label, and records separate requester and
  decider attribution with hashed credential correlation. Request credential/audit
  objects are exact non-authoritative mirrors; forged, stale, wrong-target, wrong-scope, or replayed
  proof fails before approval/audit mutation or receipt issuance. This remains a
  bounded `local_acceptance` profile with process-local trust/replay state; it
  does not add manager TLS, general inbound manager authentication,
  restart-durable revocation propagation, or gold completion.
- Added a bounded manager-owned approval-policy admission seam for real resident
  dispatch. `POST /work-orders` accepts a default-empty closed and bounded policy
  list only when every selector narrows to the signed work-order scope, then
  digest-binds that exact list to the process-local accepted record. Same-ID
  replacement and out-of-scope/expired policies fail closed; dispatch cannot
  override policies, forwards only the retained list over the existing TLS
  resident create path, and keeps policy actions empty. Approval policies can
  pause an otherwise authorized action but cannot add actions, adapters,
  permissions, or bypass C02/gateway verification. This does not authenticate
  the remaining manager inbound API, add durable policy storage, or claim gold
  completion.
- Made resident physical safety snapshots process-owned: stored device status,
  constraints, policy expiry/current time, node identity, and action parameters
  are authoritative, while request safety fields can only narrow/deny. Forged
  safe battery, geofence, altitude, emergency-stop, collision, privacy,
  proximity, offline-policy, and cloud-authority inputs cannot reach the adapter.
  Safety completion traces now derive only from actual gateway safety evidence.
- Integrated `splendorctl run` with the same signed-work-order C02 enforcement:
  the CLI now preserves `ValidatedWorkOrder`, privately derives a live per-run
  authority handle, enforces exact action/adapter/permission and identity scope,
  rechecks expiry/revocation, and durably records authority allow evidence before
  filesystem or HTTP adapter calls. Evidence failure blocks the effect, replay
  remains inspect-only, and configured work orders never fall back to explicit
  unsigned-local compatibility mode. Ambiguous multi-adapter profiles fail
  closed because the current work-order schema does not bind actions to adapters.
- Added the accepted RFC 0011 resident security correction: resident mode now
  requires Rustls TLS, a closed Ed25519 caller bearer verified against explicit
  trust/revocation state, explicit owner-only work-order/policy keyrings, and
  exact non-authoritative credential mirrors. Mutating bearer JTIs are now
  atomically one-use, audit correlation is a bounded domain-separated digest,
  audit time is server-owned, and safe create idempotency remains stable across
  fresh JTIs. Manager→resident dispatch now uses bounded no-redirect/no-proxy
  HTTPS, an exact-origin allowlist, immutable work-order/placement/node/instance
  binding, eligible-instance checks, strict typed responses, terminal
  unknown-effect outcomes without automatic retry, and real resident-router plus
  adversarial fault evidence. The UC-E2E-S4 composition generates acceptance-only
  key/TLS material in separate role volumes with per-instance work-order v1
  secrets; v1 remains a scoped shared-secret residual rather than asymmetric
  verifier separation.
- Closed the final resident-auth dispatch races: consumed mutating JTIs now live
  through expiry leeway; work-order revocation is serialized across full
  create/start dispatch with last-moment authority checks; start cancellation
  retains an unknown-effect quarantine until an authoritative success report is
  stored; signed locality rejects unknown classes; and the existing typed
  registry now backs an authenticated instance-heartbeat manager route. The
  TypeScript bearer client rejects redirects, create/idempotency fingerprints use
  domain-separated BLAKE3, verifier debug output redacts consumed JTIs, and the
  one-shot acceptance auth fixture runs only in an explicit Compose setup phase.
  Resident trace views retain only bounded `sha256:` caller-correlation digests,
  allowing central sync to verify original hash chains without exposing bearer
  or JTI material. State snapshot export/import now enforce their documented
  `splendor.state.handoff` scope plus exact signed run work-order authority,
  receiver identity/head binding, replay denial, and scheduler/loop/state-owner
  mutation. Registry freshness now uses monotonic manager receipt time rather
  than sender timestamps, and unknown work-order revoke/dispatch IDs allocate no
  revocation gate, tombstone, reservation, or terminal dispatch state.
- Corrected CLI run-level trace composition so agents sharing one configured
  `run_id` also share one runtime cursor, producing a contiguous sequence/hash
  chain with distinct agent identities. Signed resume retains that cursor and
  live pre-effect authority. Authority-profile admission rejection now records
  bounded sanitized audit evidence before state or adapter effects.
- Completed the non-gold production-local C02 service path for current local and
  resident-mode daemon run effects: immutable action/adapter/exact-
  permission profiles prevent permission omission and adapter recombination;
  a final owned effect permit closes expiry/revocation TOCTOU races; revocation
  waits for earlier permitted adapter calls; monotonic time latches observed
  expiry; scheduler traces retain one tick identity; direct/physical traces retain
  one action identity; and conditional receipts reject globally duplicated or
  unknown extras, validate after blocking verifiers, and atomically claim an owned
  one-use effect permit before evidence/adapter. Trace failure burns the claim.
  The shared receipt ledger is process-local and does not claim restart durability.
  Registered and non-empty request profiles require the complete signed permission set and ambiguous
  multi-adapter work orders fail admission. Closed Rust/OpenAPI objects and exact
  TypeScript authority unions have parity tests. The bounded resident caller
  verifier is the accepted RFC 0011 compatibility adapter; full C01/IDR-002,
  future privileged planes, and all gold cases remain downstream/not exercised.
- Hardened the daemon C02 lifecycle boundary: only pending/running runs admit
  direct or run-bound physical gateway work; terminal transitions close new
  effect permits before status publication and wait outside the broad run lock;
  resume requires the original work-order identity and canonical bound payload;
  untrusted direct/physical quota estimates have server-owned action/duration
  minima; and resident run traces retain the configured `instance_id`.
- Corrected daemon lifecycle ownership so blocked direct/physical adapters no
  longer retain the global run registry or per-run lifecycle lock. Stop/cancel
  can close admission, publish terminal status, and keep unrelated runs
  inspectable while waiting for an earlier final permit. Resident process startup
  now rejects missing, malformed, blank, or nil `SPLENDOR_INSTANCE_ID` instead of
  silently generating one. Omitted and explicit-zero duration estimates are
  covered on both direct and physical endpoints.
- Added bounded AUTH-007d exact-family current-v1 positive and v0/v2 denial
  matrices for authority operation/scope/grant/request/revocation/policy
  contracts, plus trusted authority cache/snapshot freshness, offline-TTL, and
  daemon policy-sync preservation/blocking evidence.
- Signed policy bundles whose `issued_at` is later than the receiver validation
  clock now fail closed with `future_issued_policy_bundle` before installation;
  equality remains valid. Historical 0.04-shaped v1 signatures are characterized
  as `bad_policy_signature` under current normalization, not claimed compatible.
- Hardened policy cache mutation so production callers must supply a trusted
  `ValidatedPolicyBundle`; signed issuance/content is monotonic, exact retries do
  not clear tombstones, only strictly newer authority refreshes, revoked
  candidates are identity/scope/age-bound, reconnect requires accepted install,
  and clock rollback or latched expiry cannot reactivate policy authority.
- Added exact signed revocation watermarks, tenant+agent cache ownership,
  exact-retry reconnect denial, and trace-before-commit mutation. Public callers
  now use high-level recorder-bound methods; internal plans/commit are private.
  Revocation trace failure latches an exact deny-only pending watermark. Public
  Rust cache construction/mutation APIs changed; daemon wire shapes did not.
  Post-trace commit races now preserve and latch still-applicable exact
  revocation evidence while leaving strictly newer active winners unpoisoned.
- Bound local delegating root runs to one exact trusted validated capability
  grant, including private trust state, within one manager. Cross-run/shared-
  principal and same-ID/different-content replay now fail before message routing
  or child effects. Unbound roots remain compatible for non-delegating use.
- Enforced manager-local root/child grant-ID uniqueness, added replay-visible
  delegation rejection reasons, and added an explicit bounded multi-agent/run
  legacy grant profile for one-parent/two-specialist local delegation.
- Added a partial FND-012 performance budget contract in `splendor-types`, a
  machine-readable 0.2 fixture, and conformance validation for mandatory
  latency/throughput metrics, benchmark environment capture, regression
  thresholds, retention/backpressure actions, and G29/G66/G68/G74 budget
  mappings.
- Hardened the partial FND-012 contract so issue #231 non-claims are
  machine-enforced, measured report summaries require a benchmark run reference,
  non-finite budget values are rejected, and skipped safety checks fail
  conformance.

### Explicitly not included

- No policy cache persistence/fleet redesign,
  resident persistence/watch, canonical
  historical-signature migration seam, or broad rolling-version compatibility
  claim. The additive exact receipt/profile/tick contract fields and parity tests
  are limited to the current C02 daemon effect path. AUTH-003 intentionally adds
  v2 task-request, delegation edge/chain, and redacted trace-summary contracts as
  described above. The in-memory cache state and
  public Rust mutation API did change.
- No all-plane AUTH-007, #244, or gold completion claim; Driver, Artifact
  Registry, physical helper-plan, remote/fleet, typed-instance, and independent
  response-recipient confused-deputy paths remain deferred or unexpressible.
- No generic OAuth/OIDC/PKI provider, full Principal Registry, manager inbound
  production authentication, hot trust watch/refresh, mTLS enrollment, or
  request proof-of-possession. `splendor-manager` remains explicit acceptance
  infrastructure even though its outbound resident dispatch is authenticated.
- No remote/cross-instance delegation ledger, Message Service or Agent Controller
  adoption, or durable authority reservation store; recursive support is local
  and only through exact authority-issued child grants plus explicit runtime
  edges. This bounded slice is not a catalog-wide AUTH-003 completion claim.
- No cross-manager or cross-instance grant binding and no durable trace event for
  trusted local root-binding setup; the binding API remains local run admission.
- No FND-012, #231, #180, G29, G66, G68, or G74 completion/pass claim; no 24/7
  soak, 1,000-node, GPU/training, robotics, live fleet, or physical hardware
  benchmark was executed by this slice.

## 0.1-dev — Stable primitive compatibility line

### Release and migration artifacts

- Added 0.1-dev release notes that list stable primitives, stable SDK/API
  surfaces, local and daemon example entry points, release validation commands,
  known limitations, and human-only tagging checklist.
- Added the 0.1 migration guide mapping development-era field/API changes to
  stable replacements or removal reasons, including `trace_id` to
  `trace_event_id`, `WorkOrderAuthorization.allowed_scopes` to explicit
  `WorkOrderEnvelope` fields, daemon version metadata limitations,
  daemon/Python status casing, and local-only insecure credential behavior.
- Added the 0.1 compatibility policy defining patch/minor expectations,
  deprecation requirements, validation baseline, and surfaces that remain
  experimental or future work.
- Added the 0.1-S6 milestone evidence document for migration/release validation
  and sprint-scoped non-goals.

### Explicitly not included

- No actual release tag was created by this documentation sprint.
- No 1.0 production claim, production fleet scheduler, production remote daemon,
  enterprise support policy, marketplace, adapter certification, production
  robotics safety certification, or hard real-time control claim.

## 0.05-dev — Physical and edge orchestration

### Implemented primitives

- Added the 0.05-S4 middleware-agnostic robotics adapter contract and simulated
  robot/drone adapter for high-level physical actions behind the gateway and
  local safety verifier.
- Hardened gateway physical-action validation so forbidden low-level physical
  control names are denied before adapter execution.
- Added the 0.05-S1 device profile and physical capability schemas for robots,
  drones, humanoids, edge appliances, desktop sidecars, and industrial devices,
  including validation that rejects raw motor/actuator and ambiguous direct
  physical actions.
- Added the 0.05-S2 offline policy cache behavior for disconnected physical/edge
  instances, including cached-policy TTL handling, low-risk offline allowance,
  high-risk denial/local intervention, and trace-visible connectivity changes.
- Added the 0.05-S3 local trace buffer and reconnect sync contracts, including
  offline interval markers, sync boundaries, duplicate sync handling, corruption
  quarantine/rejection, and storage-pressure fail-closed behavior for
  side-effectful actions.
- Added the 0.05-S5 safety verifier API in the existing gateway chain with
  simulated geofence, battery, emergency stop, collision, altitude, privacy,
  proximity, uncertainty, and postcondition evidence.
- Added the 0.05-S6 advisory cloud-helper pattern with scoped helper work-order
  validation, route-plan proposal messages, local route validation, helper
  failure handling, and denial of cloud direct physical or robotics adapter
  authority.
- Added the 0.05-S7 physical simulation harness covering successful high-level
  missions, safety denial before adapter execution, offline interval/reconnect
  sync, operator intervention/override request flow, cloud-helper local
  validation, final state heads, and inspect-only replay without helper or
  adapter side effects.
- Added 0.05-dev release notes and aligned release-facing documentation with the
  implemented physical/edge development primitives while preserving production
  hardware non-goals.

### Explicitly not included

- No ROS/native package, live hardware path, motor controller, direct
  cloud-to-actuator path, or robotics safety certification claim.
- No hard real-time robot control, raw actuator writes, firmware safety bypass,
  production physical hardware deployment, fleet route optimizer product, adapter
  certification program, or 0.1 stable compatibility guarantee.

## 0.04-dev — Governance workflows

### Implemented primitives

- Added the 0.04-S1 governance state model with typed approval, escalation,
  intervention, circuit-breaker, and kill-switch IDs and schemas.
- Added explicit governance scopes for global, fleet, node, instance, tenant,
  agent, run, action, and adapter boundaries.
- Added trace-ready governance transition and rejection records plus governance
  `TraceEventKind` variants for lifecycle changes and invalid transition
  rejection.
- Added recursive validation for non-authoritative governance extension fields so
  metadata cannot smuggle permissions, work orders, credentials, signatures, or
  approval tokens.
- Added the 0.04-S3 escalation engine with versioned escalation policy rules,
  deterministic threshold evaluation, `NeedsIntervention` action outcomes,
  escalation trace events, and inspect-only replay reconstruction.
- Hardened the 0.04-S3 escalation install path so invalid policy schema versions
  or zero thresholds fail closed before evaluator installation, and repeated
  adapter denials can use explicit denial counts as escalation evidence.
- Added 0.04-S4 circuit-breaker schemas, scoped gateway enforcement, local
  `splendorctl run` config support, trip/clear trace event variants, and
  inspect-only replay output for breaker-denied actions.
- Added 0.04-S5 central policy distribution with signed `PolicyBundle` envelopes,
  daemon policy sync, local policy cache/degraded mode, policy TTL/revocation
  denial, trace-safe policy metadata, and Rust/TypeScript/OpenAPI contract
  coverage.
- Added 0.04-S6 external governance adapter contracts for provider-neutral
  Harmony-compatible work-order bridging, approval grant/denial mapping,
  fail-closed adapter failure records, and trace-linked artifact references.
- Added 0.04-S7 governance replay/audit support: inspect-only replay now
  explains approval lifecycle events and `needs_approval` outcomes, and
  `splendorctl audit export` emits a redacted `0.04-dev` audit package from
  trace/state primitives with identity, work-order, policy, verifier, action,
  state-node, trace-range, and scope-filter evidence. Replay/audit inspection
  now recomputes trace payload hashes, validates referenced state evidence, and
  redacts credential-shaped replay output before emission.
- Added 0.04-dev release notes and Docker image packaging updates for the
  governed runtime deployment image, including `linux/amd64` and `linux/arm64`
  release tags.

### Explicitly not included

- No approval UI, enterprise IAM integration, broad workflow language, ticketing
  integration, notification platform, approval workflow engine, escalation
  automation, kill-switch propagation, monitoring platform, UI dashboard,
  enterprise policy authoring product, Harmony admin/product implementation,
  global policy consensus, production PKI/key management, compliance
  certification, long-term archival product, or side-effect path outside the
  Action Gateway.

## 0.03-dev — Resident nodes + fleet execution foundation

### Implemented primitives

- Added the 0.03-S1 distributed identity model with distinct fleet, node,
  instance, tenant, agent, run, tick, action, state-node, trace-event, and
  message IDs.
- Renamed serialized trace event identity to `trace_event_id` while accepting
  legacy `trace_id` during deserialization.
- Added trace identity context fields and fail-closed gateway validation for
  invalid action, tenant, agent, or run identity before adapter execution.
- Added state metadata/commit linkage for tenant, agent, run, and trace-event
  scope.
- Added 0.03-S2 node and instance registry contracts with capabilities,
  heartbeats, deterministic stale detection, and management audit events.
- Added 0.03-S3 signed work-order schemas, detached reference signature
  verification, local `splendorctl` ingestion, scoped runtime policy/quota
  narrowing, and accepted/rejected work-order trace events.
- `splendorctl run` now rejects missing work-order authority by default;
  legacy local quickstarts must opt into `allow_unsigned_local_run: true` and are
  visibly warned.
- Added a 0.03-S4 placement v0 contract in Rust for deterministic target-class,
  capability, data-locality, runtime-version, execution-mode, and
  dedicated-instance matching with explicit rejection reasons and management
  trace/audit evidence.
- Added the 0.03-S6 trace aggregation reference path: `TraceSyncBatch`,
  `CentralTraceIndex`, `InMemoryCentralTraceIndex`, hash-chain validation,
  duplicate sync idempotency, missing segment detection, corruption quarantine,
  and central trace queries by available identity metadata.
- Added `TraceDurabilityGateway` so local policy can fail closed before
  side-effectful adapter execution when central trace sync durability is
  required and stale or failed.
- Added 0.03-S7 state handoff v0 schemas, snapshot export/import validation,
  read-only state references, source/receiver handoff trace events, and replay
  handoff boundary inspection.
- Added the 0.03-S8 fleet telemetry model and in-memory collector for node
  heartbeat state, instance runtime reports, canonical run status counts, queue
  depth, quota/denial signals, trace sync lag/failure, and failure taxonomy.
- Added typed fleet/node/instance telemetry scope separation using the canonical
  distributed identity types.

### Explicitly not included

- No autoscaling, multi-region optimizer, cost optimizer, Kubernetes operator,
  remote dispatch, full PKI/OAuth product, governance approval workflow,
  analytics dashboard, long-term warehouse, governance audit product, remote
  trace transport, distributed consensus, central manager, telemetry dashboard,
  distributed mutable state, CRDTs, automatic conflict merge, full runtime
  migration engine, fleet scheduler, dashboard, anomaly detection, billing
  metrics, fleet autoscaler, observability vendor integration, telemetry-derived
  runtime authority, or physical/edge orchestration.

## 0.02-dev — Local multi-agent runtime + daemon control

### Release hygiene

- Added a multi-stage Docker deployment image and container smoke test for the
  0.02-dev local runtime surface, including `splendorctl`, `splendor-daemon`, the
  Python SDK, OCI labels, a non-root runtime user, and GitHub Container Registry
  publish workflow support.
- Added multi-architecture Docker publishing for `linux/amd64` and `linux/arm64`
  release images.
- Updated the visible Rust CLI and Python SDK milestone labels to
  `Splendor0.02-dev` while keeping package versions on the existing development
  `0.1.0` line.
- Added 0.02-dev release notes with QA evidence, compatibility notes, and
  explicit future-scope exclusions.
- Updated README and local runtime docs so the repository status reflects the
  completed 0.02-dev local multi-agent and daemon-control scope.

### Implemented primitives

- Added a 0.02-S0 daemon security boundary reference contract in Rust for
  caller principals, endpoint scopes, tenant/fleet binding, audience binding,
  credential/work-order expiry and revocation, explicit insecure local dev mode,
  and trace/audit attribution.
- Added a 0.02-S1 message schema contract in Rust for `MessageId`, `Message`,
  `MessageEnvelope`, schema-version validation, delivery status vocabulary,
  message trace links, and message lifecycle trace event definitions.
- Added a 0.02-S2 local message router for in-process inbox/outbox delivery with
  trace-linked queued, delivered, rejected, expired, and consumed events.
- Added a 0.02-S3 agent isolation ledger for per-agent permission checks,
  per-agent quota counters, local message schema/recipient grants, denial trace
  artifacts, and replay-visible message decisions.
- Added a 0.02-S4 local delegation model in Rust for typed task
  request/response messages, parent/child run metadata, explicit delegated
  authority, local child-run trace events, structured child failures, parent
  cancellation denial, and inspect-only delegation replay reconstruction.
- Hardened 0.02-S4 local delegation with duplicate child-run ID rejection and
  terminal child completion/failure guards that avoid duplicate response messages
  or terminal traces.
- Added a 0.02-S5 local runtime daemon API crate with endpoints for run
  lifecycle, percept append, ordered traces, state-head lookup, inspect-only
  replay, gateway-mediated action submission, health, and capabilities.
- Added state-node lookup through `StateStore::get_node` so daemon state-head
  responses verify that returned nodes exist in the state graph.
- Added the 0.02-S6 TypeScript surface with `@splendor/types`, a thin
  authenticated `@splendor/client`, schema parity tests, SDK docs, and a minimal
  daemon-client example.
- Added CI coverage for the 0.02-S6 TypeScript runner so package build,
  typecheck, schema/client tests, and Node coverage gates run with Rust and
  Python release checks.
- Added 0.02-S7 inspect-only multi-agent replay output for message lifecycle
  causality, local parent/child run links, and permission-laundering denial
  evidence without re-executing side effects.

### Explicitly not included

- No production OAuth/OIDC provider, PKI management, fleet mTLS rollout, node
  bootstrap, governance workflow, message broker, remote transport, fleet
  scheduler, fleet placement, long-lived child services, native Node binding,
  browser runtime, cross-instance replay, distributed trace sync, or TypeScript
  runtime enforcement.

## 0.01-dev — Local kernel baseline

### Implemented primitives

- Local scheduler and loop engine for persistent agent ticks.
- Tenant policy, adapter allowlist, permission, quota, invariant, precondition,
  and postcondition checks before side-effectful adapter execution.
- SQLite-backed state graph with state nodes and snapshots.
- Append-only trace store with per-run sequence numbers, deterministic trace IDs,
  and hash-chain metadata.
- CLI workflows for version, config-driven local run, trace export, state-head
  inspection, and replay.
- Replay from trace/state stores without repeating side effects.
- Python SDK hooks for policies, perceptors, constraints, adapters, trace
  subscription, and inspect-only replay.

### Hardening changes

- Added `splendorctl state head` and `splendorctl --version`.
- Added replay validation for run scope, sequence continuity, trace IDs, and
  trace integrity-chain continuity.
- Added baseline conformance docs, release notes, known limitations, SDK docs,
  and runnable examples.

### Explicitly not included

- No typed local message router, daemon API, or TypeScript client.
- No fleet registry, remote transport, signed work orders, or trace aggregation.
- No governance workflow engine, approvals, circuit breakers, policy TTL, or kill
  switch.
- No physical/edge device orchestration.
- No 0.1 stable compatibility guarantee.
