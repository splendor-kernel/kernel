# FND-011 Security Invariants Fixture

This directory contains the bounded FND-011 security threat/invariant mapping
fixture used by the local conformance runner.

## Scope

- Catalog task: `FND-011`
- Sprint: `V2-FND-0`
- FR bridge: `FR-0.2-01`, `FR-0.2-08`
- Gold IDs mapped: `G80` through `G89`

`security-invariants.json` is partial foundation evidence. It records assets,
principals, trust boundaries, attacker capabilities, fail-closed decisions,
enforcing components, required events, evidence links, containment actions,
incident classifications, and change-risk classifications for the G80-G89
security/adversarial gold cases.

## Non-claims

This fixture does **not** claim full FND-011 completion, G80-G89 gold passes,
red-team test execution, production secret brokering, node attestation, rollout
control, protected eval isolation, or physical safety certification. Gold cases
remain not exercised unless an exact executable gold harness runs and records
passing evidence.

The conformance suite also contains a bounded G86 driver schema-confusion denial
fixture that proves a schema/version mismatch is denied before adapter/driver
execution. Its negative guards reject contradictory execution fields, side-effect
events/evidence, duplicate trace IDs, out-of-order events, and mismatched verifier
evidence. That fixture family is partial denial evidence only; it does not
implement a driver registry, certification process, ABI negotiation service, or
runtime driver execution system, and it does not mark G86 or G80-G89 as passed.

The suite now also contains bounded G80 prompt/data-injection denial evidence.
The Python runtime test exercises the current local runtime path: a malicious
perceptor payload smuggles `allowed_actions`, `allowed_adapters`,
`allowed_permissions`, approval, verification, and gateway-bypass hints; a naive
policy proposes the requested unauthorized filesystem action; tenant/gateway
verification denies it; the adapter call count remains zero; and trace contains a
denial with no execution event. The conformance fixture mirrors that denial shape
and rejects contradictory execution, side-effect event, missing side-effect
counter, and malformed non-claim evidence. This remains partial evidence only:
G80, G80-G89, FND-011, #230, and #180 are not complete or passed.

## Validation

The fixture is validated by:

```bash
python3 conformance/0.1/run-conformance.py --format json
cargo test -p splendor-types security_invariants
python3 -m pytest python/tests/test_runtime.py
```

The validation is intentionally strict about prompt-only boundaries, skipped
mandatory conformant cases, missing G80-G89 mappings, and missing event/evidence
or containment links. It also rejects prompt-only/security-by-prompt wording such
as `system prompt`, `prompt instruction`, or `LLM instruction` in trust-boundary
or enforcement controls even when `prompt_only` is set to false. `case_status:
exercised` requires explicit executable gold evidence metadata, and the partial
G80-G89 fixture remains `mapped_not_exercised`. Crypto-agility labels use an
explicit allow-list (`ed25519`, `ecdsa_p256_sha256`) so weak or underspecified
labels such as `none`, `md5`, `rsa_md5`, `rsa_sha1`, `sha1`, `dsa_sha1`, `plain`,
and empty labels are rejected as validation failures only; this does not
implement cryptography or claim crypto enforcement.

The G80 denial fixture uses inert local canary strings only. It does not add a
route taint engine, protected-eval/data-use controller, secret broker, production
adapter registry, live side-effect path, or gold harness pass status.
