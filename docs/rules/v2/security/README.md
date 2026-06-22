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

## Validation

The fixture is validated by:

```bash
python3 conformance/0.1/run-conformance.py --format json
cargo test -p splendor-types security_invariants
```

The validation is intentionally strict about prompt-only boundaries, skipped
mandatory conformant cases, missing G80-G89 mappings, and missing event/evidence
or containment links.
