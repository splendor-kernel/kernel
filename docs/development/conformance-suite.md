# Running The 0.1 Conformance Suite

The Splendor 0.1 conformance suite is a local, secret-free compatibility check
for stable primitive contracts.

## Local Run

From the repository root:

```bash
python conformance/0.1/run-conformance.py
```

To emit JSON for CI:

```bash
python conformance/0.1/run-conformance.py --format json --output target/conformance-0.1-report.json
```

The command exits non-zero when any conformance case fails.

## What It Validates

- Runtime loop ordering and trace identity.
- Gateway positive, denial, failure, and fail-closed boundaries.
- State graph identity, hash, parent, and trace linkage.
- Replay side-effect suppression.
- Message causal graph trace linkage.
- Work-order unsigned, expired, revoked, and overbroad rejection.
- Governance approval, denial, escalation, and circuit-breaker contract evidence.
- Adapter maturity manifests without production secrets or external systems.

## Fixture Library

Primary fixtures live in:

```text
conformance/0.1/fixtures/conformance-cases.json
```

Adapter contract evidence is reused from:

```text
docs/spec/0.1/fixtures/adapter-manifests/*.json
```

The runner also includes a negative fixture that is expected to fail internally.
That case proves broken trace ordering produces an exact primitive/requirement
failure instead of a shallow file-existence pass.

## CI Usage

Recommended CI commands for this sprint:

```bash
python conformance/0.1/run-conformance.py --format json --output target/conformance-0.1-report.json
python scripts/validate-adapter-manifests.py
git diff --check
```

The adapter manifest validator remains separate so manifest regressions can be
reported both through the conformance suite and directly through the S3 validator.

## Reading Failures

Each report entry includes:

- `primitive`: failed primitive category.
- `requirement`: exact conformance requirement ID.
- `case_id`: fixture case.
- `path`: positive, denial, failure, replay, fail_closed, or negative_fixture.
- `message`: exact validation error.

## Limitations

The suite is a primitive conformance suite. It does not claim:

- complete use-case E2E acceptance through 0.1;
- production adapter certification;
- hardware or physical safety certification;
- external control-plane, SaaS, or network integration coverage;
- runtime feature completeness beyond the evidence represented in fixtures or
  existing validators.
