> **Status:** Active 0.2/v2 gold catalog source. This file defines the gold result protocol after the higher-priority safety, accepted-RFC, stable-spec, public-contract, and release-limitation hierarchy. It is not evidence that the repository implements or passes the described behavior.

# Gold conformance catalog and result protocol

`catalog.yaml` is the machine-readable registry for G00-G89. The human acceptance descriptions live in [`../gold-examples-catalog.md`](../gold-examples-catalog.md); imported generator tooling was not made active in this repository.

## Status is evidence-scoped

Catalog status describes implementation availability. A run result describes one execution against an exact catalog digest:

- `specified_not_implemented` is a catalog state and never means pass;
- `passed` means every required assertion selected for the run passed;
- `failed` means at least one exercised assertion failed;
- `not_exercised` means the case or assertion did not run, including missing hardware, feature flags, credentials, human reviewers, or implementation.

CI must not convert missing prerequisites, disabled features, or skipped cases into pass.

## Runner contract

A conforming runner:

1. pins the catalog digest, code, environment, feature flags, and case ID;
2. rejects an unknown case or assertion ID;
3. executes only under the case's declared resource and authority profile;
4. records assertion-level outcomes and immutable evidence references;
5. computes the case outcome: any failure means `failed`; otherwise any required non-exercised assertion means `not_exercised`; only complete success means `passed`;
6. emits a document conforming to the planned `schemas/gold-result.schema.json` contract once that schema is added;
7. preserves failed and not-exercised results rather than overwriting them with retries.

A future `result.fixture.yaml` may demonstrate the result envelope without claiming an implemented case. Until that fixture exists and is wired into a runner, the example result remains planned and any corresponding case stays `not_exercised`.

## Executable case directory

When implemented, a case receives `examples/gold/Gxx-name/` with:

```text
README.md
specs/
src/
tests/
fixtures/
expected-events.yaml
expected-lineage.yaml
run.py
SECURITY.md
```

The directory is not considered implemented merely because it exists. Its runner, positive path, denial path, failure/recovery path, cleanup assertions, and result envelope must all be present.
