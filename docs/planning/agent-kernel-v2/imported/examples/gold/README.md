> **Status:** Imported vNext planning reference. This file is not part of the stable 0.1 implementation contract and is not evidence that the repository implements the described behavior. Existing `AGENTS.md`, `docs/rules/*`, `docs/spec/0.1/*`, and release limitation documents remain authoritative until an RFC is accepted and implemented. If the source text below says `normative`, that status applies only to the imported vNext source pack, not to current repository rules.

# Gold conformance catalog and result protocol

`catalog.yaml` is the machine-readable registry for G00–G89. The human acceptance descriptions live in [`../../09_gold_examples_catalog.md`](../../09_gold_examples_catalog.md); `tools/generate_gold_catalog.py` keeps both views synchronized.

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
6. emits a document conforming to [`../../schemas/gold-result.schema.json`](../../schemas/gold-result.schema.json);
7. preserves failed and not-exercised results rather than overwriting them with retries.

`result.fixture.yaml` demonstrates the result envelope without claiming an implemented case. It is intentionally `not_exercised`.

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
