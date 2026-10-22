# V2-FND-0 Foundation Readiness Checkpoint

Status: **foundation-ready for C01 contract/RFC work**.

This checkpoint records that every `FND-001` through `FND-012` catalog task has a
committed foundation-level artifact or executable fixture family sufficient to
start the next 0.2/v2 component slice: **C01 / `splendor.identity-registry`**.

It deliberately does **not** claim full FND implementation, full validation, or
gold pass status. The machine-readable checkpoint is
`docs/rules/v2/foundation-readiness.json`, and the conformance runner validates
that the checkpoint keeps those non-claims explicit.

## Readiness definition

For this checkpoint, a foundation is ready when it has all of the following:

1. a concrete repo artifact, implementation seam, or executable fixture for the
   foundation topic;
2. a retained conformance/unit/integration validation path where practical;
3. explicit remaining validation/gold gaps;
4. explicit non-claims preventing the foundation marker from being treated as a
   full task or gold completion claim.

This is weaker than full catalog task completion. It is intended to avoid keeping
C01 blocked on later full gold suites while still ensuring the foundation rails
exist before identity work starts.

## Foundation coverage

| Task | Foundation checkpoint | Full validation still out of scope |
| --- | --- | --- |
| `FND-001` | 0.1 primitive/schema-extension compatibility and non-authorizing extension guardrails exist. | Full vNext object grammar, generated bindings, `G00`. |
| `FND-002` | Architecture/dependency policy plan and smoke check exist. | Full plane crate split and duplicate-owner enforcement. |
| `FND-003` | Runtime trace-before-action and state/trace transaction invariants are covered by current loop tests and fixtures. | Generic command/decision/event transaction service and full fault injection. |
| `FND-004` | Stable failure taxonomy types and tests exist. | Generated SDK/HTTP/gRPC mappings and incident/scheduler integration. |
| `FND-005` | Conformance runner, negative fixtures, adapter manifest validation, and gateway adapter tests exist. | Signed conformance artifacts, remote/resident harness, driver certification. |
| `FND-006` | Compatibility class rules and fixture matrix exist. | Version negotiation, online storage migrations, rolling upgrade. |
| `FND-007` | User-space policy/perceptor output remains proposal-only in current gateway/runtime tests. | Sealed privileged-commit interfaces across eval/training/change/deployments. |
| `FND-008` | Deterministic IDs/clocks and budget environment-capture seams exist. | Full payload-reference system and reproducibility fingerprints. |
| `FND-009` | Audit export/redaction reference and daemon test seams exist. | Secret broker/data-use/protected-eval integration. |
| `FND-010` | Runtime daemon API idempotency/reference docs and tests exist for current endpoints. | Durable ledger for every mutating endpoint and generated client tests. |
| `FND-011` | Threat/invariant mapping plus bounded G80 and G86 denial evidence exist. | Full G80-G89 red-team/gold harness. |
| `FND-012` | Performance budget/report contract and negative fixtures exist. | Benchmarks, soak tests, 1,000-node simulation, preemption proof. |

## C01 readiness boundary

The next component is C01, `splendor.identity-registry`. Foundation readiness
allows starting C01 contract and child-RFC work for `IDR-001` through `IDR-006`.

Full C01 implementation remains gated by acceptance of the Principal Registry
child RFC referenced by RFC 0008 / issue `#152`. Until that RFC is accepted, do
not implement or claim a stable Principal Registry service, proof-verifier
adapter contract, revocation propagation service, or migration mode.

## Explicit non-claims

This checkpoint does not claim:

- full `V2-FND-0` validation;
- full `FND-001..FND-012` completion;
- any gold pass status (`G00`, `G01`, `G02`, `G03`, `G04`, `G06`, `G07`,
  `G08`, `G15`, `G29`, `G35`, `G39`, `G40`, `G42`, `G47`, `G52`, `G60`,
  `G64`, `G66`, `G68`, `G70`, `G72`, `G74`, `G75`, `G78`, `G79`, `G80-G89`);
- C01 implementation;
- a `Principal` registry service;
- accepted RFC status for the Principal Registry child RFC.

## Validation

Run:

```sh
python3 conformance/0.1/run-conformance.py --format json
```

The conformance suite validates the readiness checkpoint, including that every
FND entry has evidence paths, remaining validation gaps, `not_exercised` gold
status, and non-claims. A negative fixture rejects an overclaiming foundation
status.
