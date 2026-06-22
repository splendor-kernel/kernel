# Planning Documents

This directory contains forward-looking planning material that has not yet been
accepted as a stable implementation contract.

Planning documents may describe proposed primitives, package boundaries,
conformance targets, or gold examples. They are useful for roadmap alignment,
but they do not override:

1. `AGENTS.md`
2. `docs/rules/*`
3. `docs/spec/0.1/*`
4. release notes, known limitations, and accepted RFCs

Any planning document that would change a primitive, public schema, trace event,
state format, daemon API, gateway contract, verifier pipeline, SDK contract,
governance semantics, or physical/device action model requires an RFC before
implementation.

## Current planning packs

- [`agent-kernel-v2/`](agent-kernel-v2/) — provenance and archival import notes
  for the original v2 source pack.
- Active 0.2/v2 execution rules now live under [`../rules/v2/`](../rules/v2/).
  Use [`../rules/v2/0.2-execution-sprints.md`](../rules/v2/0.2-execution-sprints.md)
  as the grouped sprint map over the v2 catalog.
