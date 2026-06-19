> **Status:** Imported vNext planning reference. This file is not part of the stable 0.1 implementation contract and is not evidence that the repository implements the described behavior. Existing `AGENTS.md`, `docs/rules/*`, `docs/spec/0.1/*`, and release limitation documents remain authoritative until an RFC is accepted and implemented. If the source text below says `normative`, that status applies only to the imported vNext source pack, not to current repository rules.

# Splendor Agent Kernel vNext — Validation Summary

- **Generated:** 2026-06-18T01:52:21+00:00
- **Status:** PASS
- **Scope:** internal consistency and executable reference invariants for this architecture pack; not proof that the current Splendor kernel implements vNext.

## Results

| Check | Result | Evidence |
|---|---|---|
| vNext schema/manifests | 15 manifests validated | `02_vnext_manifests.log` |
| Gold catalog | 90 ordered cases, G00–G89, 29 assertion definitions | `03_gold_catalog.log` |
| Component ownership | 38 unique owners across all eight planes | `03b_component_registry.log` |
| Documentation | Local links and stale-ID checks | `04_documentation.log` |
| Diagrams | 15 matching Mermaid/DOT/SVG/PNG families | `06_diagram_integrity.log` |
| Python reference API | 21 tests | `08_python_tests.log` |
| GPT-2 workload plan | Serialized and parsed as JSON | `gpt2_workload_plan.json`, `09_gpt2_plan.log` |
| Tiny Transformer training | Two-step candidate-only path completed; checkpoint SHA-256 `4d250d8b96bf255d1837e151a39ad6b774b4fab310d589c89b453f53ddc140eb` | `10_tiny_training.log`, `tiny_training_output/candidate.json` |

## Claim boundary

The 90 gold cases are **specified test contracts**, not 90 implemented or passing examples. Their catalog status remains `specified_not_implemented`. The executable checks in this pack cover schema coherence, documentation/diagram integrity, reference API invariants, GPT-style model construction, and the tiny candidate-producing training path.
