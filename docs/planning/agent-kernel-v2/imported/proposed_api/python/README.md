> **Status:** Imported vNext planning reference. This file is not part of the stable 0.1 implementation contract and is not evidence that the repository implements the described behavior. Existing `AGENTS.md`, `docs/rules/*`, `docs/spec/0.1/*`, and release limitation documents remain authoritative until an RFC is accepted and implemented. If the source text below says `normative`, that status applies only to the imported vNext source pack, not to current repository rules.

# Executable vNext reference contracts

The `splendor_vnext` reference package itself uses only the Python standard library. Its full test suite also exercises the separate PyTorch GPT fixture and therefore requires PyTorch. The package demonstrates several non-negotiable invariants from the architecture:

- scoped, narrowing capability delegation;
- immutable artifact identities;
- protected-eval isolation from training;
- feedback attached to an exact target revision;
- resource placement that preserves online/physical reservations;
- explicit PyTorch distribution planning and global-batch semantics;
- candidate/change/deployment separation;
- gated rollout and rollback state transitions.

Run:

```bash
cd proposed_api/python
python -m unittest discover -s tests -v
```

It is architecture reference code, not a replacement for the current Splendor implementation.
