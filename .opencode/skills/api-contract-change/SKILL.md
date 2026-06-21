---
name: api-contract-change
description: "API Contract Change: Use when you need to change API/contracts without surprising clients or generated artifacts."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/api-contract-change.md"
---

# API Contract Change

## Purpose

Change API/contracts without surprising clients or generated artifacts.

## Params

```yaml
  CONTRACT_FILES: "<value>"
  API_ROUTES: "<value>"
  SDK_FILES: "<value>"
  COMPAT_POLICY: "<value>"
```

## Use When

- Route changes
- Schema changes
- SDK updates
- Contract drift fixes

## Inputs

- Schemas
- Routes
- SDK clients
- Generated artifacts
- Tests

## Procedure

- Identify public request/response/error shapes affected.
- Determine compatibility: additive, breaking, deprecated, or internal-only.
- Update source schema first, then regenerate artifacts through project commands.
- Update API route mapping and SDK/client usage together.
- Add tests for valid request, invalid request, and compatibility behavior.
- Record generated hash/version when the repo uses contract evidence.
- Update docs/release notes if public behavior changes.
- Do not hand-edit generated artifacts unless repo convention requires checked-in output after generation.

## Outputs

- Schema/API/SDK updates
- Generated artifacts
- Contract tests
- Release evidence

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not change public shape silently
- Do not update docs without generation
- Do not ignore error contracts

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Source and generated artifacts agree
- Clients are not surprised
- Validation proves public behavior
