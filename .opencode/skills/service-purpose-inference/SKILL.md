---
name: service-purpose-inference
description: "Service Purpose Inference: Use when you need to infer what a service is for using evidence, not naming guesses."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "02-service-integration"
  source: "skills/02-service-integration/service-purpose-inference.md"
---

# Service Purpose Inference

## Purpose

Infer what a service is for using evidence, not naming guesses.

## Params

```yaml
  SERVICE_PATH: "<value>"
  SEARCH_ROOTS: "<value>"
  DOC_PATHS: "<value>"
  TEST_PATHS: "<value>"
```

## Use When

- A service appears unused
- A module has unclear ownership
- Before wire/remove decision

## Inputs

- Source code
- Types/interfaces
- Tests
- Docs
- Migrations
- Config

## Procedure

- Read the public API, constructor params, method names, domain terms, and error types.
- Search docs/runbooks/issues for the service name and related domain terms.
- Inspect tests to see expected behavior and boundaries.
- Look for migrations, config keys, feature flags, queues, schedules, routes, or generated clients connected to the service.
- Identify whether the service is production, test helper, adapter, scaffold, duplicate, or planned future work.
- Record confidence level and evidence.
- If purpose is unclear but risk is low, create investigation issue rather than deleting.
- If purpose is clear and useful but not wired, feed to production-wiring check.

## Outputs

- Purpose statement
- Confidence rating
- Evidence list
- Next skill recommendation

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not infer from filename alone
- Do not trust stale docs without code evidence
- Do not ignore tests as purpose evidence

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Purpose is evidence-backed
- Uncertainty is explicit
- No premature deletion occurs
