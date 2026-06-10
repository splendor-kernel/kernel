---
name: release-evidence-drift-check
description: "Release Evidence Drift Check: Use when you need to find drift between CI, scripts, generated reports, docs, release manifests, and contract/security evidence."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "05-qa-release"
  source: "skills/05-qa-release/release-evidence-drift-check.md"
---

# Release Evidence Drift Check

## Purpose

Find drift between CI, scripts, generated reports, docs, release manifests, and contract/security evidence.

## Params

```yaml
  CI_PATHS: "<value>"
  SCRIPT_PATHS: "<value>"
  DOC_PATHS: "<value>"
  REPORT_PATTERNS: "<value>"
  GENERATION_COMMANDS: "<value>"
```

## Use When

- Release readiness
- Clean arch drift discovery
- Security/contract report path changes
- Docs updates

## Inputs

- CI workflows
- Scripts
- Docs
- Generated reports
- Repo commands

## Procedure

- Search CI workflows for artifact/report paths and required files.
- Search scripts for actual generated output paths.
- Search docs/runbooks/release notes for those paths, hashes, and command examples.
- Run generation/check commands when available.
- Compare current generated paths/hashes to checked-in documentation and CI upload paths.
- Fix from a single source of truth when safe.
- Create issues when release process drift is risky or ambiguous.
- Record exact before/after evidence.

## Outputs

- Drift report
- Path/hash fixes
- Issue updates

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not hand-edit generated hashes without command evidence
- Do not update docs only
- Do not ignore CI artifact upload failures

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- CI/scripts/docs agree or drift is tracked
- Release evidence is generated, not invented
- Required artifacts are uploadable
