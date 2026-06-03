# Master Loop Status — 0.05 Physical/Edge Orchestration

## Loop identity

- Loop UUID: `fe61f1a5-bb16-4136-92e0-cc82f4e6f302`
- Master loop branch: `agent/loop-fe61f1a5-bb16-4136-92e0-cc82f4e6f302`
- Master loop worktree: `/Users/db/dev/Splendor Kernel-loop-fe61f1a5-bb16-4136-92e0-cc82f4e6f302`
- Base branch: latest `origin/dev` at loop creation (`e7d7ed3`)
- Final integration PR: source `agent/loop-fe61f1a5-bb16-4136-92e0-cc82f4e6f302`, base `dev`

## Sprint scope

- Sprint IDs: `0.05*`
- Milestone: `Splendor0.05-dev`
- Sprint objective: physical/edge orchestration primitives that keep Splendor above hard real-time control while enforcing gateway-mediated, traceable, replayable, fail-closed safety boundaries.
- Issues in scope:
  - #28 — `0.05-S1 — Device profile schema`
  - #29 — `0.05-S2 — Offline policy cache`
  - #30 — `0.05-S3 — Local trace buffer`
  - #31 — `0.05-S4 — Robotics adapter interface`
  - #32 — `0.05-S5 — Safety verifier API`
  - #33 — `0.05-S6 — Cloud-helper pattern`
  - #34 — `0.05-S7 — Physical demo harness`

## Source-of-truth reading

- `AGENTS.md` — read.
- `docs/rules/splendor_dev_model.md` — supplied/read as governing model.
- `docs/rules/sprints_frs_milestones.md` — supplied/read as governing roadmap.
- `docs/rules/verifiable_criteria/main.md` — read.
- `docs/rules/verifiable_criteria/sprints/0.05-S1-device-profile-schema.md` — read.
- `docs/rules/verifiable_criteria/sprints/0.05-S2-offline-policy-cache.md` — read.
- `docs/rules/verifiable_criteria/sprints/0.05-S3-local-trace-buffer.md` — read.
- `docs/rules/verifiable_criteria/sprints/0.05-S4-robotics-adapter-interface.md` — read.
- `docs/rules/verifiable_criteria/sprints/0.05-S5-safety-verifier-api.md` — read.
- `docs/rules/verifiable_criteria/sprints/0.05-S6-cloud-helper-pattern.md` — read.
- `docs/rules/verifiable_criteria/sprints/0.05-S7-physical-demo-harness.md` — read.

## Operating constraints for all sub-agent work

- No production side effect may bypass the Action Gateway.
- Physical actions must remain high-level and bounded; no motor control, raw actuator writes, firmware safety bypass, or certification claims.
- Safety verifiers belong to the existing verifier chain; no parallel physical execution path.
- Offline operation must stay within cached policy TTL and fail closed for high-risk or uncertain actions.
- Trace events are runtime contract data, not logs; offline buffers and sync must preserve ordering and replay boundaries.
- Cloud helpers are advisory by default: proposals/artifacts/messages only, no direct actuator authority.
- 0.05 must build on 0.03 fleet/trace/work-order/messaging and 0.04 policy/governance; do not fork those models.
- Each task must update sprint docs/examples required by its criteria and provide positive, denial/failure, trace/replay, and fail-closed evidence as applicable.

## Dependency plan

1. #28 / 0.05-S1 defines physical device/capability contracts and allowed/forbidden action vocabulary.
2. #32 / 0.05-S5 defines safety verifier contracts and simulated verifier evidence; should consume #28 action/profile vocabulary.
3. #31 / 0.05-S4 defines robotics adapter interface and simulated adapter; depends on #28 and should integrate #32 verifier chain behavior.
4. #29 / 0.05-S2 extends policy cache/offline behavior; can proceed in parallel but must align with #28 physical risk/action classes and #30 trace events.
5. #30 / 0.05-S3 implements offline trace buffering/sync; can proceed in parallel and is required by #29/#34 validation.
6. #33 / 0.05-S6 cloud-helper pattern depends on #28, #31, #32, and existing 0.03 work-order/message contracts.
7. #34 / 0.05-S7 physical demo harness is final integration validation across #28-#33.

## Sub-agent assignments

| Issue | Sprint | Branch | Worktree | Status | PR | Validation | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| #28 | 0.05-S1 | `agent/28-0.05-S1` | `/Users/db/dev/Splendor Kernel-28-0.05-S1` | planned | pending | pending | Device profiles/capabilities foundation. |
| #29 | 0.05-S2 | `agent/29-0.05-S2` | `/Users/db/dev/Splendor Kernel-29-0.05-S2` | planned | pending | pending | Offline policy cache/degraded mode. |
| #30 | 0.05-S3 | `agent/30-0.05-S3` | `/Users/db/dev/Splendor Kernel-30-0.05-S3` | planned | pending | pending | Local trace buffer/reconnect sync. |
| #31 | 0.05-S4 | `agent/31-0.05-S4` | `/Users/db/dev/Splendor Kernel-31-0.05-S4` | planned | pending | pending | Robotics adapter after #28/#32 contracts. |
| #32 | 0.05-S5 | `agent/32-0.05-S5` | `/Users/db/dev/Splendor Kernel-32-0.05-S5` | planned | pending | pending | Safety verifier API. |
| #33 | 0.05-S6 | `agent/33-0.05-S6` | `/Users/db/dev/Splendor Kernel-33-0.05-S6` | planned | pending | pending | Cloud helper advisory pattern. |
| #34 | 0.05-S7 | `agent/34-0.05-S7` | `/Users/db/dev/Splendor Kernel-34-0.05-S7` | planned | pending | pending | Final physical simulation harness. |

## QA findings

- Initial scope issue: GitHub issue bodies still point to old `docs/rules/verifiable_criteria.md`; current source of truth is the split `docs/rules/verifiable_criteria/main.md` plus per-sprint files under `docs/rules/verifiable_criteria/sprints/`.
- No repo-local `.agents/skills/*/SKILL.md` files were present; no available global skill matched this task.

## Validation log

- 2026-06-03: baseline `cargo test --workspace` on loop branch passed after tracker commit (all workspace/unit/integration/doc tests completed successfully; full output captured by tooling at `/Users/db/.local/share/opencode/tool-output/tool_e8ded165a001qEHhzwbsgWJVGm`).
- Pending: per-sub-agent validation before merging each PR.
- Pending: integrated 0.05 validation after sub-agent merges.

## Integration risks

- #28/#31/#32 can conflict on physical action names and safety evidence models; enforce a single vocabulary and keep verifier integration in the existing gateway/verifier chain.
- #29/#30 can conflict on offline trace events and storage-pressure fail-closed behavior; trace durability must block side effects when required.
- #33 must not convert cloud helper output into direct physical actions; local device validation must remain the authority.
- #34 should not hide gaps with a demo-only mock path; it must exercise the production contracts built by #28-#33.

## Human-sync decisions

- None yet.

## Remaining blockers

- Sub-agent work not started.
- Final integration PR not ready.

## Final PR readiness

- Not ready. Requires validated sub-agent PRs, integrated loop branch tests, docs/examples, and issue acceptance evidence.
