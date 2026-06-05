#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { SplendorClient } from "../../../../../typescript/packages/client/dist/index.js";

const input = JSON.parse(readFileSync(process.argv[2], "utf8"));
const out = process.argv[3];
const client = new SplendorClient({
  baseUrl: input.base_url,
  token: input.token,
  apiVersion: "0.1",
  defaultCredential: input.credential,
  defaultAudit: input.audit_attribution,
});

const events = [];
const record = async (operation, fn) => {
  const value = await fn();
  events.push(operation);
  return value;
};

const traceId = (record) => record?.payload?.trace_event_id;

const health = await record("getHealth", () => client.getHealth());
const version = await record("getVersion", () => client.getVersion());
const capabilities = await record("getCapabilities", () => client.getCapabilities());
const created = await record("createRun", () => client.createRun(input.create_run));
await record("appendPercept", () => client.appendPercept(input.run_id, input.percept));
const tick = await record("startRun", () => client.startRun(input.run_id, input.lifecycle));
const inspected = await record("inspectRun", () => client.inspectRun(input.run_id));
const state = await record("getStateHead", () => client.getStateHead(input.run_id));
const traces = await record("getRunTraces", () => client.readTraces(input.run_id, { redactionPolicy: "tenant-default" }));
const causal = traces.map(traceId).find(Boolean);
if (!causal) throw new Error("typescript workflow missing causal trace id");
const action = await record("submitAction", () => client.submitAction({ ...input.submit_action, causal_trace_id: causal }));
const exported = await record("exportTraces", () => client.exportTraces(input.run_id, { redactionPolicy: "tenant-default" }));
const beforeReplay = await client.inspectRun(input.run_id);
const replay = await record("replayRun", () => client.requestReplay(input.run_id));
const afterReplay = await client.inspectRun(input.run_id);
const stopped = await record("cancelRun", () => client.cancelRun(input.run_id, { ...input.lifecycle, reason: "typescript-client-workflow-cancel" }));

writeFileSync(out, JSON.stringify({
  status: "passed",
  executable_workflow: true,
  operations_observed: events,
  run_id: input.run_id,
  health_local_only: health.local_only,
  version: version.version,
  capabilities_local_only: capabilities.local_only,
  created_status: created.status,
  tick_id: tick.tick_id,
  inspect_status: inspected.status,
  state_node_id: state.state_node_id,
  trace_count: traces.length,
  action_status: action.status,
  trace_export_record_count: exported.record_count,
  replay_mode: replay.mode,
  replay_side_effects_allowed: replay.side_effects_allowed,
  adapter_executions_before_replay: beforeReplay.adapter_executions,
  adapter_executions_after_replay: afterReplay.adapter_executions,
  stopped_status: stopped.status,
}, null, 2) + "\n");
