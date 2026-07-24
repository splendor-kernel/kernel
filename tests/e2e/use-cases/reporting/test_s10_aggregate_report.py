#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

import aggregate_report as ar
import action_provider
import test_action_provider as provider_fixture
from acceptance_provider_evidence import (
    VERIFICATION_MATERIAL_FIELD,
    verify_evidence_envelope,
)
from acceptance_provider_output import project_private_v3_output
from acceptance_scenario_expectations import (
    PHYSICAL_COORDINATE,
    ROLE_BINDINGS,
    expectation_for,
    make_output_expectation,
)
from acceptance_provider_protocol import (
    OPERATION_MANIFEST,
    b64url_decode,
    b64url_encode,
    evidence_auth_signature,
    strict_loads,
)


def load_s10_scenario_module():
    path = (
        Path(__file__).resolve().parents[1]
        / "scenarios"
        / "uc_e2e_s10_final_journey"
        / "run.py"
    )
    spec = importlib.util.spec_from_file_location("uc_e2e_s10_final_journey_run", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load S10 scenario helper module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


S10_SCENARIO = load_s10_scenario_module()


VPC_INSTANCE = "00000000-0000-4000-8000-000000000302"
CLOUD_INSTANCE = "00000000-0000-4000-8000-000000000304"
EDGE_INSTANCE = "00000000-0000-4000-8000-000000000306"
PUBLISH_RUN = "44444444-4444-4444-8444-444444448817"
PUBLISH_ACTION_ID = "55555555-5555-4555-8555-555555558821"
TENANT_ID = "11111111-1111-4111-8111-111111111111"
AGENT_ID = "22222222-2222-4222-8222-222222222210"
PUBLISH_STATE_HEAD = "blake3:" + "1" * 64


def production_private_v3_output(
    operation_id: str,
    *,
    action_id: str,
    role: str,
    params: dict,
    expected_resource: object,
    expectation: dict | None = None,
) -> tuple[dict, dict, bytes]:
    tool = provider_fixture._verifier_path()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        private_path = root / "private.pk8"
        public_path = root / "public.raw"
        subprocess.run(
            [str(tool), "generate", str(private_path), str(public_path)],
            check=True,
            capture_output=True,
            timeout=5,
        )
        output_expectation = expectation or make_output_expectation(
            "UNIT",
            operation_id,
            operation_id,
            role,
            provider_fixture.AGENT,
            provider_fixture.RUN,
            action_id,
            expected_resource,
        )
        operation = OPERATION_MANIFEST.by_operation_id[operation_id]
        keys = provider_fixture.request_keys()
        resource_kind = None
        resource_id = None
        if operation["coordinate_rule"] == "physical_node":
            resource_kind = "physical_node"
            resource_id = expected_resource.get("node_id")
        elif operation["parameter_profile"] in {"artifact_create", "artifact_publish"}:
            resource_kind = "artifact_ref"
            resource_id = expected_resource
        elif operation["parameter_profile"] == "data_read":
            resource_kind = "data_ref"
            resource_id = expected_resource
        if resource_kind is not None:
            key_id = ROLE_BINDINGS[role]["request_key_id"]
            key = keys[key_id]
            scope = (operation_id, resource_kind, resource_id)
            keys[key_id] = action_provider.RequestKey(
                **{
                    **key.__dict__,
                    "allowed_resource_scopes": tuple(
                        sorted(set((*key.allowed_resource_scopes, scope)))
                    ),
                }
            )
        provider = provider_fixture.runtime(
            signer=action_provider.SubprocessSigner(tool, private_path),
            keys=keys,
        )
        request = provider_fixture.make_request(
            operation_id,
            role=role,
            action_id=action_id,
            request_id="66666666-6666-4666-8666-777777777777",
            agent_id=output_expectation["agent_id"],
            run_id=output_expectation["run_id"],
            params=params,
        )
        if operation["coordinate_rule"] == "physical_node":
            request["physical_action_resource_coordinate"] = copy.deepcopy(
                expected_resource
            )
            request = provider_fixture.finalize_request(request)
        response = provider_fixture.handle(provider, request)
        if response.status != 200:
            raise AssertionError(
                f"private-v3 fixture operation failed: {operation_id}: {response.status}"
            )
        envelope = provider_fixture.response_json(response)
        payload = provider_fixture.receipt_payload(response)
        output = strict_loads(
            b64url_decode(payload["output_b64"]),
            max_bytes=operation["bounds"]["max_output_bytes"],
            require_canonical=True,
        )
        output["provider_receipt"] = envelope
        projection = project_private_v3_output(
            output,
            expectation=output_expectation,
            public_key_path=public_path,
            now_ms=provider_fixture.NOW,
        )
        public_key = public_path.read_bytes()
    return output, projection, public_key


def production_private_v3_scenario_evidence(
    *, restart_second: bool = False
) -> tuple[dict, dict[str, dict], bytes]:
    tool = provider_fixture._verifier_path()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        private_path = root / "private.pk8"
        public_path = root / "public.raw"
        subprocess.run(
            [str(tool), "generate", str(private_path), str(public_path)],
            check=True,
            capture_output=True,
            timeout=5,
        )
        signer = action_provider.SubprocessSigner(tool, private_path)
        provider = provider_fixture.runtime(signer=signer)
        operation_id = "daemon.local/daemon_management_action"
        action_id = "55555555-5555-4555-8555-555555558800"
        expectation = make_output_expectation(
            "UNIT",
            "management_action",
            operation_id,
            "local",
            provider_fixture.AGENT,
            provider_fixture.RUN,
            action_id,
        )
        response = provider_fixture.handle(
            provider,
            provider_fixture.make_request(operation_id, action_id=action_id),
        )
        if response.status != 200:
            raise AssertionError(f"private-v3 marker failed: {response.status}")
        envelope = provider_fixture.response_json(response)
        payload = provider_fixture.receipt_payload(response)
        operation = OPERATION_MANIFEST.by_operation_id[operation_id]
        output = strict_loads(
            b64url_decode(payload["output_b64"]),
            max_bytes=operation["bounds"]["max_output_bytes"],
            require_canonical=True,
        )
        output["provider_receipt"] = envelope
        projection = project_private_v3_output(
            output,
            expectation=expectation,
            public_key_path=public_path,
            now_ms=provider_fixture.NOW,
        )
        public_key = public_path.read_bytes()

        def retained_evidence(
            source: action_provider.ProviderRuntime, nonce: str, now_ms: int
        ) -> dict:
            key = next(iter(source.evidence_keys.values()))
            binding = {
                "method": "GET",
                "path": "/evidence",
                "query": "view=bounded",
                "view": "bounded",
                "timestamp_unix_ms": now_ms,
                "nonce": nonce,
                "audience": key.audience,
                "key_id": key.key_id,
                "client_principal_id": key.client_principal_id,
                "provider_epoch": source.epoch,
            }
            evidence_response = source.handle_evidence(
                method="GET",
                target=action_provider.EVIDENCE_PATH,
                key_id=key.key_id,
                client_principal_id=key.client_principal_id,
                audience=key.audience,
                timestamp_ms=now_ms,
                nonce=nonce,
                provider_epoch=source.epoch,
                view="bounded",
                signature=evidence_auth_signature(binding, key.secret),
                now_ms=now_ms,
            )
            if evidence_response.status != 200:
                raise AssertionError(
                    f"private-v3 evidence failed: {evidence_response.status}"
                )
            verified = verify_evidence_envelope(
                evidence_response.body,
                public_path,
                request_binding=binding,
                now_ms=now_ms,
            )
            retained = dict(verified)
            retained[VERIFICATION_MATERIAL_FIELD] = {
                "envelope": provider_fixture.response_json(evidence_response),
                "request_binding": binding,
                "public_key_b64": b64url_encode(public_key),
                "public_key_fingerprint": "sha256:"
                + hashlib.sha256(public_key).hexdigest(),
            }
            return retained

        before = retained_evidence(
            provider, "AAECAwQFBgcICQoLDA0ODw", provider_fixture.NOW + 1
        )
        after_provider = provider
        if restart_second:
            after_provider = provider_fixture.runtime(
                signer=signer,
                epoch="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2",
            )
        after = retained_evidence(
            after_provider, "AQECAwQFBgcICQoLDA0ODw", provider_fixture.NOW + 2
        )
    return (
        {
            "private_v3_outputs": [projection],
            "provider_evidence": [before, after],
        },
        {"management_action": expectation},
        public_key,
    )


@contextmanager
def trusted_public_key_file(public_key: bytes):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "receipt-public-key.raw"
        path.write_bytes(public_key)
        path.chmod(0o644)
        yield path


def valid_security_fixture() -> tuple[dict, dict, list[dict]]:
    scoped_targets = [
        ("createRun", "runs_create", VPC_INSTANCE, "/runs", 200, "success", "POST", True),
        ("startRun", "runs_start", EDGE_INSTANCE, "/runs/run-1/start", 200, "success", "POST", True),
        ("pauseRun", "runs_pause", CLOUD_INSTANCE, "/runs/run-1/pause", 200, "success", "POST", True),
        ("resumeRun", "runs_resume", CLOUD_INSTANCE, "/runs/run-1/resume", 200, "success", "POST", True),
        ("submitAction", "actions_submit", VPC_INSTANCE, "/actions", 200, "success", "POST", True),
        ("getRunTraces", "traces_read", VPC_INSTANCE, "/runs/run-1/traces?redaction_policy=test", 200, "success", "GET", False),
        ("importStateSnapshot", "state_handoff", CLOUD_INSTANCE, "/state-snapshots/import", 503, "error", "POST", True),
        ("replayRun", "replay_create", EDGE_INSTANCE, "/runs/run-1/replay", 200, "success", "POST", True),
        ("syncCircuitBreakers", "policies_sync", VPC_INSTANCE, "/runs/run-1/governance/circuit-breakers/sync", 200, "success", "POST", True),
    ]
    calls = []
    api_rows = []
    host_by_instance = {
        VPC_INSTANCE: "resident-vpc-node",
        CLOUD_INSTANCE: "resident-cloud-node",
        EDGE_INSTANCE: "resident-edge-node",
    }
    for index, (operation, scope, instance_id, path, status, result, method, mutating) in enumerate(scoped_targets, start=1):
        credential_id = f"sha256:{index:064x}"
        call_id = f"resident-call-{index:04d}"
        credential = {
            "credential_id": credential_id,
            "scopes": [scope],
            "audience": {"instance": {"instance_id": instance_id}},
        }
        calls.append(
            {
                "call_id": call_id,
                "operation_id": operation,
                "method": method,
                "scope": scope,
                "required_scope": scope,
                "scope_expectation": "exact",
                "credential_id": credential_id,
                "target_instance_id": instance_id,
                "audience_instance_id": instance_id,
                "target_audience": f"urn:splendor:instance:{instance_id}",
                "url_scheme": "https",
                "tls_verification": "acceptance_ca",
                "header_presence": {"authorization": True, "caller_credential_mirror": True},
                "body_mirror_status": "matched" if mutating else "not_applicable",
                "redirect_policy": "disabled",
                "result_status": status,
                "expected_statuses": [status],
                "expected_result": result,
                "mutating": mutating,
                "raw_bearer_recorded": False,
                "correlation": (
                    {
                        "status": "unavailable",
                        "trace_event_ids": [],
                        "daemon_audit_trace_event_ids": [],
                        "unavailable_reason": "response_exposed_no_trace_id_and_exported_daemon_audit_attribution_was_unavailable",
                    }
                    if mutating
                    else {"status": "not_required_read_only"}
                ),
            }
        )
        row = {
            "resident_call_id": call_id,
            "operation_id": operation,
            "method": method,
            "url": f"https://{host_by_instance[instance_id]}:8091{path}",
            "status": status,
            "response": {},
            "transport": "verified_tls",
        }
        if mutating:
            row["request"] = {
                "credential": credential,
                "audit_attribution": {"credential_id": credential_id},
            }
        api_rows.append(row)
    summary = ar.derive_s10_resident_security_summary(calls)
    security = {
        "status": "passed",
        "transport": "verified_tls",
        "events": calls,
        "summary": summary,
        "all_calls_tls_verified": True,
        "all_calls_exact_one_scope": True,
        "all_calls_target_bound": True,
        "all_body_mirrors_match_verified_projection": True,
        "all_redirects_disabled": True,
        "mutating_credential_ids_unique": True,
        "all_work_orders_signed_for_target_instance": True,
        "cloud_receiver_create_import_resume_used_same_envelope": True,
        "source_and_receiver_authority_payloads_match": True,
        "raw_bearers_recorded": False,
        "local_development_work_order_key_used": False,
        "signing_profiles": {
            "vpc": {"instance_id": VPC_INSTANCE, "key_id": "work-order-acceptance-vpc"},
            "cloud": {"instance_id": CLOUD_INSTANCE, "key_id": "work-order-acceptance-cloud"},
            "edge": {"instance_id": EDGE_INSTANCE, "key_id": "work-order-acceptance-edge"},
        },
    }
    physical_actions = ["read_battery", "inspect_zone", "return_to_base"]
    profiles = {
        "artifact_profiles_split": True,
        "physical_action_allowlist": physical_actions,
        "secrets_redacted": True,
        "profiles": {
            "internal_artifact": {
                "run_id": "44444444-4444-4444-8444-444444448810",
                "allowed_actions": ["artifact.create_internal"],
                "allowed_adapters": ["artifact-store"],
                "allowed_permissions": ["artifact.create_internal"],
            },
            "external_publish": {
                "run_id": "44444444-4444-4444-8444-444444448817",
                "allowed_actions": ["artifact.publish_external"],
                "allowed_adapters": ["artifact-store"],
                "allowed_permissions": ["artifact.publish_external"],
            },
            "physical_edge": {
                "allowed_actions": physical_actions,
                "allowed_adapters": ["device-sim"],
                "allowed_permissions": ["physical.high_level"],
            },
            "cloud_receiver": {
                "signature_key_id": "work-order-acceptance-cloud",
            },
        },
    }
    return security, profiles, api_rows


def valid_approval_retry_fixture() -> tuple[dict, list[dict], list[dict], bytes]:
    artifact_ref = f"artifact://{TENANT_ID}/field-intelligence/s10-public.md"
    private_v3_output, private_v3_projection, public_key = production_private_v3_output(
        "artifact-store/artifact.publish_external",
        action_id=PUBLISH_ACTION_ID,
        role="vpc",
        params={"publish_ref": artifact_ref},
        expected_resource=artifact_ref,
        expectation=expectation_for("UC-E2E-S10", "approved_publish"),
    )
    action = {
        "name": "artifact.publish_external",
        "params": {"publish_ref": artifact_ref},
        "side_effect_class": "External",
        "required_permissions": ["artifact.publish_external"],
        "preconditions": [],
        "postconditions": [],
        "cost_estimate": None,
    }
    quota = {
        "actions": 1,
        "action_duration_ms": 1,
        "filesystem_read_bytes": 0,
        "filesystem_write_bytes": 0,
        "network_read_bytes": 0,
        "network_write_bytes": 0,
        "http_requests": 0,
    }
    challenge = {
        "approval_id": "36267d40-b425-53ad-b0f9-60afe0d81730",
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": PUBLISH_RUN,
        "action_id": PUBLISH_ACTION_ID,
        "action_name": "artifact.publish_external",
        "adapter": "artifact-store",
        "policy_id": "policy_uc_e2e_s10_artifact_publish_external",
        "subject": "2930c829-f085-4450-a1b6-037686f3ef30",
        "receipt_audience": f"splendor.daemon.approval_receipt.v2:instance:{VPC_INSTANCE}:run:{PUBLISH_RUN}",
        "authority_decision_id": "91ac7093-3411-5ca9-a279-6a543b629110",
        "authority_decision_digest": "blake3:" + "2" * 64,
        "obligation_id": "52f85249-fb42-58c2-b058-e75624a4c947",
        "canonical_request_digest": "blake3:" + "3" * 64,
        "gateway_action_request_digest": "blake3:" + "4" * 64,
        "requested_at": "2026-07-15T08:47:26Z",
        "expires_at": "2026-07-15T09:47:26Z",
    }
    grant_trace_id = "56626b3f-a980-4d9e-819a-d397e371b775"
    receipt = {
        "schema_version": "splendor.authority.obligation_receipt.v1",
        "receipt_id": "02f39efd-7817-40f8-a9df-2990a0849076",
        "issuer": "00000000-0000-4000-8000-0000000004c0",
        "kind": "approval_required",
        "approval_id": challenge["approval_id"],
        "subject": challenge["subject"],
        "audience": challenge["receipt_audience"],
        "authority_decision_id": challenge["authority_decision_id"],
        "obligation_id": challenge["obligation_id"],
        "canonical_request_digest": challenge["canonical_request_digest"],
        "evidence_digest": "blake3:" + "5" * 64,
        "expires_at": challenge["expires_at"],
        "approval_trace_event_id": grant_trace_id,
        "evidence_ref": f"approval-trace:{grant_trace_id}",
        "revocation": "active",
        "validation": {
            "digest": "blake3:" + "6" * 64,
            "signature": "[REDACTED]",
        },
    }
    approval_request = {
        "status": "requested",
        "trace_event_id": "9efd834c-44de-40be-8e5a-11558cd4ab48",
        "challenge": copy.deepcopy(challenge),
    }
    approval_grant = {
        "status": "granted",
        "approval_id": challenge["approval_id"],
        "trace_event_id": grant_trace_id,
        "challenge": copy.deepcopy(challenge),
        "authority_obligation_receipt": copy.deepcopy(receipt),
    }
    action_decision_digest = "blake3:" + "8" * 64
    approved_response = {
        "action_id": PUBLISH_ACTION_ID,
        "status": "Executed",
        "error": None,
        "output": copy.deepcopy(private_v3_output),
        "verification": {
            "allowed": True,
            "artifacts": {
                "approval": {
                    "approval": {
                        "decision": "Granted",
                        "action_id": PUBLISH_ACTION_ID,
                        "adapter": "artifact-store",
                    }
                },
                "authority": {
                    "decisions": [
                        {
                            "decision_id": challenge["authority_decision_id"],
                            "decision_digest": action_decision_digest,
                        }
                    ]
                },
                "authority_obligation": {
                    "authority_obligation_status": "satisfied",
                    "decision_id": challenge["authority_decision_id"],
                    "authority_decision_digest": challenge["authority_decision_digest"],
                    "authority_decision_evidence_digest": action_decision_digest,
                    "gateway_action_request_digest": challenge["gateway_action_request_digest"],
                    "obligation_ids": [challenge["obligation_id"]],
                    "satisfied_obligation_ids": [challenge["obligation_id"]],
                    "receipt_ids": [receipt["receipt_id"]],
                    "pre_effect_recorded": True,
                },
            },
        },
        "post_verification": {"allowed": True},
    }
    needs_approval = {
        "action_id": PUBLISH_ACTION_ID,
        "status": "NeedsApproval",
        "approval_challenge": copy.deepcopy(challenge),
        "verification": {
            "allowed": False,
            "artifacts": {"approval": {"adapter": "artifact-store"}},
        },
    }
    artifact = {
        "publish_run_id": PUBLISH_RUN,
        "publish_start": {
            "run_id": PUBLISH_RUN,
            "status": "running",
            "tick_id": 1,
            "state_node_id": PUBLISH_STATE_HEAD,
            "action_outcomes": [],
        },
        "publish_needs_approval": copy.deepcopy(needs_approval),
        "approval_request": copy.deepcopy(approval_request),
        "approval_grant": copy.deepcopy(approval_grant),
        "approved_publish": copy.deepcopy(approved_response),
        "publish_exact_action_retry": copy.deepcopy(approved_response),
        "approved_publish_evidence": {
            "private_v3_projection": copy.deepcopy(private_v3_projection),
            "trace_private_v3_projection": copy.deepcopy(private_v3_projection),
        },
        "publish_execution_count_for_positive_run": 1,
        "publish_work_order_id": "wo-publish",
        "publish_manager_submission": {
            "accepted": True,
            "work_order_id": "wo-publish",
        },
        "publish_manager_dispatch": {
            "work_order_id": "wo-publish",
            "run_id": PUBLISH_RUN,
            "selected_instance_id": VPC_INSTANCE,
            "selected_node_id": "node-vpc",
            "create_run_status": 200,
            "start_run_status": 200,
        },
    }
    admitted_action = {
        "action_id": PUBLISH_ACTION_ID,
        "action": copy.deepcopy(action),
        "adapter": "artifact-store",
        "quota_usage": copy.deepcopy(quota),
        "satisfied_preconditions": [],
    }
    exact_request = {
        "action_id": PUBLISH_ACTION_ID,
        "run_id": PUBLISH_RUN,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "causal_trace_id": "ac262256-20b8-5dd3-8a9c-d45c1f39ad8f",
        "action": copy.deepcopy(action),
        "adapter": "artifact-store",
        "quota_usage": copy.deepcopy(quota),
        "satisfied_preconditions": [],
        "requested_at": challenge["requested_at"],
        "authority_obligation_receipts": [copy.deepcopy(receipt)],
    }
    proposal_request = copy.deepcopy(exact_request)
    proposal_request.pop("authority_obligation_receipts")
    artifact["publish_exact_action_request"] = copy.deepcopy(exact_request)
    api_rows = [
        {
            "operation_id": "submitWorkOrder",
            "method": "POST",
            "url": "http://central-manager:8081/work-orders",
            "status": 200,
            "request": {"work_order": {"work_order_id": "wo-publish"}},
            "response": copy.deepcopy(artifact["publish_manager_submission"]),
        },
        {
            "operation_id": "dispatchWorkOrder",
            "method": "POST",
            "url": "http://central-manager:8081/work-orders/wo-publish/dispatch",
            "status": 200,
            "request": {"target_node_id": "node-vpc"},
            "response": copy.deepcopy(artifact["publish_manager_dispatch"]),
        },
        {
            "operation_id": "submitPublishForApproval",
            "method": "POST",
            "url": "https://resident-vpc-node:8092/actions",
            "status": 200,
            "request": copy.deepcopy(proposal_request),
            "response": copy.deepcopy(needs_approval),
        },
        {
            "operation_id": "requestApproval",
            "method": "POST",
            "url": "http://central-manager:8081/approvals",
            "status": 200,
            "request": {"challenge": copy.deepcopy(challenge)},
            "response": copy.deepcopy(approval_request),
        },
        {
            "operation_id": "grantApproval",
            "method": "POST",
            "url": f"http://central-manager:8081/approvals/{challenge['approval_id']}/grant",
            "status": 200,
            "request": {"reason": "approved"},
            "response": copy.deepcopy(approval_grant),
        },
        {
            "operation_id": "inspectPublishBeforeExactRetry",
            "method": "GET",
            "url": f"https://resident-vpc-node:8092/runs/{PUBLISH_RUN}",
            "status": 200,
            "response": {
                "status": "waiting_for_approval",
                "ticks": 1,
                "adapter_executions": 0,
                "state_head": PUBLISH_STATE_HEAD,
                "run_id": PUBLISH_RUN,
            },
        },
        {
            "operation_id": "getPublishStateBeforeExactRetry",
            "method": "GET",
            "url": f"https://resident-vpc-node:8092/runs/{PUBLISH_RUN}/state-head",
            "status": 200,
            "response": {
                "run_id": PUBLISH_RUN,
                "state_node_id": PUBLISH_STATE_HEAD,
                "data_hash": "blake3:" + "2" * 64,
                "parent_state_node_ids": [],
            },
        },
        {
            "operation_id": "submitApprovedExactAction",
            "method": "POST",
            "url": "https://resident-vpc-node:8092/actions",
            "status": 200,
            "request": exact_request,
            "response": copy.deepcopy(approved_response),
        },
        {
            "operation_id": "inspectPublishAfterExactRetry",
            "method": "GET",
            "url": f"https://resident-vpc-node:8092/runs/{PUBLISH_RUN}",
            "status": 200,
            "response": {
                "status": "running",
                "ticks": 1,
                "adapter_executions": 1,
                "state_head": PUBLISH_STATE_HEAD,
                "run_id": PUBLISH_RUN,
            },
        },
        {
            "operation_id": "getPublishStateAfterExactRetry",
            "method": "GET",
            "url": f"https://resident-vpc-node:8092/runs/{PUBLISH_RUN}/state-head",
            "status": 200,
            "response": {
                "run_id": PUBLISH_RUN,
                "state_node_id": PUBLISH_STATE_HEAD,
                "data_hash": "blake3:" + "2" * 64,
                "parent_state_node_ids": [],
            },
        },
    ]

    def trace_record(sequence: int, kind: str, body: dict, *, include_action: bool) -> dict:
        identity = {"run_id": PUBLISH_RUN}
        if include_action:
            identity["action_id"] = PUBLISH_ACTION_ID
        return {
            "sequence": sequence,
            "run_id": PUBLISH_RUN,
            "payload": {
                "sequence": sequence,
                "trace_event_id": f"00000000-0000-4000-8000-{sequence:012d}",
                "identity": identity,
                "kind": {kind: body},
            },
        }

    traces = [
        trace_record(
            10,
            "ActionNeedsApproval",
            {"action": copy.deepcopy(action)},
            include_action=True,
        ),
        trace_record(
            20,
            "ActionExecuted",
            {
                "action": copy.deepcopy(action),
                "outcome": copy.deepcopy(private_v3_output),
            },
            include_action=True,
        ),
        trace_record(
            21,
            "RunResumed",
            {"reason": "exact approved action executed"},
            include_action=False,
        ),
    ]
    return artifact, api_rows, traces, public_key


def validate_approval_retry_fixture(
    artifact: dict, api_rows: list[dict], traces: list[dict], public_key: bytes
) -> list[str]:
    with trusted_public_key_file(public_key) as trusted_key:
        return ar.validate_s10_approval_exact_retry(
            artifact, api_rows, traces, trusted_key
        )


class PrivateV3AggregateEvidenceTests(unittest.TestCase):
    def test_accepts_production_signed_output_and_evidence(self) -> None:
        scenario, expectations, public_key = production_private_v3_scenario_evidence()
        with trusted_public_key_file(public_key) as trusted_key:
            self.assertEqual(
                ar.validate_private_v3_scenario_evidence(
                    scenario,
                    expectations,
                    trusted_key,
                    "unit",
                ),
                [],
            )

    def test_rejects_restart_epoch_substitution(self) -> None:
        scenario, expectations, public_key = production_private_v3_scenario_evidence(
            restart_second=True
        )
        with trusted_public_key_file(public_key) as trusted_key:
            failures = ar.validate_private_v3_scenario_evidence(
                scenario,
                expectations,
                trusted_key,
                "unit",
            )
        self.assertIn("unit_provider_evidence_epoch_inconsistent:1", failures)
        self.assertIn("unit_provider_output_evidence_epoch_mismatch", failures)

    def test_rejects_missing_wrong_and_attacker_selected_trust(self) -> None:
        legitimate, expectations, legitimate_key = production_private_v3_scenario_evidence()
        attacker, attacker_expectations, attacker_key = (
            production_private_v3_scenario_evidence()
        )
        self.assertNotEqual(legitimate_key, attacker_key)

        missing = ar.validate_private_v3_scenario_evidence(
            legitimate,
            expectations,
            Path("/definitely/missing/private-v3-trust-root.raw"),
            "missing",
        )
        self.assertTrue(
            any(item.startswith("missing_private_v3_output_invalid:") for item in missing)
        )
        self.assertTrue(
            any(item.startswith("missing_signed_provider_evidence_invalid:") for item in missing)
        )

        with trusted_public_key_file(attacker_key) as wrong_key:
            wrong = ar.validate_private_v3_scenario_evidence(
                legitimate, expectations, wrong_key, "wrong"
            )
        self.assertTrue(
            any(item.startswith("wrong_private_v3_output_invalid:") for item in wrong)
        )
        self.assertTrue(
            any(item.startswith("wrong_signed_provider_evidence_invalid:") for item in wrong)
        )

        with trusted_public_key_file(legitimate_key) as trusted_key:
            forged = ar.validate_private_v3_scenario_evidence(
                attacker, attacker_expectations, trusted_key, "attacker"
            )
        self.assertTrue(
            any(item.startswith("attacker_private_v3_output_invalid:") for item in forged)
        )
        self.assertTrue(
            any(item.startswith("attacker_signed_provider_evidence_invalid:") for item in forged)
        )

    def test_rejects_embedded_key_id_and_fingerprint_substitution(self) -> None:
        scenario, expectations, public_key = production_private_v3_scenario_evidence()
        mutations = {
            "projection_fingerprint": lambda value: value["private_v3_outputs"][0].__setitem__(
                "public_key_fingerprint", "sha256:" + "0" * 64
            ),
            "projection_key_id": lambda value: value["private_v3_outputs"][0][
                "output"
            ]["provider_receipt"].__setitem__("signing_key_id", "attacker-key"),
            "evidence_fingerprint": lambda value: value["provider_evidence"][0][
                "_evidence_verification"
            ].__setitem__("public_key_fingerprint", "sha256:" + "0" * 64),
            "evidence_key_id": lambda value: value["provider_evidence"][0][
                "_evidence_verification"
            ]["envelope"].__setitem__("signing_key_id", "attacker-key"),
        }
        with trusted_public_key_file(public_key) as trusted_key:
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    changed = copy.deepcopy(scenario)
                    mutate(changed)
                    failures = ar.validate_private_v3_scenario_evidence(
                        changed, expectations, trusted_key, label
                    )
                    self.assertTrue(
                        any("invalid" in failure for failure in failures), failures
                    )

    def test_rejects_genuine_receipts_for_wrong_bound_identity_or_resource(self) -> None:
        canonical = expectation_for("UC-E2E-S10", "approved_publish")
        variants = {
            "artifact": make_output_expectation(
                canonical["scenario_id"],
                canonical["expectation_id"],
                canonical["operation_id"],
                "vpc",
                canonical["agent_id"],
                canonical["run_id"],
                canonical["action_id"],
                f"artifact://{canonical['tenant_id']}/field-intelligence/other.md",
            ),
            "run": make_output_expectation(
                canonical["scenario_id"], canonical["expectation_id"],
                canonical["operation_id"], "vpc", canonical["agent_id"],
                "44444444-4444-4444-8444-444444448899",
                canonical["action_id"], canonical["resource"],
            ),
            "agent": make_output_expectation(
                canonical["scenario_id"], canonical["expectation_id"],
                canonical["operation_id"], "vpc",
                "22222222-2222-4222-8222-222222222299",
                canonical["run_id"], canonical["action_id"], canonical["resource"],
            ),
            "action": make_output_expectation(
                canonical["scenario_id"], canonical["expectation_id"],
                canonical["operation_id"], "vpc", canonical["agent_id"],
                canonical["run_id"], "55555555-5555-4555-8555-555555558899",
                canonical["resource"],
            ),
            "role": make_output_expectation(
                canonical["scenario_id"], canonical["expectation_id"],
                canonical["operation_id"], "local", canonical["agent_id"],
                canonical["run_id"], canonical["action_id"], canonical["resource"],
            ),
        }
        for label, variant in variants.items():
            with self.subTest(label=label):
                output, projection, public_key = production_private_v3_output(
                    variant["operation_id"],
                    action_id=variant["action_id"],
                    role=variant["request_principal_role"],
                    params={"publish_ref": variant["resource"]},
                    expected_resource=variant["resource"],
                    expectation=variant,
                )
                with trusted_public_key_file(public_key) as trusted_key:
                    self.assertEqual(
                        ar.validate_exact_private_v3_output(
                            output,
                            projection,
                            canonical,
                            trusted_key,
                            f"wrong_{label}",
                        ),
                        [f"wrong_{label}"],
                    )

        for label, scenario_id, expectation_id, resource, params in (
            (
                "data_ref",
                "UC-E2E-S10",
                "orchestrator_data_read",
                "dataset:tenant-a.field-intel.other.v1",
                {"data_ref": "dataset:tenant-a.field-intel.other.v1"},
            ),
            (
                "physical_node",
                "UC-E2E-S6",
                "approved_capture",
                {"resource_kind": "physical_node", "node_id": "00000000-0000-4000-8000-000000000605"},
                {"physical_action": True},
            ),
        ):
            canonical_resource = expectation_for(scenario_id, expectation_id)
            variant = make_output_expectation(
                canonical_resource["scenario_id"],
                canonical_resource["expectation_id"],
                canonical_resource["operation_id"],
                canonical_resource["request_principal_role"],
                canonical_resource["agent_id"],
                canonical_resource["run_id"],
                canonical_resource["action_id"],
                resource,
            )
            output, projection, public_key = production_private_v3_output(
                variant["operation_id"],
                action_id=variant["action_id"],
                role=variant["request_principal_role"],
                params=params,
                expected_resource=resource,
                expectation=variant,
            )
            with self.subTest(label=label), trusted_public_key_file(
                public_key
            ) as trusted_key:
                self.assertEqual(
                    ar.validate_exact_private_v3_output(
                        output,
                        projection,
                        canonical_resource,
                        trusted_key,
                        f"wrong_{label}",
                    ),
                    [f"wrong_{label}"],
                )


class S2CanonicalOperationTests(unittest.TestCase):
    def test_required_operations_are_canonical_public_openapi_operations(self) -> None:
        self.assertEqual(
            {
                "getHealth",
                "getVersion",
                "getCapabilities",
                "createRun",
                "inspectRun",
                "startRun",
                "pauseRun",
                "resumeRun",
                "cancelRun",
                "appendPercept",
                "submitAction",
                "getStateHead",
                "getRunTraces",
                "exportTraces",
                "replayRun",
            },
            ar.S2_REQUIRED_OPERATIONS,
        )


class S10ResidentSecurityReportTests(unittest.TestCase):
    def test_get_run_traces_resolves_to_exact_read_scope(self) -> None:
        self.assertEqual(
            "traces_read",
            ar.s10_resident_required_scope(
                "GET",
                "https://resident-vpc-node:8092/runs/run-1/traces?redaction_policy=test",
            ),
        )

    def test_accepts_fresh_target_bound_exact_profiles(self) -> None:
        security, profiles, api_rows = valid_security_fixture()
        self.assertEqual([], ar.validate_s10_resident_security(security, profiles, api_rows, []))
        self.assertEqual(1, security["summary"]["read_only_calls"])

    def test_rejects_get_run_traces_with_wrong_scope(self) -> None:
        security, profiles, api_rows = valid_security_fixture()
        trace_event = next(
            event for event in security["events"] if event["operation_id"] == "getRunTraces"
        )
        trace_event["scope"] = "runs_read"
        failures = ar.validate_s10_resident_security(security, profiles, api_rows, [])
        self.assertTrue(
            any(failure.startswith("s10_resident_per_call_evidence_invalid:") for failure in failures)
        )
        self.assertIn("s10_resident_security_summary_event_mismatch", failures)

    def test_rejects_reused_mutating_jti(self) -> None:
        security, profiles, api_rows = valid_security_fixture()
        security["events"][1]["credential_id"] = security["events"][0]["credential_id"]
        self.assertIn(
            "s10_resident_mutating_jti_reuse_or_missing_calls",
            ar.validate_s10_resident_security(security, profiles, api_rows, []),
        )

    def test_rejects_true_summary_with_missing_calls(self) -> None:
        security, profiles, api_rows = valid_security_fixture()
        security["events"] = security["events"][:-1]
        security["status"] = "passed"
        security["summary"]["status"] = "passed"
        failures = ar.validate_s10_resident_security(security, profiles, api_rows, [])
        self.assertIn("s10_resident_event_api_traffic_cardinality_mismatch", failures)
        self.assertIn("s10_resident_security_summary_event_mismatch", failures)

    def test_rejects_plaintext_redirect_enabled_or_missing_bearer_evidence(self) -> None:
        security, profiles, api_rows = valid_security_fixture()
        security["events"][0]["url_scheme"] = "http"
        security["events"][1]["redirect_policy"] = "follow"
        security["events"][2]["header_presence"]["authorization"] = False
        api_rows[0]["url"] = api_rows[0]["url"].replace("https://", "http://")
        failures = ar.validate_s10_resident_security(security, profiles, api_rows, [])
        self.assertTrue(any(failure.startswith("s10_resident_per_call_evidence_invalid:") for failure in failures))
        self.assertIn("s10_resident_security_summary_event_mismatch", failures)

    def test_rejects_broad_artifact_and_per_action_physical_permissions(self) -> None:
        security, profiles, api_rows = valid_security_fixture()
        broken = copy.deepcopy(profiles)
        broken["profiles"]["internal_artifact"]["allowed_permissions"].append(
            "artifact.publish_external"
        )
        broken["profiles"]["physical_edge"]["allowed_permissions"] = [
            "physical.inspect_zone"
        ]
        failures = ar.validate_s10_resident_security(security, broken, api_rows, [])
        self.assertIn("s10_internal_artifact_profile_not_exact", failures)
        self.assertIn("s10_physical_profile_not_high_level_exact", failures)


class S10ApprovalExactRetryTests(unittest.TestCase):
    def test_accepts_independently_correlated_exact_retry(self) -> None:
        artifact, api_rows, traces, public_key = valid_approval_retry_fixture()
        self.assertEqual(
            [], validate_approval_retry_fixture(artifact, api_rows, traces, public_key)
        )

    def test_rejects_changed_action_payload(self) -> None:
        artifact, api_rows, traces, public_key = valid_approval_retry_fixture()
        retry = next(
            row for row in api_rows if row["operation_id"] == "submitApprovedExactAction"
        )
        retry["request"]["action"]["params"]["publish_ref"] = "artifact://wrong/payload"
        failures = validate_approval_retry_fixture(artifact, api_rows, traces, public_key)
        self.assertIn("s10_approved_exact_action_proposal_mismatch:action", failures)
        self.assertIn("s10_approved_exact_action_artifact_mismatch:action", failures)

    def test_rejects_wrong_receipt_audience(self) -> None:
        artifact, api_rows, traces, public_key = valid_approval_retry_fixture()
        retry = next(
            row for row in api_rows if row["operation_id"] == "submitApprovedExactAction"
        )
        retry["request"]["authority_obligation_receipts"][0]["audience"] = (
            "splendor.daemon.run:wrong"
        )
        self.assertIn(
            "s10_approved_exact_action_receipt_not_manager_issued",
            validate_approval_retry_fixture(artifact, api_rows, traces, public_key),
        )

    def test_rejects_raw_approval_evidence(self) -> None:
        artifact, api_rows, traces, public_key = valid_approval_retry_fixture()
        retry = next(
            row for row in api_rows if row["operation_id"] == "submitApprovedExactAction"
        )
        retry["request"]["approval_evidence"] = {"decision": "Granted"}
        self.assertIn(
            "s10_approved_exact_action_used_raw_approval_evidence",
            validate_approval_retry_fixture(artifact, api_rows, traces, public_key),
        )

    def test_rejects_publish_lifecycle_resume(self) -> None:
        artifact, api_rows, traces, public_key = valid_approval_retry_fixture()
        api_rows.append(
            {
                "operation_id": "resumeRun",
                "method": "POST",
                "url": f"https://resident-vpc-node:8092/runs/{PUBLISH_RUN}/resume",
                "status": 409,
                "request": {},
                "response": {},
            }
        )
        self.assertIn(
            "s10_approved_publish_used_lifecycle_resume",
            validate_approval_retry_fixture(artifact, api_rows, traces, public_key),
        )

    def test_rejects_tick_or_state_head_change(self) -> None:
        for field, value, expected in [
            ("ticks", 2, "s10_approved_exact_action_advanced_tick"),
            (
                "state_head",
                "blake3:" + "9" * 64,
                "s10_approved_exact_action_advanced_state_head",
            ),
        ]:
            with self.subTest(field=field):
                artifact, api_rows, traces, public_key = valid_approval_retry_fixture()
                after = next(
                    row
                    for row in api_rows
                    if row["operation_id"] == "inspectPublishAfterExactRetry"
                )
                after["response"][field] = value
                self.assertIn(
                    expected,
                    validate_approval_retry_fixture(
                        artifact, api_rows, traces, public_key
                    ),
                )


class S10ManagerApprovalAuthReportTests(unittest.TestCase):
    def fixture(self) -> tuple[dict, list[dict]]:
        events = []
        rows = []
        operations = [
            ("requestApproval", 200),
            ("grantApproval", 200),
            ("revokeApprovalClaimFirst", 409),
            ("requestRevocableApproval", 200),
            ("grantRevocableApproval", 200),
            ("revokeApproval", 200),
        ]
        for index, (operation, status) in enumerate(operations, start=1):
            call_id = f"manager-approval-call-{index:04d}"
            credential_id = f"sha256:{index:064x}"
            credential = {
                "credential_id": credential_id,
                "principal": {
                    "app": {"app_principal_id": "central-manager", "label": None},
                    "client_principal_id": "approval-management-client",
                    "label": None,
                },
                "scopes": ["approvals_manage"],
                "binding": {
                    "fleet": {
                        "fleet_id": "00000000-0000-4000-8000-000000000104"
                    }
                },
                "audience": {
                    "central_manager": {"manager_id": "central-manager"}
                },
            }
            trace_id = f"00000000-0000-4000-8000-{index:012d}"
            trace_ids = [trace_id] if status == 200 else []
            events.append(
                {
                    "call_id": call_id,
                    "operation_id": operation,
                    "method": "POST",
                    "scope": "approvals_manage",
                    "required_scope": "approvals_manage",
                    "credential_id": credential_id,
                    "fleet_id": "00000000-0000-4000-8000-000000000104",
                    "target_manager_id": "central-manager",
                    "audience_manager_id": "central-manager",
                    "header_presence": {"authorization": True},
                    "body_mirror_status": "matched",
                    "result_status": status,
                    "expected_statuses": [status],
                    "expected_result": "success" if status == 200 else "error",
                    "trace_event_ids": trace_ids,
                    "raw_bearer_recorded": False,
                    "raw_jti_recorded": False,
                    "receipt_signature_recorded": False,
                }
            )
            rows.append(
                {
                    "manager_approval_call_id": call_id,
                    "operation_id": operation,
                    "method": "POST",
                    "url": "http://central-manager:8081/approvals",
                    "status": status,
                    "transport": "local_acceptance_http",
                    "request": {
                        "credential": credential,
                        "audit_attribution": {
                            "credential_id": credential_id,
                            "principal": credential["principal"],
                        },
                    },
                    "response": (
                        {"trace_event_id": trace_id}
                        if status == 200
                        else {"code": "approval_receipt_revocation_too_late"}
                    ),
                }
            )
        return (
            {
                "status": "passed",
                "mode": "local_acceptance",
                "events": events,
                "fresh_mutating_credential_ids": True,
                "exact_scope": "approvals_manage",
                "raw_bearers_recorded": False,
                "raw_jtis_recorded": False,
                "receipt_signatures_recorded": False,
                "production_manager_auth_claimed": False,
                "other_manager_endpoints_authenticated_by_this_profile": False,
            },
            rows,
        )

    def test_accepts_token_free_fresh_manager_approval_auth_evidence(self) -> None:
        report, rows = self.fixture()
        self.assertEqual([], ar.validate_s10_manager_approval_auth(report, rows))

    def test_rejects_replayed_or_raw_manager_approval_bearer_evidence(self) -> None:
        report, rows = self.fixture()
        report["events"][1]["credential_id"] = report["events"][0]["credential_id"]
        rows[0]["authorization"] = "Bearer raw-secret"
        failures = ar.validate_s10_manager_approval_auth(report, rows)
        self.assertIn("s10_manager_approval_auth_jti_reused", failures)
        self.assertTrue(
            any(
                failure.startswith("s10_manager_approval_auth_event_invalid:")
                for failure in failures
            )
        )


def valid_s10_active_raw_fixture() -> tuple[dict, list[dict]]:
    run = {
        "run_id": PUBLISH_RUN,
        "status": "waiting_for_approval",
        "ticks": 1,
        "state_head": "blake3:" + "1" * 64,
        "adapter_executions": 0,
    }
    state = {
        "run_id": PUBLISH_RUN,
        "state_node_id": "00000000-0000-4000-8000-000000001011",
        "data_hash": "blake3:" + "2" * 64,
        "parent_state_node_ids": [],
    }
    denial = {"code": "legacy_approval_evidence_non_authorizing"}
    artifact = {
        "expired_approval": {"body": denial},
        "expired_raw_active_run": {
            "run_before": run,
            "state_before": state,
            "lifecycle_unchanged": True,
            "state_unchanged": True,
            "pre_gateway_rejected_unchanged": True,
            "no_new_approval_action_outcome_trace": True,
            "decision_trace_ids_before": [],
            "decision_trace_ids_after": [],
        },
    }

    def row(operation: str, response: dict, method: str = "GET") -> dict:
        return {
            "operation_id": operation,
            "method": method,
            "url": "https://resident.test/actions" if method == "POST" else "https://resident.test/inspect",
            "status": 409 if method == "POST" else 200,
            "request": (
                {"approval_evidence": {"decision": "Granted"}}
                if method == "POST"
                else {}
            ),
            "response": copy.deepcopy(response),
        }

    rows = [
        row("inspectPublishBeforeExpiredRaw", run),
        row("getPublishStateBeforeExpiredRaw", state),
        row("getPublishTracesBeforeExpiredRaw", {"records": []}),
        row("submitExpiredRawApprovalOnActiveRun", denial, "POST"),
        row("inspectPublishAfterExpiredRaw", run),
        row("getPublishStateAfterExpiredRaw", state),
        row("getPublishTracesAfterExpiredRaw", {"records": []}),
    ]
    return artifact, rows


class S10ActiveRawRejectionReportTests(unittest.TestCase):
    def test_accepts_active_raw_pre_gateway_rejection(self) -> None:
        artifact, rows = valid_s10_active_raw_fixture()
        self.assertEqual([], ar.validate_s10_active_raw_rejection(artifact, rows))

    def test_rejects_status_order_tick_state_trace_and_cardinality_mutations(self) -> None:
        artifact, rows = valid_s10_active_raw_fixture()
        raw_index = next(
            index
            for index, row in enumerate(rows)
            if row["operation_id"] == "submitExpiredRawApprovalOnActiveRun"
        )
        raw = rows[raw_index]
        raw["status"] = 200
        rows[raw_index], rows[raw_index - 1] = rows[raw_index - 1], rows[raw_index]
        next(
            row
            for row in rows
            if row["operation_id"] == "inspectPublishAfterExpiredRaw"
        )["response"]["ticks"] = 2
        next(
            row
            for row in rows
            if row["operation_id"] == "getPublishStateAfterExpiredRaw"
        )["response"]["data_hash"] = "blake3:" + "f" * 64
        next(
            row
            for row in rows
            if row["operation_id"] == "getPublishTracesAfterExpiredRaw"
        )["response"]["records"].append(
            {
                "payload": {
                    "trace_event_id": "00000000-0000-4000-8000-000000001012",
                    "kind": "action.denied",
                }
            }
        )
        failures = ar.validate_s10_active_raw_rejection(artifact, rows)
        self.assertIn("s10_active_raw_api_order_invalid", failures)
        self.assertIn("s10_active_raw_not_pre_gateway_rejected", failures)
        self.assertIn("s10_active_raw_changed_lifecycle_tick_state_or_effect", failures)
        self.assertIn("s10_active_raw_appended_decision_trace", failures)

        artifact, rows = valid_s10_active_raw_fixture()
        rows.append(copy.deepcopy(rows[-1]))
        self.assertIn(
            "s10_active_raw_api_cardinality_invalid",
            ar.validate_s10_active_raw_rejection(artifact, rows),
        )


def valid_s5_approval_remediation_fixture() -> tuple[dict, list[dict]]:
    run_id = "00000000-0000-4000-8000-000000000501"
    instance_id = "00000000-0000-4000-8000-000000000502"
    approval_id = "00000000-0000-4000-8000-000000000503"
    receipt_id = "00000000-0000-4000-8000-000000000504"
    audience = (
        "splendor.daemon.approval_receipt.v2:instance:"
        f"{instance_id}:run:{run_id}"
    )
    run = {
        "run_id": run_id,
        "status": "waiting_for_approval",
        "ticks": 1,
        "state_head": "blake3:" + "5" * 64,
        "adapter_executions": 0,
    }
    state = {
        "state_node_id": "00000000-0000-4000-8000-000000000505",
        "state_hash": "blake3:" + "6" * 64,
    }
    receipt = {
        "schema_version": "splendor.authority.obligation_receipt.v1",
        "receipt_id": receipt_id,
        "approval_id": approval_id,
        "audience": audience,
        "revocation": "active",
        "validation": {
            "algorithm": "ed25519",
            "digest": "sha256:" + "7" * 64,
            "key_id": "manager-key",
            "validation_kind": "detached_signature",
            "signature": "[REDACTED]",
        },
    }
    acknowledgement = {
        "schema_version": "splendor.resident.approval_receipt_revocation_ack.v1",
        "status": "revoked",
        "effect_certainty": "known",
        "receipt_id": receipt_id,
        "approval_id": approval_id,
        "receipt_audience": audience,
        "target_instance_id": instance_id,
        "run_id": run_id,
    }
    request = {"approval_id": approval_id, "status": "requested"}
    work_order_admission = {"work_order_id": "wo-s5-revocable", "status": "accepted"}
    dispatch = {
        "selected_instance_id": instance_id,
        "run_id": run_id,
        "status": "dispatched",
    }
    proposal = {"status": "NeedsApproval", "approval_id": approval_id}
    retry_denial = {
        "status": "Denied",
        "error": "authority_obligation_receipt_revoked",
        "output": None,
        "verification": {
            "reasons": ["authority_obligation_receipt_revoked"]
        },
    }
    expired_denial = {
        "status": "Denied",
        "error": "approval_expired",
        "output": None,
        "verification": {"reasons": ["approval_expired"]},
    }
    report = {
        "request": request,
        "expired": expired_denial,
        "active_run_expired_raw_rejection": {
            "run_id": run_id,
            "before": copy.deepcopy(run),
            "classification": "pre_gateway_run_action_admission_rejection",
            "gateway_invoked": False,
            "http_status": 409,
            "code": "legacy_approval_evidence_non_authorizing",
            "adapter_effect_delta": 0,
            "appended_trace_event_ids": [],
            "approval_trace_records": [],
            "trace_ids_before": [],
            "trace_ids_after": [],
        },
        "revoke": {"resident_receipt_revocation_ack": acknowledgement},
        "resident_receipt_revocation": {
            "work_order_admission": work_order_admission,
            "dispatch": dispatch,
            "proposal": proposal,
            "retained_receipt": receipt,
            "acknowledgement": acknowledgement,
            "revoked_receipt_retry": {"body": retry_denial},
            "state": {"before_manager_revoke": state},
            "action_executed_trace_records": [],
            "resident_revocation_authentication": [
                {
                    "required_scope": "splendor.approval_receipts.revoke",
                    "tls_verification": "acceptance_ca",
                    "target_instance_id": instance_id,
                    "run_id": run_id,
                    "receipt_id": receipt_id,
                    "ack_status": "revoked",
                    "raw_bearer_recorded": False,
                    "raw_jti_recorded": False,
                    "receipt_signature_recorded": False,
                }
            ],
        },
    }

    def row(
        operation: str,
        status: int,
        response: dict,
        request_body: dict | None = None,
        path: str = "/unused",
    ) -> dict:
        return {
            "operation_id": operation,
            "method": "POST",
            "url": f"https://resident.test{path}",
            "status": status,
            "request": request_body or {},
            "response": copy.deepcopy(response),
        }

    rows = [
        row("inspectRunBeforeExpiredRaw", 200, run),
        row(
            "submitExpiredRawEvidenceOnActiveRun",
            409,
            {"code": "legacy_approval_evidence_non_authorizing"},
            {"approval_evidence": {"decision": "Granted"}},
            "/actions",
        ),
        row("inspectRunAfterExpiredRaw", 200, run),
        row(
            "submitExpiredExactWaitingApproval",
            200,
            expired_denial,
            {"approval_evidence": {"decision": "Granted"}},
            "/actions",
        ),
        row("submitRevocableWorkOrder", 200, work_order_admission),
        row("dispatchRevocableWorkOrder", 200, dispatch),
        row("submitRevocableAction", 200, proposal),
        row("requestRevocableApproval", 200, request),
        row(
            "grantRevocableApproval",
            200,
            {"authority_obligation_receipt": receipt},
        ),
        row("inspectRevocableBeforeManagerRevoke", 200, run),
        row(
            "revokeApproval",
            200,
            {"resident_receipt_revocation_ack": acknowledgement},
        ),
        row("inspectRevocableAfterManagerRevoke", 200, run),
        row(
            "submitRevokedOriginalReceipt",
            200,
            retry_denial,
            {"authority_obligation_receipts": [receipt]},
            "/actions",
        ),
        row("inspectRevocableAfterDeniedRetry", 200, run),
        row("getRevocableStateAfterDeniedRetry", 200, state),
    ]
    return report, rows


class S5ApprovalRemediationReportTests(unittest.TestCase):
    def test_accepts_active_raw_expiry_and_resident_revocation_evidence(self) -> None:
        report, rows = valid_s5_approval_remediation_fixture()
        self.assertEqual([], ar.validate_s5_approval_remediation(report, rows))

    def test_rejects_raw_admission_status_and_lifecycle_mutations(self) -> None:
        report, rows = valid_s5_approval_remediation_fixture()
        raw_row = next(
            row
            for row in rows
            if row["operation_id"] == "submitExpiredRawEvidenceOnActiveRun"
        )
        after_row = next(
            row
            for row in rows
            if row["operation_id"] == "inspectRunAfterExpiredRaw"
        )
        raw_row["status"] = 200
        after_row["response"]["ticks"] = 2
        failures = ar.validate_s5_approval_remediation(report, rows)
        self.assertIn("s5_active_raw_not_pre_gateway_rejected", failures)
        self.assertIn("s5_active_raw_lifecycle_or_effect_changed", failures)

    def test_rejects_revocation_ack_order_state_and_effect_mutations(self) -> None:
        report, rows = valid_s5_approval_remediation_fixture()
        report["resident_receipt_revocation"]["acknowledgement"][
            "effect_certainty"
        ] = "unknown"
        after_row = next(
            row
            for row in rows
            if row["operation_id"] == "inspectRevocableAfterDeniedRetry"
        )
        after_row["response"]["adapter_executions"] = 1
        revoke_index = next(
            index
            for index, row in enumerate(rows)
            if row["operation_id"] == "revokeApproval"
        )
        retry_index = next(
            index
            for index, row in enumerate(rows)
            if row["operation_id"] == "submitRevokedOriginalReceipt"
        )
        rows[revoke_index], rows[retry_index] = rows[retry_index], rows[revoke_index]
        failures = ar.validate_s5_approval_remediation(report, rows)
        self.assertIn("s5_resident_revocation_api_order_invalid", failures)
        self.assertIn("s5_resident_revocation_ack_not_exact", failures)
        self.assertIn("s5_resident_revocation_changed_tick_state_or_effect", failures)

    def test_rejects_revocation_api_cardinality_mutation(self) -> None:
        report, rows = valid_s5_approval_remediation_fixture()
        rows.append(copy.deepcopy(rows[-1]))
        failures = ar.validate_s5_approval_remediation(report, rows)
        self.assertIn("s5_resident_revocation_api_cardinality_invalid", failures)

    def test_rejects_retained_receipt_signature(self) -> None:
        report, rows = valid_s5_approval_remediation_fixture()
        report["resident_receipt_revocation"]["retained_receipt"]["validation"][
            "signature"
        ] = "raw-signature"
        self.assertIn(
            "s5_retained_evidence_contains_receipt_signature",
            ar.validate_s5_approval_remediation(report, rows),
        )


def valid_s6_physical_approval_fixture() -> tuple[dict, dict, list[dict]]:
    output_expectation = expectation_for("UC-E2E-S6", "approved_capture")
    run_id = output_expectation["run_id"]
    action_id = output_expectation["action_id"]
    agent_id = output_expectation["agent_id"]
    node_a = "00000000-0000-4000-8000-000000000604"
    node_b = "00000000-0000-4000-8000-000000000605"
    instance_id = "00000000-0000-4000-8000-000000000605"
    work_order_id = "00000000-0000-4000-8000-000000000606"
    audience = (
        "splendor.daemon.approval_receipt.v2:instance:"
        f"{instance_id}:run:{run_id}"
    )
    challenge = {
        "physical_action_resource_coordinate": {
            "resource_kind": "physical_node",
            "node_id": node_a,
        },
        "canonical_request_digest": "sha256:" + "1" * 64,
        "gateway_action_request_digest": "sha256:" + "2" * 64,
        "authority_decision_digest": "sha256:" + "3" * 64,
        "receipt_audience": audience,
    }
    receipt = {
        "schema_version": "splendor.authority.obligation_receipt.v1",
        "receipt_id": "00000000-0000-4000-8000-000000000607",
        "approval_id": "00000000-0000-4000-8000-000000000608",
        "audience": audience,
        "revocation": "active",
        "validation": {
            "algorithm": "ed25519",
            "digest": "sha256:" + "4" * 64,
            "key_id": "manager-key",
            "validation_kind": "detached_signature",
            "signature": "[REDACTED]",
        },
    }
    work_order_submit = {"work_order_id": work_order_id, "status": "accepted"}
    dispatch = {
        "selected_node_id": node_a,
        "selected_instance_id": instance_id,
        "run_id": run_id,
    }
    coordinate_error = {"code": "unknown_field", "field": "physical_action_resource_coordinate"}
    authority_error = {"code": "unknown_field", "field": "authority_override"}
    wrong_body = {"code": "approval_challenge_retry_mismatch"}
    physical_coordinate = {"resource_kind": "physical_node", "node_id": node_a}
    private_v3_output, _, _ = production_private_v3_output(
        "device-sim/capture_image",
        action_id=action_id,
        role="edge",
        params={"physical_action": True},
        expected_resource=physical_coordinate,
        expectation=output_expectation,
    )
    exact_action = {
        "name": "capture_image",
        "params": {"physical_action": True},
        "side_effect_class": {"Custom": "physical.high_level"},
        "cost_estimate": None,
        "required_permissions": ["physical.high_level"],
        "preconditions": [],
        "postconditions": ["device_state_updated"],
    }
    exact_quota = {
        "actions": 1,
        "action_duration_ms": 0,
        "filesystem_read_bytes": 0,
        "filesystem_write_bytes": 0,
        "network_read_bytes": 0,
        "network_write_bytes": 0,
        "http_requests": 0,
    }
    challenge_request = {
        "action_id": action_id,
        "run_id": run_id,
        "tenant_id": output_expectation["tenant_id"],
        "agent_id": agent_id,
        "causal_trace_id": "55555555-5555-4555-8555-555555555651",
        "action": exact_action,
        "adapter": "device-sim",
        "quota_usage": exact_quota,
        "satisfied_preconditions": [],
        "requested_at": "2026-07-15T08:47:26Z",
        "approval_evidence": None,
        "authority_obligation_receipts": [],
        "safety_context": {"offline": False, "high_risk": False},
        "operator_intervention_evidence": None,
    }
    executed = {
        "status": "Executed",
        "output": private_v3_output,
        "verification": {"artifacts": {"safety": {"source": "safety_verifier"}}},
        "post_verification": {
            "artifacts": {"safety": {"source": "safety_verifier"}}
        },
    }
    replay_denial = {
        "status": "Denied",
        "error": "authority_obligation_receipt_replayed",
    }
    retry_request = copy.deepcopy(challenge_request)
    retry_request["causal_trace_id"] = "55555555-5555-4555-8555-555555555652"
    retry_request["authority_obligation_receipts"] = [receipt]
    artifact = {
        "ids": {
            "run_id": run_id,
            "action_id": action_id,
            "node_a_id": node_a,
            "node_b_id": node_b,
            "target_instance_id": instance_id,
            "work_order_id": work_order_id,
        },
        "manager_target_binding": {
            "work_order_submit": work_order_submit,
            "dispatch": dispatch,
        },
        "closed_schema": {
            "physical_action_resource_coordinate": {"body": coordinate_error},
            "unknown_authority_field": {"body": authority_error},
            "reserved_node_action_param": {
                "status": 200,
                "body": {
                    "status": "Failed",
                    "error": "adapter failed",
                },
            },
            "simulator_unchanged": True,
        },
        "challenge": challenge
        | {
            "status": "NeedsApproval",
            "request": copy.deepcopy(challenge_request),
            "caller_action_param_node_id": None,
            "caller_param_did_not_override_server_coordinate": True,
            "simulator_counter_before": {"total": 0},
            "simulator_counter_after": {"total": 0},
        },
        "manager_approval": {
            "receipt": receipt,
            "grant": {"authority_obligation_receipt": receipt},
        },
        "wrong_node_preclaim": {
            "response": {"status": 409, "body": wrong_body},
            "run_before": {"run_id": run_id, "status": "waiting_for_approval", "ticks": 1},
            "run_after": {"run_id": run_id, "status": "waiting_for_approval", "ticks": 1},
            "simulator_counter_before": {"total": 0},
            "simulator_counter_after": {"total": 0},
            "action_trace_ids_before": [],
            "action_trace_ids_after": [],
            "receipt_unclaimed": True,
        },
        "exact_node_execution": {
            "request": copy.deepcopy(retry_request),
            "response": executed,
            "simulator_counter_before": {"total": 0},
            "simulator_counter_after": {"total": 1},
            "run_after": {"adapter_executions": 1},
            "executed_exactly_once": True,
        },
        "receipt_replay": {
            "response": replay_denial,
            "simulator_counter_before": {"total": 1},
            "simulator_counter_after": {"total": 1},
            "run_after": {"adapter_executions": 1},
            "denied_without_effect": True,
        },
        "inspect_only_replay": {
            "response": {"mode": "inspect_only"},
            "simulator_counter_before": {"total": 1},
            "simulator_counter_after": {"total": 1},
            "unchanged": True,
        },
    }
    manager_auth, manager_rows = S10ManagerApprovalAuthReportTests().fixture()
    manager_auth["events"] = manager_auth["events"][:2]
    manager_rows = manager_rows[:2]

    def physical_row(
        operation: str,
        node_id: str,
        status: int,
        request: dict,
        response: dict,
    ) -> dict:
        return {
            "operation_id": operation,
            "method": "POST",
            "url": f"https://device.test/devices/{node_id}/actions",
            "status": status,
            "request": {"action_id": action_id} | copy.deepcopy(request),
            "response": copy.deepcopy(response),
        }

    rows = [
        {
            "operation_id": "submitWorkOrder",
            "method": "POST",
            "url": "http://manager.test/work-orders",
            "status": 200,
            "request": {"work_order": {"work_order_id": work_order_id}},
            "response": work_order_submit,
        },
        {
            "operation_id": "dispatchWorkOrder",
            "method": "POST",
            "url": f"http://manager.test/work-orders/{work_order_id}/dispatch",
            "status": 200,
            "request": {},
            "response": dispatch,
        },
        physical_row(
            "rejectPhysicalCoordinateField",
            node_a,
            422,
            {"physical_action_resource_coordinate": {"node_id": node_b}},
            coordinate_error,
        ),
        physical_row(
            "rejectUnknownAuthorityField",
            node_a,
            422,
            {"authority_override": True},
            authority_error,
        ),
        physical_row(
            "submitPhysicalForApproval",
            node_a,
            200,
            challenge_request,
            {"status": "NeedsApproval", "approval_challenge": challenge},
        ),
        *manager_rows,
        physical_row(
            "retryPhysicalWrongNode",
            node_b,
            409,
            retry_request,
            wrong_body,
        ),
        physical_row(
            "retryPhysicalExactNode",
            node_a,
            200,
            retry_request,
            executed,
        ),
        physical_row(
            "replayPhysicalReceipt",
            node_a,
            200,
            retry_request,
            replay_denial,
        ),
    ]
    return artifact, manager_auth, rows


class S6PhysicalApprovalBindingReportTests(unittest.TestCase):
    def test_accepts_server_bound_physical_approval_evidence(self) -> None:
        artifact, manager_auth, rows = valid_s6_physical_approval_fixture()
        self.assertEqual(
            [], ar.validate_s6_physical_approval_binding(artifact, manager_auth, rows)
        )

    def test_rejects_provider_private_reserved_field_error(self) -> None:
        artifact, manager_auth, rows = valid_s6_physical_approval_fixture()
        artifact["closed_schema"]["reserved_node_action_param"]["body"]["error"] = (
            "acceptance_operation_reserved_field"
        )
        self.assertIn(
            "s6_physical_action_transport_schema_not_closed",
            ar.validate_s6_physical_approval_binding(artifact, manager_auth, rows),
        )

    def test_rejects_wrong_node_and_manager_order_mutations(self) -> None:
        artifact, manager_auth, rows = valid_s6_physical_approval_fixture()
        wrong = next(row for row in rows if row["operation_id"] == "retryPhysicalWrongNode")
        wrong["url"] = wrong["url"].replace(
            artifact["ids"]["node_b_id"], artifact["ids"]["node_a_id"]
        )
        grant_index = next(
            index for index, row in enumerate(rows) if row["operation_id"] == "grantApproval"
        )
        rows.append(rows.pop(grant_index))
        failures = ar.validate_s6_physical_approval_binding(artifact, manager_auth, rows)
        self.assertIn("s6_physical_approval_api_cardinality_invalid", failures)
        self.assertIn("s6_physical_approval_manager_order_invalid", failures)

    def test_rejects_wrong_audience_safety_and_effect_mutations(self) -> None:
        artifact, manager_auth, rows = valid_s6_physical_approval_fixture()
        artifact["manager_approval"]["receipt"]["audience"] = "wrong-audience"
        exact = next(row for row in rows if row["operation_id"] == "retryPhysicalExactNode")
        exact["response"]["output"]["execution"] = 2
        exact["response"]["verification"]["artifacts"]["safety"]["source"] = "caller"
        failures = ar.validate_s6_physical_approval_binding(artifact, manager_auth, rows)
        self.assertIn("s6_physical_receipt_not_exact", failures)
        self.assertIn("s6_exact_node_did_not_execute_once_with_safety", failures)

    def test_rejects_signature_and_cardinality_mutations(self) -> None:
        artifact, manager_auth, rows = valid_s6_physical_approval_fixture()
        artifact["manager_approval"]["receipt"]["validation"]["signature"] = "raw"
        exact = next(row for row in rows if row["operation_id"] == "retryPhysicalExactNode")
        rows.append(copy.deepcopy(exact))
        failures = ar.validate_s6_physical_approval_binding(artifact, manager_auth, rows)
        self.assertIn("s6_retained_evidence_contains_receipt_signature", failures)
        self.assertIn("s6_physical_approval_api_cardinality_invalid", failures)

    def test_rejects_changed_exact_retry_action(self) -> None:
        artifact, manager_auth, rows = valid_s6_physical_approval_fixture()
        exact = next(row for row in rows if row["operation_id"] == "retryPhysicalExactNode")
        exact["request"]["action"]["params"]["node_id"] = artifact["ids"]["node_b_id"]
        self.assertIn(
            "s6_exact_node_did_not_execute_once_with_safety",
            ar.validate_s6_physical_approval_binding(artifact, manager_auth, rows),
        )

    def test_rejects_invalid_provider_signature_in_exact_execution(self) -> None:
        expectation = expectation_for("UC-E2E-S6", "approved_capture")
        output, projection, public_key = production_private_v3_output(
            expectation["operation_id"],
            action_id=expectation["action_id"],
            role=expectation["request_principal_role"],
            params={"physical_action": True},
            expected_resource=PHYSICAL_COORDINATE,
            expectation=expectation,
        )
        exact_execution = {"status": "Executed", "output": copy.deepcopy(output)}
        with trusted_public_key_file(public_key) as trusted_key:
            self.assertEqual(
                ar.validate_exact_private_v3_output(
                    exact_execution,
                    projection,
                    expectation,
                    trusted_key,
                    "s6_invalid_signature",
                ),
                [],
            )
            signature = bytearray(
                b64url_decode(
                    exact_execution["output"]["provider_receipt"]["signature_b64"],
                    expected_length=64,
                )
            )
            signature[0] ^= 1
            exact_execution["output"]["provider_receipt"]["signature_b64"] = (
                b64url_encode(bytes(signature))
            )
            self.assertEqual(
                ar.validate_exact_private_v3_output(
                    exact_execution,
                    projection,
                    expectation,
                    trusted_key,
                    "s6_invalid_signature",
                ),
                ["s6_invalid_signature"],
            )


def valid_s10_revocation_fixture() -> tuple[dict, dict, dict, list[dict], list[dict]]:
    run_id = "00000000-0000-4000-8000-000000001001"
    work_order_id = "wo-s10-revocable"
    instance_id = "00000000-0000-4000-8000-000000001002"
    approval_id = "00000000-0000-4000-8000-000000001003"
    receipt_id = "00000000-0000-4000-8000-000000001004"
    audience = (
        "splendor.daemon.approval_receipt.v2:instance:"
        f"{instance_id}:run:{run_id}"
    )
    challenge = {
        "action_name": "artifact.publish_external",
        "approval_id": approval_id,
        "canonical_request_digest": "blake3:" + "1" * 64,
    }
    receipt = {
        "schema_version": "splendor.authority.obligation_receipt.v1",
        "receipt_id": receipt_id,
        "approval_id": approval_id,
        "audience": audience,
        "revocation": "active",
        "validation": {
            "algorithm": "ed25519",
            "digest": "sha256:" + "2" * 64,
            "key_id": "manager-key",
            "validation_kind": "detached_signature",
            "signature": "[REDACTED]",
        },
    }
    run = {
        "run_id": run_id,
        "status": "waiting_for_approval",
        "ticks": 1,
        "state_head": "blake3:" + "3" * 64,
        "adapter_executions": 0,
    }
    state = {
        "run_id": run_id,
        "state_node_id": "00000000-0000-4000-8000-000000001005",
        "data_hash": "blake3:" + "4" * 64,
        "parent_state_node_ids": [],
    }
    submission = {"work_order_id": work_order_id, "status": "accepted"}
    dispatch = {"selected_instance_id": instance_id, "run_id": run_id}
    proposal = {"status": "NeedsApproval", "approval_challenge": challenge}
    acknowledgement = {
        "schema_version": "splendor.resident.approval_receipt_revocation_ack.v1",
        "status": "revoked",
        "effect_certainty": "known",
        "receipt_id": receipt_id,
        "approval_id": approval_id,
        "run_id": run_id,
        "target_instance_id": instance_id,
        "receipt_audience": audience,
    }
    retry_denial = {
        "status": "Denied",
        "error": "authority_obligation_receipt_revoked",
        "output": None,
    }
    manager_auth, manager_rows = S10ManagerApprovalAuthReportTests().fixture()
    by_operation = {row["operation_id"]: row for row in manager_rows}
    by_event = {event["operation_id"]: event for event in manager_auth["events"]}
    by_operation["revokeApprovalClaimFirst"]["response"] = {
        "code": "approval_receipt_revocation_too_late",
        "details": {"revocation_applied": False},
    }
    by_operation["requestRevocableApproval"]["request"]["challenge"] = challenge
    grant_trace = by_operation["grantRevocableApproval"]["response"]["trace_event_id"]
    by_operation["grantRevocableApproval"]["response"] = {
        "trace_event_id": grant_trace,
        "challenge": challenge,
        "status": "granted",
        "authority_obligation_receipt": receipt,
    }
    revoke_trace = by_operation["revokeApproval"]["response"]["trace_event_id"]
    by_operation["revokeApproval"]["response"] = {
        "trace_event_id": revoke_trace,
        "status": "revoked",
        "evidence": {"revoked": True},
        "resident_receipt_revocation_ack": acknowledgement,
    }
    resident_call = {
        "operation_id": "revokeApprovalReceipt",
        "method": "POST",
        "manager_approval_call_id": by_event["revokeApproval"]["call_id"],
        "scope": "splendor.approval_receipts.revoke",
        "required_scope": "splendor.approval_receipts.revoke",
        "scope_expectation": "exact",
        "url_scheme": "https",
        "tls_verification": "acceptance_ca",
        "redirect_policy": "disabled",
        "target_instance_id": instance_id,
        "audience_instance_id": instance_id,
        "target_audience": f"urn:splendor:instance:{instance_id}",
        "run_id": run_id,
        "receipt_id": receipt_id,
        "approval_id": approval_id,
        "receipt_audience": audience,
        "result_status": 200,
        "ack_status": "revoked",
        "effect_certainty": "known",
        "fresh_one_use_jti": True,
        "credential_id": "sha256:" + "9" * 64,
        "credential_correlation_id": "sha256:" + "9" * 64,
        "raw_bearer_recorded": False,
        "raw_jti_recorded": False,
        "receipt_signature_recorded": False,
    }
    manager_auth["resident_approval_receipt_revocations"] = [
        copy.deepcopy(resident_call)
    ]
    resident_security = {
        "manager_dispatched_approval_receipt_revocations": [
            copy.deepcopy(resident_call)
        ]
    }
    report = {
        "status": "passed",
        "schema_version": "splendor.uc_e2e_s10.approval_receipt_revocation.v1",
        "uncertainty_mocked": False,
        "exact_resident_scope": "splendor.approval_receipts.revoke",
        "fresh_manager_jtis": True,
        "fresh_resident_revocation_jtis": True,
        "raw_bearers_recorded": False,
        "raw_jtis_recorded": False,
        "receipt_signatures_recorded_in_per_call_evidence": False,
        "manager_calls": [
            copy.deepcopy(by_event["revokeApprovalClaimFirst"]),
            copy.deepcopy(by_event["revokeApproval"]),
        ],
        "resident_calls": [copy.deepcopy(resident_call)],
        "claim_before_revoke": {
            "manager_response": {
                "status": 409,
                "body": copy.deepcopy(
                    by_operation["revokeApprovalClaimFirst"]["response"]
                ),
            },
            "outcome": "too_late",
            "effect_certainty": "known",
            "too_late_observed": True,
            "successful_revocation_claimed": False,
            "effect_unknown_observed": False,
        },
        "revoke_before_claim": {
            "run_id": run_id,
            "work_order_id": work_order_id,
            "challenge": challenge,
            "retained_receipt": receipt,
            "target_instance_id": instance_id,
            "manager_submission": {"status": 200, "body": submission},
            "manager_dispatch": {"status": 200, "body": dispatch},
            "grant": {"trace_event_id": grant_trace},
            "resident_ack": acknowledgement,
            "retry_outcome": retry_denial,
            "run_before_revoke": run,
            "run_after_revoke": run,
            "run_after_retry": run,
            "state_before_revoke": state,
            "zero_effect": True,
        },
    }

    def row(operation: str, response: dict, status: int = 200, request: dict | None = None) -> dict:
        return {
            "operation_id": operation,
            "method": "POST",
            "url": "https://resident.test/unused",
            "status": status,
            "request": copy.deepcopy(request or {}),
            "response": copy.deepcopy(response),
        }

    rows = [
        by_operation["requestApproval"],
        by_operation["grantApproval"],
        by_operation["revokeApprovalClaimFirst"],
        row(
            "submitWorkOrder",
            submission,
            request={"work_order": {"work_order_id": work_order_id}},
        ),
        {
            "operation_id": "dispatchWorkOrder",
            "method": "POST",
            "url": f"https://manager.test/work-orders/{work_order_id}/dispatch",
            "status": 200,
            "request": {},
            "response": dispatch,
        },
        row("submitRevocablePublishForApproval", proposal, request={}),
        by_operation["requestRevocableApproval"],
        by_operation["grantRevocableApproval"],
        row("inspectRevocablePublishBeforeManagerRevoke", run),
        row("getRevocablePublishStateBeforeManagerRevoke", state),
        by_operation["revokeApproval"],
        row("inspectRevocablePublishAfterManagerRevoke", run),
        row(
            "submitRevokedOriginalReceipt",
            retry_denial,
            request={"authority_obligation_receipts": [receipt]},
        ),
        row("inspectRevocablePublishAfterDeniedRetry", run),
        row("getRevocablePublishStateAfterDeniedRetry", state),
    ]
    return report, resident_security, manager_auth, rows, []


class S10ApprovalRevocationReportTests(unittest.TestCase):
    def test_accepts_revoke_before_claim_and_too_late_evidence(self) -> None:
        report, security, auth, rows, traces = valid_s10_revocation_fixture()
        self.assertEqual(
            [], ar.validate_s10_approval_revocation(report, security, auth, rows, traces)
        )

    def test_rejects_ack_scope_and_status_mutations(self) -> None:
        report, security, auth, rows, traces = valid_s10_revocation_fixture()
        report["revoke_before_claim"]["resident_ack"]["effect_certainty"] = "unknown"
        report["resident_calls"][0]["scope"] = "actions_submit"
        claim = next(
            row for row in rows if row["operation_id"] == "revokeApprovalClaimFirst"
        )
        claim["status"] = 200
        failures = ar.validate_s10_approval_revocation(
            report, security, auth, rows, traces
        )
        self.assertIn("s10_revocation_resident_ack_not_exact", failures)
        self.assertIn("s10_revocation_resident_call_projection_mismatch", failures)
        self.assertIn("s10_claim_before_revoke_false_success_or_status", failures)

    def test_rejects_order_tick_state_and_effect_mutations(self) -> None:
        report, security, auth, rows, traces = valid_s10_revocation_fixture()
        revoke_index = next(
            index for index, row in enumerate(rows) if row["operation_id"] == "revokeApproval"
        )
        rows.append(rows.pop(revoke_index))
        after = next(
            row
            for row in rows
            if row["operation_id"] == "inspectRevocablePublishAfterDeniedRetry"
        )
        after["response"]["ticks"] = 2
        state_after = next(
            row
            for row in rows
            if row["operation_id"] == "getRevocablePublishStateAfterDeniedRetry"
        )
        state_after["response"]["data_hash"] = "blake3:" + "f" * 64
        traces.append(
            {
                "run_id": report["revoke_before_claim"]["run_id"],
                "payload": {
                    "kind": {
                        "ActionExecuted": {
                            "action": {"name": "artifact.publish_external"}
                        }
                    },
                },
            }
        )
        failures = ar.validate_s10_approval_revocation(
            report, security, auth, rows, traces
        )
        self.assertIn("s10_revocation_api_order_invalid", failures)
        self.assertIn("s10_revocation_changed_tick_state_or_effect", failures)
        self.assertIn("s10_revoked_receipt_reached_adapter", failures)

    def test_rejects_signature_and_cardinality_mutations(self) -> None:
        report, security, auth, rows, traces = valid_s10_revocation_fixture()
        report["revoke_before_claim"]["retained_receipt"]["validation"][
            "signature"
        ] = "raw-signature"
        rows.append(copy.deepcopy(rows[-1]))
        failures = ar.validate_s10_approval_revocation(
            report, security, auth, rows, traces
        )
        self.assertIn("s10_revocation_evidence_contains_receipt_signature", failures)
        self.assertIn("s10_revocation_api_cardinality_invalid", failures)


class S10TraceSyncReportTests(unittest.TestCase):
    def test_accepts_central_and_edge_integrity_evidence(self) -> None:
        trace_sync = {
            "vpc": {"accepted_records": 1},
            "cloud": {"accepted_records": 1},
            "edge": {"accepted_records": 1},
            "edge_central_redacted_export_rejection": {
                "status": 403,
                "body": {"code": "trace_sync_rejected"},
            },
            "redacted_edge_export_resynced": False,
            "trace_hashes_rewritten": False,
            "tampered": {"status": 403},
        }
        self.assertEqual([], ar.validate_s10_trace_sync_evidence(trace_sync))

    def test_rejects_rehashed_redacted_edge_export(self) -> None:
        trace_sync = {
            "vpc": {"accepted_records": 1},
            "cloud": {"accepted_records": 1},
            "edge": {"accepted_records": 1},
            "edge_central_redacted_export_rejection": {
                "status": 200,
                "body": {"accepted_records": 1},
            },
            "redacted_edge_export_resynced": True,
            "trace_hashes_rewritten": True,
            "tampered": {"status": 403},
        }
        self.assertIn(
            "s10_edge_redacted_trace_integrity_boundary_missing",
            ar.validate_s10_trace_sync_evidence(trace_sync),
        )


class S10ScenarioActionProfileTests(unittest.TestCase):
    def test_physical_actions_use_closed_host_postconditions(self) -> None:
        for name in S10_SCENARIO.ALLOWED_PHYSICAL_ACTIONS:
            expected = (
                "sensor_read"
                if name in {"read_battery", "read_sensor_summary"}
                else "device_state_updated"
            )
            self.assertEqual(
                [expected],
                S10_SCENARIO.physical_action(name)["postconditions"],
                name,
            )

    def test_nonphysical_postconditions_remain_unchanged(self) -> None:
        self.assertEqual(
            ["artifact_published"],
            S10_SCENARIO.action("artifact.publish_external")["postconditions"],
        )
        self.assertEqual(
            ["marker_recorded"],
            S10_SCENARIO.action("orchestrator.marker")["postconditions"],
        )


if __name__ == "__main__":
    unittest.main()
