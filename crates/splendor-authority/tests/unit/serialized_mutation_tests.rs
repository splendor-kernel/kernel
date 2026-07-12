use super::*;
use crate::capability::validate_local_profile_grant;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use splendor_types::{
    AgentId, AuthorityBudgetScope, AuthorityDecision, AuthorityDecisionId, AuthorityDecisionStatus,
    AuthorityObligation, AuthorityObligationId, AuthorityObligationKind,
    AuthorityObligationReceipt, AuthorityObligationReceiptId, AuthorityObligationReceiptValidation,
    AuthorityObligationReceiptValidationKind, AuthorityTimeScope, CapabilityGrant,
    CapabilityGrantId, CapabilityGrantValidation, CapabilityGrantValidationKind, CapabilityRequest,
    CapabilityScope, DelegationChain, DelegationGrant, DelegationResultContract,
    DelegationRoleProfile, IdentityRevision, Principal, PrincipalBinding, PrincipalDisplay,
    PrincipalId, PrincipalKind, PrincipalProofRef, PrincipalProofRefId, PrincipalStatus,
    RevocationStatus, RunId, TenantId, WorkOrder, WorkOrderEnvelope, WorkOrderId, WorkOrderKeyring,
    WorkOrderPlacement, WorkOrderQuotaPolicy, WorkOrderValidationContext,
    AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION, AUTHORITY_OBLIGATION_SCHEMA_VERSION,
    CAPABILITY_GRANT_SCHEMA_VERSION, CAPABILITY_REQUEST_SCHEMA_VERSION,
    DELEGATION_CHAIN_SCHEMA_VERSION, DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION,
    TASK_RESPONSE_SCHEMA, WORK_ORDER_SCHEMA_VERSION,
};
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime};

const CASES_PER_FAMILY: u64 = 128;
const NIL_ID: &str = "00000000-0000-0000-0000-000000000000";
const AUDIENCE: &str = "daemon:local";
const OTHER_AUDIENCE: &str = "daemon:other";
const WORK_ORDER_KEY_ID: &str = "auth007b-work-order-key";
const WORK_ORDER_SECRET: &[u8] = b"auth007b-deterministic-work-order-secret";
const RECEIPT_KEY_ID: &str = "auth007b-receipt-key";
const RECEIPT_SECRET: &str = "auth007b-deterministic-receipt-secret";
const RECEIPT_REVOCATION_REF: &str = "revocation:auth007b-receipt";
const DIGEST_A: &str = "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PLACEHOLDER_DIGEST: &str =
    "blake3:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Copy)]
struct Case<'a> {
    fixture: &'a str,
    mutation: &'a str,
    seed: u64,
}

impl std::fmt::Display for Case<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "fixture={} mutation={} seed={}",
            self.fixture, self.mutation, self.seed
        )
    }
}

fn fixed_time(seed: u64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000 + seed as i64).unwrap_or_else(|error| {
        panic!("fixture=clock mutation=construct seed={seed} error={error}")
    })
}

fn id_text(seed: u64, domain: u32, slot: u8) -> String {
    let serial = ((seed + 1) << 8) | u64::from(slot);
    format!("{domain:08x}-0000-4000-8000-{serial:012x}")
}

macro_rules! deterministic_uuid_id {
    ($name:ident, $type:ty, $domain:expr) => {
        fn $name(seed: u64, slot: u8) -> $type {
            <$type>::parse(&id_text(seed, $domain, slot)).unwrap_or_else(|error| {
                panic!(
                    "fixture=id mutation={} seed={} slot={} error={}",
                    stringify!($name),
                    seed,
                    slot,
                    error
                )
            })
        }
    };
}

deterministic_uuid_id!(tenant_id, TenantId, 0x7000_0001);
deterministic_uuid_id!(agent_id, AgentId, 0x7000_0002);
deterministic_uuid_id!(run_id, RunId, 0x7000_0003);
deterministic_uuid_id!(principal_id, PrincipalId, 0x7000_0004);
deterministic_uuid_id!(grant_id, CapabilityGrantId, 0x7000_0005);
deterministic_uuid_id!(decision_id, AuthorityDecisionId, 0x7000_0006);
deterministic_uuid_id!(obligation_id, AuthorityObligationId, 0x7000_0007);
deterministic_uuid_id!(receipt_id, AuthorityObligationReceiptId, 0x7000_0008);
deterministic_uuid_id!(proof_ref_id, PrincipalProofRefId, 0x7000_0009);

fn serialize<T: serde::Serialize>(fixture: &str, value: &T, seed: u64) -> Value {
    serde_json::to_value(value).unwrap_or_else(|error| {
        panic!("fixture={fixture} mutation=serialize seed={seed} error={error}")
    })
}

fn deserialize<T: DeserializeOwned>(_case: Case<'_>, value: Value) -> Result<T, serde_json::Error> {
    serde_json::from_value(value)
}

fn remove(value: &mut Value, object_pointer: &str, key: &str) {
    value
        .pointer_mut(object_pointer)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("invalid test mutation object pointer {object_pointer}"))
        .remove(key);
}

fn set(value: &mut Value, pointer: &str, replacement: Value) {
    *value
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("invalid test mutation pointer {pointer}")) = replacement;
}

fn scope(seed: u64, agents: Vec<AgentId>, runs: Vec<RunId>) -> CapabilityScope {
    CapabilityScope {
        tenant_ids: Some(vec![tenant_id(seed, 1)]),
        agent_ids: Some(agents),
        run_ids: Some(runs),
        audiences: Some(vec![AUDIENCE.to_string()]),
        time: AuthorityTimeScope {
            not_before: Some(fixed_time(seed) - Duration::minutes(5)),
            expires_at: Some(fixed_time(seed) + Duration::minutes(30)),
        },
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(8),
            max_action_duration_ms: Some(10_000),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn validation(algorithm: &str) -> CapabilityGrantValidation {
    CapabilityGrantValidation {
        validation_kind: CapabilityGrantValidationKind::LocallyValidated,
        algorithm: algorithm.to_string(),
        key_id: None,
        digest: DIGEST_A.to_string(),
        signature: None,
    }
}

struct CapabilityFixture {
    grant: CapabilityGrant,
    request: CapabilityRequest,
    now: OffsetDateTime,
}

fn capability_fixture(seed: u64) -> CapabilityFixture {
    let now = fixed_time(seed);
    let subject = principal_id(seed, 1);
    let operation = gateway_action_operation("artifact.create");
    let scope = scope(seed, vec![agent_id(seed, 1)], vec![run_id(seed, 1)]);
    CapabilityFixture {
        grant: CapabilityGrant {
            schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
            grant_id: grant_id(seed, 1),
            issuer: principal_id(seed, 2),
            subject: subject.clone(),
            parent_grant_ids: Vec::new(),
            operations: vec![operation.clone()],
            scope: scope.clone(),
            not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(20),
            revocation_ref: Some("revocation:auth007b-capability".to_string()),
            revocation: RevocationStatus::Active,
            obligations: Vec::new(),
            max_delegation_depth: 3,
            validation: Some(validation("auth007b-local-profile-v1")),
            metadata: BTreeMap::new(),
        },
        request: CapabilityRequest {
            schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
            subject,
            operation,
            scope,
            requested_at: now,
            metadata: BTreeMap::new(),
        },
        now,
    }
}

fn positive_capability(fixture: &CapabilityFixture, seed: u64) -> ValidatedCapabilityGrant {
    let grant: CapabilityGrant =
        serde_json::from_value(serialize("capability_grant", &fixture.grant, seed)).unwrap_or_else(
            |error| {
                panic!("fixture=capability_grant mutation=positive_serde seed={seed} error={error}")
            },
        );
    let request: CapabilityRequest =
        serde_json::from_value(serialize("capability_request", &fixture.request, seed))
            .unwrap_or_else(|error| {
                panic!(
                    "fixture=capability_request mutation=positive_serde seed={seed} error={error}"
                )
            });
    let grant = validate_local_profile_grant(grant).unwrap_or_else(|error| {
        panic!("fixture=capability_grant mutation=positive_validation seed={seed} error={error:?}")
    });
    let decision = evaluate_capability_request(std::slice::from_ref(&grant), &request, fixture.now);
    assert_eq!(
        decision.status,
        AuthorityDecisionStatus::Allowed,
        "fixture=capability mutation=positive_control seed={seed} reasons={:?}",
        decision.reasons
    );
    grant
}

fn mutate_capability(seed: u64, fixture: &CapabilityFixture) -> (&'static str, bool, Value) {
    let index = seed % 32;
    let grant = index < 19;
    let mut value = if grant {
        serialize("capability_grant", &fixture.grant, seed)
    } else {
        serialize("capability_request", &fixture.request, seed)
    };
    let mutation = match index {
        0 => {
            remove(&mut value, "", "schema_version");
            "grant.missing_schema"
        }
        1 => {
            set(&mut value, "/schema_version", Value::Null);
            "grant.null_schema"
        }
        2 => {
            set(&mut value, "/grant_id", json!(7));
            "grant.wrong_type_grant_id"
        }
        3 => {
            set(&mut value, "/grant_id", json!(NIL_ID));
            "grant.nil_grant_id"
        }
        4 => {
            set(&mut value, "/issuer", json!(NIL_ID));
            "grant.nil_issuer"
        }
        5 => {
            set(&mut value, "/subject", json!(NIL_ID));
            "grant.nil_subject"
        }
        6 => {
            remove(&mut value, "", "operations");
            "grant.missing_operations"
        }
        7 => {
            set(&mut value, "/operations", json!([]));
            "grant.empty_operations"
        }
        8 => {
            set(&mut value, "/operations/0/namespace", json!("unknown"));
            "grant.unknown_operation_enum"
        }
        9 => {
            set(&mut value, "/operations/0/name", json!("artifact.*"));
            "grant.wildcard_operation"
        }
        10 => {
            set(
                &mut value,
                "/scope/schema_version",
                json!("splendor.authority.scope.v0"),
            );
            "grant.unknown_scope_schema"
        }
        11 => {
            set(&mut value, "/scope/tenant_ids/0", json!(NIL_ID));
            "grant.nil_scope_identity"
        }
        12 => {
            set(&mut value, "/scope/audiences/0", json!("daemon:*"));
            "grant.wildcard_audience"
        }
        13 => {
            let expiry = value["expires_at"].clone();
            set(&mut value, "/not_before", expiry);
            "grant.invalid_time_window"
        }
        14 => {
            remove(&mut value, "", "validation");
            "grant.missing_validation"
        }
        15 => {
            set(&mut value, "/validation/algorithm", json!(" "));
            "grant.malformed_validation_algorithm"
        }
        16 => {
            set(&mut value, "/validation/validation_kind", json!("signed"));
            let validation = value["validation"]
                .as_object_mut()
                .expect("validation object");
            validation.insert("key_id".to_string(), json!("forged-key"));
            validation.insert("signature".to_string(), json!(DIGEST_B));
            "grant.forged_signed_downgrade"
        }
        17 => {
            let operation = value["operations"][0].clone();
            value["operations"] = json!([operation.clone(), operation]);
            set(&mut value, "/operations/1/name", json!("*"));
            "grant.duplicate_set_with_wildcard"
        }
        18 => {
            value["metadata"] = json!({"safe": [{"Approval-Token": "forged"}]});
            "grant.nested_reserved_metadata"
        }
        19 => {
            remove(&mut value, "", "schema_version");
            "request.missing_schema"
        }
        20 => {
            set(&mut value, "/subject", Value::Null);
            "request.null_subject"
        }
        21 => {
            set(&mut value, "/subject", json!(NIL_ID));
            "request.nil_subject"
        }
        22 => {
            set(&mut value, "/operation/verb", json!("superuser"));
            "request.unknown_operation_enum"
        }
        23 => {
            set(&mut value, "/operation/name", json!("artifact.*"));
            "request.wildcard_operation"
        }
        24 => {
            remove(&mut value, "/scope", "schema_version");
            "request.missing_scope_schema"
        }
        25 => {
            set(&mut value, "/scope/tenant_ids/0", json!(NIL_ID));
            "request.nil_scope_identity"
        }
        26 => {
            set(&mut value, "/scope/audiences/0", json!("daemon:*"));
            "request.wildcard_audience"
        }
        27 => {
            set(&mut value, "/requested_at", json!({"forged": true}));
            "request.wrong_type_timestamp"
        }
        28 => {
            value["metadata"] = json!({"items": [{"quota.override": 999}]});
            "request.nested_reserved_metadata"
        }
        29 => {
            set(
                &mut value,
                "/subject",
                json!(principal_id(seed, 9).to_string()),
            );
            "request.wrong_subject"
        }
        30 => {
            set(&mut value, "/operation/name", json!("artifact.publish"));
            "request.ungranted_operation"
        }
        _ => {
            set(
                &mut value,
                "/scope/tenant_ids/0",
                json!(tenant_id(seed, 9).to_string()),
            );
            "request.overbroad_tenant"
        }
    };
    (mutation, grant, value)
}

#[test]
fn serialized_mutation_capability_grants_and_requests_fail_closed() {
    for seed in 0..CASES_PER_FAMILY {
        let fixture = capability_fixture(seed);
        let positive = positive_capability(&fixture, seed);
        let (mutation, is_grant, value) = mutate_capability(seed, &fixture);
        let case = Case {
            fixture: if is_grant {
                "capability_grant"
            } else {
                "capability_request"
            },
            mutation,
            seed,
        };
        if is_grant {
            let Ok(raw) = deserialize::<CapabilityGrant>(case, value) else {
                continue;
            };
            match validate_local_profile_grant(raw) {
                Err(_) => {}
                Ok(validated) => {
                    let decision = evaluate_capability_request(
                        std::slice::from_ref(&validated),
                        &fixture.request,
                        fixture.now,
                    );
                    assert_eq!(
                        decision.status,
                        AuthorityDecisionStatus::Denied,
                        "{case} unexpectedly_authorized reasons={:?}",
                        decision.reasons
                    );
                }
            }
        } else {
            let Ok(request) = deserialize::<CapabilityRequest>(case, value) else {
                continue;
            };
            let decision =
                evaluate_capability_request(std::slice::from_ref(&positive), &request, fixture.now);
            assert_eq!(
                decision.status,
                AuthorityDecisionStatus::Denied,
                "{case} unexpectedly_authorized reasons={:?}",
                decision.reasons
            );
        }
    }
}

struct WorkOrderFixture {
    envelope: WorkOrderEnvelope,
    validation_context: WorkOrderValidationContext,
    keyring: WorkOrderKeyring,
    issuer: Principal,
    subject: Principal,
    issuer_grant: ValidatedCapabilityGrant,
    issued_grant_id: CapabilityGrantId,
}

fn principal(
    seed: u64,
    slot: u8,
    kind: PrincipalKind,
    tenant: TenantId,
    agent: Option<AgentId>,
) -> Principal {
    let now = fixed_time(seed);
    let mut bindings = vec![PrincipalBinding::Tenant {
        tenant_id: tenant.clone(),
    }];
    if let Some(agent_id) = agent {
        bindings.push(PrincipalBinding::Agent { agent_id });
    }
    let proof_refs = if kind == PrincipalKind::Service {
        vec![PrincipalProofRef {
            proof_ref_id: proof_ref_id(seed, slot),
            proof_kind: "work_order_signing_key".to_string(),
            provider: Some("local-test".to_string()),
            issuer: Some("auth007b".to_string()),
            subject: Some("issuer".to_string()),
            audience: Some(AUDIENCE.to_string()),
            key_id: Some(WORK_ORDER_KEY_ID.to_string()),
            proof_digest: DIGEST_A.to_string(),
            digest_algorithm: "blake3".to_string(),
            evidence_refs: vec!["evidence:auth007b-key".to_string()],
        }]
    } else {
        Vec::new()
    };
    Principal {
        principal_id: principal_id(seed, slot),
        kind,
        status: PrincipalStatus::Active,
        revision: IdentityRevision::initial(),
        owner_tenant_id: Some(tenant),
        owner_fleet_id: None,
        bindings,
        proof_refs,
        display: Some(PrincipalDisplay {
            display_name: Some("auth007b".to_string()),
            description: None,
        }),
        metadata: BTreeMap::new(),
        created_at: now,
        updated_at: now,
        superseded_by: None,
    }
}

fn work_order_fixture(seed: u64) -> WorkOrderFixture {
    let now = fixed_time(seed);
    let tenant = tenant_id(seed, 1);
    let agent = agent_id(seed, 1);
    let run = run_id(seed, 1);
    let issuer = principal(seed, 1, PrincipalKind::Service, tenant.clone(), None);
    let subject = principal(
        seed,
        2,
        PrincipalKind::Agent,
        tenant.clone(),
        Some(agent.clone()),
    );
    let work_order = WorkOrder {
        schema_version: WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: WorkOrderId::try_new(format!("wo_auth007b_{seed}"))
            .expect("deterministic work order id"),
        tenant_id: tenant.clone(),
        agent_id: agent.clone(),
        run_id: Some(run.clone()),
        objective: "execute bounded serialized mutation fixture".to_string(),
        allowed_actions: vec!["artifact.create".to_string()],
        allowed_adapters: vec!["artifact-store".to_string()],
        allowed_permissions: vec!["artifact.create".to_string()],
        data_refs: vec!["dataset:auth007b.fixture".to_string()],
        quotas: WorkOrderQuotaPolicy {
            max_actions_per_tick: Some(2),
            ..Default::default()
        },
        placement: WorkOrderPlacement::default(),
        issued_at: now - Duration::minutes(1),
        expires_at: now + Duration::minutes(10),
        revocation: RevocationStatus::Active,
    };
    let envelope = WorkOrderEnvelope::signed_with_shared_secret(
        work_order.clone(),
        WORK_ORDER_KEY_ID,
        WORK_ORDER_SECRET,
    )
    .expect("deterministic signed work order");
    let validation_context = WorkOrderValidationContext {
        tenant_id: tenant.clone(),
        agent_id: agent.clone(),
        run_id: Some(run.clone()),
        expected_placement_target: Some(work_order.placement.target.clone()),
        now,
    };
    let mut keyring = WorkOrderKeyring::new();
    keyring
        .insert_shared_secret(WORK_ORDER_KEY_ID, WORK_ORDER_SECRET)
        .expect("deterministic keyring");
    let issuer_grant = validate_local_profile_grant(CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: grant_id(seed, 20),
        issuer: principal_id(seed, 20),
        subject: issuer.principal_id.clone(),
        parent_grant_ids: Vec::new(),
        operations: vec![workload_admit_operation()],
        scope: CapabilityScope {
            tenant_ids: Some(vec![tenant]),
            agent_ids: Some(vec![agent]),
            run_ids: Some(vec![run]),
            audiences: Some(vec![AUDIENCE.to_string()]),
            time: AuthorityTimeScope {
                not_before: Some(now - Duration::minutes(5)),
                expires_at: Some(now + Duration::minutes(30)),
            },
            budget: AuthorityBudgetScope {
                max_actions_per_tick: Some(5),
                ..Default::default()
            },
            ..Default::default()
        },
        not_before: now - Duration::minutes(5),
        expires_at: now + Duration::minutes(30),
        revocation_ref: Some("revocation:auth007b-issuer".to_string()),
        revocation: RevocationStatus::Active,
        obligations: Vec::new(),
        max_delegation_depth: 0,
        validation: Some(validation("auth007b-issuer-grant-v1")),
        metadata: BTreeMap::new(),
    })
    .expect("real local issuer grant validation");
    WorkOrderFixture {
        envelope,
        validation_context,
        keyring,
        issuer,
        subject,
        issuer_grant,
        issued_grant_id: grant_id(seed, 21),
    }
}

fn issue_fixture(
    fixture: &WorkOrderFixture,
    envelope: &WorkOrderEnvelope,
    audience: &str,
) -> Result<WorkOrderGrantIssuanceResult, WorkOrderGrantIssuanceError> {
    issue_work_order_capability_grant(WorkOrderGrantIssuance {
        envelope,
        validation_context: &fixture.validation_context,
        keyring: &fixture.keyring,
        issuer: &fixture.issuer,
        subject: &fixture.subject,
        issuer_grants: std::slice::from_ref(&fixture.issuer_grant),
        audience: audience.to_string(),
        issued_grant_id: fixture.issued_grant_id.clone(),
    })
}

fn mutate_work_order(
    seed: u64,
    envelope: &WorkOrderEnvelope,
) -> (&'static str, bool, &'static str, Value) {
    let mut value = serialize("work_order", envelope, seed);
    let (mutation, resign, audience) = match seed % 32 {
        0 => {
            remove(&mut value, "", "signature");
            ("missing_signature", false, AUDIENCE)
        }
        1 => {
            set(&mut value, "/signature", Value::Null);
            ("null_signature", false, AUDIENCE)
        }
        2 => {
            set(&mut value, "/signature/key_id", json!(" "));
            set(&mut value, "/signature/signature", json!(""));
            ("blank_signature_key", false, AUDIENCE)
        }
        3 => {
            set(&mut value, "/signature/signature", json!({"forged": true}));
            value["signature"]
                .as_object_mut()
                .expect("signature object")
                .insert("algorithm".to_string(), json!("none"));
            ("unknown_algorithm_malformed_signature", false, AUDIENCE)
        }
        4 => {
            set(
                &mut value,
                "/signature/key_id",
                json!("unknown-algorithm:key"),
            );
            ("unknown_key_or_algorithm", false, AUDIENCE)
        }
        5 => {
            set(&mut value, "/signature/signature", json!(DIGEST_B));
            ("forged_signature", false, AUDIENCE)
        }
        6 => {
            set(
                &mut value,
                "/schema_version",
                json!("splendor.work_order.v0"),
            );
            ("unknown_schema", false, AUDIENCE)
        }
        7 => {
            set(
                &mut value,
                "/work_order_id",
                json!(format!("wo_tampered_{seed}")),
            );
            ("tampered_work_order_id", false, AUDIENCE)
        }
        8 => {
            set(
                &mut value,
                "/tenant_id",
                json!(tenant_id(seed, 9).to_string()),
            );
            ("tampered_tenant", false, AUDIENCE)
        }
        9 => {
            set(
                &mut value,
                "/agent_id",
                json!(agent_id(seed, 9).to_string()),
            );
            ("tampered_agent", false, AUDIENCE)
        }
        10 => {
            set(&mut value, "/run_id", json!(run_id(seed, 9).to_string()));
            ("tampered_run", false, AUDIENCE)
        }
        11 => {
            set(&mut value, "/objective", json!("tampered objective"));
            ("tampered_objective", false, AUDIENCE)
        }
        12 => {
            set(&mut value, "/allowed_actions/0", json!("artifact.publish"));
            ("tampered_action_allowlist", false, AUDIENCE)
        }
        13 => {
            set(&mut value, "/allowed_adapters/0", json!("shell"));
            ("tampered_adapter_allowlist", false, AUDIENCE)
        }
        14 => {
            set(&mut value, "/allowed_permissions/0", json!("admin.all"));
            ("tampered_permission_allowlist", false, AUDIENCE)
        }
        15 => {
            set(&mut value, "/data_refs/0", json!("dataset:other"));
            ("tampered_data_ref", false, AUDIENCE)
        }
        16 => {
            set(&mut value, "/quotas/max_actions_per_tick", json!(999));
            ("tampered_quota", false, AUDIENCE)
        }
        17 => {
            set(&mut value, "/placement/target", json!("physical_robot"));
            ("tampered_placement", false, AUDIENCE)
        }
        18 => {
            set(
                &mut value,
                "/placement/data_locality",
                json!("restricted-other"),
            );
            ("tampered_locality", false, AUDIENCE)
        }
        19 => {
            set(&mut value, "/placement/requires_gpu", json!(true));
            ("tampered_capability_requirement", false, AUDIENCE)
        }
        20 => {
            set(&mut value, "/issued_at", json!("2020-01-01T00:00:00Z"));
            ("tampered_issued_at", false, AUDIENCE)
        }
        21 => {
            set(&mut value, "/expires_at", json!("2099-01-01T00:00:00Z"));
            ("tampered_expiry", false, AUDIENCE)
        }
        22 => {
            set(
                &mut value,
                "/revocation",
                json!({"revoked":{"reason":"tampered"}}),
            );
            ("tampered_revocation", false, AUDIENCE)
        }
        23 => {
            remove(&mut value, "", "tenant_id");
            ("missing_tenant", false, AUDIENCE)
        }
        24 => {
            set(&mut value, "/allowed_actions", json!([]));
            ("empty_action_allowlist", false, AUDIENCE)
        }
        25 => {
            set(&mut value, "/allowed_adapters/0", json!(" "));
            ("blank_adapter_allowlist", false, AUDIENCE)
        }
        26 => {
            set(&mut value, "/quotas", json!(["not-an-object"]));
            ("malformed_quotas", false, AUDIENCE)
        }
        27 => {
            set(
                &mut value,
                "/data_refs",
                json!({"extensions":{"authority":"allow"}}),
            );
            ("malformed_data_refs_extensions", false, AUDIENCE)
        }
        28 => {
            remove(&mut value, "/placement", "target");
            ("missing_placement_target", false, AUDIENCE)
        }
        29 => {
            set(&mut value, "/issued_at", json!("2020-01-01T00:00:00Z"));
            set(&mut value, "/expires_at", json!("2020-01-01T00:01:00Z"));
            ("trusted_resigned_expired", true, AUDIENCE)
        }
        30 => {
            set(
                &mut value,
                "/revocation",
                json!({"revoked":{"reason":"operator"}}),
            );
            ("trusted_resigned_revoked", true, AUDIENCE)
        }
        _ => ("trusted_resigned_wrong_audience", true, OTHER_AUDIENCE),
    };
    (mutation, resign, audience, value)
}

#[test]
fn serialized_mutation_signed_work_orders_fail_validation_and_issuance() {
    for seed in 0..CASES_PER_FAMILY {
        let fixture = work_order_fixture(seed);
        issue_fixture(&fixture, &fixture.envelope, AUDIENCE).unwrap_or_else(|error| {
            panic!("fixture=work_order mutation=positive_control seed={seed} error={error:?}")
        });
        let (mutation, resign, audience, value) = mutate_work_order(seed, &fixture.envelope);
        let case = Case {
            fixture: "work_order",
            mutation,
            seed,
        };
        let Ok(mut envelope) = deserialize::<WorkOrderEnvelope>(case, value) else {
            continue;
        };
        if resign {
            envelope = WorkOrderEnvelope::signed_with_shared_secret(
                envelope.work_order,
                WORK_ORDER_KEY_ID,
                WORK_ORDER_SECRET,
            )
            .unwrap_or_else(|error| panic!("{case} trusted_resign_failed={error:?}"));
        }
        let error = issue_fixture(&fixture, &envelope, audience)
            .unwrap_err_or_else(|_| panic!("{case} unexpectedly_issued"));
        let expected = match seed % 32 {
            0..=3 => Some("unsigned_work_order"),
            4 => Some("unknown_signature_key"),
            5 | 7..=22 => Some("bad_signature"),
            6 | 24 | 25 | 28 => Some("malformed_work_order"),
            29 => Some("expired_work_order"),
            30 => Some("revoked_work_order"),
            31 => Some("issuer_signature_binding_mismatch"),
            _ => None,
        };
        if let Some(expected) = expected {
            assert_eq!(error.reason_code(), expected, "{case} error={error:?}");
        }
    }
}

trait ExpectErrOrElse<T, E> {
    fn unwrap_err_or_else(self, on_ok: impl FnOnce(T) -> E) -> E;
}

impl<T, E> ExpectErrOrElse<T, E> for Result<T, E> {
    fn unwrap_err_or_else(self, on_ok: impl FnOnce(T) -> E) -> E {
        match self {
            Ok(value) => on_ok(value),
            Err(error) => error,
        }
    }
}

struct ReceiptFixture {
    decision: AuthorityDecision,
    receipt: AuthorityObligationReceipt,
    context: AuthorityObligationReceiptValidationContext,
    now: OffsetDateTime,
}

fn receipt_fixture(seed: u64) -> ReceiptFixture {
    let now = fixed_time(seed);
    let mut capability = capability_fixture(seed);
    capability.grant.operations = vec![gateway_action_operation("artifact.publish")];
    capability.request.operation = gateway_action_operation("artifact.publish");
    capability.grant.obligations = vec![AuthorityObligation {
        schema_version: AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string(),
        obligation_id: obligation_id(seed, 1),
        kind: AuthorityObligationKind::ApprovalRequired,
        description: "authority owned approval obligation".to_string(),
        parameters: BTreeMap::new(),
    }];
    let grant =
        validate_local_profile_grant(capability.grant).expect("real conditional grant validation");
    let mut decision =
        evaluate_capability_request(std::slice::from_ref(&grant), &capability.request, now);
    decision.decision_id = decision_id(seed, 1);
    let issuer = principal_id(seed, 30);
    let context = AuthorityObligationReceiptValidationContext::trusted_local(
        issuer.clone(),
        AUDIENCE,
        RECEIPT_KEY_ID,
        RECEIPT_SECRET,
        RECEIPT_REVOCATION_REF,
        now,
    );
    let raw = AuthorityObligationReceipt {
        schema_version: AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: receipt_id(seed, 1),
        issuer,
        audience: AUDIENCE.to_string(),
        obligation_id: decision.obligations[0].obligation_id.clone(),
        kind: decision.obligations[0].kind,
        subject: decision.request.subject.clone(),
        authority_decision_id: decision.decision_id.clone(),
        canonical_request_digest: canonical_authority_request_digest(&decision.request)
            .expect("request digest"),
        evidence_digest: DIGEST_B.to_string(),
        evidence_ref: Some("evidence:auth007b-receipt".to_string()),
        issued_at: now - Duration::seconds(1),
        expires_at: now + Duration::minutes(10),
        revocation: RevocationStatus::Active,
        revocation_ref: RECEIPT_REVOCATION_REF.to_string(),
        approval_id: None,
        approval_trace_event_id: None,
        validation: AuthorityObligationReceiptValidation {
            validation_kind: AuthorityObligationReceiptValidationKind::LocalSignature,
            algorithm: "local-obligation-receipt-v1".to_string(),
            key_id: RECEIPT_KEY_ID.to_string(),
            digest: PLACEHOLDER_DIGEST.to_string(),
            signature: PLACEHOLDER_DIGEST.to_string(),
        },
    };
    let receipt =
        issue_local_authority_obligation_receipt(raw, &context).expect("trusted receipt issuance");
    ReceiptFixture {
        decision,
        receipt,
        context,
        now,
    }
}

fn positive_receipt(fixture: &ReceiptFixture, seed: u64) -> ValidatedAuthorityObligationReceipt {
    let receipt: AuthorityObligationReceipt =
        serde_json::from_value(serialize("obligation_receipt", &fixture.receipt, seed))
            .unwrap_or_else(|error| {
                panic!(
                    "fixture=obligation_receipt mutation=positive_serde seed={seed} error={error}"
                )
            });
    let receipt = validate_authority_obligation_receipt(receipt, &fixture.context)
        .unwrap_or_else(|error| panic!("fixture=obligation_receipt mutation=positive_validation seed={seed} error={error:?}"));
    let verification = verify_obligation_receipts(
        &fixture.decision,
        std::slice::from_ref(&receipt),
        fixture.now,
    );
    assert!(
        verification.allowed,
        "fixture=obligation_receipt mutation=positive_control seed={seed} reasons={:?}",
        verification.reasons
    );
    receipt
}

fn mutate_receipt(seed: u64, receipt: &AuthorityObligationReceipt) -> (&'static str, bool, Value) {
    let mut value = serialize("obligation_receipt", receipt, seed);
    let (mutation, resign) = match seed % 32 {
        0 => {
            remove(&mut value, "", "schema_version");
            ("missing_schema", false)
        }
        1 => {
            remove(&mut value, "", "receipt_id");
            ("missing_receipt_id", false)
        }
        2 => {
            set(&mut value, "/issuer", Value::Null);
            ("null_issuer", false)
        }
        3 => {
            set(&mut value, "/kind", json!({"approval":true}));
            ("wrong_type_kind", false)
        }
        4 => {
            set(
                &mut value,
                "/schema_version",
                json!("splendor.authority.obligation_receipt.v0"),
            );
            ("unknown_schema", false)
        }
        5 => {
            set(&mut value, "/receipt_id", json!(NIL_ID));
            ("nil_receipt_id", false)
        }
        6 => {
            set(&mut value, "/issuer", json!(NIL_ID));
            ("nil_issuer", false)
        }
        7 => {
            set(&mut value, "/audience", json!("daemon:*"));
            ("wildcard_audience", false)
        }
        8 => {
            set(&mut value, "/obligation_id", json!(NIL_ID));
            ("nil_obligation_id", false)
        }
        9 => {
            set(&mut value, "/kind", json!("root_override"));
            ("unknown_kind", false)
        }
        10 => {
            set(&mut value, "/subject", json!(NIL_ID));
            ("nil_subject", false)
        }
        11 => {
            set(&mut value, "/authority_decision_id", json!(NIL_ID));
            ("nil_decision_id", false)
        }
        12 => {
            set(&mut value, "/canonical_request_digest", json!("approved"));
            ("malformed_request_digest", false)
        }
        13 => {
            set(&mut value, "/evidence_digest", json!("approved"));
            ("malformed_evidence_digest", false)
        }
        14 => {
            set(&mut value, "/evidence_ref", json!("evidence:*"));
            ("wildcard_evidence_ref", false)
        }
        15 => {
            set(&mut value, "/issued_at", json!("2099-01-01T00:00:00Z"));
            ("future_issued_at", false)
        }
        16 => {
            set(&mut value, "/expires_at", json!("2020-01-01T00:00:00Z"));
            ("expired_receipt", false)
        }
        17 => {
            set(
                &mut value,
                "/revocation",
                json!({"revoked":{"reason":"withdrawn"}}),
            );
            ("revoked_receipt", false)
        }
        18 => {
            set(&mut value, "/revocation_ref", json!("revocation:other"));
            ("wrong_revocation_source", false)
        }
        19 => {
            remove(&mut value, "", "validation");
            ("missing_validation", false)
        }
        20 => {
            set(&mut value, "/validation/validation_kind", json!("signed"));
            ("unknown_validation_kind", false)
        }
        21 => {
            set(&mut value, "/validation/algorithm", json!("none"));
            ("downgraded_algorithm", false)
        }
        22 => {
            set(&mut value, "/validation/key_id", json!("unknown-key"));
            ("unknown_key", false)
        }
        23 => {
            set(&mut value, "/validation/digest", json!(DIGEST_B));
            ("tampered_validation_digest", false)
        }
        24 => {
            set(&mut value, "/validation/signature", json!(DIGEST_B));
            ("forged_signature", false)
        }
        25 => {
            set(
                &mut value,
                "/subject",
                json!(principal_id(seed, 31).to_string()),
            );
            ("trusted_wrong_subject", true)
        }
        26 => {
            set(
                &mut value,
                "/authority_decision_id",
                json!(decision_id(seed, 31).to_string()),
            );
            ("trusted_wrong_decision", true)
        }
        27 => {
            set(
                &mut value,
                "/obligation_id",
                json!(obligation_id(seed, 31).to_string()),
            );
            ("trusted_wrong_obligation", true)
        }
        28 => {
            set(&mut value, "/kind", json!("human_review"));
            ("trusted_wrong_kind", true)
        }
        29 => {
            set(&mut value, "/canonical_request_digest", json!(DIGEST_A));
            ("trusted_wrong_request_digest", true)
        }
        30 => ("duplicate_receipt", false),
        _ => ("extra_receipt", true),
    };
    if seed % 32 == 31 {
        set(
            &mut value,
            "/receipt_id",
            json!(receipt_id(seed, 31).to_string()),
        );
        set(
            &mut value,
            "/obligation_id",
            json!(obligation_id(seed, 31).to_string()),
        );
    }
    (mutation, resign, value)
}

#[test]
fn serialized_mutation_obligation_receipts_fail_trusted_validation_or_matching() {
    for seed in 0..CASES_PER_FAMILY {
        let fixture = receipt_fixture(seed);
        let positive = positive_receipt(&fixture, seed);
        let (mutation, resign, value) = mutate_receipt(seed, &fixture.receipt);
        let case = Case {
            fixture: "obligation_receipt",
            mutation,
            seed,
        };
        if seed % 32 == 30 {
            let verification = verify_obligation_receipts(
                &fixture.decision,
                &[positive.clone(), positive],
                fixture.now,
            );
            assert!(!verification.allowed, "{case} unexpectedly_authorized");
            assert!(
                verification
                    .reasons
                    .contains(&"duplicate_obligation_receipt_id".to_string()),
                "{case} reasons={:?}",
                verification.reasons
            );
            continue;
        }
        let Ok(mut receipt) = deserialize::<AuthorityObligationReceipt>(case, value) else {
            continue;
        };
        if resign {
            receipt = issue_local_authority_obligation_receipt(receipt, &fixture.context)
                .unwrap_or_else(|error| panic!("{case} trusted_reissue_failed={error:?}"));
        }
        let Ok(validated) = validate_authority_obligation_receipt(receipt, &fixture.context) else {
            continue;
        };
        let receipts = if seed % 32 == 31 {
            vec![positive, validated]
        } else {
            vec![validated]
        };
        let verification = verify_obligation_receipts(&fixture.decision, &receipts, fixture.now);
        assert!(!verification.allowed, "{case} unexpectedly_authorized");
    }
}

struct DelegationFixture {
    root: ValidatedCapabilityGrant,
    chain: DelegationChain,
    subjects: [PrincipalId; 2],
    now: OffsetDateTime,
}

fn delegation_request_from_edge(edge: &DelegationGrant) -> DelegationChildGrantRequest {
    let mut scope = edge.child_capability_grant.scope.clone();
    scope.budget = edge.budget;
    DelegationChildGrantRequest {
        parent_grant_id: Some(edge.parent_grant_id.clone()),
        issuer: edge.child_capability_grant.issuer.clone(),
        child_subject: Some(edge.child_capability_grant.subject.clone()),
        child_grant_id: edge.child_capability_grant.grant_id.clone(),
        parent_run_id: edge.parent_run_id.clone(),
        parent_agent_id: edge.parent_agent_id.clone(),
        child_run_id: edge.child_run_id.clone(),
        child_agent_id: edge.child_agent_id.clone(),
        objective: edge.objective.clone(),
        role_profile: edge.role_profile,
        operations: edge.child_capability_grant.operations.clone(),
        scope,
        allowed_message_schemas: edge.allowed_message_schemas.clone(),
        allowed_recipient_agent_ids: edge.allowed_recipient_agent_ids.clone(),
        result_contract: edge.result_contract.clone(),
        not_before: edge.not_before,
        expires_at: edge.expires_at,
        max_delegation_depth: edge.remaining_delegation_depth,
        max_fan_out: edge.max_fan_out,
        validation_digest: edge
            .child_capability_grant
            .validation
            .as_ref()
            .map(|validation| validation.digest.clone())
            .unwrap_or_default(),
    }
}

fn issue_edge(
    parent: &ValidatedCapabilityGrant,
    request: DelegationChildGrantRequest,
    expected_subject: PrincipalId,
    now: OffsetDateTime,
) -> Result<DelegationChildGrant, DelegationGrantError> {
    issue_delegation_child_grant(
        parent,
        request,
        DelegationValidationContext {
            now,
            audience: AUDIENCE.to_string(),
            expected_child_subject: expected_subject,
            parent_fan_out_limit: 3,
            current_parent_fan_out: 0,
        },
    )
}

fn delegation_fixture(seed: u64) -> DelegationFixture {
    let now = fixed_time(seed);
    let parent_subject = principal_id(seed, 40);
    let first_subject = principal_id(seed, 41);
    let second_subject = principal_id(seed, 42);
    let parent_agent = agent_id(seed, 40);
    let first_agent = agent_id(seed, 41);
    let second_agent = agent_id(seed, 42);
    let parent_run = run_id(seed, 40);
    let first_run = run_id(seed, 41);
    let second_run = run_id(seed, 42);
    let root = validate_local_profile_grant(CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: grant_id(seed, 40),
        issuer: principal_id(seed, 39),
        subject: parent_subject.clone(),
        parent_grant_ids: Vec::new(),
        operations: vec![gateway_action_operation("artifact.create")],
        scope: scope(
            seed,
            vec![first_agent.clone(), second_agent.clone()],
            vec![first_run.clone(), second_run.clone()],
        ),
        not_before: now - Duration::minutes(10),
        expires_at: now + Duration::minutes(30),
        revocation_ref: Some("revocation:auth007b-root".to_string()),
        revocation: RevocationStatus::Active,
        obligations: Vec::new(),
        max_delegation_depth: 3,
        validation: Some(validation("auth007b-delegation-root-v1")),
        metadata: BTreeMap::new(),
    })
    .expect("real root validation");
    let first_request = DelegationChildGrantRequest {
        parent_grant_id: Some(root.grant().grant_id.clone()),
        issuer: parent_subject,
        child_subject: Some(first_subject.clone()),
        child_grant_id: grant_id(seed, 41),
        parent_run_id: parent_run,
        parent_agent_id: parent_agent,
        child_run_id: first_run.clone(),
        child_agent_id: first_agent.clone(),
        objective: "first bounded specialist".to_string(),
        role_profile: DelegationRoleProfile::Specialist,
        operations: vec![gateway_action_operation("artifact.create")],
        scope: scope(
            seed,
            vec![first_agent.clone(), second_agent.clone()],
            vec![first_run.clone(), second_run.clone()],
        ),
        allowed_message_schemas: vec![TASK_RESPONSE_SCHEMA.to_string()],
        allowed_recipient_agent_ids: vec![agent_id(seed, 40)],
        result_contract: DelegationResultContract {
            schema_version: DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION.to_string(),
            result_schema: TASK_RESPONSE_SCHEMA.to_string(),
            requires_response: true,
            max_result_bytes: Some(4096),
        },
        not_before: now,
        expires_at: now + Duration::minutes(20),
        max_delegation_depth: 2,
        max_fan_out: 3,
        validation_digest: DIGEST_A.to_string(),
    };
    let first = issue_edge(&root, first_request, first_subject.clone(), now)
        .expect("real first delegation issuance");
    let second_request = DelegationChildGrantRequest {
        parent_grant_id: Some(first.child_grant().grant().grant_id.clone()),
        issuer: first_subject,
        child_subject: Some(second_subject.clone()),
        child_grant_id: grant_id(seed, 42),
        parent_run_id: first_run,
        parent_agent_id: first_agent,
        child_run_id: second_run.clone(),
        child_agent_id: second_agent.clone(),
        objective: "second bounded specialist".to_string(),
        role_profile: DelegationRoleProfile::Specialist,
        operations: vec![gateway_action_operation("artifact.create")],
        scope: scope(seed, vec![second_agent], vec![second_run]),
        allowed_message_schemas: vec![TASK_RESPONSE_SCHEMA.to_string()],
        allowed_recipient_agent_ids: vec![agent_id(seed, 41)],
        result_contract: DelegationResultContract {
            schema_version: DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION.to_string(),
            result_schema: TASK_RESPONSE_SCHEMA.to_string(),
            requires_response: true,
            max_result_bytes: Some(2048),
        },
        not_before: now,
        expires_at: now + Duration::minutes(10),
        max_delegation_depth: 1,
        max_fan_out: 2,
        validation_digest: DIGEST_B.to_string(),
    };
    let second = issue_edge(
        first.child_grant(),
        second_request,
        second_subject.clone(),
        now,
    )
    .expect("real second delegation issuance");
    DelegationFixture {
        root: root.clone(),
        subjects: [first.child_grant().grant().subject.clone(), second_subject],
        now,
        chain: DelegationChain {
            schema_version: DELEGATION_CHAIN_SCHEMA_VERSION.to_string(),
            root_grant_id: root.grant().grant_id.clone(),
            grants: vec![
                first.delegation_grant().clone(),
                second.delegation_grant().clone(),
            ],
            max_depth: 3,
        },
    }
}

fn validate_serialized_chain(
    fixture: &DelegationFixture,
    chain: DelegationChain,
    case: Case<'_>,
) -> Result<(), DelegationGrantError> {
    let mut parent = fixture.root.clone();
    for (index, edge) in chain.grants.iter().enumerate() {
        let expected = fixture
            .subjects
            .get(index)
            .cloned()
            .unwrap_or_else(|| principal_id(case.seed, 99));
        parent = issue_edge(
            &parent,
            delegation_request_from_edge(edge),
            expected,
            fixture.now,
        )?
        .into_child_grant();
    }
    Ok(())
}

fn mutate_delegation(seed: u64, chain: &DelegationChain) -> (&'static str, Value) {
    let mut value = serialize("delegation_chain", chain, seed);
    let mutation = match seed % 32 {
        0 => {
            remove(&mut value, "", "grants");
            "chain.missing_grants"
        }
        1 => {
            set(&mut value, "/grants", Value::Null);
            "chain.null_grants"
        }
        2 => {
            remove(&mut value, "/grants/0", "parent_grant_id");
            "edge.missing_parent"
        }
        3 => {
            remove(&mut value, "/grants/0/child_capability_grant", "subject");
            "edge.missing_child_subject"
        }
        4 => {
            set(&mut value, "/grants/0/role_profile", json!("superuser"));
            "edge.unknown_role"
        }
        5 => {
            set(&mut value, "/max_depth", json!("unbounded"));
            "chain.wrong_type_depth"
        }
        6 => {
            set(
                &mut value,
                "/grants/0/parent_grant_id",
                json!(grant_id(seed, 90).to_string()),
            );
            "edge.wrong_parent"
        }
        7 => {
            value["grants"]
                .as_array_mut()
                .expect("grants array")
                .reverse();
            "chain.reordered_edges"
        }
        8 => {
            let first = value["grants"][0].clone();
            value["grants"] = json!([first.clone(), first]);
            "chain.duplicate_edge"
        }
        9 => {
            set(
                &mut value,
                "/grants/1/parent_grant_id",
                json!(grant_id(seed, 90).to_string()),
            );
            "chain.malformed_parent_edge"
        }
        10 => {
            let parent = value["grants"][1]["parent_run_id"].clone();
            set(&mut value, "/grants/1/child_run_id", parent);
            "chain.cycle_reused_child_run"
        }
        11 => {
            let parent = value["grants"][1]["parent_agent_id"].clone();
            set(&mut value, "/grants/1/child_agent_id", parent);
            "chain.reused_child_agent"
        }
        12 => {
            set(
                &mut value,
                "/grants/1/child_capability_grant/grant_id",
                json!(NIL_ID),
            );
            "edge.nil_child_grant_id"
        }
        13 => {
            set(
                &mut value,
                "/grants/1/child_capability_grant/issuer",
                json!(principal_id(seed, 90).to_string()),
            );
            "edge.wrong_issuer"
        }
        14 => {
            set(
                &mut value,
                "/grants/1/child_capability_grant/subject",
                json!(principal_id(seed, 90).to_string()),
            );
            "edge.wrong_subject"
        }
        15 => {
            set(
                &mut value,
                "/grants/1/child_capability_grant/scope/audiences/0",
                json!("daemon:*"),
            );
            "edge.wildcard_audience"
        }
        16 => {
            set(
                &mut value,
                "/grants/1/child_capability_grant/scope/audiences/0",
                json!(OTHER_AUDIENCE),
            );
            "edge.wrong_audience"
        }
        17 => {
            set(&mut value, "/grants/1/allowed_message_schemas", json!([]));
            "edge.missing_message_schema"
        }
        18 => {
            set(
                &mut value,
                "/grants/1/allowed_message_schemas/0",
                json!("splendor.message.*.v1"),
            );
            "edge.bad_message_schema"
        }
        19 => {
            set(
                &mut value,
                "/grants/1/allowed_recipient_agent_ids",
                json!([]),
            );
            "edge.missing_recipient"
        }
        20 => {
            set(
                &mut value,
                "/grants/1/allowed_recipient_agent_ids/0",
                json!(NIL_ID),
            );
            "edge.nil_recipient"
        }
        21 => {
            set(&mut value, "/grants/1/objective", json!(" "));
            "edge.blank_objective"
        }
        22 => {
            set(
                &mut value,
                "/grants/1/result_contract/schema_version",
                json!("splendor.authority.delegation_result_contract.v0"),
            );
            "edge.unknown_result_schema"
        }
        23 => {
            set(
                &mut value,
                "/grants/1/result_contract/max_result_bytes",
                json!(0),
            );
            "edge.zero_result_budget"
        }
        24 => {
            set(&mut value, "/grants/1/remaining_delegation_depth", json!(2));
            "edge.depth_widening"
        }
        25 => {
            set(&mut value, "/grants/1/max_fan_out", json!(0));
            "edge.zero_fan_out"
        }
        26 => {
            set(
                &mut value,
                "/grants/1/budget/max_actions_per_tick",
                json!(999),
            );
            "edge.budget_widening"
        }
        27 => {
            set(
                &mut value,
                "/grants/1/not_before",
                json!("2020-01-01T00:00:00Z"),
            );
            "edge.time_start_widening"
        }
        28 => {
            set(
                &mut value,
                "/grants/1/expires_at",
                json!("2099-01-01T00:00:00Z"),
            );
            "edge.time_expiry_widening"
        }
        29 => {
            set(
                &mut value,
                "/grants/1/child_capability_grant/scope/agent_ids/0",
                json!(agent_id(seed, 90).to_string()),
            );
            "edge.scope_widening"
        }
        30 => {
            set(&mut value, "/grants/1/role_profile", json!("critic"));
            "edge.critic_external_effect"
        }
        _ => {
            set(&mut value, "/grants/1/role_profile", json!("evaluator"));
            "edge.evaluator_external_effect"
        }
    };
    (mutation, value)
}

#[test]
fn serialized_mutation_delegation_grants_and_chains_fail_real_issuance() {
    for seed in 0..CASES_PER_FAMILY {
        let fixture = delegation_fixture(seed);
        let positive: DelegationChain = serde_json::from_value(serialize(
            "delegation_chain",
            &fixture.chain,
            seed,
        ))
        .unwrap_or_else(|error| {
            panic!("fixture=delegation_chain mutation=positive_serde seed={seed} error={error}")
        });
        validate_serialized_chain(
            &fixture,
            positive,
            Case {
                fixture: "delegation_chain",
                mutation: "positive_control",
                seed,
            },
        )
        .unwrap_or_else(|error| {
            panic!("fixture=delegation_chain mutation=positive_control seed={seed} error={error:?}")
        });
        let (mutation, value) = mutate_delegation(seed, &fixture.chain);
        let case = Case {
            fixture: "delegation_chain",
            mutation,
            seed,
        };
        let Ok(chain) = deserialize::<DelegationChain>(case, value) else {
            continue;
        };
        assert!(
            validate_serialized_chain(&fixture, chain, case).is_err(),
            "{case} unexpectedly_issued"
        );
    }
}

const RESERVED_KEYS: &[&str] = &[
    "authority",
    "Authorization",
    "approval-token",
    "capability.grant",
    "credentials",
    "driverManifest",
    "gateway",
    "mfa_token",
    "policy.bundle",
    "private-key",
    "quota override",
    "secretRef",
    "sessionCookie",
    "signature",
    "verifierResult",
    "workOrderId",
];

fn hostile_nested_value(seed: u64, key: &str) -> Value {
    let sentinel = format!("auth007b-sensitive-sentinel-{seed}");
    match (seed / RESERVED_KEYS.len() as u64) % 4 {
        0 => json!({key: sentinel}),
        1 => json!({"safe": {key: sentinel}}),
        2 => json!({"safe": [{"deeper": [{key: sentinel}]}]}),
        _ => json!([{"safe": [{key: sentinel}]}]),
    }
}

#[test]
fn serialized_mutation_nested_metadata_is_non_authorizing_and_redacted() {
    for seed in 0..CASES_PER_FAMILY {
        let mut fixture = capability_fixture(seed);
        fixture
            .grant
            .metadata
            .insert("safe_note".to_string(), json!({"nested":[{"label":"ok"}]}));
        fixture
            .request
            .metadata
            .insert("safe_note".to_string(), json!({"nested":[{"label":"ok"}]}));
        let mut obligation_grant = fixture.grant.clone();
        obligation_grant.obligations = vec![AuthorityObligation {
            schema_version: AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string(),
            obligation_id: obligation_id(seed, 50),
            kind: AuthorityObligationKind::HumanReview,
            description: "approved text alone remains non authorizing".to_string(),
            parameters: BTreeMap::from([(
                "safe_claim".to_string(),
                json!({"text":"approved=true","value":"credential-like-content"}),
            )]),
        }];
        let positive = positive_capability(&fixture, seed);
        let conditional = validate_local_profile_grant(obligation_grant.clone())
            .unwrap_or_else(|error| panic!("fixture=obligation_metadata mutation=positive_validation seed={seed} error={error:?}"));
        let conditional_decision = evaluate_capability_request(
            std::slice::from_ref(&conditional),
            &fixture.request,
            fixture.now,
        );
        assert_eq!(
            conditional_decision.status,
            AuthorityDecisionStatus::Conditional,
            "fixture=obligation_metadata mutation=positive_control seed={seed}"
        );
        let no_receipt = verify_obligation_receipts(&conditional_decision, &[], fixture.now);
        assert_eq!(
            no_receipt.reasons,
            vec!["missing_obligation_receipt"],
            "fixture=obligation_metadata mutation=hostile_text_not_receipt seed={seed}"
        );

        let key = RESERVED_KEYS[seed as usize % RESERVED_KEYS.len()];
        let hostile = hostile_nested_value(seed, key);
        let target = seed % 3;
        let mutation = match target {
            0 => "grant.metadata_reserved_nested",
            1 => "request.metadata_reserved_nested",
            _ => "obligation.parameters_reserved_nested",
        };
        let case = Case {
            fixture: "nested_metadata",
            mutation,
            seed,
        };
        match target {
            0 => {
                let mut value = serialize("capability_grant", &fixture.grant, seed);
                value["metadata"] = json!({"outer": hostile});
                let raw: CapabilityGrant = deserialize(case, value)
                    .unwrap_or_else(|error| panic!("{case} serde_error={error}"));
                assert!(
                    validate_local_profile_grant(raw).is_err(),
                    "{case} unexpectedly_validated"
                );
            }
            1 => {
                let mut value = serialize("capability_request", &fixture.request, seed);
                value["metadata"] = json!({"outer": hostile});
                let request: CapabilityRequest = deserialize(case, value)
                    .unwrap_or_else(|error| panic!("{case} serde_error={error}"));
                let decision = evaluate_capability_request(
                    std::slice::from_ref(&positive),
                    &request,
                    fixture.now,
                );
                assert_eq!(
                    decision.status,
                    AuthorityDecisionStatus::Denied,
                    "{case} unexpectedly_authorized"
                );
                assert_eq!(
                    decision.reasons,
                    vec!["metadata_reserved_authority_key"],
                    "{case}"
                );
                let redacted = authority_decision_evidence(&decision)
                    .and_then(|evidence| evidence.redacted())
                    .unwrap_or_else(|error| panic!("{case} evidence_error={error:?}"));
                let encoded = serde_json::to_string(&redacted)
                    .unwrap_or_else(|error| panic!("{case} evidence_serde={error}"));
                assert!(
                    !encoded.contains(&format!("auth007b-sensitive-sentinel-{seed}")),
                    "{case} leaked_hostile_metadata"
                );
            }
            _ => {
                let mut value = serialize("obligation_grant", &obligation_grant, seed);
                value["obligations"][0]["parameters"] = json!({"outer": hostile});
                let raw: CapabilityGrant = deserialize(case, value)
                    .unwrap_or_else(|error| panic!("{case} serde_error={error}"));
                assert!(
                    validate_local_profile_grant(raw).is_err(),
                    "{case} unexpectedly_validated"
                );
            }
        }
    }
}
