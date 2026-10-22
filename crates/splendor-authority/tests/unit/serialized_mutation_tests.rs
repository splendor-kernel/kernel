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

struct SerializedMutation<'a> {
    case: Case<'a>,
    baseline: Value,
    value: Value,
}

impl<'a> SerializedMutation<'a> {
    fn new(case: Case<'a>, baseline: Value) -> Self {
        Self {
            case,
            value: baseline.clone(),
            baseline,
        }
    }

    fn remove(&mut self, object_pointer: &str, key: &str) {
        let removed = self
            .value
            .pointer_mut(object_pointer)
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("{} invalid_object_pointer={object_pointer}", self.case))
            .remove(key);
        assert!(removed.is_some(), "{} missing_key={key}", self.case);
    }

    fn set(&mut self, pointer: &str, replacement: Value) {
        *self
            .value
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("{} invalid_value_pointer={pointer}", self.case)) =
            replacement;
    }

    fn insert(&mut self, object_pointer: &str, key: &str, value: Value) {
        self.value
            .pointer_mut(object_pointer)
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("{} invalid_object_pointer={object_pointer}", self.case))
            .insert(key.to_string(), value);
    }

    fn finish(self) -> Value {
        assert_ne!(
            self.value, self.baseline,
            "{} serialized_mutation_equaled_baseline",
            self.case
        );
        self.value
    }
}

fn remove_with_context(
    value: &mut Value,
    object_pointer: &str,
    key: &str,
    fixture: &str,
    mutation: u64,
    seed: u64,
) {
    let removed = value
        .pointer_mut(object_pointer)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| {
            panic!("fixture={fixture} mutation=operator_{mutation} seed={seed} invalid_object_pointer={object_pointer}")
        })
        .remove(key);
    assert!(
        removed.is_some(),
        "fixture={fixture} mutation=operator_{mutation} seed={seed} missing_key={key}"
    );
}

fn set_with_context(
    value: &mut Value,
    pointer: &str,
    replacement: Value,
    fixture: &str,
    mutation: u64,
    seed: u64,
) {
    *value.pointer_mut(pointer).unwrap_or_else(|| {
        panic!("fixture={fixture} mutation=operator_{mutation} seed={seed} invalid_value_pointer={pointer}")
    }) = replacement;
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
    let is_grant = index < 19;
    let mutation = [
        "grant.missing_schema",
        "grant.null_schema",
        "grant.wrong_type_grant_id",
        "grant.nil_grant_id",
        "grant.nil_issuer",
        "grant.nil_subject",
        "grant.missing_operations",
        "grant.empty_operations",
        "grant.unknown_operation_enum",
        "grant.wildcard_operation",
        "grant.unknown_scope_schema",
        "grant.nil_scope_identity",
        "grant.wildcard_audience",
        "grant.invalid_time_window",
        "grant.missing_validation",
        "grant.malformed_validation_algorithm",
        "grant.forged_signed_downgrade",
        "grant.duplicate_set_with_wildcard",
        "grant.nested_reserved_metadata",
        "request.missing_schema",
        "request.null_subject",
        "request.nil_subject",
        "request.unknown_operation_enum",
        "request.wildcard_operation",
        "request.missing_scope_schema",
        "request.nil_scope_identity",
        "request.wildcard_audience",
        "request.wrong_type_timestamp",
        "request.nested_reserved_metadata",
        "request.wrong_subject",
        "request.ungranted_operation",
        "request.overbroad_tenant",
    ][index as usize];
    let fixture_name = if is_grant {
        "capability_grant"
    } else {
        "capability_request"
    };
    let baseline = if is_grant {
        serialize("capability_grant", &fixture.grant, seed)
    } else {
        serialize("capability_request", &fixture.request, seed)
    };
    let mut serialized = SerializedMutation::new(
        Case {
            fixture: fixture_name,
            mutation,
            seed,
        },
        baseline,
    );
    match index {
        0 => {
            serialized.remove("", "schema_version");
        }
        1 => {
            serialized.set("/schema_version", Value::Null);
        }
        2 => {
            serialized.set("/grant_id", json!(7));
        }
        3 => {
            serialized.set("/grant_id", json!(NIL_ID));
        }
        4 => {
            serialized.set("/issuer", json!(NIL_ID));
        }
        5 => {
            serialized.set("/subject", json!(NIL_ID));
        }
        6 => {
            serialized.remove("", "operations");
        }
        7 => {
            serialized.set("/operations", json!([]));
        }
        8 => {
            serialized.set("/operations/0/namespace", json!("unknown"));
        }
        9 => {
            serialized.set("/operations/0/name", json!("artifact.*"));
        }
        10 => {
            serialized.set(
                "/scope/schema_version",
                json!("splendor.authority.scope.v0"),
            );
        }
        11 => {
            serialized.set("/scope/tenant_ids/0", json!(NIL_ID));
        }
        12 => {
            serialized.set("/scope/audiences/0", json!("daemon:*"));
        }
        13 => {
            let expiry = serialized.value["expires_at"].clone();
            serialized.set("/not_before", expiry);
        }
        14 => {
            serialized.remove("", "validation");
        }
        15 => {
            serialized.set("/validation/algorithm", json!(" "));
        }
        16 => {
            serialized.set("/validation/validation_kind", json!("signed"));
            serialized.insert("/validation", "key_id", json!("forged-key"));
            serialized.insert("/validation", "signature", json!(DIGEST_B));
        }
        17 => {
            let operation = serialized.value["operations"][0].clone();
            serialized.set("/operations", json!([operation.clone(), operation]));
            serialized.set("/operations/1/name", json!("*"));
        }
        18 => {
            serialized.insert(
                "",
                "metadata",
                json!({"safe": [{"Approval-Token": "forged"}]}),
            );
        }
        19 => {
            serialized.remove("", "schema_version");
        }
        20 => {
            serialized.set("/subject", Value::Null);
        }
        21 => {
            serialized.set("/subject", json!(NIL_ID));
        }
        22 => {
            serialized.set("/operation/verb", json!("superuser"));
        }
        23 => {
            serialized.set("/operation/name", json!("artifact.*"));
        }
        24 => {
            serialized.remove("/scope", "schema_version");
        }
        25 => {
            serialized.set("/scope/tenant_ids/0", json!(NIL_ID));
        }
        26 => {
            serialized.set("/scope/audiences/0", json!("daemon:*"));
        }
        27 => {
            serialized.set("/requested_at", json!({"forged": true}));
        }
        28 => {
            serialized.insert("", "metadata", json!({"items": [{"quota.override": 999}]}));
        }
        29 => {
            serialized.set("/subject", json!(principal_id(seed, 9).to_string()));
        }
        30 => {
            serialized.set("/operation/name", json!("artifact.publish"));
        }
        _ => {
            serialized.set("/scope/tenant_ids/0", json!(tenant_id(seed, 9).to_string()));
        }
    }
    (mutation, is_grant, serialized.finish())
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
            let raw = match deserialize::<CapabilityGrant>(case, value) {
                Ok(raw) => raw,
                Err(error) => {
                    assert!(
                        matches!(seed % 32, 0 | 1 | 2 | 6 | 8),
                        "{case} unexpected_serde_rejection={error}"
                    );
                    continue;
                }
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
            let request = match deserialize::<CapabilityRequest>(case, value) {
                Ok(request) => request,
                Err(error) => {
                    assert!(
                        matches!(seed % 32, 19 | 20 | 22 | 24 | 27),
                        "{case} unexpected_serde_rejection={error}"
                    );
                    continue;
                }
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
        work_order_id: WorkOrderId::try_new(format!("wo_auth007b_{seed}")).unwrap_or_else(
            |error| {
                panic!(
                    "fixture=work_order mutation=fixture_work_order_id seed={seed} error={error:?}"
                )
            },
        ),
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
    .unwrap_or_else(|error| {
        panic!("fixture=work_order mutation=fixture_sign seed={seed} error={error:?}")
    });
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
        .unwrap_or_else(|error| {
            panic!("fixture=work_order mutation=fixture_keyring seed={seed} error={error:?}")
        });
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
    .unwrap_or_else(|error| {
        panic!("fixture=work_order mutation=fixture_issuer_grant seed={seed} error={error:?}")
    });
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

fn mutate_work_order(seed: u64, envelope: &WorkOrderEnvelope) -> (&'static str, bool, Value) {
    let index = seed % 32;
    let mutation = [
        "missing_signature",
        "null_signature",
        "blank_signature_key",
        "unknown_algorithm_malformed_signature",
        "unknown_key_or_algorithm",
        "forged_signature",
        "unknown_schema",
        "tampered_work_order_id",
        "tampered_tenant",
        "tampered_agent",
        "tampered_run",
        "tampered_objective",
        "tampered_action_allowlist",
        "tampered_adapter_allowlist",
        "tampered_permission_allowlist",
        "tampered_data_ref",
        "tampered_quota",
        "tampered_placement",
        "tampered_locality",
        "tampered_capability_requirement",
        "tampered_issued_at",
        "tampered_expiry",
        "tampered_revocation",
        "missing_tenant",
        "empty_action_allowlist",
        "blank_adapter_allowlist",
        "malformed_quotas",
        "malformed_data_refs",
        "missing_placement_target",
        "trusted_resigned_expired",
        "trusted_resigned_revoked",
        "trusted_resigned_tenant_binding_mismatch",
    ][index as usize];
    let baseline = serialize("work_order", envelope, seed);
    let mut serialized = SerializedMutation::new(
        Case {
            fixture: "work_order",
            mutation,
            seed,
        },
        baseline,
    );
    let resign = match index {
        0 => {
            serialized.remove("", "signature");
            false
        }
        1 => {
            serialized.set("/signature", Value::Null);
            false
        }
        2 => {
            serialized.set("/signature/key_id", json!(" "));
            serialized.set("/signature/signature", json!(""));
            false
        }
        3 => {
            serialized.set("/signature/signature", json!({"forged": true}));
            serialized.insert("/signature", "algorithm", json!("none"));
            false
        }
        4 => {
            serialized.set("/signature/key_id", json!("unknown-algorithm:key"));
            false
        }
        5 => {
            serialized.set("/signature/signature", json!(DIGEST_B));
            false
        }
        6 => {
            serialized.set("/schema_version", json!("splendor.work_order.v0"));
            false
        }
        7 => {
            serialized.set("/work_order_id", json!(format!("wo_tampered_{seed}")));
            false
        }
        8 => {
            serialized.set("/tenant_id", json!(tenant_id(seed, 9).to_string()));
            false
        }
        9 => {
            serialized.set("/agent_id", json!(agent_id(seed, 9).to_string()));
            false
        }
        10 => {
            serialized.set("/run_id", json!(run_id(seed, 9).to_string()));
            false
        }
        11 => {
            serialized.set("/objective", json!("tampered objective"));
            false
        }
        12 => {
            serialized.set("/allowed_actions/0", json!("artifact.publish"));
            false
        }
        13 => {
            serialized.set("/allowed_adapters/0", json!("shell"));
            false
        }
        14 => {
            serialized.set("/allowed_permissions/0", json!("admin.all"));
            false
        }
        15 => {
            serialized.set("/data_refs/0", json!("dataset:other"));
            false
        }
        16 => {
            serialized.set("/quotas/max_actions_per_tick", json!(999));
            false
        }
        17 => {
            serialized.set("/placement/target", json!("physical_robot"));
            false
        }
        18 => {
            serialized.set("/placement/data_locality", json!("restricted-other"));
            false
        }
        19 => {
            serialized.set("/placement/requires_gpu", json!(true));
            false
        }
        20 => {
            serialized.set("/issued_at", json!("2020-01-01T00:00:00Z"));
            false
        }
        21 => {
            serialized.set("/expires_at", json!("2099-01-01T00:00:00Z"));
            false
        }
        22 => {
            serialized.set("/revocation", json!({"revoked":{"reason":"tampered"}}));
            false
        }
        23 => {
            serialized.remove("", "tenant_id");
            false
        }
        24 => {
            serialized.set("/allowed_actions", json!([]));
            false
        }
        25 => {
            serialized.set("/allowed_adapters/0", json!(" "));
            false
        }
        26 => {
            serialized.set("/quotas", json!(["not-an-object"]));
            false
        }
        27 => {
            serialized.set("/data_refs", json!({"not":"a-list"}));
            false
        }
        28 => {
            serialized.remove("/placement", "target");
            false
        }
        29 => {
            serialized.set("/issued_at", json!("2020-01-01T00:00:00Z"));
            serialized.set("/expires_at", json!("2020-01-01T00:01:00Z"));
            true
        }
        30 => {
            serialized.set("/revocation", json!({"revoked":{"reason":"operator"}}));
            true
        }
        _ => {
            serialized.set("/tenant_id", json!(tenant_id(seed, 31).to_string()));
            true
        }
    };
    (mutation, resign, serialized.finish())
}

#[test]
fn serialized_mutation_signed_work_orders_fail_validation_and_issuance() {
    for seed in 0..CASES_PER_FAMILY {
        let fixture = work_order_fixture(seed);
        let positive_value = serialize("work_order", &fixture.envelope, seed);
        let positive: WorkOrderEnvelope = deserialize(
            Case {
                fixture: "work_order",
                mutation: "positive_round_trip",
                seed,
            },
            positive_value,
        )
        .unwrap_or_else(|error| {
            panic!("fixture=work_order mutation=positive_round_trip seed={seed} error={error}")
        });
        issue_fixture(&fixture, &positive, AUDIENCE).unwrap_or_else(|error| {
            panic!("fixture=work_order mutation=positive_control seed={seed} error={error:?}")
        });
        let (mutation, resign, value) = mutate_work_order(seed, &fixture.envelope);
        let case = Case {
            fixture: "work_order",
            mutation,
            seed,
        };
        let mut envelope = match deserialize::<WorkOrderEnvelope>(case, value) {
            Ok(envelope) => envelope,
            Err(error) => {
                assert!(
                    matches!(seed % 32, 3 | 23 | 26 | 27 | 28),
                    "{case} unexpected_serde_rejection={error}"
                );
                continue;
            }
        };
        if resign {
            envelope = WorkOrderEnvelope::signed_with_shared_secret(
                envelope.work_order,
                WORK_ORDER_KEY_ID,
                WORK_ORDER_SECRET,
            )
            .unwrap_or_else(|error| panic!("{case} trusted_resign_failed={error:?}"));
        }
        let error = issue_fixture(&fixture, &envelope, AUDIENCE)
            .unwrap_err_or_else(|_| panic!("{case} unexpectedly_issued"));
        let expected = match seed % 32 {
            0..=3 => Some("unsigned_work_order"),
            4 => Some("unknown_signature_key"),
            5 | 7..=22 => Some("bad_signature"),
            6 | 24 | 25 | 28 => Some("malformed_work_order"),
            29 => Some("expired_work_order"),
            30 => Some("revoked_work_order"),
            31 => Some("incompatible_work_order"),
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
    let grant = validate_local_profile_grant(capability.grant).unwrap_or_else(|error| {
        panic!("fixture=obligation_receipt mutation=fixture_conditional_grant seed={seed} error={error:?}")
    });
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
            .unwrap_or_else(|error| {
                panic!("fixture=obligation_receipt mutation=fixture_request_digest seed={seed} error={error:?}")
            }),
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
    let receipt = issue_local_authority_obligation_receipt(raw, &context).unwrap_or_else(|error| {
        panic!("fixture=obligation_receipt mutation=fixture_issue seed={seed} error={error:?}")
    });
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

fn mutate_receipt(
    seed: u64,
    receipt: &AuthorityObligationReceipt,
) -> (&'static str, Option<usize>, Value) {
    let index = seed % 32;
    let mutation = [
        "missing_schema",
        "missing_receipt_id",
        "null_issuer",
        "wrong_type_kind",
        "unknown_schema",
        "nil_receipt_id",
        "nil_issuer",
        "wrong_audience",
        "nil_obligation_id",
        "unknown_kind",
        "nil_subject",
        "nil_decision_id",
        "malformed_request_digest",
        "malformed_evidence_digest",
        "wildcard_evidence_ref",
        "future_issued_at",
        "expired_receipt",
        "revoked_receipt",
        "wrong_revocation_source",
        "missing_validation",
        "unknown_validation_kind",
        "downgraded_algorithm",
        "unknown_key",
        "tampered_validation_digest",
        "forged_signature",
        "trusted_wrong_subject",
        "trusted_wrong_decision",
        "trusted_wrong_obligation",
        "trusted_wrong_kind",
        "trusted_wrong_request_digest",
        "duplicate_receipt_collection_entry",
        "extra_receipt_collection_entry",
    ][index as usize];
    let baseline = serialize("obligation_receipts", &vec![receipt.clone()], seed);
    let mut serialized = SerializedMutation::new(
        Case {
            fixture: "obligation_receipt_collection",
            mutation,
            seed,
        },
        baseline,
    );
    let resign_index = match index {
        0 => {
            serialized.remove("/0", "schema_version");
            None
        }
        1 => {
            serialized.remove("/0", "receipt_id");
            None
        }
        2 => {
            serialized.set("/0/issuer", Value::Null);
            None
        }
        3 => {
            serialized.set("/0/kind", json!({"approval":true}));
            None
        }
        4 => {
            serialized.set(
                "/0/schema_version",
                json!("splendor.authority.obligation_receipt.v0"),
            );
            Some(0)
        }
        5 => {
            serialized.set("/0/receipt_id", json!(NIL_ID));
            Some(0)
        }
        6 => {
            serialized.set("/0/issuer", json!(NIL_ID));
            Some(0)
        }
        7 => {
            serialized.set("/0/audience", json!(OTHER_AUDIENCE));
            Some(0)
        }
        8 => {
            serialized.set("/0/obligation_id", json!(NIL_ID));
            Some(0)
        }
        9 => {
            serialized.set("/0/kind", json!("root_override"));
            None
        }
        10 => {
            serialized.set("/0/subject", json!(NIL_ID));
            Some(0)
        }
        11 => {
            serialized.set("/0/authority_decision_id", json!(NIL_ID));
            Some(0)
        }
        12 => {
            serialized.set("/0/canonical_request_digest", json!("approved"));
            Some(0)
        }
        13 => {
            serialized.set("/0/evidence_digest", json!("approved"));
            Some(0)
        }
        14 => {
            serialized.set("/0/evidence_ref", json!("evidence:*"));
            Some(0)
        }
        15 => {
            serialized.set("/0/issued_at", json!("2099-01-01T00:00:00Z"));
            Some(0)
        }
        16 => {
            serialized.set("/0/expires_at", json!("2020-01-01T00:00:00Z"));
            Some(0)
        }
        17 => {
            serialized.set("/0/revocation", json!({"revoked":{"reason":"withdrawn"}}));
            Some(0)
        }
        18 => {
            serialized.set("/0/revocation_ref", json!("revocation:other"));
            Some(0)
        }
        19 => {
            serialized.remove("/0", "validation");
            None
        }
        20 => {
            serialized.set("/0/validation/validation_kind", json!("signed"));
            None
        }
        21 => {
            serialized.set("/0/validation/algorithm", json!("none"));
            None
        }
        22 => {
            serialized.set("/0/validation/key_id", json!("unknown-key"));
            None
        }
        23 => {
            serialized.set("/0/validation/digest", json!(DIGEST_B));
            None
        }
        24 => {
            serialized.set("/0/validation/signature", json!(DIGEST_B));
            None
        }
        25 => {
            serialized.set("/0/subject", json!(principal_id(seed, 31).to_string()));
            Some(0)
        }
        26 => {
            serialized.set(
                "/0/authority_decision_id",
                json!(decision_id(seed, 31).to_string()),
            );
            Some(0)
        }
        27 => {
            serialized.set(
                "/0/obligation_id",
                json!(obligation_id(seed, 31).to_string()),
            );
            Some(0)
        }
        28 => {
            serialized.set("/0/kind", json!("human_review"));
            Some(0)
        }
        29 => {
            serialized.set("/0/canonical_request_digest", json!(DIGEST_A));
            Some(0)
        }
        30 => {
            let first = serialized.value[0].clone();
            serialized.set("", json!([first.clone(), first]));
            None
        }
        _ => {
            let first = serialized.value[0].clone();
            let mut extra = first.clone();
            extra["receipt_id"] = json!(receipt_id(seed, 31).to_string());
            extra["obligation_id"] = json!(obligation_id(seed, 31).to_string());
            serialized.set("", json!([first, extra]));
            Some(1)
        }
    };
    (mutation, resign_index, serialized.finish())
}

#[test]
fn serialized_mutation_obligation_receipts_fail_trusted_validation_or_matching() {
    for seed in 0..CASES_PER_FAMILY {
        let fixture = receipt_fixture(seed);
        let _positive = positive_receipt(&fixture, seed);
        let positive_collection: Vec<AuthorityObligationReceipt> = deserialize(
            Case {
                fixture: "obligation_receipt_collection",
                mutation: "positive_round_trip",
                seed,
            },
            serialize(
                "obligation_receipts",
                &vec![fixture.receipt.clone()],
                seed,
            ),
        )
        .unwrap_or_else(|error| {
            panic!("fixture=obligation_receipt_collection mutation=positive_round_trip seed={seed} error={error}")
        });
        assert_eq!(
            positive_collection.len(),
            1,
            "fixture=obligation_receipt_collection mutation=positive_round_trip seed={seed}"
        );
        let (mutation, resign_index, value) = mutate_receipt(seed, &fixture.receipt);
        let case = Case {
            fixture: "obligation_receipt_collection",
            mutation,
            seed,
        };
        let mut receipts = match deserialize::<Vec<AuthorityObligationReceipt>>(case, value) {
            Ok(receipts) => receipts,
            Err(error) => {
                assert!(
                    matches!(seed % 32, 0..=3 | 9 | 19 | 20),
                    "{case} unexpected_serde_rejection={error}"
                );
                continue;
            }
        };
        if let Some(index) = resign_index {
            let receipt = receipts
                .get(index)
                .cloned()
                .unwrap_or_else(|| panic!("{case} missing_reissue_index={index}"));
            let reissued = issue_local_authority_obligation_receipt(receipt, &fixture.context)
                .unwrap_or_else(|error| panic!("{case} trusted_reissue_failed={error:?}"));
            *receipts
                .get_mut(index)
                .unwrap_or_else(|| panic!("{case} missing_reissue_target={index}")) = reissued;
        }
        let mut validated = Vec::new();
        let mut validation_error = None;
        for receipt in receipts {
            match validate_authority_obligation_receipt(receipt, &fixture.context) {
                Ok(receipt) => validated.push(receipt),
                Err(error) => {
                    validation_error = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = validation_error {
            let expected = match seed % 32 {
                4 => "obligation_receipt_schema_unsupported",
                5 => "obligation_receipt_id_invalid",
                6 => "obligation_receipt_issuer_invalid",
                7 => "obligation_receipt_audience_mismatch",
                8 => "obligation_receipt_obligation_id_invalid",
                10 => "obligation_receipt_subject_invalid",
                11 => "obligation_receipt_decision_id_invalid",
                12 => "obligation_receipt_request_digest_malformed",
                13 => "obligation_receipt_evidence_digest_malformed",
                14 => "obligation_receipt_evidence_ref_malformed",
                15 => "obligation_receipt_not_yet_valid",
                16 => "obligation_receipt_expired",
                17 => "obligation_receipt_revoked",
                18 => "obligation_receipt_revocation_ref_mismatch",
                21 => "obligation_receipt_algorithm_mismatch",
                22 => "obligation_receipt_key_mismatch",
                23 => "obligation_receipt_validation_digest_mismatch",
                24 => "obligation_receipt_signature_mismatch",
                other => {
                    panic!("{case} unexpected_validation_rejection_index={other} error={error:?}")
                }
            };
            assert_eq!(error.reason_code(), expected, "{case} error={error:?}");
            continue;
        }
        let verification = verify_obligation_receipts(&fixture.decision, &validated, fixture.now);
        assert!(!verification.allowed, "{case} unexpectedly_authorized");
        let expected_reason = match seed % 32 {
            25 => "obligation_receipt_subject_mismatch",
            26 => "obligation_receipt_decision_mismatch",
            27 => "obligation_receipt_id_mismatch",
            28 => "obligation_receipt_kind_mismatch",
            29 => "obligation_receipt_request_digest_mismatch",
            30 => "duplicate_obligation_receipt_id",
            31 => "extra_obligation_receipt",
            other => panic!("{case} unexpected_matching_rejection_index={other}"),
        };
        assert!(
            verification.reasons.contains(&expected_reason.to_string()),
            "{case} expected_reason={expected_reason} reasons={:?}",
            verification.reasons
        );
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
    .unwrap_or_else(|error| {
        panic!(
            "fixture=delegation_chain mutation=fixture_root_validation seed={seed} error={error:?}"
        )
    });
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
    let first =
        issue_edge(&root, first_request, first_subject.clone(), now).unwrap_or_else(|error| {
            panic!(
                "fixture=delegation_chain mutation=fixture_first_edge seed={seed} error={error:?}"
            )
        });
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
    .unwrap_or_else(|error| {
        panic!("fixture=delegation_chain mutation=fixture_second_edge seed={seed} error={error:?}")
    });
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
    let mutation_index = seed % 32;
    let remove = |value: &mut Value, object_pointer: &str, key: &str| {
        remove_with_context(
            value,
            object_pointer,
            key,
            "delegation_chain",
            mutation_index,
            seed,
        );
    };
    let set = |value: &mut Value, pointer: &str, replacement: Value| {
        set_with_context(
            value,
            pointer,
            replacement,
            "delegation_chain",
            mutation_index,
            seed,
        );
    };
    let baseline = serialize("delegation_chain", chain, seed);
    let mut value = baseline.clone();
    let mutation = match mutation_index {
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
                .unwrap_or_else(|| {
                    panic!(
                        "fixture=delegation_chain mutation=chain.reordered_edges seed={seed} grants_not_array"
                    )
                })
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
    assert_ne!(
        value, baseline,
        "fixture=delegation_chain mutation={mutation} seed={seed} serialized_mutation_equaled_baseline"
    );
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
        let chain = match deserialize::<DelegationChain>(case, value) {
            Ok(chain) => chain,
            Err(error) => {
                assert!(
                    matches!(seed % 32, 0..=5),
                    "{case} unexpected_serde_rejection={error}"
                );
                continue;
            }
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
        let positive_obligation_grant: CapabilityGrant = deserialize(
            Case {
                fixture: "obligation_metadata",
                mutation: "positive_round_trip",
                seed,
            },
            serialize("obligation_grant", &obligation_grant, seed),
        )
        .unwrap_or_else(|error| {
            panic!("fixture=obligation_metadata mutation=positive_round_trip seed={seed} error={error}")
        });
        let conditional = validate_local_profile_grant(positive_obligation_grant)
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
                let mut serialized = SerializedMutation::new(
                    case,
                    serialize("capability_grant", &fixture.grant, seed),
                );
                serialized.insert("", "metadata", json!({"outer": hostile}));
                let value = serialized.finish();
                let raw: CapabilityGrant = deserialize(case, value)
                    .unwrap_or_else(|error| panic!("{case} serde_error={error}"));
                assert!(
                    validate_local_profile_grant(raw).is_err(),
                    "{case} unexpectedly_validated"
                );
            }
            1 => {
                let mut serialized = SerializedMutation::new(
                    case,
                    serialize("capability_request", &fixture.request, seed),
                );
                serialized.insert("", "metadata", json!({"outer": hostile}));
                let value = serialized.finish();
                let request: CapabilityRequest = deserialize(case, value)
                    .unwrap_or_else(|error| panic!("{case} serde_error={error}"));
                let raw_request = serde_json::to_string(&request)
                    .unwrap_or_else(|error| panic!("{case} raw_request_serde_error={error}"));
                let sentinel = format!("auth007b-sensitive-sentinel-{seed}");
                assert!(
                    raw_request.contains(&sentinel),
                    "{case} raw_request_missing_hostile_sentinel"
                );
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
                    !encoded.contains(&sentinel),
                    "{case} leaked_hostile_metadata"
                );
                assert_eq!(redacted.decision_id, decision.decision_id, "{case}");
                assert_eq!(redacted.status, AuthorityDecisionStatus::Denied, "{case}");
                assert_eq!(
                    redacted.reason_codes,
                    vec!["metadata_reserved_authority_key"],
                    "{case} safe_reason_structure_changed"
                );
                assert!(
                    !redacted.explanation.branches.is_empty(),
                    "{case} safe_explanation_structure_missing"
                );
            }
            _ => {
                let mut serialized = SerializedMutation::new(
                    case,
                    serialize("obligation_grant", &obligation_grant, seed),
                );
                serialized.set("/obligations/0/parameters", json!({"outer": hostile}));
                let value = serialized.finish();
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
