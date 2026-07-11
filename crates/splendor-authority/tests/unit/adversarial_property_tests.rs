use super::*;
use crate::capability::validate_local_profile_grant;
use splendor_types::{
    AgentId, ArtifactId, AuthorityBudgetScope, AuthorityDecision, AuthorityDecisionId,
    AuthorityDecisionStatus, AuthorityOperation, AuthorityOperationNamespace,
    AuthorityResourceKind, AuthorityRevocationId, AuthorityTimeScope, AuthorityVerb,
    CapabilityGrant, CapabilityGrantId, CapabilityGrantValidation, CapabilityGrantValidationKind,
    CapabilityRequest, CapabilityScope, DataPurpose, DelegationResultContract,
    DelegationRoleProfile, DeviceId, DriverOperationRef, FleetId, LocalityScope, NetworkScope,
    PrincipalId, RevocationRecord, RevocationStatus, RunId, StatePartitionId, TenantId, WorkloadId,
    AUTHORITY_DECISION_SCHEMA_VERSION, AUTHORITY_OPERATION_SCHEMA_VERSION,
    CAPABILITY_GRANT_SCHEMA_VERSION, CAPABILITY_REQUEST_SCHEMA_VERSION,
    DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION, REVOCATION_RECORD_SCHEMA_VERSION,
    TASK_RESPONSE_SCHEMA,
};
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime};

const ALGEBRA_CASES: u64 = 256;
const BUDGET_CASES: u64 = 512;
const EVIDENCE_CASES: u64 = 512;
const AUDIENCE: &str = "daemon:local";
const OTHER_AUDIENCE: &str = "daemon:other";
const VALIDATION_DIGEST: &str =
    "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Clone, Debug)]
struct Seeded(u64);

impl Seeded {
    fn new(seed: u64, domain: u64) -> Self {
        Self(seed ^ domain)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn bool(&mut self) -> bool {
        self.next() & 1 == 1
    }

    fn bounded(&mut self, upper: u64) -> u64 {
        self.next() % upper
    }
}

fn id_text(seed: u64, tag: u32, slot: u8) -> String {
    let serial = ((seed + 1) << 8) | u64::from(slot);
    format!("{tag:08x}-0000-4000-8000-{serial:012x}")
}

fn tenant_id(seed: u64, slot: u8) -> TenantId {
    TenantId::parse(&id_text(seed, 0x1000_0001, slot))
        .unwrap_or_else(|error| panic!("seed={seed} case=tenant_id slot={slot} error={error}"))
}

fn fleet_id(seed: u64, slot: u8) -> FleetId {
    FleetId::parse(&id_text(seed, 0x1000_0002, slot))
        .unwrap_or_else(|error| panic!("seed={seed} case=fleet_id slot={slot} error={error}"))
}

fn agent_id(seed: u64, slot: u8) -> AgentId {
    AgentId::parse(&id_text(seed, 0x1000_0003, slot))
        .unwrap_or_else(|error| panic!("seed={seed} case=agent_id slot={slot} error={error}"))
}

fn run_id(seed: u64, slot: u8) -> RunId {
    RunId::parse(&id_text(seed, 0x1000_0004, slot))
        .unwrap_or_else(|error| panic!("seed={seed} case=run_id slot={slot} error={error}"))
}

fn workload_id(seed: u64, slot: u8) -> WorkloadId {
    WorkloadId::parse(&id_text(seed, 0x1000_0005, slot))
        .unwrap_or_else(|error| panic!("seed={seed} case=workload_id slot={slot} error={error}"))
}

fn device_id(seed: u64, slot: u8) -> DeviceId {
    DeviceId::parse(&id_text(seed, 0x1000_0006, slot))
        .unwrap_or_else(|error| panic!("seed={seed} case=device_id slot={slot} error={error}"))
}

fn artifact_id(seed: u64, slot: u8) -> ArtifactId {
    ArtifactId::parse(&id_text(seed, 0x1000_0007, slot))
        .unwrap_or_else(|error| panic!("seed={seed} case=artifact_id slot={slot} error={error}"))
}

fn state_partition_id(seed: u64, slot: u8) -> StatePartitionId {
    StatePartitionId::parse(&id_text(seed, 0x1000_0008, slot)).unwrap_or_else(|error| {
        panic!("seed={seed} case=state_partition_id slot={slot} error={error}")
    })
}

fn principal_id(seed: u64, slot: u8) -> PrincipalId {
    PrincipalId::parse(&id_text(seed, 0x1000_0009, slot))
        .unwrap_or_else(|error| panic!("seed={seed} case=principal_id slot={slot} error={error}"))
}

fn grant_id(seed: u64, slot: u8) -> CapabilityGrantId {
    CapabilityGrantId::parse(&id_text(seed, 0x1000_000a, slot)).unwrap_or_else(|error| {
        panic!("seed={seed} case=capability_grant_id slot={slot} error={error}")
    })
}

fn decision_id(seed: u64, slot: u8) -> AuthorityDecisionId {
    AuthorityDecisionId::parse(&id_text(seed, 0x1000_000b, slot)).unwrap_or_else(|error| {
        panic!("seed={seed} case=authority_decision_id slot={slot} error={error}")
    })
}

fn revocation_id(seed: u64, slot: u8) -> AuthorityRevocationId {
    AuthorityRevocationId::parse(&id_text(seed, 0x1000_000c, slot)).unwrap_or_else(|error| {
        panic!("seed={seed} case=authority_revocation_id slot={slot} error={error}")
    })
}

fn fixed_time(seed: u64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000 + seed as i64)
        .unwrap_or_else(|error| panic!("seed={seed} case=fixed_time error={error}"))
}

fn generated_values<T: Clone>(rng: &mut Seeded, common: T, extra: T) -> Option<Vec<T>> {
    if rng.bounded(4) == 0 {
        return None;
    }
    let mut values = vec![common.clone()];
    if rng.bool() {
        values.push(extra);
    }
    if rng.bool() {
        values.push(common);
    }
    if rng.bool() {
        values.reverse();
    }
    Some(values)
}

fn generated_budget(rng: &mut Seeded) -> AuthorityBudgetScope {
    let u32_limit = |rng: &mut Seeded| match rng.bounded(5) {
        0 => None,
        1 => Some(0),
        2 => Some(u32::MAX),
        _ => Some(rng.next() as u32),
    };
    let u64_limit = |rng: &mut Seeded| match rng.bounded(5) {
        0 => None,
        1 => Some(0),
        2 => Some(u64::MAX),
        _ => Some(rng.next()),
    };
    AuthorityBudgetScope {
        max_actions_per_tick: u32_limit(rng),
        max_action_duration_ms: u64_limit(rng),
        max_filesystem_read_bytes: u64_limit(rng),
        max_filesystem_write_bytes: u64_limit(rng),
        max_network_read_bytes: u64_limit(rng),
        max_network_write_bytes: u64_limit(rng),
        max_http_requests_per_minute: u32_limit(rng),
    }
}

fn generated_scope(seed: u64, side: u8, rng: &mut Seeded) -> CapabilityScope {
    let now = fixed_time(seed);
    let start_offset = rng.bounded(20) as i64;
    let end_offset = 80 + rng.bounded(20) as i64;
    CapabilityScope {
        tenant_ids: generated_values(rng, tenant_id(seed, 1), tenant_id(seed, 10 + side)),
        fleet_ids: generated_values(rng, fleet_id(seed, 1), fleet_id(seed, 10 + side)),
        agent_ids: generated_values(rng, agent_id(seed, 1), agent_id(seed, 10 + side)),
        run_ids: generated_values(rng, run_id(seed, 1), run_id(seed, 10 + side)),
        workload_ids: generated_values(rng, workload_id(seed, 1), workload_id(seed, 10 + side)),
        device_ids: generated_values(rng, device_id(seed, 1), device_id(seed, 10 + side)),
        data_purposes: generated_values(rng, DataPurpose::Read, DataPurpose::TrainingUse),
        artifact_ids: generated_values(rng, artifact_id(seed, 1), artifact_id(seed, 10 + side)),
        state_partition_ids: generated_values(
            rng,
            state_partition_id(seed, 1),
            state_partition_id(seed, 10 + side),
        ),
        driver_operations: generated_values(
            rng,
            DriverOperationRef {
                driver: "artifact-store".to_string(),
                operation: "create".to_string(),
                schema_version: "splendor.driver.artifact.v1".to_string(),
            },
            DriverOperationRef {
                driver: format!("driver-{side}"),
                operation: "read".to_string(),
                schema_version: "splendor.driver.test.v1".to_string(),
            },
        ),
        audiences: generated_values(rng, AUDIENCE.to_string(), format!("daemon:side-{side}")),
        time: AuthorityTimeScope {
            not_before: rng.bool().then_some(now + Duration::seconds(start_offset)),
            expires_at: rng.bool().then_some(now + Duration::seconds(end_offset)),
        },
        budget: generated_budget(rng),
        network: NetworkScope {
            egress_schemes: generated_values(rng, "https".to_string(), format!("scheme{side}")),
            egress_hosts: generated_values(
                rng,
                "api.internal".to_string(),
                format!("side-{side}.internal"),
            ),
        },
        locality: LocalityScope {
            regions: generated_values(rng, "eu-west".to_string(), format!("region-{side}")),
            zones: generated_values(rng, "eu-west-1a".to_string(), format!("zone-{side}")),
            data_localities: generated_values(
                rng,
                "restricted-eu".to_string(),
                format!("locality-{side}"),
            ),
        },
        ..Default::default()
    }
}

fn canonicalize<T: std::fmt::Debug + PartialEq>(values: &mut Option<Vec<T>>) {
    if let Some(values) = values {
        values.sort_by_key(|value| format!("{value:?}"));
        values.dedup();
    }
}

fn canonical_scope(mut scope: CapabilityScope) -> CapabilityScope {
    canonicalize(&mut scope.tenant_ids);
    canonicalize(&mut scope.fleet_ids);
    canonicalize(&mut scope.agent_ids);
    canonicalize(&mut scope.run_ids);
    canonicalize(&mut scope.workload_ids);
    canonicalize(&mut scope.device_ids);
    canonicalize(&mut scope.data_purposes);
    canonicalize(&mut scope.artifact_ids);
    canonicalize(&mut scope.state_partition_ids);
    canonicalize(&mut scope.driver_operations);
    canonicalize(&mut scope.audiences);
    canonicalize(&mut scope.network.egress_schemes);
    canonicalize(&mut scope.network.egress_hosts);
    canonicalize(&mut scope.locality.regions);
    canonicalize(&mut scope.locality.zones);
    canonicalize(&mut scope.locality.data_localities);
    scope
}

fn option_narrows<T: PartialEq>(candidate: &Option<Vec<T>>, parent: &Option<Vec<T>>) -> bool {
    match parent {
        None => true,
        Some(parent) => candidate.as_ref().is_some_and(|candidate| {
            candidate
                .iter()
                .all(|value| parent.iter().any(|parent| parent == value))
        }),
    }
}

fn option_limit_narrows<T: Ord + Copy>(candidate: Option<T>, parent: Option<T>) -> bool {
    match parent {
        None => true,
        Some(parent) => candidate.is_some_and(|candidate| candidate <= parent),
    }
}

fn assert_budget_narrows(
    candidate: AuthorityBudgetScope,
    parent: AuthorityBudgetScope,
    seed: u64,
    label: &str,
) {
    assert!(
        option_limit_narrows(candidate.max_actions_per_tick, parent.max_actions_per_tick),
        "seed={seed} case={label}.max_actions_per_tick"
    );
    assert!(
        option_limit_narrows(
            candidate.max_action_duration_ms,
            parent.max_action_duration_ms,
        ),
        "seed={seed} case={label}.max_action_duration_ms"
    );
    assert!(
        option_limit_narrows(
            candidate.max_filesystem_read_bytes,
            parent.max_filesystem_read_bytes,
        ),
        "seed={seed} case={label}.max_filesystem_read_bytes"
    );
    assert!(
        option_limit_narrows(
            candidate.max_filesystem_write_bytes,
            parent.max_filesystem_write_bytes,
        ),
        "seed={seed} case={label}.max_filesystem_write_bytes"
    );
    assert!(
        option_limit_narrows(
            candidate.max_network_read_bytes,
            parent.max_network_read_bytes,
        ),
        "seed={seed} case={label}.max_network_read_bytes"
    );
    assert!(
        option_limit_narrows(
            candidate.max_network_write_bytes,
            parent.max_network_write_bytes,
        ),
        "seed={seed} case={label}.max_network_write_bytes"
    );
    assert!(
        option_limit_narrows(
            candidate.max_http_requests_per_minute,
            parent.max_http_requests_per_minute,
        ),
        "seed={seed} case={label}.max_http_requests_per_minute"
    );
}

fn assert_scope_narrows(candidate: &CapabilityScope, parent: &CapabilityScope, seed: u64) {
    let checks = [
        option_narrows(&candidate.tenant_ids, &parent.tenant_ids),
        option_narrows(&candidate.fleet_ids, &parent.fleet_ids),
        option_narrows(&candidate.agent_ids, &parent.agent_ids),
        option_narrows(&candidate.run_ids, &parent.run_ids),
        option_narrows(&candidate.workload_ids, &parent.workload_ids),
        option_narrows(&candidate.device_ids, &parent.device_ids),
        option_narrows(&candidate.data_purposes, &parent.data_purposes),
        option_narrows(&candidate.artifact_ids, &parent.artifact_ids),
        option_narrows(&candidate.state_partition_ids, &parent.state_partition_ids),
        option_narrows(&candidate.driver_operations, &parent.driver_operations),
        option_narrows(&candidate.audiences, &parent.audiences),
        option_narrows(
            &candidate.network.egress_schemes,
            &parent.network.egress_schemes,
        ),
        option_narrows(
            &candidate.network.egress_hosts,
            &parent.network.egress_hosts,
        ),
        option_narrows(&candidate.locality.regions, &parent.locality.regions),
        option_narrows(&candidate.locality.zones, &parent.locality.zones),
        option_narrows(
            &candidate.locality.data_localities,
            &parent.locality.data_localities,
        ),
    ];
    assert!(
        checks.into_iter().all(|check| check),
        "seed={seed} case=scope_set_monotonicity candidate={candidate:?} parent={parent:?}"
    );
    if let Some(parent_start) = parent.time.not_before {
        assert!(
            candidate
                .time
                .not_before
                .is_some_and(|candidate| candidate >= parent_start),
            "seed={seed} case=time_start_monotonicity"
        );
    }
    if let Some(parent_end) = parent.time.expires_at {
        assert!(
            candidate
                .time
                .expires_at
                .is_some_and(|candidate| candidate <= parent_end),
            "seed={seed} case=time_end_monotonicity"
        );
    }
    assert_budget_narrows(candidate.budget, parent.budget, seed, "scope_budget");
}

fn gateway_operation(name: &str) -> AuthorityOperation {
    gateway_action_operation(name)
}

fn agent_delegate_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Agent,
        resource_kind: AuthorityResourceKind::Agent,
        verb: AuthorityVerb::Delegate,
        name: None,
        resource_schema_version: Some("splendor.agent.v1".to_string()),
    }
}

fn validation() -> CapabilityGrantValidation {
    CapabilityGrantValidation {
        validation_kind: CapabilityGrantValidationKind::LocallyValidated,
        algorithm: "local-property-v1".to_string(),
        key_id: None,
        digest: VALIDATION_DIGEST.to_string(),
        signature: None,
    }
}

fn authority_scope(seed: u64, agent: AgentId, run: RunId, audience: &str) -> CapabilityScope {
    CapabilityScope {
        tenant_ids: Some(vec![tenant_id(seed, 1)]),
        agent_ids: Some(vec![agent]),
        run_ids: Some(vec![run]),
        audiences: Some(vec![audience.to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(8),
            max_action_duration_ms: Some(10_000),
            ..Default::default()
        },
        ..Default::default()
    }
}

struct GrantSpec {
    slot: u8,
    subject: PrincipalId,
    operation: AuthorityOperation,
    scope: CapabilityScope,
    not_before: OffsetDateTime,
    expires_at: OffsetDateTime,
    depth: u32,
    revocation: RevocationStatus,
}

fn validated_grant(seed: u64, spec: GrantSpec) -> ValidatedCapabilityGrant {
    let raw = CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: grant_id(seed, spec.slot),
        issuer: principal_id(seed, spec.slot.saturating_add(100)),
        subject: spec.subject,
        parent_grant_ids: Vec::new(),
        operations: vec![spec.operation],
        scope: spec.scope,
        not_before: spec.not_before,
        expires_at: spec.expires_at,
        revocation_ref: Some("revocation:property".to_string()),
        revocation: spec.revocation,
        obligations: Vec::new(),
        max_delegation_depth: spec.depth,
        validation: Some(validation()),
        metadata: BTreeMap::new(),
    };
    validate_local_profile_grant(raw)
        .unwrap_or_else(|error| panic!("seed={seed} case=validated_grant error={error:?}"))
}

fn request(
    subject: PrincipalId,
    operation: AuthorityOperation,
    mut scope: CapabilityScope,
    now: OffsetDateTime,
) -> CapabilityRequest {
    scope.budget.max_actions_per_tick = Some(1);
    scope.budget.max_action_duration_ms = Some(1_000);
    CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject,
        operation,
        scope,
        requested_at: now,
        metadata: BTreeMap::new(),
    }
}

#[test]
fn adversarial_property_scope_intersection_is_monotonic_commutative_and_idempotent() {
    for seed in 0..ALGEBRA_CASES {
        let mut left_rng = Seeded::new(seed, 0x51c0_0001);
        let mut right_rng = Seeded::new(seed, 0x51c0_0002);
        let left = generated_scope(seed, 1, &mut left_rng);
        let right = generated_scope(seed, 2, &mut right_rng);

        let left_right = intersect_capability_scopes(&left, &right)
            .unwrap_or_else(|error| panic!("seed={seed} case=left_right error={error:?}"));
        let right_left = intersect_capability_scopes(&right, &left)
            .unwrap_or_else(|error| panic!("seed={seed} case=right_left error={error:?}"));
        assert_scope_narrows(&left_right, &left, seed);
        assert_scope_narrows(&left_right, &right, seed);
        assert_eq!(
            canonical_scope(left_right),
            canonical_scope(right_left),
            "seed={seed} case=commutative_after_set_normalization"
        );

        let idempotent = intersect_capability_scopes(&left, &left)
            .unwrap_or_else(|error| panic!("seed={seed} case=idempotent error={error:?}"));
        assert_eq!(idempotent, left, "seed={seed} case=idempotent");
    }
}

fn disjoint_scopes(
    seed: u64,
    dimension: usize,
) -> (CapabilityScope, CapabilityScope, &'static str) {
    let mut left = CapabilityScope::default();
    let mut right = CapabilityScope::default();
    let name = match dimension {
        0 => {
            left.tenant_ids = Some(vec![tenant_id(seed, 1)]);
            right.tenant_ids = Some(vec![tenant_id(seed, 2)]);
            "tenant_ids"
        }
        1 => {
            left.fleet_ids = Some(vec![fleet_id(seed, 1)]);
            right.fleet_ids = Some(vec![fleet_id(seed, 2)]);
            "fleet_ids"
        }
        2 => {
            left.agent_ids = Some(vec![agent_id(seed, 1)]);
            right.agent_ids = Some(vec![agent_id(seed, 2)]);
            "agent_ids"
        }
        3 => {
            left.run_ids = Some(vec![run_id(seed, 1)]);
            right.run_ids = Some(vec![run_id(seed, 2)]);
            "run_ids"
        }
        4 => {
            left.workload_ids = Some(vec![workload_id(seed, 1)]);
            right.workload_ids = Some(vec![workload_id(seed, 2)]);
            "workload_ids"
        }
        5 => {
            left.device_ids = Some(vec![device_id(seed, 1)]);
            right.device_ids = Some(vec![device_id(seed, 2)]);
            "device_ids"
        }
        6 => {
            left.data_purposes = Some(vec![DataPurpose::Read]);
            right.data_purposes = Some(vec![DataPurpose::Publication]);
            "data_purposes"
        }
        7 => {
            left.artifact_ids = Some(vec![artifact_id(seed, 1)]);
            right.artifact_ids = Some(vec![artifact_id(seed, 2)]);
            "artifact_ids"
        }
        8 => {
            left.state_partition_ids = Some(vec![state_partition_id(seed, 1)]);
            right.state_partition_ids = Some(vec![state_partition_id(seed, 2)]);
            "state_partition_ids"
        }
        9 => {
            left.driver_operations = Some(vec![DriverOperationRef {
                driver: "driver-a".to_string(),
                operation: "read".to_string(),
                schema_version: "splendor.driver.test.v1".to_string(),
            }]);
            right.driver_operations = Some(vec![DriverOperationRef {
                driver: "driver-b".to_string(),
                operation: "read".to_string(),
                schema_version: "splendor.driver.test.v1".to_string(),
            }]);
            "driver_operations"
        }
        10 => {
            left.audiences = Some(vec![AUDIENCE.to_string()]);
            right.audiences = Some(vec![OTHER_AUDIENCE.to_string()]);
            "audiences"
        }
        11 => {
            left.network.egress_schemes = Some(vec!["https".to_string()]);
            right.network.egress_schemes = Some(vec!["wss".to_string()]);
            "network.egress_schemes"
        }
        12 => {
            left.network.egress_hosts = Some(vec!["a.internal".to_string()]);
            right.network.egress_hosts = Some(vec!["b.internal".to_string()]);
            "network.egress_hosts"
        }
        13 => {
            left.locality.regions = Some(vec!["eu-west".to_string()]);
            right.locality.regions = Some(vec!["us-east".to_string()]);
            "locality.regions"
        }
        14 => {
            left.locality.zones = Some(vec!["eu-west-1a".to_string()]);
            right.locality.zones = Some(vec!["eu-west-1b".to_string()]);
            "locality.zones"
        }
        15 => {
            left.locality.data_localities = Some(vec!["eu".to_string()]);
            right.locality.data_localities = Some(vec!["us".to_string()]);
            "locality.data_localities"
        }
        _ => {
            let now = fixed_time(seed);
            left.time = AuthorityTimeScope {
                not_before: Some(now),
                expires_at: Some(now + Duration::seconds(10)),
            };
            right.time = AuthorityTimeScope {
                not_before: Some(now + Duration::seconds(10)),
                expires_at: Some(now + Duration::seconds(20)),
            };
            "time"
        }
    };
    (left, right, name)
}

#[test]
fn adversarial_property_disjoint_and_empty_scope_dimensions_fail_deterministically() {
    for seed in 0..ALGEBRA_CASES {
        let (left, right, dimension) = disjoint_scopes(seed, seed as usize % 17);
        let first = match intersect_capability_scopes(&left, &right) {
            Err(error) => error,
            Ok(value) => {
                panic!("seed={seed} case=disjoint_left_right unexpectedly_allowed={value:?}")
            }
        };
        let second = match intersect_capability_scopes(&left, &right) {
            Err(error) => error,
            Ok(value) => {
                panic!("seed={seed} case=disjoint_repeat unexpectedly_allowed={value:?}")
            }
        };
        assert_eq!(first, second, "seed={seed} case=stable_disjoint_error");
        assert_eq!(
            first.reason_code(),
            format!("empty_intersection:{dimension}"),
            "seed={seed} case=disjoint_dimension"
        );

        let mut empty = left;
        empty.tenant_ids = Some(Vec::new());
        let first = match intersect_capability_scopes(&empty, &right) {
            Err(error) => error,
            Ok(value) => {
                panic!("seed={seed} case=empty_left_right unexpectedly_allowed={value:?}")
            }
        };
        let second = match intersect_capability_scopes(&empty, &right) {
            Err(error) => error,
            Ok(value) => {
                panic!("seed={seed} case=empty_repeat unexpectedly_allowed={value:?}")
            }
        };
        assert_eq!(first, second, "seed={seed} case=stable_empty_error");
        assert_eq!(
            first.reason_code(),
            "invalid_scope:tenant_ids:empty_scope_set",
            "seed={seed} case=empty_dimension"
        );
    }
}

#[test]
fn adversarial_property_budget_intersection_accumulates_only_narrower_limits() {
    for seed in 0..BUDGET_CASES {
        let mut rng = Seeded::new(seed, 0xb0d6_0001);
        let left_budget = generated_budget(&mut rng);
        let middle_budget = generated_budget(&mut rng);
        let right_budget = generated_budget(&mut rng);
        let scope = |budget| CapabilityScope {
            budget,
            ..Default::default()
        };
        let left = scope(left_budget);
        let middle = scope(middle_budget);
        let right = scope(right_budget);

        let left_middle = intersect_capability_scopes(&left, &middle)
            .unwrap_or_else(|error| panic!("seed={seed} case=budget_left_middle {error:?}"));
        assert_budget_narrows(left_middle.budget, left_budget, seed, "left");
        assert_budget_narrows(left_middle.budget, middle_budget, seed, "middle");

        let accumulated = intersect_capability_scopes(&left_middle, &right)
            .unwrap_or_else(|error| panic!("seed={seed} case=budget_accumulated {error:?}"));
        assert_budget_narrows(accumulated.budget, left_budget, seed, "accumulated_left");
        assert_budget_narrows(
            accumulated.budget,
            middle_budget,
            seed,
            "accumulated_middle",
        );
        assert_budget_narrows(accumulated.budget, right_budget, seed, "accumulated_right");

        let middle_right = intersect_capability_scopes(&middle, &right)
            .unwrap_or_else(|error| panic!("seed={seed} case=budget_middle_right {error:?}"));
        let regrouped = intersect_capability_scopes(&left, &middle_right)
            .unwrap_or_else(|error| panic!("seed={seed} case=budget_regrouped {error:?}"));
        assert_eq!(
            accumulated.budget, regrouped.budget,
            "seed={seed} case=budget_associative_without_overflow"
        );
    }
}

#[test]
fn adversarial_property_time_boundaries_and_unrelated_grants_fail_closed() {
    for seed in 0..ALGEBRA_CASES {
        let now = fixed_time(seed);
        let lifetime = Duration::seconds(2 + (seed % 59) as i64);
        let subject = principal_id(seed, 1);
        let operation = gateway_operation("artifact.create");
        let scope = authority_scope(seed, agent_id(seed, 1), run_id(seed, 1), AUDIENCE);
        let grant = validated_grant(
            seed,
            GrantSpec {
                slot: 1,
                subject: subject.clone(),
                operation: operation.clone(),
                scope: scope.clone(),
                not_before: now,
                expires_at: now + lifetime,
                depth: 2,
                revocation: RevocationStatus::Active,
            },
        );
        let request = request(subject.clone(), operation.clone(), scope.clone(), now);

        let at_start = evaluate_capability_request(std::slice::from_ref(&grant), &request, now);
        assert_eq!(
            at_start.status,
            AuthorityDecisionStatus::Allowed,
            "seed={seed} case=exact_not_before"
        );
        let before_start = evaluate_capability_request(
            std::slice::from_ref(&grant),
            &request,
            now - Duration::seconds(1),
        );
        assert_eq!(
            before_start.status,
            AuthorityDecisionStatus::Denied,
            "seed={seed} case=before_not_before"
        );
        assert!(
            before_start
                .reasons
                .contains(&"grant_not_yet_valid".to_string()),
            "seed={seed} case=before_not_before_reason reasons={:?}",
            before_start.reasons
        );

        let at_expiry =
            evaluate_capability_request(std::slice::from_ref(&grant), &request, now + lifetime);
        assert_eq!(
            at_expiry.status,
            AuthorityDecisionStatus::Denied,
            "seed={seed} case=exact_expiry"
        );
        assert!(
            at_expiry.reasons.contains(&"expired_grant".to_string()),
            "seed={seed} case=exact_expiry_reason reasons={:?}",
            at_expiry.reasons
        );

        let unrelated = validated_grant(
            seed,
            GrantSpec {
                slot: 2,
                subject: principal_id(seed, 2),
                operation: gateway_operation("artifact.publish"),
                scope,
                not_before: now - Duration::hours(1),
                expires_at: now + Duration::hours(1),
                depth: 0,
                revocation: RevocationStatus::Active,
            },
        );
        let expired_with_unrelated = evaluate_capability_request(
            &[grant.clone(), unrelated.clone()],
            &request,
            now + lifetime,
        );
        let future_with_unrelated =
            evaluate_capability_request(&[grant, unrelated], &request, now - Duration::seconds(1));
        assert_eq!(
            expired_with_unrelated.status,
            AuthorityDecisionStatus::Denied,
            "seed={seed} case=expired_plus_unrelated"
        );
        assert_eq!(
            future_with_unrelated.status,
            AuthorityDecisionStatus::Denied,
            "seed={seed} case=future_plus_unrelated"
        );
    }
}

#[test]
fn adversarial_property_audience_subject_and_metadata_cannot_create_authority() {
    const RESERVED_KEYS: &[&str] = &[
        "allowedActions",
        "AUTHORIZATION",
        "quota_override",
        "work-order-id",
        "capability.grant",
    ];
    for seed in 0..ALGEBRA_CASES {
        let now = fixed_time(seed);
        let subject = principal_id(seed, 1);
        let operation = gateway_operation("artifact.create");
        let request_scope =
            authority_scope(seed, agent_id(seed, 1), run_id(seed, 1), OTHER_AUDIENCE);
        let mut hostile_request = request(
            subject.clone(),
            operation.clone(),
            request_scope.clone(),
            now,
        );
        hostile_request.metadata.insert(
            format!("x_hostile_note_{seed}"),
            serde_json::json!({"claim": "allow", "actions": ["*"]}),
        );

        let wrong_subject = validated_grant(
            seed,
            GrantSpec {
                slot: 1,
                subject: principal_id(seed, 2),
                operation: operation.clone(),
                scope: request_scope.clone(),
                not_before: now - Duration::minutes(1),
                expires_at: now + Duration::minutes(10),
                depth: 0,
                revocation: RevocationStatus::Active,
            },
        );
        let wrong_audience = validated_grant(
            seed,
            GrantSpec {
                slot: 2,
                subject: subject.clone(),
                operation: operation.clone(),
                scope: authority_scope(seed, agent_id(seed, 1), run_id(seed, 1), AUDIENCE),
                not_before: now - Duration::minutes(1),
                expires_at: now + Duration::minutes(10),
                depth: 0,
                revocation: RevocationStatus::Active,
            },
        );
        let unrelated = validated_grant(
            seed,
            GrantSpec {
                slot: 3,
                subject,
                operation: gateway_operation("artifact.publish"),
                scope: request_scope,
                not_before: now - Duration::minutes(1),
                expires_at: now + Duration::minutes(10),
                depth: 0,
                revocation: RevocationStatus::Active,
            },
        );
        let grants = [wrong_subject, wrong_audience, unrelated];
        let first = evaluate_capability_request(&grants, &hostile_request, now);
        let second = evaluate_capability_request(&grants, &hostile_request, now);
        assert_eq!(
            first.status,
            AuthorityDecisionStatus::Denied,
            "seed={seed} case=mismatch_denial"
        );
        assert_eq!(
            (first.status, &first.reasons),
            (second.status, &second.reasons),
            "seed={seed} case=mismatch_determinism"
        );

        let mut reserved = hostile_request;
        reserved.metadata.insert(
            RESERVED_KEYS[seed as usize % RESERVED_KEYS.len()].to_string(),
            serde_json::json!("allow"),
        );
        let reserved_decision = evaluate_capability_request(&grants, &reserved, now);
        assert_eq!(
            reserved_decision.status,
            AuthorityDecisionStatus::Denied,
            "seed={seed} case=reserved_metadata_denial"
        );
        assert_eq!(
            reserved_decision.reasons,
            vec!["metadata_reserved_authority_key"],
            "seed={seed} case=reserved_metadata_reason"
        );

        let mut malformed = grants[0].grant().clone();
        malformed.grant_id = grant_id(seed, 10);
        malformed.scope.audiences = Some(vec!["daemon:*".to_string()]);
        let first = match validate_local_profile_grant(malformed.clone()) {
            Err(error) => error,
            Ok(value) => {
                panic!("seed={seed} case=malformed_grant unexpectedly_valid={value:?}")
            }
        };
        let second = match validate_local_profile_grant(malformed) {
            Err(error) => error,
            Ok(value) => {
                panic!("seed={seed} case=malformed_grant_repeat unexpectedly_valid={value:?}")
            }
        };
        assert_eq!(
            first.reason_code(),
            second.reason_code(),
            "seed={seed} case=malformed_grant_stable_rejection"
        );
    }
}

#[derive(Clone, Copy)]
struct DelegationShape {
    depth: u32,
    fan_out: u32,
    role: DelegationRoleProfile,
}

fn delegation_request(
    seed: u64,
    parent: &ValidatedCapabilityGrant,
    operation: AuthorityOperation,
    child_scope: CapabilityScope,
    now: OffsetDateTime,
    shape: DelegationShape,
) -> DelegationChildGrantRequest {
    DelegationChildGrantRequest {
        parent_grant_id: Some(parent.grant().grant_id.clone()),
        issuer: parent.grant().subject.clone(),
        child_subject: Some(principal_id(seed, 3)),
        child_grant_id: grant_id(seed, 3),
        parent_run_id: run_id(seed, 2),
        parent_agent_id: agent_id(seed, 2),
        child_run_id: run_id(seed, 3),
        child_agent_id: agent_id(seed, 3),
        objective: format!("bounded-objective-{seed}"),
        role_profile: shape.role,
        operations: vec![operation],
        scope: child_scope,
        allowed_message_schemas: vec![TASK_RESPONSE_SCHEMA.to_string()],
        allowed_recipient_agent_ids: vec![agent_id(seed, 2)],
        result_contract: DelegationResultContract {
            schema_version: DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION.to_string(),
            result_schema: TASK_RESPONSE_SCHEMA.to_string(),
            requires_response: true,
            max_result_bytes: Some(1_024 + seed),
        },
        not_before: now,
        expires_at: now + Duration::minutes(10),
        max_delegation_depth: shape.depth,
        max_fan_out: shape.fan_out,
        validation_digest: VALIDATION_DIGEST.to_string(),
    }
}

fn delegation_context(
    seed: u64,
    now: OffsetDateTime,
    limit: u32,
    current: u32,
) -> DelegationValidationContext {
    DelegationValidationContext {
        now,
        audience: AUDIENCE.to_string(),
        expected_child_subject: principal_id(seed, 3),
        parent_fan_out_limit: limit,
        current_parent_fan_out: current,
    }
}

fn delegation_denial(
    seed: u64,
    case: &str,
    result: Result<DelegationChildGrant, DelegationGrantError>,
) -> DelegationGrantError {
    match result {
        Err(error) => error,
        Ok(value) => panic!("seed={seed} case={case} unexpectedly_issued={value:?}"),
    }
}

#[test]
fn adversarial_property_delegation_depth_fan_out_time_budget_and_roles_fail_closed() {
    for seed in 0..ALGEBRA_CASES {
        let mut rng = Seeded::new(seed, 0xde1e_6a7e);
        let now = fixed_time(seed);
        let parent_depth = 1 + rng.bounded(8) as u32;
        let child_depth = rng.bounded(u64::from(parent_depth)) as u32;
        let fan_out = 1 + rng.bounded(8) as u32;
        let operation = gateway_operation("artifact.create");
        let mut parent_scope = authority_scope(seed, agent_id(seed, 3), run_id(seed, 3), AUDIENCE);
        parent_scope.budget.max_actions_per_tick = Some(8);
        let parent = validated_grant(
            seed,
            GrantSpec {
                slot: 1,
                subject: principal_id(seed, 2),
                operation: operation.clone(),
                scope: parent_scope.clone(),
                not_before: now - Duration::minutes(1),
                expires_at: now + Duration::minutes(20),
                depth: parent_depth,
                revocation: RevocationStatus::Active,
            },
        );
        let mut child_scope = parent_scope;
        child_scope.budget.max_actions_per_tick = Some(1 + rng.bounded(8) as u32);
        child_scope.budget.max_action_duration_ms = Some(1 + rng.bounded(10_000));
        let request = delegation_request(
            seed,
            &parent,
            operation.clone(),
            child_scope.clone(),
            now,
            DelegationShape {
                depth: child_depth,
                fan_out,
                role: DelegationRoleProfile::Specialist,
            },
        );
        let issued = issue_delegation_child_grant(
            &parent,
            request.clone(),
            delegation_context(seed, now, fan_out, 0),
        )
        .unwrap_or_else(|error| panic!("seed={seed} case=valid_delegation error={error:?}"));
        assert!(
            issued.child_grant().grant().max_delegation_depth < parent_depth,
            "seed={seed} case=depth_strictly_narrows"
        );
        assert_budget_narrows(
            issued.child_grant().grant().scope.budget,
            parent.grant().scope.budget,
            seed,
            "delegated_budget",
        );

        let exhausted = validated_grant(
            seed,
            GrantSpec {
                slot: 4,
                subject: principal_id(seed, 2),
                operation: operation.clone(),
                scope: child_scope.clone(),
                not_before: now - Duration::minutes(1),
                expires_at: now + Duration::minutes(20),
                depth: 0,
                revocation: RevocationStatus::Active,
            },
        );
        let exhausted_reason = delegation_denial(
            seed,
            "depth_exhaustion",
            issue_delegation_child_grant(
                &exhausted,
                delegation_request(
                    seed,
                    &exhausted,
                    operation.clone(),
                    child_scope.clone(),
                    now,
                    DelegationShape {
                        depth: 0,
                        fan_out,
                        role: DelegationRoleProfile::Specialist,
                    },
                ),
                delegation_context(seed, now, fan_out, 0),
            ),
        )
        .reason_code();
        assert_eq!(
            exhausted_reason, "delegation_depth_exhausted",
            "seed={seed} case=depth_exhaustion"
        );

        let fan_out_reason = delegation_denial(
            seed,
            "fan_out_exhaustion",
            issue_delegation_child_grant(
                &parent,
                request.clone(),
                delegation_context(seed, now, fan_out, fan_out),
            ),
        )
        .reason_code();
        assert_eq!(
            fan_out_reason, "fan_out_exceeded",
            "seed={seed} case=fan_out_exhaustion"
        );

        let mut early = request.clone();
        early.not_before = parent.grant().not_before - Duration::seconds(1);
        assert_eq!(
            delegation_denial(
                seed,
                "child_start_extension",
                issue_delegation_child_grant(
                    &parent,
                    early,
                    delegation_context(seed, now, fan_out, 0),
                ),
            )
            .reason_code(),
            "overbroad_time",
            "seed={seed} case=child_start_extension"
        );
        let mut late = request;
        late.expires_at = parent.grant().expires_at + Duration::seconds(1);
        assert_eq!(
            delegation_denial(
                seed,
                "child_expiry_extension",
                issue_delegation_child_grant(
                    &parent,
                    late,
                    delegation_context(seed, now, fan_out, 0),
                ),
            )
            .reason_code(),
            "overbroad_time",
            "seed={seed} case=child_expiry_extension"
        );

        let role = if rng.bool() {
            DelegationRoleProfile::Critic
        } else {
            DelegationRoleProfile::Evaluator
        };
        let restricted_operation = if rng.bool() {
            gateway_operation("artifact.create")
        } else {
            agent_delegate_operation()
        };
        let restricted_parent = validated_grant(
            seed,
            GrantSpec {
                slot: 5,
                subject: principal_id(seed, 2),
                operation: restricted_operation.clone(),
                scope: child_scope.clone(),
                not_before: now - Duration::minutes(1),
                expires_at: now + Duration::minutes(20),
                depth: 2,
                revocation: RevocationStatus::Active,
            },
        );
        let restricted = delegation_request(
            seed,
            &restricted_parent,
            restricted_operation,
            child_scope,
            now,
            DelegationShape {
                depth: 1,
                fan_out,
                role,
            },
        );
        assert_eq!(
            delegation_denial(
                seed,
                "role_restriction",
                issue_delegation_child_grant(
                    &restricted_parent,
                    restricted,
                    delegation_context(seed, now, fan_out, 0),
                ),
            )
            .reason_code(),
            "critic_evaluator_external_effect_operation",
            "seed={seed} case=role_restriction"
        );
    }
}

fn revocation_record(
    seed: u64,
    slot: u8,
    grant_id: CapabilityGrantId,
    status: RevocationStatus,
    now: OffsetDateTime,
) -> RevocationRecord {
    let revoked = matches!(status, RevocationStatus::Revoked { .. });
    RevocationRecord {
        schema_version: REVOCATION_RECORD_SCHEMA_VERSION.to_string(),
        revocation_id: revocation_id(seed, slot),
        grant_id,
        revocation_ref: Some("revocation:property".to_string()),
        status,
        revoked_at: revoked.then_some(now),
    }
}

fn cache_for(
    seed: u64,
    grant: ValidatedCapabilityGrant,
    cached_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> AuthorityGrantCache {
    let mut cache = AuthorityGrantCache::new();
    cache
        .insert_validated(grant, cached_at, expires_at)
        .unwrap_or_else(|error| panic!("seed={seed} case=cache_insert error={error:?}"));
    cache
}

#[test]
fn adversarial_property_revocation_and_cache_uncertainty_are_monotonic() {
    for seed in 0..ALGEBRA_CASES {
        let now = fixed_time(seed);
        let subject = principal_id(seed, 1);
        let operation = gateway_operation("artifact.create");
        let scope = authority_scope(seed, agent_id(seed, 1), run_id(seed, 1), AUDIENCE);
        let active_grant = validated_grant(
            seed,
            GrantSpec {
                slot: 1,
                subject: subject.clone(),
                operation: operation.clone(),
                scope: scope.clone(),
                not_before: now - Duration::hours(4),
                expires_at: now + Duration::hours(4),
                depth: 0,
                revocation: RevocationStatus::Active,
            },
        );
        let request = request(subject, operation, scope, now);
        let cache = cache_for(
            seed,
            active_grant.clone(),
            now - Duration::minutes(1),
            now + Duration::hours(1),
        );
        let policy = OfflineAuthorityPolicy::connected(Duration::minutes(30))
            .unwrap_or_else(|error| panic!("seed={seed} case=connected_policy error={error:?}"));
        let active_snapshot = RevocationSnapshot::with_max_age(
            Vec::new(),
            now - Duration::minutes(1),
            Duration::hours(1),
        )
        .unwrap_or_else(|error| panic!("seed={seed} case=active_snapshot error={error:?}"));
        let active = evaluate_cached_capability_request(
            &cache,
            Some(&active_snapshot),
            &policy,
            &request,
            now,
        );
        assert_eq!(
            active.status,
            AuthorityDecisionStatus::Allowed,
            "seed={seed} case=active_baseline"
        );

        let mut records = vec![revocation_record(
            seed,
            1,
            active_grant.grant().grant_id.clone(),
            RevocationStatus::Revoked {
                reason: format!("operator-revoked-{seed}"),
            },
            now,
        )];
        for slot in 2..(2 + (seed % 5) as u8) {
            records.push(revocation_record(
                seed,
                slot,
                grant_id(seed, slot.saturating_add(20)),
                RevocationStatus::Active,
                now,
            ));
        }
        let revoked_snapshot = RevocationSnapshot::with_max_age(
            records,
            now - Duration::minutes(1),
            Duration::hours(1),
        )
        .unwrap_or_else(|error| panic!("seed={seed} case=revoked_snapshot error={error:?}"));
        let revoked = evaluate_cached_capability_request(
            &cache,
            Some(&revoked_snapshot),
            &policy,
            &request,
            now,
        );
        assert_eq!(
            revoked.status,
            AuthorityDecisionStatus::Denied,
            "seed={seed} case=revocation_monotonicity"
        );
        assert!(
            revoked
                .reasons
                .contains(&REASON_AUTHORITY_GRANT_REVOKED.to_string()),
            "seed={seed} case=matching_revocation_survives_unrelated_records reasons={:?}",
            revoked.reasons
        );

        let mut revoked_payload = active_grant.grant().clone();
        revoked_payload.revocation = RevocationStatus::Revoked {
            reason: format!("payload-revoked-{seed}"),
        };
        let revoked_payload = validate_local_profile_grant(revoked_payload)
            .unwrap_or_else(|error| panic!("seed={seed} case=revoked_payload error={error:?}"));
        let payload_decision = evaluate_capability_request(&[revoked_payload], &request, now);
        assert_eq!(
            payload_decision.status,
            AuthorityDecisionStatus::Denied,
            "seed={seed} case=payload_revocation_monotonicity"
        );

        let stale_snapshot = RevocationSnapshot::with_max_age(
            Vec::new(),
            now - Duration::hours(2),
            Duration::minutes(1),
        )
        .unwrap_or_else(|error| panic!("seed={seed} case=stale_snapshot error={error:?}"));
        let future_snapshot = RevocationSnapshot::with_max_age(
            Vec::new(),
            now + Duration::minutes(1),
            Duration::hours(1),
        )
        .unwrap_or_else(|error| panic!("seed={seed} case=future_snapshot error={error:?}"));
        let stale_cache = cache_for(
            seed,
            active_grant.clone(),
            now - Duration::hours(2),
            now + Duration::hours(1),
        );
        let future_cache = cache_for(
            seed,
            active_grant,
            now + Duration::minutes(1),
            now + Duration::hours(1),
        );
        let uncertainty = [
            evaluate_cached_capability_request(&cache, None, &policy, &request, now),
            evaluate_cached_capability_request(
                &AuthorityGrantCache::new(),
                Some(&active_snapshot),
                &policy,
                &request,
                now,
            ),
            evaluate_cached_capability_request(
                &cache,
                Some(&stale_snapshot),
                &policy,
                &request,
                now,
            ),
            evaluate_cached_capability_request(
                &cache,
                Some(&future_snapshot),
                &policy,
                &request,
                now,
            ),
            evaluate_cached_capability_request(
                &stale_cache,
                Some(&active_snapshot),
                &policy,
                &request,
                now,
            ),
            evaluate_cached_capability_request(
                &future_cache,
                Some(&active_snapshot),
                &policy,
                &request,
                now,
            ),
        ];
        for (case, decision) in uncertainty.into_iter().enumerate() {
            assert_ne!(
                decision.status,
                AuthorityDecisionStatus::Allowed,
                "seed={seed} case=cache_uncertainty_{case} reasons={:?}",
                decision.reasons
            );
        }
    }
}

fn hostile_reason(seed: u64, rng: &mut Seeded) -> String {
    match rng.bounded(4) {
        0 => format!("hostile-secret-{seed}-{}", rng.next()),
        1 => format!("capability_allowed\r\nforged-{seed}-{}", rng.next()),
        2 => format!("\u{1b}[31msecret-{seed}-{}\u{7}", rng.next()),
        _ => format!("oversized-secret-{seed}-{}{}", rng.next(), "x".repeat(300)),
    }
}

#[test]
fn adversarial_property_denials_and_evidence_normalization_are_deterministic_and_redacted() {
    for seed in 0..EVIDENCE_CASES {
        let now = fixed_time(seed);
        let subject = principal_id(seed, 1);
        let operation = gateway_operation("artifact.create");
        let scope = authority_scope(seed, agent_id(seed, 1), run_id(seed, 1), AUDIENCE);
        let grant = validated_grant(
            seed,
            GrantSpec {
                slot: 1,
                subject: principal_id(seed, 2),
                operation: gateway_operation("artifact.publish"),
                scope: scope.clone(),
                not_before: now + Duration::minutes(1),
                expires_at: now + Duration::hours(1),
                depth: 0,
                revocation: RevocationStatus::Revoked {
                    reason: format!("secret-provider-reason-{seed}"),
                },
            },
        );
        let request = request(subject, operation, scope, now);
        let first = evaluate_capability_request(std::slice::from_ref(&grant), &request, now);
        let second = evaluate_capability_request(std::slice::from_ref(&grant), &request, now);
        assert_eq!(
            (first.status, &first.reasons),
            (second.status, &second.reasons),
            "seed={seed} case=ordered_denial_reasons"
        );

        let mut rng = Seeded::new(seed, 0xe71d_eace);
        let hostile = hostile_reason(seed, &mut rng);
        let decision = AuthorityDecision {
            schema_version: AUTHORITY_DECISION_SCHEMA_VERSION.to_string(),
            decision_id: decision_id(seed, 1),
            request,
            status: AuthorityDecisionStatus::Denied,
            reasons: vec![hostile.clone()],
            matched_grant_ids: Vec::new(),
            obligations: Vec::new(),
            decided_at: now,
        };
        let first_evidence = authority_decision_evidence(&decision)
            .unwrap_or_else(|error| panic!("seed={seed} case=first_evidence error={error:?}"));
        let second_evidence = authority_decision_evidence(&decision)
            .unwrap_or_else(|error| panic!("seed={seed} case=second_evidence error={error:?}"));
        assert_eq!(
            first_evidence, second_evidence,
            "seed={seed} case=evidence_determinism"
        );
        assert_eq!(
            first_evidence.reason_codes,
            vec!["authority_reason_unknown"],
            "seed={seed} case=reason_normalization"
        );
        let encoded = serde_json::to_string(&first_evidence)
            .unwrap_or_else(|error| panic!("seed={seed} case=evidence_json error={error:?}"));
        assert!(
            !encoded.contains(&hostile),
            "seed={seed} case=hostile_reason_leak hostile={hostile:?}"
        );
    }
}
