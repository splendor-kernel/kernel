use super::*;
use splendor_adapter_robotics::{SimulatedRoboticsAdapter, ROBOTICS_ADAPTER_ID};
use splendor_gateway::{
    ActionGateway, ActionOutcome, ActionRequest, ActionStatus, SimulatedRiskLevel,
    SimulatedSafetySnapshot, SimulatedSafetyVerifier, TenantAccess, VerifiedActionGateway,
};
use splendor_store::{
    CentralTraceIndex, InMemoryCentralTraceIndex, InMemoryStateStore, InMemoryTraceStore,
    LocalTraceBuffer, LocalTraceBufferConfig, StateData, StateMetadata, StateStore,
    TraceBufferAppendMode, TraceStore, TraceSyncScope,
};
use splendor_types::{
    validate_policy_bundle, DeviceCapability, DeviceCapabilityCategory,
    DeviceLocalPolicyIndicators, DeviceNodeKind, DeviceProfile, DeviceSafetyConstraint,
    MessageTraceContext, OfflineHighRiskBehavior, PolicyBundle, PolicyBundleEnvelope,
    PolicyBundleId, PolicyBundleKeyring, PolicyBundleValidationContext, PolicyDegradedMode,
    RemoteMessageTraceContext, RevocationStatus, RouteWaypointProposal, ValidatedPolicyBundle,
    ALLOWED_PHYSICAL_ACTIONS, ROUTE_PLAN_PROPOSAL_SCHEMA,
};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

const DEVICE_ZONE: &str = "zone:warehouse-a3";

struct AllowPhysicalTenantAccess;

impl TenantAccess for AllowPhysicalTenantAccess {
    fn verify_policy(
        &self,
        _tenant_id: &TenantId,
        _agent_id: &AgentId,
        action: &Action,
        adapter: Option<&str>,
    ) -> VerificationResult {
        if adapter == Some(ROBOTICS_ADAPTER_ID)
            && (splendor_types::is_allowed_physical_action(&action.name)
                || action.name == "move_to_waypoint")
        {
            VerificationResult::allow()
        } else {
            VerificationResult {
                allowed: false,
                reasons: vec!["physical_policy_denied".to_string()],
                artifacts: serde_json::json!({"source": "physical_simulation_harness"}),
            }
        }
    }

    fn verify_quota(
        &self,
        _tenant_id: &TenantId,
        _agent_id: &AgentId,
        _usage: QuotaUsage,
    ) -> VerificationResult {
        VerificationResult::allow()
    }
}

struct PhysicalSimulationHarness {
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
    adapter: Arc<SimulatedRoboticsAdapter>,
    gateway: Arc<dyn ActionGateway>,
    trace: LocalTraceBuffer<InMemoryTraceStore>,
    state: InMemoryStateStore,
    state_head: Option<StateNodeId>,
}

impl PhysicalSimulationHarness {
    fn new(snapshot: SimulatedSafetySnapshot, policy_cache: Option<Arc<PolicyCache>>) -> Self {
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let run_id = RunId::new();
        let adapter = Arc::new(SimulatedRoboticsAdapter::new());
        let mut verified = VerifiedActionGateway::new(Arc::new(AllowPhysicalTenantAccess));
        for action in ALLOWED_PHYSICAL_ACTIONS {
            verified.register_adapter(*action, ROBOTICS_ADAPTER_ID, adapter.clone());
        }
        verified.register_adapter("move_to_waypoint", ROBOTICS_ADAPTER_ID, adapter.clone());
        verified.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(snapshot)));
        let gateway: Arc<dyn ActionGateway> = match policy_cache {
            Some(cache) => Arc::new(PolicyDistributionGateway::new(Arc::new(verified), cache)),
            None => Arc::new(verified),
        };

        let profile = device_profile();
        profile.validate().expect("device profile is valid");
        profile
            .to_capability_document()
            .expect("physical capability document");

        Self {
            tenant_id,
            agent_id,
            run_id,
            adapter,
            gateway,
            trace: LocalTraceBuffer::new(
                InMemoryTraceStore::default(),
                LocalTraceBufferConfig::default(),
            ),
            state: InMemoryStateStore::default(),
            state_head: None,
        }
    }

    fn safe() -> Self {
        Self::new(safe_snapshot(), None)
    }

    fn with_policy_cache(cache: Arc<PolicyCache>) -> Self {
        Self::new(safe_snapshot(), Some(cache))
    }

    fn submit_physical_action(
        &mut self,
        action_name: &str,
        side_effect_class: SideEffectClass,
        params: serde_json::Value,
        satisfied_preconditions: Vec<String>,
    ) -> ActionOutcome {
        let action = physical_action(action_name, side_effect_class, params);
        self.emit(TraceEventKind::ActionVerificationStarted {
            action: action.clone(),
        });
        let outcome = self
            .gateway
            .submit(ActionRequest {
                action_id: ActionId::new(),
                tenant_id: self.tenant_id.clone(),
                agent_id: self.agent_id.clone(),
                run_id: self.run_id.clone(),
                action: action.clone(),
                adapter: Some(ROBOTICS_ADAPTER_ID.to_string()),
                quota_usage: QuotaUsage::single_action(),
                satisfied_preconditions,
                requested_at: OffsetDateTime::now_utc(),
                approval_evidence: None,
                authority_obligation_evidence: None,
            })
            .expect("gateway outcome");
        self.record_gateway_outcome(action, &outcome);
        outcome
    }

    fn record_gateway_outcome(&self, action: Action, outcome: &ActionOutcome) {
        self.emit(TraceEventKind::ActionVerificationCompleted {
            action: action.clone(),
            result: outcome.verification.clone(),
        });
        match outcome.status {
            ActionStatus::Executed => self.emit(TraceEventKind::ActionExecuted {
                action: action.clone(),
                outcome: outcome
                    .output
                    .clone()
                    .unwrap_or_else(|| serde_json::json!({})),
            }),
            ActionStatus::Denied => self.emit(TraceEventKind::ActionDenied {
                action: action.clone(),
                result: outcome.verification.clone(),
            }),
            ActionStatus::NeedsIntervention => self.emit(TraceEventKind::ActionNeedsIntervention {
                action: action.clone(),
                result: outcome.verification.clone(),
            }),
            ActionStatus::NeedsApproval => self.emit(TraceEventKind::ActionNeedsApproval {
                action: action.clone(),
                result: outcome.verification.clone(),
            }),
            ActionStatus::Failed => self.emit(TraceEventKind::ActionFailed {
                action: action.clone(),
                error: outcome
                    .error
                    .clone()
                    .unwrap_or_else(|| "failed".to_string()),
                result: outcome
                    .post_verification
                    .clone()
                    .unwrap_or_else(|| outcome.verification.clone()),
            }),
        };
        self.emit(TraceEventKind::OutcomeRecorded {
            outcome: serde_json::to_value(outcome).expect("outcome json"),
            feedback: None,
            reward: None,
        });
    }

    fn commit_state(&mut self, label: &str, status: serde_json::Value) -> StateNodeId {
        let state_bytes = serde_json::to_vec(&serde_json::json!({
            "label": label,
            "status": status,
            "adapter_calls": self.adapter.call_count(),
        }))
        .expect("state json");
        let data_ref = self
            .state
            .put_state(StateData {
                bytes: state_bytes,
                content_type: Some("application/json".to_string()),
            })
            .expect("state put");
        let mut metadata = StateMetadata::new(OffsetDateTime::now_utc(), Some(label.to_string()));
        metadata.tenant_id = Some(self.tenant_id.clone());
        metadata.agent_id = Some(self.agent_id.clone());
        metadata.run_id = Some(self.run_id.clone());
        let parents = self.state_head.clone().into_iter().collect();
        let node_id = self
            .state
            .commit_node(parents, data_ref, metadata)
            .expect("state commit");
        let node = self.state.get_node(&node_id).expect("state node");
        let snapshot_id = self.state.snapshot(&node_id).expect("state snapshot");
        self.emit(TraceEventKind::StateCommitted {
            state_hash: node.data_hash,
            snapshot_id: Some(snapshot_id),
        });
        self.state_head = Some(node_id.clone());
        node_id
    }

    fn emit(&self, kind: TraceEventKind) -> TraceEvent {
        let sequence = self
            .trace
            .store()
            .read(&self.run_id.to_string())
            .map(|records| records.len() as u64)
            .unwrap_or(0);
        let event = TraceEvent::new(
            self.run_id.clone(),
            sequence,
            OffsetDateTime::now_utc(),
            kind,
        );
        self.trace
            .append_event(&event, TraceBufferAppendMode::SideEffectful)
            .expect("trace append");
        event
    }

    fn replay_trace(&self) -> Vec<TraceEvent> {
        self.trace
            .store()
            .read(&self.run_id.to_string())
            .expect("trace records")
            .into_iter()
            .map(|record| serde_json::from_value(record.payload).expect("trace event"))
            .collect()
    }
}

fn device_profile() -> DeviceProfile {
    let mut capabilities = ALLOWED_PHYSICAL_ACTIONS
        .iter()
        .map(|action| DeviceCapability::bounded_action(*action))
        .collect::<Vec<_>>();
    capabilities.extend([
        DeviceCapability {
            category: DeviceCapabilityCategory::Sensor,
            name: "battery".to_string(),
        },
        DeviceCapability {
            category: DeviceCapabilityCategory::SafetyStatus,
            name: "emergency_stop".to_string(),
        },
    ]);
    DeviceProfile::new(
        DeviceNodeKind::Drone,
        capabilities,
        vec![
            DeviceSafetyConstraint {
                name: "geofence".to_string(),
                value: serde_json::json!({"allowed_zones": [DEVICE_ZONE]}),
            },
            DeviceSafetyConstraint {
                name: "battery_minimum".to_string(),
                value: serde_json::json!({"min_percent": 25}),
            },
        ],
        DeviceLocalPolicyIndicators {
            supports_local_policy_cache: true,
            supports_offline_operation: true,
            supports_local_operator_intervention: true,
            max_offline_policy_ttl_seconds: Some(3600),
        },
    )
    .expect("valid device profile")
}

fn safe_snapshot() -> SimulatedSafetySnapshot {
    SimulatedSafetySnapshot {
        current_zone: Some(DEVICE_ZONE.to_string()),
        allowed_zones: vec![DEVICE_ZONE.to_string()],
        battery_percent: Some(82.0),
        min_battery_percent: Some(25.0),
        emergency_stop_engaged: Some(false),
        collision_risk: Some(SimulatedRiskLevel::Low),
        altitude_m: Some(12.0),
        max_altitude_m: Some(30.0),
        sensor_refs: vec!["sensor:summary:simulated".to_string()],
        ..SimulatedSafetySnapshot::default()
    }
}

fn physical_action(
    name: &str,
    side_effect_class: SideEffectClass,
    params: serde_json::Value,
) -> Action {
    Action {
        name: name.to_string(),
        params,
        side_effect_class,
        cost_estimate: None,
        required_permissions: vec![format!("physical.{name}")],
        preconditions: vec![],
        postconditions: vec![format!("robotics.{name}.acknowledged")],
    }
}

fn route_proposal(zone_ref: &str) -> RoutePlanProposal {
    RoutePlanProposal {
        proposal_id: format!("proposal-{zone_ref}"),
        objective: "inspect warehouse zone".to_string(),
        artifact_ref: Some("artifact:simulated-route-plan".to_string()),
        data_refs: vec!["map:warehouse".to_string()],
        waypoints: vec![RouteWaypointProposal {
            waypoint_ref: "waypoint:a3-entry".to_string(),
            zone_ref: zone_ref.to_string(),
        }],
        created_at: OffsetDateTime::now_utc(),
    }
}

fn policy_bundle(tenant_id: TenantId, agent_id: AgentId) -> PolicyBundle {
    let now = OffsetDateTime::now_utc();
    PolicyBundle {
        schema_version: POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
        policy_bundle_id: PolicyBundleId::try_new("physical-sim-policy").expect("policy id"),
        version: "v1".to_string(),
        tenant_id,
        agent_id: Some(agent_id),
        issued_at: now - Duration::minutes(5),
        expires_at: now + Duration::hours(1),
        revocation: RevocationStatus::Active,
        degraded_mode: PolicyDegradedMode {
            allow_low_risk_cached: true,
            disconnected_low_risk_actions: vec!["read_battery".to_string()],
            disconnected_high_risk_actions: vec!["move_to_waypoint".to_string()],
            high_risk_disconnected_behavior: OfflineHighRiskBehavior::NeedsLocalIntervention,
        },
    }
}

fn validated_policy_bundle(bundle: PolicyBundle) -> ValidatedPolicyBundle {
    let validated_at = OffsetDateTime::now_utc();
    let envelope = PolicyBundleEnvelope::signed_with_shared_secret(
        bundle.clone(),
        "physical-policy-key",
        b"physical-policy-secret",
    )
    .expect("signed physical policy");
    let mut keyring = PolicyBundleKeyring::new();
    keyring
        .insert_shared_secret("physical-policy-key", b"physical-policy-secret")
        .expect("physical policy key");
    validate_policy_bundle(
        &envelope,
        &PolicyBundleValidationContext {
            tenant_id: bundle.tenant_id.clone(),
            agent_id: bundle.agent_id.clone(),
            now: validated_at,
        },
        &keyring,
    )
    .expect("validated physical policy")
}

fn assert_replayable_with_state_head(harness: &PhysicalSimulationHarness) {
    let replay = harness.replay_trace();
    assert!(!replay.is_empty());
    assert!(harness.state_head.is_some());
    assert!(replay
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::StateCommitted { .. })));
}

#[test]
fn physical_harness_successful_mission_uses_only_high_level_actions() {
    let mut harness = PhysicalSimulationHarness::safe();

    let inspect = harness.submit_physical_action(
        "inspect_zone",
        SideEffectClass::Custom("physical.high_level".to_string()),
        serde_json::json!({"zone_ref": DEVICE_ZONE}),
        vec![],
    );
    let dock = harness.submit_physical_action(
        "dock",
        SideEffectClass::Custom("physical.high_level".to_string()),
        serde_json::json!({"dock_ref": "dock:home"}),
        vec![],
    );
    let forbidden = harness.submit_physical_action(
        "set_motor_pwm",
        SideEffectClass::Custom("physical.low_level".to_string()),
        serde_json::json!({"motor": 1, "pwm": 255}),
        vec![],
    );
    let final_head = harness.commit_state(
        "successful simulated mission",
        serde_json::json!({"inspect": inspect.status, "dock": dock.status}),
    );

    assert_eq!(inspect.status, ActionStatus::Executed);
    assert_eq!(dock.status, ActionStatus::Executed);
    assert_eq!(forbidden.status, ActionStatus::Denied);
    assert_eq!(harness.adapter.call_count(), 2);
    assert!(!final_head.to_string().is_empty());
    let replay = harness.replay_trace();
    assert!(replay.iter().any(|event| matches!(
        event.kind,
        TraceEventKind::ActionVerificationCompleted { .. }
    )));
    assert!(replay
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ActionExecuted { .. })));
    assert!(replay.iter().all(|event| match &event.kind {
        TraceEventKind::ActionExecuted { action, .. } => {
            splendor_types::is_allowed_physical_action(&action.name)
        }
        _ => true,
    }));
    assert_replayable_with_state_head(&harness);
}

#[test]
fn physical_harness_safety_intervention_never_reaches_adapter() {
    let mut harness = PhysicalSimulationHarness::new(
        SimulatedSafetySnapshot {
            battery_percent: Some(10.0),
            ..safe_snapshot()
        },
        None,
    );

    let denied = harness.submit_physical_action(
        "move_to_waypoint",
        SideEffectClass::Custom("physical.high_level".to_string()),
        serde_json::json!({"waypoint_ref": "waypoint:a3-entry", "zone_ref": DEVICE_ZONE}),
        vec![],
    );
    harness.commit_state(
        "safety intervention",
        serde_json::json!({"status": denied.status}),
    );

    assert_eq!(denied.status, ActionStatus::NeedsIntervention);
    assert_eq!(harness.adapter.call_count(), 0);
    assert!(harness
        .replay_trace()
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ActionNeedsIntervention { .. })));
    assert_replayable_with_state_head(&harness);
}

#[test]
fn physical_harness_offline_interval_syncs_without_duplicates() {
    let cache = Arc::new(PolicyCache::new(PolicyCacheConfig {
        enforcement_required: true,
    }));
    let mut harness = PhysicalSimulationHarness::with_policy_cache(cache.clone());
    cache
        .install_validated(
            validated_policy_bundle(policy_bundle(
                harness.tenant_id.clone(),
                harness.agent_id.clone(),
            )),
            false,
        )
        .expect("trusted physical policy installs");
    let mut scope = TraceSyncScope::new(harness.run_id.to_string());
    scope.node_id = Some("node-sim-drone-01".to_string());
    scope.instance_id = Some("instance-physical-sim".to_string());
    scope.tenant_id = Some(harness.tenant_id.to_string());
    scope.agent_id = Some(harness.agent_id.to_string());
    let interval = harness
        .trace
        .begin_offline_interval(&scope, Some("simulated_link_loss".to_string()))
        .expect("offline start");
    if let Some(event) = cache.mark_disconnected_with_trace(OffsetDateTime::now_utc()) {
        harness.emit(event);
    }

    let low_risk = harness.submit_physical_action(
        "read_battery",
        SideEffectClass::ReadOnly,
        serde_json::json!({"source": "cached_status"}),
        vec![],
    );
    let high_risk = harness.submit_physical_action(
        "move_to_waypoint",
        SideEffectClass::Custom("physical.high_level".to_string()),
        serde_json::json!({"waypoint_ref": "waypoint:a3-entry", "zone_ref": DEVICE_ZONE}),
        vec![],
    );
    let ended = harness
        .trace
        .end_offline_interval(&harness.run_id.to_string())
        .expect("offline end");
    harness.commit_state(
        "offline interval",
        serde_json::json!({"low_risk": low_risk.status, "high_risk": high_risk.status}),
    );

    assert_eq!(low_risk.status, ActionStatus::Executed);
    assert_eq!(high_risk.status, ActionStatus::NeedsIntervention);
    assert_eq!(harness.adapter.call_count(), 1);
    assert_eq!(interval.offline_interval_id, ended.offline_interval_id);

    let central = InMemoryCentralTraceIndex::default();
    let record_count = harness
        .trace
        .store()
        .read(&harness.run_id.to_string())
        .expect("records")
        .len() as u64;
    let batch = harness
        .trace
        .reconnect_batch(scope.clone(), 0, record_count, Some(ended.clone()))
        .expect("reconnect batch");
    let first = central.sync_batch(batch.clone()).expect("first sync");
    let second = central.sync_batch(batch).expect("duplicate sync");

    assert_eq!(first.accepted_records, record_count as usize);
    assert_eq!(second.accepted_records, 0);
    assert_eq!(second.duplicate_records, record_count as usize);
    assert_eq!(
        central
            .offline_intervals(&scope.run_id)
            .expect("intervals")
            .len(),
        1
    );
    assert_eq!(
        central
            .sync_boundaries(&scope.run_id)
            .expect("bounds")
            .len(),
        1
    );
    let replay = harness.replay_trace();
    assert!(replay.iter().any(|event| matches!(
        event.kind,
        TraceEventKind::OfflineTraceIntervalStarted { .. }
    )));
    assert!(replay
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::OfflineTraceIntervalEnded { .. })));
    assert_replayable_with_state_head(&harness);
}

#[test]
fn physical_harness_operator_intervention_then_override_request_is_traced() {
    let cache = Arc::new(PolicyCache::new(PolicyCacheConfig {
        enforcement_required: true,
    }));
    let mut harness = PhysicalSimulationHarness::with_policy_cache(cache.clone());
    cache
        .install_validated(
            validated_policy_bundle(policy_bundle(
                harness.tenant_id.clone(),
                harness.agent_id.clone(),
            )),
            false,
        )
        .expect("trusted physical policy installs");
    cache.mark_disconnected();

    let intervention = harness.submit_physical_action(
        "move_to_waypoint",
        SideEffectClass::Custom("physical.high_level".to_string()),
        serde_json::json!({"waypoint_ref": "waypoint:a3-entry", "zone_ref": DEVICE_ZONE}),
        vec![],
    );
    assert_eq!(intervention.status, ActionStatus::NeedsIntervention);
    assert_eq!(harness.adapter.call_count(), 0);

    cache
        .install_validated(
            validated_policy_bundle(policy_bundle(
                harness.tenant_id.clone(),
                harness.agent_id.clone(),
            )),
            true,
        )
        .expect("strict newer trusted policy reconnects");
    let override_request = harness.submit_physical_action(
        "request_operator_override",
        SideEffectClass::Custom("physical.high_level".to_string()),
        serde_json::json!({"reason": "safety_verifier_uncertain"}),
        vec![],
    );
    let final_head = harness.commit_state(
        "operator override requested",
        serde_json::json!({
            "intervention": intervention.status,
            "override": override_request.status,
        }),
    );

    assert_eq!(override_request.status, ActionStatus::Executed);
    assert_eq!(harness.adapter.call_count(), 1);
    let calls_before_replay = harness.adapter.call_count();
    let replay = harness.replay_trace();
    let intervention_index = replay
        .iter()
        .position(|event| matches!(event.kind, TraceEventKind::ActionNeedsIntervention { .. }))
        .expect("intervention trace");
    let override_index = replay
        .iter()
        .position(|event| {
            matches!(
                &event.kind,
                TraceEventKind::ActionExecuted { action, .. }
                    if action.name == "request_operator_override"
            )
        })
        .expect("override execution trace");
    assert!(intervention_index < override_index);
    assert_eq!(harness.adapter.call_count(), calls_before_replay);

    let node = harness
        .state
        .get_node(&final_head)
        .expect("final state node");
    let state = harness
        .state
        .get_state(&node.data_ref)
        .expect("final state bytes");
    let summary: serde_json::Value = serde_json::from_slice(&state.bytes).expect("state json");
    assert_eq!(
        summary["status"]["intervention"],
        serde_json::json!(ActionStatus::NeedsIntervention)
    );
    assert_eq!(
        summary["status"]["override"],
        serde_json::json!(ActionStatus::Executed)
    );
    assert_replayable_with_state_head(&harness);
}

#[test]
fn physical_harness_cloud_helper_proposal_is_locally_validated_before_action() {
    let mut harness = PhysicalSimulationHarness::safe();
    let message = MessageTraceContext {
        message_id: MessageId::new(),
        source_agent_id: AgentId::new(),
        target_agent_id: harness.agent_id.clone(),
        run_id: harness.run_id.clone(),
        schema: ROUTE_PLAN_PROPOSAL_SCHEMA.to_string(),
        causal_parent: None,
    };
    let remote = RemoteMessageTraceContext {
        message: message.clone(),
        tenant_id: harness.tenant_id.clone(),
        source_instance_id: "cloud-helper-sim".to_string(),
        target_instance_id: "device-instance-sim".to_string(),
        work_order_id: "wo-helper-sim".to_string(),
        attempt: 1,
        idempotency_key: Some("route-plan-a3".to_string()),
    };
    harness.emit(TraceEventKind::RemoteMessageSent {
        remote_message: remote,
    });
    harness.emit(TraceEventKind::MessageDelivered { message });

    let accepted = validate_route_plan_for_local_execution(
        &route_proposal(DEVICE_ZONE),
        &[DEVICE_ZONE.to_string()],
    );
    assert!(accepted.result.allowed);
    let action = accepted.bounded_actions[0].clone();
    harness.emit(TraceEventKind::ActionVerificationCompleted {
        action: action.clone(),
        result: accepted.result.clone(),
    });
    let outcome = harness.submit_physical_action(
        &action.name,
        action.side_effect_class.clone(),
        action.params.clone(),
        vec!["cloud_helper.local_plan_validated".to_string()],
    );
    assert_eq!(outcome.status, ActionStatus::Executed);

    let rejected = validate_route_plan_for_local_execution(
        &route_proposal("zone:outside-geofence"),
        &[DEVICE_ZONE.to_string()],
    );
    assert!(!rejected.result.allowed);
    assert!(rejected.bounded_actions.is_empty());
    harness.emit(TraceEventKind::ActionDenied {
        action: physical_action(
            "move_to_waypoint",
            SideEffectClass::Custom("physical.high_level".to_string()),
            serde_json::json!({"proposal": "unsafe"}),
        ),
        result: rejected.result,
    });
    harness.commit_state(
        "cloud helper proposal",
        serde_json::json!({"local_action": outcome.status}),
    );

    assert_eq!(harness.adapter.call_count(), 1);
    let replay = harness.replay_trace();
    assert!(replay
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::RemoteMessageSent { .. })));
    assert!(replay
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ActionDenied { .. })));
    assert_replayable_with_state_head(&harness);
}
