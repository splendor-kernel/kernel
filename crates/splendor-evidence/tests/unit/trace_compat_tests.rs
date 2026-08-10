use super::*;
use splendor_store::{
    compute_trace_envelope_hash, compute_trace_event_hash, InMemoryTraceStore, RuntimeTraceLimits,
    RuntimeTracePage, RuntimeTracePortError, RuntimeTraceProfile, RuntimeTraceReader,
    RuntimeTraceReaderHandle, RuntimeTraceStoreIdentity, RuntimeTraceTail, RuntimeTraceWriter,
    RuntimeTraceWriterHandle, SqliteTraceStore, TraceRecord, TraceStore,
};
use splendor_types::{
    Action, ActionId, AgentId, AuditAttribution, ClientPrincipal, ContentHash, CostEstimate,
    HashAlgorithm, MessageId, MessageTraceContext, Percept, PerceptProvenance,
    RemoteMessageTraceContext, RunId, SideEffectClass, SnapshotId, StateHandoffTraceContext,
    StateNodeId, StateReferenceMode, TenantId, TickId, TraceEvent, TraceEventKind,
    TraceIdentityContext, TraceIntegrity, VerificationResult,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use time::OffsetDateTime;

const HASH_REDACTION_MARKER: &str = "[REDACTED:hash-candidate]";

fn exact_identity(
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
    tick_id: Option<u64>,
) -> TraceIdentityContext {
    let identity = TraceIdentityContext::new(run_id.clone())
        .with_tenant_agent(tenant_id.clone(), agent_id.clone());
    match tick_id {
        Some(tick_id) => identity.with_tick_id(TickId::from(tick_id)),
        None => identity,
    }
}

fn action(name: &str, params: serde_json::Value) -> Action {
    Action {
        name: name.to_string(),
        params,
        side_effect_class: SideEffectClass::External,
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    }
}

fn current_writer(
    store: &InMemoryTraceStore,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
) -> (RuntimeTraceWriterHandle, RuntimeTraceTail) {
    let writer = acquire_current_trace_writer(
        store,
        run_id,
        tenant_id,
        agent_id,
        RuntimeTraceLimits::default(),
    )
    .expect("current writer");
    let tail = writer.tail().expect("current tail");
    (writer, tail)
}

fn append_event(
    writer: &dyn RuntimeTraceWriter,
    tail: &mut RuntimeTraceTail,
    identity: TraceIdentityContext,
    kind: TraceEventKind,
) -> TraceEvent {
    let mut event = TraceEvent::try_new_with_identity(
        identity,
        tail.next_sequence(),
        OffsetDateTime::UNIX_EPOCH,
        kind,
    )
    .expect("trace event");
    if let TraceEventKind::LoopTickCompleted { tick_id, .. } = event.kind {
        let payload = serde_json::to_value(&event).expect("completion payload");
        let event_hash =
            compute_trace_event_hash(tail.stable_tail_hash(), &payload).expect("completion hash");
        event.kind = TraceEventKind::LoopTickCompleted {
            tick_id,
            integrity: Some(TraceIntegrity {
                prev_event_hash: tail.stable_tail_hash().cloned(),
                event_hash,
            }),
        };
    }
    *tail = append_stable_trace_event(writer, tail, &event)
        .expect("semantic append")
        .into_tail();
    event
}

fn append_completed_snapshot(
    writer: &dyn RuntimeTraceWriter,
    tail: &mut RuntimeTraceTail,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
    tick_id: u64,
    state_label: &[u8],
) -> (SnapshotId, StateNodeId, ContentHash) {
    let identity = exact_identity(run_id, tenant_id, agent_id, Some(tick_id));
    append_event(
        writer,
        tail,
        identity.clone(),
        TraceEventKind::LoopTickStarted { tick_id },
    );
    append_completed_snapshot_suffix(writer, tail, identity, tick_id, state_label)
}

fn append_completed_snapshot_suffix(
    writer: &dyn RuntimeTraceWriter,
    tail: &mut RuntimeTraceTail,
    identity: TraceIdentityContext,
    tick_id: u64,
    state_label: &[u8],
) -> (SnapshotId, StateNodeId, ContentHash) {
    append_event(
        writer,
        tail,
        identity.clone(),
        no_action_tick_outcome(tick_id),
    );
    let state_hash = ContentHash::blake3(state_label);
    let state_node_id = StateNodeId::from_hash(state_hash.clone());
    let snapshot_id = SnapshotId::from_bytes(state_label);
    append_event(
        writer,
        tail,
        identity.clone().with_state_node_id(state_node_id.clone()),
        TraceEventKind::StateCommitted {
            state_hash: state_hash.clone(),
            snapshot_id: Some(snapshot_id.clone()),
        },
    );
    append_event(
        writer,
        tail,
        identity,
        TraceEventKind::LoopTickCompleted {
            tick_id,
            integrity: None,
        },
    );
    (snapshot_id, state_node_id, state_hash)
}

fn no_action_tick_outcome(tick_id: u64) -> TraceEventKind {
    TraceEventKind::OutcomeRecorded {
        outcome: serde_json::json!({
            "tick_id": tick_id,
            "duration_ms": 1,
            "needs_intervention": false,
            "needs_approval": false,
            "escalations": [],
            "actions": [],
        }),
        feedback: None,
        reward: None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletedActionTerminal {
    Executed,
    Denied,
    Failed,
    NeedsApproval,
    NeedsIntervention,
}

fn approval_challenge_for(
    identity: &TraceIdentityContext,
    candidate: &Action,
    physical: bool,
) -> splendor_types::ApprovalChallenge {
    let run_id = identity.run_id.clone();
    splendor_types::ApprovalChallenge {
        schema_version: splendor_types::APPROVAL_CHALLENGE_SCHEMA_VERSION.to_string(),
        approval_id: splendor_types::ApprovalId::new(),
        tenant_id: identity.tenant_id.clone().expect("tenant identity"),
        agent_id: identity.agent_id.clone().expect("agent identity"),
        run_id: run_id.clone(),
        action_id: identity.action_id.clone().expect("action identity"),
        action_name: candidate.name.clone(),
        adapter: "adapter.test".to_string(),
        policy_id: "policy.test".to_string(),
        risk_level: None,
        subject: splendor_types::PrincipalId::new(),
        authority_decision_id: splendor_types::AuthorityDecisionId::new(),
        obligation_id: splendor_types::AuthorityObligationId::new(),
        receipt_audience: "test.audience".to_string(),
        canonical_request_digest: format!("blake3:{}", "1".repeat(64)),
        gateway_action_request_digest: format!("blake3:{}", "2".repeat(64)),
        physical_action_resource_coordinate: physical.then(|| {
            splendor_types::PhysicalActionResourceCoordinate::physical_node(
                splendor_types::NodeId::new(),
            )
        }),
        authority_decision_digest: format!("blake3:{}", "3".repeat(64)),
        requested_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
    }
}

fn append_completed_tickless_action(
    writer: &dyn RuntimeTraceWriter,
    tail: &mut RuntimeTraceTail,
    identity: TraceIdentityContext,
    source: &str,
    terminal: CompletedActionTerminal,
) {
    let candidate = action("external", serde_json::json!({"source": source}));
    append_completed_tickless_action_with_candidate(
        writer, tail, identity, candidate, source, terminal,
    );
}

fn append_completed_tickless_action_with_candidate(
    writer: &dyn RuntimeTraceWriter,
    tail: &mut RuntimeTraceTail,
    identity: TraceIdentityContext,
    candidate: Action,
    source: &str,
    terminal: CompletedActionTerminal,
) {
    let action_id = identity.action_id.clone().expect("action identity");
    let verification = match terminal {
        CompletedActionTerminal::Denied
        | CompletedActionTerminal::NeedsApproval
        | CompletedActionTerminal::NeedsIntervention => {
            VerificationResult::deny("approval_required")
        }
        CompletedActionTerminal::Failed => VerificationResult {
            allowed: false,
            reasons: vec!["adapter_failed".to_string()],
            artifacts: serde_json::json!({"adapter_entered": false}),
        },
        CompletedActionTerminal::Executed => VerificationResult::allow(),
    };
    append_event(
        writer,
        tail,
        identity.clone(),
        TraceEventKind::ActionVerificationStarted {
            action: candidate.clone(),
        },
    );
    append_event(
        writer,
        tail,
        identity.clone(),
        TraceEventKind::ActionVerificationCompleted {
            action: candidate.clone(),
            result: verification.clone(),
        },
    );
    let terminal_kind = match terminal {
        CompletedActionTerminal::Executed => TraceEventKind::ActionExecuted {
            action: candidate.clone(),
            outcome: serde_json::json!({"completed": true}),
        },
        CompletedActionTerminal::Denied => TraceEventKind::ActionDenied {
            action: candidate.clone(),
            result: verification.clone(),
        },
        CompletedActionTerminal::Failed => TraceEventKind::ActionFailed {
            action: candidate.clone(),
            error: "adapter_failed".to_string(),
            result: verification.clone(),
        },
        CompletedActionTerminal::NeedsApproval => TraceEventKind::ActionNeedsApproval {
            action: candidate.clone(),
            result: verification.clone(),
        },
        CompletedActionTerminal::NeedsIntervention => TraceEventKind::ActionNeedsIntervention {
            action: candidate.clone(),
            result: verification.clone(),
        },
    };
    append_event(writer, tail, identity.clone(), terminal_kind);
    let status = match terminal {
        CompletedActionTerminal::Executed => "Executed",
        CompletedActionTerminal::Denied => "Denied",
        CompletedActionTerminal::Failed => "Failed",
        CompletedActionTerminal::NeedsApproval => "NeedsApproval",
        CompletedActionTerminal::NeedsIntervention => "NeedsIntervention",
    };
    let output = matches!(terminal, CompletedActionTerminal::Executed)
        .then(|| serde_json::json!({"completed": true}));
    let error = match terminal {
        CompletedActionTerminal::Executed => None,
        CompletedActionTerminal::Denied | CompletedActionTerminal::NeedsApproval => {
            Some("approval_required")
        }
        CompletedActionTerminal::Failed => Some("adapter_failed"),
        CompletedActionTerminal::NeedsIntervention => Some("intervention_required"),
    };
    let approval_challenge = matches!(terminal, CompletedActionTerminal::NeedsApproval)
        .then(|| approval_challenge_for(&identity, &candidate, source == "daemon.physical_action"));
    append_event(
        writer,
        tail,
        identity,
        TraceEventKind::OutcomeRecorded {
            outcome: serde_json::json!({
                "source": source,
                "action_outcome": {
                    "action_id": action_id,
                    "status": status,
                    "verification": verification,
                    "post_verification": null,
                    "output": output,
                    "error": error,
                    "approval_challenge": approval_challenge,
                    "completed_at": OffsetDateTime::UNIX_EPOCH,
                },
            }),
            feedback: None,
            reward: None,
        },
    );
}

fn append_completed_tick_approval(
    writer: &dyn RuntimeTraceWriter,
    tail: &mut RuntimeTraceTail,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
    tick_id: u64,
    action_id: &ActionId,
) -> Action {
    let tick_identity = exact_identity(run_id, tenant_id, agent_id, Some(tick_id));
    let action_identity = tick_identity.clone().with_action_id(action_id.clone());
    let candidate = action("external", serde_json::json!({"source": "daemon.action"}));
    let verification = VerificationResult::deny("approval_required");
    let challenge = approval_challenge_for(&action_identity, &candidate, false);
    append_event(
        writer,
        tail,
        tick_identity.clone(),
        TraceEventKind::LoopTickStarted { tick_id },
    );
    append_event(
        writer,
        tail,
        action_identity.clone(),
        TraceEventKind::ActionVerificationStarted {
            action: candidate.clone(),
        },
    );
    append_event(
        writer,
        tail,
        action_identity.clone(),
        TraceEventKind::ActionVerificationCompleted {
            action: candidate.clone(),
            result: verification.clone(),
        },
    );
    append_event(
        writer,
        tail,
        action_identity,
        TraceEventKind::ActionNeedsApproval {
            action: candidate.clone(),
            result: verification.clone(),
        },
    );
    append_event(
        writer,
        tail,
        tick_identity.clone(),
        TraceEventKind::OutcomeRecorded {
            outcome: serde_json::json!({
                "tick_id": tick_id,
                "duration_ms": 1,
                "needs_intervention": false,
                "needs_approval": true,
                "escalations": [],
                "actions": [{
                    "action_id": action_id,
                    "status": "NeedsApproval",
                    "verification": verification,
                    "post_verification": null,
                    "output": null,
                    "error": "approval_required",
                    "approval_challenge": challenge,
                    "completed_at": OffsetDateTime::UNIX_EPOCH,
                }],
            }),
            feedback: None,
            reward: None,
        },
    );
    let state_hash = ContentHash::blake3(format!("tick-{tick_id}-state").as_bytes());
    append_event(
        writer,
        tail,
        tick_identity
            .clone()
            .with_state_node_id(StateNodeId::from_hash(state_hash.clone())),
        TraceEventKind::StateCommitted {
            state_hash,
            snapshot_id: None,
        },
    );
    append_event(
        writer,
        tail,
        tick_identity,
        TraceEventKind::LoopTickCompleted {
            tick_id,
            integrity: None,
        },
    );
    candidate
}

fn append_completed_tick_execution(
    writer: &dyn RuntimeTraceWriter,
    tail: &mut RuntimeTraceTail,
    tick_identity: TraceIdentityContext,
    action_id: &ActionId,
    candidate: &Action,
    state_label: &[u8],
) -> (SnapshotId, StateNodeId, ContentHash) {
    let tick_id = tick_identity.tick_id.as_ref().expect("tick identity").get();
    let action_identity = tick_identity.clone().with_action_id(action_id.clone());
    let verification = VerificationResult::allow();
    let output = serde_json::json!({"completed": true});
    append_event(
        writer,
        tail,
        tick_identity.clone(),
        TraceEventKind::LoopTickStarted { tick_id },
    );
    append_event(
        writer,
        tail,
        action_identity.clone(),
        TraceEventKind::ActionVerificationStarted {
            action: candidate.clone(),
        },
    );
    append_event(
        writer,
        tail,
        action_identity.clone(),
        TraceEventKind::ActionVerificationCompleted {
            action: candidate.clone(),
            result: verification.clone(),
        },
    );
    append_event(
        writer,
        tail,
        action_identity,
        TraceEventKind::ActionExecuted {
            action: candidate.clone(),
            outcome: output.clone(),
        },
    );
    append_event(
        writer,
        tail,
        tick_identity.clone(),
        TraceEventKind::OutcomeRecorded {
            outcome: serde_json::json!({
                "tick_id": tick_id,
                "duration_ms": 1,
                "needs_intervention": false,
                "needs_approval": false,
                "escalations": [],
                "actions": [{
                    "action_id": action_id,
                    "status": "Executed",
                    "verification": verification,
                    "post_verification": null,
                    "output": output,
                    "error": null,
                    "approval_challenge": null,
                    "completed_at": OffsetDateTime::UNIX_EPOCH,
                }],
            }),
            feedback: None,
            reward: None,
        },
    );
    let state_hash = ContentHash::blake3(state_label);
    let state_node_id = StateNodeId::from_hash(state_hash.clone());
    let snapshot_id = SnapshotId::from_bytes(state_label);
    append_event(
        writer,
        tail,
        tick_identity
            .clone()
            .with_state_node_id(state_node_id.clone()),
        TraceEventKind::StateCommitted {
            state_hash: state_hash.clone(),
            snapshot_id: Some(snapshot_id.clone()),
        },
    );
    append_event(
        writer,
        tail,
        tick_identity,
        TraceEventKind::LoopTickCompleted {
            tick_id,
            integrity: None,
        },
    );
    (snapshot_id, state_node_id, state_hash)
}

fn append_denied_tickless_action_with_outcome(
    writer: &dyn RuntimeTraceWriter,
    tail: &mut RuntimeTraceTail,
    identity: TraceIdentityContext,
    candidate: Action,
    verification: VerificationResult,
    outcome: serde_json::Value,
) {
    for kind in [
        TraceEventKind::ActionVerificationStarted {
            action: candidate.clone(),
        },
        TraceEventKind::ActionVerificationCompleted {
            action: candidate.clone(),
            result: verification.clone(),
        },
        TraceEventKind::ActionDenied {
            action: candidate,
            result: verification,
        },
        TraceEventKind::OutcomeRecorded {
            outcome,
            feedback: None,
            reward: None,
        },
    ] {
        append_event(writer, tail, identity.clone(), kind);
    }
}

fn stored_daemon_action_outcome(
    action_id: &ActionId,
    status: &str,
    verification: &VerificationResult,
    post_verification: Option<&VerificationResult>,
    output: Option<serde_json::Value>,
    error: Option<&str>,
    approval_challenge: Option<splendor_types::ApprovalChallenge>,
) -> serde_json::Value {
    serde_json::json!({
        "source": "daemon.action",
        "action_outcome": {
            "action_id": action_id,
            "status": status,
            "verification": verification,
            "post_verification": post_verification,
            "output": output,
            "error": error,
            "approval_challenge": approval_challenge,
            "completed_at": OffsetDateTime::UNIX_EPOCH,
        },
    })
}

fn verify_redacted_projection_hash(
    previous: Option<&ContentHash>,
    payload: &serde_json::Value,
) -> ContentHash {
    let mut normalized = payload.clone();
    if let Some(completion) = normalized
        .get_mut("kind")
        .and_then(|kind| kind.get_mut("LoopTickCompleted"))
        .and_then(serde_json::Value::as_object_mut)
    {
        completion.remove("integrity");
    }
    let mut bytes = b"splendor.trace.redacted-projection.v1\0".to_vec();
    if let Some(previous) = previous {
        bytes.extend_from_slice(previous.to_string().as_bytes());
    }
    bytes.extend_from_slice(&serde_json::to_vec(&normalized).expect("projection payload"));
    ContentHash::blake3(bytes)
}

fn action_with_hash_candidate(candidate: &str) -> Action {
    let exact_key =
        serde_json::Map::from_iter([(candidate.to_string(), serde_json::json!("exact"))]);
    let embedded_key = serde_json::Map::from_iter([(
        format!("prefix-{candidate}-suffix"),
        serde_json::json!("embedded"),
    )]);
    Action {
        name: format!("name-{candidate}"),
        params: serde_json::json!({
            "direct": candidate,
            "embedded": format!("prefix-{candidate}-suffix"),
            "nested": {
                "value": candidate,
                "exact_key": exact_key,
                "embedded_key": embedded_key,
            },
            "plain": "retained",
        }),
        side_effect_class: SideEffectClass::Custom(format!("custom-{candidate}")),
        cost_estimate: Some(CostEstimate {
            units: format!("units-{candidate}"),
            amount: 7.5,
        }),
        required_permissions: vec![format!("permission-{candidate}")],
        preconditions: vec![format!("precondition-{candidate}")],
        postconditions: vec![format!("postcondition-{candidate}")],
    }
}

fn append_hash_candidate_action_events(
    store: &InMemoryTraceStore,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
    action_id: &ActionId,
    use_source_member: bool,
) -> (RuntimeTraceWriterHandle, String, String) {
    let (writer, mut tail) = current_writer(store, run_id, tenant_id, agent_id);
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(run_id, tenant_id, agent_id, None),
        TraceEventKind::RunStarted,
    );
    let source_digest = tail
        .stable_tail_hash()
        .expect("source digest")
        .value
        .clone();
    let nonmember = if source_digest == "f".repeat(64) {
        "e".repeat(64)
    } else {
        "f".repeat(64)
    };
    let candidate = if use_source_member {
        source_digest.as_str()
    } else {
        nonmember.as_str()
    };
    let action = action_with_hash_candidate(candidate);
    let action_identity =
        exact_identity(run_id, tenant_id, agent_id, None).with_action_id(action_id.clone());
    for kind in [
        TraceEventKind::CandidatesProposed {
            actions: vec![action.clone()],
        },
        TraceEventKind::ActionVerificationStarted {
            action: action.clone(),
        },
        TraceEventKind::ActionVerificationCompleted {
            action: action.clone(),
            result: VerificationResult::allow(),
        },
        TraceEventKind::ActionNeedsApproval {
            action: action.clone(),
            result: VerificationResult::deny("approval_required"),
        },
        TraceEventKind::ActionExecuted {
            action: action.clone(),
            outcome: serde_json::json!({"plain": "retained"}),
        },
        TraceEventKind::ActionDenied {
            action: action.clone(),
            result: VerificationResult::deny("permission_denied"),
        },
        TraceEventKind::ActionFailed {
            action: action.clone(),
            error: "adapter_failed".to_string(),
            result: VerificationResult::deny("adapter_failed"),
        },
        TraceEventKind::ActionNeedsIntervention {
            action,
            result: VerificationResult::deny("intervention_required"),
        },
    ] {
        let identity = if matches!(&kind, TraceEventKind::CandidatesProposed { .. }) {
            exact_identity(run_id, tenant_id, agent_id, None)
        } else {
            action_identity.clone()
        };
        append_event(writer.as_ref(), &mut tail, identity, kind);
    }
    let state_hash = ContentHash::blake3(b"trusted-state-hash");
    assert_ne!(state_hash.value, source_digest);
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(run_id, tenant_id, agent_id, None),
        TraceEventKind::StateLoaded {
            state_hash: Some(state_hash),
        },
    );
    (writer, source_digest, nonmember)
}

fn assert_redacted_action_hash_candidates(action: &Action) {
    assert_eq!(action.name, format!("name-{HASH_REDACTION_MARKER}"));
    assert_eq!(action.params["direct"], HASH_REDACTION_MARKER);
    assert_eq!(
        action.params["embedded"],
        format!("prefix-{HASH_REDACTION_MARKER}-suffix")
    );
    assert_eq!(action.params["nested"]["value"], HASH_REDACTION_MARKER);
    assert_eq!(
        action.params["nested"]["exact_key"],
        serde_json::json!({HASH_REDACTION_MARKER: "exact"})
    );
    let embedded_key = format!("prefix-{HASH_REDACTION_MARKER}-suffix");
    assert_eq!(
        action.params["nested"]["embedded_key"],
        serde_json::Value::Object(serde_json::Map::from_iter([(
            embedded_key,
            serde_json::json!("embedded"),
        )]))
    );
    assert_eq!(action.params["plain"], "retained");
    assert_eq!(
        action.side_effect_class,
        SideEffectClass::Custom(format!("custom-{HASH_REDACTION_MARKER}"))
    );
    let cost = action
        .cost_estimate
        .as_ref()
        .expect("cost estimate retained");
    assert_eq!(cost.units, format!("units-{HASH_REDACTION_MARKER}"));
    assert_eq!(cost.amount, 7.5);
    assert_eq!(
        action.required_permissions,
        vec![format!("permission-{HASH_REDACTION_MARKER}")]
    );
    assert_eq!(
        action.preconditions,
        vec![format!("precondition-{HASH_REDACTION_MARKER}")]
    );
    assert_eq!(
        action.postconditions,
        vec![format!("postcondition-{HASH_REDACTION_MARKER}")]
    );
}

fn assert_all_projected_actions_are_redacted(records: &[TraceRecord]) {
    let mut action_count = 0;
    for record in records {
        let event: TraceEvent =
            serde_json::from_value(record.payload.clone()).expect("projected typed event");
        match &event.kind {
            TraceEventKind::CandidatesProposed { actions } => {
                assert_eq!(actions.len(), 1);
                assert_redacted_action_hash_candidates(&actions[0]);
                action_count += 1;
            }
            TraceEventKind::ActionVerificationStarted { action }
            | TraceEventKind::ActionVerificationCompleted { action, .. }
            | TraceEventKind::ActionNeedsApproval { action, .. }
            | TraceEventKind::ActionExecuted { action, .. }
            | TraceEventKind::ActionDenied { action, .. }
            | TraceEventKind::ActionFailed { action, .. }
            | TraceEventKind::ActionNeedsIntervention { action, .. } => {
                assert_redacted_action_hash_candidates(action);
                action_count += 1;
            }
            TraceEventKind::StateLoaded { state_hash } => {
                assert_eq!(
                    state_hash.as_ref(),
                    Some(&ContentHash::new(
                        HashAlgorithm::Blake3,
                        HASH_REDACTION_MARKER,
                    ))
                );
            }
            _ => {}
        }
    }
    assert_eq!(action_count, 8);
}

fn assert_membership_independent_projection(left: &[TraceRecord], right: &[TraceRecord]) {
    assert_eq!(left.len(), right.len());
    for (left, right) in left.iter().zip(right) {
        // Independent stores may assign different storage timestamps. The stable
        // event identity, payload, and projection-local integrity must not differ.
        assert_eq!(left.run_id, right.run_id);
        assert_eq!(left.sequence, right.sequence);
        assert_eq!(left.payload, right.payload);
        assert_eq!(left.prev_event_hash, right.prev_event_hash);
        assert_eq!(left.event_hash, right.event_hash);
    }
}

fn assert_source_digests_absent(records: &[TraceRecord], source: &[TraceRecord]) {
    let encoded = serde_json::to_string(records).expect("redacted projection JSON");
    for record in source {
        assert!(!encoded.contains(&record.event_hash.value));
        if let Some(previous) = &record.prev_event_hash {
            assert!(!encoded.contains(&previous.value));
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ExternalHashProbe {
    Percept,
    RemoteMessage,
    StateHandoff,
    StateCommit,
}

fn nonmember_digest(source_digest: &str) -> String {
    if source_digest == "f".repeat(64) {
        "e".repeat(64)
    } else {
        "f".repeat(64)
    }
}

fn external_hash_probe_event(
    probe: ExternalHashProbe,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
    other_agent_id: &AgentId,
    message_id: &MessageId,
    candidate: &str,
) -> (TraceIdentityContext, TraceEventKind) {
    match probe {
        ExternalHashProbe::Percept => {
            let payload_key = format!("payload-key-{candidate}");
            let payload = serde_json::Value::Object(serde_json::Map::from_iter([(
                payload_key,
                serde_json::json!(format!("payload-value-{candidate}")),
            )]));
            (
                exact_identity(run_id, tenant_id, agent_id, None),
                TraceEventKind::PerceptsReceived {
                    percepts: vec![Percept {
                        schema: "splendor.percept.hash-probe.v1".to_string(),
                        payload,
                        provenance: PerceptProvenance {
                            source: format!("perceptor-{candidate}"),
                            detail: Some(format!("correlation-{candidate}")),
                        },
                        timestamp: OffsetDateTime::UNIX_EPOCH,
                    }],
                },
            )
        }
        ExternalHashProbe::RemoteMessage => (
            exact_identity(run_id, tenant_id, agent_id, None).with_message_id(message_id.clone()),
            TraceEventKind::RemoteMessageSent {
                remote_message: RemoteMessageTraceContext {
                    message: MessageTraceContext {
                        message_id: message_id.clone(),
                        source_agent_id: agent_id.clone(),
                        target_agent_id: other_agent_id.clone(),
                        run_id: run_id.clone(),
                        schema: format!("splendor.message.{candidate}.v1"),
                        causal_parent: None,
                    },
                    tenant_id: tenant_id.clone(),
                    source_instance_id: format!("source-instance-{candidate}"),
                    target_instance_id: format!("target-instance-{candidate}"),
                    work_order_id: format!("work-order-{candidate}"),
                    attempt: 1,
                    idempotency_key: Some(format!("idempotency-{candidate}")),
                },
            },
        ),
        ExternalHashProbe::StateHandoff => (
            exact_identity(run_id, tenant_id, agent_id, None),
            TraceEventKind::StateHandoffExported {
                handoff: StateHandoffTraceContext {
                    handoff_id: format!("handoff-{candidate}"),
                    mode: StateReferenceMode::SnapshotImport,
                    tenant_id: tenant_id.clone(),
                    agent_id: agent_id.clone(),
                    run_id: run_id.clone(),
                    work_order_id: format!("work-order-{candidate}"),
                    source_instance_id: Some(format!("source-instance-{candidate}")),
                    receiver_instance_id: Some(format!("receiver-instance-{candidate}")),
                    source_state_node_id: format!("blake3:{candidate}"),
                    previous_state_node_id: Some(format!("blake3:{candidate}")),
                    receiver_state_node_id: Some(format!("blake3:{candidate}")),
                    snapshot_id: Some(SnapshotId::from_hash(ContentHash::new(
                        HashAlgorithm::Blake3,
                        candidate,
                    ))),
                    source_trace_id: None,
                },
            },
        ),
        ExternalHashProbe::StateCommit => {
            let state_hash = ContentHash::new(HashAlgorithm::Blake3, candidate);
            (
                exact_identity(run_id, tenant_id, agent_id, None)
                    .with_state_node_id(StateNodeId::from_hash(state_hash.clone())),
                TraceEventKind::StateCommitted {
                    state_hash: state_hash.clone(),
                    snapshot_id: Some(SnapshotId::from_hash(state_hash)),
                },
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn append_external_hash_probe(
    store: &InMemoryTraceStore,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
    other_agent_id: &AgentId,
    message_id: &MessageId,
    probe: ExternalHashProbe,
    use_source_member: bool,
) -> (RuntimeTraceWriterHandle, String, String) {
    let (writer, mut tail) = current_writer(store, run_id, tenant_id, agent_id);
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(run_id, tenant_id, agent_id, None),
        TraceEventKind::RunStarted,
    );
    let source_digest = tail
        .stable_tail_hash()
        .expect("source digest")
        .value
        .clone();
    let nonmember = nonmember_digest(&source_digest);
    let candidate = if use_source_member {
        source_digest.as_str()
    } else {
        nonmember.as_str()
    };
    let (identity, kind) = external_hash_probe_event(
        probe,
        run_id,
        tenant_id,
        agent_id,
        other_agent_id,
        message_id,
        candidate,
    );
    append_event(writer.as_ref(), &mut tail, identity, kind);
    (writer, source_digest, nonmember)
}

fn append_legacy_events(store: &InMemoryTraceStore, run_id: &RunId) {
    for (sequence, kind) in [
        TraceEventKind::LoopTickStarted { tick_id: 1 },
        TraceEventKind::LoopTickCompleted {
            tick_id: 1,
            integrity: None,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let event = TraceEvent::try_new_with_identity(
            TraceIdentityContext::new(run_id.clone()).with_tick_id(TickId::from(1)),
            sequence as u64,
            OffsetDateTime::UNIX_EPOCH,
            kind,
        )
        .expect("legacy event");
        TraceStore::append(
            store,
            &run_id.to_string(),
            serde_json::to_value(event).expect("legacy payload"),
        )
        .expect("legacy append");
    }
}

#[test]
fn legacy_history_is_valid_for_inspection_but_never_live_resume() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    append_legacy_events(&store, &run_id);
    let reader =
        open_trace_reader(&store, &run_id, RuntimeTraceLimits::default()).expect("legacy reader");

    let inspected = inspect_trace(reader.as_ref(), &run_id).expect("legacy inspection");
    assert_eq!(inspected.profile, RuntimeTraceProfile::LegacyUnanchored);
    assert_eq!(inspected.records.len(), 2);
    assert_eq!(
        inspect_durable_action_history(
            reader.as_ref(),
            &run_id,
            &TenantId::new(),
            &AgentId::new(),
            &ActionId::new(),
        )
        .expect("legacy action disposition"),
        DurableActionHistoryDisposition::ReconciliationRequired,
    );
    assert!(matches!(
        resume_trace(reader.as_ref(), &run_id, &TenantId::new(), &AgentId::new()),
        Err(TraceCompatibilityError::LegacyInspectOnly)
    ));
}

#[test]
fn current_history_resumes_exact_latest_snapshot_and_global_tick_floor() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let target_agent = AgentId::new();
    let other_agent = AgentId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &target_agent);
    let (snapshot_id, state_node_id, state_hash) = append_completed_snapshot(
        writer.as_ref(),
        &mut tail,
        &run_id,
        &tenant_id,
        &target_agent,
        1,
        b"target-state",
    );
    append_completed_snapshot(
        writer.as_ref(),
        &mut tail,
        &run_id,
        &tenant_id,
        &other_agent,
        7,
        b"other-state",
    );

    let resumed =
        resume_trace(writer.as_ref(), &run_id, &tenant_id, &target_agent).expect("exact resume");
    assert_eq!(resumed.snapshot_id, snapshot_id);
    assert_eq!(resumed.state_node_id, state_node_id);
    assert_eq!(resumed.state_hash, state_hash);
    assert_eq!(resumed.tick_id, 1);
    assert_eq!(resumed.max_tick_id, 7);
    assert_eq!(resumed.tail, tail);
}

#[test]
fn current_completion_integrity_is_required_and_cannot_be_removed_or_changed() {
    #[derive(Clone, Copy)]
    enum Corruption {
        Missing,
        Null,
        Wrong,
    }

    for corruption in [Corruption::Missing, Corruption::Null, Corruption::Wrong] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        let identity = exact_identity(&run_id, &tenant_id, &agent_id, Some(1));
        append_event(
            writer.as_ref(),
            &mut tail,
            identity.clone(),
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        );
        let mut completion = TraceEvent::try_new_with_identity(
            identity,
            tail.next_sequence(),
            OffsetDateTime::UNIX_EPOCH,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        )
        .expect("completion");
        if matches!(corruption, Corruption::Wrong) {
            completion.kind = TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: Some(TraceIntegrity {
                    prev_event_hash: tail.stable_tail_hash().cloned(),
                    event_hash: ContentHash::blake3(b"wrong-completion-integrity"),
                }),
            };
        }
        let mut payload = serde_json::to_value(completion).expect("completion payload");
        if matches!(corruption, Corruption::Missing) {
            payload
                .pointer_mut("/kind/LoopTickCompleted")
                .and_then(serde_json::Value::as_object_mut)
                .expect("completion object")
                .remove("integrity");
        }
        writer
            .append(&tail, payload)
            .expect("mechanical store accepts compatibility-owner fixture");

        assert!(matches!(
            inspect_trace(writer.as_ref(), &run_id),
            Err(TraceCompatibilityError::CompletionIntegrity)
        ));
    }
}

#[test]
fn incomplete_effect_boundary_and_uncertain_failure_require_reconciliation() {
    for use_action_failure in [false, true] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        let tick_identity = exact_identity(&run_id, &tenant_id, &agent_id, Some(1));
        append_event(
            writer.as_ref(),
            &mut tail,
            tick_identity.clone(),
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        );
        let action_identity = tick_identity.with_action_id(ActionId::new());
        let candidate = action("external", serde_json::json!({"ok": true}));
        if use_action_failure {
            append_event(
                writer.as_ref(),
                &mut tail,
                action_identity,
                TraceEventKind::ActionFailed {
                    action: candidate,
                    error: "adapter_failed".to_string(),
                    result: VerificationResult {
                        allowed: false,
                        reasons: vec!["adapter_failed".to_string()],
                        artifacts: serde_json::json!({
                            "adapter_entered": true,
                            "reconciliation_required": true,
                        }),
                    },
                },
            );
        } else {
            append_event(
                writer.as_ref(),
                &mut tail,
                action_identity,
                TraceEventKind::ActionVerificationStarted { action: candidate },
            );
        }

        assert!(matches!(
            resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id),
            Err(TraceCompatibilityError::ReconciliationRequired)
        ));
    }
}

#[test]
fn durable_action_history_reports_source_bound_terminal_and_approval_states() {
    for (source, expected_source) in [
        ("daemon.action", DurableActionHistorySource::Direct),
        (
            "daemon.physical_action",
            DurableActionHistorySource::Physical,
        ),
    ] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let action_id = ActionId::new();
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &action_id,
            )
            .expect("fresh history"),
            DurableActionHistoryDisposition::Fresh,
        );
        append_completed_tickless_action(
            writer.as_ref(),
            &mut tail,
            exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(action_id.clone()),
            source,
            CompletedActionTerminal::Executed,
        );
        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &action_id,
            )
            .expect("complete history"),
            DurableActionHistoryDisposition::Complete {
                source: expected_source,
            },
        );
    }

    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let action_id = ActionId::new();
    let identity =
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(action_id.clone());
    let candidate = action("external", serde_json::json!({"source": "daemon.action"}));
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    append_completed_tickless_action_with_candidate(
        writer.as_ref(),
        &mut tail,
        identity.clone(),
        candidate.clone(),
        "daemon.action",
        CompletedActionTerminal::NeedsApproval,
    );
    assert_eq!(
        inspect_durable_action_history(
            writer.as_ref(),
            &run_id,
            &tenant_id,
            &agent_id,
            &action_id,
        )
        .expect("pending direct approval"),
        DurableActionHistoryDisposition::PendingApproval {
            source: DurableActionHistorySource::Direct,
        },
    );
    append_completed_tickless_action_with_candidate(
        writer.as_ref(),
        &mut tail,
        identity,
        candidate,
        "daemon.action",
        CompletedActionTerminal::Executed,
    );
    assert_eq!(
        inspect_durable_action_history(
            writer.as_ref(),
            &run_id,
            &tenant_id,
            &agent_id,
            &action_id,
        )
        .expect("completed direct continuation"),
        DurableActionHistoryDisposition::Complete {
            source: DurableActionHistorySource::Direct,
        },
    );

    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let action_id = ActionId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    let candidate = append_completed_tick_approval(
        writer.as_ref(),
        &mut tail,
        &run_id,
        &tenant_id,
        &agent_id,
        1,
        &action_id,
    );
    assert_eq!(
        inspect_durable_action_history(
            writer.as_ref(),
            &run_id,
            &tenant_id,
            &agent_id,
            &action_id,
        )
        .expect("pending tick approval"),
        DurableActionHistoryDisposition::PendingApproval {
            source: DurableActionHistorySource::Tick,
        },
    );
    append_completed_tickless_action_with_candidate(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(action_id.clone()),
        candidate,
        "daemon.action",
        CompletedActionTerminal::Executed,
    );
    assert_eq!(
        inspect_durable_action_history(
            writer.as_ref(),
            &run_id,
            &tenant_id,
            &agent_id,
            &action_id,
        )
        .expect("completed tick continuation"),
        DurableActionHistoryDisposition::Complete {
            source: DurableActionHistorySource::Tick,
        },
    );
}

#[test]
fn stable_action_id_reuse_on_later_completed_ticks_selects_the_latest_snapshot() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let action_id = ActionId::new();
    let candidate = action("external", serde_json::json!({"stable": true}));
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    append_completed_tick_execution(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, Some(1)),
        &action_id,
        &candidate,
        b"first-action-state",
    );
    let (snapshot_id, state_node_id, state_hash) = append_completed_tick_execution(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, Some(2)),
        &action_id,
        &candidate,
        b"second-action-state",
    );

    assert_eq!(
        inspect_durable_action_history(
            writer.as_ref(),
            &run_id,
            &tenant_id,
            &agent_id,
            &action_id,
        )
        .expect("later completed tick history"),
        DurableActionHistoryDisposition::Complete {
            source: DurableActionHistorySource::Tick,
        },
    );
    let resumed = resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id)
        .expect("latest repeated-action snapshot");
    assert_eq!(resumed.tick_id, 2);
    assert_eq!(resumed.snapshot_id, snapshot_id);
    assert_eq!(resumed.state_node_id, state_node_id);
    assert_eq!(resumed.state_hash, state_hash);
}

#[test]
fn each_completed_tick_challenge_allows_one_direct_continuation_before_later_reuse() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let action_id = ActionId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);

    for tick_id in [1, 2] {
        let candidate = append_completed_tick_approval(
            writer.as_ref(),
            &mut tail,
            &run_id,
            &tenant_id,
            &agent_id,
            tick_id,
            &action_id,
        );
        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &action_id,
            )
            .expect("tick challenge"),
            DurableActionHistoryDisposition::PendingApproval {
                source: DurableActionHistorySource::Tick,
            },
        );
        append_completed_tickless_action_with_candidate(
            writer.as_ref(),
            &mut tail,
            exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(action_id.clone()),
            candidate,
            "daemon.action",
            CompletedActionTerminal::Executed,
        );
    }

    let candidate = action("external", serde_json::json!({"source": "daemon.action"}));
    let (latest_snapshot, _, _) = append_completed_tick_execution(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, Some(3)),
        &action_id,
        &candidate,
        b"state-after-second-continuation",
    );
    assert_eq!(
        inspect_durable_action_history(
            writer.as_ref(),
            &run_id,
            &tenant_id,
            &agent_id,
            &action_id,
        )
        .expect("closed challenge followed by later tick"),
        DurableActionHistoryDisposition::Complete {
            source: DurableActionHistorySource::Tick,
        },
    );
    assert_eq!(
        resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id)
            .expect("resume after repeated challenge continuations")
            .snapshot_id,
        latest_snapshot,
    );
}

#[test]
fn repeated_tick_action_id_still_reconciles_decreasing_or_changed_episodes() {
    for case in ["decreasing_tick", "changed_action", "challenge_not_closed"] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let action_id = ActionId::new();
        let stable = action("external", serde_json::json!({"stable": true}));
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        if case == "challenge_not_closed" {
            append_completed_tick_approval(
                writer.as_ref(),
                &mut tail,
                &run_id,
                &tenant_id,
                &agent_id,
                1,
                &action_id,
            );
        } else {
            append_completed_tick_execution(
                writer.as_ref(),
                &mut tail,
                exact_identity(&run_id, &tenant_id, &agent_id, Some(2)),
                &action_id,
                &stable,
                b"initial-repeated-action-state",
            );
        }
        let repeated = if case == "changed_action" {
            action("external", serde_json::json!({"stable": false}))
        } else {
            stable.clone()
        };
        append_completed_tick_execution(
            writer.as_ref(),
            &mut tail,
            exact_identity(
                &run_id,
                &tenant_id,
                &agent_id,
                Some(if case == "decreasing_tick" { 1 } else { 3 }),
            ),
            &action_id,
            &repeated,
            b"illegal-repeated-action-state",
        );

        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &action_id,
            )
            .expect("bounded illegal repeated tick disposition"),
            DurableActionHistoryDisposition::ReconciliationRequired,
            "case={case}",
        );
        assert!(matches!(
            resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id),
            Err(TraceCompatibilityError::ReconciliationRequired)
        ));
    }
}

#[test]
fn strictly_later_completed_tick_supersedes_pre_action_attempt() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, Some(1)),
        TraceEventKind::LoopTickStarted { tick_id: 1 },
    );
    let second_identity = exact_identity(&run_id, &tenant_id, &agent_id, Some(2));
    append_event(
        writer.as_ref(),
        &mut tail,
        second_identity.clone(),
        TraceEventKind::LoopTickStarted { tick_id: 2 },
    );
    let (snapshot_id, state_node_id, state_hash) = append_completed_snapshot_suffix(
        writer.as_ref(),
        &mut tail,
        second_identity,
        2,
        b"state-after-safe-tick-supersession",
    );

    assert_eq!(
        inspect_durable_action_history(
            writer.as_ref(),
            &run_id,
            &tenant_id,
            &agent_id,
            &ActionId::new(),
        )
        .expect("safe supersession action history"),
        DurableActionHistoryDisposition::Fresh,
    );
    let resumed = resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id)
        .expect("safe pre-action tick supersession");
    assert_eq!(resumed.tick_id, 2);
    assert_eq!(resumed.max_tick_id, 2);
    assert_eq!(resumed.snapshot_id, snapshot_id);
    assert_eq!(resumed.state_node_id, state_node_id);
    assert_eq!(resumed.state_hash, state_hash);
}

#[test]
fn action_outcome_state_and_unknown_action_evidence_prevent_tick_supersession() {
    for case in ["action_started", "outcome", "state", "unknown_action"] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        let first_identity = exact_identity(&run_id, &tenant_id, &agent_id, Some(1));
        append_event(
            writer.as_ref(),
            &mut tail,
            first_identity.clone(),
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        );
        match case {
            "action_started" => append_event(
                writer.as_ref(),
                &mut tail,
                first_identity.clone().with_action_id(ActionId::new()),
                TraceEventKind::ActionVerificationStarted {
                    action: action("external", serde_json::json!({"case": case})),
                },
            ),
            "outcome" => append_event(
                writer.as_ref(),
                &mut tail,
                first_identity.clone(),
                no_action_tick_outcome(1),
            ),
            "state" => {
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    first_identity.clone(),
                    no_action_tick_outcome(1),
                );
                let state_hash = ContentHash::blake3(b"incomplete-stateful-tick");
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    first_identity
                        .clone()
                        .with_state_node_id(StateNodeId::from_hash(state_hash.clone())),
                    TraceEventKind::StateCommitted {
                        state_hash,
                        snapshot_id: Some(SnapshotId::from_bytes(b"incomplete-stateful-tick")),
                    },
                )
            }
            "unknown_action" => append_event(
                writer.as_ref(),
                &mut tail,
                first_identity.with_action_id(ActionId::new()),
                TraceEventKind::RunPaused {
                    reason: Some("unknown action-scoped evidence".to_string()),
                },
            ),
            _ => unreachable!("closed unsafe supersession matrix"),
        };
        let second_identity = exact_identity(&run_id, &tenant_id, &agent_id, Some(2));
        append_event(
            writer.as_ref(),
            &mut tail,
            second_identity.clone(),
            TraceEventKind::LoopTickStarted { tick_id: 2 },
        );
        append_completed_snapshot_suffix(
            writer.as_ref(),
            &mut tail,
            second_identity,
            2,
            format!("unsafe-supersession-{case}").as_bytes(),
        );

        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &ActionId::new(),
            )
            .expect("bounded unsafe supersession disposition"),
            DurableActionHistoryDisposition::ReconciliationRequired,
            "case={case}",
        );
        assert!(
            matches!(
                resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id),
                Err(TraceCompatibilityError::ReconciliationRequired)
                    | Err(TraceCompatibilityError::TickLifecycle)
            ),
            "case={case}",
        );
    }
}

#[test]
fn equal_or_decreasing_tick_cannot_supersede_a_pre_action_attempt() {
    for (first_tick_id, next_tick_id) in [(1, 1), (2, 1)] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        append_event(
            writer.as_ref(),
            &mut tail,
            exact_identity(&run_id, &tenant_id, &agent_id, Some(first_tick_id)),
            TraceEventKind::LoopTickStarted {
                tick_id: first_tick_id,
            },
        );
        let next_identity = exact_identity(&run_id, &tenant_id, &agent_id, Some(next_tick_id));
        append_event(
            writer.as_ref(),
            &mut tail,
            next_identity.clone(),
            TraceEventKind::LoopTickStarted {
                tick_id: next_tick_id,
            },
        );
        append_completed_snapshot_suffix(
            writer.as_ref(),
            &mut tail,
            next_identity,
            next_tick_id,
            b"misordered-tick-state",
        );

        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &ActionId::new(),
            )
            .expect("bounded non-monotonic tick disposition"),
            DurableActionHistoryDisposition::ReconciliationRequired,
        );
        assert!(matches!(
            resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id),
            Err(TraceCompatibilityError::ReconciliationRequired)
                | Err(TraceCompatibilityError::TickLifecycle)
        ));
    }
}

#[test]
fn superseded_tick_cannot_complete_out_of_order() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, Some(1)),
        TraceEventKind::LoopTickStarted { tick_id: 1 },
    );
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, Some(2)),
        TraceEventKind::LoopTickStarted { tick_id: 2 },
    );
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, Some(1)),
        TraceEventKind::LoopTickCompleted {
            tick_id: 1,
            integrity: None,
        },
    );

    assert_eq!(
        inspect_durable_action_history(
            writer.as_ref(),
            &run_id,
            &tenant_id,
            &agent_id,
            &ActionId::new(),
        )
        .expect("bounded out-of-order disposition"),
        DurableActionHistoryDisposition::ReconciliationRequired,
    );
    assert!(matches!(
        resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id),
        Err(TraceCompatibilityError::ReconciliationRequired)
            | Err(TraceCompatibilityError::TickLifecycle)
    ));
}

#[test]
fn one_approval_continuation_closes_on_every_nonapproval_terminal() {
    for terminal in [
        CompletedActionTerminal::Denied,
        CompletedActionTerminal::Executed,
        CompletedActionTerminal::Failed,
        CompletedActionTerminal::NeedsIntervention,
    ] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let action_id = ActionId::new();
        let identity =
            exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(action_id.clone());
        let candidate = action("external", serde_json::json!({"stable": true}));
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        append_completed_snapshot(
            writer.as_ref(),
            &mut tail,
            &run_id,
            &tenant_id,
            &agent_id,
            1,
            b"state-before-approval-continuation",
        );
        append_completed_tickless_action_with_candidate(
            writer.as_ref(),
            &mut tail,
            identity.clone(),
            candidate.clone(),
            "daemon.action",
            CompletedActionTerminal::NeedsApproval,
        );
        append_completed_tickless_action_with_candidate(
            writer.as_ref(),
            &mut tail,
            identity,
            candidate,
            "daemon.action",
            terminal,
        );

        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &action_id,
            )
            .expect("terminal approval continuation"),
            DurableActionHistoryDisposition::Complete {
                source: DurableActionHistorySource::Direct,
            },
            "terminal={terminal:?}",
        );
        assert_eq!(
            resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id)
                .expect("resume shares legal action-history validation")
                .tick_id,
            1,
            "terminal={terminal:?}",
        );
    }
}

#[test]
fn approval_continuation_cannot_issue_a_second_challenge() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let action_id = ActionId::new();
    let identity =
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(action_id.clone());
    let candidate = action("external", serde_json::json!({"stable": true}));
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    append_completed_snapshot(
        writer.as_ref(),
        &mut tail,
        &run_id,
        &tenant_id,
        &agent_id,
        1,
        b"state-before-repeat-challenge",
    );
    for _ in 0..2 {
        append_completed_tickless_action_with_candidate(
            writer.as_ref(),
            &mut tail,
            identity.clone(),
            candidate.clone(),
            "daemon.action",
            CompletedActionTerminal::NeedsApproval,
        );
    }

    assert_eq!(
        inspect_durable_action_history(
            writer.as_ref(),
            &run_id,
            &tenant_id,
            &agent_id,
            &action_id,
        )
        .expect("repeat challenge disposition"),
        DurableActionHistoryDisposition::ReconciliationRequired,
    );
    assert!(matches!(
        resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id),
        Err(TraceCompatibilityError::ReconciliationRequired)
    ));
}

#[test]
fn completed_approval_continuation_rejects_a_third_episode() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let action_id = ActionId::new();
    let identity =
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(action_id.clone());
    let candidate = action("external", serde_json::json!({"stable": true}));
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    append_completed_snapshot(
        writer.as_ref(),
        &mut tail,
        &run_id,
        &tenant_id,
        &agent_id,
        1,
        b"state-before-third-episode",
    );
    for terminal in [
        CompletedActionTerminal::NeedsApproval,
        CompletedActionTerminal::Executed,
        CompletedActionTerminal::Denied,
    ] {
        append_completed_tickless_action_with_candidate(
            writer.as_ref(),
            &mut tail,
            identity.clone(),
            candidate.clone(),
            "daemon.action",
            terminal,
        );
    }

    assert_eq!(
        inspect_durable_action_history(
            writer.as_ref(),
            &run_id,
            &tenant_id,
            &agent_id,
            &action_id,
        )
        .expect("third episode disposition"),
        DurableActionHistoryDisposition::ReconciliationRequired,
    );
    assert!(matches!(
        resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id),
        Err(TraceCompatibilityError::ReconciliationRequired)
    ));
}

#[test]
fn durable_action_history_reconciles_malformed_or_illegal_episodes() {
    for case in [
        "missing_source",
        "unknown_source",
        "malformed_outcome",
        "wrong_action_id",
        "unknown_status",
        "status_mismatch",
        "effect_uncertain",
    ] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let action_id = ActionId::new();
        let identity =
            exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(action_id.clone());
        let candidate = action("external", serde_json::json!({"case": case}));
        let verification = if case == "effect_uncertain" {
            VerificationResult {
                allowed: false,
                reasons: vec!["denied".to_string()],
                artifacts: serde_json::json!({
                    "adapter_entered": true,
                    "effect_certainty": "uncertain",
                    "reconciliation_required": false,
                }),
            }
        } else {
            VerificationResult::deny("denied")
        };
        let mut outcome = serde_json::json!({
            "source": "daemon.action",
            "action_outcome": {
                "action_id": action_id,
                "status": "Denied",
                "verification": verification,
                "post_verification": null,
                "output": null,
                "error": "denied",
                "approval_challenge": null,
                "completed_at": OffsetDateTime::UNIX_EPOCH,
            },
        });
        match case {
            "missing_source" => {
                outcome
                    .as_object_mut()
                    .expect("outcome object")
                    .remove("source");
            }
            "unknown_source" => outcome["source"] = serde_json::json!("unknown.action"),
            "malformed_outcome" => outcome["action_outcome"] = serde_json::json!("invalid"),
            "wrong_action_id" => {
                outcome["action_outcome"]["action_id"] = serde_json::json!(ActionId::new());
            }
            "unknown_status" => {
                outcome["action_outcome"]["status"] = serde_json::json!("Unknown");
            }
            "status_mismatch" => {
                outcome["action_outcome"]["status"] = serde_json::json!("Executed");
            }
            "effect_uncertain" => {}
            _ => unreachable!(),
        }
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        append_denied_tickless_action_with_outcome(
            writer.as_ref(),
            &mut tail,
            identity,
            candidate,
            verification,
            outcome,
        );
        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &action_id,
            )
            .expect("bounded malformed disposition"),
            DurableActionHistoryDisposition::ReconciliationRequired,
            "case={case}",
        );
    }

    for case in ["repeat_without_approval", "changed_body", "changed_source"] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let action_id = ActionId::new();
        let identity =
            exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(action_id.clone());
        let candidate = action("external", serde_json::json!({"stable": true}));
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        append_completed_tickless_action_with_candidate(
            writer.as_ref(),
            &mut tail,
            identity.clone(),
            candidate.clone(),
            "daemon.action",
            if case == "repeat_without_approval" {
                CompletedActionTerminal::Denied
            } else {
                CompletedActionTerminal::NeedsApproval
            },
        );
        append_completed_tickless_action_with_candidate(
            writer.as_ref(),
            &mut tail,
            identity,
            if case == "changed_body" {
                action("external", serde_json::json!({"stable": false}))
            } else {
                candidate
            },
            if case == "changed_source" {
                "daemon.physical_action"
            } else {
                "daemon.action"
            },
            CompletedActionTerminal::Executed,
        );
        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &action_id,
            )
            .expect("bounded illegal-repeat disposition"),
            DurableActionHistoryDisposition::ReconciliationRequired,
            "case={case}",
        );
    }
}

#[test]
fn malformed_action_transition_matrix_requires_reconciliation() {
    for case in [
        "action_after_tick_outcome",
        "duplicate_verification",
        "execution_before_verification",
        "failure_before_verification",
        "action_scoped_tick_outcome",
        "tick_action_with_tickless_outcome",
        "unknown_action_event",
        "changed_event_action",
        "terminal_effect_uncertain",
        "direct_then_tick",
    ] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let action_id = ActionId::new();
        let candidate = action("external", serde_json::json!({"case": case}));
        let tick_id = 1;
        let tick_identity = exact_identity(&run_id, &tenant_id, &agent_id, Some(tick_id));
        let tick_action_identity = tick_identity.clone().with_action_id(action_id.clone());
        let direct_identity =
            exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(action_id.clone());
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);

        match case {
            "action_after_tick_outcome" => {
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    tick_identity.clone(),
                    TraceEventKind::LoopTickStarted { tick_id },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    tick_identity,
                    no_action_tick_outcome(tick_id),
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    tick_action_identity,
                    TraceEventKind::ActionVerificationStarted { action: candidate },
                );
            }
            "duplicate_verification" => {
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity.clone(),
                    TraceEventKind::ActionVerificationStarted {
                        action: candidate.clone(),
                    },
                );
                for _ in 0..2 {
                    append_event(
                        writer.as_ref(),
                        &mut tail,
                        direct_identity.clone(),
                        TraceEventKind::ActionVerificationCompleted {
                            action: candidate.clone(),
                            result: VerificationResult::deny("denied"),
                        },
                    );
                }
            }
            "execution_before_verification" => {
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity.clone(),
                    TraceEventKind::ActionVerificationStarted {
                        action: candidate.clone(),
                    },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity,
                    TraceEventKind::ActionExecuted {
                        action: candidate,
                        outcome: serde_json::json!({"unexpected": true}),
                    },
                );
            }
            "failure_before_verification" => {
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity.clone(),
                    TraceEventKind::ActionVerificationStarted {
                        action: candidate.clone(),
                    },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity,
                    TraceEventKind::ActionFailed {
                        action: candidate,
                        error: "adapter_failed".to_string(),
                        result: VerificationResult {
                            allowed: false,
                            reasons: vec!["adapter_failed".to_string()],
                            artifacts: serde_json::json!({"adapter_entered": false}),
                        },
                    },
                );
            }
            "action_scoped_tick_outcome" => {
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    tick_identity,
                    TraceEventKind::LoopTickStarted { tick_id },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    tick_action_identity.clone(),
                    TraceEventKind::ActionVerificationStarted {
                        action: candidate.clone(),
                    },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    tick_action_identity,
                    TraceEventKind::OutcomeRecorded {
                        outcome: stored_daemon_action_outcome(
                            &action_id,
                            "Denied",
                            &VerificationResult::deny("denied"),
                            None,
                            None,
                            Some("denied"),
                            None,
                        ),
                        feedback: None,
                        reward: None,
                    },
                );
            }
            "tick_action_with_tickless_outcome" => {
                let verification = VerificationResult::deny("denied");
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    tick_identity,
                    TraceEventKind::LoopTickStarted { tick_id },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    tick_action_identity.clone(),
                    TraceEventKind::ActionVerificationStarted {
                        action: candidate.clone(),
                    },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    tick_action_identity.clone(),
                    TraceEventKind::ActionVerificationCompleted {
                        action: candidate.clone(),
                        result: verification.clone(),
                    },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    tick_action_identity,
                    TraceEventKind::ActionDenied {
                        action: candidate,
                        result: verification.clone(),
                    },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity,
                    TraceEventKind::OutcomeRecorded {
                        outcome: stored_daemon_action_outcome(
                            &action_id,
                            "Denied",
                            &verification,
                            None,
                            None,
                            Some("denied"),
                            None,
                        ),
                        feedback: None,
                        reward: None,
                    },
                );
            }
            "unknown_action_event" => {
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity,
                    TraceEventKind::RunPaused {
                        reason: Some("action-scoped unknown event".to_string()),
                    },
                );
            }
            "changed_event_action" => {
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity.clone(),
                    TraceEventKind::ActionVerificationStarted {
                        action: candidate.clone(),
                    },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity,
                    TraceEventKind::ActionVerificationCompleted {
                        action: action("changed", serde_json::json!({})),
                        result: VerificationResult::deny("denied"),
                    },
                );
            }
            "terminal_effect_uncertain" => {
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity.clone(),
                    TraceEventKind::ActionVerificationStarted {
                        action: candidate.clone(),
                    },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity.clone(),
                    TraceEventKind::ActionVerificationCompleted {
                        action: candidate.clone(),
                        result: VerificationResult::allow(),
                    },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity,
                    TraceEventKind::ActionDenied {
                        action: candidate,
                        result: VerificationResult {
                            allowed: false,
                            reasons: vec!["uncertain".to_string()],
                            artifacts: serde_json::json!({
                                "adapter_entered": true,
                                "effect_certainty": "uncertain",
                                "reconciliation_required": false,
                            }),
                        },
                    },
                );
            }
            "direct_then_tick" => {
                append_completed_tickless_action_with_candidate(
                    writer.as_ref(),
                    &mut tail,
                    direct_identity,
                    candidate.clone(),
                    "daemon.action",
                    CompletedActionTerminal::Denied,
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    tick_identity,
                    TraceEventKind::LoopTickStarted { tick_id },
                );
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    tick_action_identity,
                    TraceEventKind::ActionVerificationStarted { action: candidate },
                );
            }
            _ => unreachable!(),
        }

        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &action_id,
            )
            .expect("bounded malformed transition disposition"),
            DurableActionHistoryDisposition::ReconciliationRequired,
            "case={case}",
        );
    }
}

#[test]
fn malformed_terminal_outcome_contracts_require_reconciliation() {
    for case in [
        "denial_with_output",
        "approval_without_challenge",
        "denial_with_challenge",
    ] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let action_id = ActionId::new();
        let identity =
            exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(action_id.clone());
        let candidate = action("external", serde_json::json!({"case": case}));
        let verification = VerificationResult::deny("approval_required");
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);

        if case == "approval_without_challenge" {
            for kind in [
                TraceEventKind::ActionVerificationStarted {
                    action: candidate.clone(),
                },
                TraceEventKind::ActionVerificationCompleted {
                    action: candidate.clone(),
                    result: verification.clone(),
                },
                TraceEventKind::ActionNeedsApproval {
                    action: candidate,
                    result: verification.clone(),
                },
                TraceEventKind::OutcomeRecorded {
                    outcome: stored_daemon_action_outcome(
                        &action_id,
                        "NeedsApproval",
                        &verification,
                        None,
                        None,
                        Some("approval_required"),
                        None,
                    ),
                    feedback: None,
                    reward: None,
                },
            ] {
                append_event(writer.as_ref(), &mut tail, identity.clone(), kind);
            }
        } else {
            let challenge = (case == "denial_with_challenge")
                .then(|| approval_challenge_for(&identity, &candidate, false));
            append_denied_tickless_action_with_outcome(
                writer.as_ref(),
                &mut tail,
                identity,
                candidate,
                verification.clone(),
                stored_daemon_action_outcome(
                    &action_id,
                    "Denied",
                    &verification,
                    None,
                    (case == "denial_with_output").then(|| serde_json::json!({"invalid": true})),
                    Some("approval_required"),
                    challenge,
                ),
            );
        }

        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &action_id,
            )
            .expect("bounded malformed terminal disposition"),
            DurableActionHistoryDisposition::ReconciliationRequired,
            "case={case}",
        );
    }
}

#[test]
fn foreign_and_unscoped_action_id_histories_require_reconciliation() {
    for case in ["unscoped", "foreign_only", "foreign_overlap"] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let foreign_agent_id = AgentId::new();
        let action_id = ActionId::new();
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);

        if case == "unscoped" {
            let event = TraceEvent::try_new_with_identity(
                exact_identity(&run_id, &tenant_id, &agent_id, None)
                    .with_action_id(action_id.clone()),
                tail.next_sequence(),
                OffsetDateTime::UNIX_EPOCH,
                TraceEventKind::ActionVerificationStarted {
                    action: action("external", serde_json::json!({"case": case})),
                },
            )
            .expect("scoped source event");
            let mut payload = serde_json::to_value(event).expect("source payload");
            payload["identity"]["tenant_id"] = serde_json::Value::Null;
            payload["identity"]["agent_id"] = serde_json::Value::Null;
            tail = writer
                .append(&tail, payload)
                .expect("mechanical malformed append")
                .into_tail();
            assert_eq!(tail.next_sequence(), 1);
        } else {
            if case == "foreign_overlap" {
                append_completed_tickless_action(
                    writer.as_ref(),
                    &mut tail,
                    exact_identity(&run_id, &tenant_id, &agent_id, None)
                        .with_action_id(action_id.clone()),
                    "daemon.action",
                    CompletedActionTerminal::Denied,
                );
            }
            append_completed_tickless_action(
                writer.as_ref(),
                &mut tail,
                exact_identity(&run_id, &tenant_id, &foreign_agent_id, None)
                    .with_action_id(action_id.clone()),
                "daemon.action",
                CompletedActionTerminal::Denied,
            );
        }

        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &action_id,
            )
            .expect("bounded foreign/unscoped disposition"),
            DurableActionHistoryDisposition::ReconciliationRequired,
            "case={case}",
        );
    }
}

#[test]
fn complete_direct_and_physical_tickless_actions_preserve_resume_snapshot() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    let (snapshot_id, state_node_id, state_hash) = append_completed_snapshot(
        writer.as_ref(),
        &mut tail,
        &run_id,
        &tenant_id,
        &agent_id,
        1,
        b"state-before-tickless-actions",
    );
    append_completed_tickless_action(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(ActionId::new()),
        "daemon.action",
        CompletedActionTerminal::Executed,
    );
    append_completed_tickless_action(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(ActionId::new()),
        "daemon.physical_action",
        CompletedActionTerminal::Executed,
    );
    append_completed_tickless_action(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(ActionId::new()),
        "daemon.action",
        CompletedActionTerminal::Denied,
    );
    append_completed_tickless_action(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(ActionId::new()),
        "daemon.action",
        CompletedActionTerminal::Failed,
    );
    let approval_action_id = ActionId::new();
    append_completed_tickless_action(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None)
            .with_action_id(approval_action_id.clone()),
        "daemon.action",
        CompletedActionTerminal::NeedsApproval,
    );
    append_completed_tickless_action(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(approval_action_id),
        "daemon.action",
        CompletedActionTerminal::Executed,
    );

    let resumed = resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id)
        .expect("complete tickless actions are recovery-terminal");
    assert_eq!(resumed.snapshot_id, snapshot_id);
    assert_eq!(resumed.state_node_id, state_node_id);
    assert_eq!(resumed.state_hash, state_hash);
    assert_eq!(resumed.tick_id, 1);
    assert_eq!(resumed.max_tick_id, 1);
    assert_eq!(resumed.tail, tail);
}

#[test]
fn complete_tickless_action_without_snapshot_does_not_fabricate_state() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    append_completed_tickless_action(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(ActionId::new()),
        "daemon.action",
        CompletedActionTerminal::Executed,
    );

    assert!(matches!(
        resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id),
        Err(TraceCompatibilityError::SnapshotUnavailable)
    ));
}

#[test]
fn incomplete_or_uncertain_tickless_actions_require_reconciliation() {
    for episode in [
        "started_only",
        "terminal_without_outcome",
        "terminal_without_verification",
        "failure_missing_effect_facts",
        "failure_malformed_effect_facts",
        "uncertain_terminal",
    ] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        append_completed_snapshot(
            writer.as_ref(),
            &mut tail,
            &run_id,
            &tenant_id,
            &agent_id,
            1,
            b"state-before-incomplete-action",
        );
        let identity =
            exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(ActionId::new());
        let candidate = action("external", serde_json::json!({"ok": true}));
        append_event(
            writer.as_ref(),
            &mut tail,
            identity.clone(),
            TraceEventKind::ActionVerificationStarted {
                action: candidate.clone(),
            },
        );
        if episode == "terminal_without_outcome" {
            append_event(
                writer.as_ref(),
                &mut tail,
                identity.clone(),
                TraceEventKind::ActionVerificationCompleted {
                    action: candidate.clone(),
                    result: VerificationResult::deny("permission_denied"),
                },
            );
        }
        if matches!(
            episode,
            "terminal_without_outcome" | "terminal_without_verification"
        ) {
            append_event(
                writer.as_ref(),
                &mut tail,
                identity.clone(),
                TraceEventKind::ActionDenied {
                    action: candidate,
                    result: VerificationResult::deny("permission_denied"),
                },
            );
            if episode == "terminal_without_verification" {
                append_event(
                    writer.as_ref(),
                    &mut tail,
                    identity,
                    TraceEventKind::OutcomeRecorded {
                        outcome: serde_json::json!({"source": "daemon.action"}),
                        feedback: None,
                        reward: None,
                    },
                );
            }
        } else if matches!(
            episode,
            "failure_missing_effect_facts"
                | "failure_malformed_effect_facts"
                | "uncertain_terminal"
        ) {
            append_event(
                writer.as_ref(),
                &mut tail,
                identity.clone(),
                TraceEventKind::ActionVerificationCompleted {
                    action: candidate.clone(),
                    result: VerificationResult::allow(),
                },
            );
            let result = match episode {
                "uncertain_terminal" => VerificationResult {
                    allowed: false,
                    reasons: vec!["adapter_failed".to_string()],
                    artifacts: serde_json::json!({
                        "adapter_entered": true,
                        "effect_certainty": "uncertain",
                        "reconciliation_required": false,
                    }),
                },
                "failure_malformed_effect_facts" => VerificationResult {
                    allowed: false,
                    reasons: vec!["adapter_failed".to_string()],
                    artifacts: serde_json::json!({"adapter_entered": "unknown"}),
                },
                _ => VerificationResult::deny("adapter_failed"),
            };
            append_event(
                writer.as_ref(),
                &mut tail,
                identity.clone(),
                TraceEventKind::ActionFailed {
                    action: candidate,
                    error: "adapter_failed".to_string(),
                    result,
                },
            );
            append_event(
                writer.as_ref(),
                &mut tail,
                identity,
                TraceEventKind::OutcomeRecorded {
                    outcome: serde_json::json!({"source": "daemon.action"}),
                    feedback: None,
                    reward: None,
                },
            );
        }

        assert!(matches!(
            resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id),
            Err(TraceCompatibilityError::ReconciliationRequired)
        ));
    }
}

#[test]
fn completed_tick_failure_with_known_effect_facts_remains_recoverable() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let action_id = ActionId::new();
    let candidate = action("external", serde_json::json!({"known_effect": true}));
    let verification = VerificationResult::allow();
    let failure = VerificationResult {
        allowed: false,
        reasons: vec!["adapter_failed".to_string()],
        artifacts: serde_json::json!({
            "adapter_entered": true,
            "effect_certainty": "known",
            "reconciliation_required": false,
        }),
    };
    let tick_id = 1;
    let tick_identity = exact_identity(&run_id, &tenant_id, &agent_id, Some(tick_id));
    let action_identity = tick_identity.clone().with_action_id(action_id.clone());
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);

    append_event(
        writer.as_ref(),
        &mut tail,
        tick_identity.clone(),
        TraceEventKind::LoopTickStarted { tick_id },
    );
    append_event(
        writer.as_ref(),
        &mut tail,
        action_identity.clone(),
        TraceEventKind::ActionVerificationStarted {
            action: candidate.clone(),
        },
    );
    append_event(
        writer.as_ref(),
        &mut tail,
        action_identity.clone(),
        TraceEventKind::ActionVerificationCompleted {
            action: candidate.clone(),
            result: verification.clone(),
        },
    );
    append_event(
        writer.as_ref(),
        &mut tail,
        action_identity,
        TraceEventKind::ActionFailed {
            action: candidate,
            error: "adapter_failed".to_string(),
            result: failure.clone(),
        },
    );
    append_event(
        writer.as_ref(),
        &mut tail,
        tick_identity.clone(),
        TraceEventKind::OutcomeRecorded {
            outcome: serde_json::json!({
                "tick_id": tick_id,
                "duration_ms": 1,
                "needs_intervention": true,
                "needs_approval": false,
                "escalations": [],
                "actions": [{
                    "action_id": action_id,
                    "status": "Failed",
                    "verification": verification,
                    "post_verification": failure,
                    "output": null,
                    "error": "adapter_failed",
                    "approval_challenge": null,
                    "completed_at": OffsetDateTime::UNIX_EPOCH,
                }],
            }),
            feedback: None,
            reward: None,
        },
    );
    let state_bytes = b"known-effect-failure-state";
    let state_hash = ContentHash::blake3(state_bytes);
    let state_node_id = StateNodeId::from_hash(state_hash.clone());
    let snapshot_id = SnapshotId::from_bytes(state_bytes);
    append_event(
        writer.as_ref(),
        &mut tail,
        tick_identity
            .clone()
            .with_state_node_id(state_node_id.clone()),
        TraceEventKind::StateCommitted {
            state_hash: state_hash.clone(),
            snapshot_id: Some(snapshot_id.clone()),
        },
    );
    append_event(
        writer.as_ref(),
        &mut tail,
        tick_identity,
        TraceEventKind::LoopTickCompleted {
            tick_id,
            integrity: None,
        },
    );

    assert_eq!(
        inspect_durable_action_history(
            writer.as_ref(),
            &run_id,
            &tenant_id,
            &agent_id,
            &action_id,
        )
        .expect("known-effect failure history"),
        DurableActionHistoryDisposition::Complete {
            source: DurableActionHistorySource::Tick,
        },
    );
    let resumed = resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id)
        .expect("known-effect failure remains recoverable");
    assert_eq!(resumed.tick_id, tick_id);
    assert_eq!(resumed.snapshot_id, snapshot_id);
    assert_eq!(resumed.state_node_id, state_node_id);
    assert_eq!(resumed.state_hash, state_hash);
}

#[test]
fn completed_no_action_tick_is_valid_for_history_and_resume() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    let (snapshot_id, state_node_id, state_hash) = append_completed_snapshot(
        writer.as_ref(),
        &mut tail,
        &run_id,
        &tenant_id,
        &agent_id,
        1,
        b"no-action-state",
    );

    assert_eq!(
        inspect_durable_action_history(
            writer.as_ref(),
            &run_id,
            &tenant_id,
            &agent_id,
            &ActionId::new(),
        )
        .expect("complete no-action history"),
        DurableActionHistoryDisposition::Fresh,
    );
    let resumed =
        resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id).expect("no-action resume");
    assert_eq!(resumed.tick_id, 1);
    assert_eq!(resumed.snapshot_id, snapshot_id);
    assert_eq!(resumed.state_node_id, state_node_id);
    assert_eq!(resumed.state_hash, state_hash);
}

#[test]
fn incomplete_or_misordered_no_action_ticks_require_reconciliation() {
    #[derive(Clone, Copy)]
    enum LifecycleEvent {
        Start(u64),
        Outcome(u64),
        State(u64),
        Complete(u64),
    }

    use LifecycleEvent::{Complete, Outcome, Start, State};

    for (case, events) in [
        ("open", vec![Start(1)]),
        ("missing_outcome", vec![Start(1), State(1), Complete(1)]),
        ("missing_state", vec![Start(1), Outcome(1), Complete(1)]),
        ("missing_completion", vec![Start(1), Outcome(1), State(1)]),
        (
            "state_before_outcome",
            vec![Start(1), State(1), Outcome(1), Complete(1)],
        ),
        ("orphan_outcome", vec![Outcome(1)]),
        ("orphan_state", vec![State(1)]),
        ("orphan_completion", vec![Complete(1)]),
        (
            "duplicate_outcome",
            vec![Start(1), Outcome(1), Outcome(1), State(1), Complete(1)],
        ),
        (
            "duplicate_state",
            vec![Start(1), Outcome(1), State(1), State(1), Complete(1)],
        ),
        (
            "duplicate_completion",
            vec![Start(1), Outcome(1), State(1), Complete(1), Complete(1)],
        ),
    ] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        for lifecycle_event in events {
            let tick_id = match lifecycle_event {
                Start(tick_id) | Outcome(tick_id) | State(tick_id) | Complete(tick_id) => tick_id,
            };
            let identity = exact_identity(&run_id, &tenant_id, &agent_id, Some(tick_id));
            let (identity, kind) = match lifecycle_event {
                Start(tick_id) => (identity, TraceEventKind::LoopTickStarted { tick_id }),
                Outcome(tick_id) => (identity, no_action_tick_outcome(tick_id)),
                State(tick_id) => {
                    let state_bytes = format!("{case}-state-{tick_id}");
                    let state_hash = ContentHash::blake3(state_bytes.as_bytes());
                    (
                        identity.with_state_node_id(StateNodeId::from_hash(state_hash.clone())),
                        TraceEventKind::StateCommitted {
                            state_hash,
                            snapshot_id: Some(SnapshotId::from_bytes(state_bytes.as_bytes())),
                        },
                    )
                }
                Complete(tick_id) => (
                    identity,
                    TraceEventKind::LoopTickCompleted {
                        tick_id,
                        integrity: None,
                    },
                ),
            };
            append_event(writer.as_ref(), &mut tail, identity, kind);
        }

        assert_eq!(
            inspect_durable_action_history(
                writer.as_ref(),
                &run_id,
                &tenant_id,
                &agent_id,
                &ActionId::new(),
            )
            .expect("bounded malformed no-action disposition"),
            DurableActionHistoryDisposition::ReconciliationRequired,
            "case={case}",
        );
        assert!(
            matches!(
                resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id),
                Err(TraceCompatibilityError::ReconciliationRequired)
            ),
            "case={case}"
        );
    }
}

#[test]
fn trace_limits_accept_exact_values_and_reject_limit_plus_one() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    append_legacy_events(&store, &run_id);
    let records = TraceStore::read(&store, &run_id.to_string()).expect("legacy records");
    let payload_sizes = records
        .iter()
        .map(|record| {
            serde_json::to_vec(&record.payload)
                .expect("payload bytes")
                .len()
        })
        .collect::<Vec<_>>();
    let total_bytes = payload_sizes.iter().sum::<usize>();
    let max_payload = *payload_sizes.iter().max().expect("payload maximum");

    let exact = RuntimeTraceLimits::checked(1, records.len(), total_bytes, max_payload)
        .expect("exact limits");
    let reader = open_trace_reader(&store, &run_id, exact).expect("exact reader");
    assert_eq!(
        inspect_trace(reader.as_ref(), &run_id)
            .expect("exact inspection")
            .records
            .len(),
        records.len()
    );

    let record_limited =
        RuntimeTraceLimits::checked(1, records.len() - 1, total_bytes, max_payload)
            .expect("record limit");
    let reader = open_trace_reader(&store, &run_id, record_limited).expect("record reader");
    assert!(matches!(
        inspect_trace(reader.as_ref(), &run_id),
        Err(TraceCompatibilityError::LimitExceeded)
    ));

    let byte_limited = RuntimeTraceLimits::checked(1, records.len(), total_bytes - 1, max_payload)
        .expect("byte limit");
    let reader = open_trace_reader(&store, &run_id, byte_limited).expect("byte reader");
    assert!(matches!(
        inspect_trace(reader.as_ref(), &run_id),
        Err(TraceCompatibilityError::LimitExceeded)
    ));

    let payload_limited =
        RuntimeTraceLimits::checked(1, records.len(), total_bytes, max_payload - 1)
            .expect("payload limit");
    let reader = open_trace_reader(&store, &run_id, payload_limited).expect("payload reader");
    assert!(matches!(
        inspect_trace(reader.as_ref(), &run_id),
        Err(TraceCompatibilityError::LimitExceeded)
    ));
}

#[test]
fn redacted_projection_removes_sensitive_content_after_complete_validation() {
    const CANARY: &str = "EVIDENCE_REDACTION_CANARY_NEVER_RETURN";
    const NESTED_KEY_CANARY: &str = "NESTED_SECRET_OBJECT_KEY_NEVER_RETURN";
    const ARBITRARY_KEY_CANARY: &str = "ARBITRARY_SENSITIVE_KEY_NEVER_RETURN";
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(ActionId::new()),
        TraceEventKind::ActionVerificationStarted {
            action: action(
                "inspect",
                serde_json::json!({
                    "secret": {
                        "NESTED_SECRET_OBJECT_KEY_NEVER_RETURN": CANARY,
                        "nested": {"api_token": CANARY},
                    },
                    "nullable_secret": null,
                    "ARBITRARY_SENSITIVE_KEY_NEVER_RETURN_api_token": "opaque",
                    "schema": format!("token {CANARY}"),
                    "visibility": "protected-eval",
                    "plain_context": "causal shape retained",
                }),
            ),
        },
    );

    let trusted = project_trace(writer.as_ref(), &run_id, TraceProjection::Trusted)
        .expect("trusted projection");
    assert!(serde_json::to_string(&trusted)
        .expect("trusted JSON")
        .contains(CANARY));
    let redacted = project_trace(writer.as_ref(), &run_id, TraceProjection::Redacted)
        .expect("redacted projection");
    let event: TraceEvent =
        serde_json::from_value(redacted[0].payload.clone()).expect("projected event");
    let TraceEventKind::ActionVerificationStarted { action } = event.kind else {
        panic!("projected action event");
    };
    assert!(action.params.get("secret").is_none());
    assert!(action.params.get("nullable_secret").is_none());
    assert_eq!(action.params["[REDACTED:sensitive-key]"], "[REDACTED]");
    let encoded = serde_json::to_string(&redacted).expect("redacted JSON");
    assert!(!encoded.contains(CANARY));
    assert!(!encoded.contains(NESTED_KEY_CANARY));
    assert!(!encoded.contains(ARBITRARY_KEY_CANARY));
    assert!(encoded.contains("[REDACTED]"));
    assert!(encoded.contains("[REDACTED:sensitive-key]"));
    assert!(encoded.contains("[REDACTED:protected-eval]"));
    assert!(encoded.contains("causal shape retained"));
}

#[test]
fn redacted_projection_rebuilds_payload_from_the_validated_typed_event() {
    const UNKNOWN_ROOT_CANARY: &str = "UNKNOWN_ROOT_FIELD_NEVER_RETURN";
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (writer, tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    let event = TraceEvent::try_new_with_identity(
        exact_identity(&run_id, &tenant_id, &agent_id, None),
        tail.next_sequence(),
        OffsetDateTime::UNIX_EPOCH,
        TraceEventKind::RunStarted,
    )
    .expect("trace event");
    let mut payload = serde_json::to_value(event).expect("event payload");
    payload["unknown_root"] = serde_json::json!({
        "ARBITRARY_SENSITIVE_KEY_NEVER_RETURN_api_token": UNKNOWN_ROOT_CANARY,
    });
    writer
        .append(&tail, payload)
        .expect("mechanical append accepts unknown non-authorizing source field");

    let trusted = project_trace(writer.as_ref(), &run_id, TraceProjection::Trusted)
        .expect("trusted projection");
    assert!(trusted[0].payload.get("unknown_root").is_some());
    let redacted = project_trace(writer.as_ref(), &run_id, TraceProjection::Redacted)
        .expect("redacted projection");
    assert!(redacted[0].payload.get("unknown_root").is_none());
    assert!(!serde_json::to_string(&redacted)
        .expect("redacted JSON")
        .contains(UNKNOWN_ROOT_CANARY));
    serde_json::from_value::<TraceEvent>(redacted[0].payload.clone())
        .expect("canonical typed projection");
}

#[test]
fn redacted_projection_uses_a_verifiable_projection_local_hash_chain() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None),
        TraceEventKind::RunStarted,
    );
    let source_link_hash = tail
        .stable_tail_hash()
        .cloned()
        .expect("source linkage hash");
    let mut source_hash_key_container = serde_json::Map::new();
    source_hash_key_container.insert(source_link_hash.value.clone(), serde_json::json!("opaque"));
    source_hash_key_container.insert(
        format!("prefix-{}-suffix", source_link_hash.value),
        serde_json::json!("opaque"),
    );
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(ActionId::new()),
        TraceEventKind::ActionVerificationStarted {
            action: action(
                "inspect",
                serde_json::json!({
                    "secret": "projection-hash-oracle-canary",
                    "source_event_hash": source_link_hash.clone(),
                    "embedded_source_event_hash": format!(
                        "prefix-{}-suffix",
                        source_link_hash.value
                    ),
                    "source_hash_key_container": source_hash_key_container,
                }),
            ),
        },
    );
    append_completed_snapshot(
        writer.as_ref(),
        &mut tail,
        &run_id,
        &tenant_id,
        &agent_id,
        1,
        b"projection-state",
    );

    let trusted = project_trace(writer.as_ref(), &run_id, TraceProjection::Trusted)
        .expect("trusted projection");
    let redacted = project_trace(writer.as_ref(), &run_id, TraceProjection::Redacted)
        .expect("redacted projection");
    assert_eq!(trusted.len(), redacted.len());

    let mut projected_previous = None;
    for (source, projected) in trusted.iter().zip(&redacted) {
        assert_eq!(projected.run_id, source.run_id);
        assert_eq!(projected.sequence, source.sequence);
        assert_eq!(projected.recorded_at, source.recorded_at);
        assert_ne!(projected.event_hash, source.event_hash);
        assert_eq!(projected.prev_event_hash, projected_previous);

        let source_event: TraceEvent =
            serde_json::from_value(source.payload.clone()).expect("source event");
        let projected_event: TraceEvent =
            serde_json::from_value(projected.payload.clone()).expect("projected event");
        assert_eq!(projected_event.trace_event_id, source_event.trace_event_id);
        assert_eq!(projected_event.run_id, source_event.run_id);
        assert_eq!(projected_event.sequence, source_event.sequence);
        assert_eq!(
            projected_event.identity.fleet_id,
            source_event.identity.fleet_id
        );
        assert_eq!(
            projected_event.identity.node_id,
            source_event.identity.node_id
        );
        assert_eq!(
            projected_event.identity.instance_id,
            source_event.identity.instance_id
        );
        assert_eq!(
            projected_event.identity.tenant_id,
            source_event.identity.tenant_id
        );
        assert_eq!(
            projected_event.identity.agent_id,
            source_event.identity.agent_id
        );
        assert_eq!(
            projected_event.identity.run_id,
            source_event.identity.run_id
        );
        assert_eq!(
            projected_event.identity.tick_id,
            source_event.identity.tick_id
        );
        assert_eq!(
            projected_event.identity.action_id,
            source_event.identity.action_id
        );
        assert_eq!(
            projected_event.identity.approval_id,
            source_event.identity.approval_id
        );
        assert_eq!(
            projected_event.identity.message_id,
            source_event.identity.message_id
        );
        match (
            projected_event.identity.state_node_id.as_ref(),
            source_event.identity.state_node_id.as_ref(),
        ) {
            (Some(projected), Some(source)) => {
                assert_ne!(projected, source);
                assert_eq!(projected.hash().value, HASH_REDACTION_MARKER);
            }
            (None, None) => {}
            _ => panic!("state-node identity shape changed"),
        }

        let computed =
            verify_redacted_projection_hash(projected_previous.as_ref(), &projected.payload);
        assert_eq!(projected.event_hash, computed);
        if let TraceEventKind::LoopTickCompleted { integrity, .. } = projected_event.kind {
            let integrity = integrity.expect("projected completion integrity");
            assert_eq!(integrity.prev_event_hash, projected_previous);
            assert_eq!(integrity.event_hash, computed);
        }
        projected_previous = Some(computed);
    }

    let encoded = serde_json::to_string(&redacted).expect("redacted JSON");
    for source in &trusted {
        assert!(!encoded.contains(&source.event_hash.to_string()));
        assert!(!encoded.contains(&source.event_hash.value));
        if let Some(previous) = &source.prev_event_hash {
            assert!(!encoded.contains(&previous.to_string()));
            assert!(!encoded.contains(&previous.value));
        }
    }
}

#[test]
fn redacted_action_hash_suppression_is_independent_of_source_membership() {
    let member_store = InMemoryTraceStore::default();
    let nonmember_store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let action_id = ActionId::new();
    let (member_writer, source_digest, _) = append_hash_candidate_action_events(
        &member_store,
        &run_id,
        &tenant_id,
        &agent_id,
        &action_id,
        true,
    );
    let (nonmember_writer, nonmember_source_digest, nonmember) =
        append_hash_candidate_action_events(
            &nonmember_store,
            &run_id,
            &tenant_id,
            &agent_id,
            &action_id,
            false,
        );
    assert_eq!(source_digest, nonmember_source_digest);

    let member_source = project_trace(member_writer.as_ref(), &run_id, TraceProjection::Trusted)
        .expect("member source projection");
    let nonmember_source =
        project_trace(nonmember_writer.as_ref(), &run_id, TraceProjection::Trusted)
            .expect("nonmember source projection");
    assert!(member_source
        .iter()
        .any(|record| record.event_hash.value == source_digest));
    assert!(nonmember_source
        .iter()
        .all(|record| record.event_hash.value != nonmember));

    let member_full = project_trace(member_writer.as_ref(), &run_id, TraceProjection::Redacted)
        .expect("member full projection");
    let nonmember_full = project_trace(
        nonmember_writer.as_ref(),
        &run_id,
        TraceProjection::Redacted,
    )
    .expect("nonmember full projection");
    assert_membership_independent_projection(&member_full, &nonmember_full);
    assert_all_projected_actions_are_redacted(&member_full);
    assert_all_projected_actions_are_redacted(&nonmember_full);
    assert_source_digests_absent(&member_full, &member_source);
    assert_source_digests_absent(&nonmember_full, &nonmember_source);
    let member_encoded = serde_json::to_string(&member_full).expect("member projection JSON");
    let nonmember_encoded =
        serde_json::to_string(&nonmember_full).expect("nonmember projection JSON");
    assert!(!member_encoded.contains(&source_digest));
    assert!(!nonmember_encoded.contains(&nonmember));

    let range_end = u64::try_from(member_full.len()).expect("range end");
    let member_range = project_trace_range(
        member_writer.as_ref(),
        &run_id,
        TraceProjection::Redacted,
        1,
        range_end,
    )
    .expect("member range projection");
    let nonmember_range = project_trace_range(
        nonmember_writer.as_ref(),
        &run_id,
        TraceProjection::Redacted,
        1,
        range_end,
    )
    .expect("nonmember range projection");
    assert_eq!(member_range.len() + 1, member_full.len());
    assert_eq!(member_range[0].sequence, 1);
    assert_eq!(nonmember_range[0].sequence, 1);
    assert!(member_range[0].prev_event_hash.is_none());
    assert!(nonmember_range[0].prev_event_hash.is_none());
    assert_membership_independent_projection(&member_range, &nonmember_range);
    assert_all_projected_actions_are_redacted(&member_range);
    assert_all_projected_actions_are_redacted(&nonmember_range);
    assert_source_digests_absent(&member_range, &member_source);
    assert_source_digests_absent(&nonmember_range, &nonmember_source);
    assert!(!serde_json::to_string(&member_range)
        .expect("member range JSON")
        .contains(&source_digest));
    assert!(!serde_json::to_string(&nonmember_range)
        .expect("nonmember range JSON")
        .contains(&nonmember));
}

#[test]
fn percept_provenance_hash_redaction_is_membership_independent_in_full_and_omitted_source_ranges() {
    let member_store = InMemoryTraceStore::default();
    let nonmember_store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let other_agent_id = AgentId::new();
    let message_id = MessageId::new();
    let (member_writer, source_digest, _) = append_external_hash_probe(
        &member_store,
        &run_id,
        &tenant_id,
        &agent_id,
        &other_agent_id,
        &message_id,
        ExternalHashProbe::Percept,
        true,
    );
    let (nonmember_writer, nonmember_source_digest, nonmember) = append_external_hash_probe(
        &nonmember_store,
        &run_id,
        &tenant_id,
        &agent_id,
        &other_agent_id,
        &message_id,
        ExternalHashProbe::Percept,
        false,
    );
    assert_eq!(source_digest, nonmember_source_digest);

    let member_source = project_trace(member_writer.as_ref(), &run_id, TraceProjection::Trusted)
        .expect("member source");
    let nonmember_source =
        project_trace(nonmember_writer.as_ref(), &run_id, TraceProjection::Trusted)
            .expect("nonmember source");
    let member_full = project_trace(member_writer.as_ref(), &run_id, TraceProjection::Redacted)
        .expect("member full projection");
    let nonmember_full = project_trace(
        nonmember_writer.as_ref(),
        &run_id,
        TraceProjection::Redacted,
    )
    .expect("nonmember full projection");
    assert_membership_independent_projection(&member_full, &nonmember_full);
    assert_source_digests_absent(&member_full, &member_source);
    assert_source_digests_absent(&nonmember_full, &nonmember_source);

    let percept_event: TraceEvent = serde_json::from_value(member_full[1].payload.clone())
        .expect("redacted percept event remains typed");
    let TraceEventKind::PerceptsReceived { percepts } = percept_event.kind else {
        panic!("percept probe event");
    };
    assert_eq!(percepts.len(), 1);
    assert_eq!(
        percepts[0].provenance.source,
        format!("perceptor-{HASH_REDACTION_MARKER}")
    );
    assert_eq!(
        percepts[0].provenance.detail.as_deref(),
        Some(format!("correlation-{HASH_REDACTION_MARKER}").as_str())
    );
    let expected_key = format!("payload-key-{HASH_REDACTION_MARKER}");
    assert_eq!(
        percepts[0].payload[&expected_key],
        format!("payload-value-{HASH_REDACTION_MARKER}")
    );

    let member_range = project_trace_range(
        member_writer.as_ref(),
        &run_id,
        TraceProjection::Redacted,
        1,
        2,
    )
    .expect("member range projection");
    let nonmember_range = project_trace_range(
        nonmember_writer.as_ref(),
        &run_id,
        TraceProjection::Redacted,
        1,
        2,
    )
    .expect("nonmember range projection");
    assert_eq!(member_range.len(), 1);
    assert_eq!(member_range[0].sequence, 1);
    assert!(member_range[0].prev_event_hash.is_none());
    assert_membership_independent_projection(&member_range, &nonmember_range);
    assert_eq!(member_range[0].payload, member_full[1].payload);
    assert_eq!(
        member_range[0].event_hash,
        verify_redacted_projection_hash(None, &member_range[0].payload)
    );
    assert_source_digests_absent(&member_range, &member_source);
    assert_source_digests_absent(&nonmember_range, &nonmember_source);
    let member_encoded = serde_json::to_string(&member_range).expect("member range JSON");
    let nonmember_encoded = serde_json::to_string(&nonmember_range).expect("nonmember range JSON");
    assert!(!member_encoded.contains(&source_digest));
    assert!(!nonmember_encoded.contains(&nonmember));
}

#[test]
fn representative_external_hash_fields_and_keys_are_unconditionally_tokenized() {
    for probe in [
        ExternalHashProbe::Percept,
        ExternalHashProbe::RemoteMessage,
        ExternalHashProbe::StateHandoff,
        ExternalHashProbe::StateCommit,
    ] {
        let member_store = InMemoryTraceStore::default();
        let nonmember_store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let other_agent_id = AgentId::new();
        let message_id = MessageId::new();
        let (member_writer, source_digest, _) = append_external_hash_probe(
            &member_store,
            &run_id,
            &tenant_id,
            &agent_id,
            &other_agent_id,
            &message_id,
            probe,
            true,
        );
        let (nonmember_writer, nonmember_source_digest, nonmember) = append_external_hash_probe(
            &nonmember_store,
            &run_id,
            &tenant_id,
            &agent_id,
            &other_agent_id,
            &message_id,
            probe,
            false,
        );
        assert_eq!(source_digest, nonmember_source_digest, "probe={probe:?}");

        let member_source =
            project_trace(member_writer.as_ref(), &run_id, TraceProjection::Trusted)
                .expect("member source");
        let nonmember_source =
            project_trace(nonmember_writer.as_ref(), &run_id, TraceProjection::Trusted)
                .expect("nonmember source");
        let member_full = project_trace(member_writer.as_ref(), &run_id, TraceProjection::Redacted)
            .expect("member full projection");
        let nonmember_full = project_trace(
            nonmember_writer.as_ref(),
            &run_id,
            TraceProjection::Redacted,
        )
        .expect("nonmember full projection");
        assert_membership_independent_projection(&member_full, &nonmember_full);
        assert_source_digests_absent(&member_full, &member_source);
        assert_source_digests_absent(&nonmember_full, &nonmember_source);
        serde_json::from_value::<TraceEvent>(member_full[1].payload.clone())
            .expect("redacted representative event remains typed");

        let member_range = project_trace_range(
            member_writer.as_ref(),
            &run_id,
            TraceProjection::Redacted,
            1,
            2,
        )
        .expect("member range projection");
        let nonmember_range = project_trace_range(
            nonmember_writer.as_ref(),
            &run_id,
            TraceProjection::Redacted,
            1,
            2,
        )
        .expect("nonmember range projection");
        assert_membership_independent_projection(&member_range, &nonmember_range);
        assert_source_digests_absent(&member_range, &member_source);
        assert_source_digests_absent(&nonmember_range, &nonmember_source);
        let member_encoded = serde_json::to_string(&member_full).expect("member full JSON");
        let nonmember_encoded =
            serde_json::to_string(&nonmember_full).expect("nonmember full JSON");
        assert!(
            member_encoded.contains(HASH_REDACTION_MARKER),
            "probe={probe:?}"
        );
        assert!(!member_encoded.contains(&source_digest), "probe={probe:?}");
        assert!(!nonmember_encoded.contains(&nonmember), "probe={probe:?}");
    }
}

#[test]
fn redacted_projection_preserves_audit_attribution_with_a_fixed_credential_marker() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None),
        TraceEventKind::RunStarted,
    );
    let source_digest = tail.stable_tail_hash().expect("source hash").value.clone();
    let correlation = format!("sha256:{source_digest}");
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None),
        TraceEventKind::DaemonAudit {
            endpoint: "splendor.actions.submit".to_string(),
            audit: AuditAttribution {
                principal: ClientPrincipal::new("app", "client"),
                credential_id: Some(correlation.clone()),
                requested_at: OffsetDateTime::UNIX_EPOCH,
            },
        },
    );
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None),
        TraceEventKind::DaemonAudit {
            endpoint: "splendor.actions.submit".to_string(),
            audit: AuditAttribution {
                principal: ClientPrincipal::new("app", "client"),
                credential_id: Some("sha256:not-a-valid-correlation".to_string()),
                requested_at: OffsetDateTime::UNIX_EPOCH,
            },
        },
    );
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(ActionId::new()),
        TraceEventKind::ActionVerificationStarted {
            action: action(
                "inspect",
                serde_json::json!({
                    "credential_id": correlation,
                    "nested": {"credential_id": correlation},
                }),
            ),
        },
    );

    let trusted = project_trace(writer.as_ref(), &run_id, TraceProjection::Trusted)
        .expect("trusted projection");
    let redacted = project_trace(writer.as_ref(), &run_id, TraceProjection::Redacted)
        .expect("redacted projection");
    let trusted_audit: TraceEvent =
        serde_json::from_value(trusted[1].payload.clone()).expect("trusted audit");
    let redacted_audit: TraceEvent =
        serde_json::from_value(redacted[1].payload.clone()).expect("redacted audit");
    let invalid_redacted_audit: TraceEvent =
        serde_json::from_value(redacted[2].payload.clone()).expect("invalid redacted audit");
    let TraceEventKind::DaemonAudit {
        audit: trusted_audit,
        ..
    } = trusted_audit.kind
    else {
        panic!("trusted daemon audit");
    };
    let TraceEventKind::DaemonAudit {
        audit: redacted_audit,
        ..
    } = redacted_audit.kind
    else {
        panic!("redacted daemon audit");
    };
    assert_eq!(
        trusted_audit.credential_id.as_deref(),
        Some(correlation.as_str())
    );
    assert_eq!(redacted_audit.principal, trusted_audit.principal);
    assert_eq!(redacted_audit.requested_at, trusted_audit.requested_at);
    assert_eq!(
        redacted_audit.credential_id.as_deref(),
        Some("[REDACTED:credential-correlation]")
    );
    let TraceEventKind::DaemonAudit { audit, .. } = invalid_redacted_audit.kind else {
        panic!("invalid redacted daemon audit");
    };
    assert_eq!(
        audit.credential_id.as_deref(),
        Some("[REDACTED:credential-correlation]")
    );

    let action_event: TraceEvent =
        serde_json::from_value(redacted[3].payload.clone()).expect("redacted action");
    let TraceEventKind::ActionVerificationStarted { action } = action_event.kind else {
        panic!("redacted action event");
    };
    assert!(action.params.get("credential_id").is_none());
    assert_eq!(action.params["[REDACTED:credential-id]"], "[REDACTED]");
    assert!(action.params["nested"].get("credential_id").is_none());
    assert_eq!(
        action.params["nested"]["[REDACTED:credential-id]"],
        "[REDACTED]"
    );
    let encoded = serde_json::to_string(&redacted).expect("redacted JSON");
    assert!(!encoded.contains(&correlation));
    assert!(!encoded.contains(&source_digest));
}

#[test]
fn redacted_range_projection_chains_only_the_selected_records() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    for reason in ["first", "second", "third"] {
        append_event(
            writer.as_ref(),
            &mut tail,
            exact_identity(&run_id, &tenant_id, &agent_id, None),
            TraceEventKind::RunPaused {
                reason: Some(reason.to_string()),
            },
        );
    }

    let full = project_trace(writer.as_ref(), &run_id, TraceProjection::Redacted)
        .expect("full redacted projection");
    let full_via_range = project_trace_range(
        writer.as_ref(),
        &run_id,
        TraceProjection::Redacted,
        0,
        u64::MAX,
    )
    .expect("full redacted range projection");
    assert_eq!(full_via_range, full);

    let selected = project_trace_range(writer.as_ref(), &run_id, TraceProjection::Redacted, 1, 3)
        .expect("selected redacted range projection");
    assert_eq!(
        selected
            .iter()
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(selected[0].prev_event_hash.is_none());
    assert_ne!(selected[0].event_hash, full[1].event_hash);

    let mut previous = None;
    for record in &selected {
        let computed = verify_redacted_projection_hash(previous.as_ref(), &record.payload);
        assert_eq!(record.prev_event_hash, previous);
        assert_eq!(record.event_hash, computed);
        previous = Some(computed);
    }

    let trusted_full = project_trace(writer.as_ref(), &run_id, TraceProjection::Trusted)
        .expect("full trusted projection");
    let trusted = project_trace_range(writer.as_ref(), &run_id, TraceProjection::Trusted, 1, 3)
        .expect("trusted range projection");
    assert_eq!(trusted, trusted_full[1..3]);
}

struct AppendOnFirstPageReader {
    inner: RuntimeTraceReaderHandle,
    writer: RuntimeTraceWriterHandle,
    append: Mutex<Option<(RuntimeTraceTail, serde_json::Value)>>,
}

impl RuntimeTraceReader for AppendOnFirstPageReader {
    fn store_identity(&self) -> RuntimeTraceStoreIdentity {
        self.inner.store_identity()
    }

    fn run_id(&self) -> &str {
        self.inner.run_id()
    }

    fn limits(&self) -> RuntimeTraceLimits {
        self.inner.limits()
    }

    fn tail(&self) -> Result<RuntimeTraceTail, RuntimeTracePortError> {
        self.inner.tail()
    }

    fn read_page(&self, start: u64) -> Result<RuntimeTracePage, RuntimeTracePortError> {
        if let Some((tail, payload)) = self
            .append
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?
            .take()
        {
            self.writer.append(&tail, payload)?;
        }
        self.inner.read_page(start)
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        self.inner.confirm_tail(expected)
    }
}

fn assert_concurrent_tail_append_is_transient(store: &dyn TraceStore) {
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let writer = acquire_current_trace_writer(
        store,
        &run_id,
        &tenant_id,
        &agent_id,
        RuntimeTraceLimits::default(),
    )
    .expect("current writer");
    let mut tail = writer.tail().expect("initial tail");
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None),
        TraceEventKind::RunStarted,
    );
    let appended = TraceEvent::try_new_with_identity(
        exact_identity(&run_id, &tenant_id, &agent_id, None),
        tail.next_sequence(),
        OffsetDateTime::UNIX_EPOCH,
        TraceEventKind::RunPaused {
            reason: Some("concurrent append".to_string()),
        },
    )
    .expect("concurrent event");
    let reader =
        open_trace_reader(store, &run_id, RuntimeTraceLimits::default()).expect("runtime reader");
    let racing = AppendOnFirstPageReader {
        inner: reader,
        writer: writer.clone(),
        append: Mutex::new(Some((
            tail,
            serde_json::to_value(appended).expect("concurrent payload"),
        ))),
    };

    assert!(matches!(
        inspect_trace(&racing, &run_id),
        Err(TraceCompatibilityError::TailMoved)
    ));
    assert_eq!(
        inspect_trace(writer.as_ref(), &run_id)
            .expect("fresh inspection after append")
            .records
            .len(),
        2,
    );
}

#[test]
fn concurrent_tail_append_is_transient_for_in_memory_and_sqlite_readers() {
    assert_concurrent_tail_append_is_transient(&InMemoryTraceStore::default());

    let directory = tempfile::tempdir().expect("temporary SQLite directory");
    let sqlite =
        SqliteTraceStore::open(directory.path().join("trace.db")).expect("SQLite trace store");
    assert_concurrent_tail_append_is_transient(&sqlite);
}

#[derive(Clone)]
struct StaticReader {
    run_id: String,
    records: Vec<TraceRecord>,
    tail: RuntimeTraceTail,
    limits: RuntimeTraceLimits,
    store_identity_override: Option<RuntimeTraceStoreIdentity>,
    confirmation_error: Option<RuntimeTracePortError>,
    page_next_override: Option<u64>,
    page_complete_override: Option<bool>,
}

impl RuntimeTraceReader for StaticReader {
    fn store_identity(&self) -> RuntimeTraceStoreIdentity {
        self.store_identity_override
            .clone()
            .unwrap_or_else(|| self.tail.store_identity().clone())
    }

    fn run_id(&self) -> &str {
        &self.run_id
    }

    fn limits(&self) -> RuntimeTraceLimits {
        self.limits
    }

    fn tail(&self) -> Result<RuntimeTraceTail, RuntimeTracePortError> {
        Ok(self.tail.clone())
    }

    fn read_page(&self, start: u64) -> Result<RuntimeTracePage, RuntimeTracePortError> {
        let start = usize::try_from(start).map_err(|_| RuntimeTracePortError::LimitExceeded)?;
        if start > self.records.len() {
            return Err(RuntimeTracePortError::BackendContract);
        }
        let end = start
            .saturating_add(self.limits.page_records)
            .min(self.records.len());
        Ok(RuntimeTracePage::new(
            self.records[start..end].to_vec(),
            self.page_next_override.unwrap_or(end as u64),
            self.page_complete_override
                .unwrap_or(end == self.records.len()),
        ))
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        if let Some(error) = self.confirmation_error {
            Err(error)
        } else if expected != &self.tail {
            Err(RuntimeTracePortError::FenceRejected)
        } else {
            Ok(())
        }
    }
}

fn static_legacy_reader(store: &InMemoryTraceStore, run_id: &RunId) -> StaticReader {
    let source = store
        .open_runtime_reader(&run_id.to_string(), RuntimeTraceLimits::default())
        .expect("source reader");
    StaticReader {
        run_id: run_id.to_string(),
        records: TraceStore::read(store, &run_id.to_string()).expect("source records"),
        tail: source.tail().expect("source tail"),
        limits: RuntimeTraceLimits::default(),
        store_identity_override: None,
        confirmation_error: None,
        page_next_override: None,
        page_complete_override: None,
    }
}

#[test]
fn bounded_reader_rejects_identity_and_resource_contract_violations() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    append_legacy_events(&store, &run_id);
    let source = static_legacy_reader(&store, &run_id);

    assert!(matches!(
        inspect_trace(&source, &RunId::new()),
        Err(TraceCompatibilityError::Envelope)
    ));

    let mut wrong_store = source.clone();
    wrong_store.store_identity_override = Some(RuntimeTraceStoreIdentity::from_opaque_material(
        "different-store",
    ));
    assert!(matches!(
        inspect_trace(&wrong_store, &run_id),
        Err(TraceCompatibilityError::Integrity)
    ));

    let mut record_limited = source.clone();
    record_limited.limits.max_records = source.records.len() - 1;
    assert!(matches!(
        inspect_trace(&record_limited, &run_id),
        Err(TraceCompatibilityError::LimitExceeded)
    ));

    let mut empty_page = source.clone();
    empty_page.records.clear();
    assert!(matches!(
        inspect_trace(&empty_page, &run_id),
        Err(TraceCompatibilityError::Integrity)
    ));

    let payload_sizes = source
        .records
        .iter()
        .map(|record| {
            serde_json::to_vec(&record.payload)
                .expect("payload bytes")
                .len()
        })
        .collect::<Vec<_>>();
    let max_payload = *payload_sizes.iter().max().expect("payload maximum");
    let total_bytes = payload_sizes.iter().sum::<usize>();

    let mut payload_limited = source.clone();
    payload_limited.limits.max_payload_bytes = max_payload - 1;
    assert!(matches!(
        inspect_trace(&payload_limited, &run_id),
        Err(TraceCompatibilityError::LimitExceeded)
    ));

    let mut aggregate_limited = source;
    aggregate_limited.limits.max_payload_bytes = max_payload;
    aggregate_limited.limits.max_bytes = total_bytes - 1;
    assert!(matches!(
        inspect_trace(&aggregate_limited, &run_id),
        Err(TraceCompatibilityError::LimitExceeded)
    ));

    let legacy_error: TraceCompatibilityError = RuntimeTracePortError::LegacyInspectOnly.into();
    assert_eq!(legacy_error, TraceCompatibilityError::LegacyInspectOnly);
}

struct MovingTailReader {
    base: StaticReader,
    actual_tail: Result<RuntimeTraceTail, RuntimeTracePortError>,
    tail_calls: AtomicUsize,
}

impl RuntimeTraceReader for MovingTailReader {
    fn store_identity(&self) -> RuntimeTraceStoreIdentity {
        self.base.store_identity()
    }

    fn run_id(&self) -> &str {
        self.base.run_id()
    }

    fn limits(&self) -> RuntimeTraceLimits {
        self.base.limits()
    }

    fn tail(&self) -> Result<RuntimeTraceTail, RuntimeTracePortError> {
        if self.tail_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(self.base.tail.clone())
        } else {
            self.actual_tail.clone()
        }
    }

    fn read_page(&self, start: u64) -> Result<RuntimeTracePage, RuntimeTracePortError> {
        self.base.read_page(start)
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        if expected == &self.base.tail {
            Err(RuntimeTracePortError::FenceRejected)
        } else {
            Err(RuntimeTracePortError::BackendContract)
        }
    }
}

#[test]
fn corrupt_stable_or_storage_envelope_history_is_rejected_before_projection() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    append_legacy_events(&store, &run_id);

    let mut stable_corrupt = static_legacy_reader(&store, &run_id);
    stable_corrupt.records[0].payload["sequence"] = serde_json::json!(99);
    assert!(matches!(
        project_trace(&stable_corrupt, &run_id, TraceProjection::Redacted),
        Err(TraceCompatibilityError::Integrity)
    ));
    assert!(matches!(
        project_trace_range(&stable_corrupt, &run_id, TraceProjection::Redacted, 1, 2,),
        Err(TraceCompatibilityError::Integrity)
    ));

    let mut envelope_corrupt = static_legacy_reader(&store, &run_id);
    envelope_corrupt.records[0].recorded_at = OffsetDateTime::UNIX_EPOCH
        .checked_add(time::Duration::seconds(1))
        .expect("timestamp");
    assert!(matches!(
        project_trace(&envelope_corrupt, &run_id, TraceProjection::Redacted),
        Err(TraceCompatibilityError::Integrity)
    ));
}

#[test]
fn tail_truncation_and_late_tail_change_return_no_projection() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    append_legacy_events(&store, &run_id);

    let mut truncated = static_legacy_reader(&store, &run_id);
    truncated.records.pop();
    assert!(matches!(
        project_trace(&truncated, &run_id, TraceProjection::Redacted),
        Err(TraceCompatibilityError::Integrity)
    ));

    let mut changed = static_legacy_reader(&store, &run_id);
    changed.confirmation_error = Some(RuntimeTracePortError::FenceRejected);
    assert!(matches!(
        project_trace(&changed, &run_id, TraceProjection::Redacted),
        Err(TraceCompatibilityError::Integrity)
    ));

    let mut malformed_next = static_legacy_reader(&store, &run_id);
    malformed_next.page_next_override = Some(3);
    assert!(matches!(
        inspect_trace(&malformed_next, &run_id),
        Err(TraceCompatibilityError::Integrity)
    ));

    let mut false_growth = static_legacy_reader(&store, &run_id);
    false_growth.page_complete_override = Some(false);
    assert!(matches!(
        inspect_trace(&false_growth, &run_id),
        Err(TraceCompatibilityError::Integrity)
    ));

    let mut unavailable_confirmation = static_legacy_reader(&store, &run_id);
    unavailable_confirmation.confirmation_error = Some(RuntimeTracePortError::Unavailable);
    assert!(matches!(
        inspect_trace(&unavailable_confirmation, &run_id),
        Err(TraceCompatibilityError::Store)
    ));

    let mut corrupt_before_growth = static_legacy_reader(&store, &run_id);
    let appended = TraceEvent::try_new_with_identity(
        TraceIdentityContext::new(run_id.clone()),
        2,
        OffsetDateTime::UNIX_EPOCH,
        TraceEventKind::RunPaused {
            reason: Some("later append".to_string()),
        },
    )
    .expect("later legacy event");
    TraceStore::append(
        &store,
        &run_id.to_string(),
        serde_json::to_value(appended).expect("later legacy payload"),
    )
    .expect("later legacy append");
    corrupt_before_growth.records =
        TraceStore::read(&store, &run_id.to_string()).expect("grown legacy records");
    let impossible_growth = corrupt_before_growth.clone();
    assert!(matches!(
        inspect_trace(&impossible_growth, &run_id),
        Err(TraceCompatibilityError::Integrity)
    ));
    corrupt_before_growth.records[0].payload["sequence"] = serde_json::json!(99);
    corrupt_before_growth.confirmation_error = Some(RuntimeTracePortError::FenceRejected);
    assert!(matches!(
        inspect_trace(&corrupt_before_growth, &run_id),
        Err(TraceCompatibilityError::Integrity)
    ));
}

#[test]
fn tail_rejection_is_transient_only_for_a_monotonic_actual_advance() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    append_legacy_events(&store, &run_id);
    let old = static_legacy_reader(&store, &run_id);
    let old_tail = old.tail.clone();

    let appended = TraceEvent::try_new_with_identity(
        TraceIdentityContext::new(run_id.clone()),
        2,
        OffsetDateTime::UNIX_EPOCH,
        TraceEventKind::RunPaused {
            reason: Some("monotonic append".to_string()),
        },
    )
    .expect("later legacy event");
    TraceStore::append(
        &store,
        &run_id.to_string(),
        serde_json::to_value(appended).expect("later legacy payload"),
    )
    .expect("later legacy append");
    let grown = static_legacy_reader(&store, &run_id);
    let grown_tail = grown.tail.clone();

    let advanced = MovingTailReader {
        base: old.clone(),
        actual_tail: Ok(grown_tail.clone()),
        tail_calls: AtomicUsize::new(0),
    };
    assert!(matches!(
        inspect_trace(&advanced, &run_id),
        Err(TraceCompatibilityError::TailMoved)
    ));

    let decreased = MovingTailReader {
        base: grown,
        actual_tail: Ok(old_tail.clone()),
        tail_calls: AtomicUsize::new(0),
    };
    assert!(matches!(
        inspect_trace(&decreased, &run_id),
        Err(TraceCompatibilityError::Integrity)
    ));

    let changed_hash_tail = RuntimeTraceTail::legacy(
        old_tail.store_identity().clone(),
        old_tail.next_sequence(),
        Some(ContentHash::blake3(b"changed stable tail")),
        Some(ContentHash::blake3(b"changed envelope tail")),
    )
    .expect("changed hash tail");
    let changed_hash = MovingTailReader {
        base: old.clone(),
        actual_tail: Ok(changed_hash_tail),
        tail_calls: AtomicUsize::new(0),
    };
    assert!(matches!(
        inspect_trace(&changed_hash, &run_id),
        Err(TraceCompatibilityError::Integrity)
    ));

    let unavailable = MovingTailReader {
        base: old,
        actual_tail: Err(RuntimeTracePortError::Unavailable),
        tail_calls: AtomicUsize::new(0),
    };
    assert!(matches!(
        inspect_trace(&unavailable, &run_id),
        Err(TraceCompatibilityError::Store)
    ));
}

#[test]
fn storage_envelope_hash_changes_when_nonstable_record_metadata_changes() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    append_legacy_events(&store, &run_id);
    let records = TraceStore::read(&store, &run_id.to_string()).expect("records");
    let original = compute_trace_envelope_hash(None, &records[0]).expect("original envelope");
    let mut changed = records[0].clone();
    changed.recorded_at = changed
        .recorded_at
        .checked_add(time::Duration::nanoseconds(1))
        .expect("changed timestamp");
    let changed = compute_trace_envelope_hash(None, &changed).expect("changed envelope");
    assert_ne!(original, changed);
}

#[test]
fn compatibility_errors_and_store_identity_diagnostics_are_nonreflecting() {
    let secret = "trace-path-run-hash-canary";
    let identity = RuntimeTraceStoreIdentity::from_opaque_material(secret);
    let rendered = format!("{identity:?} {:?}", TraceCompatibilityError::Integrity);
    assert!(!rendered.contains(secret));
    assert_eq!(
        TraceCompatibilityError::Store.to_string(),
        "trace_compatibility_store_failure"
    );
    assert_eq!(
        TraceCompatibilityError::TailMoved.to_string(),
        "trace_compatibility_tail_moved"
    );
}
