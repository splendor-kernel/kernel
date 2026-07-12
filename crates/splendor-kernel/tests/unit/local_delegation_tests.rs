use super::*;
use crate::{
    AgentIsolationPolicy, AgentRuntimeConfig, KernelRuntime, KernelRuntimeConfig, TraceSink,
};
use splendor_authority::{
    grant_from_legacy_allowlists, grant_from_legacy_multi_scope_allowlists,
    CompatibilityGrantContext, LegacyMultiScopeProfile, LegacyScopeProfile, RevocationSnapshot,
    ValidatedCapabilityGrant, REASON_AUTHORITY_GRANT_REVOKED,
    REASON_AUTHORITY_REVOCATION_SNAPSHOT_FUTURE_DATED, REASON_AUTHORITY_REVOCATION_SNAPSHOT_STALE,
};
use splendor_types::{
    AuthorityBudgetScope, AuthorityRevocationId, CapabilityGrantId, PrincipalId, RevocationRecord,
    RevocationStatus, TraceEvent, REVOCATION_RECORD_SCHEMA_VERSION, TASK_REQUEST_SCHEMA,
    TASK_RESPONSE_SCHEMA,
};
use std::sync::{mpsc, Arc, Barrier, Condvar, Mutex};
use std::time::Duration as StdDuration;

#[derive(Default)]
struct CapturingSink {
    events: Arc<Mutex<Vec<TraceEvent>>>,
}

impl TraceSink for CapturingSink {
    fn record(&self, event: &TraceEvent) -> Result<(), crate::TraceError> {
        self.events.lock().expect("events lock").push(event.clone());
        Ok(())
    }
}

struct SimpleRecorder {
    run_id: RunId,
}

const AUTHORITY_AUDIENCE: &str = "daemon:local";
const AUTHORITY_DIGEST: &str =
    "blake3:1111111111111111111111111111111111111111111111111111111111111111";

impl MessageTraceRecorder for SimpleRecorder {
    fn run_id(&self) -> &RunId {
        &self.run_id
    }

    fn record_message_event(&self, _kind: TraceEventKind) -> Result<TraceId, MessageRouterError> {
        Ok(TraceId::new())
    }
}

struct FailingRecorder {
    run_id: RunId,
}

impl MessageTraceRecorder for FailingRecorder {
    fn run_id(&self) -> &RunId {
        &self.run_id
    }

    fn record_message_event(&self, _kind: TraceEventKind) -> Result<TraceId, MessageRouterError> {
        Err(MessageRouterError::StorageUnavailable)
    }
}

struct BlockingDelegationRecorder {
    run_id: RunId,
    entered: Mutex<Option<mpsc::Sender<()>>>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl MessageTraceRecorder for BlockingDelegationRecorder {
    fn run_id(&self) -> &RunId {
        &self.run_id
    }

    fn record_message_event(&self, kind: TraceEventKind) -> Result<TraceId, MessageRouterError> {
        if matches!(&kind, TraceEventKind::DelegationRequested { .. }) {
            if let Some(sender) = self.entered.lock().expect("entered lock").take() {
                let _ = sender.send(());
            }
            let (lock, cvar) = &*self.release;
            let mut released = lock.lock().expect("release lock");
            while !*released {
                released = cvar.wait(released).expect("release wait");
            }
        }
        Ok(TraceId::new())
    }
}

struct BlockingRevocationRecorder {
    run_id: RunId,
    entered: Mutex<Option<mpsc::Sender<()>>>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl MessageTraceRecorder for BlockingRevocationRecorder {
    fn run_id(&self) -> &RunId {
        &self.run_id
    }

    fn record_message_event(&self, kind: TraceEventKind) -> Result<TraceId, MessageRouterError> {
        if matches!(&kind, TraceEventKind::ChildRunFailed { .. }) {
            if let Some(sender) = self.entered.lock().expect("entered lock").take() {
                let _ = sender.send(());
            }
            let (lock, cvar) = &*self.release;
            let mut released = lock.lock().expect("release lock");
            while !*released {
                released = cvar.wait(released).expect("release wait");
            }
        }
        Ok(TraceId::new())
    }
}

fn runtime_for(run_id: RunId) -> (KernelRuntime, Arc<Mutex<Vec<TraceEvent>>>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(CapturingSink {
            events: Arc::clone(&events),
        }),
        run_id: Some(run_id),
        ..KernelRuntimeConfig::default()
    });
    (runtime, events)
}

fn authority(actions: &[&str], adapters: &[&str], permissions: &[&str]) -> DelegatedAuthority {
    DelegatedAuthority {
        allowed_actions: actions.iter().map(|value| value.to_string()).collect(),
        allowed_adapters: adapters.iter().map(|value| value.to_string()).collect(),
        allowed_permissions: permissions.iter().map(|value| value.to_string()).collect(),
    }
}

fn setup_manager() -> (
    LocalDelegationManager,
    AgentContext,
    AgentContext,
    PrincipalId,
    PrincipalId,
    RunId,
    RunId,
) {
    let manager = LocalDelegationManager::new();
    let tenant_id = TenantId::new();
    let parent_id = AgentId::new();
    let child_id = AgentId::new();
    let parent_principal = PrincipalId::new();
    let child_principal = PrincipalId::new();
    let parent = AgentContext::new(
        parent_id.clone(),
        tenant_id.clone(),
        AgentRuntimeConfig {
            isolation: AgentIsolationPolicy {
                allowed_message_schemas: vec![TASK_REQUEST_SCHEMA.to_string()],
                allowed_message_recipients: vec![child_id.clone()],
                ..AgentIsolationPolicy::default()
            },
            ..AgentRuntimeConfig::default()
        },
    );
    let child = AgentContext::new(
        child_id,
        tenant_id,
        AgentRuntimeConfig {
            isolation: AgentIsolationPolicy {
                allowed_message_schemas: vec![TASK_RESPONSE_SCHEMA.to_string()],
                allowed_message_recipients: vec![parent_id],
                ..AgentIsolationPolicy::default()
            },
            ..AgentRuntimeConfig::default()
        },
    );
    manager
        .register_agent_with_principal(
            parent.clone(),
            parent_principal.clone(),
            authority(
                &["query", "publish"],
                &["sql", "artifact"],
                &["finance.read", "artifact.publish"],
            ),
        )
        .expect("parent registered");
    manager
        .register_agent_with_principal(
            child.clone(),
            child_principal.clone(),
            authority(&["query"], &["sql"], &["finance.read"]),
        )
        .expect("child registered");
    let parent_run_id = RunId::new();
    let child_run_id = RunId::new();
    manager
        .register_root_run(parent_run_id.clone(), parent.agent_id.clone())
        .expect("parent run registered");
    (
        manager,
        parent,
        child,
        parent_principal,
        child_principal,
        parent_run_id,
        child_run_id,
    )
}

fn delegation_request(
    parent: &AgentContext,
    child: &AgentContext,
    parent_run_id: RunId,
    child_run_id: RunId,
) -> LocalDelegationRequest {
    let mut request = LocalDelegationRequest::new(
        parent_run_id,
        parent.agent_id.clone(),
        child.agent_id.clone(),
        "summarize receivables",
        authority(&["query"], &["sql"], &["finance.read"]),
        None,
    );
    request.child_run_id = child_run_id;
    request
}

fn parent_grant_for_request(
    parent_principal: &PrincipalId,
    request: &LocalDelegationRequest,
    tenant_id: &TenantId,
) -> ValidatedCapabilityGrant {
    parent_grant_with_allowlists(
        parent_principal,
        request,
        tenant_id,
        &request.delegated_authority.allowed_actions,
        &request.delegated_authority.allowed_adapters,
        &request.delegated_authority.allowed_permissions,
        AuthorityBudgetScope {
            max_actions_per_tick: Some(4),
            max_action_duration_ms: Some(1_000),
            ..AuthorityBudgetScope::default()
        },
    )
}

fn parent_grant_with_allowlists(
    parent_principal: &PrincipalId,
    request: &LocalDelegationRequest,
    tenant_id: &TenantId,
    actions: &[String],
    adapters: &[String],
    permissions: &[String],
    quotas: AuthorityBudgetScope,
) -> ValidatedCapabilityGrant {
    parent_grant_with_allowlists_and_window(
        parent_principal,
        request,
        tenant_id,
        actions,
        adapters,
        permissions,
        quotas,
        OffsetDateTime::now_utc() - time::Duration::minutes(1),
        OffsetDateTime::now_utc() + time::Duration::minutes(30),
    )
}

#[allow(clippy::too_many_arguments)]
fn parent_grant_with_allowlists_and_window(
    parent_principal: &PrincipalId,
    request: &LocalDelegationRequest,
    tenant_id: &TenantId,
    actions: &[String],
    adapters: &[String],
    permissions: &[String],
    quotas: AuthorityBudgetScope,
    not_before: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> ValidatedCapabilityGrant {
    grant_from_legacy_allowlists(
        CompatibilityGrantContext {
            grant_id: CapabilityGrantId::new(),
            issuer: PrincipalId::new(),
            subject: parent_principal.clone(),
            audience: AUTHORITY_AUDIENCE.to_string(),
            validation_digest: AUTHORITY_DIGEST.to_string(),
            max_delegation_depth: 2,
            parent_grant_ids: Vec::new(),
        },
        LegacyScopeProfile {
            tenant_id: tenant_id.clone(),
            agent_id: request.target_agent_id.clone(),
            run_id: Some(request.child_run_id.clone()),
            quotas,
        },
        actions,
        adapters,
        permissions,
        not_before,
        expires_at,
        RevocationStatus::Active,
        Some("local_delegation:test".to_string()),
    )
    .expect("parent capability grant")
}

fn parent_grant_for_requests(
    parent_principal: &PrincipalId,
    tenant_id: &TenantId,
    requests: &[&LocalDelegationRequest],
) -> ValidatedCapabilityGrant {
    let first = requests.first().expect("at least one delegation request");
    grant_from_legacy_multi_scope_allowlists(
        CompatibilityGrantContext {
            grant_id: CapabilityGrantId::new(),
            issuer: PrincipalId::new(),
            subject: parent_principal.clone(),
            audience: AUTHORITY_AUDIENCE.to_string(),
            validation_digest: AUTHORITY_DIGEST.to_string(),
            max_delegation_depth: 2,
            parent_grant_ids: Vec::new(),
        },
        LegacyMultiScopeProfile {
            tenant_id: tenant_id.clone(),
            agent_ids: requests
                .iter()
                .map(|request| request.target_agent_id.clone())
                .collect(),
            run_ids: requests
                .iter()
                .map(|request| request.child_run_id.clone())
                .collect(),
            quotas: AuthorityBudgetScope {
                max_actions_per_tick: Some(4),
                max_action_duration_ms: Some(1_000),
                ..AuthorityBudgetScope::default()
            },
        },
        &first.delegated_authority.allowed_actions,
        &first.delegated_authority.allowed_adapters,
        &first.delegated_authority.allowed_permissions,
        OffsetDateTime::now_utc() - time::Duration::minutes(1),
        OffsetDateTime::now_utc() + time::Duration::minutes(30),
        RevocationStatus::Active,
        Some("local_delegation:multi-request-test".to_string()),
    )
    .expect("multi-request parent capability grant")
}

fn authority_input(
    parent_principal: &PrincipalId,
    child_principal: &PrincipalId,
    parent: &AgentContext,
    request: &LocalDelegationRequest,
) -> LocalDelegationAuthority {
    let parent_grant = parent_grant_for_request(parent_principal, request, &parent.tenant_id);
    let mut authority = LocalDelegationAuthority::new(
        parent_grant,
        child_principal.clone(),
        AUTHORITY_AUDIENCE,
        OffsetDateTime::now_utc(),
    );
    authority.max_fan_out = 3;
    authority
}

fn bind_parent_authority(
    manager: &LocalDelegationManager,
    parent_run_id: &RunId,
    authority: &LocalDelegationAuthority,
) {
    manager
        .bind_root_run_capability_grant(parent_run_id, &authority.parent_capability_grant)
        .expect("trusted parent grant bound to root run");
}

fn revocation_snapshot_for(grant_id: CapabilityGrantId) -> RevocationSnapshot {
    let now = OffsetDateTime::now_utc();
    RevocationSnapshot::with_max_age(
        vec![RevocationRecord {
            schema_version: REVOCATION_RECORD_SCHEMA_VERSION.to_string(),
            revocation_id: AuthorityRevocationId::new(),
            grant_id,
            revocation_ref: Some("revocation:local-delegation-test".to_string()),
            status: RevocationStatus::Revoked {
                reason: "operator_revoked".to_string(),
            },
            revoked_at: Some(now),
        }],
        now,
        time::Duration::minutes(30),
    )
    .expect("revocation snapshot")
}

fn stale_revocation_snapshot() -> RevocationSnapshot {
    let refreshed_at = OffsetDateTime::now_utc() - time::Duration::minutes(10);
    RevocationSnapshot::with_max_age(Vec::new(), refreshed_at, time::Duration::minutes(1))
        .expect("stale revocation snapshot")
}

fn future_dated_revocation_snapshot() -> RevocationSnapshot {
    let refreshed_at = OffsetDateTime::now_utc() + time::Duration::minutes(10);
    RevocationSnapshot::with_max_age(Vec::new(), refreshed_at, time::Duration::minutes(30))
        .expect("future-dated revocation snapshot")
}

fn fill_child_response_outbox(
    manager: &LocalDelegationManager,
    parent: &AgentContext,
    child: &AgentContext,
    parent_run_id: &RunId,
    child_run_id: &RunId,
) {
    let recorder = SimpleRecorder {
        run_id: parent_run_id.clone(),
    };
    for index in 0..1024 {
        let response = TaskResponse::new(
            parent_run_id.clone(),
            child_run_id.clone(),
            TaskResponseStatus::Completed,
            Some(serde_json::json!({ "filler": index })),
            None,
        )
        .expect("filler response");
        let message = Message::new(
            MessageId::new(),
            child.agent_id.clone(),
            parent.agent_id.clone(),
            parent_run_id.clone(),
            TASK_RESPONSE_SCHEMA,
            serde_json::to_value(response).expect("filler response payload"),
            None,
            false,
            OffsetDateTime::now_utc(),
        )
        .expect("filler message");
        manager
            .router()
            .send(
                &recorder,
                MessageEnvelope::new(message).expect("filler envelope"),
            )
            .expect("filler message routed");
    }
}

struct CreatedDelegation {
    manager: LocalDelegationManager,
    parent: AgentContext,
    child: AgentContext,
    parent_run_id: RunId,
    child_run_id: RunId,
    parent_runtime: KernelRuntime,
    child_runtime: KernelRuntime,
    parent_events: Arc<Mutex<Vec<TraceEvent>>>,
    child_events: Arc<Mutex<Vec<TraceEvent>>>,
    authority_evidence: LocalDelegationAuthorityEvidence,
}

fn create_delegation_for_revocation() -> CreatedDelegation {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);
    let child_run = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect("child run created");
    let authority_evidence = child_run
        .run
        .authority_evidence
        .clone()
        .expect("authority evidence");
    CreatedDelegation {
        manager,
        parent,
        child,
        parent_run_id,
        child_run_id,
        parent_runtime,
        child_runtime,
        parent_events,
        child_events,
        authority_evidence,
    }
}

fn count_events(events: &[TraceEvent], predicate: impl Fn(&TraceEventKind) -> bool) -> usize {
    events.iter().filter(|event| predicate(&event.kind)).count()
}

fn assert_run_record_unchanged(before: &LocalRunRecord, after: &LocalRunRecord) {
    assert_eq!(after.run_id, before.run_id);
    assert_eq!(after.agent_id, before.agent_id);
    assert_eq!(after.principal_id, before.principal_id);
    assert_eq!(after.tenant_id, before.tenant_id);
    assert_eq!(after.parent_run_id, before.parent_run_id);
    assert_eq!(after.child_run_ids, before.child_run_ids);
    assert_eq!(after.authority, before.authority);
    assert_eq!(after.capability_grant_id, before.capability_grant_id);
    assert_eq!(after.authority_evidence, before.authority_evidence);
    assert_eq!(after.objective, before.objective);
    assert_eq!(after.parent_trace_id, before.parent_trace_id);
    assert_eq!(after.status, before.status);
    assert_eq!(after.request_message_id, before.request_message_id);
    assert_eq!(after.response_message_id, before.response_message_id);
}

struct DeniedDelegationEffects<'a> {
    manager: &'a LocalDelegationManager,
    parent: &'a AgentContext,
    child: &'a AgentContext,
    parent_run_id: &'a RunId,
    child_run_id: &'a RunId,
    parent_before: &'a LocalRunRecord,
    parent_events: &'a Arc<Mutex<Vec<TraceEvent>>>,
    child_events: &'a Arc<Mutex<Vec<TraceEvent>>>,
    expected_reason: &'a str,
}

fn assert_delegation_rejected_without_effects(input: DeniedDelegationEffects<'_>) {
    let parent_after = input
        .manager
        .run(input.parent_run_id)
        .expect("parent remains registered");
    assert_run_record_unchanged(input.parent_before, &parent_after);
    assert!(
        input.manager.run(input.child_run_id).is_err(),
        "child record not inserted"
    );
    assert!(input
        .manager
        .router()
        .outbox(&input.parent.agent_id, input.parent_run_id)
        .expect("parent outbox")
        .is_empty());
    assert!(input
        .manager
        .router()
        .inbox(&input.child.agent_id, input.parent_run_id)
        .expect("child inbox")
        .is_empty());
    assert!(input.child_events.lock().expect("child events").is_empty());
    let parent_events = input.parent_events.lock().expect("parent events");
    assert_eq!(parent_events.len(), 1, "only one rejection is recorded");
    assert!(matches!(
        &parent_events[0].kind,
        TraceEventKind::DelegationRejected { reason, .. } if reason == input.expected_reason
    ));
    let replay = replay_local_delegations(&parent_events);
    assert_eq!(replay.delegations.len(), 1);
    assert!(replay.messages.is_empty());
    assert!(replay.failures.is_empty());
    assert_eq!(replay.rejections.len(), 1);
    assert_eq!(replay.rejections[0].reason, input.expected_reason);
    assert_eq!(
        replay.rejections[0].delegation.parent_run_id,
        *input.parent_run_id
    );
    assert_eq!(
        replay.rejections[0].delegation.child_run_id,
        *input.child_run_id
    );
    assert_eq!(
        replay.rejections[0].delegation.source_agent_id,
        input.parent.agent_id
    );
    assert_eq!(
        replay.rejections[0].delegation.target_agent_id,
        input.child.agent_id
    );
}

#[derive(Clone, Copy, Debug)]
enum ParentGrantReplayCase {
    DifferentTenant,
    DifferentParentAgentSharedPrincipal,
    DifferentParentPrincipal,
    DifferentParentRun,
    DifferentChildAgent,
    DifferentChildRun,
    DifferentAudience,
    UnrelatedAuthorityEvidence,
    UnrelatedTrustedGrant,
}

#[derive(Clone, Copy, Debug)]
enum SameIdParentGrantMutationCase {
    Operation,
    Tenant,
    Agent,
    Run,
    Audience,
    Budget,
    Expiry,
    Revocation,
    ValidationDigest,
}

fn parent_grant_with_same_id_mutation(
    grant_id: CapabilityGrantId,
    parent_principal: &PrincipalId,
    request: &LocalDelegationRequest,
    tenant_id: &TenantId,
    now: OffsetDateTime,
    mutation: Option<SameIdParentGrantMutationCase>,
) -> ValidatedCapabilityGrant {
    let mut actions = request.delegated_authority.allowed_actions.clone();
    let mut profile_tenant = tenant_id.clone();
    let mut profile_agent = request.target_agent_id.clone();
    let mut profile_run = request.child_run_id.clone();
    let mut audience = AUTHORITY_AUDIENCE.to_string();
    let mut quotas = AuthorityBudgetScope {
        max_actions_per_tick: Some(4),
        max_action_duration_ms: Some(1_000),
        ..AuthorityBudgetScope::default()
    };
    let not_before = now - time::Duration::minutes(1);
    let mut expires_at = now + time::Duration::minutes(30);
    let mut revocation = RevocationStatus::Active;
    let mut validation_digest = AUTHORITY_DIGEST.to_string();

    match mutation {
        None => {}
        Some(SameIdParentGrantMutationCase::Operation) => {
            actions.push("publish".to_string());
        }
        Some(SameIdParentGrantMutationCase::Tenant) => profile_tenant = TenantId::new(),
        Some(SameIdParentGrantMutationCase::Agent) => profile_agent = AgentId::new(),
        Some(SameIdParentGrantMutationCase::Run) => profile_run = RunId::new(),
        Some(SameIdParentGrantMutationCase::Audience) => {
            audience = "daemon:other".to_string();
        }
        Some(SameIdParentGrantMutationCase::Budget) => {
            quotas.max_actions_per_tick = Some(3);
        }
        Some(SameIdParentGrantMutationCase::Expiry) => {
            expires_at -= time::Duration::minutes(1);
        }
        Some(SameIdParentGrantMutationCase::Revocation) => {
            revocation = RevocationStatus::Revoked {
                reason: "same_id_mutation".to_string(),
            };
        }
        Some(SameIdParentGrantMutationCase::ValidationDigest) => {
            validation_digest =
                "blake3:9999999999999999999999999999999999999999999999999999999999999999"
                    .to_string();
        }
    }

    grant_from_legacy_allowlists(
        CompatibilityGrantContext {
            grant_id,
            issuer: PrincipalId::new(),
            subject: parent_principal.clone(),
            audience,
            validation_digest,
            max_delegation_depth: 2,
            parent_grant_ids: Vec::new(),
        },
        LegacyScopeProfile {
            tenant_id: profile_tenant,
            agent_id: profile_agent,
            run_id: Some(profile_run),
            quotas,
        },
        &actions,
        &request.delegated_authority.allowed_adapters,
        &request.delegated_authority.allowed_permissions,
        not_before,
        expires_at,
        revocation,
        Some("local_delegation:same-id-mutation".to_string()),
    )
    .expect("same-ID validated grant mutation")
}

#[test]
fn root_run_grant_binding_is_idempotent_unique_and_subject_bound() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id);
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    let grant_id = authority.parent_capability_grant.grant().grant_id.clone();

    let first = manager
        .bind_root_run_capability_grant(&parent_run_id, &authority.parent_capability_grant)
        .expect("first trusted binding succeeds");
    let retry = manager
        .bind_root_run_capability_grant(&parent_run_id, &authority.parent_capability_grant)
        .expect("same run and grant binding is idempotent");
    assert_eq!(first.capability_grant_id, Some(grant_id.clone()));
    assert_eq!(retry.capability_grant_id, first.capability_grant_id);
    let manager_debug = format!("{manager:?}");
    assert!(manager_debug.contains("<redacted trusted grant bindings>"));
    assert!(!manager_debug.contains(&grant_id.to_string()));

    let other_grant = parent_grant_for_request(&parent_principal, &request, &parent.tenant_id);
    let error = manager
        .bind_root_run_capability_grant(&parent_run_id, &other_grant)
        .expect_err("different grant cannot replace root binding");
    assert!(matches!(
        error,
        LocalDelegationError::ParentRunGrantBindingConflict {
            run_id,
            bound_grant_id,
            supplied_grant_id,
        } if run_id == parent_run_id
            && bound_grant_id == grant_id
            && supplied_grant_id == other_grant.grant().grant_id
    ));

    let other_run_id = RunId::new();
    manager
        .register_root_run(other_run_id.clone(), parent.agent_id.clone())
        .expect("second root registered");
    let error = manager
        .bind_root_run_capability_grant(&other_run_id, &authority.parent_capability_grant)
        .expect_err("same grant cannot bind another root run");
    assert!(matches!(
        error,
        LocalDelegationError::CapabilityGrantRunBindingConflict {
            grant_id: conflict_grant_id,
            bound_run_id,
            requested_run_id,
        } if conflict_grant_id == grant_id
            && bound_run_id == parent_run_id
            && requested_run_id == other_run_id
    ));

    let wrong_subject_grant =
        parent_grant_for_request(&PrincipalId::new(), &request, &parent.tenant_id);
    let error = manager
        .bind_root_run_capability_grant(&other_run_id, &wrong_subject_grant)
        .expect_err("grant subject must match root principal snapshot");
    assert!(matches!(
        error,
        LocalDelegationError::ParentRunGrantSubjectMismatch { run_id, .. }
            if run_id == other_run_id
    ));
    assert!(manager
        .run(&other_run_id)
        .expect("other root remains unbound")
        .capability_grant_id
        .is_none());

    let (parent_runtime, _) = runtime_for(parent_run_id.clone());
    let (child_runtime, _) = runtime_for(request.child_run_id.clone());
    let created = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority.clone())
        .expect("bound root creates child");
    let child_grant_id = created
        .run
        .authority_evidence
        .as_ref()
        .expect("child authority evidence")
        .child_capability_grant_id
        .clone();
    assert_eq!(
        created.run.capability_grant_id.as_ref(),
        Some(&child_grant_id)
    );
    let error = manager
        .bind_root_run_capability_grant(&created.run.run_id, &authority.parent_capability_grant)
        .expect_err("child is auto-bound evidence state, not an explicit root binding target");
    assert!(matches!(
        error,
        LocalDelegationError::ParentGrantBindingRequiresRootRun(run_id)
            if run_id == created.run.run_id
    ));
}

#[test]
fn same_id_different_validated_parent_grant_content_denies_before_effects() {
    for mutation in [
        SameIdParentGrantMutationCase::Operation,
        SameIdParentGrantMutationCase::Tenant,
        SameIdParentGrantMutationCase::Agent,
        SameIdParentGrantMutationCase::Run,
        SameIdParentGrantMutationCase::Audience,
        SameIdParentGrantMutationCase::Budget,
        SameIdParentGrantMutationCase::Expiry,
        SameIdParentGrantMutationCase::Revocation,
        SameIdParentGrantMutationCase::ValidationDigest,
    ] {
        let (
            manager,
            parent,
            child,
            parent_principal,
            child_principal,
            parent_run_id,
            child_run_id,
        ) = setup_manager();
        let request =
            delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
        let grant_id = CapabilityGrantId::new();
        let now = OffsetDateTime::now_utc();
        let bound_grant = parent_grant_with_same_id_mutation(
            grant_id.clone(),
            &parent_principal,
            &request,
            &parent.tenant_id,
            now,
            None,
        );
        manager
            .bind_root_run_capability_grant(&parent_run_id, &bound_grant)
            .expect("exact parent grant bound");
        let mutated_grant = parent_grant_with_same_id_mutation(
            grant_id,
            &parent_principal,
            &request,
            &parent.tenant_id,
            now,
            Some(mutation),
        );
        assert_ne!(bound_grant, mutated_grant, "case {mutation:?}");
        let bind_error = manager
            .bind_root_run_capability_grant(&parent_run_id, &mutated_grant)
            .expect_err("same ID with different validated content is not idempotent");
        assert!(matches!(
            bind_error,
            LocalDelegationError::ParentRunGrantBindingConflict {
                bound_grant_id,
                supplied_grant_id,
                ..
            } if bound_grant_id == supplied_grant_id
        ));
        let mut mutated_authority = LocalDelegationAuthority::new(
            mutated_grant,
            child_principal.clone(),
            AUTHORITY_AUDIENCE,
            now,
        );
        mutated_authority.max_fan_out = 3;
        let parent_before = manager.run(&parent_run_id).expect("bound parent");
        let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
        let (child_runtime, child_events) = runtime_for(child_run_id.clone());

        let error = manager
            .create_child_run(&parent_runtime, &child_runtime, request, mutated_authority)
            .expect_err("same ID with different validated content must deny");
        assert!(matches!(
            error,
            LocalDelegationError::AuthorityDenied { reason }
                if reason == REASON_PARENT_RUN_GRANT_MISMATCH
        ));
        assert_delegation_rejected_without_effects(DeniedDelegationEffects {
            manager: &manager,
            parent: &parent,
            child: &child,
            parent_run_id: &parent_run_id,
            child_run_id: &child_run_id,
            parent_before: &parent_before,
            parent_events: &parent_events,
            child_events: &child_events,
            expected_reason: REASON_PARENT_RUN_GRANT_MISMATCH,
        });
    }
}

#[test]
fn missing_parent_run_grant_binding_denies_once_without_downstream_effects() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    let parent_before = manager.run(&parent_run_id).expect("unbound parent");
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());

    let error = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect_err("unbound root cannot delegate");
    assert!(matches!(
        error,
        LocalDelegationError::AuthorityDenied { reason }
            if reason == REASON_MISSING_PARENT_RUN_GRANT_BINDING
    ));
    assert_delegation_rejected_without_effects(DeniedDelegationEffects {
        manager: &manager,
        parent: &parent,
        child: &child,
        parent_run_id: &parent_run_id,
        child_run_id: &child_run_id,
        parent_before: &parent_before,
        parent_events: &parent_events,
        child_events: &child_events,
        expected_reason: REASON_MISSING_PARENT_RUN_GRANT_BINDING,
    });
}

#[test]
fn child_grant_id_collision_with_root_binding_denies_before_effects() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let mut authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);
    authority
        .authority_evidence
        .as_mut()
        .expect("authority evidence")
        .child_capability_grant_id = authority.parent_capability_grant.grant().grant_id.clone();
    let parent_before = manager.run(&parent_run_id).expect("bound parent");
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());

    let error = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect_err("child grant ID cannot collide with a root binding");
    assert!(matches!(
        error,
        LocalDelegationError::AuthorityDenied { reason }
            if reason == REASON_CHILD_CAPABILITY_GRANT_ID_COLLISION
    ));
    assert_delegation_rejected_without_effects(DeniedDelegationEffects {
        manager: &manager,
        parent: &parent,
        child: &child,
        parent_run_id: &parent_run_id,
        child_run_id: &child_run_id,
        parent_before: &parent_before,
        parent_events: &parent_events,
        child_events: &child_events,
        expected_reason: REASON_CHILD_CAPABILITY_GRANT_ID_COLLISION,
    });
}

#[test]
fn sibling_child_grant_id_collision_denies_without_additional_effects() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, first_run_id) =
        setup_manager();
    let second_run_id = RunId::new();
    let first_request =
        delegation_request(&parent, &child, parent_run_id.clone(), first_run_id.clone());
    let second_request = delegation_request(
        &parent,
        &child,
        parent_run_id.clone(),
        second_run_id.clone(),
    );
    let parent_grant = parent_grant_for_requests(
        &parent_principal,
        &parent.tenant_id,
        &[&first_request, &second_request],
    );
    manager
        .bind_root_run_capability_grant(&parent_run_id, &parent_grant)
        .expect("multi-scope parent grant bound once");
    let mut first_authority = LocalDelegationAuthority::new(
        parent_grant.clone(),
        child_principal.clone(),
        AUTHORITY_AUDIENCE,
        OffsetDateTime::now_utc(),
    );
    first_authority.max_fan_out = 3;
    let (parent_runtime, _) = runtime_for(parent_run_id.clone());
    let (first_runtime, _) = runtime_for(first_run_id.clone());
    let first_child = manager
        .create_child_run(
            &parent_runtime,
            &first_runtime,
            first_request,
            first_authority,
        )
        .expect("first sibling child created");
    let issued_child_grant_id = first_child
        .run
        .capability_grant_id
        .clone()
        .expect("first child grant ID");

    let mut second_authority = LocalDelegationAuthority::new(
        parent_grant,
        child_principal,
        AUTHORITY_AUDIENCE,
        OffsetDateTime::now_utc(),
    );
    second_authority.max_fan_out = 3;
    second_authority
        .authority_evidence
        .as_mut()
        .expect("second authority evidence")
        .child_capability_grant_id = issued_child_grant_id;
    let parent_before = manager
        .run(&parent_run_id)
        .expect("parent before collision");
    let outbox_before = manager
        .router()
        .outbox(&parent.agent_id, &parent_run_id)
        .expect("parent outbox")
        .len();
    let inbox_before = manager
        .router()
        .inbox(&child.agent_id, &parent_run_id)
        .expect("child inbox")
        .len();
    let (collision_parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (second_runtime, child_events) = runtime_for(second_run_id.clone());

    let error = manager
        .create_child_run(
            &collision_parent_runtime,
            &second_runtime,
            second_request,
            second_authority,
        )
        .expect_err("sibling child grant ID collision denied");
    assert!(matches!(
        error,
        LocalDelegationError::AuthorityDenied { reason }
            if reason == REASON_CHILD_CAPABILITY_GRANT_ID_COLLISION
    ));
    assert_run_record_unchanged(
        &parent_before,
        &manager.run(&parent_run_id).expect("parent unchanged"),
    );
    assert!(manager.run(&second_run_id).is_err());
    assert_eq!(
        manager
            .router()
            .outbox(&parent.agent_id, &parent_run_id)
            .expect("parent outbox after collision")
            .len(),
        outbox_before
    );
    assert_eq!(
        manager
            .router()
            .inbox(&child.agent_id, &parent_run_id)
            .expect("child inbox after collision")
            .len(),
        inbox_before
    );
    assert!(child_events.lock().expect("child events").is_empty());
    let parent_events = parent_events.lock().expect("parent events");
    assert_eq!(parent_events.len(), 1);
    let replay = replay_local_delegations(&parent_events);
    assert_eq!(replay.rejections.len(), 1);
    assert_eq!(
        replay.rejections[0].reason,
        REASON_CHILD_CAPABILITY_GRANT_ID_COLLISION
    );
    assert!(replay.messages.is_empty());
    assert!(replay.failures.is_empty());
}

#[test]
fn cross_tenant_child_grant_id_collision_denies_before_effects() {
    let (manager, parent_a, child_a, principal_a, child_principal_a, run_a, child_run_a) =
        setup_manager();
    let request_a = delegation_request(&parent_a, &child_a, run_a.clone(), child_run_a.clone());
    let authority_a = authority_input(&principal_a, &child_principal_a, &parent_a, &request_a);
    bind_parent_authority(&manager, &run_a, &authority_a);
    let (runtime_a, _) = runtime_for(run_a);
    let (child_runtime_a, _) = runtime_for(child_run_a);
    let created_a = manager
        .create_child_run(&runtime_a, &child_runtime_a, request_a, authority_a)
        .expect("tenant A child created");
    let issued_child_grant_id = created_a
        .run
        .capability_grant_id
        .expect("tenant A child grant ID");

    let tenant_b = TenantId::new();
    let parent_b_principal = PrincipalId::new();
    let child_b_principal = PrincipalId::new();
    let child_b_id = AgentId::new();
    let parent_b = AgentContext::new(
        AgentId::new(),
        tenant_b.clone(),
        AgentRuntimeConfig {
            isolation: AgentIsolationPolicy {
                allowed_message_schemas: vec![TASK_REQUEST_SCHEMA.to_string()],
                allowed_message_recipients: vec![child_b_id.clone()],
                ..AgentIsolationPolicy::default()
            },
            ..AgentRuntimeConfig::default()
        },
    );
    let child_b = AgentContext::new(child_b_id, tenant_b, AgentRuntimeConfig::default());
    manager
        .register_agent_with_principal(
            parent_b.clone(),
            parent_b_principal.clone(),
            authority(&["query"], &["sql"], &["finance.read"]),
        )
        .expect("tenant B parent registered");
    manager
        .register_agent_with_principal(
            child_b.clone(),
            child_b_principal.clone(),
            authority(&["query"], &["sql"], &["finance.read"]),
        )
        .expect("tenant B child registered");
    let run_b = RunId::new();
    let child_run_b = RunId::new();
    manager
        .register_root_run(run_b.clone(), parent_b.agent_id.clone())
        .expect("tenant B root registered");
    let request_b = delegation_request(&parent_b, &child_b, run_b.clone(), child_run_b.clone());
    let mut authority_b = authority_input(
        &parent_b_principal,
        &child_b_principal,
        &parent_b,
        &request_b,
    );
    bind_parent_authority(&manager, &run_b, &authority_b);
    authority_b
        .authority_evidence
        .as_mut()
        .expect("tenant B authority evidence")
        .child_capability_grant_id = issued_child_grant_id;
    let parent_before = manager.run(&run_b).expect("tenant B parent before");
    let (parent_runtime_b, parent_events) = runtime_for(run_b.clone());
    let (child_runtime_b, child_events) = runtime_for(child_run_b.clone());

    let error = manager
        .create_child_run(&parent_runtime_b, &child_runtime_b, request_b, authority_b)
        .expect_err("cross-tenant child grant ID collision denied");
    assert!(matches!(
        error,
        LocalDelegationError::AuthorityDenied { reason }
            if reason == REASON_CHILD_CAPABILITY_GRANT_ID_COLLISION
    ));
    assert_delegation_rejected_without_effects(DeniedDelegationEffects {
        manager: &manager,
        parent: &parent_b,
        child: &child_b,
        parent_run_id: &run_b,
        child_run_id: &child_run_b,
        parent_before: &parent_before,
        parent_events: &parent_events,
        child_events: &child_events,
        expected_reason: REASON_CHILD_CAPABILITY_GRANT_ID_COLLISION,
    });
}

#[test]
fn recursive_local_delegation_rejects_broader_replacement_grant_before_effects() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let child_request =
        delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let child_authority =
        authority_input(&parent_principal, &child_principal, &parent, &child_request);
    bind_parent_authority(&manager, &parent_run_id, &child_authority);
    let (parent_runtime, _) = runtime_for(parent_run_id);
    let (child_runtime, _) = runtime_for(child_run_id.clone());
    manager
        .create_child_run(
            &parent_runtime,
            &child_runtime,
            child_request,
            child_authority,
        )
        .expect("child run created and auto-bound to issued grant ID");

    let grandchild_principal = PrincipalId::new();
    let grandchild = AgentContext::new(
        AgentId::new(),
        child.tenant_id.clone(),
        AgentRuntimeConfig::default(),
    );
    manager
        .register_agent_with_principal(
            grandchild.clone(),
            grandchild_principal.clone(),
            authority(&["query"], &["sql"], &["finance.read"]),
        )
        .expect("grandchild registered");
    let grandchild_run_id = RunId::new();
    let grandchild_request = delegation_request(
        &child,
        &grandchild,
        child_run_id.clone(),
        grandchild_run_id.clone(),
    );
    let replacement_authority = authority_input(
        &child_principal,
        &grandchild_principal,
        &child,
        &grandchild_request,
    );
    let child_before = manager.run(&child_run_id).expect("auto-bound child record");
    let (child_parent_runtime, child_parent_events) = runtime_for(child_run_id.clone());
    let (grandchild_runtime, grandchild_events) = runtime_for(grandchild_run_id.clone());

    let error = manager
        .create_child_run(
            &child_parent_runtime,
            &grandchild_runtime,
            grandchild_request,
            replacement_authority,
        )
        .expect_err("a broader replacement grant cannot authorize recursive delegation");
    assert!(matches!(
        error,
        LocalDelegationError::AuthorityDenied { reason }
            if reason == REASON_PARENT_RUN_GRANT_MISMATCH
    ));
    assert_delegation_rejected_without_effects(DeniedDelegationEffects {
        manager: &manager,
        parent: &child,
        child: &grandchild,
        parent_run_id: &child_run_id,
        child_run_id: &grandchild_run_id,
        parent_before: &child_before,
        parent_events: &child_parent_events,
        child_events: &grandchild_events,
        expected_reason: REASON_PARENT_RUN_GRANT_MISMATCH,
    });
}

#[test]
fn reused_parent_capability_grant_confused_deputy_replay_matrix() {
    {
        let (
            manager,
            parent,
            child,
            parent_principal,
            child_principal,
            parent_run_id,
            child_run_id,
        ) = setup_manager();
        let request =
            delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
        let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
        bind_parent_authority(&manager, &parent_run_id, &authority);
        let (parent_runtime, _) = runtime_for(parent_run_id);
        let (child_runtime, _) = runtime_for(child_run_id.clone());

        let created = manager
            .create_child_run(&parent_runtime, &child_runtime, request, authority)
            .expect("intended bound context creates exactly one child");
        assert_eq!(created.run.run_id, child_run_id);
        let issued_grant_id = created
            .run
            .authority_evidence
            .as_ref()
            .expect("child authority evidence")
            .child_capability_grant_id
            .clone();
        assert_eq!(
            created.run.capability_grant_id.as_ref(),
            Some(&issued_grant_id)
        );
        assert_eq!(created.run.principal_id, child_principal);
    }

    for case in [
        ParentGrantReplayCase::DifferentTenant,
        ParentGrantReplayCase::DifferentParentAgentSharedPrincipal,
        ParentGrantReplayCase::DifferentParentPrincipal,
        ParentGrantReplayCase::DifferentParentRun,
        ParentGrantReplayCase::DifferentChildAgent,
        ParentGrantReplayCase::DifferentChildRun,
        ParentGrantReplayCase::DifferentAudience,
        ParentGrantReplayCase::UnrelatedAuthorityEvidence,
        ParentGrantReplayCase::UnrelatedTrustedGrant,
    ] {
        let (
            manager,
            mut parent,
            mut child,
            parent_principal,
            mut child_principal,
            intended_parent_run_id,
            intended_child_run_id,
        ) = setup_manager();
        let intended_request = delegation_request(
            &parent,
            &child,
            intended_parent_run_id.clone(),
            intended_child_run_id.clone(),
        );
        let intended_authority = authority_input(
            &parent_principal,
            &child_principal,
            &parent,
            &intended_request,
        );
        manager
            .bind_root_run_capability_grant(
                &intended_parent_run_id,
                &intended_authority.parent_capability_grant,
            )
            .expect("intended root binding");

        let mut parent_run_id = intended_parent_run_id.clone();
        let mut child_run_id = intended_child_run_id.clone();
        let mut request = intended_request;
        let mut delegation_authority = intended_authority;
        let expected_reason = match case {
            ParentGrantReplayCase::DifferentTenant => {
                // Grant-ID uniqueness is intentionally manager-local. This
                // isolated manager exercises only the trusted grant's tenant
                // scope; it is not cross-manager or cross-instance binding proof.
                let other_tenant = TenantId::new();
                parent.tenant_id = other_tenant.clone();
                child.tenant_id = other_tenant;
                let isolated_manager = LocalDelegationManager::new();
                isolated_manager
                    .register_agent_with_principal(
                        parent.clone(),
                        parent_principal.clone(),
                        authority(
                            &["query", "publish"],
                            &["sql", "artifact"],
                            &["finance.read", "artifact.publish"],
                        ),
                    )
                    .expect("other-tenant parent registered");
                isolated_manager
                    .register_agent_with_principal(
                        child.clone(),
                        child_principal.clone(),
                        authority(&["query"], &["sql"], &["finance.read"]),
                    )
                    .expect("other-tenant child registered");
                isolated_manager
                    .register_root_run(parent_run_id.clone(), parent.agent_id.clone())
                    .expect("other-tenant root registered");
                isolated_manager
                    .bind_root_run_capability_grant(
                        &parent_run_id,
                        &delegation_authority.parent_capability_grant,
                    )
                    .expect("trusted grant explicitly bound in isolated manager");
                request = delegation_request(
                    &parent,
                    &child,
                    parent_run_id.clone(),
                    child_run_id.clone(),
                );
                let parent_before = isolated_manager.run(&parent_run_id).expect("bound parent");
                let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
                let (child_runtime, child_events) = runtime_for(child_run_id.clone());
                let error = isolated_manager
                    .create_child_run(
                        &parent_runtime,
                        &child_runtime,
                        request,
                        delegation_authority,
                    )
                    .expect_err("tenant replay denied");
                assert!(matches!(
                    error,
                    LocalDelegationError::AuthorityDenied { reason } if reason == "overbroad_scope"
                ));
                assert_delegation_rejected_without_effects(DeniedDelegationEffects {
                    manager: &isolated_manager,
                    parent: &parent,
                    child: &child,
                    parent_run_id: &parent_run_id,
                    child_run_id: &child_run_id,
                    parent_before: &parent_before,
                    parent_events: &parent_events,
                    child_events: &child_events,
                    expected_reason: "overbroad_scope",
                });
                continue;
            }
            ParentGrantReplayCase::DifferentParentAgentSharedPrincipal => {
                let different_parent = AgentContext::new(
                    AgentId::new(),
                    parent.tenant_id.clone(),
                    AgentRuntimeConfig {
                        isolation: AgentIsolationPolicy {
                            allowed_message_schemas: vec![TASK_REQUEST_SCHEMA.to_string()],
                            allowed_message_recipients: vec![child.agent_id.clone()],
                            ..AgentIsolationPolicy::default()
                        },
                        ..AgentRuntimeConfig::default()
                    },
                );
                manager
                    .register_agent_with_principal(
                        different_parent.clone(),
                        parent_principal.clone(),
                        authority(
                            &["query", "publish"],
                            &["sql", "artifact"],
                            &["finance.read", "artifact.publish"],
                        ),
                    )
                    .expect("shared-principal parent registered");
                parent = different_parent;
                parent_run_id = RunId::new();
                manager
                    .register_root_run(parent_run_id.clone(), parent.agent_id.clone())
                    .expect("shared-principal root registered");
                let bind_error = manager
                    .bind_root_run_capability_grant(
                        &parent_run_id,
                        &delegation_authority.parent_capability_grant,
                    )
                    .expect_err("grant ID is already bound to intended root");
                assert!(matches!(
                    bind_error,
                    LocalDelegationError::CapabilityGrantRunBindingConflict { .. }
                ));
                request = delegation_request(
                    &parent,
                    &child,
                    parent_run_id.clone(),
                    child_run_id.clone(),
                );
                REASON_MISSING_PARENT_RUN_GRANT_BINDING
            }
            ParentGrantReplayCase::DifferentParentPrincipal => {
                let different_principal = PrincipalId::new();
                parent_run_id = RunId::new();
                manager
                    .register_agent_with_principal(
                        parent.clone(),
                        different_principal,
                        authority(
                            &["query", "publish"],
                            &["sql", "artifact"],
                            &["finance.read", "artifact.publish"],
                        ),
                    )
                    .expect("future runs use different principal");
                manager
                    .register_root_run(parent_run_id.clone(), parent.agent_id.clone())
                    .expect("different-principal root registered");
                let bind_error = manager
                    .bind_root_run_capability_grant(
                        &parent_run_id,
                        &delegation_authority.parent_capability_grant,
                    )
                    .expect_err("grant subject does not match different-principal root");
                assert!(matches!(
                    bind_error,
                    LocalDelegationError::ParentRunGrantSubjectMismatch { .. }
                ));
                request = delegation_request(
                    &parent,
                    &child,
                    parent_run_id.clone(),
                    child_run_id.clone(),
                );
                REASON_MISSING_PARENT_RUN_GRANT_BINDING
            }
            ParentGrantReplayCase::DifferentParentRun => {
                parent_run_id = RunId::new();
                manager
                    .register_root_run(parent_run_id.clone(), parent.agent_id.clone())
                    .expect("different parent run registered");
                let bind_error = manager
                    .bind_root_run_capability_grant(
                        &parent_run_id,
                        &delegation_authority.parent_capability_grant,
                    )
                    .expect_err("grant ID cannot move to different parent run");
                assert!(matches!(
                    bind_error,
                    LocalDelegationError::CapabilityGrantRunBindingConflict { .. }
                ));
                request = delegation_request(
                    &parent,
                    &child,
                    parent_run_id.clone(),
                    child_run_id.clone(),
                );
                REASON_MISSING_PARENT_RUN_GRANT_BINDING
            }
            ParentGrantReplayCase::DifferentChildAgent => {
                let different_child = AgentContext::new(
                    AgentId::new(),
                    child.tenant_id.clone(),
                    AgentRuntimeConfig::default(),
                );
                child_principal = PrincipalId::new();
                manager
                    .register_agent_with_principal(
                        different_child.clone(),
                        child_principal.clone(),
                        authority(&["query"], &["sql"], &["finance.read"]),
                    )
                    .expect("different child registered");
                child = different_child;
                request = delegation_request(
                    &parent,
                    &child,
                    parent_run_id.clone(),
                    child_run_id.clone(),
                );
                delegation_authority.child_subject = child_principal;
                "overbroad_scope"
            }
            ParentGrantReplayCase::DifferentChildRun => {
                child_run_id = RunId::new();
                request = delegation_request(
                    &parent,
                    &child,
                    parent_run_id.clone(),
                    child_run_id.clone(),
                );
                "overbroad_scope"
            }
            ParentGrantReplayCase::DifferentAudience => {
                delegation_authority.audience = "daemon:other".to_string();
                "overbroad_audience"
            }
            ParentGrantReplayCase::UnrelatedAuthorityEvidence => {
                delegation_authority
                    .authority_evidence
                    .as_mut()
                    .expect("authority evidence")
                    .parent_capability_grant_id = CapabilityGrantId::new();
                "authority_evidence_parent_mismatch"
            }
            ParentGrantReplayCase::UnrelatedTrustedGrant => {
                delegation_authority.parent_capability_grant =
                    parent_grant_for_request(&parent_principal, &request, &parent.tenant_id);
                delegation_authority.authority_evidence =
                    Some(LocalDelegationAuthorityEvidence::issued(
                        delegation_authority
                            .parent_capability_grant
                            .grant()
                            .grant_id
                            .clone(),
                        CapabilityGrantId::new(),
                    ));
                REASON_PARENT_RUN_GRANT_MISMATCH
            }
        };

        let parent_before = manager.run(&parent_run_id).expect("attempt parent");
        let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
        let (child_runtime, child_events) = runtime_for(child_run_id.clone());
        let error = manager
            .create_child_run(
                &parent_runtime,
                &child_runtime,
                request,
                delegation_authority,
            )
            .unwrap_err();
        let actual_reason = match &error {
            LocalDelegationError::AuthorityDenied { reason }
            | LocalDelegationError::AuthorityEvidenceDenied { reason } => reason.as_str(),
            other => panic!("{case:?} returned unexpected error: {other:?}"),
        };
        assert_eq!(actual_reason, expected_reason, "case {case:?}");
        assert_delegation_rejected_without_effects(DeniedDelegationEffects {
            manager: &manager,
            parent: &parent,
            child: &child,
            parent_run_id: &parent_run_id,
            child_run_id: &child_run_id,
            parent_before: &parent_before,
            parent_events: &parent_events,
            child_events: &child_events,
            expected_reason,
        });
    }
}

#[test]
fn parent_creates_child_with_explicit_target_objective_and_trace_links() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let child_authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &child_authority);

    let child_run = manager
        .create_child_run(&parent_runtime, &child_runtime, request, child_authority)
        .expect("child run created");

    assert_eq!(child_run.run.parent_run_id, Some(parent_run_id.clone()));
    assert_eq!(child_run.run.agent_id, child.agent_id);
    assert_eq!(child_run.run.principal_id, child_principal);
    assert_eq!(child_run.run.status, LocalRunStatus::Running);
    let authority_evidence = child_run
        .run
        .authority_evidence
        .clone()
        .expect("child run records authority evidence");
    assert_eq!(
        child_run.run.capability_grant_id,
        Some(authority_evidence.child_capability_grant_id.clone())
    );
    assert_eq!(
        child_run.child_agent.delegated_authority,
        Some(authority(&["query"], &["sql"], &["finance.read"]))
    );
    assert_eq!(
        child_run.request_message.message.payload["objective"].as_str(),
        Some("summarize receivables")
    );
    let task_request = TaskRequest::from_payload(&child_run.request_message.message.payload)
        .expect("task request payload decodes");
    assert_eq!(
        task_request.authority_evidence,
        Some(authority_evidence.clone())
    );

    let parent_record = manager.run(&parent_run_id).expect("parent record");
    assert_eq!(
        parent_record.child_run_ids,
        vec![child_run.run.run_id.clone()]
    );

    let parent_events = parent_events.lock().expect("parent events");
    assert!(parent_events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::DelegationRequested { .. })));
    assert!(parent_events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::MessageDelivered { .. })));

    let child_events = child_events.lock().expect("child events");
    let started = child_events
        .iter()
        .find(|event| matches!(event.kind, TraceEventKind::ChildRunStarted { .. }))
        .expect("child start trace");
    match &started.kind {
        TraceEventKind::ChildRunStarted { delegation } => {
            assert_eq!(delegation.parent_run_id, parent_run_id);
            assert_eq!(delegation.child_run_id, child_run_id);
            assert!(delegation.parent_trace_id.is_some());
            assert!(delegation.request_message_id.is_some());
            assert_eq!(delegation.authority_evidence, Some(authority_evidence));
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn delegated_scope_cannot_exceed_parent_or_target_authority() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, _parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, _child_events) = runtime_for(child_run_id.clone());
    let mut request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id);
    request
        .delegated_authority
        .allowed_actions
        .push("publish".to_string());
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);

    let error = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect_err("target cannot receive publish authority");

    assert!(matches!(
        error,
        LocalDelegationError::DelegatedAuthorityDenied { scope: "target" }
    ));
}

#[test]
fn authority_denial_rejects_before_delegation_requested_routing_or_child_insert() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let limited_parent_grant = parent_grant_with_allowlists(
        &parent_principal,
        &request,
        &parent.tenant_id,
        &["other.query".to_string()],
        &request.delegated_authority.allowed_adapters,
        &request.delegated_authority.allowed_permissions,
        AuthorityBudgetScope {
            max_actions_per_tick: Some(4),
            max_action_duration_ms: Some(1_000),
            ..AuthorityBudgetScope::default()
        },
    );
    let mut authority = LocalDelegationAuthority::new(
        limited_parent_grant,
        child_principal,
        AUTHORITY_AUDIENCE,
        OffsetDateTime::now_utc(),
    );
    authority.max_fan_out = 3;
    bind_parent_authority(&manager, &parent_run_id, &authority);

    let error = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect_err("authority denies overbroad child grant");

    assert!(matches!(
        error,
        LocalDelegationError::AuthorityDenied { reason } if reason == "overbroad_operation"
    ));
    assert!(
        manager.run(&child_run_id).is_err(),
        "child record not inserted"
    );
    assert!(manager
        .router()
        .outbox(&parent.agent_id, &parent_run_id)
        .expect("parent outbox")
        .is_empty());
    assert!(manager
        .router()
        .inbox(&child.agent_id, &parent_run_id)
        .expect("child inbox")
        .is_empty());
    assert!(child_events.lock().expect("child events").is_empty());
    let parent_events = parent_events.lock().expect("parent events");
    assert_eq!(
        count_events(&parent_events, |kind| matches!(
            kind,
            TraceEventKind::DelegationRequested { .. }
        )),
        0
    );
    assert!(parent_events.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::DelegationRejected { reason, delegation }
            if reason == "overbroad_operation"
                && delegation.authority_evidence.as_ref().is_some_and(|evidence|
                    evidence.authority_reason.as_deref() == Some("overbroad_operation"))
    )));
}

#[test]
fn unrelated_parent_grant_denies_before_routing_or_child_insert() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let bound_authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &bound_authority);
    let wrong_parent_grant =
        parent_grant_for_request(&PrincipalId::new(), &request, &parent.tenant_id);
    let mut authority = LocalDelegationAuthority::new(
        wrong_parent_grant,
        child_principal,
        AUTHORITY_AUDIENCE,
        OffsetDateTime::now_utc(),
    );
    authority.max_fan_out = 3;

    let error = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect_err("wrong parent principal grant denied");

    assert!(matches!(
        error,
        LocalDelegationError::AuthorityDenied { reason }
            if reason == REASON_PARENT_RUN_GRANT_MISMATCH
    ));
    assert!(
        manager.run(&child_run_id).is_err(),
        "child record not inserted"
    );
    assert!(manager
        .router()
        .outbox(&parent.agent_id, &parent_run_id)
        .expect("parent outbox")
        .is_empty());
    assert!(manager
        .router()
        .inbox(&child.agent_id, &parent_run_id)
        .expect("child inbox")
        .is_empty());
    assert!(child_events.lock().expect("child events").is_empty());
    let parent_events = parent_events.lock().expect("parent events");
    assert_eq!(
        count_events(&parent_events, |kind| matches!(
            kind,
            TraceEventKind::DelegationRequested { .. }
        )),
        0
    );
    assert!(parent_events.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::DelegationRejected { reason, .. }
            if reason == REASON_PARENT_RUN_GRANT_MISMATCH
    )));
}

#[test]
fn parent_run_principal_binding_survives_agent_reregistration() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let replacement_parent_principal = PrincipalId::new();
    manager
        .register_agent_with_principal(
            parent.clone(),
            replacement_parent_principal.clone(),
            authority(
                &["query", "publish"],
                &["sql", "artifact"],
                &["finance.read", "artifact.publish"],
            ),
        )
        .expect("parent can be re-registered for future runs");
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let original_parent_grant =
        parent_grant_for_request(&parent_principal, &request, &parent.tenant_id);
    manager
        .bind_root_run_capability_grant(&parent_run_id, &original_parent_grant)
        .expect("root run retains original principal grant binding");
    let replacement_parent_grant =
        parent_grant_for_request(&replacement_parent_principal, &request, &parent.tenant_id);
    let mut authority = LocalDelegationAuthority::new(
        replacement_parent_grant,
        child_principal,
        AUTHORITY_AUDIENCE,
        OffsetDateTime::now_utc(),
    );
    authority.max_fan_out = 3;

    let error = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect_err("existing parent run keeps its original principal binding");

    assert!(matches!(
        error,
        LocalDelegationError::AuthorityDenied { reason }
            if reason == REASON_PARENT_RUN_GRANT_MISMATCH
    ));
    assert!(manager.run(&child_run_id).is_err());
    assert!(manager
        .router()
        .outbox(&parent.agent_id, &parent_run_id)
        .expect("parent outbox")
        .is_empty());
    assert!(child_events.lock().expect("child events").is_empty());
    let parent_events = parent_events.lock().expect("parent events");
    assert_eq!(
        count_events(&parent_events, |kind| matches!(
            kind,
            TraceEventKind::DelegationRequested { .. }
        )),
        0
    );
}

#[test]
fn not_yet_valid_parent_grant_denies_at_actual_decision_time() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let future_not_before = OffsetDateTime::now_utc() + time::Duration::minutes(10);
    let future_parent_grant = parent_grant_with_allowlists_and_window(
        &parent_principal,
        &request,
        &parent.tenant_id,
        &request.delegated_authority.allowed_actions,
        &request.delegated_authority.allowed_adapters,
        &request.delegated_authority.allowed_permissions,
        AuthorityBudgetScope {
            max_actions_per_tick: Some(4),
            max_action_duration_ms: Some(1_000),
            ..AuthorityBudgetScope::default()
        },
        future_not_before,
        future_not_before + time::Duration::minutes(30),
    );
    let mut authority = LocalDelegationAuthority::new(
        future_parent_grant,
        child_principal,
        AUTHORITY_AUDIENCE,
        OffsetDateTime::now_utc(),
    );
    authority.max_fan_out = 3;
    bind_parent_authority(&manager, &parent_run_id, &authority);

    let error = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect_err("future parent grant is not valid yet");

    assert!(matches!(
        error,
        LocalDelegationError::AuthorityDenied { reason }
            if reason == "parent_not_yet_valid"
    ));
    assert!(manager.run(&child_run_id).is_err());
    assert!(manager
        .router()
        .outbox(&parent.agent_id, &parent_run_id)
        .expect("parent outbox")
        .is_empty());
    assert!(child_events.lock().expect("child events").is_empty());
    let parent_events = parent_events.lock().expect("parent events");
    assert_eq!(
        count_events(&parent_events, |kind| matches!(
            kind,
            TraceEventKind::DelegationRequested { .. }
        )),
        0
    );
    assert!(parent_events.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::DelegationRejected { reason, .. } if reason == "parent_not_yet_valid"
    )));
}

#[test]
fn expired_parent_grant_denies_at_actual_decision_time() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let expired_at = OffsetDateTime::now_utc() - time::Duration::minutes(5);
    let expired_parent_grant = parent_grant_with_allowlists_and_window(
        &parent_principal,
        &request,
        &parent.tenant_id,
        &request.delegated_authority.allowed_actions,
        &request.delegated_authority.allowed_adapters,
        &request.delegated_authority.allowed_permissions,
        AuthorityBudgetScope {
            max_actions_per_tick: Some(4),
            max_action_duration_ms: Some(1_000),
            ..AuthorityBudgetScope::default()
        },
        expired_at - time::Duration::minutes(30),
        expired_at,
    );
    let mut authority = LocalDelegationAuthority::new(
        expired_parent_grant,
        child_principal,
        AUTHORITY_AUDIENCE,
        OffsetDateTime::now_utc(),
    );
    authority.max_fan_out = 3;
    bind_parent_authority(&manager, &parent_run_id, &authority);

    let error = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect_err("expired parent grant is denied");

    assert!(matches!(
        error,
        LocalDelegationError::AuthorityDenied { reason } if reason == "parent_expired"
    ));
    assert!(manager.run(&child_run_id).is_err());
    assert!(manager
        .router()
        .outbox(&parent.agent_id, &parent_run_id)
        .expect("parent outbox")
        .is_empty());
    assert!(child_events.lock().expect("child events").is_empty());
    let parent_events = parent_events.lock().expect("parent events");
    assert_eq!(
        count_events(&parent_events, |kind| matches!(
            kind,
            TraceEventKind::DelegationRequested { .. }
        )),
        0
    );
    assert!(parent_events.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::DelegationRejected { reason, .. } if reason == "parent_expired"
    )));
}

#[test]
fn future_child_grant_window_denies_before_routing_or_child_insert() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let mut authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    authority.not_before = OffsetDateTime::now_utc() + time::Duration::minutes(5);
    bind_parent_authority(&manager, &parent_run_id, &authority);

    let error = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect_err("future child grant must not start immediately");

    assert!(matches!(
        error,
        LocalDelegationError::AuthorityDenied { reason }
            if reason == "child_grant_not_yet_valid"
    ));
    assert!(manager.run(&child_run_id).is_err());
    assert!(manager
        .router()
        .outbox(&parent.agent_id, &parent_run_id)
        .expect("parent outbox")
        .is_empty());
    assert!(manager
        .router()
        .inbox(&child.agent_id, &parent_run_id)
        .expect("child inbox")
        .is_empty());
    assert!(child_events.lock().expect("child events").is_empty());
    let parent_events = parent_events.lock().expect("parent events");
    assert_eq!(
        count_events(&parent_events, |kind| matches!(
            kind,
            TraceEventKind::DelegationRequested { .. }
        )),
        0
    );
    assert!(parent_events.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::DelegationRejected { reason, delegation }
            if reason == "child_grant_not_yet_valid"
                && delegation.authority_evidence.as_ref().is_some_and(|evidence|
                    evidence.authority_reason.as_deref() == Some("child_grant_not_yet_valid"))
    )));
}

#[test]
fn missing_authority_evidence_is_not_replaced_by_task_payload_authority() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let mut forged_task_request = TaskRequest::new(
        parent_run_id.clone(),
        child_run_id.clone(),
        child.agent_id.clone(),
        "summarize receivables",
        request.delegated_authority.clone(),
    )
    .expect("task request can be forged as data");
    forged_task_request.authority_evidence = Some(LocalDelegationAuthorityEvidence::issued(
        CapabilityGrantId::new(),
        CapabilityGrantId::new(),
    ));
    forged_task_request
        .validate()
        .expect("message payload evidence remains behavior-free");

    let mut authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);
    authority.authority_evidence = None;
    let error = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect_err("runtime authority evidence is required");

    assert!(matches!(
        error,
        LocalDelegationError::AuthorityEvidenceDenied { reason }
            if reason == "missing_authority_evidence"
    ));
    assert!(
        manager.run(&child_run_id).is_err(),
        "child record not inserted"
    );
    assert!(manager
        .router()
        .outbox(&parent.agent_id, &parent_run_id)
        .expect("parent outbox")
        .is_empty());
    assert!(child_events.lock().expect("child events").is_empty());
    assert!(parent_events
        .lock()
        .expect("parent events")
        .iter()
        .any(|event| {
            matches!(
                &event.kind,
                TraceEventKind::DelegationRejected { reason, .. }
                    if reason == "missing_authority_evidence"
            )
        }));
}

#[test]
fn duplicate_child_run_id_is_rejected_before_task_message_or_state_mutation() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, _child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);
    manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect("first child run created");

    let parent_outbox_len = manager
        .router()
        .outbox(&parent.agent_id, &parent_run_id)
        .expect("parent outbox")
        .len();
    let child_inbox_len = manager
        .router()
        .inbox(&child.agent_id, &parent_run_id)
        .expect("child inbox")
        .len();
    let (duplicate_child_runtime, duplicate_child_events) = runtime_for(child_run_id.clone());
    let duplicate_request =
        delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let duplicate_authority = authority_input(
        &parent_principal,
        &child_principal,
        &parent,
        &duplicate_request,
    );
    let error = manager
        .create_child_run(
            &parent_runtime,
            &duplicate_child_runtime,
            duplicate_request,
            duplicate_authority,
        )
        .expect_err("duplicate child run ID rejected");

    assert!(matches!(error, LocalDelegationError::DuplicateChildRun(id) if id == child_run_id));
    assert_eq!(
        manager
            .run(&parent_run_id)
            .expect("parent record")
            .child_run_ids,
        vec![child_run_id]
    );
    assert_eq!(
        manager
            .router()
            .outbox(&parent.agent_id, &parent_run_id)
            .expect("parent outbox after duplicate")
            .len(),
        parent_outbox_len
    );
    assert_eq!(
        manager
            .router()
            .inbox(&child.agent_id, &parent_run_id)
            .expect("child inbox after duplicate")
            .len(),
        child_inbox_len
    );
    assert!(duplicate_child_events
        .lock()
        .expect("duplicate child events")
        .is_empty());

    let parent_events = parent_events.lock().expect("parent events");
    assert_eq!(
        count_events(&parent_events, |kind| matches!(
            kind,
            TraceEventKind::DelegationRequested { .. }
        )),
        1
    );
    assert!(parent_events.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::DelegationRejected { reason, .. } if reason == "duplicate_child_run_id"
    )));
}

#[test]
fn active_child_run_id_cannot_be_registered_as_root() {
    let CreatedDelegation {
        manager,
        parent,
        child_run_id,
        ..
    } = create_delegation_for_revocation();
    let before = manager.run(&child_run_id).expect("active child record");

    let error = manager
        .register_root_run(child_run_id.clone(), parent.agent_id)
        .expect_err("active child cannot be replaced by broader root authority");

    assert!(matches!(error, LocalDelegationError::DuplicateRun(id) if id == child_run_id));
    let after = manager.run(&child_run_id).expect("active child preserved");
    assert_run_record_unchanged(&before, &after);
    assert_eq!(after.status, LocalRunStatus::Running);
    assert!(after.parent_run_id.is_some());
    assert!(after.authority_evidence.is_some());
}

#[test]
fn cancelled_child_run_id_cannot_be_reregistered_or_resurrected() {
    let CreatedDelegation {
        manager,
        parent,
        child_run_id,
        parent_runtime,
        child_runtime,
        authority_evidence,
        ..
    } = create_delegation_for_revocation();
    let revocations = revocation_snapshot_for(authority_evidence.child_capability_grant_id);
    manager
        .cancel_child_if_authority_revoked(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            &revocations,
        )
        .expect("revocation cancellation succeeds")
        .expect("child cancelled");
    let before = manager.run(&child_run_id).expect("cancelled child record");

    let error = manager
        .register_root_run(child_run_id.clone(), parent.agent_id)
        .expect_err("cancelled child cannot be resurrected as root");

    assert!(matches!(error, LocalDelegationError::DuplicateRun(id) if id == child_run_id));
    let after = manager
        .run(&child_run_id)
        .expect("cancelled child preserved");
    assert_run_record_unchanged(&before, &after);
    assert_eq!(after.status, LocalRunStatus::Cancelled);
}

#[test]
fn duplicate_root_run_registration_is_rejected_without_mutation() {
    let (manager, _parent, child, _, _, parent_run_id, _) = setup_manager();
    let before = manager.run(&parent_run_id).expect("root record");

    let error = manager
        .register_root_run(parent_run_id.clone(), child.agent_id)
        .expect_err("existing root cannot be replaced");

    assert!(matches!(error, LocalDelegationError::DuplicateRun(id) if id == parent_run_id));
    let after = manager.run(&parent_run_id).expect("root preserved");
    assert_run_record_unchanged(&before, &after);
    assert_eq!(after.status, LocalRunStatus::Running);
    assert!(after.parent_run_id.is_none());
    assert!(after.authority_evidence.is_none());
}

#[test]
fn failed_child_run_returns_structured_task_response_and_replays_causality() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);
    manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect("child run created");

    let failure = TaskFailure::new("specialist_failed", "specialist policy failed", false);
    let response = manager
        .fail_child_run(&parent_runtime, &child_runtime, &child_run_id, failure)
        .expect("structured failure response");

    assert_eq!(response.response.status, TaskResponseStatus::Failed);
    let failure = response.response.failure.expect("failure");
    assert_eq!(failure.code, "specialist_failed");
    assert!(failure.trace_id.is_some());
    assert_eq!(
        response.response_message.message.schema,
        TASK_RESPONSE_SCHEMA
    );

    let child_record = manager.run(&child_run_id).expect("child record");
    assert_eq!(child_record.status, LocalRunStatus::Failed);
    assert!(child_record.response_message_id.is_some());

    let mut events = parent_events.lock().expect("parent events").clone();
    events.extend(child_events.lock().expect("child events").clone());
    let replay = replay_local_delegations(&events);
    assert_eq!(replay.delegations.len(), 1);
    assert_eq!(replay.delegations[0].parent_run_id, parent_run_id);
    assert_eq!(replay.delegations[0].child_run_id, child_run_id);
    assert_eq!(replay.messages.len(), 2, "request and response messages");
    assert_eq!(replay.failures.len(), 2, "child and parent failure traces");
}

#[test]
fn revoked_child_grant_cancels_active_child_and_replays_failure() {
    let CreatedDelegation {
        manager,
        parent,
        child,
        parent_run_id,
        child_run_id,
        parent_runtime,
        child_runtime,
        parent_events,
        child_events,
        authority_evidence,
    } = create_delegation_for_revocation();
    let revocations = revocation_snapshot_for(authority_evidence.child_capability_grant_id);

    let response = manager
        .cancel_child_if_authority_revoked(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            &revocations,
        )
        .expect("revocation check succeeds")
        .expect("child grant revocation cancels child run");

    assert_eq!(response.response.status, TaskResponseStatus::Cancelled);
    let failure = response.response.failure.expect("cancellation failure");
    assert_eq!(failure.code, REASON_AUTHORITY_GRANT_REVOKED);
    assert!(!failure.retryable);
    assert!(failure.trace_id.is_some());
    assert_eq!(
        manager.run(&child_run_id).expect("child record").status,
        LocalRunStatus::Cancelled
    );
    assert!(manager
        .router()
        .outbox(&child.agent_id, &parent_run_id)
        .expect("child response outbox")
        .iter()
        .any(|envelope| envelope.message.schema == TASK_RESPONSE_SCHEMA));
    assert!(manager
        .router()
        .inbox(&parent.agent_id, &parent_run_id)
        .expect("parent response inbox")
        .iter()
        .any(|envelope| envelope.message.schema == TASK_RESPONSE_SCHEMA));

    let mut events = parent_events.lock().expect("parent events").clone();
    events.extend(child_events.lock().expect("child events").clone());
    let replay = replay_local_delegations(&events);
    assert_eq!(replay.delegations.len(), 1);
    assert_eq!(replay.failures.len(), 2, "child and parent failure traces");
    assert!(replay
        .failures
        .iter()
        .all(|failure| failure.code == REASON_AUTHORITY_GRANT_REVOKED && !failure.retryable));
}

#[test]
fn revoked_parent_grant_cancels_active_child() {
    let CreatedDelegation {
        manager,
        child_run_id,
        parent_runtime,
        child_runtime,
        authority_evidence,
        ..
    } = create_delegation_for_revocation();
    let revocations = revocation_snapshot_for(authority_evidence.parent_capability_grant_id);

    let response = manager
        .cancel_child_if_authority_revoked(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            &revocations,
        )
        .expect("revocation check succeeds")
        .expect("parent grant revocation cancels child run");

    assert_eq!(response.response.status, TaskResponseStatus::Cancelled);
    let failure = response.response.failure.expect("cancellation failure");
    assert_eq!(failure.code, REASON_AUTHORITY_GRANT_REVOKED);
    assert!(!failure.retryable);
    assert_eq!(
        manager.run(&child_run_id).expect("child record").status,
        LocalRunStatus::Cancelled
    );
}

#[test]
fn stale_revocation_snapshot_cancels_active_child_fail_closed() {
    let CreatedDelegation {
        manager,
        child_run_id,
        parent_runtime,
        child_runtime,
        ..
    } = create_delegation_for_revocation();
    let revocations = stale_revocation_snapshot();

    let response = manager
        .cancel_child_if_authority_revoked(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            &revocations,
        )
        .expect("stale snapshot cancellation finishes")
        .expect("stale snapshot cancels active child");

    assert_eq!(response.response.status, TaskResponseStatus::Cancelled);
    let failure = response.response.failure.expect("stale snapshot failure");
    assert_eq!(failure.code, REASON_AUTHORITY_REVOCATION_SNAPSHOT_STALE);
    assert!(!failure.retryable);
    assert_eq!(
        manager.run(&child_run_id).expect("child record").status,
        LocalRunStatus::Cancelled
    );
}

#[test]
fn future_dated_revocation_snapshot_cancels_active_child_fail_closed() {
    let CreatedDelegation {
        manager,
        child_run_id,
        parent_runtime,
        child_runtime,
        ..
    } = create_delegation_for_revocation();
    let revocations = future_dated_revocation_snapshot();

    let response = manager
        .cancel_child_if_authority_revoked(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            &revocations,
        )
        .expect("future snapshot cancellation finishes")
        .expect("future snapshot cancels active child");

    assert_eq!(response.response.status, TaskResponseStatus::Cancelled);
    let failure = response.response.failure.expect("future snapshot failure");
    assert_eq!(
        failure.code,
        REASON_AUTHORITY_REVOCATION_SNAPSHOT_FUTURE_DATED
    );
    assert!(!failure.retryable);
    assert_eq!(
        manager.run(&child_run_id).expect("child record").status,
        LocalRunStatus::Cancelled
    );
}

#[test]
fn missing_authority_evidence_on_known_child_cancels_fail_closed() {
    let CreatedDelegation {
        manager,
        child_run_id,
        parent_runtime,
        child_runtime,
        ..
    } = create_delegation_for_revocation();
    {
        let mut state = manager.lock_state().expect("delegation state");
        let child = state
            .runs
            .get_mut(&child_run_id)
            .expect("known child record");
        assert!(child.parent_run_id.is_some());
        child.authority_evidence = None;
    }
    let now = OffsetDateTime::now_utc();
    let revocations =
        RevocationSnapshot::with_max_age(Vec::new(), now, time::Duration::minutes(30))
            .expect("live revocation snapshot");

    let response = manager
        .cancel_child_if_authority_revoked(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            &revocations,
        )
        .expect("missing evidence cancellation finishes")
        .expect("known child with missing evidence cancels");

    assert_eq!(response.response.status, TaskResponseStatus::Cancelled);
    let failure = response.response.failure.expect("missing evidence failure");
    assert_eq!(failure.code, "missing_authority_evidence");
    assert!(!failure.retryable);
    let child = manager.run(&child_run_id).expect("cancelled child record");
    assert_eq!(child.status, LocalRunStatus::Cancelled);
    assert!(child.parent_run_id.is_some());
    assert!(child.authority_evidence.is_none());
}

#[test]
fn revocation_trace_failure_still_marks_child_cancelled() {
    let CreatedDelegation {
        manager,
        child_run_id,
        parent_runtime,
        authority_evidence,
        ..
    } = create_delegation_for_revocation();
    let revocations = revocation_snapshot_for(authority_evidence.child_capability_grant_id);
    let failing_child_recorder = FailingRecorder {
        run_id: child_run_id.clone(),
    };

    let error = manager
        .cancel_child_if_authority_revoked(
            &parent_runtime,
            &failing_child_recorder,
            &child_run_id,
            &revocations,
        )
        .expect_err("child trace failure surfaces");

    assert!(matches!(
        error,
        LocalDelegationError::Router(MessageRouterError::StorageUnavailable)
    ));
    let child_record = manager.run(&child_run_id).expect("child record");
    assert_eq!(child_record.status, LocalRunStatus::Cancelled);
    assert!(child_record.response_message_id.is_none());
}

#[test]
fn concurrent_root_registration_and_revocation_cannot_leave_child_running() {
    let CreatedDelegation {
        manager,
        parent,
        parent_run_id,
        child_run_id,
        authority_evidence,
        ..
    } = create_delegation_for_revocation();
    let manager = Arc::new(manager);
    let revocations = revocation_snapshot_for(authority_evidence.child_capability_grant_id);
    let parent_recorder = Arc::new(SimpleRecorder {
        run_id: parent_run_id,
    });
    let (entered_tx, entered_rx) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let child_recorder = Arc::new(BlockingRevocationRecorder {
        run_id: child_run_id.clone(),
        entered: Mutex::new(Some(entered_tx)),
        release: Arc::clone(&release),
    });

    let cancel_manager = Arc::clone(&manager);
    let cancel_child_id = child_run_id.clone();
    let cancel_parent_recorder = Arc::clone(&parent_recorder);
    let cancel_child_recorder = Arc::clone(&child_recorder);
    let cancel_handle = std::thread::spawn(move || {
        cancel_manager.cancel_child_if_authority_revoked(
            cancel_parent_recorder.as_ref(),
            cancel_child_recorder.as_ref(),
            &cancel_child_id,
            &revocations,
        )
    });

    entered_rx
        .recv_timeout(StdDuration::from_secs(1))
        .expect("revocation marked child cancelled and reached trace recording");

    let register_manager = Arc::clone(&manager);
    let register_child_id = child_run_id.clone();
    let register_agent_id = parent.agent_id;
    let (register_tx, register_rx) = mpsc::channel();
    let register_handle = std::thread::spawn(move || {
        let result =
            register_manager.register_root_run(register_child_id.clone(), register_agent_id);
        let duplicate_rejected = matches!(
            result,
            Err(LocalDelegationError::DuplicateRun(id)) if id == register_child_id
        );
        register_tx
            .send(duplicate_rejected)
            .expect("register result sent");
    });

    assert!(
        register_rx
            .recv_timeout(StdDuration::from_millis(50))
            .is_err(),
        "root registration must wait for revocation lifecycle"
    );

    let (lock, cvar) = &*release;
    *lock.lock().expect("release lock") = true;
    cvar.notify_all();

    cancel_handle
        .join()
        .expect("cancel thread")
        .expect("revocation cancellation succeeds")
        .expect("child cancelled");
    assert!(
        register_rx
            .recv_timeout(StdDuration::from_secs(1))
            .expect("register result received"),
        "root registration rejects existing child ID"
    );
    register_handle.join().expect("register thread");

    let child = manager.run(&child_run_id).expect("child record preserved");
    assert_eq!(child.status, LocalRunStatus::Cancelled);
    assert!(child.parent_run_id.is_some());
    assert!(child.authority_evidence.is_some());
}

#[test]
fn revocation_response_routing_failure_still_marks_child_cancelled() {
    let CreatedDelegation {
        manager,
        parent,
        child,
        parent_run_id,
        child_run_id,
        parent_runtime,
        child_runtime,
        authority_evidence,
        ..
    } = create_delegation_for_revocation();
    fill_child_response_outbox(&manager, &parent, &child, &parent_run_id, &child_run_id);
    let revocations = revocation_snapshot_for(authority_evidence.child_capability_grant_id);

    let error = manager
        .cancel_child_if_authority_revoked(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            &revocations,
        )
        .expect_err("response routing failure surfaces");

    assert!(matches!(
        error,
        LocalDelegationError::Router(MessageRouterError::OutboxFull { .. })
    ));
    let child_record = manager.run(&child_run_id).expect("child record");
    assert_eq!(child_record.status, LocalRunStatus::Cancelled);
    assert!(child_record.response_message_id.is_none());
}

#[test]
fn unrelated_revocation_is_noop_and_child_remains_running() {
    let CreatedDelegation {
        manager,
        child,
        parent_run_id,
        child_run_id,
        parent_runtime,
        child_runtime,
        parent_events,
        child_events,
        ..
    } = create_delegation_for_revocation();
    let revocations = revocation_snapshot_for(CapabilityGrantId::new());
    let parent_failure_count =
        count_events(&parent_events.lock().expect("parent events"), |kind| {
            matches!(kind, TraceEventKind::ChildRunFailed { .. })
        });
    let child_failure_count = count_events(&child_events.lock().expect("child events"), |kind| {
        matches!(kind, TraceEventKind::ChildRunFailed { .. })
    });
    let response_outbox_len = manager
        .router()
        .outbox(&child.agent_id, &parent_run_id)
        .expect("child response outbox")
        .len();

    let response = manager
        .cancel_child_if_authority_revoked(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            &revocations,
        )
        .expect("revocation check succeeds");

    assert!(response.is_none());
    assert_eq!(
        manager.run(&child_run_id).expect("child record").status,
        LocalRunStatus::Running
    );
    assert_eq!(
        manager
            .router()
            .outbox(&child.agent_id, &parent_run_id)
            .expect("child response outbox")
            .len(),
        response_outbox_len
    );
    assert_eq!(
        count_events(&parent_events.lock().expect("parent events"), |kind| {
            matches!(kind, TraceEventKind::ChildRunFailed { .. })
        }),
        parent_failure_count
    );
    assert_eq!(
        count_events(&child_events.lock().expect("child events"), |kind| {
            matches!(kind, TraceEventKind::ChildRunFailed { .. })
        }),
        child_failure_count
    );
}

#[test]
fn terminal_children_are_not_cancelled_again_by_revocation_snapshot() {
    fn assert_terminal_noop(
        terminalize: impl FnOnce(&LocalDelegationManager, &KernelRuntime, &KernelRuntime, &RunId),
        expected_status: LocalRunStatus,
    ) {
        let CreatedDelegation {
            manager,
            child,
            parent_run_id,
            child_run_id,
            parent_runtime,
            child_runtime,
            parent_events,
            child_events,
            authority_evidence,
            ..
        } = create_delegation_for_revocation();
        terminalize(&manager, &parent_runtime, &child_runtime, &child_run_id);
        let parent_failure_count =
            count_events(&parent_events.lock().expect("parent events"), |kind| {
                matches!(kind, TraceEventKind::ChildRunFailed { .. })
            });
        let child_failure_count =
            count_events(&child_events.lock().expect("child events"), |kind| {
                matches!(kind, TraceEventKind::ChildRunFailed { .. })
            });
        let response_outbox_len = manager
            .router()
            .outbox(&child.agent_id, &parent_run_id)
            .expect("child response outbox")
            .len();
        let revocations = revocation_snapshot_for(authority_evidence.child_capability_grant_id);

        let response = manager
            .cancel_child_if_authority_revoked(
                &parent_runtime,
                &child_runtime,
                &child_run_id,
                &revocations,
            )
            .expect("terminal child revocation check is a no-op");

        assert!(response.is_none());
        assert_eq!(
            manager.run(&child_run_id).expect("child record").status,
            expected_status
        );
        assert_eq!(
            manager
                .router()
                .outbox(&child.agent_id, &parent_run_id)
                .expect("child response outbox")
                .len(),
            response_outbox_len
        );
        assert_eq!(
            count_events(&parent_events.lock().expect("parent events"), |kind| {
                matches!(kind, TraceEventKind::ChildRunFailed { .. })
            }),
            parent_failure_count
        );
        assert_eq!(
            count_events(&child_events.lock().expect("child events"), |kind| {
                matches!(kind, TraceEventKind::ChildRunFailed { .. })
            }),
            child_failure_count
        );
    }

    assert_terminal_noop(
        |manager, parent_runtime, child_runtime, child_run_id| {
            manager
                .complete_child_run(
                    parent_runtime,
                    child_runtime,
                    child_run_id,
                    serde_json::json!({"summary_ref": "artifact:summary"}),
                )
                .expect("child completed");
        },
        LocalRunStatus::Completed,
    );
    assert_terminal_noop(
        |manager, parent_runtime, child_runtime, child_run_id| {
            manager
                .fail_child_run(
                    parent_runtime,
                    child_runtime,
                    child_run_id,
                    TaskFailure::new("specialist_failed", "specialist failed", false),
                )
                .expect("child failed");
        },
        LocalRunStatus::Failed,
    );
    assert_terminal_noop(
        |manager, parent_runtime, child_runtime, child_run_id| {
            let evidence = manager
                .run(child_run_id)
                .expect("child record")
                .authority_evidence
                .expect("authority evidence");
            let revocations = revocation_snapshot_for(evidence.child_capability_grant_id);
            manager
                .cancel_child_if_authority_revoked(
                    parent_runtime,
                    child_runtime,
                    child_run_id,
                    &revocations,
                )
                .expect("child cancelled")
                .expect("first revocation cancels child");
        },
        LocalRunStatus::Cancelled,
    );
}

#[test]
fn cancelled_parent_prevents_new_child_delegation_and_records_trace() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, _child_events) = runtime_for(child_run_id.clone());
    manager
        .cancel_parent_run(&parent_runtime, &parent_run_id, "operator_cancelled")
        .expect("cancel parent");

    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id);
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);
    let error = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect_err("cancelled parent rejects delegation");
    assert!(matches!(error, LocalDelegationError::ParentCancelled(id) if id == parent_run_id));

    let parent_events = parent_events.lock().expect("parent events");
    assert!(parent_events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ParentRunCancelled { .. })));
    assert!(parent_events.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::DelegationRejected { reason, .. } if reason == "parent_run_cancelled"
    )));
}

#[test]
fn concurrent_root_grant_bindings_serialize_to_one_exact_winner() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let manager = Arc::new(manager);
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id);
    let grant_a = authority_input(&parent_principal, &child_principal, &parent, &request)
        .parent_capability_grant;
    let grant_b = parent_grant_for_request(&parent_principal, &request, &parent.tenant_id);
    let barrier = Arc::new(Barrier::new(3));

    let manager_a = Arc::clone(&manager);
    let run_a = parent_run_id.clone();
    let barrier_a = Arc::clone(&barrier);
    let grant_a_id = grant_a.grant().grant_id.clone();
    let handle_a = std::thread::spawn(move || {
        barrier_a.wait();
        manager_a.bind_root_run_capability_grant(&run_a, &grant_a)
    });
    let manager_b = Arc::clone(&manager);
    let run_b = parent_run_id.clone();
    let barrier_b = Arc::clone(&barrier);
    let grant_b_id = grant_b.grant().grant_id.clone();
    let handle_b = std::thread::spawn(move || {
        barrier_b.wait();
        manager_b.bind_root_run_capability_grant(&run_b, &grant_b)
    });
    barrier.wait();

    let result_a = handle_a.join().expect("binding thread A");
    let result_b = handle_b.join().expect("binding thread B");
    assert_ne!(result_a.is_ok(), result_b.is_ok());
    let error = if let Err(error) = result_a {
        error
    } else {
        result_b.expect_err("one concurrent binding must lose")
    };
    assert!(matches!(
        error,
        LocalDelegationError::ParentRunGrantBindingConflict { .. }
    ));
    let bound_id = manager
        .run(&parent_run_id)
        .expect("root remains bound")
        .capability_grant_id
        .expect("winning binding ID");
    assert!(bound_id == grant_a_id || bound_id == grant_b_id);
}

#[test]
fn root_grant_rebind_waits_for_inflight_child_creation_lifecycle() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let manager = Arc::new(manager);
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);
    let replacement_grant =
        parent_grant_for_request(&parent_principal, &request, &parent.tenant_id);
    let (entered_tx, entered_rx) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let parent_recorder = Arc::new(BlockingDelegationRecorder {
        run_id: parent_run_id.clone(),
        entered: Mutex::new(Some(entered_tx)),
        release: Arc::clone(&release),
    });
    let child_recorder = Arc::new(SimpleRecorder {
        run_id: child_run_id,
    });

    let create_manager = Arc::clone(&manager);
    let create_parent_recorder = Arc::clone(&parent_recorder);
    let create_child_recorder = Arc::clone(&child_recorder);
    let create_handle = std::thread::spawn(move || {
        create_manager.create_child_run(
            create_parent_recorder.as_ref(),
            create_child_recorder.as_ref(),
            request,
            authority,
        )
    });
    entered_rx
        .recv_timeout(StdDuration::from_secs(1))
        .expect("child creation holds lifecycle lock at request trace");

    let bind_manager = Arc::clone(&manager);
    let bind_run_id = parent_run_id.clone();
    let (bind_tx, bind_rx) = mpsc::channel();
    let bind_handle = std::thread::spawn(move || {
        let result = bind_manager.bind_root_run_capability_grant(&bind_run_id, &replacement_grant);
        bind_tx.send(result).expect("bind result sent");
    });
    assert!(
        bind_rx.recv_timeout(StdDuration::from_millis(50)).is_err(),
        "rebind must wait for in-flight child creation"
    );

    let (lock, cvar) = &*release;
    *lock.lock().expect("release lock") = true;
    cvar.notify_all();
    create_handle
        .join()
        .expect("create thread")
        .expect("child creation succeeds");
    let bind_error = bind_rx
        .recv_timeout(StdDuration::from_secs(1))
        .expect("bind result received")
        .expect_err("replacement binding fails after create completes");
    assert!(matches!(
        bind_error,
        LocalDelegationError::ParentRunGrantBindingConflict { .. }
    ));
    bind_handle.join().expect("bind thread");
}

#[test]
fn delegation_creation_and_parent_cancellation_are_serialized() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let manager = Arc::new(manager);
    let (entered_tx, entered_rx) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let parent_recorder = Arc::new(BlockingDelegationRecorder {
        run_id: parent_run_id.clone(),
        entered: Mutex::new(Some(entered_tx)),
        release: Arc::clone(&release),
    });
    let child_recorder = Arc::new(SimpleRecorder {
        run_id: child_run_id.clone(),
    });
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);

    let create_manager = Arc::clone(&manager);
    let create_parent_recorder = Arc::clone(&parent_recorder);
    let create_child_recorder = Arc::clone(&child_recorder);
    let create_handle = std::thread::spawn(move || {
        create_manager.create_child_run(
            create_parent_recorder.as_ref(),
            create_child_recorder.as_ref(),
            request,
            authority,
        )
    });

    entered_rx
        .recv_timeout(StdDuration::from_secs(1))
        .expect("child creation reached delegation trace while holding lifecycle lock");

    let cancel_manager = Arc::clone(&manager);
    let cancel_parent_run_id = parent_run_id.clone();
    let (cancel_tx, cancel_rx) = mpsc::channel();
    let cancel_handle = std::thread::spawn(move || {
        let recorder = SimpleRecorder {
            run_id: cancel_parent_run_id.clone(),
        };
        let result = cancel_manager.cancel_parent_run(
            &recorder,
            &cancel_parent_run_id,
            "operator_cancelled",
        );
        cancel_tx.send(result).expect("cancel result sent");
    });

    assert!(
        cancel_rx
            .recv_timeout(StdDuration::from_millis(50))
            .is_err(),
        "cancellation must wait for in-flight child creation lifecycle"
    );

    let (lock, cvar) = &*release;
    *lock.lock().expect("release lock") = true;
    cvar.notify_all();

    let created = create_handle
        .join()
        .expect("create thread")
        .expect("child creation completes first");
    cancel_rx
        .recv_timeout(StdDuration::from_secs(1))
        .expect("cancel result received")
        .expect("cancel succeeds after create completes");
    cancel_handle.join().expect("cancel thread");

    let parent_record = manager.run(&parent_run_id).expect("parent record");
    assert_eq!(parent_record.status, LocalRunStatus::Cancelled);
    assert_eq!(
        parent_record.child_run_ids,
        vec![created.run.run_id.clone()]
    );
    assert_eq!(
        manager
            .run(&created.run.run_id)
            .expect("child record")
            .status,
        LocalRunStatus::Running
    );
}

#[test]
fn completed_child_run_returns_response_and_parent_completion_trace() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);
    manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect("child run created");

    let response = manager
        .complete_child_run(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            serde_json::json!({"summary_ref": "artifact:summary"}),
        )
        .expect("child completed");

    assert_eq!(response.response.status, TaskResponseStatus::Completed);
    assert_eq!(
        response.response.output,
        Some(serde_json::json!({"summary_ref": "artifact:summary"}))
    );
    assert!(response.response.failure.is_none());
    assert_eq!(
        manager.run(&child_run_id).expect("child").status,
        LocalRunStatus::Completed
    );
    assert!(manager
        .router()
        .outbox(&child.agent_id, &parent_run_id)
        .expect("child response outbox")
        .iter()
        .any(|envelope| envelope.message.schema == TASK_RESPONSE_SCHEMA));

    assert!(parent_events
        .lock()
        .expect("parent events")
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ChildRunCompleted { .. })));
    assert!(child_events
        .lock()
        .expect("child events")
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ChildRunCompleted { .. })));
}

#[test]
fn repeated_child_completion_is_rejected_without_duplicate_response() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);
    manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect("child run created");

    manager
        .complete_child_run(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            serde_json::json!({"summary_ref": "artifact:summary"}),
        )
        .expect("first child completion succeeds");
    let parent_events_len = parent_events.lock().expect("parent events").len();
    let child_events_len = child_events.lock().expect("child events").len();
    let response_outbox_len = manager
        .router()
        .outbox(&child.agent_id, &parent_run_id)
        .expect("child response outbox")
        .len();

    let error = manager
        .complete_child_run(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            serde_json::json!({"summary_ref": "artifact:duplicate"}),
        )
        .expect_err("second completion rejected");
    assert!(matches!(
        error,
        LocalDelegationError::ChildRunAlreadyFinished {
            status: LocalRunStatus::Completed,
            ..
        }
    ));
    assert_eq!(
        parent_events.lock().expect("parent events").len(),
        parent_events_len
    );
    assert_eq!(
        child_events.lock().expect("child events").len(),
        child_events_len
    );
    assert_eq!(
        manager
            .router()
            .outbox(&child.agent_id, &parent_run_id)
            .expect("child response outbox after duplicate")
            .len(),
        response_outbox_len
    );
}

#[test]
fn repeated_child_failure_is_rejected_without_duplicate_failure_trace() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);
    manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect("child run created");

    manager
        .fail_child_run(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            TaskFailure::new("specialist_failed", "specialist failed", false),
        )
        .expect("first child failure succeeds");
    let parent_failure_count =
        count_events(&parent_events.lock().expect("parent events"), |kind| {
            matches!(kind, TraceEventKind::ChildRunFailed { .. })
        });
    let child_failure_count = count_events(&child_events.lock().expect("child events"), |kind| {
        matches!(kind, TraceEventKind::ChildRunFailed { .. })
    });
    let response_outbox_len = manager
        .router()
        .outbox(&child.agent_id, &parent_run_id)
        .expect("child response outbox")
        .len();

    let error = manager
        .fail_child_run(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            TaskFailure::new("second_failure", "second failure", false),
        )
        .expect_err("second failure rejected");
    assert!(matches!(
        error,
        LocalDelegationError::ChildRunAlreadyFinished {
            status: LocalRunStatus::Failed,
            ..
        }
    ));
    assert_eq!(
        count_events(
            &parent_events.lock().expect("parent events"),
            |kind| matches!(kind, TraceEventKind::ChildRunFailed { .. })
        ),
        parent_failure_count
    );
    assert_eq!(
        count_events(
            &child_events.lock().expect("child events"),
            |kind| matches!(kind, TraceEventKind::ChildRunFailed { .. })
        ),
        child_failure_count
    );
    assert_eq!(
        manager
            .router()
            .outbox(&child.agent_id, &parent_run_id)
            .expect("child response outbox after duplicate")
            .len(),
        response_outbox_len
    );
}

#[test]
fn child_failure_after_completion_is_rejected_without_failure_trace() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);
    manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect("child run created");
    manager
        .complete_child_run(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            serde_json::json!({"summary_ref": "artifact:summary"}),
        )
        .expect("child completion succeeds");

    let response_outbox_len = manager
        .router()
        .outbox(&child.agent_id, &parent_run_id)
        .expect("child response outbox")
        .len();
    let error = manager
        .fail_child_run(
            &parent_runtime,
            &child_runtime,
            &child_run_id,
            TaskFailure::new("late_failure", "late failure", false),
        )
        .expect_err("failure after completion rejected");

    assert!(matches!(
        error,
        LocalDelegationError::ChildRunAlreadyFinished {
            status: LocalRunStatus::Completed,
            ..
        }
    ));
    assert_eq!(
        count_events(
            &parent_events.lock().expect("parent events"),
            |kind| matches!(kind, TraceEventKind::ChildRunFailed { .. })
        ),
        0
    );
    assert_eq!(
        count_events(
            &child_events.lock().expect("child events"),
            |kind| matches!(kind, TraceEventKind::ChildRunFailed { .. })
        ),
        0
    );
    assert_eq!(
        manager
            .router()
            .outbox(&child.agent_id, &parent_run_id)
            .expect("child response outbox after late failure")
            .len(),
        response_outbox_len
    );
}

#[test]
fn delegation_denies_parent_scope_source_tenant_and_unknown_run_failures() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, _parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, _child_events) = runtime_for(child_run_id.clone());

    let mut parent_scope =
        delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    parent_scope
        .delegated_authority
        .allowed_actions
        .push("admin.delete".to_string());
    let parent_scope_authority =
        authority_input(&parent_principal, &child_principal, &parent, &parent_scope);
    bind_parent_authority(&manager, &parent_run_id, &parent_scope_authority);
    let error = manager
        .create_child_run(
            &parent_runtime,
            &child_runtime,
            parent_scope,
            parent_scope_authority,
        )
        .expect_err("parent authority exceeded");
    assert!(matches!(
        error,
        LocalDelegationError::DelegatedAuthorityDenied { scope: "parent" }
    ));

    let mut source_mismatch =
        delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    source_mismatch.source_agent_id = AgentId::new();
    let source_mismatch_authority = authority_input(
        &parent_principal,
        &child_principal,
        &parent,
        &source_mismatch,
    );
    let error = manager
        .create_child_run(
            &parent_runtime,
            &child_runtime,
            source_mismatch,
            source_mismatch_authority,
        )
        .expect_err("source mismatch denied");
    assert!(matches!(error, LocalDelegationError::SourceAgentMismatch));

    let other_tenant_agent = AgentContext::new(
        AgentId::new(),
        TenantId::new(),
        AgentRuntimeConfig::default(),
    );
    manager
        .register_agent(
            other_tenant_agent.clone(),
            authority(&["query"], &["sql"], &["finance.read"]),
        )
        .expect("other tenant agent");
    let mut tenant_mismatch =
        delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    tenant_mismatch.target_agent_id = other_tenant_agent.agent_id;
    let tenant_mismatch_authority = authority_input(
        &parent_principal,
        &child_principal,
        &parent,
        &tenant_mismatch,
    );
    let error = manager
        .create_child_run(
            &parent_runtime,
            &child_runtime,
            tenant_mismatch,
            tenant_mismatch_authority,
        )
        .expect_err("tenant mismatch denied");
    assert!(matches!(error, LocalDelegationError::TenantMismatch));

    let unknown_parent_request = delegation_request(&parent, &child, RunId::new(), child_run_id);
    let authority = authority_input(
        &parent_principal,
        &child_principal,
        &parent,
        &unknown_parent_request,
    );
    let unknown_parent = manager
        .create_child_run(
            &parent_runtime,
            &child_runtime,
            unknown_parent_request,
            authority,
        )
        .expect_err("recorder run mismatch rejected first");
    assert!(matches!(
        unknown_parent,
        LocalDelegationError::TraceRunMismatch { .. }
    ));

    let missing_child_run = RunId::new();
    let (missing_child_runtime, _) = runtime_for(missing_child_run.clone());
    let unknown_child = manager
        .fail_child_run(
            &parent_runtime,
            &missing_child_runtime,
            &missing_child_run,
            TaskFailure::new("missing", "missing child", false),
        )
        .expect_err("unknown child");
    assert!(matches!(
        unknown_child,
        LocalDelegationError::UnknownChildRun(_)
    ));
}

#[test]
fn registration_and_lookup_fail_closed_for_unknown_agents_and_runs() {
    let manager = LocalDelegationManager::new();
    let unknown_agent = AgentId::new();
    let error = manager
        .register_root_run(RunId::new(), unknown_agent.clone())
        .expect_err("unknown agent");
    assert!(matches!(error, LocalDelegationError::UnknownAgent(id) if id == unknown_agent));

    let unknown_run = RunId::new();
    let error = manager.run(&unknown_run).expect_err("unknown run");
    assert!(matches!(error, LocalDelegationError::UnknownChildRun(id) if id == unknown_run));
}

#[test]
fn replay_collects_rejected_delegation_and_consumed_task_message() {
    let (manager, parent, child, parent_principal, child_principal, parent_run_id, child_run_id) =
        setup_manager();
    let (parent_runtime, parent_events) = runtime_for(parent_run_id.clone());
    let (child_runtime, _child_events) = runtime_for(child_run_id.clone());
    let request = delegation_request(&parent, &child, parent_run_id.clone(), child_run_id.clone());
    let authority = authority_input(&parent_principal, &child_principal, &parent, &request);
    bind_parent_authority(&manager, &parent_run_id, &authority);
    let created = manager
        .create_child_run(&parent_runtime, &child_runtime, request, authority)
        .expect("child run created");
    manager
        .router()
        .consume(
            &parent_runtime,
            &child.agent_id,
            &parent_run_id,
            &created.request_message.message.message_id,
        )
        .expect("consume task request");

    manager
        .cancel_parent_run(&parent_runtime, &parent_run_id, "cancel")
        .expect("cancel");
    let mut rejected = delegation_request(&parent, &child, parent_run_id, RunId::new());
    rejected.parent_causal_trace_id = None;
    let rejected_authority =
        authority_input(&parent_principal, &child_principal, &parent, &rejected);
    let (rejected_child_runtime, _) = runtime_for(rejected.child_run_id.clone());
    let _ = manager
        .create_child_run(
            &parent_runtime,
            &rejected_child_runtime,
            rejected,
            rejected_authority,
        )
        .expect_err("cancelled");

    let events = parent_events.lock().expect("events").clone();
    let replay = replay_local_delegations(&events);
    assert_eq!(replay.delegations.len(), 2);
    assert!(replay
        .messages
        .iter()
        .any(|message| message.schema == TASK_REQUEST_SCHEMA));
}
