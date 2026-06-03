use super::*;
use splendor_gateway::{ActionGateway, ActionId, ActionOutcome, ActionRequest, GatewayError};
use splendor_types::{
    Action, AgentId, OfflineHighRiskBehavior, PolicyBundle, PolicyBundleEnvelope, PolicyBundleId,
    PolicyDegradedMode, QuotaUsage, RevocationStatus, RunId, SideEffectClass, TenantId,
};
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

struct CountingGateway {
    calls: Arc<Mutex<u32>>,
}

impl ActionGateway for CountingGateway {
    fn submit(&self, request: ActionRequest) -> Result<ActionOutcome, GatewayError> {
        *self.calls.lock().expect("calls lock") += 1;
        Ok(ActionOutcome {
            action_id: request.action_id,
            status: ActionStatus::Executed,
            verification: VerificationResult::allow(),
            post_verification: Some(VerificationResult::allow()),
            output: Some(serde_json::json!({"ok": true})),
            error: None,
            completed_at: OffsetDateTime::now_utc(),
        })
    }
}

fn bundle(expires_at: OffsetDateTime, allow_low_risk_cached: bool) -> PolicyBundle {
    PolicyBundle {
        schema_version: splendor_types::POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
        policy_bundle_id: PolicyBundleId::try_new("pol_cache").expect("policy id"),
        version: "v1".to_string(),
        tenant_id: TenantId::new(),
        agent_id: None,
        issued_at: expires_at - Duration::hours(1),
        expires_at,
        revocation: RevocationStatus::Active,
        degraded_mode: PolicyDegradedMode {
            allow_low_risk_cached,
            disconnected_low_risk_actions: vec!["read_battery".to_string()],
            disconnected_high_risk_actions: vec!["move_to_waypoint".to_string()],
            high_risk_disconnected_behavior: OfflineHighRiskBehavior::Deny,
        },
    }
}

fn named_request(name: &str, side_effect_class: SideEffectClass) -> ActionRequest {
    ActionRequest {
        action_id: ActionId::new(),
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id: RunId::new(),
        action: Action {
            name: name.to_string(),
            params: serde_json::json!({}),
            side_effect_class,
            cost_estimate: None,
            required_permissions: vec![],
            preconditions: vec![],
            postconditions: vec![],
        },
        adapter: None,
        quota_usage: QuotaUsage::single_action(),
        satisfied_preconditions: vec![],
        requested_at: OffsetDateTime::now_utc(),
        approval_evidence: None,
    }
}

fn request(side_effect_class: SideEffectClass) -> ActionRequest {
    named_request("file.write", side_effect_class)
}

#[test]
fn non_enforced_empty_cache_allows_policy_and_gateway_forwarding() {
    let cache = PolicyCache::new(PolicyCacheConfig {
        enforcement_required: false,
    });

    let decision = cache.verify_policy_invocation("legacy", OffsetDateTime::now_utc());
    assert!(decision.verification.allowed);
    assert_eq!(decision.trace_event, None);

    let calls = Arc::new(Mutex::new(0));
    let gateway = PolicyDistributionGateway::new(
        Arc::new(CountingGateway {
            calls: calls.clone(),
        }),
        Arc::new(cache),
    );

    let outcome = gateway
        .submit(request(SideEffectClass::External))
        .expect("gateway outcome");

    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(*calls.lock().expect("calls lock"), 1);
}

#[test]
fn missing_required_policy_fails_closed_before_policy_invocation() {
    let cache = PolicyCache::new(PolicyCacheConfig {
        enforcement_required: true,
    });

    let decision = cache.verify_policy_invocation("static", OffsetDateTime::now_utc());

    assert!(!decision.verification.allowed);
    assert_eq!(decision.verification.reasons, vec!["policy_unavailable"]);
    assert_eq!(decision.trace_event, None);
}

#[test]
fn missing_required_policy_fails_closed_before_inner_gateway() {
    let cache = PolicyCache::new(PolicyCacheConfig {
        enforcement_required: true,
    });
    let calls = Arc::new(Mutex::new(0));
    let gateway = PolicyDistributionGateway::new(
        Arc::new(CountingGateway {
            calls: calls.clone(),
        }),
        Arc::new(cache),
    );

    let outcome = gateway
        .submit(request(SideEffectClass::External))
        .expect("gateway outcome");

    assert_eq!(outcome.status, ActionStatus::Denied);
    assert_eq!(outcome.verification.reasons, vec!["policy_unavailable"]);
    assert_eq!(*calls.lock().expect("calls lock"), 0);
}

#[test]
fn expired_policy_denies_even_disconnected_explicit_low_risk_actions() {
    let now = OffsetDateTime::now_utc();
    let cache = PolicyCache::with_bundle(bundle(now - Duration::minutes(1), true), now);
    cache.set_disconnected(true);

    let denied = cache.verify_policy_action(&request(SideEffectClass::Network), now);
    assert!(!denied.allowed);
    assert_eq!(denied.reasons, vec!["policy_expired"]);

    let low_risk_denied = cache.verify_policy_action(
        &named_request("read_battery", SideEffectClass::ReadOnly),
        now,
    );
    assert!(!low_risk_denied.allowed);
    assert_eq!(low_risk_denied.reasons, vec!["policy_expired"]);
}

#[test]
fn disconnected_within_ttl_allows_only_explicit_low_risk_actions() {
    let now = OffsetDateTime::now_utc();
    let cache = PolicyCache::with_bundle(bundle(now + Duration::hours(1), true), now);
    cache.set_disconnected(true);

    let allowed = cache.verify_policy_action(
        &named_request("read_battery", SideEffectClass::ReadOnly),
        now,
    );
    assert!(allowed.allowed);

    let denied =
        cache.verify_policy_action(&named_request("file.read", SideEffectClass::ReadOnly), now);
    assert!(!denied.allowed);
    assert_eq!(denied.reasons, vec!["offline_action_not_allowed"]);
}

#[test]
fn disconnected_high_risk_action_fails_closed_before_inner_gateway() {
    let now = OffsetDateTime::now_utc();
    let cache = PolicyCache::with_bundle(bundle(now + Duration::hours(1), true), now);
    cache.set_disconnected(true);
    let calls = Arc::new(Mutex::new(0));
    let gateway = PolicyDistributionGateway::new(
        Arc::new(CountingGateway {
            calls: calls.clone(),
        }),
        Arc::new(cache),
    );

    let outcome = gateway
        .submit(named_request("move_to_waypoint", SideEffectClass::External))
        .expect("gateway outcome");

    assert_eq!(outcome.status, ActionStatus::Denied);
    assert_eq!(
        outcome.verification.reasons,
        vec!["offline_high_risk_denied"]
    );
    assert_eq!(*calls.lock().expect("calls lock"), 0);
}

#[test]
fn disconnected_high_risk_can_require_local_intervention() {
    let now = OffsetDateTime::now_utc();
    let mut high_risk_intervention = bundle(now + Duration::hours(1), true);
    high_risk_intervention
        .degraded_mode
        .high_risk_disconnected_behavior = OfflineHighRiskBehavior::NeedsLocalIntervention;
    let cache = PolicyCache::with_bundle(high_risk_intervention, now);
    cache.set_disconnected(true);
    let calls = Arc::new(Mutex::new(0));
    let gateway = PolicyDistributionGateway::new(
        Arc::new(CountingGateway {
            calls: calls.clone(),
        }),
        Arc::new(cache),
    );

    let outcome = gateway
        .submit(named_request("move_to_waypoint", SideEffectClass::External))
        .expect("gateway outcome");

    assert_eq!(outcome.status, ActionStatus::NeedsIntervention);
    assert_eq!(
        outcome.verification.reasons,
        vec!["offline_high_risk_needs_local_intervention"]
    );
    assert_eq!(*calls.lock().expect("calls lock"), 0);
}

#[test]
fn expired_disconnected_low_risk_action_does_not_reach_inner_gateway() {
    let now = OffsetDateTime::now_utc();
    let cache = PolicyCache::with_bundle(bundle(now - Duration::minutes(1), true), now);
    cache.set_disconnected(true);
    let calls = Arc::new(Mutex::new(0));
    let gateway = PolicyDistributionGateway::new(
        Arc::new(CountingGateway {
            calls: calls.clone(),
        }),
        Arc::new(cache),
    );

    let outcome = gateway
        .submit(named_request("read_battery", SideEffectClass::ReadOnly))
        .expect("gateway outcome");

    assert_eq!(outcome.status, ActionStatus::Denied);
    assert_eq!(outcome.verification.reasons, vec!["policy_expired"]);
    assert_eq!(*calls.lock().expect("calls lock"), 0);
}

#[test]
fn expired_policy_blocks_policy_invocation_when_not_in_degraded_offline_mode() {
    let now = OffsetDateTime::now_utc();
    let cache = PolicyCache::with_bundle(bundle(now - Duration::minutes(1), false), now);

    let decision = cache.verify_policy_invocation("static", now);

    assert!(!decision.verification.allowed);
    assert_eq!(decision.verification.reasons, vec!["policy_expired"]);
    assert!(matches!(
        decision.trace_event,
        Some(TraceEventKind::PolicyExpired { .. })
    ));
}

#[test]
fn expired_policy_blocks_policy_invocation_even_in_disconnected_degraded_mode() {
    let now = OffsetDateTime::now_utc();
    let cache = PolicyCache::with_bundle(bundle(now - Duration::minutes(1), true), now);
    cache.set_disconnected(true);

    let decision = cache.verify_policy_invocation("static", now);

    assert!(!decision.verification.allowed);
    assert_eq!(decision.verification.reasons, vec!["policy_expired"]);
    assert!(matches!(
        decision.trace_event,
        Some(TraceEventKind::PolicyExpired { .. })
    ));
}

#[test]
fn cache_snapshot_records_ttl_scope_validation_and_last_sync() {
    let now = OffsetDateTime::now_utc();
    let mut envelope = PolicyBundleEnvelope {
        bundle: bundle(now + Duration::hours(1), true),
        signature: None,
    };
    envelope.signature = Some(splendor_types::WorkOrderSignature {
        key_id: "policy-key-a".to_string(),
        signature: "trace-redacted".to_string(),
    });
    let cache = PolicyCache::new(PolicyCacheConfig {
        enforcement_required: true,
    });
    cache.install_validated_envelope(envelope, now);

    let snapshot = cache.snapshot();

    assert_eq!(snapshot.last_sync_at, Some(now));
    assert_eq!(snapshot.offline_status, PolicyOfflineStatus::Connected);
    assert_eq!(
        snapshot.validation.expect("validation").signature_key_id,
        Some("policy-key-a".to_string())
    );
    let bundle = snapshot.bundle.expect("bundle");
    assert_eq!(bundle.version, "v1");
    assert_eq!(bundle.expires_at, now + Duration::hours(1));
}

#[test]
fn expired_policy_snapshot_reports_expired_or_degraded_status() {
    let now = OffsetDateTime::now_utc();
    let cache = PolicyCache::with_bundle(bundle(now - Duration::minutes(1), true), now);

    assert_eq!(
        cache.snapshot().offline_status,
        PolicyOfflineStatus::Expired
    );
    cache.set_disconnected(true);
    assert_eq!(
        cache.snapshot().offline_status,
        PolicyOfflineStatus::DegradedExpired
    );
}

#[test]
fn disconnected_reconnect_transition_is_trace_visible() {
    let now = OffsetDateTime::now_utc();
    let cache = PolicyCache::with_bundle(bundle(now + Duration::hours(1), true), now);

    let offline = cache
        .set_disconnected_with_trace(true, now)
        .expect("offline transition");
    assert!(matches!(
        offline,
        TraceEventKind::PolicyConnectivityChanged {
            disconnected: true,
            bundle: Some(_),
            ..
        }
    ));
    assert_eq!(
        cache.snapshot().offline_status,
        PolicyOfflineStatus::DisconnectedWithinTtl
    );

    let reconnected = cache
        .set_disconnected_with_trace(false, now + Duration::minutes(1))
        .expect("reconnect transition");
    assert!(matches!(
        reconnected,
        TraceEventKind::PolicyConnectivityChanged {
            disconnected: false,
            bundle: Some(_),
            ..
        }
    ));
}

#[test]
fn revocation_blocks_policy_invocation_and_side_effects() {
    let now = OffsetDateTime::now_utc();
    let cache = PolicyCache::with_bundle(bundle(now + Duration::hours(1), true), now);
    cache.revoke_current("central_revocation");

    let decision = cache.verify_policy_invocation("static", now);
    assert!(!decision.verification.allowed);
    assert_eq!(decision.verification.reasons, vec!["policy_revoked"]);
    assert!(matches!(
        decision.trace_event,
        Some(TraceEventKind::PolicyRevoked { .. })
    ));

    let action = cache.verify_policy_action(&request(SideEffectClass::ReadOnly), now);
    assert!(!action.allowed);
    assert_eq!(action.reasons, vec!["policy_revoked"]);
}

#[test]
fn sync_failure_is_recorded_without_replacing_cached_bundle() {
    let now = OffsetDateTime::now_utc();
    let cache = PolicyCache::with_bundle(bundle(now + Duration::hours(1), true), now);

    let failure = cache.record_sync_failure("central_unavailable", now);
    let snapshot = cache.snapshot();

    assert_eq!(failure.reason, "central_unavailable");
    assert_eq!(
        snapshot.bundle.expect("bundle").policy_bundle_id.as_str(),
        "pol_cache"
    );
    assert_eq!(
        snapshot.last_sync_failure.expect("failure").reason,
        "central_unavailable"
    );
}

#[test]
fn policy_cache_sanitizes_trace_visible_reasons() {
    let now = OffsetDateTime::now_utc();
    let cache = PolicyCache::with_bundle(bundle(now + Duration::hours(1), true), now);

    let failure = cache.record_sync_failure("central failed token=super-secret", now);
    assert_eq!(failure.reason, "policy_reason_redacted");

    cache.revoke_current("operator revoked signature=raw-secret");
    let decision = cache.verify_policy_invocation("static", now);
    let Some(TraceEventKind::PolicyRevoked { reason, .. }) = decision.trace_event else {
        panic!("revocation should emit sanitized trace event");
    };
    assert_eq!(reason, "policy_reason_redacted");

    let action = cache.verify_policy_action(&request(SideEffectClass::External), now);
    assert_eq!(
        action.artifacts["reason"].as_str(),
        Some("policy_reason_redacted")
    );

    let unspecified = PolicyCache::with_bundle(bundle(now + Duration::hours(1), true), now);
    unspecified.revoke_current("   ");
    let decision = unspecified.verify_policy_invocation("static", now);
    let Some(TraceEventKind::PolicyRevoked { reason, .. }) = decision.trace_event else {
        panic!("empty revocation should emit sanitized trace event");
    };
    assert_eq!(reason, "policy_reason_unspecified");
}
