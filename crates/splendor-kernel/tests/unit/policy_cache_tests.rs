use super::*;
use splendor_gateway::{ActionGateway, ActionId, ActionOutcome, ActionRequest, GatewayError};
use splendor_types::{
    validate_policy_bundle, validate_policy_bundle_candidate, Action, AgentId,
    OfflineHighRiskBehavior, PolicyBundle, PolicyBundleEnvelope, PolicyBundleId,
    PolicyBundleKeyring, PolicyBundleValidationContext, PolicyDegradedMode, QuotaUsage,
    RevocationStatus, RunId, SideEffectClass, TenantId, ValidatedPolicyBundle,
};
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

struct CountingGateway {
    calls: Arc<Mutex<u32>>,
}

fn cache_owner() -> PolicyCacheOwner {
    PolicyCacheOwner {
        tenant_id: TenantId::parse("00000000-0000-0000-0000-000000000101").expect("tenant id"),
        agent_id: AgentId::parse("00000000-0000-0000-0000-000000000102").expect("agent id"),
    }
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
        tenant_id: cache_owner().tenant_id,
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

fn policy_keyring() -> PolicyBundleKeyring {
    let mut keyring = PolicyBundleKeyring::new();
    keyring
        .insert_shared_secret("policy-key-a", b"policy-cache-test-secret")
        .expect("policy cache test key");
    keyring
}

fn validated_policy(bundle: PolicyBundle, validated_at: OffsetDateTime) -> ValidatedPolicyBundle {
    validated_policy_for_owner(bundle, validated_at, &cache_owner())
}

fn validated_policy_for_owner(
    bundle: PolicyBundle,
    validated_at: OffsetDateTime,
    owner: &PolicyCacheOwner,
) -> ValidatedPolicyBundle {
    let envelope = PolicyBundleEnvelope::signed_with_shared_secret(
        bundle.clone(),
        "policy-key-a",
        b"policy-cache-test-secret",
    )
    .expect("signed policy cache fixture");
    validate_policy_bundle(
        &envelope,
        &PolicyBundleValidationContext {
            tenant_id: owner.tenant_id.clone(),
            agent_id: Some(owner.agent_id.clone()),
            now: validated_at,
        },
        &policy_keyring(),
    )
    .expect("validated policy cache fixture")
}

fn validated_candidate(
    bundle: PolicyBundle,
    validated_at: OffsetDateTime,
) -> ValidatedPolicyBundle {
    let envelope = PolicyBundleEnvelope::signed_with_shared_secret(
        bundle.clone(),
        "policy-key-a",
        b"policy-cache-test-secret",
    )
    .expect("signed policy cache candidate");
    validate_policy_bundle_candidate(
        &envelope,
        &PolicyBundleValidationContext {
            tenant_id: cache_owner().tenant_id,
            agent_id: Some(cache_owner().agent_id),
            now: validated_at,
        },
        &policy_keyring(),
    )
    .expect("trusted policy cache candidate")
    .into_validated()
}

fn cache_with_bundle(bundle: PolicyBundle, observed_at: OffsetDateTime) -> PolicyCache {
    let validated_at = if bundle.expires_at <= observed_at {
        bundle.expires_at - Duration::minutes(1)
    } else {
        observed_at
    };
    let cache = PolicyCache::new(
        PolicyCacheConfig {
            enforcement_required: true,
        },
        cache_owner(),
    );
    install_policy(&cache, validated_policy(bundle, validated_at), false)
        .expect("trusted policy installs");
    cache
}

fn install_policy(
    cache: &PolicyCache,
    validated: ValidatedPolicyBundle,
    reconnect: bool,
) -> Result<PolicyCacheInstallResult, PolicyCacheInstallError> {
    let plan = cache.prepare_install(validated, reconnect)?;
    cache.commit_install(plan)
}

fn apply_revocation(
    cache: &PolicyCache,
    mut bundle: PolicyBundle,
    validated_at: OffsetDateTime,
    reason: &str,
) {
    bundle.revocation = RevocationStatus::Revoked {
        reason: reason.to_string(),
    };
    cache
        .commit_revocation(
            cache
                .prepare_revocation(validated_candidate(bundle, validated_at))
                .expect("matching trusted revocation prepares"),
        )
        .expect("matching trusted revocation applies");
}

fn named_request(name: &str, side_effect_class: SideEffectClass) -> ActionRequest {
    ActionRequest {
        action_id: ActionId::new(),
        tenant_id: cache_owner().tenant_id,
        agent_id: cache_owner().agent_id,
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
        authority_obligation_evidence: None,
    }
}

fn request(side_effect_class: SideEffectClass) -> ActionRequest {
    named_request("file.write", side_effect_class)
}

#[test]
fn non_enforced_empty_cache_allows_policy_and_gateway_forwarding() {
    let cache = PolicyCache::new(
        PolicyCacheConfig {
            enforcement_required: false,
        },
        cache_owner(),
    );

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
    let cache = PolicyCache::new(
        PolicyCacheConfig {
            enforcement_required: true,
        },
        cache_owner(),
    );

    let decision = cache.verify_policy_invocation("static", OffsetDateTime::now_utc());

    assert!(!decision.verification.allowed);
    assert_eq!(decision.verification.reasons, vec!["policy_unavailable"]);
    assert_eq!(decision.trace_event, None);
}

#[test]
fn missing_required_policy_fails_closed_before_inner_gateway() {
    let cache = PolicyCache::new(
        PolicyCacheConfig {
            enforcement_required: true,
        },
        cache_owner(),
    );
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
    let cache = cache_with_bundle(bundle(now - Duration::minutes(1), true), now);
    cache.mark_disconnected();

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
    let cache = cache_with_bundle(bundle(now + Duration::hours(1), true), now);
    cache.mark_disconnected();

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
    let cache = cache_with_bundle(bundle(now + Duration::hours(1), true), now);
    cache.mark_disconnected();
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
    let cache = cache_with_bundle(high_risk_intervention, now);
    cache.mark_disconnected();
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
    let cache = cache_with_bundle(bundle(now - Duration::minutes(1), true), now);
    cache.mark_disconnected();
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
    let cache = cache_with_bundle(bundle(now - Duration::minutes(1), false), now);

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
    let cache = cache_with_bundle(bundle(now - Duration::minutes(1), true), now);
    cache.mark_disconnected();

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
    let policy = bundle(now + Duration::hours(1), true);
    let cache = PolicyCache::new(
        PolicyCacheConfig {
            enforcement_required: true,
        },
        cache_owner(),
    );
    install_policy(&cache, validated_policy(policy, now), false).expect("trusted policy installs");

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
    let cache = cache_with_bundle(bundle(now - Duration::minutes(1), true), now);

    assert_eq!(
        cache.snapshot().offline_status,
        PolicyOfflineStatus::Expired
    );
    cache.mark_disconnected();
    assert_eq!(
        cache.snapshot().offline_status,
        PolicyOfflineStatus::DegradedExpired
    );
}

#[test]
fn exact_retry_cannot_reconnect_but_strict_newer_transition_is_trace_visible() {
    let now = OffsetDateTime::now_utc();
    let policy = bundle(now + Duration::hours(1), true);
    let cache = cache_with_bundle(policy.clone(), now);

    let offline = cache
        .mark_disconnected_with_trace(now)
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

    let exact = install_policy(
        &cache,
        validated_policy(policy.clone(), OffsetDateTime::now_utc()),
        true,
    )
    .expect("trusted exact retry remains idempotent");
    assert_eq!(exact.status, PolicyCacheInstallStatus::Idempotent);
    assert_eq!(exact.connectivity_event, None);
    assert!(cache.snapshot().disconnected);

    let calls = Arc::new(Mutex::new(0));
    let gateway = PolicyDistributionGateway::new(
        Arc::new(CountingGateway {
            calls: calls.clone(),
        }),
        Arc::new(cache.clone()),
    );
    let denied = gateway
        .submit(named_request("file.read", SideEffectClass::ReadOnly))
        .expect("offline-disallowed action returns denial");
    assert_eq!(denied.status, ActionStatus::Denied);
    assert_eq!(
        denied.verification.reasons,
        vec!["offline_action_not_allowed"]
    );
    assert_eq!(*calls.lock().expect("calls lock"), 0);

    let mut refresh = policy;
    refresh.version = "strict-newer-reconnect".to_string();
    refresh.issued_at = now + Duration::minutes(2);
    let reconnected = install_policy(
        &cache,
        validated_policy(refresh, now + Duration::minutes(2)),
        true,
    )
    .expect("strict newer trusted policy reconnects")
    .connectivity_event
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
    let policy = bundle(now + Duration::hours(1), true);
    let cache = cache_with_bundle(policy.clone(), now);
    apply_revocation(&cache, policy, now, "central_revocation");

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
    let cache = cache_with_bundle(bundle(now + Duration::hours(1), true), now);

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
    let policy = bundle(now + Duration::hours(1), true);
    let cache = cache_with_bundle(policy.clone(), now);

    let failure = cache.record_sync_failure("central failed token=super-secret", now);
    assert_eq!(failure.reason, "policy_reason_redacted");

    apply_revocation(&cache, policy, now, "operator revoked signature=raw-secret");
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

    let policy = bundle(now + Duration::hours(1), true);
    let unspecified = cache_with_bundle(policy.clone(), now);
    apply_revocation(&unspecified, policy, now, "   ");
    let decision = unspecified.verify_policy_invocation("static", now);
    let Some(TraceEventKind::PolicyRevoked { reason, .. }) = decision.trace_event else {
        panic!("empty revocation should emit sanitized trace event");
    };
    assert_eq!(reason, "policy_reason_unspecified");
}

#[test]
fn monotonic_signed_install_rejects_rollback_conflict_and_preserves_tombstone() {
    let now = OffsetDateTime::now_utc();
    let mut older_broader = bundle(now + Duration::hours(2), true);
    older_broader.version = "older-broader".to_string();
    older_broader.issued_at = now - Duration::minutes(20);
    older_broader
        .degraded_mode
        .disconnected_low_risk_actions
        .push("file.read".to_string());
    let mut newer_narrower = older_broader.clone();
    newer_narrower.version = "newer-narrower".to_string();
    newer_narrower.issued_at = now - Duration::minutes(10);
    newer_narrower.degraded_mode.disconnected_low_risk_actions = vec!["read_battery".to_string()];

    let cache = PolicyCache::new(
        PolicyCacheConfig {
            enforcement_required: true,
        },
        cache_owner(),
    );
    install_policy(&cache, validated_policy(older_broader.clone(), now), false)
        .expect("initial trusted authority installs");
    let newer = install_policy(&cache, validated_policy(newer_narrower.clone(), now), false)
        .expect("strictly newer signed authority installs");
    assert_eq!(newer.status, PolicyCacheInstallStatus::Installed);
    assert_eq!(newer.bundle.version, "newer-narrower");

    let rollback = install_policy(&cache, validated_policy(older_broader, now), false)
        .expect_err("older broader replay must fail before mutation");
    assert_eq!(rollback, PolicyCacheInstallError::Rollback);
    assert_eq!(rollback.reason_code(), "policy_cache_install_rollback");
    assert_eq!(
        cache
            .snapshot_at(now)
            .bundle
            .expect("current bundle")
            .version,
        "newer-narrower"
    );

    let mut conflict = newer_narrower.clone();
    conflict.version = "same-time-different-content".to_string();
    let conflict = install_policy(&cache, validated_policy(conflict, now), false)
        .expect_err("same-issued-at different signed content must fail");
    assert_eq!(conflict, PolicyCacheInstallError::SameIssuedAtConflict);
    assert_eq!(conflict.reason_code(), "policy_cache_install_conflict");

    let exact = install_policy(&cache, validated_policy(newer_narrower.clone(), now), false)
        .expect("exact signed retry is idempotent");
    assert_eq!(exact.status, PolicyCacheInstallStatus::Idempotent);
    assert!(!exact.revocation_preserved);

    apply_revocation(&cache, newer_narrower.clone(), now, "central_revocation");
    let mut earlier_active = newer_narrower.clone();
    earlier_active.version = "earlier-active-replay".to_string();
    earlier_active.issued_at = now - Duration::minutes(15);
    let earlier_replay = install_policy(&cache, validated_policy(earlier_active, now), false)
        .expect_err("earlier active replay cannot clear revocation tombstone");
    assert_eq!(earlier_replay, PolicyCacheInstallError::Rollback);
    let exact_after_revocation =
        install_policy(&cache, validated_policy(newer_narrower.clone(), now), false)
            .expect("exact active retry remains idempotent");
    assert_eq!(
        exact_after_revocation.status,
        PolicyCacheInstallStatus::Idempotent
    );
    assert!(exact_after_revocation.revocation_preserved);
    assert_eq!(
        cache
            .verify_policy_action(&request(SideEffectClass::External), now)
            .reasons,
        vec!["policy_revoked"]
    );

    let mut refresh = newer_narrower;
    refresh.version = "strict-newer-refresh".to_string();
    refresh.issued_at = now - Duration::minutes(5);
    let refreshed = install_policy(&cache, validated_policy(refresh, now), false)
        .expect("strictly newer signed refresh clears tombstone");
    assert_eq!(refreshed.status, PolicyCacheInstallStatus::Installed);
    assert!(
        cache
            .verify_policy_action(
                &request(SideEffectClass::External),
                OffsetDateTime::now_utc(),
            )
            .allowed
    );
}

#[test]
fn unrelated_or_older_signed_revocation_cannot_block_current_authority() {
    let now = OffsetDateTime::now_utc();
    let mut current = bundle(now + Duration::hours(2), true);
    current.issued_at = now - Duration::minutes(10);
    let cache = cache_with_bundle(current.clone(), now);

    let mut older = current.clone();
    older.issued_at = now - Duration::minutes(20);
    older.revocation = RevocationStatus::Revoked {
        reason: "stale_revoke".to_string(),
    };
    let error = cache
        .prepare_revocation(validated_candidate(older, now))
        .expect_err("older revocation cannot block newer authority");
    assert_eq!(error, PolicyCacheInstallError::RevocationRollback);

    let mut unrelated = current;
    unrelated.policy_bundle_id =
        PolicyBundleId::try_new("pol_unrelated").expect("unrelated policy id");
    unrelated.issued_at = now - Duration::minutes(5);
    unrelated.revocation = RevocationStatus::Revoked {
        reason: "unrelated_revoke".to_string(),
    };
    let error = cache
        .prepare_revocation(validated_candidate(unrelated, now))
        .expect_err("unrelated revocation cannot block current authority");
    assert_eq!(error, PolicyCacheInstallError::RevocationUnrelated);
    assert!(
        cache
            .verify_policy_action(
                &request(SideEffectClass::External),
                OffsetDateTime::now_utc(),
            )
            .allowed
    );
}

#[test]
fn signed_revocation_watermark_blocks_intermediate_active_and_orders_retries() {
    let now = OffsetDateTime::now_utc();
    let t10 = now - Duration::minutes(20);
    let t15 = now - Duration::minutes(15);
    let t19 = now - Duration::minutes(11);
    let t20 = now - Duration::minutes(10);
    let t21 = now - Duration::minutes(9);
    let mut active_t10 = bundle(now + Duration::hours(1), true);
    active_t10.issued_at = t10;
    let cache = cache_with_bundle(active_t10.clone(), t10);

    let mut revoked_t20 = active_t10.clone();
    revoked_t20.issued_at = t20;
    revoked_t20.revocation = RevocationStatus::Revoked {
        reason: "revoked_at_t20".to_string(),
    };
    let revocation = validated_candidate(revoked_t20.clone(), t20);
    let applied = cache
        .commit_revocation(
            cache
                .prepare_revocation(revocation)
                .expect("T20 revocation prepares"),
        )
        .expect("T20 revocation commits");
    assert_eq!(applied.status, PolicyCacheRevocationStatus::Applied);

    let mut active_t15 = active_t10.clone();
    active_t15.version = "active-t15".to_string();
    active_t15.issued_at = t15;
    let error = cache
        .prepare_install(validated_policy(active_t15, now), false)
        .expect_err("T15 active cannot clear T20 tombstone");
    assert_eq!(error, PolicyCacheInstallError::RevocationWatermark);

    let calls = Arc::new(Mutex::new(0));
    let gateway = PolicyDistributionGateway::new(
        Arc::new(CountingGateway {
            calls: calls.clone(),
        }),
        Arc::new(cache.clone()),
    );
    let denied = gateway
        .submit(request(SideEffectClass::External))
        .expect("revocation denial");
    assert_eq!(denied.status, ActionStatus::Denied);
    assert_eq!(denied.verification.reasons, vec!["policy_revoked"]);
    assert_eq!(*calls.lock().expect("calls lock"), 0);

    let mut older_revocation = revoked_t20.clone();
    older_revocation.issued_at = t19;
    let error = cache
        .prepare_revocation(validated_candidate(
            older_revocation,
            OffsetDateTime::now_utc(),
        ))
        .expect_err("older revocation cannot replace T20 watermark");
    assert_eq!(error, PolicyCacheInstallError::RevocationRollback);

    let exact = cache
        .commit_revocation(
            cache
                .prepare_revocation(validated_candidate(
                    revoked_t20.clone(),
                    OffsetDateTime::now_utc(),
                ))
                .expect("exact T20 revocation retry prepares"),
        )
        .expect("exact T20 revocation retry commits");
    assert_eq!(exact.status, PolicyCacheRevocationStatus::Idempotent);

    let mut conflicting = revoked_t20;
    conflicting.revocation = RevocationStatus::Revoked {
        reason: "different_t20_content".to_string(),
    };
    let error = cache
        .prepare_revocation(validated_candidate(conflicting, OffsetDateTime::now_utc()))
        .expect_err("different T20 revocation content conflicts");
    assert_eq!(error, PolicyCacheInstallError::RevocationConflict);

    let mut active_t21 = active_t10;
    active_t21.version = "active-t21-refresh".to_string();
    active_t21.issued_at = t21;
    let refreshed = install_policy(
        &cache,
        validated_policy(active_t21, OffsetDateTime::now_utc()),
        false,
    )
    .expect("T21 active refresh clears T20 tombstone");
    assert_eq!(refreshed.status, PolicyCacheInstallStatus::Installed);
    assert!(
        cache
            .verify_policy_action(
                &request(SideEffectClass::External),
                OffsetDateTime::now_utc(),
            )
            .allowed
    );
}

#[test]
fn cache_owner_rejects_cross_agent_wrapper_and_action_forwarding() {
    let now = OffsetDateTime::now_utc();
    let owner_a = cache_owner();
    let owner_b = PolicyCacheOwner {
        tenant_id: owner_a.tenant_id.clone(),
        agent_id: AgentId::parse("00000000-0000-0000-0000-000000000103").expect("other agent"),
    };
    let tenant_wide = bundle(now + Duration::hours(1), true);
    let validated_for_a = validated_policy_for_owner(tenant_wide.clone(), now, &owner_a);
    let cache_b = PolicyCache::new(
        PolicyCacheConfig {
            enforcement_required: true,
        },
        owner_b,
    );
    let error = cache_b
        .prepare_install(validated_for_a, false)
        .expect_err("tenant-wide wrapper validated for another agent is rejected");
    assert_eq!(error, PolicyCacheInstallError::OwnerMismatch);
    assert_eq!(error.reason_code(), "policy_cache_owner_mismatch");

    let source_cache = PolicyCache::new(
        PolicyCacheConfig {
            enforcement_required: true,
        },
        owner_a.clone(),
    );
    let target_cache = PolicyCache::new(
        PolicyCacheConfig {
            enforcement_required: true,
        },
        owner_a.clone(),
    );
    let foreign_plan = source_cache
        .prepare_install(
            validated_policy_for_owner(tenant_wide.clone(), now, &owner_a),
            false,
        )
        .expect("source cache plan");
    let error = target_cache
        .commit_install(foreign_plan)
        .expect_err("plan cannot commit through another cache instance");
    assert_eq!(error, PolicyCacheInstallError::ConcurrentMutation);

    let cache_a = cache_with_bundle(tenant_wide, now);
    let calls = Arc::new(Mutex::new(0));
    let gateway = PolicyDistributionGateway::new(
        Arc::new(CountingGateway {
            calls: calls.clone(),
        }),
        Arc::new(cache_a),
    );
    let mut wrong_owner_request = request(SideEffectClass::External);
    wrong_owner_request.agent_id = AgentId::new();
    let denied = gateway
        .submit(wrong_owner_request)
        .expect("owner mismatch is a structured denial");
    assert_eq!(denied.status, ActionStatus::Denied);
    assert_eq!(
        denied.verification.reasons,
        vec!["policy_cache_request_owner_mismatch"]
    );
    assert_eq!(*calls.lock().expect("calls lock"), 0);
}

#[test]
fn policy_clock_rollback_and_latched_expiry_deny_policy_action_and_gateway() {
    let now = OffsetDateTime::now_utc();
    let future_validation = now + Duration::minutes(10);
    let future_cache = PolicyCache::new(
        PolicyCacheConfig {
            enforcement_required: true,
        },
        cache_owner(),
    );
    let mut future_observed_policy = bundle(now + Duration::hours(2), true);
    future_observed_policy.issued_at = now;
    install_policy(
        &future_cache,
        validated_policy(future_observed_policy, future_validation),
        false,
    )
    .expect("trusted future observation installs");
    assert_eq!(
        future_cache
            .verify_policy_invocation("static", now)
            .verification
            .reasons,
        vec!["policy_clock_rollback"]
    );
    assert_eq!(
        future_cache
            .verify_policy_action(&request(SideEffectClass::External), now)
            .reasons,
        vec!["policy_clock_rollback"]
    );
    assert_eq!(
        future_cache.snapshot_at(now).offline_status,
        PolicyOfflineStatus::ClockRollback
    );
    let calls = Arc::new(Mutex::new(0));
    let gateway = PolicyDistributionGateway::new(
        Arc::new(CountingGateway {
            calls: calls.clone(),
        }),
        Arc::new(future_cache),
    );
    let outcome = gateway
        .submit(request(SideEffectClass::External))
        .expect("clock rollback gateway denial");
    assert_eq!(outcome.status, ActionStatus::Denied);
    assert_eq!(outcome.verification.reasons, vec!["policy_clock_rollback"]);
    assert_eq!(*calls.lock().expect("calls lock"), 0);

    let expiry = now + Duration::minutes(10);
    let expiring_cache = cache_with_bundle(bundle(expiry, true), now);
    let policy_expired = expiring_cache.verify_policy_invocation("static", expiry);
    assert_eq!(policy_expired.verification.reasons, vec!["policy_expired"]);
    let action_expired = expiring_cache.verify_policy_action(
        &request(SideEffectClass::External),
        expiry + Duration::seconds(1),
    );
    assert_eq!(action_expired.reasons, vec!["policy_expired"]);

    let rolled_back = now + Duration::minutes(5);
    assert_eq!(
        expiring_cache
            .verify_policy_invocation("static", rolled_back)
            .verification
            .reasons,
        vec!["policy_clock_rollback"]
    );
    assert_eq!(
        expiring_cache
            .verify_policy_action(&request(SideEffectClass::External), rolled_back)
            .reasons,
        vec!["policy_clock_rollback"]
    );
    assert_eq!(
        expiring_cache.snapshot_at(rolled_back).offline_status,
        PolicyOfflineStatus::ClockRollback
    );
}
