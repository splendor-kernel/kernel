use super::*;
use splendor_gateway::{
    ActionAdapter, ActionGateway, ActionRequest, ActionStatus, AdapterError, AdapterResult,
    PreEffectAuthorityDecisionRecorder, ResourceBoundaryVerifier, TenantAccess,
    TrustedActionProfile, VerifiedActionGateway,
};
use splendor_types::{
    Action, AgentId, QuotaUsage, RevocationStatus, SideEffectClass, TenantId, VerificationResult,
    WorkOrder, WorkOrderEnvelope, WorkOrderId, WorkOrderKeyring, WorkOrderPlacement,
    WorkOrderQuotaPolicy, WorkOrderValidationContext, WORK_ORDER_SCHEMA_VERSION,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use time::{Duration, OffsetDateTime};

const ACTION: &str = "fixture.write";
const ADAPTER: &str = "fixture";
const PERMISSION: &str = "fixture.write";

struct AllowTenant;

impl TenantAccess for AllowTenant {
    fn verify_policy(
        &self,
        _tenant_id: &TenantId,
        _agent_id: &AgentId,
        _action: &Action,
        _adapter: Option<&str>,
    ) -> VerificationResult {
        VerificationResult::allow()
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

#[derive(Default)]
struct CountingAdapter(AtomicUsize);

impl ActionAdapter for CountingAdapter {
    fn execute(&self, _action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(AdapterResult {
            output: serde_json::json!({"ok": true}),
            satisfied_postconditions: Vec::new(),
        })
    }
}

struct BlockingResourceVerifier {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl ResourceBoundaryVerifier for BlockingResourceVerifier {
    fn verify_resource_boundary(
        &self,
        _action: &ActionRequest,
        _adapter: Option<&str>,
    ) -> VerificationResult {
        self.entered.send(()).expect("verifier entered");
        self.release
            .lock()
            .expect("release lock")
            .recv()
            .expect("verifier release");
        VerificationResult::allow()
    }
}

struct AllowRecorder;

impl PreEffectAuthorityDecisionRecorder for AllowRecorder {
    fn record_pre_effect_authority_allow(
        &self,
        _action: &ActionRequest,
        _verification: &VerificationResult,
    ) -> Result<(), String> {
        Ok(())
    }
}

struct BlockingRecorder {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl PreEffectAuthorityDecisionRecorder for BlockingRecorder {
    fn record_pre_effect_authority_allow(
        &self,
        _action: &ActionRequest,
        _verification: &VerificationResult,
    ) -> Result<(), String> {
        self.entered.send(()).map_err(|_| "entered".to_string())?;
        self.release
            .lock()
            .map_err(|_| "release_lock".to_string())?
            .recv()
            .map_err(|_| "release".to_string())?;
        Ok(())
    }
}

fn admitted_authority(
    expires_at: OffsetDateTime,
) -> (RunAuthorityHandle, TenantId, AgentId, RunId) {
    let now = OffsetDateTime::now_utc();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let envelope = WorkOrderEnvelope::signed_with_shared_secret(
        WorkOrder {
            schema_version: WORK_ORDER_SCHEMA_VERSION.to_string(),
            work_order_id: WorkOrderId::try_new(format!("wo_{run_id}")).expect("work order id"),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: None,
            objective: "permit race test".to_string(),
            allowed_actions: vec![ACTION.to_string()],
            allowed_adapters: vec![ADAPTER.to_string()],
            allowed_permissions: vec![PERMISSION.to_string()],
            data_refs: Vec::new(),
            quotas: WorkOrderQuotaPolicy::default(),
            placement: WorkOrderPlacement::default(),
            issued_at: now - Duration::minutes(1),
            expires_at,
            revocation: RevocationStatus::Active,
        },
        "test-key",
        b"run-authority-kernel-test-secret",
    )
    .expect("signed work order");
    let mut keyring = WorkOrderKeyring::new();
    keyring
        .insert_shared_secret("test-key", b"run-authority-kernel-test-secret")
        .expect("keyring");
    let validated = splendor_types::validate_work_order(
        &envelope,
        &WorkOrderValidationContext {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: None,
            expected_placement_target: None,
            now,
        },
        &keyring,
    )
    .expect("validated work order");
    let authority = RunAuthorityHandle::admit_signed_work_order_compatibility(
        &validated,
        run_id.clone(),
        format!("splendor.test.run:{run_id}"),
    )
    .expect("run authority");
    (authority, tenant_id, agent_id, run_id)
}

fn request(tenant_id: TenantId, agent_id: AgentId, run_id: RunId) -> ActionRequest {
    ActionRequest {
        action_id: splendor_gateway::ActionId::new(),
        tenant_id,
        agent_id,
        run_id,
        tick_id: None,
        action: Action {
            name: ACTION.to_string(),
            params: serde_json::json!({"fixture": true}),
            side_effect_class: SideEffectClass::External,
            cost_estimate: None,
            required_permissions: vec![PERMISSION.to_string()],
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        },
        adapter: Some(ADAPTER.to_string()),
        quota_usage: QuotaUsage::single_action(),
        satisfied_preconditions: Vec::new(),
        requested_at: OffsetDateTime::now_utc(),
        physical_action_resource_coordinate: None,
        approval_evidence: None,
        authority_obligation_evidence: None,
        authority_obligation_receipts: Vec::new(),
    }
}

fn gateway(authority: RunAuthorityHandle, adapter: Arc<CountingAdapter>) -> VerifiedActionGateway {
    let mut gateway = VerifiedActionGateway::new(Arc::new(AllowTenant));
    gateway.set_action_authority_evaluator(Arc::new(authority));
    gateway.set_pre_effect_authority_recorder(Arc::new(AllowRecorder));
    gateway
        .set_trusted_action_profiles(vec![TrustedActionProfile {
            action_name: ACTION.to_string(),
            adapter: ADAPTER.to_string(),
            required_permissions: vec![PERMISSION.to_string()],
        }])
        .expect("profiles");
    gateway.register_adapter(ACTION, ADAPTER, adapter);
    gateway
}

#[test]
fn final_permit_denies_expiry_and_revocation_crossing_blocking_verifier() {
    for revoke in [false, true] {
        let expiry = if revoke {
            OffsetDateTime::now_utc() + Duration::minutes(5)
        } else {
            OffsetDateTime::now_utc() + Duration::milliseconds(120)
        };
        let (authority, tenant_id, agent_id, run_id) = admitted_authority(expiry);
        assert!(!authority.grant_id().to_string().is_empty());
        let adapter = Arc::new(CountingAdapter::default());
        let mut gateway = gateway(authority.clone(), adapter.clone());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        gateway.set_resource_boundary_verifier(Arc::new(BlockingResourceVerifier {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }));
        let request = request(tenant_id, agent_id, run_id);
        let thread = std::thread::spawn(move || gateway.submit(request).expect("outcome"));
        entered_rx.recv().expect("early authority completed");
        if revoke {
            authority.revoke();
        } else {
            std::thread::sleep(std::time::Duration::from_millis(180));
        }
        release_tx.send(()).expect("release verifier");
        let outcome = thread.join().expect("gateway thread");
        assert_eq!(outcome.status, ActionStatus::Denied);
        assert_eq!(adapter.0.load(Ordering::SeqCst), 0);
        assert!(outcome
            .verification
            .reasons
            .iter()
            .any(|reason| { reason == "expired_grant" || reason == "authority_grant_revoked" }));
    }
}

#[test]
fn permit_holds_authority_epoch_across_blocking_recorder() {
    let (authority, tenant_id, agent_id, run_id) =
        admitted_authority(OffsetDateTime::now_utc() + Duration::minutes(5));
    let adapter = Arc::new(CountingAdapter::default());
    let mut gateway = gateway(authority.clone(), adapter.clone());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    gateway.set_pre_effect_authority_recorder(Arc::new(BlockingRecorder {
        entered: entered_tx,
        release: Mutex::new(release_rx),
    }));
    let request = request(tenant_id, agent_id, run_id);
    let gateway_thread = std::thread::spawn(move || gateway.submit(request).expect("outcome"));
    entered_rx.recv().expect("permit acquired before recorder");

    let (revoked_tx, revoked_rx) = mpsc::channel();
    let revoking = authority.clone();
    let revoke_thread = std::thread::spawn(move || {
        revoking.revoke();
        revoked_tx.send(()).expect("revoked signal");
    });
    assert!(revoked_rx
        .recv_timeout(std::time::Duration::from_millis(50))
        .is_err());
    release_tx.send(()).expect("release recorder");
    let outcome = gateway_thread.join().expect("gateway thread");
    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(adapter.0.load(Ordering::SeqCst), 1);
    revoked_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("revocation completes after permit release");
    revoke_thread.join().expect("revoke thread");
}

#[test]
fn permit_linearized_before_expiry_remains_valid_through_blocking_recorder() {
    let (authority, tenant_id, agent_id, run_id) =
        admitted_authority(OffsetDateTime::now_utc() + Duration::seconds(1));
    let adapter = Arc::new(CountingAdapter::default());
    let mut gateway = gateway(authority, adapter.clone());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    gateway.set_pre_effect_authority_recorder(Arc::new(BlockingRecorder {
        entered: entered_tx,
        release: Mutex::new(release_rx),
    }));
    let request = request(tenant_id, agent_id, run_id);
    let gateway_thread = std::thread::spawn(move || gateway.submit(request).expect("outcome"));
    entered_rx.recv().expect("permit acquired before recorder");
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    release_tx.send(()).expect("release recorder");
    let outcome = gateway_thread.join().expect("gateway thread");
    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(adapter.0.load(Ordering::SeqCst), 1);
}
