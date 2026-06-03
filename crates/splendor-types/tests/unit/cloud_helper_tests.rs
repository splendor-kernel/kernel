use super::*;
use crate::{
    AgentId, Message, MessageId, PlacementExecutionMode, RevocationStatus, RunId, TenantId,
    WorkOrderId, WorkOrderPlacement, WorkOrderQuotaPolicy, WORK_ORDER_SCHEMA_VERSION,
};
use time::{Duration, OffsetDateTime};

fn helper_work_order() -> WorkOrder {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::seconds(10);
    WorkOrder {
        schema_version: WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: WorkOrderId::try_new("wo_cloud_helper").expect("work order id"),
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id: Some(RunId::new()),
        objective: "propose a safe route through zone A".to_string(),
        allowed_actions: vec![
            ROUTE_PLAN_PROPOSE_ACTION.to_string(),
            "message.send".to_string(),
        ],
        allowed_adapters: vec![
            CLOUD_HELPER_ADAPTER_ID.to_string(),
            "artifact-store".to_string(),
        ],
        allowed_permissions: vec!["route.plan".to_string()],
        data_refs: vec!["map:warehouse-a".to_string(), "zone:allowed-a".to_string()],
        quotas: WorkOrderQuotaPolicy::default(),
        placement: WorkOrderPlacement {
            target: "resident_cloud_pool".to_string(),
            execution_mode: PlacementExecutionMode::CloudHelper,
            ..WorkOrderPlacement::default()
        },
        issued_at: now,
        expires_at: now + Duration::hours(1),
        revocation: RevocationStatus::Active,
    }
}

fn route_proposal() -> RoutePlanProposal {
    RoutePlanProposal {
        proposal_id: "route-proposal-1".to_string(),
        objective: "inspect zone A".to_string(),
        artifact_ref: Some("artifact:route-proposal-1".to_string()),
        data_refs: vec!["map:warehouse-a".to_string()],
        waypoints: vec![
            RouteWaypointProposal {
                waypoint_ref: "waypoint:a-1".to_string(),
                zone_ref: "zone:a".to_string(),
            },
            RouteWaypointProposal {
                waypoint_ref: "waypoint:a-2".to_string(),
                zone_ref: "zone:a".to_string(),
            },
        ],
        created_at: OffsetDateTime::UNIX_EPOCH + Duration::seconds(20),
    }
}

#[test]
fn cloud_helper_work_order_is_advisory_and_scoped() {
    let authority = validate_cloud_helper_work_order(&helper_work_order())
        .expect("advisory helper work order accepted");

    assert_eq!(
        authority.allowed_adapters,
        vec!["cloud_helper", "artifact-store"]
    );
    assert!(authority
        .allowed_actions
        .contains(&ROUTE_PLAN_PROPOSE_ACTION.to_string()));
    assert_eq!(authority.data_refs.len(), 2);
}

#[test]
fn cloud_helper_work_order_denies_robotics_or_physical_authority() {
    let mut missing_mode = helper_work_order();
    missing_mode.placement.execution_mode = PlacementExecutionMode::Live;
    assert_eq!(
        validate_cloud_helper_work_order(&missing_mode),
        Err(CloudHelperValidationError::MissingCloudHelperMode)
    );

    let mut robotics = helper_work_order();
    robotics.allowed_adapters.push("robotics".to_string());
    assert_eq!(
        validate_cloud_helper_work_order(&robotics),
        Err(CloudHelperValidationError::RoboticsAdapterAuthorityDenied)
    );

    let mut direct_action = helper_work_order();
    direct_action
        .allowed_actions
        .push("move_to_waypoint".to_string());
    assert_eq!(
        validate_cloud_helper_work_order(&direct_action),
        Err(CloudHelperValidationError::PhysicalActionAuthorityDenied {
            action: "move_to_waypoint".to_string()
        })
    );

    let mut low_level = helper_work_order();
    low_level
        .allowed_actions
        .push("set_motor_pwm_1".to_string());
    assert!(matches!(
        validate_cloud_helper_work_order(&low_level),
        Err(CloudHelperValidationError::PhysicalActionAuthorityDenied { action }) if action == "set_motor_pwm_1"
    ));
}

#[test]
fn route_plan_proposal_message_is_typed_and_not_a_direct_command() {
    let proposal = route_proposal();
    let message = Message::new(
        MessageId::new(),
        AgentId::new(),
        AgentId::new(),
        RunId::new(),
        ROUTE_PLAN_PROPOSAL_SCHEMA,
        serde_json::to_value(&proposal).expect("proposal payload"),
        None,
        true,
        proposal.created_at,
    )
    .expect("route proposal message accepted");

    assert_eq!(message.schema, ROUTE_PLAN_PROPOSAL_SCHEMA);

    let mut unsafe_proposal = route_proposal();
    unsafe_proposal.waypoints[0].waypoint_ref = "set_motor_pwm_1".to_string();
    assert!(matches!(
        unsafe_proposal.validate(),
        Err(CloudHelperValidationError::MalformedProposal { reason })
            if reason == "proposal_contains_direct_physical_command"
    ));
}

#[test]
fn local_validation_converts_only_accepted_plan_to_bounded_actions() {
    let proposal = route_proposal();
    let validation = validate_route_plan_for_local_execution(&proposal, &["zone:a".to_string()]);

    assert!(validation.result.allowed);
    assert_eq!(validation.bounded_actions.len(), 2);
    for action in &validation.bounded_actions {
        assert_eq!(action.name, "move_to_waypoint");
        assert_eq!(
            action.side_effect_class,
            SideEffectClass::Custom("physical.high_level".to_string())
        );
        assert!(action
            .preconditions
            .contains(&"cloud_helper.local_plan_validated".to_string()));
    }

    let rejected = validate_route_plan_for_local_execution(&proposal, &["zone:b".to_string()]);
    assert!(!rejected.result.allowed);
    assert!(rejected.bounded_actions.is_empty());
    assert!(rejected
        .result
        .reasons
        .contains(&"route_plan_zone_not_allowed".to_string()));
}

#[test]
fn helper_failure_validation_has_no_action_candidates() {
    let validation = cloud_helper_failure_validation("timeout contacting helper");

    assert!(!validation.result.allowed);
    assert_eq!(
        validation.result.reasons,
        vec![CLOUD_HELPER_UNAVAILABLE_REASON]
    );
    assert!(validation.bounded_actions.is_empty());
}
