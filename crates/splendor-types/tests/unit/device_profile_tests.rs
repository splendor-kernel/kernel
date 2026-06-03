use super::*;

fn local_policy() -> DeviceLocalPolicyIndicators {
    DeviceLocalPolicyIndicators {
        supports_local_policy_cache: true,
        supports_offline_operation: true,
        supports_local_operator_intervention: true,
        max_offline_policy_ttl_seconds: Some(300),
    }
}

fn safety_constraints() -> Vec<DeviceSafetyConstraint> {
    vec![
        DeviceSafetyConstraint {
            name: "geofence.required".to_string(),
            value: serde_json::json!(true),
        },
        DeviceSafetyConstraint {
            name: "emergency_stop.status_required".to_string(),
            value: serde_json::json!("healthy"),
        },
    ]
}

fn profile(kind: DeviceNodeKind, actions: &[&str]) -> DeviceProfile {
    let mut capabilities = vec![
        DeviceCapability {
            category: DeviceCapabilityCategory::Sensor,
            name: "camera.rgb".to_string(),
        },
        DeviceCapability {
            category: DeviceCapabilityCategory::Power,
            name: "battery.status".to_string(),
        },
        DeviceCapability {
            category: DeviceCapabilityCategory::SafetyStatus,
            name: "emergency_stop.status".to_string(),
        },
        DeviceCapability {
            category: DeviceCapabilityCategory::Network,
            name: "network.restricted".to_string(),
        },
        DeviceCapability {
            category: DeviceCapabilityCategory::LocalCompute,
            name: "policy.cache.local".to_string(),
        },
    ];
    capabilities.extend(
        actions
            .iter()
            .map(|action| DeviceCapability::bounded_action(*action)),
    );
    DeviceProfile::new(kind, capabilities, safety_constraints(), local_policy())
        .expect("valid profile")
}

#[test]
fn drone_and_robot_profiles_accept_high_level_bounded_actions() {
    for kind in [DeviceNodeKind::Drone, DeviceNodeKind::Robot] {
        let profile = profile(
            kind,
            &[
                "move_to_waypoint",
                "dock",
                "inspect_zone",
                "capture_image",
                "return_to_base",
            ],
        );

        profile.validate().expect("profile remains valid");
        let document = profile
            .to_capability_document()
            .expect("compat capability document");
        assert_eq!(document.schema, crate::CAPABILITY_DOCUMENT_SCHEMA);
        assert!(document
            .capabilities
            .contains(&format!("{DEVICE_KIND_CAPABILITY_PREFIX}{}", kind.as_str())));
        assert!(document
            .capabilities
            .contains(&physical_action_capability("move_to_waypoint")));
        validate_physical_capability_document(&document).expect("physical capabilities valid");
    }
}

#[test]
fn profile_examples_cover_supported_device_kinds() {
    let cases = [
        (DeviceNodeKind::Drone, "move_to_waypoint"),
        (DeviceNodeKind::Robot, "inspect_zone"),
        (DeviceNodeKind::Humanoid, "request_operator_override"),
        (DeviceNodeKind::EdgeAppliance, "read_sensor_summary"),
        (DeviceNodeKind::DesktopSidecar, "notify_operator"),
        (DeviceNodeKind::IndustrialDevice, "pause_mission"),
    ];

    for (kind, action) in cases {
        let profile = profile(kind, &[action]);
        assert_eq!(profile.kind, kind);
        assert!(profile.local_policy.supports_local_policy_cache);
        assert!(!profile.safety_constraints.is_empty());
    }
}

#[test]
fn rejects_raw_motor_and_actuator_advertisements() {
    for action in [
        "set_motor_pwm",
        "set.motor.pwm",
        "raw_actuator_write",
        "raw.actuator.write",
        "disable_firmware_safety",
        "bypass_collision_avoidance",
        "ignore_emergency_stop",
    ] {
        let candidate = DeviceProfile {
            schema: DEVICE_PROFILE_SCHEMA.to_string(),
            kind: DeviceNodeKind::Drone,
            capabilities: vec![DeviceCapability::bounded_action(action)],
            safety_constraints: safety_constraints(),
            local_policy: local_policy(),
        };
        assert!(matches!(
            candidate.validate(),
            Err(DeviceProfileValidationError::ForbiddenPhysicalAction { .. })
        ));
    }
}

#[test]
fn rejects_ambiguous_or_unknown_bounded_action_classes() {
    for action in ["move", "motor", "fly", "navigate"] {
        let candidate = DeviceProfile {
            schema: DEVICE_PROFILE_SCHEMA.to_string(),
            kind: DeviceNodeKind::Drone,
            capabilities: vec![DeviceCapability::bounded_action(action)],
            safety_constraints: safety_constraints(),
            local_policy: local_policy(),
        };
        assert_eq!(
            candidate.validate(),
            Err(DeviceProfileValidationError::UnknownPhysicalAction {
                action: action.to_string()
            })
        );
    }
}

#[test]
fn rejects_missing_safety_and_invalid_offline_indicators() {
    let missing_safety = DeviceProfile {
        schema: DEVICE_PROFILE_SCHEMA.to_string(),
        kind: DeviceNodeKind::IndustrialDevice,
        capabilities: vec![DeviceCapability::bounded_action("pause_mission")],
        safety_constraints: vec![],
        local_policy: local_policy(),
    };
    assert_eq!(
        missing_safety.validate(),
        Err(DeviceProfileValidationError::MissingSafetyConstraints)
    );

    let offline_without_cache = DeviceProfile {
        schema: DEVICE_PROFILE_SCHEMA.to_string(),
        kind: DeviceNodeKind::EdgeAppliance,
        capabilities: vec![DeviceCapability::bounded_action("read_sensor_summary")],
        safety_constraints: safety_constraints(),
        local_policy: DeviceLocalPolicyIndicators {
            supports_local_policy_cache: false,
            supports_offline_operation: true,
            supports_local_operator_intervention: true,
            max_offline_policy_ttl_seconds: Some(120),
        },
    };
    assert_eq!(
        offline_without_cache.validate(),
        Err(DeviceProfileValidationError::OfflineRequiresLocalPolicyCache)
    );
}

#[test]
fn validates_physical_capability_documents_without_forking_capability_model() {
    let document = CapabilityDocument::new(
        vec![
            "runtime.resident".to_string(),
            physical_action_capability("dock"),
            physical_action_capability("return_to_base"),
        ],
        serde_json::json!({"device_profile_schema": DEVICE_PROFILE_SCHEMA}),
    )
    .expect("base capability document");
    validate_physical_capability_document(&document).expect("physical document valid");

    let unsafe_document = CapabilityDocument::new(
        vec![physical_action_capability("set_motor_pwm")],
        serde_json::json!({}),
    )
    .expect("base token syntax still valid");
    assert!(matches!(
        validate_physical_capability_document(&unsafe_document),
        Err(DeviceProfileValidationError::ForbiddenPhysicalAction { .. })
    ));
}
