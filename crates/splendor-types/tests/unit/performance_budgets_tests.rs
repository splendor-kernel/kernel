use super::*;

fn boundary() -> MeasurementBoundary {
    MeasurementBoundary {
        kernel_control_plane_only: true,
        provider_model_training_time_included: false,
        evidence_checks_included: true,
        authority_checks_included: true,
        safety_checks_included: true,
        notes: Some(
            "kernel control-plane overhead only; provider/model/training time measured separately"
                .to_string(),
        ),
    }
}

fn latency(metric_id: &str, max_p99_ms: f64) -> LatencyBudget {
    LatencyBudget {
        metric_id: metric_id.to_string(),
        description: format!("{metric_id} latency budget"),
        max_p50_ms: max_p99_ms / 4.0,
        max_p95_ms: max_p99_ms / 2.0,
        max_p99_ms,
        measurement_boundary: boundary(),
    }
}

fn throughput(metric_id: &str, min_rate_per_second: f64) -> ThroughputBudget {
    ThroughputBudget {
        metric_id: metric_id.to_string(),
        description: format!("{metric_id} throughput budget"),
        min_rate_per_second,
        window_seconds: 60,
        measurement_boundary: boundary(),
        scale_target: None,
    }
}

fn threshold(metric_id: &str) -> RegressionThreshold {
    RegressionThreshold {
        metric_id: metric_id.to_string(),
        max_regression_percent: 10.0,
        baseline_ref: "artifact:perf-baseline.reference-v0".to_string(),
        action_on_regression: "block release gate and require benchmark triage".to_string(),
    }
}

fn resource(resource_id: &str, kind: ResourceBudgetKind) -> ResourceBudget {
    ResourceBudget {
        resource_id: resource_id.to_string(),
        kind,
        cpu_cores: Some(1.0),
        memory_mib: Some(512),
        storage_mib: Some(1024),
        network_mbps: Some(10.0),
        max_nodes: None,
        notes: "reference resource budget, not measured capacity evidence".to_string(),
    }
}

fn gold(gold_id: &str, metrics: &[&str], resources: Vec<ResourceBudget>) -> GoldSloResourceBudget {
    GoldSloResourceBudget {
        gold_id: gold_id.to_string(),
        evidence_status: GoldBudgetEvidenceStatus::NotExercised,
        slo_metric_ids: metrics.iter().map(|metric| metric.to_string()).collect(),
        resource_budgets: resources,
        notes: vec!["budget mapping only; gold case remains not_exercised".to_string()],
    }
}

fn valid_catalog() -> PerformanceBudgetCatalog {
    let latency_budgets = REQUIRED_LATENCY_BUDGET_METRICS
        .iter()
        .enumerate()
        .map(|(index, metric)| latency(metric, 10.0 + index as f64))
        .collect::<Vec<_>>();
    let throughput_budgets = REQUIRED_THROUGHPUT_BUDGET_METRICS
        .iter()
        .enumerate()
        .map(|(index, metric)| throughput(metric, 100.0 + index as f64))
        .collect::<Vec<_>>();
    let regression_thresholds = REQUIRED_LATENCY_BUDGET_METRICS
        .iter()
        .chain(REQUIRED_THROUGHPUT_BUDGET_METRICS.iter())
        .map(|metric| threshold(metric))
        .collect();

    PerformanceBudgetCatalog {
        schema_version: PERFORMANCE_BUDGET_SCHEMA_VERSION.to_string(),
        task_id: "FND-012".to_string(),
        evidence_scope: PERFORMANCE_BUDGET_EVIDENCE_SCOPE.to_string(),
        non_claims: REQUIRED_PERFORMANCE_NON_CLAIMS
            .iter()
            .map(|claim| claim.to_string())
            .collect(),
        benchmark_environment: BenchmarkEnvironment {
            environment_id: "perf-reference-contract-local".to_string(),
            captured_at: "2026-06-22T12:00:00Z".to_string(),
            host_class: "developer_local_reference".to_string(),
            os: "darwin-arm64".to_string(),
            cpu_model: "reference-cpu".to_string(),
            cpu_cores: 8,
            memory_gib: 32,
            storage_backend: "local-ssd".to_string(),
            rustc_version: "captured-by-benchmark-runner".to_string(),
            splendor_commit: "captured-by-benchmark-runner".to_string(),
            clock_source: "monotonic".to_string(),
            network_topology: "loopback-only".to_string(),
            accelerator: None,
        },
        report_summary: PerformanceReportSummary {
            report_id: "perf-budget-reference-v0".to_string(),
            status: PerformanceReportStatus::BudgetContractOnly,
            benchmark_suite: "fnd-012-reference-budget-contract".to_string(),
            measured: false,
            summary: "Reference budget contract only; no benchmark executed".to_string(),
            benchmark_run_ref: None,
        },
        latency_budgets,
        throughput_budgets,
        regression_thresholds,
        retention_backpressure_actions: vec![
            RetentionBackpressureAction {
                action_id: "retain_event_log_by_budget".to_string(),
                kind: RetentionBackpressureKind::Retention,
                trigger_metric_id: "event_ingestion".to_string(),
                trigger: "storage growth exceeds configured retention budget".to_string(),
                action: "compact/archive old event partitions without dropping required evidence"
                    .to_string(),
                required_event: "performance.retention_action_required".to_string(),
                fail_closed: true,
            },
            RetentionBackpressureAction {
                action_id: "apply_inbox_backpressure".to_string(),
                kind: RetentionBackpressureKind::Backpressure,
                trigger_metric_id: "percept_routing".to_string(),
                trigger: "bounded inbox or routing queue approaches configured limit".to_string(),
                action:
                    "throttle admission and preserve trace/evidence for dropped or delayed work"
                        .to_string(),
                required_event: "performance.backpressure_applied".to_string(),
                fail_closed: true,
            },
        ],
        gold_slo_resource_budgets: vec![
            gold(
                "G29",
                &[
                    "local_event_append",
                    "percept_routing",
                    "tick_admission",
                    "event_ingestion",
                ],
                vec![resource(
                    "g29_agent_control_plane",
                    ResourceBudgetKind::ControlPlane,
                )],
            ),
            gold(
                "G66",
                &[
                    "model_invocation_overhead",
                    "scheduler_offers",
                    "workload_transitions",
                ],
                vec![resource(
                    "g66_inference_reservation",
                    ResourceBudgetKind::InferenceReservation,
                )],
            ),
            gold(
                "G68",
                &[
                    "scheduler_offers",
                    "workload_transitions",
                    "one_thousand_node_simulation",
                ],
                vec![ResourceBudget {
                    max_nodes: Some(1000),
                    ..resource("g68_simulation_fleet", ResourceBudgetKind::Simulation)
                }],
            ),
            gold(
                "G74",
                &["gateway_preflight", "authority_decision", "tick_admission"],
                vec![resource(
                    "g74_physical_safety_reservation",
                    ResourceBudgetKind::PhysicalSafety,
                )],
            ),
        ],
    }
}

#[test]
fn validates_complete_performance_budget_catalog() {
    valid_catalog().validate().expect("valid budget catalog");
}

#[test]
fn repository_fixture_deserializes_and_validates() {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("docs/spec/0.2/performance-budgets.json");
    let bytes = std::fs::read(&fixture_path).expect("read performance budget fixture");
    let catalog: PerformanceBudgetCatalog =
        serde_json::from_slice(&bytes).expect("deserialize fixture");
    catalog.validate().expect("valid repository fixture");
}

#[test]
fn rejects_missing_mandatory_latency_metric() {
    let mut catalog = valid_catalog();
    catalog
        .latency_budgets
        .retain(|budget| budget.metric_id != "state_commit");
    assert!(matches!(
        catalog.validate(),
        Err(PerformanceBudgetValidationError::MissingLatencyMetric {
            metric_id: "state_commit"
        })
    ));
}

#[test]
fn rejects_provider_time_mixed_into_kernel_overhead() {
    let mut catalog = valid_catalog();
    catalog.latency_budgets[0]
        .measurement_boundary
        .provider_model_training_time_included = true;
    assert!(matches!(
        catalog.validate(),
        Err(PerformanceBudgetValidationError::ProviderModelTimeMixed { metric_id })
            if metric_id == "local_event_append"
    ));
}

#[test]
fn report_summary_status_must_match_measured_evidence() {
    let mut contract_only = valid_catalog();
    contract_only.report_summary.measured = true;
    assert!(matches!(
        contract_only.validate(),
        Err(
            PerformanceBudgetValidationError::InconsistentReportSummary {
                field: "budget_contract_only_requires_measured_false"
            }
        )
    ));

    let mut measured_false = valid_catalog();
    measured_false.report_summary.status = PerformanceReportStatus::Measured;
    measured_false.report_summary.measured = false;
    measured_false.report_summary.benchmark_run_ref = Some("artifact:benchmark-run".to_string());
    assert!(matches!(
        measured_false.validate(),
        Err(
            PerformanceBudgetValidationError::InconsistentReportSummary {
                field: "measured_status_requires_measured_true"
            }
        )
    ));

    let mut missing_ref = valid_catalog();
    missing_ref.report_summary.status = PerformanceReportStatus::Measured;
    missing_ref.report_summary.measured = true;
    missing_ref.report_summary.benchmark_run_ref = None;
    assert!(matches!(
        missing_ref.validate(),
        Err(
            PerformanceBudgetValidationError::MissingReportSummaryField {
                field: "benchmark_run_ref"
            }
        )
    ));

    let mut measured = valid_catalog();
    measured.report_summary.status = PerformanceReportStatus::Measured;
    measured.report_summary.measured = true;
    measured.report_summary.benchmark_run_ref = Some("artifact:benchmark-run".to_string());
    measured
        .validate()
        .expect("measured report summary is valid with run ref");
}

#[test]
fn rejects_non_finite_and_non_positive_f64_budget_values() {
    let mut nan_latency = valid_catalog();
    nan_latency.latency_budgets[0].max_p50_ms = f64::NAN;
    assert!(matches!(
        nan_latency.validate(),
        Err(PerformanceBudgetValidationError::InvalidLatencyBudget { metric_id })
            if metric_id == "local_event_append"
    ));

    let mut infinite_throughput = valid_catalog();
    infinite_throughput.throughput_budgets[0].min_rate_per_second = f64::INFINITY;
    assert!(matches!(
        infinite_throughput.validate(),
        Err(PerformanceBudgetValidationError::InvalidThroughputBudget { metric_id })
            if metric_id == "event_ingestion"
    ));

    let mut nan_threshold = valid_catalog();
    nan_threshold.regression_thresholds[0].max_regression_percent = f64::NAN;
    assert!(matches!(
        nan_threshold.validate(),
        Err(PerformanceBudgetValidationError::InvalidRegressionThreshold { metric_id })
            if metric_id == "local_event_append"
    ));

    let mut infinite_resource = valid_catalog();
    infinite_resource.gold_slo_resource_budgets[0].resource_budgets[0].cpu_cores =
        Some(f64::NEG_INFINITY);
    assert!(matches!(
        infinite_resource.validate(),
        Err(PerformanceBudgetValidationError::InvalidGoldBudget { gold_id })
            if gold_id == "G29"
    ));
}

#[test]
fn rejects_missing_environment_capture() {
    let mut catalog = valid_catalog();
    catalog.benchmark_environment.rustc_version.clear();
    assert!(matches!(
        catalog.validate(),
        Err(PerformanceBudgetValidationError::MissingEnvironmentField {
            field: "rustc_version"
        })
    ));
}

#[test]
fn rejects_missing_regression_threshold() {
    let mut catalog = valid_catalog();
    catalog
        .regression_thresholds
        .retain(|threshold| threshold.metric_id != "gateway_preflight");
    assert!(matches!(
        catalog.validate(),
        Err(PerformanceBudgetValidationError::MissingRegressionThreshold { metric_id })
            if metric_id == "gateway_preflight"
    ));
}

#[test]
fn rejects_missing_retention_or_backpressure_action() {
    let mut catalog = valid_catalog();
    catalog
        .retention_backpressure_actions
        .retain(|action| action.kind != RetentionBackpressureKind::Retention);
    assert!(matches!(
        catalog.validate(),
        Err(
            PerformanceBudgetValidationError::MissingRetentionBackpressureKind {
                kind: "retention"
            }
        )
    ));
}

#[test]
fn rejects_missing_gold_budget_mapping() {
    let mut catalog = valid_catalog();
    catalog
        .gold_slo_resource_budgets
        .retain(|budget| budget.gold_id != "G68");
    assert!(matches!(
        catalog.validate(),
        Err(PerformanceBudgetValidationError::MissingGoldBudget { gold_id: "G68" })
    ));
}
