//! Performance budget and reference-scale report contract primitives.
//!
//! This module is a bounded FND-012 seam. It defines behavior-light schemas and
//! validation for latency/throughput budget contracts, benchmark environment
//! capture, regression thresholds, and retention/backpressure actions. It does
//! not execute benchmarks, optimize runtime paths, or turn one fixture into a
//! gold pass or production performance guarantee.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Canonical schema identifier for the FND-012 performance budget contract.
pub const PERFORMANCE_BUDGET_SCHEMA_VERSION: &str = "splendor.performance_budgets.v1";
/// Evidence scope used by the initial partial FND-012 fixture.
pub const PERFORMANCE_BUDGET_EVIDENCE_SCOPE: &str = "partial_fnd_012_budget_contract_v0";

/// Non-claim markers required on the partial FND-012 budget fixture.
pub const REQUIRED_PERFORMANCE_NON_CLAIMS: &[&str] = &[
    "no_fnd_012_completion",
    "no_issue_231_completion",
    "no_issue_180_completion",
    "no_g29_pass",
    "no_g66_pass",
    "no_g68_pass",
    "no_g74_pass",
    "no_benchmark_execution",
];

/// Mandatory latency budget metric identifiers from FND-012.
pub const REQUIRED_LATENCY_BUDGET_METRICS: &[&str] = &[
    "local_event_append",
    "state_commit",
    "authority_decision",
    "gateway_preflight",
    "model_invocation_overhead",
    "percept_routing",
    "tick_admission",
];

/// Mandatory throughput/scale budget metric identifiers from FND-012.
pub const REQUIRED_THROUGHPUT_BUDGET_METRICS: &[&str] = &[
    "event_ingestion",
    "artifact_transfer",
    "scheduler_offers",
    "workload_transitions",
    "feedback_ingestion",
    "eval_fan_out",
    "one_thousand_node_simulation",
];

/// Gold cases that FND-012 requires to run under explicit SLO/resource budgets.
pub const REQUIRED_PERFORMANCE_GOLD_IDS: &[&str] = &["G29", "G66", "G68", "G74"];

/// Complete performance budget catalog fixture.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerformanceBudgetCatalog {
    /// Schema identifier. FND-012 accepts only `splendor.performance_budgets.v1`.
    pub schema_version: String,
    /// Catalog task identifier, expected to be `FND-012` for this contract.
    pub task_id: String,
    /// Evidence boundary for this fixture/report.
    pub evidence_scope: String,
    /// Explicit non-claims that prevent budget contracts being reported as pass evidence.
    #[serde(default)]
    pub non_claims: Vec<String>,
    /// Captured environment metadata for benchmark/report reproducibility.
    pub benchmark_environment: BenchmarkEnvironment,
    /// Human/machine summary of the report represented by this catalog.
    pub report_summary: PerformanceReportSummary,
    /// Latency budget records for kernel control-plane operations.
    #[serde(default)]
    pub latency_budgets: Vec<LatencyBudget>,
    /// Throughput and scale budget records for sustained control-plane work.
    #[serde(default)]
    pub throughput_budgets: Vec<ThroughputBudget>,
    /// Per-metric regression thresholds and required handling.
    #[serde(default)]
    pub regression_thresholds: Vec<RegressionThreshold>,
    /// Retention and backpressure actions that bound long-run growth.
    #[serde(default)]
    pub retention_backpressure_actions: Vec<RetentionBackpressureAction>,
    /// Explicit SLO/resource budget mappings for required gold cases.
    #[serde(default)]
    pub gold_slo_resource_budgets: Vec<GoldSloResourceBudget>,
}

impl PerformanceBudgetCatalog {
    /// Validates this budget catalog before it is used as conformance evidence.
    pub fn validate(&self) -> Result<(), PerformanceBudgetValidationError> {
        validate_performance_budget_catalog(self)
    }
}

/// Benchmark environment capture required for interpreting performance reports.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BenchmarkEnvironment {
    pub environment_id: String,
    pub captured_at: String,
    pub host_class: String,
    pub os: String,
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub memory_gib: u32,
    pub storage_backend: String,
    pub rustc_version: String,
    pub splendor_commit: String,
    pub clock_source: String,
    pub network_topology: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accelerator: Option<String>,
}

/// Whether a report contains measurements or a contract-only reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceReportStatus {
    /// Budget/report shape only; no measured benchmark result is claimed.
    BudgetContractOnly,
    /// Measurements were captured and should be validated by a benchmark harness.
    Measured,
    /// Measurements exist but are invalidated or non-comparable.
    Invalidated,
}

/// Summary for a benchmark report or reference budget contract.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PerformanceReportSummary {
    pub report_id: String,
    pub status: PerformanceReportStatus,
    pub benchmark_suite: String,
    pub measured: bool,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark_run_ref: Option<String>,
}

/// Measurement boundary for a control-plane budget.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MeasurementBoundary {
    /// True when the budget measures Splendor control-plane overhead only.
    pub kernel_control_plane_only: bool,
    /// Must be false for kernel overhead budgets; provider/model/training time is separate.
    pub provider_model_training_time_included: bool,
    /// Evidence/trace checks must not be skipped to meet a budget.
    pub evidence_checks_included: bool,
    /// Authority/gateway checks must not be skipped to meet a budget.
    pub authority_checks_included: bool,
    /// Safety checks must not be skipped where the operation can affect safety.
    pub safety_checks_included: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Latency budget for a named control-plane operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LatencyBudget {
    pub metric_id: String,
    pub description: String,
    pub max_p50_ms: f64,
    pub max_p95_ms: f64,
    pub max_p99_ms: f64,
    pub measurement_boundary: MeasurementBoundary,
}

/// Throughput or scale budget for a named control-plane operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ThroughputBudget {
    pub metric_id: String,
    pub description: String,
    pub min_rate_per_second: f64,
    pub window_seconds: u64,
    pub measurement_boundary: MeasurementBoundary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale_target: Option<ScaleTarget>,
}

/// Optional target shape for scale-oriented throughput budgets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScaleTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workloads: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sustained_seconds: Option<u64>,
}

/// Regression threshold for a named metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RegressionThreshold {
    pub metric_id: String,
    pub max_regression_percent: f64,
    pub baseline_ref: String,
    pub action_on_regression: String,
}

/// Retention/backpressure action kind for long-run bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionBackpressureKind {
    Retention,
    Backpressure,
}

/// Explicit action triggered when resource growth or queues approach a budget.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RetentionBackpressureAction {
    pub action_id: String,
    pub kind: RetentionBackpressureKind,
    pub trigger_metric_id: String,
    pub trigger: String,
    pub action: String,
    pub required_event: String,
    pub fail_closed: bool,
}

/// Current evidence status for a gold budget mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoldBudgetEvidenceStatus {
    /// The gold case has not run; budget mapping is contract evidence only.
    NotExercised,
    /// The catalog/gold source describes the case, but no implementation exists.
    SpecifiedNotImplemented,
}

/// Resource budget class for a gold case.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceBudgetKind {
    ControlPlane,
    InferenceReservation,
    Worker,
    PhysicalSafety,
    Simulation,
}

/// Bounded resource budget record. At least one numeric budget must be positive.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ResourceBudget {
    pub resource_id: String,
    pub kind: ResourceBudgetKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_mib: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_mbps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes: Option<u32>,
    pub notes: String,
}

/// SLO/resource budget mapping for a required gold case.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GoldSloResourceBudget {
    pub gold_id: String,
    pub evidence_status: GoldBudgetEvidenceStatus,
    pub slo_metric_ids: Vec<String>,
    pub resource_budgets: Vec<ResourceBudget>,
    pub notes: Vec<String>,
}

/// Structured validation failures for performance budget contracts.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum PerformanceBudgetValidationError {
    #[error("performance budget schema is required")]
    MissingSchema,
    #[error("unsupported performance budget schema: {schema}")]
    UnsupportedSchema { schema: String },
    #[error("performance budget task_id must be FND-012")]
    WrongTaskId,
    #[error("performance budget evidence_scope must be partial_fnd_012_budget_contract_v0")]
    WrongEvidenceScope,
    #[error("performance budget non_claims missing: {claim}")]
    MissingNonClaim { claim: &'static str },
    #[error("benchmark environment field {field} is required")]
    MissingEnvironmentField { field: &'static str },
    #[error("performance report summary field {field} is required")]
    MissingReportSummaryField { field: &'static str },
    #[error("performance report summary status and measured fields are inconsistent: {field}")]
    InconsistentReportSummary { field: &'static str },
    #[error("latency budget missing mandatory metric: {metric_id}")]
    MissingLatencyMetric { metric_id: &'static str },
    #[error("throughput budget missing mandatory metric: {metric_id}")]
    MissingThroughputMetric { metric_id: &'static str },
    #[error("duplicate performance metric: {metric_id}")]
    DuplicateMetric { metric_id: String },
    #[error("latency budget {metric_id} has invalid percentile bounds")]
    InvalidLatencyBudget { metric_id: String },
    #[error("throughput budget {metric_id} has invalid rate or window")]
    InvalidThroughputBudget { metric_id: String },
    #[error(
        "provider/model time must not be mixed into kernel control-plane overhead for {metric_id}"
    )]
    ProviderModelTimeMixed { metric_id: String },
    #[error("performance budget {metric_id} must include evidence checks")]
    EvidenceChecksSkipped { metric_id: String },
    #[error("performance budget {metric_id} must include authority checks")]
    AuthorityChecksSkipped { metric_id: String },
    #[error("performance budget {metric_id} must include safety checks")]
    SafetyChecksSkipped { metric_id: String },
    #[error("regression threshold missing for metric: {metric_id}")]
    MissingRegressionThreshold { metric_id: String },
    #[error("regression threshold {metric_id} is invalid")]
    InvalidRegressionThreshold { metric_id: String },
    #[error("retention/backpressure actions must include {kind}")]
    MissingRetentionBackpressureKind { kind: &'static str },
    #[error("retention/backpressure action {action_id} is invalid")]
    InvalidRetentionBackpressureAction { action_id: String },
    #[error("gold SLO/resource budget missing for {gold_id}")]
    MissingGoldBudget { gold_id: &'static str },
    #[error("gold SLO/resource budget {gold_id} is invalid")]
    InvalidGoldBudget { gold_id: String },
    #[error("gold SLO/resource budget {gold_id} references unknown metric {metric_id}")]
    UnknownGoldMetricReference { gold_id: String, metric_id: String },
}

/// Validates a performance budget catalog fixture.
pub fn validate_performance_budget_catalog(
    catalog: &PerformanceBudgetCatalog,
) -> Result<(), PerformanceBudgetValidationError> {
    validate_header(catalog)?;
    validate_environment(&catalog.benchmark_environment)?;
    validate_report_summary(&catalog.report_summary)?;

    let latency_metrics = validate_latency_budgets(&catalog.latency_budgets)?;
    let throughput_metrics = validate_throughput_budgets(&catalog.throughput_budgets)?;
    let mut known_metrics = latency_metrics;
    known_metrics.extend(throughput_metrics);

    validate_regression_thresholds(&catalog.regression_thresholds, &known_metrics)?;
    validate_retention_backpressure_actions(
        &catalog.retention_backpressure_actions,
        &known_metrics,
    )?;
    validate_gold_budgets(&catalog.gold_slo_resource_budgets, &known_metrics)?;
    Ok(())
}

fn validate_header(
    catalog: &PerformanceBudgetCatalog,
) -> Result<(), PerformanceBudgetValidationError> {
    if catalog.schema_version.trim().is_empty() {
        return Err(PerformanceBudgetValidationError::MissingSchema);
    }
    if catalog.schema_version != PERFORMANCE_BUDGET_SCHEMA_VERSION {
        return Err(PerformanceBudgetValidationError::UnsupportedSchema {
            schema: catalog.schema_version.clone(),
        });
    }
    if catalog.task_id != "FND-012" {
        return Err(PerformanceBudgetValidationError::WrongTaskId);
    }
    if catalog.evidence_scope != PERFORMANCE_BUDGET_EVIDENCE_SCOPE {
        return Err(PerformanceBudgetValidationError::WrongEvidenceScope);
    }
    for claim in REQUIRED_PERFORMANCE_NON_CLAIMS {
        if !catalog.non_claims.iter().any(|value| value == claim) {
            return Err(PerformanceBudgetValidationError::MissingNonClaim { claim });
        }
    }
    Ok(())
}

fn validate_environment(
    environment: &BenchmarkEnvironment,
) -> Result<(), PerformanceBudgetValidationError> {
    require_non_empty("environment_id", &environment.environment_id)?;
    require_non_empty("captured_at", &environment.captured_at)?;
    require_non_empty("host_class", &environment.host_class)?;
    require_non_empty("os", &environment.os)?;
    require_non_empty("cpu_model", &environment.cpu_model)?;
    require_non_empty("storage_backend", &environment.storage_backend)?;
    require_non_empty("rustc_version", &environment.rustc_version)?;
    require_non_empty("splendor_commit", &environment.splendor_commit)?;
    require_non_empty("clock_source", &environment.clock_source)?;
    require_non_empty("network_topology", &environment.network_topology)?;
    if environment.cpu_cores == 0 {
        return Err(PerformanceBudgetValidationError::MissingEnvironmentField {
            field: "cpu_cores",
        });
    }
    if environment.memory_gib == 0 {
        return Err(PerformanceBudgetValidationError::MissingEnvironmentField {
            field: "memory_gib",
        });
    }
    Ok(())
}

fn validate_report_summary(
    summary: &PerformanceReportSummary,
) -> Result<(), PerformanceBudgetValidationError> {
    if summary.report_id.trim().is_empty() {
        return Err(
            PerformanceBudgetValidationError::MissingReportSummaryField { field: "report_id" },
        );
    }
    if summary.benchmark_suite.trim().is_empty() {
        return Err(
            PerformanceBudgetValidationError::MissingReportSummaryField {
                field: "benchmark_suite",
            },
        );
    }
    if summary.summary.trim().is_empty() {
        return Err(
            PerformanceBudgetValidationError::MissingReportSummaryField { field: "summary" },
        );
    }
    match summary.status {
        PerformanceReportStatus::BudgetContractOnly if summary.measured => {
            return Err(
                PerformanceBudgetValidationError::InconsistentReportSummary {
                    field: "budget_contract_only_requires_measured_false",
                },
            );
        }
        PerformanceReportStatus::Measured if !summary.measured => {
            return Err(
                PerformanceBudgetValidationError::InconsistentReportSummary {
                    field: "measured_status_requires_measured_true",
                },
            );
        }
        PerformanceReportStatus::Measured
            if summary
                .benchmark_run_ref
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty() =>
        {
            return Err(
                PerformanceBudgetValidationError::MissingReportSummaryField {
                    field: "benchmark_run_ref",
                },
            );
        }
        _ => {}
    }
    Ok(())
}

fn validate_latency_budgets(
    budgets: &[LatencyBudget],
) -> Result<BTreeSet<String>, PerformanceBudgetValidationError> {
    let mut metrics = BTreeSet::new();
    for budget in budgets {
        let metric_id = budget.metric_id.trim();
        if metric_id.is_empty() || !metrics.insert(metric_id.to_string()) {
            return Err(PerformanceBudgetValidationError::DuplicateMetric {
                metric_id: budget.metric_id.clone(),
            });
        }
        if budget.description.trim().is_empty()
            || !is_finite_positive(budget.max_p50_ms)
            || !is_finite_positive(budget.max_p95_ms)
            || !is_finite_positive(budget.max_p99_ms)
            || budget.max_p95_ms < budget.max_p50_ms
            || budget.max_p99_ms < budget.max_p95_ms
        {
            return Err(PerformanceBudgetValidationError::InvalidLatencyBudget {
                metric_id: budget.metric_id.clone(),
            });
        }
        validate_measurement_boundary(metric_id, &budget.measurement_boundary)?;
    }
    for required in REQUIRED_LATENCY_BUDGET_METRICS {
        if !metrics.contains(*required) {
            return Err(PerformanceBudgetValidationError::MissingLatencyMetric {
                metric_id: required,
            });
        }
    }
    Ok(metrics)
}

fn validate_throughput_budgets(
    budgets: &[ThroughputBudget],
) -> Result<BTreeSet<String>, PerformanceBudgetValidationError> {
    let mut metrics = BTreeSet::new();
    for budget in budgets {
        let metric_id = budget.metric_id.trim();
        if metric_id.is_empty() || !metrics.insert(metric_id.to_string()) {
            return Err(PerformanceBudgetValidationError::DuplicateMetric {
                metric_id: budget.metric_id.clone(),
            });
        }
        if budget.description.trim().is_empty()
            || !is_finite_positive(budget.min_rate_per_second)
            || budget.window_seconds == 0
        {
            return Err(PerformanceBudgetValidationError::InvalidThroughputBudget {
                metric_id: budget.metric_id.clone(),
            });
        }
        validate_measurement_boundary(metric_id, &budget.measurement_boundary)?;
    }
    for required in REQUIRED_THROUGHPUT_BUDGET_METRICS {
        if !metrics.contains(*required) {
            return Err(PerformanceBudgetValidationError::MissingThroughputMetric {
                metric_id: required,
            });
        }
    }
    Ok(metrics)
}

fn validate_measurement_boundary(
    metric_id: &str,
    boundary: &MeasurementBoundary,
) -> Result<(), PerformanceBudgetValidationError> {
    if !boundary.kernel_control_plane_only || boundary.provider_model_training_time_included {
        return Err(PerformanceBudgetValidationError::ProviderModelTimeMixed {
            metric_id: metric_id.to_string(),
        });
    }
    if !boundary.evidence_checks_included {
        return Err(PerformanceBudgetValidationError::EvidenceChecksSkipped {
            metric_id: metric_id.to_string(),
        });
    }
    if !boundary.authority_checks_included {
        return Err(PerformanceBudgetValidationError::AuthorityChecksSkipped {
            metric_id: metric_id.to_string(),
        });
    }
    if !boundary.safety_checks_included {
        return Err(PerformanceBudgetValidationError::SafetyChecksSkipped {
            metric_id: metric_id.to_string(),
        });
    }
    Ok(())
}

fn validate_regression_thresholds(
    thresholds: &[RegressionThreshold],
    known_metrics: &BTreeSet<String>,
) -> Result<(), PerformanceBudgetValidationError> {
    let mut threshold_metrics = BTreeSet::new();
    for threshold in thresholds {
        if threshold.metric_id.trim().is_empty()
            || !is_finite_positive(threshold.max_regression_percent)
            || threshold.baseline_ref.trim().is_empty()
            || threshold.action_on_regression.trim().is_empty()
        {
            return Err(
                PerformanceBudgetValidationError::InvalidRegressionThreshold {
                    metric_id: threshold.metric_id.clone(),
                },
            );
        }
        threshold_metrics.insert(threshold.metric_id.clone());
    }
    for metric_id in known_metrics {
        if !threshold_metrics.contains(metric_id) {
            return Err(
                PerformanceBudgetValidationError::MissingRegressionThreshold {
                    metric_id: metric_id.clone(),
                },
            );
        }
    }
    Ok(())
}

fn validate_retention_backpressure_actions(
    actions: &[RetentionBackpressureAction],
    known_metrics: &BTreeSet<String>,
) -> Result<(), PerformanceBudgetValidationError> {
    let mut has_retention = false;
    let mut has_backpressure = false;
    for action in actions {
        if action.action_id.trim().is_empty()
            || action.trigger_metric_id.trim().is_empty()
            || !known_metrics.contains(&action.trigger_metric_id)
            || action.trigger.trim().is_empty()
            || action.action.trim().is_empty()
            || action.required_event.trim().is_empty()
            || !action.fail_closed
        {
            return Err(
                PerformanceBudgetValidationError::InvalidRetentionBackpressureAction {
                    action_id: action.action_id.clone(),
                },
            );
        }
        match action.kind {
            RetentionBackpressureKind::Retention => has_retention = true,
            RetentionBackpressureKind::Backpressure => has_backpressure = true,
        }
    }
    if !has_retention {
        return Err(
            PerformanceBudgetValidationError::MissingRetentionBackpressureKind {
                kind: "retention",
            },
        );
    }
    if !has_backpressure {
        return Err(
            PerformanceBudgetValidationError::MissingRetentionBackpressureKind {
                kind: "backpressure",
            },
        );
    }
    Ok(())
}

fn validate_gold_budgets(
    budgets: &[GoldSloResourceBudget],
    known_metrics: &BTreeSet<String>,
) -> Result<(), PerformanceBudgetValidationError> {
    let mut gold_ids = BTreeSet::new();
    for budget in budgets {
        if budget.gold_id.trim().is_empty() || !gold_ids.insert(budget.gold_id.clone()) {
            return Err(PerformanceBudgetValidationError::InvalidGoldBudget {
                gold_id: budget.gold_id.clone(),
            });
        }
        if !matches!(
            budget.evidence_status,
            GoldBudgetEvidenceStatus::NotExercised
        ) || budget.slo_metric_ids.is_empty()
            || budget.resource_budgets.is_empty()
            || budget.notes.is_empty()
        {
            return Err(PerformanceBudgetValidationError::InvalidGoldBudget {
                gold_id: budget.gold_id.clone(),
            });
        }
        for metric_id in &budget.slo_metric_ids {
            if !known_metrics.contains(metric_id) {
                return Err(
                    PerformanceBudgetValidationError::UnknownGoldMetricReference {
                        gold_id: budget.gold_id.clone(),
                        metric_id: metric_id.clone(),
                    },
                );
            }
        }
        for resource_budget in &budget.resource_budgets {
            validate_resource_budget(&budget.gold_id, resource_budget)?;
        }
    }
    for required in REQUIRED_PERFORMANCE_GOLD_IDS {
        if !gold_ids.contains(*required) {
            return Err(PerformanceBudgetValidationError::MissingGoldBudget { gold_id: required });
        }
    }
    Ok(())
}

fn validate_resource_budget(
    gold_id: &str,
    budget: &ResourceBudget,
) -> Result<(), PerformanceBudgetValidationError> {
    if let Some(value) = budget.cpu_cores {
        if !is_finite_positive(value) {
            return Err(PerformanceBudgetValidationError::InvalidGoldBudget {
                gold_id: gold_id.to_string(),
            });
        }
    }
    if let Some(value) = budget.network_mbps {
        if !is_finite_positive(value) {
            return Err(PerformanceBudgetValidationError::InvalidGoldBudget {
                gold_id: gold_id.to_string(),
            });
        }
    }
    for value in [budget.memory_mib, budget.storage_mib]
        .into_iter()
        .flatten()
    {
        if value == 0 {
            return Err(PerformanceBudgetValidationError::InvalidGoldBudget {
                gold_id: gold_id.to_string(),
            });
        }
    }
    if matches!(budget.max_nodes, Some(0)) {
        return Err(PerformanceBudgetValidationError::InvalidGoldBudget {
            gold_id: gold_id.to_string(),
        });
    }
    let has_positive = budget.cpu_cores.is_some()
        || budget.memory_mib.is_some()
        || budget.storage_mib.is_some()
        || budget.network_mbps.is_some()
        || budget.max_nodes.is_some();
    if budget.resource_id.trim().is_empty() || budget.notes.trim().is_empty() || !has_positive {
        return Err(PerformanceBudgetValidationError::InvalidGoldBudget {
            gold_id: gold_id.to_string(),
        });
    }
    Ok(())
}

fn is_finite_positive(value: f64) -> bool {
    value.is_finite() && value > 0.0
}

fn require_non_empty(
    field: &'static str,
    value: &str,
) -> Result<(), PerformanceBudgetValidationError> {
    if value.trim().is_empty() {
        Err(PerformanceBudgetValidationError::MissingEnvironmentField { field })
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/unit/performance_budgets_tests.rs"]
mod tests;
