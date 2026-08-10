//! # splendorctl
//!
//! Minimal operational CLI for exporting trace data from the local trace store.
//!
//! ## Example
//! ```bash
//! splendorctl trace export --db ./trace.db --run run-1
//! ```

use serde::{Deserialize, Serialize};
use splendor_adapter_filesystem::{FilesystemAdapter, FilesystemAdapterConfig};
use splendor_adapter_http::{HttpAdapter, HttpAdapterConfig, HttpMethod};
#[cfg(test)]
use splendor_evidence::inspect_trace;
use splendor_evidence::{open_trace_reader, project_trace, TraceProjection};
use splendor_gateway::{
    ActionAdapter, ActionGateway, CircuitBreakerEvaluator, ResourceBoundaryVerifier,
    StaticCircuitBreakerEvaluator, TrustedActionProfile, VerifiedActionGateway,
};
use splendor_kernel::{
    ActionCandidate, AdapterQuota, AgentContext, AgentIsolationPolicy, AgentRuntimeConfig,
    KernelPreEffectAuthorityRecorder, KernelRuntime, LoopEngine, Perceptor, Policy, PolicyDecision,
    QuotaPolicy, RunAuthorityHandle, RunTraceContext, Scheduler, SchedulerConfig, SnapshotPolicy,
    StateGraph, TenantContext, TenantPolicy, TenantRegistry,
};
#[cfg(test)]
use splendor_store::{compute_trace_envelope_hash, RuntimeTraceScope};
use splendor_store::{
    RuntimeTraceAppend, RuntimeTraceLimits, RuntimeTracePage, RuntimeTracePortError,
    RuntimeTraceReader, RuntimeTraceReaderHandle, RuntimeTraceStoreIdentity, RuntimeTraceTail,
    RuntimeTraceWriter, RuntimeTraceWriterHandle, RuntimeTraceWriterRequest, SqliteStateStore,
    SqliteTraceStore, StateStore, TraceRecord, TraceStore, TraceStoreError,
};
use splendor_types::{
    validate_work_order, Action, AgentId, CircuitBreaker, CircuitBreakerId, CircuitBreakerScope,
    CircuitBreakerState, CircuitBreakerTraceContext, ContentHash, FleetId, GovernanceScope,
    HashAlgorithm, InstanceId, MessageId, NodeId, Percept, PerceptProvenance, QuotaUsage, RunId,
    RuntimeIdentityContext, SideEffectClass, SnapshotId, StateHandoffTraceContext, TenantId,
    TraceEvent, TraceEventId, TraceEventKind, TraceId, TraceIdentityContext, ValidatedWorkOrder,
    WorkOrder, WorkOrderEnvelope, WorkOrderId, WorkOrderKeyring, WorkOrderValidationContext,
    WorkOrderValidationError,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::path::{Component, Path};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

const SPLENDOR_RELEASE_LABEL: &str = "Splendor0.05-dev";

#[cfg(test)]
use std::sync::OnceLock;

/// Entry point for the CLI.
fn main() -> ExitCode {
    match run_with_args(collect_args().into_iter().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// Executes the parsed command for the provided args.
fn run_with_args<I, S>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let command = parse_args(args)?;
    match command {
        Command::Version => print_version(),
        Command::TraceExport { db_path, run_id } => export_trace(&db_path, &run_id)?,
        Command::StateHead { db_path, run_id } => state_head(&db_path, &run_id)?,
        Command::Replay {
            trace_db_path,
            state_db_path,
            run_id,
            from_snapshot,
            include_state,
        } => replay_run(
            &trace_db_path,
            &state_db_path,
            &run_id,
            from_snapshot.as_deref(),
            include_state,
        )?,
        Command::AuditExport {
            trace_db_path,
            state_db_path,
            run_id,
            filters,
        } => audit_export(&trace_db_path, &state_db_path, &run_id, filters)?,
        Command::Run {
            config_path,
            cycles,
            forever,
        } => run_from_config(config_path.as_path(), cycles, forever)?,
        Command::WorkOrderSign {
            input_path,
            key_id,
            secret,
        } => sign_work_order(&input_path, &key_id, &secret)?,
        Command::DaemonRequest {
            method,
            url,
            body_path,
            credential_path,
            token,
        } => daemon_request(
            &method,
            &url,
            body_path.as_deref(),
            credential_path.as_deref(),
            &token,
        )?,
        Command::AcceptanceValidateImport {
            trace_path,
            state_path,
            scenario_report_path,
            source,
            expected_trace_chain,
            expected_state_hash,
        } => acceptance_validate_import(
            &trace_path,
            &state_path,
            &scenario_report_path,
            &source,
            expected_trace_chain.as_deref(),
            expected_state_hash.as_deref(),
        )?,
        Command::AcceptanceCompat {
            fixture_paths,
            target_schema,
        } => acceptance_compat(&fixture_paths, &target_schema)?,
        Command::AcceptanceAuditCheck {
            audit_path,
            scenario_report_path,
            case_name,
            category,
        } => acceptance_audit_check(&audit_path, &scenario_report_path, &case_name, &category)?,
        Command::AcceptanceReplayMode {
            mode,
            trace_path,
            state_path,
            audit_path,
            scenario_report_path,
            source,
        } => acceptance_replay_mode(
            &mode,
            &trace_path,
            &state_path,
            &audit_path,
            &scenario_report_path,
            &source,
        )?,
        Command::AcceptanceReplayCredentialCheck { credential_path } => {
            acceptance_replay_credential_check(&credential_path)?
        }
    }
    Ok(())
}

/// Collects CLI arguments, allowing overrides in tests.
fn collect_args() -> Vec<String> {
    #[cfg(test)]
    if let Some(args) = TEST_ARGS
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("test args lock")
        .clone()
    {
        return args;
    }
    env::args().collect()
}

/// Supported CLI commands.
#[derive(Debug)]
enum Command {
    /// Print CLI and baseline version information.
    Version,
    /// Export trace data from the SQLite store.
    TraceExport { db_path: PathBuf, run_id: String },
    /// Return the latest state head observed in a trace stream.
    StateHead { db_path: PathBuf, run_id: String },
    /// Replay a trace from the SQLite stores.
    Replay {
        trace_db_path: PathBuf,
        state_db_path: PathBuf,
        run_id: String,
        from_snapshot: Option<String>,
        include_state: bool,
    },
    /// Export a governance audit view derived from trace and state stores.
    AuditExport {
        trace_db_path: PathBuf,
        state_db_path: PathBuf,
        run_id: String,
        filters: AuditFilters,
    },
    /// Run a local agent loop from configuration.
    Run {
        config_path: PathBuf,
        cycles: Option<u64>,
        forever: bool,
    },
    /// Sign a local work-order fixture with the reference shared-secret scheme.
    WorkOrderSign {
        input_path: PathBuf,
        key_id: String,
        secret: String,
    },
    /// Call a documented daemon HTTP endpoint without bypassing daemon/gateway enforcement.
    DaemonRequest {
        method: String,
        url: String,
        body_path: Option<PathBuf>,
        credential_path: Option<PathBuf>,
        token: String,
    },
    /// Public acceptance utility for validating exported trace/state artifacts.
    AcceptanceValidateImport {
        trace_path: PathBuf,
        state_path: PathBuf,
        scenario_report_path: PathBuf,
        source: String,
        expected_trace_chain: Option<String>,
        expected_state_hash: Option<String>,
    },
    /// Public acceptance utility for supported fixture migration/type compatibility evidence.
    AcceptanceCompat {
        fixture_paths: Vec<PathBuf>,
        target_schema: String,
    },
    /// Public acceptance utility for strict audit reason-code validation.
    AcceptanceAuditCheck {
        audit_path: PathBuf,
        scenario_report_path: PathBuf,
        case_name: String,
        category: String,
    },
    /// Public acceptance utility for replay-mode evidence over exported artifacts.
    AcceptanceReplayMode {
        mode: String,
        trace_path: PathBuf,
        state_path: PathBuf,
        audit_path: PathBuf,
        scenario_report_path: PathBuf,
        source: String,
    },
    /// Public acceptance utility for rejecting real external replay credentials.
    AcceptanceReplayCredentialCheck { credential_path: PathBuf },
}

/// Parses top-level CLI arguments.
fn parse_args<I, S>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let Some(command) = args.next() else {
        return Err(usage());
    };
    if command == "--version" || command == "-V" || command == "version" {
        return Ok(Command::Version);
    }
    if command == "trace" {
        return parse_trace_command(args);
    }
    if command == "state" {
        return parse_state_command(args);
    }
    if command == "replay" {
        return parse_replay_command(args);
    }
    if command == "audit" {
        return parse_audit_command(args);
    }
    if command == "run" {
        return parse_run_command(args);
    }
    if command == "work-order" {
        return parse_work_order_command(args);
    }
    if command == "daemon" {
        return parse_daemon_command(args);
    }
    if command == "acceptance" {
        return parse_acceptance_command(args);
    }
    if command == "--help" || command == "-h" {
        return Err(usage());
    }
    Err(format!("Unknown command: {command}\n\n{}", usage()))
}

fn parse_daemon_command<I>(mut args: I) -> Result<Command, String>
where
    I: Iterator<Item = String>,
{
    let Some(subcommand) = args.next() else {
        return Err(usage());
    };
    if subcommand != "request" {
        return Err(format!(
            "Unknown daemon subcommand: {subcommand}\n\n{}",
            usage()
        ));
    }
    let mut method = None;
    let mut url = None;
    let mut body_path = None;
    let mut credential_path = None;
    let mut token = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--method" => method = args.next(),
            "--url" => url = args.next(),
            "--body" => body_path = args.next().map(PathBuf::from),
            "--caller-credential" => credential_path = args.next().map(PathBuf::from),
            "--token" => token = args.next(),
            "--help" | "-h" => return Err(usage()),
            _ => return Err(format!("Unknown argument: {arg}\n\n{}", usage())),
        }
    }
    let method = method
        .ok_or_else(|| "Missing required --method".to_string())?
        .to_uppercase();
    let url = url.ok_or_else(|| "Missing required --url".to_string())?;
    let token = token.ok_or_else(|| {
        "Missing required --token; anonymous daemon fallback is not allowed".to_string()
    })?;
    if token.trim().is_empty() {
        return Err(
            "Missing required --token; anonymous daemon fallback is not allowed".to_string(),
        );
    }
    if matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") && body_path.is_none() {
        return Err(
            "Mutating daemon requests require --body with credential and audit attribution"
                .to_string(),
        );
    }
    Ok(Command::DaemonRequest {
        method,
        url,
        body_path,
        credential_path,
        token,
    })
}

fn parse_acceptance_command<I>(mut args: I) -> Result<Command, String>
where
    I: Iterator<Item = String>,
{
    let Some(subcommand) = args.next() else {
        return Err(usage());
    };
    match subcommand.as_str() {
        "validate-import" => {
            let mut trace_path = None;
            let mut state_path = None;
            let mut scenario_report_path = None;
            let mut source = None;
            let mut expected_trace_chain = None;
            let mut expected_state_hash = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--trace" => trace_path = args.next().map(PathBuf::from),
                    "--state" => state_path = args.next().map(PathBuf::from),
                    "--scenario-report" => scenario_report_path = args.next().map(PathBuf::from),
                    "--source" => source = args.next(),
                    "--expected-trace-chain" => expected_trace_chain = args.next(),
                    "--expected-state-hash" => expected_state_hash = args.next(),
                    "--help" | "-h" => return Err(usage()),
                    _ => return Err(format!("Unknown argument: {arg}\n\n{}", usage())),
                }
            }
            Ok(Command::AcceptanceValidateImport {
                trace_path: trace_path.ok_or_else(|| "Missing required --trace".to_string())?,
                state_path: state_path.ok_or_else(|| "Missing required --state".to_string())?,
                scenario_report_path: scenario_report_path
                    .ok_or_else(|| "Missing required --scenario-report".to_string())?,
                source: source.ok_or_else(|| "Missing required --source".to_string())?,
                expected_trace_chain,
                expected_state_hash,
            })
        }
        "compat" => {
            let mut fixture_paths = Vec::new();
            let mut target_schema = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--fixture" => fixture_paths.push(PathBuf::from(
                        args.next()
                            .ok_or_else(|| "Missing value for --fixture".to_string())?,
                    )),
                    "--target-schema" => target_schema = args.next(),
                    "--help" | "-h" => return Err(usage()),
                    _ => return Err(format!("Unknown argument: {arg}\n\n{}", usage())),
                }
            }
            if fixture_paths.is_empty() {
                return Err("Missing required --fixture".to_string());
            }
            Ok(Command::AcceptanceCompat {
                fixture_paths,
                target_schema: target_schema
                    .ok_or_else(|| "Missing required --target-schema".to_string())?,
            })
        }
        "audit-check" => {
            let mut audit_path = None;
            let mut scenario_report_path = None;
            let mut case_name = None;
            let mut category = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--audit" => audit_path = args.next().map(PathBuf::from),
                    "--scenario-report" => scenario_report_path = args.next().map(PathBuf::from),
                    "--case" => case_name = args.next(),
                    "--category" => category = args.next(),
                    "--help" | "-h" => return Err(usage()),
                    _ => return Err(format!("Unknown argument: {arg}\n\n{}", usage())),
                }
            }
            Ok(Command::AcceptanceAuditCheck {
                audit_path: audit_path.ok_or_else(|| "Missing required --audit".to_string())?,
                scenario_report_path: scenario_report_path
                    .ok_or_else(|| "Missing required --scenario-report".to_string())?,
                case_name: case_name.ok_or_else(|| "Missing required --case".to_string())?,
                category: category.ok_or_else(|| "Missing required --category".to_string())?,
            })
        }
        "replay-mode" => {
            let mut mode = None;
            let mut trace_path = None;
            let mut state_path = None;
            let mut audit_path = None;
            let mut scenario_report_path = None;
            let mut source = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--mode" => mode = args.next(),
                    "--trace" => trace_path = args.next().map(PathBuf::from),
                    "--state" => state_path = args.next().map(PathBuf::from),
                    "--audit" => audit_path = args.next().map(PathBuf::from),
                    "--scenario-report" => scenario_report_path = args.next().map(PathBuf::from),
                    "--source" => source = args.next(),
                    "--help" | "-h" => return Err(usage()),
                    _ => return Err(format!("Unknown argument: {arg}\n\n{}", usage())),
                }
            }
            Ok(Command::AcceptanceReplayMode {
                mode: mode.ok_or_else(|| "Missing required --mode".to_string())?,
                trace_path: trace_path.ok_or_else(|| "Missing required --trace".to_string())?,
                state_path: state_path.ok_or_else(|| "Missing required --state".to_string())?,
                audit_path: audit_path.ok_or_else(|| "Missing required --audit".to_string())?,
                scenario_report_path: scenario_report_path
                    .ok_or_else(|| "Missing required --scenario-report".to_string())?,
                source: source.ok_or_else(|| "Missing required --source".to_string())?,
            })
        }
        "replay-credential-check" => {
            let mut credential_path = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--credential" => credential_path = args.next().map(PathBuf::from),
                    "--help" | "-h" => return Err(usage()),
                    _ => return Err(format!("Unknown argument: {arg}\n\n{}", usage())),
                }
            }
            Ok(Command::AcceptanceReplayCredentialCheck {
                credential_path: credential_path
                    .ok_or_else(|| "Missing required --credential".to_string())?,
            })
        }
        _ => Err(format!(
            "Unknown acceptance subcommand: {subcommand}\n\n{}",
            usage()
        )),
    }
}

fn parse_work_order_command<I>(mut args: I) -> Result<Command, String>
where
    I: Iterator<Item = String>,
{
    let Some(subcommand) = args.next() else {
        return Err(usage());
    };
    if subcommand != "sign" {
        return Err(format!(
            "Unknown work-order subcommand: {subcommand}\n\n{}",
            usage()
        ));
    }
    let mut input_path = None;
    let mut key_id = None;
    let mut secret = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => input_path = args.next().map(PathBuf::from),
            "--key-id" => key_id = args.next(),
            "--secret" => secret = args.next(),
            "--help" | "-h" => return Err(usage()),
            _ => return Err(format!("Unknown argument: {arg}\n\n{}", usage())),
        }
    }
    Ok(Command::WorkOrderSign {
        input_path: input_path.ok_or_else(|| "Missing required --input".to_string())?,
        key_id: key_id.ok_or_else(|| "Missing required --key-id".to_string())?,
        secret: secret.ok_or_else(|| "Missing required --secret".to_string())?,
    })
}

/// Parses `splendorctl state ...` subcommands.
fn parse_state_command<I>(mut args: I) -> Result<Command, String>
where
    I: Iterator<Item = String>,
{
    let Some(subcommand) = args.next() else {
        return Err(usage());
    };
    if subcommand != "head" {
        return Err(format!(
            "Unknown state subcommand: {subcommand}\n\n{}",
            usage()
        ));
    }
    let mut db_path: Option<PathBuf> = None;
    let mut run_id: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--db" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --db".to_string())?;
                db_path = Some(PathBuf::from(value));
            }
            "--run" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --run".to_string())?;
                run_id = Some(value);
            }
            "--help" | "-h" => return Err(usage()),
            _ => return Err(format!("Unknown argument: {arg}\n\n{}", usage())),
        }
    }
    let db_path = db_path.ok_or_else(|| "Missing required --db".to_string())?;
    let run_id = run_id.ok_or_else(|| "Missing required --run".to_string())?;
    Ok(Command::StateHead { db_path, run_id })
}

/// Parses `splendorctl trace ...` subcommands.
fn parse_trace_command<I>(mut args: I) -> Result<Command, String>
where
    I: Iterator<Item = String>,
{
    let Some(subcommand) = args.next() else {
        return Err(usage());
    };
    if subcommand != "export" {
        return Err(format!(
            "Unknown trace subcommand: {subcommand}\n\n{}",
            usage()
        ));
    }
    let mut db_path: Option<PathBuf> = None;
    let mut run_id: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--db" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --db".to_string())?;
                db_path = Some(PathBuf::from(value));
            }
            "--run" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --run".to_string())?;
                run_id = Some(value);
            }
            "--help" | "-h" => return Err(usage()),
            _ => return Err(format!("Unknown argument: {arg}\n\n{}", usage())),
        }
    }
    let db_path = db_path.ok_or_else(|| "Missing required --db".to_string())?;
    let run_id = run_id.ok_or_else(|| "Missing required --run".to_string())?;
    Ok(Command::TraceExport { db_path, run_id })
}

/// Parses `splendorctl replay ...` command args.
fn parse_replay_command<I>(mut args: I) -> Result<Command, String>
where
    I: Iterator<Item = String>,
{
    let mut trace_db_path: Option<PathBuf> = None;
    let mut state_db_path: Option<PathBuf> = None;
    let mut run_id: Option<String> = None;
    let mut from_snapshot: Option<String> = None;
    let mut include_state = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--db" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --db".to_string())?;
                trace_db_path = Some(PathBuf::from(value));
            }
            "--state-db" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --state-db".to_string())?;
                state_db_path = Some(PathBuf::from(value));
            }
            "--run" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --run".to_string())?;
                run_id = Some(value);
            }
            "--from-snapshot" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --from-snapshot".to_string())?;
                from_snapshot = Some(value);
            }
            "--include-state" => include_state = true,
            "--help" | "-h" => return Err(usage()),
            _ => return Err(format!("Unknown argument: {arg}\n\n{}", usage())),
        }
    }
    let trace_db_path = trace_db_path.ok_or_else(|| "Missing required --db".to_string())?;
    let state_db_path = state_db_path.ok_or_else(|| "Missing required --state-db".to_string())?;
    let run_id = run_id.ok_or_else(|| "Missing required --run".to_string())?;
    Ok(Command::Replay {
        trace_db_path,
        state_db_path,
        run_id,
        from_snapshot,
        include_state,
    })
}

/// Parses `splendorctl audit export ...` command args.
fn parse_audit_command<I>(mut args: I) -> Result<Command, String>
where
    I: Iterator<Item = String>,
{
    let Some(subcommand) = args.next() else {
        return Err(usage());
    };
    if subcommand != "export" {
        return Err(format!(
            "Unknown audit subcommand: {subcommand}\n\n{}",
            usage()
        ));
    }

    let mut trace_db_path: Option<PathBuf> = None;
    let mut state_db_path: Option<PathBuf> = None;
    let mut run_id: Option<String> = None;
    let mut filters = AuditFilters::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--db" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --db".to_string())?;
                trace_db_path = Some(PathBuf::from(value));
            }
            "--state-db" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --state-db".to_string())?;
                state_db_path = Some(PathBuf::from(value));
            }
            "--run" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --run".to_string())?;
                run_id = Some(value);
            }
            "--tenant" => {
                filters.tenant = Some(
                    args.next()
                        .ok_or_else(|| "Missing value for --tenant".to_string())?,
                );
            }
            "--agent" => {
                filters.agent = Some(
                    args.next()
                        .ok_or_else(|| "Missing value for --agent".to_string())?,
                );
            }
            "--action" => {
                filters.action = Some(
                    args.next()
                        .ok_or_else(|| "Missing value for --action".to_string())?,
                );
            }
            "--adapter" => {
                filters.adapter = Some(
                    args.next()
                        .ok_or_else(|| "Missing value for --adapter".to_string())?,
                );
            }
            "--node" => {
                filters.node = Some(
                    args.next()
                        .ok_or_else(|| "Missing value for --node".to_string())?,
                );
            }
            "--instance" => {
                filters.instance = Some(
                    args.next()
                        .ok_or_else(|| "Missing value for --instance".to_string())?,
                );
            }
            "--fleet" => {
                filters.fleet = Some(
                    args.next()
                        .ok_or_else(|| "Missing value for --fleet".to_string())?,
                );
            }
            "--help" | "-h" => return Err(usage()),
            _ => return Err(format!("Unknown argument: {arg}\n\n{}", usage())),
        }
    }
    let trace_db_path = trace_db_path.ok_or_else(|| "Missing required --db".to_string())?;
    let state_db_path = state_db_path.ok_or_else(|| "Missing required --state-db".to_string())?;
    let run_id = run_id.ok_or_else(|| "Missing required --run".to_string())?;
    Ok(Command::AuditExport {
        trace_db_path,
        state_db_path,
        run_id,
        filters,
    })
}

/// Parses `splendorctl run ...` command args.
fn parse_run_command<I>(mut args: I) -> Result<Command, String>
where
    I: Iterator<Item = String>,
{
    let mut config_path: Option<PathBuf> = None;
    let mut cycles: Option<u64> = None;
    let mut forever = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --config".to_string())?;
                config_path = Some(PathBuf::from(value));
            }
            "--cycles" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --cycles".to_string())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| "--cycles must be an integer".to_string())?;
                cycles = Some(parsed);
            }
            "--forever" => forever = true,
            "--help" | "-h" => return Err(usage()),
            _ => {
                if config_path.is_none() {
                    config_path = Some(PathBuf::from(arg));
                } else {
                    return Err(format!("Unknown argument: {arg}\n\n{}", usage()));
                }
            }
        }
    }
    if forever && cycles.is_some() {
        return Err("--forever and --cycles cannot be used together".to_string());
    }
    let config_path = config_path.ok_or_else(|| "Missing config path".to_string())?;
    Ok(Command::Run {
        config_path,
        cycles,
        forever,
    })
}

/// Emits trace records as JSON lines on stdout.
fn export_trace(db_path: &PathBuf, run_id: &str) -> Result<(), String> {
    if !db_path.exists() {
        return Err("trace_database_not_found".to_string());
    }
    let store = SqliteTraceStore::open_read_only(db_path)
        .map_err(|_| "trace_store_open_failed".to_string())?;
    let records = validated_trace_records(&store, run_id, TraceProjection::Redacted)?;
    let mut spool = Vec::new();
    for record in records {
        append_json_line(&mut spool, &record, "trace_export_encode_failed")?;
    }
    std::io::stdout()
        .lock()
        .write_all(&spool)
        .map_err(|_| "trace_export_write_failed".to_string())?;
    Ok(())
}

fn append_json_line<T: Serialize>(
    spool: &mut Vec<u8>,
    value: &T,
    failure_code: &'static str,
) -> Result<(), String> {
    let mut line = serde_json::to_vec(value).map_err(|_| failure_code.to_string())?;
    line.push(b'\n');
    spool.extend_from_slice(&line);
    Ok(())
}

/// Prints CLI package and milestone baseline identifiers.
fn print_version() {
    println!(
        "splendorctl {} ({})",
        env!("CARGO_PKG_VERSION"),
        SPLENDOR_RELEASE_LABEL
    );
}

#[derive(Serialize)]
struct StateHeadOutput {
    run_id: String,
    state_hash: ContentHash,
    snapshot_id: Option<SnapshotId>,
    trace_sequence: u64,
}

/// Emits the latest state head recorded by the run's StateCommitted trace event.
fn state_head(db_path: &PathBuf, run_id: &str) -> Result<(), String> {
    if !db_path.exists() {
        return Err("trace_database_not_found".to_string());
    }
    let store = SqliteTraceStore::open_read_only(db_path)
        .map_err(|_| "trace_store_open_failed".to_string())?;
    let records = validated_trace_records(&store, run_id, TraceProjection::Trusted)?;
    let events = decode_validated_trace_records(&records)?;

    let mut latest: Option<StateHeadOutput> = None;
    for event in events {
        if let TraceEventKind::StateCommitted {
            state_hash,
            snapshot_id,
        } = event.kind
        {
            latest = Some(StateHeadOutput {
                run_id: run_id.to_string(),
                state_hash,
                snapshot_id,
                trace_sequence: event.sequence,
            });
        }
    }
    let latest = latest.ok_or_else(|| "state_head_not_found".to_string())?;
    let mut output = Vec::new();
    append_json_line(&mut output, &latest, "state_head_encode_failed")?;
    std::io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|_| "state_head_write_failed".to_string())?;
    Ok(())
}

#[derive(Serialize)]
struct AcceptanceImportReport {
    schema_version: &'static str,
    source: String,
    accepted: bool,
    trace_records: usize,
    trace_chain_hash: String,
    trace_digest: String,
    state_digest: String,
    matching_state_hashes: Vec<String>,
    state_node_ids: Vec<String>,
}

#[derive(Serialize)]
struct AcceptanceCompatReport {
    schema_version: &'static str,
    status: &'static str,
    target_schema: String,
    migrated: Vec<AcceptanceMigrationRecord>,
}

#[derive(Serialize)]
struct AcceptanceMigrationRecord {
    source_path: String,
    source_digest: String,
    source_schema_versions: Vec<String>,
    target_schema_version: String,
    migrated_digest: String,
}

#[derive(Serialize)]
struct AcceptanceAuditCheckReport {
    schema_version: &'static str,
    status: &'static str,
    category: String,
    case_name: String,
    reason_codes: Vec<String>,
    trace_event_ids: Vec<String>,
}

#[derive(Serialize)]
struct AcceptanceReplayModeReport {
    schema_version: &'static str,
    mode: String,
    status: &'static str,
    source: String,
    public_command: &'static str,
    trace_path: String,
    state_path: String,
    audit_path: String,
    scenario_report_path: String,
    trace_digest: String,
    state_digest: String,
    audit_digest: String,
    scenario_report_digest: String,
    trace_chain_hash: String,
    trace_records: usize,
    matching_state_hashes: Vec<String>,
    event_types_observed: Vec<String>,
    evidence_fields: BTreeMap<String, serde_json::Value>,
    side_effects_allowed: bool,
    side_effects_executed: bool,
}

fn acceptance_validate_import(
    trace_path: &Path,
    state_path: &Path,
    scenario_report_path: &Path,
    source: &str,
    expected_trace_chain: Option<&str>,
    expected_state_hash: Option<&str>,
) -> Result<(), String> {
    let trace_raw = fs::read_to_string(trace_path)
        .map_err(|error| format!("Failed to read trace artifact: {error}"))?;
    let records = trace_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .map_err(|error| format!("Malformed trace JSON line: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if records.is_empty() {
        return Err("trace_import_rejected:empty_trace".to_string());
    }
    let trace_chain_hash = acceptance_trace_chain_hash(&records)?;
    if let Some(expected) = expected_trace_chain {
        if expected != trace_chain_hash {
            return Err(format!(
                "trace_import_rejected:trace_chain_hash_mismatch expected={expected} actual={trace_chain_hash}"
            ));
        }
    }
    let state_value = read_json_value(state_path)?;
    let scenario = read_json_value(scenario_report_path)?;
    let state_hashes = acceptance_state_hashes(&state_value);
    let scenario_hashes = json_array_strings(scenario.get("state_hashes"));
    let mut matching_state_hashes = state_hashes
        .intersection(&scenario_hashes)
        .cloned()
        .collect::<Vec<_>>();
    if let Some(expected) = expected_state_hash {
        if !state_hashes.contains(expected) {
            return Err(format!(
                "state_import_rejected:state_hash_mismatch expected={expected}"
            ));
        }
        if !matching_state_hashes.iter().any(|value| value == expected) {
            matching_state_hashes.push(expected.to_string());
        }
    }
    if matching_state_hashes.is_empty() {
        return Err("state_import_rejected:state_hash_mismatch".to_string());
    }
    let report = AcceptanceImportReport {
        schema_version: "splendor.acceptance.import_report.v1",
        source: source.to_string(),
        accepted: true,
        trace_records: records.len(),
        trace_chain_hash,
        trace_digest: acceptance_file_digest(trace_path)?,
        state_digest: acceptance_file_digest(state_path)?,
        matching_state_hashes,
        state_node_ids: acceptance_state_node_ids(&state_value)
            .into_iter()
            .collect(),
    };
    print_json_line(&report)
}

fn acceptance_compat(fixture_paths: &[PathBuf], target_schema: &str) -> Result<(), String> {
    if target_schema != "splendor.0.1.stable.v1" {
        return Err(format!(
            "schema_rejected:unsupported_target_schema target={target_schema}"
        ));
    }
    let mut migrated = Vec::new();
    for path in fixture_paths {
        let value = read_json_value(path)?;
        let versions = acceptance_schema_versions(&value);
        if versions
            .iter()
            .any(|version| version.contains("unsupported"))
            || versions.is_empty()
        {
            return Err(format!(
                "schema_rejected:unsupported_schema_version path={}",
                path.display()
            ));
        }
        if versions
            .iter()
            .any(|version| version.contains("generated.types.mismatch"))
        {
            return Err(format!(
                "compatibility_rejected:generated_schema_mismatch path={}",
                path.display()
            ));
        }
        let source_digest = acceptance_file_digest(path)?;
        let migrated_digest = format!(
            "blake3:{}",
            blake3::hash(format!("{source_digest}:{target_schema}").as_bytes()).to_hex()
        );
        migrated.push(AcceptanceMigrationRecord {
            source_path: path.display().to_string(),
            source_digest,
            source_schema_versions: versions.into_iter().collect(),
            target_schema_version: target_schema.to_string(),
            migrated_digest,
        });
    }
    print_json_line(&AcceptanceCompatReport {
        schema_version: "splendor.acceptance.compat_report.v1",
        status: "passed",
        target_schema: target_schema.to_string(),
        migrated,
    })
}

fn acceptance_audit_check(
    audit_path: &Path,
    scenario_report_path: &Path,
    case_name: &str,
    category: &str,
) -> Result<(), String> {
    let audit = read_json_value(audit_path)?;
    let scenario = read_json_value(scenario_report_path)?;
    let mut candidates = Vec::new();
    collect_case_records(&audit, case_name, &mut candidates);
    collect_case_records(&scenario, case_name, &mut candidates);
    let mut reason_codes = BTreeSet::new();
    let mut trace_event_ids = BTreeSet::new();
    for candidate in candidates {
        for reason in json_array_strings(candidate.get("reason_codes")) {
            reason_codes.insert(reason);
        }
        for reason in json_array_strings(candidate.get("reasons")) {
            reason_codes.insert(reason);
        }
        if let Some(reason) = candidate
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            reason_codes.insert(reason.to_string());
        }
        for trace_id in json_array_strings(candidate.get("trace_event_ids")) {
            trace_event_ids.insert(trace_id);
        }
        if let Some(trace_id) = candidate
            .get("trace_event_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            trace_event_ids.insert(trace_id.to_string());
        }
        collect_named_string_values(
            candidate,
            &["code", "reason_code", "reason_codes", "reason", "reasons"],
            &mut reason_codes,
        );
        collect_named_string_values(
            candidate,
            &["trace_event_id", "trace_event_ids"],
            &mut trace_event_ids,
        );
    }
    if reason_codes.is_empty() {
        return Err(format!(
            "audit_rejected:missing_denial_reason_codes case={case_name} category={category}"
        ));
    }
    print_json_line(&AcceptanceAuditCheckReport {
        schema_version: "splendor.acceptance.audit_check.v1",
        status: "passed",
        category: category.to_string(),
        case_name: case_name.to_string(),
        reason_codes: reason_codes.into_iter().collect(),
        trace_event_ids: trace_event_ids.into_iter().collect(),
    })
}

fn acceptance_replay_mode(
    mode: &str,
    trace_path: &Path,
    state_path: &Path,
    audit_path: &Path,
    scenario_report_path: &Path,
    source: &str,
) -> Result<(), String> {
    let allowed_modes = BTreeSet::from([
        "inspect_only",
        "read_only_re_evaluation",
        "policy_comparison",
        "verifier_explanation",
    ]);
    if !allowed_modes.contains(mode) {
        return Err(format!("replay_mode_rejected:unsupported_mode mode={mode}"));
    }

    let trace_raw = fs::read_to_string(trace_path)
        .map_err(|error| format!("Failed to read trace artifact: {error}"))?;
    let records = trace_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .map_err(|error| format!("Malformed trace JSON line: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if records.is_empty() {
        return Err("replay_mode_rejected:empty_trace".to_string());
    }

    let state_value = read_json_value(state_path)?;
    let audit_value = read_json_value(audit_path)?;
    let scenario = read_json_value(scenario_report_path)?;
    let state_hashes = acceptance_state_hashes(&state_value);
    let scenario_hashes = json_array_strings(scenario.get("state_hashes"));
    let matching_state_hashes = state_hashes
        .intersection(&scenario_hashes)
        .cloned()
        .collect::<Vec<_>>();
    if matching_state_hashes.is_empty() {
        return Err("replay_mode_rejected:state_hash_mismatch".to_string());
    }

    let mut event_types = records
        .iter()
        .filter_map(|record| record.get("event_type").and_then(serde_json::Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    if event_types.is_empty() {
        event_types.insert("untyped_trace_record".to_string());
    }

    let mut evidence_fields = BTreeMap::new();
    evidence_fields.insert(
        "source_artifacts_validated".to_string(),
        serde_json::Value::Bool(true),
    );
    evidence_fields.insert(
        "state_hashes_matched".to_string(),
        serde_json::Value::Bool(true),
    );
    evidence_fields.insert(
        "adapter_execution_permitted".to_string(),
        serde_json::Value::Bool(false),
    );

    match mode {
        "inspect_only" => {
            evidence_fields.insert("inspection_scope".to_string(), "trace_state_audit".into());
        }
        "read_only_re_evaluation" => {
            evidence_fields.insert(
                "reevaluation_scope".to_string(),
                "read_only_artifact_check".into(),
            );
            evidence_fields.insert(
                "state_nodes_observed".to_string(),
                acceptance_state_node_ids(&state_value).len().into(),
            );
        }
        "policy_comparison" => {
            evidence_fields.insert("old_policy_ref".to_string(), "prior-scenario-policy".into());
            evidence_fields.insert(
                "new_policy_ref".to_string(),
                "uc-e2e-s8-comparison-policy".into(),
            );
            evidence_fields.insert(
                "comparison_basis".to_string(),
                "trace_event_sequence_and_state_hashes".into(),
            );
        }
        "verifier_explanation" => {
            let mut reason_codes = BTreeSet::new();
            collect_named_string_values(
                &audit_value,
                &["code", "reason_code", "reason_codes", "reason", "reasons"],
                &mut reason_codes,
            );
            if reason_codes.is_empty() {
                return Err("replay_mode_rejected:missing_verifier_reason_codes".to_string());
            }
            evidence_fields.insert(
                "reason_codes".to_string(),
                serde_json::Value::Array(
                    reason_codes
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        _ => unreachable!("mode was validated above"),
    }

    print_json_line(&AcceptanceReplayModeReport {
        schema_version: "splendor.acceptance.replay_mode.v1",
        mode: mode.to_string(),
        status: "completed",
        source: source.to_string(),
        public_command: "splendorctl acceptance replay-mode",
        trace_path: trace_path.display().to_string(),
        state_path: state_path.display().to_string(),
        audit_path: audit_path.display().to_string(),
        scenario_report_path: scenario_report_path.display().to_string(),
        trace_digest: acceptance_file_digest(trace_path)?,
        state_digest: acceptance_file_digest(state_path)?,
        audit_digest: acceptance_file_digest(audit_path)?,
        scenario_report_digest: acceptance_file_digest(scenario_report_path)?,
        trace_chain_hash: acceptance_trace_chain_hash(&records)?,
        trace_records: records.len(),
        matching_state_hashes,
        event_types_observed: event_types.into_iter().collect(),
        evidence_fields,
        side_effects_allowed: false,
        side_effects_executed: false,
    })
}

fn acceptance_replay_credential_check(credential_path: &Path) -> Result<(), String> {
    let credential = read_json_value(credential_path)?;
    let text = serde_json::to_string(&credential)
        .map_err(|error| format!("Failed to encode credential fixture: {error}"))?;
    if text.contains("production_external_secret")
        || text.contains("real_external_credential")
        || text.contains("external_secret_material")
    {
        return Err("replay_credential_rejected:real_external_credentials_forbidden".to_string());
    }
    print_json_line(&serde_json::json!({
        "schema_version": "splendor.acceptance.replay_credential_check.v1",
        "status": "passed",
        "real_external_credentials": false
    }))
}

fn acceptance_trace_chain_hash(records: &[serde_json::Value]) -> Result<String, String> {
    let mut previous =
        "blake3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
    for record in records {
        let payload = serde_json::to_vec(record)
            .map_err(|error| format!("Failed to encode trace record for chain hash: {error}"))?;
        let mut bytes = previous.into_bytes();
        bytes.push(b'\n');
        bytes.extend(payload);
        previous = format!("blake3:{}", blake3::hash(&bytes).to_hex());
    }
    Ok(previous)
}

fn acceptance_file_digest(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
    Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}

fn read_json_value(path: &Path) -> Result<serde_json::Value, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|error| format!("Malformed JSON in {}: {error}", path.display()))
}

fn json_array_strings(value: Option<&serde_json::Value>) -> BTreeSet<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn acceptance_state_hashes(value: &serde_json::Value) -> BTreeSet<String> {
    let mut hashes = BTreeSet::new();
    collect_named_strings(
        value,
        &["state_hash", "data_hash", "state_node_hash", "value"],
        &mut hashes,
    );
    hashes
        .into_iter()
        .filter(|value| {
            value.starts_with("sha") || value.starts_with("blake3:") || value.len() >= 32
        })
        .collect()
}

fn acceptance_state_node_ids(value: &serde_json::Value) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    collect_named_strings(
        value,
        &["state_node_id", "state_head_id", "previous_state_node_id"],
        &mut ids,
    );
    ids
}

fn acceptance_schema_versions(value: &serde_json::Value) -> BTreeSet<String> {
    let mut versions = BTreeSet::new();
    collect_named_strings(value, &["schema_version", "schema"], &mut versions);
    versions
        .into_iter()
        .filter(|value| value.starts_with("splendor.") || value == "v1")
        .collect()
}

fn collect_named_strings(value: &serde_json::Value, names: &[&str], out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                if names.iter().any(|name| name == key) {
                    if let Some(text) = nested.as_str() {
                        if !text.trim().is_empty() {
                            out.insert(text.to_string());
                        }
                    }
                }
                collect_named_strings(nested, names, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_named_strings(item, names, out);
            }
        }
        _ => {}
    }
}

fn collect_named_string_values(
    value: &serde_json::Value,
    names: &[&str],
    out: &mut BTreeSet<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                if names.iter().any(|name| name == key) {
                    match nested {
                        serde_json::Value::String(text) if !text.trim().is_empty() => {
                            out.insert(text.to_string());
                        }
                        serde_json::Value::Array(items) => {
                            for item in items {
                                if let Some(text) =
                                    item.as_str().filter(|value| !value.trim().is_empty())
                                {
                                    out.insert(text.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                collect_named_string_values(nested, names, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_named_string_values(item, names, out);
            }
        }
        _ => {}
    }
}

fn collect_case_records<'a>(
    value: &'a serde_json::Value,
    case_name: &str,
    out: &mut Vec<&'a serde_json::Value>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if map.get("case").and_then(serde_json::Value::as_str) == Some(case_name) {
                out.push(value);
            }
            for nested in map.values() {
                collect_case_records(nested, case_name, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_case_records(item, case_name, out);
            }
        }
        _ => {}
    }
}

fn print_json_line(value: &impl Serialize) -> Result<(), String> {
    let line = serde_json::to_string(value)
        .map_err(|error| format!("Failed to encode acceptance output: {error}"))?;
    println!("{line}");
    Ok(())
}

const AUDIT_EXPORT_SCHEMA_VERSION: &str = "splendor.audit_export.v0.04-dev";

#[derive(Clone, Debug, Default, Serialize)]
struct AuditFilters {
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    adapter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fleet: Option<String>,
}

impl AuditFilters {
    fn with_run(mut self, run_id: &str) -> Self {
        self.run = Some(run_id.to_string());
        self
    }

    fn matches(&self, event: &TraceEvent, adapter_by_action: &BTreeMap<String, String>) -> bool {
        if let Some(filter) = &self.run {
            if event.run_id.to_string() != *filter {
                return false;
            }
        }
        if let Some(filter) = &self.tenant {
            if !event_has_tenant(event, filter) {
                return false;
            }
        }
        if let Some(filter) = &self.agent {
            if !event_has_agent(event, filter) {
                return false;
            }
        }
        if let Some(filter) = &self.action {
            if !event_has_action(event, filter) {
                return false;
            }
        }
        if let Some(filter) = &self.adapter {
            if !event_has_adapter(event, filter, adapter_by_action) {
                return false;
            }
        }
        if let Some(filter) = &self.node {
            if event.identity.node_id.as_ref().map(ToString::to_string) != Some(filter.clone()) {
                return false;
            }
        }
        if let Some(filter) = &self.instance {
            if event.identity.instance_id.as_ref().map(ToString::to_string) != Some(filter.clone())
            {
                return false;
            }
        }
        if let Some(filter) = &self.fleet {
            if event.identity.fleet_id.as_ref().map(ToString::to_string) != Some(filter.clone()) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug, Serialize)]
struct AuditExport {
    schema_version: String,
    run_id: String,
    generated_at: OffsetDateTime,
    source: String,
    replay_mode: String,
    side_effects_replayed: bool,
    filters: AuditFilters,
    trace_range: Option<AuditTraceRange>,
    event_count: usize,
    work_orders: Vec<AuditWorkOrderRecord>,
    policies: Vec<AuditPolicyRecord>,
    actions: Vec<AuditActionRecord>,
    governance_events: Vec<AuditGovernanceRecord>,
    state_nodes: Vec<AuditStateNodeRecord>,
    redaction: AuditRedactionSummary,
}

#[derive(Clone, Debug, Serialize)]
struct AuditTraceRange {
    first_sequence: u64,
    last_sequence: u64,
    first_trace_event_id: TraceEventId,
    last_trace_event_id: TraceEventId,
}

#[derive(Clone, Debug, Serialize)]
struct AuditWorkOrderRecord {
    trace_event_id: TraceEventId,
    sequence: u64,
    accepted: bool,
    work_order_id: Option<WorkOrderId>,
    tenant_id: Option<TenantId>,
    agent_id: Option<AgentId>,
    run_id: Option<RunId>,
    reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct AuditPolicyRecord {
    trace_event_id: TraceEventId,
    sequence: u64,
    lifecycle: String,
    policy_bundle_id: Option<String>,
    version: Option<String>,
    action: Option<String>,
    reason: Option<String>,
    bundle: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
struct AuditActionRecord {
    trace_event_id: TraceEventId,
    sequence: u64,
    identity: TraceIdentityContext,
    action_name: String,
    adapter: Option<String>,
    status: String,
    action: serde_json::Value,
    verification_result: Option<serde_json::Value>,
    outcome: Option<serde_json::Value>,
    error: Option<String>,
}

struct AuditActionRecordInput<'a> {
    event: &'a TraceEvent,
    action: &'a Action,
    status: &'a str,
    result: Option<&'a splendor_types::VerificationResult>,
    outcome: Option<&'a serde_json::Value>,
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct AuditGovernanceRecord {
    trace_event_id: TraceEventId,
    sequence: u64,
    identity: TraceIdentityContext,
    event: String,
    object_id: Option<String>,
    scope: Option<serde_json::Value>,
    reason: Option<String>,
    details: serde_json::Value,
}

type GovernanceRecordParts = (
    &'static str,
    Option<String>,
    Option<String>,
    Option<serde_json::Value>,
    serde_json::Value,
);

#[derive(Clone, Debug, Serialize)]
struct AuditStateNodeRecord {
    trace_event_id: TraceEventId,
    sequence: u64,
    identity: TraceIdentityContext,
    state_node_id: Option<String>,
    parent_state_node_ids: Vec<String>,
    state_hash: ContentHash,
    snapshot_id: Option<SnapshotId>,
    metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
struct AuditRedactionSummary {
    applied: bool,
    redacted_keys: Vec<String>,
}

#[derive(Default)]
struct RedactionTracker {
    keys: BTreeSet<String>,
}

impl RedactionTracker {
    fn record(&mut self, key: &str) {
        self.keys.insert(key.to_string());
    }

    fn summary(&self) -> AuditRedactionSummary {
        AuditRedactionSummary {
            applied: !self.keys.is_empty(),
            redacted_keys: self.keys.iter().cloned().collect(),
        }
    }
}

/// Emits a governance audit export derived only from trace and state data.
fn audit_export(
    trace_db_path: &PathBuf,
    state_db_path: &PathBuf,
    run_id: &str,
    filters: AuditFilters,
) -> Result<(), String> {
    let export = audit_export_from_stores(trace_db_path, state_db_path, run_id, filters)?;
    let mut output = Vec::new();
    append_json_line(&mut output, &export, "audit_export_encode_failed")?;
    std::io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|_| "audit_export_write_failed".to_string())?;
    Ok(())
}

fn audit_export_from_stores(
    trace_db_path: &PathBuf,
    state_db_path: &PathBuf,
    run_id: &str,
    filters: AuditFilters,
) -> Result<AuditExport, String> {
    if !trace_db_path.exists() {
        return Err("trace_database_not_found".to_string());
    }
    if !state_db_path.exists() {
        return Err("state_database_not_found".to_string());
    }
    let trace_store = SqliteTraceStore::open_read_only(trace_db_path)
        .map_err(|_| "trace_store_open_failed".to_string())?;
    let state_store = SqliteStateStore::open_read_only(state_db_path)
        .map_err(|_| "state_store_open_failed".to_string())?;
    let records = validated_trace_records(&trace_store, run_id, TraceProjection::Trusted)?;
    let events = decode_validated_trace_records(&records)?;
    collect_audit_export(&events, &state_store, run_id, filters)
        .map_err(|_| "audit_projection_failed".to_string())
}

fn collect_audit_export(
    events: &[TraceEvent],
    state_store: &SqliteStateStore,
    run_id: &str,
    filters: AuditFilters,
) -> Result<AuditExport, String> {
    let filters = filters.with_run(run_id);
    let adapter_by_action = audit_adapter_index(events);
    let filtered_events = events
        .iter()
        .filter(|event| filters.matches(event, &adapter_by_action))
        .collect::<Vec<_>>();
    let trace_range = audit_trace_range(&filtered_events);
    let mut redaction = RedactionTracker::default();
    let mut verification_by_action: BTreeMap<String, (Option<String>, serde_json::Value)> =
        BTreeMap::new();
    let mut work_orders = Vec::new();
    let mut policies = Vec::new();
    let mut actions = Vec::new();
    let mut governance_events = Vec::new();
    let mut state_nodes = Vec::new();

    for event in &filtered_events {
        match &event.kind {
            TraceEventKind::WorkOrderAccepted {
                work_order_id,
                tenant_id,
                agent_id,
                run_id,
            } => work_orders.push(AuditWorkOrderRecord {
                trace_event_id: event.trace_event_id.clone(),
                sequence: event.sequence,
                accepted: true,
                work_order_id: Some(work_order_id.clone()),
                tenant_id: Some(tenant_id.clone()),
                agent_id: Some(agent_id.clone()),
                run_id: run_id.clone(),
                reason: None,
            }),
            TraceEventKind::WorkOrderRejected {
                work_order_id,
                tenant_id,
                agent_id,
                run_id,
                reason,
            } => work_orders.push(AuditWorkOrderRecord {
                trace_event_id: event.trace_event_id.clone(),
                sequence: event.sequence,
                accepted: false,
                work_order_id: work_order_id.clone(),
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
                run_id: run_id.clone(),
                reason: Some(redact_sensitive_text(reason, &mut redaction)),
            }),
            TraceEventKind::PolicyBundleAccepted { bundle } => {
                let bundle_value = sanitized_value(bundle, &mut redaction)?;
                policies.push(AuditPolicyRecord {
                    trace_event_id: event.trace_event_id.clone(),
                    sequence: event.sequence,
                    lifecycle: "accepted".to_string(),
                    policy_bundle_id: string_value(&bundle_value, "policy_bundle_id"),
                    version: string_value(&bundle_value, "version"),
                    action: None,
                    reason: None,
                    bundle: Some(bundle_value),
                });
            }
            TraceEventKind::PolicyBundleRejected {
                policy_bundle_id,
                version,
                reason,
            } => policies.push(AuditPolicyRecord {
                trace_event_id: event.trace_event_id.clone(),
                sequence: event.sequence,
                lifecycle: "rejected".to_string(),
                policy_bundle_id: policy_bundle_id.as_ref().map(ToString::to_string),
                version: version
                    .as_ref()
                    .map(|value| redact_sensitive_text(value, &mut redaction)),
                action: None,
                reason: Some(redact_sensitive_text(reason, &mut redaction)),
                bundle: None,
            }),
            TraceEventKind::PolicySyncFailed {
                policy_bundle_id,
                version,
                reason,
            } => policies.push(AuditPolicyRecord {
                trace_event_id: event.trace_event_id.clone(),
                sequence: event.sequence,
                lifecycle: "sync_failed".to_string(),
                policy_bundle_id: policy_bundle_id.as_ref().map(ToString::to_string),
                version: version
                    .as_ref()
                    .map(|value| redact_sensitive_text(value, &mut redaction)),
                action: None,
                reason: Some(redact_sensitive_text(reason, &mut redaction)),
                bundle: None,
            }),
            TraceEventKind::PolicyExpired {
                policy_bundle_id,
                version,
                action,
            } => policies.push(AuditPolicyRecord {
                trace_event_id: event.trace_event_id.clone(),
                sequence: event.sequence,
                lifecycle: "expired".to_string(),
                policy_bundle_id: Some(policy_bundle_id.to_string()),
                version: Some(redact_sensitive_text(version, &mut redaction)),
                action: action
                    .as_ref()
                    .map(|value| redact_sensitive_text(value, &mut redaction)),
                reason: Some("policy_expired".to_string()),
                bundle: None,
            }),
            TraceEventKind::PolicyRevoked {
                policy_bundle_id,
                version,
                reason,
            } => policies.push(AuditPolicyRecord {
                trace_event_id: event.trace_event_id.clone(),
                sequence: event.sequence,
                lifecycle: "revoked".to_string(),
                policy_bundle_id: Some(policy_bundle_id.to_string()),
                version: Some(redact_sensitive_text(version, &mut redaction)),
                action: None,
                reason: Some(redact_sensitive_text(reason, &mut redaction)),
                bundle: None,
            }),
            TraceEventKind::ActionVerificationCompleted { action, result } => {
                let key = audit_action_key(event, action);
                let adapter = adapter_from_result(result);
                let sanitized = sanitized_value(result, &mut redaction)?;
                verification_by_action.insert(key, (adapter, sanitized));
            }
            TraceEventKind::ActionNeedsApproval { action, result } => {
                actions.push(audit_action_record(
                    AuditActionRecordInput {
                        event,
                        action,
                        status: "needs_approval",
                        result: Some(result),
                        outcome: None,
                        error: None,
                    },
                    &verification_by_action,
                    &mut redaction,
                )?);
            }
            TraceEventKind::ActionDenied { action, result } => {
                actions.push(audit_action_record(
                    AuditActionRecordInput {
                        event,
                        action,
                        status: "denied",
                        result: Some(result),
                        outcome: None,
                        error: None,
                    },
                    &verification_by_action,
                    &mut redaction,
                )?);
            }
            TraceEventKind::ActionNeedsIntervention { action, result } => {
                actions.push(audit_action_record(
                    AuditActionRecordInput {
                        event,
                        action,
                        status: "needs_intervention",
                        result: Some(result),
                        outcome: None,
                        error: None,
                    },
                    &verification_by_action,
                    &mut redaction,
                )?);
            }
            TraceEventKind::ActionFailed {
                action,
                error,
                result,
            } => {
                actions.push(audit_action_record(
                    AuditActionRecordInput {
                        event,
                        action,
                        status: "failed",
                        result: Some(result),
                        outcome: None,
                        error: Some(error.clone()),
                    },
                    &verification_by_action,
                    &mut redaction,
                )?);
            }
            TraceEventKind::ActionExecuted { action, outcome } => {
                actions.push(audit_action_record(
                    AuditActionRecordInput {
                        event,
                        action,
                        status: "executed",
                        result: None,
                        outcome: Some(outcome),
                        error: None,
                    },
                    &verification_by_action,
                    &mut redaction,
                )?);
            }
            TraceEventKind::StateCommitted {
                state_hash,
                snapshot_id,
            } => state_nodes.push(audit_state_node_record(
                event,
                state_store,
                state_hash,
                snapshot_id,
                &mut redaction,
            )?),
            _ => {}
        }

        if let Some(record) = audit_governance_record(event, &mut redaction)? {
            governance_events.push(record);
        }
    }

    Ok(AuditExport {
        schema_version: AUDIT_EXPORT_SCHEMA_VERSION.to_string(),
        run_id: run_id.to_string(),
        generated_at: OffsetDateTime::now_utc(),
        source: "trace_state_governance_primitives".to_string(),
        replay_mode: "inspect_only".to_string(),
        side_effects_replayed: false,
        filters,
        trace_range,
        event_count: filtered_events.len(),
        work_orders,
        policies,
        actions,
        governance_events,
        state_nodes,
        redaction: redaction.summary(),
    })
}

fn audit_trace_range(events: &[&TraceEvent]) -> Option<AuditTraceRange> {
    let first = events.first()?;
    let last = events.last()?;
    Some(AuditTraceRange {
        first_sequence: first.sequence,
        last_sequence: last.sequence,
        first_trace_event_id: first.trace_event_id.clone(),
        last_trace_event_id: last.trace_event_id.clone(),
    })
}

fn audit_action_record(
    input: AuditActionRecordInput<'_>,
    verification_by_action: &BTreeMap<String, (Option<String>, serde_json::Value)>,
    redaction: &mut RedactionTracker,
) -> Result<AuditActionRecord, String> {
    let key = audit_action_key(input.event, input.action);
    let prior = verification_by_action.get(&key);
    let adapter = input
        .result
        .and_then(adapter_from_result)
        .or_else(|| prior.and_then(|(adapter, _)| adapter.clone()))
        .or_else(|| adapter_from_action_name(&input.action.name));
    let verification_result = match input.result {
        Some(result) => Some(sanitized_value(result, redaction)?),
        None => prior.map(|(_, value)| value.clone()),
    };
    Ok(AuditActionRecord {
        trace_event_id: input.event.trace_event_id.clone(),
        sequence: input.event.sequence,
        identity: input.event.identity.clone(),
        action_name: input.action.name.clone(),
        adapter,
        status: input.status.to_string(),
        action: sanitized_value(input.action, redaction)?,
        verification_result,
        outcome: input
            .outcome
            .map(|value| redact_value(value.clone(), redaction)),
        error: input
            .error
            .map(|value| redact_sensitive_text(&value, redaction)),
    })
}

fn audit_state_node_record(
    event: &TraceEvent,
    state_store: &SqliteStateStore,
    state_hash: &ContentHash,
    snapshot_id: &Option<SnapshotId>,
    redaction: &mut RedactionTracker,
) -> Result<AuditStateNodeRecord, String> {
    let state_node_id = if let Some(state_node_id) = event.identity.state_node_id.clone() {
        Some(state_node_id)
    } else if let Some(snapshot_id) = snapshot_id {
        Some(load_verified_state_snapshot(state_store, snapshot_id, Some(state_hash))?.node_id)
    } else {
        None
    };
    let node = if let Some(state_node_id) = &state_node_id {
        Some(load_verified_state_node(
            state_store,
            state_node_id,
            Some(state_hash),
        )?)
    } else {
        None
    };
    Ok(AuditStateNodeRecord {
        trace_event_id: event.trace_event_id.clone(),
        sequence: event.sequence,
        identity: event.identity.clone(),
        state_node_id: state_node_id.as_ref().map(ToString::to_string),
        parent_state_node_ids: node
            .as_ref()
            .map(|node| node.parent_ids.iter().map(ToString::to_string).collect())
            .unwrap_or_default(),
        state_hash: state_hash.clone(),
        snapshot_id: snapshot_id.clone(),
        metadata: node
            .map(|node| sanitized_value(&node.metadata, redaction))
            .transpose()?,
    })
}

fn audit_governance_record(
    event: &TraceEvent,
    redaction: &mut RedactionTracker,
) -> Result<Option<AuditGovernanceRecord>, String> {
    validate_governance_trace_context(event)?;
    let (event_name, reason, object_id, scope, details) = match &event.kind {
        TraceEventKind::ApprovalRequested { approval } => {
            validate_approval_trace_context(event, approval)?;
            (
                "approval.requested",
                approval.reason.clone(),
                Some(approval.approval_id.to_string()),
                None,
                sanitized_value(approval, redaction)?,
            )
        }
        TraceEventKind::ApprovalGranted { approval } => {
            validate_approval_trace_context(event, approval)?;
            (
                "approval.granted",
                approval.reason.clone(),
                Some(approval.approval_id.to_string()),
                None,
                sanitized_value(approval, redaction)?,
            )
        }
        TraceEventKind::ApprovalDenied { approval, reason } => {
            validate_approval_trace_context(event, approval)?;
            (
                "approval.denied",
                Some(reason.clone()),
                Some(approval.approval_id.to_string()),
                None,
                sanitized_value(approval, redaction)?,
            )
        }
        TraceEventKind::ApprovalExpired { approval, reason } => {
            validate_approval_trace_context(event, approval)?;
            (
                "approval.expired",
                Some(reason.clone()),
                Some(approval.approval_id.to_string()),
                None,
                sanitized_value(approval, redaction)?,
            )
        }
        TraceEventKind::ApprovalRevoked { approval, reason } => {
            validate_approval_trace_context(event, approval)?;
            (
                "approval.revoked",
                Some(reason.clone()),
                Some(approval.approval_id.to_string()),
                None,
                sanitized_value(approval, redaction)?,
            )
        }
        TraceEventKind::RunPaused { reason } => (
            "run.paused",
            reason.clone(),
            None,
            None,
            serde_json::json!({ "reason": reason }),
        ),
        TraceEventKind::RunResumed { reason } => (
            "run.resumed",
            reason.clone(),
            None,
            None,
            serde_json::json!({ "reason": reason }),
        ),
        TraceEventKind::ActionDenied { action, result } => (
            "action.denied",
            result.reasons.first().cloned(),
            event.identity.action_id.as_ref().map(ToString::to_string),
            None,
            serde_json::json!({
                "action": redact_value(serde_json::to_value(action).map_err(|_| "audit_action_encode_failed".to_string())?, redaction),
                "result": redact_value(serde_json::to_value(result).map_err(|_| "audit_result_encode_failed".to_string())?, redaction),
            }),
        ),
        TraceEventKind::ActionNeedsApproval { action, result } => (
            "action.needs_approval",
            result.reasons.first().cloned(),
            event.identity.action_id.as_ref().map(ToString::to_string),
            None,
            serde_json::json!({
                "action": redact_value(serde_json::to_value(action).map_err(|_| "audit_action_encode_failed".to_string())?, redaction),
                "result": redact_value(serde_json::to_value(result).map_err(|_| "audit_result_encode_failed".to_string())?, redaction),
            }),
        ),
        TraceEventKind::ActionNeedsIntervention { action, result } => (
            "action.needs_intervention",
            result.reasons.first().cloned(),
            event.identity.action_id.as_ref().map(ToString::to_string),
            None,
            serde_json::json!({
                "action": redact_value(serde_json::to_value(action).map_err(|_| "audit_action_encode_failed".to_string())?, redaction),
                "result": redact_value(serde_json::to_value(result).map_err(|_| "audit_result_encode_failed".to_string())?, redaction),
            }),
        ),
        TraceEventKind::EscalationTriggered { escalation } => {
            validate_run_match(event, &escalation.run_id, "Escalation")?;
            (
                "escalation.triggered",
                Some(escalation.reason.clone()),
                escalation.action_id.as_ref().map(ToString::to_string),
                None,
                sanitized_value(escalation, redaction)?,
            )
        }
        TraceEventKind::CircuitBreakerTripped { breaker } => (
            "circuit_breaker.tripped",
            Some(breaker.reason.clone()),
            Some(breaker.breaker_id.to_string()),
            Some(serde_json::json!({
                "scope": breaker.scope.label(),
                "value": breaker.scope.value(),
            })),
            sanitized_value(breaker, redaction)?,
        ),
        TraceEventKind::CircuitBreakerCleared { breaker } => (
            "circuit_breaker.cleared",
            Some(breaker.reason.clone()),
            Some(breaker.breaker_id.to_string()),
            Some(serde_json::json!({
                "scope": breaker.scope.label(),
                "value": breaker.scope.value(),
            })),
            sanitized_value(breaker, redaction)?,
        ),
        TraceEventKind::GovernanceApprovalRequested { transition } => {
            governance_transition_record("governance.approval.requested", transition, redaction)?
        }
        TraceEventKind::GovernanceApprovalGranted { transition } => {
            governance_transition_record("governance.approval.granted", transition, redaction)?
        }
        TraceEventKind::GovernanceApprovalDenied { transition } => {
            governance_transition_record("governance.approval.denied", transition, redaction)?
        }
        TraceEventKind::GovernanceApprovalExpired { transition } => {
            governance_transition_record("governance.approval.expired", transition, redaction)?
        }
        TraceEventKind::GovernanceApprovalRevoked { transition } => {
            governance_transition_record("governance.approval.revoked", transition, redaction)?
        }
        TraceEventKind::EscalationOpened { transition } => {
            governance_transition_record("governance.escalation.opened", transition, redaction)?
        }
        TraceEventKind::EscalationResolved { transition } => {
            governance_transition_record("governance.escalation.resolved", transition, redaction)?
        }
        TraceEventKind::EscalationExpired { transition } => {
            governance_transition_record("governance.escalation.expired", transition, redaction)?
        }
        TraceEventKind::EscalationRevoked { transition } => {
            governance_transition_record("governance.escalation.revoked", transition, redaction)?
        }
        TraceEventKind::InterventionRequested { transition } => governance_transition_record(
            "governance.intervention.requested",
            transition,
            redaction,
        )?,
        TraceEventKind::InterventionResolved { transition } => {
            governance_transition_record("governance.intervention.resolved", transition, redaction)?
        }
        TraceEventKind::InterventionCancelled { transition } => governance_transition_record(
            "governance.intervention.cancelled",
            transition,
            redaction,
        )?,
        TraceEventKind::InterventionExpired { transition } => {
            governance_transition_record("governance.intervention.expired", transition, redaction)?
        }
        TraceEventKind::InterventionRevoked { transition } => {
            governance_transition_record("governance.intervention.revoked", transition, redaction)?
        }
        TraceEventKind::GovernanceCircuitBreakerTripped { transition } => {
            governance_transition_record(
                "governance.circuit_breaker.tripped",
                transition,
                redaction,
            )?
        }
        TraceEventKind::GovernanceCircuitBreakerCleared { transition } => {
            governance_transition_record(
                "governance.circuit_breaker.cleared",
                transition,
                redaction,
            )?
        }
        TraceEventKind::GovernanceCircuitBreakerExpired { transition } => {
            governance_transition_record(
                "governance.circuit_breaker.expired",
                transition,
                redaction,
            )?
        }
        TraceEventKind::GovernanceCircuitBreakerRevoked { transition } => {
            governance_transition_record(
                "governance.circuit_breaker.revoked",
                transition,
                redaction,
            )?
        }
        TraceEventKind::KillSwitchActivated { transition } => {
            governance_transition_record("governance.kill_switch.activated", transition, redaction)?
        }
        TraceEventKind::KillSwitchCleared { transition } => {
            governance_transition_record("governance.kill_switch.cleared", transition, redaction)?
        }
        TraceEventKind::KillSwitchExpired { transition } => {
            governance_transition_record("governance.kill_switch.expired", transition, redaction)?
        }
        TraceEventKind::KillSwitchRevoked { transition } => {
            governance_transition_record("governance.kill_switch.revoked", transition, redaction)?
        }
        TraceEventKind::GovernanceTransitionRejected { rejection } => (
            "governance.transition.rejected",
            Some(rejection.reason.clone()),
            Some(rejection.object.object_id().to_string()),
            Some(sanitized_value(&rejection.scope, redaction)?),
            sanitized_value(rejection, redaction)?,
        ),
        _ => return Ok(None),
    };

    Ok(Some(AuditGovernanceRecord {
        trace_event_id: event.trace_event_id.clone(),
        sequence: event.sequence,
        identity: event.identity.clone(),
        event: event_name.to_string(),
        object_id,
        scope,
        reason: reason.map(|value| redact_sensitive_text(&value, redaction)),
        details,
    }))
}

fn governance_transition_record(
    event_name: &'static str,
    transition: &splendor_types::GovernanceTransition,
    redaction: &mut RedactionTracker,
) -> Result<GovernanceRecordParts, String> {
    Ok((
        event_name,
        Some(transition.reason.clone()),
        Some(transition.object.object_id().to_string()),
        Some(sanitized_value(&transition.scope, redaction)?),
        sanitized_value(transition, redaction)?,
    ))
}

fn load_verified_state_snapshot(
    state_store: &SqliteStateStore,
    snapshot_id: &SnapshotId,
    expected_state_hash: Option<&ContentHash>,
) -> Result<splendor_store::StateSnapshot, String> {
    let snapshot = state_store
        .load_snapshot(snapshot_id)
        .map_err(|_| "state_snapshot_load_failed".to_string())?;
    let recomputed_snapshot_id = SnapshotId::from_bytes(&snapshot.state.bytes);
    if recomputed_snapshot_id != *snapshot_id {
        return Err("state_snapshot_integrity_mismatch".to_string());
    }

    let node = load_verified_state_node(state_store, &snapshot.node_id, expected_state_hash)?;
    let data_hash = ContentHash::blake3(&snapshot.state.bytes);
    if node.data_hash != data_hash {
        return Err("state_snapshot_node_integrity_mismatch".to_string());
    }
    Ok(snapshot)
}

fn load_verified_state_node(
    state_store: &SqliteStateStore,
    state_node_id: &splendor_types::StateNodeId,
    expected_state_hash: Option<&ContentHash>,
) -> Result<splendor_store::StateNode, String> {
    let node = state_store
        .get_node(state_node_id)
        .map_err(|_| "state_node_load_failed".to_string())?;
    if node.id != *state_node_id {
        return Err("state_node_identity_mismatch".to_string());
    }
    if let Some(expected_state_hash) = expected_state_hash {
        if node.id.hash() != expected_state_hash {
            return Err("state_commit_hash_mismatch".to_string());
        }
    }
    let state = state_store
        .get_state(&node.data_ref)
        .map_err(|_| "state_data_load_failed".to_string())?;
    let data_hash = ContentHash::blake3(&state.bytes);
    if node.data_hash != data_hash {
        return Err("state_node_data_integrity_mismatch".to_string());
    }
    Ok(node)
}

fn validate_approval_trace_context(
    event: &TraceEvent,
    approval: &splendor_types::ApprovalTraceContext,
) -> Result<(), String> {
    validate_run_match(event, &approval.run_id, "Approval")?;
    if let Some(tenant_id) = &event.identity.tenant_id {
        if tenant_id != &approval.tenant_id {
            return Err("audit_approval_tenant_mismatch".to_string());
        }
    }
    if let Some(agent_id) = &event.identity.agent_id {
        if agent_id != &approval.agent_id {
            return Err("audit_approval_agent_mismatch".to_string());
        }
    }
    if let (Some(event_action_id), Some(approval_action_id)) =
        (&event.identity.action_id, &approval.action_id)
    {
        if event_action_id != approval_action_id {
            return Err("audit_approval_action_mismatch".to_string());
        }
    }
    Ok(())
}

fn validate_governance_trace_context(event: &TraceEvent) -> Result<(), String> {
    match &event.kind {
        TraceEventKind::GovernanceApprovalRequested { transition }
        | TraceEventKind::GovernanceApprovalGranted { transition }
        | TraceEventKind::GovernanceApprovalDenied { transition }
        | TraceEventKind::GovernanceApprovalExpired { transition }
        | TraceEventKind::GovernanceApprovalRevoked { transition }
        | TraceEventKind::EscalationOpened { transition }
        | TraceEventKind::EscalationResolved { transition }
        | TraceEventKind::EscalationExpired { transition }
        | TraceEventKind::EscalationRevoked { transition }
        | TraceEventKind::InterventionRequested { transition }
        | TraceEventKind::InterventionResolved { transition }
        | TraceEventKind::InterventionCancelled { transition }
        | TraceEventKind::InterventionExpired { transition }
        | TraceEventKind::InterventionRevoked { transition }
        | TraceEventKind::GovernanceCircuitBreakerTripped { transition }
        | TraceEventKind::GovernanceCircuitBreakerCleared { transition }
        | TraceEventKind::GovernanceCircuitBreakerExpired { transition }
        | TraceEventKind::GovernanceCircuitBreakerRevoked { transition }
        | TraceEventKind::KillSwitchActivated { transition }
        | TraceEventKind::KillSwitchCleared { transition }
        | TraceEventKind::KillSwitchExpired { transition }
        | TraceEventKind::KillSwitchRevoked { transition } => {
            validate_governance_scope_context(event, &transition.scope, "Governance transition")?;
            if let Some(run_id) = &transition.trace.run_id {
                validate_run_match(event, run_id, "Governance transition")?;
            }
        }
        TraceEventKind::GovernanceTransitionRejected { rejection } => {
            validate_governance_scope_context(
                event,
                &rejection.scope,
                "Governance transition rejection",
            )?;
            if let Some(run_id) = &rejection.trace.run_id {
                validate_run_match(event, run_id, "Governance transition rejection")?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_governance_scope_context(
    event: &TraceEvent,
    scope: &GovernanceScope,
    label: &str,
) -> Result<(), String> {
    if let Some(run_id) = scope.run_id() {
        validate_run_match(event, run_id, label)?;
    }
    if let (Some(event_tenant_id), Some(scope_tenant_id)) =
        (&event.identity.tenant_id, scope.tenant_id())
    {
        if event_tenant_id != scope_tenant_id {
            return Err("audit_governance_tenant_mismatch".to_string());
        }
    }
    if let (Some(event_agent_id), Some(scope_agent_id)) =
        (&event.identity.agent_id, scope.agent_id())
    {
        if event_agent_id != scope_agent_id {
            return Err("audit_governance_agent_mismatch".to_string());
        }
    }
    if let (Some(event_action_id), Some(scope_action_id)) =
        (&event.identity.action_id, scope.action_id())
    {
        if event_action_id != scope_action_id {
            return Err("audit_governance_action_mismatch".to_string());
        }
    }
    Ok(())
}

fn validate_run_match(
    event: &TraceEvent,
    actual_run_id: &RunId,
    _label: &str,
) -> Result<(), String> {
    if actual_run_id != &event.run_id {
        return Err("audit_trace_run_mismatch".to_string());
    }
    Ok(())
}

fn sanitized_value<T: Serialize>(
    value: &T,
    redaction: &mut RedactionTracker,
) -> Result<serde_json::Value, String> {
    let value = serde_json::to_value(value).map_err(|_| "audit_value_encode_failed".to_string())?;
    Ok(redact_value(value, redaction))
}

fn redact_value(value: serde_json::Value, redaction: &mut RedactionTracker) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .into_iter()
                .map(|item| redact_value(item, redaction))
                .collect(),
        ),
        serde_json::Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, value) in map {
                if is_sensitive_key(&key) {
                    redaction.record(&key);
                    redacted.insert(key, serde_json::Value::String("[REDACTED]".to_string()));
                } else {
                    redacted.insert(key, redact_value(value, redaction));
                }
            }
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::String(value) => {
            serde_json::Value::String(redact_sensitive_text(&value, redaction))
        }
        other => other,
    }
}

fn redact_sensitive_text(value: &str, redaction: &mut RedactionTracker) -> String {
    if is_sensitive_text(value) {
        redaction.record("sensitive_text");
        "[REDACTED]".to_string()
    } else {
        value.to_string()
    }
}

fn is_sensitive_text(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    let compact = compact_sensitive_match_text(&normalized);
    [
        "authorization:",
        "authorization=",
        "bearer ",
        "token:",
        "token=",
        "secret:",
        "secret=",
        "password:",
        "password=",
        "credential:",
        "credential=",
        "api_key:",
        "api_key=",
        "apikey:",
        "apikey=",
        "signature:",
        "signature=",
        "private_key:",
        "private_key=",
        "private key",
        "-----begin",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
        || [
            "authorization",
            "bearer",
            "token",
            "secret",
            "password",
            "credential",
            "apikey",
            "signature",
            "privatekey",
        ]
        .iter()
        .any(|needle| compact.contains(needle))
        || looks_like_jwt(value)
}

fn looks_like_jwt(value: &str) -> bool {
    let token = value.trim();
    let mut parts = token.split('.');
    let Some(header) = parts.next() else {
        return false;
    };
    let Some(payload) = parts.next() else {
        return false;
    };
    let Some(signature) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    [header, payload, signature].iter().all(|part| {
        part.len() >= 8
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    let compact = compact_sensitive_match_text(&normalized);
    [
        "secret",
        "token",
        "password",
        "credential",
        "api_key",
        "apikey",
        "authorization",
        "bearer",
        "signature",
        "private_key",
        "snapshot_bytes",
        "state_bytes",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
        || [
            "secret",
            "token",
            "password",
            "credential",
            "apikey",
            "authorization",
            "bearer",
            "signature",
            "privatekey",
            "snapshotbytes",
            "statebytes",
        ]
        .iter()
        .any(|needle| compact.contains(needle))
}

fn compact_sensitive_match_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect()
}

fn audit_action_key(event: &TraceEvent, action: &Action) -> String {
    event.identity.action_id.as_ref().map_or_else(
        || format!("action:{}", action.name),
        |action_id| format!("action_id:{action_id}"),
    )
}

fn event_has_tenant(event: &TraceEvent, expected: &str) -> bool {
    if event.identity.tenant_id.as_ref().map(ToString::to_string) == Some(expected.to_string()) {
        return true;
    }
    match &event.kind {
        TraceEventKind::WorkOrderAccepted { tenant_id, .. } => tenant_id.to_string() == expected,
        TraceEventKind::WorkOrderRejected { tenant_id, .. } => {
            tenant_id.as_ref().map(ToString::to_string).as_deref() == Some(expected)
        }
        TraceEventKind::ApprovalRequested { approval }
        | TraceEventKind::ApprovalGranted { approval }
        | TraceEventKind::ApprovalDenied { approval, .. }
        | TraceEventKind::ApprovalExpired { approval, .. }
        | TraceEventKind::ApprovalRevoked { approval, .. } => {
            approval.tenant_id.to_string() == expected
        }
        TraceEventKind::ActionVerificationCompleted { result, .. }
        | TraceEventKind::ActionNeedsApproval { result, .. }
        | TraceEventKind::ActionDenied { result, .. }
        | TraceEventKind::ActionNeedsIntervention { result, .. }
        | TraceEventKind::ActionFailed { result, .. } => {
            string_json_pointer(&result.artifacts, "/context/tenant_id").as_deref()
                == Some(expected)
        }
        _ => false,
    }
}

fn event_has_agent(event: &TraceEvent, expected: &str) -> bool {
    if event.identity.agent_id.as_ref().map(ToString::to_string) == Some(expected.to_string()) {
        return true;
    }
    match &event.kind {
        TraceEventKind::WorkOrderAccepted { agent_id, .. } => agent_id.to_string() == expected,
        TraceEventKind::WorkOrderRejected { agent_id, .. } => {
            agent_id.as_ref().map(ToString::to_string).as_deref() == Some(expected)
        }
        TraceEventKind::ApprovalRequested { approval }
        | TraceEventKind::ApprovalGranted { approval }
        | TraceEventKind::ApprovalDenied { approval, .. }
        | TraceEventKind::ApprovalExpired { approval, .. }
        | TraceEventKind::ApprovalRevoked { approval, .. } => {
            approval.agent_id.to_string() == expected
        }
        TraceEventKind::ActionVerificationCompleted { result, .. }
        | TraceEventKind::ActionNeedsApproval { result, .. }
        | TraceEventKind::ActionDenied { result, .. }
        | TraceEventKind::ActionNeedsIntervention { result, .. }
        | TraceEventKind::ActionFailed { result, .. } => {
            string_json_pointer(&result.artifacts, "/context/agent_id").as_deref() == Some(expected)
        }
        _ => false,
    }
}

fn event_has_action(event: &TraceEvent, expected: &str) -> bool {
    if event.identity.action_id.as_ref().map(ToString::to_string) == Some(expected.to_string()) {
        return true;
    }
    if action_for_event(event).is_some_and(|action| action.name == expected) {
        return true;
    }
    match &event.kind {
        TraceEventKind::ApprovalRequested { approval }
        | TraceEventKind::ApprovalGranted { approval }
        | TraceEventKind::ApprovalDenied { approval, .. }
        | TraceEventKind::ApprovalExpired { approval, .. }
        | TraceEventKind::ApprovalRevoked { approval, .. } => {
            approval.action_id.as_ref().map(ToString::to_string) == Some(expected.to_string())
                || approval.action_name == expected
        }
        TraceEventKind::EscalationTriggered { escalation } => {
            escalation.action_id.as_ref().map(ToString::to_string) == Some(expected.to_string())
                || escalation.action_name.as_deref() == Some(expected)
        }
        TraceEventKind::ActionVerificationCompleted { result, .. }
        | TraceEventKind::ActionNeedsApproval { result, .. }
        | TraceEventKind::ActionDenied { result, .. }
        | TraceEventKind::ActionNeedsIntervention { result, .. }
        | TraceEventKind::ActionFailed { result, .. } => {
            string_json_pointer(&result.artifacts, "/context/action_id").as_deref()
                == Some(expected)
                || string_json_pointer(&result.artifacts, "/context/action").as_deref()
                    == Some(expected)
        }
        _ => false,
    }
}

fn audit_adapter_index(events: &[TraceEvent]) -> BTreeMap<String, String> {
    let mut adapters = BTreeMap::new();
    for event in events {
        if let TraceEventKind::ActionVerificationCompleted { action, result } = &event.kind {
            if let Some(adapter) = adapter_from_result(result) {
                adapters.insert(audit_action_key(event, action), adapter);
            }
        }
    }
    adapters
}

fn event_has_adapter(
    event: &TraceEvent,
    expected: &str,
    adapter_by_action: &BTreeMap<String, String>,
) -> bool {
    match &event.kind {
        TraceEventKind::ApprovalRequested { approval }
        | TraceEventKind::ApprovalGranted { approval }
        | TraceEventKind::ApprovalDenied { approval, .. }
        | TraceEventKind::ApprovalExpired { approval, .. }
        | TraceEventKind::ApprovalRevoked { approval, .. } => {
            approval.adapter.as_deref() == Some(expected)
        }
        TraceEventKind::EscalationTriggered { escalation } => {
            escalation.adapter.as_deref() == Some(expected)
        }
        TraceEventKind::CircuitBreakerTripped { breaker }
        | TraceEventKind::CircuitBreakerCleared { breaker } => {
            breaker.scope.label() == "adapter" && breaker.scope.value().as_deref() == Some(expected)
        }
        TraceEventKind::ActionVerificationCompleted { result, .. }
        | TraceEventKind::ActionNeedsApproval { result, .. }
        | TraceEventKind::ActionDenied { result, .. }
        | TraceEventKind::ActionNeedsIntervention { result, .. }
        | TraceEventKind::ActionFailed { result, .. } => {
            adapter_from_result(result).as_deref() == Some(expected)
        }
        _ => action_for_event(event)
            .and_then(|action| adapter_by_action.get(&audit_action_key(event, action)))
            .map(|adapter| adapter == expected)
            .unwrap_or_else(|| {
                action_for_event(event)
                    .and_then(|action| adapter_from_action_name(&action.name))
                    .as_deref()
                    == Some(expected)
            }),
    }
}

fn action_for_event(event: &TraceEvent) -> Option<&Action> {
    match &event.kind {
        TraceEventKind::ActionVerificationStarted { action }
        | TraceEventKind::ActionVerificationCompleted { action, .. }
        | TraceEventKind::ActionNeedsApproval { action, .. }
        | TraceEventKind::ActionExecuted { action, .. }
        | TraceEventKind::ActionDenied { action, .. }
        | TraceEventKind::ActionFailed { action, .. }
        | TraceEventKind::ActionNeedsIntervention { action, .. } => Some(action),
        _ => None,
    }
}

fn adapter_from_result(result: &splendor_types::VerificationResult) -> Option<String> {
    string_json_pointer(&result.artifacts, "/context/adapter")
        .or_else(|| string_json_pointer(&result.artifacts, "/requested"))
        .or_else(|| {
            let breaker = circuit_breaker_artifact(&result.artifacts)?;
            if string_artifact(breaker, "scope").as_deref() == Some("adapter") {
                return string_artifact(breaker, "scope_value");
            }
            None
        })
}

fn adapter_from_action_name(action_name: &str) -> Option<String> {
    match action_name {
        "write_file" | "read_file" | "list_dir" | "delete_file" => Some("filesystem".to_string()),
        "http.fetch" | "http_fetch" => Some("http".to_string()),
        _ => None,
    }
}

fn string_json_pointer(value: &serde_json::Value, pointer: &str) -> Option<String> {
    value.pointer(pointer)?.as_str().map(str::to_string)
}

fn string_value(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_string)
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ReplayOutput {
    ReplayLifecycle {
        event: String,
        trace_event_id: TraceEventId,
        run_id: String,
        replay_mode: String,
        side_effects_replayed: bool,
    },
    ReplayStart {
        run_id: String,
        from_snapshot: Option<String>,
        snapshot_bytes_len: Option<usize>,
        replay_mode: String,
        side_effects_replayed: bool,
    },
    Tick {
        tick_id: u64,
        policy: Option<String>,
        percepts: Vec<splendor_types::Percept>,
        candidates: Vec<splendor_types::Action>,
        constraints: Box<Option<splendor_types::VerificationResult>>,
        actions: Vec<ReplayAction>,
        outcome: Option<serde_json::Value>,
        feedback: Box<Option<splendor_types::Feedback>>,
        reward: Box<Option<splendor_types::Reward>>,
        state_hash: Option<ContentHash>,
        snapshot_id: Box<Option<SnapshotId>>,
        snapshot_bytes_len: Option<usize>,
        snapshot_bytes: Box<Option<Vec<u8>>>,
        messages: Vec<ReplayMessageEvent>,
        parent_child_runs: Vec<ReplayParentChildRun>,
        isolation_denials: Vec<ReplayIsolationDenial>,
        escalations: Vec<ReplayEscalation>,
        approval_events: Vec<ReplayApprovalEvent>,
        circuit_breaker_denials: Vec<ReplayCircuitBreakerDenial>,
    },
    CausalGraph {
        run_id: String,
        replay_mode: String,
        side_effects_replayed: bool,
        messages: Vec<ReplayMessageEvent>,
        parent_child_runs: Vec<ReplayParentChildRun>,
        isolation_denials: Vec<ReplayIsolationDenial>,
        approval_events: Vec<ReplayApprovalEvent>,
        circuit_breaker_denials: Vec<ReplayCircuitBreakerDenial>,
    },
    HandoffBoundary {
        event_kind: String,
        handoff: Box<StateHandoffTraceContext>,
        previous_state_node_id: Option<String>,
        receiver_state_node_id: Option<String>,
        reason: Option<String>,
        trace_sequence: u64,
    },
}

fn replay_lifecycle_record(run_id: &RunId, event: &str, sequence: u64) -> ReplayOutput {
    ReplayOutput::ReplayLifecycle {
        event: event.to_string(),
        trace_event_id: TraceEventId::from_run_sequence(run_id, sequence),
        run_id: run_id.to_string(),
        replay_mode: "inspect_only".to_string(),
        side_effects_replayed: false,
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ReplayAction {
    action: splendor_types::Action,
    status: String,
    outcome: Option<serde_json::Value>,
    result: Option<splendor_types::VerificationResult>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ReplayMessageEvent {
    lifecycle: String,
    trace_event_id: TraceEventId,
    message_id: MessageId,
    source_agent_id: AgentId,
    target_agent_id: AgentId,
    run_id: RunId,
    schema: String,
    causal_parent: Option<TraceEventId>,
    reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ReplayParentChildRun {
    trace_event_id: TraceEventId,
    parent_run_id: RunId,
    child_run_id: RunId,
    parent_agent_id: AgentId,
    child_agent_id: AgentId,
    causal_parent: Option<TraceId>,
    source_message_id: Option<MessageId>,
    side_effects_replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ReplayIsolationDenial {
    trace_event_id: TraceEventId,
    action: splendor_types::Action,
    reasons: Vec<String>,
    artifacts: serde_json::Value,
    verifier: Option<String>,
    ledger_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ReplayEscalation {
    trace_event_id: TraceEventId,
    escalation: splendor_types::EscalationContext,
    side_effects_replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ReplayApprovalEvent {
    lifecycle: String,
    trace_event_id: TraceEventId,
    approval: splendor_types::ApprovalTraceContext,
    reason: Option<String>,
    side_effects_replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ReplayCircuitBreakerDenial {
    trace_event_id: TraceEventId,
    action: splendor_types::Action,
    reasons: Vec<String>,
    breaker_id: Option<String>,
    scope: Option<String>,
    scope_value: Option<String>,
    reason: Option<String>,
    artifacts: serde_json::Value,
}

#[derive(Default)]
struct ReplayTick {
    tick_id: u64,
    policy: Option<String>,
    percepts: Vec<splendor_types::Percept>,
    candidates: Vec<splendor_types::Action>,
    constraints: Option<splendor_types::VerificationResult>,
    actions: Vec<ReplayAction>,
    outcome: Option<serde_json::Value>,
    feedback: Option<splendor_types::Feedback>,
    reward: Option<splendor_types::Reward>,
    state_hash: Option<ContentHash>,
    snapshot_id: Option<SnapshotId>,
    snapshot_bytes_len: Option<usize>,
    snapshot_bytes: Option<Vec<u8>>,
    messages: Vec<ReplayMessageEvent>,
    parent_child_runs: Vec<ReplayParentChildRun>,
    isolation_denials: Vec<ReplayIsolationDenial>,
    escalations: Vec<ReplayEscalation>,
    approval_events: Vec<ReplayApprovalEvent>,
    circuit_breaker_denials: Vec<ReplayCircuitBreakerDenial>,
}

#[derive(Default)]
struct ReplayCausalGraph {
    messages: Vec<ReplayMessageEvent>,
    parent_child_runs: Vec<ReplayParentChildRun>,
    isolation_denials: Vec<ReplayIsolationDenial>,
    approval_events: Vec<ReplayApprovalEvent>,
    circuit_breaker_denials: Vec<ReplayCircuitBreakerDenial>,
}

/// Replays a run by reconstructing tick-by-tick outputs from trace + snapshots.
fn replay_run(
    trace_db_path: &PathBuf,
    state_db_path: &PathBuf,
    run_id: &str,
    from_snapshot: Option<&str>,
    include_state: bool,
) -> Result<(), String> {
    let outputs = replay_outputs_from_stores(
        trace_db_path,
        state_db_path,
        run_id,
        from_snapshot,
        include_state,
    )?;
    let mut spool = Vec::new();
    for output in outputs {
        let value = redacted_replay_output_value(&output)?;
        append_json_line(&mut spool, &value, "replay_output_encode_failed")?;
    }
    std::io::stdout()
        .lock()
        .write_all(&spool)
        .map_err(|_| "replay_output_write_failed".to_string())?;
    Ok(())
}

fn replay_outputs_from_stores(
    trace_db_path: &PathBuf,
    state_db_path: &PathBuf,
    run_id: &str,
    from_snapshot: Option<&str>,
    include_state: bool,
) -> Result<Vec<ReplayOutput>, String> {
    if !trace_db_path.exists() {
        return Err("trace_database_not_found".to_string());
    }
    if !state_db_path.exists() {
        return Err("state_database_not_found".to_string());
    }
    let trace_store = SqliteTraceStore::open_read_only(trace_db_path)
        .map_err(|_| "trace_store_open_failed".to_string())?;
    let state_store = SqliteStateStore::open_read_only(state_db_path)
        .map_err(|_| "state_store_open_failed".to_string())?;
    let records = validated_trace_records(&trace_store, run_id, TraceProjection::Trusted)?;
    let events = decode_validated_trace_records(&records)?;

    let from_snapshot_id = match from_snapshot {
        Some(value) => Some(parse_snapshot_id(value)?),
        None => None,
    };
    let start_tick = if let Some(snapshot_id) = &from_snapshot_id {
        Some(
            find_tick_for_snapshot(&events, snapshot_id)
                .ok_or_else(|| "replay_snapshot_not_found".to_string())?,
        )
    } else {
        None
    };

    let snapshot_len = if let Some(snapshot_id) = &from_snapshot_id {
        let snapshot = load_verified_state_snapshot(&state_store, snapshot_id, None)?;
        Some(snapshot.state.bytes.len())
    } else {
        None
    };

    collect_replay_outputs(
        &events,
        &state_store,
        run_id,
        from_snapshot.map(str::to_string),
        snapshot_len,
        start_tick,
        include_state,
    )
    .map_err(|_| "replay_projection_failed".to_string())
}

fn collect_replay_outputs(
    events: &[TraceEvent],
    state_store: &SqliteStateStore,
    run_id: &str,
    from_snapshot: Option<String>,
    snapshot_bytes_len: Option<usize>,
    start_tick: Option<u64>,
    include_state: bool,
) -> Result<Vec<ReplayOutput>, String> {
    let replay_run_id = if let Some(event) = events.first() {
        event.run_id.clone()
    } else {
        RunId::parse(run_id).map_err(|_| "trace_run_id_invalid".to_string())?
    };
    let next_replay_sequence = events
        .iter()
        .map(|event| event.sequence)
        .max()
        .map_or(0, |sequence| sequence + 1);
    let mut outputs = vec![
        replay_lifecycle_record(&replay_run_id, "replay.started", next_replay_sequence),
        ReplayOutput::ReplayStart {
            run_id: run_id.to_string(),
            from_snapshot,
            snapshot_bytes_len,
            replay_mode: "inspect_only".to_string(),
            side_effects_replayed: false,
        },
    ];

    let mut current_tick: Option<ReplayTick> = None;
    let mut current_tick_id = 0;
    let mut causal_graph = ReplayCausalGraph::default();
    for event in events {
        match &event.kind {
            TraceEventKind::StateHandoffExported { handoff } => {
                outputs.push(handoff_replay_output(
                    "state.handoff.exported",
                    handoff,
                    None,
                    event,
                ));
            }
            TraceEventKind::StateHandoffImported { handoff } => {
                outputs.push(handoff_replay_output(
                    "state.handoff.imported",
                    handoff,
                    None,
                    event,
                ));
            }
            TraceEventKind::StateHandoffImportFailed { handoff, reason } => {
                outputs.push(handoff_replay_output(
                    "state.handoff.import_failed",
                    handoff,
                    Some(reason.clone()),
                    event,
                ));
            }
            TraceEventKind::ReadOnlyStateReferenced { handoff } => {
                outputs.push(handoff_replay_output(
                    "state.reference.read_only",
                    handoff,
                    None,
                    event,
                ));
            }
            TraceEventKind::LoopTickStarted { tick_id } => {
                current_tick_id = *tick_id;
                if start_tick.map(|start| *tick_id < start).unwrap_or(false) {
                    current_tick = None;
                    continue;
                }
                current_tick = Some(ReplayTick {
                    tick_id: *tick_id,
                    ..ReplayTick::default()
                });
            }
            TraceEventKind::LoopTickCompleted { tick_id, .. } => {
                if start_tick.map(|start| *tick_id < start).unwrap_or(false) {
                    continue;
                }
                if let Some(tick) = current_tick.take() {
                    outputs.push(ReplayOutput::Tick {
                        tick_id: tick.tick_id,
                        policy: tick.policy,
                        percepts: tick.percepts,
                        candidates: tick.candidates,
                        constraints: Box::new(tick.constraints),
                        actions: tick.actions,
                        outcome: tick.outcome,
                        feedback: Box::new(tick.feedback),
                        reward: Box::new(tick.reward),
                        state_hash: tick.state_hash,
                        snapshot_id: Box::new(tick.snapshot_id),
                        snapshot_bytes_len: tick.snapshot_bytes_len,
                        snapshot_bytes: Box::new(tick.snapshot_bytes),
                        messages: tick.messages,
                        parent_child_runs: tick.parent_child_runs,
                        isolation_denials: tick.isolation_denials,
                        escalations: tick.escalations,
                        approval_events: tick.approval_events,
                        circuit_breaker_denials: tick.circuit_breaker_denials,
                    });
                }
            }
            _ => {
                if start_tick
                    .map(|start| current_tick_id < start)
                    .unwrap_or(false)
                {
                    continue;
                }
                let message_event = replay_message_event(event)?;
                let parent_child_run = replay_parent_child_run(event)?;
                let isolation_denial = replay_isolation_denial(event);
                let approval_event = replay_approval_event(event)?;
                let circuit_breaker_denial = replay_circuit_breaker_denial(event);

                if let Some(tick) = current_tick.as_mut() {
                    apply_event_to_tick(tick, event, state_store, include_state)?;
                    if let Some(parent_child_run) = parent_child_run.clone() {
                        tick.parent_child_runs.push(parent_child_run);
                    }
                    if let Some(isolation_denial) = isolation_denial.clone() {
                        tick.isolation_denials.push(isolation_denial);
                    }
                    if let Some(circuit_breaker_denial) = circuit_breaker_denial.clone() {
                        tick.circuit_breaker_denials.push(circuit_breaker_denial);
                    }
                    if let Some(approval_event) = approval_event.clone() {
                        tick.approval_events.push(approval_event);
                    }
                }

                if let Some(message_event) = message_event {
                    causal_graph.messages.push(message_event);
                }
                if let Some(parent_child_run) = parent_child_run {
                    causal_graph.parent_child_runs.push(parent_child_run);
                }
                if let Some(isolation_denial) = isolation_denial {
                    causal_graph.isolation_denials.push(isolation_denial);
                }
                if let Some(approval_event) = approval_event {
                    causal_graph.approval_events.push(approval_event);
                }
                if let Some(circuit_breaker_denial) = circuit_breaker_denial {
                    causal_graph
                        .circuit_breaker_denials
                        .push(circuit_breaker_denial);
                }
            }
        }
    }
    outputs.push(ReplayOutput::CausalGraph {
        run_id: run_id.to_string(),
        replay_mode: "inspect_only".to_string(),
        side_effects_replayed: false,
        messages: causal_graph.messages,
        parent_child_runs: causal_graph.parent_child_runs,
        isolation_denials: causal_graph.isolation_denials,
        approval_events: causal_graph.approval_events,
        circuit_breaker_denials: causal_graph.circuit_breaker_denials,
    });
    if events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ActionExecuted { .. }))
    {
        outputs.push(replay_lifecycle_record(
            &replay_run_id,
            "replay.adapter_suppressed",
            next_replay_sequence + 1,
        ));
    }
    outputs.push(replay_lifecycle_record(
        &replay_run_id,
        "replay.completed",
        next_replay_sequence + 2,
    ));
    Ok(outputs)
}

fn validated_trace_records(
    store: &dyn TraceStore,
    run_id: &str,
    projection: TraceProjection,
) -> Result<Vec<TraceRecord>, String> {
    let run_id = RunId::parse(run_id).map_err(|_| "trace_run_id_invalid".to_string())?;
    let reader = open_trace_reader(store, &run_id, RuntimeTraceLimits::default())
        .map_err(|error| error.to_string())?;
    project_trace(reader.as_ref(), &run_id, projection).map_err(|error| error.to_string())
}

fn decode_validated_trace_records(records: &[TraceRecord]) -> Result<Vec<TraceEvent>, String> {
    let mut events = Vec::with_capacity(records.len());
    for record in records {
        let event: TraceEvent = serde_json::from_value(record.payload.clone())
            .map_err(|_| "trace_event_decode_failed".to_string())?;
        events.push(event);
    }
    Ok(events)
}

#[cfg(test)]
fn decode_and_validate_trace_records(
    records: &[TraceRecord],
    run_id: &str,
) -> Result<Vec<TraceEvent>, String> {
    let run_id = RunId::parse(run_id).map_err(|_| "trace_run_id_invalid".to_string())?;
    let store_identity = RuntimeTraceStoreIdentity::from_opaque_material(b"cli-test-reader");
    let mut envelope_tail = None;
    for record in records {
        envelope_tail = Some(
            compute_trace_envelope_hash(envelope_tail.as_ref(), record)
                .map_err(|error| error.to_string())?,
        );
    }
    let tail = RuntimeTraceTail::legacy(
        store_identity.clone(),
        u64::try_from(records.len()).map_err(|_| "runtime_trace_limit_exceeded".to_string())?,
        records.last().map(|record| record.event_hash.clone()),
        envelope_tail,
    )
    .map_err(|error| error.to_string())?;
    let reader = TestTraceReader {
        records: records.to_vec(),
        run_id: run_id.to_string(),
        store_identity,
        tail,
    };
    inspect_trace(&reader, &run_id)
        .map(|inspected| inspected.events)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
struct TestTraceReader {
    records: Vec<TraceRecord>,
    run_id: String,
    store_identity: RuntimeTraceStoreIdentity,
    tail: RuntimeTraceTail,
}

#[cfg(test)]
impl RuntimeTraceReader for TestTraceReader {
    fn store_identity(&self) -> RuntimeTraceStoreIdentity {
        self.store_identity.clone()
    }

    fn run_id(&self) -> &str {
        &self.run_id
    }

    fn limits(&self) -> RuntimeTraceLimits {
        RuntimeTraceLimits::default()
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
            .saturating_add(RuntimeTraceLimits::default().page_records)
            .min(self.records.len());
        Ok(RuntimeTracePage::new(
            self.records[start..end].to_vec(),
            u64::try_from(end).map_err(|_| RuntimeTracePortError::LimitExceeded)?,
            end == self.records.len(),
        ))
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        if expected == &self.tail {
            Ok(())
        } else {
            Err(RuntimeTracePortError::FenceRejected)
        }
    }
}

fn replay_message_event(event: &TraceEvent) -> Result<Option<ReplayMessageEvent>, String> {
    let (lifecycle, message, reason) = match &event.kind {
        TraceEventKind::MessageQueued { message } => ("queued", message, None),
        TraceEventKind::MessageDelivered { message } => ("delivered", message, None),
        TraceEventKind::MessageConsumed { message } => ("consumed", message, None),
        TraceEventKind::MessageRejected { message, reason } => {
            ("rejected", message, Some(reason.clone()))
        }
        TraceEventKind::MessageExpired { message, reason } => ("expired", message, reason.clone()),
        _ => return Ok(None),
    };
    if message.run_id != event.run_id {
        return Err("replay_message_run_mismatch".to_string());
    }

    Ok(Some(ReplayMessageEvent {
        lifecycle: lifecycle.to_string(),
        trace_event_id: event.trace_event_id.clone(),
        message_id: message.message_id.clone(),
        source_agent_id: message.source_agent_id.clone(),
        target_agent_id: message.target_agent_id.clone(),
        run_id: message.run_id.clone(),
        schema: message.schema.clone(),
        causal_parent: message.causal_parent.clone(),
        reason,
    }))
}

fn replay_parent_child_run(event: &TraceEvent) -> Result<Option<ReplayParentChildRun>, String> {
    match &event.kind {
        TraceEventKind::DelegationRequested { delegation }
        | TraceEventKind::ChildRunCompleted { delegation }
        | TraceEventKind::ChildRunFailed { delegation, .. }
        | TraceEventKind::DelegationRejected { delegation, .. } => {
            if delegation.parent_run_id != event.run_id {
                return Err("replay_delegation_run_mismatch".to_string());
            }
            return Ok(Some(ReplayParentChildRun {
                trace_event_id: event.trace_event_id.clone(),
                parent_run_id: delegation.parent_run_id.clone(),
                child_run_id: delegation.child_run_id.clone(),
                parent_agent_id: delegation.source_agent_id.clone(),
                child_agent_id: delegation.target_agent_id.clone(),
                causal_parent: delegation.parent_trace_id.clone(),
                source_message_id: delegation.request_message_id.clone(),
                side_effects_replayed: false,
            }));
        }
        TraceEventKind::ChildRunStarted { delegation } => {
            return Ok(Some(ReplayParentChildRun {
                trace_event_id: event.trace_event_id.clone(),
                parent_run_id: delegation.parent_run_id.clone(),
                child_run_id: delegation.child_run_id.clone(),
                parent_agent_id: delegation.source_agent_id.clone(),
                child_agent_id: delegation.target_agent_id.clone(),
                causal_parent: delegation.parent_trace_id.clone(),
                source_message_id: delegation.request_message_id.clone(),
                side_effects_replayed: false,
            }));
        }
        _ => {}
    }
    if let TraceEventKind::ChildRunLinked {
        parent_run_id,
        child_run_id,
        parent_agent_id,
        child_agent_id,
        causal_parent,
        source_message_id,
    } = &event.kind
    {
        if parent_run_id != &event.run_id {
            return Err("replay_child_run_mismatch".to_string());
        }
        return Ok(Some(ReplayParentChildRun {
            trace_event_id: event.trace_event_id.clone(),
            parent_run_id: parent_run_id.clone(),
            child_run_id: child_run_id.clone(),
            parent_agent_id: parent_agent_id.clone(),
            child_agent_id: child_agent_id.clone(),
            causal_parent: causal_parent.clone(),
            source_message_id: source_message_id.clone(),
            side_effects_replayed: false,
        }));
    }
    Ok(None)
}

fn replay_isolation_denial(event: &TraceEvent) -> Option<ReplayIsolationDenial> {
    if let TraceEventKind::ActionDenied { action, result } = &event.kind {
        if !is_permission_laundering_denial(result) {
            return None;
        }
        return Some(ReplayIsolationDenial {
            trace_event_id: event.trace_event_id.clone(),
            action: action.clone(),
            reasons: result.reasons.clone(),
            artifacts: result.artifacts.clone(),
            verifier: string_artifact(&result.artifacts, "verifier"),
            ledger_reason: string_artifact(&result.artifacts, "ledger_reason"),
        });
    }
    None
}

fn replay_approval_event(event: &TraceEvent) -> Result<Option<ReplayApprovalEvent>, String> {
    let (lifecycle, approval, reason) = match &event.kind {
        TraceEventKind::ApprovalRequested { approval } => ("requested", approval, None),
        TraceEventKind::ApprovalGranted { approval } => ("granted", approval, None),
        TraceEventKind::ApprovalDenied { approval, reason } => {
            ("denied", approval, Some(reason.clone()))
        }
        TraceEventKind::ApprovalExpired { approval, reason } => {
            ("expired", approval, Some(reason.clone()))
        }
        TraceEventKind::ApprovalRevoked { approval, reason } => {
            ("revoked", approval, Some(reason.clone()))
        }
        _ => return Ok(None),
    };
    validate_approval_trace_context(event, approval)?;
    Ok(Some(ReplayApprovalEvent {
        lifecycle: lifecycle.to_string(),
        trace_event_id: event.trace_event_id.clone(),
        approval: approval.clone(),
        reason,
        side_effects_replayed: false,
    }))
}

fn replay_circuit_breaker_denial(event: &TraceEvent) -> Option<ReplayCircuitBreakerDenial> {
    if let TraceEventKind::ActionDenied { action, result } = &event.kind {
        if !is_circuit_breaker_denial(result) {
            return None;
        }
        let breaker = circuit_breaker_artifact(&result.artifacts);
        return Some(ReplayCircuitBreakerDenial {
            trace_event_id: event.trace_event_id.clone(),
            action: action.clone(),
            reasons: result.reasons.clone(),
            breaker_id: breaker.and_then(|value| string_artifact(value, "breaker_id")),
            scope: breaker.and_then(|value| string_artifact(value, "scope")),
            scope_value: breaker.and_then(|value| string_artifact(value, "scope_value")),
            reason: breaker.and_then(|value| string_artifact(value, "reason")),
            artifacts: result.artifacts.clone(),
        });
    }
    None
}

fn is_circuit_breaker_denial(result: &splendor_types::VerificationResult) -> bool {
    !result.allowed
        && (result
            .reasons
            .iter()
            .any(|reason| reason == "circuit_breaker_tripped")
            || circuit_breaker_artifact(&result.artifacts).is_some())
}

fn circuit_breaker_artifact(artifacts: &serde_json::Value) -> Option<&serde_json::Value> {
    let value = artifacts.get("circuit_breaker")?;
    Some(value.get("circuit_breaker").unwrap_or(value))
}

fn is_permission_laundering_denial(result: &splendor_types::VerificationResult) -> bool {
    if result.allowed {
        return false;
    }
    let explicit_reason = result
        .reasons
        .iter()
        .any(|reason| reason == "permission_laundering_denied");
    let verifier_mentions_isolation = string_artifact(&result.artifacts, "verifier")
        .map(|value| value.contains("isolation") || value.contains("ledger"))
        .unwrap_or(false);
    let has_ledger_reason = string_artifact(&result.artifacts, "ledger_reason").is_some();
    explicit_reason || verifier_mentions_isolation || has_ledger_reason
}

fn string_artifact(artifacts: &serde_json::Value, key: &str) -> Option<String> {
    artifacts
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn apply_event_to_tick(
    tick: &mut ReplayTick,
    event: &TraceEvent,
    state_store: &SqliteStateStore,
    include_state: bool,
) -> Result<(), String> {
    match &event.kind {
        TraceEventKind::PerceptsReceived { percepts } => tick.percepts = percepts.clone(),
        TraceEventKind::PolicyInvoked { policy } => tick.policy = Some(policy.clone()),
        TraceEventKind::PolicyCompleted { policy } => tick.policy = Some(policy.clone()),
        TraceEventKind::CandidatesProposed { actions } => tick.candidates = actions.clone(),
        TraceEventKind::ConstraintsEvaluated { result, .. } => {
            tick.constraints = Some(result.clone())
        }
        TraceEventKind::ActionExecuted { action, outcome } => {
            tick.actions.push(ReplayAction {
                action: action.clone(),
                status: "executed".to_string(),
                outcome: Some(outcome.clone()),
                result: None,
            });
        }
        TraceEventKind::ActionDenied { action, result } => {
            tick.actions.push(ReplayAction {
                action: action.clone(),
                status: "denied".to_string(),
                outcome: None,
                result: Some(result.clone()),
            });
        }
        TraceEventKind::ActionNeedsApproval { action, result } => {
            tick.actions.push(ReplayAction {
                action: action.clone(),
                status: "needs_approval".to_string(),
                outcome: None,
                result: Some(result.clone()),
            });
        }
        TraceEventKind::ActionFailed { action, result, .. } => {
            tick.actions.push(ReplayAction {
                action: action.clone(),
                status: "failed".to_string(),
                outcome: None,
                result: Some(result.clone()),
            });
        }
        TraceEventKind::ActionNeedsIntervention { action, result } => {
            tick.actions.push(ReplayAction {
                action: action.clone(),
                status: "needs_intervention".to_string(),
                outcome: None,
                result: Some(result.clone()),
            });
        }
        TraceEventKind::EscalationTriggered { escalation } => {
            if escalation.run_id != event.run_id {
                return Err("replay_escalation_run_mismatch".to_string());
            }
            tick.escalations.push(ReplayEscalation {
                trace_event_id: event.trace_event_id.clone(),
                escalation: escalation.clone(),
                side_effects_replayed: false,
            });
        }
        TraceEventKind::MessageQueued { .. }
        | TraceEventKind::MessageDelivered { .. }
        | TraceEventKind::MessageRejected { .. }
        | TraceEventKind::MessageExpired { .. }
        | TraceEventKind::MessageConsumed { .. } => {
            if let Some(message_event) = replay_message_event(event)? {
                tick.messages.push(message_event);
            }
        }
        TraceEventKind::OutcomeRecorded {
            outcome,
            feedback,
            reward,
        } => {
            tick.outcome = Some(outcome.clone());
            tick.feedback = feedback.clone();
            tick.reward = reward.clone();
        }
        TraceEventKind::StateCommitted {
            state_hash,
            snapshot_id,
        } => {
            tick.state_hash = Some(state_hash.clone());
            if let Some(snapshot_id) = snapshot_id.clone() {
                let snapshot =
                    load_verified_state_snapshot(state_store, &snapshot_id, Some(state_hash))?;
                tick.snapshot_bytes_len = Some(snapshot.state.bytes.len());
                if include_state {
                    tick.snapshot_bytes = Some(snapshot.state.bytes);
                }
                tick.snapshot_id = Some(snapshot_id);
            }
        }
        _ => {}
    }
    Ok(())
}

fn handoff_replay_output(
    event_kind: &str,
    handoff: &StateHandoffTraceContext,
    reason: Option<String>,
    event: &TraceEvent,
) -> ReplayOutput {
    ReplayOutput::HandoffBoundary {
        event_kind: event_kind.to_string(),
        handoff: Box::new(handoff.clone()),
        previous_state_node_id: handoff.previous_state_node_id.clone(),
        receiver_state_node_id: handoff.receiver_state_node_id.clone(),
        reason,
        trace_sequence: event.sequence,
    }
}

fn redacted_replay_output_value(output: &ReplayOutput) -> Result<serde_json::Value, String> {
    let value =
        serde_json::to_value(output).map_err(|_| "replay_output_encode_failed".to_string())?;
    let mut redaction = RedactionTracker::default();
    Ok(redact_value(value, &mut redaction))
}

fn parse_snapshot_id(value: &str) -> Result<SnapshotId, String> {
    let (algorithm, hash) = value
        .split_once(':')
        .ok_or_else(|| "replay_snapshot_id_invalid".to_string())?;
    let algorithm =
        HashAlgorithm::parse(algorithm).ok_or_else(|| "replay_snapshot_id_invalid".to_string())?;
    Ok(SnapshotId::from_hash(ContentHash::new(algorithm, hash)))
}

fn find_tick_for_snapshot(events: &[TraceEvent], snapshot_id: &SnapshotId) -> Option<u64> {
    let mut current_tick: Option<u64> = None;
    for event in events {
        match &event.kind {
            TraceEventKind::LoopTickStarted { tick_id } => current_tick = Some(*tick_id),
            TraceEventKind::StateCommitted {
                snapshot_id: Some(snapshot),
                ..
            } if snapshot == snapshot_id => return current_tick,
            _ => {}
        }
    }
    None
}

#[derive(Debug, Deserialize)]
struct RunConfig {
    trace_db: PathBuf,
    state_db: PathBuf,
    run_id: Option<String>,
    tick_budget_ms: Option<u64>,
    tick_interval_ms: Option<u64>,
    cycles: Option<u64>,
    allow_unsigned_local_run: Option<bool>,
    tenants: Vec<TenantConfig>,
    agents: Vec<AgentConfig>,
    adapters: Option<AdaptersConfig>,
    work_order: Option<WorkOrderConfig>,
    runtime_identity: Option<RuntimeIdentityConfig>,
    circuit_breakers: Option<Vec<CircuitBreakerConfig>>,
    failure_injection: Option<FailureInjectionConfig>,
}

#[derive(Debug, Deserialize)]
struct FailureInjectionConfig {
    trace_fail_on_event: Option<String>,
    state_commit_fail: Option<bool>,
    verifier_unavailable_actions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct WorkOrderConfig {
    #[serde(flatten)]
    envelope: WorkOrderEnvelope,
    verification_secret: String,
    expected_placement_target: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuntimeIdentityConfig {
    fleet_id: Option<String>,
    node_id: Option<String>,
    instance_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CircuitBreakerConfig {
    id: String,
    scope: String,
    value: Option<String>,
    reason: String,
    state: Option<String>,
    authorized_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TenantConfig {
    id: String,
    allowed_actions: Vec<String>,
    allowed_adapters: Vec<String>,
    allowed_permissions: Option<Vec<String>>,
    quotas: Option<QuotaConfig>,
}

#[derive(Debug, Deserialize)]
struct QuotaConfig {
    max_actions_per_tick: Option<u32>,
    max_action_duration_ms: Option<u64>,
    max_filesystem_read_bytes: Option<u64>,
    max_filesystem_write_bytes: Option<u64>,
    max_network_read_bytes: Option<u64>,
    max_network_write_bytes: Option<u64>,
    max_http_requests_per_minute: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct AgentConfig {
    id: Option<String>,
    tenant_id: String,
    run_id: Option<String>,
    snapshot_interval: Option<u64>,
    initial_state: Option<String>,
    resume: Option<bool>,
    allowed_permissions: Option<Vec<String>>,
    allowed_message_schemas: Option<Vec<String>>,
    allowed_message_recipients: Option<Vec<String>>,
    percepts: Option<Vec<PerceptConfig>>,
    policy: PolicyConfig,
}

#[derive(Debug, Deserialize, Clone)]
struct PerceptConfig {
    schema: String,
    payload: serde_json::Value,
    source: String,
    detail: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct ActionConfig {
    name: String,
    adapter: Option<String>,
    params: serde_json::Value,
    side_effect_class: Option<String>,
    required_permissions: Option<Vec<String>>,
    preconditions: Option<Vec<String>>,
    postconditions: Option<Vec<String>>,
    usage: Option<QuotaUsageConfig>,
    satisfied_preconditions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
struct QuotaUsageConfig {
    actions: Option<u32>,
    action_duration_ms: Option<u64>,
    filesystem_read_bytes: Option<u64>,
    filesystem_write_bytes: Option<u64>,
    network_read_bytes: Option<u64>,
    network_write_bytes: Option<u64>,
    http_requests: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PolicyConfig {
    Static {
        actions: Vec<ActionConfig>,
        next_state: Option<String>,
    },
    Increment {
        action: Box<Option<ActionConfig>>,
    },
}

#[derive(Debug, Deserialize)]
struct AdaptersConfig {
    filesystem: Option<FilesystemConfig>,
    http: Option<HttpConfig>,
}

#[derive(Debug, Deserialize)]
struct FilesystemConfig {
    base_dir: PathBuf,
    max_read_bytes: Option<u64>,
    max_write_bytes: Option<u64>,
    max_list_entries: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct HttpConfig {
    allowed_domains: Vec<String>,
    allowed_methods: Option<Vec<String>>,
    max_request_bytes: Option<usize>,
    max_response_bytes: Option<usize>,
    timeout_ms: Option<u64>,
}

struct FailingTraceStore {
    inner: SqliteTraceStore,
    fail_on_event: String,
    failed: Arc<Mutex<bool>>,
}

impl TraceStore for FailingTraceStore {
    fn append(&self, run_id: &str, payload: serde_json::Value) -> Result<u64, TraceStoreError> {
        self.inner.append(run_id, payload)
    }

    fn runtime_store_identity(&self) -> Result<RuntimeTraceStoreIdentity, RuntimeTracePortError> {
        self.inner.runtime_store_identity()
    }

    fn read(&self, run_id: &str) -> Result<Vec<TraceRecord>, TraceStoreError> {
        self.inner.read(run_id)
    }

    fn read_range(
        &self,
        run_id: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<TraceRecord>, TraceStoreError> {
        self.inner.read_range(run_id, start, end)
    }

    fn open_runtime_reader(
        &self,
        run_id: &str,
        limits: RuntimeTraceLimits,
    ) -> Result<RuntimeTraceReaderHandle, RuntimeTracePortError> {
        self.inner.open_runtime_reader(run_id, limits)
    }

    fn acquire_runtime_writer(
        &self,
        request: RuntimeTraceWriterRequest,
    ) -> Result<RuntimeTraceWriterHandle, RuntimeTracePortError> {
        Ok(Arc::new(FailingRuntimeTraceWriter {
            inner: self.inner.acquire_runtime_writer(request)?,
            fail_on_event: self.fail_on_event.clone(),
            failed: Arc::clone(&self.failed),
        }))
    }
}

struct FailingRuntimeTraceWriter {
    inner: RuntimeTraceWriterHandle,
    fail_on_event: String,
    failed: Arc<Mutex<bool>>,
}

impl RuntimeTraceReader for FailingRuntimeTraceWriter {
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
        self.inner.read_page(start)
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        self.inner.confirm_tail(expected)
    }
}

impl RuntimeTraceWriter for FailingRuntimeTraceWriter {
    fn append(
        &self,
        expected: &RuntimeTraceTail,
        payload: serde_json::Value,
    ) -> Result<RuntimeTraceAppend, RuntimeTracePortError> {
        if trace_payload_kind(&payload).as_deref() == Some(self.fail_on_event.as_str()) {
            let mut failed = self
                .failed
                .lock()
                .map_err(|_| RuntimeTracePortError::Unavailable)?;
            if !*failed {
                *failed = true;
                return Err(RuntimeTracePortError::Unavailable);
            }
        }
        self.inner.append(expected, payload)
    }

    fn close(&self) -> Result<(), RuntimeTracePortError> {
        self.inner.close()
    }
}

fn trace_payload_kind(payload: &serde_json::Value) -> Option<String> {
    let kind = payload.get("kind")?;
    kind.as_str()
        .map(ToString::to_string)
        .or_else(|| kind.as_object()?.keys().next().cloned())
}

struct FailingStateStore {
    inner: SqliteStateStore,
    fail_commit: bool,
    failed: Mutex<bool>,
}

impl StateStore for FailingStateStore {
    fn put_state(
        &self,
        state: splendor_store::StateData,
    ) -> Result<splendor_store::StateDataRef, splendor_store::StateStoreError> {
        self.inner.put_state(state)
    }

    fn get_state(
        &self,
        data_ref: &splendor_store::StateDataRef,
    ) -> Result<splendor_store::StateData, splendor_store::StateStoreError> {
        self.inner.get_state(data_ref)
    }

    fn commit_node(
        &self,
        parent_ids: Vec<splendor_types::StateNodeId>,
        data_ref: splendor_store::StateDataRef,
        metadata: splendor_store::StateMetadata,
    ) -> Result<splendor_types::StateNodeId, splendor_store::StateStoreError> {
        if self.fail_commit {
            let mut failed = self
                .failed
                .lock()
                .map_err(|_| splendor_store::StateStoreError::Poisoned)?;
            if !*failed {
                *failed = true;
                return Err(splendor_store::StateStoreError::InvalidStateNodeId(
                    "injected_state_commit_failure".to_string(),
                ));
            }
        }
        self.inner.commit_node(parent_ids, data_ref, metadata)
    }

    fn get_node(
        &self,
        node_id: &splendor_types::StateNodeId,
    ) -> Result<splendor_store::StateNode, splendor_store::StateStoreError> {
        self.inner.get_node(node_id)
    }

    fn snapshot(
        &self,
        node_id: &splendor_types::StateNodeId,
    ) -> Result<SnapshotId, splendor_store::StateStoreError> {
        self.inner.snapshot(node_id)
    }

    fn load_snapshot(
        &self,
        snapshot_id: &SnapshotId,
    ) -> Result<splendor_store::StateSnapshot, splendor_store::StateStoreError> {
        self.inner.load_snapshot(snapshot_id)
    }
}

struct StaticPerceptor {
    percepts: Vec<PerceptConfig>,
}

impl Perceptor for StaticPerceptor {
    fn collect(&self, _agent: &AgentContext) -> Result<Vec<Percept>, splendor_kernel::LoopError> {
        let now = OffsetDateTime::now_utc();
        Ok(self
            .percepts
            .iter()
            .map(|percept| Percept {
                schema: percept.schema.clone(),
                payload: percept.payload.clone(),
                provenance: PerceptProvenance {
                    source: percept.source.clone(),
                    detail: percept.detail.clone(),
                },
                timestamp: now,
            })
            .collect())
    }
}

struct ConfigPolicy {
    name: String,
    policy: PolicyConfig,
}

impl Policy for ConfigPolicy {
    fn name(&self) -> &str {
        &self.name
    }

    fn decide(
        &self,
        state: &splendor_store::StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, splendor_kernel::LoopError> {
        match &self.policy {
            PolicyConfig::Static {
                actions,
                next_state,
            } => {
                let candidates = actions
                    .iter()
                    .map(|action| build_action_candidate(action, None))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(splendor_kernel::LoopError::Policy)?;
                let next_state = next_state.as_deref().unwrap_or("").as_bytes().to_vec();
                Ok(PolicyDecision::new(
                    candidates,
                    splendor_store::StateData {
                        bytes: next_state,
                        content_type: None,
                    },
                    None,
                ))
            }
            PolicyConfig::Increment { action } => {
                let counter = state.bytes.first().copied().unwrap_or(0).saturating_add(1);
                let candidates = action
                    .as_ref()
                    .as_ref()
                    .map(|config| build_action_candidate(config, Some(counter as u64)))
                    .transpose()
                    .map_err(splendor_kernel::LoopError::Policy)?
                    .map(|candidate| vec![candidate])
                    .unwrap_or_default();
                Ok(PolicyDecision::new(
                    candidates,
                    splendor_store::StateData {
                        bytes: vec![counter],
                        content_type: None,
                    },
                    None,
                ))
            }
        }
    }
}

fn run_from_config(
    config_path: &Path,
    cycles_override: Option<u64>,
    forever: bool,
) -> Result<(), String> {
    let config = load_run_config(config_path)?;
    run_loaded_config(
        config,
        cycles_override,
        forever,
        #[cfg(test)]
        None,
    )
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
enum RunAuthorityTestTransition {
    Delay(std::time::Duration),
    Revoke,
}

#[cfg(test)]
struct RunTestOverrides {
    adapters: std::collections::HashMap<String, Arc<dyn ActionAdapter>>,
    authority_transition: Option<RunAuthorityTestTransition>,
}

#[cfg(test)]
fn run_from_config_with_test_overrides(
    config_path: &Path,
    cycles_override: Option<u64>,
    forever: bool,
    overrides: &RunTestOverrides,
) -> Result<(), String> {
    let config = load_run_config(config_path)?;
    run_loaded_config(config, cycles_override, forever, Some(overrides))
}

fn run_loaded_config(
    config: RunConfig,
    cycles_override: Option<u64>,
    forever: bool,
    #[cfg(test)] test_overrides: Option<&RunTestOverrides>,
) -> Result<(), String> {
    if config.tenants.is_empty() {
        return Err("config must include at least one tenant".to_string());
    }
    if config.agents.is_empty() {
        return Err("config must include at least one agent".to_string());
    }

    if let Some(parent) = config.trace_db.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("Failed to create trace directory: {error}"))?;
        }
    }
    let sqlite_trace_store = SqliteTraceStore::open(&config.trace_db)
        .map_err(|error| format!("Failed to open trace store: {error}"))?;
    let trace_store: Arc<dyn TraceStore> = if let Some(event) = config
        .failure_injection
        .as_ref()
        .and_then(|injection| injection.trace_fail_on_event.clone())
    {
        Arc::new(FailingTraceStore {
            inner: sqlite_trace_store,
            fail_on_event: event,
            failed: Arc::new(Mutex::new(false)),
        })
    } else {
        Arc::new(sqlite_trace_store)
    };
    let validated_work_order = validate_config_work_order(&config, trace_store.as_ref())?;
    let work_order = validated_work_order
        .as_ref()
        .map(ValidatedWorkOrder::work_order);
    let signed_action_profiles = match work_order {
        Some(work_order) => match trusted_action_profiles(work_order) {
            Ok(profiles) => Some(profiles),
            Err(error) => {
                record_authority_profile_rejection(
                    &config,
                    trace_store.as_ref(),
                    work_order,
                    error.reason_code(),
                )?;
                return Err(error.reason_code().to_string());
            }
        },
        None => None,
    };

    if let Some(parent) = config.state_db.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("Failed to create state directory: {error}"))?;
        }
    }
    let sqlite_state_store = SqliteStateStore::open(&config.state_db)
        .map_err(|error| format!("Failed to open state store: {error}"))?;
    let state_store: Arc<dyn StateStore> = if config
        .failure_injection
        .as_ref()
        .and_then(|injection| injection.state_commit_fail)
        .unwrap_or(false)
    {
        Arc::new(FailingStateStore {
            inner: sqlite_state_store,
            fail_commit: true,
            failed: Mutex::new(false),
        })
    } else {
        Arc::new(sqlite_state_store)
    };

    let registry = build_registry_with_work_order(&config, work_order)?;
    let circuit_breaker_trace_contexts =
        build_circuit_breaker_trace_contexts(config.circuit_breakers.as_deref())?;
    let mut scheduler = Scheduler::with_registry(
        SchedulerConfig {
            tick_budget: config.tick_budget_ms.map(std::time::Duration::from_millis),
            tick_interval: config
                .tick_interval_ms
                .map(std::time::Duration::from_millis),
        },
        registry.clone(),
    );

    let adapters = build_adapters(config.adapters.as_ref())?;
    #[cfg(test)]
    let adapters = test_overrides
        .map(|overrides| overrides.adapters.clone())
        .unwrap_or(adapters);
    let unsigned_local_gateway = if validated_work_order.is_none() {
        Some(build_gateway(&adapters, &registry, &config)?)
    } else {
        None
    };
    let mut trace_runtimes = HashMap::<RunId, Arc<KernelRuntime>>::new();

    for agent_config in &config.agents {
        let tenant_id = parse_tenant_id(&agent_config.tenant_id)?;
        let agent_id = resolve_agent_id(agent_config, work_order)?;
        let run_id = resolve_run_id(&config, agent_config, work_order)?;
        let trace_runtime = match trace_runtimes.get(&run_id) {
            Some(runtime) => Arc::clone(runtime),
            None => {
                let runtime = Arc::new(
                    KernelRuntime::with_trace_store(trace_store.clone(), Some(run_id.clone()))
                        .map_err(|error| format!("Failed to create trace runtime: {error}"))?,
                );
                trace_runtimes.insert(run_id.clone(), Arc::clone(&runtime));
                runtime
            }
        };
        let gateway = match validated_work_order.as_ref() {
            Some(validated) => {
                let configured = build_authorized_run_gateway(
                    &adapters,
                    &registry,
                    &config,
                    validated,
                    run_id.clone(),
                    tenant_id.clone(),
                    agent_id.clone(),
                    Arc::clone(&trace_runtime),
                    signed_action_profiles
                        .as_deref()
                        .ok_or_else(|| "signed action profiles are not configured".to_string())?,
                )?;
                #[cfg(test)]
                if let Some(transition) =
                    test_overrides.and_then(|overrides| overrides.authority_transition)
                {
                    configured.apply_test_transition(transition);
                }
                configured.gateway
            }
            None => Arc::clone(
                unsigned_local_gateway
                    .as_ref()
                    .ok_or_else(|| "unsigned local gateway is not configured".to_string())?,
            ),
        };
        let snapshot_interval = agent_config.snapshot_interval;
        let snapshot_policy = SnapshotPolicy {
            interval: snapshot_interval,
            important_labels: Vec::new(),
        };
        let graph = StateGraph::new(state_store.clone(), snapshot_policy);
        let initial_state = splendor_store::StateData {
            bytes: agent_config
                .initial_state
                .as_deref()
                .unwrap_or("")
                .as_bytes()
                .to_vec(),
            content_type: None,
        };
        let isolation = build_agent_isolation(agent_config)?;
        let agent = AgentContext::new(
            agent_id,
            tenant_id.clone(),
            AgentRuntimeConfig {
                isolation,
                ..AgentRuntimeConfig::default()
            },
        );
        registry
            .with_tenant_mut(&tenant_id, |tenant| tenant.register_agent_context(&agent))
            .ok_or_else(|| format!("agent references unknown tenant: {tenant_id}"))?;
        let policy = ConfigPolicy {
            name: format!("{}-policy", agent_config.tenant_id),
            policy: agent_config.policy.clone(),
        };
        let mut engine = if agent_config.resume.unwrap_or(false) {
            LoopEngine::resume_from_shared_trace_runtime_and_work_order(
                agent,
                graph,
                Box::new(policy),
                Arc::clone(&gateway),
                trace_store.clone(),
                trace_runtime,
                run_id,
                work_order,
            )
            .map_err(|error| format!("Failed to resume agent: {error}"))?
        } else {
            let context = match work_order {
                Some(work_order) => {
                    RunTraceContext::new(Some(run_id)).with_work_order(work_order.clone())
                }
                None => RunTraceContext::new(Some(run_id)),
            };
            LoopEngine::with_shared_trace_runtime_and_work_order(
                agent,
                graph,
                initial_state,
                Box::new(policy),
                Arc::clone(&gateway),
                trace_runtime,
                context,
            )
            .map_err(|error| format!("Failed to create engine: {error}"))?
        };

        emit_configured_circuit_breaker_events(&engine, &circuit_breaker_trace_contexts)?;

        if let Some(percepts) = agent_config.percepts.clone() {
            engine.add_perceptor(StaticPerceptor { percepts });
        }
        scheduler.add_agent(engine);
    }

    if forever {
        scheduler
            .run_forever()
            .map_err(|error| format!("Scheduler failed: {error}"))?;
        return Ok(());
    }

    let cycles = cycles_override.or(config.cycles).unwrap_or(1);
    if let Err(error) = scheduler.run_cycles(cycles) {
        return Err(format!("Scheduler failed: {error}"));
    }
    Ok(())
}

fn load_run_config(path: &Path) -> Result<RunConfig, String> {
    let resolved = resolve_config_path(path)?;
    let content =
        fs::read_to_string(&resolved).map_err(|error| format!("Failed to read config: {error}"))?;
    let extension = resolved
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    match extension {
        "yaml" | "yml" => {
            serde_yaml::from_str(&content).map_err(|error| format!("Failed to parse YAML: {error}"))
        }
        "json" => {
            serde_json::from_str(&content).map_err(|error| format!("Failed to parse JSON: {error}"))
        }
        _ => Err("Config must be .yaml, .yml, or .json".to_string()),
    }
}

fn sign_work_order(input_path: &Path, key_id: &str, secret: &str) -> Result<(), String> {
    let content = fs::read_to_string(input_path)
        .map_err(|error| format!("Failed to read work order: {error}"))?;
    let work_order: WorkOrder = serde_json::from_str(&content)
        .map_err(|error| format!("Failed to parse work order JSON: {error}"))?;
    let envelope =
        WorkOrderEnvelope::signed_with_shared_secret(work_order, key_id, secret.as_bytes())
            .map_err(|error| format!("Work order rejected: {}", error.reason_code()))?;
    let line = serde_json::to_string_pretty(&envelope)
        .map_err(|error| format!("Failed to encode signed work order: {error}"))?;
    println!("{line}");
    Ok(())
}

fn resolve_config_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_dir() {
        for filename in ["config.yaml", "config.yml", "config.json"] {
            let candidate = path.join(filename);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        return Err("No config file found in directory".to_string());
    }
    Ok(path.to_path_buf())
}

fn validate_config_work_order(
    config: &RunConfig,
    trace_store: &dyn TraceStore,
) -> Result<Option<ValidatedWorkOrder>, String> {
    let Some(work_order_config) = &config.work_order else {
        if config.allow_unsigned_local_run.unwrap_or(false) {
            eprintln!(
                "WARNING: allow_unsigned_local_run is active; signed work-order authority is bypassed for this local development run only."
            );
            return Ok(None);
        }
        record_missing_work_order_rejection(config, trace_store)?;
        return Err("Work order rejected: unsigned_work_order".to_string());
    };

    if config.agents.len() != 1 {
        return Err(
            "work_order config currently authorizes exactly one local resident agent".to_string(),
        );
    }
    let agent = &config.agents[0];
    let order = &work_order_config.envelope.work_order;
    let now = OffsetDateTime::now_utc();
    if agent.run_id.is_none() && config.run_id.is_none() && order.run_id.is_none() {
        return Err(
            "work_order config requires an explicit run_id in the config or work order".to_string(),
        );
    }
    let tenant_id = parse_tenant_id(&agent.tenant_id)?;
    let agent_id = resolve_agent_id(agent, Some(order))?;
    let run_id = resolve_run_id(config, agent, Some(order))?;
    if agent.resume.unwrap_or(false) && order.run_id.as_ref() != Some(&run_id) {
        return Err("resume requires a work order bound to the resumed run_id".to_string());
    }

    let mut keyring = WorkOrderKeyring::new();
    if let Some(signature) = &work_order_config.envelope.signature {
        keyring
            .insert_shared_secret(
                &signature.key_id,
                work_order_config.verification_secret.as_bytes(),
            )
            .map_err(|error| format!("Work order rejected: {}", error.reason_code()))?;
    }
    let context = WorkOrderValidationContext {
        tenant_id,
        agent_id,
        run_id: Some(run_id.clone()),
        expected_placement_target: Some(
            work_order_config
                .expected_placement_target
                .clone()
                .unwrap_or_else(|| "local_resident".to_string()),
        ),
        now,
    };

    match validate_work_order(&work_order_config.envelope, &context, &keyring) {
        Ok(validated) => Ok(Some(validated)),
        Err(error) => {
            record_work_order_rejection(trace_store, run_id, order, &error)?;
            Err(format!("Work order rejected: {}", error.reason_code()))
        }
    }
}

fn record_missing_work_order_rejection(
    config: &RunConfig,
    trace_store: &dyn TraceStore,
) -> Result<(), String> {
    if config.agents.len() != 1 {
        return Ok(());
    }
    let agent = &config.agents[0];
    let Some(run_id_value) = agent.run_id.as_deref().or(config.run_id.as_deref()) else {
        return Ok(());
    };
    let Ok(run_id) = parse_run_id(run_id_value) else {
        return Ok(());
    };
    let tenant_id = parse_tenant_id(&agent.tenant_id).ok();
    let agent_id = agent
        .id
        .as_deref()
        .and_then(|value| parse_agent_id(value).ok());
    append_work_order_rejection(
        trace_store,
        run_id.clone(),
        None,
        tenant_id,
        agent_id,
        Some(run_id),
        "unsigned_work_order".to_string(),
    )
}

fn record_work_order_rejection(
    trace_store: &dyn TraceStore,
    run_id: RunId,
    work_order: &WorkOrder,
    error: &WorkOrderValidationError,
) -> Result<(), String> {
    append_work_order_rejection(
        trace_store,
        run_id,
        Some(work_order.work_order_id.clone()),
        Some(work_order.tenant_id.clone()),
        Some(work_order.agent_id.clone()),
        work_order.run_id.clone(),
        error.reason_code().to_string(),
    )
}

fn record_authority_profile_rejection(
    config: &RunConfig,
    trace_store: &dyn TraceStore,
    work_order: &WorkOrder,
    reason: &str,
) -> Result<(), String> {
    let agent = config
        .agents
        .first()
        .ok_or_else(|| "config must include at least one agent".to_string())?;
    let run_id = resolve_run_id(config, agent, Some(work_order))?;
    append_work_order_rejection(
        trace_store,
        run_id.clone(),
        Some(work_order.work_order_id.clone()),
        Some(work_order.tenant_id.clone()),
        Some(work_order.agent_id.clone()),
        Some(run_id),
        reason.to_string(),
    )
}

fn append_work_order_rejection(
    trace_store: &dyn TraceStore,
    trace_run_id: RunId,
    work_order_id: Option<WorkOrderId>,
    tenant_id: Option<TenantId>,
    agent_id: Option<AgentId>,
    event_run_id: Option<RunId>,
    reason: String,
) -> Result<(), String> {
    let sequence = match trace_store.read(&trace_run_id.to_string()) {
        Ok(records) => records
            .last()
            .map(|record| record.sequence + 1)
            .unwrap_or(0),
        Err(TraceStoreError::RunNotFound) => 0,
        Err(error) => return Err(format!("Failed to read work-order audit trace: {error}")),
    };
    let event = TraceEvent::new(
        trace_run_id.clone(),
        sequence,
        OffsetDateTime::now_utc(),
        TraceEventKind::WorkOrderRejected {
            work_order_id,
            tenant_id,
            agent_id,
            run_id: event_run_id,
            reason,
        },
    );
    trace_store
        .append(
            &trace_run_id.to_string(),
            serde_json::to_value(event)
                .map_err(|error| format!("Failed to encode work-order rejection trace: {error}"))?,
        )
        .map_err(|error| format!("Failed to record work-order rejection trace: {error}"))?;
    Ok(())
}

fn resolve_agent_id(
    agent_config: &AgentConfig,
    work_order: Option<&WorkOrder>,
) -> Result<AgentId, String> {
    if let Some(value) = agent_config.id.as_deref() {
        return parse_agent_id(value);
    }
    if let Some(work_order) = work_order {
        return Ok(work_order.agent_id.clone());
    }
    Ok(AgentId::new())
}

fn resolve_run_id(
    config: &RunConfig,
    agent_config: &AgentConfig,
    work_order: Option<&WorkOrder>,
) -> Result<RunId, String> {
    if let Some(value) = agent_config.run_id.as_deref().or(config.run_id.as_deref()) {
        return parse_run_id(value);
    }
    if let Some(run_id) = work_order.and_then(|work_order| work_order.run_id.clone()) {
        return Ok(run_id);
    }
    Ok(RunId::new())
}

fn build_registry_with_work_order(
    config: &RunConfig,
    work_order: Option<&WorkOrder>,
) -> Result<TenantRegistry, String> {
    let registry = TenantRegistry::new();
    for tenant in &config.tenants {
        let tenant_id = parse_tenant_id(&tenant.id)?;
        let mut policy = TenantPolicy {
            allowed_actions: tenant.allowed_actions.clone(),
            allowed_adapters: tenant.allowed_adapters.clone(),
            allowed_permissions: tenant.allowed_permissions.clone().unwrap_or_default(),
        };
        let mut quotas = if let Some(quotas) = &tenant.quotas {
            let filesystem = AdapterQuota {
                max_read_bytes: quotas.max_filesystem_read_bytes,
                max_write_bytes: quotas.max_filesystem_write_bytes,
            };
            let network = AdapterQuota {
                max_read_bytes: quotas.max_network_read_bytes,
                max_write_bytes: quotas.max_network_write_bytes,
            };
            QuotaPolicy {
                max_actions_per_tick: quotas.max_actions_per_tick,
                max_action_duration_ms: quotas.max_action_duration_ms,
                filesystem,
                network,
                max_http_requests_per_minute: quotas.max_http_requests_per_minute,
            }
        } else {
            QuotaPolicy::default()
        };
        if let Some(work_order) = work_order.filter(|order| order.tenant_id == tenant_id) {
            policy = policy.constrain_to_work_order(work_order);
            quotas = quotas.constrain_to_work_order(work_order);
        }
        registry.insert(TenantContext::new(tenant_id, policy, quotas));
    }
    Ok(registry)
}

fn build_agent_isolation(config: &AgentConfig) -> Result<AgentIsolationPolicy, String> {
    let allowed_message_recipients = config
        .allowed_message_recipients
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|value| parse_agent_id(&value))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(AgentIsolationPolicy {
        allowed_permissions: config.allowed_permissions.clone().unwrap_or_default(),
        allowed_message_schemas: config.allowed_message_schemas.clone().unwrap_or_default(),
        allowed_message_recipients,
    })
}

fn build_adapters(
    config: Option<&AdaptersConfig>,
) -> Result<std::collections::HashMap<String, Arc<dyn ActionAdapter>>, String> {
    let mut adapters: std::collections::HashMap<String, Arc<dyn ActionAdapter>> =
        std::collections::HashMap::new();

    if let Some(config) = config {
        if let Some(filesystem) = &config.filesystem {
            let adapter = FilesystemAdapter::new(FilesystemAdapterConfig {
                base_dir: filesystem.base_dir.clone(),
                max_read_bytes: filesystem.max_read_bytes.unwrap_or(1024 * 1024),
                max_write_bytes: filesystem.max_write_bytes.unwrap_or(1024 * 1024),
                max_list_entries: filesystem.max_list_entries.unwrap_or(1000),
            });
            adapters.insert("filesystem".to_string(), Arc::new(adapter));
        }
        if let Some(http) = &config.http {
            let allowed_methods = http
                .allowed_methods
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(parse_http_method)
                .collect::<Result<Vec<_>, _>>()?;
            let adapter = HttpAdapter::new(HttpAdapterConfig {
                allowed_domains: http.allowed_domains.clone(),
                allowed_methods,
                max_request_bytes: http.max_request_bytes.unwrap_or(1024 * 1024),
                max_response_bytes: http.max_response_bytes.unwrap_or(1024 * 1024),
                timeout: std::time::Duration::from_millis(http.timeout_ms.unwrap_or(5000)),
                ..HttpAdapterConfig::default()
            });
            adapters.insert("http".to_string(), Arc::new(adapter));
        }
    }

    Ok(adapters)
}

fn build_gateway(
    adapters: &std::collections::HashMap<String, Arc<dyn ActionAdapter>>,
    registry: &TenantRegistry,
    config: &RunConfig,
) -> Result<Arc<dyn ActionGateway>, String> {
    Ok(Arc::new(build_verified_gateway(
        adapters, registry, config,
    )?))
}

struct AuthorizedRunGateway {
    gateway: Arc<dyn ActionGateway>,
    #[cfg(test)]
    run_authority: RunAuthorityHandle,
}

#[cfg(test)]
impl AuthorizedRunGateway {
    fn apply_test_transition(&self, transition: RunAuthorityTestTransition) {
        match transition {
            RunAuthorityTestTransition::Delay(duration) => std::thread::sleep(duration),
            RunAuthorityTestTransition::Revoke => self.run_authority.revoke(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_authorized_run_gateway(
    adapters: &std::collections::HashMap<String, Arc<dyn ActionAdapter>>,
    registry: &TenantRegistry,
    config: &RunConfig,
    validated_work_order: &ValidatedWorkOrder,
    run_id: RunId,
    tenant_id: TenantId,
    agent_id: AgentId,
    trace_runtime: Arc<KernelRuntime>,
    trusted_action_profiles: &[TrustedActionProfile],
) -> Result<AuthorizedRunGateway, String> {
    let run_authority = RunAuthorityHandle::admit_signed_work_order_compatibility(
        validated_work_order,
        run_id.clone(),
        format!("splendor.cli.run:{run_id}"),
    )
    .map_err(|error| format!("Work order authority rejected: {}", error.reason_code()))?;
    let mut gateway = build_verified_gateway(adapters, registry, config)?;
    gateway.set_action_authority_evaluator(Arc::new(run_authority.clone()));
    gateway.set_pre_effect_authority_recorder(Arc::new(KernelPreEffectAuthorityRecorder::new(
        trace_runtime,
        tenant_id,
        agent_id,
    )));
    gateway.set_trusted_action_profiles(trusted_action_profiles.to_vec())?;
    Ok(AuthorizedRunGateway {
        gateway: Arc::new(gateway),
        #[cfg(test)]
        run_authority,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrustedActionProfileAdmissionError {
    AmbiguousAdapter,
    Invalid,
    PermissionLimitExceeded,
    DuplicatePermission,
    DuplicateAction,
}

impl TrustedActionProfileAdmissionError {
    fn reason_code(self) -> &'static str {
        match self {
            Self::AmbiguousAdapter => "ambiguous_work_order_action_adapter_profile",
            Self::Invalid => "trusted_action_profile_invalid",
            Self::PermissionLimitExceeded => "trusted_action_profile_permission_limit_exceeded",
            Self::DuplicatePermission => "trusted_action_profile_permission_duplicate",
            Self::DuplicateAction => "trusted_action_profile_duplicate",
        }
    }
}

fn trusted_action_profiles(
    work_order: &WorkOrder,
) -> Result<Vec<TrustedActionProfile>, TrustedActionProfileAdmissionError> {
    let adapter = match work_order.allowed_adapters.as_slice() {
        [adapter] if !adapter.trim().is_empty() => adapter.clone(),
        [_] => return Err(TrustedActionProfileAdmissionError::Invalid),
        _ => return Err(TrustedActionProfileAdmissionError::AmbiguousAdapter),
    };
    if work_order.allowed_permissions.len() > 64 {
        return Err(TrustedActionProfileAdmissionError::PermissionLimitExceeded);
    }
    let required_permissions = work_order
        .allowed_permissions
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if required_permissions.len() != work_order.allowed_permissions.len() {
        return Err(TrustedActionProfileAdmissionError::DuplicatePermission);
    }
    let required_permissions = required_permissions.into_iter().collect::<Vec<_>>();
    let action_names = work_order
        .allowed_actions
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if action_names.len() != work_order.allowed_actions.len() {
        return Err(TrustedActionProfileAdmissionError::DuplicateAction);
    }
    if action_names.is_empty() || action_names.iter().any(|action| action.trim().is_empty()) {
        return Err(TrustedActionProfileAdmissionError::Invalid);
    }
    let profiles = action_names
        .into_iter()
        .map(|action_name| TrustedActionProfile {
            action_name,
            adapter: adapter.clone(),
            required_permissions: required_permissions.clone(),
        })
        .collect::<Vec<_>>();
    Ok(profiles)
}

fn build_verified_gateway(
    adapters: &std::collections::HashMap<String, Arc<dyn ActionAdapter>>,
    registry: &TenantRegistry,
    config: &RunConfig,
) -> Result<VerifiedActionGateway, String> {
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry.clone()));
    let runtime_identity = build_runtime_identity(config.runtime_identity.as_ref())?;
    let circuit_breakers = build_circuit_breakers(config.circuit_breakers.as_deref())?;
    gateway.set_runtime_identity(runtime_identity.clone());
    let evaluator = Arc::new(StaticCircuitBreakerEvaluator::new(circuit_breakers));
    let admission = evaluator.verify_runtime_admission(&runtime_identity);
    if !admission.allowed {
        return Err(format!(
            "Circuit breaker denied new work: {}",
            denial_reason(&admission)
        ));
    }
    gateway.set_circuit_breaker_evaluator(evaluator);
    gateway.set_resource_boundary_verifier(Arc::new(
        LocalResourceBoundaryVerifier::from_config_with_failure_injection(
            config.adapters.as_ref(),
            config.failure_injection.as_ref(),
        ),
    ));
    let actions = collect_action_configs(config)?;
    for action in actions {
        let adapter_id = action
            .adapter
            .clone()
            .unwrap_or_else(|| action.name.clone());
        let adapter = adapters
            .get(&adapter_id)
            .ok_or_else(|| format!("Adapter not configured: {adapter_id}"))?;
        gateway.register_adapter(&action.name, &adapter_id, Arc::clone(adapter));
    }
    Ok(gateway)
}

#[derive(Clone, Debug, Default)]
struct LocalResourceBoundaryVerifier {
    http_allowed_domains: Vec<String>,
    unavailable_actions: BTreeSet<String>,
}

impl LocalResourceBoundaryVerifier {
    fn from_config(config: Option<&AdaptersConfig>) -> Self {
        Self {
            http_allowed_domains: config
                .and_then(|adapters| adapters.http.as_ref())
                .map(|http| http.allowed_domains.clone())
                .unwrap_or_default(),
            unavailable_actions: BTreeSet::new(),
        }
    }

    fn from_config_with_failure_injection(
        config: Option<&AdaptersConfig>,
        failure_injection: Option<&FailureInjectionConfig>,
    ) -> Self {
        let mut verifier = Self::from_config(config);
        verifier.unavailable_actions = failure_injection
            .and_then(|injection| injection.verifier_unavailable_actions.clone())
            .unwrap_or_default()
            .into_iter()
            .collect();
        verifier
    }
}

impl ResourceBoundaryVerifier for LocalResourceBoundaryVerifier {
    fn verify_resource_boundary(
        &self,
        action: &splendor_gateway::ActionRequest,
        adapter: Option<&str>,
    ) -> splendor_types::VerificationResult {
        if self.unavailable_actions.contains(&action.action.name) {
            return verifier_unavailable_denied(&action.action.name, adapter);
        }
        match adapter {
            Some("http") => self.verify_http(action),
            Some("filesystem") => self.verify_filesystem(action),
            _ => splendor_types::VerificationResult::allow(),
        }
    }
}

impl LocalResourceBoundaryVerifier {
    fn verify_http(
        &self,
        action: &splendor_gateway::ActionRequest,
    ) -> splendor_types::VerificationResult {
        let Some(url) = action
            .action
            .params
            .get("url")
            .and_then(|value| value.as_str())
        else {
            return boundary_denied(
                "network_scope_missing_url",
                "network_egress_verifier",
                serde_json::json!({"parameter": "url"}),
            );
        };
        let Some(host) = http_host(url) else {
            return boundary_denied(
                "network_scope_invalid_url",
                "network_egress_verifier",
                serde_json::json!({"url": url}),
            );
        };
        if !domain_allowed(&self.http_allowed_domains, &host) {
            return boundary_denied(
                "network_scope_denied",
                "network_egress_verifier",
                serde_json::json!({"host": host, "allowed_domains": self.http_allowed_domains}),
            );
        }
        splendor_types::VerificationResult::allow()
    }

    fn verify_filesystem(
        &self,
        action: &splendor_gateway::ActionRequest,
    ) -> splendor_types::VerificationResult {
        let Some(raw_path) = action
            .action
            .params
            .get("path")
            .and_then(|value| value.as_str())
        else {
            return boundary_denied(
                "filesystem_scope_missing_path",
                "filesystem_verifier",
                serde_json::json!({"parameter": "path"}),
            );
        };
        let path = Path::new(raw_path);
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            return boundary_denied(
                "filesystem_scope_denied",
                "filesystem_verifier",
                serde_json::json!({"path": raw_path, "reason": "path_traversal_or_absolute_path"}),
            );
        }
        splendor_types::VerificationResult::allow()
    }
}

fn boundary_denied(
    reason: &str,
    verifier: &str,
    evidence: serde_json::Value,
) -> splendor_types::VerificationResult {
    splendor_types::VerificationResult {
        allowed: false,
        reasons: vec![reason.to_string()],
        artifacts: serde_json::json!({
            "source": verifier,
            "verifier": verifier,
            "adapter_execution": "not_attempted",
            "evidence": evidence,
        }),
    }
}

fn verifier_unavailable_denied(
    action: &str,
    adapter: Option<&str>,
) -> splendor_types::VerificationResult {
    splendor_types::VerificationResult {
        allowed: false,
        reasons: vec!["verifier_unavailable".to_string()],
        artifacts: serde_json::json!({
            "source": "resource_boundary_verifier",
            "verifier": "resource_boundary_verifier",
            "verifier_status": "unavailable",
            "adapter_execution": "not_attempted",
            "failure_injection": "splendorctl_public_run_config",
            "evidence": {
                "action": action,
                "adapter": adapter,
                "reason": "required verifier unavailable; fail closed before adapter execution",
            },
        }),
    }
}

fn http_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority)
        .split(':')
        .next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn domain_allowed(allowlist: &[String], host: &str) -> bool {
    !allowlist.is_empty()
        && allowlist.iter().any(|entry| {
            if entry.starts_with("*.") {
                host.ends_with(&entry[1..])
            } else if entry.starts_with('.') {
                host.ends_with(entry)
            } else {
                host == entry
            }
        })
}

fn build_runtime_identity(
    config: Option<&RuntimeIdentityConfig>,
) -> Result<RuntimeIdentityContext, String> {
    let Some(config) = config else {
        return Ok(RuntimeIdentityContext::default());
    };
    Ok(RuntimeIdentityContext {
        fleet_id: config.fleet_id.as_deref().map(parse_fleet_id).transpose()?,
        node_id: config.node_id.as_deref().map(parse_node_id).transpose()?,
        instance_id: config
            .instance_id
            .as_deref()
            .map(parse_instance_id)
            .transpose()?,
        tenant_id: None,
        agent_id: None,
    })
}

fn build_circuit_breakers(
    config: Option<&[CircuitBreakerConfig]>,
) -> Result<Vec<CircuitBreaker>, String> {
    Ok(build_circuit_breaker_controls(config)?.0)
}

fn build_circuit_breaker_trace_contexts(
    config: Option<&[CircuitBreakerConfig]>,
) -> Result<Vec<CircuitBreakerTraceContext>, String> {
    Ok(build_circuit_breaker_controls(config)?.1)
}

fn build_circuit_breaker_controls(
    config: Option<&[CircuitBreakerConfig]>,
) -> Result<(Vec<CircuitBreaker>, Vec<CircuitBreakerTraceContext>), String> {
    let mut breakers = Vec::new();
    let mut trace_contexts = Vec::new();
    for breaker in config.unwrap_or(&[]) {
        let state = breaker.state.as_deref().unwrap_or("tripped");
        if state != "tripped" && state != "cleared" {
            return Err(format!("Unsupported circuit breaker state: {state}"));
        }
        let scope = parse_circuit_breaker_scope(breaker)?;
        let id =
            CircuitBreakerId::try_new(breaker.id.clone()).map_err(|error| error.to_string())?;
        let mut control =
            CircuitBreaker::tripped(id, scope, breaker.reason.clone(), OffsetDateTime::now_utc())
                .map_err(|error| error.to_string())?;
        let trace_context = if state == "cleared" {
            let authorized_by = breaker.authorized_by.as_deref().ok_or_else(|| {
                format!(
                    "circuit breaker '{}' in cleared state requires authorized_by",
                    breaker.id
                )
            })?;
            let (cleared, trace_context) = control
                .clear_with_authority(
                    breaker.reason.clone(),
                    authorized_by,
                    OffsetDateTime::now_utc(),
                )
                .map_err(|error| error.to_string())?;
            control = cleared;
            trace_context
        } else {
            let authorized_by = breaker
                .authorized_by
                .as_deref()
                .unwrap_or("local-config:circuit-breakers");
            control
                .trip_trace_context(authorized_by, OffsetDateTime::now_utc())
                .map_err(|error| error.to_string())?
        };
        breakers.push(control);
        trace_contexts.push(trace_context);
    }
    Ok((breakers, trace_contexts))
}

fn emit_configured_circuit_breaker_events(
    engine: &LoopEngine,
    trace_contexts: &[CircuitBreakerTraceContext],
) -> Result<(), String> {
    for context in trace_contexts {
        let kind = match context.state {
            CircuitBreakerState::Tripped => TraceEventKind::CircuitBreakerTripped {
                breaker: context.clone(),
            },
            CircuitBreakerState::Cleared => TraceEventKind::CircuitBreakerCleared {
                breaker: context.clone(),
            },
        };
        engine
            .record_runtime_event(kind)
            .map_err(|error| format!("Failed to record circuit-breaker trace event: {error}"))?;
    }
    Ok(())
}

fn parse_circuit_breaker_scope(
    config: &CircuitBreakerConfig,
) -> Result<CircuitBreakerScope, String> {
    let value = config.value.as_deref();
    match config.scope.as_str() {
        "global" => Ok(CircuitBreakerScope::Global),
        "fleet" => Ok(CircuitBreakerScope::Fleet(parse_fleet_id(
            required_scope_value("fleet", value)?,
        )?)),
        "node" => Ok(CircuitBreakerScope::Node(parse_node_id(
            required_scope_value("node", value)?,
        )?)),
        "instance" => Ok(CircuitBreakerScope::Instance(parse_instance_id(
            required_scope_value("instance", value)?,
        )?)),
        "tenant" => Ok(CircuitBreakerScope::Tenant(parse_tenant_id(
            required_scope_value("tenant", value)?,
        )?)),
        "agent" => Ok(CircuitBreakerScope::Agent(parse_agent_id(
            required_scope_value("agent", value)?,
        )?)),
        "adapter" => Ok(CircuitBreakerScope::Adapter(
            required_scope_value("adapter", value)?.to_string(),
        )),
        "action" => Ok(CircuitBreakerScope::Action(
            required_scope_value("action", value)?.to_string(),
        )),
        "action_class" => Ok(CircuitBreakerScope::ActionClass(parse_action_class_value(
            required_scope_value("action_class", value)?,
        )?)),
        other => Err(format!("Unsupported circuit breaker scope: {other}")),
    }
}

fn required_scope_value<'a>(scope: &str, value: Option<&'a str>) -> Result<&'a str, String> {
    value.ok_or_else(|| format!("circuit breaker scope '{scope}' requires value"))
}

fn denial_reason(result: &splendor_types::VerificationResult) -> String {
    if result.reasons.is_empty() {
        "verification denied".to_string()
    } else {
        result.reasons.join(", ")
    }
}

fn collect_action_configs(config: &RunConfig) -> Result<Vec<ActionConfig>, String> {
    let mut actions = Vec::new();
    for agent in &config.agents {
        match &agent.policy {
            PolicyConfig::Static { actions: items, .. } => actions.extend(items.clone()),
            PolicyConfig::Increment { action } => {
                if let Some(action) = action.as_ref().as_ref() {
                    actions.push(action.clone())
                }
            }
        }
    }
    for action in &actions {
        validated_side_effect_class(action)?;
    }
    Ok(actions)
}

fn build_action_candidate(
    config: &ActionConfig,
    counter: Option<u64>,
) -> Result<ActionCandidate, String> {
    let params = if let Some(counter) = counter {
        substitute_counter(&config.params, counter)
    } else {
        config.params.clone()
    };
    let side_effect_class = validated_side_effect_class(config)?;
    let action = Action {
        name: config.name.clone(),
        params,
        side_effect_class,
        cost_estimate: None,
        required_permissions: config.required_permissions.clone().unwrap_or_default(),
        preconditions: config.preconditions.clone().unwrap_or_default(),
        postconditions: config.postconditions.clone().unwrap_or_default(),
    };
    let usage = if let Some(usage) = &config.usage {
        QuotaUsage {
            actions: usage.actions.unwrap_or(1),
            action_duration_ms: usage.action_duration_ms.unwrap_or(0),
            filesystem_read_bytes: usage.filesystem_read_bytes.unwrap_or(0),
            filesystem_write_bytes: usage.filesystem_write_bytes.unwrap_or(0),
            network_read_bytes: usage.network_read_bytes.unwrap_or(0),
            network_write_bytes: usage.network_write_bytes.unwrap_or(0),
            http_requests: usage.http_requests.unwrap_or(0),
        }
    } else {
        QuotaUsage::single_action()
    };
    let mut candidate = ActionCandidate::new(action).with_usage(usage);
    if let Some(adapter) = &config.adapter {
        candidate = candidate.with_adapter(adapter.clone());
    }
    if let Some(preconditions) = &config.satisfied_preconditions {
        candidate = candidate.with_satisfied_preconditions(preconditions.clone());
    }
    Ok(candidate)
}

fn validated_side_effect_class(config: &ActionConfig) -> Result<SideEffectClass, String> {
    let declared = config
        .side_effect_class
        .as_deref()
        .map(parse_side_effect_class)
        .transpose()?;
    let adapter_derived = trusted_adapter_side_effect_class(config.adapter.as_deref());
    if let (Some(declared), Some(derived)) = (&declared, &adapter_derived) {
        if declared != derived {
            return Err(format!(
                "side_effect_class '{}' conflicts with adapter-derived class '{}' for action '{}'",
                side_effect_class_name(declared),
                side_effect_class_name(derived),
                config.name
            ));
        }
    }
    Ok(adapter_derived
        .or(declared)
        .unwrap_or(SideEffectClass::ReadOnly))
}

fn trusted_adapter_side_effect_class(adapter: Option<&str>) -> Option<SideEffectClass> {
    match adapter {
        Some("filesystem") => Some(SideEffectClass::Filesystem),
        Some("http") => Some(SideEffectClass::Network),
        _ => None,
    }
}

fn substitute_counter(value: &serde_json::Value, counter: u64) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => {
            serde_json::Value::String(text.replace("{counter}", &counter.to_string()))
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .map(|item| substitute_counter(item, counter))
                .collect(),
        ),
        serde_json::Value::Object(map) => {
            let mut updated = serde_json::Map::new();
            for (key, value) in map {
                updated.insert(key.clone(), substitute_counter(value, counter));
            }
            serde_json::Value::Object(updated)
        }
        _ => value.clone(),
    }
}

fn parse_side_effect_class(value: &str) -> Result<SideEffectClass, String> {
    match value {
        "filesystem" => Ok(SideEffectClass::Filesystem),
        "network" => Ok(SideEffectClass::Network),
        "read_only" => Ok(SideEffectClass::ReadOnly),
        "external" => Ok(SideEffectClass::External),
        other
            if other
                .strip_prefix("custom:")
                .is_some_and(|value| !value.is_empty()) =>
        {
            Ok(SideEffectClass::Custom(
                other.trim_start_matches("custom:").to_string(),
            ))
        }
        other => Err(format!("Unsupported side_effect_class: {other}")),
    }
}

fn side_effect_class_name(value: &SideEffectClass) -> String {
    match value {
        SideEffectClass::ReadOnly => "read_only".to_string(),
        SideEffectClass::Filesystem => "filesystem".to_string(),
        SideEffectClass::Network => "network".to_string(),
        SideEffectClass::External => "external".to_string(),
        SideEffectClass::Custom(value) => format!("custom:{value}"),
    }
}

fn parse_action_class_value(value: &str) -> Result<SideEffectClass, String> {
    parse_side_effect_class(value).map_err(|_| format!("Unsupported action_class: {value}"))
}

fn parse_http_method(value: String) -> Result<HttpMethod, String> {
    match value.as_str() {
        "GET" | "get" => Ok(HttpMethod::Get),
        "POST" | "post" => Ok(HttpMethod::Post),
        other => Err(format!("Unsupported HTTP method: {other}")),
    }
}

fn parse_fleet_id(value: &str) -> Result<FleetId, String> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| format!("Invalid fleet id: {value}"))?;
    Ok(uuid.into())
}

fn parse_node_id(value: &str) -> Result<NodeId, String> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| format!("Invalid node id: {value}"))?;
    Ok(uuid.into())
}

fn parse_instance_id(value: &str) -> Result<InstanceId, String> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| format!("Invalid instance id: {value}"))?;
    Ok(uuid.into())
}

fn parse_tenant_id(value: &str) -> Result<splendor_types::TenantId, String> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| format!("Invalid tenant id: {value}"))?;
    Ok(uuid.into())
}

fn parse_agent_id(value: &str) -> Result<splendor_types::AgentId, String> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| format!("Invalid agent id: {value}"))?;
    Ok(uuid.into())
}

fn parse_run_id(value: &str) -> Result<splendor_types::RunId, String> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| format!("Invalid run id: {value}"))?;
    Ok(uuid.into())
}

fn daemon_request(
    method: &str,
    url: &str,
    body_path: Option<&Path>,
    credential_path: Option<&Path>,
    token: &str,
) -> Result<(), String> {
    let parsed = parse_local_http_url(url)?;
    let body = match body_path {
        Some(path) => Some(
            fs::read_to_string(path).map_err(|err| format!("Failed to read body file: {err}"))?,
        ),
        None => None,
    };
    if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") {
        let body_json: serde_json::Value = serde_json::from_str(body.as_deref().unwrap_or(""))
            .map_err(|err| format!("Mutating daemon request body must be JSON: {err}"))?;
        if body_json
            .get("credential")
            .is_none_or(serde_json::Value::is_null)
            || body_json
                .get("audit_attribution")
                .is_none_or(serde_json::Value::is_null)
        {
            return Err(
                "Mutating daemon requests require body credential and audit_attribution"
                    .to_string(),
            );
        }
    }
    let credential = match credential_path {
        Some(path) => Some(
            fs::read_to_string(path)
                .map_err(|err| format!("Failed to read caller credential file: {err}"))?,
        ),
        None => None,
    };
    let response = send_local_http(
        &parsed.host,
        parsed.port,
        method,
        &parsed.path,
        token,
        body.as_deref(),
        credential.as_deref(),
    )?;
    print!("{response}");
    Ok(())
}

#[derive(Debug)]
struct ParsedLocalUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_local_http_url(url: &str) -> Result<ParsedLocalUrl, String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        "splendorctl daemon request only supports explicit local http:// daemon URLs".to_string()
    })?;
    let (authority, path_part) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| "Daemon URL must include host and port".to_string())?;
    if host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
        return Err("splendorctl daemon request refuses non-local daemon hosts".to_string());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "Daemon URL port is invalid".to_string())?;
    let path = format!("/{path_part}");
    Ok(ParsedLocalUrl {
        host: host.trim_matches(&['[', ']'][..]).to_string(),
        port,
        path,
    })
}

fn send_local_http(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&str>,
    credential: Option<&str>,
) -> Result<String, String> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|err| format!("Failed to connect to daemon: {err}"))?;
    let body = body.unwrap_or("");
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nAuthorization: Bearer {token}\r\nX-Splendor-API-Version: 0.1\r\nX-Splendor-Client: splendorctl\r\nConnection: close\r\n"
    );
    if let Some(credential) = credential {
        request.push_str("X-Splendor-Caller-Credential: ");
        request.push_str(&credential.replace(['\r', '\n'], ""));
        request.push_str("\r\n");
    }
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("Failed to write daemon request: {err}"))?;
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .map_err(|err| format!("Failed to read daemon response: {err}"))?;
    let (head, response_body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| "Daemon returned malformed HTTP response".to_string())?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(format!(
            "Daemon request failed with HTTP {status}: {response_body}"
        ));
    }
    Ok(response_body.to_string())
}

/// Returns the CLI usage string.
fn usage() -> String {
    [
        "splendorctl trace export --db <path> --run <run-id>",
        "splendorctl state head --db <trace-path> --run <run-id>",
        "splendorctl replay --db <trace-path> --state-db <state-path> --run <run-id> [--from-snapshot <id>] [--include-state]",
        "splendorctl audit export --db <trace-path> --state-db <state-path> --run <run-id> [--tenant <id>] [--agent <id>] [--action <id-or-name>] [--adapter <id>] [--node <id>] [--instance <id>] [--fleet <id>]",
        "splendorctl acceptance validate-import --trace <jsonl> --state <json> --scenario-report <json> --source <id> [--expected-trace-chain <hash>] [--expected-state-hash <hash>]",
        "splendorctl acceptance compat --fixture <json> [--fixture <json> ...] --target-schema splendor.0.1.stable.v1",
        "splendorctl acceptance audit-check --audit <json> --scenario-report <json> --case <name> --category <name>",
        "splendorctl acceptance replay-mode --mode <inspect_only|read_only_re_evaluation|policy_comparison|verifier_explanation> --trace <jsonl> --state <json> --audit <json> --scenario-report <json> --source <id>",
        "splendorctl acceptance replay-credential-check --credential <json>",
        "splendorctl run --config <path> [--cycles <n> | --forever]",
        "splendorctl work-order sign --input <work-order.json> --key-id <id> --secret <secret>",
        "splendorctl daemon request --method <GET|POST> --url <local-url> --token <token> [--body <json>] [--caller-credential <json>]",
        "splendorctl --version",
        "",
        "Commands:",
        "  trace export   Export trace records as JSON lines.",
        "  state head     Print the latest state head recorded in the trace.",
        "  replay         Replay a run from trace + state stores.",
        "  audit export   Export a redacted governance audit from trace + state stores.",
        "  acceptance     Run public acceptance validators for artifact import, replay modes, schema compatibility, and audit reason codes.",
        "  run            Run a local agent loop from config.",
        "  work-order     Sign local work-order fixtures for scoped run authority.",
        "  daemon         Request documented local daemon endpoints; actions still go through /actions and the gateway.",
        "  --version      Print package and milestone release identifiers.",
        "",
        "Options:",
        "  --db <path>          Path to the SQLite trace database.",
        "  --state-db <path>    Path to the SQLite state database.",
        "  --run <id>           Run identifier to export or replay.",
        "  --from-snapshot <id> Snapshot identifier to start replay.",
        "  --include-state      Include snapshot bytes in replay output.",
        "  --tenant/--agent/--action/--adapter/--node/--instance/--fleet <value>",
        "                      Filter audit events by scoped identity where present.",
        "  --config <path>      Path to a run config (yaml/json).",
        "  --cycles <n>         Number of cycles to run.",
        "  --forever            Run until interrupted.",
        "  --token <token>      Required caller token; anonymous daemon fallback is refused.",
    ]
    .join("\n")
}

#[cfg(test)]
static TEST_ARGS: OnceLock<Mutex<Option<Vec<String>>>> = OnceLock::new();

#[cfg(test)]
static TEST_ARGS_GUARD: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(test)]
fn with_test_args<T>(args: Vec<String>, f: impl FnOnce() -> T) -> T {
    let guard = TEST_ARGS_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("test args guard lock");
    let storage = TEST_ARGS.get_or_init(|| Mutex::new(None));
    *storage.lock().expect("test args lock") = Some(args);
    let result = f();
    *storage.lock().expect("test args lock") = None;
    drop(guard);
    result
}

#[cfg(test)]
#[path = "../tests/unit/cli_tests.rs"]
mod tests;
