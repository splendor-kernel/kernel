use rusqlite::{params, Connection};
use splendor_store::{SqliteStateStore, SqliteTraceStore, TraceStore};
use splendor_types::{ContentHash, RunId, TraceEvent, TraceEventKind};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;
use time::OffsetDateTime;

const CORRUPT_CANARY: &str = "C03_LATE_CORRUPT_CANARY_MUST_NOT_ESCAPE";

struct CliFixture {
    _directory: TempDir,
    trace_path: PathBuf,
    state_path: PathBuf,
    run_id: RunId,
}

fn cli_fixture(corrupt_tail: bool) -> CliFixture {
    let directory = tempfile::tempdir().expect("CLI fixture directory");
    let trace_path = directory.path().join("private-trace.sqlite3");
    let state_path = directory.path().join("private-state.sqlite3");
    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    SqliteStateStore::open(&state_path).expect("state store");
    let run_id = RunId::new();
    let timestamp = OffsetDateTime::UNIX_EPOCH;
    for event in [
        TraceEvent::new(
            run_id.clone(),
            0,
            timestamp,
            TraceEventKind::RunPaused {
                reason: Some("fixture".to_string()),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            timestamp,
            TraceEventKind::StateCommitted {
                state_hash: ContentHash::blake3(b"fixture-state"),
                snapshot_id: None,
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            2,
            timestamp,
            TraceEventKind::RunResumed {
                reason: Some("fixture".to_string()),
            },
        ),
    ] {
        TraceStore::append(
            &store,
            &run_id.to_string(),
            serde_json::to_value(event).expect("trace event"),
        )
        .expect("trace append");
    }
    drop(store);

    if corrupt_tail {
        let connection = Connection::open(&trace_path).expect("corruption connection");
        let corrupt_payload = serde_json::to_vec(&serde_json::json!({
            "late_corruption": CORRUPT_CANARY,
        }))
        .expect("corrupt payload");
        connection
            .execute(
                "UPDATE trace_events SET payload = ?1 WHERE run_id = ?2 AND sequence = 2",
                params![corrupt_payload, run_id.to_string()],
            )
            .expect("late tail corruption");
    }

    CliFixture {
        _directory: directory,
        trace_path,
        state_path,
        run_id,
    }
}

fn cli_commands(fixture: &CliFixture) -> Vec<(&'static str, Vec<String>, &'static str)> {
    let trace = fixture.trace_path.display().to_string();
    let state = fixture.state_path.display().to_string();
    let run = fixture.run_id.to_string();
    vec![
        (
            "trace export",
            vec![
                "trace".to_string(),
                "export".to_string(),
                "--db".to_string(),
                trace.clone(),
                "--run".to_string(),
                run.clone(),
            ],
            "trace_export_write_failed",
        ),
        (
            "state head",
            vec![
                "state".to_string(),
                "head".to_string(),
                "--db".to_string(),
                trace.clone(),
                "--run".to_string(),
                run.clone(),
            ],
            "state_head_write_failed",
        ),
        (
            "replay",
            vec![
                "replay".to_string(),
                "--db".to_string(),
                trace.clone(),
                "--state-db".to_string(),
                state.clone(),
                "--run".to_string(),
                run.clone(),
            ],
            "replay_output_write_failed",
        ),
        (
            "audit export",
            vec![
                "audit".to_string(),
                "export".to_string(),
                "--db".to_string(),
                trace,
                "--state-db".to_string(),
                state,
                "--run".to_string(),
                run,
            ],
            "audit_export_write_failed",
        ),
    ]
}

fn run_cli(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_splendorctl"))
        .args(args)
        .output()
        .expect("run splendorctl")
}

fn assert_private_diagnostics(stderr: &[u8], fixture: &CliFixture) {
    let stderr = String::from_utf8_lossy(stderr);
    assert!(!stderr.contains(CORRUPT_CANARY));
    assert!(!stderr.contains(&fixture.run_id.to_string()));
    assert!(!stderr.contains(&fixture.trace_path.display().to_string()));
    assert!(!stderr.contains(&fixture.state_path.display().to_string()));
}

#[test]
fn late_trace_corruption_is_nonzero_and_emits_exactly_zero_stdout_for_all_consumers() {
    let fixture = cli_fixture(true);
    for (label, args, _) in cli_commands(&fixture) {
        let output = run_cli(&args);
        assert!(!output.status.success(), "{label} unexpectedly succeeded");
        assert!(
            output.stdout.is_empty(),
            "{label} emitted partial stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stderr).trim(),
            "trace_compatibility_integrity_failure",
            "{label} returned an unstable diagnostic"
        );
        assert_private_diagnostics(&output.stderr, &fixture);
    }
}

#[cfg(unix)]
#[test]
fn fully_spooled_outputs_return_nonzero_without_writing_when_stdout_rejects_the_commit() {
    let fixture = cli_fixture(false);
    for (label, args, expected_error) in cli_commands(&fixture) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_splendorctl"))
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn splendorctl with rejecting stdout");
        drop(child.stdout.take().expect("child stdout pipe"));
        let output = child
            .wait_with_output()
            .expect("wait for splendorctl with rejecting stdout");
        assert!(!output.status.success(), "{label} unexpectedly succeeded");
        assert!(output.stdout.is_empty(), "{label} returned captured stdout");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr).trim(),
            expected_error,
            "{label} returned an unstable write diagnostic"
        );
        assert_private_diagnostics(&output.stderr, &fixture);
    }
}

#[test]
fn missing_database_diagnostics_do_not_reflect_private_paths_or_run_identity() {
    let directory = tempfile::tempdir().expect("missing database directory");
    let private_trace = directory.path().join("TRACE_PATH_CANARY.sqlite3");
    let private_state = directory.path().join("STATE_PATH_CANARY.sqlite3");
    let private_run = "RUN_ID_CANARY";
    for args in [
        vec![
            "trace",
            "export",
            "--db",
            private_trace.to_str().expect("trace path"),
            "--run",
            private_run,
        ],
        vec![
            "state",
            "head",
            "--db",
            private_trace.to_str().expect("trace path"),
            "--run",
            private_run,
        ],
        vec![
            "replay",
            "--db",
            private_trace.to_str().expect("trace path"),
            "--state-db",
            private_state.to_str().expect("state path"),
            "--run",
            private_run,
        ],
        vec![
            "audit",
            "export",
            "--db",
            private_trace.to_str().expect("trace path"),
            "--state-db",
            private_state.to_str().expect("state path"),
            "--run",
            private_run,
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_splendorctl"))
            .args(args)
            .output()
            .expect("run missing database command");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(stderr.trim(), "trace_database_not_found");
        assert!(!stderr.contains(private_run));
        assert!(!stderr.contains(private_trace.to_str().expect("trace path")));
        assert!(!stderr.contains(private_state.to_str().expect("state path")));
    }

    let existing_trace = directory.path().join("existing.sqlite3");
    SqliteTraceStore::open(&existing_trace).expect("existing trace database");
    for args in [
        vec![
            "replay",
            "--db",
            existing_trace.to_str().expect("trace path"),
            "--state-db",
            private_state.to_str().expect("state path"),
            "--run",
            private_run,
        ],
        vec![
            "audit",
            "export",
            "--db",
            existing_trace.to_str().expect("trace path"),
            "--state-db",
            private_state.to_str().expect("state path"),
            "--run",
            private_run,
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_splendorctl"))
            .args(args)
            .output()
            .expect("run missing state database command");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(stderr.trim(), "state_database_not_found");
        assert!(!stderr.contains(private_run));
        assert!(!stderr.contains(private_state.to_str().expect("state path")));
    }
}
