//! Minimal local daemon binary for 0.02-S5 development smoke tests.

use splendor_daemon::{router, DaemonState};
use std::env;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = DaemonState::local_dev();
    let app = router(state);
    let acceptance_bind = env::var("SPLENDOR_DAEMON_ACCEPTANCE_BIND_UNSAFE")
        .ok()
        .as_deref()
        == Some("1")
        && env::var("SPLENDOR_RUNTIME_MODE").ok().as_deref() == Some("acceptance");
    let bind_addr = if acceptance_bind {
        "0.0.0.0:8077"
    } else {
        "127.0.0.1:8077"
    };
    let listener = TcpListener::bind(bind_addr).await?;
    if acceptance_bind {
        eprintln!(
            "WARNING: Splendor runtime daemon is running in explicit acceptance-only insecure dev mode on 0.0.0.0:8077; use only inside local E2E compose topology"
        );
    } else {
        eprintln!(
            "WARNING: Splendor runtime daemon is running in explicit local-only insecure dev mode on 127.0.0.1:8077"
        );
    }
    axum::serve(listener, app).await?;
    Ok(())
}
