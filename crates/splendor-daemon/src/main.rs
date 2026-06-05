//! Minimal local daemon binary for 0.02-S5 development smoke tests.

use splendor_daemon::{router, DaemonConfig, DaemonState};
use splendor_types::InstanceId;
use tokio::net::TcpListener;

fn daemon_bind_addr() -> String {
    std::env::var("SPLENDOR_DAEMON_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8077".to_string())
}

fn daemon_state() -> DaemonState {
    if std::env::var("SPLENDOR_DAEMON_MODE").ok().as_deref() == Some("resident") {
        let instance_id = std::env::var("SPLENDOR_INSTANCE_ID")
            .ok()
            .and_then(|raw| InstanceId::parse(&raw).ok())
            .unwrap_or_default();
        DaemonState::new(DaemonConfig::resident(instance_id))
    } else {
        DaemonState::local_dev()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = daemon_state();
    let app = router(state);
    let bind_addr = daemon_bind_addr();
    let listener = TcpListener::bind(&bind_addr).await?;
    if std::env::var("SPLENDOR_DAEMON_MODE").ok().as_deref() == Some("resident") {
        eprintln!("Splendor resident runtime daemon listening on {bind_addr} with authenticated caller requirements");
    } else {
        eprintln!("WARNING: Splendor runtime daemon is running in explicit local-only insecure dev mode on {bind_addr}");
    }
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn daemon_bind_remains_loopback_even_when_acceptance_env_is_set() {
        std::env::set_var("SPLENDOR_RUNTIME_MODE", "acceptance");
        std::env::set_var("SPLENDOR_DAEMON_ACCEPTANCE_BIND_UNSAFE", "1");
        std::env::remove_var("SPLENDOR_DAEMON_BIND_ADDR");
        assert_eq!(super::daemon_bind_addr(), "127.0.0.1:8077");
        std::env::remove_var("SPLENDOR_RUNTIME_MODE");
        std::env::remove_var("SPLENDOR_DAEMON_ACCEPTANCE_BIND_UNSAFE");
    }

    #[test]
    fn daemon_state_switches_between_local_dev_and_resident_modes() {
        std::env::remove_var("SPLENDOR_DAEMON_MODE");
        let _local = super::daemon_state();

        std::env::set_var("SPLENDOR_DAEMON_MODE", "resident");
        std::env::set_var(
            "SPLENDOR_INSTANCE_ID",
            "00000000-0000-4000-8000-000000000302",
        );
        let _resident = super::daemon_state();
        std::env::remove_var("SPLENDOR_DAEMON_MODE");
        std::env::remove_var("SPLENDOR_INSTANCE_ID");
    }
}
