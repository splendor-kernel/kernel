//! Minimal local daemon binary for 0.02-S5 development smoke tests.

use splendor_daemon::{router, DaemonState};
use tokio::net::TcpListener;

fn daemon_bind_addr() -> &'static str {
    "127.0.0.1:8077"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = DaemonState::local_dev();
    let app = router(state);
    let listener = TcpListener::bind(daemon_bind_addr()).await?;
    eprintln!(
        "WARNING: Splendor runtime daemon is running in explicit local-only insecure dev mode on 127.0.0.1:8077"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn daemon_bind_remains_loopback_even_when_acceptance_env_is_set() {
        std::env::set_var("SPLENDOR_RUNTIME_MODE", "acceptance");
        std::env::set_var("SPLENDOR_DAEMON_ACCEPTANCE_BIND_UNSAFE", "1");
        assert_eq!(super::daemon_bind_addr(), "127.0.0.1:8077");
        std::env::remove_var("SPLENDOR_RUNTIME_MODE");
        std::env::remove_var("SPLENDOR_DAEMON_ACCEPTANCE_BIND_UNSAFE");
    }
}
