//! Minimal local daemon binary for 0.02-S5 development smoke tests.

use splendor_daemon::{router, DaemonConfig, DaemonState};
use splendor_types::InstanceId;
use tokio::net::TcpListener;

fn daemon_bind_addr() -> String {
    std::env::var("SPLENDOR_DAEMON_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8077".to_string())
}

fn daemon_state_from_config(
    mode: Option<&str>,
    instance_id: Option<&str>,
) -> Result<DaemonState, std::io::Error> {
    if mode == Some("resident") {
        let raw = instance_id
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "resident mode requires explicit SPLENDOR_INSTANCE_ID",
                )
            })?;
        let instance_id = InstanceId::parse(raw).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SPLENDOR_INSTANCE_ID must be a valid non-nil UUID",
            )
        })?;
        if instance_id.is_nil() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SPLENDOR_INSTANCE_ID must be a valid non-nil UUID",
            ));
        }
        Ok(DaemonState::new(DaemonConfig::resident(instance_id)))
    } else {
        Ok(DaemonState::local_dev())
    }
}

fn daemon_state() -> Result<DaemonState, std::io::Error> {
    let mode = std::env::var("SPLENDOR_DAEMON_MODE").ok();
    let instance_id = std::env::var("SPLENDOR_INSTANCE_ID").ok();
    daemon_state_from_config(mode.as_deref(), instance_id.as_deref())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = daemon_state()?;
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
    static STARTUP_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct StartupEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl StartupEnvGuard {
        fn acquire() -> Self {
            let lock = STARTUP_ENV_LOCK.lock().expect("startup env lock");
            std::env::remove_var("SPLENDOR_DAEMON_MODE");
            std::env::remove_var("SPLENDOR_INSTANCE_ID");
            Self { _lock: lock }
        }
    }

    impl Drop for StartupEnvGuard {
        fn drop(&mut self) {
            std::env::remove_var("SPLENDOR_DAEMON_MODE");
            std::env::remove_var("SPLENDOR_INSTANCE_ID");
        }
    }

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
    fn daemon_startup_config_requires_explicit_valid_resident_instance_id() {
        let _env = StartupEnvGuard::acquire();
        super::daemon_state().expect("local development remains available");

        std::env::set_var("SPLENDOR_DAEMON_MODE", "resident");
        let missing = super::daemon_state()
            .err()
            .expect("resident identity is required");
        assert_eq!(missing.kind(), std::io::ErrorKind::InvalidInput);
        assert!(missing.to_string().contains("requires explicit"));

        std::env::set_var("SPLENDOR_INSTANCE_ID", "not-a-uuid");
        let malformed = super::daemon_state()
            .err()
            .expect("malformed resident identity denied");
        assert_eq!(malformed.kind(), std::io::ErrorKind::InvalidInput);
        assert!(malformed.to_string().contains("valid non-nil UUID"));

        std::env::set_var(
            "SPLENDOR_INSTANCE_ID",
            "00000000-0000-0000-0000-000000000000",
        );
        let nil = super::daemon_state()
            .err()
            .expect("nil resident identity denied");
        assert_eq!(nil.kind(), std::io::ErrorKind::InvalidInput);

        std::env::set_var(
            "SPLENDOR_INSTANCE_ID",
            "00000000-0000-4000-8000-000000000302",
        );
        super::daemon_state().expect("valid resident identity accepted");
    }
}
