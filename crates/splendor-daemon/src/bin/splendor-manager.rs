use splendor_daemon::manager::{router, ManagerState};
use tokio::net::TcpListener;

fn manager_bind_addr() -> String {
    std::env::var("SPLENDOR_MANAGER_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string())
}

fn validate_manager_bind_addr(bind_addr: &str) -> Result<(), &'static str> {
    if bind_addr.starts_with("0.0.0.0:")
        && std::env::var("SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV")
            .ok()
            .as_deref()
            != Some("1")
    {
        return Err(
            "SPLENDOR_MANAGER_BIND_ADDR=0.0.0.0 requires explicit SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV=1",
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = manager_bind_addr();
    validate_manager_bind_addr(&bind_addr)?;
    let app = router(ManagerState::local_acceptance());
    let listener = TcpListener::bind(&bind_addr).await?;
    if bind_addr.starts_with("0.0.0.0:") {
        eprintln!("WARNING: Splendor central manager is running in explicit local acceptance non-loopback dev mode on {bind_addr} with authenticated caller requirements");
    } else {
        eprintln!("Splendor central manager listening on {bind_addr} with authenticated caller requirements");
    }
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn manager_bind_defaults_to_loopback() {
        std::env::remove_var("SPLENDOR_MANAGER_BIND_ADDR");
        assert_eq!(super::manager_bind_addr(), "127.0.0.1:8081");
    }

    #[test]
    fn manager_non_loopback_requires_explicit_dev_flag() {
        std::env::remove_var("SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV");
        let error = super::validate_manager_bind_addr("0.0.0.0:8081")
            .expect_err("non-loopback rejected without explicit flag");
        assert!(error.contains("SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV=1"));

        std::env::set_var("SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV", "1");
        super::validate_manager_bind_addr("0.0.0.0:8081")
            .expect("explicit local acceptance non-loopback allowed");
        std::env::remove_var("SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV");
    }
}
