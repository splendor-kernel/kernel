use splendor_daemon::manager::{router, ManagerState};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = std::env::var("SPLENDOR_MANAGER_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8081".to_string());
    if bind_addr.starts_with("0.0.0.0:")
        && std::env::var("SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV")
            .ok()
            .as_deref()
            != Some("1")
    {
        return Err(
            "SPLENDOR_MANAGER_BIND_ADDR=0.0.0.0 requires explicit SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV=1"
                .into(),
        );
    }
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
