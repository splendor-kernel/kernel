use splendor_daemon::manager::{router, ManagerState};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr =
        std::env::var("SPLENDOR_MANAGER_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".to_string());
    let app = router(ManagerState::local_acceptance());
    let listener = TcpListener::bind(&bind_addr).await?;
    eprintln!(
        "Splendor central manager listening on {bind_addr} with authenticated caller requirements"
    );
    axum::serve(listener, app).await?;
    Ok(())
}
