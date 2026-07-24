//! Production runtime daemon binary.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    splendor_daemon::process::run_adapterless().await
}
