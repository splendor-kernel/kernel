//! Explicit non-production composition host for use-case acceptance only.

use splendor_acceptance_action_host::configured_adapters;

const LOCAL_ACCEPTANCE_INSTANCE_ID: &str = "00000000-0000-4000-8000-000000000300";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("SPLENDOR_ACCEPTANCE_ONLY").as_deref() != Ok("1") {
        return Err("splendor-acceptance-action-host requires SPLENDOR_ACCEPTANCE_ONLY=1".into());
    }
    let endpoint = std::env::var("SPLENDOR_ACCEPTANCE_PROVIDER_ENDPOINT")
        .map_err(|_| "SPLENDOR_ACCEPTANCE_PROVIDER_ENDPOINT is required")?;
    let credential_path = std::env::var("SPLENDOR_ACCEPTANCE_REQUEST_CREDENTIAL_FILE")
        .map_err(|_| "SPLENDOR_ACCEPTANCE_REQUEST_CREDENTIAL_FILE is required")?;
    let public_key_path = std::env::var("SPLENDOR_ACCEPTANCE_RECEIPT_PUBLIC_KEY_FILE")
        .map_err(|_| "SPLENDOR_ACCEPTANCE_RECEIPT_PUBLIC_KEY_FILE is required")?;
    let source_instance_id = std::env::var("SPLENDOR_INSTANCE_ID")
        .unwrap_or_else(|_| LOCAL_ACCEPTANCE_INSTANCE_ID.to_string());
    let adapters = configured_adapters(
        &endpoint,
        std::path::Path::new(&credential_path),
        std::path::Path::new(&public_key_path),
        &source_instance_id,
    )?;
    eprintln!(
        "WARNING: explicit acceptance-only Splendor host composed with controlled fixture adapters"
    );
    splendor_daemon::process::run_with_action_adapters(adapters).await
}
