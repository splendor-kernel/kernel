use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;
use splendor_daemon::caller_auth::CallerTokenSigner;
use splendor_daemon::manager::{router, ManagerState, ResidentDispatchOptions};
use splendor_types::{FleetId, WorkOrderKeyring};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::TcpListener;

const CONFIG_FILE_LIMIT: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkOrderKeyringFile {
    schema_version: String,
    keys: Vec<SharedSecretKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedSecretKey {
    key_id: String,
    shared_secret_base64url: String,
}

fn manager_bind_addr() -> String {
    std::env::var("SPLENDOR_MANAGER_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string())
}

fn validate_manager_bind_addr(bind_addr: &str) -> Result<(), String> {
    let parsed = bind_addr
        .parse::<SocketAddr>()
        .map_err(|_| "SPLENDOR_MANAGER_BIND_ADDR must be a socket address".to_string())?;
    if !parsed.ip().is_loopback()
        && std::env::var("SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV")
            .ok()
            .as_deref()
            != Some("1")
    {
        return Err("a non-loopback SPLENDOR_MANAGER_BIND_ADDR requires explicit SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV=1".to_string());
    }
    Ok(())
}

fn validate_manager_mode() -> Result<(), &'static str> {
    match std::env::var("SPLENDOR_MANAGER_MODE").ok().as_deref() {
        Some("local_acceptance") => Ok(()),
        _ => Err(
            "SPLENDOR_MANAGER_MODE=local_acceptance is required; production inbound caller authentication is not implemented",
        ),
    }
}

fn required_env(name: &str) -> Result<String, std::io::Error> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{name} is required"),
            )
        })
}

fn configured_manager_state() -> Result<ManagerState, std::io::Error> {
    let manager_id = required_env("SPLENDOR_MANAGER_ID")?;
    let fleet_id = FleetId::parse(&required_env("SPLENDOR_FLEET_ID")?).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SPLENDOR_FLEET_ID must be a valid non-nil UUID",
        )
    })?;
    if fleet_id.is_nil() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SPLENDOR_FLEET_ID must be a valid non-nil UUID",
        ));
    }
    let signer = CallerTokenSigner::from_pkcs8_file(
        required_env("SPLENDOR_MANAGER_CALLER_ISSUER")?,
        required_env("SPLENDOR_MANAGER_CALLER_APP_PRINCIPAL_ID")?,
        required_env("SPLENDOR_MANAGER_CALLER_CLIENT_PRINCIPAL_ID")?,
        required_env("SPLENDOR_MANAGER_CALLER_KEY_ID")?,
        required_env("SPLENDOR_MANAGER_CALLER_SIGNING_KEY_FILE")?,
    )
    .map_err(|_| invalid_config("caller signing key"))?;
    let work_order_keyring = load_work_order_keyring(Path::new(&required_env(
        "SPLENDOR_MANAGER_WORK_ORDER_KEYRING_FILE",
    )?))?;
    let root_ca_path = required_env("SPLENDOR_MANAGER_RESIDENT_ROOT_CA_FILE")?;
    let root_ca_metadata = fs::metadata(&root_ca_path)?;
    if root_ca_metadata.len() > CONFIG_FILE_LIMIT {
        return Err(invalid_config("resident root CA"));
    }
    let mut options = ResidentDispatchOptions::production();
    options.root_ca_pem = Some(fs::read(root_ca_path)?);
    ManagerState::acceptance_with_dispatch_config(
        manager_id,
        fleet_id,
        work_order_keyring,
        signer,
        options,
    )
    .map_err(|_| invalid_config("resident dispatch"))
}

fn load_work_order_keyring(path: &Path) -> Result<WorkOrderKeyring, std::io::Error> {
    require_private_file_permissions(path)?;
    if fs::metadata(path)?.len() > CONFIG_FILE_LIMIT {
        return Err(invalid_config("work-order keyring"));
    }
    let file: WorkOrderKeyringFile = serde_json::from_slice(&fs::read(path)?)
        .map_err(|_| invalid_config("work-order keyring"))?;
    if file.schema_version != "splendor.work_order_keyring.v1" || file.keys.is_empty() {
        return Err(invalid_config("work-order keyring"));
    }
    let mut keyring = WorkOrderKeyring::new();
    let mut key_ids = std::collections::HashSet::new();
    for key in file.keys {
        if key.key_id.trim().is_empty() || !key_ids.insert(key.key_id.clone()) {
            return Err(invalid_config("work-order keyring"));
        }
        let secret = URL_SAFE_NO_PAD
            .decode(key.shared_secret_base64url.as_bytes())
            .map_err(|_| invalid_config("work-order keyring"))?;
        if secret.len() < 32 {
            return Err(invalid_config("work-order keyring"));
        }
        keyring
            .insert_shared_secret(key.key_id, &secret)
            .map_err(|_| invalid_config("work-order keyring"))?;
    }
    Ok(keyring)
}

fn invalid_config(kind: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("invalid {kind} configuration"),
    )
}

#[cfg(unix)]
fn require_private_file_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{} must not be group/world accessible", path.display()),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_file_permissions(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    validate_manager_mode()?;
    let bind_addr = manager_bind_addr();
    validate_manager_bind_addr(&bind_addr)?;
    let app = router(configured_manager_state()?);
    let listener = TcpListener::bind(&bind_addr).await?;
    if bind_addr.starts_with("0.0.0.0:") {
        eprintln!("WARNING: Splendor central manager is running in explicit local acceptance non-loopback mode on {bind_addr}; inbound caller proof is not production-ready");
    } else {
        eprintln!("WARNING: Splendor central manager is running in explicit local acceptance mode on {bind_addr}; inbound caller proof is not production-ready");
    }
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    static MANAGER_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct ManagerEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl ManagerEnvGuard {
        fn acquire() -> Self {
            let lock = MANAGER_ENV_LOCK.lock().expect("manager env lock");
            clear_manager_env();
            Self { _lock: lock }
        }
    }

    impl Drop for ManagerEnvGuard {
        fn drop(&mut self) {
            clear_manager_env();
        }
    }

    fn clear_manager_env() {
        for name in [
            "SPLENDOR_MANAGER_MODE",
            "SPLENDOR_MANAGER_BIND_ADDR",
            "SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV",
            "SPLENDOR_MANAGER_ID",
            "SPLENDOR_FLEET_ID",
            "SPLENDOR_MANAGER_CALLER_ISSUER",
            "SPLENDOR_MANAGER_CALLER_APP_PRINCIPAL_ID",
            "SPLENDOR_MANAGER_CALLER_CLIENT_PRINCIPAL_ID",
            "SPLENDOR_MANAGER_CALLER_KEY_ID",
            "SPLENDOR_MANAGER_CALLER_SIGNING_KEY_FILE",
            "SPLENDOR_MANAGER_WORK_ORDER_KEYRING_FILE",
            "SPLENDOR_MANAGER_RESIDENT_ROOT_CA_FILE",
        ] {
            std::env::remove_var(name);
        }
    }

    #[test]
    fn manager_bind_defaults_to_loopback() {
        let _env = ManagerEnvGuard::acquire();
        assert_eq!(super::manager_bind_addr(), "127.0.0.1:8081");
    }

    #[test]
    fn manager_mode_must_be_explicit_and_acceptance_only() {
        let _env = ManagerEnvGuard::acquire();
        assert!(super::validate_manager_mode().is_err());
        std::env::set_var("SPLENDOR_MANAGER_MODE", "production");
        assert!(super::validate_manager_mode().is_err());
        std::env::set_var("SPLENDOR_MANAGER_MODE", "local_acceptance");
        super::validate_manager_mode().expect("explicit local acceptance mode");
    }

    #[test]
    fn manager_non_loopback_requires_explicit_dev_flag() {
        let _env = ManagerEnvGuard::acquire();
        let error = super::validate_manager_bind_addr("0.0.0.0:8081")
            .expect_err("non-loopback rejected without explicit flag");
        assert!(error.contains("SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV=1"));

        std::env::set_var("SPLENDOR_MANAGER_ALLOW_NON_LOOPBACK_DEV", "1");
        super::validate_manager_bind_addr("0.0.0.0:8081")
            .expect("explicit local acceptance non-loopback allowed");
        assert!(super::validate_manager_bind_addr("manager.example:8081").is_err());
    }

    #[test]
    fn manager_outbound_dispatch_requires_explicit_private_keys_and_root_ca() {
        use ring::rand::SystemRandom;
        use ring::signature::Ed25519KeyPair;

        let _env = ManagerEnvGuard::acquire();
        let root =
            std::env::temp_dir().join(format!("splendor-manager-startup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).expect("fixture directory");
        let signing_key = root.join("caller-signing-key.pk8");
        let work_order_keyring = root.join("work-order-keyring.json");
        let root_ca = root.join("resident-root-ca.pem");
        let pkcs8 =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("caller signing key");
        write_private_bytes(&signing_key, pkcs8.as_ref());
        write_private_json(
            &work_order_keyring,
            serde_json::json!({
                "schema_version": "splendor.work_order_keyring.v1",
                "keys": [{
                    "key_id": "manager-work-order",
                    "shared_secret_base64url": base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        [7_u8; 32]
                    )
                }]
            }),
        );
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("resident root CA");
        std::fs::write(&root_ca, certificate.cert.pem()).expect("root CA file");

        for (name, value) in [
            ("SPLENDOR_MANAGER_ID", "central-manager".to_string()),
            (
                "SPLENDOR_FLEET_ID",
                "00000000-0000-4000-8000-000000000104".to_string(),
            ),
            (
                "SPLENDOR_MANAGER_CALLER_ISSUER",
                "urn:splendor:manager:central-manager".to_string(),
            ),
            (
                "SPLENDOR_MANAGER_CALLER_APP_PRINCIPAL_ID",
                "central-manager".to_string(),
            ),
            (
                "SPLENDOR_MANAGER_CALLER_CLIENT_PRINCIPAL_ID",
                "resident-dispatch-client".to_string(),
            ),
            (
                "SPLENDOR_MANAGER_CALLER_KEY_ID",
                "manager-resident-test".to_string(),
            ),
            (
                "SPLENDOR_MANAGER_CALLER_SIGNING_KEY_FILE",
                signing_key.display().to_string(),
            ),
            (
                "SPLENDOR_MANAGER_WORK_ORDER_KEYRING_FILE",
                work_order_keyring.display().to_string(),
            ),
            (
                "SPLENDOR_MANAGER_RESIDENT_ROOT_CA_FILE",
                root_ca.display().to_string(),
            ),
        ] {
            std::env::set_var(name, value);
        }
        super::configured_manager_state().expect("explicit outbound dispatch configuration");

        std::env::remove_var("SPLENDOR_MANAGER_CALLER_SIGNING_KEY_FILE");
        assert!(super::configured_manager_state()
            .err()
            .expect("missing signer denied")
            .to_string()
            .contains("SPLENDOR_MANAGER_CALLER_SIGNING_KEY_FILE"));
        std::env::set_var("SPLENDOR_MANAGER_CALLER_SIGNING_KEY_FILE", &signing_key);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&work_order_keyring, std::fs::Permissions::from_mode(0o644))
                .expect("permissive keyring mode");
            assert!(super::configured_manager_state()
                .err()
                .expect("permissive keyring denied")
                .to_string()
                .contains("group/world"));
        }
        std::fs::remove_dir_all(root).expect("remove fixture directory");
    }

    fn write_private_json(path: &std::path::Path, value: serde_json::Value) {
        write_private_bytes(path, &serde_json::to_vec(&value).expect("fixture JSON"));
    }

    fn write_private_bytes(path: &std::path::Path, value: &[u8]) {
        std::fs::write(path, value).expect("private fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("private fixture mode");
        }
    }
}
