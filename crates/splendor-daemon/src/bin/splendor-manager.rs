use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;
use splendor_daemon::caller_auth::{CallerTokenSigner, CallerTokenVerifier};
use splendor_daemon::manager::{router, ManagerState, ResidentDispatchOptions};
use splendor_kernel::LocalAuthorityObligationReceiptConfig;
use splendor_types::{FleetId, PrincipalId, WorkOrderKeyring};
use std::fs::{File, OpenOptions};
use std::io::Read as _;
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityReceiptConfigFile {
    schema_version: String,
    issuer_principal_id: String,
    audience_prefix: String,
    key_id: String,
    validation_secret_base64url: String,
    revocation_ref: String,
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
    let authority_receipt_config = load_authority_receipt_config(Path::new(&required_env(
        "SPLENDOR_AUTHORITY_OBLIGATION_RECEIPT_CONFIG_FILE",
    )?))?;
    let approval_caller_verifier = CallerTokenVerifier::from_manager_file(
        required_env("SPLENDOR_MANAGER_APPROVAL_CALLER_TRUST_FILE")?,
        manager_id.clone(),
        fleet_id.clone(),
    )
    .map_err(|_| invalid_config("manager approval caller trust"))?;
    let root_ca_path = required_env("SPLENDOR_MANAGER_RESIDENT_ROOT_CA_FILE")?;
    let mut options = ResidentDispatchOptions::production();
    options.root_ca_pem = Some(read_regular_file(
        Path::new(&root_ca_path),
        CONFIG_FILE_LIMIT,
        false,
    )?);
    options.allowed_origins = required_env("SPLENDOR_MANAGER_RESIDENT_ALLOWED_ORIGINS")?
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(str::to_string)
        .collect();
    if options.allowed_origins.is_empty() {
        return Err(invalid_config("resident allowed origins"));
    }
    ManagerState::acceptance_with_dispatch_receipt_and_approval_auth(
        manager_id,
        fleet_id,
        work_order_keyring,
        signer,
        options,
        authority_receipt_config,
        approval_caller_verifier,
    )
    .map_err(|_| invalid_config("resident dispatch"))
}

fn load_authority_receipt_config(
    path: &Path,
) -> Result<LocalAuthorityObligationReceiptConfig, std::io::Error> {
    let bytes = read_regular_file(path, CONFIG_FILE_LIMIT, true)?;
    let file: AuthorityReceiptConfigFile =
        serde_json::from_slice(&bytes).map_err(|_| invalid_config("authority receipt"))?;
    if file.schema_version != "splendor.authority_obligation_receipt_config.v1" {
        return Err(invalid_config("authority receipt"));
    }
    let issuer = PrincipalId::parse(&file.issuer_principal_id)
        .map_err(|_| invalid_config("authority receipt"))?;
    let secret = URL_SAFE_NO_PAD
        .decode(file.validation_secret_base64url.as_bytes())
        .map_err(|_| invalid_config("authority receipt"))?;
    if secret.len() < 32 {
        return Err(invalid_config("authority receipt"));
    }
    LocalAuthorityObligationReceiptConfig::trusted_local(
        issuer,
        file.audience_prefix,
        file.key_id,
        file.validation_secret_base64url,
        file.revocation_ref,
    )
    .map_err(|_| invalid_config("authority receipt"))
}

fn load_work_order_keyring(path: &Path) -> Result<WorkOrderKeyring, std::io::Error> {
    let bytes = read_regular_file(path, CONFIG_FILE_LIMIT, true)?;
    let file: WorkOrderKeyringFile =
        serde_json::from_slice(&bytes).map_err(|_| invalid_config("work-order keyring"))?;
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
fn require_private_file_permissions(file: &File, path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = file.metadata()?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} must be owned by the service user and not be group/world accessible",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_file_permissions(_file: &File, _path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

fn open_regular_file(path: &Path) -> Result<File, std::io::Error> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} must be a regular file", path.display()),
        ));
    }
    Ok(file)
}

fn read_regular_file(
    path: &Path,
    maximum_bytes: u64,
    private: bool,
) -> Result<Vec<u8>, std::io::Error> {
    let mut file = open_regular_file(path)?;
    if private {
        require_private_file_permissions(&file, path)?;
    }
    let metadata = file.metadata()?;
    if metadata.len() > maximum_bytes {
        return Err(invalid_config("oversized file"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(invalid_config("oversized file"));
    }
    Ok(bytes)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    validate_manager_mode()?;
    let bind_addr = manager_bind_addr();
    validate_manager_bind_addr(&bind_addr)?;
    let app = router(configured_manager_state()?);
    let listener = TcpListener::bind(&bind_addr).await?;
    if bind_addr.starts_with("0.0.0.0:") {
        eprintln!("WARNING: Splendor central manager is running in explicit local acceptance non-loopback mode on {bind_addr}; only approval mutations have bounded inbound bearer verification and all other manager endpoints remain acceptance-only");
    } else {
        eprintln!("WARNING: Splendor central manager is running in explicit local acceptance mode on {bind_addr}; only approval mutations have bounded inbound bearer verification and all other manager endpoints remain acceptance-only");
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
            "SPLENDOR_AUTHORITY_OBLIGATION_RECEIPT_CONFIG_FILE",
            "SPLENDOR_MANAGER_APPROVAL_CALLER_TRUST_FILE",
            "SPLENDOR_MANAGER_RESIDENT_ROOT_CA_FILE",
            "SPLENDOR_MANAGER_RESIDENT_ALLOWED_ORIGINS",
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
    fn manager_config_reads_reject_non_regular_and_symlink_files() {
        let root = std::env::temp_dir().join(format!(
            "splendor-manager-file-hardening-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).expect("fixture directory");
        assert!(super::read_regular_file(&root, super::CONFIG_FILE_LIMIT, false).is_err());
        let target = root.join("target.json");
        write_private_bytes(&target, b"{}");
        #[cfg(unix)]
        {
            let link = root.join("link.json");
            std::os::unix::fs::symlink(&target, &link).expect("fixture symlink");
            assert!(super::read_regular_file(&link, super::CONFIG_FILE_LIMIT, false).is_err());
            assert!(super::read_regular_file(&link, super::CONFIG_FILE_LIMIT, true).is_err());
        }
        std::fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn manager_outbound_dispatch_requires_explicit_private_keys_and_root_ca() {
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let _env = ManagerEnvGuard::acquire();
        let root =
            std::env::temp_dir().join(format!("splendor-manager-startup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).expect("fixture directory");
        let signing_key = root.join("caller-signing-key.pk8");
        let work_order_keyring = root.join("work-order-keyring.json");
        let authority_receipt_config = root.join("authority-receipt-config.json");
        let approval_caller_trust = root.join("approval-caller-trust.json");
        let root_ca = root.join("resident-root-ca.pem");
        let pkcs8 =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("caller signing key");
        write_private_bytes(&signing_key, pkcs8.as_ref());
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("caller key pair");
        let approval_pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .expect("approval caller signing key");
        let approval_key_pair =
            Ed25519KeyPair::from_pkcs8(approval_pkcs8.as_ref()).expect("approval caller key pair");
        let trust_now = time::OffsetDateTime::now_utc();
        let approval_trust = splendor_daemon::caller_auth::CallerTokenTrustSnapshot::single_key(
            "urn:splendor:manager:approval-control-plane",
            "approval-control-plane",
            "manager-approval-test",
            approval_key_pair.public_key().as_ref(),
            vec![splendor_types::EndpointScope::ApprovalsManage],
            trust_now - time::Duration::seconds(1),
        )
        .with_expected_client_principal_id("approval-management-client");
        write_private_json(
            &approval_caller_trust,
            serde_json::to_value(&approval_trust).expect("approval trust JSON"),
        );
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
        write_private_json(
            &authority_receipt_config,
            serde_json::json!({
                "schema_version": "splendor.authority_obligation_receipt_config.v1",
                "issuer_principal_id": "00000000-0000-4000-8000-0000000004c0",
                "audience_prefix": "splendor.daemon.run",
                "key_id": "approval-receipt-local-key",
                "validation_secret_base64url": base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    [11_u8; 32]
                ),
                "revocation_ref": "local-approval-receipts"
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
                "SPLENDOR_AUTHORITY_OBLIGATION_RECEIPT_CONFIG_FILE",
                authority_receipt_config.display().to_string(),
            ),
            (
                "SPLENDOR_MANAGER_APPROVAL_CALLER_TRUST_FILE",
                approval_caller_trust.display().to_string(),
            ),
            (
                "SPLENDOR_MANAGER_RESIDENT_ROOT_CA_FILE",
                root_ca.display().to_string(),
            ),
            (
                "SPLENDOR_MANAGER_RESIDENT_ALLOWED_ORIGINS",
                "https://localhost:8091".to_string(),
            ),
        ] {
            std::env::set_var(name, value);
        }

        let overlapping_trust = splendor_daemon::caller_auth::CallerTokenTrustSnapshot::single_key(
            "urn:splendor:manager:central-manager",
            "central-manager",
            "manager-resident-test",
            key_pair.public_key().as_ref(),
            vec![splendor_types::EndpointScope::ApprovalsManage],
            trust_now - time::Duration::seconds(1),
        )
        .with_expected_client_principal_id("resident-dispatch-client");
        write_private_json(
            &approval_caller_trust,
            serde_json::to_value(&overlapping_trust).expect("overlapping approval trust JSON"),
        );
        assert!(super::configured_manager_state()
            .err()
            .expect("overlapping approval and dispatch keys denied")
            .to_string()
            .contains("resident dispatch"));
        let mut revoked_overlapping_trust = overlapping_trust;
        revoked_overlapping_trust.keys[0].status =
            splendor_daemon::caller_auth::CallerVerificationKeyStatus::Revoked;
        write_private_json(
            &approval_caller_trust,
            serde_json::to_value(revoked_overlapping_trust)
                .expect("revoked overlapping approval trust JSON"),
        );
        assert!(super::configured_manager_state()
            .err()
            .expect("revoked overlapping approval and dispatch keys denied")
            .to_string()
            .contains("resident dispatch"));
        write_private_json(
            &approval_caller_trust,
            serde_json::to_value(&approval_trust).expect("approval trust JSON"),
        );
        super::configured_manager_state().expect("explicit outbound dispatch configuration");

        for invalid_fleet_id in ["not-a-uuid", "00000000-0000-0000-0000-000000000000"] {
            std::env::set_var("SPLENDOR_FLEET_ID", invalid_fleet_id);
            assert!(super::configured_manager_state()
                .err()
                .expect("invalid fleet denied")
                .to_string()
                .contains("non-nil UUID"));
        }
        std::env::set_var("SPLENDOR_FLEET_ID", "00000000-0000-4000-8000-000000000104");

        std::env::set_var("SPLENDOR_MANAGER_RESIDENT_ALLOWED_ORIGINS", " , ");
        assert!(super::configured_manager_state()
            .err()
            .expect("empty origin list denied")
            .to_string()
            .contains("resident allowed origins"));
        std::env::set_var(
            "SPLENDOR_MANAGER_RESIDENT_ALLOWED_ORIGINS",
            "https://localhost:8091",
        );

        std::env::remove_var("SPLENDOR_MANAGER_CALLER_SIGNING_KEY_FILE");
        assert!(super::configured_manager_state()
            .err()
            .expect("missing signer denied")
            .to_string()
            .contains("SPLENDOR_MANAGER_CALLER_SIGNING_KEY_FILE"));
        std::env::set_var("SPLENDOR_MANAGER_CALLER_SIGNING_KEY_FILE", &signing_key);

        std::env::remove_var("SPLENDOR_MANAGER_APPROVAL_CALLER_TRUST_FILE");
        assert!(super::configured_manager_state()
            .err()
            .expect("missing approval trust denied")
            .to_string()
            .contains("SPLENDOR_MANAGER_APPROVAL_CALLER_TRUST_FILE"));
        std::env::set_var(
            "SPLENDOR_MANAGER_APPROVAL_CALLER_TRUST_FILE",
            &approval_caller_trust,
        );

        write_private_bytes(&approval_caller_trust, b"not-json");
        assert!(super::configured_manager_state()
            .err()
            .expect("malformed approval trust denied")
            .to_string()
            .contains("manager approval caller trust"));
        let mut stale_trust = approval_trust.clone();
        stale_trust.issued_at = trust_now - time::Duration::hours(2);
        stale_trust.expires_at = trust_now - time::Duration::seconds(1);
        write_private_json(
            &approval_caller_trust,
            serde_json::to_value(stale_trust).expect("stale trust JSON"),
        );
        assert!(super::configured_manager_state()
            .err()
            .expect("stale approval trust denied")
            .to_string()
            .contains("manager approval caller trust"));
        write_private_json(
            &approval_caller_trust,
            serde_json::to_value(approval_trust).expect("approval trust JSON"),
        );

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

    #[test]
    fn manager_work_order_keyring_rejects_malformed_ambiguous_and_weak_secrets() {
        let root = std::env::temp_dir().join(format!(
            "splendor-manager-keyring-validation-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).expect("fixture directory");
        let path = root.join("keyring.json");

        write_private_bytes(&path, b"not-json");
        assert!(super::load_work_order_keyring(&path).is_err());
        for value in [
            serde_json::json!({"schema_version": "wrong", "keys": [{"key_id": "key", "shared_secret_base64url": "AA"}]}),
            serde_json::json!({"schema_version": "splendor.work_order_keyring.v1", "keys": []}),
            serde_json::json!({"schema_version": "splendor.work_order_keyring.v1", "keys": [{"key_id": "", "shared_secret_base64url": "AA"}]}),
            serde_json::json!({"schema_version": "splendor.work_order_keyring.v1", "keys": [
                {"key_id": "duplicate", "shared_secret_base64url": "AA"},
                {"key_id": "duplicate", "shared_secret_base64url": "AA"}
            ]}),
            serde_json::json!({"schema_version": "splendor.work_order_keyring.v1", "keys": [{"key_id": "key", "shared_secret_base64url": "%%%"}]}),
            serde_json::json!({"schema_version": "splendor.work_order_keyring.v1", "keys": [{"key_id": "key", "shared_secret_base64url": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [1_u8; 8])}]}),
        ] {
            write_private_json(&path, value);
            assert!(super::load_work_order_keyring(&path).is_err());
        }

        write_private_json(
            &path,
            serde_json::json!({
                "schema_version": "splendor.work_order_keyring.v1",
                "keys": [{
                    "key_id": "manager-key",
                    "shared_secret_base64url": base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        [7_u8; 32]
                    )
                }]
            }),
        );
        super::load_work_order_keyring(&path).expect("valid manager keyring");
        assert!(super::read_regular_file(&path, 1, false).is_err());
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
