//! Runtime daemon process composition.

use axum_server::tls_rustls::RustlsConfig;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;
use splendor_daemon::caller_auth::CallerTokenVerifier;
use splendor_daemon::{router, DaemonConfig, DaemonState};
use splendor_kernel::LocalAuthorityObligationReceiptConfig;
use splendor_types::{InstanceId, PolicyBundleKeyring, PrincipalId, WorkOrderKeyring};
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::net::TcpListener;

const KEYRING_FILE_LIMIT: u64 = 1024 * 1024;

enum DaemonRuntime {
    LocalDev {
        state: DaemonState,
        bind_addr: SocketAddr,
    },
    Resident {
        state: DaemonState,
        bind_addr: SocketAddr,
        tls_cert_pem: Vec<u8>,
        tls_key_pem: Vec<u8>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedSecretKeyringFile {
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

fn bind_addr(default: &str) -> Result<SocketAddr, std::io::Error> {
    std::env::var("SPLENDOR_DAEMON_BIND_ADDR")
        .unwrap_or_else(|_| default.to_string())
        .parse()
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SPLENDOR_DAEMON_BIND_ADDR must be a socket address",
            )
        })
}

fn daemon_runtime() -> Result<DaemonRuntime, std::io::Error> {
    match required_env("SPLENDOR_DAEMON_MODE")?.as_str() {
        "local_dev" => {
            let bind_addr = bind_addr("127.0.0.1:8077")?;
            if !bind_addr.ip().is_loopback() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "local_dev mode requires a loopback bind address",
                ));
            }
            let config = match std::env::var("SPLENDOR_AUTHORITY_OBLIGATION_RECEIPT_CONFIG_FILE") {
                Ok(path) if !path.trim().is_empty() => DaemonConfig::local_dev()
                    .with_authority_obligation_receipt_config(load_authority_receipt_config(
                        Path::new(&path),
                    )?),
                _ => DaemonConfig::local_dev(),
            };
            Ok(DaemonRuntime::LocalDev {
                state: DaemonState::new(config),
                bind_addr,
            })
        }
        "resident" => resident_runtime(),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SPLENDOR_DAEMON_MODE must be exactly local_dev or resident",
        )),
    }
}

fn resident_runtime() -> Result<DaemonRuntime, std::io::Error> {
    let instance_id = InstanceId::parse(&required_env("SPLENDOR_INSTANCE_ID")?).map_err(|_| {
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

    let caller_trust_path = required_env("SPLENDOR_CALLER_TRUST_FILE")?;
    let work_order_keyring_path = required_env("SPLENDOR_WORK_ORDER_KEYRING_FILE")?;
    let policy_keyring_path = required_env("SPLENDOR_POLICY_KEYRING_FILE")?;
    let authority_receipt_config_path =
        required_env("SPLENDOR_AUTHORITY_OBLIGATION_RECEIPT_CONFIG_FILE")?;
    let tls_cert_path = PathBuf::from(required_env("SPLENDOR_TLS_CERT_FILE")?);
    let tls_key_path = PathBuf::from(required_env("SPLENDOR_TLS_KEY_FILE")?);
    let tls_key_pem = read_regular_file(&tls_key_path, KEYRING_FILE_LIMIT, true)?;
    let tls_cert_pem = read_regular_file(&tls_cert_path, KEYRING_FILE_LIMIT, false)?;

    let caller_token_verifier =
        CallerTokenVerifier::from_file(caller_trust_path, instance_id.clone()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SPLENDOR_CALLER_TRUST_FILE is invalid or unavailable",
            )
        })?;
    let work_order_keyring = load_work_order_keyring(Path::new(&work_order_keyring_path))?;
    let policy_bundle_keyring = load_policy_keyring(Path::new(&policy_keyring_path))?;
    let bind_addr = bind_addr("127.0.0.1:8077")?;

    Ok(DaemonRuntime::Resident {
        state: DaemonState::new(
            DaemonConfig::resident(
                instance_id,
                caller_token_verifier,
                work_order_keyring,
                policy_bundle_keyring,
            )
            .with_authority_obligation_receipt_config(load_authority_receipt_config(
                Path::new(&authority_receipt_config_path),
            )?),
        ),
        bind_addr,
        tls_cert_pem,
        tls_key_pem,
    })
}

fn load_work_order_keyring(path: &Path) -> Result<WorkOrderKeyring, std::io::Error> {
    let file = load_secret_keyring(path, "splendor.work_order_keyring.v1")?;
    let mut keyring = WorkOrderKeyring::new();
    for key in file.keys {
        let secret = decode_secret(&key)?;
        keyring
            .insert_shared_secret(key.key_id, &secret)
            .map_err(|_| invalid_keyring("work-order"))?;
    }
    Ok(keyring)
}

fn load_policy_keyring(path: &Path) -> Result<PolicyBundleKeyring, std::io::Error> {
    let file = load_secret_keyring(path, "splendor.policy_keyring.v1")?;
    let mut keyring = PolicyBundleKeyring::new();
    for key in file.keys {
        let secret = decode_secret(&key)?;
        keyring
            .insert_shared_secret(key.key_id, &secret)
            .map_err(|_| invalid_keyring("policy"))?;
    }
    Ok(keyring)
}

fn load_authority_receipt_config(
    path: &Path,
) -> Result<LocalAuthorityObligationReceiptConfig, std::io::Error> {
    let bytes = read_regular_file(path, KEYRING_FILE_LIMIT, true)?;
    let file: AuthorityReceiptConfigFile =
        serde_json::from_slice(&bytes).map_err(|_| invalid_keyring("authority receipt"))?;
    if file.schema_version != "splendor.authority_obligation_receipt_config.v1" {
        return Err(invalid_keyring("authority receipt"));
    }
    let issuer = PrincipalId::parse(&file.issuer_principal_id)
        .map_err(|_| invalid_keyring("authority receipt"))?;
    let secret = URL_SAFE_NO_PAD
        .decode(file.validation_secret_base64url.as_bytes())
        .map_err(|_| invalid_keyring("authority receipt"))?;
    if secret.len() < 32 {
        return Err(invalid_keyring("authority receipt"));
    }
    LocalAuthorityObligationReceiptConfig::trusted_local(
        issuer,
        file.audience_prefix,
        file.key_id,
        file.validation_secret_base64url,
        file.revocation_ref,
    )
    .map_err(|_| invalid_keyring("authority receipt"))
}

fn load_secret_keyring(
    path: &Path,
    expected_schema: &str,
) -> Result<SharedSecretKeyringFile, std::io::Error> {
    let bytes = read_regular_file(path, KEYRING_FILE_LIMIT, true)?;
    let file: SharedSecretKeyringFile =
        serde_json::from_slice(&bytes).map_err(|_| invalid_keyring("malformed"))?;
    if file.schema_version != expected_schema || file.keys.is_empty() {
        return Err(invalid_keyring("schema"));
    }
    let mut key_ids = std::collections::HashSet::new();
    if file
        .keys
        .iter()
        .any(|key| key.key_id.trim().is_empty() || !key_ids.insert(key.key_id.as_str()))
    {
        return Err(invalid_keyring("duplicate or blank key id"));
    }
    Ok(file)
}

fn decode_secret(key: &SharedSecretKey) -> Result<Vec<u8>, std::io::Error> {
    if key.key_id.trim().is_empty() {
        return Err(invalid_keyring("blank key id"));
    }
    let secret = URL_SAFE_NO_PAD
        .decode(key.shared_secret_base64url.as_bytes())
        .map_err(|_| invalid_keyring("secret encoding"))?;
    if secret.len() < 32 {
        return Err(invalid_keyring("short secret"));
    }
    Ok(secret)
}

fn invalid_keyring(kind: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("invalid {kind} keyring"),
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
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} exceeds the configured file limit", path.display()),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} exceeds the configured file limit", path.display()),
        ));
    }
    Ok(bytes)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match daemon_runtime()? {
        DaemonRuntime::LocalDev { state, bind_addr } => {
            eprintln!(
                "WARNING: Splendor runtime daemon is running in explicit local-only insecure dev mode on {bind_addr}"
            );
            let listener = TcpListener::bind(bind_addr).await?;
            axum::serve(listener, router(state)).await?;
        }
        DaemonRuntime::Resident {
            state,
            bind_addr,
            tls_cert_pem,
            tls_key_pem,
        } => {
            let tls = RustlsConfig::from_pem(tls_cert_pem, tls_key_pem).await?;
            eprintln!(
                "Splendor resident runtime daemon listening with TLS and verified caller authentication on {bind_addr}"
            );
            axum_server::bind_rustls(bind_addr, tls)
                .serve(router(state).into_make_service())
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use splendor_daemon::caller_auth::{CallerTokenSigner, CallerTokenTrustSnapshot};
    use splendor_types::EndpointScope;
    use time::OffsetDateTime;

    static STARTUP_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct StartupEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl StartupEnvGuard {
        fn acquire() -> Self {
            let lock = STARTUP_ENV_LOCK.lock().expect("startup env lock");
            for name in [
                "SPLENDOR_DAEMON_MODE",
                "SPLENDOR_DAEMON_BIND_ADDR",
                "SPLENDOR_INSTANCE_ID",
                "SPLENDOR_CALLER_TRUST_FILE",
                "SPLENDOR_WORK_ORDER_KEYRING_FILE",
                "SPLENDOR_POLICY_KEYRING_FILE",
                "SPLENDOR_AUTHORITY_OBLIGATION_RECEIPT_CONFIG_FILE",
                "SPLENDOR_TLS_CERT_FILE",
                "SPLENDOR_TLS_KEY_FILE",
            ] {
                std::env::remove_var(name);
            }
            Self { _lock: lock }
        }
    }

    impl Drop for StartupEnvGuard {
        fn drop(&mut self) {
            for name in [
                "SPLENDOR_DAEMON_MODE",
                "SPLENDOR_DAEMON_BIND_ADDR",
                "SPLENDOR_INSTANCE_ID",
                "SPLENDOR_CALLER_TRUST_FILE",
                "SPLENDOR_WORK_ORDER_KEYRING_FILE",
                "SPLENDOR_POLICY_KEYRING_FILE",
                "SPLENDOR_AUTHORITY_OBLIGATION_RECEIPT_CONFIG_FILE",
                "SPLENDOR_TLS_CERT_FILE",
                "SPLENDOR_TLS_KEY_FILE",
            ] {
                std::env::remove_var(name);
            }
        }
    }

    #[test]
    fn daemon_mode_is_explicit_and_local_dev_is_loopback_only() {
        let _env = StartupEnvGuard::acquire();
        assert!(super::daemon_runtime().is_err());
        std::env::set_var("SPLENDOR_DAEMON_MODE", "unknown");
        assert!(super::daemon_runtime().is_err());
        std::env::set_var("SPLENDOR_DAEMON_MODE", "local_dev");
        assert!(matches!(
            super::daemon_runtime().expect("local dev"),
            super::DaemonRuntime::LocalDev { .. }
        ));
        std::env::set_var("SPLENDOR_DAEMON_BIND_ADDR", "0.0.0.0:8077");
        assert!(super::daemon_runtime().is_err());
    }

    #[test]
    fn resident_startup_fails_closed_without_identity_and_trust_files() {
        let _env = StartupEnvGuard::acquire();
        std::env::set_var("SPLENDOR_DAEMON_MODE", "resident");
        assert!(super::daemon_runtime()
            .err()
            .expect("resident identity is required")
            .to_string()
            .contains("SPLENDOR_INSTANCE_ID"));
        std::env::set_var(
            "SPLENDOR_INSTANCE_ID",
            "00000000-0000-0000-0000-000000000000",
        );
        assert!(super::daemon_runtime()
            .err()
            .expect("nil resident identity is denied")
            .to_string()
            .contains("non-nil"));
        std::env::set_var(
            "SPLENDOR_INSTANCE_ID",
            "00000000-0000-4000-8000-000000000302",
        );
        assert!(super::daemon_runtime()
            .err()
            .expect("resident trust is required")
            .to_string()
            .contains("SPLENDOR_CALLER_TRUST_FILE"));
    }

    #[test]
    fn resident_startup_requires_each_explicit_trust_keyring_and_tls_file() {
        let _env = StartupEnvGuard::acquire();
        let root = std::env::temp_dir().join(format!(
            "splendor-resident-startup-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).expect("fixture directory");
        let instance_id = splendor_types::InstanceId::parse("00000000-0000-4000-8000-000000000302")
            .expect("instance");
        let signer = CallerTokenSigner::generate_for_test(
            "urn:splendor:manager:startup-test",
            "startup-manager",
            "startup-client",
            "startup-key",
        )
        .expect("signer");
        let trust = CallerTokenTrustSnapshot::single_key(
            signer.issuer(),
            signer.app_principal_id(),
            signer.kid(),
            &signer.public_key_bytes(),
            vec![EndpointScope::RunsCreate],
            OffsetDateTime::now_utc(),
        );
        let trust_path = root.join("caller-trust.json");
        let work_order_path = root.join("work-order-keyring.json");
        let policy_path = root.join("policy-keyring.json");
        let authority_receipt_path = root.join("authority-receipt-config.json");
        let cert_path = root.join("resident-cert.pem");
        let key_path = root.join("resident-key.pem");
        std::fs::write(&trust_path, serde_json::to_vec(&trust).expect("trust JSON"))
            .expect("trust file");
        write_private_fixture(
            &work_order_path,
            serde_json::json!({
                "schema_version": "splendor.work_order_keyring.v1",
                "keys": [{
                    "key_id": "resident-work-order",
                    "shared_secret_base64url": base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        [7_u8; 32]
                    )
                }]
            }),
        );
        write_private_fixture(
            &policy_path,
            serde_json::json!({
                "schema_version": "splendor.policy_keyring.v1",
                "keys": [{
                    "key_id": "resident-policy",
                    "shared_secret_base64url": base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        [9_u8; 32]
                    )
                }]
            }),
        );
        write_private_fixture(
            &authority_receipt_path,
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
        std::fs::write(&cert_path, b"acceptance certificate placeholder").expect("cert file");
        write_private_bytes(&key_path, b"acceptance key placeholder");

        let values = [
            ("SPLENDOR_CALLER_TRUST_FILE", trust_path.as_os_str()),
            (
                "SPLENDOR_WORK_ORDER_KEYRING_FILE",
                work_order_path.as_os_str(),
            ),
            ("SPLENDOR_POLICY_KEYRING_FILE", policy_path.as_os_str()),
            (
                "SPLENDOR_AUTHORITY_OBLIGATION_RECEIPT_CONFIG_FILE",
                authority_receipt_path.as_os_str(),
            ),
            ("SPLENDOR_TLS_CERT_FILE", cert_path.as_os_str()),
            ("SPLENDOR_TLS_KEY_FILE", key_path.as_os_str()),
        ];
        std::env::set_var("SPLENDOR_DAEMON_MODE", "resident");
        std::env::set_var("SPLENDOR_INSTANCE_ID", instance_id.to_string());
        for (name, value) in values {
            std::env::set_var(name, value);
        }
        assert!(matches!(
            super::daemon_runtime().expect("complete resident config"),
            super::DaemonRuntime::Resident { .. }
        ));

        for (missing, _) in values {
            std::env::remove_var(missing);
            let error = super::daemon_runtime()
                .err()
                .expect("missing resident input denied");
            assert!(error.to_string().contains(missing), "{missing}: {error}");
            let value = values
                .iter()
                .find_map(|(name, value)| (*name == missing).then_some(*value))
                .expect("fixture value");
            std::env::set_var(missing, value);
        }

        write_private_bytes(&trust_path, b"not-json");
        assert!(super::daemon_runtime()
            .err()
            .expect("invalid caller trust denied")
            .to_string()
            .contains("CALLER_TRUST_FILE"));
        std::fs::write(&trust_path, serde_json::to_vec(&trust).expect("trust JSON"))
            .expect("restore trust file");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&work_order_path, std::fs::Permissions::from_mode(0o644))
                .expect("permissive mode");
            assert!(super::daemon_runtime()
                .err()
                .expect("permissive private file denied")
                .to_string()
                .contains("group/world"));
        }

        std::fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn resident_keyrings_reject_malformed_ambiguous_and_weak_secrets() {
        let root = std::env::temp_dir().join(format!(
            "splendor-resident-keyring-validation-{}",
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
            write_private_fixture(&path, value);
            assert!(super::load_work_order_keyring(&path).is_err());
        }

        write_private_fixture(
            &path,
            serde_json::json!({
                "schema_version": "splendor.policy_keyring.v1",
                "keys": [{
                    "key_id": "policy-key",
                    "shared_secret_base64url": base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        [9_u8; 32]
                    )
                }]
            }),
        );
        super::load_policy_keyring(&path).expect("valid policy keyring");
        assert!(super::load_work_order_keyring(&path).is_err());

        write_private_bytes(&path, b"oversized");
        assert!(super::read_regular_file(&path, 1, false).is_err());
        std::fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn resident_startup_rejects_malformed_instance_identity() {
        let _env = StartupEnvGuard::acquire();
        std::env::set_var("SPLENDOR_DAEMON_MODE", "resident");
        std::env::set_var("SPLENDOR_INSTANCE_ID", "not-a-uuid");
        assert!(super::daemon_runtime()
            .err()
            .expect("malformed instance denied")
            .to_string()
            .contains("non-nil UUID"));
    }

    #[test]
    fn socket_address_parser_rejects_hostnames_and_malformed_values() {
        let _env = StartupEnvGuard::acquire();
        std::env::set_var("SPLENDOR_DAEMON_BIND_ADDR", "localhost:8077");
        assert!(super::bind_addr("127.0.0.1:8077").is_err());
        std::env::set_var("SPLENDOR_DAEMON_BIND_ADDR", "127.0.0.1:8077");
        let parsed = super::bind_addr("127.0.0.1:8077").expect("socket");
        assert_eq!(parsed.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn resident_config_reads_reject_non_regular_and_symlink_files() {
        let root = std::env::temp_dir().join(format!(
            "splendor-resident-file-hardening-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).expect("fixture directory");
        assert!(super::read_regular_file(&root, super::KEYRING_FILE_LIMIT, false).is_err());
        let target = root.join("target.json");
        write_private_bytes(&target, b"{}");
        #[cfg(unix)]
        {
            let link = root.join("link.json");
            std::os::unix::fs::symlink(&target, &link).expect("fixture symlink");
            assert!(super::read_regular_file(&link, super::KEYRING_FILE_LIMIT, false).is_err());
            assert!(super::read_regular_file(&link, super::KEYRING_FILE_LIMIT, true).is_err());
        }
        std::fs::remove_dir_all(root).expect("remove fixture directory");
    }

    fn write_private_fixture(path: &std::path::Path, value: serde_json::Value) {
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
