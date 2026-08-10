#![cfg(any(feature = "local-file-secret-provider", test))]

//! Explicit Unix local-file Secret Provider for tests and local development.
//!
//! The provider retains an owner-only trusted-root descriptor and resolves only
//! a finite startup-supplied coordinate-to-relative-file map with descriptor-
//! relative, no-follow opens. It has no environment, home-directory, current-
//! directory, enumeration, listener, fallback, or independent material API.

#[cfg(not(unix))]
compile_error!("splendor-adapter-secrets-local-file requires Unix");

use splendor_authority::{
    ProcessLocalSecretProvider as SecretProvider,
    ProcessLocalSecretProviderAuditEvidence as SecretProviderAuditEvidence,
    ProcessLocalSecretProviderControlRequest as SecretProviderControlRequest,
    ProcessLocalSecretProviderError as SecretProviderError,
    ProcessLocalSecretProviderErrorCode as SecretProviderErrorCode,
    ProcessLocalSecretProviderFetchRequest as SecretProviderFetchRequest,
    ProcessLocalSecretProviderFetchResult as SecretProviderFetchResult,
    ProcessLocalSecretProviderHealthEvidence as SecretProviderHealthEvidence,
    ProcessLocalSecretProviderOperation as SecretProviderOperation,
    ProcessLocalSecretProviderOutcome as SecretProviderOutcome,
};
use splendor_types::{
    EffectCertainty, SecretProviderId, SecretProviderVersionRef, SecretRefId, TenantId,
};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

const MAX_MATERIAL_BYTES: usize = 65_536;
const MAX_CONFIGURED_ENTRIES: usize = 4_096;
const MAX_ROOT_PATH_BYTES: usize = 4_096;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;
const MAX_ROOT_COMPONENTS: usize = 128;
const MAX_RELATIVE_PATH_COMPONENTS: usize = 64;
const MAX_PATH_COMPONENT_BYTES: usize = 255;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const DIRECTORY_OPEN_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
const FILE_OPEN_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;

/// Explicit runtime modes accepted or rejected by the development provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalFileSecretProviderRuntimeMode {
    Test,
    LocalDevelopment,
    Resident,
    Remote,
    Fleet,
    Production,
    Unknown,
}

/// Fixed, non-reflecting startup failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalFileSecretProviderConfigError {
    UnsupportedRuntimeMode,
    InvalidTrustedRoot,
    InvalidCoordinates,
    InvalidRelativePath,
    DuplicateCoordinates,
    AmbiguousPath,
    CapacityExceeded,
    PathUnavailable,
    FilesystemPolicyDenied,
    InvalidMaterial,
}

impl LocalFileSecretProviderConfigError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedRuntimeMode => "local_file_secret_provider_runtime_mode_unsupported",
            Self::InvalidTrustedRoot => "local_file_secret_provider_trusted_root_invalid",
            Self::InvalidCoordinates => "local_file_secret_provider_coordinates_invalid",
            Self::InvalidRelativePath => "local_file_secret_provider_relative_path_invalid",
            Self::DuplicateCoordinates => "local_file_secret_provider_coordinates_duplicate",
            Self::AmbiguousPath => "local_file_secret_provider_path_ambiguous",
            Self::CapacityExceeded => "local_file_secret_provider_capacity_exceeded",
            Self::PathUnavailable => "local_file_secret_provider_path_unavailable",
            Self::FilesystemPolicyDenied => "local_file_secret_provider_filesystem_policy_denied",
            Self::InvalidMaterial => "local_file_secret_provider_material_invalid",
        }
    }
}

impl fmt::Display for LocalFileSecretProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for LocalFileSecretProviderConfigError {}

/// One exact startup coordinate-to-relative-file mapping.
///
/// The path is never rendered through `Debug` and is validated only when the
/// complete provider is constructed against its explicit trusted root.
pub struct LocalFileSecretProviderEntry {
    tenant_id: TenantId,
    secret_ref_id: SecretRefId,
    secret_ref_revision: u64,
    provider_version_ref: SecretProviderVersionRef,
    relative_path: PathBuf,
}

impl LocalFileSecretProviderEntry {
    pub fn new(
        tenant_id: TenantId,
        secret_ref_id: SecretRefId,
        secret_ref_revision: u64,
        provider_version_ref: SecretProviderVersionRef,
        relative_path: PathBuf,
    ) -> Self {
        Self {
            tenant_id,
            secret_ref_id,
            secret_ref_revision,
            provider_version_ref,
            relative_path,
        }
    }
}

impl fmt::Debug for LocalFileSecretProviderEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalFileSecretProviderEntry(<redacted>)")
    }
}

/// Development-only local-file provider implementation.
pub struct LocalFileSecretProvider {
    provider_id: SecretProviderId,
    trusted_root: File,
    expected_uid: u32,
    integrity_key: Zeroizing<[u8; 32]>,
    entries: HashMap<EntryKey, RegisteredFile>,
    state: Mutex<ProviderState>,
    fetch_calls: AtomicU64,
    control_calls: AtomicU64,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct EntryKey {
    tenant_id: TenantId,
    secret_ref_id: SecretRefId,
    secret_ref_revision: u64,
    provider_version_ref: SecretProviderVersionRef,
}

struct RegisteredFile {
    relative_path: PathBuf,
    fingerprint: FileFingerprint,
    integrity_tag: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileFingerprint {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    uid: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

struct ProviderState {
    available: bool,
}

#[derive(Clone, Copy)]
enum OpenFailure {
    Unavailable,
    PolicyDenied,
    InvalidMaterial,
}

struct TransientMaterial {
    bytes: Option<Vec<u8>>,
}

impl TransientMaterial {
    fn with_len(length: usize) -> Self {
        Self {
            bytes: Some(vec![0; length]),
        }
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        self.bytes.as_mut().expect("transient material is present")
    }

    fn bytes(&self) -> &[u8] {
        self.bytes
            .as_deref()
            .expect("transient material is present")
    }

    fn into_bytes(mut self) -> Vec<u8> {
        self.bytes.take().expect("transient material is present")
    }
}

impl Drop for TransientMaterial {
    fn drop(&mut self) {
        if let Some(bytes) = self.bytes.as_mut() {
            bytes.zeroize();
        }
    }
}

impl LocalFileSecretProvider {
    /// Constructs only in explicit test or local-development mode from one
    /// absolute trusted root and one finite exact mapping.
    pub fn try_new(
        provider_id: SecretProviderId,
        mode: LocalFileSecretProviderRuntimeMode,
        trusted_root: PathBuf,
        configured_entries: Vec<LocalFileSecretProviderEntry>,
    ) -> Result<Self, LocalFileSecretProviderConfigError> {
        if !matches!(
            mode,
            LocalFileSecretProviderRuntimeMode::Test
                | LocalFileSecretProviderRuntimeMode::LocalDevelopment
        ) {
            return Err(LocalFileSecretProviderConfigError::UnsupportedRuntimeMode);
        }
        if configured_entries.is_empty() {
            return Err(LocalFileSecretProviderConfigError::InvalidCoordinates);
        }
        if configured_entries.len() > MAX_CONFIGURED_ENTRIES {
            return Err(LocalFileSecretProviderConfigError::CapacityExceeded);
        }
        validate_absolute_root(&trusted_root)?;

        let mut unique_keys = HashSet::with_capacity(configured_entries.len());
        let mut unique_paths = HashSet::with_capacity(configured_entries.len());
        let mut validated_entries = Vec::with_capacity(configured_entries.len());
        for entry in configured_entries {
            validate_coordinates(&entry.tenant_id, entry.secret_ref_revision)?;
            validate_relative_path(&entry.relative_path)?;
            let key = EntryKey {
                tenant_id: entry.tenant_id,
                secret_ref_id: entry.secret_ref_id,
                secret_ref_revision: entry.secret_ref_revision,
                provider_version_ref: entry.provider_version_ref,
            };
            if !unique_keys.insert(key.clone()) {
                return Err(LocalFileSecretProviderConfigError::DuplicateCoordinates);
            }
            if !unique_paths.insert(entry.relative_path.clone()) {
                return Err(LocalFileSecretProviderConfigError::AmbiguousPath);
            }
            validated_entries.push((key, entry.relative_path));
        }

        let expected_uid = effective_uid();
        let trusted_root = open_trusted_root(&trusted_root, expected_uid)?;
        let integrity_key = generate_integrity_key()?;
        let mut entries = HashMap::with_capacity(validated_entries.len());
        let mut unique_backing_sources = HashSet::with_capacity(validated_entries.len());
        for (key, relative_path) in validated_entries {
            let (mut file, fingerprint) =
                open_relative_secret_file(&trusted_root, &relative_path, expected_uid)
                    .map_err(config_error_from_open_failure)?;
            let material = read_open_material(&mut file, &fingerprint, expected_uid)
                .map_err(config_error_from_open_failure)?;
            let integrity_tag = keyed_integrity_tag(&integrity_key, material.bytes());
            register_unique_backing_source(&mut unique_backing_sources, &fingerprint)?;
            entries.insert(
                key,
                RegisteredFile {
                    relative_path,
                    fingerprint,
                    integrity_tag,
                },
            );
        }

        Ok(Self {
            provider_id,
            trusted_root,
            expected_uid,
            integrity_key,
            entries,
            state: Mutex::new(ProviderState { available: true }),
            fetch_calls: AtomicU64::new(0),
            control_calls: AtomicU64::new(0),
        })
    }

    /// Enables deterministic local outage injection without changing mappings.
    pub fn set_available(&self, available: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.available = available;
        }
    }

    /// Number of real provider-port fetch calls.
    pub fn fetch_call_count(&self) -> u64 {
        self.fetch_calls.load(Ordering::SeqCst)
    }

    /// Number of real provider-port control calls.
    pub fn control_call_count(&self) -> u64 {
        self.control_calls.load(Ordering::SeqCst)
    }

    fn fetch_scoped<'session>(
        &self,
        request: &'session SecretProviderFetchRequest,
    ) -> Result<SecretProviderFetchResult<'session>, SecretProviderError> {
        self.fetch_calls.fetch_add(1, Ordering::SeqCst);
        let registered = self.registered_file(fetch_key(request), request.secret_provider_id())?;
        let audit = SecretProviderAuditEvidence::for_fetch_request(
            request,
            SecretProviderOutcome::Succeeded,
            EffectCertainty::Known,
            request.requested_at().clone(),
        )?;
        let material = self.read_registered_file(registered)?;
        SecretProviderFetchResult::try_new(request, material, audit)
    }

    fn registered_file(
        &self,
        key: EntryKey,
        requested_provider: &SecretProviderId,
    ) -> Result<&RegisteredFile, SecretProviderError> {
        if requested_provider != &self.provider_id {
            return Err(provider_error(SecretProviderErrorCode::VersionNotAvailable));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| provider_error(SecretProviderErrorCode::InternalFailure))?;
        if !state.available {
            return Err(provider_error(SecretProviderErrorCode::Unavailable));
        }
        drop(state);
        self.entries
            .get(&key)
            .ok_or_else(|| provider_error(SecretProviderErrorCode::VersionNotAvailable))
    }

    fn read_registered_file(
        &self,
        registered: &RegisteredFile,
    ) -> Result<Vec<u8>, SecretProviderError> {
        let (mut file, before) = open_relative_secret_file(
            &self.trusted_root,
            &registered.relative_path,
            self.expected_uid,
        )
        .map_err(provider_error_from_open_failure)?;
        if before != registered.fingerprint {
            return Err(provider_error(SecretProviderErrorCode::IntegrityFailure));
        }

        let material = read_open_material(&mut file, &before, self.expected_uid)
            .map_err(provider_error_from_open_failure)?;
        let integrity_tag = keyed_integrity_tag(&self.integrity_key, material.bytes());
        if !integrity_tags_match(&integrity_tag, &registered.integrity_tag) {
            return Err(provider_error(SecretProviderErrorCode::IntegrityFailure));
        }
        Ok(material.into_bytes())
    }

    fn audit_scoped(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.control_calls.fetch_add(1, Ordering::SeqCst);
        let registered =
            self.registered_file(control_key(request), request.secret_provider_id())?;
        self.validate_registered_file(registered)?;
        SecretProviderAuditEvidence::for_control_request(
            request,
            SecretProviderOperation::Audit,
            SecretProviderOutcome::Succeeded,
            EffectCertainty::Known,
            request.requested_at().clone(),
        )
    }

    fn unsupported_control(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.control_calls.fetch_add(1, Ordering::SeqCst);
        if request.secret_provider_id() != &self.provider_id {
            return Err(provider_error(SecretProviderErrorCode::VersionNotAvailable));
        }
        Err(provider_error(
            SecretProviderErrorCode::UnsupportedOperation,
        ))
    }

    fn health_scoped(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderHealthEvidence, SecretProviderError> {
        self.control_calls.fetch_add(1, Ordering::SeqCst);
        if request.secret_provider_id() != &self.provider_id {
            return Err(provider_error(SecretProviderErrorCode::VersionNotAvailable));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| provider_error(SecretProviderErrorCode::InternalFailure))?;
        let configured_available = state.available;
        drop(state);

        if !configured_available {
            return Ok(SecretProviderHealthEvidence::new(
                self.provider_id.clone(),
                false,
                request.requested_at().clone(),
            ));
        }

        let key = control_key(request);
        let registered = self
            .entries
            .get(&key)
            .ok_or_else(|| provider_error(SecretProviderErrorCode::VersionNotAvailable))?;
        let available = self.validate_registered_file(registered).is_ok();
        Ok(SecretProviderHealthEvidence::new(
            self.provider_id.clone(),
            available,
            request.requested_at().clone(),
        ))
    }

    fn validate_registered_file(
        &self,
        registered: &RegisteredFile,
    ) -> Result<(), SecretProviderError> {
        let (mut file, current) = open_relative_secret_file(
            &self.trusted_root,
            &registered.relative_path,
            self.expected_uid,
        )
        .map_err(provider_error_from_open_failure)?;
        if current != registered.fingerprint {
            return Err(provider_error(SecretProviderErrorCode::IntegrityFailure));
        }
        let material = read_open_material(&mut file, &current, self.expected_uid)
            .map_err(provider_error_from_open_failure)?;
        let integrity_tag = keyed_integrity_tag(&self.integrity_key, material.bytes());
        if !integrity_tags_match(&integrity_tag, &registered.integrity_tag) {
            return Err(provider_error(SecretProviderErrorCode::IntegrityFailure));
        }
        Ok(())
    }
}

impl fmt::Debug for LocalFileSecretProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalFileSecretProvider(<redacted>)")
    }
}

impl SecretProvider for LocalFileSecretProvider {
    fn provider_id(&self) -> &SecretProviderId {
        &self.provider_id
    }

    fn fetch<'session>(
        &self,
        request: &'session SecretProviderFetchRequest,
    ) -> Result<SecretProviderFetchResult<'session>, SecretProviderError> {
        self.fetch_scoped(request)
    }

    fn renew(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.unsupported_control(request)
    }

    fn revoke(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.unsupported_control(request)
    }

    fn audit(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.audit_scoped(request)
    }

    fn health(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderHealthEvidence, SecretProviderError> {
        self.health_scoped(request)
    }
}

fn validate_absolute_root(root: &Path) -> Result<(), LocalFileSecretProviderConfigError> {
    if !root.is_absolute() || root.as_os_str().as_bytes().len() > MAX_ROOT_PATH_BYTES {
        return Err(LocalFileSecretProviderConfigError::InvalidTrustedRoot);
    }
    let mut saw_root = false;
    let mut canonical = PathBuf::from("/");
    let mut components = 0usize;
    for component in root.components() {
        match component {
            Component::RootDir if !saw_root => saw_root = true,
            Component::Normal(name) if saw_root => {
                validate_component_name(name)
                    .map_err(|_| LocalFileSecretProviderConfigError::InvalidTrustedRoot)?;
                canonical.push(name);
                components += 1;
            }
            _ => return Err(LocalFileSecretProviderConfigError::InvalidTrustedRoot),
        }
    }
    if saw_root
        && components <= MAX_ROOT_COMPONENTS
        && canonical.as_os_str().as_bytes() == root.as_os_str().as_bytes()
    {
        Ok(())
    } else {
        Err(LocalFileSecretProviderConfigError::InvalidTrustedRoot)
    }
}

fn validate_relative_path(path: &Path) -> Result<(), LocalFileSecretProviderConfigError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.as_os_str().as_bytes().len() > MAX_RELATIVE_PATH_BYTES
    {
        return Err(LocalFileSecretProviderConfigError::InvalidRelativePath);
    }
    let mut components = 0usize;
    let mut canonical = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                validate_component_name(name)
                    .map_err(|_| LocalFileSecretProviderConfigError::InvalidRelativePath)?;
                canonical.push(name);
            }
            _ => return Err(LocalFileSecretProviderConfigError::InvalidRelativePath),
        }
        components += 1;
    }
    if components == 0
        || components > MAX_RELATIVE_PATH_COMPONENTS
        || canonical.as_os_str().as_bytes() != path.as_os_str().as_bytes()
    {
        Err(LocalFileSecretProviderConfigError::InvalidRelativePath)
    } else {
        Ok(())
    }
}

fn validate_component_name(name: &OsStr) -> Result<(), ()> {
    if name.as_bytes().len() > MAX_PATH_COMPONENT_BYTES {
        return Err(());
    }
    CString::new(name.as_bytes()).map(|_| ()).map_err(|_| ())
}

fn validate_coordinates(
    tenant_id: &TenantId,
    revision: u64,
) -> Result<(), LocalFileSecretProviderConfigError> {
    if tenant_id.is_nil() || !(1..=MAX_SAFE_INTEGER).contains(&revision) {
        Err(LocalFileSecretProviderConfigError::InvalidCoordinates)
    } else {
        Ok(())
    }
}

fn register_unique_backing_source(
    sources: &mut HashSet<(u64, u64)>,
    fingerprint: &FileFingerprint,
) -> Result<(), LocalFileSecretProviderConfigError> {
    if sources.insert((fingerprint.device, fingerprint.inode)) {
        Ok(())
    } else {
        Err(LocalFileSecretProviderConfigError::AmbiguousPath)
    }
}

fn open_trusted_root(
    root: &Path,
    expected_uid: u32,
) -> Result<File, LocalFileSecretProviderConfigError> {
    let mut current = open_at(libc::AT_FDCWD, OsStr::new("/"), DIRECTORY_OPEN_FLAGS)
        .map_err(config_open_error)?;
    validate_path_selection_directory(&current, expected_uid)
        .map_err(|_| LocalFileSecretProviderConfigError::FilesystemPolicyDenied)?;
    let mut components = root.components().skip(1).peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(LocalFileSecretProviderConfigError::InvalidTrustedRoot);
        };
        current =
            open_at(current.as_raw_fd(), name, DIRECTORY_OPEN_FLAGS).map_err(config_open_error)?;
        if components.peek().is_some() {
            validate_path_selection_directory(&current, expected_uid)
                .map_err(|_| LocalFileSecretProviderConfigError::FilesystemPolicyDenied)?;
        }
    }
    validate_directory(&current, expected_uid)
        .map_err(|_| LocalFileSecretProviderConfigError::FilesystemPolicyDenied)?;
    Ok(current)
}

fn open_relative_secret_file(
    trusted_root: &File,
    relative_path: &Path,
    expected_uid: u32,
) -> Result<(File, FileFingerprint), OpenFailure> {
    if effective_uid() != expected_uid {
        return Err(OpenFailure::PolicyDenied);
    }
    validate_directory(trusted_root, expected_uid)?;
    let mut current = trusted_root
        .try_clone()
        .map_err(|_| OpenFailure::Unavailable)?;
    let mut components = relative_path.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(OpenFailure::PolicyDenied);
        };
        if components.peek().is_some() {
            current = open_at(current.as_raw_fd(), name, DIRECTORY_OPEN_FLAGS)
                .map_err(classify_open_error)?;
            validate_directory(&current, expected_uid)?;
        } else {
            let file =
                open_at(current.as_raw_fd(), name, FILE_OPEN_FLAGS).map_err(classify_open_error)?;
            let fingerprint = fingerprint_for_open_file(&file, expected_uid)?;
            return Ok((file, fingerprint));
        }
    }
    Err(OpenFailure::PolicyDenied)
}

fn open_at(directory_fd: RawFd, name: &OsStr, flags: libc::c_int) -> io::Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path component"))?;
    // SAFETY: `name` is NUL-terminated and valid for the duration of the call;
    // successful ownership of the returned descriptor transfers to `File`.
    let descriptor = unsafe { libc::openat(directory_fd, name.as_ptr(), flags) };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `openat` returned a fresh owned descriptor on success.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn validate_directory(directory: &File, expected_uid: u32) -> Result<(), OpenFailure> {
    let metadata = directory.metadata().map_err(|_| OpenFailure::Unavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o500 != 0o500
        || metadata.mode() & 0o7000 != 0
    {
        return Err(OpenFailure::PolicyDenied);
    }
    validate_no_extended_acl(directory)
}

fn validate_path_selection_directory(
    directory: &File,
    expected_uid: u32,
) -> Result<(), OpenFailure> {
    let metadata = directory.metadata().map_err(|_| OpenFailure::Unavailable)?;
    let mode = metadata.mode();
    let trusted_owner = metadata.uid() == 0 || metadata.uid() == expected_uid;
    let group_or_other_writable = mode & 0o022 != 0;
    let sticky = mode & 0o1000 != 0;
    if !metadata.file_type().is_dir()
        || !trusted_owner
        || mode & 0o6000 != 0
        || group_or_other_writable && !sticky
    {
        return Err(OpenFailure::PolicyDenied);
    }
    validate_no_extended_acl(directory)
}

fn fingerprint_for_open_file(
    file: &File,
    expected_uid: u32,
) -> Result<FileFingerprint, OpenFailure> {
    let metadata = file.metadata().map_err(|_| OpenFailure::Unavailable)?;
    validate_secret_file_metadata(&metadata, expected_uid)?;
    validate_no_extended_acl(file)?;
    Ok(FileFingerprint {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        links: metadata.nlink(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn validate_secret_file_metadata(
    metadata: &Metadata,
    expected_uid: u32,
) -> Result<(), OpenFailure> {
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o400 != 0o400
        || metadata.mode() & 0o111 != 0
        || metadata.mode() & 0o7000 != 0
        || metadata.nlink() != 1
    {
        return Err(OpenFailure::PolicyDenied);
    }
    if metadata.size() == 0 || metadata.size() > MAX_MATERIAL_BYTES as u64 {
        return Err(OpenFailure::InvalidMaterial);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_no_extended_acl(file: &File) -> Result<(), OpenFailure> {
    use std::ffi::c_void;
    use std::ptr;

    type Acl = *mut c_void;
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> Acl;
        fn acl_get_entry(acl: Acl, entry_id: libc::c_int, entry: *mut Acl) -> libc::c_int;
        fn acl_free(object: *mut c_void) -> libc::c_int;
    }

    // SAFETY: the descriptor remains live; returned ACL ownership is released
    // exactly once with `acl_free` below.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        return match io::Error::last_os_error().raw_os_error() {
            Some(code) if code == libc::ENOENT => Ok(()),
            _ => Err(OpenFailure::Unavailable),
        };
    }
    let mut entry: Acl = ptr::null_mut();
    // SAFETY: `acl` is live and `entry` is a valid out pointer.
    let entry_result = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
    let entry_errno = io::Error::last_os_error().raw_os_error();
    // SAFETY: `acl` was returned by `acl_get_fd_np` and has not been freed.
    let free_result = unsafe { acl_free(acl) };
    if entry_result == 0 {
        return Err(OpenFailure::PolicyDenied);
    }
    if entry_result != -1 || entry_errno != Some(libc::EINVAL) || free_result != 0 {
        return Err(OpenFailure::Unavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_no_extended_acl(file: &File) -> Result<(), OpenFailure> {
    const POSIX_ACCESS_ACL: &[u8] = b"system.posix_acl_access\0";
    // SAFETY: the descriptor remains live and the attribute name is
    // NUL-terminated; a null buffer with size zero requests only its size.
    let length = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            POSIX_ACCESS_ACL.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if length >= 0 {
        return Err(OpenFailure::PolicyDenied);
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(code) if code == libc::ENODATA => Ok(()),
        _ => Err(OpenFailure::Unavailable),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn validate_no_extended_acl(_file: &File) -> Result<(), OpenFailure> {
    Err(OpenFailure::Unavailable)
}

fn read_open_material(
    file: &mut File,
    fingerprint: &FileFingerprint,
    expected_uid: u32,
) -> Result<TransientMaterial, OpenFailure> {
    let expected_length =
        usize::try_from(fingerprint.size).map_err(|_| OpenFailure::InvalidMaterial)?;
    let mut material = TransientMaterial::with_len(expected_length);
    file.read_exact(material.bytes_mut())
        .map_err(|_| OpenFailure::Unavailable)?;
    let mut extra = [0u8; 1];
    let extra_length = match file.read(&mut extra) {
        Ok(length) => length,
        Err(_) => {
            extra.zeroize();
            return Err(OpenFailure::Unavailable);
        }
    };
    extra.zeroize();
    if extra_length != 0 {
        return Err(OpenFailure::InvalidMaterial);
    }
    let after = fingerprint_for_open_file(file, expected_uid)?;
    if &after != fingerprint {
        return Err(OpenFailure::PolicyDenied);
    }
    Ok(material)
}

fn generate_integrity_key() -> Result<Zeroizing<[u8; 32]>, LocalFileSecretProviderConfigError> {
    let mut key = Zeroizing::new([0u8; 32]);
    // SAFETY: `key` points to 32 writable bytes for the duration of the call.
    let result = unsafe { libc::getentropy(key.as_mut_ptr().cast(), key.len()) };
    if result == 0 {
        Ok(key)
    } else {
        Err(LocalFileSecretProviderConfigError::FilesystemPolicyDenied)
    }
}

fn keyed_integrity_tag(key: &[u8; 32], bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(*blake3::keyed_hash(key, bytes).as_bytes())
}

fn integrity_tags_match(left: &[u8; 32], right: &[u8; 32]) -> bool {
    // `blake3::Hash` equality uses the crate's constant-time 32-byte compare.
    blake3::Hash::from_bytes(*left) == *right
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and returns the calling process UID.
    unsafe { libc::geteuid() }
}

fn classify_open_error(error: io::Error) -> OpenFailure {
    if matches!(
        error.raw_os_error(),
        Some(code) if code == libc::ELOOP || code == libc::ENOTDIR
    ) {
        OpenFailure::PolicyDenied
    } else {
        OpenFailure::Unavailable
    }
}

fn config_open_error(error: io::Error) -> LocalFileSecretProviderConfigError {
    match classify_open_error(error) {
        OpenFailure::PolicyDenied => LocalFileSecretProviderConfigError::FilesystemPolicyDenied,
        OpenFailure::Unavailable | OpenFailure::InvalidMaterial => {
            LocalFileSecretProviderConfigError::PathUnavailable
        }
    }
}

fn config_error_from_open_failure(failure: OpenFailure) -> LocalFileSecretProviderConfigError {
    match failure {
        OpenFailure::Unavailable => LocalFileSecretProviderConfigError::PathUnavailable,
        OpenFailure::PolicyDenied => LocalFileSecretProviderConfigError::FilesystemPolicyDenied,
        OpenFailure::InvalidMaterial => LocalFileSecretProviderConfigError::InvalidMaterial,
    }
}

fn provider_error_from_open_failure(failure: OpenFailure) -> SecretProviderError {
    match failure {
        OpenFailure::Unavailable => provider_error(SecretProviderErrorCode::Unavailable),
        OpenFailure::PolicyDenied | OpenFailure::InvalidMaterial => {
            provider_error(SecretProviderErrorCode::IntegrityFailure)
        }
    }
}

fn provider_error(code: SecretProviderErrorCode) -> SecretProviderError {
    SecretProviderError::new(code)
}

fn fetch_key(request: &SecretProviderFetchRequest) -> EntryKey {
    EntryKey {
        tenant_id: request.tenant_id().clone(),
        secret_ref_id: request.secret_ref_id().clone(),
        secret_ref_revision: request.secret_ref_revision(),
        provider_version_ref: request.provider_version_ref().clone(),
    }
}

fn control_key(request: &SecretProviderControlRequest) -> EntryKey {
    EntryKey {
        tenant_id: request.tenant_id().clone(),
        secret_ref_id: request.secret_ref_id().clone(),
        secret_ref_revision: request.secret_ref_revision(),
        provider_version_ref: request.provider_version_ref().clone(),
    }
}

#[cfg(test)]
#[path = "../tests/unit/local_file_provider_tests.rs"]
mod tests;
