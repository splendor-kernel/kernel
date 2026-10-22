//! Acceptance-only Ed25519 key helper for the containerized resident harness.
//!
//! This example is copied only into the acceptance-runner image. It never logs
//! private key or signing-input bytes.

use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair as _};
use std::io::{Read as _, Write as _};
use std::path::Path;

const PRIVATE_KEY_LIMIT: usize = 256;
const SIGNING_INPUT_LIMIT: usize = 262_144;
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [command, private_path, public_path] if command == "generate" => {
            generate(Path::new(private_path), Path::new(public_path))
        }
        [command, private_path] if command == "sign" => sign(Path::new(private_path)),
        [command, public_path] if command == "verify" => verify(Path::new(public_path)),
        _ => Err("usage: resident_auth_key_tool generate <private-pkcs8> <public-raw> | sign <private-pkcs8> | verify <public-raw>".into()),
    }
}

fn generate(private_path: &Path, public_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "Ed25519 key generation failed")?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| "generated Ed25519 key was invalid")?;
    write_no_follow(private_path, pkcs8.as_ref(), 0o600)?;
    write_no_follow(public_path, key_pair.public_key().as_ref(), 0o644)?;
    Ok(())
}

fn sign(private_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let pkcs8 = read_no_follow(private_path, PRIVATE_KEY_LIMIT, true)?;
    let key_pair =
        Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| "Ed25519 signing key was invalid")?;
    let input = read_stdin_bounded(SIGNING_INPUT_LIMIT)?;
    std::io::stdout().write_all(key_pair.sign(&input).as_ref())?;
    Ok(())
}

fn verify(public_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let public_key = read_no_follow(public_path, PUBLIC_KEY_BYTES, false)?;
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err("Ed25519 public key must be exactly 32 bytes".into());
    }
    let input = read_stdin_bounded(SIGNING_INPUT_LIMIT + SIGNATURE_BYTES)?;
    if input.len() < SIGNATURE_BYTES {
        return Err("Ed25519 verification input is truncated".into());
    }
    let (signature_bytes, message) = input.split_at(SIGNATURE_BYTES);
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(message, signature_bytes)
        .map_err(|_| "Ed25519 signature verification failed")?;
    Ok(())
}

fn read_stdin_bounded(limit: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(limit as u64 + 1)
        .read_to_end(&mut input)?;
    if input.len() > limit {
        return Err("signing input exceeds the fixed acceptance limit".into());
    }
    Ok(input)
}

fn read_no_follow(
    path: &Path,
    limit: usize,
    owner_only: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    validate_parent(path)?;
    let before = std::fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.file_type().is_file() {
        return Err("key file type is invalid".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > limit as u64 {
        return Err("key file metadata is invalid".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.dev() != before.dev()
            || metadata.ino() != before.ino()
            || (owner_only && metadata.permissions().mode() & 0o077 != 0)
            || (!owner_only && metadata.permissions().mode() & 0o022 != 0)
        {
            return Err("key file ownership or mode is invalid".into());
        }
    }
    let mut data = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1).read_to_end(&mut data)?;
    if data.len() != metadata.len() as usize || data.len() > limit {
        return Err("key file size changed during read".into());
    }
    Ok(data)
}

fn write_no_follow(path: &Path, bytes: &[u8], mode: u32) -> Result<(), std::io::Error> {
    validate_parent(path)?;
    let before = match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(std::io::Error::other("key output type is invalid"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                if metadata.nlink() != 1 || metadata.uid() != unsafe { libc::geteuid() } {
                    return Err(std::io::Error::other(
                        "key output ownership or link count is invalid",
                    ));
                }
            }
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        options.mode(mode);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let opened = file.metadata()?;
        if opened.nlink() != 1
            || opened.uid() != unsafe { libc::geteuid() }
            || before.as_ref().is_some_and(|metadata| {
                metadata.dev() != opened.dev() || metadata.ino() != opened.ino()
            })
        {
            return Err(std::io::Error::other("key output changed during open"));
        }
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn validate_parent(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("key file parent is missing"))?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(std::io::Error::other(
            "key file parent ownership or mode is invalid",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_parent(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}
