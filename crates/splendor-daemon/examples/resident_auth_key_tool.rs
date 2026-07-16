//! Acceptance-only Ed25519 key helper for the containerized resident harness.
//!
//! This example is copied only into the acceptance-runner image. It never logs
//! private key or signing-input bytes.

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use std::io::{Read as _, Write as _};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [command, private_path, public_path] if command == "generate" => {
            generate(Path::new(private_path), Path::new(public_path))
        }
        [command, private_path] if command == "sign" => sign(Path::new(private_path)),
        _ => Err("usage: resident_auth_key_tool generate <private-pkcs8> <public-raw> | sign <private-pkcs8>".into()),
    }
}

fn generate(private_path: &Path, public_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "Ed25519 key generation failed")?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| "generated Ed25519 key was invalid")?;
    std::fs::write(private_path, pkcs8.as_ref())?;
    std::fs::write(public_path, key_pair.public_key().as_ref())?;
    set_mode(private_path, 0o600)?;
    set_mode(public_path, 0o644)?;
    Ok(())
}

fn sign(private_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let pkcs8 = std::fs::read(private_path)?;
    let key_pair =
        Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| "Ed25519 signing key was invalid")?;
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    std::io::stdout().write_all(key_pair.sign(&input).as_ref())?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), std::io::Error> {
    Ok(())
}
