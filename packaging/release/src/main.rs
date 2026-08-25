//! `obs-release` — maintainer-only release tooling.
//!
//! This is deliberately a separate binary from `obs`. Cutting a release is not
//! a sandbox operation: nobody running a sandbox needs it, and shipping it
//! inside the launcher put GitHub upload logic in every user's hands.
//!
//!   obs-release scan <dir>          Reject a candidate carrying credentials.
//!   obs-release publish <dir> [tag] Scan, verify checksums, then upload.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod publish;

// Output helpers the moved publish module expects. They lived in the launcher.
pub(crate) fn step(message: &str) {
    eprintln!("\u{25b8} {message}");
}

pub(crate) fn ok(message: &str) {
    eprintln!("  \u{2713} {message}");
}

pub(crate) fn info(message: &str) {
    eprintln!("  \u{2022} {message}");
}

pub(crate) fn err(message: &str) {
    eprintln!("  \u{2717} {message}");
}

pub(crate) fn banner() {
    eprintln!("obs-release\n");
}

/// File names that must never appear in a release candidate.
const CREDENTIAL_NAMES: &[&str] = &[
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials",
    "credentials.json",
    "ca-bundle.crt",
    "client.p12",
];

/// Extensions that must never appear in a release candidate.
const CREDENTIAL_EXTENSIONS: &[&str] = &[
    "key",
    "pem",
    "p12",
    "pfx",
    "pkcs8",
    "ed25519",
    "pub",
    "credentials",
];

fn credential_kind(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;
    if CREDENTIAL_NAMES.contains(&name) {
        return Some("credential file");
    }
    if name == ".env" || name.starts_with(".env.") {
        return Some("environment file");
    }
    if name.starts_with("service-account") && name.ends_with(".json") {
        return Some("cloud credential");
    }
    let extension = path.extension()?.to_str()?;
    if CREDENTIAL_EXTENSIONS.contains(&extension) {
        return Some("key material");
    }
    None
}

fn walk(root: &Path, found: &mut Vec<(PathBuf, &'static str)>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            // Build output and version control are not release payload.
            // Nothing else is exempt: a release directory carries no test
            // tree, so a key under one is a finding, not a fixture.
            if name == "target" || name == ".git" {
                continue;
            }
            walk(&path, found);
        } else if let Some(kind) = credential_kind(&path) {
            found.push((path, kind));
        }
    }
}

/// Reject a release candidate that carries secrets.
///
/// Provisioning writes real mTLS material on the same machine that assembles a
/// release, so this runs before anything is uploaded.
pub fn scan(directory: &str) -> ExitCode {
    let root = PathBuf::from(directory);
    if !root.is_dir() {
        eprintln!("release: directory not found: {}", root.display());
        return ExitCode::FAILURE;
    }
    println!("scanning {} for credentials", root.display());
    let mut found = Vec::new();
    walk(&root, &mut found);
    if found.is_empty() {
        println!("  ok: no credential files found");
        return ExitCode::SUCCESS;
    }
    for (path, kind) in &found {
        eprintln!("  reject: {kind}: {}", path.display());
    }
    eprintln!("release: {} credential file(s) found", found.len());
    ExitCode::FAILURE
}

fn usage() -> ExitCode {
    eprintln!(
        "obs-release — maintainer-only release tooling

USAGE:
  obs-release scan <dir>             Reject a candidate carrying credentials.
  obs-release publish <dir> [tag]    Scan, verify checksums, then upload.

`obs` itself contains no release commands. This binary is not published as a
release asset."
    );
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("scan") => match args.get(1) {
            Some(directory) => scan(directory),
            None => usage(),
        },
        Some("publish") => match args.get(1) {
            Some(directory) => {
                // The gate is a precondition, not a suggestion.
                if scan(directory) != ExitCode::SUCCESS {
                    eprintln!("release: credential scan failed; nothing was published");
                    return ExitCode::FAILURE;
                }
                publish::run(directory, args.get(2).map(String::as_str).unwrap_or(""))
            }
            None => usage(),
        },
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::credential_kind;
    use std::path::Path;

    #[test]
    fn key_material_and_environment_files_are_rejected() {
        for name in [
            "server.key",
            "chain.pem",
            "bundle.p12",
            "id_ed25519",
            "agent.pub",
            ".env",
            ".env.production",
            "service-account-prod.json",
            "credentials.json",
        ] {
            assert!(
                credential_kind(Path::new(name)).is_some(),
                "expected {name} to be rejected"
            );
        }
    }

    #[test]
    fn a_key_under_a_test_directory_is_still_a_finding() {
        assert!(credential_kind(Path::new("tests/fixture.pem")).is_some());
    }

    #[test]
    fn release_payload_names_are_accepted() {
        for name in [
            "obs-darwin-arm64",
            "SHA256SUMS",
            "policy-allow-network-dev.yaml",
            "prepared-vm-cache-darwin-arm64.tar.gz",
        ] {
            assert!(
                credential_kind(Path::new(name)).is_none(),
                "expected {name} to be accepted"
            );
        }
    }
}
