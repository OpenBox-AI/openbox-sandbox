//! OpenShell dependency pinning + startup verification.
//!
//! The launcher drives OpenShell as an external dependency (Homebrew install,
//! a release tarball fetched by `scripts/fetch-openshell-deps.sh`, or a local
//! build). An unpinned or drifted OpenShell is a real hazard: this project has
//! been bitten by broker↔OpenShell contract drift (the 40-char → 19-char
//! `MAX_ROUTABLE_NAME_LEN` mismatch after a pin bump). So the launcher refuses
//! to run against an OpenShell whose version does not match the pinned release.
//!
//! Two layers:
//!   1. **Version** — `<gateway> --version` must report the pinned version.
//!      Fast, always on. This is the reliable runtime guard: Homebrew re-signs
//!      mach-Os on install (ARM64), so the on-disk binary hash differs from the
//!      release-tarball hash — therefore the binary content hash is *not* a
//!      stable default runtime check, and the launcher does not use it.
//!   2. **Content hash (opt-in)** — an operator may pin the sha256 of the
//!      resolved gateway/driver binaries via env (`OPENBOX_SANDBOX_GATEWAY_SHA256`,
//!      `OPENBOX_SANDBOX_DRIVER_SHA256`); when set, the launcher verifies them.
//!      This is for air-gapped deployments that control the exact on-disk bytes.
//!      Supply-chain verification of the *downloaded release tarball* lives in
//!      `scripts/fetch-openshell-deps.sh`, because that hash is over the tarball,
//!      not the extracted binary.
//!
//! `REQUIRED_VERSION` is the single pin; override at runtime with
//! `OPENBOX_SANDBOX_REQUIRED_OPENSHELL_VERSION` (e.g. to test a local build of a
//! different version).

use std::path::Path;
use std::process::Command;

use crate::bundle::Artifacts;

/// The OpenShell version this launcher is built and tested against.
pub const REQUIRED_VERSION: &str = "0.0.85";

/// Reported by [`verify`]: the artifact that failed, and why.
#[derive(Debug)]
pub struct VerifyError {
    pub artifact: &'static str,
    pub reason: String,
}

/// Verify the resolved OpenShell artifacts match the pinned manifest.
///
/// Version is always checked for the gateway and CLI. The optional VM driver
/// version is checked when present. Operator-pinned binary sha256 values (via
/// env) are checked only when present — the launcher does not bundle tarball
/// hashes because Homebrew re-signs mach-Os on install, so the on-disk hash is
/// not stable across installs. `strict` toggles whether operator-pinned hashes
/// are enforced; pass `false` (`--skip-hash`) to skip even those.
pub fn verify(artifacts: &Artifacts, strict: bool) -> Result<(), VerifyError> {
    let required = required_version();

    // Version: run `<binary> --version` and require the pinned version.
    let gateway_version = extract_version(&artifacts.gateway).map_err(|reason| VerifyError {
        artifact: "openshell-gateway",
        reason,
    })?;
    if !version_satisfies(&gateway_version, &required) {
        return Err(VerifyError {
            artifact: "openshell-gateway",
            reason: format!("version mismatch: required {required}, found {gateway_version}"),
        });
    }

    let cli_version = extract_version(&artifacts.cli).map_err(|reason| VerifyError {
        artifact: "openshell-cli",
        reason,
    })?;
    if !version_satisfies(&cli_version, &required) {
        return Err(VerifyError {
            artifact: "openshell-cli",
            reason: format!("version mismatch: required {required}, found {cli_version}"),
        });
    }

    if let Some(driver) = &artifacts.driver_vm {
        let driver_version = extract_version(driver).map_err(|reason| VerifyError {
            artifact: "openshell-driver-vm",
            reason,
        })?;
        if !version_satisfies(&driver_version, &required) {
            return Err(VerifyError {
                artifact: "openshell-driver-vm",
                reason: format!("version mismatch: required {required}, found {driver_version}"),
            });
        }
    }

    if strict {
        if let Ok(expected) = std::env::var("OPENBOX_SANDBOX_GATEWAY_SHA256") {
            if !expected.is_empty() {
                check_sha256(&artifacts.gateway, &expected).map_err(|reason| VerifyError {
                    artifact: "openshell-gateway",
                    reason,
                })?;
            }
        }
        if let Ok(expected) = std::env::var("OPENBOX_SANDBOX_CLI_SHA256") {
            if !expected.is_empty() {
                check_sha256(&artifacts.cli, &expected).map_err(|reason| VerifyError {
                    artifact: "openshell-cli",
                    reason,
                })?;
            }
        }
        if let Some(driver) = &artifacts.driver_vm {
            if let Ok(expected) = std::env::var("OPENBOX_SANDBOX_DRIVER_SHA256") {
                if !expected.is_empty() {
                    check_sha256(driver, &expected).map_err(|reason| VerifyError {
                        artifact: "openshell-driver-vm",
                        reason,
                    })?;
                }
            }
        }
    }

    Ok(())
}

/// The required OpenShell version, overridable via env for testing.
fn required_version() -> String {
    std::env::var("OPENBOX_SANDBOX_REQUIRED_OPENSHELL_VERSION")
        .unwrap_or_else(|_| REQUIRED_VERSION.to_string())
}

/// Run `<binary> --version` and return the trailing version token, falling back
/// to the whole output if there is no token.
fn extract_version(binary: &Path) -> Result<String, String> {
    let output = Command::new(binary)
        .arg("--version")
        .output()
        .map_err(|e| format!("failed to run --version: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        return Err("--version printed nothing".to_string());
    }
    // "openshell-gateway 0.0.85" → "0.0.85"
    Ok(text
        .split_whitespace()
        .last()
        .filter(|t| t.chars().any(|c| c.is_ascii_digit()))
        .unwrap_or(&text)
        .to_string())
}

/// Exact version match. We pin an exact OpenShell release, not a range, because
/// the wire contract (sandbox name length, hook shape) can change between
/// minor releases and the launcher must fail closed on drift.
fn version_satisfies(found: &str, required: &str) -> bool {
    found == required
}

/// sha256 of a file. Uses `shasum` on macOS (coreutil) and `sha256sum` on
/// Linux (GNU coreutils). Kept dependency-free, like the rest of the launcher.
fn check_sha256(path: &Path, expected: &str) -> Result<(), String> {
    let (cmd, args): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("shasum", &["-a", "256"])
    } else {
        ("sha256sum", &[])
    };
    let mut full_args = args.to_vec();
    full_args.push(path.to_str().unwrap_or(""));
    let output = Command::new(cmd)
        .args(&full_args)
        .output()
        .map_err(|e| format!("failed to run {cmd}: {e}"))?;
    if !output.status.success() {
        return Err(format!("{cmd} exited {}", output.status));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let digest = text.split_whitespace().next().unwrap_or("");
    if digest.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(format!(
            "sha256 mismatch: expected {expected}, found {digest}"
        ))
    }
}
