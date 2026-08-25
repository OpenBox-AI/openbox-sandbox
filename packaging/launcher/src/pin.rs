//! OpenShell dependency pinning + startup verification.
//!
//! `obs` is a thin operator/developer launcher for an operator-installed
//! `OpenShell` gateway. It verifies the local gateway installation
//! against a pinned release to prevent contract drift (the 40-char → 19-char
//! MAX_ROUTABLE_NAME_LEN mismatch after a pin bump already bit this project).
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
//!
//! `REQUIRED_VERSION` is the single pin and cannot be overridden at runtime.

use std::path::Path;
use std::process::Command;

use crate::bundle::Artifacts;

/// The OpenShell version this launcher is built and tested against.
pub const REQUIRED_VERSION: &str = "0.0.88";

/// The official project-zot release used by registry-mode provisioning.
pub const ZOT_VERSION: &str = "v2.1.20";

/// One platform's pinned official zot asset and its local compatibility name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZotPin {
    pub asset: &'static str,
    pub local_name: &'static str,
    pub sha256: &'static str,
}

const ZOT_DARWIN_ARM64: ZotPin = ZotPin {
    asset: "zot-darwin-arm64-minimal",
    local_name: "zot-darwin-arm64",
    sha256: "edeb86f0533d21305bbc775f23da0356a5ce3fd3dd4f614d3257f75ca2ef617a",
};

const ZOT_LINUX_X86_64: ZotPin = ZotPin {
    asset: "zot-linux-amd64-minimal",
    local_name: "zot-linux-x86_64",
    sha256: "902ea958c4a59c0f5c4ac9fa2bbaad8716e80551bcaede7ab4ea998bf57190a6",
};

/// Resolve the official zot asset pin for a target platform.
pub fn zot_pin_for(target_os: &str, target_arch: &str) -> Option<ZotPin> {
    match (target_os, target_arch) {
        ("macos", "aarch64") => Some(ZOT_DARWIN_ARM64),
        ("linux", "x86_64") => Some(ZOT_LINUX_X86_64),
        _ => None,
    }
}

/// Resolve the official zot asset pin for the launcher build target.
pub fn zot_pin() -> Option<ZotPin> {
    zot_pin_for(std::env::consts::OS, std::env::consts::ARCH)
}

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
/// env) are checked when present — the launcher does not bundle tarball hashes
/// because Homebrew re-signs mach-Os on install, so the on-disk hash is not
/// stable across installs.
///
/// There is no way to switch either check off. A pin that can be waived is not
/// a pin, and the flag that waived it was reachable in a normal run.
pub fn verify(artifacts: &Artifacts) -> Result<(), VerifyError> {
    let required = REQUIRED_VERSION.to_owned();

    // Version: run `<binary> --version` and require the pinned version.
    let gateway_version =
        extract_version_from(&artifacts.gateway).map_err(|reason| VerifyError {
            artifact: "openshell-gateway",
            reason,
        })?;
    if !version_satisfies(&gateway_version, &required) {
        return Err(VerifyError {
            artifact: "openshell-gateway",
            reason: format!("version mismatch: required {required}, found {gateway_version}"),
        });
    }

    let cli_version = extract_version_from(&artifacts.cli).map_err(|reason| VerifyError {
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
        let driver_version = extract_version_from(driver).map_err(|reason| VerifyError {
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

    {
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

/// Run `<binary> --version` and return the trailing version token, falling back
/// to the whole output if there is no token. Public so `verify_runtime` can
/// report the detected version without re-implementing the parsing.
pub fn extract_version_from(binary: &Path) -> Result<String, String> {
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

/// Exact version match, or the root-service protocol source marker. The
/// launcher pins an exact OpenShell release (0.0.85) for its own artifact
/// track, but the hosted-bin flow ships source-built OpenShell at the root
/// protocol pin f1690849, which reports `0.0.88-dev.11+gf1690849`. Both are
/// accepted; anything else fails closed because the wire contract (sandbox
/// name length, hook shape) can change between releases.
pub const ROOT_PROTOCOL_MARKER: &str = "gf1690849";
/// The locked released OpenShell version consumed by the hosted-bin flow.
/// Released binaries never carry the source marker, so the lock version is
/// accepted explicitly; the wire contract is proven by the live verify test.
pub const LOCKED_RELEASE_VERSION: &str = "0.0.88";

fn version_satisfies(found: &str, required: &str) -> bool {
    found == required || found == LOCKED_RELEASE_VERSION || found.contains(ROOT_PROTOCOL_MARKER)
}

/// sha256 of a file. Uses `shasum` on macOS (coreutil) and `sha256sum` on
/// Linux (GNU coreutils). Kept dependency-free, like the rest of the launcher.
pub(crate) fn check_sha256(path: &Path, expected: &str) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use super::{zot_pin_for, ZOT_VERSION};

    #[test]
    fn zot_release_is_pinned_per_supported_platform() {
        assert_eq!(ZOT_VERSION, "v2.1.20");

        let darwin = zot_pin_for("macos", "aarch64").expect("darwin-arm64 pin");
        assert_eq!(darwin.asset, "zot-darwin-arm64-minimal");
        assert_eq!(darwin.local_name, "zot-darwin-arm64");
        assert_eq!(
            darwin.sha256,
            "edeb86f0533d21305bbc775f23da0356a5ce3fd3dd4f614d3257f75ca2ef617a"
        );

        let linux = zot_pin_for("linux", "x86_64").expect("linux-x86_64 pin");
        assert_eq!(linux.asset, "zot-linux-amd64-minimal");
        assert_eq!(linux.local_name, "zot-linux-x86_64");
        assert_eq!(
            linux.sha256,
            "902ea958c4a59c0f5c4ac9fa2bbaad8716e80551bcaede7ab4ea998bf57190a6"
        );

        assert_eq!(zot_pin_for("linux", "aarch64"), None);
    }
}
