use core::fmt::Write as _;
use std::fs;
use std::path::Path;

use openshell_core::proto::SandboxPolicy;
use sha2::{Digest as _, Sha256};

use super::SrtConfigError;

/// Compile a deployment-owned `OpenBox` policy into the native local-sandbox profile.
///
/// Governance requests never call this function. Provisioning invokes it once, pins
/// the resulting digest in service configuration, and the runtime only verifies and
/// consumes those bytes.
pub fn compile_srt_policy(
    policy_document: &Path,
    output: &Path,
    workspace_root: &Path,
) -> Result<String, SrtConfigError> {
    if !policy_document.is_absolute() || !output.is_absolute() || !workspace_root.is_absolute() {
        return Err(SrtConfigError::InvalidConfiguration);
    }
    let yaml = fs::read_to_string(policy_document).map_err(|_| SrtConfigError::PolicyRead)?;
    let policy =
        openshell_policy::parse_sandbox_policy(&yaml).map_err(|_| SrtConfigError::InvalidPolicy)?;
    validate_policy_floor(&policy)?;
    fs::create_dir_all(workspace_root).map_err(|_| SrtConfigError::PolicyWrite)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(workspace_root, fs::Permissions::from_mode(0o700))
            .map_err(|_| SrtConfigError::PolicyWrite)?;
    }
    let workspace_root = workspace_root
        .canonicalize()
        .map_err(|_| SrtConfigError::PolicyWrite)?;

    let compiled = if cfg!(target_os = "macos") {
        compile_seatbelt()
    } else if cfg!(target_os = "linux") {
        compile_bwrap(&workspace_root)
    } else {
        return Err(SrtConfigError::UnsupportedPlatform);
    };
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|_| SrtConfigError::PolicyWrite)?;
    }
    let temporary = output.with_extension("tmp");
    fs::write(&temporary, compiled.as_bytes()).map_err(|_| SrtConfigError::PolicyWrite)?;
    fs::rename(&temporary, output).map_err(|_| SrtConfigError::PolicyWrite)?;
    sha256_file(output)
}

fn validate_policy_floor(policy: &SandboxPolicy) -> Result<(), SrtConfigError> {
    let filesystem = policy
        .filesystem
        .as_ref()
        .ok_or(SrtConfigError::InvalidPolicy)?;
    let process = policy
        .process
        .as_ref()
        .ok_or(SrtConfigError::InvalidPolicy)?;
    if policy.version == 0
        || filesystem.include_workdir
        || filesystem.read_write != ["/sandbox"]
        || process.run_as_user != "sandbox"
        || process.run_as_group != "sandbox"
        || !policy.network_policies.is_empty()
        || !policy.network_middlewares.is_empty()
    {
        return Err(SrtConfigError::InvalidPolicy);
    }
    Ok(())
}

fn compile_seatbelt() -> String {
    // Native implementation of the SRT-style local provider. The default-deny
    // profile deliberately contains no network allow rule. The compiled bytes
    // stay deployment-pinned while sandbox-exec parameters narrow each process
    // to one request-owned directory. Rule order matters: Seatbelt uses the
    // later, more-specific workspace allow to reopen only that directory after
    // the workspace-root and user-home read denies.
    r#";; OpenBox native srt profile v1 (deployment compiled; never request generated)
(version 1)
(define workspace-root (param "WORKSPACE_ROOT"))
(define workspace (param "WORKSPACE"))
(deny default)
(allow process*)
(allow file-read*)
(deny file-read* (subpath "/Users"))
(deny file-read* (subpath "/home"))
(deny file-read* (subpath "/Volumes"))
(deny file-read* (subpath workspace-root))
(allow file-read* (subpath workspace))
(allow file-write* (subpath workspace))
(allow file-read* file-write* (literal "/dev/null"))
(allow file-read* (literal "/dev/random") (literal "/dev/urandom"))
(allow file-ioctl (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom"))
(allow sysctl-read)
"#
    .to_owned()
}

fn compile_bwrap(workspace_root: &Path) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "format": "openbox-native-srt-bwrap-v1",
        "network": "deny",
        "workspace_root": workspace_root,
        "workdir": "/sandbox",
        "clear_environment": true
    }))
    .expect("static bwrap policy is serializable")
        + "\n"
}

pub fn sha256_file(path: &Path) -> Result<String, SrtConfigError> {
    let bytes = fs::read(path).map_err(|_| SrtConfigError::PolicyRead)?;
    let digest = Sha256::digest(bytes);
    Ok(digest
        .iter()
        .fold(String::with_capacity(64), |mut encoded, byte| {
            write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
            encoded
        }))
}

pub(super) fn verify_compiled_profile(
    path: &Path,
    expected_sha256: &str,
    workspace_root: &Path,
) -> Result<(), SrtConfigError> {
    if sha256_file(path)? != expected_sha256 {
        return Err(SrtConfigError::PolicyMismatch);
    }
    if cfg!(target_os = "linux") {
        let bytes = fs::read(path).map_err(|_| SrtConfigError::PolicyRead)?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| SrtConfigError::InvalidPolicy)?;
        if value["format"] != "openbox-native-srt-bwrap-v1"
            || value["network"] != "deny"
            || value["workdir"] != "/sandbox"
            || value["clear_environment"] != true
            || value["workspace_root"] != workspace_root.to_string_lossy().as_ref()
        {
            return Err(SrtConfigError::InvalidPolicy);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn checked_in_deny_policy_compiles_to_a_pinned_native_profile() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("workspaces");
        let profile = temporary.path().join(if cfg!(target_os = "macos") {
            "policy.sb"
        } else {
            "policy.json"
        });
        let policy = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("deploy/policies/policy-deny-network.yaml");
        let digest = compile_srt_policy(&policy, &profile, &workspace).unwrap();
        assert_eq!(digest.len(), 64);
        verify_compiled_profile(&profile, &digest, &workspace.canonicalize().unwrap()).unwrap();
        let body = fs::read_to_string(profile).unwrap();
        assert!(body.contains("deny") || body.contains("network"));
    }

    #[test]
    fn network_policy_is_not_silently_weakened_to_deny_all() {
        let temporary = tempfile::tempdir().unwrap();
        let policy = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("deploy/policies/policy-allow-network-dev.yaml");
        assert_eq!(
            compile_srt_policy(
                &policy,
                &temporary.path().join("profile"),
                &temporary.path().join("workspaces")
            ),
            Err(SrtConfigError::InvalidPolicy)
        );
    }
}
