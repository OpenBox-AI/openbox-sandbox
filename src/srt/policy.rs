use core::fmt::Write as _;
use std::fs;
use std::path::Path;

use openshell_core::proto::SandboxPolicy;
use sha2::{Digest as _, Sha256};

use super::SrtConfigError;

const DEV_NETWORK_HOST: &str = "example.com";
const DEV_NETWORK_PORT: u16 = 443;
const DEV_NETWORK_BINARY: &str = "/usr/bin/curl";

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
    let network = validate_policy_floor(&policy)?;
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
        compile_seatbelt(network)
    } else if cfg!(target_os = "linux") {
        compile_bwrap(&workspace_root, network)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum NetworkAccess {
    Deny,
    Allowlist(Vec<(String, u16)>),
}

fn validate_policy_floor(policy: &SandboxPolicy) -> Result<NetworkAccess, SrtConfigError> {
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
        || !policy.network_middlewares.is_empty()
    {
        return Err(SrtConfigError::InvalidPolicy);
    }
    if policy.network_policies.is_empty() {
        return Ok(NetworkAccess::Deny);
    }

    // The native provider deliberately supports the same one-purpose dev
    // allow-list shipped for OpenShell. Reject every other network shape rather
    // than silently broadening or weakening it during native compilation.
    if policy.network_policies.len() != 1 {
        return Err(SrtConfigError::InvalidPolicy);
    }
    let rule = policy
        .network_policies
        .values()
        .next()
        .ok_or(SrtConfigError::InvalidPolicy)?;
    if rule.endpoints.len() != 1 || rule.binaries.len() != 1 {
        return Err(SrtConfigError::InvalidPolicy);
    }
    let endpoint = &rule.endpoints[0];
    let binary = &rule.binaries[0];
    let mut expected_endpoint = openshell_core::proto::NetworkEndpoint::default();
    DEV_NETWORK_HOST.clone_into(&mut expected_endpoint.host);
    expected_endpoint.port = u32::from(DEV_NETWORK_PORT);
    expected_endpoint.ports = vec![u32::from(DEV_NETWORK_PORT)];
    let mut expected_binary = openshell_core::proto::NetworkBinary::default();
    DEV_NETWORK_BINARY.clone_into(&mut expected_binary.path);
    #[allow(deprecated)]
    {
        expected_binary.harness = false;
    }
    if endpoint.host != DEV_NETWORK_HOST
        || endpoint.port != u32::from(DEV_NETWORK_PORT)
        || endpoint != &expected_endpoint
        || binary.path != DEV_NETWORK_BINARY
        || binary != &expected_binary
    {
        return Err(SrtConfigError::InvalidPolicy);
    }
    Ok(NetworkAccess::Allowlist(vec![(
        DEV_NETWORK_HOST.to_owned(),
        DEV_NETWORK_PORT,
    )]))
}

fn compile_seatbelt(network: NetworkAccess) -> String {
    // Rule order matters: Seatbelt uses the later, more-specific workspace
    // allow to reopen only that directory after the workspace-root and user-home
    // read denies. The command can connect only to one runtime-selected localhost
    // TCP endpoint; the out-of-sandbox proxy performs DNS and host filtering.
    let network_rule = match network {
        NetworkAccess::Deny => String::new(),
        NetworkAccess::Allowlist(endpoints) => {
            let metadata = endpoints
                .iter()
                .fold(String::new(), |mut output, (host, port)| {
                    writeln!(output, ";; OPENBOX_EGRESS_ALLOW {host}:{port}")
                        .expect("writing to String cannot fail");
                    output
                });
            format!("{metadata}(allow network-outbound (remote tcp (param \"PROXY_ENDPOINT\")))\n")
        }
    };
    format!(
        r#";; OpenBox native srt profile v2 (deployment compiled; never request generated)
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
{network_rule}"#
    )
}

fn compile_bwrap(workspace_root: &Path, network: NetworkAccess) -> String {
    let network = match network {
        NetworkAccess::Deny => serde_json::json!({"mode": "deny"}),
        NetworkAccess::Allowlist(endpoints) => serde_json::json!({
            "mode": "allowlist",
            "endpoints": endpoints.into_iter().map(|(host, port)| {
                serde_json::json!({"host": host, "port": port})
            }).collect::<Vec<_>>(),
            "binaries": [DEV_NETWORK_BINARY]
        }),
    };
    serde_json::to_string_pretty(&serde_json::json!({
        "format": "openbox-native-srt-bwrap-v1",
        "network": network,
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
    let bytes = fs::read(path).map_err(|_| SrtConfigError::PolicyRead)?;
    if cfg!(target_os = "macos") {
        let body = std::str::from_utf8(&bytes).map_err(|_| SrtConfigError::InvalidPolicy)?;
        let access = parse_seatbelt_network(body)?;
        if !body.starts_with(";; OpenBox native srt profile v2 ")
            || (matches!(access, NetworkAccess::Deny) && body.contains("network-outbound"))
            || body.matches("network-outbound").count() > 1
        {
            return Err(SrtConfigError::InvalidPolicy);
        }
    } else if cfg!(target_os = "linux") {
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| SrtConfigError::InvalidPolicy)?;
        let valid_network = value["network"]["mode"] == "deny"
            || (value["network"]["mode"] == "allowlist"
                && value["network"]["endpoints"]
                    == serde_json::json!([{"host": DEV_NETWORK_HOST, "port": DEV_NETWORK_PORT}])
                && value["network"]["binaries"] == serde_json::json!([DEV_NETWORK_BINARY]));
        if value["format"] != "openbox-native-srt-bwrap-v1"
            || !valid_network
            || value["workdir"] != "/sandbox"
            || value["clear_environment"] != true
            || value["workspace_root"] != workspace_root.to_string_lossy().as_ref()
        {
            return Err(SrtConfigError::InvalidPolicy);
        }
    }
    Ok(())
}

pub(super) fn compiled_network_access(path: &Path) -> Result<NetworkAccess, SrtConfigError> {
    let bytes = fs::read(path).map_err(|_| SrtConfigError::PolicyRead)?;
    if cfg!(target_os = "macos") {
        return parse_seatbelt_network(
            std::str::from_utf8(&bytes).map_err(|_| SrtConfigError::InvalidPolicy)?,
        );
    }
    if cfg!(target_os = "linux") {
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| SrtConfigError::InvalidPolicy)?;
        if value["network"]["mode"] == "deny" {
            return Ok(NetworkAccess::Deny);
        }
        if value["network"]["mode"] == "allowlist" {
            let endpoints = value["network"]["endpoints"]
                .as_array()
                .ok_or(SrtConfigError::InvalidPolicy)?
                .iter()
                .map(|endpoint| {
                    let host = endpoint["host"]
                        .as_str()
                        .ok_or(SrtConfigError::InvalidPolicy)?
                        .to_owned();
                    let port = u16::try_from(
                        endpoint["port"]
                            .as_u64()
                            .ok_or(SrtConfigError::InvalidPolicy)?,
                    )
                    .map_err(|_| SrtConfigError::InvalidPolicy)?;
                    Ok((host, port))
                })
                .collect::<Result<Vec<_>, SrtConfigError>>()?;
            return Ok(NetworkAccess::Allowlist(endpoints));
        }
    }
    Err(SrtConfigError::UnsupportedPlatform)
}

fn parse_seatbelt_network(body: &str) -> Result<NetworkAccess, SrtConfigError> {
    let endpoints = body
        .lines()
        .filter_map(|line| line.strip_prefix(";; OPENBOX_EGRESS_ALLOW "))
        .map(|target| {
            let (host, port) = target
                .rsplit_once(':')
                .ok_or(SrtConfigError::InvalidPolicy)?;
            let port = port
                .parse::<u16>()
                .map_err(|_| SrtConfigError::InvalidPolicy)?;
            if host.is_empty() {
                return Err(SrtConfigError::InvalidPolicy);
            }
            Ok((host.to_owned(), port))
        })
        .collect::<Result<Vec<_>, SrtConfigError>>()?;
    if endpoints.is_empty() {
        Ok(NetworkAccess::Deny)
    } else if body.contains("(allow network-outbound (remote tcp (param \"PROXY_ENDPOINT\")))") {
        Ok(NetworkAccess::Allowlist(endpoints))
    } else {
        Err(SrtConfigError::InvalidPolicy)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn compile_checked_in(name: &str) -> String {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("workspaces");
        let profile = temporary.path().join(if cfg!(target_os = "macos") {
            "policy.sb"
        } else {
            "policy.json"
        });
        let policy = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("deploy/policies")
            .join(name);
        let digest = compile_srt_policy(&policy, &profile, &workspace).unwrap();
        assert_eq!(digest.len(), 64);
        verify_compiled_profile(&profile, &digest, &workspace.canonicalize().unwrap()).unwrap();
        fs::read_to_string(profile).unwrap()
    }

    #[test]
    fn checked_in_deny_policy_compiles_without_a_network_allow_rule() {
        let body = compile_checked_in("policy-deny-network.yaml");
        if cfg!(target_os = "macos") {
            assert!(!body.contains("allow network-outbound"));
        } else {
            assert!(body.contains(r#"\"mode\": \"deny\""#));
        }
    }

    #[test]
    fn checked_in_dev_policy_compiles_only_the_example_curl_allow_list() {
        let body = compile_checked_in("policy-allow-network-dev.yaml");
        if cfg!(target_os = "macos") {
            assert!(body.contains(";; OPENBOX_EGRESS_ALLOW example.com:443"));
            assert!(
                body.contains(r#"(allow network-outbound (remote tcp (param "PROXY_ENDPOINT")))"#)
            );
            assert!(!body.contains("mDNSResponder"));
            assert!(!body.contains("*:443"));
            assert!(!body.contains("network-inbound"));
        } else {
            assert!(body.contains(r#"\"mode\": \"allowlist\""#));
            assert!(body.contains(r#"\"host\": \"example.com\""#));
            assert!(body.contains(r#"\"port\": 443"#));
            assert!(body.contains(r#"\"/usr/bin/curl\""#));
        }
    }

    #[test]
    fn unrecognized_network_policy_is_rejected_instead_of_broadened() {
        let temporary = tempfile::tempdir().unwrap();
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("deploy/policies/policy-allow-network-dev.yaml");
        let changed = fs::read_to_string(source)
            .unwrap()
            .replace("example.com", "example.org");
        let policy = temporary.path().join("changed.yaml");
        fs::write(&policy, changed).unwrap();
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
