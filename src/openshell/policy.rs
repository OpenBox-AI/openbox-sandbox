use core::fmt::Write as _;

use std::collections::HashSet;

use crate::{PolicyDocument, PolicyIdentity, TemplateIdentity};
use openshell_core::proto::{FilesystemPolicy, SandboxPolicy};
use sha2::{Digest, Sha256};

const SANDBOX_WRITABLE_PATH: &str = "/sandbox";
const PROXY_TEMP_PATH: &str = "/tmp";
// Baseline filesystem paths OpenShell injects for proxy-mode sandboxes when
// the policy declares network policies. Mirrors PROXY_BASELINE_READ_ONLY and
// PROXY_BASELINE_READ_WRITE in the pinned OpenShell release (0.1.2,
// crates/openshell-supervisor). Since 0.1.x the workspace comes from
// include_workdir rather than the read-write baseline, and /dev/null is
// read-write so child launchers can open discarded stdio.
// /app is deliberately absent — the released sandbox images do not ship /app
// and OpenShell skips it via its runtime existence check. If a future image
// adds /app the enriched policy diverges and readiness fails closed.
const PROXY_BASELINE_READ_ONLY: &[&str] =
    &["/usr", "/lib", "/etc", "/var/log", "/proc", "/dev/urandom"];
const PROXY_BASELINE_READ_WRITE: &[&str] = &["/tmp", "/dev/null"];

pub fn validate_image(template: &TemplateIdentity) -> Result<String, ()> {
    let image = template.as_str();
    let (repository, digest) = image.rsplit_once("@sha256:").ok_or_else(|| {
        eprintln!("ERROR: validate_image: missing @sha256: digest in template '{image}'");
    })?;
    if repository.is_empty()
        || image.chars().any(char::is_whitespace)
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        eprintln!("ERROR: validate_image: malformed template reference '{image}'");
        return Err(());
    }
    Ok(image.to_owned())
}

pub fn parse_and_validate_policy(
    document: &PolicyDocument,
    identity: &PolicyIdentity,
    allow_degraded_landlock: bool,
) -> Result<SandboxPolicy, ()> {
    if document.media_type() != "application/yaml" {
        eprintln!(
            "ERROR: parse_and_validate_policy: unsupported media type '{}' for policy '{}' v{}",
            document.media_type(),
            identity.id(),
            identity.version()
        );
        return Err(());
    }
    let document_sha = sha256_hex(document.as_bytes());
    if document_sha != identity.sha256().as_str() {
        eprintln!(
            "ERROR: parse_and_validate_policy: SHA mismatch for policy '{}' v{} (expected {} got {})",
            identity.id(),
            identity.version(),
            identity.sha256().as_str(),
            document_sha
        );
        return Err(());
    }
    let yaml = std::str::from_utf8(document.as_bytes()).map_err(|_| {
        eprintln!(
            "ERROR: parse_and_validate_policy: invalid UTF-8 in policy document for '{}' v{}",
            identity.id(),
            identity.version()
        );
    })?;
    let policy = openshell_policy::parse_sandbox_policy(yaml).map_err(|_| {
        eprintln!(
            "ERROR: parse_and_validate_policy: YAML parse failed for policy '{}' v{}",
            identity.id(),
            identity.version()
        );
    })?;
    if u64::from(policy.version) != identity.version() {
        eprintln!(
            "ERROR: parse_and_validate_policy: version mismatch for policy '{}' (expected v{} got v{})",
            identity.id(),
            identity.version(),
            policy.version
        );
        return Err(());
    }
    if !meets_security_floor(&policy, allow_degraded_landlock) {
        eprintln!(
            "ERROR: parse_and_validate_policy: security floor not met for policy '{}' v{}",
            identity.id(),
            identity.version()
        );
        return Err(());
    }
    let mut effective = policy;
    apply_proxy_baseline_enrichment(&mut effective);
    Ok(effective)
}

fn meets_security_floor(policy: &SandboxPolicy, allow_degraded_landlock: bool) -> bool {
    let Some(filesystem) = policy.filesystem.as_ref() else {
        return false;
    };
    let Some(landlock) = policy.landlock.as_ref() else {
        return false;
    };
    let Some(process) = policy.process.as_ref() else {
        return false;
    };
    !filesystem.include_workdir
        && filesystem.read_write == [SANDBOX_WRITABLE_PATH]
        && filesystem_paths_are_unambiguous(filesystem)
        && proxy_temp_path_is_pinned_read_only(policy, filesystem)
        && (landlock.compatibility == "hard_requirement"
            || (allow_degraded_landlock && landlock.compatibility == "best_effort"))
        && process.run_as_user == "sandbox"
        && process.run_as_group == "sandbox"
        && policy.network_middlewares.is_empty()
}

/// Mirror `OpenShell`'s baseline-path enrichment for proxy-mode sandboxes.
///
/// `OpenShell` (`crates/openshell-supervisor::enrich_proto_baseline_paths`) adds
/// baseline filesystem paths to policies that declare network policies, then
/// syncs the enriched document back to the gateway as a NEW policy revision.
/// The service must normalize identically so the readiness content check
/// compares like-for-like (the stored effective policy vs. the expected
/// policy). Paths already declared in either list are skipped, matching
/// `OpenShell`'s `enrich_proto_baseline_paths_with`.
fn apply_proxy_baseline_enrichment(policy: &mut SandboxPolicy) {
    if policy.network_policies.is_empty() {
        return;
    }
    let Some(filesystem) = policy.filesystem.as_mut() else {
        return;
    };
    for path in PROXY_BASELINE_READ_ONLY {
        if !filesystem.read_only.iter().any(|p| p == path)
            && !filesystem.read_write.iter().any(|p| p == path)
        {
            filesystem.read_only.push((*path).to_owned());
        }
    }
    for path in PROXY_BASELINE_READ_WRITE {
        if !filesystem.read_only.iter().any(|p| p == path)
            && !filesystem.read_write.iter().any(|p| p == path)
        {
            filesystem.read_write.push((*path).to_owned());
        }
    }
}

fn filesystem_paths_are_unambiguous(filesystem: &FilesystemPolicy) -> bool {
    let mut paths = HashSet::new();
    filesystem
        .read_only
        .iter()
        .chain(&filesystem.read_write)
        .all(|path| paths.insert(openshell_policy::normalize_path(path)))
}

fn proxy_temp_path_is_pinned_read_only(
    policy: &SandboxPolicy,
    filesystem: &FilesystemPolicy,
) -> bool {
    policy.network_policies.is_empty()
        || filesystem
            .read_only
            .iter()
            .any(|path| path == PROXY_TEMP_PATH)
}

/// Registration and attachment name the `OpenBox` front desk (governance
/// interceptor) stamps onto every sandbox in a governed gateway.
const OPENBOX_ATTACHMENT: &str = "openbox";

/// The policy this service asked for, recovered from what a governed
/// gateway stored.
///
/// In a gateway running the `OpenBox` front desk, every created sandbox gets
/// `network_middlewares.openbox` added: the `OpenBox` verdict middleware on
/// every host (`**`), failing closed. That only adds inspection, so it is the
/// one addition accepted here, and only in exactly that shape. Anything else
/// the gateway added, and any other shape of the `openbox` entry, returns
/// `None` so readiness fails closed as a mismatch.
pub fn without_openbox_attachment(policy: &SandboxPolicy) -> Option<SandboxPolicy> {
    let Some(attachment) = policy.network_middlewares.get(OPENBOX_ATTACHMENT) else {
        return Some(policy.clone());
    };
    let selector = attachment.endpoints.as_ref()?;
    let tls_skip_hosts: HashSet<String> = policy
        .network_policies
        .values()
        .flat_map(|rule| &rule.endpoints)
        .filter(|endpoint| endpoint.tls == openshell_core::proto::NetworkTlsMode::Skip as i32)
        .map(|endpoint| endpoint.host.to_ascii_lowercase())
        .collect();
    let approval_mode_ok = attachment.config.as_ref().is_none_or(|config| {
        config.fields.iter().all(|(key, value)| {
            key == "approval_mode"
                && matches!(
                    &value.kind,
                    Some(prost_types::value::Kind::StringValue(mode)) if mode == "queue" || mode == "deny"
                )
        })
    });
    let shape_ok = attachment.middleware == OPENBOX_ATTACHMENT
        && attachment.on_error == "fail_closed"
        && selector.include == ["**"]
        && selector
            .exclude
            .iter()
            .all(|host| tls_skip_hosts.contains(&host.to_ascii_lowercase()))
        && approval_mode_ok;
    if !shape_ok {
        return None;
    }
    let mut requested = policy.clone();
    requested.network_middlewares.remove(OPENBOX_ATTACHMENT);
    Some(requested)
}

/// The gateway's policy identity hash. Delegates to `OpenShell`'s own
/// canonical encoding (public in `openshell-core` since 0.1.x) so the readiness
/// check cannot drift from the gateway when the encoding changes upstream.
pub fn deterministic_policy_hash(policy: &SandboxPolicy) -> String {
    openshell_core::policy_identity::deterministic_policy_hash(policy)
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest_hex(Sha256::digest(bytes))
}

fn digest_hex(digest: impl AsRef<[u8]>) -> String {
    digest
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        })
}

#[cfg(test)]
mod tests {
    use crate::{PolicyDocument, PolicyIdentity, Sha256Digest, TemplateIdentity};

    use super::*;

    fn governed(
        mutate: impl FnOnce(&mut openshell_core::proto::NetworkMiddlewareConfig),
    ) -> SandboxPolicy {
        use openshell_core::proto::{MiddlewareEndpointSelector, NetworkMiddlewareConfig};
        let mut policy = SandboxPolicy {
            version: 1,
            ..SandboxPolicy::default()
        };
        let mut attachment = NetworkMiddlewareConfig {
            name: "OpenBox verdicts".to_owned(),
            middleware: "openbox".to_owned(),
            config: Some(prost_types::Struct {
                fields: [(
                    "approval_mode".to_owned(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue("queue".to_owned())),
                    },
                )]
                .into(),
            }),
            on_error: "fail_closed".to_owned(),
            endpoints: Some(MiddlewareEndpointSelector {
                include: vec!["**".to_owned()],
                exclude: Vec::new(),
            }),
            order: 1000,
        };
        mutate(&mut attachment);
        policy
            .network_middlewares
            .insert("openbox".to_owned(), attachment);
        policy
    }

    #[test]
    fn the_front_desk_attachment_is_recognised_and_removed() {
        let requested = SandboxPolicy {
            version: 1,
            ..SandboxPolicy::default()
        };
        assert_eq!(
            without_openbox_attachment(&requested),
            Some(requested.clone())
        );
        assert_eq!(
            without_openbox_attachment(&governed(|_| {})),
            Some(requested)
        );
    }

    type Mutation = fn(&mut openshell_core::proto::NetworkMiddlewareConfig);

    #[test]
    fn any_other_shape_of_the_attachment_is_a_mismatch() {
        let cases: [(&str, Mutation); 6] = [
            ("fail open", |a| a.on_error = "fail_open".to_owned()),
            ("other middleware", |a| {
                a.middleware = "openshell/regex".to_owned();
            }),
            ("narrowed", |a| {
                a.endpoints.as_mut().unwrap().include = vec!["api.example.com".to_owned()];
            }),
            ("inspectable host excluded", |a| {
                a.endpoints.as_mut().unwrap().exclude = vec!["api.example.com".to_owned()];
            }),
            ("no selector", |a| a.endpoints = None),
            ("unknown config", |a| {
                a.config.as_mut().unwrap().fields.insert(
                    "mode".to_owned(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue("off".to_owned())),
                    },
                );
            }),
        ];
        for (name, mutate) in cases {
            assert_eq!(
                without_openbox_attachment(&governed(mutate)),
                None,
                "{name}"
            );
        }
    }

    const POLICY: &str = include_str!("../../deploy/policies/policy-deny-network.yaml");

    #[test]
    fn immutable_image_validation_rejects_mutable_or_malformed_references() {
        let valid =
            TemplateIdentity::new(format!("example.invalid/proof@sha256:{}", "a".repeat(64)))
                .unwrap();
        assert_eq!(validate_image(&valid).unwrap(), valid.as_str());
        for value in [
            "example.invalid/proof:latest".to_owned(),
            format!("example.invalid/proof@sha256:{}", "A".repeat(64)),
            format!("example.invalid/proof@sha256:{}", "a".repeat(63)),
        ] {
            assert!(validate_image(&TemplateIdentity::new(value).unwrap()).is_err());
        }
    }

    #[test]
    fn checked_in_deny_network_policy_meets_the_adapter_security_floor() {
        let document = PolicyDocument::new("application/yaml", POLICY.as_bytes().to_vec()).unwrap();
        let identity = PolicyIdentity::new(
            "openbox-deny-network",
            1,
            Sha256Digest::parse(sha256_hex(POLICY.as_bytes())).unwrap(),
        )
        .unwrap();
        let policy = parse_and_validate_policy(&document, &identity, false).unwrap();
        assert_eq!(policy.version, 1);
        // OpenShell 0.1.2's canonical policy encoding (openshell-core
        // policy_identity); changes whenever the gateway's hash changes.
        assert_eq!(
            deterministic_policy_hash(&policy),
            "7d84b4bda748e7b32384509d21f03f3f57353c82047e8a231222c78ffa1b4b14"
        );
    }

    const NETWORK_POLICY: &str = r"version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr, /lib, /etc, /proc, /tmp]
  read_write: [/sandbox]
landlock:
  compatibility: hard_requirement
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  approved_egress:
    name: approved-egress
    endpoints:
      - host: api.example.test
        port: 443
    binaries:
      - path: /usr/bin/client
";

    fn parse_with_matching_identity(yaml: &str) -> Result<SandboxPolicy, ()> {
        let document = PolicyDocument::new("application/yaml", yaml.as_bytes().to_vec()).unwrap();
        let identity = PolicyIdentity::new(
            "approved-client-policy",
            1,
            Sha256Digest::parse(sha256_hex(yaml.as_bytes())).unwrap(),
        )
        .unwrap();
        parse_and_validate_policy(&document, &identity, false)
    }

    const BEST_EFFORT_POLICY: &str = r"version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr, /lib, /etc, /proc]
  read_write: [/sandbox]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies: {}
";

    fn parse_allowing_degraded(yaml: &str, allow_degraded: bool) -> Result<SandboxPolicy, ()> {
        let document = PolicyDocument::new("application/yaml", yaml.as_bytes().to_vec()).unwrap();
        let identity = PolicyIdentity::new(
            "approved-client-policy",
            1,
            Sha256Digest::parse(sha256_hex(yaml.as_bytes())).unwrap(),
        )
        .unwrap();
        parse_and_validate_policy(&document, &identity, allow_degraded)
    }

    #[test]
    fn best_effort_landlock_is_rejected_by_default_and_accepted_only_when_opted_in() {
        assert!(parse_allowing_degraded(BEST_EFFORT_POLICY, false).is_err());
        assert!(parse_allowing_degraded(BEST_EFFORT_POLICY, true).is_ok());
    }

    #[test]
    fn hard_requirement_landlock_is_accepted_in_both_tiers() {
        assert!(parse_allowing_degraded(NETWORK_POLICY, false).is_ok());
        assert!(parse_allowing_degraded(NETWORK_POLICY, true).is_ok());
    }

    #[test]
    fn degraded_tier_still_enforces_every_other_floor_rule() {
        let wrong_user = BEST_EFFORT_POLICY.replace("run_as_user: sandbox", "run_as_user: root");
        assert!(parse_allowing_degraded(&wrong_user, true).is_err());
        let writable_workdir =
            BEST_EFFORT_POLICY.replace("include_workdir: false", "include_workdir: true");
        assert!(parse_allowing_degraded(&writable_workdir, true).is_err());
    }

    #[test]
    fn exact_release_bound_network_policy_is_framework_neutral() {
        let policy = parse_with_matching_identity(NETWORK_POLICY).unwrap();
        assert_eq!(policy.network_policies.len(), 1);
        // /dev/null is OpenShell 0.1.x's read-write baseline; /tmp stays
        // read-only because the policy pins it.
        assert_eq!(
            policy.filesystem.unwrap().read_write,
            ["/sandbox", "/dev/null"]
        );

        let document =
            PolicyDocument::new("application/yaml", NETWORK_POLICY.as_bytes().to_vec()).unwrap();
        let wrong_identity = PolicyIdentity::new(
            "approved-client-policy",
            1,
            Sha256Digest::parse("0".repeat(64)).unwrap(),
        )
        .unwrap();
        assert!(parse_and_validate_policy(&document, &wrong_identity, false).is_err());
    }

    #[test]
    fn network_policy_requires_explicit_read_only_temp_path() {
        let without_temp = NETWORK_POLICY.replace(", /tmp", "");
        assert!(parse_with_matching_identity(&without_temp).is_err());
    }

    #[test]
    fn network_policy_rejects_writable_temp_path() {
        let writable_temp = NETWORK_POLICY
            .replace(", /tmp", "")
            .replace("read_write: [/sandbox]", "read_write: [/sandbox, /tmp]");
        assert!(parse_with_matching_identity(&writable_temp).is_err());
    }

    #[test]
    fn network_policy_rejects_duplicate_or_conflicting_paths() {
        let duplicate = NETWORK_POLICY.replace("/proc, /tmp", "/proc, /tmp, /tmp/");
        assert!(parse_with_matching_identity(&duplicate).is_err());

        let conflicting =
            NETWORK_POLICY.replace("read_write: [/sandbox]", "read_write: [/sandbox, /tmp]");
        assert!(parse_with_matching_identity(&conflicting).is_err());
    }

    #[test]
    fn explicit_read_only_temp_path_prevents_proxy_temp_enrichment() {
        let mut policy = parse_with_matching_identity(NETWORK_POLICY).unwrap();
        let before = policy.clone();
        model_proxy_temp_baseline_enrichment(&mut policy);
        assert_eq!(policy, before);
    }

    fn model_proxy_temp_baseline_enrichment(policy: &mut SandboxPolicy) {
        // The pinned proxy adds writable temporary storage only when the path is undeclared.
        if policy.network_policies.is_empty() {
            return;
        }
        let filesystem = policy.filesystem.as_mut().unwrap();
        if !filesystem
            .read_only
            .iter()
            .chain(&filesystem.read_write)
            .any(|path| path == PROXY_TEMP_PATH)
        {
            filesystem.read_write.push(PROXY_TEMP_PATH.to_owned());
        }
    }
}
