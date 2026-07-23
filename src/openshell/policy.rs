use core::fmt::Write as _;

use crate::{PolicyDocument, PolicyIdentity, TemplateIdentity};
use openshell_core::proto::SandboxPolicy;
use sha2::{Digest, Sha256};

pub fn validate_image(template: &TemplateIdentity) -> Result<String, ()> {
    let image = template.as_str();
    let (repository, digest) = image.rsplit_once("@sha256:").ok_or(())?;
    if repository.is_empty()
        || image.chars().any(char::is_whitespace)
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    Ok(image.to_owned())
}

pub fn parse_and_validate_policy(
    document: &PolicyDocument,
    identity: &PolicyIdentity,
) -> Result<SandboxPolicy, ()> {
    if document.media_type() != "application/yaml"
        || sha256_hex(document.as_bytes()) != identity.sha256().as_str()
    {
        return Err(());
    }
    let yaml = std::str::from_utf8(document.as_bytes()).map_err(|_| ())?;
    let policy = openshell_policy::parse_sandbox_policy(yaml).map_err(|_| ())?;
    if u64::from(policy.version) != identity.version() || !meets_security_floor(&policy) {
        return Err(());
    }
    Ok(policy)
}

fn meets_security_floor(policy: &SandboxPolicy) -> bool {
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
        && filesystem.read_write == ["/sandbox"]
        && landlock.compatibility == "hard_requirement"
        && process.run_as_user == "sandbox"
        && process.run_as_group == "sandbox"
        && policy.network_middlewares.is_empty()
}

pub fn deterministic_policy_hash(policy: &SandboxPolicy) -> String {
    use prost::Message as _;

    let mut hasher = Sha256::new();
    hasher.update(policy.version.to_le_bytes());
    if let Some(filesystem) = &policy.filesystem {
        hasher.update(filesystem.encode_to_vec());
    }
    if let Some(landlock) = &policy.landlock {
        hasher.update(landlock.encode_to_vec());
    }
    if let Some(process) = &policy.process {
        hasher.update(process.encode_to_vec());
    }
    let mut network_entries = policy.network_policies.iter().collect::<Vec<_>>();
    network_entries.sort_by_key(|(name, _)| name.as_str());
    for (name, rule) in network_entries {
        hasher.update(name.as_bytes());
        hasher.update(rule.encode_to_vec());
    }
    if !policy.network_middlewares.is_empty() {
        hasher.update(b"network_middlewares");
        let mut middleware_entries = policy.network_middlewares.iter().collect::<Vec<_>>();
        middleware_entries.sort_by_key(|(name, _)| name.as_str());
        for (name, middleware) in middleware_entries {
            hasher.update(name.as_bytes());
            let encoded = middleware.encode_to_vec();
            hasher.update(
                u64::try_from(encoded.len())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes(),
            );
            hasher.update(encoded);
        }
    }
    digest_hex(hasher.finalize())
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
    fn checked_in_policy_meets_the_adapter_security_floor() {
        let document = PolicyDocument::new("application/yaml", POLICY.as_bytes().to_vec()).unwrap();
        let identity = PolicyIdentity::new(
            "openbox-deny-network",
            1,
            Sha256Digest::parse(sha256_hex(POLICY.as_bytes())).unwrap(),
        )
        .unwrap();
        let policy = parse_and_validate_policy(&document, &identity).unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(
            deterministic_policy_hash(&policy),
            "500aedd115d9b62509ba13dbc1458003a312bf98dbd557e168a66c1111a385ef"
        );
    }

    #[test]
    fn exact_release_bound_network_policy_is_framework_neutral() {
        const NETWORK_POLICY: &str = r"version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr, /lib, /etc, /proc]
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
        let document =
            PolicyDocument::new("application/yaml", NETWORK_POLICY.as_bytes().to_vec()).unwrap();
        let digest = sha256_hex(NETWORK_POLICY.as_bytes());
        let identity = PolicyIdentity::new(
            "approved-client-policy",
            1,
            Sha256Digest::parse(digest).unwrap(),
        )
        .unwrap();
        let policy = parse_and_validate_policy(&document, &identity).unwrap();
        assert_eq!(policy.network_policies.len(), 1);

        let wrong_identity = PolicyIdentity::new(
            "approved-client-policy",
            1,
            Sha256Digest::parse("0".repeat(64)).unwrap(),
        )
        .unwrap();
        assert!(parse_and_validate_policy(&document, &wrong_identity).is_err());
    }
}
