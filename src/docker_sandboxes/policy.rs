//! Deployment-level policy validation for the Docker Sandboxes adapter.
//!
//! Docker Sandboxes has no OpenShell-compatible supervisor policy engine, so
//! this adapter cannot attest in-sandbox policy enforcement. It can and does
//! verify the request's policy identity integrity (media type and SHA-256)
//! and, when the deployment pins an identity, requires the request to match
//! it exactly. The pinned identity is also the readiness attestation anchor.

use crate::{PolicyDocument, PolicyIdentity, TemplateIdentity};
use sha2::{Digest as _, Sha256};

/// Validates the immutable image reference carried by the template.
///
/// Mirrors the `OpenShell` adapter's immutable-reference rule: the template
/// must be a `repository@sha256:<64-hex>` reference with no whitespace.
pub fn validate_template(template: &TemplateIdentity) -> Result<(), ()> {
    crate::openshell::policy::validate_image(template).map(|_| ())
}

/// Validates the policy document integrity against its expected identity.
///
/// The document must be YAML and its SHA-256 must exactly match the expected
/// identity digest. This proves the request carries the attested policy
/// document; it does not claim that Docker Sandboxes enforces it.
pub fn validate_policy_document(
    document: &PolicyDocument,
    identity: &PolicyIdentity,
) -> Result<(), ()> {
    if document.media_type() != "application/yaml" {
        return Err(());
    }
    let digest = Sha256::digest(document.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(encoded, "{byte:02x}").map_err(|_| ())?;
    }
    if encoded != identity.sha256().as_str() {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = include_str!("../../deploy/policies/policy-deny-network.yaml");

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        digest
            .iter()
            .fold(String::with_capacity(64), |mut output, byte| {
                use core::fmt::Write as _;
                write!(output, "{byte:02x}").expect("writing to String cannot fail");
                output
            })
    }

    #[test]
    fn immutable_template_validation_rejects_mutable_or_malformed_references() {
        let valid =
            TemplateIdentity::new(format!("example.invalid/proof@sha256:{}", "a".repeat(64)))
                .unwrap();
        assert_eq!(validate_template(&valid), Ok(()));
        for value in [
            "example.invalid/proof:latest".to_owned(),
            format!("example.invalid/proof@sha256:{}", "A".repeat(64)),
            format!("example.invalid/proof@sha256:{}", "a".repeat(63)),
            "example.invalid/proof@sha256:".to_owned(),
        ] {
            assert!(validate_template(&TemplateIdentity::new(value).unwrap()).is_err());
        }
    }

    #[test]
    fn policy_document_must_match_its_identity_exactly() {
        let document = PolicyDocument::new("application/yaml", POLICY.as_bytes().to_vec()).unwrap();
        let identity = PolicyIdentity::new(
            "openbox-deny-network",
            1,
            crate::Sha256Digest::parse(sha256_hex(POLICY.as_bytes())).unwrap(),
        )
        .unwrap();
        assert_eq!(validate_policy_document(&document, &identity), Ok(()));

        let wrong_digest = PolicyIdentity::new(
            "openbox-deny-network",
            1,
            crate::Sha256Digest::parse("0".repeat(64)).unwrap(),
        )
        .unwrap();
        assert!(validate_policy_document(&document, &wrong_digest).is_err());

        let wrong_media_type =
            PolicyDocument::new("application/json", POLICY.as_bytes().to_vec()).unwrap();
        assert!(validate_policy_document(&wrong_media_type, &identity).is_err());
    }
}
