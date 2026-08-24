#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::Duration;

use openbox_sandbox::{
    Argv, CommandTimeout, CreateRequest, DeleteOutcome, EgressDecisionKind, ExecRequest,
    NativeConfig, NativeRuntime, ObservedTimeout, OperationContext, OperationDeadline,
    OutputLimits, PolicyDocument, PolicyIdentity, RequestOwnedId, SandboxRuntime, Sha256Digest,
    TemplateIdentity, ViolationCategory, compile_native_policy,
};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

fn context(seconds: u64) -> OperationContext {
    OperationContext::new(
        CancellationToken::new(),
        OperationDeadline::new(Duration::from_secs(seconds)).unwrap(),
    )
}

fn digest(bytes: &[u8]) -> String {
    use core::fmt::Write as _;

    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut encoded, byte| {
            write!(encoded, "{byte:02x}").unwrap();
            encoded
        })
}

fn exec(argv: Vec<String>, timeout: u16) -> ExecRequest {
    ExecRequest::new(
        Argv::new(argv).unwrap(),
        CommandTimeout::new(timeout).unwrap(),
        OutputLimits::new(65_536, 65_536, 131_072, 65_536).unwrap(),
    )
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn native_enforces_profile_and_preserves_argv_lifecycle() {
    if cfg!(target_os = "linux")
        && std::process::Command::new("bwrap")
            .arg("--version")
            .output()
            .is_err()
    {
        eprintln!("SKIP live native: bwrap is absent");
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let workspace_root = root.join("workspaces");
    let profile = root.join(if cfg!(target_os = "macos") {
        "policy.sb"
    } else {
        "policy.json"
    });
    let policy_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/policies/policy-deny-network.yaml");
    let profile_sha = compile_native_policy(&policy_path, &profile, &workspace_root).unwrap();
    let policy_bytes = fs::read(&policy_path).unwrap();
    let identity = PolicyIdentity::new(
        "native-deny-network",
        1,
        Sha256Digest::parse(digest(&policy_bytes)).unwrap(),
    )
    .unwrap();
    let runtime = NativeRuntime::new(
        NativeConfig::new(
            &profile,
            Sha256Digest::parse(profile_sha).unwrap(),
            &workspace_root,
            identity.clone(),
        )
        .unwrap(),
    )
    .unwrap();
    let request_id = RequestOwnedId::generate();
    let workspace = workspace_root.join(request_id.as_str());
    let created = runtime
        .create(
            CreateRequest::new(
                request_id.clone(),
                TemplateIdentity::new("native://native").unwrap(),
                PolicyDocument::new("application/yaml", policy_bytes).unwrap(),
                identity.clone(),
            ),
            context(5),
        )
        .await
        .unwrap();
    let cleanup = created.cleanup_target();

    let proof = workspace.join("argv-proof");
    fs::write(
        &proof,
        b"#!/bin/sh\nfor value do printf '%s\\036' \"$value\"; done\n",
    )
    .unwrap();
    fs::set_permissions(&proof, fs::Permissions::from_mode(0o700)).unwrap();
    let ready = runtime
        .wait_ready(created, identity.clone(), context(5))
        .await
        .unwrap();
    let adversarial = vec![
        String::new(),
        "a b".to_owned(),
        "'quoted'".to_owned(),
        "$HOME".to_owned(),
        "semi;colon".to_owned(),
        "雪".to_owned(),
    ];
    let mut argv = vec!["./argv-proof".to_owned()];
    argv.extend(adversarial.clone());
    let completed = runtime
        .exec(ready, exec(argv, 5), context(10))
        .await
        .unwrap();
    assert_eq!(completed.exit_code().get(), 0);
    let expected = adversarial.join("\u{1e}") + "\u{1e}";
    assert_eq!(completed.stdout(), expected.as_bytes());

    let created = runtime
        .create(
            CreateRequest::new(
                RequestOwnedId::generate(),
                TemplateIdentity::new("native://native").unwrap(),
                PolicyDocument::new("application/yaml", fs::read(&policy_path).unwrap()).unwrap(),
                identity.clone(),
            ),
            context(5),
        )
        .await
        .unwrap();
    let timeout_cleanup = created.cleanup_target();
    let ready = runtime
        .wait_ready(created, identity.clone(), context(5))
        .await
        .unwrap();
    let timed_out = runtime
        .exec(
            ready,
            exec(vec!["/bin/sleep".to_owned(), "2".to_owned()], 1),
            context(5),
        )
        .await
        .unwrap();
    assert_eq!(timed_out.exit_code().get(), 124);
    assert_eq!(timed_out.timeout(), ObservedTimeout::Confirmed);

    let created = runtime
        .create(
            CreateRequest::new(
                RequestOwnedId::generate(),
                TemplateIdentity::new("native://native").unwrap(),
                PolicyDocument::new("application/yaml", fs::read(&policy_path).unwrap()).unwrap(),
                identity.clone(),
            ),
            context(5),
        )
        .await
        .unwrap();
    let network_cleanup = created.cleanup_target();
    let ready = runtime
        .wait_ready(created, identity, context(5))
        .await
        .unwrap();
    let network = runtime
        .exec(
            ready,
            exec(
                vec![
                    "/usr/bin/curl".to_owned(),
                    "--connect-timeout".to_owned(),
                    "1".to_owned(),
                    "http://example.com".to_owned(),
                ],
                5,
            ),
            context(10),
        )
        .await
        .unwrap();
    assert_ne!(
        network.exit_code().get(),
        0,
        "deny-network profile blocked egress"
    );

    let victim_id = RequestOwnedId::generate();
    let victim = runtime
        .create(
            CreateRequest::new(
                victim_id.clone(),
                TemplateIdentity::new("native://native").unwrap(),
                PolicyDocument::new("application/yaml", fs::read(&policy_path).unwrap()).unwrap(),
                policy_identity_for(&policy_path),
            ),
            context(5),
        )
        .await
        .unwrap();
    let victim_cleanup = victim.cleanup_target();
    fs::write(
        workspace_root.join(victim_id.as_str()).join("secret"),
        b"sibling-secret",
    )
    .unwrap();
    let attacker = runtime
        .create(
            CreateRequest::new(
                RequestOwnedId::generate(),
                TemplateIdentity::new("native://native").unwrap(),
                PolicyDocument::new("application/yaml", fs::read(&policy_path).unwrap()).unwrap(),
                policy_identity_for(&policy_path),
            ),
            context(5),
        )
        .await
        .unwrap();
    let attacker_cleanup = attacker.cleanup_target();
    let ready = runtime
        .wait_ready(attacker, policy_identity_for(&policy_path), context(5))
        .await
        .unwrap();
    let sibling_read = runtime
        .exec(
            ready,
            exec(
                vec![
                    "/bin/sh".to_owned(),
                    "-c".to_owned(),
                    format!("cat ../{}/secret", victim_id.as_str()),
                ],
                5,
            ),
            context(10),
        )
        .await
        .unwrap();
    assert_ne!(sibling_read.exit_code().get(), 0);
    assert!(
        !sibling_read
            .stdout()
            .windows(14)
            .any(|bytes| bytes == b"sibling-secret")
    );

    if cfg!(target_os = "macos") {
        let sentinel = root.join("outside-sentinel");
        let status = std::process::Command::new("/usr/bin/sandbox-exec")
            .arg("-D")
            .arg(format!("WORKSPACE_ROOT={}", workspace_root.display()))
            .arg("-D")
            .arg(format!("WORKSPACE={}", workspace_root.display()))
            .args(["-f"])
            .arg(&profile)
            .arg("--")
            .args(["/usr/bin/touch"])
            .arg(&sentinel)
            .status()
            .unwrap();
        assert!(!status.success());
        assert!(!sentinel.exists());
    }

    assert_eq!(
        runtime.delete(cleanup.clone(), context(5)).await.unwrap(),
        DeleteOutcome::Deleted
    );
    runtime.wait_deleted(cleanup, context(5)).await.unwrap();
    runtime
        .delete(timeout_cleanup.clone(), context(5))
        .await
        .unwrap();
    runtime
        .wait_deleted(timeout_cleanup, context(5))
        .await
        .unwrap();
    runtime
        .delete(network_cleanup.clone(), context(5))
        .await
        .unwrap();
    runtime
        .wait_deleted(network_cleanup, context(5))
        .await
        .unwrap();
    runtime
        .delete(victim_cleanup.clone(), context(5))
        .await
        .unwrap();
    runtime
        .wait_deleted(victim_cleanup, context(5))
        .await
        .unwrap();
    runtime
        .delete(attacker_cleanup.clone(), context(5))
        .await
        .unwrap();
    runtime
        .wait_deleted(attacker_cleanup, context(5))
        .await
        .unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn native_proxy_filters_pinned_domains_and_fails_closed() {
    if !cfg!(target_os = "macos") {
        eprintln!("SKIP macOS proxy and violation-store conformance");
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();

    let allow_policy = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("deploy/policies/policy-allow-network-dev.yaml");
    let allow_bytes = fs::read(&allow_policy).unwrap();
    let allow_root = root.join("allow-workspaces");
    let allow_profile = root.join("allow.sb");
    let allow_sha = compile_native_policy(&allow_policy, &allow_profile, &allow_root).unwrap();
    let allow_identity = PolicyIdentity::new(
        "native-example-egress",
        1,
        Sha256Digest::parse(digest(&allow_bytes)).unwrap(),
    )
    .unwrap();
    let allow_runtime = NativeRuntime::new(
        NativeConfig::new(
            allow_profile,
            Sha256Digest::parse(allow_sha).unwrap(),
            allow_root,
            allow_identity.clone(),
        )
        .unwrap(),
    )
    .unwrap();

    for (target, expected, expected_host) in [
        (
            "https://example.com/".to_owned(),
            EgressDecisionKind::Allowed,
            "example.com".to_owned(),
        ),
        (
            "https://example.org/".to_owned(),
            EgressDecisionKind::Denied,
            "example.org".to_owned(),
        ),
        (
            "https://93.184.216.34/".to_owned(),
            EgressDecisionKind::Denied,
            "93.184.216.34".to_owned(),
        ),
    ] {
        let request_id = RequestOwnedId::generate();
        let created = allow_runtime
            .create(
                CreateRequest::new(
                    request_id,
                    TemplateIdentity::new("native://native").unwrap(),
                    PolicyDocument::new("application/yaml", allow_bytes.clone()).unwrap(),
                    allow_identity.clone(),
                ),
                context(5),
            )
            .await
            .unwrap();
        let cleanup = created.cleanup_target();
        let ready = allow_runtime
            .wait_ready(created, allow_identity.clone(), context(5))
            .await
            .unwrap();
        let completed = allow_runtime
            .exec(
                ready,
                exec(
                    vec![
                        "/usr/bin/curl".to_owned(),
                        "-sS".to_owned(),
                        "--connect-timeout".to_owned(),
                        "5".to_owned(),
                        "-o".to_owned(),
                        "/dev/null".to_owned(),
                        target,
                    ],
                    10,
                ),
                context(20),
            )
            .await
            .unwrap();
        assert_eq!(
            completed.exit_code().get() == 0,
            expected == EgressDecisionKind::Allowed
        );
        let decision = completed
            .sandbox_evidence()
            .egress_decisions()
            .first()
            .expect("proxy decision evidence");
        assert_eq!(decision.decision(), expected);
        assert_eq!(decision.host(), expected_host);
        assert_eq!(decision.port(), 443);
        allow_runtime
            .delete(cleanup.clone(), context(5))
            .await
            .unwrap();
        allow_runtime
            .wait_deleted(cleanup, context(5))
            .await
            .unwrap();
    }

    // A client that ignores the proxy still has no fallback path: Seatbelt
    // permits only the runtime-selected localhost proxy endpoint.
    let created = allow_runtime
        .create(
            CreateRequest::new(
                RequestOwnedId::generate(),
                TemplateIdentity::new("native://native").unwrap(),
                PolicyDocument::new("application/yaml", allow_bytes.clone()).unwrap(),
                allow_identity.clone(),
            ),
            context(5),
        )
        .await
        .unwrap();
    let cleanup = created.cleanup_target();
    let ready = allow_runtime
        .wait_ready(created, allow_identity, context(5))
        .await
        .unwrap();
    let bypass = allow_runtime
        .exec(
            ready,
            exec(
                vec![
                    "/usr/bin/curl".to_owned(),
                    "-sS".to_owned(),
                    "--noproxy".to_owned(),
                    "*".to_owned(),
                    "--connect-timeout".to_owned(),
                    "2".to_owned(),
                    "-o".to_owned(),
                    "/dev/null".to_owned(),
                    "https://93.184.216.34/".to_owned(),
                ],
                5,
            ),
            context(15),
        )
        .await
        .unwrap();
    assert_ne!(bypass.exit_code().get(), 0);
    assert!(bypass.sandbox_evidence().egress_decisions().is_empty());
    assert!(
        bypass
            .sandbox_evidence()
            .violation()
            .is_some_and(|violation| violation
                .categories()
                .contains(&ViolationCategory::DeniedNetwork))
    );
    allow_runtime
        .delete(cleanup.clone(), context(5))
        .await
        .unwrap();
    allow_runtime
        .wait_deleted(cleanup, context(5))
        .await
        .unwrap();

    let deny_policy =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/policies/policy-deny-network.yaml");
    let deny_bytes = fs::read(&deny_policy).unwrap();
    let deny_root = root.join("deny-workspaces");
    let deny_profile = root.join("deny.sb");
    let deny_sha = compile_native_policy(&deny_policy, &deny_profile, &deny_root).unwrap();
    let deny_identity = PolicyIdentity::new(
        "native-deny-violation",
        1,
        Sha256Digest::parse(digest(&deny_bytes)).unwrap(),
    )
    .unwrap();
    let deny_runtime = NativeRuntime::new(
        NativeConfig::new(
            deny_profile,
            Sha256Digest::parse(deny_sha).unwrap(),
            deny_root,
            deny_identity.clone(),
        )
        .unwrap(),
    )
    .unwrap();
    let created = deny_runtime
        .create(
            CreateRequest::new(
                RequestOwnedId::generate(),
                TemplateIdentity::new("native://native").unwrap(),
                PolicyDocument::new("application/yaml", deny_bytes).unwrap(),
                deny_identity.clone(),
            ),
            context(5),
        )
        .await
        .unwrap();
    let cleanup = created.cleanup_target();
    let ready = deny_runtime
        .wait_ready(created, deny_identity, context(5))
        .await
        .unwrap();
    let forbidden = format!("/tmp/openbox-native-violation-{}", std::process::id());
    let completed = deny_runtime
        .exec(
            ready,
            exec(vec!["/usr/bin/touch".to_owned(), forbidden.clone()], 5),
            context(15),
        )
        .await
        .unwrap();
    assert_ne!(completed.exit_code().get(), 0);
    assert!(!std::path::Path::new(&forbidden).exists());
    let violation = completed
        .sandbox_evidence()
        .violation()
        .expect("macOS violation-store evidence");
    assert!(violation.count() >= 1);
    assert!(
        violation
            .categories()
            .contains(&ViolationCategory::DeniedFileWrite)
    );
    deny_runtime
        .delete(cleanup.clone(), context(5))
        .await
        .unwrap();
    deny_runtime
        .wait_deleted(cleanup, context(5))
        .await
        .unwrap();
}

#[tokio::test]
async fn native_violation_store_reports_denied_write() {
    if !cfg!(target_os = "macos") {
        eprintln!("SKIP macOS violation-store conformance");
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let policy_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/policies/policy-deny-network.yaml");
    let policy_bytes = fs::read(&policy_path).unwrap();
    let workspace_root = root.join("workspaces");
    let profile = root.join("policy.sb");
    let profile_sha = compile_native_policy(&policy_path, &profile, &workspace_root).unwrap();
    let identity = PolicyIdentity::new(
        "native-violation-conformance",
        1,
        Sha256Digest::parse(digest(&policy_bytes)).unwrap(),
    )
    .unwrap();
    let runtime = NativeRuntime::new(
        NativeConfig::new(
            profile,
            Sha256Digest::parse(profile_sha).unwrap(),
            workspace_root,
            identity.clone(),
        )
        .unwrap(),
    )
    .unwrap();
    let created = runtime
        .create(
            CreateRequest::new(
                RequestOwnedId::generate(),
                TemplateIdentity::new("native://native").unwrap(),
                PolicyDocument::new("application/yaml", policy_bytes).unwrap(),
                identity.clone(),
            ),
            context(5),
        )
        .await
        .unwrap();
    let cleanup = created.cleanup_target();
    let ready = runtime
        .wait_ready(created, identity, context(5))
        .await
        .unwrap();
    let target = format!(
        "/tmp/openbox-native-violation-scenario-{}",
        std::process::id()
    );
    let completed = runtime
        .exec(
            ready,
            exec(vec!["/usr/bin/touch".to_owned(), target.clone()], 5),
            context(15),
        )
        .await
        .unwrap();
    assert_ne!(completed.exit_code().get(), 0);
    assert!(!std::path::Path::new(&target).exists());
    let evidence = completed.sandbox_evidence().violation().unwrap();
    assert!(evidence.count() >= 1);
    assert!(
        evidence
            .categories()
            .contains(&ViolationCategory::DeniedFileWrite)
    );
    runtime.delete(cleanup.clone(), context(5)).await.unwrap();
    runtime.wait_deleted(cleanup, context(5)).await.unwrap();
}

fn policy_identity_for(path: &std::path::Path) -> PolicyIdentity {
    let bytes = fs::read(path).unwrap();
    PolicyIdentity::new(
        "native-deny-network",
        1,
        Sha256Digest::parse(digest(&bytes)).unwrap(),
    )
    .unwrap()
}
