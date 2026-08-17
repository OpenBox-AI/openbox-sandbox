#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::Duration;

use openbox_sandbox::{
    Argv, CommandTimeout, CreateRequest, DeleteOutcome, ExecRequest, ObservedTimeout,
    OperationContext, OperationDeadline, OutputLimits, PolicyDocument, PolicyIdentity,
    RequestOwnedId, SandboxRuntime, Sha256Digest, SrtConfig, SrtRuntime, TemplateIdentity,
    compile_srt_policy,
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
async fn native_srt_enforces_profile_and_preserves_argv_lifecycle() {
    if cfg!(target_os = "linux")
        && std::process::Command::new("bwrap")
            .arg("--version")
            .output()
            .is_err()
    {
        eprintln!("SKIP live native srt: bwrap is absent");
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
    let profile_sha = compile_srt_policy(&policy_path, &profile, &workspace_root).unwrap();
    let policy_bytes = fs::read(&policy_path).unwrap();
    let identity = PolicyIdentity::new(
        "native-srt-deny-network",
        1,
        Sha256Digest::parse(digest(&policy_bytes)).unwrap(),
    )
    .unwrap();
    let runtime = SrtRuntime::new(
        SrtConfig::new(
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
                TemplateIdentity::new("native://srt").unwrap(),
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
    let mut argv = vec![proof.to_string_lossy().into_owned()];
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
                TemplateIdentity::new("native://srt").unwrap(),
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
                TemplateIdentity::new("native://srt").unwrap(),
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
                TemplateIdentity::new("native://srt").unwrap(),
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
                TemplateIdentity::new("native://srt").unwrap(),
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
    if cfg!(target_os = "macos") {
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

fn policy_identity_for(path: &std::path::Path) -> PolicyIdentity {
    let bytes = fs::read(path).unwrap();
    PolicyIdentity::new(
        "native-srt-deny-network",
        1,
        Sha256Digest::parse(digest(&bytes)).unwrap(),
    )
    .unwrap()
}
