#![allow(clippy::doc_markdown, clippy::too_many_lines)]

//! Live real-Docker-Sandboxes integration test.
//!
//! Skipped when `OPENBOX_LIVE_DOCKER_SANDBOXES_IMAGE` is unset so `cargo test`
//! on a bare checkout doesn't require an external runtime. When the env is
//! set, this test **must** drive a real create → wait_ready → exec → delete →
//! wait_deleted lifecycle end-to-end through the standalone `sbx` CLI. No
//! fakes.
//!
//! Host prerequisites (documented in `docs/design/docker-sandboxes-runtime.md`):
//!   brew trust docker/tap && brew install docker/tap/sbx
//!   sbx login                                   # Docker account OAuth, one-time
//!   sbx policy init deny-all                    # one-time global network policy
//!   sbx diagnose                                # all checks pass
//!
//! Required env:
//!   OPENBOX_LIVE_DOCKER_SANDBOXES_IMAGE         image reference for --template
//!                                               (repo@sha256:<64hex> or a tag)
//!
//! Optional env:
//!   OPENBOX_LIVE_DOCKER_SANDBOXES_SBX          default: sbx (or an absolute path)
//!   OPENBOX_LIVE_DOCKER_SANDBOXES_WORKSPACE    default: fresh tempdir (auto-created)
//!   OPENBOX_LIVE_DOCKER_SANDBOXES_POLICY_FILE  default: deploy/policies/policy-deny-network.yaml
//!   OPENBOX_LIVE_DOCKER_SANDBOXES_POLICY_ID    default: openbox-deny-network
//!   OPENBOX_LIVE_DOCKER_SANDBOXES_POLICY_VERSION default: 1
//!   OPENBOX_LIVE_DOCKER_SANDBOXES_CMD          default: uname -a
//!   OPENBOX_LIVE_DOCKER_SANDBOXES_PROBE        e.g. "/bin/true" to enable the
//!                                               readiness probe (space-split argv)
//!   OPENBOX_LIVE_DOCKER_SANDBOXES_EXEC_USER    user for sbx exec --user
//!   OPENBOX_LIVE_DOCKER_SANDBOXES_CREATE_SECS  default: 300 (first VM boot pulls
//!                                               the image and can be slow)
//!   OPENBOX_LIVE_DOCKER_SANDBOXES_EXEC_SECS    default: 60
//!
//! The `_CMD` default (`uname -a`) is a real kernel proof: Docker Sandboxes
//! runs each sandbox in a microVM, so stdout must contain a Linux banner.

use std::path::PathBuf;
use std::time::Duration;

use openbox_sandbox::{
    Argv, CommandTimeout, CreateRequest, DockerSandboxesConfig, DockerSandboxesRuntime,
    ExecRequest, OperationContext, OperationDeadline, OutputLimits, PolicyDocument, PolicyIdentity,
    RequestOwnedId, SandboxRuntime, Sha256Digest, TemplateIdentity,
};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

fn env_optional(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

fn env_or(key: &str, default: &str) -> String {
    env_optional(key).unwrap_or_else(|| default.to_owned())
}

fn ctx(seconds: u64) -> OperationContext {
    OperationContext::new(
        CancellationToken::new(),
        OperationDeadline::new(Duration::from_secs(seconds)).expect("deadline positive"),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

/// Shared connection helper for the real-sbx tests below.
async fn connect_from_env() -> Option<(
    DockerSandboxesRuntime,
    Vec<u8>,
    PolicyIdentity,
    TemplateIdentity,
    Option<tempfile::TempDir>,
)> {
    let image = env_optional("OPENBOX_LIVE_DOCKER_SANDBOXES_IMAGE")?;
    let sbx_binary = env_or("OPENBOX_LIVE_DOCKER_SANDBOXES_SBX", "sbx");
    let policy_file = env_or(
        "OPENBOX_LIVE_DOCKER_SANDBOXES_POLICY_FILE",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/deploy/policies/policy-deny-network.yaml"
        ),
    );
    let policy_id = env_or(
        "OPENBOX_LIVE_DOCKER_SANDBOXES_POLICY_ID",
        "openbox-deny-network",
    );
    let policy_version: u64 = env_or("OPENBOX_LIVE_DOCKER_SANDBOXES_POLICY_VERSION", "1")
        .parse()
        .expect("policy version integer");
    let (workspace, workspace_guard) = env_optional("OPENBOX_LIVE_DOCKER_SANDBOXES_WORKSPACE")
        .map_or_else(
            || {
                let guard = tempfile::tempdir().expect("tempdir");
                let path = guard.path().canonicalize().expect("canonical workspace");
                (path, Some(guard))
            },
            |path| (PathBuf::from(path), None),
        );

    let policy_bytes = std::fs::read(&policy_file).expect("read policy file");
    let policy_sha = sha256_hex(&policy_bytes);

    let mut config = DockerSandboxesConfig::new(sbx_binary, workspace)
        .expect("docker sandboxes config")
        .with_connect_timeout(Duration::from_secs(10))
        .expect("connect timeout")
        .with_poll_interval(Duration::from_millis(500))
        .expect("poll interval");
    if let Some(user) = env_optional("OPENBOX_LIVE_DOCKER_SANDBOXES_EXEC_USER") {
        config = config
            .with_exec_user(user)
            .expect("exec user must be valid");
    }
    if let Some(probe) = env_optional("OPENBOX_LIVE_DOCKER_SANDBOXES_PROBE") {
        config = config
            .with_readiness_probe(Some(
                Argv::new(probe.split_whitespace().map(str::to_owned).collect())
                    .expect("probe argv nonempty"),
            ))
            .expect("probe must be valid");
    }

    let runtime = DockerSandboxesRuntime::connect(config)
        .await
        .expect("real sbx CLI must be installed and reachable");
    let template = TemplateIdentity::new(image).expect("template");
    let policy_identity = PolicyIdentity::new(
        policy_id,
        policy_version,
        Sha256Digest::parse(policy_sha).expect("sha256 shape"),
    )
    .expect("policy identity");
    Some((
        runtime,
        policy_bytes,
        policy_identity,
        template,
        workspace_guard,
    ))
}

/// Real sbx: full create → wait_ready → exec → delete → wait_deleted lifecycle.
#[tokio::test]
async fn live_docker_sandboxes_create_exec_delete() {
    let Some((runtime, policy_bytes, policy_identity, template, _workspace_guard)) =
        connect_from_env().await
    else {
        eprintln!("SKIP live_docker_sandboxes_create_exec_delete");
        return;
    };
    let command = env_or("OPENBOX_LIVE_DOCKER_SANDBOXES_CMD", "uname -a");
    let create_secs: u64 = env_or("OPENBOX_LIVE_DOCKER_SANDBOXES_CREATE_SECS", "300")
        .parse()
        .expect("create secs integer");
    let exec_secs: u64 = env_or("OPENBOX_LIVE_DOCKER_SANDBOXES_EXEC_SECS", "60")
        .parse()
        .expect("exec secs integer");

    let request_id = RequestOwnedId::generate();
    eprintln!("live_docker_sandboxes: request_id={}", request_id.as_str());

    let create_request = CreateRequest::new(
        request_id,
        template,
        PolicyDocument::new("application/yaml", policy_bytes).expect("policy document"),
        policy_identity.clone(),
    );

    let created = runtime
        .create(create_request, ctx(create_secs))
        .await
        .expect("real create must succeed");
    let cleanup_target = created.cleanup_target();
    eprintln!("live_docker_sandboxes: created; waiting ready ...");

    let ready = runtime
        .wait_ready(created, policy_identity, ctx(create_secs))
        .await
        .expect("real wait_ready must succeed");
    eprintln!("live_docker_sandboxes: ready; exec: {command}");

    let argv =
        Argv::new(vec!["/bin/sh".to_owned(), "-c".to_owned(), command.clone()]).expect("argv");
    let exec_request = ExecRequest::new(
        argv,
        CommandTimeout::new(60).expect("command timeout"),
        OutputLimits::new(65_536, 65_536, 131_072, 65_536).expect("output limits"),
    );
    let completed = runtime
        .exec(ready, exec_request, ctx(exec_secs))
        .await
        .expect("real exec must succeed");
    let stdout = String::from_utf8_lossy(completed.stdout()).to_string();
    eprintln!(
        "live_docker_sandboxes: exit_code={:?} stdout_bytes={} stderr_bytes={}",
        completed.exit_code(),
        completed.stdout_bytes(),
        completed.stderr_bytes()
    );
    eprintln!("live_docker_sandboxes: stdout={stdout:?}");
    // Real proof: uname stdout contains "Linux" from a real microVM kernel.
    if command.contains("uname") {
        assert!(
            stdout.contains("Linux"),
            "expected real Linux kernel banner in stdout, got {stdout:?}"
        );
    }

    runtime
        .delete(cleanup_target.clone(), ctx(60))
        .await
        .expect("real delete must succeed");
    runtime
        .wait_deleted(cleanup_target, ctx(60))
        .await
        .expect("real wait_deleted must succeed");
}

/// Real sbx: a non-zero-exit exec must be surfaced as `ExecCompleted` with the
/// real exit code, not swallowed. Cleanup must still succeed.
#[tokio::test]
async fn live_docker_sandboxes_exec_reports_real_nonzero_exit() {
    let Some((runtime, policy_bytes, policy_identity, template, _workspace_guard)) =
        connect_from_env().await
    else {
        eprintln!("SKIP live_docker_sandboxes_exec_reports_real_nonzero_exit");
        return;
    };
    let request_id = RequestOwnedId::generate();
    let create_request = CreateRequest::new(
        request_id,
        template,
        PolicyDocument::new("application/yaml", policy_bytes).expect("policy document"),
        policy_identity.clone(),
    );
    let created = runtime
        .create(create_request, ctx(300))
        .await
        .expect("real create must succeed");
    let cleanup_target = created.cleanup_target();
    let ready = runtime
        .wait_ready(created, policy_identity, ctx(300))
        .await
        .expect("real wait_ready must succeed");

    let argv = Argv::new(vec![
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        "exit 42".to_owned(),
    ])
    .expect("argv");
    let exec_request = ExecRequest::new(
        argv,
        CommandTimeout::new(30).expect("command timeout"),
        OutputLimits::new(65_536, 65_536, 131_072, 65_536).expect("output limits"),
    );
    let completed = runtime
        .exec(ready, exec_request, ctx(60))
        .await
        .expect("real exec must return a completed observation");
    eprintln!(
        "live_docker_sandboxes_exec_reports_real_nonzero_exit: exit={:?} stdout_bytes={} stderr_bytes={}",
        completed.exit_code(),
        completed.stdout_bytes(),
        completed.stderr_bytes()
    );
    assert_eq!(
        format!("{:?}", completed.exit_code()),
        "ObservedExitCode(42)",
        "real nonzero exit code must surface unchanged"
    );

    runtime
        .delete(cleanup_target.clone(), ctx(60))
        .await
        .expect("real delete must succeed");
    runtime
        .wait_deleted(cleanup_target, ctx(60))
        .await
        .expect("real wait_deleted must succeed");
}
