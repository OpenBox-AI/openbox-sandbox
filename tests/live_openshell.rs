#![allow(clippy::doc_markdown, clippy::too_many_lines)]

//! Live real-OpenShell integration test.
//!
//! Skipped when `OPENBOX_LIVE_OPENSHELL_ENDPOINT` is unset so `cargo test` on a
//! bare checkout doesn't require an external gateway. When the env is set, this
//! test **must** connect to that gateway and drive a real create → wait_ready
//! → exec → delete → wait_deleted lifecycle end-to-end. No fakes.
//!
//! Purpose: this is the specific class of drift the fake-runtime-only test
//! surface let slip (broker's `RequestOwnedId` diverged from the OpenShell
//! gateway's `MAX_ROUTABLE_NAME_LEN` and nothing caught it). This test binds
//! the two together with an actual wire handshake.
//!
//! Required env:
//!   OPENBOX_LIVE_OPENSHELL_ENDPOINT       e.g. http://127.0.0.1:18081
//!   OPENBOX_LIVE_OPENSHELL_IMAGE          repo@sha256:<64hex>
//!   OPENBOX_LIVE_OPENSHELL_POLICY_FILE    path to a policy YAML that meets the floor
//!
//! Optional env:
//!   OPENBOX_LIVE_OPENSHELL_MTLS_DIR       required unless _INSECURE=1
//!   OPENBOX_LIVE_OPENSHELL_INSECURE       "1" to skip mTLS (dev gateway `--disable-tls`)
//!   OPENBOX_LIVE_OPENSHELL_POLICY_ID      default: openbox-deny-network-dev
//!   OPENBOX_LIVE_OPENSHELL_POLICY_VERSION default: 1
//!   OPENBOX_LIVE_OPENSHELL_DEGRADED_LANDLOCK default: 1
//!   OPENBOX_LIVE_OPENSHELL_CMD            default: uname -a
//!   OPENBOX_LIVE_OPENSHELL_CREATE_SECS    default: 300 (microVM boot can be slow)
//!   OPENBOX_LIVE_OPENSHELL_EXEC_SECS      default: 60

use std::path::PathBuf;
use std::time::Duration;

use openbox_sandbox::{
    Argv, CommandTimeout, CreateRequest, ExecRequest, OpenShellConfig, OpenShellRuntime,
    OperationContext, OperationDeadline, OutputLimits, PolicyDocument, PolicyIdentity,
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

/// Shared connection helper for the real-gateway tests below.
async fn connect_from_env() -> Option<(
    OpenShellRuntime,
    Vec<u8>,
    String,
    PolicyIdentity,
    TemplateIdentity,
)> {
    let endpoint = env_optional("OPENBOX_LIVE_OPENSHELL_ENDPOINT")?;
    let image = env_optional("OPENBOX_LIVE_OPENSHELL_IMAGE")
        .expect("OPENBOX_LIVE_OPENSHELL_IMAGE required when endpoint is set");
    let policy_file = env_optional("OPENBOX_LIVE_OPENSHELL_POLICY_FILE")
        .expect("OPENBOX_LIVE_OPENSHELL_POLICY_FILE required when endpoint is set");
    let policy_id = env_or(
        "OPENBOX_LIVE_OPENSHELL_POLICY_ID",
        "openbox-deny-network-dev",
    );
    let policy_version: u64 = env_or("OPENBOX_LIVE_OPENSHELL_POLICY_VERSION", "1")
        .parse()
        .expect("policy version integer");
    let insecure = env_or("OPENBOX_LIVE_OPENSHELL_INSECURE", "0") == "1";
    let degraded = env_or("OPENBOX_LIVE_OPENSHELL_DEGRADED_LANDLOCK", "1") == "1";
    let mtls_dir = PathBuf::from(env_or("OPENBOX_LIVE_OPENSHELL_MTLS_DIR", "/tmp"));

    let policy_bytes = std::fs::read(&policy_file).expect("read policy file");
    let policy_sha = sha256_hex(&policy_bytes);

    let mut cfg = OpenShellConfig::new(endpoint, mtls_dir)
        .expect("config")
        .with_connect_timeout(Duration::from_secs(10))
        .expect("connect_timeout")
        .with_poll_interval(Duration::from_millis(500))
        .expect("poll_interval");
    if degraded {
        cfg = cfg.with_degraded_landlock(true);
    }
    if insecure {
        cfg = cfg.with_insecure_gateway(true);
    }

    let runtime = OpenShellRuntime::connect(cfg)
        .await
        .expect("real openshell gateway must be reachable");
    let template = TemplateIdentity::new(image).expect("template");
    let policy_identity = PolicyIdentity::new(
        policy_id,
        policy_version,
        Sha256Digest::parse(policy_sha.clone()).expect("sha256 shape"),
    )
    .expect("policy identity");
    Some((runtime, policy_bytes, policy_sha, policy_identity, template))
}

#[tokio::test]
#[ignore = "requires a live OpenShell endpoint: set OPENBOX_LIVE_OPENSHELL_ENDPOINT, then `cargo test -- --ignored`"]
async fn live_openshell_create_exec_delete() {
    let Some(endpoint) = env_optional("OPENBOX_LIVE_OPENSHELL_ENDPOINT") else {
        eprintln!(
            "SKIP live_openshell_create_exec_delete: \
             OPENBOX_LIVE_OPENSHELL_ENDPOINT not set"
        );
        return;
    };
    let image = env_optional("OPENBOX_LIVE_OPENSHELL_IMAGE")
        .expect("OPENBOX_LIVE_OPENSHELL_IMAGE required when endpoint is set");
    let policy_file = env_optional("OPENBOX_LIVE_OPENSHELL_POLICY_FILE")
        .expect("OPENBOX_LIVE_OPENSHELL_POLICY_FILE required when endpoint is set");
    let policy_id = env_or(
        "OPENBOX_LIVE_OPENSHELL_POLICY_ID",
        "openbox-deny-network-dev",
    );
    let policy_version: u64 = env_or("OPENBOX_LIVE_OPENSHELL_POLICY_VERSION", "1")
        .parse()
        .expect("policy version must be an integer");
    let insecure = env_or("OPENBOX_LIVE_OPENSHELL_INSECURE", "0") == "1";
    let degraded = env_or("OPENBOX_LIVE_OPENSHELL_DEGRADED_LANDLOCK", "1") == "1";
    let command = env_or("OPENBOX_LIVE_OPENSHELL_CMD", "uname -a");
    let create_secs: u64 = env_or("OPENBOX_LIVE_OPENSHELL_CREATE_SECS", "300")
        .parse()
        .expect("create secs integer");
    let exec_secs: u64 = env_or("OPENBOX_LIVE_OPENSHELL_EXEC_SECS", "60")
        .parse()
        .expect("exec secs integer");
    let mtls_dir = PathBuf::from(env_or("OPENBOX_LIVE_OPENSHELL_MTLS_DIR", "/tmp"));

    let policy_bytes = std::fs::read(&policy_file).expect("read policy file");
    let policy_sha = sha256_hex(&policy_bytes);

    eprintln!("live_openshell: endpoint={endpoint} insecure={insecure} degraded={degraded}");
    eprintln!("live_openshell: image={image}");
    eprintln!("live_openshell: policy={policy_file} sha256={policy_sha}");

    let mut cfg = OpenShellConfig::new(endpoint, mtls_dir)
        .expect("config")
        .with_connect_timeout(Duration::from_secs(10))
        .expect("connect_timeout")
        .with_poll_interval(Duration::from_millis(500))
        .expect("poll_interval");
    if degraded {
        cfg = cfg.with_degraded_landlock(true);
    }
    if insecure {
        cfg = cfg.with_insecure_gateway(true);
    }

    let runtime = OpenShellRuntime::connect(cfg)
        .await
        .expect("real openshell gateway must be reachable");

    let request_id = RequestOwnedId::generate();
    eprintln!(
        "live_openshell: request_id={} (len={})",
        request_id.as_str(),
        request_id.as_str().len()
    );
    assert_eq!(
        request_id.as_str().len(),
        19,
        "broker id must fit OpenShell MAX_ROUTABLE_NAME_LEN"
    );

    let template = TemplateIdentity::new(image).expect("template");
    let policy_document =
        PolicyDocument::new("application/yaml", policy_bytes).expect("policy document");
    let policy_identity = PolicyIdentity::new(
        policy_id,
        policy_version,
        Sha256Digest::parse(policy_sha).expect("sha256 shape"),
    )
    .expect("policy identity");
    let create_request = CreateRequest::new(
        request_id,
        template,
        policy_document,
        policy_identity.clone(),
    );

    let created = runtime
        .create(create_request, ctx(create_secs))
        .await
        .expect("real create must succeed");
    let cleanup_target = created.cleanup_target();
    eprintln!("live_openshell: created; waiting ready ...");

    let exec_and_cleanup = async {
        let ready = runtime
            .wait_ready(created, policy_identity, ctx(create_secs))
            .await
            .expect("real wait_ready must succeed");
        eprintln!("live_openshell: ready; exec: {command}");

        let argv =
            Argv::new(vec!["/bin/sh".to_owned(), "-c".to_owned(), command.clone()]).expect("argv");
        let exec_request = ExecRequest::new(
            argv,
            CommandTimeout::new(30).expect("command timeout"),
            OutputLimits::new(65_536, 65_536, 131_072, 65_536).expect("output limits"),
        );
        let completed = runtime
            .exec(ready, exec_request, ctx(exec_secs))
            .await
            .expect("real exec must succeed");
        let stdout = String::from_utf8_lossy(completed.stdout()).to_string();
        eprintln!("live_openshell: stdout={stdout:?}");
        eprintln!(
            "live_openshell: exit_code={:?} stdout_bytes={} stderr_bytes={}",
            completed.exit_code(),
            completed.stdout_bytes(),
            completed.stderr_bytes()
        );
        // Real proof: uname stdout contains "Linux" from a real guest kernel.
        if command.contains("uname") {
            assert!(
                stdout.contains("Linux"),
                "expected real Linux kernel banner in stdout, got {stdout:?}"
            );
        }
    };

    exec_and_cleanup.await;

    runtime
        .delete(cleanup_target.clone(), ctx(60))
        .await
        .expect("real delete must succeed");
    runtime
        .wait_deleted(cleanup_target, ctx(60))
        .await
        .expect("real wait_deleted must succeed");
}

/// Real gateway: a non-zero-exit exec must be surfaced as `ExecCompleted` with
/// the real exit code, not swallowed. Cleanup must still succeed.
#[tokio::test]
#[ignore = "requires a live OpenShell endpoint: set OPENBOX_LIVE_OPENSHELL_ENDPOINT, then `cargo test -- --ignored`"]
async fn live_openshell_exec_reports_real_nonzero_exit() {
    let Some((runtime, policy_bytes, _sha, policy_identity, template)) = connect_from_env().await
    else {
        eprintln!("SKIP live_openshell_exec_reports_real_nonzero_exit");
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
        "live_openshell_exec_reports_real_nonzero_exit: exit={:?} stdout_bytes={} stderr_bytes={}",
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

/// Real gateway: a policy that violates the security floor (here: a
/// `hard_requirement` Landlock policy submitted without the degraded tier
/// enabled) must be rejected by the broker BEFORE any gateway call, with no
/// sandbox created. This is the security-floor invariant, proven against real
/// components rather than a fake runtime.
#[tokio::test]
#[ignore = "requires a live OpenShell endpoint: set OPENBOX_LIVE_OPENSHELL_ENDPOINT, then `cargo test -- --ignored`"]
async fn live_openshell_floor_rejects_mismatched_policy() {
    let Some(endpoint) = env_optional("OPENBOX_LIVE_OPENSHELL_ENDPOINT") else {
        eprintln!("SKIP live_openshell_floor_rejects_mismatched_policy");
        return;
    };
    let image = env_optional("OPENBOX_LIVE_OPENSHELL_IMAGE")
        .expect("OPENBOX_LIVE_OPENSHELL_IMAGE required");
    let insecure = env_or("OPENBOX_LIVE_OPENSHELL_INSECURE", "0") == "1";
    let mtls_dir = PathBuf::from(env_or("OPENBOX_LIVE_OPENSHELL_MTLS_DIR", "/tmp"));

    // A best_effort policy submitted WITHOUT with_degraded_landlock(true) must
    // be rejected by the floor. Same YAML as the passing test, opposite tier.
    let policy_file = env_optional("OPENBOX_LIVE_OPENSHELL_POLICY_FILE")
        .expect("OPENBOX_LIVE_OPENSHELL_POLICY_FILE required");
    let policy_bytes = std::fs::read(&policy_file).expect("read policy file");
    let policy_sha = sha256_hex(&policy_bytes);

    let mut cfg = OpenShellConfig::new(endpoint, mtls_dir)
        .expect("config")
        .with_connect_timeout(Duration::from_secs(10))
        .expect("connect_timeout")
        .with_poll_interval(Duration::from_millis(500))
        .expect("poll_interval");
    // NOTE: NOT calling with_degraded_landlock(true) — that's the point.
    if insecure {
        cfg = cfg.with_insecure_gateway(true);
    }
    let runtime = OpenShellRuntime::connect(cfg)
        .await
        .expect("gateway reachable");

    let request_id = RequestOwnedId::generate();
    let create_request = CreateRequest::new(
        request_id,
        TemplateIdentity::new(image).expect("template"),
        PolicyDocument::new("application/yaml", policy_bytes).expect("policy document"),
        PolicyIdentity::new(
            env_or(
                "OPENBOX_LIVE_OPENSHELL_POLICY_ID",
                "openbox-deny-network-dev",
            ),
            env_or("OPENBOX_LIVE_OPENSHELL_POLICY_VERSION", "1")
                .parse()
                .expect("policy version integer"),
            Sha256Digest::parse(policy_sha).expect("sha256 shape"),
        )
        .expect("policy identity"),
    );
    let result = runtime.create(create_request, ctx(60)).await;
    match result {
        Ok(created) => {
            // Shouldn't happen: floor should have rejected before submission.
            let _ = runtime.delete(created.cleanup_target(), ctx(60)).await;
            panic!("floor MUST reject best_effort policy without with_degraded_landlock(true)");
        }
        Err(failure) => {
            eprintln!(
                "live_openshell_floor_rejects_mismatched_policy: expected reject, code={:?}",
                failure.code()
            );
            assert!(
                failure.cleanup_target().is_none(),
                "floor rejection must be pre-submission (no cleanup target)"
            );
        }
    }
}
