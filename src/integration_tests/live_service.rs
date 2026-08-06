#![allow(clippy::doc_markdown, clippy::too_many_lines)]

//! Live real-OpenBox-Sandbox-service integration test (in-crate).
//!
//! Dogfoods the authenticated sandbox service boundary over a real mTLS
//! connection against a running `openbox-sandbox` process. Unlike
//! `tests/live_openshell.rs`, which drives the `OpenShell` gateway directly,
//! this exercises the full local boundary: client → TLS → sandbox service →
//! external `OpenShell` gateway → libkrun microVM.
//!
//! Reads the SDK env contract (`OPENBOX_SANDBOX_*`) — exactly what an OpenBox
//! SDK agent sources from `agent.env` after `provision-local-sandbox.sh`. CI
//! may override any field with the `OPENBOX_LIVE_SERVICE_*` prefix.
//!
//! Skipped when no endpoint is configured. When configured, it drives one
//! complete lifecycle: create -> wait_ready -> exec -> delete -> wait_deleted,
//! observing a real Linux kernel banner from the spawned microVM.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::{
    Argv, AssetBundleIdentity, CommandTimeout, CreateRequest, ExecRequest, OperationContext,
    OperationDeadline, OutputLimits, PolicyDocument, PolicyIdentity, RequestOwnedId,
    SandboxRuntime, TemplateIdentity,
};
use crate::{SandboxRuntimeClient, SandboxRuntimeClientConfig, Sha256Digest};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

fn sdk_key(suffix: &str) -> String {
    format!("OPENBOX_SANDBOX_{suffix}")
}

fn live_key(suffix: &str) -> String {
    format!("OPENBOX_LIVE_SERVICE_{suffix}")
}

/// Read an env override: live-test prefix first, then the SDK contract.
fn env_of(suffix: &str) -> Option<String> {
    std::env::var(live_key(suffix))
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var(sdk_key(suffix))
                .ok()
                .filter(|value| !value.is_empty())
        })
}

fn env_or(suffix: &str, default: &str) -> String {
    env_of(suffix).unwrap_or_else(|| default.to_owned())
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

#[tokio::test]
async fn live_service_create_exec_delete() {
    let Some(endpoint_str) = env_of("ENDPOINT") else {
        eprintln!(
            "SKIP live_service_create_exec_delete: \
             OPENBOX_SANDBOX_ENDPOINT (or OPENBOX_LIVE_SERVICE_ENDPOINT) not set"
        );
        return;
    };
    let endpoint: SocketAddr = endpoint_str.parse().expect("endpoint must be a SocketAddr");
    let server_name = env_or("SERVER_NAME", "localhost");
    let ca = PathBuf::from(env_of("CA").expect("OPENBOX_SANDBOX_CA required when endpoint is set"));
    let cert =
        PathBuf::from(env_of("CERT").expect("OPENBOX_SANDBOX_CERT required when endpoint is set"));
    let key =
        PathBuf::from(env_of("KEY").expect("OPENBOX_SANDBOX_KEY required when endpoint is set"));
    let adapter_sha =
        env_of("ADAPTER_SHA").expect("OPENBOX_SANDBOX_ADAPTER_SHA required when endpoint is set");
    let template =
        env_of("TEMPLATE").expect("OPENBOX_SANDBOX_TEMPLATE required when endpoint is set");
    let policy_file =
        env_of("POLICY_FILE").expect("OPENBOX_SANDBOX_POLICY_FILE required when endpoint is set");
    let policy_id = env_or("POLICY_ID", "openbox-deny-network-dev");
    let policy_version: u64 = env_or("POLICY_VERSION", "1")
        .parse()
        .expect("policy version integer");
    let compat_id = env_or("COMPAT_ID", "darwin-dev-1");
    let command = env_or("CMD", "uname -a");
    let create_secs: u64 = env_or("CREATE_SECS", "120")
        .parse()
        .expect("create secs integer (<=120 — service RPC deadline cap)");
    let exec_secs: u64 = env_or("EXEC_SECS", "60")
        .parse()
        .expect("exec secs integer (<=120)");

    let policy_bytes = std::fs::read(&policy_file).expect("read policy file");
    let policy_sha = sha256_hex(&policy_bytes);
    eprintln!("live_service: endpoint={endpoint} server_name={server_name}");
    eprintln!("live_service: template={template}");
    eprintln!("live_service: policy={policy_file} sha256={policy_sha}");
    eprintln!("live_service: adapter_sha={adapter_sha}");
    eprintln!("live_service: compat_id={compat_id} cmd={command:?}");

    let bundle = AssetBundleIdentity::new(
        1,
        Sha256Digest::parse(adapter_sha.clone()).expect("adapter sha256 shape"),
        TemplateIdentity::new(template.clone()).expect("template"),
        PolicyIdentity::new(
            policy_id.clone(),
            policy_version,
            Sha256Digest::parse(policy_sha.clone()).expect("policy sha256 shape"),
        )
        .expect("policy identity"),
        compat_id,
    )
    .expect("asset bundle identity");

    let client = SandboxRuntimeClient::connect(
        SandboxRuntimeClientConfig::new(endpoint, server_name, ca, cert, key, bundle)
            .expect("client config"),
    )
    .expect("connect to live sandbox service");
    eprintln!("live_service: connected to service boundary; creating sandbox ...");

    let request_id = RequestOwnedId::generate();
    eprintln!(
        "live_service: request_id={} (len={})",
        request_id.as_str(),
        request_id.as_str().len()
    );
    let policy_identity = PolicyIdentity::new(
        policy_id,
        policy_version,
        Sha256Digest::parse(policy_sha).expect("policy sha256 shape"),
    )
    .expect("policy identity");
    let create_request = CreateRequest::new(
        request_id,
        TemplateIdentity::new(template).expect("template"),
        PolicyDocument::new("application/yaml", policy_bytes).expect("policy document"),
        policy_identity.clone(),
    );

    let created = client
        .create(create_request, ctx(create_secs))
        .await
        .expect("real service create must succeed");
    let cleanup_target = created.cleanup_target();
    eprintln!("live_service: created by service; waiting ready ...");

    let ready = client
        .wait_ready(created, policy_identity, ctx(create_secs))
        .await
        .expect("real service wait_ready must succeed");
    eprintln!("live_service: ready; exec: {command}");

    let argv =
        Argv::new(vec!["/bin/sh".to_owned(), "-c".to_owned(), command.clone()]).expect("argv");
    let exec_request = ExecRequest::new(
        argv,
        CommandTimeout::new(30).expect("command timeout"),
        OutputLimits::new(65_536, 65_536, 131_072, 65_536).expect("output limits"),
    );
    let completed = client
        .exec(ready, exec_request, ctx(exec_secs))
        .await
        .expect("real service exec must succeed");
    let stdout = String::from_utf8_lossy(completed.stdout()).to_string();
    eprintln!("live_service: stdout={stdout:?}");
    eprintln!(
        "live_service: exit_code={:?} stdout_bytes={} stderr_bytes={}",
        completed.exit_code(),
        completed.stdout_bytes(),
        completed.stderr_bytes()
    );
    let expected_linux_banner = command.contains("uname");

    client
        .delete(cleanup_target.clone(), ctx(60))
        .await
        .expect("real service delete must succeed");
    client
        .wait_deleted(cleanup_target, ctx(60))
        .await
        .expect("real service wait_deleted must succeed");
    if expected_linux_banner {
        assert!(
            stdout.contains("Linux"),
            "expected real Linux kernel banner in stdout, got {stdout:?}"
        );
    }
    eprintln!(
        "live_service: complete lifecycle \
         (create->wait_ready->exec->delete->wait_deleted) SUCCEEDED"
    );
}
