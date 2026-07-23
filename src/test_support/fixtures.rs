//! Canonical provider-neutral fixtures reused by fake and real-adapter conformance.

use std::time::Duration;

use crate::{
    Argv, CommandTimeout, CreateRequest, ExecRequest, OperationContext, OperationDeadline,
    OutputLimits, PolicyDocument, PolicyIdentity, RequestOwnedId, Sha256Digest, TemplateIdentity,
};
use tokio_util::sync::CancellationToken;

use crate::LifecycleContexts;

/// Returns the canonical adversarial argv fixture without an inserted shell.
pub fn adversarial_argv() -> Argv {
    Argv::new(vec![
        "/bin/proof".to_owned(),
        String::new(),
        "a b".to_owned(),
        "'quoted'".to_owned(),
        "$HOME".to_owned(),
        "semi;colon".to_owned(),
        "雪".to_owned(),
        "/bin/proof".to_owned(),
    ])
    .expect("canonical argv is nonempty")
}

/// Returns canonical stdout bytes containing NUL and invalid UTF-8.
pub fn raw_stdout_fixture() -> Vec<u8> {
    vec![0, 0xff, b'o', b'u', b't']
}

/// Returns canonical stderr bytes containing NUL and invalid UTF-8.
pub fn raw_stderr_fixture() -> Vec<u8> {
    vec![0, 0xfe, b'e', b'r', b'r']
}

/// Returns a deterministic valid request-owned identifier for a nonzero fixture index.
pub fn request_id_fixture(index: u64) -> RequestOwnedId {
    RequestOwnedId::parse(format!("sbx-00000000-0000-4000-8000-{index:012x}"))
        .expect("fixture index produces a valid UUID-v4-shaped ID")
}

/// Returns a deterministic expected policy identity.
pub fn policy_fixture(version: u64) -> PolicyIdentity {
    PolicyIdentity::new(
        "conformance-policy",
        version,
        Sha256Digest::parse(format!("{version:064x}"))
            .expect("fixture version produces a SHA-256-shaped digest"),
    )
    .expect("fixture policy identity is valid")
}

/// Returns the canonical fixed-shape create request.
pub fn create_request_fixture(index: u64) -> CreateRequest {
    CreateRequest::new(
        request_id_fixture(index),
        TemplateIdentity::new("conformance-template@immutable")
            .expect("fixture template is nonempty"),
        PolicyDocument::new("application/yaml", b"version: 1\n".to_vec())
            .expect("fixture policy document is nonempty"),
        policy_fixture(1),
    )
}

/// Returns the canonical execution request with supplied limits.
pub fn exec_request_fixture(limits: OutputLimits) -> ExecRequest {
    ExecRequest::new(adversarial_argv(), CommandTimeout::default(), limits)
}

/// Returns the canonical small positive output limits.
pub fn output_limits_fixture() -> OutputLimits {
    OutputLimits::new(64, 64, 96, 64).expect("canonical output limits are positive")
}

/// Returns five fresh, uncancelled operation contexts.
pub fn lifecycle_contexts_fixture() -> LifecycleContexts {
    LifecycleContexts::new(
        operation_context(),
        operation_context(),
        operation_context(),
        operation_context(),
        operation_context(),
    )
}

/// Returns contexts with execution cancelled before dispatch and fresh cleanup contexts.
pub fn cancelled_exec_contexts_fixture() -> LifecycleContexts {
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    LifecycleContexts::new(
        operation_context(),
        operation_context(),
        OperationContext::new(cancellation, operation_deadline()),
        operation_context(),
        operation_context(),
    )
}

fn operation_context() -> OperationContext {
    OperationContext::new(CancellationToken::new(), operation_deadline())
}

fn operation_deadline() -> OperationDeadline {
    OperationDeadline::new(Duration::from_secs(5)).expect("fixture deadline is positive")
}
