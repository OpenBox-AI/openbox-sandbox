#![cfg(feature = "serde")]

use crate::{
    Argv, CleanupTarget, CommandTimeout, CreateFailure, CreateFailureCode, CreateRequest,
    DispatchState, ExecCompleted, ExecFailure, ExecFailureCode, ExecRequest, FailureTimeout,
    ObservedExitCode, ObservedTimeout, OperatorDetail, OutputByteCounts, OutputLimits,
    PolicyDocument, PolicyIdentity, RequestOwnedId, Sha256Digest, TemplateIdentity,
};
use serde_json::{Value, json};

fn id() -> RequestOwnedId {
    RequestOwnedId::parse("sbx-550e8400-e29b-41d4-a716-446655440000").unwrap()
}

fn cleanup() -> CleanupTarget {
    CleanupTarget::new(id())
}

fn policy() -> PolicyIdentity {
    PolicyIdentity::new("policy", 1, Sha256Digest::parse("a".repeat(64)).unwrap()).unwrap()
}

fn exec_request() -> ExecRequest {
    ExecRequest::new(
        Argv::new(vec![
            "/bin/echo".to_owned(),
            String::new(),
            "a b".to_owned(),
        ])
        .unwrap(),
        CommandTimeout::default(),
        OutputLimits::new(10, 11, 12, 13).unwrap(),
    )
}

#[test]
fn creation_request_round_trips_strictly_with_base64_policy_bytes() {
    let request = CreateRequest::new(
        id(),
        TemplateIdentity::new("template@immutable").unwrap(),
        PolicyDocument::new("application/yaml", vec![0, 0xff]).unwrap(),
        policy(),
    );
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded["policy_document"]["document_base64"], "AP8=");
    assert_eq!(
        serde_json::from_value::<CreateRequest>(encoded.clone()).unwrap(),
        request
    );

    let mut unknown = encoded;
    unknown
        .as_object_mut()
        .unwrap()
        .insert("providers".to_owned(), json!([]));
    assert!(serde_json::from_value::<CreateRequest>(unknown).is_err());
}

#[test]
fn execution_request_rejects_shell_strings_envelopes_and_invalid_fields() {
    let encoded = serde_json::to_value(exec_request()).unwrap();
    assert_eq!(
        serde_json::from_value::<ExecRequest>(encoded.clone()).unwrap(),
        exec_request()
    );

    let limits = json!({
        "stdout_bytes": 1,
        "stderr_bytes": 1,
        "combined_bytes": 1,
        "chunk_bytes": 1
    });
    for invalid in [
        json!({"argv": "echo unsafe", "timeout": 30, "output_limits": limits}),
        json!({"command": ["echo", "unsafe"], "timeout": 30, "output_limits": limits}),
        json!({"cmd": "echo unsafe", "timeout": 30, "output_limits": limits}),
        json!({"code": "print(1)", "timeout": 30, "output_limits": limits}),
        json!({"argv": [], "timeout": 30, "output_limits": limits}),
        json!({"argv": ["echo", 7], "timeout": 30, "output_limits": limits}),
        json!({"argv": ["echo"], "timeout": 0, "output_limits": limits}),
        json!({"argv": ["echo"], "timeout": 301, "output_limits": limits}),
    ] {
        assert!(serde_json::from_value::<ExecRequest>(invalid).is_err());
    }

    let mut unknown = encoded;
    unknown
        .as_object_mut()
        .unwrap()
        .insert("tty".to_owned(), json!(true));
    assert!(serde_json::from_value::<ExecRequest>(unknown).is_err());

    let zero_limit = json!({
        "argv": ["echo"],
        "timeout": 30,
        "output_limits": {
            "stdout_bytes": 0,
            "stderr_bytes": 1,
            "combined_bytes": 1,
            "chunk_bytes": 1
        }
    });
    assert!(serde_json::from_value::<ExecRequest>(zero_limit).is_err());
}

#[test]
fn raw_output_uses_exact_base64_and_rejects_negative_exit_sentinel() {
    let completed = ExecCompleted::new(
        ObservedExitCode::new(124).unwrap(),
        vec![0, 0xff, b'o'],
        vec![0xfe, b'e'],
        ObservedTimeout::Possible,
    );
    let encoded = serde_json::to_value(&completed).unwrap();
    assert_eq!(encoded["stdout_base64"], "AP9v");
    assert_eq!(encoded["stderr_base64"], "/mU=");
    assert_eq!(
        serde_json::from_value::<ExecCompleted>(encoded.clone()).unwrap(),
        completed
    );

    let mut sentinel = encoded;
    sentinel["exit_code"] = json!(-1);
    assert!(serde_json::from_value::<ExecCompleted>(sentinel).is_err());
}

#[test]
fn failure_serialization_preserves_structural_cleanup_invariants() {
    let not_created = CreateFailure::not_created(
        CreateFailureCode::Validation,
        OperatorDetail::redacted("safe"),
    );
    let encoded = serde_json::to_value(&not_created).unwrap();
    assert_eq!(encoded["state"], "not_created");
    assert!(encoded.get("cleanup_target").is_none());
    assert_eq!(
        serde_json::from_value::<CreateFailure>(encoded.clone()).unwrap(),
        not_created
    );
    let mut unknown = encoded;
    unknown.as_object_mut().unwrap().insert(
        "cleanup_target".to_owned(),
        serde_json::to_value(cleanup()).unwrap(),
    );
    assert!(serde_json::from_value::<CreateFailure>(unknown).is_err());

    let possible = CreateFailure::possibly_created(
        cleanup(),
        CreateFailureCode::Transport,
        OperatorDetail::redacted("safe"),
    );
    let encoded = serde_json::to_value(&possible).unwrap();
    assert_eq!(encoded["state"], "possibly_created");
    assert!(encoded.get("cleanup_target").is_some());
    assert_eq!(
        serde_json::from_value::<CreateFailure>(encoded).unwrap(),
        possible
    );
}

#[test]
fn crafted_execution_failure_cannot_bypass_constructor_rules() {
    let failure = ExecFailure::possibly_dispatched(
        cleanup(),
        ExecFailureCode::Transport,
        FailureTimeout::Unknown,
        OutputByteCounts::new(3, 4),
        OperatorDetail::redacted("safe"),
    )
    .unwrap();
    let encoded = serde_json::to_value(&failure).unwrap();
    assert_eq!(encoded["dispatch_state"], "possibly_dispatched");
    assert_eq!(
        serde_json::from_value::<ExecFailure>(encoded.clone()).unwrap(),
        failure
    );

    let mut invalid_timeout = encoded.clone();
    invalid_timeout["timeout_state"] = json!("not_observed");
    assert!(serde_json::from_value::<ExecFailure>(invalid_timeout).is_err());

    let mut invalid_missing = encoded.clone();
    invalid_missing["dispatch_state"] = json!("not_dispatched");
    invalid_missing["timeout_state"] = json!("not_observed");
    invalid_missing["code"] = json!("missing_terminal_exit");
    invalid_missing["counts"] = json!({"stdout_bytes": 0, "stderr_bytes": 0});
    assert!(serde_json::from_value::<ExecFailure>(invalid_missing).is_err());

    let mut unknown = encoded;
    unknown
        .as_object_mut()
        .unwrap()
        .insert("partial_stdout_base64".to_owned(), json!("c2VjcmV0"));
    assert!(serde_json::from_value::<ExecFailure>(unknown).is_err());
}

#[test]
fn unknown_enum_values_and_invalid_base64_fail_closed() {
    assert!(serde_json::from_str::<RequestOwnedId>("\"sbx-not-a-uuid\"").is_err());
    let mut completed = serde_json::to_value(ExecCompleted::new(
        ObservedExitCode::new(0).unwrap(),
        vec![],
        vec![],
        ObservedTimeout::NotObserved,
    ))
    .unwrap();
    completed["timeout"] = Value::String("unknown".to_owned());
    assert!(serde_json::from_value::<ExecCompleted>(completed).is_err());

    let mut request = serde_json::to_value(CreateRequest::new(
        id(),
        TemplateIdentity::new("template").unwrap(),
        PolicyDocument::new("application/yaml", vec![1]).unwrap(),
        policy(),
    ))
    .unwrap();
    request["policy_document"]["document_base64"] = json!("not-base64!");
    assert!(serde_json::from_value::<CreateRequest>(request).is_err());
}

#[test]
fn serialized_failure_exposes_only_explicitly_sanitized_detail() {
    let failure = ExecFailure::not_dispatched(
        cleanup(),
        ExecFailureCode::Protocol,
        OperatorDetail::redacted("sanitized-code-only"),
    )
    .unwrap();
    let encoded = serde_json::to_string(&failure).unwrap();
    assert!(encoded.contains("sanitized-code-only"));
    assert_eq!(failure.dispatch_state(), DispatchState::NotDispatched);
    assert!(!format!("{failure:?}").contains("sanitized-code-only"));
    assert!(!failure.to_string().contains("sanitized-code-only"));
}
