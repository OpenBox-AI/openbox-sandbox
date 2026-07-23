use crate::{
    CleanupFailure, CleanupFailureCode, CleanupTarget, CreateFailure, CreateFailureCode,
    CreatedSandbox, CreationState, DispatchState, ExecFailure, ExecFailureCode, FailureTimeout,
    OpaqueProviderHandle, OperatorDetail, OutputByteCounts, OutputLimitKind, PolicyIdentity,
    ReadinessFailure, ReadinessFailureCode, ReadySandbox, RequestOwnedId, Sha256Digest,
    ValidationCode,
};
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(CreatedSandbox: Clone);
assert_not_impl_any!(ReadySandbox: Clone);
assert_not_impl_any!(OpaqueProviderHandle: Clone);

fn id() -> RequestOwnedId {
    RequestOwnedId::parse("sbx-550e8400-e29b-41d4-a716-446655440000").unwrap()
}

fn cleanup() -> CleanupTarget {
    CleanupTarget::new(id())
}

fn detail() -> OperatorDetail {
    OperatorDetail::redacted("SECRET_ARG SECRET_OUTPUT")
}

fn policy() -> PolicyIdentity {
    PolicyIdentity::new("candidate", 1, Sha256Digest::parse("a".repeat(64)).unwrap()).unwrap()
}

#[test]
fn creation_variants_make_cleanup_ownership_structural() {
    let not_created = CreateFailure::not_created(CreateFailureCode::Validation, detail());
    assert_eq!(not_created.state(), CreationState::NotCreated);
    assert!(not_created.cleanup_target().is_none());

    let possible =
        CreateFailure::possibly_created(cleanup(), CreateFailureCode::Transport, detail());
    assert_eq!(possible.state(), CreationState::PossiblyCreated);
    assert_eq!(possible.cleanup_target(), Some(&cleanup()));

    let conflict = CreateFailure::conflict(CreateFailureCode::Provider, detail());
    assert_eq!(conflict.state(), CreationState::Conflict);
    assert!(conflict.cleanup_target().is_none());
}

#[test]
fn lifecycle_handles_are_consuming_and_policy_attestation_is_exact() {
    let created = CreatedSandbox::from_runtime(
        id(),
        OpaqueProviderHandle::new(b"provider-id".to_vec()).unwrap(),
        policy(),
    );
    assert_eq!(created.cleanup_target(), cleanup());
    assert!(!format!("{created:?}").contains("provider-id"));

    let mismatched =
        PolicyIdentity::new("candidate", 2, Sha256Digest::parse("a".repeat(64)).unwrap()).unwrap();
    let created = ReadySandbox::attest(created, mismatched.clone(), &mismatched).unwrap_err();
    assert_eq!(created.cleanup_target(), cleanup());
    assert_eq!(created.expected_policy(), &policy());

    let expected = policy();
    let ready = ReadySandbox::attest(created, expected.clone(), &expected).unwrap();
    assert_eq!(ready.active_policy(), &expected);
    assert_eq!(ready.cleanup_target(), cleanup());
    assert_eq!(ready.provider_handle().as_bytes(), b"provider-id");
    assert!(!format!("{ready:?}").contains("provider-id"));
}

#[test]
fn post_create_failures_always_retain_cleanup_target() {
    let readiness =
        ReadinessFailure::new(cleanup(), ReadinessFailureCode::PolicyMismatch, detail());
    assert_eq!(readiness.cleanup_target(), &cleanup());

    let cleanup_failure = CleanupFailure::new(cleanup(), CleanupFailureCode::Transport, detail());
    assert_eq!(cleanup_failure.cleanup_target(), &cleanup());
}

#[test]
fn predispatch_failure_cannot_claim_indeterminate_evidence() {
    let failure =
        ExecFailure::not_dispatched(cleanup(), ExecFailureCode::Cancelled, detail()).unwrap();
    assert_eq!(failure.dispatch_state(), DispatchState::NotDispatched);
    assert_eq!(failure.timeout_state(), FailureTimeout::NotObserved);
    assert_eq!(failure.counts(), OutputByteCounts::default());
    assert!(failure.output_limit().is_none());

    let invalid =
        ExecFailure::not_dispatched(cleanup(), ExecFailureCode::MissingTerminalExit, detail())
            .unwrap_err();
    assert_eq!(invalid.code(), ValidationCode::InvalidCombination);
}

#[test]
fn ambiguous_failure_requires_unknown_or_positive_timeout_evidence() {
    assert!(
        ExecFailure::possibly_dispatched(
            cleanup(),
            ExecFailureCode::Transport,
            FailureTimeout::NotObserved,
            OutputByteCounts::new(1, 2),
            detail(),
        )
        .is_err()
    );

    let failure = ExecFailure::possibly_dispatched(
        cleanup(),
        ExecFailureCode::Transport,
        FailureTimeout::Unknown,
        OutputByteCounts::new(1, 2),
        detail(),
    )
    .unwrap();
    assert_eq!(failure.dispatch_state(), DispatchState::PossiblyDispatched);
    assert_eq!(failure.counts().combined_bytes(), Some(3));
}

#[test]
fn missing_exit_and_overflow_are_always_possibly_dispatched() {
    let missing = ExecFailure::missing_terminal_exit(
        cleanup(),
        FailureTimeout::Unknown,
        OutputByteCounts::new(10, 20),
        detail(),
    )
    .unwrap();
    assert_eq!(missing.code(), ExecFailureCode::MissingTerminalExit);
    assert_eq!(missing.dispatch_state(), DispatchState::PossiblyDispatched);
    assert!(missing.output_limit().is_none());

    let overflow = ExecFailure::output_limit_exceeded(
        cleanup(),
        FailureTimeout::Unknown,
        OutputByteCounts::new(100, 20),
        OutputLimitKind::Stdout,
        detail(),
    )
    .unwrap();
    assert_eq!(overflow.code(), ExecFailureCode::OutputLimitExceeded);
    assert_eq!(overflow.dispatch_state(), DispatchState::PossiblyDispatched);
    assert_eq!(overflow.output_limit(), Some(OutputLimitKind::Stdout));
}

#[test]
fn public_error_formatting_never_contains_operator_content() {
    let errors: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(CreateFailure::possibly_created(
            cleanup(),
            CreateFailureCode::Transport,
            detail(),
        )),
        Box::new(ReadinessFailure::new(
            cleanup(),
            ReadinessFailureCode::Protocol,
            detail(),
        )),
        Box::new(
            ExecFailure::missing_terminal_exit(
                cleanup(),
                FailureTimeout::Unknown,
                OutputByteCounts::new(1, 1),
                detail(),
            )
            .unwrap(),
        ),
        Box::new(CleanupFailure::new(
            cleanup(),
            CleanupFailureCode::Provider,
            detail(),
        )),
    ];

    for error in errors {
        let display = error.to_string();
        let debug = format!("{error:?}");
        for secret in ["SECRET_ARG", "SECRET_OUTPUT"] {
            assert!(!display.contains(secret));
            assert!(!debug.contains(secret));
        }
    }
}
