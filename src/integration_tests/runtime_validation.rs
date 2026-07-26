use std::time::Duration;

use crate::{
    Argv, CommandTimeout, ExecCompleted, ExecRequest, ObservedExitCode, ObservedTimeout,
    OperationDeadline, OutputLimits, PolicyDocument, PolicyIdentity, RequestOwnedId,
    SANDBOX_WORKDIR, Sha256Digest, TemplateIdentity, ValidationCode,
};
use proptest::prelude::*;

fn digest() -> Sha256Digest {
    Sha256Digest::parse("a".repeat(64)).unwrap()
}

#[test]
fn request_owned_id_uses_gateway_compatible_short_shape() {
    // sbx-<15 lowercase hex> = 19 chars total, fits OpenShell's
    // MAX_ROUTABLE_NAME_LEN = 19 while retaining 60 bits of entropy.
    let id = RequestOwnedId::generate();
    assert_eq!(id.as_str().len(), 19);
    assert!(id.as_str().starts_with("sbx-"));
    let suffix = &id.as_str()[4..];
    assert_eq!(suffix.len(), 15);
    assert!(
        suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "generated suffix must be lowercase hex"
    );
    assert_eq!(RequestOwnedId::parse(id.to_string()).unwrap(), id);

    // A hand-crafted valid value round-trips.
    let hand = RequestOwnedId::parse("sbx-000000000000abc").unwrap();
    assert_eq!(hand.as_str(), "sbx-000000000000abc");

    for invalid in [
        "",
        "sbx-not-a-uuid",
        "SBX-000000000000000",                      // uppercase prefix
        "sbx-ABCDEF012345678",                      // uppercase hex
        "sbx-00000000000000",                       // 14 hex, too short
        "sbx-0000000000000000",                     // 16 hex, too long
        "sbx-550e8400-e29b-41d4-a716-446655440000", // old 40-char shape
        "sbx-00000000000000g",                      // non-hex char
        "prefix-sbx-000000000000000",
    ] {
        assert!(
            RequestOwnedId::parse(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn policy_and_template_values_reject_empty_or_malformed_inputs() {
    assert_eq!(
        TemplateIdentity::new("").unwrap_err().code(),
        ValidationCode::Empty
    );
    assert!(TemplateIdentity::new("template@immutable").is_ok());

    for invalid in ["", "a", &"A".repeat(64), &"g".repeat(64)] {
        assert!(Sha256Digest::parse(invalid).is_err());
    }
    assert!(Sha256Digest::parse("0".repeat(64)).is_ok());

    assert!(PolicyIdentity::new("", 1, digest()).is_err());
    assert!(PolicyIdentity::new("policy", 0, digest()).is_err());
    let identity = PolicyIdentity::new("policy", 1, digest()).unwrap();
    assert_eq!(identity.id(), "policy");
    assert_eq!(identity.version(), 1);

    assert!(PolicyDocument::new("", vec![1]).is_err());
    assert!(PolicyDocument::new("application/yaml", vec![]).is_err());
    assert!(PolicyDocument::new("application/yaml", vec![0, 0xff]).is_ok());
}

#[test]
fn argv_is_nonempty_and_snapshots_every_element() {
    assert!(Argv::new(vec![]).is_err());
    let mut source = vec![
        "program".to_owned(),
        String::new(),
        "a b".to_owned(),
        "$HOME; echo no".to_owned(),
        "雪".to_owned(),
        "program".to_owned(),
    ];
    let argv = Argv::new(source.clone()).unwrap();
    source[0] = "mutated".to_owned();
    assert_eq!(argv.as_slice()[0], "program");
    assert_eq!(argv.as_slice()[1], "");
    assert_eq!(argv.as_slice()[5], "program");
    assert!(!format!("{argv:?}").contains("$HOME"));
}

#[test]
fn timeout_and_output_limits_enforce_only_approved_bounds() {
    assert!(CommandTimeout::new(0).is_err());
    assert_eq!(CommandTimeout::new(1).unwrap().seconds(), 1);
    assert_eq!(CommandTimeout::default().seconds(), 30);
    assert_eq!(CommandTimeout::new(300).unwrap().seconds(), 300);
    assert!(CommandTimeout::new(301).is_err());

    assert!(OutputLimits::new(0, 1, 1, 1).is_err());
    assert!(OutputLimits::new(1, 0, 1, 1).is_err());
    assert!(OutputLimits::new(1, 1, 0, 1).is_err());
    assert!(OutputLimits::new(1, 1, 1, 0).is_err());
    let local = OutputLimits::new(1 << 20, 1 << 20, 2 << 20, 4 << 20).unwrap();
    assert_eq!(local.chunk_bytes(), 4 << 20);
}

#[test]
fn execution_request_has_no_dangerous_options() {
    let request = ExecRequest::new(
        Argv::new(vec!["/usr/bin/true".to_owned()]).unwrap(),
        CommandTimeout::default(),
        OutputLimits::new(1, 1, 1, 1).unwrap(),
    );
    assert_eq!(request.workdir(), SANDBOX_WORKDIR);
    assert_eq!(request.argv().as_slice(), ["/usr/bin/true"]);
}

#[test]
fn operation_deadline_must_be_positive() {
    assert!(OperationDeadline::new(Duration::ZERO).is_err());
    assert_eq!(
        OperationDeadline::new(Duration::from_millis(1))
            .unwrap()
            .duration(),
        Duration::from_millis(1)
    );
}

#[test]
fn completed_result_requires_real_exit_and_preserves_raw_bytes() {
    assert!(ObservedExitCode::new(-1).is_err());
    assert_eq!(ObservedExitCode::new(0).unwrap().get(), 0);
    assert_eq!(ObservedExitCode::new(124).unwrap().get(), 124);

    let result = ExecCompleted::new(
        ObservedExitCode::new(7).unwrap(),
        vec![0, 0xff, b'o'],
        vec![0xfe, b'e'],
        ObservedTimeout::NotObserved,
    );
    assert_eq!(result.exit_code().get(), 7);
    assert_eq!(result.stdout(), [0, 0xff, b'o']);
    assert_eq!(result.stderr(), [0xfe, b'e']);
    assert_eq!(result.stdout_bytes(), 3);
    assert_eq!(result.stderr_bytes(), 2);
    let debug = format!("{result:?}");
    assert!(!debug.contains("255"));
    assert!(debug.contains("stdout_bytes"));
}

proptest! {
    #[test]
    fn any_nonempty_argv_round_trips_without_normalization(values in prop::collection::vec(any::<String>(), 1..32)) {
        let argv = Argv::new(values.clone()).unwrap();
        prop_assert_eq!(argv.as_slice(), values.as_slice());
    }

    #[test]
    fn timeout_acceptance_matches_the_contract(value in any::<u16>()) {
        prop_assert_eq!(CommandTimeout::new(value).is_ok(), (1..=300).contains(&value));
    }
}
