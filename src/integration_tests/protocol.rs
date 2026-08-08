use crate::{
    Argv, CommandTimeout, ExecCompleted, ExecRequest, ObservedExitCode, ObservedTimeout,
    OutputLimits, PolicyIdentity, RequestOwnedId, Sha256Digest, TemplateIdentity,
};
use crate::{
    AssetBundleIdentity, DeadlineMillis, FrameError, OperationId, RequestEnvelope,
    ResponseEnvelope, ServiceRequest, ServiceResponse, decode_request, decode_response,
    read_request, write_request,
};

fn digest(byte: char) -> Sha256Digest {
    Sha256Digest::parse(byte.to_string().repeat(64)).unwrap()
}

fn policy() -> PolicyIdentity {
    PolicyIdentity::new("deny-network", 1, digest('b')).unwrap()
}

fn bundle() -> AssetBundleIdentity {
    AssetBundleIdentity::new(
        1,
        digest('a'),
        TemplateIdentity::new(format!(
            "registry.invalid/sandbox@sha256:{}",
            "c".repeat(64)
        ))
        .unwrap(),
        policy(),
        "linux-arm64-runtime-v1",
    )
    .unwrap()
}

fn exec_request() -> ExecRequest {
    ExecRequest::new(
        Argv::new(vec![
            "/bin/proof".to_owned(),
            String::new(),
            "space value".to_owned(),
            "$literal".to_owned(),
        ])
        .unwrap(),
        CommandTimeout::new(30).unwrap(),
        OutputLimits::new(1024, 1024, 2048, 4096).unwrap(),
    )
}

#[test]
fn request_round_trip_preserves_exact_argv_and_rejects_unknown_fields() {
    let envelope = RequestEnvelope::new(
        OperationId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        bundle(),
        ServiceRequest::PrepareExec {
            request_id: RequestOwnedId::parse("sbx-000000000000001").unwrap(),
            lifecycle_token: crate::CapabilityToken::generate(),
            request: exec_request(),
            deadline_ms: DeadlineMillis::new(45_000).unwrap(),
        },
    );
    let encoded = serde_json::to_vec(&envelope).unwrap();
    let decoded = decode_request(&encoded).unwrap();
    assert_eq!(decoded, envelope);

    let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert_eq!(
        decode_request(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
        FrameError::InvalidJson
    );
}

#[test]
fn response_round_trip_preserves_binary_output_and_real_exit() {
    let response = ResponseEnvelope::new(
        OperationId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        ServiceResponse::Executed {
            result: ExecCompleted::new(
                ObservedExitCode::new(7).unwrap(),
                vec![0, 0xff],
                vec![0xfe, 0],
                ObservedTimeout::NotObserved,
            ),
        },
    );
    let encoded = serde_json::to_vec(&response).unwrap();
    assert!(!encoded.windows(2).any(|window| window == [0, 0xff]));
    assert_eq!(decode_response(&encoded).unwrap(), response);
}

#[test]
fn identifiers_deadlines_and_bundle_fields_fail_closed() {
    assert!(OperationId::parse("not-a-v4-uuid").is_err());
    assert!(DeadlineMillis::new(0).is_err());
    assert!(DeadlineMillis::new(1_200_001).is_err());
    assert!(DeadlineMillis::new(1_200_000).is_ok());
    assert!(
        AssetBundleIdentity::new(
            0,
            digest('a'),
            TemplateIdentity::new("x").unwrap(),
            policy(),
            "v1"
        )
        .is_err()
    );
    assert!(
        AssetBundleIdentity::new(
            1,
            digest('a'),
            TemplateIdentity::new("x").unwrap(),
            policy(),
            "contains spaces"
        )
        .is_err()
    );
}

#[tokio::test]
async fn framed_io_round_trips_and_rejects_oversized_prefix_before_body() {
    let envelope = RequestEnvelope::new(OperationId::generate(), bundle(), ServiceRequest::Health);
    let (mut writer, mut reader) = tokio::io::duplex(8192);
    let expected = envelope.clone();
    let write = tokio::spawn(async move { write_request(&mut writer, &envelope).await });
    assert_eq!(read_request(&mut reader).await.unwrap(), expected);
    write.await.unwrap().unwrap();

    let (mut writer, mut reader) = tokio::io::duplex(8);
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        writer.write_u32(u32::MAX).await.unwrap();
    });
    assert_eq!(
        read_request(&mut reader).await.unwrap_err(),
        FrameError::TooLarge
    );
}
