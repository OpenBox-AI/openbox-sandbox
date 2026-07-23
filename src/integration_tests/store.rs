use std::os::unix::fs::{PermissionsExt as _, symlink};

use crate::create_request_fixture;
use crate::{CallerFingerprint, DurableRecord, DurableStage, DurableStore};

fn record(index: u64) -> DurableRecord {
    let request = create_request_fixture(index);
    DurableRecord::new(
        request.request_id().clone(),
        CallerFingerprint::parse("e".repeat(64)).unwrap(),
        DurableStage::CreatePossible,
        request.template().clone(),
        request.expected_policy().clone(),
    )
    .unwrap()
}

#[tokio::test]
async fn store_uses_owner_only_atomic_records_and_strict_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let store = DurableStore::initialize(directory.path()).unwrap();
    assert_eq!(
        std::fs::metadata(directory.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let mut expected = record(1);
    store.write(&expected).await.unwrap();
    let path = directory
        .path()
        .join(format!("{}.json", expected.request_id()));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(store.load_all().await.unwrap(), vec![expected.clone()]);

    expected.transition(DurableStage::ExecPossible).unwrap();
    store.write(&expected).await.unwrap();
    assert_eq!(store.load_all().await.unwrap(), vec![expected.clone()]);
    assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')
    }));

    store.remove(expected.request_id()).await.unwrap();
    store.remove(expected.request_id()).await.unwrap();
    assert!(store.load_all().await.unwrap().is_empty());
}

#[tokio::test]
async fn malformed_unowned_and_symlink_entries_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let store = DurableStore::initialize(directory.path()).unwrap();
    std::fs::write(directory.path().join("unexpected.json"), b"{}").unwrap();
    assert!(store.load_all().await.is_err());
    std::fs::remove_file(directory.path().join("unexpected.json")).unwrap();

    let outside = tempfile::NamedTempFile::new().unwrap();
    symlink(
        outside.path(),
        directory
            .path()
            .join("sbx-00000000-0000-4000-8000-000000000001.json"),
    )
    .unwrap();
    assert!(store.load_all().await.is_err());
}

#[test]
fn symlink_state_directory_is_rejected() {
    let parent = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let link = parent.path().join("state");
    symlink(target.path(), &link).unwrap();
    assert!(DurableStore::initialize(link).is_err());
}
