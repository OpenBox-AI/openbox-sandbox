use core::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::OperationId;
use crate::{PolicyIdentity, RequestOwnedId, TemplateIdentity};

use crate::CallerFingerprint;

const RECORD_SCHEMA_VERSION: u16 = 1;
const MAX_RECORD_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableStage {
    CreatePossible,
    Created,
    Ready,
    ExecPossible,
    CleanupOnly,
    DeletePending,
    Unowned,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableRecord {
    schema_version: u16,
    request_id: RequestOwnedId,
    caller: CallerFingerprint,
    stage: DurableStage,
    template: TemplateIdentity,
    policy: PolicyIdentity,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
}

impl DurableRecord {
    pub fn new(
        request_id: RequestOwnedId,
        caller: CallerFingerprint,
        stage: DurableStage,
        template: TemplateIdentity,
        policy: PolicyIdentity,
    ) -> Result<Self, StoreError> {
        let now = unix_time_millis()?;
        Ok(Self {
            schema_version: RECORD_SCHEMA_VERSION,
            request_id,
            caller,
            stage,
            template,
            policy,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
        })
    }

    pub const fn request_id(&self) -> &RequestOwnedId {
        &self.request_id
    }

    pub const fn caller(&self) -> &CallerFingerprint {
        &self.caller
    }

    pub const fn stage(&self) -> DurableStage {
        self.stage
    }

    pub const fn template(&self) -> &TemplateIdentity {
        &self.template
    }

    pub const fn policy(&self) -> &PolicyIdentity {
        &self.policy
    }

    pub fn transition(&mut self, stage: DurableStage) -> Result<(), StoreError> {
        self.stage = stage;
        self.updated_at_unix_ms = unix_time_millis()?;
        Ok(())
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.schema_version != RECORD_SCHEMA_VERSION
            || self.created_at_unix_ms == 0
            || self.updated_at_unix_ms < self.created_at_unix_ms
        {
            return Err(StoreError);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DurableStore {
    directory: PathBuf,
}

impl DurableStore {
    pub fn initialize(directory: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let directory = directory.into();
        if directory.as_os_str().is_empty() {
            return Err(StoreError);
        }
        if let Ok(metadata) = fs::symlink_metadata(&directory) {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(StoreError);
            }
        } else {
            fs::create_dir_all(&directory).map_err(|_| StoreError)?;
        }
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| StoreError)?;
        let mode = fs::metadata(&directory)
            .map_err(|_| StoreError)?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o700 {
            return Err(StoreError);
        }
        Ok(Self { directory })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub async fn write(&self, record: &DurableRecord) -> Result<(), StoreError> {
        let directory = self.directory.clone();
        let record = record.clone();
        tokio::task::spawn_blocking(move || write_record(&directory, &record))
            .await
            .map_err(|_| StoreError)?
    }

    pub async fn remove(&self, request_id: &RequestOwnedId) -> Result<(), StoreError> {
        let directory = self.directory.clone();
        let request_id = request_id.clone();
        tokio::task::spawn_blocking(move || remove_record(&directory, &request_id))
            .await
            .map_err(|_| StoreError)?
    }

    pub async fn load_all(&self) -> Result<Vec<DurableRecord>, StoreError> {
        let directory = self.directory.clone();
        tokio::task::spawn_blocking(move || load_records(&directory))
            .await
            .map_err(|_| StoreError)?
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreError;

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("durable cleanup state operation failed")
    }
}

impl std::error::Error for StoreError {}

fn write_record(directory: &Path, record: &DurableRecord) -> Result<(), StoreError> {
    record.validate()?;
    let bytes = serde_json::to_vec(record).map_err(|_| StoreError)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(StoreError);
    }
    let target = record_path(directory, record.request_id());
    let temporary = directory.join(format!(
        ".{}.{}.tmp",
        record.request_id(),
        OperationId::generate().as_str()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| StoreError)?;
        file.write_all(&bytes).map_err(|_| StoreError)?;
        file.sync_all().map_err(|_| StoreError)?;
        fs::rename(&temporary, &target).map_err(|_| StoreError)?;
        File::open(directory)
            .and_then(|directory_file| directory_file.sync_all())
            .map_err(|_| StoreError)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_record(directory: &Path, request_id: &RequestOwnedId) -> Result<(), StoreError> {
    let path = record_path(directory, request_id);
    match fs::remove_file(path) {
        Ok(()) => File::open(directory)
            .and_then(|directory_file| directory_file.sync_all())
            .map_err(|_| StoreError),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StoreError),
    }
}

fn load_records(directory: &Path) -> Result<Vec<DurableRecord>, StoreError> {
    let mut records = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| StoreError)? {
        let entry = entry.map_err(|_| StoreError)?;
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_str().ok_or(StoreError)?;
        if file_name.starts_with('.') {
            continue;
        }
        let relative = Path::new(file_name);
        if !file_name.starts_with("sbx-")
            || relative.extension() != Some(std::ffi::OsStr::new("json"))
        {
            return Err(StoreError);
        }
        let metadata = fs::symlink_metadata(&path).map_err(|_| StoreError)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || usize::try_from(metadata.len()).map_err(|_| StoreError)? > MAX_RECORD_BYTES
        {
            return Err(StoreError);
        }
        let bytes = fs::read(&path).map_err(|_| StoreError)?;
        let record: DurableRecord = serde_json::from_slice(&bytes).map_err(|_| StoreError)?;
        record.validate()?;
        if record_path(directory, record.request_id()) != path {
            return Err(StoreError);
        }
        records.push(record);
    }
    records.sort_by(|left, right| left.request_id().cmp(right.request_id()));
    Ok(records)
}

fn record_path(directory: &Path, request_id: &RequestOwnedId) -> PathBuf {
    directory.join(format!("{request_id}.json"))
}

fn unix_time_millis() -> Result<u64, StoreError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError)?;
    u64::try_from(duration.as_millis()).map_err(|_| StoreError)
}
