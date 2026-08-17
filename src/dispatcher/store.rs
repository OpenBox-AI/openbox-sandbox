use core::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;

use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};

use super::{
    DispatchId, ErrorPhase, GovernanceOutcome, GovernedCleanupState, GovernedCommandResult,
    GovernedDispatchState, GovernedError, GovernedErrorCode, SelectedExecutor, TimeoutState,
};
use crate::{ObservedExitCode, RequestOwnedId, Sha256Digest};

const RECORD_SCHEMA_VERSION: u16 = 1;
const MAX_RECORD_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RecordStage {
    GovernancePending,
    HostDispatchPossible,
    SandboxCreatePossible,
    SandboxReady,
    SandboxDispatchPossible,
    Terminal,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompletionMetadata {
    exit_code: ObservedExitCode,
    stdout_bytes: u64,
    stderr_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DispatchRecord {
    schema_version: u16,
    dispatch_id: DispatchId,
    command_digest: Sha256Digest,
    selected_executor: SelectedExecutor,
    stage: RecordStage,
    governance: Option<GovernanceOutcome>,
    dispatch_state: GovernedDispatchState,
    timeout_state: TimeoutState,
    cleanup_id: Option<RequestOwnedId>,
    cleanup_state: GovernedCleanupState,
    completion: Option<CompletionMetadata>,
    stdout_bytes_observed: u64,
    stderr_bytes_observed: u64,
    error: Option<GovernedError>,
}

impl DispatchRecord {
    pub(crate) const fn new(dispatch_id: DispatchId, command_digest: Sha256Digest) -> Self {
        Self {
            schema_version: RECORD_SCHEMA_VERSION,
            dispatch_id,
            command_digest,
            selected_executor: SelectedExecutor::None,
            stage: RecordStage::GovernancePending,
            governance: None,
            dispatch_state: GovernedDispatchState::NotDispatched,
            timeout_state: TimeoutState::NotObserved,
            cleanup_id: None,
            cleanup_state: GovernedCleanupState::NotNeeded,
            completion: None,
            stdout_bytes_observed: 0,
            stderr_bytes_observed: 0,
            error: None,
        }
    }

    pub(crate) const fn dispatch_id(&self) -> &DispatchId {
        &self.dispatch_id
    }
    pub(crate) const fn command_digest(&self) -> &Sha256Digest {
        &self.command_digest
    }
    pub(crate) const fn cleanup_id(&self) -> Option<&RequestOwnedId> {
        self.cleanup_id.as_ref()
    }
    pub(crate) const fn cleanup_state(&self) -> GovernedCleanupState {
        self.cleanup_state
    }

    pub(crate) fn select_host(&mut self, governance: GovernanceOutcome) {
        self.governance = Some(governance);
        self.selected_executor = SelectedExecutor::Host;
        self.stage = RecordStage::HostDispatchPossible;
        self.dispatch_state = GovernedDispatchState::PossiblyDispatched;
    }

    pub(crate) fn select_sandbox(
        &mut self,
        governance: GovernanceOutcome,
        cleanup_id: RequestOwnedId,
    ) {
        self.governance = Some(governance);
        self.selected_executor = SelectedExecutor::Sandbox;
        self.stage = RecordStage::SandboxCreatePossible;
        self.cleanup_id = Some(cleanup_id);
        self.cleanup_state = GovernedCleanupState::PendingReconciliation;
    }

    pub(crate) fn sandbox_ready(&mut self) {
        self.stage = RecordStage::SandboxReady;
    }

    pub(crate) fn sandbox_dispatch_possible(&mut self) {
        self.stage = RecordStage::SandboxDispatchPossible;
        self.dispatch_state = GovernedDispatchState::PossiblyDispatched;
    }

    pub(crate) fn terminal(&mut self, result: &GovernedCommandResult) {
        self.stage = RecordStage::Terminal;
        self.governance = Some(result.governance().clone());
        self.selected_executor = result.selected_executor();
        self.dispatch_state = result.dispatch_state();
        self.timeout_state = result.timeout_state();
        self.cleanup_state = result.cleanup_state();
        self.error = result.error();
        self.completion = None;
        self.stdout_bytes_observed = 0;
        self.stderr_bytes_observed = 0;
        match result.execution_outcome() {
            super::ExecutionOutcome::NotExecuted => {}
            super::ExecutionOutcome::Completed { result } => {
                self.completion = Some(CompletionMetadata {
                    exit_code: result.exit_code(),
                    stdout_bytes: u64::try_from(result.stdout_bytes()).unwrap_or(u64::MAX),
                    stderr_bytes: u64::try_from(result.stderr_bytes()).unwrap_or(u64::MAX),
                });
            }
            super::ExecutionOutcome::Indeterminate {
                stdout_bytes_observed,
                stderr_bytes_observed,
            } => {
                self.stdout_bytes_observed = *stdout_bytes_observed;
                self.stderr_bytes_observed = *stderr_bytes_observed;
            }
        }
    }

    pub(crate) fn cleanup_confirmed(&mut self) {
        self.cleanup_state = GovernedCleanupState::ConfirmedAbsent;
    }

    #[allow(clippy::option_if_let_else)]
    pub(crate) fn replay_result(&self) -> GovernedCommandResult {
        let governance = self
            .governance
            .clone()
            .unwrap_or(GovernanceOutcome::Unavailable);
        if self.stage != RecordStage::Terminal {
            let (execution, timeout) =
                if self.dispatch_state == GovernedDispatchState::PossiblyDispatched {
                    (
                        super::ExecutionOutcome::indeterminate(crate::OutputByteCounts::default()),
                        TimeoutState::Unknown,
                    )
                } else {
                    (
                        super::ExecutionOutcome::NotExecuted,
                        TimeoutState::NotObserved,
                    )
                };
            return GovernedCommandResult::new(
                self.dispatch_id.clone(),
                governance,
                self.selected_executor,
                self.dispatch_state,
                execution,
                timeout,
                self.cleanup_state,
                Some(GovernedError::new(
                    GovernedErrorCode::ReplayIndeterminate,
                    ErrorPhase::DispatchPersistence,
                )),
            );
        }
        let execution = if let Some(completion) = &self.completion {
            // Durable records retain only body lengths. On replay, an empty body is returned rather
            // than persisting sensitive command output; the observed exit remains terminal.
            super::ExecutionOutcome::Completed {
                result: crate::ExecCompleted::new(
                    completion.exit_code,
                    Vec::new(),
                    Vec::new(),
                    match self.timeout_state {
                        TimeoutState::Confirmed => crate::ObservedTimeout::Confirmed,
                        TimeoutState::Possible => crate::ObservedTimeout::Possible,
                        TimeoutState::NotObserved | TimeoutState::Unknown => {
                            crate::ObservedTimeout::NotObserved
                        }
                    },
                ),
            }
        } else if self.dispatch_state == GovernedDispatchState::PossiblyDispatched {
            super::ExecutionOutcome::Indeterminate {
                stdout_bytes_observed: self.stdout_bytes_observed,
                stderr_bytes_observed: self.stderr_bytes_observed,
            }
        } else {
            super::ExecutionOutcome::NotExecuted
        };
        GovernedCommandResult::new(
            self.dispatch_id.clone(),
            governance,
            self.selected_executor,
            self.dispatch_state,
            execution,
            self.timeout_state,
            self.cleanup_state,
            self.error,
        )
    }

    fn validate(&self) -> Result<(), DispatchStoreError> {
        if self.schema_version != RECORD_SCHEMA_VERSION
            || (self.selected_executor != SelectedExecutor::Sandbox && self.cleanup_id.is_some())
            || (self.stage == RecordStage::Terminal
                && self.dispatch_state == GovernedDispatchState::Completed
                && self.completion.is_none())
            || (self.completion.is_some()
                && self.dispatch_state != GovernedDispatchState::Completed)
        {
            return Err(DispatchStoreError);
        }
        Ok(())
    }
}

pub(super) struct DispatchStore {
    directory: PathBuf,
    lock_path: PathBuf,
}

impl DispatchStore {
    pub(crate) fn initialize(directory: PathBuf) -> Result<Self, DispatchStoreError> {
        if directory.as_os_str().is_empty() {
            return Err(DispatchStoreError);
        }
        if let Ok(metadata) = fs::symlink_metadata(&directory) {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(DispatchStoreError);
            }
        } else {
            fs::create_dir_all(&directory).map_err(|_| DispatchStoreError)?;
        }
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| DispatchStoreError)?;
        if fs::metadata(&directory)
            .map_err(|_| DispatchStoreError)?
            .permissions()
            .mode()
            & 0o777
            != 0o700
        {
            return Err(DispatchStoreError);
        }
        let lock_path = directory.join(".dispatcher.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|_| DispatchStoreError)?;
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
            .map_err(|_| DispatchStoreError)?;
        drop(lock);
        Ok(Self {
            directory,
            lock_path,
        })
    }

    pub(crate) fn lock(&self) -> Result<DispatchStoreGuard<'_>, DispatchStoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .map_err(|_| DispatchStoreError)?;
        flock(&file, FlockOperation::LockExclusive).map_err(|_| DispatchStoreError)?;
        Ok(DispatchStoreGuard { store: self, file })
    }

    fn path(&self, dispatch_id: &DispatchId) -> PathBuf {
        self.directory.join(format!("{dispatch_id}.json"))
    }
}

pub(super) struct DispatchStoreGuard<'a> {
    store: &'a DispatchStore,
    file: File,
}

impl DispatchStoreGuard<'_> {
    pub(crate) fn load(
        &self,
        dispatch_id: &DispatchId,
    ) -> Result<Option<DispatchRecord>, DispatchStoreError> {
        let path = self.store.path(dispatch_id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(DispatchStoreError),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || usize::try_from(metadata.len()).map_err(|_| DispatchStoreError)? > MAX_RECORD_BYTES
        {
            return Err(DispatchStoreError);
        }
        let bytes = fs::read(path).map_err(|_| DispatchStoreError)?;
        let record: DispatchRecord =
            serde_json::from_slice(&bytes).map_err(|_| DispatchStoreError)?;
        record.validate()?;
        if record.dispatch_id() != dispatch_id {
            return Err(DispatchStoreError);
        }
        Ok(Some(record))
    }

    pub(crate) fn load_all(&self) -> Result<Vec<DispatchRecord>, DispatchStoreError> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.store.directory).map_err(|_| DispatchStoreError)? {
            let entry = entry.map_err(|_| DispatchStoreError)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(DispatchStoreError);
            };
            if name.starts_with('.') {
                continue;
            }
            let Some(id) = name.strip_suffix(".json") else {
                return Err(DispatchStoreError);
            };
            let dispatch_id = DispatchId::parse(id).map_err(|_| DispatchStoreError)?;
            records.push(self.load(&dispatch_id)?.ok_or(DispatchStoreError)?);
        }
        records.sort_by(|left, right| left.dispatch_id().cmp(right.dispatch_id()));
        Ok(records)
    }

    pub(crate) fn write(&self, record: &DispatchRecord) -> Result<(), DispatchStoreError> {
        record.validate()?;
        let bytes = serde_json::to_vec(record).map_err(|_| DispatchStoreError)?;
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(DispatchStoreError);
        }
        let target = self.store.path(record.dispatch_id());
        let temporary = self.store.directory.join(format!(
            ".{}.{}.tmp",
            record.dispatch_id(),
            UuidSuffix::generate()
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|_| DispatchStoreError)?;
            file.write_all(&bytes).map_err(|_| DispatchStoreError)?;
            file.sync_all().map_err(|_| DispatchStoreError)?;
            fs::rename(&temporary, &target).map_err(|_| DispatchStoreError)?;
            File::open(&self.store.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| DispatchStoreError)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

impl Drop for DispatchStoreGuard<'_> {
    fn drop(&mut self) {
        let _ = flock(&self.file, FlockOperation::Unlock);
    }
}

struct UuidSuffix(String);

impl UuidSuffix {
    fn generate() -> Self {
        Self(uuid::Uuid::new_v4().simple().to_string())
    }
}

impl fmt::Display for UuidSuffix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DispatchStoreError;

impl fmt::Display for DispatchStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("durable dispatch state operation failed")
    }
}

impl std::error::Error for DispatchStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_serialization_contains_no_command_or_output_bodies() {
        let dispatch_id = DispatchId::generate();
        let mut record =
            DispatchRecord::new(dispatch_id, Sha256Digest::parse("a".repeat(64)).unwrap());
        let result = GovernedCommandResult::new(
            record.dispatch_id.clone(),
            GovernanceOutcome::Authoritative {
                verdict: super::super::GovernanceVerdict::Allow,
                response: serde_json::json!({"activity_id": record.dispatch_id.as_str(), "verdict": "ALLOW"}),
            },
            SelectedExecutor::Host,
            GovernedDispatchState::Completed,
            super::super::ExecutionOutcome::Completed {
                result: crate::ExecCompleted::new(
                    ObservedExitCode::new(0).unwrap(),
                    b"RAW_STDOUT_SECRET".to_vec(),
                    b"RAW_STDERR_SECRET".to_vec(),
                    crate::ObservedTimeout::NotObserved,
                ),
            },
            TimeoutState::NotObserved,
            GovernedCleanupState::NotNeeded,
            None,
        );
        record.terminal(&result);
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("RAW_STDOUT_SECRET"));
        assert!(!json.contains("RAW_STDERR_SECRET"));
        assert!(!json.contains("argv"));
        assert!(json.contains("command_digest"));
    }
}
