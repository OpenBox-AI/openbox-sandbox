//! Native SRT-style provider built from OS sandbox primitives.
//!
//! This is intentionally not the Anthropic npm CLI. `OpenBox` owns the runner so
//! argv crosses the boundary without a shell, while macOS Seatbelt and Linux
//! bubblewrap enforce a deployment-compiled, hash-pinned profile.

#[cfg(test)]
mod conformance_tests;
mod policy;

use core::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::{
    CleanupFailure, CleanupFailureCode, CleanupTarget, CreateFailure, CreateFailureCode,
    CreateRequest, CreatedSandbox, DeleteOutcome, ExecCompleted, ExecFailure, ExecFailureCode,
    ExecRequest, FailureTimeout, ObservedExitCode, ObservedTimeout, OpaqueProviderHandle,
    OperationContext, OperatorDetail, OutputByteCounts, OutputLimitKind, PolicyIdentity,
    ProviderCapability, ReadinessFailure, ReadinessFailureCode, ReadySandbox, RequestOwnedId,
    SandboxRuntime, Sha256Digest,
};

use policy::verify_compiled_profile;
pub use policy::{compile_srt_policy, sha256_file};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SrtConfigError {
    InvalidConfiguration,
    UnsupportedPlatform,
    PolicyRead,
    PolicyWrite,
    InvalidPolicy,
    PolicyMismatch,
}

impl fmt::Display for SrtConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("native srt configuration rejected")
    }
}

impl std::error::Error for SrtConfigError {}

#[derive(Clone, Debug)]
pub struct SrtConfig {
    profile_path: PathBuf,
    profile_sha256: Sha256Digest,
    workspace_root: PathBuf,
    policy_identity: PolicyIdentity,
}

impl SrtConfig {
    pub fn new(
        profile_path: impl Into<PathBuf>,
        profile_sha256: Sha256Digest,
        workspace_root: impl Into<PathBuf>,
        policy_identity: PolicyIdentity,
    ) -> Result<Self, SrtConfigError> {
        let profile_path = profile_path.into();
        let workspace_root = workspace_root.into();
        if !profile_path.is_absolute() || !workspace_root.is_absolute() {
            return Err(SrtConfigError::InvalidConfiguration);
        }
        let workspace_root = workspace_root
            .canonicalize()
            .map_err(|_| SrtConfigError::InvalidConfiguration)?;
        verify_compiled_profile(&profile_path, profile_sha256.as_str(), &workspace_root)?;
        Ok(Self {
            profile_path,
            profile_sha256,
            workspace_root,
            policy_identity,
        })
    }

    pub const fn capability(&self) -> ProviderCapability {
        ProviderCapability::EnforcedLocally
    }
}

pub struct SrtRuntime {
    config: SrtConfig,
}

impl SrtRuntime {
    pub fn new(config: SrtConfig) -> Result<Self, SrtConfigError> {
        verify_compiled_profile(
            &config.profile_path,
            config.profile_sha256.as_str(),
            &config.workspace_root,
        )?;
        Ok(Self { config })
    }

    pub const fn capability(&self) -> ProviderCapability {
        ProviderCapability::EnforcedLocally
    }

    fn verify_profile(&self) -> Result<(), SrtConfigError> {
        verify_compiled_profile(
            &self.config.profile_path,
            self.config.profile_sha256.as_str(),
            &self.config.workspace_root,
        )
    }

    fn workspace(&self, request_id: &RequestOwnedId) -> PathBuf {
        self.config.workspace_root.join(request_id.as_str())
    }
}

#[async_trait]
impl SandboxRuntime for SrtRuntime {
    async fn create(
        &self,
        request: CreateRequest,
        context: OperationContext,
    ) -> Result<CreatedSandbox, CreateFailure> {
        preflight(&context).map_err(create_context_failure)?;
        if self.verify_profile().is_err()
            || request.expected_policy() != &self.config.policy_identity
            || sha256_bytes(request.policy_document().as_bytes())
                != request.expected_policy().sha256().as_str()
        {
            return Err(CreateFailure::not_created(
                CreateFailureCode::Validation,
                detail("deployment policy identity or native profile mismatch"),
            ));
        }
        let request_id = request.request_id().clone();
        let workspace = self.workspace(&request_id);
        match tokio::fs::create_dir(&workspace).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(CreateFailure::conflict(
                    CreateFailureCode::Provider,
                    detail("request-owned workspace already exists"),
                ));
            }
            Err(_) => {
                return Err(CreateFailure::not_created(
                    CreateFailureCode::Provider,
                    detail("request-owned workspace could not be created"),
                ));
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if tokio::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700))
                .await
                .is_err()
            {
                return Err(CreateFailure::possibly_created(
                    CleanupTarget::new(request_id),
                    CreateFailureCode::Provider,
                    detail("request-owned workspace permissions could not be set"),
                ));
            }
        }
        let handle =
            OpaqueProviderHandle::new(request_id.as_str().as_bytes().to_vec()).map_err(|_| {
                CreateFailure::possibly_created(
                    CleanupTarget::new(request_id.clone()),
                    CreateFailureCode::Protocol,
                    detail("native provider handle could not be retained"),
                )
            })?;
        Ok(CreatedSandbox::from_runtime(
            request_id,
            handle,
            request.expected_policy().clone(),
        ))
    }

    async fn wait_ready(
        &self,
        sandbox: CreatedSandbox,
        expected_policy: PolicyIdentity,
        context: OperationContext,
    ) -> Result<ReadySandbox, ReadinessFailure> {
        let target = sandbox.cleanup_target();
        preflight(&context).map_err(|failure| {
            ReadinessFailure::new(target.clone(), failure.readiness_code(), failure.detail())
        })?;
        if self.verify_profile().is_err()
            || expected_policy != self.config.policy_identity
            || sandbox.expected_policy() != &expected_policy
            || !self.workspace(sandbox.request_id()).is_dir()
            || sandbox.provider_handle().as_bytes() != sandbox.request_id().as_str().as_bytes()
        {
            return Err(ReadinessFailure::new(
                target,
                ReadinessFailureCode::PolicyMismatch,
                detail("native profile attestation or workspace readiness failed"),
            ));
        }
        ReadySandbox::attest(sandbox, expected_policy.clone(), &expected_policy).map_err(|_| {
            ReadinessFailure::new(
                target,
                ReadinessFailureCode::PolicyMismatch,
                detail("native local-attestation transition failed"),
            )
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn exec(
        &self,
        sandbox: ReadySandbox,
        request: ExecRequest,
        context: OperationContext,
    ) -> Result<ExecCompleted, ExecFailure> {
        let target = sandbox.cleanup_target();
        preflight(&context).map_err(|failure| {
            ExecFailure::not_dispatched(target.clone(), failure.exec_code(), failure.detail())
                .expect("pre-dispatch context failure is valid")
        })?;
        if self.verify_profile().is_err()
            || sandbox.active_policy() != &self.config.policy_identity
            || sandbox.provider_handle().as_bytes() != sandbox.request_id().as_str().as_bytes()
        {
            return Err(ExecFailure::not_dispatched(
                target,
                ExecFailureCode::Protocol,
                detail("native profile verification failed before dispatch"),
            )
            .expect("pre-dispatch protocol failure is valid"));
        }
        let workspace = self.workspace(sandbox.request_id());
        if !workspace.is_dir() {
            return Err(ExecFailure::not_dispatched(
                target,
                ExecFailureCode::Provider,
                detail("request-owned workspace is absent"),
            )
            .expect("pre-dispatch provider failure is valid"));
        }

        let mut command = native_command(&self.config, &workspace, &request).map_err(|_| {
            ExecFailure::not_dispatched(
                target.clone(),
                ExecFailureCode::Provider,
                detail("native sandbox runner is unavailable"),
            )
            .expect("pre-dispatch provider failure is valid")
        })?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        let mut child = command.spawn().map_err(|_| {
            ExecFailure::not_dispatched(
                target.clone(),
                ExecFailureCode::Transport,
                detail("native sandbox process could not be spawned"),
            )
            .expect("spawn failure is before dispatch")
        })?;
        let stdout = child.stdout.take().expect("configured stdout pipe");
        let stderr = child.stderr.take().expect("configured stderr pipe");
        let stdout_count = Arc::new(AtomicU64::new(0));
        let stderr_count = Arc::new(AtomicU64::new(0));
        let (overflow_tx, mut overflow_rx) = mpsc::channel(2);
        let limits = request.output_limits();
        let stdout_task = tokio::spawn(read_bounded(
            stdout,
            OutputLimitKind::Stdout,
            limits.stdout_bytes(),
            limits.combined_bytes(),
            limits.chunk_bytes(),
            stdout_count.clone(),
            stderr_count.clone(),
            overflow_tx.clone(),
        ));
        let stderr_task = tokio::spawn(read_bounded(
            stderr,
            OutputLimitKind::Stderr,
            limits.stderr_bytes(),
            limits.combined_bytes(),
            limits.chunk_bytes(),
            stderr_count.clone(),
            stdout_count.clone(),
            overflow_tx.clone(),
        ));
        // Keep the channel open until process observation completes; otherwise
        // two early pipe EOFs could race child.wait() as a false transport error.
        let _overflow_guard = overflow_tx;

        let outcome = {
            let wait = child.wait();
            tokio::pin!(wait);
            let command_timeout = tokio::time::sleep(std::time::Duration::from_secs(u64::from(
                request.timeout().seconds(),
            )));
            tokio::pin!(command_timeout);
            let deadline = tokio::time::sleep(context.deadline().duration());
            tokio::pin!(deadline);
            tokio::select! {
                biased;
                () = context.cancellation().cancelled() => WaitOutcome::Cancelled,
                () = &mut deadline => WaitOutcome::Deadline,
                () = &mut command_timeout => WaitOutcome::CommandTimeout,
                overflow = overflow_rx.recv() => overflow.map_or(WaitOutcome::WaitFailed, WaitOutcome::Overflow),
                status = &mut wait => status.map_or(WaitOutcome::WaitFailed, WaitOutcome::Exited),
            }
        };
        if !matches!(outcome, WaitOutcome::Exited(_)) {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        let stdout_result = stdout_task.await.unwrap_or_default();
        let stderr_result = stderr_task.await.unwrap_or_default();
        let counts = OutputByteCounts::new(
            stdout_count.load(Ordering::Relaxed),
            stderr_count.load(Ordering::Relaxed),
        );
        let detected_overflow = match outcome {
            WaitOutcome::Overflow(kind) => Some(kind),
            _ => stdout_result.overflow.or(stderr_result.overflow),
        };
        if let Some(kind) = detected_overflow {
            return Err(ExecFailure::output_limit_exceeded(
                target,
                FailureTimeout::Unknown,
                counts,
                kind,
                detail("native sandbox output limit exceeded"),
            )
            .expect("post-dispatch overflow is valid"));
        }
        match outcome {
            WaitOutcome::Exited(status) => {
                let code = observed_status(status).ok_or_else(|| {
                    ExecFailure::missing_terminal_exit(
                        target.clone(),
                        FailureTimeout::Unknown,
                        counts,
                        detail("native sandbox process omitted an observable exit"),
                    )
                    .expect("post-dispatch missing exit is valid")
                })?;
                Ok(ExecCompleted::new(
                    code,
                    stdout_result.bytes,
                    stderr_result.bytes,
                    ObservedTimeout::NotObserved,
                ))
            }
            WaitOutcome::CommandTimeout => Ok(ExecCompleted::new(
                ObservedExitCode::new(124).expect("124 is a nonnegative exit code"),
                stdout_result.bytes,
                stderr_result.bytes,
                ObservedTimeout::Confirmed,
            )),
            WaitOutcome::Deadline => Err(ExecFailure::possibly_dispatched(
                target,
                ExecFailureCode::Deadline,
                FailureTimeout::Unknown,
                counts,
                detail("native sandbox operation deadline elapsed"),
            )
            .expect("post-dispatch deadline is valid")),
            WaitOutcome::Cancelled => Err(ExecFailure::possibly_dispatched(
                target,
                ExecFailureCode::Cancelled,
                FailureTimeout::Unknown,
                counts,
                detail("native sandbox operation was cancelled"),
            )
            .expect("post-dispatch cancellation is valid")),
            WaitOutcome::WaitFailed | WaitOutcome::Overflow(_) => {
                Err(ExecFailure::possibly_dispatched(
                    target,
                    ExecFailureCode::Transport,
                    FailureTimeout::Unknown,
                    counts,
                    detail("native sandbox process observation failed"),
                )
                .expect("post-dispatch observation failure is valid"))
            }
        }
    }

    async fn delete(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<DeleteOutcome, CleanupFailure> {
        preflight(&context).map_err(|failure| {
            CleanupFailure::new(target.clone(), failure.cleanup_code(), failure.detail())
        })?;
        let workspace = self.workspace(target.request_id());
        match tokio::fs::remove_dir_all(workspace).await {
            Ok(()) => Ok(DeleteOutcome::Deleted),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(DeleteOutcome::AlreadyAbsent)
            }
            Err(_) => Err(CleanupFailure::new(
                target,
                CleanupFailureCode::Provider,
                detail("request-owned workspace could not be removed"),
            )),
        }
    }

    async fn wait_deleted(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<(), CleanupFailure> {
        preflight(&context).map_err(|failure| {
            CleanupFailure::new(target.clone(), failure.cleanup_code(), failure.detail())
        })?;
        if self.workspace(target.request_id()).exists() {
            Err(CleanupFailure::new(
                target,
                CleanupFailureCode::Provider,
                detail("request-owned workspace remains present"),
            ))
        } else {
            Ok(())
        }
    }
}

fn native_command(
    config: &SrtConfig,
    workspace: &Path,
    request: &ExecRequest,
) -> Result<Command, SrtConfigError> {
    let argv = request.argv().as_slice();
    if cfg!(target_os = "macos") {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .arg("-D")
            .arg(format!(
                "WORKSPACE_ROOT={}",
                config.workspace_root.to_string_lossy()
            ))
            .arg("-D")
            .arg(format!("WORKSPACE={}", workspace.to_string_lossy()))
            .arg("-f")
            .arg(&config.profile_path)
            .arg("--");
        command
            .arg(&argv[0])
            .args(&argv[1..])
            .current_dir(workspace);
        Ok(command)
    } else if cfg!(target_os = "linux") {
        let mut command = Command::new("bwrap");
        command.args([
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--unshare-net",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]);
        for path in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"] {
            if Path::new(path).exists() {
                command.arg("--ro-bind").arg(path).arg(path);
            }
        }
        command
            .arg("--bind")
            .arg(workspace)
            .arg("/sandbox")
            .arg("--chdir")
            .arg("/sandbox")
            .arg("--")
            .arg(&argv[0])
            .args(&argv[1..]);
        Ok(command)
    } else {
        Err(SrtConfigError::UnsupportedPlatform)
    }
}

enum WaitOutcome {
    Exited(std::process::ExitStatus),
    Overflow(OutputLimitKind),
    CommandTimeout,
    Deadline,
    Cancelled,
    WaitFailed,
}

#[derive(Default)]
struct ReadResult {
    bytes: Vec<u8>,
    overflow: Option<OutputLimitKind>,
}

#[allow(clippy::too_many_arguments)]
async fn read_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    stream_kind: OutputLimitKind,
    stream_limit: u64,
    combined_limit: u64,
    chunk_limit: u64,
    own_count: Arc<AtomicU64>,
    other_count: Arc<AtomicU64>,
    overflow_tx: mpsc::Sender<OutputLimitKind>,
) -> ReadResult {
    let mut result = ReadResult::default();
    let mut buffer = vec![0_u8; 8192];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        let read_u64 = u64::try_from(read).unwrap_or(u64::MAX);
        let own = own_count
            .fetch_add(read_u64, Ordering::Relaxed)
            .saturating_add(read_u64);
        let combined = own.saturating_add(other_count.load(Ordering::Relaxed));
        let overflow = if read_u64 > chunk_limit {
            Some(OutputLimitKind::Chunk)
        } else if own > stream_limit {
            Some(stream_kind)
        } else if combined > combined_limit {
            Some(OutputLimitKind::Combined)
        } else {
            None
        };
        if let Some(kind) = overflow {
            if result.overflow.is_none() {
                result.overflow = Some(kind);
                let _ = overflow_tx.try_send(kind);
            }
        } else if result.overflow.is_none() {
            result.bytes.extend_from_slice(&buffer[..read]);
        }
    }
    result
}

fn observed_status(status: std::process::ExitStatus) -> Option<ObservedExitCode> {
    if let Some(code) = status.code() {
        return ObservedExitCode::new(code).ok();
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        return status
            .signal()
            .and_then(|signal| ObservedExitCode::new(128_i32.saturating_add(signal)).ok());
    }
    #[allow(unreachable_code)]
    None
}

fn sha256_bytes(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut encoded, byte| {
            write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
            encoded
        })
}

#[derive(Clone, Copy)]
enum ContextFailure {
    Cancelled,
    Deadline,
}

impl ContextFailure {
    const fn exec_code(self) -> ExecFailureCode {
        match self {
            Self::Cancelled => ExecFailureCode::Cancelled,
            Self::Deadline => ExecFailureCode::Deadline,
        }
    }

    const fn readiness_code(self) -> ReadinessFailureCode {
        match self {
            Self::Cancelled => ReadinessFailureCode::Cancelled,
            Self::Deadline => ReadinessFailureCode::Deadline,
        }
    }

    const fn cleanup_code(self) -> CleanupFailureCode {
        match self {
            Self::Cancelled => CleanupFailureCode::Cancelled,
            Self::Deadline => CleanupFailureCode::Deadline,
        }
    }

    fn detail(self) -> OperatorDetail {
        match self {
            Self::Cancelled => OperatorDetail::redacted("native sandbox operation cancelled"),
            Self::Deadline => OperatorDetail::redacted("native sandbox operation deadline elapsed"),
        }
    }
}

fn preflight(context: &OperationContext) -> Result<(), ContextFailure> {
    if context.cancellation().is_cancelled() {
        Err(ContextFailure::Cancelled)
    } else if context.deadline().duration().is_zero() {
        Err(ContextFailure::Deadline)
    } else {
        Ok(())
    }
}

fn create_context_failure(failure: ContextFailure) -> CreateFailure {
    let code = match failure {
        ContextFailure::Cancelled => CreateFailureCode::Cancelled,
        ContextFailure::Deadline => CreateFailureCode::Deadline,
    };
    CreateFailure::not_created(code, failure.detail())
}

fn detail(message: &'static str) -> OperatorDetail {
    OperatorDetail::redacted(message)
}
