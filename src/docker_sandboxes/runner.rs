//! Asynchronous `sbx` CLI process runner with budget and output-bound enforcement.
//!
//! The runtime talks to Docker Sandboxes exclusively through the standalone
//! `sbx` CLI (there is no documented third-party API surface; the CLI talks to
//! the local `sandboxd` daemon). This module owns subprocess spawn, concurrent
//! stdout/stderr capture, output-limit enforcement, and kill-on-budget
//! behavior, so the operations layer only sees typed outcomes.

use std::path::PathBuf;
use std::process::Stdio;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::time::sleep_until;

use crate::docker_sandboxes::process::{SbxStderrHints, classify_stderr};
use crate::openshell::budget::OperationBudget;
use crate::{
    ObservedTimeout, OperationContext, OperationDeadline, OutputByteCounts, OutputLimitKind,
    OutputLimits,
};

/// Hard capture ceiling for short `sbx` commands (create, ls, rm, version).
const SIMPLE_OUTPUT_CEILING: u64 = 1024 * 1024;

/// One sandbox row from `sbx ls --json`.
pub use crate::docker_sandboxes::process::ListedSandbox;

/// A non-zero or otherwise failed short `sbx` invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SbxRunFailure {
    /// The binary could not be spawned at all.
    Spawn,
    /// The invocation was cancelled before it produced a terminal exit.
    Cancelled,
    /// The invocation reached its operation deadline.
    Deadline,
    /// The invocation exited non-zero.
    NonZero {
        /// The observed exit code.
        exit_code: i32,
        /// Raw stderr, consumed only by [`SbxRunFailure::hints`].
        stderr: Vec<u8>,
    },
}

impl SbxRunFailure {
    /// Returns conservative stderr hints for classification.
    pub fn hints(&self) -> SbxStderrHints {
        match self {
            Self::NonZero { stderr, .. } => classify_stderr(stderr),
            Self::Spawn | Self::Cancelled | Self::Deadline => SbxStderrHints::default(),
        }
    }
}

/// Terminal outcome of a bounded `sbx exec` invocation.
#[derive(Debug, Eq, PartialEq)]
pub struct ExecCapture {
    /// The propagated command exit code, or `None` when the process was killed
    /// by a signal or by this adapter (no terminal code was observed).
    pub exit_code: Option<i32>,
    /// Captured stdout (partial when a limit was exceeded).
    pub stdout: Vec<u8>,
    /// Captured stderr (partial when a limit was exceeded).
    pub stderr: Vec<u8>,
    /// The exceeded output limit, if any.
    pub overflow: Option<OutputLimitKind>,
    /// Byte counts observed for both streams.
    pub counts: OutputByteCounts,
    /// Timeout evidence attached to a completed process.
    pub timeout: ObservedTimeout,
    /// CLI-level failure hints from the `sbx exec` process itself.
    pub cli_hints: SbxStderrHints,
}

/// Why a bounded `sbx exec` invocation did not produce a capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecRunFailure {
    /// The binary could not be spawned; the command was never dispatched.
    Spawn,
    /// The invocation was cancelled after the child started.
    Cancelled(OutputByteCounts),
    /// The invocation reached its operation deadline after the child started.
    Deadline(OutputByteCounts),
}

/// Typed `sbx` process outcomes for the operations layer.
#[async_trait]
pub trait SbxRunner: Send + Sync {
    /// Runs `sbx version` bounded by the given timeout.
    async fn version(&self, timeout: std::time::Duration) -> Result<String, SbxRunFailure>;

    /// Runs `sbx create` with the built argv.
    async fn create(&self, args: &[String], budget: &OperationBudget) -> Result<(), SbxRunFailure>;

    /// Runs `sbx ls --json` and parses the sandbox rows.
    async fn list(&self, budget: &OperationBudget) -> Result<Vec<ListedSandbox>, SbxRunFailure>;

    /// Runs one bounded `sbx exec` invocation.
    async fn exec(
        &self,
        args: &[String],
        budget: &OperationBudget,
        limits: OutputLimits,
    ) -> Result<ExecCapture, ExecRunFailure>;

    /// Runs `sbx rm --force` with the built argv.
    async fn remove(&self, args: &[String], budget: &OperationBudget) -> Result<(), SbxRunFailure>;
}

/// The real runner: spawns the configured `sbx` binary.
pub struct ProcessSbxRunner {
    binary: PathBuf,
}

impl ProcessSbxRunner {
    /// Creates a runner for the configured binary path or bare name.
    pub const fn new(binary: PathBuf) -> Self {
        Self { binary }
    }

    fn command(&self, args: &[String]) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

/// Owns a spawned child and guarantees it is killed unless reaped first.
///
/// The guard is disarmed by `wait` (a completed reap) and kills the child in
/// `Drop` otherwise, so dropping a cancelled capture future cannot orphan the
/// process.
struct ChildGuard {
    child: Child,
    disarmed: bool,
}

impl ChildGuard {
    const fn new(child: Child) -> Self {
        Self {
            child,
            disarmed: false,
        }
    }

    async fn wait(&mut self) -> std::process::ExitStatus {
        self.disarmed = true;
        self.child
            .wait()
            .await
            .expect("reaping a spawned child cannot fail")
    }

    async fn kill_and_wait(&mut self) {
        if !self.disarmed {
            let _ = self.child.kill().await;
            let _ = self.child.wait().await;
            self.disarmed = true;
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            let _ = self.child.start_kill();
        }
    }
}

/// Shared byte accounting for the two concurrent capture readers.
#[derive(Default)]
struct CaptureState {
    stdout_bytes: u64,
    stderr_bytes: u64,
    overflow: Option<OutputLimitKind>,
}

impl CaptureState {
    fn observe(
        &mut self,
        stream: OutputLimitKind,
        chunk_bytes: u64,
        limits: OutputLimits,
    ) -> Option<OutputLimitKind> {
        if let Some(overflow) = self.overflow {
            return Some(overflow);
        }
        match stream {
            OutputLimitKind::Stdout => {
                self.stdout_bytes = self.stdout_bytes.saturating_add(chunk_bytes);
            }
            OutputLimitKind::Stderr => {
                self.stderr_bytes = self.stderr_bytes.saturating_add(chunk_bytes);
            }
            OutputLimitKind::Combined | OutputLimitKind::Chunk => {}
        }
        let combined = self.stdout_bytes.saturating_add(self.stderr_bytes);
        let overflow = if chunk_bytes > limits.chunk_bytes() {
            Some(OutputLimitKind::Chunk)
        } else if stream == OutputLimitKind::Stdout && self.stdout_bytes > limits.stdout_bytes() {
            Some(OutputLimitKind::Stdout)
        } else if stream == OutputLimitKind::Stderr && self.stderr_bytes > limits.stderr_bytes() {
            Some(OutputLimitKind::Stderr)
        } else if combined > limits.combined_bytes() {
            Some(OutputLimitKind::Combined)
        } else {
            None
        };
        self.overflow = overflow;
        overflow
    }

    const fn counts(&self) -> OutputByteCounts {
        OutputByteCounts::new(self.stdout_bytes, self.stderr_bytes)
    }
}

#[async_trait]
impl SbxRunner for ProcessSbxRunner {
    async fn version(&self, timeout: std::time::Duration) -> Result<String, SbxRunFailure> {
        let budget = OperationBudget::new(OperationContext::new(
            tokio_util::sync::CancellationToken::new(),
            OperationDeadline::new(timeout).expect("connect timeout is validated positive"),
        ));
        let mut command = self.command(&crate::docker_sandboxes::process::build_version_args());
        match run_simple(&mut command, &budget).await {
            Ok(output) if output.status.success() => {
                String::from_utf8(output.stdout).map_err(|_| SbxRunFailure::NonZero {
                    exit_code: 0,
                    stderr: Vec::new(),
                })
            }
            Ok(output) => Err(SbxRunFailure::NonZero {
                exit_code: output.status.code().unwrap_or(1),
                stderr: output.stderr,
            }),
            Err(failure) => Err(failure),
        }
    }

    async fn create(&self, args: &[String], budget: &OperationBudget) -> Result<(), SbxRunFailure> {
        let mut command = self.command(args);
        match run_simple(&mut command, budget).await {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(SbxRunFailure::NonZero {
                exit_code: output.status.code().unwrap_or(1),
                stderr: output.stderr,
            }),
            Err(failure) => Err(failure),
        }
    }

    async fn list(&self, budget: &OperationBudget) -> Result<Vec<ListedSandbox>, SbxRunFailure> {
        let mut command = self.command(&crate::docker_sandboxes::process::build_list_args());
        match run_simple(&mut command, budget).await {
            Ok(output) if output.status.success() => {
                let body =
                    String::from_utf8(output.stdout).map_err(|_| SbxRunFailure::NonZero {
                        exit_code: 0,
                        stderr: Vec::new(),
                    })?;
                crate::docker_sandboxes::process::parse_sandbox_list(&body).map_err(|()| {
                    SbxRunFailure::NonZero {
                        exit_code: 0,
                        stderr: body.into_bytes(),
                    }
                })
            }
            Ok(output) => Err(SbxRunFailure::NonZero {
                exit_code: output.status.code().unwrap_or(1),
                stderr: output.stderr,
            }),
            Err(failure) => Err(failure),
        }
    }

    async fn exec(
        &self,
        args: &[String],
        budget: &OperationBudget,
        limits: OutputLimits,
    ) -> Result<ExecCapture, ExecRunFailure> {
        let mut command = self.command(args);
        let mut child = command.spawn().map_err(|_| ExecRunFailure::Spawn)?;
        let stdout = child.stdout.take().expect("sbx stdout is piped");
        let stderr = child.stderr.take().expect("sbx stderr is piped");
        collect_exec(child, stdout, stderr, budget, limits).await
    }

    async fn remove(&self, args: &[String], budget: &OperationBudget) -> Result<(), SbxRunFailure> {
        let mut command = self.command(args);
        match run_simple(&mut command, budget).await {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(SbxRunFailure::NonZero {
                exit_code: output.status.code().unwrap_or(1),
                stderr: output.stderr,
            }),
            Err(failure) => Err(failure),
        }
    }
}

struct SimpleOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Runs a short `sbx` command with capped output and kill-on-budget.
async fn run_simple(
    command: &mut Command,
    budget: &OperationBudget,
) -> Result<SimpleOutput, SbxRunFailure> {
    let Ok(mut child) = command.spawn() else {
        return Err(SbxRunFailure::Spawn);
    };
    let stdout = child.stdout.take().expect("sbx stdout is piped");
    let stderr = child.stderr.take().expect("sbx stderr is piped");
    let mut guard = ChildGuard::new(child);
    let out_task = tokio::spawn(read_capped(stdout, SIMPLE_OUTPUT_CEILING));
    let err_task = tokio::spawn(read_capped(stderr, SIMPLE_OUTPUT_CEILING));
    let branch = tokio::select! {
        biased;
        () = budget.cancellation().cancelled() => SimpleBranch::Cancelled,
        () = sleep_until(budget.deadline_instant()) => SimpleBranch::Deadline,
        status = guard.wait() => SimpleBranch::Completed(status),
    };
    if !matches!(branch, SimpleBranch::Completed(_)) {
        guard.kill_and_wait().await;
    }
    let stdout = out_task.await.unwrap_or_default();
    let stderr = err_task.await.unwrap_or_default();
    match branch {
        SimpleBranch::Cancelled => Err(SbxRunFailure::Cancelled),
        SimpleBranch::Deadline => Err(SbxRunFailure::Deadline),
        SimpleBranch::Completed(status) => Ok(SimpleOutput {
            status,
            stdout,
            stderr,
        }),
    }
}

enum SimpleBranch {
    Cancelled,
    Deadline,
    Completed(std::process::ExitStatus),
}

/// Reads a stream up to a hard ceiling, then stops (the caller kills the
/// child when the ceiling is hit so it cannot block on a full pipe).
async fn read_capped<R>(mut reader: R, ceiling: u64) -> Vec<u8>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut sink = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let count = match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        let remaining = ceiling.saturating_sub(u64::try_from(sink.len()).unwrap_or(u64::MAX));
        let take = usize::try_from(remaining.min(u64::try_from(count).unwrap_or(u64::MAX)))
            .unwrap_or(count);
        sink.extend_from_slice(&chunk[..take]);
        if take < count || u64::try_from(sink.len()).unwrap_or(u64::MAX) >= ceiling {
            break;
        }
    }
    sink
}

enum ExecBranch {
    Cancelled,
    Deadline,
    Overflow,
    Completed(std::process::ExitStatus),
}

/// Captures one `sbx exec` invocation with per-stream, combined, and chunk
/// ceilings enforced concurrently with the operation budget.
async fn collect_exec<R1, R2>(
    child: Child,
    stdout: R1,
    stderr: R2,
    budget: &OperationBudget,
    limits: OutputLimits,
) -> Result<ExecCapture, ExecRunFailure>
where
    R1: AsyncRead + Unpin + Send + 'static,
    R2: AsyncRead + Unpin + Send + 'static,
{
    let mut guard = ChildGuard::new(child);
    let state = std::sync::Arc::new(std::sync::Mutex::new(CaptureState::default()));
    let (overflow_tx, mut overflow_rx) = tokio::sync::mpsc::channel::<OutputLimitKind>(1);
    let out_state = state.clone();
    let err_state = state.clone();
    let out_overflow = overflow_tx.clone();
    let out_task = tokio::spawn(read_bounded(
        stdout,
        OutputLimitKind::Stdout,
        limits,
        out_state,
        out_overflow,
    ));
    let err_task = tokio::spawn(read_bounded(
        stderr,
        OutputLimitKind::Stderr,
        limits,
        err_state,
        overflow_tx,
    ));
    let branch = tokio::select! {
        biased;
        () = budget.cancellation().cancelled() => ExecBranch::Cancelled,
        () = sleep_until(budget.deadline_instant()) => ExecBranch::Deadline,
        _ = overflow_rx.recv() => ExecBranch::Overflow,
        status = guard.wait() => ExecBranch::Completed(status),
    };
    if !matches!(branch, ExecBranch::Completed(_)) {
        guard.kill_and_wait().await;
    }
    let (stdout, stderr) = tokio::join!(out_task, err_task);
    let (stdout, stderr) = (stdout.unwrap_or_default(), stderr.unwrap_or_default());
    let counts = state.lock().expect("capture state mutex poisoned").counts();
    match branch {
        ExecBranch::Cancelled => Err(ExecRunFailure::Cancelled(counts)),
        ExecBranch::Deadline => Err(ExecRunFailure::Deadline(counts)),
        ExecBranch::Overflow => {
            let overflow = state.lock().expect("capture state mutex poisoned").overflow;
            Ok(ExecCapture {
                exit_code: None,
                stdout,
                stderr,
                overflow,
                counts,
                timeout: ObservedTimeout::NotObserved,
                cli_hints: SbxStderrHints::default(),
            })
        }
        ExecBranch::Completed(status) => {
            let hints = classify_stderr(&stderr);
            let timeout = if status.code() == Some(124) {
                ObservedTimeout::Possible
            } else {
                ObservedTimeout::NotObserved
            };
            Ok(ExecCapture {
                exit_code: status.code(),
                stdout,
                stderr,
                overflow: None,
                counts,
                timeout,
                cli_hints: hints,
            })
        }
    }
}

/// Reads one stream, enforcing the shared ceilings, and signals the first
/// overflow on the channel before stopping.
async fn read_bounded<R>(
    mut reader: R,
    stream: OutputLimitKind,
    limits: OutputLimits,
    state: std::sync::Arc<std::sync::Mutex<CaptureState>>,
    overflow: tokio::sync::mpsc::Sender<OutputLimitKind>,
) -> Vec<u8>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut sink = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let count = match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        let overflowed = state.lock().expect("capture state mutex poisoned").observe(
            stream,
            u64::try_from(count).unwrap_or(u64::MAX),
            limits,
        );
        if let Some(kind) = overflowed {
            let _ = overflow.try_send(kind);
            break;
        }
        sink.extend_from_slice(&chunk[..count]);
    }
    sink
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_state_enforces_stream_combined_and_chunk_ceilings() {
        let limits = OutputLimits::new(3, 3, 5, 3).unwrap();
        let mut state = CaptureState::default();
        assert_eq!(state.observe(OutputLimitKind::Stdout, 2, limits), None);
        assert_eq!(state.observe(OutputLimitKind::Stderr, 2, limits), None);
        assert_eq!(
            state.observe(OutputLimitKind::Stdout, 2, limits),
            Some(OutputLimitKind::Stdout)
        );
        assert_eq!(state.counts().combined_bytes(), Some(6));

        let mut chunked = CaptureState::default();
        assert_eq!(
            chunked.observe(OutputLimitKind::Stdout, 4, limits),
            Some(OutputLimitKind::Chunk)
        );

        let mut combined = CaptureState::default();
        assert_eq!(combined.observe(OutputLimitKind::Stdout, 3, limits), None);
        assert_eq!(
            combined.observe(OutputLimitKind::Stderr, 3, limits),
            Some(OutputLimitKind::Combined)
        );
    }

    #[test]
    fn first_overflow_wins_after_the_fact() {
        let limits = OutputLimits::new(3, 3, 5, 3).unwrap();
        let mut state = CaptureState::default();
        assert_eq!(state.observe(OutputLimitKind::Stderr, 3, limits), None);
        assert_eq!(
            state.observe(OutputLimitKind::Stderr, 1, limits),
            Some(OutputLimitKind::Stderr)
        );
        assert_eq!(
            state.observe(OutputLimitKind::Stdout, 1, limits),
            Some(OutputLimitKind::Stderr)
        );
    }

    #[tokio::test]
    async fn capped_reader_stops_at_the_ceiling() {
        let payload = vec![7_u8; 100_000];
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);
        let writer_task = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut payload.as_slice(), &mut writer).await;
        });
        let read = read_capped(reader, 10_000).await;
        assert_eq!(read.len(), 10_000);
        writer_task.await.unwrap();
    }

    #[tokio::test]
    async fn bounded_reader_signals_overflow_and_stops() {
        let limits = OutputLimits::new(1024, 1024, 2048, 8192).unwrap();
        let (overflow_tx, mut overflow_rx) = tokio::sync::mpsc::channel::<OutputLimitKind>(1);
        let payload = vec![7_u8; 4096];
        let (mut writer, reader) = tokio::io::duplex(8192);
        let state = std::sync::Arc::new(std::sync::Mutex::new(CaptureState::default()));
        let writer_task = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut payload.as_slice(), &mut writer).await;
        });
        let read = read_bounded(
            reader,
            OutputLimitKind::Stdout,
            limits,
            state.clone(),
            overflow_tx,
        )
        .await;
        assert_eq!(overflow_rx.recv().await, Some(OutputLimitKind::Stdout));
        assert!(read.len() <= 1024 + 8192);
        writer_task.await.unwrap();
    }
}
