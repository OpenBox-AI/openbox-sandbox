use crate::{ObservedExitCode, ObservedTimeout, OutputByteCounts, OutputLimitKind, OutputLimits};

use crate::openshell::transport::ExecTransportEvent;

const MAX_STDOUT_BYTES: u64 = 1024 * 1024;
const MAX_STDERR_BYTES: u64 = 1024 * 1024;
const MAX_COMBINED_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CHUNK_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub enum CollectionFailure {
    MissingTerminalExit(OutputByteCounts),
    Overflow {
        counts: OutputByteCounts,
        kind: OutputLimitKind,
    },
    Protocol(OutputByteCounts),
}

pub struct CollectedOutput {
    pub exit_code: ObservedExitCode,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timeout: ObservedTimeout,
}

pub struct OutputCollector {
    limits: OutputLimits,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    counts: OutputByteCounts,
    terminal: Option<(ObservedExitCode, ObservedTimeout)>,
}

impl OutputCollector {
    pub fn new(limits: OutputLimits) -> Self {
        Self {
            limits,
            stdout: Vec::new(),
            stderr: Vec::new(),
            counts: OutputByteCounts::default(),
            terminal: None,
        }
    }

    pub fn push(&mut self, payload: ExecTransportEvent) -> Result<(), CollectionFailure> {
        if self.terminal.is_some() {
            return Err(CollectionFailure::Protocol(self.counts));
        }
        match payload {
            ExecTransportEvent::Stdout(data) => self.push_stdout(data),
            ExecTransportEvent::Stderr(data) => self.push_stderr(data),
            ExecTransportEvent::Exit { code, timeout } => {
                let exit_code = ObservedExitCode::new(code)
                    .map_err(|_| CollectionFailure::Protocol(self.counts))?;
                self.terminal = Some((exit_code, timeout));
                Ok(())
            }
        }
    }

    pub fn finish(self) -> Result<CollectedOutput, CollectionFailure> {
        let Some((exit_code, timeout)) = self.terminal else {
            return Err(CollectionFailure::MissingTerminalExit(self.counts));
        };
        Ok(CollectedOutput {
            exit_code,
            stdout: self.stdout,
            stderr: self.stderr,
            timeout,
        })
    }

    pub const fn counts(&self) -> OutputByteCounts {
        self.counts
    }

    fn push_stdout(&mut self, chunk: Vec<u8>) -> Result<(), CollectionFailure> {
        let chunk_bytes = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        self.counts = OutputByteCounts::new(
            self.counts.stdout_bytes().saturating_add(chunk_bytes),
            self.counts.stderr_bytes(),
        );
        self.check_limits(chunk_bytes, OutputLimitKind::Stdout)?;
        self.stdout.extend_from_slice(&chunk);
        Ok(())
    }

    fn push_stderr(&mut self, chunk: Vec<u8>) -> Result<(), CollectionFailure> {
        let chunk_bytes = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        self.counts = OutputByteCounts::new(
            self.counts.stdout_bytes(),
            self.counts.stderr_bytes().saturating_add(chunk_bytes),
        );
        self.check_limits(chunk_bytes, OutputLimitKind::Stderr)?;
        self.stderr.extend_from_slice(&chunk);
        Ok(())
    }

    fn check_limits(
        &self,
        chunk_bytes: u64,
        stream: OutputLimitKind,
    ) -> Result<(), CollectionFailure> {
        if chunk_bytes > self.limits.chunk_bytes() {
            return Err(self.overflow(OutputLimitKind::Chunk));
        }
        let stream_overflow = match stream {
            OutputLimitKind::Stdout => self.counts.stdout_bytes() > self.limits.stdout_bytes(),
            OutputLimitKind::Stderr => self.counts.stderr_bytes() > self.limits.stderr_bytes(),
            OutputLimitKind::Combined | OutputLimitKind::Chunk => false,
        };
        if stream_overflow {
            return Err(self.overflow(stream));
        }
        if self
            .counts
            .combined_bytes()
            .is_none_or(|total| total > self.limits.combined_bytes())
        {
            return Err(self.overflow(OutputLimitKind::Combined));
        }
        Ok(())
    }

    const fn overflow(&self, kind: OutputLimitKind) -> CollectionFailure {
        CollectionFailure::Overflow {
            counts: self.counts,
            kind,
        }
    }
}

pub const fn limits_within_process_ceiling(limits: OutputLimits) -> bool {
    limits.stdout_bytes() <= MAX_STDOUT_BYTES
        && limits.stderr_bytes() <= MAX_STDERR_BYTES
        && limits.combined_bytes() <= MAX_COMBINED_BYTES
        && limits.chunk_bytes() <= MAX_CHUNK_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> OutputLimits {
        OutputLimits::new(3, 3, 5, 3).unwrap()
    }

    #[test]
    fn collector_preserves_binary_streams_and_raw_nonzero_exit() {
        let mut collector = OutputCollector::new(limits());
        collector
            .push(ExecTransportEvent::Stdout(vec![0, 0xff]))
            .unwrap();
        collector
            .push(ExecTransportEvent::Stderr(vec![0xfe]))
            .unwrap();
        collector
            .push(ExecTransportEvent::Exit {
                code: 7,
                timeout: ObservedTimeout::NotObserved,
            })
            .unwrap();
        let output = collector.finish().unwrap();
        assert_eq!(output.stdout, [0, 0xff]);
        assert_eq!(output.stderr, [0xfe]);
        assert_eq!(output.exit_code.get(), 7);
        assert_eq!(output.timeout, ObservedTimeout::NotObserved);
    }

    #[test]
    fn exit_124_is_preserved_with_only_possible_timeout_evidence() {
        let mut collector = OutputCollector::new(limits());
        collector
            .push(ExecTransportEvent::Exit {
                code: 124,
                timeout: ObservedTimeout::Possible,
            })
            .unwrap();
        let output = collector.finish().unwrap();
        assert_eq!(output.exit_code.get(), 124);
        assert_eq!(output.timeout, ObservedTimeout::Possible);
    }

    #[test]
    fn missing_exit_and_overflow_remain_indeterminate_and_bounded() {
        let mut missing = OutputCollector::new(limits());
        missing.push(ExecTransportEvent::Stdout(vec![1])).unwrap();
        assert!(matches!(
            missing.finish(),
            Err(CollectionFailure::MissingTerminalExit(_))
        ));

        let mut overflow = OutputCollector::new(limits());
        let failure = overflow
            .push(ExecTransportEvent::Stdout(vec![1, 2, 3, 4]))
            .unwrap_err();
        assert!(matches!(
            failure,
            CollectionFailure::Overflow {
                kind: OutputLimitKind::Chunk,
                ..
            }
        ));
        assert_eq!(overflow.stdout, Vec::<u8>::new());
    }

    #[test]
    fn negative_or_post_terminal_events_are_protocol_failures() {
        let mut negative = OutputCollector::new(limits());
        assert!(matches!(
            negative.push(ExecTransportEvent::Exit {
                code: -1,
                timeout: ObservedTimeout::NotObserved,
            }),
            Err(CollectionFailure::Protocol(_))
        ));

        let mut late = OutputCollector::new(limits());
        late.push(ExecTransportEvent::Exit {
            code: 0,
            timeout: ObservedTimeout::NotObserved,
        })
        .unwrap();
        assert!(matches!(
            late.push(ExecTransportEvent::Stderr(vec![1])),
            Err(CollectionFailure::Protocol(_))
        ));
    }
}
