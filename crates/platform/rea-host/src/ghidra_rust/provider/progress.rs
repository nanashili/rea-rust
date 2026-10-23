//! Best-effort progress projection for the Rust Ghidra worker.
//!
//! Progress is deliberately kept separate from request replies.  A caller can
//! drain the latest update when its sink is ready, while a completed wire
//! reply never needs to wait for that sink.

const MAX_METHOD_BYTES: usize = 64;
const MAX_LABEL_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerProgress {
    pub label: String,
    pub completed: usize,
    pub total: Option<usize>,
}

impl WorkerProgress {
    pub fn new(
        label: impl Into<String>,
        completed: usize,
        total: Option<usize>,
    ) -> Result<Self, String> {
        let label = label.into();
        validate_text(&label, MAX_LABEL_BYTES, "progress label")?;

        if let Some(total) = total {
            if total < completed {
                return Err("progress total cannot be less than completed".into());
            }
        }

        Ok(Self {
            label,
            completed,
            total,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressUpdate {
    pub phase: String,
    pub completed: usize,
    pub total: Option<usize>,
    pub message: String,
}

impl ProgressUpdate {
    pub fn from_worker(
        sequence: usize,
        method: &str,
        progress: WorkerProgress,
    ) -> Result<Self, String> {
        validate_text(method, MAX_METHOD_BYTES, "worker method")?;
        if method.is_empty() {
            return Err("worker method must not be empty".into());
        }

        let counts = match progress.total {
            Some(total) => format!("{}/{}", progress.completed, total),
            None => progress.completed.to_string(),
        };

        Ok(Self {
            phase: format!("ghidra-rust:{method}"),
            completed: sequence,
            total: None,
            message: format!("{} ({counts})", progress.label),
        })
    }
}

/// Coalesces updates while a caller's progress sink is busy.
#[derive(Default)]
pub struct ProgressBuffer {
    latest: Option<ProgressUpdate>,
    last_sequence: usize,
    discarded: bool,
}

impl ProgressBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept(
        &mut self,
        sequence: usize,
        method: &str,
        progress: WorkerProgress,
    ) -> Result<(), String> {
        if self.discarded {
            return Ok(());
        }

        if sequence == 0 || sequence <= self.last_sequence {
            return Err("progress sequence must increase monotonically".into());
        }

        let update = ProgressUpdate::from_worker(sequence, method, progress)?;
        self.last_sequence = sequence;
        self.latest = Some(update);
        Ok(())
    }

    pub fn take_latest(&mut self) -> Option<ProgressUpdate> {
        if self.discarded {
            return None;
        }
        self.latest.take()
    }

    /// Deliver retained updates through a best-effort sink.
    ///
    /// The sink may observe more recent progress while it handles an update.
    /// Taking each item before invoking the sink keeps the buffer bounded and
    /// lets the next iteration deliver that newer item.  Sink failures are
    /// intentionally ignored: progress cannot replace the worker's result.
    pub fn deliver_pending<S, E>(&mut self, mut sink: S)
    where
        S: FnMut(ProgressUpdate) -> Result<(), E>,
    {
        if self.discarded {
            return;
        }

        while let Some(update) = self.latest.take() {
            let _ = sink(update);

            if self.discarded {
                break;
            }
        }
    }

    /// Stop delivery after the request's terminal reply has been received.
    pub fn discard_pending(&mut self) {
        self.discarded = true;
        self.latest = None;
    }

    pub fn is_discarded(&self) -> bool {
        self.discarded
    }
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.len() > maximum {
        return Err(format!("{label} exceeds the bounded size"));
    }
    Ok(())
}
