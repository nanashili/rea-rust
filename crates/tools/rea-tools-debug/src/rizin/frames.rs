//! Rizin NUL-frame receiver and per-command frame correlation.
//!
//! Compatibility owner: `src/rizin/RizinDebugSessionManager.ts`
//! (`#receive`, `#deliverBufferedFrame`, `#deliverFrame`, `#failProtocol`,
//! `bufferedRizinFrame`, `hasUnclaimedRizinFrames`, `waitForFrame`,
//! `waitForCommandFrames`, `truncateUtf8`). The TypeScript single waiter
//! (`frameWaiters`) is modelled by `Core::waiting` plus a one-frame hand-off
//! slot and a rejection slot, so a frame delivered while a command waits is
//! never queued (and never charged against the unsolicited-frame bound).

use rea_core::cancellation::Cancellation;
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::debugger::OwnedInferiorIdentity;
use crate::debugger::process::DebuggerProcess;

pub(super) const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_COMMAND_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_QUEUED_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_QUEUED_FRAMES: usize = 4096;
const MIN_QUEUED_FRAME_CHARGE_BYTES: usize = 64;
const MAX_COMMAND_FRAMES: usize = 4096;
const MAX_RECENT_FRAME_BYTES: usize = 16 * 1024;
const MAX_RECENT_FRAMES: usize = 64;
pub(super) const CLEANUP_COMMAND_TIMEOUT_MS: u64 = 1_000;
/// Poll interval for exit observation and cancellation while waiting.
const WAIT_POLL: Duration = Duration::from_millis(10);

/// One decoded NUL frame (`RizinFrame`).
#[derive(Clone, Debug)]
pub(super) struct Frame {
    pub(super) text: String,
    pub(super) truncated: bool,
    pub(super) invalid_utf8: bool,
}

/// Rejection delivered to the single pending frame waiter.
#[derive(Clone, Debug)]
enum Rejection {
    Exited,
    Failed(String),
}

/// `waitForFrame` failure causes.
#[derive(Clone, Debug)]
pub(super) enum WaitError {
    Cancelled,
    /// `RizinProcessExitError` with its message.
    Exited(String),
    Timeout,
    Failed(String),
}

pub(super) const PROCESS_EXIT_MESSAGE: &str = "Rizin exited before completing the active command";
const FRAME_TIMEOUT_MESSAGE: &str = "Timed out waiting for the next Rizin NUL frame";

impl WaitError {
    pub(super) fn message(&self) -> String {
        match self {
            Self::Cancelled => "Analysis operation was cancelled.".to_owned(),
            Self::Exited(message) | Self::Failed(message) => message.clone(),
            Self::Timeout => FRAME_TIMEOUT_MESSAGE.to_owned(),
        }
    }
}

/// Mutable session protocol state shared with the stdout reader thread.
#[derive(Default)]
pub(super) struct Core {
    frames: VecDeque<(Frame, usize)>,
    waiting: bool,
    handoff: Option<Frame>,
    rejection: Option<Rejection>,
    pub(super) history: Vec<String>,
    queued_frame_bytes: usize,
    pub(super) history_truncated: bool,
    frame_chunks: Vec<u8>,
    pub(super) ready: bool,
    pub(super) exited: bool,
    pub(super) protocol_error: Option<String>,
    pub(super) command_capture_active: bool,
    pub(super) command_output_dropped: bool,
    discarding_oversized_frame: bool,
    pub(super) invalid_utf8_observed: bool,
    pub(super) closing: bool,
    pub(super) inferior_inventory_complete: bool,
    pub(super) known_inferior_identities: Vec<OwnedInferiorIdentity>,
}

impl Core {
    /// `hasUnclaimedRizinFrames`.
    pub(super) fn has_unclaimed_frames(&self) -> bool {
        !self.frames.is_empty() || !self.frame_chunks.is_empty() || self.discarding_oversized_frame
    }

    /// `#failProtocol`.
    pub(super) fn fail_protocol(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.protocol_error = Some(message.clone());
        if !self.command_capture_active {
            self.frame_chunks.clear();
        }
        if self.waiting {
            self.waiting = false;
            self.rejection = Some(Rejection::Failed(message));
        }
    }

    /// Process `exit` listener: mark exited and reject the pending waiter.
    fn mark_exited(&mut self) {
        if self.exited {
            return;
        }
        self.exited = true;
        if self.waiting {
            self.waiting = false;
            self.rejection = Some(Rejection::Exited);
        }
    }

    /// `#receive`: split a stdout chunk into bounded NUL frames.
    pub(super) fn receive(&mut self, chunk: &[u8]) {
        let mut offset = 0;
        while offset < chunk.len() {
            let boundary = chunk[offset..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|index| offset + index);
            let end = boundary.unwrap_or(chunk.len());
            let piece = &chunk[offset..end];
            if self.discarding_oversized_frame {
                let Some(boundary) = boundary else { return };
                self.discarding_oversized_frame = false;
                offset = boundary + 1;
                continue;
            }
            if self.frame_chunks.len() + piece.len() > MAX_FRAME_BYTES {
                let message = "Rizin emitted an NUL frame exceeding the 16 MiB protocol limit.";
                if !self.command_capture_active {
                    self.fail_protocol(message);
                    return;
                }
                self.protocol_error = Some(message.to_owned());
                self.history_truncated = true;
                let remaining = MAX_FRAME_BYTES - self.frame_chunks.len();
                if remaining > 0 {
                    self.frame_chunks.extend_from_slice(&piece[..remaining]);
                }
                let Some(boundary) = boundary else {
                    self.discarding_oversized_frame = true;
                    self.deliver_buffered_frame(true);
                    return;
                };
                self.deliver_buffered_frame(true);
                offset = boundary + 1;
                continue;
            }
            self.frame_chunks.extend_from_slice(piece);
            let Some(boundary) = boundary else { return };
            self.deliver_buffered_frame(false);
            offset = boundary + 1;
        }
    }

    /// `bufferedRizinFrame`: decode the retained partial frame once.
    pub(super) fn buffered_frame(&mut self, truncated: bool) -> (usize, Frame) {
        let invalid_utf8 = std::str::from_utf8(&self.frame_chunks).is_err();
        self.invalid_utf8_observed |= invalid_utf8;
        (
            self.frame_chunks.len(),
            Frame {
                text: String::from_utf8_lossy(&self.frame_chunks).into_owned(),
                truncated,
                invalid_utf8,
            },
        )
    }

    fn deliver_buffered_frame(&mut self, truncated: bool) {
        let (bytes, frame) = self.buffered_frame(truncated);
        self.frame_chunks.clear();
        self.deliver_frame(frame, bytes);
    }

    /// `#deliverFrame`.
    fn deliver_frame(&mut self, frame: Frame, frame_bytes: usize) {
        let prefix = truncate_utf8(&frame.text, MAX_RECENT_FRAME_BYTES);
        let history_truncated = prefix.len() < frame.text.len() || frame.truncated;
        if history_truncated {
            self.history_truncated = true;
        }
        self.history.push(if history_truncated {
            format!("{prefix}[recent frame truncated]")
        } else {
            prefix.to_owned()
        });
        if self.history.len() > MAX_RECENT_FRAMES {
            let excess = self.history.len() - MAX_RECENT_FRAMES;
            self.history.drain(..excess);
            self.history_truncated = true;
        }
        if self.waiting {
            self.waiting = false;
            self.handoff = Some(frame);
            return;
        }
        let charge = frame_bytes.max(MIN_QUEUED_FRAME_CHARGE_BYTES);
        if self.frames.len() >= MAX_QUEUED_FRAMES
            || self.queued_frame_bytes + charge > MAX_QUEUED_FRAME_BYTES
        {
            self.command_output_dropped |= self.command_capture_active;
            self.fail_protocol(
                "Rizin produced unsolicited frames exceeding the bounded queue limit.",
            );
            return;
        }
        self.frames.push_back((frame, charge));
        self.queued_frame_bytes += charge;
    }

    fn pop_queued(&mut self) -> Option<Frame> {
        let (frame, charge) = self.frames.pop_front()?;
        self.queued_frame_bytes -= charge;
        Some(frame)
    }

    /// Startup diagnostics text: history plus any partial frame.
    pub(super) fn protocol_output(&mut self) -> String {
        let (_, partial) = self.buffered_frame(false);
        self.history
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(partial.text.as_str()))
            .filter(|frame| !frame.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Session protocol state plus its change notification.
#[derive(Default)]
pub(super) struct Shared {
    pub(super) core: Mutex<Core>,
    changed: Condvar,
}

impl Shared {
    pub(super) fn lock(&self) -> MutexGuard<'_, Core> {
        self.core
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Stdout reader callback.
    pub(super) fn on_stdout(&self, chunk: &[u8]) {
        self.lock().receive(chunk);
        self.changed.notify_all();
    }

    pub(super) fn notify(&self) {
        self.changed.notify_all();
    }

    /// Observe the owned leader's exit (the TS `exit` event).
    pub(super) fn observe_exit(core: &mut Core, process: &DebuggerProcess) {
        if !core.exited && matches!(process.try_wait(), Ok(Some(_))) {
            core.mark_exited();
        }
    }

    /// `waitForFrame`.
    pub(super) fn wait_for_frame<'a>(
        &'a self,
        mut core: MutexGuard<'a, Core>,
        process: &DebuggerProcess,
        timeout: Duration,
        cancellation: Option<&Cancellation>,
    ) -> (MutexGuard<'a, Core>, Result<Frame, WaitError>) {
        let cancelled = || cancellation.is_some_and(|c| c.reason().is_some());
        if cancelled() {
            return (core, Err(WaitError::Cancelled));
        }
        if let Some(frame) = core.pop_queued() {
            return (core, Ok(frame));
        }
        Self::observe_exit(&mut core, process);
        if core.exited {
            return (
                core,
                Err(WaitError::Exited(PROCESS_EXIT_MESSAGE.to_owned())),
            );
        }
        let deadline = Instant::now() + timeout;
        core.waiting = true;
        core.handoff = None;
        core.rejection = None;
        loop {
            if let Some(frame) = core.handoff.take() {
                return (core, Ok(frame));
            }
            if let Some(rejection) = core.rejection.take() {
                return (
                    core,
                    Err(match rejection {
                        Rejection::Exited => WaitError::Exited(PROCESS_EXIT_MESSAGE.to_owned()),
                        Rejection::Failed(message) => WaitError::Failed(message),
                    }),
                );
            }
            if cancelled() {
                core.waiting = false;
                return (core, Err(WaitError::Cancelled));
            }
            Self::observe_exit(&mut core, process);
            if !core.waiting {
                continue;
            }
            let now = Instant::now();
            if now >= deadline {
                core.waiting = false;
                return (core, Err(WaitError::Timeout));
            }
            let wait = (deadline - now).min(WAIT_POLL);
            core = self
                .changed
                .wait_timeout(core, wait)
                .map(|(guard, _)| guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner().0);
        }
    }
}

/// Collected command output (`RizinCommandCapture`).
#[derive(Clone, Debug, Default)]
pub(super) struct Capture {
    pub(super) output: String,
    pub(super) output_truncated: bool,
    pub(super) output_invalid_utf8: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InterruptionKind {
    Cancelled,
    Exited,
    Timeout,
    Failed,
}

/// `RizinCommandInterruption`.
#[derive(Clone, Debug)]
pub(super) struct Interruption {
    pub(super) kind: InterruptionKind,
    pub(super) cause: String,
    pub(super) capture: Capture,
}

struct Accumulator<'m> {
    marker: &'m str,
    max_bytes: usize,
    output: Vec<String>,
    output_bytes: usize,
    invalid_utf8: bool,
    truncated: bool,
    frame_count: usize,
}

impl Accumulator<'_> {
    fn snapshot(&self, core: &Core) -> Capture {
        Capture {
            output: self.output.join("\n"),
            output_truncated: self.truncated || core.command_output_dropped,
            output_invalid_utf8: self.invalid_utf8,
        }
    }

    /// `append`: returns whether the private marker was seen.
    fn append(&mut self, frame: &Frame) -> bool {
        self.invalid_utf8 |= frame.invalid_utf8;
        self.truncated |= frame.truncated;
        let marker_index = frame.text.find(self.marker);
        let text = marker_index.map_or(frame.text.as_str(), |index| &frame.text[..index]);
        if marker_index.is_some() && text.is_empty() {
            return true;
        }
        let separator = usize::from(!self.output.is_empty());
        let remaining = self
            .max_bytes
            .saturating_sub(self.output_bytes)
            .saturating_sub(separator);
        if text.len() > remaining {
            self.truncated = true;
            let retained = truncate_utf8(text, remaining);
            if !retained.is_empty() {
                self.output.push(retained.to_owned());
            }
            self.output_bytes = self.max_bytes;
        } else {
            self.output.push(text.to_owned());
            self.output_bytes += separator + text.len();
        }
        marker_index.is_some()
    }

    /// `interrupted`: claim queued and partial frames for this command.
    fn interrupted(&mut self, core: &mut Core) -> Capture {
        let mut marker_seen = false;
        while let Some(frame) = core.pop_queued() {
            self.frame_count += 1;
            if self.frame_count > MAX_COMMAND_FRAMES {
                self.truncated = true;
                break;
            }
            marker_seen = self.append(&frame);
            if marker_seen || self.truncated {
                break;
            }
        }
        if !marker_seen && !self.truncated && !core.frame_chunks.is_empty() {
            let discarding = core.discarding_oversized_frame;
            let (_, frame) = core.buffered_frame(discarding);
            self.append(&frame);
        } else if !core.frame_chunks.is_empty() && !marker_seen {
            self.truncated = true;
        }
        core.frame_chunks.clear();
        self.snapshot(core)
    }
}

/// `waitForCommandFrames`.
pub(super) fn wait_for_command_frames(
    shared: &Shared,
    process: &DebuggerProcess,
    marker: &str,
    timeout_ms: u64,
    cancellation: Option<&Cancellation>,
    max_command_output_bytes: usize,
) -> Result<Capture, Interruption> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut acc = Accumulator {
        marker,
        max_bytes: max_command_output_bytes,
        output: Vec::new(),
        output_bytes: 0,
        invalid_utf8: false,
        truncated: false,
        frame_count: 0,
    };
    loop {
        let mut core = shared.lock();
        if let Some(error) = core.protocol_error.clone() {
            let capture = acc.interrupted(&mut core);
            if core.command_output_dropped {
                return Ok(capture);
            }
            return Err(Interruption {
                kind: InterruptionKind::Failed,
                cause: error,
                capture,
            });
        }
        let now = Instant::now();
        if now >= deadline {
            let capture = acc.interrupted(&mut core);
            return Err(Interruption {
                kind: InterruptionKind::Timeout,
                cause: FRAME_TIMEOUT_MESSAGE.to_owned(),
                capture,
            });
        }
        let (mut core, received) =
            shared.wait_for_frame(core, process, deadline - now, cancellation);
        match received {
            Err(cause) => {
                let mut drained = true;
                if matches!(cause, WaitError::Exited(_)) {
                    drop(core);
                    // `exit` observes the leader, not its pipe lifetime.
                    drained = process
                        .wait_for_output_close(Duration::from_millis(CLEANUP_COMMAND_TIMEOUT_MS));
                    core = shared.lock();
                }
                let mut capture = acc.interrupted(&mut core);
                capture.output_truncated |= !drained;
                let kind = match cause {
                    WaitError::Cancelled => InterruptionKind::Cancelled,
                    WaitError::Exited(_) => InterruptionKind::Exited,
                    WaitError::Timeout => InterruptionKind::Timeout,
                    WaitError::Failed(_) => InterruptionKind::Failed,
                };
                return Err(Interruption {
                    kind,
                    cause: cause.message(),
                    capture,
                });
            }
            Ok(frame) => {
                acc.frame_count += 1;
                if acc.frame_count > MAX_COMMAND_FRAMES {
                    core.protocol_error = Some(
                        "Rizin emitted more than 4096 frames for one command; the session was stopped because output correlation is ambiguous."
                            .to_owned(),
                    );
                    acc.truncated = true;
                    return Ok(acc.snapshot(&core));
                }
                let marker_seen = acc.append(&frame);
                if acc.truncated {
                    core.protocol_error.get_or_insert_with(|| {
                        "Rizin command output exceeded the 16 MiB command limit.".to_owned()
                    });
                    return Ok(acc.snapshot(&core));
                }
                if marker_seen {
                    return Ok(acc.snapshot(&core));
                }
            }
        }
    }
}

/// `truncateUtf8`: longest UTF-8 prefix within `maximum_bytes`.
pub(super) fn truncate_utf8(value: &str, maximum_bytes: usize) -> &str {
    if value.len() <= maximum_bytes {
        return value;
    }
    let mut end = maximum_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}
