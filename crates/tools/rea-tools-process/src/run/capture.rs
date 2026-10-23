//! One controlled process run on an owned PTY.
//!
//! Compatibility owners: `runProcessScenario`, `startCaptureRuntime`,
//! `completeCapture` and `finishProcessRun` (`ProcessHarness.ts`) with
//! `awaitTerminalExit`, `captureTerminalFrames`, `observeSettlement`,
//! `prepareProcessCapture` and the resource owner of
//! `ProcessCaptureLifecycle.ts`, and `scheduleScenarioInteractions`
//! (`ProcessCaptureJournal.ts`).
//!
//! The run is driven from one thread: PTY output, scheduled interactions,
//! exit, deadlines and cancellation are polled in observation order, and the
//! sampler runs on its own thread. Rendering of a chunk is applied after the
//! exit check of the same turn, like xterm's asynchronous write callback.
//!
//! Root authority: the PTY child is this process's own unreaped child and
//! session leader (`rea_host::process::pty`), so root signals and the root
//! group kill are identity-verified through that owner instead of by reading
//! the root's environment. The original could only use the run token and
//! therefore could not signal or clean up Apple platform-binary roots after a
//! finalization deadline. Descendants outside the root group still need the
//! run token (`rea_host::process::ownership`).

use super::normalize::{Bounded, Normalizer, RawSample, bucket};
use super::paths::{LaunchedExecutable, capture_environment, observe_launched_executable, observe_selected_executable};
use super::renderer::Renderer;
use super::result::{self, CaptureFacts};
use super::sampler::{Sampler, SamplerContext};
use super::scenario::{EventKind, Scenario};
use super::snapshot::{Snapshot, classify_effects, snapshot_roots};
use rea_host::process::ownership::{self, GroupObservation, OwnershipBaseline, OwnershipRelation};
use rea_host::process::pty::{OwnedPtyProcess, PtyEvent, PtyLaunchSpec, PtyOutput};
use rea_host::process::terminal::{TerminalSize, Utf8Decoder};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

const POLL: Duration = Duration::from_millis(2);
/// The oracle writes input inside a timer callback and can read the master
/// only on a later libuv loop turn (measured 50-100 µs on macOS), so the
/// line-discipline echo and the child's reply are usually one onData chunk.
/// Reading immediately after write(2) sees the echo alone. Holding the first
/// read after an input write for one loop turn reproduces that coalescing;
/// it does not delay reads otherwise. Remains timing-dependent, as in Node.
const INPUT_LOOP_TURN: Duration = Duration::from_micros(250);
const SETTLE_INTERVAL: Duration = Duration::from_millis(50);
const JOURNAL_QUIET: Duration = Duration::from_millis(25);
const JOURNAL_MAX_WAIT: Duration = Duration::from_millis(500);

/// Host facilities for one run.
pub struct CaptureHost<'a> {
    pub environment: &'a HashMap<String, String>,
    pub cancelled: &'a (dyn Fn() -> bool + Sync),
    pub progress: &'a dyn Fn(&str, String),
}

/// Why a run did not produce a verified capture (`ProcessCaptureError` facts).
#[derive(Debug)]
pub struct CaptureFailure {
    pub message: String,
    pub cancelled: bool,
    pub execution_failure: Option<String>,
    pub cleanup_report: Option<Value>,
    pub partial_observation: Option<Value>,
    /// Owner of resources whose cleanup did not finish.
    pub retained: Option<RetainedResources>,
}

/// Resources retained for retry after a failed cleanup.
#[derive(Debug)]
pub struct RetainedResources {
    pub pty: Option<OwnedPtyProcess>,
    pub run_id: String,
    pub baseline: OwnershipBaseline,
    pub relation: OwnershipRelation,
    pub temporary_root: Option<PathBuf>,
    pub report: Value,
}

/// `{ state, reason }` cleanup outcome.
fn outcome(state: &str, reason: Option<String>) -> Value {
    json!({"state": state, "reason": reason})
}

fn sorted_report(owned: Value, renderer: Value, temporary: Value) -> Value {
    json!({"owned_process_group": owned, "terminal_renderer": renderer, "temporary_root": temporary})
}

/// `cleanupReportFailure`.
pub fn report_failure(report: &Value) -> Option<String> {
    let failures: Vec<String> = ["owned_process_group", "terminal_renderer", "temporary_root"]
        .iter()
        .filter(|key| matches!(report[**key]["state"].as_str(), Some("failed" | "unverified")))
        .map(|key| format!("{key}: {}", report[*key]["reason"].as_str().unwrap_or_else(|| report[*key]["state"].as_str().unwrap_or_default())))
        .collect();
    (!failures.is_empty()).then(|| failures.join("; "))
}

/// Unresolved resource names of a report.
pub fn report_resources(report: &Value) -> Vec<String> {
    ["owned_process_group", "terminal_renderer", "temporary_root"]
        .iter()
        .filter(|key| matches!(report[**key]["state"].as_str(), Some("failed" | "unverified")))
        .map(|key| (*key).to_owned())
        .collect()
}

impl RetainedResources {
    /// Release the PTY group, sweep token-owned descendants, remove the root.
    pub fn release(&mut self) -> Value {
        let owned = if self.report["owned_process_group"]["state"] == "cleaned" || self.report["owned_process_group"]["state"] == "not_required" {
            self.report["owned_process_group"].clone()
        } else {
            let root = match self.pty.as_mut().map(OwnedPtyProcess::cancel) {
                Some(Err(error)) => Some(error.message),
                _ => None,
            };
            match root {
                Some(reason) => outcome("failed", Some(reason)),
                None => {
                    let result = ownership::cleanup_token_owned_processes(&self.run_id, &self.baseline, &self.relation);
                    let mut value = if result.cleaned {
                        outcome("cleaned", None)
                    } else {
                        outcome("unverified", result.reason.clone())
                    };
                    if !result.unverified.is_empty() {
                        let mut seen = Vec::new();
                        for item in &result.unverified {
                            let entry = json!({"pid": item.pid, "reason": item.diagnostic});
                            if !seen.contains(&entry) {
                                seen.push(entry);
                            }
                        }
                        value["unverified_processes"] = Value::Array(seen);
                    }
                    value
                }
            }
        };
        let temporary = if self.report["temporary_root"]["state"] == "cleaned" || self.report["temporary_root"]["state"] == "not_required" {
            self.report["temporary_root"].clone()
        } else if matches!(owned["state"].as_str(), Some("failed" | "unverified")) {
            outcome(
                "unverified",
                Some(format!(
                    "temporary root retained because owned process cleanup is {}: {}",
                    owned["state"].as_str().unwrap_or_default(),
                    owned["reason"].as_str().unwrap_or("ownership could not be verified")
                )),
            )
        } else {
            match &self.temporary_root {
                None => outcome("not_required", None),
                Some(path) => match std::fs::remove_dir_all(path) {
                    Ok(()) => outcome("cleaned", None),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => outcome("cleaned", None),
                    Err(error) => outcome("failed", Some(error.to_string())),
                },
            }
        };
        let renderer = if self.report["terminal_renderer"].is_null() {
            outcome("not_required", None)
        } else {
            self.report["terminal_renderer"].clone()
        };
        self.report = sorted_report(owned, renderer, temporary);
        self.report.clone()
    }

}

/// `event_journal` writer.
#[derive(Default)]
struct Journal(Vec<Value>);

impl Journal {
    fn record(&mut self, collection: &str, index: usize) {
        let order = self.0.len();
        self.0.push(json!({"capture_order": order, "collection": collection, "index": index}));
    }
}

/// The finalization attempt record (`ProcessCaptureFinalization`).
#[derive(Default)]
struct Finalization {
    started: Option<Instant>,
    escalated: bool,
    signals: Vec<Value>,
}

impl Finalization {
    fn snapshot(&self, requested: u64, elapsed: Option<u64>, exit_code: Option<i64>) -> Value {
        json!({"requested_ms": requested, "elapsed_ms": elapsed, "exit_code": exit_code, "signals": self.signals})
    }
}

/// Exit as node-pty reports it: `exitCode` 0 and the signal for signaled exits.
struct ObservedExit {
    exit_code: i64,
    signal: i64,
}

enum ExitWait {
    Exited { exit: ObservedExit, reason: &'static str, finalization: Option<Value> },
    /// The finalization SIGKILL could not be delivered (`unobserved: true`).
    Unobserved { reason: &'static str, finalization: Value },
}

struct Runtime<'a> {
    scenario: &'a Scenario,
    host: &'a CaptureHost<'a>,
    started: Instant,
    pty: OwnedPtyProcess,
    output: PtyOutput,
    output_closed: bool,
    decoder: Utf8Decoder,
    normalizer: Normalizer,
    renderer: Renderer,
    pending_render: Vec<(String, u64)>,
    root_pid: i64,
    last_output: Instant,
    /// No master read before this instant (see `INPUT_LOOP_TURN`).
    read_not_before: Option<Instant>,
    frames: Vec<Value>,
    interactions: Vec<Value>,
    dispatched: Vec<bool>,
    journal: Journal,
    raw_bytes: u64,
    normalized_bytes: u64,
    observed_bytes: u64,
    observed_frames: u64,
    normalized_omitted: u64,
    sampler: Sampler,
}

fn signal_number(name: &str) -> i32 {
    match name {
        "SIGINT" => libc::SIGINT,
        "SIGTERM" => libc::SIGTERM,
        _ => libc::SIGKILL,
    }
}

impl Runtime<'_> {
    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// `captureTerminalFrames` for one PTY chunk.
    fn on_output(&mut self, bytes: &[u8]) {
        let data = self.decoder.write(bytes);
        if data.is_empty() {
            return;
        }
        self.last_output = Instant::now();
        let length = data.len() as u64;
        self.observed_bytes += length;
        self.observed_frames += 1;
        let budget = self.scenario.output_bytes;
        if length > budget.saturating_sub(self.raw_bytes) {
            return;
        }
        let Bounded::Normalized(normalized) = self.normalizer.bounded(&data, budget.saturating_sub(self.normalized_bytes), self.root_pid) else {
            self.normalized_omitted += 1;
            return;
        };
        self.raw_bytes += length;
        self.normalized_bytes += normalized.len() as u64;
        let at_ms = bucket(self.elapsed_ms(), self.scenario.time_bucket_ms);
        let sequence = self.frames.len();
        let mut frame = Map::new();
        frame.insert("sequence".into(), json!(sequence));
        frame.insert("at_ms".into(), json!(at_ms));
        frame.insert("data".into(), json!(normalized));
        if normalized != data {
            frame.insert("raw_data".into(), json!(data));
        }
        self.frames.push(Value::Object(frame));
        self.pending_render.push((data, at_ms));
        self.journal.record("frames", sequence);
    }

    fn flush_render(&mut self) {
        for (text, at_ms) in std::mem::take(&mut self.pending_render) {
            if let Some(sequence) = self.renderer.write(&text, at_ms, &self.normalizer, self.root_pid) {
                self.journal.record("rendered_frames", sequence);
            }
        }
    }

    fn record_samples(&mut self) {
        for index in self.sampler.drain_recorded() {
            self.journal.record("process_samples", index);
        }
    }

    /// Drain available PTY events (and wait up to `wait` for the first).
    fn pump(&mut self, wait: Duration) {
        if self.output_closed {
            std::thread::sleep(wait);
            self.record_samples();
            return;
        }
        let mut wait = wait;
        if let Some(not_before) = self.read_not_before.take() {
            let hold = not_before.saturating_duration_since(Instant::now());
            std::thread::sleep(hold);
            wait = wait.saturating_sub(hold);
        }
        let mut next = self.output.next_timeout(wait);
        while let Some(event) = next {
            match event {
                PtyEvent::Output { bytes, .. } => self.on_output(&bytes),
                PtyEvent::Closed { .. } | PtyEvent::ReadFailed { .. } => {
                    self.output_closed = true;
                    break;
                }
            }
            next = self.output.try_next();
        }
        self.record_samples();
    }

    fn interaction(&mut self, scheduled: u64, kind: &str, data: String, outcome: &str) {
        let sequence = self.interactions.len();
        self.interactions.push(json!({
            "sequence": sequence, "scheduled_at_ms": scheduled, "dispatched_at_ms": self.elapsed_ms(),
            "type": kind, "data": data, "outcome": outcome,
        }));
        self.journal.record("interaction_events", sequence);
    }

    /// `scheduleScenarioInteractions`: dispatch every event that is due.
    fn dispatch_due(&mut self) {
        let elapsed = self.elapsed_ms();
        for index in 0..self.scenario.events.len() {
            let event = &self.scenario.events[index];
            if self.dispatched[index] || event.at_ms > elapsed {
                continue;
            }
            self.dispatched[index] = true;
            let dispatched_at = self.elapsed_ms();
            let (data, ok) = match &event.kind {
                EventKind::Input { data, sensitive } => {
                    let ok = self.pty.write_input(data.as_bytes()).is_ok();
                    if ok {
                        self.read_not_before = Some(Instant::now() + INPUT_LOOP_TURN);
                    }
                    let shown = if *sensitive {
                        format!("<redacted-input:{}-bytes>", data.len())
                    } else {
                        Normalizer::new(self.scenario, "<no-temporary-root>").text(data, -1)
                    };
                    (shown, ok)
                }
                EventKind::Resize { columns, rows } => {
                    let ok = TerminalSize::new(*columns, *rows).is_some_and(|size| self.pty.resize(size).is_ok());
                    if ok {
                        // xterm applies the resize after every preceding write.
                        self.flush_render();
                        let at_ms = bucket(dispatched_at, self.scenario.time_bucket_ms);
                        if let Some(sequence) = self.renderer.resize(*columns, *rows, at_ms, &self.normalizer, self.root_pid) {
                            self.journal.record("rendered_frames", sequence);
                        }
                    }
                    (format!("{columns}x{rows}"), ok)
                }
                EventKind::Signal(name) => (name.clone(), self.pty.signal_root(signal_number(name)).is_ok()),
            };
            let kind = event.type_name();
            let scheduled = event.at_ms;
            self.interaction(scheduled, kind, data, if ok { "dispatched" } else { "failed" });
        }
    }

    /// Identity-verified root signal with the original delivery vocabulary.
    fn deliver(&mut self, signal: i32) -> (&'static str, Option<String>) {
        match self.pty.try_wait() {
            Ok(Some(_)) => return ("gone", None),
            Ok(None) => {}
            Err(error) => return ("unverified", Some(error.message)),
        }
        match self.pty.signal_root(signal) {
            Ok(()) => ("signaled", None),
            Err(error) => ("unverified", Some(error.message)),
        }
    }

    fn attempt(&mut self, finalization: &mut Finalization, name: &str) -> bool {
        let started = finalization.started.expect("finalization started");
        let sent = started.elapsed().as_millis() as u64;
        let (delivery, reason) = self.deliver(signal_number(name));
        let mut record = Map::new();
        record.insert("signal".into(), json!(name));
        record.insert("sent_at_ms".into(), json!(sent));
        record.insert("delivery".into(), json!(delivery));
        if let Some(reason) = reason {
            record.insert("reason".into(), json!(reason));
        }
        finalization.signals.push(Value::Object(record));
        delivery == "signaled" || delivery == "gone"
    }

    /// `awaitTerminalExit`.
    fn await_exit(&mut self) -> ExitWait {
        let mut reason: &'static str = "exited";
        let mut finalization = Finalization::default();
        let requested = self.scenario.finalization_ms;
        loop {
            self.pump(POLL);
            self.dispatch_due();
            if let Ok(Some(exit)) = self.pty.try_wait() {
                let elapsed = finalization.started.map(|started| started.elapsed().as_millis() as u64);
                let exit = ObservedExit {
                    exit_code: if exit.signal.is_some() { 0 } else { i64::from(exit.code) },
                    signal: exit.signal.map_or(0, i64::from),
                };
                self.journal.record("lifecycle", 0);
                for index in 0..self.scenario.events.len() {
                    if self.dispatched[index] {
                        continue;
                    }
                    let event = &self.scenario.events[index];
                    let data = match &event.kind {
                        EventKind::Input { .. } => "<not-dispatched>".to_owned(),
                        EventKind::Resize { columns, rows } => format!("{columns}x{rows}"),
                        EventKind::Signal(name) => name.clone(),
                    };
                    let (scheduled, kind) = (event.at_ms, event.type_name());
                    self.interaction(scheduled, kind, data, "target_exited");
                }
                self.dispatched.iter_mut().for_each(|dispatched| *dispatched = true);
                self.flush_render();
                let finalization = elapsed.map(|elapsed| {
                    finalization.snapshot(requested, Some(elapsed), (exit.exit_code >= 0 && exit.signal == 0).then_some(exit.exit_code))
                });
                return ExitWait::Exited { exit, reason, finalization };
            }
            self.flush_render();
            let now = Instant::now();
            if (self.host.cancelled)() {
                reason = "cancelled";
                if finalization.started.is_some() {
                    if !finalization.escalated {
                        finalization.escalated = true;
                        if !self.attempt(&mut finalization, "SIGKILL") {
                            return ExitWait::Unobserved { reason, finalization: finalization.snapshot(requested, None, None) };
                        }
                    }
                } else {
                    let _ = self.pty.signal_root(libc::SIGKILL);
                }
            } else if let Some(started) = finalization.started {
                if !finalization.escalated && now.duration_since(started).as_millis() as u64 >= requested {
                    finalization.escalated = true;
                    if !self.attempt(&mut finalization, "SIGKILL") {
                        return ExitWait::Unobserved {
                            reason: if reason == "exited" { "timeout" } else { reason },
                            finalization: finalization.snapshot(requested, None, None),
                        };
                    }
                }
            } else {
                let deadline = if self.elapsed_ms() >= self.scenario.timeout_ms {
                    Some("timeout")
                } else if now.duration_since(self.last_output).as_millis() as u64 >= self.scenario.idle_timeout_ms {
                    Some("idle_timeout")
                } else {
                    None
                };
                if let Some(deadline) = deadline {
                    reason = deadline;
                    if requested == 0 {
                        let _ = self.pty.signal_root(libc::SIGKILL);
                    } else {
                        finalization.started = Some(Instant::now());
                        self.attempt(&mut finalization, "SIGTERM");
                    }
                }
            }
        }
    }

    /// `observeSettlement` over the captured process groups.
    fn observe_settlement(&mut self, run_id: &str, groups: &[u32]) -> Value {
        let started = Instant::now();
        let mut consecutive_empty = 0;
        let mut saw_live = false;
        let state = loop {
            let observations = ownership::observe_process_groups(run_id, groups, Some(self.root_pid as u32));
            if observations.values().any(|observation| matches!(observation, GroupObservation::Unverifiable(_))) {
                break "unverifiable";
            }
            if observations.values().all(|observation| *observation == GroupObservation::Empty) {
                consecutive_empty += 1;
                if consecutive_empty >= 2 {
                    break "quiesced";
                }
            } else {
                consecutive_empty = 0;
                saw_live = true;
            }
            if started.elapsed().as_millis() as u64 >= self.scenario.settle_ms {
                break if saw_live { "alive_at_deadline" } else { "unverifiable" };
            }
            let until = Instant::now() + SETTLE_INTERVAL;
            while Instant::now() < until {
                self.pump(POLL);
                self.flush_render();
            }
        };
        // The lifecycle entry is recorded when settlement concludes.
        self.journal.record("lifecycle", 1);
        json!({"state": state, "elapsed_ms": started.elapsed().as_millis() as u64})
    }

    /// `settleProcessCaptureJournal`: wait for trailing PTY callbacks.
    fn settle_journal(&mut self) {
        let deadline = Instant::now() + JOURNAL_MAX_WAIT;
        let mut observed = self.journal.0.len();
        let mut changed = Instant::now();
        while Instant::now() < deadline {
            self.pump(Duration::from_millis(4));
            self.flush_render();
            if self.journal.0.len() != observed {
                observed = self.journal.0.len();
                changed = Instant::now();
            } else if changed.elapsed() >= JOURNAL_QUIET {
                return;
            }
        }
    }

    fn terminal_retention(&self) -> (Value, Value) {
        let budget = self.scenario.output_bytes;
        (
            json!({
                "budget_bytes": budget, "observed_bytes": self.observed_bytes, "retained_bytes": self.raw_bytes,
                "observed_frames": self.observed_frames, "retained_frames": self.frames.len(),
            }),
            json!({"budget_bytes": budget, "retained_bytes": self.normalized_bytes, "omitted_frames": self.normalized_omitted}),
        )
    }
}

/// Observation buffer seeded like `createProcessCaptureObservationBuffer`.
struct Observations(Map<String, Value>);

fn available(value: Value) -> Value {
    json!({"state": "available", "value": value})
}

fn unavailable(reason: &str) -> Value {
    json!({"state": "unavailable", "reason": reason})
}

fn snapshot_value(snapshot: &Snapshot) -> Value {
    json!({"files": snapshot.files, "truncated": snapshot.truncated, "completeRoots": snapshot.complete_roots, "coverage": snapshot.coverage})
}

impl Observations {
    fn new(before: Option<&Snapshot>, finalization: bool) -> Self {
        let mut map = Map::new();
        map.insert("target_pid".into(), unavailable("No PTY process was spawned before the run failed."));
        map.insert("frames".into(), available(json!([])));
        map.insert("rendered_frames".into(), unavailable("Rendered terminal frames were not collected before capture completion finished."));
        map.insert("interaction_events".into(), available(json!([])));
        map.insert("exit".into(), unavailable("Terminal exit was not observed before the run failed."));
        if finalization {
            map.insert("finalization".into(), unavailable("Finalization was not observed before capture completion finished."));
        }
        map.insert("settlement".into(), unavailable("Process settlement was not observed before capture completion finished."));
        map.insert("process_samples".into(), available(json!([])));
        map.insert(
            "filesystem_snapshots".into(),
            json!({
                "before": before.map_or_else(|| unavailable("Initial filesystem snapshot did not complete."), |before| available(snapshot_value(before))),
                "after": unavailable("Final filesystem snapshot was not collected before capture completion finished."),
            }),
        );
        map.insert("event_journal".into(), available(json!([])));
        map.insert("manifest".into(), unavailable("Capture manifest was not produced before capture completion finished."));
        Self(map)
    }

    fn set(&mut self, key: &str, value: Value) {
        self.0.insert(key.into(), value);
    }
}

fn cancelled_failure() -> CaptureFailure {
    CaptureFailure {
        message: "process capture was cancelled".to_owned(),
        cancelled: true,
        execution_failure: Some("process capture was cancelled".to_owned()),
        cleanup_report: None,
        partial_observation: None,
        retained: None,
    }
}

fn failure(message: impl Into<String>) -> CaptureFailure {
    let message = message.into();
    CaptureFailure {
        execution_failure: Some(message.clone()),
        message,
        cancelled: false,
        cleanup_report: None,
        partial_observation: None,
        retained: None,
    }
}

/// `selectCapturedProcessGroupIds`.
fn captured_groups(root: i64, samples: &[RawSample]) -> Vec<u32> {
    let mut groups = vec![root as u32];
    for sample in samples {
        if Some(sample.pid) == sample.process_group_id && !groups.contains(&(sample.pid as u32)) {
            groups.push(sample.pid as u32);
        }
    }
    groups
}

fn temporary_directory(host: &HashMap<String, String>) -> PathBuf {
    // Node `os.tmpdir()`: TMPDIR without its trailing separator, else /tmp.
    host.get("TMPDIR")
        .filter(|value| !value.is_empty())
        .map(|value| PathBuf::from(value.trim_end_matches('/')))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// Run one resolved scenario to a verified capture value.
pub fn run(scenario: &Scenario, host: &CaptureHost<'_>) -> Result<Value, CaptureFailure> {
    (host.progress)("prepare", "Preparing process capture".to_owned());
    if (host.cancelled)() {
        return Err(cancelled_failure());
    }
    let run_id = uuid::Uuid::new_v4().to_string();
    let finalization_enabled = scenario.finalization_ms > 0;
    let not_required = || sorted_report(outcome("not_required", None), outcome("not_required", None), outcome("not_required", None));
    let before = snapshot_roots(scenario, None).map_err(|message| {
        let mut failure = failure("process capture failed");
        failure.execution_failure = Some(message);
        failure.cleanup_report = Some(not_required());
        failure
    })?;
    let temporary_root = tempfile::Builder::new()
        .prefix("rea-process-")
        .tempdir_in(temporary_directory(host.environment))
        .map(tempfile::TempDir::keep)
        .map_err(|error| {
            let mut failure = failure("process capture failed");
            failure.execution_failure = Some(error.to_string());
            failure.cleanup_report = Some(not_required());
            failure
        })?;
    let baseline = ownership::capture_baseline().unwrap_or_default();
    let mut observations = Observations::new(Some(&before), finalization_enabled);
    let temporary_text = temporary_root.to_string_lossy().into_owned();

    // startCaptureRuntime
    let selected = observe_selected_executable(&scenario.executable);
    let started_at = SystemTime::now();
    let started = Instant::now();
    let normalizer = Normalizer::new(scenario, &temporary_text);
    let renderer = Renderer::new(scenario.columns, scenario.rows, scenario.scrollback, scenario.output_bytes);
    let mut retained = RetainedResources {
        pty: None,
        run_id: run_id.clone(),
        baseline: baseline.clone(),
        relation: OwnershipRelation::default(),
        temporary_root: Some(temporary_root.clone()),
        report: sorted_report(outcome("not_required", None), json!(null), outcome("unverified", Some("temporary root cleanup was not attempted".to_owned()))),
    };
    let finish_failure = |mut failure: CaptureFailure, mut retained: RetainedResources, observations: Observations| -> CaptureFailure {
        let report = retained.release();
        failure.partial_observation = Some(json!({
            "observations": Value::Object(observations.0),
            "cleanup": report,
            "execution_failure": failure.execution_failure,
        }));
        if report_failure(&report).is_some() {
            failure.retained = Some(retained);
        }
        failure.cleanup_report = Some(report);
        failure
    };
    if (host.cancelled)() {
        return Err(finish_failure(cancelled_failure(), retained, observations));
    }
    let environment: Vec<(OsString, OsString)> = capture_environment(scenario, host.environment, &run_id)
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
    let launch = OwnedPtyProcess::launch(PtyLaunchSpec {
        executable: PathBuf::from(&scenario.executable),
        arguments: scenario.arguments.iter().map(OsString::from).collect(),
        working_directory: PathBuf::from(&scenario.working_directory),
        environment: environment.clone(),
        size: TerminalSize::new(scenario.columns, scenario.rows).expect("validated terminal size"),
    });
    let (pty, output) = match launch {
        Ok(launched) => launched,
        Err(error) => {
            let mut failed = failure("process capture failed");
            failed.execution_failure = Some(error.message);
            return Err(finish_failure(failed, retained, observations));
        }
    };
    let root_pid = i64::from(pty.id());
    observations.set("target_pid", available(json!(if scenario.normalize_pids { 1 } else { root_pid })));
    retained.report["owned_process_group"] = outcome("unverified", Some("owned process cleanup was not attempted".to_owned()));
    retained.report["terminal_renderer"] = outcome("cleaned", None);
    retained.relation = OwnershipRelation {
        leader_pid: root_pid as u32,
        process_group_id: root_pid as u32,
        sampled_process_group_ids: Vec::new(),
    };
    let launched: LaunchedExecutable = observe_launched_executable(&scenario.executable, &selected);
    let sampler = Sampler::start(SamplerContext {
        root_pid,
        run_id: run_id.clone(),
        started,
        limit: scenario.processes,
    });
    let mut runtime = Runtime {
        scenario,
        host,
        started,
        pty,
        output,
        output_closed: false,
        decoder: Utf8Decoder::default(),
        normalizer,
        renderer,
        pending_render: Vec::new(),
        root_pid,
        last_output: started,
        read_not_before: None,
        frames: Vec::new(),
        interactions: Vec::new(),
        dispatched: vec![false; scenario.events.len()],
        journal: Journal::default(),
        raw_bytes: 0,
        normalized_bytes: 0,
        observed_bytes: 0,
        observed_frames: 0,
        normalized_omitted: 0,
        sampler,
    };
    runtime.journal.record("filesystem_checkpoints", 0);
    (host.progress)("running", "Running process capture".to_owned());
    let exit = runtime.await_exit();

    let mut execution: Result<CaptureFacts, CaptureFailure> = match exit {
        ExitWait::Unobserved { reason, finalization } => {
            observations.set("finalization", available(finalization));
            observations.set(
                "exit",
                unavailable(&format!(
                    "The captured process exit was not observed because the finalization SIGKILL could not be delivered (initiating reason: {reason})."
                )),
            );
            Err(if reason == "cancelled" {
                cancelled_failure()
            } else {
                failure("The captured process exit was not observed because the finalization SIGKILL could not be delivered.")
            })
        }
        ExitWait::Exited { exit, reason, finalization } => {
            if let Some(finalization) = &finalization {
                observations.set("finalization", available(finalization.clone()));
            }
            let mut exit_value = json!({
                "code": if reason == "exited" && exit.exit_code >= 0 { json!(exit.exit_code) } else { Value::Null },
                "signal": exit.signal,
                "reason": reason,
            });
            if let Some(finalization) = finalization {
                exit_value["finalization"] = finalization;
            }
            observations.set("exit", available(exit_value.clone()));
            if reason == "cancelled" {
                Err(cancelled_failure())
            } else {
                (host.progress)("settling", "Settling process capture".to_owned());
                complete(&mut runtime, &run_id, exit_value, &before, &launched, started_at, &mut observations)
            }
        }
    };
    if execution.is_ok() && (host.cancelled)() {
        execution = Err(cancelled_failure());
    }

    // finishProcessRun: stop sampling and release every owned resource.
    let sampling = runtime.sampler.stop();
    runtime.pump(Duration::ZERO);
    runtime.flush_render();
    observations.set("frames", available(json!(runtime.frames)));
    observations.set("interaction_events", available(json!(runtime.interactions)));
    observations.set("event_journal", available(json!(runtime.journal.0)));
    observations.set("process_samples", available(json!(super::normalize::normalize_samples(&sampling.samples, scenario, root_pid))));
    if !observations.0.get("rendered_frames").is_some_and(|value| value["state"] == "available") {
        observations.set("rendered_frames", available(json!(runtime.renderer.frames())));
    }
    retained.relation.sampled_process_group_ids = captured_groups(root_pid, &sampling.samples).into_iter().filter(|group| i64::from(*group) != root_pid).collect();
    retained.pty = Some(runtime.pty);
    let report = retained.release();
    (host.progress)("cleanup", "Released process capture resources".to_owned());
    let cleanup_failure = report_failure(&report);
    match execution {
        Ok(facts) if cleanup_failure.is_none() => {
            let capture = result::verified(facts, &sampling, &report);
            capture.map_err(|message| {
                let mut failed = failure(message);
                failed.cleanup_report = Some(report.clone());
                failed
            })
        }
        Ok(facts) => {
            let pending = result::pending(facts, &sampling);
            let message = cleanup_failure.clone().unwrap_or_default();
            Err(CaptureFailure {
                message: message.clone(),
                cancelled: false,
                execution_failure: None,
                partial_observation: Some(json!({"capture": pending, "cleanup": report, "execution_failure": null})),
                cleanup_report: Some(report),
                retained: Some(retained),
            })
        }
        Err(mut failure) => {
            failure.partial_observation = Some(json!({
                "observations": Value::Object(observations.0),
                "cleanup": report,
                "execution_failure": failure.execution_failure,
            }));
            if cleanup_failure.is_some() {
                failure.retained = Some(retained);
            }
            failure.cleanup_report = Some(report);
            Err(failure)
        }
    }
}

/// `completeCapture`.
fn complete(
    runtime: &mut Runtime<'_>,
    run_id: &str,
    exit: Value,
    before: &Snapshot,
    launched: &LaunchedExecutable,
    started_at: SystemTime,
    observations: &mut Observations,
) -> Result<CaptureFacts, CaptureFailure> {
    let scenario = runtime.scenario;
    let groups = captured_groups(runtime.root_pid, &runtime.sampler.snapshot());
    let settlement = runtime.observe_settlement(run_id, &groups);
    observations.set("settlement", available(settlement.clone()));
    runtime.settle_journal();
    if (runtime.host.cancelled)() {
        return Err(cancelled_failure());
    }
    let after = match snapshot_roots(scenario, Some(before)) {
        Ok(after) => after,
        Err(message) => {
            let mut filesystem = observations.0["filesystem_snapshots"].clone();
            filesystem["after"] = unavailable(&format!("Final filesystem snapshot failed: {message}"));
            observations.set("filesystem_snapshots", filesystem);
            let mut failed = failure("process capture failed");
            failed.execution_failure = Some(message);
            return Err(failed);
        }
    };
    let mut filesystem = observations.0["filesystem_snapshots"].clone();
    filesystem["after"] = available(snapshot_value(&after));
    observations.set("filesystem_snapshots", filesystem);
    runtime.journal.record("filesystem_checkpoints", 1);
    let rendered_frames = runtime.renderer.frames();
    observations.set("rendered_frames", available(json!(rendered_frames)));
    let checkpoints = json!([
        {"name": "before", "at_ms": 0, "files": before.files, "effects": [], "truncated": before.truncated},
        {"name": "after_settlement", "at_ms": runtime.elapsed_ms(), "files": after.files, "effects": classify_effects(before, &after), "truncated": after.truncated},
    ]);
    let manifest = result::manifest(scenario, started_at, SystemTime::now(), launched);
    observations.set("manifest", available(manifest.clone()));
    let (raw_terminal, normalized_terminal) = runtime.terminal_retention();
    Ok(CaptureFacts {
        scenario: scenario.clone(),
        manifest,
        frames: runtime.frames.clone(),
        rendered_frames,
        interactions: runtime.interactions.clone(),
        exit,
        settlement,
        checkpoints,
        journal: runtime.journal.0.clone(),
        before: before.clone(),
        after,
        raw_terminal,
        normalized_terminal,
        rendered_terminal: runtime.renderer.retention(),
        root_pid: runtime.root_pid,
    })
}

/// Process-wide release used by session close (`retryCleanup`).
pub fn release_retained(retained: &mut RetainedResources) -> Result<(), String> {
    let report = retained.release();
    match report_failure(&report) {
        None => Ok(()),
        Some(reason) => Err(reason),
    }
}
