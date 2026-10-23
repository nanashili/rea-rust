//! Sampled RSS supervision for an owned Rust Ghidra worker.
//!
//! This file intentionally remains unregistered as a crate module until the
//! provider wiring has a complete lifecycle contract.  The state machine is
//! nevertheless kept executable and source-backed: it owns observation state,
//! while the caller retains process termination and cleanup authority.

use std::{
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde_json::{json, Map, Value};
use rea_core::cancellation::Cancellation;

use crate::{
    ghidra_rust::memory_policy::{
        ghidra_rust_memory_policy, GHIDRA_RUST_MEMORY_SAMPLE_INTERVAL_MS,
        GHIDRA_RUST_MEMORY_SAMPLE_TIMEOUT_MS, GHIDRA_RUST_MIB,
    },
    process::observation::{
        observe_owned_resident_memory, OwnedResidentMemoryObservation, ProcessIdentitySource,
        ProcessMemorySource,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MonitorState {
    NotStarted,
    Active,
    Exited,
    Stopped,
    LimitReached,
    Unavailable,
}

impl MonitorState {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Active => "active",
            Self::Exited => "exited",
            Self::Stopped => "stopped",
            Self::LimitReached => "limit_reached",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A timestamped, verified resident-memory sample.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemorySample {
    pub identity: String,
    pub bytes: u64,
    pub observed_at: String,
}

/// Observation outcomes preserve exit and unknown states separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemorySampleObservation {
    Sample(MemorySample),
    Exited,
    Unavailable { reason: String },
}

/// Failures reported by the monitor. The callback is responsible for routing
/// these into the provider's existing analysis-error algebra.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemorySupervisorFailure {
    ResourceConstraint { diagnostics: Value },
    CapabilityUnavailable { cause: String, diagnostics: Value },
}

/// A read-only source of worker RSS observations.
pub trait MemorySampler: Send + Sync + 'static {
    fn sample(&self, expected_identity: Option<&str>, timeout: Duration)
        -> MemorySampleObservation;
}

/// Adapter over the shared identity and memory observers.
pub struct OwnedWorkerMemorySampler<S> {
    source: S,
    pid: u64,
    parent_pid: Option<u64>,
    process_group_id: Option<u64>,
}

impl<S> OwnedWorkerMemorySampler<S> {
    pub fn new(
        source: S,
        pid: u64,
        parent_pid: Option<u64>,
        process_group_id: Option<u64>,
    ) -> Self {
        Self {
            source,
            pid,
            parent_pid,
            process_group_id,
        }
    }
}

impl<S> MemorySampler for OwnedWorkerMemorySampler<S>
where
    S: ProcessIdentitySource + ProcessMemorySource + Send + Sync + 'static,
{
    fn sample(
        &self,
        expected_identity: Option<&str>,
        _timeout: Duration,
    ) -> MemorySampleObservation {
        match observe_owned_resident_memory(
            &self.source,
            self.pid,
            expected_identity,
            self.parent_pid,
            self.process_group_id,
        ) {
            OwnedResidentMemoryObservation::Sampled {
                identity,
                resident_bytes,
            } => MemorySampleObservation::Sample(MemorySample {
                identity,
                bytes: resident_bytes,
                observed_at: observed_at_now(),
            }),
            OwnedResidentMemoryObservation::Exited => MemorySampleObservation::Exited,
            OwnedResidentMemoryObservation::Unavailable { reason } => {
                MemorySampleObservation::Unavailable { reason }
            }
        }
    }
}

struct MonitorData {
    identity: Option<String>,
    state: MonitorState,
    failure: Option<MemorySupervisorFailure>,
    last_bytes: Option<u64>,
    peak_bytes: Option<u64>,
    observed_at: Option<String>,
    samples: u64,
}

impl Default for MonitorData {
    fn default() -> Self {
        Self {
            identity: None,
            state: MonitorState::NotStarted,
            failure: None,
            last_bytes: None,
            peak_bytes: None,
            observed_at: None,
            samples: 0,
        }
    }
}

struct MonitorShared {
    data: Mutex<MonitorData>,
    wake: Condvar,
    stopped: Mutex<bool>,
    caller_cancellation: Mutex<Option<Cancellation>>,
}

/// Periodically samples only the owned worker process and reports failures
/// exactly once. `stop` never terminates the worker; its owner still does that.
pub struct GhidraRustMemorySupervisor<S, F>
where
    S: MemorySampler,
    F: Fn(MemorySupervisorFailure) + Send + Sync + 'static,
{
    sampler: Arc<S>,
    memory_limit_mib: u64,
    failed: Arc<F>,
    shared: Arc<MonitorShared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl<S, F> GhidraRustMemorySupervisor<S, F>
where
    S: MemorySampler,
    F: Fn(MemorySupervisorFailure) + Send + Sync + 'static,
{
    pub fn new(sampler: S, memory_limit_mib: u64, failed: F) -> Self {
        Self {
            sampler: Arc::new(sampler),
            memory_limit_mib,
            failed: Arc::new(failed),
            shared: Arc::new(MonitorShared {
                data: Mutex::new(MonitorData::default()),
                wake: Condvar::new(),
                stopped: Mutex::new(false),
                caller_cancellation: Mutex::new(None),
            }),
            worker: Mutex::new(None),
        }
    }

    /// Take the first sample synchronously, then start periodic supervision.
    pub fn start(&self) -> Result<(), MemorySupervisorFailure> {
        self.start_with_cancellation(Cancellation::default())
    }

    /// Start supervision while observing the caller's cancellation identity.
    ///
    /// Cancellation does not terminate the worker.  It only prevents new
    /// observations and lets the process owner retain termination authority.
    pub fn start_with_cancellation(
        &self,
        cancellation: Cancellation,
    ) -> Result<(), MemorySupervisorFailure> {
        *self
            .shared
            .caller_cancellation
            .lock()
            .expect("memory monitor caller cancellation lock poisoned") = Some(cancellation);
        self.sample_once();

        let failure = self
            .shared
            .data
            .lock()
            .expect("memory monitor state lock poisoned")
            .failure
            .clone();
        if let Some(failure) = failure {
            return Err(failure);
        }

        let state = self
            .shared
            .data
            .lock()
            .expect("memory monitor state lock poisoned")
            .state;
        if state != MonitorState::Active {
            return Err(MemorySupervisorFailure::CapabilityUnavailable {
                cause: "worker exited before RSS supervision was ready".into(),
                diagnostics: self.diagnostics(),
            });
        }

        let sampler = Arc::clone(&self.sampler);
        let shared = Arc::clone(&self.shared);
        let failed = Arc::clone(&self.failed);
        let memory_limit_mib = self.memory_limit_mib;
        let worker = thread::spawn(move || {
            monitor_loop(sampler, shared, failed, memory_limit_mib);
        });
        *self.worker.lock().expect("memory monitor worker lock poisoned") = Some(worker);
        Ok(())
    }

    /// Stop future observations and wait for an in-flight sample to finish.
    pub fn stop(&self) {
        {
            let mut stopped = self
                .shared
                .stopped
                .lock()
                .expect("memory monitor stop lock poisoned");
            *stopped = true;
        }
        self.shared.wake.notify_all();

        let state = &mut *self.worker.lock().expect("memory monitor worker lock poisoned");
        if let Some(worker) = state.take() {
            let _ = worker.join();
        }

        let mut data = self
            .shared
            .data
            .lock()
            .expect("memory monitor state lock poisoned");
        if data.failure.is_none() && data.state != MonitorState::Exited {
            data.state = MonitorState::Stopped;
        }
    }

    pub fn diagnostics(&self) -> Value {
        let data = self
            .shared
            .data
            .lock()
            .expect("memory monitor state lock poisoned");
        let mut diagnostics = match ghidra_rust_memory_policy(Some(self.memory_limit_mib)) {
            Value::Object(fields) => fields,
            _ => Map::new(),
        };
        diagnostics.extend([
            ("memory_monitor_state".into(), json!(data.state.as_str())),
            ("memory_rss_bytes".into(), json!(data.last_bytes)),
            (
                "memory_peak_sampled_rss_bytes".into(),
                json!(data.peak_bytes),
            ),
            ("memory_last_observed_at".into(), json!(data.observed_at)),
            ("memory_samples".into(), json!(data.samples)),
        ]);
        Value::Object(diagnostics)
    }

    fn sample_once(&self) {
        sample_once_shared(
            &self.sampler,
            &self.shared,
            &self.failed,
            self.memory_limit_mib,
        );
    }
}

fn monitor_loop<S, F>(
    sampler: Arc<S>,
    shared: Arc<MonitorShared>,
    failed: Arc<F>,
    memory_limit_mib: u64,
)
where
    S: MemorySampler,
    F: Fn(MemorySupervisorFailure) + Send + Sync + 'static,
{
    loop {
        let stopped = shared
            .stopped
            .lock()
            .expect("memory monitor stop lock poisoned");
        let (stopped, _) = shared
            .wake
            .wait_timeout_while(
                stopped,
                Duration::from_millis(GHIDRA_RUST_MEMORY_SAMPLE_INTERVAL_MS),
                |stopped| !*stopped,
            )
            .expect("memory monitor wait lock poisoned");
        if *stopped || caller_cancelled(&shared) {
            return;
        }
        drop(stopped);

        sample_once_shared(&sampler, &shared, &failed, memory_limit_mib);
        let state = shared
            .data
            .lock()
            .expect("memory monitor state lock poisoned")
            .state;
        if matches!(
            state,
            MonitorState::Exited | MonitorState::LimitReached | MonitorState::Unavailable
        ) {
            return;
        }
    }
}

fn sample_once_shared<S, F>(
    sampler: &Arc<S>,
    shared: &Arc<MonitorShared>,
    failed: &Arc<F>,
    memory_limit_mib: u64,
)
where
    S: MemorySampler,
    F: Fn(MemorySupervisorFailure) + Send + Sync + 'static,
{
    if is_stopped(shared) || caller_cancelled(shared) {
        return;
    }

    let expected_identity = shared
        .data
        .lock()
        .expect("memory monitor state lock poisoned")
        .identity
        .clone();
    let sample_started_at = Instant::now();
    let observation = sampler.sample(
        expected_identity.as_deref(),
        Duration::from_millis(GHIDRA_RUST_MEMORY_SAMPLE_TIMEOUT_MS),
    );

    if is_stopped(shared) || caller_cancelled(shared) {
        return;
    }

    if sample_started_at.elapsed()
        >= Duration::from_millis(GHIDRA_RUST_MEMORY_SAMPLE_TIMEOUT_MS)
    {
        fail_unavailable(
            shared,
            failed,
            memory_limit_mib,
            "worker RSS observation deadline elapsed".into(),
        );
        return;
    }

    match observation {
        MemorySampleObservation::Sample(sample) => {
            accept_sample(shared, failed, memory_limit_mib, sample)
        }
        MemorySampleObservation::Exited => {
            shared
                .data
                .lock()
                .expect("memory monitor state lock poisoned")
                .state = MonitorState::Exited;
        }
        MemorySampleObservation::Unavailable { reason } => {
            fail_unavailable(shared, failed, memory_limit_mib, reason);
        }
    }
}

fn is_stopped(shared: &Arc<MonitorShared>) -> bool {
    *shared
        .stopped
        .lock()
        .expect("memory monitor stop lock poisoned")
}

fn caller_cancelled(shared: &Arc<MonitorShared>) -> bool {
    shared
        .caller_cancellation
        .lock()
        .expect("memory monitor caller cancellation lock poisoned")
        .as_ref()
        .and_then(Cancellation::reason)
        .is_some()
}

fn accept_sample<F>(
    shared: &Arc<MonitorShared>,
    failed: &Arc<F>,
    memory_limit_mib: u64,
    sample: MemorySample,
)
where
    F: Fn(MemorySupervisorFailure) + Send + Sync + 'static,
{
    let limit = memory_limit_mib.saturating_mul(GHIDRA_RUST_MIB);
    let mut data = shared
        .data
        .lock()
        .expect("memory monitor state lock poisoned");
    if data.failure.is_some() {
        return;
    }

    data.identity = Some(sample.identity);
    data.last_bytes = Some(sample.bytes);
    data.peak_bytes = Some(data.peak_bytes.unwrap_or(0).max(sample.bytes));
    data.observed_at = Some(sample.observed_at);
    data.samples += 1;
    data.state = MonitorState::Active;
    if sample.bytes < limit {
        return;
    }

    data.state = MonitorState::LimitReached;
    let mut diagnostics = diagnostics_from_data(&data, memory_limit_mib);
    diagnostics.insert("failure_kind".into(), json!("memory"));
    let failure = MemorySupervisorFailure::ResourceConstraint { diagnostics };
    data.failure = Some(failure.clone());
    drop(data);
    failed(failure);
}

fn fail_unavailable<F>(
    shared: &Arc<MonitorShared>,
    failed: &Arc<F>,
    memory_limit_mib: u64,
    cause: String,
)
where
    F: Fn(MemorySupervisorFailure) + Send + Sync + 'static,
{
    let mut data = shared
        .data
        .lock()
        .expect("memory monitor state lock poisoned");
    if data.failure.is_some() {
        return;
    }
    data.state = MonitorState::Unavailable;
    let mut diagnostics = diagnostics_from_data(&data, memory_limit_mib);
    diagnostics.insert("failure_kind".into(), json!("memory_monitor"));
    let failure = MemorySupervisorFailure::CapabilityUnavailable {
        cause,
        diagnostics: Value::Object(diagnostics),
    };
    data.failure = Some(failure.clone());
    drop(data);
    failed(failure);
}

fn diagnostics_from_data(data: &MonitorData, memory_limit_mib: u64) -> Map<String, Value> {
    let mut diagnostics = match ghidra_rust_memory_policy(
        (memory_limit_mib != 0).then_some(memory_limit_mib),
    ) {
        Value::Object(fields) => fields,
        _ => Map::new(),
    };
    diagnostics.extend([
        ("memory_monitor_state".into(), json!(data.state.as_str())),
        ("memory_rss_bytes".into(), json!(data.last_bytes)),
        (
            "memory_peak_sampled_rss_bytes".into(),
            json!(data.peak_bytes),
        ),
        ("memory_last_observed_at".into(), json!(data.observed_at)),
        ("memory_samples".into(), json!(data.samples)),
    ]);
    diagnostics
}

fn observed_at_now() -> String {
    // The provider contract carries an ISO timestamp; this helper keeps the
    // source self-contained until the shared timestamp utility is wired in.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}
