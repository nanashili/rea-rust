//! Bounded process-tree sampling of the captured PTY root.
//!
//! Compatibility owner: `startProcessSampler` and `samplePs`
//! (`ProcessSampling.ts`, `ProcessSamplingObservation.ts`). Samples start
//! only after the root is proven to be the initialized PTY session leader
//! carrying this run's token; each attempt runs on a 50 ms cadence, an
//! attempt in flight when sampling stops is interrupted and recorded.
//!
//! The process table carries the original `ps -axo pid=,ppid=,pgid=,sess=,command=`
//! facts, read natively (see `read_ps`). On Linux, each row is additionally
//! bracketed by the shared procfs start-time identity observer. This keeps
//! `ps`-style breadth-first discovery while refusing to attribute a reused
//! PID to this capture.

use super::normalize::RawSample;
#[cfg(target_os = "linux")]
use rea_host::process::linux::identity::{
    Observation as ProcessIdentityObservation, ProcessIdentityObserver,
};
use rea_host::process::linux::run_token::{ProcessRunTokenObserver, RunTokenObservation};
use rea_host::process::ownership;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_millis(50);
const INTERRUPTED: &str = "Sampler shutdown interrupted an unfinished process observation; unexamined processes remain unknown";

#[derive(Clone, Debug)]
struct Row {
    pid: i64,
    parent_pid: i64,
    process_group_id: i64,
    session_id: Option<i64>,
    command: String,
    start_time: Option<String>,
}

/// `SamplingDiagnostics`.
#[derive(Clone, Debug, Default)]
struct Diagnostics {
    count: u64,
    first: Option<String>,
    interrupted: bool,
}

impl Diagnostics {
    fn merge(&mut self, other: Diagnostics) {
        self.count += other.count;
        if self.first.is_none() {
            self.first = other.first;
        }
        self.interrupted |= other.interrupted;
    }

    fn failure(message: String) -> Self {
        Self {
            count: 1,
            first: Some(message),
            interrupted: false,
        }
    }

    fn interrupted() -> Self {
        Self {
            interrupted: true,
            ..Self::default()
        }
    }
}

/// Shared environment and stop state for one sampler.
pub struct SamplerContext {
    pub root_pid: i64,
    pub run_id: String,
    pub started: Instant,
    pub limit: u64,
}

#[derive(Default)]
struct State {
    samples: Vec<RawSample>,
    last: HashMap<i64, String>,
    #[cfg(target_os = "linux")]
    identities: HashMap<i64, String>,
    limit_reached: bool,
    diagnostics: Diagnostics,
    root_initialized: bool,
    /// Indexes recorded since the journal last drained them.
    recorded: Vec<usize>,
}

/// Running sampler; `stop` returns the samples and their coverage.
pub struct Sampler {
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<State>>,
    thread: Option<JoinHandle<()>>,
    limit: u64,
}

/// Result of `stop()`.
pub struct Sampling {
    pub samples: Vec<RawSample>,
    pub partial: bool,
    pub coverage: Value,
}

enum Read<T> {
    Value(T),
    Interrupted,
    Failed(String),
}

/// The process table with `ps -axo pid=,ppid=,pgid=,sess=,command=` facts.
///
/// `ps` is setuid root on macOS, so the launcher cannot verify its identity
/// and own it; the same rows are read natively (`KERN_PROCARGS2` argv is the
/// source `ps -o command` prints). macOS reports no session ID (`sess` is 0,
/// which the original maps to null).
fn read_ps(_context: &SamplerContext, stop: &AtomicBool) -> Read<Vec<Row>> {
    if stop.load(Ordering::SeqCst) {
        return Read::Interrupted;
    }
    match ownership::list_process_commands() {
        Ok(rows) => {
            let mut observed = Vec::with_capacity(rows.len());
            for row in rows {
                #[cfg(target_os = "linux")]
                let (session_id, start_time) =
                    match ProcessIdentityObserver.observe(u64::from(row.pid), false) {
                        ProcessIdentityObservation::Readable {
                            identity,
                            relation: Some(relation),
                            ..
                        } => (
                            relation
                                .session_id
                                .and_then(|value| i64::try_from(value).ok()),
                            Some(identity),
                        ),
                        // `list_process_commands` already filtered unreadable rows. A
                        // concurrent exit can still race this second observation;
                        // absence is an expected exit race, while other failures
                        // remain sampling failures rather than becoming ownership.
                        ProcessIdentityObservation::Absent { .. } => continue,
                        ProcessIdentityObservation::Unavailable { reason } => {
                            return Read::Failed(format!(
                                "Linux process identity for PID {}: {reason}",
                                row.pid
                            ));
                        }
                        ProcessIdentityObservation::Readable { .. } => {
                            return Read::Failed(format!(
                                "Linux process identity for PID {} did not include relations",
                                row.pid
                            ));
                        }
                    };
                #[cfg(not(target_os = "linux"))]
                let (session_id, start_time) = (None, None);
                observed.push(Row {
                    pid: i64::from(row.pid),
                    parent_pid: i64::from(row.parent_pid),
                    process_group_id: i64::from(row.process_group_id),
                    session_id,
                    command: row.command,
                    start_time,
                });
            }
            Read::Value(observed)
        }
        Err(message) => Read::Failed(format!("process table (ps): Error: {message}")),
    }
}

#[cfg(test)]
/// `/\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)/u` over one line.
fn parse_row(line: &str) -> Option<Row> {
    let mut rest = line.trim_start();
    let mut numbers = [0_i64; 4];
    for number in &mut numbers {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        *number = rest[..end].parse().ok()?;
        let after = &rest[end..];
        let trimmed = after.trim_start();
        if trimmed.len() == after.len() {
            return None;
        }
        rest = trimmed;
    }
    let [pid, parent_pid, process_group_id, session] = numbers;
    (pid > 0 && parent_pid >= 0).then(|| Row {
        pid,
        parent_pid,
        process_group_id,
        session_id: (session != 0).then_some(session),
        command: rest.trim_end_matches('\r').to_owned(),
        start_time: None,
    })
}

/// `readProcessRunId` on the PTY root.
fn read_root_token(pid: i64) -> Result<Option<String>, String> {
    match ProcessRunTokenObserver.observe(pid as u64) {
        RunTokenObservation::Readable { run_id } => Ok(run_id),
        RunTokenObservation::Unavailable { reason } if reason == "process_not_in_snapshot" => {
            Err(format!("process {pid} is not live"))
        }
        RunTokenObservation::Absent { .. } => Err(format!("process {pid} is not live")),
        RunTokenObservation::Unavailable { reason } => Err(reason),
    }
}

/// `inspectInitializedPtyRoot`.
fn initialized_root(context: &SamplerContext, stop: &AtomicBool) -> (bool, Diagnostics) {
    let root = context.root_pid;
    let find = |read: Read<Vec<Row>>, diagnostics: &mut Diagnostics| -> Option<Row> {
        match read {
            Read::Value(rows) => rows.into_iter().find(|row| row.pid == root),
            Read::Interrupted => {
                diagnostics.merge(Diagnostics::interrupted());
                None
            }
            Read::Failed(message) => {
                diagnostics.merge(Diagnostics::failure(message));
                None
            }
        }
    };
    let mut diagnostics = Diagnostics::default();
    let Some(before) = find(read_ps(context, stop), &mut diagnostics) else {
        return (false, diagnostics);
    };
    if before.process_group_id != root
        || (before.session_id != Some(root) && before.session_id.is_some())
    {
        return (false, diagnostics);
    }
    let observed = if stop.load(Ordering::SeqCst) {
        diagnostics.merge(Diagnostics::interrupted());
        None
    } else {
        match read_root_token(root) {
            Ok(run_id) => run_id,
            Err(message) => {
                diagnostics.merge(Diagnostics::failure(format!(
                    "run token for PID {root}: Error: {message}"
                )));
                None
            }
        }
    };
    let Some(after) = find(read_ps(context, stop), &mut diagnostics) else {
        return (false, diagnostics);
    };
    let session_matches = (before.session_id == Some(root) && after.session_id == Some(root))
        || (before.session_id.is_none() && after.session_id.is_none());
    let initialized = session_matches
        && after.parent_pid == before.parent_pid
        && after.process_group_id == root
        && (before.start_time.is_none()
            || after.start_time.is_some() && before.start_time == after.start_time)
        && observed.as_deref() == Some(context.run_id.as_str());
    (initialized, diagnostics)
}

/// `samplePs`: breadth-first descendants of the root, at most `limit` rows.
fn sample_ps(context: &SamplerContext, stop: &AtomicBool, limit: u64) -> (Vec<Row>, Diagnostics) {
    match read_ps(context, stop) {
        Read::Value(rows) => {
            let by_pid: HashMap<i64, &Row> = rows.iter().map(|row| (row.pid, row)).collect();
            let mut children: HashMap<i64, Vec<&Row>> = HashMap::new();
            for row in &rows {
                children.entry(row.parent_pid).or_default().push(row);
            }
            let mut result = Vec::new();
            let mut visited = std::collections::HashSet::new();
            let mut queue = vec![context.root_pid];
            let mut index = 0;
            while index < queue.len() && (result.len() as u64) < limit {
                let pid = queue[index];
                index += 1;
                if !visited.insert(pid) {
                    continue;
                }
                if let Some(row) = by_pid.get(&pid) {
                    result.push((*row).clone());
                }
                if result.len() as u64 >= limit {
                    break;
                }
                for child in children.get(&pid).into_iter().flatten() {
                    if !visited.contains(&child.pid) {
                        queue.push(child.pid);
                    }
                }
            }
            (result, Diagnostics::default())
        }
        Read::Interrupted => (Vec::new(), Diagnostics::interrupted()),
        Read::Failed(message) => (Vec::new(), Diagnostics::failure(message)),
    }
}

fn sample_once(context: &SamplerContext, stop: &AtomicBool, state: &Mutex<State>) {
    let mut diagnostics = Diagnostics::default();
    let initialized = state
        .lock()
        .map(|state| state.root_initialized)
        .unwrap_or(false);
    let mut rows = Vec::new();
    let mut elapsed = 0;
    if !initialized {
        let (ok, root) = initialized_root(context, stop);
        diagnostics.merge(root);
        if ok && let Ok(mut state) = state.lock() {
            state.root_initialized = true;
        }
        if ok {
            elapsed = context.started.elapsed().as_millis() as u64;
            let (sampled, sampled_diagnostics) = sample_ps(context, stop, context.limit + 1);
            rows = sampled;
            diagnostics.merge(sampled_diagnostics);
        }
    } else {
        elapsed = context.started.elapsed().as_millis() as u64;
        let (sampled, sampled_diagnostics) = sample_ps(context, stop, context.limit + 1);
        rows = sampled;
        diagnostics.merge(sampled_diagnostics);
    }
    let Ok(mut state) = state.lock() else {
        return;
    };
    state.diagnostics.merge(diagnostics);
    for row in rows {
        #[cfg(target_os = "linux")]
        if let Some(start_time) = row.start_time.as_ref() {
            if state
                .identities
                .get(&row.pid)
                .is_some_and(|existing| existing != start_time)
            {
                continue;
            }
            state.identities.insert(row.pid, start_time.clone());
        }
        let observation = json!([
            row.parent_pid,
            row.command,
            row.process_group_id,
            row.session_id
        ])
        .to_string();
        if state.last.get(&row.pid) == Some(&observation) {
            continue;
        }
        if state.samples.len() as u64 >= context.limit {
            state.limit_reached = true;
            continue;
        }
        state.last.insert(row.pid, observation);
        let index = state.samples.len();
        state.samples.push(RawSample {
            at_ms: elapsed,
            pid: row.pid,
            parent_pid: row.parent_pid,
            command: row.command,
            process_group_id: Some(row.process_group_id),
            session_id: row.session_id,
        });
        state.recorded.push(index);
    }
}

impl Sampler {
    /// `startProcessSampler`: sample now and on every 50 ms tick that is not busy.
    pub fn start(context: SamplerContext) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(State::default()));
        let limit = context.limit;
        if limit > 0 {
            // Capture can settle a short-lived root before the worker gets its
            // first scheduling slice. Establish the initial observation in
            // the launching thread so a live, readable root always has a
            // chance to contribute a sample.
            sample_once(&context, &stop, &state);
        }
        let thread = (limit > 0).then(|| {
            let stop = Arc::clone(&stop);
            let state = Arc::clone(&state);
            std::thread::spawn(move || {
                let origin = Instant::now();
                while !stop.load(Ordering::SeqCst) {
                    sample_once(&context, &stop, &state);
                    // The next interval tick after this attempt settled.
                    let ticks = origin.elapsed().as_millis() / INTERVAL.as_millis() + 1;
                    let next = origin + INTERVAL * ticks as u32;
                    while !stop.load(Ordering::SeqCst) && Instant::now() < next {
                        std::thread::sleep(
                            Duration::from_millis(2)
                                .min(next.saturating_duration_since(Instant::now())),
                        );
                    }
                }
            })
        });
        Self {
            stop,
            state,
            thread,
            limit,
        }
    }

    /// Sample indexes retained since the previous call (journal order).
    pub fn drain_recorded(&self) -> Vec<usize> {
        self.state
            .lock()
            .map(|mut state| std::mem::take(&mut state.recorded))
            .unwrap_or_default()
    }

    /// Current samples (for process-group selection while running).
    pub fn snapshot(&self) -> Vec<RawSample> {
        self.state
            .lock()
            .map(|state| state.samples.clone())
            .unwrap_or_default()
    }

    /// Stop, interrupt an attempt in flight and report coverage.
    pub fn stop(&mut self) -> Sampling {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let state = self
            .state
            .lock()
            .map(|state| {
                (
                    state.samples.clone(),
                    state.limit_reached,
                    state.diagnostics.clone(),
                )
            })
            .unwrap_or_default();
        let (samples, limit_reached, diagnostics) = state;
        let failures = diagnostics.count + u64::from(diagnostics.interrupted);
        let first = if diagnostics.interrupted {
            Some(match diagnostics.first {
                None => INTERRUPTED.to_owned(),
                Some(first) => format!("{first}; {INTERRUPTED}"),
            })
        } else {
            diagnostics.first
        };
        let partial = limit_reached || failures > 0;
        Sampling {
            coverage: json!({
                "sample_limit": self.limit,
                "sampling_partial": partial,
                "retained_samples": samples.len(),
                "sample_limit_reached": limit_reached,
                "sampling_failures": failures,
                "first_sampling_failure": first,
                "coverage": "sampled",
            }),
            samples,
            partial,
        }
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ps_rows_like_the_original_expression() {
        let row = parse_row("  123   1 123   0 /bin/sh -c sleep 1").unwrap();
        assert_eq!(
            (
                row.pid,
                row.parent_pid,
                row.process_group_id,
                row.session_id
            ),
            (123, 1, 123, None)
        );
        assert_eq!(row.command, "/bin/sh -c sleep 1");
        assert!(parse_row("PID PPID").is_none());
        assert!(parse_row("0 0 0 0 kernel").is_none());
    }
}
