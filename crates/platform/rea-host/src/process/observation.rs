//! Shared process observation orchestration.
//!
//! Platform modules own how identity facts are read.  This layer owns only
//! caller-supplied PID batching and preserves each platform's explicit
//! readable, absent, or unavailable outcome.

use crate::process::affinity::{AffinityObservation, ProcessAffinityObserver};
use crate::process::handle_count::{HandleCountObservation, ProcessHandleCountObserver};
use crate::process::io_counters::{IoCountersObservation, ProcessIoCountersObserver};
use crate::process::linux::cmdline::{CommandLineObservation, ProcessCommandLineObserver};
use crate::process::linux::identity::{Observation, ProcessIdentityObserver};
#[cfg(not(windows))]
use crate::process::linux::memory::{MemoryObservation, ProcessMemoryObserver};
use crate::process::linux::run_token::{ProcessRunTokenObserver, RunTokenObservation};
use crate::process::linux::status_observer::{ProcessStatusObserver, StatusObservation};
use crate::process::macos::fds::{DescriptorObservation, ProcessDescriptorObserver};
use crate::process::nice::{NiceObservation, ProcessNiceObserver};
use crate::process::priority::{PriorityObservation, ProcessPriorityObserver};
use crate::process::scheduler::{ProcessSchedulerObserver, SchedulerObservation};
#[cfg(windows)]
use crate::process::windows::memory::{MemoryObservation, ProcessMemoryObserver};
use std::collections::BTreeMap;

/// One process retained in a verified, read-only lineage snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageNode {
    pub pid: u64,
    pub identity: String,
    pub parent_pid: u64,
    pub process_group_id: Option<u64>,
    pub session_id: Option<u64>,
}

/// Result for one caller-selected lineage root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LineageObservation {
    Verified {
        root: LineageNode,
        descendants: Vec<LineageNode>,
    },
    Unavailable {
        reason: String,
    },
}

/// Read-only source of process identity observations.
pub trait ProcessIdentitySource {
    fn observe(&self, pid: u64, include_effective_uid: bool) -> Observation;
}

pub trait ProcessAffinitySource {
    fn observe_affinity(&self, pid: u64) -> AffinityObservation;
}
pub trait ProcessNiceSource {
    fn observe_nice(&self, pid: u64) -> NiceObservation;
}
pub trait ProcessSchedulerSource {
    fn observe_scheduler(&self, pid: u64) -> SchedulerObservation;
}

pub trait ProcessCommandLineSource {
    fn observe_cmdline(&self, pid: u64) -> CommandLineObservation;
}

pub trait ProcessMemorySource {
    fn observe_memory(&self, pid: u64) -> MemoryObservation;
}

pub trait ProcessStatusSource {
    fn observe_status(&self, pid: u64) -> StatusObservation;
}

pub trait ProcessRunTokenSource {
    fn observe_run_token(&self, pid: u64) -> RunTokenObservation;
}

pub trait ProcessDescriptorSource {
    fn observe_descriptors(&self, pid: u64) -> DescriptorObservation;
}

pub trait ProcessHandleCountSource {
    fn observe_handle_count(&self, pid: u64) -> HandleCountObservation;
}

pub trait ProcessIoCountersSource {
    fn observe_io_counters(&self, pid: u64) -> IoCountersObservation;
}

pub trait ProcessPrioritySource {
    fn observe_priority(&self, pid: u64) -> PriorityObservation;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedResidentMemoryObservation {
    Sampled {
        identity: String,
        resident_bytes: u64,
    },
    Exited,
    Unavailable {
        reason: String,
    },
}

impl ProcessIdentitySource for ProcessIdentityObserver {
    fn observe(&self, pid: u64, include_effective_uid: bool) -> Observation {
        ProcessIdentityObserver::observe(self, pid, include_effective_uid)
    }
}

impl ProcessAffinitySource for ProcessAffinityObserver {
    fn observe_affinity(&self, pid: u64) -> AffinityObservation {
        ProcessAffinityObserver::observe(self, pid)
    }
}

impl ProcessAffinitySource for ProcessIdentityObserver {
    fn observe_affinity(&self, pid: u64) -> AffinityObservation {
        ProcessAffinityObserver.observe(pid)
    }
}
impl ProcessNiceSource for ProcessNiceObserver {
    fn observe_nice(&self, pid: u64) -> NiceObservation {
        ProcessNiceObserver::observe(self, pid)
    }
}
impl ProcessNiceSource for ProcessIdentityObserver {
    fn observe_nice(&self, pid: u64) -> NiceObservation {
        ProcessNiceObserver.observe(pid)
    }
}
impl ProcessSchedulerSource for ProcessSchedulerObserver {
    fn observe_scheduler(&self, pid: u64) -> SchedulerObservation {
        ProcessSchedulerObserver::observe(self, pid)
    }
}
impl ProcessSchedulerSource for ProcessIdentityObserver {
    fn observe_scheduler(&self, pid: u64) -> SchedulerObservation {
        ProcessSchedulerObserver.observe(pid)
    }
}

impl ProcessCommandLineSource for ProcessCommandLineObserver {
    fn observe_cmdline(&self, pid: u64) -> CommandLineObservation {
        ProcessCommandLineObserver::observe(self, pid)
    }
}

impl ProcessCommandLineSource for ProcessIdentityObserver {
    fn observe_cmdline(&self, pid: u64) -> CommandLineObservation {
        ProcessCommandLineObserver.observe(pid)
    }
}

impl ProcessMemorySource for ProcessMemoryObserver {
    fn observe_memory(&self, pid: u64) -> MemoryObservation {
        ProcessMemoryObserver::observe(self, pid)
    }
}

impl ProcessMemorySource for ProcessIdentityObserver {
    fn observe_memory(&self, pid: u64) -> MemoryObservation {
        ProcessMemoryObserver.observe(pid)
    }
}

impl ProcessStatusSource for ProcessStatusObserver {
    fn observe_status(&self, pid: u64) -> StatusObservation {
        ProcessStatusObserver::observe(self, pid)
    }
}

impl ProcessStatusSource for ProcessIdentityObserver {
    fn observe_status(&self, pid: u64) -> StatusObservation {
        ProcessStatusObserver.observe(pid)
    }
}

impl ProcessRunTokenSource for ProcessRunTokenObserver {
    fn observe_run_token(&self, pid: u64) -> RunTokenObservation {
        ProcessRunTokenObserver::observe(self, pid)
    }
}

impl ProcessRunTokenSource for ProcessIdentityObserver {
    fn observe_run_token(&self, pid: u64) -> RunTokenObservation {
        ProcessRunTokenObserver.observe(pid)
    }
}

impl ProcessDescriptorSource for ProcessDescriptorObserver {
    fn observe_descriptors(&self, pid: u64) -> DescriptorObservation {
        ProcessDescriptorObserver::observe(self, pid)
    }
}

impl ProcessDescriptorSource for ProcessIdentityObserver {
    fn observe_descriptors(&self, pid: u64) -> DescriptorObservation {
        ProcessDescriptorObserver.observe(pid)
    }
}

impl ProcessHandleCountSource for ProcessHandleCountObserver {
    fn observe_handle_count(&self, pid: u64) -> HandleCountObservation {
        ProcessHandleCountObserver::observe(self, pid)
    }
}

impl ProcessHandleCountSource for ProcessIdentityObserver {
    fn observe_handle_count(&self, pid: u64) -> HandleCountObservation {
        ProcessHandleCountObserver.observe(pid)
    }
}

impl ProcessIoCountersSource for ProcessIoCountersObserver {
    fn observe_io_counters(&self, pid: u64) -> IoCountersObservation {
        ProcessIoCountersObserver::observe(self, pid)
    }
}

impl ProcessIoCountersSource for ProcessIdentityObserver {
    fn observe_io_counters(&self, pid: u64) -> IoCountersObservation {
        ProcessIoCountersObserver.observe(pid)
    }
}

impl ProcessPrioritySource for ProcessPriorityObserver {
    fn observe_priority(&self, pid: u64) -> PriorityObservation {
        ProcessPriorityObserver::observe(self, pid)
    }
}

impl ProcessPrioritySource for ProcessIdentityObserver {
    fn observe_priority(&self, pid: u64) -> PriorityObservation {
        ProcessPriorityObserver.observe(pid)
    }
}

/// Observe explicit PIDs without enumerating or controlling the process table.
pub fn observe_processes<S, I>(
    source: &S,
    pids: I,
    include_effective_uid: bool,
) -> BTreeMap<u64, Observation>
where
    S: ProcessIdentitySource,
    I: IntoIterator<Item = u64>,
{
    pids.into_iter()
        .map(|pid| (pid, source.observe(pid, include_effective_uid)))
        .collect()
}

pub fn observe_process_affinity<S>(source: &S, pid: u64) -> AffinityObservation
where
    S: ProcessIdentitySource + ProcessAffinitySource,
{
    let before = source.observe(pid, false);
    let affinity = source.observe_affinity(pid);
    let after = source.observe(pid, false);
    match crate::process::linux::identity::generation(&before, &after) {
        crate::process::linux::identity::Generation::Same => affinity,
        crate::process::linux::identity::Generation::Absent => AffinityObservation::Absent {
            reason: "process disappeared during affinity observation",
        },
        crate::process::linux::identity::Generation::Replaced => AffinityObservation::Unavailable {
            reason: "process identity changed during affinity observation".into(),
        },
        crate::process::linux::identity::Generation::Unavailable => {
            AffinityObservation::Unavailable {
                reason: "process identity could not be revalidated during affinity observation"
                    .into(),
            }
        }
    }
}
pub fn observe_process_nice<S>(source: &S, pid: u64) -> NiceObservation
where
    S: ProcessIdentitySource + ProcessNiceSource,
{
    let before = source.observe(pid, false);
    let value = source.observe_nice(pid);
    let after = source.observe(pid, false);
    match crate::process::linux::identity::generation(&before, &after) {
        crate::process::linux::identity::Generation::Same => value,
        crate::process::linux::identity::Generation::Absent => NiceObservation::Absent {
            reason: "process disappeared during nice observation",
        },
        crate::process::linux::identity::Generation::Replaced => NiceObservation::Unavailable {
            reason: "process identity changed during nice observation".into(),
        },
        crate::process::linux::identity::Generation::Unavailable => NiceObservation::Unavailable {
            reason: "process identity could not be revalidated during nice observation".into(),
        },
    }
}
pub fn observe_process_scheduler<S>(source: &S, pid: u64) -> SchedulerObservation
where
    S: ProcessIdentitySource + ProcessSchedulerSource,
{
    let before = source.observe(pid, false);
    let value = source.observe_scheduler(pid);
    let after = source.observe(pid, false);
    match crate::process::linux::identity::generation(&before, &after) {
        crate::process::linux::identity::Generation::Same => value,
        crate::process::linux::identity::Generation::Absent => SchedulerObservation::Absent {
            reason: "process disappeared during scheduler observation",
        },
        crate::process::linux::identity::Generation::Replaced => {
            SchedulerObservation::Unavailable {
                reason: "process identity changed during scheduler observation".into(),
            }
        }
        crate::process::linux::identity::Generation::Unavailable => {
            SchedulerObservation::Unavailable {
                reason: "process identity could not be revalidated during scheduler observation"
                    .into(),
            }
        }
    }
}

/// Observe memory only when the selected PID retains one generation across the read.
pub fn observe_process_memory<S>(source: &S, pid: u64) -> MemoryObservation
where
    S: ProcessIdentitySource + ProcessMemorySource,
{
    let before = source.observe(pid, false);
    let memory = source.observe_memory(pid);
    let after = source.observe(pid, false);
    match crate::process::linux::identity::generation(&before, &after) {
        crate::process::linux::identity::Generation::Same => memory,
        crate::process::linux::identity::Generation::Absent => MemoryObservation::Absent {
            reason: "process disappeared during memory observation",
        },
        crate::process::linux::identity::Generation::Replaced => MemoryObservation::Unavailable {
            reason: "process identity changed during memory observation".into(),
        },
        crate::process::linux::identity::Generation::Unavailable => {
            MemoryObservation::Unavailable {
                reason: "process identity could not be revalidated during memory observation"
                    .into(),
            }
        }
    }
}

/// Observe status fields only when the selected PID retains one generation.
pub fn observe_process_status<S>(source: &S, pid: u64) -> StatusObservation
where
    S: ProcessIdentitySource + ProcessStatusSource,
{
    let before = source.observe(pid, false);
    let status = source.observe_status(pid);
    let after = source.observe(pid, false);
    match crate::process::linux::identity::generation(&before, &after) {
        crate::process::linux::identity::Generation::Same => status,
        crate::process::linux::identity::Generation::Absent => StatusObservation::Absent {
            reason: "process disappeared during status observation",
        },
        crate::process::linux::identity::Generation::Replaced => StatusObservation::Unavailable {
            reason: "process identity changed during status observation".into(),
        },
        crate::process::linux::identity::Generation::Unavailable => {
            StatusObservation::Unavailable {
                reason: "process identity could not be revalidated during status observation"
                    .into(),
            }
        }
    }
}

pub fn observe_process_run_token<S>(source: &S, pid: u64) -> RunTokenObservation
where
    S: ProcessIdentitySource + ProcessRunTokenSource,
{
    let before = source.observe(pid, false);
    let token = source.observe_run_token(pid);
    let after = source.observe(pid, false);
    match crate::process::linux::identity::generation(&before, &after) {
        crate::process::linux::identity::Generation::Same => token,
        crate::process::linux::identity::Generation::Absent => RunTokenObservation::Absent {
            reason: "process disappeared during run-token observation",
        },
        crate::process::linux::identity::Generation::Replaced => RunTokenObservation::Unavailable {
            reason: "process identity changed during run-token observation".into(),
        },
        crate::process::linux::identity::Generation::Unavailable => {
            RunTokenObservation::Unavailable {
                reason: "process identity could not be revalidated during run-token observation"
                    .into(),
            }
        }
    }
}

/// Observe descriptor metadata only when the selected PID retains one generation.
pub fn observe_process_descriptors<S>(source: &S, pid: u64) -> DescriptorObservation
where
    S: ProcessIdentitySource + ProcessDescriptorSource,
{
    let before = source.observe(pid, false);
    let descriptors = source.observe_descriptors(pid);
    let after = source.observe(pid, false);
    match crate::process::linux::identity::generation(&before, &after) {
        crate::process::linux::identity::Generation::Same => descriptors,
        crate::process::linux::identity::Generation::Absent => DescriptorObservation::Absent {
            reason: "process disappeared during descriptor observation",
        },
        crate::process::linux::identity::Generation::Replaced => {
            DescriptorObservation::Unavailable {
                reason: "process identity changed during descriptor observation".into(),
            }
        }
        crate::process::linux::identity::Generation::Unavailable => {
            DescriptorObservation::Unavailable {
                reason: "process identity could not be revalidated during descriptor observation"
                    .into(),
            }
        }
    }
}

pub fn observe_process_handle_count<S>(source: &S, pid: u64) -> HandleCountObservation
where
    S: ProcessIdentitySource + ProcessHandleCountSource,
{
    let before = source.observe(pid, false);
    let count = source.observe_handle_count(pid);
    let after = source.observe(pid, false);
    match crate::process::linux::identity::generation(&before, &after) {
        crate::process::linux::identity::Generation::Same => count,
        crate::process::linux::identity::Generation::Absent => HandleCountObservation::Absent {
            reason: "process disappeared during handle-count observation",
        },
        crate::process::linux::identity::Generation::Replaced => {
            HandleCountObservation::Unavailable {
                reason: "process identity changed during handle-count observation".into(),
            }
        }
        crate::process::linux::identity::Generation::Unavailable => {
            HandleCountObservation::Unavailable {
                reason: "process identity could not be revalidated during handle-count observation"
                    .into(),
            }
        }
    }
}

pub fn observe_process_io_counters<S>(source: &S, pid: u64) -> IoCountersObservation
where
    S: ProcessIdentitySource + ProcessIoCountersSource,
{
    let before = source.observe(pid, false);
    let counters = source.observe_io_counters(pid);
    let after = source.observe(pid, false);
    match crate::process::linux::identity::generation(&before, &after) {
        crate::process::linux::identity::Generation::Same => counters,
        crate::process::linux::identity::Generation::Absent => IoCountersObservation::Absent {
            reason: "process disappeared during I/O observation",
        },
        crate::process::linux::identity::Generation::Replaced => {
            IoCountersObservation::Unavailable {
                reason: "process identity changed during I/O observation".into(),
            }
        }
        crate::process::linux::identity::Generation::Unavailable => {
            IoCountersObservation::Unavailable {
                reason: "process identity could not be revalidated during I/O observation".into(),
            }
        }
    }
}

pub fn observe_process_priority<S>(source: &S, pid: u64) -> PriorityObservation
where
    S: ProcessIdentitySource + ProcessPrioritySource,
{
    let before = source.observe(pid, false);
    let priority = source.observe_priority(pid);
    let after = source.observe(pid, false);
    match crate::process::linux::identity::generation(&before, &after) {
        crate::process::linux::identity::Generation::Same => priority,
        crate::process::linux::identity::Generation::Absent => PriorityObservation::Absent {
            reason: "process disappeared during priority observation",
        },
        crate::process::linux::identity::Generation::Replaced => PriorityObservation::Unavailable {
            reason: "process identity changed during priority observation".into(),
        },
        crate::process::linux::identity::Generation::Unavailable => {
            PriorityObservation::Unavailable {
                reason: "process identity could not be revalidated during priority observation"
                    .into(),
            }
        }
    }
}

/// Sample resident memory only while the expected owned process identity and
/// relation remain stable. This observes and never controls the target.
pub fn observe_owned_resident_memory<S>(
    source: &S,
    pid: u64,
    expected_identity: Option<&str>,
    expected_parent_pid: Option<u64>,
    expected_process_group_id: Option<u64>,
) -> OwnedResidentMemoryObservation
where
    S: ProcessIdentitySource + ProcessMemorySource,
{
    let before = source.observe(pid, false);
    let Some(identity) = owned_identity_matches(
        &before,
        expected_identity,
        expected_parent_pid,
        expected_process_group_id,
    ) else {
        return if matches!(before, Observation::Absent { .. }) {
            OwnedResidentMemoryObservation::Exited
        } else {
            OwnedResidentMemoryObservation::Unavailable {
                reason: "owned process identity was unavailable or did not match".into(),
            }
        };
    };

    let memory = source.observe_memory(pid);
    let after = source.observe(pid, false);
    if !matches!(
        crate::process::linux::identity::generation(&before, &after),
        crate::process::linux::identity::Generation::Same
    ) {
        return if matches!(after, Observation::Absent { .. }) {
            OwnedResidentMemoryObservation::Exited
        } else {
            OwnedResidentMemoryObservation::Unavailable {
                reason: "owned process identity changed during resident memory observation".into(),
            }
        };
    }
    let resident_bytes = match memory {
        MemoryObservation::Readable { resident_bytes, .. } => resident_bytes,
        MemoryObservation::Absent { .. } => return OwnedResidentMemoryObservation::Exited,
        MemoryObservation::Unavailable { reason } => {
            return OwnedResidentMemoryObservation::Unavailable { reason };
        }
    };
    if owned_identity_matches(
        &after,
        Some(&identity),
        expected_parent_pid,
        expected_process_group_id,
    )
    .is_none()
    {
        return OwnedResidentMemoryObservation::Unavailable {
            reason: "owned process relation was unavailable after resident memory observation"
                .into(),
        };
    }
    OwnedResidentMemoryObservation::Sampled {
        identity,
        resident_bytes,
    }
}

fn owned_identity_matches(
    observation: &Observation,
    expected_identity: Option<&str>,
    expected_parent_pid: Option<u64>,
    expected_process_group_id: Option<u64>,
) -> Option<String> {
    let Observation::Readable {
        identity,
        relation: Some(relation),
        ..
    } = observation
    else {
        return None;
    };
    if expected_identity.is_some_and(|expected| expected != identity)
        || expected_parent_pid.is_some_and(|expected| expected != relation.parent_pid)
        || expected_process_group_id
            .is_some_and(|expected| Some(expected) != relation.process_group_id)
    {
        return None;
    }
    Some(identity.clone())
}

/// Revalidate caller-selected roots and their candidate descendants.
///
/// The candidate set is deliberately supplied by the caller; this operation
/// never enumerates or controls the process table. A root is verified only
/// when its before/after identities match and every currently reachable
/// descendant has the same generation. `max_nodes` bounds the retained graph.
pub fn observe_process_lineages<S, R, C>(
    source: &S,
    roots: R,
    candidates: C,
    include_effective_uid: bool,
    max_nodes: usize,
) -> BTreeMap<u64, LineageObservation>
where
    S: ProcessIdentitySource,
    R: IntoIterator<Item = u64>,
    C: IntoIterator<Item = u64>,
{
    let roots: Vec<u64> = roots.into_iter().collect();
    let mut selected: Vec<u64> = roots.clone();
    selected.extend(candidates);
    selected.sort_unstable();
    selected.dedup();

    if selected.len() > max_nodes {
        let reason = format!("process lineage candidate set exceeds bound of {max_nodes} nodes");
        return roots
            .into_iter()
            .map(|pid| {
                (
                    pid,
                    LineageObservation::Unavailable {
                        reason: reason.clone(),
                    },
                )
            })
            .collect();
    }

    let before = observe_processes(source, selected.iter().copied(), include_effective_uid);
    let after = observe_processes(source, selected.iter().copied(), include_effective_uid);

    roots
        .into_iter()
        .map(|root_pid| {
            let observation = observe_one_lineage(root_pid, &before, &after);
            (root_pid, observation)
        })
        .collect()
}

fn observe_one_lineage(
    root_pid: u64,
    before: &BTreeMap<u64, Observation>,
    after: &BTreeMap<u64, Observation>,
) -> LineageObservation {
    let Some(root_after) = after.get(&root_pid) else {
        return unavailable_lineage("root was not returned during after observation");
    };
    if !matches!(
        crate::process::linux::identity::generation(
            before.get(&root_pid).unwrap_or(&Observation::Unavailable {
                reason: "root was not returned during before observation".into(),
            }),
            root_after,
        ),
        crate::process::linux::identity::Generation::Same
    ) {
        return unavailable_lineage("root generation could not be revalidated");
    }

    let root = match lineage_node(root_pid, root_after) {
        Some(node) => node,
        None => return unavailable_lineage("root relation was unavailable"),
    };
    let mut descendants = Vec::new();
    let mut visited = std::collections::BTreeSet::from([root_pid]);
    let mut frontier = vec![root_pid];
    while let Some(parent_pid) = frontier.pop() {
        let mut children: Vec<u64> = after
            .iter()
            .filter_map(|(&pid, observation)| {
                let relation = readable_relation(observation)?;
                (relation.parent_pid == parent_pid).then_some(pid)
            })
            .collect();
        children.sort_unstable();
        for child_pid in children.into_iter().rev() {
            if !visited.insert(child_pid) {
                continue;
            }
            let Some(child_after) = after.get(&child_pid) else {
                continue;
            };
            let Some(child_before) = before.get(&child_pid) else {
                return unavailable_lineage(
                    "descendant was not returned during before observation",
                );
            };
            if !matches!(
                crate::process::linux::identity::generation(child_before, child_after),
                crate::process::linux::identity::Generation::Same
            ) {
                return unavailable_lineage("descendant generation could not be revalidated");
            }
            let Some(node) = lineage_node(child_pid, child_after) else {
                return unavailable_lineage("descendant relation was unavailable");
            };
            descendants.push(node);
            frontier.push(child_pid);
        }
    }

    descendants.sort_by_key(|node| node.pid);
    LineageObservation::Verified { root, descendants }
}

fn lineage_node(pid: u64, observation: &Observation) -> Option<LineageNode> {
    let Observation::Readable {
        identity,
        relation: Some(relation),
        ..
    } = observation
    else {
        return None;
    };
    Some(LineageNode {
        pid,
        identity: identity.clone(),
        parent_pid: relation.parent_pid,
        process_group_id: relation.process_group_id,
        session_id: relation.session_id,
    })
}

fn readable_relation(
    observation: &Observation,
) -> Option<&crate::process::linux::identity::Relation> {
    match observation {
        Observation::Readable {
            relation: Some(relation),
            ..
        } => Some(relation),
        _ => None,
    }
}

fn unavailable_lineage(reason: &str) -> LineageObservation {
    LineageObservation::Unavailable {
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct FakeSource {
        observations: BTreeMap<u64, Observation>,
    }

    struct SequencedSource {
        rounds: Mutex<Vec<BTreeMap<u64, Observation>>>,
        calls: Mutex<usize>,
        width: usize,
    }

    impl ProcessIdentitySource for SequencedSource {
        fn observe(&self, pid: u64, _include_effective_uid: bool) -> Observation {
            let mut calls = self.calls.lock().expect("fixture lock should not fail");
            let round_index = (*calls / self.width).min(
                self.rounds
                    .lock()
                    .expect("fixture lock should not fail")
                    .len()
                    .saturating_sub(1),
            );
            *calls += 1;
            let rounds = self.rounds.lock().expect("fixture lock should not fail");
            let round = rounds
                .get(round_index)
                .expect("fixture should provide an observation round");
            round
                .get(&pid)
                .cloned()
                .unwrap_or(Observation::Unavailable {
                    reason: "missing sequenced fixture".into(),
                })
        }
    }

    impl ProcessMemorySource for SequencedSource {
        fn observe_memory(&self, _pid: u64) -> MemoryObservation {
            MemoryObservation::Readable {
                virtual_pages: 10,
                resident_pages: 4,
                page_size_bytes: 4096,
                virtual_bytes: 40_960,
                resident_bytes: 16_384,
                page_size_source: "fixture-page-size",
            }
        }
    }

    impl ProcessStatusSource for SequencedSource {
        fn observe_status(&self, _pid: u64) -> StatusObservation {
            StatusObservation::Readable {
                name: Some("fixture".into()),
                uid: Some(1001),
                gid: Some(21),
                parent_pid: Some(7),
                threads: Some(2),
                state: Some("R".into()),
                unknown_fields: Vec::new(),
            }
        }
    }

    impl ProcessDescriptorSource for SequencedSource {
        fn observe_descriptors(&self, _pid: u64) -> DescriptorObservation {
            DescriptorObservation::Readable {
                descriptors: vec![crate::process::macos::fds::ProcessDescriptor { fd: 3, kind: 1 }],
                complete: true,
            }
        }
    }

    impl ProcessHandleCountSource for SequencedSource {
        fn observe_handle_count(&self, _pid: u64) -> HandleCountObservation {
            HandleCountObservation::Readable { count: 12 }
        }
    }

    impl ProcessIoCountersSource for SequencedSource {
        fn observe_io_counters(&self, _pid: u64) -> IoCountersObservation {
            IoCountersObservation::Readable(crate::process::io_counters::ProcessIoCounters {
                read_bytes: 100,
                write_bytes: 200,
                read_operations: 3,
                write_operations: 4,
            })
        }
    }

    fn readable_with_relation(
        identity: &str,
        parent_pid: u64,
        process_group_id: u64,
    ) -> Observation {
        Observation::Readable {
            identity: identity.into(),
            lifecycle: None,
            relation: Some(crate::process::linux::identity::Relation {
                parent_pid,
                process_group_id: Some(process_group_id),
                session_id: Some(9),
                parent_identity: None,
            }),
            effective_uid: None,
        }
    }

    impl ProcessIdentitySource for FakeSource {
        fn observe(&self, pid: u64, _include_effective_uid: bool) -> Observation {
            self.observations
                .get(&pid)
                .cloned()
                .unwrap_or(Observation::Unavailable {
                    reason: "fake source did not provide this PID".into(),
                })
        }
    }

    #[test]
    fn preserves_platform_outcomes_for_caller_selected_pids() {
        let source = FakeSource {
            observations: BTreeMap::from([
                (
                    11,
                    Observation::Readable {
                        identity: "fixture-generation".into(),
                        lifecycle: None,
                        relation: None,
                        effective_uid: None,
                    },
                ),
                (
                    12,
                    Observation::Absent {
                        reason: "not-found-in-caller-process-namespace",
                    },
                ),
                (
                    13,
                    Observation::Unavailable {
                        reason: "permission denied".into(),
                    },
                ),
            ]),
        };

        let observations = observe_processes(&source, [13, 11, 12], true);

        assert_eq!(observations.len(), 3);
        assert!(matches!(
            observations.get(&11),
            Some(Observation::Readable { identity, .. }) if identity == "fixture-generation"
        ));
        assert!(matches!(
            observations.get(&12),
            Some(Observation::Absent { reason })
                if *reason == "not-found-in-caller-process-namespace"
        ));
        assert!(matches!(
            observations.get(&13),
            Some(Observation::Unavailable { reason }) if reason == "permission denied"
        ));
    }

    #[test]
    fn verifies_stable_root_and_descendant_generations() {
        let round = BTreeMap::from([
            (10, readable_with_relation("root", 1, 10)),
            (11, readable_with_relation("child", 10, 10)),
            (12, readable_with_relation("grandchild", 11, 10)),
        ]);
        let source = SequencedSource {
            rounds: Mutex::new(vec![round.clone(), round]),
            calls: Mutex::new(0),
            width: 3,
        };

        let observations = observe_process_lineages(&source, [10], [11, 12], false, 8);
        let LineageObservation::Verified { root, descendants } = &observations[&10] else {
            panic!("stable fixture should produce a verified lineage");
        };
        assert_eq!(root.identity, "root");
        assert_eq!(
            descendants.iter().map(|node| node.pid).collect::<Vec<_>>(),
            vec![11, 12]
        );
    }

    #[test]
    fn preserves_unknown_when_a_descendant_generation_changes() {
        let before = BTreeMap::from([
            (10, readable_with_relation("root", 1, 10)),
            (11, readable_with_relation("child-old", 10, 10)),
        ]);
        let after = BTreeMap::from([
            (10, readable_with_relation("root", 1, 10)),
            (11, readable_with_relation("child-new", 10, 10)),
        ]);
        let source = SequencedSource {
            rounds: Mutex::new(vec![before, after]),
            calls: Mutex::new(0),
            width: 2,
        };

        let observations = observe_process_lineages(&source, [10], [11], false, 8);
        assert!(matches!(
            observations.get(&10),
            Some(LineageObservation::Unavailable { reason })
                if reason == "descendant generation could not be revalidated"
        ));
    }

    #[test]
    fn bounds_caller_selected_lineage_candidates() {
        let source = FakeSource {
            observations: BTreeMap::new(),
        };
        let observations = observe_process_lineages(&source, [10], [11, 12], false, 2);
        assert!(matches!(
            observations.get(&10),
            Some(LineageObservation::Unavailable { reason })
                if reason.contains("exceeds bound")
        ));
    }

    #[test]
    fn preserves_unknown_when_memory_pid_generation_changes() {
        let before = BTreeMap::from([(10, readable_with_relation("old", 1, 10))]);
        let after = BTreeMap::from([(10, readable_with_relation("new", 1, 10))]);
        let source = SequencedSource {
            rounds: Mutex::new(vec![before, after]),
            calls: Mutex::new(0),
            width: 1,
        };

        assert!(matches!(
            observe_process_memory(&source, 10),
            MemoryObservation::Unavailable { reason }
                if reason == "process identity changed during memory observation"
        ));
    }

    #[test]
    fn preserves_unknown_when_status_pid_generation_changes() {
        let before = BTreeMap::from([(10, readable_with_relation("old", 1, 10))]);
        let after = BTreeMap::from([(10, readable_with_relation("new", 1, 10))]);
        let source = SequencedSource {
            rounds: Mutex::new(vec![before, after]),
            calls: Mutex::new(0),
            width: 1,
        };

        assert!(matches!(
            observe_process_status(&source, 10),
            StatusObservation::Unavailable { reason }
                if reason == "process identity changed during status observation"
        ));
    }

    #[test]
    fn preserves_unknown_when_descriptor_pid_generation_changes() {
        let before = BTreeMap::from([(10, readable_with_relation("old", 1, 10))]);
        let after = BTreeMap::from([(10, readable_with_relation("new", 1, 10))]);
        let source = SequencedSource {
            rounds: Mutex::new(vec![before, after]),
            calls: Mutex::new(0),
            width: 1,
        };

        assert!(matches!(
            observe_process_descriptors(&source, 10),
            DescriptorObservation::Unavailable { reason }
                if reason == "process identity changed during descriptor observation"
        ));
    }

    #[test]
    fn preserves_unknown_when_handle_count_pid_generation_changes() {
        let before = BTreeMap::from([(10, readable_with_relation("old", 1, 10))]);
        let after = BTreeMap::from([(10, readable_with_relation("new", 1, 10))]);
        let source = SequencedSource {
            rounds: Mutex::new(vec![before, after]),
            calls: Mutex::new(0),
            width: 1,
        };

        assert!(matches!(
            observe_process_handle_count(&source, 10),
            HandleCountObservation::Unavailable { reason }
                if reason == "process identity changed during handle-count observation"
        ));
    }

    #[test]
    fn preserves_unknown_when_io_pid_generation_changes() {
        let before = BTreeMap::from([(10, readable_with_relation("old", 1, 10))]);
        let after = BTreeMap::from([(10, readable_with_relation("new", 1, 10))]);
        let source = SequencedSource {
            rounds: Mutex::new(vec![before, after]),
            calls: Mutex::new(0),
            width: 1,
        };

        assert!(matches!(
            observe_process_io_counters(&source, 10),
            IoCountersObservation::Unavailable { reason }
                if reason == "process identity changed during I/O observation"
        ));
    }

    #[test]
    fn samples_owned_resident_memory_only_for_matching_identity_and_relation() {
        let round = BTreeMap::from([(10, readable_with_relation("owned", 1, 10))]);
        let source = SequencedSource {
            rounds: Mutex::new(vec![round.clone(), round]),
            calls: Mutex::new(0),
            width: 1,
        };
        assert_eq!(
            observe_owned_resident_memory(&source, 10, Some("owned"), Some(1), Some(10)),
            OwnedResidentMemoryObservation::Sampled {
                identity: "owned".into(),
                resident_bytes: 16_384,
            }
        );
    }
}
