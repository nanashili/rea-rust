//! Evidence projection for read-only process identity observations.

use rea_core::{
    evidence::record::{EvidenceRecord, EvidenceRecordError},
    linux_proc::stat::Lifecycle,
};
use rea_host::{
    process::affinity::AffinityObservation,
    process::handle_count::HandleCountObservation,
    process::io_counters::{IoCountersObservation, ProcessIoCounters},
    process::linux::cmdline::{ArgumentRange, CommandLineObservation},
    process::linux::identity::{Observation, Relation},
    process::linux::memory::MemoryObservation,
    process::linux::run_token::RunTokenObservation,
    process::linux::status_observer::StatusObservation,
    process::macos::fds::{DescriptorObservation, ProcessDescriptor},
    process::nice::NiceObservation,
    process::observation::{
        LineageNode, LineageObservation, ProcessAffinitySource, ProcessCommandLineSource,
        ProcessDescriptorSource, ProcessHandleCountSource, ProcessIdentitySource,
        ProcessIoCountersSource, ProcessMemorySource, ProcessNiceSource, ProcessPrioritySource,
        ProcessRunTokenSource, ProcessSchedulerSource, ProcessStatusSource,
        observe_process_affinity, observe_process_descriptors, observe_process_handle_count,
        observe_process_io_counters, observe_process_lineages, observe_process_memory,
        observe_process_nice, observe_process_priority, observe_process_run_token,
        observe_process_scheduler, observe_process_status, observe_processes,
    },
    process::priority::PriorityObservation,
    process::scheduler::SchedulerObservation,
};
use serde::Serialize;
use serde_json::json;

pub const OPERATION: &str = "inspect_process_observation";
pub const LINEAGE_OPERATION: &str = "inspect_process_lineage";
pub const CMDLINE_OPERATION: &str = "inspect_process_cmdline";
pub const MEMORY_OPERATION: &str = "inspect_process_memory";
pub const STATUS_OPERATION: &str = "inspect_process_status";
pub const RUN_TOKEN_OPERATION: &str = "inspect_process_run_token";
pub const DESCRIPTORS_OPERATION: &str = "inspect_process_descriptors";
pub const HANDLE_COUNT_OPERATION: &str = "inspect_process_handle_count";
pub const IO_COUNTERS_OPERATION: &str = "inspect_process_io_counters";
pub const PRIORITY_OPERATION: &str = "inspect_process_priority";
pub const NICE_OPERATION: &str = "inspect_process_nice";
pub const SCHEDULER_OPERATION: &str = "inspect_process_scheduler";
pub const AFFINITY_OPERATION: &str = "inspect_process_affinity";

#[derive(Serialize)]
struct ResultEnvelope {
    source: &'static str,
    observations: Vec<ProcessObservationResult>,
}

#[derive(Serialize)]
struct ProcessObservationResult {
    pid: u64,
    #[serde(flatten)]
    state: ProcessObservationState,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum ProcessObservationState {
    Readable {
        identity: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        lifecycle: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        relation: Option<ProcessRelationResult>,
        #[serde(skip_serializing_if = "Option::is_none")]
        effective_uid: Option<u64>,
    },
    Absent {
        reason: &'static str,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Serialize)]
struct ProcessRelationResult {
    parent_pid: u64,
    process_group_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_identity: Option<String>,
}

#[derive(Serialize)]
struct LineageResultEnvelope {
    source: &'static str,
    lineages: Vec<ProcessLineageResult>,
}

#[derive(Serialize)]
struct ProcessLineageResult {
    root_pid: u64,
    #[serde(flatten)]
    state: ProcessLineageState,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum ProcessLineageState {
    Verified {
        root: ProcessLineageNode,
        descendants: Vec<ProcessLineageNode>,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Serialize)]
struct ProcessLineageNode {
    pid: u64,
    identity: String,
    parent_pid: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_group_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<u64>,
}

#[derive(Serialize)]
struct CommandLineResultEnvelope {
    source: &'static str,
    observations: Vec<CommandLineResult>,
}

#[derive(Serialize)]
struct CommandLineResult {
    pid: u64,
    #[serde(flatten)]
    state: CommandLineState,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum CommandLineState {
    Readable {
        raw_len: usize,
        nul_terminated: bool,
        arguments: Vec<CommandLineArgument>,
    },
    Empty,
    MalformedUtf8 {
        raw_len: usize,
    },
    Absent {
        reason: &'static str,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Serialize)]
struct CommandLineArgument {
    start: usize,
    end: usize,
    value: String,
}

#[derive(Serialize)]
struct MemoryResultEnvelope {
    source: &'static str,
    observations: Vec<MemoryResult>,
}

#[derive(Serialize)]
struct MemoryResult {
    pid: u64,
    #[serde(flatten)]
    state: MemoryState,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum MemoryState {
    Readable {
        virtual_pages: u64,
        resident_pages: u64,
        page_size_bytes: u64,
        virtual_bytes: u64,
        resident_bytes: u64,
        page_size_source: &'static str,
    },
    Absent {
        reason: &'static str,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Serialize)]
struct StatusResultEnvelope {
    source: &'static str,
    observations: Vec<StatusResult>,
}

#[derive(Serialize)]
struct StatusResult {
    pid: u64,
    #[serde(flatten)]
    state: StatusState,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum StatusState {
    Readable {
        name: Option<String>,
        uid: Option<u64>,
        gid: Option<u64>,
        parent_pid: Option<u64>,
        threads: Option<u64>,
        process_state: Option<String>,
        unknown_fields: Vec<&'static str>,
    },
    Absent {
        reason: &'static str,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Serialize)]
struct RunTokenResultEnvelope {
    source: &'static str,
    observations: Vec<RunTokenResult>,
}
#[derive(Serialize)]
struct RunTokenResult {
    pid: u64,
    #[serde(flatten)]
    state: RunTokenState,
}

#[derive(Serialize)]
struct DescriptorResultEnvelope {
    source: &'static str,
    observations: Vec<DescriptorResult>,
}

#[derive(Serialize)]
struct DescriptorResult {
    pid: u64,
    #[serde(flatten)]
    state: DescriptorState,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum DescriptorState {
    Readable {
        descriptors: Vec<DescriptorResultEntry>,
        complete: bool,
    },
    Absent {
        reason: &'static str,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Serialize)]
struct DescriptorResultEntry {
    fd: i32,
    kind: u32,
}

#[derive(Serialize)]
struct HandleCountResultEnvelope {
    source: &'static str,
    observations: Vec<HandleCountResult>,
}

#[derive(Serialize)]
struct HandleCountResult {
    pid: u64,
    #[serde(flatten)]
    state: HandleCountState,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum HandleCountState {
    Readable { count: u32 },
    Absent { reason: &'static str },
    Unavailable { reason: String },
}

#[derive(Serialize)]
struct IoCountersResultEnvelope {
    source: &'static str,
    observations: Vec<IoCountersResult>,
}

#[derive(Serialize)]
struct IoCountersResult {
    pid: u64,
    #[serde(flatten)]
    state: IoCountersState,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum IoCountersState {
    Readable {
        read_bytes: u64,
        write_bytes: u64,
        read_operations: u64,
        write_operations: u64,
    },
    Absent {
        reason: &'static str,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Serialize)]
struct PriorityResultEnvelope {
    source: &'static str,
    observations: Vec<PriorityResult>,
}

#[derive(Serialize)]
struct PriorityResult {
    pid: u64,
    #[serde(flatten)]
    state: PriorityState,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum PriorityState {
    Readable { class: u32 },
    Absent { reason: &'static str },
    Unavailable { reason: String },
}

#[derive(Serialize)]
struct AffinityResultEnvelope {
    source: &'static str,
    observations: Vec<AffinityResult>,
}
#[derive(Serialize)]
struct AffinityResult {
    pid: u64,
    #[serde(flatten)]
    state: AffinityState,
}
#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum AffinityState {
    Readable { cpu_count: u32 },
    Absent { reason: &'static str },
    Unavailable { reason: String },
}

#[derive(Serialize)]
struct NiceResultEnvelope {
    source: &'static str,
    observations: Vec<NiceResult>,
}
#[derive(Serialize)]
struct NiceResult {
    pid: u64,
    #[serde(flatten)]
    state: NiceState,
}
#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum NiceState {
    Readable { value: i32 },
    Absent { reason: &'static str },
    Unavailable { reason: String },
}

#[derive(Serialize)]
struct SchedulerResultEnvelope {
    source: &'static str,
    observations: Vec<SchedulerResult>,
}
#[derive(Serialize)]
struct SchedulerResult {
    pid: u64,
    #[serde(flatten)]
    state: SchedulerState,
}
#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum SchedulerState {
    Readable { policy: i32 },
    Absent { reason: &'static str },
    Unavailable { reason: String },
}
#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum RunTokenState {
    Readable { run_id: Option<String> },
    Absent { reason: &'static str },
    Unavailable { reason: String },
}

fn provider() -> serde_json::Value {
    json!({
        "id": "rea-process-observer",
        "name": "REA process identity observer",
        "version": null
    })
}

#[cfg(target_os = "linux")]
fn process_observation_source() -> &'static str {
    "linux.procfs.stat"
}

#[cfg(target_os = "linux")]
fn cmdline_observation_source() -> &'static str {
    "linux.procfs.cmdline"
}

#[cfg(windows)]
fn cmdline_observation_source() -> &'static str {
    "windows.query-full-process-image-name"
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn cmdline_observation_source() -> &'static str {
    "unsupported.linux-proc-cmdline-observer"
}

fn cmdline_observation_limitations() -> Vec<&'static str> {
    #[cfg(windows)]
    let mut limitations = vec![
        "caller-selected-pids-only",
        "bounded-proc-cmdline-read",
        "identity-observation-does-not-grant-process-control-authority",
    ];
    #[cfg(not(windows))]
    let limitations = vec![
        "caller-selected-pids-only",
        "bounded-proc-cmdline-read",
        "identity-observation-does-not-grant-process-control-authority",
    ];
    #[cfg(windows)]
    limitations.push("windows-command-line-observation-is-executable-image-path-only");
    limitations
}

#[cfg(target_os = "macos")]
fn process_observation_source() -> &'static str {
    "macos.proc_pidinfo"
}

#[cfg(windows)]
fn process_observation_source() -> &'static str {
    "windows.process-query"
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
fn process_observation_source() -> &'static str {
    "unsupported.native-process-observer"
}

/// Observe caller-selected PIDs and commit the result as authenticated Evidence.
pub fn observe_processes_evidence<S, I>(
    source: &S,
    pids: I,
    include_effective_uid: bool,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessIdentitySource,
    I: IntoIterator<Item = u64>,
{
    let selected_pids: Vec<u64> = pids.into_iter().collect();
    let observations =
        observe_processes(source, selected_pids.iter().copied(), include_effective_uid);
    let result = ResultEnvelope {
        source: process_observation_source(),
        observations: observations
            .into_iter()
            .map(|(pid, observation)| ProcessObservationResult {
                pid,
                state: project_observation(observation),
            })
            .collect(),
    };
    let raw = json!({
        "subject": null,
        "provider": provider(),
        "analysis_profile": null,
        "predicate_type": "rea.process-identity",
        "operation": OPERATION,
        "parameters": {
            "pids": selected_pids,
            "include_effective_uid": include_effective_uid,
        },
        "raw_result": null,
        "normalized_result": result,
        "confidence": "observed",
        "authority": "shipped-artifact",
        "environment": null,
        "limitations": [
            "caller-selected-pids-only",
            "identity-observation-does-not-grant-process-control-authority"
        ],
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": []
    });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

/// Observe caller-selected process lineages and commit them as Evidence.
pub fn observe_process_lineages_evidence<S, R, C>(
    source: &S,
    roots: R,
    candidates: C,
    include_effective_uid: bool,
    max_nodes: usize,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessIdentitySource,
    R: IntoIterator<Item = u64>,
    C: IntoIterator<Item = u64>,
{
    let selected_roots: Vec<u64> = roots.into_iter().collect();
    let selected_candidates: Vec<u64> = candidates.into_iter().collect();
    let lineages = observe_process_lineages(
        source,
        selected_roots.iter().copied(),
        selected_candidates.iter().copied(),
        include_effective_uid,
        max_nodes,
    );
    let result = LineageResultEnvelope {
        source: process_observation_source(),
        lineages: lineages
            .into_iter()
            .map(|(root_pid, observation)| ProcessLineageResult {
                root_pid,
                state: project_lineage(observation),
            })
            .collect(),
    };
    let raw = json!({
        "subject": null,
        "provider": provider(),
        "analysis_profile": null,
        "predicate_type": "rea.process-lineage",
        "operation": LINEAGE_OPERATION,
        "parameters": {
            "roots": selected_roots,
            "candidates": selected_candidates,
            "include_effective_uid": include_effective_uid,
            "max_nodes": max_nodes,
        },
        "raw_result": null,
        "normalized_result": result,
        "confidence": "observed",
        "authority": "shipped-artifact",
        "environment": null,
        "limitations": [
            "caller-selected-roots-and-candidates-only",
            "bounded-lineage-candidate-set",
            "identity-observation-does-not-grant-process-control-authority"
        ],
        "relationship_coverage": {
            "status": "partial",
            "limitations": [
                "caller-selected-roots-and-candidates-only",
                "bounded-lineage-candidate-set"
            ],
            "diagnostics": ["generation-validated-parent-relations"]
        },
        "locations": [],
        "evidence_links": []
    });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

/// Observe caller-selected process command-line facts and commit byte-range metadata as Evidence.
pub fn observe_cmdlines_evidence<S, I>(
    source: &S,
    pids: I,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessCommandLineSource,
    I: IntoIterator<Item = u64>,
{
    let selected_pids: Vec<u64> = pids.into_iter().collect();
    let result = CommandLineResultEnvelope {
        source: cmdline_observation_source(),
        observations: selected_pids
            .iter()
            .copied()
            .map(|pid| CommandLineResult {
                pid,
                state: project_cmdline(source.observe_cmdline(pid)),
            })
            .collect(),
    };
    let raw = json!({
        "subject": null,
        "provider": provider(),
        "analysis_profile": null,
        "predicate_type": "rea.process-cmdline",
        "operation": CMDLINE_OPERATION,
        "parameters": { "pids": selected_pids },
        "raw_result": null,
        "normalized_result": result,
        "confidence": "observed",
        "authority": "shipped-artifact",
        "environment": null,
        "limitations": cmdline_observation_limitations(),
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": []
    });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

/// Observe caller-selected process memory after generation validation.
pub fn observe_memory_evidence<S, I>(
    source: &S,
    pids: I,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessIdentitySource + ProcessMemorySource,
    I: IntoIterator<Item = u64>,
{
    let selected_pids: Vec<u64> = pids.into_iter().collect();
    let result = MemoryResultEnvelope {
        source: memory_observation_source(),
        observations: selected_pids
            .iter()
            .copied()
            .map(|pid| MemoryResult {
                pid,
                state: project_memory(observe_process_memory(source, pid)),
            })
            .collect(),
    };
    let raw = json!({
        "subject": null,
        "provider": provider(),
        "analysis_profile": null,
        "predicate_type": "rea.process-memory",
        "operation": MEMORY_OPERATION,
        "parameters": { "pids": selected_pids },
        "raw_result": null,
        "normalized_result": result,
        "confidence": "observed",
        "authority": "shipped-artifact",
        "environment": null,
        "limitations": [
            "caller-selected-pids-only",
            memory_observation_limitations(),
            "page-count-conversion-uses-observed-page-size",
            "identity-observation-does-not-grant-process-control-authority"
        ],
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": []
    });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

/// Observe caller-selected structured status fields after generation validation.
pub fn observe_status_evidence<S, I>(
    source: &S,
    pids: I,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessIdentitySource + ProcessStatusSource,
    I: IntoIterator<Item = u64>,
{
    let selected_pids: Vec<u64> = pids.into_iter().collect();
    let result = StatusResultEnvelope {
        source: status_observation_source(),
        observations: selected_pids
            .iter()
            .copied()
            .map(|pid| StatusResult {
                pid,
                state: project_status(observe_process_status(source, pid)),
            })
            .collect(),
    };
    let raw = json!({
        "subject": null,
        "provider": provider(),
        "analysis_profile": null,
        "predicate_type": "rea.process-status",
        "operation": STATUS_OPERATION,
        "parameters": { "pids": selected_pids },
        "raw_result": null,
        "normalized_result": result,
        "confidence": "observed",
        "authority": "shipped-artifact",
        "environment": null,
        "limitations": [
            "caller-selected-pids-only",
            "bounded-structured-proc-status-read",
            "generation-validated-status-read",
            "arbitrary-status-text-is-not-exposed",
            "identity-observation-does-not-grant-process-control-authority"
        ],
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": []
    });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

pub fn observe_run_token_evidence<S, I>(
    source: &S,
    pids: I,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessIdentitySource + ProcessRunTokenSource,
    I: IntoIterator<Item = u64>,
{
    let selected_pids: Vec<u64> = pids.into_iter().collect();
    let result = RunTokenResultEnvelope {
        source: run_token_observation_source(),
        observations: selected_pids
            .iter()
            .copied()
            .map(|pid| RunTokenResult {
                pid,
                state: project_run_token(observe_process_run_token(source, pid)),
            })
            .collect(),
    };
    let raw = json!({
        "subject": null, "provider": provider(), "analysis_profile": null,
        "predicate_type": "rea.process-run-token", "operation": RUN_TOKEN_OPERATION,
        "parameters": { "pids": selected_pids }, "raw_result": null,
        "normalized_result": result, "confidence": "observed", "authority": "shipped-artifact",
        "environment": null,
        "limitations": ["caller-selected-pids-only", "bounded-run-token-read", "generation-validated-run-token-read", "only-rea-process-run-id-is-extracted", "identity-observation-does-not-grant-process-control-authority"],
        "relationship_coverage": null, "locations": [], "evidence_links": []
    });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

/// Observe bounded descriptor metadata for caller-selected PIDs after generation validation.
pub fn observe_descriptors_evidence<S, I>(
    source: &S,
    pids: I,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessIdentitySource + ProcessDescriptorSource,
    I: IntoIterator<Item = u64>,
{
    let selected_pids: Vec<u64> = pids.into_iter().collect();
    let result = DescriptorResultEnvelope {
        source: descriptor_observation_source(),
        observations: selected_pids
            .iter()
            .copied()
            .map(|pid| DescriptorResult {
                pid,
                state: project_descriptors(observe_process_descriptors(source, pid)),
            })
            .collect(),
    };
    let raw = json!({
        "subject": null,
        "provider": provider(),
        "analysis_profile": null,
        "predicate_type": "rea.process-descriptors",
        "operation": DESCRIPTORS_OPERATION,
        "parameters": { "pids": selected_pids },
        "raw_result": null,
        "normalized_result": result,
        "confidence": "observed",
        "authority": "shipped-artifact",
        "environment": null,
        "limitations": [
            "caller-selected-pids-only",
            "bounded-process-descriptor-metadata",
            "generation-validated-descriptor-read",
            "descriptor-contents-are-not-exposed",
            "identity-observation-does-not-grant-process-control-authority"
        ],
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": []
    });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

pub fn observe_handle_count_evidence<S, I>(
    source: &S,
    pids: I,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessIdentitySource + ProcessHandleCountSource,
    I: IntoIterator<Item = u64>,
{
    let selected_pids: Vec<u64> = pids.into_iter().collect();
    let result = HandleCountResultEnvelope {
        source: handle_count_observation_source(),
        observations: selected_pids
            .iter()
            .copied()
            .map(|pid| HandleCountResult {
                pid,
                state: project_handle_count(observe_process_handle_count(source, pid)),
            })
            .collect(),
    };
    let raw = json!({
        "subject": null,
        "provider": provider(),
        "analysis_profile": null,
        "predicate_type": "rea.process-handle-count",
        "operation": HANDLE_COUNT_OPERATION,
        "parameters": { "pids": selected_pids },
        "raw_result": null,
        "normalized_result": result,
        "confidence": "observed",
        "authority": "shipped-artifact",
        "environment": null,
        "limitations": [
            "caller-selected-pids-only",
            "bounded-read-only-handle-count",
            "generation-validated-handle-count-read",
            "identity-observation-does-not-grant-process-control-authority"
        ],
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": []
    });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

pub fn observe_io_counters_evidence<S, I>(
    source: &S,
    pids: I,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessIdentitySource + ProcessIoCountersSource,
    I: IntoIterator<Item = u64>,
{
    let selected_pids: Vec<u64> = pids.into_iter().collect();
    let result = IoCountersResultEnvelope {
        source: io_counters_observation_source(),
        observations: selected_pids
            .iter()
            .copied()
            .map(|pid| IoCountersResult {
                pid,
                state: project_io_counters(observe_process_io_counters(source, pid)),
            })
            .collect(),
    };
    let raw = json!({
        "subject": null,
        "provider": provider(),
        "analysis_profile": null,
        "predicate_type": "rea.process-io-counters",
        "operation": IO_COUNTERS_OPERATION,
        "parameters": { "pids": selected_pids },
        "raw_result": null,
        "normalized_result": result,
        "confidence": "observed",
        "authority": "shipped-artifact",
        "environment": null,
        "limitations": [
            "caller-selected-pids-only",
            "bounded-read-only-process-io-accounting",
            "generation-validated-io-counter-read",
            "identity-observation-does-not-grant-process-control-authority"
        ],
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": []
    });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

pub fn observe_priority_evidence<S, I>(
    source: &S,
    pids: I,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessIdentitySource + ProcessPrioritySource,
    I: IntoIterator<Item = u64>,
{
    let selected_pids: Vec<u64> = pids.into_iter().collect();
    let result = PriorityResultEnvelope {
        source: priority_observation_source(),
        observations: selected_pids
            .iter()
            .copied()
            .map(|pid| PriorityResult {
                pid,
                state: project_priority(observe_process_priority(source, pid)),
            })
            .collect(),
    };
    let raw = json!({
        "subject": null,
        "provider": provider(),
        "analysis_profile": null,
        "predicate_type": "rea.process-priority",
        "operation": PRIORITY_OPERATION,
        "parameters": { "pids": selected_pids },
        "raw_result": null,
        "normalized_result": result,
        "confidence": "observed",
        "authority": "shipped-artifact",
        "environment": null,
        "limitations": [
            "caller-selected-pids-only",
            "bounded-read-only-priority-class-observation",
            "generation-validated-priority-read",
            "identity-observation-does-not-grant-process-control-authority"
        ],
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": []
    });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

pub fn observe_affinity_evidence<S, I>(
    source: &S,
    pids: I,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessIdentitySource + ProcessAffinitySource,
    I: IntoIterator<Item = u64>,
{
    let selected_pids: Vec<u64> = pids.into_iter().collect();
    let result = AffinityResultEnvelope {
        source: affinity_observation_source(),
        observations: selected_pids
            .iter()
            .copied()
            .map(|pid| AffinityResult {
                pid,
                state: project_affinity(observe_process_affinity(source, pid)),
            })
            .collect(),
    };
    let raw = json!({
        "subject": null, "provider": provider(), "analysis_profile": null,
        "predicate_type": "rea.process-affinity", "operation": AFFINITY_OPERATION,
        "parameters": { "pids": selected_pids }, "raw_result": null,
        "normalized_result": result, "confidence": "observed", "authority": "shipped-artifact",
        "environment": null,
        "limitations": ["caller-selected-pids-only", "bounded-read-only-affinity-observation", "generation-validated-affinity-read", "identity-observation-does-not-grant-process-control-authority"],
        "relationship_coverage": null, "locations": [], "evidence_links": []
    });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

fn project_observation(observation: Observation) -> ProcessObservationState {
    match observation {
        Observation::Readable {
            identity,
            lifecycle,
            relation,
            effective_uid,
        } => ProcessObservationState::Readable {
            identity,
            lifecycle: lifecycle.map(lifecycle_name),
            relation: relation.map(project_relation),
            effective_uid,
        },
        Observation::Absent { reason } => ProcessObservationState::Absent {
            reason: process_absence_reason(reason),
        },
        Observation::Unavailable { reason } => ProcessObservationState::Unavailable { reason },
    }
}

/// Keep process absence diagnostics aligned with the TypeScript ownership
/// boundary.  The host observers use a slightly broader namespace label, but
/// callers receive the stable PID-scoped reason shared by both adapters.
fn process_absence_reason(reason: &'static str) -> &'static str {
    match reason {
        "not-found-in-caller-process-namespace" => "not-found-in-caller-pid-namespace",
        other => other,
    }
}

fn lifecycle_name(lifecycle: Lifecycle) -> &'static str {
    match lifecycle {
        Lifecycle::Zombie => "zombie",
        Lifecycle::Dead => "dead",
        Lifecycle::Exiting => "exiting",
        Lifecycle::NonZombie => "non-zombie",
    }
}

fn project_relation(relation: Relation) -> ProcessRelationResult {
    ProcessRelationResult {
        parent_pid: relation.parent_pid,
        process_group_id: relation.process_group_id,
        session_id: relation.session_id,
        parent_identity: relation.parent_identity,
    }
}

fn project_lineage(observation: LineageObservation) -> ProcessLineageState {
    match observation {
        LineageObservation::Verified { root, descendants } => ProcessLineageState::Verified {
            root: project_lineage_node(root),
            descendants: descendants.into_iter().map(project_lineage_node).collect(),
        },
        LineageObservation::Unavailable { reason } => ProcessLineageState::Unavailable { reason },
    }
}

fn project_lineage_node(node: LineageNode) -> ProcessLineageNode {
    ProcessLineageNode {
        pid: node.pid,
        identity: node.identity,
        parent_pid: node.parent_pid,
        process_group_id: node.process_group_id,
        session_id: node.session_id,
    }
}

fn project_cmdline(observation: CommandLineObservation) -> CommandLineState {
    match observation {
        CommandLineObservation::Readable {
            raw,
            arguments,
            nul_terminated,
        } => CommandLineState::Readable {
            raw_len: raw.len(),
            nul_terminated,
            arguments: arguments
                .into_iter()
                .map(|range| project_cmdline_argument(&raw, range))
                .collect(),
        },
        CommandLineObservation::Empty => CommandLineState::Empty,
        CommandLineObservation::MalformedUtf8 { raw_len } => {
            CommandLineState::MalformedUtf8 { raw_len }
        }
        CommandLineObservation::Absent { reason } => CommandLineState::Absent { reason },
        CommandLineObservation::Unavailable { reason } => CommandLineState::Unavailable { reason },
    }
}

fn project_cmdline_argument(raw: &[u8], range: ArgumentRange) -> CommandLineArgument {
    CommandLineArgument {
        start: range.start,
        end: range.end,
        value: String::from_utf8_lossy(&raw[range.start..range.end]).into_owned(),
    }
}

#[cfg(target_os = "linux")]
fn memory_observation_source() -> &'static str {
    "linux.procfs.statm"
}

#[cfg(target_os = "macos")]
fn memory_observation_source() -> &'static str {
    "macos.proc_pidinfo.taskinfo"
}

#[cfg(windows)]
fn memory_observation_source() -> &'static str {
    "windows.process-memory-info"
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
fn memory_observation_source() -> &'static str {
    "unsupported.native-process-memory-observer"
}

#[cfg(target_os = "linux")]
fn memory_observation_limitations() -> &'static str {
    "generation-validated-statm-read"
}

#[cfg(target_os = "macos")]
fn memory_observation_limitations() -> &'static str {
    "generation-validated-proc-pidinfo-task-read"
}

#[cfg(windows)]
fn memory_observation_limitations() -> &'static str {
    "generation-validated-process-memory-info-read"
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
fn memory_observation_limitations() -> &'static str {
    "generation-validated-native-process-memory-read"
}

fn project_memory(observation: MemoryObservation) -> MemoryState {
    match observation {
        MemoryObservation::Readable {
            virtual_pages,
            resident_pages,
            page_size_bytes,
            virtual_bytes,
            resident_bytes,
            page_size_source,
        } => MemoryState::Readable {
            virtual_pages,
            resident_pages,
            page_size_bytes,
            virtual_bytes,
            resident_bytes,
            page_size_source,
        },
        MemoryObservation::Absent { reason } => MemoryState::Absent { reason },
        MemoryObservation::Unavailable { reason } => MemoryState::Unavailable { reason },
    }
}

#[cfg(target_os = "linux")]
fn status_observation_source() -> &'static str {
    "linux.procfs.status"
}

#[cfg(target_os = "macos")]
fn status_observation_source() -> &'static str {
    "macos.proc_pidinfo"
}

#[cfg(windows)]
fn status_observation_source() -> &'static str {
    "windows.GetExitCodeProcess"
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
fn status_observation_source() -> &'static str {
    "unsupported.native-process-status-observer"
}

fn project_status(observation: StatusObservation) -> StatusState {
    match observation {
        StatusObservation::Readable {
            name,
            uid,
            gid,
            parent_pid,
            threads,
            state,
            unknown_fields,
        } => StatusState::Readable {
            name,
            uid,
            gid,
            parent_pid,
            threads,
            process_state: state,
            unknown_fields,
        },
        StatusObservation::Absent { reason } => StatusState::Absent { reason },
        StatusObservation::Unavailable { reason } => StatusState::Unavailable { reason },
    }
}

#[cfg(target_os = "linux")]
fn run_token_observation_source() -> &'static str {
    "linux.procfs.environ"
}
#[cfg(target_os = "macos")]
fn run_token_observation_source() -> &'static str {
    "macos.sysctl.procargs"
}
#[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
fn run_token_observation_source() -> &'static str {
    "unsupported.linux-proc-environ-observer"
}

fn project_run_token(observation: RunTokenObservation) -> RunTokenState {
    match observation {
        RunTokenObservation::Readable { run_id } => RunTokenState::Readable { run_id },
        RunTokenObservation::Absent { reason } => RunTokenState::Absent { reason },
        RunTokenObservation::Unavailable { reason } => RunTokenState::Unavailable { reason },
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn descriptor_observation_source() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux.procfs.fd-metadata"
    }
    #[cfg(target_os = "macos")]
    {
        "macos.proc_pidinfo.process-descriptors"
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn descriptor_observation_source() -> &'static str {
    "unsupported.macos-process-descriptor-observer"
}

fn project_descriptors(observation: DescriptorObservation) -> DescriptorState {
    match observation {
        DescriptorObservation::Readable {
            descriptors,
            complete,
        } => DescriptorState::Readable {
            descriptors: descriptors.into_iter().map(project_descriptor).collect(),
            complete,
        },
        DescriptorObservation::Absent { reason } => DescriptorState::Absent { reason },
        DescriptorObservation::Unavailable { reason } => DescriptorState::Unavailable { reason },
    }
}

#[cfg(windows)]
fn handle_count_observation_source() -> &'static str {
    "windows.GetProcessHandleCount"
}

#[cfg(not(windows))]
fn handle_count_observation_source() -> &'static str {
    "unsupported.windows-process-handle-count-observer"
}

fn project_handle_count(observation: HandleCountObservation) -> HandleCountState {
    match observation {
        HandleCountObservation::Readable { count } => HandleCountState::Readable { count },
        HandleCountObservation::Absent { reason } => HandleCountState::Absent { reason },
        HandleCountObservation::Unavailable { reason } => HandleCountState::Unavailable { reason },
    }
}

#[cfg(windows)]
fn io_counters_observation_source() -> &'static str {
    "windows.GetProcessIoCounters"
}

#[cfg(not(windows))]
fn io_counters_observation_source() -> &'static str {
    "unsupported.windows-process-io-observer"
}

fn project_io_counters(observation: IoCountersObservation) -> IoCountersState {
    match observation {
        IoCountersObservation::Readable(ProcessIoCounters {
            read_bytes,
            write_bytes,
            read_operations,
            write_operations,
        }) => IoCountersState::Readable {
            read_bytes,
            write_bytes,
            read_operations,
            write_operations,
        },
        IoCountersObservation::Absent { reason } => IoCountersState::Absent { reason },
        IoCountersObservation::Unavailable { reason } => IoCountersState::Unavailable { reason },
    }
}

#[cfg(windows)]
fn priority_observation_source() -> &'static str {
    "windows.GetPriorityClass"
}

#[cfg(not(windows))]
fn priority_observation_source() -> &'static str {
    "unsupported.windows-process-priority-observer"
}

fn project_priority(observation: PriorityObservation) -> PriorityState {
    match observation {
        PriorityObservation::Readable { class } => PriorityState::Readable { class },
        PriorityObservation::Absent { reason } => PriorityState::Absent { reason },
        PriorityObservation::Unavailable { reason } => PriorityState::Unavailable { reason },
    }
}

#[cfg(target_os = "linux")]
fn affinity_observation_source() -> &'static str {
    "linux.sched_getaffinity"
}
#[cfg(not(target_os = "linux"))]
fn affinity_observation_source() -> &'static str {
    "unsupported.linux-process-affinity-observer"
}

pub fn observe_nice_evidence<S, I>(
    source: &S,
    pids: I,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessIdentitySource + ProcessNiceSource,
    I: IntoIterator<Item = u64>,
{
    let selected_pids: Vec<u64> = pids.into_iter().collect();
    let result = NiceResultEnvelope {
        source: nice_observation_source(),
        observations: selected_pids
            .iter()
            .copied()
            .map(|pid| NiceResult {
                pid,
                state: project_nice(observe_process_nice(source, pid)),
            })
            .collect(),
    };
    let raw = json!({
        "subject": null, "provider": provider(), "analysis_profile": null,
        "predicate_type": "rea.process-nice", "operation": NICE_OPERATION,
        "parameters": { "pids": selected_pids }, "raw_result": null,
        "normalized_result": result, "confidence": "observed", "authority": "shipped-artifact",
        "environment": null,
        "limitations": ["caller-selected-pids-only", "generation-validated-nice-read", "identity-observation-does-not-grant-process-control-authority"],
        "relationship_coverage": null, "locations": [], "evidence_links": []
    });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

#[cfg(target_os = "linux")]
fn nice_observation_source() -> &'static str {
    "linux.getpriority"
}

pub fn observe_scheduler_evidence<S, I>(
    source: &S,
    pids: I,
) -> Result<EvidenceRecord, EvidenceRecordError>
where
    S: ProcessIdentitySource + ProcessSchedulerSource,
    I: IntoIterator<Item = u64>,
{
    let selected_pids: Vec<u64> = pids.into_iter().collect();
    let result = SchedulerResultEnvelope {
        source: scheduler_observation_source(),
        observations: selected_pids
            .iter()
            .copied()
            .map(|pid| SchedulerResult {
                pid,
                state: project_scheduler(observe_process_scheduler(source, pid)),
            })
            .collect(),
    };
    let raw = json!({ "subject": null, "provider": provider(), "analysis_profile": null,
        "predicate_type": "rea.process-scheduler", "operation": SCHEDULER_OPERATION,
        "parameters": { "pids": selected_pids }, "raw_result": null,
        "normalized_result": result, "confidence": "observed", "authority": "shipped-artifact",
        "environment": null, "limitations": ["caller-selected-pids-only", "generation-validated-scheduler-read", "identity-observation-does-not-grant-process-control-authority"],
        "relationship_coverage": null, "locations": [], "evidence_links": [] });
    let raw = serde_json::value::to_raw_value(&raw).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

#[cfg(target_os = "linux")]
fn scheduler_observation_source() -> &'static str {
    "linux.sched_getscheduler"
}
#[cfg(not(target_os = "linux"))]
fn scheduler_observation_source() -> &'static str {
    "unsupported.linux-process-scheduler-observer"
}

fn project_scheduler(observation: SchedulerObservation) -> SchedulerState {
    match observation {
        SchedulerObservation::Readable { policy } => SchedulerState::Readable { policy },
        SchedulerObservation::Absent { reason } => SchedulerState::Absent { reason },
        SchedulerObservation::Unavailable { reason } => SchedulerState::Unavailable { reason },
    }
}
#[cfg(not(target_os = "linux"))]
fn nice_observation_source() -> &'static str {
    "unsupported.linux-process-nice-observer"
}

fn project_nice(observation: NiceObservation) -> NiceState {
    match observation {
        NiceObservation::Readable { value } => NiceState::Readable { value },
        NiceObservation::Absent { reason } => NiceState::Absent { reason },
        NiceObservation::Unavailable { reason } => NiceState::Unavailable { reason },
    }
}

fn project_affinity(observation: AffinityObservation) -> AffinityState {
    match observation {
        AffinityObservation::Readable { cpu_count } => AffinityState::Readable { cpu_count },
        AffinityObservation::Absent { reason } => AffinityState::Absent { reason },
        AffinityObservation::Unavailable { reason } => AffinityState::Unavailable { reason },
    }
}

fn project_descriptor(descriptor: ProcessDescriptor) -> DescriptorResultEntry {
    DescriptorResultEntry {
        fd: descriptor.fd,
        kind: descriptor.kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct FakeSource(BTreeMap<u64, Observation>);

    impl ProcessIdentitySource for FakeSource {
        fn observe(&self, pid: u64, _include_effective_uid: bool) -> Observation {
            self.0
                .get(&pid)
                .cloned()
                .unwrap_or(Observation::Unavailable {
                    reason: "missing fixture".into(),
                })
        }
    }

    impl ProcessCommandLineSource for FakeSource {
        fn observe_cmdline(&self, pid: u64) -> CommandLineObservation {
            if pid == 70 {
                CommandLineObservation::Readable {
                    raw: b"worker\0--mode\0".to_vec(),
                    arguments: vec![
                        ArgumentRange { start: 0, end: 6 },
                        ArgumentRange { start: 7, end: 13 },
                    ],
                    nul_terminated: true,
                }
            } else {
                CommandLineObservation::MalformedUtf8 { raw_len: 3 }
            }
        }
    }

    struct StableMemorySource;

    impl ProcessIdentitySource for StableMemorySource {
        fn observe(&self, _pid: u64, _include_effective_uid: bool) -> Observation {
            Observation::Readable {
                identity: "stable-generation".into(),
                lifecycle: None,
                relation: None,
                effective_uid: None,
            }
        }
    }

    impl ProcessMemorySource for StableMemorySource {
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

    impl ProcessStatusSource for StableMemorySource {
        fn observe_status(&self, _pid: u64) -> StatusObservation {
            StatusObservation::Readable {
                name: Some("fixture".into()),
                uid: Some(1001),
                gid: Some(21),
                parent_pid: Some(7),
                threads: Some(2),
                state: Some("R".into()),
                unknown_fields: vec!["session"],
            }
        }
    }

    impl ProcessDescriptorSource for StableMemorySource {
        fn observe_descriptors(&self, _pid: u64) -> DescriptorObservation {
            DescriptorObservation::Readable {
                descriptors: vec![ProcessDescriptor { fd: 3, kind: 1 }],
                complete: true,
            }
        }
    }

    impl ProcessHandleCountSource for StableMemorySource {
        fn observe_handle_count(&self, _pid: u64) -> HandleCountObservation {
            HandleCountObservation::Readable { count: 12 }
        }
    }

    impl ProcessIoCountersSource for StableMemorySource {
        fn observe_io_counters(&self, _pid: u64) -> IoCountersObservation {
            IoCountersObservation::Readable(ProcessIoCounters {
                read_bytes: 100,
                write_bytes: 200,
                read_operations: 3,
                write_operations: 4,
            })
        }
    }

    impl ProcessPrioritySource for StableMemorySource {
        fn observe_priority(&self, _pid: u64) -> PriorityObservation {
            PriorityObservation::Readable { class: 32 }
        }
    }

    impl ProcessAffinitySource for StableMemorySource {
        fn observe_affinity(&self, _pid: u64) -> AffinityObservation {
            AffinityObservation::Readable { cpu_count: 4 }
        }
    }

    impl ProcessNiceSource for StableMemorySource {
        fn observe_nice(&self, _pid: u64) -> NiceObservation {
            NiceObservation::Readable { value: 0 }
        }
    }

    impl ProcessSchedulerSource for StableMemorySource {
        fn observe_scheduler(&self, _pid: u64) -> SchedulerObservation {
            SchedulerObservation::Readable { policy: 0 }
        }
    }

    #[test]
    fn evidence_preserves_readable_absent_and_unavailable_results() {
        let source = FakeSource(BTreeMap::from([
            (
                41,
                Observation::Readable {
                    identity: "generation-41".into(),
                    lifecycle: Some(Lifecycle::NonZombie),
                    relation: Some(Relation {
                        parent_pid: 7,
                        process_group_id: Some(8),
                        session_id: None,
                        parent_identity: Some("parent-generation".into()),
                    }),
                    effective_uid: None,
                },
            ),
            (
                42,
                Observation::Absent {
                    reason: "not-found-in-caller-process-namespace",
                },
            ),
            (
                43,
                Observation::Unavailable {
                    reason: "malformed native status".into(),
                },
            ),
        ]));

        let evidence = observe_processes_evidence(&source, [43, 41, 42], false)
            .expect("process observations should form valid Evidence");
        let result: serde_json::Value = serde_json::from_str(evidence.normalized_result().get())
            .expect("normalized result should be JSON");
        let observations = result["observations"]
            .as_array()
            .expect("observations array");
        assert!(result["source"].as_str().is_some());
        assert_eq!(observations.len(), 3);
        assert_eq!(observations[0]["pid"], 41);
        assert_eq!(observations[0]["state"], "readable");
        assert_eq!(observations[0]["identity"], "generation-41");
        assert_eq!(
            observations[0]["relation"]["session_id"],
            serde_json::Value::Null
        );
        assert_eq!(
            observations[0]["relation"]["parent_identity"],
            "parent-generation"
        );
        assert_eq!(observations[1]["state"], "absent");
        assert_eq!(observations[2]["state"], "unavailable");
        assert_eq!(observations[2]["reason"], "malformed native status");
    }

    #[test]
    fn lineage_evidence_preserves_selected_inputs_and_relations() {
        let source = FakeSource(BTreeMap::from([
            (
                51,
                Observation::Readable {
                    identity: "root-generation".into(),
                    lifecycle: None,
                    relation: Some(Relation {
                        parent_pid: 1,
                        process_group_id: Some(51),
                        session_id: Some(4),
                        parent_identity: None,
                    }),
                    effective_uid: None,
                },
            ),
            (
                52,
                Observation::Readable {
                    identity: "child-generation".into(),
                    lifecycle: None,
                    relation: Some(Relation {
                        parent_pid: 51,
                        process_group_id: Some(51),
                        session_id: Some(4),
                        parent_identity: None,
                    }),
                    effective_uid: None,
                },
            ),
        ]));

        let evidence = observe_process_lineages_evidence(&source, [51], [52], false, 8)
            .expect("lineage should form valid Evidence");
        let normalized: serde_json::Value =
            serde_json::from_str(evidence.normalized_result().get())
                .expect("normalized lineage result should be JSON");
        assert_eq!(normalized["lineages"][0]["root_pid"], 51);
        assert!(normalized["source"].as_str().is_some());
        assert_eq!(normalized["lineages"][0]["state"], "verified");
        assert_eq!(
            normalized["lineages"][0]["root"]["identity"],
            "root-generation"
        );
        assert_eq!(normalized["lineages"][0]["descendants"][0]["pid"], 52);
        assert_eq!(
            normalized["lineages"][0]["descendants"][0]["parent_pid"],
            51
        );
        let raw: serde_json::Value =
            serde_json::from_str(evidence.raw().get()).expect("raw Evidence should be JSON");
        assert_eq!(raw["parameters"]["roots"], serde_json::json!([51]));
        assert_eq!(raw["parameters"]["candidates"], serde_json::json!([52]));
        assert_eq!(raw["relationship_coverage"]["status"], "partial");
        assert_eq!(
            raw["relationship_coverage"]["diagnostics"],
            serde_json::json!(["generation-validated-parent-relations"])
        );
    }

    #[test]
    fn cmdline_evidence_preserves_nul_boundaries_and_unavailable_states() {
        let source = FakeSource(BTreeMap::new());
        let evidence = observe_cmdlines_evidence(&source, [70, 71])
            .expect("cmdline observations should form valid Evidence");
        let normalized: serde_json::Value =
            serde_json::from_str(evidence.normalized_result().get())
                .expect("normalized cmdline result should be JSON");
        assert!(normalized["source"].as_str().is_some());
        assert_eq!(normalized["observations"][0]["state"], "readable");
        assert_eq!(
            normalized["observations"][0]["arguments"][0]["value"],
            "worker"
        );
        assert_eq!(normalized["observations"][0]["arguments"][1]["start"], 7);
        assert_eq!(normalized["observations"][0]["nul_terminated"], true);
        assert_eq!(normalized["observations"][1]["state"], "malformed_utf8");
    }

    #[test]
    fn memory_evidence_preserves_page_counts_and_generation_validation() {
        let evidence = observe_memory_evidence(&StableMemorySource, [80])
            .expect("memory observations should form valid Evidence");
        let normalized: serde_json::Value =
            serde_json::from_str(evidence.normalized_result().get())
                .expect("normalized memory result should be JSON");
        assert_eq!(normalized["observations"][0]["state"], "readable");
        assert_eq!(normalized["observations"][0]["virtual_pages"], 10);
        assert_eq!(normalized["observations"][0]["resident_pages"], 4);
        assert_eq!(normalized["observations"][0]["virtual_bytes"], 40_960);
        assert_eq!(
            normalized["observations"][0]["page_size_source"],
            "fixture-page-size"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_memory_evidence_reads_the_current_process_with_native_provenance() {
        let observer = rea_host::process::linux::identity::ProcessIdentityObserver;
        let pid = u64::from(std::process::id());
        let evidence = observe_memory_evidence(&observer, [pid])
            .expect("current macOS process memory should form valid Evidence");
        let normalized: serde_json::Value =
            serde_json::from_str(evidence.normalized_result().get())
                .expect("normalized memory result should be JSON");
        assert_eq!(normalized["source"], "macos.proc_pidinfo.taskinfo");
        assert_eq!(normalized["observations"][0]["state"], "readable");
        assert!(
            normalized["observations"][0]["resident_bytes"]
                .as_u64()
                .is_some_and(|bytes| bytes > 0)
        );

        let raw: serde_json::Value =
            serde_json::from_str(evidence.raw().get()).expect("raw Evidence should be JSON");
        assert_eq!(
            raw["limitations"][1],
            "generation-validated-proc-pidinfo-task-read"
        );
    }

    #[test]
    fn status_evidence_preserves_structured_fields_and_unknowns() {
        let evidence = observe_status_evidence(&StableMemorySource, [80])
            .expect("status observations should form valid Evidence");
        let normalized: serde_json::Value =
            serde_json::from_str(evidence.normalized_result().get())
                .expect("normalized status result should be JSON");
        assert!(normalized["source"].as_str().is_some());
        assert_eq!(normalized["observations"][0]["state"], "readable");
        assert_eq!(normalized["observations"][0]["name"], "fixture");
        assert_eq!(normalized["observations"][0]["uid"], 1001);
        assert_eq!(normalized["observations"][0]["parent_pid"], 7);
        assert_eq!(
            normalized["observations"][0]["unknown_fields"],
            serde_json::json!(["session"])
        );
    }

    #[test]
    fn descriptor_evidence_preserves_bounded_metadata_and_generation_state() {
        let evidence = observe_descriptors_evidence(&StableMemorySource, [80])
            .expect("descriptor observations should form valid Evidence");
        let normalized: serde_json::Value =
            serde_json::from_str(evidence.normalized_result().get())
                .expect("normalized descriptor result should be JSON");
        assert_eq!(normalized["observations"][0]["state"], "readable");
        assert_eq!(normalized["observations"][0]["complete"], true);
        assert_eq!(normalized["observations"][0]["descriptors"][0]["fd"], 3);
        assert_eq!(normalized["observations"][0]["descriptors"][0]["kind"], 1);

        let raw: serde_json::Value =
            serde_json::from_str(evidence.raw().get()).expect("raw Evidence should be JSON");
        assert_eq!(raw["parameters"]["pids"], serde_json::json!([80]));
        assert!(
            raw["limitations"]
                .as_array()
                .expect("limitations should be an array")
                .iter()
                .any(|value| value == "descriptor-contents-are-not-exposed")
        );
    }

    #[test]
    fn handle_count_evidence_preserves_generation_validated_count() {
        let evidence = observe_handle_count_evidence(&StableMemorySource, [80])
            .expect("handle-count observations should form valid Evidence");
        let normalized: serde_json::Value =
            serde_json::from_str(evidence.normalized_result().get())
                .expect("normalized handle-count result should be JSON");
        assert_eq!(normalized["observations"][0]["state"], "readable");
        assert_eq!(normalized["observations"][0]["count"], 12);
    }

    #[test]
    fn io_counters_evidence_preserves_generation_validated_accounting() {
        let evidence = observe_io_counters_evidence(&StableMemorySource, [80])
            .expect("I/O counter observations should form valid Evidence");
        let normalized: serde_json::Value =
            serde_json::from_str(evidence.normalized_result().get())
                .expect("normalized I/O result should be JSON");
        assert_eq!(normalized["observations"][0]["state"], "readable");
        assert_eq!(normalized["observations"][0]["read_bytes"], 100);
        assert_eq!(normalized["observations"][0]["write_operations"], 4);
    }

    #[test]
    fn priority_evidence_preserves_generation_validated_class() {
        let evidence = observe_priority_evidence(&StableMemorySource, [80])
            .expect("priority observations should form valid Evidence");
        let normalized: serde_json::Value =
            serde_json::from_str(evidence.normalized_result().get())
                .expect("normalized priority result should be JSON");
        assert_eq!(normalized["observations"][0]["state"], "readable");
        assert_eq!(normalized["observations"][0]["class"], 32);
    }

    #[test]
    fn affinity_evidence_preserves_generation_validated_cpu_count() {
        let evidence = observe_affinity_evidence(&StableMemorySource, [80])
            .expect("affinity observations should form valid Evidence");
        let normalized: serde_json::Value =
            serde_json::from_str(evidence.normalized_result().get())
                .expect("normalized affinity result should be JSON");
        assert_eq!(normalized["observations"][0]["state"], "readable");
        assert_eq!(normalized["observations"][0]["cpu_count"], 4);
    }

    #[test]
    fn nice_evidence_preserves_generation_validated_value() {
        let evidence = observe_nice_evidence(&StableMemorySource, [80])
            .expect("nice observations should form valid Evidence");
        let normalized: serde_json::Value =
            serde_json::from_str(evidence.normalized_result().get())
                .expect("normalized nice result should be JSON");
        assert_eq!(normalized["observations"][0]["state"], "readable");
        assert_eq!(normalized["observations"][0]["value"], 0);
    }

    #[test]
    fn scheduler_evidence_preserves_generation_validated_policy() {
        let evidence = observe_scheduler_evidence(&StableMemorySource, [80])
            .expect("scheduler observations should form valid Evidence");
        let normalized: serde_json::Value =
            serde_json::from_str(evidence.normalized_result().get())
                .expect("normalized scheduler result should be JSON");
        assert_eq!(normalized["observations"][0]["state"], "readable");
        assert_eq!(normalized["observations"][0]["policy"], 0);
    }
}
