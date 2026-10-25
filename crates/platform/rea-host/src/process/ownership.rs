//! Run-token process ownership for controlled captures (Unix).
//!
//! Compatibility owners: `ProcessOwnership.ts` (`cleanupOwnedProcessGroup`,
//! `verifyNoTokenOwnedProcesses`, `scanTokenOwnedProcesses`),
//! `observeOwnedProcessGroups` (`ProcessOwnershipObservation.ts`) and
//! `ProcessOwnershipProcessTree.ts`.
//!
//! A capture child carries `REA_PROCESS_RUN_ID=<run>`. Authority to signal a
//! process comes only from reading that token from the same process
//! generation (identity before and after the token read); the PID, group or
//! a baseline row alone never grants it. Unreadable related processes keep
//! cleanup fail-closed. Unrelated processes whose environment the kernel
//! withholds (Apple platform binaries, `CS_RESTRICT`, other accounts) are
//! reported as unverified instead of failing an otherwise clean capture.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, Instant};

#[cfg(not(target_os = "macos"))]
use super::linux::identity::{Observation, ProcessIdentityObserver};
use super::linux::run_token::{ProcessRunTokenObserver, RunTokenObservation};

/// `PROCESS_CLEANUP_VERIFICATION_GRACE_MS` / `_INTERVAL_MS`.
pub const CLEANUP_VERIFICATION_GRACE: Duration = Duration::from_millis(1_000);
pub const CLEANUP_VERIFICATION_INTERVAL: Duration = Duration::from_millis(25);
const TOKEN_READ_RETRY_ATTEMPTS: usize = 3;
const TOKEN_READ_RETRY_DELAY: Duration = Duration::from_millis(40);
const PLATFORM_BINARY_ENVIRONMENT_WITHHELD: &str = "platform_binary_environment_withheld";
const RESTRICTED_PROCESS_ENVIRONMENT_WITHHELD: &str = "restricted_process_environment_withheld";

/// One live (non-zombie) process with native identity and relation facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_group_id: u32,
    pub uid: Option<u64>,
    pub identity: String,
}

/// Prelaunch identities; `None` means the identity could not be established.
pub type OwnershipBaseline = Vec<(u32, Option<String>)>;

/// The capture's launch relation used to decide which candidates are related.
#[derive(Clone, Debug, Default)]
pub struct OwnershipRelation {
    pub leader_pid: u32,
    pub process_group_id: u32,
    pub sampled_process_group_ids: Vec<u32>,
}

/// A live process whose ownership could not be established.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipFailure {
    pub pid: u32,
    /// environment-unreadable, process-identity-unavailable or run-token-mismatch.
    pub reason: &'static str,
    pub diagnostic: Option<String>,
}

/// An unrelated live process whose environment the kernel withheld.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedProcess {
    pub pid: u32,
    pub diagnostic: String,
}

/// `TokenOwnedProcessScan`.
#[derive(Clone, Debug, Default)]
pub struct TokenScan {
    pub owned: Vec<ProcessEntry>,
    pub failures: Vec<OwnershipFailure>,
    pub unverified: Vec<UnverifiedProcess>,
}

/// `ProcessCleanupResult`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupResult {
    pub cleaned: bool,
    pub reason: Option<String>,
    pub signaled: bool,
    pub unverified: Vec<UnverifiedProcess>,
}

/// `ProcessGroupObservation`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupObservation {
    Empty,
    Alive,
    Unverifiable(String),
}

/// Observe whether requested process groups still have live members.
///
/// This deliberately reports membership only. It does not authenticate a
/// member to a run token, and `Unverifiable` must remain a cleanup failure.
pub fn observe_process_group_members(group_ids: &[u32]) -> BTreeMap<u32, GroupObservation> {
    let groups: BTreeSet<u32> = group_ids.iter().copied().collect();
    let mut observations: BTreeMap<u32, GroupObservation> = groups
        .iter()
        .map(|group| (*group, GroupObservation::Empty))
        .collect();

    match strict_rows() {
        Ok(processes) => {
            for process in processes.into_iter().filter(|row| !row.zombie) {
                if let Some(observation) = observations.get_mut(&process.entry.process_group_id) {
                    *observation = GroupObservation::Alive;
                }
            }
        }
        Err(reason) => {
            for observation in observations.values_mut() {
                *observation = GroupObservation::Unverifiable(reason.clone());
            }
        }
    }
    observations
}

/// One process-table row; zombies are kept so callers can choose.
struct Row {
    entry: ProcessEntry,
    zombie: bool,
}

#[cfg(target_os = "macos")]
fn rows() -> Result<Vec<Row>, String> {
    Ok(super::macos::process_table::snapshot()?
        .into_values()
        .map(|process| Row {
            zombie: process.zombie,
            entry: ProcessEntry {
                pid: process.pid,
                parent_pid: process.parent_pid,
                process_group_id: process.process_group_id,
                uid: Some(u64::from(process.uid)),
                identity: process.identity,
            },
        })
        .collect())
}

#[cfg(target_os = "macos")]
fn lookup(pid: u32) -> Result<Option<Row>, String> {
    let Some(process) = super::macos::process_table::process(pid)? else {
        return Ok(None);
    };
    Ok(Some(Row {
        zombie: process.zombie,
        entry: ProcessEntry {
            pid: process.pid,
            parent_pid: process.parent_pid,
            process_group_id: process.process_group_id,
            uid: Some(u64::from(process.uid)),
            identity: process.identity,
        },
    }))
}

#[cfg(not(target_os = "macos"))]
fn row_from(pid: u32, observation: &Observation) -> Option<Row> {
    // Display inventories intentionally include only readable entries. Cleanup
    // uses strict_rows so this omission is never an absence proof.
    required_row(pid, observation).ok().flatten()
}

#[cfg(not(target_os = "macos"))]
fn rows() -> Result<Vec<Row>, String> {
    Ok(all_pids()?
        .into_iter()
        .filter_map(|pid| row_from(pid, &ProcessIdentityObserver.observe(u64::from(pid), true)))
        .collect())
}

#[cfg(not(target_os = "macos"))]
fn lookup(pid: u32) -> Result<Option<Row>, String> {
    required_row(pid, &ProcessIdentityObserver.observe(u64::from(pid), true))
}

/// The live (non-zombie) generation of one PID.
fn live_entry(pid: u32) -> Result<Option<ProcessEntry>, String> {
    Ok(lookup(pid)?.filter(|row| !row.zombie).map(|row| row.entry))
}

#[cfg(target_os = "linux")]
fn all_pids() -> Result<Vec<u32>, String> {
    let entries = std::fs::read_dir("/proc")
        .map_err(|error| format!("process table could not be listed: {error}"))?;
    let mut pids = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("process table entry could not be read: {error}"))?;
        if let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        {
            pids.push(pid);
        }
    }
    Ok(pids)
}

/// Observe every listed process through the existing bounded identity parser.
/// Unlike the display inventory, this cannot omit an unreadable record when
/// its absence would be used to release cleanup ownership.
#[cfg(target_os = "linux")]
fn strict_rows() -> Result<Vec<Row>, String> {
    let mut processes = Vec::new();
    for pid in all_pids()? {
        let observation = ProcessIdentityObserver.observe(u64::from(pid), false);
        if let Some(row) = required_row(pid, &observation)? {
            processes.push(row);
        }
    }
    Ok(processes)
}

#[cfg(target_os = "macos")]
fn strict_rows() -> Result<Vec<Row>, String> {
    rows()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn strict_rows() -> Result<Vec<Row>, String> {
    Err("process group liveness inspection is unsupported on this host".to_owned())
}

#[cfg(any(not(target_os = "macos"), test))]
fn required_row(
    pid: u32,
    observation: &super::linux::identity::Observation,
) -> Result<Option<Row>, String> {
    use super::linux::identity::Observation;
    use rea_core::linux_proc::stat::Lifecycle;

    match observation {
        Observation::Absent { .. } => Ok(None),
        Observation::Unavailable { reason } => {
            Err(format!("process {pid} could not be observed: {reason}"))
        }
        Observation::Readable {
            identity,
            lifecycle,
            relation,
            effective_uid,
        } => {
            let relation = relation
                .as_ref()
                .ok_or_else(|| format!("process {pid} has no observed process relations"))?;
            let parent_pid = u32::try_from(relation.parent_pid)
                .map_err(|_| format!("process {pid} parent PID is out of range"))?;
            let process_group_id = relation
                .process_group_id
                .and_then(|group| u32::try_from(group).ok())
                .ok_or_else(|| format!("process {pid} has no valid process group"))?;
            Ok(Some(Row {
                entry: ProcessEntry {
                    pid,
                    parent_pid,
                    process_group_id,
                    uid: *effective_uid,
                    identity: identity.clone(),
                },
                zombie: matches!(lifecycle, Some(Lifecycle::Zombie | Lifecycle::Dead)),
            }))
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_owned_groups(
    relation: &OwnershipRelation,
    observed: &[ProcessEntry],
) -> Result<(), String> {
    let groups: BTreeSet<_> = [relation.process_group_id]
        .into_iter()
        .chain(relation.sampled_process_group_ids.iter().copied())
        .collect();
    for row in strict_rows()? {
        if row.zombie || !groups.contains(&row.entry.process_group_id) {
            continue;
        }
        if !observed.iter().any(|process| {
            process.pid == row.entry.pid
                && process.identity == row.entry.identity
                && process.process_group_id == row.entry.process_group_id
        }) {
            return Err(format!(
                "live group member {} was missing or changed during cleanup observation",
                row.entry.pid
            ));
        }
    }
    Ok(())
}

/// Membership alone grants no signal authority. An unknown observation is
/// retained so callers cannot mistake it for a zombie-only process group.
pub(crate) fn group_has_live_members(group_id: u32) -> Result<bool, String> {
    match observe_process_group_members(&[group_id]).remove(&group_id) {
        Some(GroupObservation::Empty) => Ok(false),
        Some(GroupObservation::Alive) => Ok(true),
        Some(GroupObservation::Unverifiable(reason)) => Err(reason),
        None => Err("process group was not observed".to_owned()),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn all_pids() -> Result<Vec<u32>, String> {
    Err("process table inspection is unsupported on this host".to_owned())
}

/// `liveProcesses(listProcesses())` with native facts; unreadable rows are omitted.
pub fn list_live_processes() -> Result<Vec<ProcessEntry>, String> {
    let mut entries: Vec<_> = rows()?
        .into_iter()
        .filter(|row| !row.zombie)
        .map(|row| row.entry)
        .collect();
    entries.sort_by_key(|entry| entry.pid);
    Ok(entries)
}

/// One process-table row as `ps -axo pid=,ppid=,pgid=,command=` reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandRow {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_group_id: u32,
    pub command: String,
}

#[cfg(target_os = "macos")]
fn command_of(pid: u32) -> String {
    match super::macos::run_token::read_arguments(pid as libc::pid_t) {
        Ok(arguments) if !arguments.is_empty() => arguments.join(" "),
        // `ps` prints the kernel short name (`p_comm`) in parentheses; it
        // survives exit (zombies, exiting processes), unlike `proc_name`.
        _ => match super::macos::process_table::process(pid) {
            Ok(Some(process)) => format!("({})", process.command_name),
            _ => "()".to_owned(),
        },
    }
}

#[cfg(target_os = "linux")]
fn command_of(pid: u32) -> String {
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(bytes) if !bytes.is_empty() => {
            let text =
                String::from_utf8_lossy(bytes.strip_suffix(&[0]).unwrap_or(&bytes)).into_owned();
            text.replace('\0', " ")
        }
        _ => {
            let name = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            format!("[{}]", name.trim_end())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn command_of(_pid: u32) -> String {
    String::new()
}

/// Every readable process with its command line (zombies included, like `ps`).
pub fn list_process_commands() -> Result<Vec<CommandRow>, String> {
    let mut rows: Vec<CommandRow> = rows()?
        .into_iter()
        .map(|row| CommandRow {
            pid: row.entry.pid,
            parent_pid: row.entry.parent_pid,
            process_group_id: row.entry.process_group_id,
            command: command_of(row.entry.pid),
        })
        .collect();
    rows.sort_by_key(|row| row.pid);
    Ok(rows)
}

/// Capture the prelaunch identities the sweep uses to select new candidates.
pub fn capture_baseline() -> Result<OwnershipBaseline, String> {
    Ok(rows()?
        .into_iter()
        .map(|row| (row.entry.pid, Some(row.entry.identity)))
        .collect())
}

/// Breadth-first live descendants of `roots` (`descendantsOf`).
pub fn descendants_of(roots: &[u32], processes: &[ProcessEntry]) -> Vec<ProcessEntry> {
    let mut children: HashMap<u32, Vec<&ProcessEntry>> = HashMap::new();
    for process in processes {
        children
            .entry(process.parent_pid)
            .or_default()
            .push(process);
    }
    let mut visited: BTreeSet<u32> = roots.iter().copied().collect();
    let mut pending: Vec<&ProcessEntry> = roots
        .iter()
        .flat_map(|pid| children.get(pid).cloned().unwrap_or_default())
        .collect();
    let mut result = Vec::new();
    let mut index = 0;
    while index < pending.len() {
        let process = pending[index];
        index += 1;
        if !visited.insert(process.pid) {
            continue;
        }
        result.push(process.clone());
        pending.extend(children.get(&process.pid).cloned().unwrap_or_default());
    }
    result
}

/// One same-generation token read: identity before and after must match.
enum TokenFact {
    Exited,
    Changed,
    Unavailable(String),
    Token(RunTokenObservation),
}

fn read_token_fact(process: &ProcessEntry) -> TokenFact {
    let token = ProcessRunTokenObserver.observe(u64::from(process.pid));
    match live_entry(process.pid) {
        Ok(None) => TokenFact::Exited,
        Ok(Some(after))
            if after.identity != process.identity
                || after.process_group_id != process.process_group_id =>
        {
            TokenFact::Changed
        }
        Ok(Some(_)) => TokenFact::Token(token),
        Err(reason) => TokenFact::Unavailable(reason),
    }
}

fn withheld(diagnostic: &str, uid: Option<u64>) -> bool {
    // SAFETY: getuid has no preconditions.
    let own = u64::from(unsafe { libc::getuid() });
    uid.is_some_and(|uid| uid != own)
        || diagnostic == PLATFORM_BINARY_ENVIRONMENT_WITHHELD
        || diagnostic == RESTRICTED_PROCESS_ENVIRONMENT_WITHHELD
}

/// `scanTokenOwnedProcesses` over candidates new since the baseline.
pub fn scan_token_owned(
    processes: &[ProcessEntry],
    run_id: &str,
    baseline: &OwnershipBaseline,
    relation: Option<&OwnershipRelation>,
) -> TokenScan {
    let baseline: HashMap<u32, &Option<String>> = baseline
        .iter()
        .map(|(pid, identity)| (*pid, identity))
        .collect();
    let candidates: Vec<&ProcessEntry> = processes
        .iter()
        .filter(|process| match baseline.get(&process.pid) {
            None | Some(None) => true,
            Some(Some(identity)) => *identity != process.identity,
        })
        .collect();
    let mut scan = TokenScan::default();
    let mut unreadable: Vec<(&ProcessEntry, String)> = Vec::new();
    for process in candidates {
        match read_token_fact(process) {
            TokenFact::Exited => {}
            TokenFact::Changed => unreadable.push((
                process,
                "process_identity_changed_during_token_read".to_owned(),
            )),
            TokenFact::Token(RunTokenObservation::Readable {
                run_id: Some(found),
            }) if found == run_id => scan.owned.push(process.clone()),
            TokenFact::Token(
                RunTokenObservation::Readable { .. } | RunTokenObservation::Absent { .. },
            ) => {}
            TokenFact::Unavailable(reason)
            | TokenFact::Token(RunTokenObservation::Unavailable { reason }) => {
                unreadable.push((process, reason))
            }
        }
    }
    // Bounded retries settle transient token-read races.
    for _ in 0..TOKEN_READ_RETRY_ATTEMPTS {
        if unreadable.is_empty() {
            break;
        }
        std::thread::sleep(TOKEN_READ_RETRY_DELAY);
        let mut remaining = Vec::new();
        for (process, first) in unreadable {
            match read_token_fact(process) {
                TokenFact::Exited => {}
                TokenFact::Token(RunTokenObservation::Readable {
                    run_id: Some(found),
                }) if found == run_id => scan.owned.push(process.clone()),
                TokenFact::Token(
                    RunTokenObservation::Readable { .. } | RunTokenObservation::Absent { .. },
                ) => {}
                _ => remaining.push((process, first)),
            }
        }
        unreadable = remaining;
    }
    let mut related_pids = BTreeSet::new();
    let mut related_groups = BTreeSet::new();
    if let Some(relation) = relation {
        related_pids.insert(relation.leader_pid);
        related_pids.extend(
            descendants_of(&[relation.leader_pid], processes)
                .into_iter()
                .map(|process| process.pid),
        );
        related_groups.insert(relation.process_group_id);
        related_groups.extend(
            relation
                .sampled_process_group_ids
                .iter()
                .copied()
                .filter(|group| *group > 0),
        );
        related_groups.extend(scan.owned.iter().map(|process| process.process_group_id));
    }
    // The strict token/identity retries above already discard exited
    // generations. A display inventory omits unreadable rows and therefore
    // cannot establish that any remaining unknown process has exited.
    for (process, diagnostic) in unreadable {
        let related = relation.is_none()
            || related_pids.contains(&process.pid)
            || related_groups.contains(&process.process_group_id);
        if !related && withheld(&diagnostic, process.uid) {
            scan.unverified.push(UnverifiedProcess {
                pid: process.pid,
                diagnostic,
            });
        } else {
            scan.failures.push(OwnershipFailure {
                pid: process.pid,
                reason: "environment-unreadable",
                diagnostic: Some(diagnostic),
            });
        }
    }
    scan
}

/// `observeOwnedProcessGroups`: alive only when every live member carries the token.
///
/// `session_group` is the process group of a PTY session leader this process
/// launched and still owns (`pty::OwnedPtyProcess`): a POSIX group ID cannot
/// be reused while the group has members, and only members of the same
/// session can join it, so its live members are attributed to the run by
/// session ownership even when the kernel withholds their environment.
pub fn observe_process_groups(
    run_id: &str,
    group_ids: &[u32],
    session_group: Option<u32>,
) -> BTreeMap<u32, GroupObservation> {
    let groups: BTreeSet<u32> = group_ids.iter().copied().collect();
    let processes = match list_live_processes() {
        Ok(processes) => processes,
        Err(reason) => {
            let failure = GroupObservation::Unverifiable(format!(
                "process group could not be inspected: {reason}"
            ));
            return groups
                .into_iter()
                .map(|group| (group, failure.clone()))
                .collect();
        }
    };
    let mut observations: BTreeMap<u32, GroupObservation> = groups
        .iter()
        .map(|group| (*group, GroupObservation::Empty))
        .collect();
    for process in processes
        .iter()
        .filter(|process| groups.contains(&process.process_group_id))
    {
        let group = process.process_group_id;
        if matches!(
            observations.get(&group),
            Some(GroupObservation::Unverifiable(_))
        ) {
            continue;
        }
        if session_group == Some(group) {
            observations.insert(group, GroupObservation::Alive);
            continue;
        }
        let observation = match read_token_fact(process) {
            TokenFact::Exited => continue,
            TokenFact::Changed => GroupObservation::Unverifiable(format!(
                "native process-group membership could not be revalidated for PID {}",
                process.pid
            )),
            TokenFact::Token(RunTokenObservation::Readable {
                run_id: Some(found),
            }) if found == run_id => GroupObservation::Alive,
            TokenFact::Unavailable(reason)
            | TokenFact::Token(RunTokenObservation::Unavailable { reason }) => {
                GroupObservation::Unverifiable(format!(
                    "process ownership could not be revalidated for PID {}: {reason}",
                    process.pid
                ))
            }
            TokenFact::Token(_) => {
                GroupObservation::Unverifiable("process ownership did not match".to_owned())
            }
        };
        observations.insert(group, observation);
    }
    observations
}

fn merge_unverified(into: &mut Vec<UnverifiedProcess>, more: Vec<UnverifiedProcess>) {
    for item in more {
        if !into.contains(&item) {
            into.push(item);
        }
    }
}

/// `sanitizedTokenReadFailure`: a closed category for one token-read diagnostic.
pub fn sanitized_token_read_failure(diagnostic: Option<&str>) -> String {
    let diagnostic = diagnostic.unwrap_or_default();
    const KNOWN: [&str; 11] = [
        "environment_unavailable",
        PLATFORM_BINARY_ENVIRONMENT_WITHHELD,
        RESTRICTED_PROCESS_ENVIRONMENT_WITHHELD,
        "apple_vector_unavailable",
        "ambiguous_environment_boundary",
        "malformed_procargs",
        "process_identity_changed_during_token_read",
        "process_not_in_snapshot",
        "reader_failure",
        "duplicate_run_token",
        "invalid_run_token_encoding",
    ];
    if KNOWN.contains(&diagnostic) {
        return diagnostic.to_owned();
    }
    for code in ["EACCES", "EPERM", "ENOENT", "ESRCH"] {
        if diagnostic.starts_with(&format!("{code}:")) {
            return format!("environment_errno_{code}");
        }
    }
    let numbered = |prefix: &str, output: &str| {
        diagnostic
            .strip_prefix(prefix)
            .filter(|number| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
            .map(|number| format!("{output}{number}"))
    };
    numbered("process_table_failed_", "process_table_errno_")
        .or_else(|| numbered("sysctl_failed_", "sysctl_errno_"))
        .unwrap_or_else(|| "other_unavailable".to_owned())
}

/// `cleanupValidationFailure` reason text.
fn validation_failure(failures: &[OwnershipFailure]) -> String {
    let mut mismatched: Vec<u32> = failures
        .iter()
        .filter(|failure| failure.reason == "run-token-mismatch")
        .map(|failure| failure.pid)
        .collect();
    if !mismatched.is_empty() {
        mismatched.sort_unstable();
        mismatched.dedup();
        let pids = mismatched
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        return format!("process ownership token mismatch for PID(s): {pids}");
    }
    if failures
        .iter()
        .any(|failure| failure.reason == "process-identity-unavailable")
    {
        return "process identity could not be revalidated".to_owned();
    }
    let unreadable: Vec<_> = failures
        .iter()
        .filter(|failure| failure.reason == "environment-unreadable")
        .collect();
    if !unreadable.is_empty() {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut candidates = Vec::new();
        for failure in &unreadable {
            let category = sanitized_token_read_failure(failure.diagnostic.as_deref());
            candidates.push(format!("{}={category}", failure.pid));
            *counts.entry(category).or_default() += 1;
        }
        candidates.sort();
        let breakdown = counts
            .iter()
            .map(|(category, count)| format!("{category}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "process ownership token could not be read for {} live process(es): {breakdown}; live candidates {}",
            unreadable.len(),
            candidates.join(", ")
        );
    }
    "process ownership could not be revalidated".to_owned()
}

/// Refresh membership immediately before signaling. A historical group with
/// no currently authenticated live member grants no signal authority.
fn revalidate_group_members(
    group: u32,
    run_id: &str,
    previously_owned: &[ProcessEntry],
) -> Result<bool, String> {
    let members = strict_rows()?
        .into_iter()
        .filter(|row| !row.zombie && row.entry.process_group_id == group)
        .map(|row| row.entry);
    verify_group_members(members, run_id, previously_owned, read_token_fact)
}

fn verify_group_members(
    members: impl Iterator<Item = ProcessEntry>,
    run_id: &str,
    previously_owned: &[ProcessEntry],
    mut observe: impl FnMut(&ProcessEntry) -> TokenFact,
) -> Result<bool, String> {
    let mut has_verified_member = false;
    for member in members {
        if !previously_owned.iter().any(|owned| {
            owned.pid == member.pid
                && owned.identity == member.identity
                && owned.process_group_id == member.process_group_id
        }) {
            return Err(format!(
                "process group gained an unverified member before signal: PID {}",
                member.pid
            ));
        }
        match observe(&member) {
            TokenFact::Exited => {}
            TokenFact::Token(RunTokenObservation::Readable {
                run_id: Some(found),
            }) if found == run_id => has_verified_member = true,
            TokenFact::Unavailable(reason)
            | TokenFact::Token(RunTokenObservation::Unavailable { reason }) => {
                return Err(format!(
                    "process {} could not be revalidated before signal: {reason}",
                    member.pid
                ));
            }
            _ => {
                return Err(format!(
                    "process {} identity or ownership changed before signal",
                    member.pid
                ));
            }
        }
    }
    Ok(has_verified_member)
}

/// Signal every token-owned process group whose live members all carry the
/// token from the same generation, then verify no owned process remains.
/// The PTY root group itself is released by its owner before this sweep.
pub fn cleanup_token_owned_processes(
    run_id: &str,
    baseline: &OwnershipBaseline,
    relation: &OwnershipRelation,
) -> CleanupResult {
    let processes = match list_live_processes() {
        Ok(processes) => processes,
        Err(reason) => {
            return CleanupResult {
                cleaned: false,
                reason: Some(format!("process table could not be inspected: {reason}")),
                signaled: false,
                unverified: Vec::new(),
            };
        }
    };
    #[cfg(target_os = "linux")]
    if let Err(reason) = validate_owned_groups(relation, &processes) {
        return CleanupResult {
            cleaned: false,
            reason: Some(reason),
            signaled: false,
            unverified: Vec::new(),
        };
    }
    let scan = scan_token_owned(&processes, run_id, baseline, Some(relation));
    let mut unverified = scan.unverified.clone();
    let mut signaled = false;
    let owned_groups: BTreeSet<u32> = scan
        .owned
        .iter()
        .map(|process| process.process_group_id)
        .collect();
    for group in owned_groups {
        match revalidate_group_members(group, run_id, &scan.owned) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(reason) => {
                return CleanupResult {
                    cleaned: false,
                    reason: Some(reason),
                    signaled,
                    unverified,
                };
            }
        }
        // SAFETY: kill(2) on a group whose every live member carries this run's token.
        let result = unsafe { libc::kill(-(group as libc::pid_t), libc::SIGKILL) };
        if result == 0 {
            signaled = true;
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return CleanupResult {
                    cleaned: false,
                    reason: Some(format!("owned process group signal failed: {error}")),
                    signaled,
                    unverified,
                };
            }
        }
    }
    if !scan.failures.is_empty() {
        return CleanupResult {
            cleaned: false,
            reason: Some(validation_failure(&scan.failures)),
            signaled,
            unverified,
        };
    }
    let deadline = Instant::now() + CLEANUP_VERIFICATION_GRACE;
    loop {
        let verification = verify_no_token_owned_processes(run_id, baseline, relation);
        merge_unverified(&mut unverified, verification.unverified.clone());
        if verification.cleaned || Instant::now() >= deadline {
            return CleanupResult {
                cleaned: verification.cleaned,
                reason: verification.reason,
                signaled,
                unverified,
            };
        }
        std::thread::sleep(
            CLEANUP_VERIFICATION_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

/// `verifyNoTokenOwnedProcesses`.
pub fn verify_no_token_owned_processes(
    run_id: &str,
    baseline: &OwnershipBaseline,
    relation: &OwnershipRelation,
) -> CleanupResult {
    let processes = match list_live_processes() {
        Ok(processes) => processes,
        Err(reason) => {
            return CleanupResult {
                cleaned: false,
                reason: Some(format!("process table could not be inspected: {reason}")),
                signaled: false,
                unverified: Vec::new(),
            };
        }
    };
    #[cfg(target_os = "linux")]
    if let Err(reason) = validate_owned_groups(relation, &processes) {
        return CleanupResult {
            cleaned: false,
            reason: Some(reason),
            signaled: false,
            unverified: Vec::new(),
        };
    }
    let scan = scan_token_owned(&processes, run_id, baseline, Some(relation));
    let (cleaned, reason) = if !scan.failures.is_empty() {
        (false, Some(validation_failure(&scan.failures)))
    } else if !scan.owned.is_empty() {
        (
            false,
            Some("token-owned process remained after cleanup".to_owned()),
        )
    } else {
        (true, None)
    };
    CleanupResult {
        cleaned,
        reason,
        signaled: false,
        unverified: scan.unverified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    #[test]
    fn group_signal_requires_a_current_verified_member() {
        let owned = ProcessEntry {
            pid: 42,
            parent_pid: 1,
            process_group_id: 42,
            uid: Some(501),
            identity: "generation-1".into(),
        };
        let previous = [owned.clone()];
        assert!(
            !verify_group_members(std::iter::empty(), "run-1", &previous, |_| panic!(
                "empty groups require no token read"
            ),)
            .unwrap()
        );
        assert!(
            !verify_group_members([owned.clone()].into_iter(), "run-1", &previous, |_| {
                TokenFact::Exited
            },)
            .unwrap()
        );
        assert!(
            verify_group_members([owned.clone()].into_iter(), "run-1", &previous, |_| {
                TokenFact::Token(RunTokenObservation::Readable {
                    run_id: Some("run-1".into()),
                })
            },)
            .unwrap()
        );
        assert!(
            verify_group_members([owned.clone()].into_iter(), "run-1", &previous, |_| {
                TokenFact::Unavailable("identity read failed".into())
            },)
            .is_err()
        );

        let newcomer = ProcessEntry { pid: 43, ..owned };
        assert!(
            verify_group_members([newcomer].into_iter(), "run-1", &previous, |_| panic!(
                "new members have no previous ownership proof"
            ),)
            .is_err()
        );
    }

    #[test]
    fn strict_rows_preserve_unknowns_and_terminal_lifecycle() {
        use super::super::linux::identity::{Observation, Relation};
        use rea_core::linux_proc::stat::Lifecycle;

        let absent = Observation::Absent {
            reason: "not-found",
        };
        assert!(required_row(42, &absent).unwrap().is_none());
        let unavailable = Observation::Unavailable {
            reason: "malformed stat".into(),
        };
        assert!(required_row(42, &unavailable).is_err());

        let mut readable = Observation::Readable {
            identity: "linux-starttime:10".into(),
            lifecycle: None,
            relation: None,
            effective_uid: None,
        };
        assert!(required_row(42, &readable).is_err());
        if let Observation::Readable { relation, .. } = &mut readable {
            *relation = Some(Relation {
                parent_pid: 1,
                process_group_id: Some(42),
                session_id: Some(42),
                parent_identity: None,
            });
        }
        // Unknown lifecycle cannot establish that a process has exited.
        assert!(!required_row(42, &readable).unwrap().unwrap().zombie);
        for terminal in [Lifecycle::Zombie, Lifecycle::Dead] {
            if let Observation::Readable { lifecycle, .. } = &mut readable {
                *lifecycle = Some(terminal);
            }
            assert!(required_row(42, &readable).unwrap().unwrap().zombie);
        }
    }

    #[test]
    fn lists_own_process_with_native_relation() {
        let own = std::process::id();
        let processes = list_live_processes().unwrap();
        assert!(processes.iter().any(|process| process.pid == own));
    }

    #[test]
    fn observes_live_members_without_token_authentication() {
        let own = std::process::id();
        let process = list_live_processes()
            .unwrap()
            .into_iter()
            .find(|process| process.pid == own)
            .unwrap();
        let observations = observe_process_group_members(&[process.process_group_id]);
        assert_eq!(
            observations.get(&process.process_group_id),
            Some(&GroupObservation::Alive)
        );
    }

    #[test]
    fn command_rows_match_the_process_argument_vector() {
        let own = std::process::id();
        let row = list_process_commands()
            .unwrap()
            .into_iter()
            .find(|row| row.pid == own)
            .unwrap();
        let expected: Vec<String> = std::env::args().collect();
        assert_eq!(row.command, expected.join(" "));
    }

    #[test]
    fn descendants_are_breadth_first_and_cycle_safe() {
        let entry = |pid, parent_pid| ProcessEntry {
            pid,
            parent_pid,
            process_group_id: 1,
            uid: None,
            identity: String::new(),
        };
        let processes = vec![entry(2, 1), entry(3, 2), entry(4, 1), entry(1, 3)];
        let pids: Vec<_> = descendants_of(&[1], &processes)
            .into_iter()
            .map(|process| process.pid)
            .collect();
        assert_eq!(pids, vec![2, 4, 3]);
    }

    #[test]
    fn baseline_processes_are_not_sweep_candidates() {
        let processes = list_live_processes().unwrap();
        let baseline: OwnershipBaseline = processes
            .iter()
            .map(|process| (process.pid, Some(process.identity.clone())))
            .collect();
        let scan = scan_token_owned(&processes, "run-not-present", &baseline, None);
        assert!(scan.owned.is_empty() && scan.failures.is_empty() && scan.unverified.is_empty());
    }

    #[test]
    fn token_owned_child_is_found_signaled_and_verified_gone() {
        let baseline = capture_baseline().unwrap();
        let run_id = format!("ownership-test-{}", std::process::id());
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exec sleep 30"])
            .env("REA_PROCESS_RUN_ID", &run_id)
            .process_group(0)
            .spawn()
            .unwrap();
        // Let exec complete so the environment is the sleep's own.
        std::thread::sleep(Duration::from_millis(100));
        let relation = OwnershipRelation {
            leader_pid: child.id(),
            process_group_id: child.id(),
            sampled_process_group_ids: Vec::new(),
        };
        let processes = list_live_processes().unwrap();
        let scan = scan_token_owned(&processes, &run_id, &baseline, Some(&relation));
        // /bin/sleep is a platform binary on macOS: its environment is withheld,
        // so a related unreadable process must keep cleanup fail-closed.
        if cfg!(target_os = "macos") {
            assert!(scan.owned.is_empty());
            assert!(
                scan.failures
                    .iter()
                    .any(|failure| failure.pid == child.id()),
                "{scan:?}"
            );
            let result = cleanup_token_owned_processes(&run_id, &baseline, &relation);
            assert!(!result.cleaned);
            // Token-only observation cannot attribute it; session ownership can.
            assert!(matches!(
                observe_process_groups(&run_id, &[child.id()], None).get(&child.id()),
                Some(GroupObservation::Unverifiable(_))
            ));
            assert_eq!(
                observe_process_groups(&run_id, &[child.id()], Some(child.id())).get(&child.id()),
                Some(&GroupObservation::Alive)
            );
            let _ = child.kill();
        } else {
            assert!(scan.owned.iter().any(|process| process.pid == child.id()));
            let result = cleanup_token_owned_processes(&run_id, &baseline, &relation);
            assert!(result.cleaned && result.signaled, "{result:?}");
        }
        let _ = child.wait();
    }

    /// Helper entry point: the test binary re-executed as a long-lived child.
    #[test]
    #[ignore = "helper process for token_owned_non_platform_group_is_signaled"]
    fn ownership_sleeper_helper() {
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn token_owned_non_platform_group_is_signaled_and_verified_gone() {
        let baseline = capture_baseline().unwrap();
        let run_id = format!("ownership-owned-{}", std::process::id());
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process::ownership::tests::ownership_sleeper_helper",
                "--ignored",
                "--quiet",
            ])
            .env("REA_PROCESS_RUN_ID", &run_id)
            .stdout(std::process::Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(150));
        let relation = OwnershipRelation {
            leader_pid: child.id(),
            process_group_id: child.id(),
            sampled_process_group_ids: Vec::new(),
        };
        let processes = list_live_processes().unwrap();
        let scan = scan_token_owned(&processes, &run_id, &baseline, Some(&relation));
        assert!(
            scan.owned.iter().any(|process| process.pid == child.id()),
            "{scan:?}"
        );
        assert_eq!(
            observe_process_groups(&run_id, &[child.id()], None).get(&child.id()),
            Some(&GroupObservation::Alive)
        );
        // A different run never owns the process.
        assert!(
            scan_token_owned(&processes, "other-run", &baseline, None)
                .owned
                .is_empty()
        );
        let result = cleanup_token_owned_processes(&run_id, &baseline, &relation);
        assert!(result.signaled, "{result:?}");
        let status = child.wait().unwrap();
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL)
        );
        assert!(verify_no_token_owned_processes(&run_id, &baseline, &relation).cleaned);
    }
}
