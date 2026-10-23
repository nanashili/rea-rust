//! `collectProcessCaptureIssues` and the finalization rules of
//! `src/domain/process/processCaptureValidation.ts`, plus the coverage
//! helpers of `processCaptureCoverage.ts`.
//!
//! The checks run on the Zod-shaped capture. When only non-aborting shape
//! issues were found the original still evaluates these refinements, so
//! every accessor tolerates out-of-range values instead of assuming them.
use crate::json::{array, boolean, byte_length, commitment, field, safe_integer, text};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};

/// One custom issue (dotted path, message).
pub type CustomIssue = (String, String);

fn ordered(values: impl IntoIterator<Item = Option<f64>>) -> bool {
    let mut previous: Option<f64> = None;
    for value in values {
        let value = value.unwrap_or(f64::NAN);
        if let Some(previous) = previous
            && (value < previous || value.is_nan() || previous.is_nan())
        {
            return false;
        }
        previous = Some(value);
    }
    true
}

fn number(value: &Value, key: &str) -> Option<f64> {
    field(value, key).and_then(Value::as_f64)
}

fn u(value: &Value, key: &str) -> f64 {
    number(value, key).unwrap_or(f64::NAN)
}

struct Require<'a>(&'a mut Vec<CustomIssue>);

impl Require<'_> {
    fn check(&mut self, condition: bool, path: &str, message: &str) {
        if !condition {
            self.0.push((path.to_owned(), message.to_owned()));
        }
    }
}

fn validate_commitments(capture: &Value, require: &mut Require<'_>) {
    let manifest = &capture["manifest"];
    let scenario = &manifest["scenario"];
    let executable = scenario
        .get("executable_sha256")
        .cloned()
        .unwrap_or(Value::Null);
    let selected = manifest
        .get("selected_executable_sha256")
        .cloned()
        .unwrap_or(Value::Null);
    // `undefined === null` is false: an absent projection never matches.
    require.check(
        scenario.get("executable_sha256").is_some() && executable == selected,
        "manifest.selected_executable_sha256",
        "selected executable commitment does not match the scenario projection",
    );
    let identity = &manifest["executable_identity"];
    let launch = if text(identity, "state") == Some("path_metadata_unchanged") {
        manifest["executable_sha256"] == selected && identity["reason"].is_null()
    } else {
        manifest["executable_sha256"].is_null() && !identity["reason"].is_null()
    };
    require.check(
        launch,
        "manifest.executable_identity",
        "launch identity and executable digest do not agree",
    );
    for (name, value) in [
        ("full_scenario_sha256", &manifest["scenario"]),
        (
            "comparison_contract_sha256",
            &manifest["comparison_contract"],
        ),
        ("normalization_sha256", &capture["normalization"]),
    ] {
        let matches = commitment(value)
            .is_some_and(|digest| manifest.get(name).and_then(Value::as_str) == Some(&digest));
        require.check(
            matches,
            &format!("manifest.{name}"),
            "commitment does not match its canonical value",
        );
    }
}

fn validate_ordering(capture: &Value, require: &mut Require<'_>) {
    for name in ["frames", "rendered_frames", "interaction_events"] {
        let contiguous = array(capture, name)
            .iter()
            .enumerate()
            .all(|(index, item)| number(item, "sequence") == Some(index as f64));
        require.check(
            contiguous,
            name,
            "sequence values must be contiguous from zero",
        );
    }
    for name in ["frames", "rendered_frames", "process_samples"] {
        require.check(
            ordered(
                array(capture, name)
                    .iter()
                    .map(|item| number(item, "at_ms")),
            ),
            name,
            "timestamps must be ordered",
        );
    }
    require.check(
        ordered(
            array(capture, "interaction_events")
                .iter()
                .map(|item| number(item, "dispatched_at_ms")),
        ),
        "interaction_events",
        "dispatch timestamps must be ordered",
    );
}

fn collection_sizes(capture: &Value) -> BTreeMap<&'static str, usize> {
    BTreeMap::from([
        ("frames", array(capture, "frames").len()),
        ("rendered_frames", array(capture, "rendered_frames").len()),
        (
            "interaction_events",
            array(capture, "interaction_events").len(),
        ),
        ("lifecycle", 2),
        ("process_samples", array(capture, "process_samples").len()),
        (
            "filesystem_checkpoints",
            array(capture, "filesystem_checkpoints").len(),
        ),
    ])
}

fn validate_event_journal(capture: &Value, require: &mut Require<'_>) {
    let journal = array(capture, "event_journal");
    if journal.is_empty() {
        return;
    }
    let sizes = collection_sizes(capture);
    let mut references = HashSet::new();
    for (position, entry) in journal.iter().enumerate() {
        require.check(
            number(entry, "capture_order") == Some(position as f64),
            &format!("event_journal.{position}.capture_order"),
            "capture order must be contiguous from zero",
        );
        let collection = text(entry, "collection").unwrap_or_default();
        let size = sizes.get(collection).copied();
        let index = u(entry, "index");
        require.check(
            size.is_some_and(|size| index < size as f64),
            &format!("event_journal.{position}.index"),
            "journal reference is outside its capture collection",
        );
        let reference = format!("{collection}:{}", js_number(&entry["index"]));
        require.check(
            !references.contains(&reference),
            &format!("event_journal.{position}"),
            "journal references must be unique",
        );
        references.insert(reference);
    }
    let expected: usize = sizes.values().sum();
    require.check(
        journal.len() == expected,
        "event_journal",
        "nonempty journal must reference every captured observation",
    );
}

/// `String(number)` for a JSON number.
fn js_number(value: &Value) -> String {
    match safe_integer(value) {
        Some(integer) => integer.to_string(),
        None => value.to_string(),
    }
}

/// `finalizationManifestIssue`.
pub fn finalization_manifest_issue(scenario: &Value, comparison: &Value) -> Option<&'static str> {
    (!strict_equal(
        scenario.get("finalization_ms"),
        comparison.get("finalization_ms"),
    ))
    .then_some("comparison_contract finalization_ms must match the committed scenario")
}

/// `finalizationConsistencyIssue` for a complete capture exit.
fn finalization_consistency_issue(
    exit: &Value,
    scenario: &Value,
    comparison: &Value,
) -> Option<&'static str> {
    if let Some(issue) = finalization_manifest_issue(scenario, comparison) {
        return Some(issue);
    }
    let reason = text(exit, "reason");
    let Some(finalization) = exit.get("finalization") else {
        let committed = scenario.get("finalization_ms").and_then(Value::as_f64);
        return (matches!(reason, Some("timeout" | "idle_timeout"))
            && committed.is_some_and(|committed| committed > 0.0))
        .then_some(
            "a deadline exit under a committed finalization_ms requires finalization evidence",
        );
    };
    if reason == Some("exited") {
        return Some("finalization requires a deadline exit reason");
    }
    let signals = array(finalization, "signals");
    let Some(first) = signals.first() else {
        return Some("finalization signals must start with SIGTERM");
    };
    if text(first, "signal") != Some("SIGTERM") {
        return Some("finalization signals must start with SIGTERM");
    }
    let kills = signals
        .iter()
        .enumerate()
        .filter(|(_, attempt)| text(attempt, "signal") == Some("SIGKILL"))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if kills.len() > 1
        || kills
            .first()
            .is_some_and(|index| *index != signals.len() - 1)
    {
        return Some("finalization may contain at most one final SIGKILL");
    }
    if !ordered(signals.iter().map(|attempt| number(attempt, "sent_at_ms"))) {
        return Some("finalization signal attempt times must not decrease");
    }
    if signals
        .iter()
        .filter(|attempt| text(attempt, "signal") == Some("SIGTERM"))
        .count()
        != 1
    {
        return Some("finalization must attempt SIGTERM exactly once");
    }
    let requested = u(finalization, "requested_ms");
    if let Some(kill) = signals
        .iter()
        .find(|attempt| text(attempt, "signal") == Some("SIGKILL"))
        && u(kill, "sent_at_ms") < requested
        && reason != Some("cancelled")
    {
        return Some("finalization SIGKILL cannot precede the requested interval");
    }
    let elapsed = &finalization["elapsed_ms"];
    if elapsed.is_null() {
        return Some("finalization requires an observed elapsed_ms");
    }
    let signal = &exit["signal"];
    if !finalization["exit_code"].is_null() && !signal.is_null() && signal.as_f64() != Some(0.0) {
        return Some("finalization exit_code requires an exit not caused by a signal");
    }
    let last = signals.last().unwrap_or(first);
    if elapsed.as_f64().unwrap_or(f64::NAN) < u(last, "sent_at_ms") {
        return Some("finalization elapsed_ms cannot precede the last signal attempt");
    }
    if !strict_equal(
        scenario.get("finalization_ms"),
        finalization.get("requested_ms"),
    ) {
        return Some("finalization must match the committed finalization_ms");
    }
    None
}

/// JavaScript `===` between two optional JSON values (`undefined` when absent).
/// Objects and arrays are distinct references and never strictly equal.
fn strict_equal(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(Value::Number(left)), Some(Value::Number(right))) => left.as_f64() == right.as_f64(),
        (Some(Value::String(left)), Some(Value::String(right))) => left == right,
        (Some(Value::Bool(left)), Some(Value::Bool(right))) => left == right,
        (Some(Value::Null), Some(Value::Null)) => true,
        _ => false,
    }
}

/// Nested `processCaptureFinalizationSchema.superRefine` issues.
pub fn finalization_refinements(finalization: &Value, path: &str) -> Vec<CustomIssue> {
    let mut issues = Vec::new();
    if !finalization["exit_code"].is_null() && finalization["elapsed_ms"].is_null() {
        issues.push((
            format!("{path}.exit_code"),
            "finalization exit_code requires an observed exit".to_owned(),
        ));
    }
    for (index, attempt) in array(finalization, "signals").iter().enumerate() {
        if attempt.get("reason").is_some() && text(attempt, "delivery") != Some("unverified") {
            issues.push((
                format!("{path}.signals.{index}.reason"),
                "finalization reason is only allowed for an unverified delivery".to_owned(),
            ));
        }
    }
    issues
}

fn validate_lifecycle(capture: &Value, require: &mut Require<'_>) {
    let checkpoints = array(capture, "filesystem_checkpoints");
    let names = checkpoints
        .iter()
        .map(|checkpoint| text(checkpoint, "name").unwrap_or_default())
        .collect::<Vec<_>>()
        .join(",");
    require.check(
        names == "before,after_settlement",
        "filesystem_checkpoints",
        "capture must include initial and final filesystem snapshots",
    );
    require.check(
        ordered(
            checkpoints
                .iter()
                .map(|checkpoint| number(checkpoint, "at_ms")),
        ),
        "filesystem_checkpoints",
        "filesystem snapshot times must be ordered",
    );
    require.check(
        !checkpoints
            .iter()
            .any(|checkpoint| boolean(checkpoint, "truncated") == Some(true))
            || boolean(capture, "truncated") == Some(true),
        "truncated",
        "filesystem snapshot truncation must propagate to the capture",
    );
    let exit = &capture["exit"];
    require.check(
        text(exit, "reason") == Some("exited") || exit["code"].is_null(),
        "exit",
        "deadline termination cannot declare a normal exit code",
    );
    let manifest = &capture["manifest"];
    let issue = finalization_consistency_issue(
        exit,
        &manifest["scenario"],
        &manifest["comparison_contract"],
    );
    require.check(issue.is_none(), "exit", issue.unwrap_or_default());
}

fn retention_omitted(retention: &Value) -> bool {
    u(retention, "observed_frames") > u(retention, "retained_frames")
}

fn filesystem_truncated(coverage: &Value) -> bool {
    boolean(coverage, "enumeration_truncated") == Some(true)
        || !array(coverage, "enumeration_omissions").is_empty()
        || !array(coverage, "hash_omissions").is_empty()
}

/// `hasCaptureTruncation`.
pub fn has_capture_truncation(details: &Value) -> bool {
    retention_omitted(&details["raw_terminal"])
        || retention_omitted(&details["rendered_terminal"])
        || number(&details["normalized_terminal"], "omitted_frames").unwrap_or(0.0) > 0.0
        || number(&details["rendered_terminal"], "unknown_size_frames").unwrap_or(0.0) > 0.0
        || filesystem_truncated(&details["filesystem_before"])
        || filesystem_truncated(&details["filesystem_after"])
        || boolean(&details["process"], "sampling_partial") == Some(true)
}

/// `processSourceTruncated`.
pub fn source_truncated(capture: &Value, source: &str) -> bool {
    let details = &capture["truncation_details"];
    match source {
        "terminal_raw" => retention_omitted(&details["raw_terminal"]),
        "terminal_rendered" => {
            retention_omitted(&details["raw_terminal"])
                || retention_omitted(&details["rendered_terminal"])
        }
        "filesystem" => {
            filesystem_truncated(&details["filesystem_before"])
                || filesystem_truncated(&details["filesystem_after"])
        }
        "process" => boolean(&details["process"], "sampling_partial") == Some(true),
        _ => false,
    }
}

fn validate_coverage(capture: &Value, require: &mut Require<'_>) {
    let details = &capture["truncation_details"];
    let process = &details["process"];
    let failures = u(process, "sampling_failures");
    require.check(
        u(process, "retained_samples") == array(capture, "process_samples").len() as f64
            && u(process, "retained_samples") <= u(process, "sample_limit")
            && boolean(process, "sampling_partial")
                == Some(boolean(process, "sample_limit_reached") == Some(true) || failures > 0.0)
            && (failures == 0.0) == process["first_sampling_failure"].is_null(),
        "truncation_details.process",
        "sampling coverage must agree with retained samples and observed failures",
    );
    require.check(
        boolean(capture, "truncated") == Some(has_capture_truncation(details)),
        "truncation_details",
        "aggregate truncation must match producer coverage",
    );
    let frames = array(capture, "frames");
    let rendered = array(capture, "rendered_frames");
    let raw_bytes: u64 = frames
        .iter()
        .map(|frame| {
            byte_length(
                text(frame, "raw_data")
                    .or(text(frame, "data"))
                    .unwrap_or_default(),
            )
        })
        .sum();
    let rendered_bytes: u64 = rendered
        .iter()
        .map(|frame| {
            byte_length(text(frame, "serialized_state").unwrap_or_default())
                + array(frame, "lines")
                    .iter()
                    .map(|line| byte_length(line.as_str().unwrap_or_default()))
                    .sum::<u64>()
        })
        .sum();
    for (name, count, bytes) in [
        ("raw_terminal", frames.len(), raw_bytes),
        ("rendered_terminal", rendered.len(), rendered_bytes),
    ] {
        let retention = &details[name];
        let count = count as f64;
        let observed_frames = u(retention, "observed_frames");
        let retained_bytes = u(retention, "retained_bytes");
        let observed_bytes = u(retention, "observed_bytes");
        require.check(
            u(retention, "retained_frames") == count
                && observed_frames >= count
                && retained_bytes == bytes as f64
                && observed_bytes >= retained_bytes
                && (observed_frames > count || observed_bytes == retained_bytes)
                && retained_bytes <= u(retention, "budget_bytes")
                && number(retention, "unknown_size_frames").unwrap_or(0.0)
                    <= observed_frames - u(retention, "retained_frames"),
            &format!("truncation_details.{name}"),
            "retained observations and budget accounting do not agree",
        );
    }
    if let Some(normalized) = details.get("normalized_terminal") {
        let limits = &capture["manifest"]["scenario"]["limits"];
        let budget = limits
            .as_object()
            .and_then(|limits| limits.get("output_bytes"))
            .and_then(safe_integer)
            .filter(|budget| *budget > 0);
        require.check(
            budget.is_some(),
            "manifest.scenario.limits.output_bytes",
            "committed process scenario must include an explicit valid output_bytes budget",
        );
        let retained: u64 = frames
            .iter()
            .map(|frame| byte_length(text(frame, "data").unwrap_or_default()))
            .sum();
        if let Some(budget) = budget {
            let raw = &details["raw_terminal"];
            require.check(
                u(normalized, "budget_bytes") == budget as f64
                    && u(normalized, "retained_bytes") == retained as f64
                    && u(normalized, "retained_bytes") <= u(normalized, "budget_bytes")
                    && u(normalized, "omitted_frames")
                        <= u(raw, "observed_frames") - u(raw, "retained_frames"),
                "truncation_details.normalized_terminal",
                "normalized terminal retention must agree with the committed budget and retained frames",
            );
        }
    }
    let checkpoints = array(capture, "filesystem_checkpoints");
    for (name, files_key, checkpoint) in [
        ("filesystem_before", "files_before", checkpoints.first()),
        ("filesystem_after", "files_after", checkpoints.get(1)),
    ] {
        let coverage = &details[name];
        let files = array(capture, files_key);
        validate_filesystem_coverage(name, coverage, files, checkpoint, require);
    }
}

fn validate_filesystem_coverage(
    name: &str,
    coverage: &Value,
    files: &[Value],
    checkpoint: Option<&Value>,
    require: &mut Require<'_>,
) {
    let is_file = |file: &Value| text(file, "type") == Some("file");
    // `new Map(...)`: later duplicates win.
    let mut unhashed: HashMap<&str, &Value> = HashMap::new();
    for file in files
        .iter()
        .filter(|file| is_file(file) && file["sha256"].is_null())
    {
        unhashed.insert(text(file, "path").unwrap_or_default(), file);
    }
    let mut entry_types: HashMap<&str, &str> = HashMap::new();
    for file in files {
        entry_types.insert(
            text(file, "path").unwrap_or_default(),
            text(file, "type").unwrap_or_default(),
        );
    }
    let hash_omissions = array(coverage, "hash_omissions");
    let hash_budget = u(coverage, "hash_budget_bytes");
    let omission_paths = hash_omissions
        .iter()
        .map(|omission| text(omission, "path").unwrap_or_default())
        .collect::<HashSet<_>>();
    require.check(
        hash_omissions.len() == unhashed.len()
            && omission_paths.len() == unhashed.len()
            && hash_omissions.iter().all(|omission| {
                unhashed
                    .get(text(omission, "path").unwrap_or_default())
                    .is_some_and(|file| number(file, "size") == number(omission, "size_bytes"))
                    && u(omission, "remaining_budget_bytes") <= hash_budget
                    && if text(omission, "reason") == Some("file_unavailable") {
                        !omission["system_code"].is_null()
                    } else {
                        omission["system_code"].is_null()
                    }
            }),
        &format!("truncation_details.{name}.hash_omissions"),
        "every retained regular file without a digest must have one matching omission reason",
    );
    let omissions = array(coverage, "enumeration_omissions");
    let reasons = array(coverage, "enumeration_reasons")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let unique_paths = omissions
        .iter()
        .map(|omission| text(omission, "path").unwrap_or_default())
        .collect::<HashSet<_>>();
    require.check(
        unique_paths.len() == omissions.len()
            && (!reasons.contains(&"entry_unavailable")
                || omissions
                    .iter()
                    .any(|omission| text(omission, "reason") == Some("entry_unavailable")))
            && omissions.iter().all(|omission| {
                let reason = text(omission, "reason").unwrap_or_default();
                let entry = entry_types
                    .get(text(omission, "path").unwrap_or_default())
                    .copied();
                let system = !omission["system_code"].is_null();
                reasons.contains(&reason)
                    && if reason == "directory_unavailable" {
                        entry == Some("directory") && system
                    } else {
                        (entry.is_none() || entry == Some("directory"))
                            && if reason == "entry_unavailable" {
                                system
                            } else {
                                !system
                            }
                    }
            }),
        &format!("truncation_details.{name}.enumeration_omissions"),
        "every enumeration omission must identify an unavailable entry or retained directory, with a matching reason and system error only for unavailable reads",
    );
    let hashed: f64 = files
        .iter()
        .filter(|file| is_file(file) && !file["sha256"].is_null())
        .map(|file| u(file, "size"))
        .sum();
    let hashed_bytes = u(coverage, "hashed_bytes");
    require.check(
        hashed_bytes == hashed
            && hashed_bytes <= hash_budget
            && files.len() as f64 <= u(coverage, "files_limit"),
        &format!("truncation_details.{name}"),
        "filesystem budget accounting does not match retained observations",
    );
    let enumeration_truncated = boolean(coverage, "enumeration_truncated");
    require.check(
        enumeration_truncated == Some(!array(coverage, "enumeration_reasons").is_empty())
            && checkpoint.and_then(|checkpoint| boolean(checkpoint, "truncated"))
                == Some(
                    enumeration_truncated == Some(true)
                        || !omissions.is_empty()
                        || !hash_omissions.is_empty(),
                ),
        &format!("truncation_details.{name}"),
        "filesystem checkpoint truncation must match enumeration and digest coverage",
    );
}

/// `collectProcessCaptureIssues`.
pub fn collect_issues(capture: &Value) -> Vec<CustomIssue> {
    let mut issues = Vec::new();
    let mut require = Require(&mut issues);
    validate_commitments(capture, &mut require);
    validate_ordering(capture, &mut require);
    validate_event_journal(capture, &mut require);
    validate_lifecycle(capture, &mut require);
    validate_coverage(capture, &mut require);
    issues
}
