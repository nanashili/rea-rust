//! Capture result, manifest, limitations and residual unknowns.
//!
//! Compatibility owners: `buildCaptureResult`, `captureCoverageUnknowns`,
//! `createRunManifest` and the success branch of `resolveProcessResult`
//! (`ProcessCaptureLifecycle.ts`). The verified value is the original's
//! `parseProcessCapture` output (`crate::capture::parse`).

use super::normalize::normalize_samples;
use super::paths::LaunchedExecutable;
use super::sampler::Sampling;
use super::scenario::{Scenario, digest};
use super::snapshot::{Snapshot, classify_effects};
use crate::capture;
use crate::capture::validation::has_capture_truncation;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

/// Observations of one completed run before cleanup is known.
pub struct CaptureFacts {
    pub scenario: Scenario,
    pub manifest: Value,
    pub frames: Vec<Value>,
    pub rendered_frames: Vec<Value>,
    pub interactions: Vec<Value>,
    pub exit: Value,
    pub settlement: Value,
    pub checkpoints: Value,
    pub journal: Vec<Value>,
    pub before: Snapshot,
    pub after: Snapshot,
    pub raw_terminal: Value,
    pub normalized_terminal: Value,
    pub rendered_terminal: Value,
    pub root_pid: i64,
}

/// JavaScript `Date#toISOString`.
pub fn iso_timestamp(time: SystemTime) -> String {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let millis = since.as_millis() as i64;
    let days = millis.div_euclid(86_400_000);
    let of_day = millis.rem_euclid(86_400_000);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        of_day / 3_600_000,
        of_day / 60_000 % 60,
        of_day / 1_000 % 60,
        of_day % 1_000
    )
}

fn host_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

fn host_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        "x86" => "ia32",
        other => other,
    }
}

/// `createRunManifest`.
pub fn manifest(scenario: &Scenario, started_at: SystemTime, completed_at: SystemTime, executable: &LaunchedExecutable) -> Value {
    let commitment = scenario.commitment(executable.selected_sha256.as_deref());
    let contract = scenario.comparison_contract();
    json!({
        "rea_version": rea_tools_binary::PACKAGE_VERSION,
        "provider_version": "3",
        "platform": host_platform(),
        "architecture": host_architecture(),
        // The capture contract names the PTY backend of the original runtime.
        "pty_backend": "node-pty",
        "started_at": iso_timestamp(started_at),
        "completed_at": iso_timestamp(completed_at),
        "scenario": commitment,
        "comparison_contract": contract,
        "full_scenario_sha256": digest(&commitment),
        "comparison_contract_sha256": digest(&contract),
        "selected_executable_sha256": executable.selected_sha256,
        "executable_sha256": executable.sha256,
        "executable_identity": {"state": executable.state, "reason": executable.reason},
        "normalization_sha256": digest(&scenario.normalization()),
    })
}

/// `captureCoverageUnknowns`: (scope, reason).
fn coverage_unknowns(details: &Value) -> Vec<(&'static str, String)> {
    let mut unknowns = Vec::new();
    let number = |value: &Value| value.as_u64().unwrap_or_default();
    let raw = &details["raw_terminal"];
    if number(&raw["observed_frames"]) > number(&raw["retained_frames"]) {
        unknowns.push((
            "terminal",
            if number(&details["normalized_terminal"]["omitted_frames"]) > 0 {
                "Raw PTY chunks were omitted because original input exceeded output_bytes or an ordered normalization stage exceeded its remaining bound; final normalized sizes for the latter omissions are unknown. Rendered states also lack those inputs. See raw_terminal and normalized_terminal retention details, including the normalized omission count.".to_owned()
            } else {
                "Raw PTY chunks exceeded output_bytes and were omitted; rendered states also lack those inputs. See truncation_details.raw_terminal.".to_owned()
            },
        ));
    }
    let rendered = &details["rendered_terminal"];
    if number(&rendered["observed_frames"]) > number(&rendered["retained_frames"]) {
        unknowns.push((
            "terminal",
            if number(&rendered["unknown_size_frames"]) > 0 {
                "Rendered frames were omitted because a normalization stage exceeded the remaining output_bytes budget; final rendered byte totals are unknown for those frames. See truncation_details.rendered_terminal.".to_owned()
            } else {
                "Cumulative rendered state and visible-line bytes exceeded output_bytes; whole rendered frames were omitted. Raw PTY coverage is reported separately. See truncation_details.rendered_terminal.".to_owned()
            },
        ));
    }
    for (name, key) in [("before", "filesystem_before"), ("after_settlement", "filesystem_after")] {
        let coverage = &details[key];
        if coverage["enumeration_truncated"] == true {
            let reasons: Vec<&str> = coverage["enumeration_reasons"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            unknowns.push(("filesystem", format!("Filesystem {name} path enumeration was incomplete: {}. See truncation_details.", reasons.join(", "))));
        }
        let omissions = coverage["hash_omissions"].as_array().map_or(0, Vec::len);
        if omissions > 0 {
            unknowns.push((
                "filesystem",
                format!("Filesystem {name} omitted {omissions} whole-file digests; per-path reasons and remaining file_bytes budget are in truncation_details."),
            ));
        }
    }
    let process = &details["process"];
    if process["sampling_partial"] == true {
        unknowns.push((
            "process",
            match process["first_sampling_failure"].as_str() {
                Some(failure) => format!("Process sampling has incomplete observations: {failure}. See truncation_details.process."),
                None => "The process sample limit was reached; see truncation_details.process.".to_owned(),
            },
        ));
    }
    unknowns
}

const SENSITIVE_INPUT_UNKNOWN: &str = "Sensitive scripted input values are redacted from process capture Evidence.";
const FILESYSTEM_OBSERVATION_UNKNOWN: &str = "No filesystem observation paths were selected; filesystem effects remain unknown.";
const EXECUTABLE_DIGEST_LIMITATION: &str = "The executable digest is a prelaunch file sample; matching path metadata immediately after spawn does not prove an atomic operating-system image binding.";
const SAMPLED_TREES: &str = "Process trees are sampled and may omit short-lived descendants.";

/// `buildCaptureResult` (settlement without `cleanup_outcome`, no `cleanup`).
pub fn pending(facts: CaptureFacts, sampling: &Sampling) -> Value {
    let scenario = &facts.scenario;
    let effects = classify_effects(&facts.before, &facts.after);
    let mut filesystem_unknowns: Vec<String> = Vec::new();
    for effect in &effects {
        if effect["status"] == "unknown"
            && let Some(reason) = effect["reason"].as_str()
            && !filesystem_unknowns.iter().any(|known| known == reason)
        {
            filesystem_unknowns.push(reason.to_owned());
        }
    }
    let details = json!({
        "raw_terminal": facts.raw_terminal,
        "normalized_terminal": facts.normalized_terminal,
        "rendered_terminal": facts.rendered_terminal,
        "filesystem_before": facts.before.coverage,
        "filesystem_after": facts.after.coverage,
        "process": sampling.coverage,
    });
    let observations = !scenario.filesystem_observation_paths.is_empty();
    let sensitive = scenario.has_sensitive_input();
    let coverage = coverage_unknowns(&details);
    let completed_first = super::super::comparison::parse_timestamp_ms(facts.manifest["completed_at"].as_str().unwrap_or_default())
        < super::super::comparison::parse_timestamp_ms(facts.manifest["started_at"].as_str().unwrap_or_default());
    let mut limitations = vec![EXECUTABLE_DIGEST_LIMITATION.to_owned()];
    if completed_first {
        limitations.push("Wall-clock completion time precedes start time; elapsed capture timing is recorded separately and remains monotonic.".to_owned());
    }
    limitations.push(SAMPLED_TREES.to_owned());
    if sampling.partial {
        limitations.push("Process-tree sampling ended with an incomplete observation.".to_owned());
    }
    limitations.push("Filesystem observations are before/after snapshots, not syscall traces.".to_owned());
    limitations.push("Inherited host environment variables are not recorded and may affect results.".to_owned());
    if !observations {
        limitations.push(FILESYSTEM_OBSERVATION_UNKNOWN.to_owned());
    }
    limitations.extend(filesystem_unknowns.iter().cloned());
    limitations.extend(coverage.iter().map(|(_, reason)| reason.clone()));
    if sensitive {
        limitations.push(SENSITIVE_INPUT_UNKNOWN.to_owned());
    }
    let mut residual = vec![
        json!({"scope": "process", "reason": SAMPLED_TREES}),
        json!({"scope": "process", "reason": "The executable digest is a prelaunch file sample; operating-system image binding is not atomically observed."}),
        json!({"scope": "environment", "reason": "Inherited host environment variables are not recorded."}),
        json!({"scope": "network", "reason": "Network activity is not observed by this capture."}),
    ];
    if !observations {
        residual.push(json!({"scope": "filesystem", "reason": FILESYSTEM_OBSERVATION_UNKNOWN}));
    }
    residual.extend(filesystem_unknowns.iter().map(|reason| json!({"scope": "filesystem", "reason": reason})));
    if sensitive {
        residual.push(json!({"scope": "interaction", "reason": SENSITIVE_INPUT_UNKNOWN}));
    }
    residual.extend(coverage.iter().filter(|(scope, _)| *scope != "terminal").map(|(scope, reason)| json!({"scope": scope, "reason": reason})));
    json!({
        "manifest": facts.manifest,
        "normalization": scenario.normalization(),
        "frames": facts.frames,
        "rendered_frames": facts.rendered_frames,
        "interaction_events": facts.interactions,
        "exit": facts.exit,
        "settlement": facts.settlement,
        "process_samples": normalize_samples(&sampling.samples, scenario, facts.root_pid),
        "filesystem_checkpoints": facts.checkpoints,
        "event_journal": facts.journal,
        "files_before": facts.before.files,
        "files_after": facts.after.files,
        "filesystem_effects": effects,
        "truncated": has_capture_truncation(&details),
        "truncation_details": details,
        "limitations": limitations,
        "residual_unknowns": residual,
    })
}

/// The verified capture after a clean release (`resolveProcessResult`).
pub fn verified(facts: CaptureFacts, sampling: &Sampling, report: &Value) -> Result<Value, String> {
    let mut capture = pending(facts, sampling);
    let quiesced = capture["settlement"]["state"] == "quiesced";
    capture["settlement"]["cleanup_outcome"] = json!(if quiesced { "not_required" } else { "cleaned" });
    let mut cleanup = json!({"owned_process_group": "verified", "temporary_root": "removed"});
    if let Some(unverified) = report["owned_process_group"]["unverified_processes"].as_array() {
        cleanup["unverified_processes"] = Value::Array(unverified.clone());
        let residual = capture["residual_unknowns"].as_array_mut().expect("residual unknowns");
        for process in unverified {
            residual.push(json!({
                "scope": "process",
                "reason": format!(
                    "Ownership of unrelated process {} could not be verified; it was left untouched: {}",
                    process["pid"],
                    process["reason"].as_str().unwrap_or_default()
                ),
            }));
        }
    }
    capture["cleanup"] = cleanup;
    capture::parse(&capture).map_err(|error| format!("process capture validation failed: {}", error.describe()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn formats_iso_timestamps_like_javascript() {
        assert_eq!(iso_timestamp(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_timestamp(UNIX_EPOCH + Duration::from_millis(1_792_748_155_679)), "2026-10-23T09:35:55.679Z");
    }
}
