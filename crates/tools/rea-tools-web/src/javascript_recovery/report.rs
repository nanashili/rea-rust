//! Parse the Wakaru report/provenance JSON before projecting artifacts.
//!
//! Compatibility owner: `src/javascript/recovery/WakaruReport.ts`.
//!
//! Wakaru adds fields and category values within a major version, so unknown
//! keys are kept and `status` stays the reported string; identity, path, range
//! and file-set checks remain exact. This path is only reached on the Linux
//! execution path after a successful launch.

use std::collections::{BTreeMap, BTreeSet};

use rea_core::analysis_error::AnalysisError;
use serde_json::Value;

use crate::javascript_recovery::OPERATION;
use crate::javascript_recovery::command::CommandRun;
use crate::javascript_recovery::recovery_files::{StagedFile, read_recovery_file};
use crate::javascript_recovery::release::{RECOVERY_LIMITS, WAKARU_PROVIDER_ID};

/// A reported module entry (`report.modules[i]`).
pub(crate) struct ReportModule {
    pub filename: String,
    pub status: String,
}

/// A reported warning (`report.warnings[i]`).
pub(crate) struct ReportWarning {
    pub filename: String,
    pub kind: String,
    pub is_error: bool,
    pub message: String,
}

/// Validated producer report (`stdout` JSON).
pub(crate) struct ParsedReport {
    pub detected_formats: Vec<String>,
    pub safety: String,
    pub modules: Vec<ReportModule>,
    pub warnings: Vec<ReportWarning>,
    pub total: u64,
    pub failed: u64,
}

/// Per-module provenance (`provenance.modules[path]`).
pub(crate) struct ModuleProvenance {
    pub input: String,
    pub ranges: Vec<(u64, u64)>,
    pub extraction: String,
    pub context_ranges: Vec<(u64, u64)>,
}

/// Validated provenance (`provenance.json`).
pub(crate) struct ParsedProvenance {
    pub format: String,
    pub strategy: String,
    pub modules: BTreeMap<String, ModuleProvenance>,
}

/// Output of `parseWakaruReports`.
pub(crate) struct ParsedReports {
    pub report: ParsedReport,
    pub provenance: ParsedProvenance,
    pub report_value: Value,
    pub provenance_value: Value,
    pub status: &'static str,
}

/// Parse producer JSON before projecting provider-neutral artifacts.
pub(crate) fn parse_wakaru_reports(
    execution: &CommandRun,
    provenance_path: &str,
    snapshots: &BTreeMap<String, Vec<u8>>,
    files: &[StagedFile],
) -> Result<ParsedReports, AnalysisError> {
    parse_inner(execution, provenance_path, snapshots, files).map_err(|reason| {
        AnalysisError::provider_adapter(WAKARU_PROVIDER_ID, OPERATION).with_diagnostics(
            serde_json::Map::from_iter([
                (
                    "reason".to_owned(),
                    Value::String(format!("Unusable Wakaru recovery report: {reason}")),
                ),
                (
                    "exit_code".to_owned(),
                    execution.exit_code.map_or(Value::Null, |code| code.into()),
                ),
                ("signal".to_owned(), execution.signal.clone()),
                ("stdout".to_owned(), Value::String(execution.stdout.clone())),
                ("stderr".to_owned(), Value::String(execution.stderr.clone())),
            ]),
        )
    })
}

fn parse_inner(
    execution: &CommandRun,
    provenance_path: &str,
    snapshots: &BTreeMap<String, Vec<u8>>,
    files: &[StagedFile],
) -> Result<ParsedReports, String> {
    if execution.exit_code != Some(0) && execution.exit_code != Some(1) {
        return Err(
            "Wakaru did not complete recovery (expected exit 0 or a reported partial exit 1)"
                .to_owned(),
        );
    }
    let report_value: Value = serde_json::from_str(&execution.stdout).map_err(|e| e.to_string())?;
    let provenance_bytes = read_recovery_file(provenance_path, RECOVERY_LIMITS.report_bytes)
        .map_err(|error| error.project()["message"].as_str().unwrap_or("").to_owned())?;
    let provenance_value: Value =
        serde_json::from_slice(&provenance_bytes).map_err(|e| e.to_string())?;

    let report = parse_report(&report_value)?;
    let provenance = parse_provenance(&provenance_value)?;

    if report.total != report.modules.len() as u64 || report.failed > report.total {
        return Err("Reported module totals disagree".to_owned());
    }
    let has_error_warning = report.warnings.iter().any(|warning| warning.is_error);
    if execution.exit_code == Some(1) && report.failed == 0 && !has_error_warning {
        return Err("Wakaru exited 1 without a reported partial recovery reason".to_owned());
    }

    validate_module_set(&report, &provenance, snapshots, files)?;

    let status = if report.failed > 0 || has_error_warning || execution.exit_code == Some(1) {
        "partial"
    } else {
        "complete"
    };

    Ok(ParsedReports {
        report,
        provenance,
        report_value,
        provenance_value,
        status,
    })
}

fn parse_report(value: &Value) -> Result<ParsedReport, String> {
    let object = value.as_object().ok_or("report is not an object")?;
    let detected_formats = string_array(object.get("detected_formats"))?;
    let safety = require_string(object.get("safety"), "safety")?;
    let total = require_u64(object.get("total"), "total")?;
    let failed = require_u64(object.get("failed"), "failed")?;
    require_u64(object.get("elapsed_ms"), "elapsed_ms")?;

    let mut modules = Vec::new();
    for module in object
        .get("modules")
        .and_then(Value::as_array)
        .ok_or("modules is not an array")?
    {
        let module = module.as_object().ok_or("module is not an object")?;
        let filename = require_nonempty(module.get("filename"), "filename")?;
        if module.get("kind").and_then(Value::as_str) != Some("javascript") {
            return Err("module kind is not javascript".to_owned());
        }
        let status = require_nonempty(module.get("status"), "status")?;
        modules.push(ReportModule { filename, status });
    }

    let mut warnings = Vec::new();
    for warning in object
        .get("warnings")
        .and_then(Value::as_array)
        .ok_or("warnings is not an array")?
    {
        let warning = warning.as_object().ok_or("warning is not an object")?;
        warnings.push(ReportWarning {
            filename: require_string(warning.get("filename"), "warning.filename")?,
            kind: require_string(warning.get("kind"), "warning.kind")?,
            is_error: warning
                .get("is_error")
                .and_then(Value::as_bool)
                .ok_or("warning.is_error is not a boolean")?,
            message: require_string(warning.get("message"), "warning.message")?,
        });
    }

    Ok(ParsedReport {
        detected_formats,
        safety,
        modules,
        warnings,
        total,
        failed,
    })
}

fn parse_provenance(value: &Value) -> Result<ParsedProvenance, String> {
    let object = value.as_object().ok_or("provenance is not an object")?;
    let format = require_string(object.get("format"), "format")?;
    let strategy = require_string(object.get("strategy"), "strategy")?;
    let mut modules = BTreeMap::new();
    for (path, entry) in object
        .get("modules")
        .and_then(Value::as_object)
        .ok_or("provenance.modules is not an object")?
    {
        let entry = entry.as_object().ok_or("provenance module is not object")?;
        modules.insert(
            path.clone(),
            ModuleProvenance {
                input: require_string(entry.get("input"), "input")?,
                ranges: parse_ranges(entry.get("ranges"), "ranges")?,
                extraction: require_string(entry.get("extraction"), "extraction")?,
                context_ranges: match entry.get("context_ranges") {
                    None | Some(Value::Null) => Vec::new(),
                    other => parse_ranges(other, "context_ranges")?,
                },
            },
        );
    }
    Ok(ParsedProvenance {
        format,
        strategy,
        modules,
    })
}

fn validate_module_set(
    report: &ParsedReport,
    provenance: &ParsedProvenance,
    snapshots: &BTreeMap<String, Vec<u8>>,
    files: &[StagedFile],
) -> Result<(), String> {
    let observed: BTreeSet<&str> = files.iter().map(|f| f.relative_path.as_str()).collect();
    let mut expected: BTreeSet<String> = BTreeSet::from(["provenance.json".to_owned()]);
    let mut registry: BTreeSet<String> = BTreeSet::new();

    for module in &report.modules {
        let path =
            crate::javascript_recovery::publication::normalize_artifact_path(&module.filename);
        if path != module.filename || !is_js_module(&path) {
            return Err(format!("Unsupported module path: {}", module.filename));
        }
        if !registry.insert(path.clone()) {
            return Err(format!("Duplicate module path: {path}"));
        }
        if !observed.contains(path.as_str()) {
            return Err(format!("Missing reported module file: {path}"));
        }
        expected.insert(path.clone());
        let map = format!("{path}.map");
        if observed.contains(map.as_str()) {
            expected.insert(map);
        }
        let entry = provenance.modules.get(&path);
        let source_bytes = entry.and_then(|entry| snapshots.get(&entry.input));
        match (entry, source_bytes) {
            (Some(entry), Some(bytes)) => {
                let mut ranges = entry.ranges.clone();
                ranges.extend(entry.context_ranges.iter().copied());
                validate_ranges(&ranges, bytes, &path)?;
            }
            _ => {
                return Err(format!(
                    "Module provenance does not bind the selected input snapshot: {path}"
                ));
            }
        }
    }

    if provenance.modules.len() != report.modules.len() {
        return Err("Provenance and reported module sets disagree".to_owned());
    }
    for path in observed {
        if !expected.contains(path) {
            return Err(format!("Unreported recovery artifact: {path}"));
        }
    }
    Ok(())
}

fn is_js_module(path: &str) -> bool {
    path.ends_with(".js") || path.ends_with(".mjs") || path.ends_with(".cjs")
}

fn validate_ranges(ranges: &[(u64, u64)], bytes: &[u8], filename: &str) -> Result<(), String> {
    for &(start, end) in ranges {
        let len = bytes.len() as u64;
        if start > end || end > len || !utf8_boundary(bytes, start) || !utf8_boundary(bytes, end) {
            return Err(format!(
                "Invalid half-open UTF-8 byte range [{start},{end}) for {filename}"
            ));
        }
    }
    Ok(())
}

fn utf8_boundary(bytes: &[u8], offset: u64) -> bool {
    match bytes.get(offset as usize) {
        None => true,
        Some(value) => (value & 0xc0) != 0x80,
    }
}

fn parse_ranges(value: Option<&Value>, field: &str) -> Result<Vec<(u64, u64)>, String> {
    let array = value
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{field} is not an array"))?;
    let mut ranges = Vec::with_capacity(array.len());
    for pair in array {
        let pair = pair
            .as_array()
            .filter(|pair| pair.len() == 2)
            .ok_or_else(|| format!("{field} entry is not a pair"))?;
        let start = pair[0].as_u64().ok_or_else(|| format!("{field} start"))?;
        let end = pair[1].as_u64().ok_or_else(|| format!("{field} end"))?;
        ranges.push((start, end));
    }
    Ok(ranges)
}

fn string_array(value: Option<&Value>) -> Result<Vec<String>, String> {
    value
        .and_then(Value::as_array)
        .ok_or("expected a string array".to_owned())?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or("expected a string".to_owned())
        })
        .collect()
}

fn require_string(value: Option<&Value>, field: &str) -> Result<String, String> {
    value
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{field} is not a string"))
}

fn require_nonempty(value: Option<&Value>, field: &str) -> Result<String, String> {
    let text = require_string(value, field)?;
    if text.is_empty() {
        Err(format!("{field} is empty"))
    } else {
        Ok(text)
    }
}

fn require_u64(value: Option<&Value>, field: &str) -> Result<u64, String> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{field} is not a non-negative integer"))
}
