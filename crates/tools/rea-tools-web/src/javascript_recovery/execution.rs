//! Linux execution: launch the engine, validate reports, publish artifacts.
//!
//! Compatibility owners: `src/javascript/recovery/WakaruExecution.ts` and the
//! `WakaruProvider.#recover` workspace setup.
//!
//! This whole path is unreachable on this macOS host: `resolve_wakaru_command`
//! returns the typed capability-unavailable error on any non-Linux/x64 host, so
//! nothing here runs. It is a faithful port of the Linux success/partial path.
//! The actual process launch has a documented limitation: the shared
//! `rea_host::process::launcher` cannot yet select the child environment
//! (`TMPDIR`/`RAYON_NUM_THREADS`/`NO_COLOR`) or report a POSIX terminating
//! signal, both of which this adapter needs. That shared capability is
//! requested in the worker report; until it lands, this path cannot be
//! exercised and remains unverified.

use std::collections::BTreeMap;
use std::path::Path;

use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::SubjectTarget;
use rea_mcp::ToolContext;
use serde_json::{Value, json};

use crate::javascript_recovery::command::{
    CommandRun, ResolvedEngine, WakaruCommandContext, run_wakaru_command,
};
use crate::javascript_recovery::provider::Execution;
use crate::javascript_recovery::publication::publish_wakaru_artifacts;
use crate::javascript_recovery::recovery_files::{
    RecoveryInputSnapshot, fingerprint_recovery_file, inventory_recovery_files, read_recovery_file,
};
use crate::javascript_recovery::release::{
    RECOVERY_LIMITS, WAKARU_PROVIDER_ID, WAKARU_PROVIDER_VERSION_PLACEHOLDER,
};
use crate::javascript_recovery::report::parse_wakaru_reports;
use crate::javascript_recovery::snapshots::snapshot_recovery_inputs;
use crate::javascript_recovery::version::{WakaruVersionAdmission, admit_wakaru_version};
use crate::javascript_recovery::{OPERATION, ParsedInput};

const MODES: [(&str, &str); 3] = [
    ("structural", "strict"),
    ("heuristic", "auto"),
    ("inspection", "inspect"),
];

fn mode_flag(extraction_mode: &str) -> &'static str {
    MODES
        .iter()
        .find(|(mode, _)| *mode == extraction_mode)
        .map(|(_, flag)| *flag)
        .unwrap_or("strict")
}

/// Prepare a private workspace, run Wakaru, publish and bind the result.
pub(crate) fn prepare_wakaru_execution(
    context: &ToolContext<'_>,
    input: &ParsedInput,
    engine: &ResolvedEngine,
) -> Result<Execution, AnalysisError> {
    let root = tempfile::tempdir()
        .map_err(|cause| AnalysisError::output(OPERATION, format!("workspace: {cause}")))?;
    let root_path = root.path().to_string_lossy().into_owned();
    let inputs = Path::new(&root_path).join("inputs");
    let staging = Path::new(&root_path).join("modules");
    std::fs::create_dir(&inputs)
        .and_then(|()| std::fs::create_dir(&staging))
        .map_err(|cause| AnalysisError::output(OPERATION, format!("workspace: {cause}")))?;
    let staging = staging.to_string_lossy().into_owned();

    let sources = snapshot_recovery_inputs(&input.all_paths(), &inputs.to_string_lossy())?;

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(RECOVERY_LIMITS.timeout_ms);
    let command_context = WakaruCommandContext {
        command: engine.command.clone(),
        limiter: engine.limiter.clone(),
        cwd: root_path.clone(),
        deadline,
        cancellation: context.cancellation.clone(),
    };

    // 1. Version probe.
    let version = run_wakaru_command(&command_context, &["--version".to_owned()], None)?;
    let admitted = if version.exit_code == Some(0) {
        admit_wakaru_version(version.stdout.trim())
    } else {
        WakaruVersionAdmission::Unsupported {
            message: format!(
                "Wakaru --version failed; reported version: {}",
                version.stdout.trim()
            ),
        }
    };
    if let WakaruVersionAdmission::Unsupported { message } = &admitted {
        let mismatch = format!("{message}; exit: {:?}", version.exit_code);
        return Err(AnalysisError::capability_unavailable(
            WAKARU_PROVIDER_ID,
            OPERATION,
            format!("{mismatch}; stderr: {}", version.stderr),
        )
        .with_user_message(format!("{mismatch}.")));
    }

    // 2. Recovery run.
    let mut arguments: Vec<String> = sources.iter().map(|s| s.snapshot_path.clone()).collect();
    arguments.push(format!("--unpack={}", mode_flag(&input.extraction_mode)));
    arguments.push(format!("--level={}", input.rewrite_level));
    arguments.push("--provenance".to_owned());
    arguments.push("--emit-source-map".to_owned());
    arguments.push("--json".to_owned());
    arguments.push("-o".to_owned());
    arguments.push(staging.clone());
    let run = run_wakaru_command(&command_context, &arguments, Some(&staging))?;

    // 3. Report + provenance validation.
    let files = inventory_recovery_files(&staging)?;
    let mut snapshots: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for source in &sources {
        snapshots.insert(
            source.snapshot_path.clone(),
            read_recovery_file(&source.snapshot_path, source.bytes)?,
        );
    }
    let provenance_path = Path::new(&staging)
        .join("provenance.json")
        .to_string_lossy()
        .into_owned();
    let parsed = parse_wakaru_reports(&run, &provenance_path, &snapshots, &files)?;

    // 4. Publish and verify identities.
    let result = publish_wakaru_artifacts(
        &input.output_directory,
        &staging,
        input,
        &sources,
        &engine.command,
        &engine.sha256,
        engine.bytes,
        &admitted,
        &parsed,
        &run,
        &context.cancellation,
    )?;

    verify_stable_inputs(&sources)?;
    verify_stable_engine(engine)?;

    let admitted_version = admitted_version_of(&admitted);
    let subject = SubjectTarget {
        path: sources[0].path.clone(),
        sha256: sources[0].sha256.clone(),
        format: "javascript".to_owned(),
        architecture: None,
    };
    let locations = recovery_locations(&sources, &result);
    let limitations = result["limitations"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    Ok(Execution {
        raw_result: json!({
            "version": command_run_value(&version),
            "execution": command_run_value(&run),
            "report": parsed.report_value,
            "provenance": parsed.provenance_value,
        }),
        result,
        provider_id: WAKARU_PROVIDER_ID.to_owned(),
        provider_version: admitted_version,
        limitations,
        locations,
        subject,
    })
}

fn admitted_version_of(admitted: &WakaruVersionAdmission) -> String {
    match admitted {
        WakaruVersionAdmission::Verified { version }
        | WakaruVersionAdmission::Compatible { version, .. } => version.clone(),
        WakaruVersionAdmission::Unsupported { .. } => {
            WAKARU_PROVIDER_VERSION_PLACEHOLDER.to_owned()
        }
    }
}

fn recovery_locations(sources: &[RecoveryInputSnapshot], result: &Value) -> Vec<Value> {
    let mut locations: Vec<Value> = sources
        .iter()
        .map(|source| json!({ "kind": "artifact-path", "path": source.path }))
        .collect();
    if let Some(modules) = result["modules"].as_array() {
        for module in modules {
            if let Some(path) = module["artifact"]["path"].as_str() {
                locations.push(json!({ "kind": "artifact-path", "path": path }));
            }
        }
    }
    locations
}

fn verify_stable_inputs(sources: &[RecoveryInputSnapshot]) -> Result<(), AnalysisError> {
    for source in sources {
        let current = fingerprint_recovery_file(&source.path, RECOVERY_LIMITS.input_bytes, None)?;
        if current.sha256 != source.sha256 || current.bytes != source.bytes {
            return Err(AnalysisError::output(
                OPERATION,
                format!("Original input changed during recovery: {}", source.path),
            ));
        }
    }
    Ok(())
}

fn verify_stable_engine(engine: &ResolvedEngine) -> Result<(), AnalysisError> {
    let current = fingerprint_recovery_file(&engine.command, RECOVERY_LIMITS.output_bytes, None)?;
    if current.sha256 != engine.sha256 {
        return Err(AnalysisError::output(
            OPERATION,
            "Configured engine bytes changed during recovery",
        ));
    }
    Ok(())
}

fn command_run_value(run: &CommandRun) -> Value {
    json!({
        "exit_code": run.exit_code,
        "signal": run.signal,
        "stdout": run.stdout,
        "stderr": run.stderr,
        "command": run.command,
        "arguments": run.arguments,
        "resource_limiter": run.resource_limiter,
    })
}
