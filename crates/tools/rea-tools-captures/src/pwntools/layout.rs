//! `inspect_binary_layout`: ELF-specific projection and byte binding.
//!
//! Compatibility owners: `src/application/binaryDiagnostics/BinaryLayoutService.ts`,
//! `src/native/pwntools/PwntoolsLayoutProvider.ts` and
//! `src/domain/native/binaryLayout.ts`.
use crate::pwntools::decoder::{self, DecoderReport, Profile, ProjectContext};
use crate::pwntools::release;
use crate::resources::AnalysisResources;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, Observation, SubjectTarget};
use rea_mcp::{Registry, ToolContext};
use serde_json::{Map, Value, json};

const OPERATION: &str = "inspect_binary_layout";

/// Session-owned layout provider: one admitted inspection at a time.
struct Layout(AnalysisResources);

impl Default for Layout {
    fn default() -> Self {
        Self(AnalysisResources::new(
            release::PROVIDER_ID,
            OPERATION,
            "Provider is closing; create a new inspection service.",
            || json!({ "max_concurrent_inspections": 1 }),
        ))
    }
}

impl rea_mcp::SessionResource for Layout {
    fn close(&self) -> Result<(), AnalysisError> {
        self.0.close()
    }
}

static PROFILE: Profile = Profile {
    operation: OPERATION,
    bridge_dir: "pwntools",
    bridge_script: "layout.py",
    runtime_prefix: "rea-elf-layout-",
    project,
};

pub fn register_binary_layout(registry: &mut Registry) {
    registry.handle(OPERATION, |context, input| inspect(context, &input).into());
}

fn provider(context: &ToolContext<'_>) -> std::sync::Arc<Layout> {
    let state = context.session.state::<Layout>();
    context.session.own_once::<Layout>(state.clone());
    state
}

fn inspect(context: &ToolContext<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(OPERATION));
    }
    let path = rea_mcp::support::string(input, "path").to_owned();
    if !crate::node::is_absolute(&path) {
        return Err(AnalysisError::input(
            OPERATION,
            vec![rea_core::analysis_error::InputIssue {
                path: vec![json!("path")],
                reason: "invalid_format",
                message: Some("Expected an absolute filesystem path on this host.".to_owned()),
                expected: None,
                minimum: None,
                maximum: None,
            }],
        ));
    }

    let provider = provider(context);
    let environment = context.session.environment();
    let report = decoder::inspect(
        &PROFILE,
        &provider.0,
        environment,
        cancellation,
        input,
        &path,
    )?;

    let evidence = build_evidence(input, &report)?;
    if cancellation.reason().is_some() {
        return Err(
            AnalysisError::cancelled(OPERATION).retain_partial_observation(evidence.into_value())
        );
    }

    // detail="summary": record the complete Evidence and project its summary.
    if input.get("detail").and_then(Value::as_str) == Some("summary") {
        context.session.record(&evidence)?;
        let view = rea_application::analysis_view::project(
            evidence.value(),
            &json!({ "kind": "summary" }),
        )
        .map_err(AnalysisError::from)?;
        let value: Value = serde_json::from_str(view.get())
            .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
        return rea_mcp::support::adopt_evidence(value);
    }
    Ok(evidence)
}

/// Build Evidence with the exact TS subject, confidence and locations.
fn build_evidence(input: &Value, report: &DecoderReport) -> Result<Evidence, AnalysisError> {
    // The registration layer strips `detail` before the service, so the
    // Evidence parameters are the parsed `{ path }` input only.
    let parameters = json!({ "path": rea_mcp::support::string(input, "path") });
    let observation = Observation::new(OPERATION, parameters, report.result.clone())
        .confidence(report.confidence)
        .locations(vec![json!({
            "kind": "artifact-path",
            "path": report.result["artifact"]["path"],
        })])
        .limitations(report.limitations.clone());
    rea_mcp::support::evidence(Some(&report.subject), &release::provider(), observation)
}

/// `PwntoolsLayoutProvider.project` plus `BinaryLayoutService` artifact binding.
fn project(context: ProjectContext<'_>) -> Result<DecoderReport, AnalysisError> {
    let payload = context
        .payload
        .as_object()
        .ok_or_else(|| output("ELF reply payload is not an object"))?;

    let sha256 = &context.snapshot.sha256;
    let path = rea_mcp::support::string(context.input, "path");
    let artifact = json!({
        "path": path,
        "sha256": sha256,
        "bytes": context.snapshot.bytes.len(),
    });
    let diagnostics = json!({
        "stdout": context.diagnostics.stdout,
        "stderr": context.diagnostics.stderr,
        "truncated": context.diagnostics.truncated,
    });

    // Rebuild in `binaryLayoutObjectSchema` shape order: artifact, format,
    // architecture, image_type, entry_point, runtime_load_base, sections,
    // segments, symbols, relocations, packed_relative_relocations,
    // relocation_inventory_completeness, linkage, mitigations, diagnostics,
    // limitations.
    let mut report = Map::new();
    report.insert("artifact".into(), artifact);
    for key in [
        "format",
        "architecture",
        "image_type",
        "entry_point",
        "runtime_load_base",
        "sections",
        "segments",
        "symbols",
        "relocations",
        "packed_relative_relocations",
        "relocation_inventory_completeness",
        "linkage",
        "mitigations",
    ] {
        report.insert(
            key.to_owned(),
            payload.get(key).cloned().ok_or_else(|| {
                output(
                    "ELF reply contains invalid source ranges or value meanings: schema mismatch",
                )
            })?,
        );
    }
    report.insert("diagnostics".into(), diagnostics);
    let limitations_value = payload.get("limitations").cloned().ok_or_else(|| {
        output("ELF reply contains invalid source ranges or value meanings: schema mismatch")
    })?;
    report.insert("limitations".into(), limitations_value.clone());

    // Re-validate source ranges and value meanings at the public boundary,
    // exactly like `binaryLayoutSchema.superRefine` before the service re-parse.
    let report_value = Value::Object(report);
    if let Some(message) = crate::pwntools::refine::layout_issues(&report_value) {
        return Err(output_captured(
            &format!("ELF reply contains invalid source ranges or value meanings: {message}"),
            context.diagnostics,
        ));
    }
    let report = match report_value {
        Value::Object(report) => report,
        _ => unreachable!("report is an object"),
    };

    // Bind packed relocation bytes to the snapshot at their original range.
    bind_packed_relocations(&report, &context.snapshot.bytes, context.diagnostics)?;

    let limitations = limitations_value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(DecoderReport {
        result: Value::Object(report),
        subject: SubjectTarget {
            path: path.to_owned(),
            sha256: sha256.to_owned(),
            format: "elf".to_owned(),
            architecture: Some("x86_64".to_owned()),
        },
        confidence: "observed",
        limitations,
    })
}

/// `PwntoolsLayoutProvider.project` packed relocation byte binding.
fn bind_packed_relocations(
    report: &Map<String, Value>,
    bytes: &[u8],
    diagnostics: &rea_core::analysis_error::CapturedOutput,
) -> Result<(), AnalysisError> {
    let Some(tables) = report
        .get("packed_relative_relocations")
        .and_then(Value::as_array)
    else {
        return Ok(());
    };
    for table in tables {
        let offset = hex_to_u64(table.get("location").and_then(|l| l.get("offset")));
        let length = hex_to_u64(table.get("location").and_then(|l| l.get("bytes")));
        let encoded = table
            .get("encoded_bytes_base64")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let (Some(offset), Some(length)) = (offset, length) else {
            return Err(output_captured(
                "Reported packed relocation bytes differ from the selected snapshot at their original file range.",
                diagnostics,
            ));
        };
        let decoded = base64_decode(encoded);
        let start = offset as usize;
        let end = start.saturating_add(length as usize);
        let slice = bytes.get(start..end.min(bytes.len())).unwrap_or(&[]);
        if decoded.as_deref() != Some(slice) || end > bytes.len() {
            return Err(output_captured(
                "Reported packed relocation bytes differ from the selected snapshot at their original file range.",
                diagnostics,
            ));
        }
    }
    Ok(())
}

fn output(reason: &str) -> AnalysisError {
    AnalysisError::output(OPERATION, reason)
}

fn output_captured(
    reason: &str,
    diagnostics: &rea_core::analysis_error::CapturedOutput,
) -> AnalysisError {
    AnalysisError::output(OPERATION, reason).with_captured_output(diagnostics.clone())
}

/// Parse an `unsignedHex` value (`0x...`) to a `u64`.
pub fn hex_to_u64(value: Option<&Value>) -> Option<u64> {
    let text = value?.as_str()?;
    let digits = text.strip_prefix("0x")?;
    u64::from_str_radix(digits, 16).ok()
}

/// Decode canonical base64 (standard alphabet, with padding).
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const INVALID: u8 = 0xFF;
    let value = |byte: u8| -> u8 {
        match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => INVALID,
        }
    };
    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&byte| byte == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut accumulator = 0_u32;
        for &byte in chunk {
            let sextet = if byte == b'=' { 0 } else { value(byte) };
            if byte != b'=' && sextet == INVALID {
                return None;
            }
            accumulator = (accumulator << 6) | u32::from(sextet);
        }
        output.push((accumulator >> 16) as u8);
        if pad < 2 {
            output.push((accumulator >> 8) as u8);
        }
        if pad < 1 {
            output.push(accumulator as u8);
        }
    }
    Some(output)
}
