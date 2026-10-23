//! `inspect_recorded_crash`: supplied Linux ELF core projection.
//!
//! Compatibility owners:
//! `src/application/binaryDiagnostics/RecordedCrashService.ts`,
//! `src/native/pwntools/PwntoolsRecordedCrashProvider.ts`,
//! `src/native/pwntools/RecordedCrashStructureBindings.ts`,
//! `src/native/pwntools/RecordedCrashSourceBindings.ts` and
//! `src/domain/native/recordedCrash.ts`.
use crate::pwntools::decoder::{self, DecoderReport, Profile, ProjectContext};
use crate::pwntools::layout::hex_to_u64;
use crate::pwntools::{pwndbg, release};
use crate::resources::AnalysisResources;
use rea_core::analysis_error::{AnalysisError, CapturedOutput, InputIssue};
use rea_core::evidence::envelope::{Evidence, Observation, SubjectTarget};
use rea_mcp::{Registry, ToolContext};
use serde_json::{Map, Value, json};

const OPERATION: &str = "inspect_recorded_crash";

/// One recorded-core architecture profile (`RECORDED_LINUX_CORE_PROFILES`).
struct Profile2 {
    evidence_architecture: &'static str,
    registers: &'static [&'static str],
    register_bytes: u64,
    register_offset: u64,
    prstatus_bytes: usize,
}

const AMD64_REGISTERS: &[&str] = &[
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
    "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs",
    "gs",
];
const AARCH64_REGISTERS: &[&str] = &[
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30", "sp", "pc", "pstate",
];

fn profile_for(architecture: &str) -> Option<Profile2> {
    match architecture {
        "x86_64-little-endian" => Some(Profile2 {
            evidence_architecture: "x86_64",
            registers: AMD64_REGISTERS,
            register_bytes: 8,
            register_offset: 112,
            prstatus_bytes: 336,
        }),
        "aarch64-little-endian" => Some(Profile2 {
            evidence_architecture: "arm64",
            registers: AARCH64_REGISTERS,
            register_bytes: 8,
            register_offset: 112,
            prstatus_bytes: 392,
        }),
        _ => None,
    }
}

/// Session-owned recorded-crash provider: one admitted inspection at a time.
struct Crash(AnalysisResources);

impl Default for Crash {
    fn default() -> Self {
        Self(AnalysisResources::new(
            release::PROVIDER_ID,
            OPERATION,
            "Provider is closing; create a new inspection service.",
            || json!({ "max_concurrent_inspections": 1 }),
        ))
    }
}

impl rea_mcp::SessionResource for Crash {
    fn close(&self) -> Result<(), AnalysisError> {
        self.0.close()
    }
}

static PROFILE: Profile = Profile {
    operation: OPERATION,
    bridge_dir: "pwntools",
    bridge_script: "recorded_crash.py",
    runtime_prefix: "rea-recorded-crash-",
    project,
};

pub fn register_recorded_crash(registry: &mut Registry) {
    registry.handle(OPERATION, |context, input| inspect(context, &input).into());
}

fn provider(context: &ToolContext<'_>) -> std::sync::Arc<Crash> {
    let state = context.session.state::<Crash>();
    context.session.own_once::<Crash>(state.clone());
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
            vec![InputIssue {
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
    Ok(evidence)
}

fn build_evidence(input: &Value, report: &DecoderReport) -> Result<Evidence, AnalysisError> {
    let observation = Observation::new(OPERATION, input.clone(), report.result.clone())
        .confidence(report.confidence)
        .locations(vec![json!({
            "kind": "artifact-path",
            "path": report.result["artifact"]["path"],
        })])
        .limitations(report.limitations.clone());
    rea_mcp::support::evidence(Some(&report.subject), &release::provider(), observation)
}

fn output(reason: impl Into<String>, diagnostics: &CapturedOutput) -> AnalysisError {
    AnalysisError::output(OPERATION, reason).with_captured_output(diagnostics.clone())
}

/// Build a `CapturedOutput` from an assembled `{ stdout, stderr, truncated }`.
fn captured_from_value(value: &Value) -> CapturedOutput {
    CapturedOutput {
        stdout: value
            .get("stdout")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        stderr: value
            .get("stderr")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        truncated: value
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        stdout_bytes: None,
        stderr_bytes: None,
        exit_code: None,
        signal: None,
    }
}

/// `PwntoolsRecordedCrashProvider.project`.
fn project(context: ProjectContext<'_>) -> Result<DecoderReport, AnalysisError> {
    let payload = context.payload.as_object().cloned().ok_or_else(|| {
        output(
            "Recorded core reply is invalid: schema mismatch",
            context.diagnostics,
        )
    })?;

    let architecture = payload
        .get("architecture")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            output(
                "Recorded core reply is invalid: schema mismatch",
                context.diagnostics,
            )
        })?
        .to_owned();
    let profile = profile_for(&architecture).ok_or_else(|| {
        output(
            "Recorded core reply is invalid: schema mismatch",
            context.diagnostics,
        )
    })?;

    let path = rea_mcp::support::string(context.input, "path").to_owned();
    let sha256 = context.snapshot.sha256.clone();
    let bytes = &context.snapshot.bytes;
    let diagnostics_value = json!({
        "stdout": context.diagnostics.stdout,
        "stderr": context.diagnostics.stderr,
        "truncated": context.diagnostics.truncated,
    });

    // Build the "not-requested" base value in schema key order.
    let base = assemble(
        &payload,
        &path,
        &sha256,
        bytes.len(),
        json!({ "status": "not-requested" }),
        &diagnostics_value,
        &diagnostics_value,
        context.diagnostics,
    )?;

    // Re-validate note links, identities and value meanings at the public
    // boundary, exactly like `recordedCrashSchema.superRefine` before the byte
    // bindings and the service re-parse.
    if let Some(message) = crate::pwntools::refine::recorded_crash_issues(&base) {
        return Err(output(
            format!("Recorded core reply is invalid: {message}"),
            context.diagnostics,
        ));
    }

    // Byte bindings against the recorded snapshot (`project` + structure/source
    // bindings), performed on the not-requested value.
    validate_structure(&base, bytes, context.diagnostics)?;
    validate_note_bytes(&base, bytes, context.diagnostics)?;
    validate_sources(&base, bytes, &profile, &architecture, context.diagnostics)?;
    validate_registers(&base, bytes, context.diagnostics)?;

    let requested = context
        .input
        .get("include_debugger_context")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let (debugger, decoder_diagnostics, diagnostics, confidence) = if !requested {
        (
            json!({ "status": "not-requested" }),
            diagnostics_value.clone(),
            diagnostics_value.clone(),
            "observed",
        )
    } else {
        match enrich(&base, bytes, &architecture, &context) {
            Ok(debugger) => {
                let debugger_diag = debugger.get("diagnostics").cloned().unwrap_or(Value::Null);
                let combined = combine_stage(context.diagnostics, &debugger_diag);
                (debugger, diagnostics_value.clone(), combined, "derived")
            }
            Err(error) => {
                // Retain the basic core evidence as a partial observation.
                let partial = partial_observation(&base);
                return Err(error.retain_partial_observation(partial));
            }
        }
    };

    let result = assemble(
        &payload,
        &path,
        &sha256,
        bytes.len(),
        debugger,
        &decoder_diagnostics,
        &diagnostics,
        context.diagnostics,
    )?;

    // Re-validate the enriched report, exactly like the second
    // `recordedCrashSchema.safeParse` after debugger enrichment.
    if confidence == "derived" {
        if let Some(message) = crate::pwntools::refine::recorded_crash_issues(&result) {
            let combined = captured_from_value(&diagnostics);
            return Err(AnalysisError::output(
                OPERATION,
                format!("Recorded debugger context is invalid: {message}"),
            )
            .with_captured_output(combined)
            .retain_partial_observation(partial_observation(&base)));
        }
    }

    let limitations = result["limitations"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    Ok(DecoderReport {
        result,
        subject: SubjectTarget {
            path,
            sha256,
            format: "elf".to_owned(),
            architecture: Some(profile.evidence_architecture.to_owned()),
        },
        confidence,
        limitations,
    })
}

/// Build the recorded-crash report in `recordedCrashObjectSchema` key order.
#[allow(clippy::too_many_arguments)]
fn assemble(
    payload: &Map<String, Value>,
    path: &str,
    sha256: &str,
    bytes: usize,
    debugger: Value,
    decoder_diagnostics: &Value,
    diagnostics: &Value,
    captured: &CapturedOutput,
) -> Result<Value, AnalysisError> {
    let mut report = Map::new();
    report.insert(
        "artifact".into(),
        json!({ "path": path, "sha256": sha256, "bytes": bytes }),
    );
    for key in [
        "format",
        "architecture",
        "target_execution",
        "live_process_identity",
        "segments",
        "notes",
        "note_padding",
        "threads",
        "signals",
    ] {
        report.insert(
            key.to_owned(),
            payload.get(key).cloned().ok_or_else(|| {
                output("Recorded core reply is invalid: schema mismatch", captured)
            })?,
        );
    }
    report.insert("debugger".into(), debugger);
    report.insert(
        "note_interpretation_completeness".into(),
        payload
            .get("note_interpretation_completeness")
            .cloned()
            .ok_or_else(|| output("Recorded core reply is invalid: schema mismatch", captured))?,
    );
    report.insert("decoder_diagnostics".into(), decoder_diagnostics.clone());
    report.insert("diagnostics".into(), diagnostics.clone());
    report.insert(
        "limitations".into(),
        payload
            .get("limitations")
            .cloned()
            .ok_or_else(|| output("Recorded core reply is invalid: schema mismatch", captured))?,
    );
    Ok(Value::Object(report))
}

/// `{ ...value, debugger: { status: "unavailable", requested: true } }`.
fn partial_observation(base: &Value) -> Value {
    let mut object = base.as_object().cloned().unwrap_or_default();
    object.insert(
        "debugger".into(),
        json!({ "status": "unavailable", "requested": true }),
    );
    Value::Object(object)
}

fn combine_stage(basic: &CapturedOutput, debugger: &Value) -> Value {
    if debugger.is_null() {
        return json!({
            "stdout": basic.stdout,
            "stderr": basic.stderr,
            "truncated": basic.truncated,
        });
    }
    let stdout = debugger
        .get("stdout")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let stderr = debugger
        .get("stderr")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let truncated = debugger
        .get("truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    json!({
        "stdout": format!("[core decoder]\n{}\n[debugger]\n{}", basic.stdout, stdout),
        "stderr": format!("[core decoder]\n{}\n[debugger]\n{}", basic.stderr, stderr),
        "truncated": basic.truncated || truncated,
    })
}

/// Validate authority then run the owned debugger stage.
fn enrich(
    base: &Value,
    bytes: &[u8],
    architecture: &str,
    context: &ProjectContext<'_>,
) -> Result<Value, AnalysisError> {
    if context.cancellation.reason().is_some() {
        return Err(
            AnalysisError::cancelled(OPERATION).with_captured_output(context.diagnostics.clone())
        );
    }
    pwndbg::validate_mapping_authority(base, bytes, context.diagnostics)?;
    let debugger = pwndbg::inspect_core(
        context.environment,
        architecture,
        context.root_path,
        context.diagnostics,
        context.cancellation,
        context.run_command,
    )?;
    Ok(debugger)
}

// ---- Byte bindings ----------------------------------------------------------

fn note_descriptor(note: &Value) -> Option<(u64, u64)> {
    let offset = hex_to_u64(
        note.get("descriptor_location")
            .and_then(|l| l.get("offset")),
    )?;
    let length = hex_to_u64(note.get("descriptor_location").and_then(|l| l.get("bytes")))?;
    Some((offset, length))
}

fn slice<'a>(bytes: &'a [u8], offset: u64, length: u64) -> Option<&'a [u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(length).ok()?)?;
    bytes.get(start..end)
}

/// `validateRecordedCrashStructure` (header/segment/note header binding).
fn validate_structure(
    value: &Value,
    bytes: &[u8],
    diagnostics: &CapturedOutput,
) -> Result<(), AnalysisError> {
    let fail = || {
        output(
            "Reported core structure differs from its original ELF/note headers.",
            diagnostics,
        )
    };
    let architecture = value["architecture"].as_str().unwrap_or_default();
    let expected_machine: u16 = match architecture {
        "x86_64-little-endian" => 62,
        "aarch64-little-endian" => 183,
        _ => return Err(fail()),
    };
    let header = slice(bytes, 0, 64).ok_or_else(fail)?;
    if header[0..6] != [0x7f, 0x45, 0x4c, 0x46, 2, 1]
        || header[6] != 1
        || read_u32(header, 20) != 1
        || !matches!(header[7], 0 | 3)
        || header[8] != 0
        || read_u16(header, 16) != 4
        || read_u16(header, 18) != expected_machine
    {
        return Err(fail());
    }
    let table = read_u64(header, 32);
    let entry_bytes = read_u16(header, 54) as u64;
    let mut count = read_u16(header, 56) as u64;
    if count == 0xffff {
        if read_u16(header, 58) < 64 {
            return Err(fail());
        }
        let extended = slice(bytes, read_u64(header, 40), 64).ok_or_else(fail)?;
        count = read_u32(extended, 44) as u64;
    }
    let segments = value["segments"].as_array().cloned().unwrap_or_default();
    if count != segments.len() as u64 || (count > 0 && entry_bytes < 56) {
        return Err(fail());
    }
    for segment in &segments {
        let index = segment["index"].as_u64().unwrap_or(u64::MAX);
        let offset = table + index * entry_bytes;
        if hex_to_u64(segment.get("header_location").and_then(|l| l.get("offset"))) != Some(offset)
            || hex_to_u64(segment.get("header_location").and_then(|l| l.get("bytes")))
                != Some(entry_bytes)
        {
            return Err(fail());
        }
        let raw = slice(bytes, offset, entry_bytes).ok_or_else(fail)?;
        if !segment_matches(segment, raw) {
            return Err(fail());
        }
    }
    for note in value["notes"].as_array().cloned().unwrap_or_default() {
        let location_offset =
            hex_to_u64(note.get("location").and_then(|l| l.get("offset"))).ok_or_else(fail)?;
        let raw = slice(bytes, location_offset, 12).ok_or_else(fail)?;
        if hex_to_u64(note.get("owner_location").and_then(|l| l.get("bytes")))
            != Some(read_u32(raw, 0) as u64)
            || hex_to_u64(note.get("descriptor_location").and_then(|l| l.get("bytes")))
                != Some(read_u32(raw, 4) as u64)
            || !matches_kind(read_u32(raw, 8), note.get("type"), NOTE_KINDS)
        {
            return Err(fail());
        }
        let owner_offset = hex_to_u64(note.get("owner_location").and_then(|l| l.get("offset")))
            .ok_or_else(fail)?;
        let owner = slice(bytes, owner_offset, read_u32(raw, 0) as u64).ok_or_else(fail)?;
        let terminator = owner.iter().position(|&byte| byte == 0);
        let display = if owner.is_empty() {
            Value::Null
        } else {
            let end = terminator.unwrap_or(owner.len());
            json!(String::from_utf8_lossy(&owner[..end]).into_owned())
        };
        if (!owner.is_empty() && terminator.is_none())
            || note.get("owner_display").cloned().unwrap_or(Value::Null) != display
        {
            return Err(fail());
        }
    }
    Ok(())
}

const SEGMENT_KINDS: &[(u32, &str)] = &[
    (0, "PT_NULL"),
    (1, "PT_LOAD"),
    (2, "PT_DYNAMIC"),
    (3, "PT_INTERP"),
    (4, "PT_NOTE"),
    (5, "PT_SHLIB"),
    (6, "PT_PHDR"),
    (7, "PT_TLS"),
    (0x60000000, "PT_LOOS"),
    (0x6fffffff, "PT_HIOS"),
    (0x6474e550, "PT_GNU_EH_FRAME"),
    (0x6474e551, "PT_GNU_STACK"),
    (0x6474e552, "PT_GNU_RELRO"),
    (0x6474e553, "PT_GNU_PROPERTY"),
];
const NOTE_KINDS: &[(u32, &str)] = &[
    (1, "NT_PRSTATUS"),
    (2, "NT_FPREGSET"),
    (3, "NT_PRPSINFO"),
    (4, "NT_TASKSTRUCT"),
    (6, "NT_AUXV"),
    (0x53494749, "NT_SIGINFO"),
    (0x46494c45, "NT_FILE"),
];

fn matches_kind(raw: u32, reported: Option<&Value>, kinds: &[(u32, &str)]) -> bool {
    let known = kinds
        .iter()
        .find(|(value, _)| *value == raw)
        .map(|(_, name)| *name);
    match reported {
        Some(Value::String(text)) => known == Some(text.as_str()),
        Some(Value::Number(number)) => known.is_none() && number.as_u64() == Some(raw as u64),
        _ => false,
    }
}

fn segment_matches(segment: &Value, raw: &[u8]) -> bool {
    let kind = read_u32(raw, 0);
    matches_kind(kind, segment.get("type"), SEGMENT_KINDS)
        && hex_to_u64(segment.get("flags")) == Some(read_u32(raw, 4) as u64)
        && segment.get("file_backing").and_then(Value::as_str)
            == Some(if kind == 0 || read_u64(raw, 32) == 0 {
                "none"
            } else {
                "file"
            })
        && [
            ("offset", 8),
            ("virtual_address", 16),
            ("physical_address", 24),
            ("file_size", 32),
            ("memory_size", 40),
            ("alignment", 48),
        ]
        .iter()
        .all(|(field, relative)| hex_to_u64(segment.get(*field)) == Some(read_u64(raw, *relative)))
}

/// `project` raw-note and padding byte binding.
fn validate_note_bytes(
    value: &Value,
    bytes: &[u8],
    diagnostics: &CapturedOutput,
) -> Result<(), AnalysisError> {
    let fail = || {
        output(
            "Reported raw note bytes differ from the selected snapshot.",
            diagnostics,
        )
    };
    for note in value["notes"].as_array().cloned().unwrap_or_default() {
        check_bytes(
            note.get("owner_bytes_base64"),
            note.get("owner_location"),
            bytes,
        )
        .ok_or_else(fail)?;
        check_bytes(
            note.get("descriptor_bytes_base64"),
            note.get("descriptor_location"),
            bytes,
        )
        .ok_or_else(fail)?;
    }
    for padding in value["note_padding"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        check_bytes(padding.get("bytes_base64"), padding.get("location"), bytes)
            .ok_or_else(fail)?;
    }
    Ok(())
}

fn check_bytes(raw: Option<&Value>, range: Option<&Value>, bytes: &[u8]) -> Option<()> {
    let encoded = raw?.as_str()?;
    let offset = hex_to_u64(range?.get("offset"))?;
    let length = hex_to_u64(range?.get("bytes"))?;
    let decoded = crate::pwntools::layout::base64_decode(encoded)?;
    let slice = slice(bytes, offset, length)?;
    (decoded == slice).then_some(())
}

/// `validateRecordedCrashSources`: PID/signal and register identity binding.
fn validate_sources(
    value: &Value,
    bytes: &[u8],
    profile: &Profile2,
    architecture: &str,
    diagnostics: &CapturedOutput,
) -> Result<(), AnalysisError> {
    let notes = value["notes"].as_array().cloned().unwrap_or_default();
    let fail_value = || {
        output(
            format!(
                "Reported PID or signal value differs from its recorded {architecture} source bytes."
            ),
            diagnostics,
        )
    };
    let fail_register = || {
        output(
            format!(
                "Reported register source does not match its {architecture} register identity."
            ),
            diagnostics,
        )
    };
    let descriptor = |note_index: usize, minimum: usize| -> Option<(&[u8], u64)> {
        let note = notes.get(note_index)?;
        let (offset, length) = note_descriptor(note)?;
        if (length as usize) < minimum {
            return None;
        }
        Some((slice(bytes, offset, length)?, offset))
    };

    for thread in value["threads"].as_array().cloned().unwrap_or_default() {
        let note_index = thread["note_index"].as_u64().unwrap_or(u64::MAX) as usize;
        let (descriptor_bytes, descriptor_offset) =
            descriptor(note_index, profile.prstatus_bytes).ok_or_else(fail_value)?;
        if thread["historical_pid"].as_i64() != Some(read_i32(descriptor_bytes, 32) as i64)
            || thread["recorded_current_signal"].as_i64()
                != Some(read_i16(descriptor_bytes, 12) as i64)
        {
            return Err(fail_value());
        }
        for register in thread["registers"].as_array().cloned().unwrap_or_default() {
            let name = register["name"].as_str().unwrap_or_default();
            let Some(position) = profile.registers.iter().position(|reg| *reg == name) else {
                return Err(fail_register());
            };
            let expected = descriptor_offset
                + profile.register_offset
                + position as u64 * profile.register_bytes;
            if hex_to_u64(register.get("location").and_then(|l| l.get("offset"))) != Some(expected)
            {
                return Err(fail_register());
            }
        }
    }

    for signal in value["signals"].as_array().cloned().unwrap_or_default() {
        let note_index = signal["note_index"].as_u64().unwrap_or(u64::MAX) as usize;
        let (descriptor_bytes, _) = descriptor(note_index, 32).ok_or_else(fail_value)?;
        let fault = signal.get("fault_address").and_then(Value::as_str);
        let fault_ok = match fault {
            None => true,
            Some(text) => {
                hex_to_u64(Some(&Value::String(text.to_owned())))
                    == Some(read_u64(descriptor_bytes, 16))
            }
        };
        if signal["number"].as_i64() != Some(read_i32(descriptor_bytes, 0) as i64)
            || signal["errno"].as_i64() != Some(read_i32(descriptor_bytes, 4) as i64)
            || signal["code"].as_i64() != Some(read_i32(descriptor_bytes, 8) as i64)
            || !fault_ok
        {
            return Err(fail_value());
        }
    }
    Ok(())
}

/// `project` register value binding against recorded little-endian source.
fn validate_registers(
    value: &Value,
    bytes: &[u8],
    diagnostics: &CapturedOutput,
) -> Result<(), AnalysisError> {
    let fail = || {
        output(
            "Reported register value differs from its recorded source bytes.",
            diagnostics,
        )
    };
    for thread in value["threads"].as_array().cloned().unwrap_or_default() {
        for register in thread["registers"].as_array().cloned().unwrap_or_default() {
            let offset = hex_to_u64(register.get("location").and_then(|l| l.get("offset")))
                .ok_or_else(fail)?;
            let source = slice(bytes, offset, 8).ok_or_else(fail)?;
            let recorded = u64::from_le_bytes(source.try_into().expect("8 bytes"));
            let reported = hex_to_u64(register.get("value")).ok_or_else(fail)?;
            if recorded != reported {
                return Err(fail());
            }
        }
    }
    Ok(())
}

// ---- Little-endian readers --------------------------------------------------

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
fn read_u64(bytes: &[u8], at: usize) -> u64 {
    let mut array = [0_u8; 8];
    array.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(array)
}
fn read_i16(bytes: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn read_i32(bytes: &[u8], at: usize) -> i32 {
    i32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
