//! sigrok signal-recording decoding and decoder discovery.
//!
//! Compatibility owners: `src/application/signals/SignalRecordingService.ts`,
//! `src/signals/SigrokRecordingProvider.ts`, `src/signals/parseDecoderDiscovery.ts`,
//! `src/domain/signals/*` and `src/domain/signals/annotationTextWindow.ts`.
use crate::errors::{self, object};
use crate::limits::BOUNDED_PRODUCER_LIMITS;
use crate::producer::{self, Cause, Execution, Phase, ProducerConfig, Request};
use crate::resources::AnalysisResources;
use crate::validation;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::Evidence;
use rea_mcp::{Registry, ToolContext};
use serde_json::{Map, Value, json};

const DECODE: &str = "decode_signal_recording";
const DECODERS: &str = "inspect_signal_decoders";
const LINE_BUDGET: usize = 65536;

static CONFIG: ProducerConfig = ProducerConfig {
    provider_id: "sigrok-recording",
    provider_name: "REA sigrok recording adapter",
    provider_version: "sigrok-cli@0.7.2",
    command_variable: "REA_SIGROK_COMMAND",
    limiter_variable: "REA_SIGROK_PRLIMIT_COMMAND",
    platform_message: "Signal decoding requires Linux with util-linux prlimit and REA_SIGROK_COMMAND so expanded recordings are processed under an enforced address-space limit.",
    configure_message: "Supply absolute REA_SIGROK_COMMAND for sigrok-cli 0.7.2 with libsigrokdecode.",
    executable_changed: "Configured decoder executable changed during analysis.",
    capability_suffix: " On Linux, configure sigrok-cli 0.7.2 through REA_SIGROK_COMMAND and util-linux prlimit through REA_SIGROK_PRLIMIT_COMMAND (default /usr/bin/prlimit).",
    run_prefix: "rea-sigrok-",
    root_prefix: "rea-sigrok-",
};

/// Session-owned sigrok provider: one admitted operation at a time.
struct Sigrok(AnalysisResources);

impl Default for Sigrok {
    fn default() -> Self {
        Self(AnalysisResources::new(
            "sigrok-recording",
            DECODE,
            "A sigrok operation is already active; retry after it completes.",
            || json!({ "max_concurrent_decodes": 1 }),
        ))
    }
}

impl rea_mcp::SessionResource for Sigrok {
    fn close(&self) -> Result<(), AnalysisError> {
        self.0.close()
    }
}

pub fn register(registry: &mut Registry) {
    registry.handle(DECODE, |context, input| decode(context, &input).into());
    registry.handle(DECODERS, |context, input| {
        inspect_decoders(context, &input).into()
    });
}

fn provider(context: &ToolContext<'_>) -> std::sync::Arc<Sigrok> {
    let state = context.session.state::<Sigrok>();
    context.session.own_once::<Sigrok>(state.clone());
    state
}

const DECODE_LIMITATIONS: [&str; 4] = [
    "Annotations are the selected decoder's interpretation of the recorded samples and caller-selected settings, not independently verified protocol semantics. Empty output does not establish absence of traffic.",
    "Sample-number ranges and display text are preserved verbatim, not converted to timestamps or parsed as a lossless byte stream. All producer stderr is retained, including warnings on exit zero.",
    "Only a private copy of the selected file is decoded. Hardware discovery/acquisition and target execution are not requested. Caller-supplied tools, plugins and decoder modules are trusted; this is not an OS sandbox.",
    "Linux prlimit enforces soft and hard ceilings before execution, preserving stricter inherited limits: at most 1 GiB address space per process, 64 MiB per file, 30 CPU seconds and no core dumps. Effective limits are reported. Resident input is capped at 32 MiB, each command at 30 wall-clock seconds and combined output at 4 MiB. Output overflow fails. These are per-process/per-file limits, not aggregate memory or filesystem quotas; caller-supplied tools and the limiter are trusted.",
];

const DISCOVERY_LIMITATIONS: [&str; 3] = [
    "Catalog and help are observed from the selected sigrok installation. Help lines preserve producer descriptions, not a separately validated parameter schema.",
    "Each request probes the installation again; pages do not share a frozen catalog. Decoder modules and libraries are trusted and not fully fingerprinted.",
    "Hardware discovery, recording reads and acquisition are not requested. Linux per-process limits and bounded output apply; this is not an OS sandbox.",
];

/// `decodeSignalRecordingInputSchema` refinements beyond the advertised schema.
fn validate_decode(input: &Value) -> Result<(), AnalysisError> {
    let mut issues = Vec::new();
    let selections = [
        ("decoders", "--protocol-decoders="),
        ("input_format", "--input-format="),
        ("annotations", "--protocol-decoder-annotations="),
    ];
    for (key, _) in selections {
        if let Some(value) = input.get(key).and_then(Value::as_str) {
            validation::argument(&mut issues, &[key], None, value);
        }
    }
    let mut bytes = 0_usize;
    for (key, prefix) in selections {
        if let Some(value) = input.get(key).and_then(Value::as_str) {
            bytes += prefix.len() + value.len() + 9;
        }
    }
    if bytes > 32768 {
        issues.push(validation::custom(
            &[],
            "Signal selectors exceed the 32 KiB encoded argument budget; reduce decoder, format or annotation selections.",
        ));
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(AnalysisError::input(DECODE, issues))
    }
}

fn configure(request: &mut Request<'_>) -> Result<(), Cause> {
    request.prepare()?;
    let version = request.probe_version()?;
    let text = version.stdout();
    let pattern =
        regex::Regex::new(r"^sigrok-cli 0\.7\.2(?:\r?\n|$)").expect("static version pattern");
    if !pattern.is_match(text) || !text.contains("libsigrokdecode") {
        return Err(Cause::raw(
            "Expected sigrok-cli 0.7.2 with libsigrokdecode; inspect the selected installation.",
        ));
    }
    Ok(())
}

fn decode(context: &ToolContext<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(DECODE));
    }
    validate_decode(input)?;
    let path = rea_mcp::support::string(input, "path").to_owned();
    if !crate::node::is_absolute(&path) {
        return Err(errors::input_issue(
            DECODE,
            vec![errors::segment("path")],
            "invalid_format",
            "Expected an absolute local path.",
        ));
    }
    let provider = provider(context);
    let environment = context.session.environment();
    let execution = provider.0.run(DECODE, cancellation, || {
        let mut request = Request::new(
            &CONFIG,
            &provider.0,
            environment,
            cancellation,
            DECODE,
            BOUNDED_PRODUCER_LIMITS,
            Some(path.clone()),
            "sigrok decoder catalog",
        );
        let result =
            decode_request(&mut request, input, &path).map_err(|cause| request.failure(cause));
        let identity = CONFIG.provider();
        provider.0.finish(
            result,
            |execution| producer::partial_evidence(DECODE, input, &identity, execution),
            DECODE,
            cancellation,
        )
    })?;
    producer::evidence(
        DECODE,
        input.clone(),
        &CONFIG.provider(),
        execution,
        cancellation,
    )
}

fn decode_request(
    request: &mut Request<'_>,
    input: &Value,
    path: &str,
) -> Result<Execution, Cause> {
    configure(request)?;
    request.phase = Phase::Artifact;
    let selected = crate::artifact::read_stable(
        path,
        BOUNDED_PRODUCER_LIMITS.input_bytes as usize,
        request.cancellation,
    )?;
    request.phase = Phase::Workspace;
    let snapshot_path = request.write_snapshot("recording", &selected.bytes)?;
    request.phase = Phase::Producer;
    let mut arguments = vec![
        "--dont-scan".to_owned(),
        "--input-file=recording".to_owned(),
        format!(
            "--protocol-decoders={}",
            rea_mcp::support::string(input, "decoders")
        ),
        "--protocol-decoder-samplenum".to_owned(),
    ];
    if let Some(format) = input.get("input_format").and_then(Value::as_str) {
        arguments.push(format!("--input-format={format}"));
    }
    if let Some(annotations) = input.get("annotations").and_then(Value::as_str) {
        arguments.push(format!("--protocol-decoder-annotations={annotations}"));
    }
    let output = request.execute(&arguments)?;
    request.phase = Phase::Integrity;
    request.resource_path = snapshot_path.clone();
    let reread = crate::artifact::read_stable_uncancelled(
        &snapshot_path,
        BOUNDED_PRODUCER_LIMITS.input_bytes as usize,
    )?;
    if reread.sha256 != selected.sha256 {
        return Err(errors::with_output(
            AnalysisError::artifact_changed(
                DECODE,
                snapshot_path,
                "Decoder changed the private recording copy.",
            ),
            request.captured.as_ref(),
        )
        .into());
    }
    request.phase = Phase::Producer;
    request.resource_path = path.to_owned();
    let offset = validation::uint(input, "line_offset").unwrap_or(0);
    let limit = validation::uint(input, "line_limit");
    let (annotations_text, window) = window_annotation_text(output.stdout(), offset, limit);
    let mut report = Map::new();
    report.insert(
        "artifact".into(),
        object([
            ("path", json!(path)),
            ("sha256", json!(selected.sha256)),
            ("bytes", json!(selected.bytes.len())),
        ]),
    );
    report.insert("selection".into(), input.clone());
    report.insert("annotations_text".into(), json!(annotations_text));
    report.insert("output_window".into(), window);
    report.insert("diagnostics".into(), json!(output.stderr()));
    report.insert("tool".into(), request.tool(&arguments));
    report.insert("resource_limiter".into(), request.resource_limiter());
    report.insert("limits".into(), Value::Object(request.limits_report()));
    report.insert("hardware_acquisition".into(), json!("not-performed"));
    Ok(Execution {
        result: Value::Object(report),
        subject: producer::file_subject(path, &selected.sha256),
        locations: vec![json!({ "kind": "artifact-path", "path": path })],
        limitations: DECODE_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    })
}

/// Page literal LF-separated display lines without interpreting annotations.
fn window_annotation_text(text: &str, offset: u64, limit: Option<u64>) -> (String, Value) {
    let (mut total, mut returned) = (0_u64, 0_u64);
    let (mut start, mut end) = (text.len(), text.len());
    let mut from = 0;
    while from < text.len() {
        let next = text[from..]
            .find('\n')
            .map_or(text.len(), |index| from + index + 1);
        if total == offset {
            start = from;
        }
        if total >= offset && limit.is_none_or(|limit| returned < limit) {
            end = next;
            returned += 1;
        }
        total += 1;
        from = next;
    }
    let annotations = if start == 0 && end == text.len() {
        text.to_owned()
    } else {
        text[start..end.max(start)].to_owned()
    };
    let window = object([
        ("total_lines", json!(total)),
        ("returned_lines", json!(returned)),
        ("has_more", json!(offset.min(total) + returned < total)),
    ]);
    (annotations, window)
}

fn inspect_decoders(context: &ToolContext<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(DECODERS));
    }
    let provider = provider(context);
    let environment = context.session.environment();
    let execution = provider.0.run(DECODERS, cancellation, || {
        let mut request = Request::new(
            &CONFIG,
            &provider.0,
            environment,
            cancellation,
            DECODERS,
            BOUNDED_PRODUCER_LIMITS,
            None,
            "sigrok decoder catalog",
        );
        let result = decoders_request(&mut request, input).map_err(|cause| request.failure(cause));
        let identity = CONFIG.provider();
        provider.0.finish(
            result,
            |execution| producer::partial_evidence(DECODERS, input, &identity, execution),
            DECODERS,
            cancellation,
        )
    })?;
    producer::evidence(
        DECODERS,
        input.clone(),
        &CONFIG.provider(),
        execution,
        cancellation,
    )
}

fn decoders_request(request: &mut Request<'_>, input: &Value) -> Result<Execution, Cause> {
    configure(request)?;
    request.phase = Phase::Producer;
    let decoder = input.get("decoder").and_then(Value::as_str);
    let arguments = match decoder {
        None => vec!["--dont-scan".to_owned(), "--list-supported".to_owned()],
        Some(decoder) => vec![
            "--dont-scan".to_owned(),
            format!("--protocol-decoders={decoder}"),
            "--show".to_owned(),
        ],
    };
    let output = request.execute(&arguments)?;
    let (decoders, help_lines, window) = parse_decoder_discovery(output.stdout(), input)?;
    let mut report = Map::new();
    report.insert("selection".into(), input.clone());
    report.insert("decoders".into(), Value::Array(decoders));
    report.insert("help_lines".into(), Value::Array(help_lines));
    report.insert("output_window".into(), window);
    report.insert("diagnostics".into(), json!(output.stderr()));
    report.insert("tool".into(), request.tool(&arguments));
    report.insert("resource_limiter".into(), request.resource_limiter());
    report.insert("limits".into(), Value::Object(request.limits_report()));
    report.insert("hardware_acquisition".into(), json!("not-performed"));
    Ok(Execution {
        result: Value::Object(report),
        subject: producer::file_subject(&request.command, &request.tool_sha256),
        locations: Vec::new(),
        limitations: DISCOVERY_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    })
}

/// Parse only the 0.7.2 catalog grammar; help remains literal producer text.
fn parse_decoder_discovery(
    text: &str,
    input: &Value,
) -> Result<(Vec<Value>, Vec<Value>, Value), Cause> {
    if text
        .bytes()
        .filter(|byte| *byte == b'\n')
        .nth(LINE_BUDGET - 1)
        .is_some()
    {
        return Err(Cause::Budget {
            message: "Decoder discovery exceeds the 65,536-line representation budget".into(),
            limits: json!({ "line_budget": 65536 }),
        });
    }
    let mut lines = split_crlf(text);
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let decoder = input.get("decoder").and_then(Value::as_str);
    let query = crate::node::lowercase(
        input
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let offset = validation::uint(input, "offset").unwrap_or(0) as usize;
    let limit = validation::uint(input, "limit");
    let catalog = decoder.is_none();
    // (id, name) records or (line_number, text) help lines.
    let mut records: Vec<(String, String)> = Vec::new();
    let mut help: Vec<(usize, &str)> = Vec::new();
    match decoder {
        None => {
            let Some(start) = lines
                .iter()
                .position(|line| *line == "Supported protocol decoders:")
            else {
                return Err(Cause::raw("sigrok decoder catalog heading is missing"));
            };
            let pattern = regex::Regex::new(r"^ {2}([a-zA-Z0-9_+-]+) +([^\n\r\u{2028}\u{2029}]+)$")
                .expect("static catalog pattern");
            for line in &lines[start + 1..] {
                if line.is_empty() {
                    continue;
                }
                let captures = pattern.captures(line);
                let Some((id, name)) = captures.as_ref().and_then(|captures| {
                    Some((captures.get(1)?.as_str(), captures.get(2)?.as_str()))
                }) else {
                    return Err(Cause::raw(
                        "Malformed or duplicate sigrok decoder catalog record",
                    ));
                };
                if records.iter().any(|(seen, _)| seen == id) {
                    return Err(Cause::raw(
                        "Malformed or duplicate sigrok decoder catalog record",
                    ));
                }
                records.push((id.to_owned(), name.to_owned()));
            }
            if records.is_empty() {
                return Err(Cause::raw("sigrok returned an empty decoder catalog"));
            }
        }
        Some(decoder) => {
            if lines.first().copied() != Some(format!("ID: {decoder}").as_str()) {
                return Err(Cause::raw(
                    "Decoder help does not identify the selected decoder",
                ));
            }
            help = lines
                .iter()
                .enumerate()
                .map(|(index, line)| (index + 1, *line))
                .collect();
        }
    }
    let (examined, matching): (usize, Vec<Value>) = if catalog {
        (
            records.len(),
            records
                .iter()
                .filter(|(id, name)| {
                    crate::node::lowercase(&format!("{id} {name}")).contains(&query)
                })
                .map(|(id, name)| object([("id", json!(id)), ("name", json!(name))]))
                .collect(),
        )
    } else {
        (
            help.len(),
            help.iter()
                .filter(|(_, line)| crate::node::lowercase(line).contains(&query))
                .map(|(number, line)| {
                    object([("line_number", json!(number)), ("text", json!(line))])
                })
                .collect(),
        )
    };
    let start = offset.min(matching.len());
    let count = limit
        .map_or(matching.len(), |limit| {
            limit.min(usize::MAX as u64) as usize
        })
        .min(matching.len() - start);
    let total = matching.len();
    let page = matching
        .into_iter()
        .skip(start)
        .take(count)
        .collect::<Vec<_>>();
    let window = object([
        (
            "unit",
            json!(if catalog { "decoders" } else { "help-lines" }),
        ),
        ("examined", json!(examined)),
        ("matching", json!(total)),
        ("returned", json!(page.len())),
        ("has_more", json!(start + count < total)),
    ]);
    Ok(if catalog {
        (page, Vec::new(), window)
    } else {
        (Vec::new(), page, window)
    })
}

/// `text.split(/\r?\n/u)`.
fn split_crlf(text: &str) -> Vec<&str> {
    let mut lines = text.split('\n').collect::<Vec<_>>();
    let last = lines.len() - 1;
    for line in &mut lines[..last] {
        *line = line.strip_suffix('\r').unwrap_or(line);
    }
    lines
}
