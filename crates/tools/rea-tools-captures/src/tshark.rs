//! TShark packet-capture inspection and field discovery.
//!
//! Compatibility owners: `src/application/captures/PacketCaptureService.ts`,
//! `src/captures/TsharkCaptureProvider.ts`, `src/captures/parsePacketOutput.ts`,
//! `src/captures/parseFieldDiscovery.ts` and `src/domain/captures/*`.
use crate::errors::{self, object};
use crate::limits::{BOUNDED_PRODUCER_LIMITS, ProducerLimits};
use crate::producer::{self, Cause, Execution, Phase, ProducerConfig, Request};
use crate::resources::AnalysisResources;
use crate::validation;
use rea_core::analysis_error::AnalysisError;
use rea_mcp::{Registry, ToolContext};
use serde_json::{Map, Value, json};

const CAPTURE: &str = "inspect_packet_capture";
const FIELDS: &str = "inspect_packet_fields";
const FIELD_RECORD_BUDGET: u64 = 8 * 1024 * 1024;

static CONFIG: ProducerConfig = ProducerConfig {
    provider_id: "tshark-capture",
    provider_name: "REA TShark capture adapter",
    provider_version: "tshark@4",
    command_variable: "REA_TSHARK_COMMAND",
    limiter_variable: "REA_TSHARK_PRLIMIT_COMMAND",
    platform_message: "Packet inspection requires Linux with util-linux prlimit and REA_TSHARK_COMMAND so expanded captures are processed under an enforced address-space limit.",
    configure_message: "Supply absolute REA_TSHARK_COMMAND for TShark 4.x.",
    executable_changed: "Configured TShark executable changed during analysis.",
    capability_suffix: " On Linux, configure TShark 4.x through REA_TSHARK_COMMAND and util-linux prlimit through REA_TSHARK_PRLIMIT_COMMAND (default /usr/bin/prlimit).",
    run_prefix: "rea-tshark-",
    root_prefix: "rea-tshark-",
};

/// Session-owned TShark provider: one admitted inspection at a time.
struct Tshark(AnalysisResources);

impl Default for Tshark {
    fn default() -> Self {
        Self(AnalysisResources::new(
            "tshark-capture",
            CAPTURE,
            "A packet inspection is already active; retry after it completes.",
            || json!({ "max_concurrent_inspections": 1 }),
        ))
    }
}

impl rea_mcp::SessionResource for Tshark {
    fn close(&self) -> Result<(), AnalysisError> {
        self.0.close()
    }
}

pub fn register(registry: &mut Registry) {
    registry.handle(CAPTURE, |context, input| {
        inspect_capture(context, &input).into()
    });
    registry.handle(FIELDS, |context, input| {
        inspect_fields(context, &input).into()
    });
}

fn provider(context: &ToolContext<'_>) -> std::sync::Arc<Tshark> {
    let state = context.session.state::<Tshark>();
    context.session.own_once::<Tshark>(state.clone());
    state
}

const CAPTURE_LIMITATIONS: [&str; 5] = [
    "Fields are TShark dissector observations under the selected filter/decode-as/pass settings, not independently verified protocol semantics. Missing fields are absent from the producer output, not known zero or empty values.",
    "Packet limits count input packets before display filtering. Filtered results do not establish whole-capture or device traffic absence. Two-pass reassembly cannot recover bytes missing from the recording or beyond the read limit.",
    "Repeated field values remain ordered string arrays; raw packet bytes are included only when explicitly selected as a supported field. Export index/score metadata are omitted. All stderr, including warnings on exit zero, is retained.",
    "A private empty personal configuration is used. Installed libraries, global configuration and dissector plugins are trusted and not fully fingerprinted. File-only analysis and disabled name resolution do not constitute an OS sandbox.",
    "Linux prlimit enforces soft and hard ceilings before execution, preserving stricter inherited limits: at most 1 GiB address space per process, 64 MiB per file, 30 CPU seconds and no core dumps. Effective limits are reported. Resident input is capped at 32 MiB, each command at 30 wall-clock seconds and combined output at 4 MiB. Output overflow fails. These are per-process/per-file limits, not aggregate memory or filesystem quotas; caller-supplied tools and the limiter are trusted.",
];

const FIELD_LIMITATIONS: [&str; 3] = [
    "Protocol and field registrations describe the selected installation, not traffic observed in a capture. Duplicate abbreviations remain distinct producer records with source line numbers.",
    "Each request probes again without caching. The private empty personal profile does not fingerprint or isolate installed libraries, global configuration or plugins; they remain trusted.",
    "No capture file, interface or device is opened. Resource ceilings do not constitute an OS sandbox. Glossary output is capped at 32 MiB and selected record representation at 8 MiB before expansion.",
];

fn strings(input: &Value, key: &str) -> Vec<String> {
    input
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// `inspectPacketCaptureInputSchema` refinements beyond the advertised schema.
fn validate_capture(input: &Value) -> Result<(), AnalysisError> {
    let fields = strings(input, "fields");
    let decode_as = strings(input, "decode_as");
    let display_filter = input.get("display_filter").and_then(Value::as_str);
    let mut issues = Vec::new();
    for (index, value) in fields.iter().enumerate() {
        validation::argument(&mut issues, &["fields"], Some(index), value);
    }
    if let Some(filter) = display_filter {
        validation::argument(&mut issues, &["display_filter"], None, filter);
    }
    for (index, value) in decode_as.iter().enumerate() {
        validation::argument(&mut issues, &["decode_as"], Some(index), value);
    }
    let within = (|| {
        if fields.len() > 1024 || decode_as.len() > 1024 {
            return false;
        }
        let mut bytes = 0_usize;
        for value in fields.iter().chain(decode_as.iter()) {
            bytes += value.len() + 20;
            if bytes > 32768 {
                return false;
            }
        }
        if let Some(filter) = display_filter {
            bytes += filter.len() + 20;
        }
        bytes <= 32768
    })();
    if !within {
        issues.push(validation::custom(
            &[],
            "Packet selectors exceed the 32 KiB encoded argument budget; reduce fields, decode-as rules or filter text.",
        ));
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(AnalysisError::input(CAPTURE, issues))
    }
}

fn inspect_capture(
    context: &ToolContext<'_>,
    input: &Value,
) -> Result<rea_core::evidence::envelope::Evidence, AnalysisError> {
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(CAPTURE));
    }
    validate_capture(input)?;
    let path = rea_mcp::support::string(input, "path").to_owned();
    if !crate::node::is_absolute(&path) {
        return Err(errors::input_issue(
            CAPTURE,
            vec![errors::segment("path")],
            "invalid_format",
            "Expected an absolute local path.",
        ));
    }
    let provider = provider(context);
    let environment = context.session.environment();
    let execution = provider.0.run(CAPTURE, cancellation, || {
        let mut request = Request::new(
            &CONFIG,
            &provider.0,
            environment,
            cancellation,
            CAPTURE,
            BOUNDED_PRODUCER_LIMITS,
            Some(path.clone()),
            "TShark field glossary",
        );
        let result =
            capture_request(&mut request, input, &path).map_err(|cause| request.failure(cause));
        let identity = CONFIG.provider();
        provider.0.finish(
            result,
            |execution| producer::partial_evidence(CAPTURE, input, &identity, execution),
            CAPTURE,
            cancellation,
        )
    })?;
    producer::evidence(
        CAPTURE,
        input.clone(),
        &CONFIG.provider(),
        execution,
        cancellation,
    )
}

fn configure(request: &mut Request<'_>) -> Result<(), Cause> {
    request.prepare()?;
    let configuration = request.make_directory("configuration")?;
    request
        .overrides
        .push(("WIRESHARK_CONFIG_DIR".to_owned(), configuration));
    request.phase = Phase::Configuration;
    let version = request.probe_version()?;
    let pattern = regex::Regex::new(r"^TShark \(Wireshark\) 4\.[0-9]+\.[0-9]+(?:[ .(\r\n]|$)")
        .expect("static version pattern");
    if !pattern.is_match(version.stdout()) {
        return Err(Cause::raw(
            "Expected TShark 4.x; inspect the selected installation.",
        ));
    }
    Ok(())
}

fn capture_request(
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
    let snapshot_path = request.write_snapshot("capture", &selected.bytes)?;
    request.phase = Phase::Producer;
    let fields = strings(input, "fields");
    let mut arguments = [
        "-n",
        "-r",
        "capture",
        "-T",
        "json",
        "--no-duplicate-keys",
        "--temp-dir=.",
    ]
    .map(str::to_owned)
    .to_vec();
    if input
        .get("two_pass")
        .and_then(Value::as_bool)
        .unwrap_or(true)
    {
        arguments.push("-2".into());
    }
    if let Some(limit) = validation::uint(input, "packet_limit") {
        arguments.push("-c".into());
        arguments.push(limit.to_string());
    }
    if let Some(filter) = input.get("display_filter").and_then(Value::as_str) {
        arguments.push("-Y".into());
        arguments.push(filter.to_owned());
    }
    for value in strings(input, "decode_as") {
        arguments.push("-d".into());
        arguments.push(value);
    }
    let mut selected_fields: Vec<String> = Vec::new();
    for field in std::iter::once("frame.number".to_owned()).chain(fields.iter().cloned()) {
        if !selected_fields.contains(&field) {
            selected_fields.push(field);
        }
    }
    for field in &selected_fields {
        arguments.push("-e".into());
        arguments.push(field.clone());
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
                CAPTURE,
                snapshot_path,
                "TShark changed the private capture copy.",
            ),
            request.captured.as_ref(),
        )
        .into());
    }
    request.phase = Phase::Producer;
    request.resource_path = path.to_owned();
    let matching = parse_packet_output(output.stdout(), &selected_fields)?;
    let offset = validation::uint(input, "match_offset").unwrap_or(0) as usize;
    let start = offset.min(matching.len());
    let end = match validation::uint(input, "match_limit") {
        None => matching.len(),
        Some(limit) => start + (limit as usize).min(matching.len() - start),
    };
    let total = matching.len();
    let packets = matching[start..end].to_vec();
    let returned = packets.len();
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
    report.insert("packets".into(), Value::Array(packets));
    report.insert(
        "output_window".into(),
        object([
            ("matching_packets", json!(total)),
            ("returned_packets", json!(returned)),
            ("has_more", json!(end < total)),
        ]),
    );
    report.insert(
        "read_scope".into(),
        json!(if input.get("packet_limit").is_none_or(Value::is_null) {
            "to-eof"
        } else {
            "up-to-input-packet-limit"
        }),
    );
    report.insert("diagnostics".into(), json!(output.stderr()));
    report.insert("tool".into(), request.tool(&arguments));
    report.insert(
        "configuration".into(),
        json!("private-empty-personal-profile"),
    );
    report.insert("resource_limiter".into(), request.resource_limiter());
    report.insert("limits".into(), Value::Object(request.limits_report()));
    report.insert("hardware_acquisition".into(), json!("not-performed"));
    Ok(Execution {
        result: Value::Object(report),
        subject: producer::file_subject(path, &selected.sha256),
        locations: vec![json!({ "kind": "artifact-path", "path": path })],
        limitations: CAPTURE_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    })
}

/// Zod v4 `invalid_type` issue (`{ expected, code, path, message }`).
fn type_issue(path: Vec<Value>, expected: &str, received: Option<&Value>) -> Value {
    let received = received.map_or("undefined", validation::received_type);
    json!({
        "expected": expected,
        "code": "invalid_type",
        "path": path,
        "message": format!("Invalid input: expected {expected}, received {received}"),
    })
}

/// `frame.number` element: `z.string().regex(/^[1-9][0-9]*$/)`.
fn frame_element_issue(path: Vec<Value>, value: Option<&Value>) -> Option<Value> {
    match value {
        Some(Value::String(text)) => {
            let bytes = text.as_bytes();
            let valid = !bytes.is_empty()
                && (b'1'..=b'9').contains(&bytes[0])
                && bytes.iter().all(u8::is_ascii_digit);
            (!valid).then(|| {
                json!({
                    "origin": "string",
                    "code": "invalid_format",
                    "format": "regex",
                    "pattern": "/^[1-9][0-9]*$/",
                    "path": path,
                    "message": "Invalid string: must match pattern /^[1-9][0-9]*$/",
                })
            })
        }
        other => Some(type_issue(path, "string", other)),
    }
}

/// `producerSchema` (`z.array(z.object({ _source: z.object({ layers }) }))`)
/// issues in Zod v4 emission order; empty when the output conforms.
fn producer_issues(decoded: &Value) -> Vec<Value> {
    let Value::Array(entries) = decoded else {
        return vec![type_issue(Vec::new(), "array", Some(decoded))];
    };
    let mut issues = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let at = |rest: &[Value]| {
            let mut path = vec![json!(index)];
            path.extend_from_slice(rest);
            path
        };
        let Some(entry) = entry.as_object() else {
            issues.push(type_issue(at(&[]), "object", Some(entry)));
            continue;
        };
        let source = entry.get("_source");
        let Some(source) = source.and_then(Value::as_object) else {
            issues.push(type_issue(at(&[json!("_source")]), "object", source));
            continue;
        };
        let layers = source.get("layers");
        let Some(layers) = layers.and_then(Value::as_object) else {
            issues.push(type_issue(
                at(&[json!("_source"), json!("layers")]),
                "object",
                layers,
            ));
            continue;
        };
        let field_path = |key: &str| at(&[json!("_source"), json!("layers"), json!(key)]);
        // Shape key first: `fixedTupleSchema([frameNumber])` with a union rest.
        let frame = layers.get("frame.number");
        match frame {
            Some(Value::Array(values)) => {
                let element = |position: usize| {
                    let mut path = field_path("frame.number");
                    path.push(json!(position));
                    path
                };
                // Rest elements are reported before the positional element,
                // then the length check over the rebuilt (at least one) value.
                for (position, value) in values.iter().enumerate().skip(1) {
                    issues.extend(frame_element_issue(element(position), Some(value)));
                }
                issues.extend(frame_element_issue(element(0), values.first()));
                if values.len() > 1 {
                    issues.push(json!({
                        "origin": "array",
                        "code": "too_big",
                        "maximum": 1,
                        "inclusive": true,
                        "path": field_path("frame.number"),
                        "message": "Too big: expected array to have <=1 items",
                    }));
                }
            }
            other => issues.push(type_issue(field_path("frame.number"), "tuple", other)),
        }
        // Catchall keys in input order: `z.array(z.string())`.
        for (key, value) in layers {
            if key == "frame.number" {
                continue;
            }
            match value {
                Value::Array(values) => {
                    for (position, item) in values.iter().enumerate() {
                        if !item.is_string() {
                            let mut path = field_path(key);
                            path.push(json!(position));
                            issues.push(type_issue(path, "string", Some(item)));
                        }
                    }
                }
                other => issues.push(type_issue(field_path(key), "array", Some(other))),
            }
        }
    }
    issues
}

/// Parse `-T json` output into ordered layers and check frame order/selection.
fn parse_packet_output(text: &str, selected: &[String]) -> Result<Vec<Value>, Cause> {
    let decoded: Value = serde_json::from_str(text)
        .map_err(|error| Cause::raw(validation::json_parse_message(text, &error)))?;
    let issues = producer_issues(&decoded);
    if !issues.is_empty() {
        return Err(Cause::raw(validation::zod_issues(issues)));
    }
    let Value::Array(entries) = decoded else {
        unreachable!("producer_issues rejects a non-array root");
    };
    let mut packets = Vec::with_capacity(entries.len());
    for entry in entries {
        // `_index`/`_score` export metadata are stripped; layers keep the
        // shape key first, then the producer's field order.
        let layers = &entry["_source"]["layers"];
        let mut ordered = Map::new();
        ordered.insert("frame.number".into(), layers["frame.number"].clone());
        if let Some(layers) = layers.as_object() {
            for (key, value) in layers {
                if key != "frame.number" {
                    ordered.insert(key.clone(), value.clone());
                }
            }
        }
        packets.push(Value::Object(ordered));
    }
    let mut previous: u128 = 0;
    for packet in &packets {
        let frame = packet["frame.number"][0]
            .as_str()
            .and_then(|text| text.parse::<u128>().ok())
            .unwrap_or(u128::MAX);
        let unselected = packet.as_object().is_some_and(|layers| {
            layers
                .keys()
                .any(|name| !selected.iter().any(|field| field == name))
        });
        if frame <= previous || unselected {
            return Err(AnalysisError::output(
                CAPTURE,
                "TShark returned unordered frames or unselected fields.",
            )
            .into());
        }
        previous = frame;
    }
    Ok(packets)
}

fn inspect_fields(
    context: &ToolContext<'_>,
    input: &Value,
) -> Result<rea_core::evidence::envelope::Evidence, AnalysisError> {
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(FIELDS));
    }
    let provider = provider(context);
    let environment = context.session.environment();
    let limits = ProducerLimits {
        output_bytes: 32 * 1024 * 1024,
        ..BOUNDED_PRODUCER_LIMITS
    };
    let execution = provider.0.run(FIELDS, cancellation, || {
        let mut request = Request::new(
            &CONFIG,
            &provider.0,
            environment,
            cancellation,
            FIELDS,
            limits,
            None,
            "TShark field glossary",
        );
        let result = fields_request(&mut request, input).map_err(|cause| request.failure(cause));
        let identity = CONFIG.provider();
        provider.0.finish(
            result,
            |execution| producer::partial_evidence(FIELDS, input, &identity, execution),
            FIELDS,
            cancellation,
        )
    })?;
    producer::evidence(
        FIELDS,
        input.clone(),
        &CONFIG.provider(),
        execution,
        cancellation,
    )
}

fn fields_request(request: &mut Request<'_>, input: &Value) -> Result<Execution, Cause> {
    configure(request)?;
    request.phase = Phase::Producer;
    let arguments = vec!["-G".to_owned(), "fields".to_owned()];
    let output = request.execute(&arguments)?;
    let (records, window) = parse_field_discovery(output.stdout(), input)?;
    let mut limits = request.limits_report();
    limits.insert("record_budget_bytes".into(), json!(FIELD_RECORD_BUDGET));
    let mut report = Map::new();
    report.insert("selection".into(), input.clone());
    report.insert("records".into(), Value::Array(records));
    report.insert("output_window".into(), window);
    report.insert("diagnostics".into(), json!(output.stderr()));
    report.insert("tool".into(), request.tool(&arguments));
    report.insert("resource_limiter".into(), request.resource_limiter());
    report.insert("limits".into(), Value::Object(limits));
    report.insert(
        "configuration".into(),
        json!("private-empty-personal-profile"),
    );
    report.insert("hardware_acquisition".into(), json!("not-performed"));
    Ok(Execution {
        result: Value::Object(report),
        subject: producer::file_subject(&request.command, &request.tool_sha256),
        locations: Vec::new(),
        limitations: FIELD_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    })
}

/// TShark -G fields: P/name/abbreviation or F/name/abbreviation/type/parent/base/mask/blurb.
fn parse_field_discovery(text: &str, input: &Value) -> Result<(Vec<Value>, Value), Cause> {
    let kind_protocols = input.get("kind").and_then(Value::as_str) != Some("fields");
    let protocol = input.get("protocol").and_then(Value::as_str);
    let query = crate::node::lowercase(
        input
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let offset = validation::uint(input, "offset").unwrap_or(0);
    let limit = validation::uint(input, "limit").unwrap_or(9_007_199_254_740_991);
    let mut records = Vec::new();
    let (mut examined, mut matching, mut source_line, mut budget) = (0_u64, 0_u64, 0_u64, 0_u64);
    let mut start = 0_usize;
    while start < text.len() {
        let end = text[start..].find('\n').map(|offset| start + offset);
        let mut line = &text[start..end.unwrap_or(text.len())];
        start = end.map_or(text.len(), |end| end + 1);
        source_line += 1;
        if let Some(stripped) = line.strip_suffix('\r') {
            line = stripped;
        }
        let columns = line.split('\t').take(9).collect::<Vec<_>>();
        let tag = columns[0];
        let valid = ((tag == "P" && columns.len() == 3) || (tag == "F" && columns.len() == 8))
            && columns.len() >= 3
            && !columns[2].is_empty();
        if !valid {
            return Err(Cause::raw(format!(
                "Malformed TShark field glossary record at line {source_line}"
            )));
        }
        let (name, abbreviation) = (columns[1], columns[2]);
        let protocol_record = tag == "P";
        if kind_protocols != protocol_record {
            continue;
        }
        examined += 1;
        if let Some(protocol) = protocol {
            let owner = if protocol_record {
                abbreviation
            } else {
                columns[4]
            };
            if owner != protocol {
                continue;
            }
        }
        let mut candidates = vec![name, abbreviation];
        if !protocol_record {
            candidates.push(columns[7]);
        }
        if !candidates
            .iter()
            .any(|value| crate::node::lowercase(value).contains(&query))
        {
            continue;
        }
        matching += 1;
        if matching <= offset || records.len() as u64 >= limit {
            continue;
        }
        budget += line.len() as u64 * 6 + 512;
        if budget > FIELD_RECORD_BUDGET {
            return Err(Cause::Budget {
                message: "Selected glossary records exceed the 8 MiB representation budget; narrow the query or page size".into(),
                limits: json!({ "record_budget_bytes": FIELD_RECORD_BUDGET }),
            });
        }
        let field = |index: usize| {
            if protocol_record {
                Value::Null
            } else {
                json!(columns[index])
            }
        };
        let mut record = Map::new();
        record.insert("source_line".into(), json!(source_line));
        record.insert(
            "kind".into(),
            json!(if protocol_record { "protocol" } else { "field" }),
        );
        record.insert("name".into(), json!(name));
        record.insert("abbreviation".into(), json!(abbreviation));
        record.insert("field_type".into(), field(3));
        record.insert("parent_protocol".into(), field(4));
        record.insert("display_base".into(), field(5));
        record.insert("bitmask".into(), field(6));
        record.insert("description".into(), field(7));
        records.push(Value::Object(record));
    }
    if source_line == 0 {
        return Err(Cause::raw("TShark returned an empty field glossary"));
    }
    let returned = records.len() as u64;
    let window = object([
        ("examined", json!(examined)),
        ("matching", json!(matching)),
        ("returned", json!(returned)),
        (
            "has_more",
            json!(matching.saturating_sub(offset) > returned),
        ),
    ]);
    Ok((records, window))
}

#[allow(dead_code)]
fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::Configuration => "configuration",
        Phase::Artifact => "artifact",
        Phase::Workspace => "workspace",
        Phase::Producer => "producer",
        Phase::Integrity => "integrity",
    }
}
