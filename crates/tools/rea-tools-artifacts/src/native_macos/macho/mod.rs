//! `inspect_macho`: inspect one Mach-O with the required native commands and
//! normalized output (`native-macos` provider).
//!
//! Compatibility owners: `src/native/NativeMacOSProvider.ts` (`#inspectMacho`),
//! `src/native/NativeMachoInspection.ts`, `src/native/AppleMachoSelection.ts`
//! (slice selection helpers reused via `MachoArchitectureSelection.ts`),
//! `src/native/MachoArchitectureSelection.ts`,
//! `src/native/parsers/{otool,dyldInfo,machoUuid,echoedPath,lipo}.ts`,
//! `src/domain/native/nativeInspection.ts` (`inspectMachoSchema`), and
//! `src/server/registerNativeTools.ts` (summary delivery).

mod dyld_info;
mod echoed_path;
mod otool;
mod selection;
mod uuid;

use crate::common::{self, Execution, ProviderCall, native_macos_provider, run_provider_tool};
use crate::lipo::{self, LipoArchitecture};
use crate::native_command;
use crate::native_macos::{self, run_tool};
use dyld_info::{DyldMode, ParsedDyldSymbol, parse_dyld_symbols};
use echoed_path::without_echoed_path_header;
use otool::{ParsedOtool, parse_otool_load_commands};
use rea_analysis::BinaryTarget;
use rea_core::analysis_error::{AnalysisError, CapturedOutput, ErrorKind};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use selection::{
    ArchitectureSelection, select_architecture, selected_architecture_arguments,
    tool_architecture_name,
};
use serde_json::{Value, json};
use std::collections::HashSet;
use uuid::{UuidArchitectureSelection, reconcile_macho_uuid};

const VTOOL_UNAVAILABLE_LIMITATION: &str =
    "vtool is unavailable; build metadata is normalized from otool only.";

/// Bind the native Mach-O inspection tool.
pub(super) fn register(registry: &mut Registry) {
    registry.handle("inspect_macho", inspect_macho);
}

/// `inspect_macho` handler. The delivery-only `detail` is stripped from both
/// the execution and Evidence parameters; `detail: "summary"` delivers the
/// retained summary view.
fn inspect_macho(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let summary = input
        .get("detail")
        .and_then(Value::as_str)
        .is_some_and(|detail| detail == "summary");
    let parameters = common::without_detail(&input);
    run_provider_tool(
        context,
        ProviderCall {
            execution_parameters: parameters.clone(),
            evidence_parameters: Value::Object(parameters),
            summary,
            unavailable: native_macos::unavailable_reason(),
        },
        |target, _parameters| execute_inspect_macho(context, target),
    )
}

/// `NativeMacOSProvider.#inspectMacho`.
fn execute_inspect_macho(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
) -> Result<common::ProviderOutcome, AnalysisError> {
    if !native_macos::is_macho_format(&target.format) {
        return Err(AnalysisError::capability_unavailable(
            native_macos::IDENTITY_ID,
            "inspect_macho",
            "Active artifact is not Mach-O.",
        ));
    }
    let observation = inspect_native_macho(context, target)?;
    let mut execution = Execution::new(observation.result, native_macos_provider());
    execution.limitations = observation.limitations;
    execution.locations = observation.locations;
    Ok(execution.into())
}

/// Observation returned by `inspectNativeMacho`.
struct NativeMachoObservation {
    result: Value,
    limitations: Vec<String>,
    locations: Vec<Value>,
}

/// `inspectNativeMacho(context)`.
fn inspect_native_macho(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
) -> Result<NativeMachoObservation, AnalysisError> {
    let path = target.path.clone();
    // DISCOVERY_COMMANDS: lipo -detailed_info.
    let lipo_capture = run_slice_tool(
        context,
        "lipo",
        &["-detailed_info".to_owned(), path.clone()],
    )?;
    let mut captures: Vec<native_command::NativeCommandCapture> = vec![lipo_capture.clone()];

    let parsed_lipo = lipo::parse_lipo_output(&lipo_capture.stdout, Some(&path))
        .map_err(|reason| AnalysisError::output("inspect_macho", reason))?;
    let architectures = parsed_lipo.architectures;
    let format = parsed_lipo.format;

    let selected_architecture = match select_architecture(target, &architectures) {
        ArchitectureSelection::Absent(architecture) => {
            return Err(AnalysisError::output(
                "inspect_macho",
                format!("lipo did not list {architecture}; refusing to read another slice"),
            ));
        }
        ArchitectureSelection::Selected(architecture) => Some(architecture),
        ArchitectureSelection::Unfiltered => None,
    };
    let selected_ref = selected_architecture.as_deref();

    // vtool knows no variant subtypes, so no spelling selects an arm64e.x1 slice.
    let vtool_selects_slice = match selected_ref {
        None => true,
        Some(architecture) => !tool_architecture_name("vtool", architecture).contains('.'),
    };

    // Slice commands only read the selected artifact. Declared order fixes
    // provenance and which failure is reported, so run them sequentially in
    // the same order the TypeScript `Promise.all` settles them.
    let required_commands: [(&str, &[&str]); 5] = [
        ("otool", &["-h", "-l"]),
        ("nm", &["-gjU", "--no-dyldinfo"]),
        ("dyld_info", &["-imports"]),
        ("dyld_info", &["-exports"]),
        ("dwarfdump", &["--uuid"]),
    ];
    let mut required = Vec::new();
    for (tool, prefix) in required_commands {
        required.push(run_slice_command(
            context,
            &path,
            selected_ref,
            tool,
            prefix,
        )?);
    }

    let optional = if vtool_selects_slice {
        Some(run_slice_command_result(
            context,
            &path,
            selected_ref,
            "vtool",
            &["-show-build"],
        ))
    } else {
        None
    };

    for capture in required {
        captures.push(capture);
    }

    let mut limitations: Vec<String> = Vec::new();
    match optional {
        None => limitations.push(format!(
            "vtool cannot select the {} slice; build metadata is normalized from otool only.",
            selected_ref.unwrap_or("null")
        )),
        Some(Ok(capture)) => captures.push(capture),
        Some(Err(error)) if matches!(error.kind, ErrorKind::CapabilityUnavailable { .. }) => {
            limitations.push(VTOOL_UNAVAILABLE_LIMITATION.to_owned());
        }
        Some(Err(error)) => return Err(error),
    }

    // Locate the nm capture and the second dyld_info (exports) capture.
    let nm_index = captures
        .iter()
        .position(|capture| capture.tool == "nm")
        .ok_or_else(|| AnalysisError::output("inspect_macho", "Missing nm capture"))?;
    let dyld_exports_index = captures
        .iter()
        .enumerate()
        .filter(|(_, capture)| capture.tool == "dyld_info")
        .map(|(index, _)| index)
        .nth(1)
        .ok_or_else(|| {
            AnalysisError::output("inspect_macho", "Missing dyld_info export capture")
        })?;

    // A stripped symbol table can omit names the export trie keeps; only then
    // does llvm-nm's dyld-info pass add names, so rerun it rather than lose them.
    if !names_every_export(&captures[nm_index].stdout, &captures[dyld_exports_index]) {
        let with_dyld_info = run_slice_command(context, &path, selected_ref, "nm", &["-gjU"])?;
        captures[nm_index] = with_dyld_info;
    }

    let otool_index = captures
        .iter()
        .position(|capture| capture.tool == "otool")
        .ok_or_else(|| AnalysisError::output("inspect_macho", "Missing otool capture"))?;
    let otool_slice = slice_output(&captures[otool_index]);
    let load = match parse_otool_load_commands(&otool_slice) {
        Ok(load) => load,
        Err(_cause) => {
            let otool = &captures[otool_index];
            let captured = CapturedOutput {
                stdout: otool.stdout.clone(),
                stderr: otool.stderr.clone(),
                truncated: false,
                stdout_bytes: Some(otool.stdout_bytes as u64),
                stderr_bytes: Some(otool.stderr_bytes as u64),
                exit_code: Some(otool.exit_code),
                signal: Some(otool.signal.clone()),
            };
            return Err(AnalysisError::output(
                "inspect_macho",
                "Malformed otool load-command output",
            )
            .with_captured_output(captured));
        }
    };

    let selected_architecture_name: Option<String> = selected_architecture.clone().or_else(|| {
        if architectures.len() == 1 {
            architectures
                .first()
                .map(|architecture| architecture.name.clone())
        } else {
            None
        }
    });

    // `undefined` (unknown) vs `Some(value)`. We model the TS `undefined`
    // sentinel with `ContainerOffset::Unknown`.
    let container_offset = match &selected_architecture_name {
        None => ContainerOffset::Unknown,
        Some(name) => {
            if format == "thin" {
                ContainerOffset::Known(0)
            } else {
                match architectures
                    .iter()
                    .find(|architecture| &architecture.name == name)
                    .and_then(|architecture| architecture.file_offset)
                {
                    Some(offset) => ContainerOffset::Known(offset),
                    None => ContainerOffset::Unknown,
                }
            }
        }
    };

    let selected_value = json!({
        "name": selected_architecture_name,
        "container_file_offset": match container_offset {
            ContainerOffset::Known(offset) => json!(offset),
            ContainerOffset::Unknown => Value::Null,
        },
    });

    let normalized = normalize_macho(
        &captures,
        target,
        &limitations,
        &load,
        &architectures,
        &path,
        selected_architecture_name.as_deref(),
        selected_value,
    );

    let mut result = normalized.result;
    let mut result_limitations = normalized.limitations;
    if matches!(container_offset, ContainerOffset::Unknown) {
        let extra = if selected_architecture_name.is_none() {
            "The selected Mach-O slice is unknown; slice-based evidence locations are unavailable."
        } else {
            "The selected Mach-O slice's container file offset was not observed; slice-based evidence locations are unavailable."
        };
        result_limitations.push(extra.to_owned());
        if let Some(object) = result.as_object_mut() {
            object.insert(
                "limitations".to_owned(),
                Value::Array(
                    result_limitations
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
    }

    let locations = file_offset_locations(&result, container_offset);

    Ok(NativeMachoObservation {
        result,
        limitations: result_limitations,
        locations,
    })
}

/// The container offset of the selected slice; `Unknown` is the TS `undefined`.
#[derive(Clone, Copy)]
enum ContainerOffset {
    Known(u64),
    Unknown,
}

/// Normalized Mach-O result (`normalizeMacho`) plus its limitations list.
struct NormalizedMacho {
    result: Value,
    limitations: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn normalize_macho(
    captures: &[native_command::NativeCommandCapture],
    target: &BinaryTarget,
    additional_limitations: &[String],
    load: &ParsedOtool,
    architectures: &[LipoArchitecture],
    artifact_path: &str,
    selected_name: Option<&str>,
    selected_value: Value,
) -> NormalizedMacho {
    let imports_capture = capture_lookup(captures, "dyld_info", 0);
    let imports = parse_dyld_symbols(
        &slice_output(imports_capture),
        DyldMode::Imports,
        None,
        &HashSet::new(),
    );

    // Image base: the segment mapping file offset 0 with a non-zero file size.
    let image_base = load
        .segments
        .iter()
        .find(|segment| segment.file_offset == Some(0) && segment.file_size.unwrap_or(0) > 0)
        .and_then(|segment| segment.vm_address.clone());

    let nm_capture = capture_lookup(captures, "nm", 0);
    let nm_exports = parse_nm_exports(&nm_capture.stdout);
    let nm_names: HashSet<String> = nm_exports
        .iter()
        .map(|symbol| symbol.name.clone())
        .collect();

    let dyld_exports_capture = capture_lookup(captures, "dyld_info", 1);
    let dyld_exports = parse_dyld_symbols(
        &slice_output(dyld_exports_capture),
        DyldMode::Exports,
        image_base.as_deref(),
        &nm_names,
    );

    let has_renamed_reexport = dyld_exports
        .iter()
        .any(|symbol| symbol.source_symbol.is_some());

    let exports = unique_symbols(
        dyld_exports
            .iter()
            .cloned()
            .chain(nm_exports.iter().cloned())
            .collect(),
    );

    let dwarfdump_capture = capture_lookup(captures, "dwarfdump", 0);
    let uuid_selection = selected_name.map(|name| UuidArchitectureSelection {
        name: name.to_owned(),
        dwarfdump_name: tool_architecture_name("dwarfdump", name),
    });
    let uuid = reconcile_macho_uuid(
        &load.commands,
        &dwarfdump_capture.stdout,
        artifact_path,
        uuid_selection.as_ref(),
    );

    let provenance: Vec<Value> = captures
        .iter()
        .map(|capture| native_command::invocation(capture, &target.path, "$ARTIFACT"))
        .collect();

    // A thread-state command carries the entrypoint in architecture-specific
    // register state, so an absent decoded offset means unknown, not absent.
    let thread_entrypoint = load.entrypoints.is_empty()
        && load
            .commands
            .iter()
            .any(|command| command.kind == "LC_UNIXTHREAD" || command.kind == "LC_THREAD");
    let thread_entrypoint_limitation = "Thread-state entrypoints (LC_UNIXTHREAD/LC_THREAD) are retained as raw load commands; file offsets are not derived.";

    let exports_dyld_header_offsets = {
        // `/^\s*offset\s+symbol\s*$/m.test(sliceOutput(dyld_info[1]))`.
        let text = slice_output(dyld_exports_capture);
        offset_symbol_header(&text)
    };

    let mut limitations: Vec<String> = Vec::new();
    limitations.push(
        "Imports and exports combine dyld_info and nm; stripped or toolchain-hidden symbols may be absent."
            .to_owned(),
    );
    if captures.iter().any(|capture| capture.tool == "vtool") {
        limitations.push(
            "vtool output is retained as provenance but only otool build metadata is normalized."
                .to_owned(),
        );
    }
    limitations.extend(additional_limitations.iter().cloned());
    limitations.extend(uuid.limitations.iter().cloned());
    if thread_entrypoint {
        limitations.push(thread_entrypoint_limitation.to_owned());
    }
    if image_base.is_none() && exports_dyld_header_offsets {
        limitations.push(
            "Export virtual addresses are unavailable because no file-backed image base was observed."
                .to_owned(),
        );
    }

    // Collection limitations.
    let imports_limitations = vec![
        "dyld_info textual imports may omit chained or toolchain-unsupported metadata.".to_owned(),
    ];
    let mut exports_limitations =
        vec!["Merged nm/dyld_info results may be incomplete for stripped binaries.".to_owned()];
    if has_renamed_reexport {
        exports_limitations.push(
            "Renamed re-exports are listed under their exported name; the source library's symbol name is not reported."
                .to_owned(),
        );
    }
    let entrypoint_limitations = if thread_entrypoint {
        vec![thread_entrypoint_limitation.to_owned()]
    } else {
        Vec::new()
    };

    let result = json!({
        "format": "mach-o",
        "selected_architecture": selected_value,
        "endian": load.endian,
        "word_size": load.word_size,
        "file_type": load.file_type,
        "flags": load.flags,
        "uuid": uuid.value,
        "entrypoints": covered(
            load.entrypoints
                .iter()
                .map(|offset| json!({ "file_offset": offset }))
                .collect(),
            !thread_entrypoint,
            entrypoint_limitations,
        ),
        "architectures": covered(
            architectures.iter().map(LipoArchitecture::to_value).collect(),
            true,
            Vec::new(),
        ),
        "build_metadata": covered(
            load.builds.iter().map(build_to_value).collect(),
            true,
            Vec::new(),
        ),
        "load_commands": covered(
            load.commands.iter().map(load_command_to_value).collect(),
            true,
            Vec::new(),
        ),
        "dependencies": covered(
            load.dependencies.iter().map(dependency_to_value).collect(),
            true,
            Vec::new(),
        ),
        "imports": covered(
            imports.iter().map(symbol_to_value).collect(),
            false,
            imports_limitations,
        ),
        "exports": covered(
            exports.iter().map(symbol_to_value).collect(),
            false,
            exports_limitations,
        ),
        "segments": covered(
            load.segments.iter().map(segment_to_value).collect(),
            true,
            Vec::new(),
        ),
        "provenance": provenance,
        "limitations": limitations.clone(),
    });

    NormalizedMacho {
        result,
        limitations,
    }
}

/// `covered(items, exhaustive, limitations)`.
fn covered(items: Vec<Value>, exhaustive: bool, limitations: Vec<String>) -> Value {
    let total = if exhaustive {
        json!(items.len())
    } else {
        Value::Null
    };
    json!({
        "items": items,
        "total": total,
        "exhaustive": exhaustive,
        "limitations": limitations,
    })
}

fn symbol_to_value(symbol: &ParsedDyldSymbol) -> Value {
    json!({
        "name": symbol.name,
        "address": symbol.address,
        "weak": symbol.weak,
        "reexport": symbol.reexport,
        "source": symbol.source,
    })
}

fn load_command_to_value(command: &otool::LoadCommand) -> Value {
    json!({
        "index": command.index,
        "kind": command.kind,
        "fields": Value::Object(command.fields.clone()),
    })
}

fn dependency_to_value(dependency: &otool::Dependency) -> Value {
    json!({
        "path": dependency.path,
        "kind": dependency.kind,
        "current_version": dependency.current_version,
        "compatibility_version": dependency.compatibility_version,
    })
}

fn build_to_value(build: &otool::BuildMetadata) -> Value {
    json!({
        "platform": build.platform,
        "minimum_os": build.minimum_os,
        "sdk": build.sdk,
        "tools": build
            .tools
            .iter()
            .map(|tool| json!({ "name": tool.name, "version": tool.version }))
            .collect::<Vec<_>>(),
    })
}

fn segment_to_value(segment: &otool::ParsedSegment) -> Value {
    json!({
        "name": segment.name,
        "vm_address": segment.vm_address,
        "vm_size": segment.vm_size,
        "file_offset": segment.file_offset,
        "file_size": segment.file_size,
        "maximum_permissions": segment.maximum_permissions.to_value(),
        "initial_permissions": segment.initial_permissions.to_value(),
        "sections": covered(
            segment.sections.iter().map(section_to_value).collect(),
            true,
            Vec::new(),
        ),
    })
}

fn section_to_value(section: &otool::ParsedSection) -> Value {
    json!({
        "segment": section.segment,
        "name": section.name,
        "address": section.address,
        "size": section.size,
        "file_offset": section.file_offset,
        "alignment": section.alignment,
        "flags": section.flags,
    })
}

/// `parseNmExports(output)`.
fn parse_nm_exports(output: &str) -> Vec<ParsedDyldSymbol> {
    split_lines(output)
        .into_iter()
        .filter(|name| !name.is_empty())
        .map(|name| ParsedDyldSymbol {
            name: name.to_owned(),
            address: None,
            weak: None,
            reexport: None,
            source: Some("nm".to_owned()),
            source_symbol: None,
        })
        .collect()
}

/// `uniqueSymbols(items)`: keep the first occurrence of each name, sorted by
/// Unicode code point.
fn unique_symbols(items: Vec<ParsedDyldSymbol>) -> Vec<ParsedDyldSymbol> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut unique: Vec<ParsedDyldSymbol> = Vec::new();
    for item in items {
        if seen.insert(item.name.clone()) {
            unique.push(item);
        }
    }
    unique.sort_by(|left, right| compare_unicode_code_points(&left.name, &right.name));
    unique
}

/// `compareUnicodeCodePoints`. Rust `str` ordering already compares by Unicode
/// scalar value, matching JavaScript's code-point comparison for valid UTF-8.
fn compare_unicode_code_points(left: &str, right: &str) -> std::cmp::Ordering {
    left.cmp(right)
}

/// `namesEveryExport(nmOutput, dyldExports)`.
fn names_every_export(
    nm_output: &str,
    dyld_exports: &native_command::NativeCommandCapture,
) -> bool {
    let names: HashSet<String> = parse_nm_exports(nm_output)
        .into_iter()
        .map(|symbol| symbol.name)
        .collect();
    slice_output(dyld_exports)
        .split('\n')
        .map(trim_trailing_cr)
        .enumerate()
        .all(|(index, raw_line)| {
            let line = raw_line.trim();
            if line.is_empty()
                || (index == 0 && line.ends_with(':'))
                || is_exports_header(line)
                || is_offset_symbol_line(line)
            {
                return true;
            }
            let rows = parse_dyld_symbols(line, DyldMode::Exports, None, &names);
            // The parser withholds a row only when nm names both of its readings.
            if rows.is_empty() {
                let raw_name = export_line_name(line).unwrap_or_default();
                return names.contains(&raw_name);
            }
            rows.len() == 1 && names.contains(&rows[0].name)
        })
}

fn trim_trailing_cr(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

/// `/^-?exports:$/`.
fn is_exports_header(line: &str) -> bool {
    line == "exports:" || line == "-exports:"
}

/// `/^offset\s+symbol$/` (single line).
fn is_offset_symbol_line(line: &str) -> bool {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^offset\s+symbol$").expect("valid"));
    re.is_match(line)
}

/// `/^\s*offset\s+symbol\s*$/m.test(...)` over multiline text.
fn offset_symbol_header(text: &str) -> bool {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?m)^\s*offset\s+symbol\s*$").expect("valid"));
    re.is_match(text)
}

/// `/^0x[\da-f]+\s+(.+)$/i.exec(line)?.[1]`.
fn export_line_name(line: &str) -> Option<String> {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)^0x[\da-f]+\s+(.+)$").expect("valid"));
    re.captures(line)
        .and_then(|caps| caps.get(1).map(|matched| matched.as_str().to_owned()))
}

/// `captureLookup(captures)(tool, occurrence)`.
fn capture_lookup<'a>(
    captures: &'a [native_command::NativeCommandCapture],
    tool: &str,
    occurrence: usize,
) -> &'a native_command::NativeCommandCapture {
    captures
        .iter()
        .filter(|capture| capture.tool == tool)
        .nth(occurrence)
        .expect("capture present")
}

/// `sliceOutput(capture)`: slice output without the echoed operand path.
fn slice_output(capture: &native_command::NativeCommandCapture) -> String {
    without_echoed_path_header(
        &capture.stdout,
        capture.arguments.last().map(String::as_str),
    )
}

/// `fileOffsetLocations(macho, containerOffset)`.
fn file_offset_locations(result: &Value, container_offset: ContainerOffset) -> Vec<Value> {
    let mut locations = architecture_locations(result);
    let ContainerOffset::Known(offset) = container_offset else {
        return locations;
    };
    if let Some(entrypoints) = result
        .get("entrypoints")
        .and_then(|value| value.get("items"))
        .and_then(Value::as_array)
    {
        for entrypoint in entrypoints {
            if let Some(file_offset) = entrypoint.get("file_offset").and_then(Value::as_u64) {
                locations.push(json!({
                    "kind": "file-offset",
                    "offset": offset + file_offset,
                }));
            }
        }
    }
    if let Some(segments) = result
        .get("segments")
        .and_then(|value| value.get("items"))
        .and_then(Value::as_array)
    {
        for segment in segments {
            let file_offset = segment.get("file_offset").and_then(Value::as_u64);
            let file_size = segment.get("file_size").and_then(Value::as_u64);
            let (Some(file_offset), Some(file_size)) = (file_offset, file_size) else {
                continue;
            };
            if file_size == 0 {
                continue;
            }
            locations.push(json!({
                "kind": "file-offset-range",
                "start": offset + file_offset,
                "end": offset + file_offset + file_size,
            }));
        }
    }
    locations
}

/// `architectureLocations(macho.architectures.items)` working over the JSON
/// result. Mirrors `native_macos::architecture_locations`.
fn architecture_locations(result: &Value) -> Vec<Value> {
    let mut locations = Vec::new();
    let Some(items) = result
        .get("architectures")
        .and_then(|value| value.get("items"))
        .and_then(Value::as_array)
    else {
        return locations;
    };
    for architecture in items {
        let Some(offset) = architecture.get("file_offset").and_then(Value::as_u64) else {
            continue;
        };
        match architecture.get("size").and_then(Value::as_u64) {
            None => locations.push(json!({ "kind": "file-offset", "offset": offset })),
            Some(size) => locations.push(json!({
                "kind": "file-offset-range",
                "start": offset,
                "end": offset + size,
            })),
        }
    }
    locations
}

/// Build the argv for a slice command and run it, returning the typed error.
fn run_slice_command(
    context: &ToolContext<'_>,
    path: &str,
    selected: Option<&str>,
    tool: &str,
    prefix: &[&str],
) -> Result<native_command::NativeCommandCapture, AnalysisError> {
    run_slice_command_result(context, path, selected, tool, prefix)
}

/// Same as `run_slice_command` but keeps the `Result` for optional commands.
fn run_slice_command_result(
    context: &ToolContext<'_>,
    path: &str,
    selected: Option<&str>,
    tool: &str,
    prefix: &[&str],
) -> Result<native_command::NativeCommandCapture, AnalysisError> {
    let mut arguments: Vec<String> = prefix.iter().map(|value| (*value).to_owned()).collect();
    arguments.extend(selected_architecture_arguments(tool, selected));
    arguments.push(path.to_owned());
    run_tool(context, "inspect_macho", tool, &arguments, false)
}

/// Run a discovery command (no `-arch` selection); shares the `inspect_macho`
/// operation name for failure mapping.
fn run_slice_tool(
    context: &ToolContext<'_>,
    tool: &str,
    arguments: &[String],
) -> Result<native_command::NativeCommandCapture, AnalysisError> {
    run_tool(context, "inspect_macho", tool, arguments, false)
}

/// Split on `\n`, trimming an optional trailing `\r` (JS `split(/\r?\n/)`).
fn split_lines(text: &str) -> Vec<&str> {
    text.split('\n').map(trim_trailing_cr).collect()
}
