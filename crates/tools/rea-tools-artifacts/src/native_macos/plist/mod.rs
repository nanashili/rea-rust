//! `inspect_plist` native macOS tool.
//!
//! Compatibility owners: `src/server/registerNativeTools.ts`,
//! `src/native/NativeMacOSProvider.ts` (`#inspectPlist`, `plutilDiagnostic`),
//! `src/native/NativePlistSource.ts` (source resolution, regular-file
//! admission, source-format classification, failure mapping),
//! `src/native/parsers/plist.ts` and the `src/domain/apple/**` /
//! `src/domain/propertyList*.ts` decoders it imports.

mod json;
mod numbers;
mod scalar;
mod value;
mod xml;

use crate::common::{
    self, Execution, ProviderCall, ProviderOutcome, bundle_info_plist, native_macos_provider,
    source_or_path,
};
use crate::native_command::{self, NATIVE_FAILURE_DIAGNOSTIC_BYTES, bounded_utf8_text};
use rea_analysis::BinaryTarget;
use rea_core::analysis_error::{AnalysisError, CapturedOutput, InputIssue};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::path::{Component, Path, PathBuf};

use super::{IDENTITY_ID, run_tool, unavailable_reason};

/// Shared XML-plist projection used by `inspect_signature` entitlements.
pub(super) use entitlements::parse_entitlements;

/// Bind this tool to its catalog contract.
pub(super) fn register(registry: &mut Registry) {
    registry.handle("inspect_plist", inspect_plist);
}

fn inspect_plist(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let evidence_parameters = input.clone();
    let execution_parameters = common::without_detail(&input);
    common::run_provider_tool(
        context,
        ProviderCall {
            execution_parameters,
            evidence_parameters,
            summary: false,
            unavailable: unavailable_reason(),
        },
        |target, parameters| execute_inspect_plist(context, target, parameters),
    )
}

/// How the plist path was chosen (`NativePlistSelection.origin`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum SelectionOrigin {
    Selected,
    Default,
}

struct PlistSelection {
    path: String,
    origin: SelectionOrigin,
}

fn execute_inspect_plist(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
    parameters: &Map<String, Value>,
) -> Result<ProviderOutcome, AnalysisError> {
    // The provider maps a non-string `path` to AnalysisOutputError.
    let requested = match parameters.get("path") {
        None | Some(Value::Null) => None,
        Some(Value::String(path)) => Some(path.clone()),
        Some(_) => {
            return Err(AnalysisError::output(
                "inspect_plist",
                "path was not a string",
            ));
        }
    };

    let selection = resolve_selection(target, requested.as_deref())?;

    // Shared admission verifies one readable regular file.
    require_regular_plist(&selection)?;

    let classified = run_tool(
        context,
        "inspect_plist",
        "file",
        &["-b".to_owned(), selection.path.clone()],
        false,
    )?;
    let json_capture = run_tool(
        context,
        "inspect_plist",
        "plutil",
        &[
            "-convert".to_owned(),
            "json".to_owned(),
            "-o".to_owned(),
            "-".to_owned(),
            "--".to_owned(),
            selection.path.clone(),
        ],
        true,
    )?;

    let json_decoded = json_capture.exit_code == Some(0);
    // JSON cannot express data, dates, or non-finite reals; plutil rejects
    // such plists, so decode its lossless XML conversion instead. JSON also
    // prints an integral <real> like an <integer>, so a number beyond the
    // exact JSON range takes its element type from the XML conversion.
    let needs_xml = !json_decoded || json::plist_json_needs_number_types(&json_capture.stdout);
    let xml_capture = if needs_xml {
        Some(run_tool(
            context,
            "inspect_plist",
            "plutil",
            &[
                "-convert".to_owned(),
                "xml1".to_owned(),
                "-o".to_owned(),
                "-".to_owned(),
                "--".to_owned(),
                selection.path.clone(),
            ],
            !json_decoded,
        )?)
    } else {
        None
    };

    if let Some(xml_capture) = &xml_capture
        && xml_capture.exit_code != Some(0)
    {
        let (stdout, stdout_truncated) =
            bounded_utf8_text(&xml_capture.stdout, NATIVE_FAILURE_DIAGNOSTIC_BYTES);
        let (stderr, stderr_truncated) =
            bounded_utf8_text(&xml_capture.stderr, NATIVE_FAILURE_DIAGNOSTIC_BYTES);
        let diagnostic = plutil_diagnostic(&stdout, &stderr, &selection.path);
        let captured = CapturedOutput {
            stdout,
            stderr,
            truncated: stdout_truncated || stderr_truncated,
            stdout_bytes: Some(xml_capture.stdout_bytes as u64),
            stderr_bytes: Some(xml_capture.stderr_bytes as u64),
            exit_code: Some(xml_capture.exit_code),
            signal: Some(xml_capture.signal.clone()),
        };
        return Err(unreadable_plist(
            &selection,
            &format!("plutil could not decode it as a property list ({diagnostic})"),
            Some(captured),
        ));
    }

    let parsed = match &xml_capture {
        None => json::parse_plist_json(&json_capture.stdout, None),
        Some(xml_capture) if json_decoded => {
            json::parse_plist_json(&json_capture.stdout, Some(&xml_capture.stdout))
        }
        Some(xml_capture) => json::parse_plist_xml(&xml_capture.stdout),
    }
    .map_err(|reason| AnalysisError::output("inspect_plist", reason))?;

    let mut provenance = vec![native_command::invocation(
        &classified,
        &selection.path,
        "$PLIST",
    )];
    provenance.push(native_command::invocation(
        &json_capture,
        &selection.path,
        "$PLIST",
    ));
    if let Some(xml_capture) = &xml_capture {
        provenance.push(native_command::invocation(
            xml_capture,
            &selection.path,
            "$PLIST",
        ));
    }

    let format = plist_source_format(&classified.stdout, &selection)?;

    let result = json!({
        "format": format,
        "value": parsed.value,
        "bundle": parsed.bundle,
        "source_path": selection.path,
        "provenance": provenance,
        "limitations": parsed.limitations,
    });

    let mut execution = Execution::new(result, native_macos_provider());
    execution.limitations = parsed.limitations.clone();
    execution.locations = vec![json!({ "kind": "artifact-path", "path": selection.path })];
    Ok(execution.into())
}

/// `resolveNativePlistSelection(target, requested)`.
fn resolve_selection(
    target: &BinaryTarget,
    requested: Option<&str>,
) -> Result<PlistSelection, AnalysisError> {
    if let Some(requested) = requested
        && Path::new(requested).is_absolute()
    {
        return Ok(PlistSelection {
            path: normalize_path(Path::new(requested)),
            origin: SelectionOrigin::Selected,
        });
    }
    if requested.is_none() && target.kind == "artifact" && target.format == "plist" {
        return Ok(PlistSelection {
            path: target.path.clone(),
            origin: SelectionOrigin::Selected,
        });
    }
    let source = source_or_path(target).to_owned();
    let metadata = std::fs::symlink_metadata(&source).or_else(|_| std::fs::metadata(&source));
    let metadata = match metadata {
        Ok(metadata) => metadata,
        Err(cause) => {
            // `stat` failure maps to a provider-adapter error, not a file verdict.
            return Err(provider_adapter_cause("inspect_plist", &cause.to_string()));
        }
    };
    let root = if metadata.is_dir() {
        PathBuf::from(&source)
    } else {
        macos_bundle_root(&target.path).unwrap_or_else(|| parent_dir(&target.path))
    };
    if let Some(requested) = requested {
        return Ok(PlistSelection {
            path: normalize_path(&root.join(requested)),
            origin: SelectionOrigin::Selected,
        });
    }
    let path = match bundle_info_plist(target) {
        Some(plist) => plist.to_owned(),
        None => normalize_path(&root.join("Contents/Info.plist")),
    };
    Ok(PlistSelection {
        path,
        origin: SelectionOrigin::Default,
    })
}

/// `macOSBundleRoot(path)`.
fn macos_bundle_root(path: &str) -> Option<PathBuf> {
    let programs = Path::new(path).parent()?;
    let contents = programs.parent()?;
    if programs.file_name().and_then(|name| name.to_str()) == Some("MacOS")
        && contents.file_name().and_then(|name| name.to_str()) == Some("Contents")
    {
        contents.parent().map(Path::to_path_buf)
    } else {
        None
    }
}

fn parent_dir(path: &str) -> PathBuf {
    Path::new(path)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `path.resolve(...)` lexical normalization without touching the filesystem.
fn normalize_path(path: &Path) -> String {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized.to_string_lossy().into_owned()
}

/// `requireRegularPlist`: verify one readable regular descriptor.
fn require_regular_plist(selection: &PlistSelection) -> Result<(), AnalysisError> {
    match std::fs::metadata(&selection.path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(unreadable_plist(
            selection,
            "it is not a regular file",
            None,
        )),
        Err(cause) => Err(map_plist_file_error(selection, &cause)),
    }
}

/// Map a filesystem error on the selected plist to the TypeScript verdict.
fn map_plist_file_error(selection: &PlistSelection, cause: &std::io::Error) -> AnalysisError {
    use std::io::ErrorKind;
    match cause.kind() {
        ErrorKind::NotFound => unreadable_plist(selection, "no file exists there", None),
        ErrorKind::PermissionDenied => {
            AnalysisError::access_denied("inspect_plist", selection.path.clone(), "EACCES")
        }
        _ => {
            // ENOTDIR surfaces as "no file exists there" like the TS mapping.
            #[cfg(unix)]
            if cause.raw_os_error() == Some(libc::ENOTDIR) {
                return unreadable_plist(selection, "no file exists there", None);
            }
            provider_adapter_cause("inspect_plist", &cause.to_string())
        }
    }
}

/// `unreadablePlist(selection, reason, options)`.
fn unreadable_plist(
    selection: &PlistSelection,
    reason: &str,
    captured: Option<CapturedOutput>,
) -> AnalysisError {
    let sentence = if reason.ends_with('.') {
        reason.to_owned()
    } else {
        format!("{reason}.")
    };
    let path = &selection.path;
    match selection.origin {
        SelectionOrigin::Default => {
            let message = format!(
                "The target has no readable default plist at {path}: {sentence} Select another plist in the target with the path input (CLI: --relative-path)."
            );
            let mut error = AnalysisError::capability_unavailable(
                IDENTITY_ID,
                "inspect_plist",
                message.clone(),
            )
            .with_user_message(message);
            if let Some(captured) = captured {
                error = error.with_captured_output(captured);
            }
            error
        }
        SelectionOrigin::Selected => {
            let mut error = AnalysisError::input(
                "inspect_plist",
                vec![InputIssue {
                    path: vec![json!("path")],
                    reason: "invalid_value",
                    message: Some(format!("Cannot inspect {path}: {sentence}")),
                    expected: None,
                    minimum: None,
                    maximum: None,
                }],
            );
            if let Some(captured) = captured {
                error = error.with_captured_output(captured);
            }
            error
        }
    }
}

fn provider_adapter_cause(operation: &str, reason: &str) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert("phase".into(), json!("plist-file"));
    diagnostics.insert("reason".into(), json!(reason));
    AnalysisError::provider_adapter(IDENTITY_ID, operation).with_diagnostics(diagnostics)
}

/// `plistSourceFormat(description, input)`.
fn plist_source_format(
    description: &str,
    selection: &PlistSelection,
) -> Result<&'static str, AnalysisError> {
    let lower = description.to_ascii_lowercase();
    if lower.contains("binary property list") {
        return Ok("binary");
    }
    if contains_word(&lower, "xml") {
        return Ok("xml");
    }
    if contains_word(&lower, "json") {
        return Ok("json");
    }
    if !contains_word(&lower, "text") {
        return Ok("unknown");
    }
    classify_text_markup(selection)
}

/// Read the leading bytes and classify text that `file` reported generically.
fn classify_text_markup(selection: &PlistSelection) -> Result<&'static str, AnalysisError> {
    const PROBE_BYTES: usize = 4096;
    let mut head = match std::fs::read(&selection.path) {
        Ok(bytes) => bytes,
        Err(cause) => return Err(map_plist_file_error(selection, &cause)),
    };
    head.truncate(PROBE_BYTES);
    let text = decode_probe(&head);
    let trimmed = text.trim_start();
    Ok(if looks_like_xml_markup(trimmed) {
        "xml"
    } else {
        "unknown"
    })
}

/// Decode the markup probe using the BOM-selected encoding, UTF-8 by default.
fn decode_probe(head: &[u8]) -> String {
    match head {
        [0xff, 0xfe, ..] => decode_utf16(&head[2..], false),
        [0xfe, 0xff, ..] => decode_utf16(&head[2..], true),
        _ => String::from_utf8_lossy(head).into_owned(),
    }
}

fn decode_utf16(bytes: &[u8], big_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            if big_endian {
                u16::from_be_bytes([pair[0], pair[1]])
            } else {
                u16::from_le_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

/// `/^<(?:[!?]|(?:plist|dict|array|string|integer|real|data|date|true|false)[\s/>])/`
fn looks_like_xml_markup(text: &str) -> bool {
    let Some(rest) = text.strip_prefix('<') else {
        return false;
    };
    if rest.starts_with('!') || rest.starts_with('?') {
        return true;
    }
    for tag in [
        "plist", "dict", "array", "string", "integer", "real", "data", "date", "true", "false",
    ] {
        if let Some(after) = rest.strip_prefix(tag)
            && matches!(after.chars().next(), Some(character) if character.is_whitespace() || character == '/' || character == '>')
        {
            return true;
        }
    }
    false
}

/// Case-insensitive word-boundary match for the lower-cased `file` description.
fn contains_word(haystack: &str, word: &str) -> bool {
    let mut start = 0;
    while let Some(relative) = haystack[start..].find(word) {
        let index = start + relative;
        let before = index == 0
            || !haystack[..index]
                .chars()
                .next_back()
                .is_some_and(|character| character.is_alphanumeric());
        let after_index = index + word.len();
        let after = after_index == haystack.len()
            || !haystack[after_index..]
                .chars()
                .next()
                .is_some_and(|character| character.is_alphanumeric());
        if before && after {
            return true;
        }
        start = index + word.len();
    }
    false
}

/// `plutilDiagnostic(capture, path)`.
fn plutil_diagnostic(stdout: &str, stderr: &str, path: &str) -> String {
    let prefix = format!("{path}: ");
    let diagnostics: Vec<String> = [stderr, stdout]
        .into_iter()
        .map(|stream| {
            let text = stream.trim();
            text.strip_prefix(&prefix).unwrap_or(text).to_owned()
        })
        .filter(|text| !text.is_empty())
        .collect();
    if diagnostics.is_empty() {
        "plutil printed no diagnostic".to_owned()
    } else {
        diagnostics.join("\n")
    }
}

/// Entitlements XML projection, reused by `inspect_signature`.
mod entitlements {
    use super::json;
    use super::numbers::PlistNumberProjection;
    use super::value::{
        negative_zero_real_limitation, non_finite_real_limitation, unknown_date_limitation,
        unknown_scalar_limitation,
    };
    use super::xml;
    use serde_json::Value;

    /// Result of `parseEntitlements(output)`.
    pub(in crate::native_macos) struct ParsedEntitlements {
        pub value: Value,
        pub omitted_prototype_keys: usize,
        pub limitations: Vec<String>,
    }

    /// `parseEntitlements(output)`: project the entitlements XML plist codesign
    /// prints to stdout, framed by `<?xml` and `</plist>`.
    pub(in crate::native_macos) fn parse_entitlements(output: &str) -> ParsedEntitlements {
        let Some(start) = output.find("<?xml") else {
            return empty();
        };
        let Some(end) = output.rfind("</plist>") else {
            return empty();
        };
        if end < start {
            return empty();
        }
        let slice = &output[start..end + "</plist>".len()];
        let decoded = match xml::decode_xml_property_list(slice) {
            Ok(decoded) => decoded,
            // The TypeScript decoder would throw and be caught by the provider
            // output-failure boundary; an undecodable entitlements blob there is
            // surfaced as a native output failure, matching that behavior.
            Err(_) => return empty(),
        };
        let projected = match json::project_node(&decoded.value) {
            Ok(projected) => projected,
            Err(_) => return empty(),
        };
        let mut projection = PlistNumberProjection::new(decoded.number_literals);
        let value = projection.project(projected.value);
        let mut limitations = projection.limitations();
        if projected.non_finite_real_count != 0 {
            limitations.push(non_finite_real_limitation(projected.non_finite_real_count));
        }
        if projected.negative_zero_real_count != 0 {
            limitations.push(negative_zero_real_limitation(
                projected.negative_zero_real_count,
            ));
        }
        if projected.unknown_date_count != 0 {
            limitations.push(unknown_date_limitation(projected.unknown_date_count));
        }
        if projected.unknown_scalar_count != 0 {
            limitations.push(unknown_scalar_limitation(projected.unknown_scalar_count));
        }
        ParsedEntitlements {
            value,
            omitted_prototype_keys: decoded.omitted_prototype_keys,
            limitations,
        }
    }

    fn empty() -> ParsedEntitlements {
        ParsedEntitlements {
            value: Value::Null,
            omitted_prototype_keys: 0,
            limitations: Vec::new(),
        }
    }
}

/// `omittedPrototypeKeysLimitation(count)`, reused by the signature family.
pub(super) fn omitted_prototype_keys_limitation(count: usize) -> String {
    json::omitted_prototype_keys_limitation(count)
}
