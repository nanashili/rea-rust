//! `inspect_signature` native macOS tool.
//!
//! Compatibility owners: `src/native/NativeMacOSProvider.ts`
//! (`#inspectSignature`, `#inspectBoundSignature`, `#inspectMixedSignatureSlices`,
//! `#captureSignature`, `isNonzeroUnsignedObservation`, `codeSignCaptureFailure`,
//! `translateCodeSignExitFailure`, `codeSignArchitectures`, `canonicalPath`),
//! `src/native/SignatureTargetBinding.ts` and `src/native/parsers/codesign.ts`.

mod binding;

use crate::common::{self, Execution, ProviderCall, ProviderOutcome, native_macos_provider};
use crate::native_command::{
    self, FailureCapture, FailureReason, NATIVE_FAILURE_DIAGNOSTIC_BYTES, NativeCommandCapture,
    NativeCommandFailure, bounded_utf8_text,
};
use rea_analysis::BinaryTarget;
use rea_core::analysis_error::AnalysisError;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use regex::Regex;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::OnceLock;

use super::plist::{omitted_prototype_keys_limitation, parse_entitlements};
use super::{IDENTITY_ID, is_macho_format, run_tool, unavailable_reason};

use binding::{SignatureCleanup, SignatureTargetBinding, canonical_path, verify_signature_target};

const OPERATION: &str = "inspect_signature";

/// Bind this tool to its catalog contract.
pub(super) fn register(registry: &mut Registry) {
    registry.handle("inspect_signature", inspect_signature);
}

fn inspect_signature(context: &ToolContext<'_>, input: Value) -> ToolOutput {
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
        |target, _parameters| execute_inspect_signature(context, target),
    )
}

fn execute_inspect_signature(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
) -> Result<ProviderOutcome, AnalysisError> {
    // Signature inspection covers Mach-O code signatures only. On another
    // container, codesign's "not signed" verdict cannot see a format-level
    // signature, so reporting it would claim unsigned for an unevaluated layer.
    if target.kind != "executable" || !is_macho_format(&target.format) {
        return Err(AnalysisError::capability_unavailable(
            IDENTITY_ID,
            OPERATION,
            "Active artifact is not Mach-O; its container-level signature layer is not evaluated by codesign.",
        ));
    }

    let cleanup = context.session.state::<SignatureCleanup>();
    context.session.own_once(cleanup.clone());

    let (result, limitations) =
        binding::with_signature_target(target, &cleanup, &context.cancellation, |bound| {
            inspect_bound_signature(context, target, bound)
        })?;

    let mut execution = Execution::new(result, native_macos_provider());
    execution.limitations = limitations;
    Ok(execution.into())
}

/// `#inspectBoundSignature(binding)`.
fn inspect_bound_signature(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
    bound: &SignatureTargetBinding,
) -> Result<(Value, Vec<String>), AnalysisError> {
    let display = capture_signature(context, target, bound, &["-d", "--verbose=4"])?;
    let unsigned = is_nonzero_unsigned_observation(&display);
    if let Some(failure) = code_sign_capture_failure(&display) {
        return Err(failure);
    }

    let requirements = capture_signature(context, target, bound, &["-d", "-r-"])?;
    if let Some(failure) = code_sign_capture_failure(&requirements) {
        return Err(failure);
    }

    let entitlements = capture_signature(context, target, bound, &["-d", "--entitlements", ":-"])?;
    if let Some(failure) = code_sign_capture_failure(&entitlements) {
        return Err(failure);
    }

    // codesign echoes the resolved executable path in its diagnostics.
    let mut executable_paths = vec![bound.snapshot_path.clone()];
    executable_paths.extend(canonical_path(&bound.snapshot_path));
    let parsed = parse_code_signature(&display.stderr, unsigned, &executable_paths);

    // The requirement is printed to stdout; stderr echoes the path.
    let requirement_text = designated_requirement(&requirements.stdout);
    // Entitlements XML is printed to stdout; stderr echoes the path.
    let entitlement_value = parse_entitlements(&entitlements.stdout);

    let mut captures = vec![display.clone(), requirements.clone(), entitlements.clone()];
    let mut limitations: Vec<String> = Vec::new();
    limitations.extend(parsed.limitations.iter().cloned());
    limitations.extend(
        entitlement_value
            .limitations
            .iter()
            .map(|note| format!("Entitlements: {note}")),
    );
    limitations.push(
        "Inspected a digest-verified Mach-O byte snapshot; filesystem-bound signing context and trust validation are not examined.".to_owned(),
    );
    if entitlement_value.omitted_prototype_keys != 0 {
        limitations.push(format!(
            "Entitlements: {}",
            omitted_prototype_keys_limitation(entitlement_value.omitted_prototype_keys)
        ));
    }

    let mixed_signing = !unsigned
        && (is_nonzero_unsigned_observation(&requirements)
            || is_nonzero_unsigned_observation(&entitlements));
    if mixed_signing {
        let slices = inspect_mixed_signature_slices(
            context,
            target,
            bound,
            parsed.format.as_deref(),
            requirements.exit_code,
            entitlements.exit_code,
        )?;
        captures.extend(slices.captures);
        limitations.extend(slices.limitations);
    }

    let provenance: Vec<Value> = captures
        .iter()
        .map(|capture| native_command::invocation(capture, &bound.snapshot_path, "$ARTIFACT"))
        .collect();

    // Reject target drift one last time before committing the result.
    verify_signature_target(target, bound, &context.cancellation)?;

    let result = json!({
        "signed": parsed.signed,
        "identifier": parsed.identifier,
        "team_identifier": parsed.team_identifier,
        "format": parsed.format,
        "cdhashes": parsed.cdhashes,
        "hash_algorithms": parsed.hash_algorithms,
        "authorities": parsed.authorities,
        "designated_requirement": requirement_text,
        "entitlements": entitlement_value.value,
        "timestamp": parsed.timestamp,
        "hardened_runtime": parsed.hardened_runtime,
        "provenance": provenance,
        "limitations": limitations.clone(),
    });
    Ok((result, limitations))
}

struct MixedSlices {
    captures: Vec<NativeCommandCapture>,
    limitations: Vec<String>,
}

/// `#inspectMixedSignatureSlices(...)`.
fn inspect_mixed_signature_slices(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
    bound: &SignatureTargetBinding,
    format: Option<&str>,
    requirements_exit: Option<i64>,
    entitlements_exit: Option<i64>,
) -> Result<MixedSlices, AnalysisError> {
    let mut captures = Vec::new();
    let mut unsigned: Vec<String> = Vec::new();
    let mut unclassified: Vec<String> = Vec::new();
    for architecture in code_sign_architectures(format, target) {
        let slice = capture_signature(
            context,
            target,
            bound,
            &["-d", "-a", &architecture, "--verbose=4"],
        )?;
        captures.push(slice.clone());
        if slice.exit_code == Some(0) {
            continue;
        }
        if is_nonzero_unsigned_observation(&slice) {
            unsigned.push(architecture);
        } else {
            unclassified.push(architecture);
        }
    }
    let mut limitations = vec![if !unsigned.is_empty() {
        format!("Unsigned Mach-O slices: {}.", unsigned.join(", "))
    } else {
        "One or more Mach-O slices are unsigned, but their architectures could not be classified."
            .to_owned()
    }];
    if !unclassified.is_empty() {
        limitations.push(format!(
            "Signature state could not be classified for Mach-O slices: {}.",
            unclassified.join(", ")
        ));
    }
    if requirements_exit != Some(0) {
        limitations.push(
            "The aggregate designated requirement is unavailable because Mach-O slices have mixed signing states."
                .to_owned(),
        );
    }
    if entitlements_exit != Some(0) {
        limitations.push(
            "The aggregate entitlements are unavailable because Mach-O slices have mixed signing states."
                .to_owned(),
        );
    }
    Ok(MixedSlices {
        captures,
        limitations,
    })
}

/// `#captureSignature(binding, args)`: verify the target before and after the
/// codesign capture so a later capture never reads another version.
fn capture_signature(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
    bound: &SignatureTargetBinding,
    args: &[&str],
) -> Result<NativeCommandCapture, AnalysisError> {
    verify_signature_target(target, bound, &context.cancellation)?;
    let mut arguments: Vec<String> = args.iter().map(|argument| (*argument).to_owned()).collect();
    arguments.push(bound.snapshot_path.clone());
    let capture = run_tool(context, OPERATION, "codesign", &arguments, true);
    // Verify after too: a disappearing target is not a codesign failure.
    verify_signature_target(target, bound, &context.cancellation)?;
    capture
}

/// `isNonzeroUnsignedObservation(capture)`.
fn is_nonzero_unsigned_observation(capture: &NativeCommandCapture) -> bool {
    let Some(exit) = capture.exit_code else {
        return false;
    };
    if exit == 0 {
        return false;
    }
    let output = format!("{}\n{}", capture.stdout, capture.stderr).to_ascii_lowercase();
    output.contains("not signed at all") || output.contains("code object is not signed")
}

/// `codeSignCaptureFailure(capture)`.
fn code_sign_capture_failure(capture: &NativeCommandCapture) -> Option<AnalysisError> {
    if capture.exit_code == Some(0) || is_nonzero_unsigned_observation(capture) {
        None
    } else {
        Some(translate_code_sign_exit_failure(capture))
    }
}

/// `translateCodeSignExitFailure(capture)`: route an accepted nonzero codesign
/// exit through `translateCommandFailure` as a nonzero-exit provider failure.
fn translate_code_sign_exit_failure(capture: &NativeCommandCapture) -> AnalysisError {
    // `failureCapture(capture, false)`: a bounded diagnostic excerpt of the
    // accepted output that the provider has decided is a failure.
    let (stdout, stdout_truncated) =
        bounded_utf8_text(&capture.stdout, NATIVE_FAILURE_DIAGNOSTIC_BYTES);
    let (stderr, stderr_truncated) =
        bounded_utf8_text(&capture.stderr, NATIVE_FAILURE_DIAGNOSTIC_BYTES);
    let failure = NativeCommandFailure {
        tool: "codesign".to_owned(),
        reason: FailureReason::NonzeroExit,
        exit_code: capture.exit_code,
        capture: Some(FailureCapture {
            stdout,
            stderr,
            stdout_bytes: capture.stdout_bytes,
            stderr_bytes: capture.stderr_bytes,
            exit_code: capture.exit_code,
            signal: capture.signal.clone(),
            truncated: stdout_truncated || stderr_truncated,
        }),
        cleanup_failure: None,
        cleanup_resources: Vec::new(),
        detail: None,
    };
    super::translate_command_failure(OPERATION, &failure)
}

/// `/designated\s*=>\s*(.+)$/mu` on the requirements stdout.
fn designated_requirement(stdout: &str) -> Option<String> {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| Regex::new(r"(?m)designated\s*=>\s*(.+)$").unwrap());
    pattern
        .captures(stdout)
        .and_then(|captures| captures.get(1))
        .map(|group| group.as_str().trim_end_matches('\r').to_owned())
}

/// `codeSignArchitectures(format, target)`.
fn code_sign_architectures(format: Option<&str>, target: &BinaryTarget) -> Vec<String> {
    static UNIVERSAL: OnceLock<Regex> = OnceLock::new();
    static ARCHITECTURE: OnceLock<Regex> = OnceLock::new();
    let universal_pattern =
        UNIVERSAL.get_or_init(|| Regex::new(r"^Mach-O universal \(([^)\r\n]+)\)$").unwrap());
    let architecture_pattern =
        ARCHITECTURE.get_or_init(|| Regex::new(r"^(?:i386|x86_64|armv7|arm64|arm64e)$").unwrap());

    if let Some(captures) = universal_pattern.captures(format.unwrap_or("")) {
        let listed = captures.get(1).map(|group| group.as_str()).unwrap_or("");
        let mut seen = HashSet::new();
        let mut architectures = Vec::new();
        for architecture in listed.split_whitespace() {
            if architecture_pattern.is_match(architecture) && seen.insert(architecture.to_owned()) {
                architectures.push(architecture.to_owned());
            }
        }
        if !architectures.is_empty() {
            return architectures;
        }
    }

    if target.kind != "executable" || !is_macho_format(&target.format) {
        return Vec::new();
    }
    target
        .available_architectures
        .iter()
        .map(|architecture| {
            if architecture == "x86" {
                "i386".to_owned()
            } else {
                architecture.clone()
            }
        })
        .collect()
}

// ----------------------------------------------------------------------------
// codesign display parsing (`src/native/parsers/codesign.ts`)
// ----------------------------------------------------------------------------

/// Parsed codesign fields, omitting the provider-assembled `provenance`,
/// `entitlements` and `designated_requirement`.
struct ParsedSignature {
    signed: bool,
    identifier: Option<String>,
    team_identifier: Option<String>,
    format: Option<String>,
    cdhashes: Vec<String>,
    hash_algorithms: Vec<String>,
    authorities: Vec<String>,
    timestamp: Option<String>,
    hardened_runtime: Option<bool>,
    limitations: Vec<String>,
}

/// `parseCodeSignature(output, unsigned, executablePaths)`.
fn parse_code_signature(
    output: &str,
    unsigned: bool,
    executable_paths: &[String],
) -> ParsedSignature {
    let (identifier, fields) = split_echoed_values(output, executable_paths);
    let mut values: Vec<(String, String)> = Vec::new();
    let mut authorities = Vec::new();
    let mut cdhashes = Vec::new();
    let mut code_directory: Option<String> = None;

    for line in split_lines(&fields) {
        if let Some(rest) = line.strip_prefix("CodeDirectory ") {
            code_directory = Some(rest.to_owned());
            continue;
        }
        let Some(separator) = line.find('=') else {
            continue;
        };
        if separator < 1 {
            continue;
        }
        let key = line[..separator].trim();
        let value = line[separator + 1..].trim();
        match key {
            "Authority" => authorities.push(value.to_owned()),
            "CDHash" => cdhashes.push(value.to_owned()),
            _ => set_value(&mut values, key, value),
        }
    }

    let limitations = if unsigned {
        vec!["Artifact is not signed.".to_owned()]
    } else {
        vec![
            "Entitlements and designated requirements require separate bounded commands."
                .to_owned(),
        ]
    };

    ParsedSignature {
        signed: !unsigned,
        identifier,
        team_identifier: nullable_codesign_value(get_value(&values, "TeamIdentifier")),
        format: get_value(&values, "Format").map(ToOwned::to_owned),
        cdhashes,
        hash_algorithms: split_algorithms(get_value(&values, "Hash choices")),
        authorities,
        timestamp: get_value(&values, "Timestamp").map(ToOwned::to_owned),
        hardened_runtime: parse_runtime(code_directory.as_deref()),
        limitations,
    }
}

fn set_value(values: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(entry) = values.iter_mut().find(|(existing, _)| existing == key) {
        entry.1 = value.to_owned();
    } else {
        values.push((key.to_owned(), value.to_owned()));
    }
}

fn get_value<'a>(values: &'a [(String, String)], key: &str) -> Option<&'a str> {
    values
        .iter()
        .find(|(existing, _)| existing == key)
        .map(|(_, value)| value.as_str())
}

/// Split on `\r?\n`, matching `fields.split(/\r?\n/u)`.
fn split_lines(text: &str) -> Vec<String> {
    text.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line).to_owned())
        .collect()
}

/// `splitEchoedValues(text, executablePaths)`.
fn split_echoed_values(text: &str, executable_paths: &[String]) -> (Option<String>, String) {
    let mut rest = text.to_owned();
    let mut matched = false;
    let mut newline: Option<String> = None;
    // Frame the exact source path before interpreting record separators.
    for path in executable_paths {
        let prefix = format!("Executable={path}");
        if !text.starts_with(&prefix) {
            continue;
        }
        let after = &text[prefix.len()..];
        let Some(separator) = leading_newline(after) else {
            continue;
        };
        newline = Some(separator.to_owned());
        rest = text[prefix.len() + separator.len()..].to_owned();
        matched = true;
        break;
    }
    if !matched && text.starts_with("Executable=") {
        match text.find("\nIdentifier=") {
            Some(index) => rest = text[index + 1..].to_owned(),
            None => rest = text.to_owned(),
        }
    }
    if !rest.starts_with("Identifier=") {
        return (None, rest);
    }
    // The last `Format=` line is the one codesign printed after the identifier.
    let format = rfind_at(&rest, "\nFormat=");
    if newline.is_none()
        && let Some(format_index) = format
    {
        newline = leading_newline_in(&rest[format_index + 1..]).map(ToOwned::to_owned);
    }
    let boundary = match format {
        Some(index) => Some(index),
        None => rest.find('\n'),
    };
    let crlf = matches!(newline.as_deref(), None | Some("\r\n"));
    let identifier_start = "Identifier=".len();
    let end = match boundary {
        None => rest.len(),
        Some(boundary) => {
            if crlf && rest.as_bytes().get(boundary.wrapping_sub(1)) == Some(&b'\r') {
                boundary - 1
            } else {
                boundary
            }
        }
    };
    let identifier = rest[identifier_start..end].to_owned();
    (Some(identifier), rest[end..].to_owned())
}

/// `/^\r?\n/` at the start of `text`.
fn leading_newline(text: &str) -> Option<&str> {
    if let Some(stripped) = text.strip_prefix("\r\n") {
        Some(&text[..text.len() - stripped.len()])
    } else if text.starts_with('\n') {
        Some(&text[..1])
    } else {
        None
    }
}

/// `/\r?\n/` matched anywhere from the start of `text` (first occurrence).
fn leading_newline_in(text: &str) -> Option<&str> {
    let index = text.find('\n')?;
    if index > 0 && text.as_bytes()[index - 1] == b'\r' {
        Some(&text[index - 1..index + 1])
    } else {
        Some(&text[index..index + 1])
    }
}

/// `rest.lastIndexOf(needle)`.
fn rfind_at(text: &str, needle: &str) -> Option<usize> {
    text.rfind(needle)
}

fn nullable_codesign_value(value: Option<&str>) -> Option<String> {
    match value {
        None => None,
        Some("not set") => None,
        Some(value) => Some(value.to_owned()),
    }
}

fn split_algorithms(value: Option<&str>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    value
        .split(|character: char| character == ',' || character == '+' || character.is_whitespace())
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// `parseRuntime(value)`.
fn parse_runtime(value: Option<&str>) -> Option<bool> {
    let value = value?;
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| Regex::new(r"(?:^|\s)flags=[^(]*\(([^)]*)\)").unwrap());
    let flags = pattern.captures(value)?.get(1)?.as_str();
    Some(flags.split(',').any(|flag| flag.trim() == "runtime"))
}
