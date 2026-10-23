//! Pure parsing and projection for the `demangle_swift` native workflow.
//!
//! The process boundary belongs to the runtime/host adapter.  This module
//! keeps the producer's line protocol and Swift spelling rules in one place,
//! so adapters cannot accidentally reinterpret an undecoded symbol.

use serde::Serialize;
use serde_json::Value;

pub const OPERATION: &str = "demangle_swift";
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// A single result emitted by `swift-demangle --compact`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DemangledSymbol {
    pub input: String,
    pub output: String,
    pub status: DemangleStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DemangleStatus {
    Demangled,
    Unchanged,
    Invalid,
}

/// Parse compact demangler output while preserving input order and spelling.
///
/// `swift-demangle` emits one LF-terminated record per input.  Only one final
/// LF is removed, matching the TypeScript parser: an additional LF therefore
/// remains a meaningful empty record rather than being silently discarded.
pub fn parse_demangled_symbols(
    inputs: &[String],
    output: &str,
) -> Result<Vec<DemangledSymbol>, String> {
    if inputs.is_empty() {
        if output.is_empty() || output == "\n" {
            return Ok(Vec::new());
        }
        return Err("swift-demangle emitted output for an empty input".into());
    }

    let without_final_lf = output.strip_suffix('\n').unwrap_or(output);
    let lines: Vec<&str> = without_final_lf.split('\n').collect();
    if lines.len() != inputs.len() {
        return Err(format!(
            "swift-demangle output count does not match input: expected {}, received {}",
            inputs.len(),
            lines.len()
        ));
    }

    inputs
        .iter()
        .zip(lines)
        .map(|(input, value)| {
            let decoded = value != input && value != undecoded_spelling(input);
            Ok(DemangledSymbol {
                input: input.clone(),
                output: value.to_owned(),
                status: if decoded {
                    DemangleStatus::Demangled
                } else if is_swift_mangled_symbol_name(&linkage_name(input)) {
                    DemangleStatus::Invalid
                } else {
                    DemangleStatus::Unchanged
                },
            })
        })
        .collect()
}

/// Validate the caller-supplied capture before parsing its line protocol.
///
/// The runtime owns the JSON envelope and turns these reasons into its
/// structured invalid-input failure.  Keeping the boundary rules here makes
/// the parser safe for every adapter that uses it.
pub fn validate_capture(inputs: &[String], stdout: &str, provenance: &Value) -> Result<(), String> {
    if stdout.len() > MAX_OUTPUT_BYTES {
        return Err("stdout exceeds the 8 MiB capture limit".into());
    }
    if inputs
        .iter()
        .any(|symbol| symbol.is_empty() || symbol.contains('\n') || symbol.contains('\0'))
    {
        return Err("symbols must be non-empty single-line strings without NUL".into());
    }
    if !provenance.is_array() {
        return Err("provenance must be an array".into());
    }
    Ok(())
}

/// Build the native result envelope after the host adapter has captured the
/// command invocation.  The provenance value is intentionally supplied by the
/// adapter because it owns executable identity and process accounting.
pub fn result(
    inputs: &[String],
    stdout: &str,
    provenance: Value,
    limitations: Vec<String>,
) -> Result<Value, String> {
    validate_capture(inputs, stdout, &provenance)?;
    let symbols = parse_demangled_symbols(inputs, stdout)?;
    Ok(serde_json::json!({
        "symbols": symbols,
        "provenance": provenance,
        "limitations": limitations,
    }))
}

fn linkage_name(input: &str) -> String {
    input
        .strip_prefix("__")
        .map_or_else(|| input.to_owned(), |rest| format!("_{rest}"))
}

fn undecoded_spelling(input: &str) -> String {
    if matches!(input.as_bytes().first(), Some(b'S' | b's' | b'e')) {
        format!("${input}")
    } else {
        linkage_name(input)
    }
}

/// Recognize names accepted as Swift manglings by the native demangler.
pub fn is_swift_mangled_symbol_name(name: &str) -> bool {
    [
        "_T0",
        "$S",
        "_$S",
        "$s",
        "_$s",
        "@__swiftmacro_",
        "$e",
        "_$e",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}
