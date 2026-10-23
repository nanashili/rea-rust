//! Input refinements the advertised JSON Schema cannot express.
//!
//! Compatibility owners: the `.refine`/`.superRefine` checks of
//! `src/contracts/sessionLifecycleInputs.ts`, `sessionStatusContract.ts`,
//! `src/domain/native/nativeFunctionAnnotations.ts`, `nativeDataType.ts` and
//! `bytePattern.ts`. Refinement issues do not abort later Zod checks, so every
//! failed refinement is reported, in schema order, exactly like the original
//! SDK input-validation failure.
use crate::target::raw_binary_selection_error;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_mcp::ToolOutput;
use rea_mcp::catalog::ToolContract;
use rea_mcp::schema::{Issue, validation_error_text};
use rea_mcp::support::optional_string;
use serde_json::{Value, json};

/// One failed refinement at an argument path.
pub(crate) struct Refinement {
    path: Vec<String>,
    message: String,
}

impl Refinement {
    fn at(path: &[&str], message: impl Into<String>) -> Self {
        Self {
            path: path.iter().map(|part| (*part).to_owned()).collect(),
            message: message.into(),
        }
    }
}

/// The SDK's text-only validation failure, carrying the typed input failure
/// for in-process (CLI) callers.
pub(crate) fn failure(contract: &ToolContract, issues: Vec<Refinement>) -> ToolOutput {
    let rendered = issues
        .iter()
        .map(|issue| Issue {
            path: issue.path.clone(),
            message: issue.message.clone(),
        })
        .collect::<Vec<_>>();
    let text = validation_error_text(&contract.name, &rendered);
    let error = AnalysisError::input(
        contract.name.clone(),
        issues
            .into_iter()
            .map(|issue| InputIssue {
                path: issue.path.into_iter().map(Value::String).collect(),
                reason: "invalid_value",
                message: Some(issue.message),
                expected: None,
                minimum: None,
                maximum: None,
            })
            .collect(),
    );
    ToolOutput::Raw(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": { "error": error.project() },
        "isError": true,
    }))
}

/// `node:path` `isAbsolute` on this host.
pub(crate) fn is_absolute(path: &str) -> bool {
    if cfg!(windows) {
        let bytes = path.as_bytes();
        let separator = |byte: u8| byte == b'/' || byte == b'\\';
        match bytes {
            [] => false,
            [first, ..] if separator(*first) => true,
            [drive, b':', third, ..] => drive.is_ascii_alphabetic() && separator(*third),
            _ => false,
        }
    } else {
        path.starts_with('/')
    }
}

fn absolute(input: &Value, key: &str, message: &str, issues: &mut Vec<Refinement>) {
    if let Some(path) = optional_string(input, key)
        && !is_absolute(path)
    {
        issues.push(Refinement::at(&[key], message));
    }
}

const SNAPSHOT_PATH_MESSAGE: &str = "snapshot_path must be an absolute local filesystem path (for example /tmp/rea/analysis.json or C:\\rea\\analysis.json)";

/// `openBinaryInputSchema` refinements.
fn open_binary(input: &Value) -> Vec<Refinement> {
    let mut issues = Vec::new();
    absolute(
        input,
        "path",
        "path must be an absolute local filesystem path (for example /tmp/fixture.bin or C:\\analysis\\fixture.bin)",
        &mut issues,
    );
    absolute(input, "snapshot_path", SNAPSHOT_PATH_MESSAGE, &mut issues);
    let format = optional_string(input, "format");
    let architecture = input.get("architecture").is_some();
    let entry_point = input.get("entry_point").is_some();
    if let Some(pairing) = raw_binary_selection_error(format, architecture, entry_point) {
        let path = if format == Some("raw-binary") {
            if architecture {
                "entry_point"
            } else {
                "architecture"
            }
        } else if architecture {
            "architecture"
        } else {
            "entry_point"
        };
        issues.push(Refinement::at(&[path], pairing));
    }
    issues
}

/// `closeBinaryInputSchema` refinements.
fn close_binary(input: &Value) -> Vec<Refinement> {
    let mut issues = Vec::new();
    absolute(input, "snapshot_path", SNAPSHOT_PATH_MESSAGE, &mut issues);
    issues
}

/// `binarySessionInputSchema` refinements.
fn binary_session(input: &Value) -> Vec<Refinement> {
    let mut issues = Vec::new();
    absolute(
        input,
        "expected_server_path",
        "expected_server_path must be an absolute local filesystem path (for example /opt/rea/dist/main.js)",
        &mut issues,
    );
    issues
}

/// JavaScript `/\s/u` for one UTF-16 code unit.
fn is_js_whitespace(unit: u16) -> bool {
    matches!(
        unit,
        0x0009..=0x000d
            | 0x0020
            | 0x00a0
            | 0x1680
            | 0x2000..=0x200a
            | 0x2028
            | 0x2029
            | 0x202f
            | 0x205f
            | 0x3000
            | 0xfeff
    )
}

fn hex_digit(unit: Option<u16>) -> Option<u16> {
    match unit? {
        unit @ 0x30..=0x39 => Some(unit - 0x30),
        unit @ 0x41..=0x46 => Some(unit - 0x37),
        unit @ 0x61..=0x66 => Some(unit - 0x57),
        _ => None,
    }
}

enum Pair {
    Byte(u16),
    Wildcard,
}

fn read_byte_pair(value: &[u16], offset: usize) -> Option<Pair> {
    let question = u16::from(b'?');
    if value.get(offset) == Some(&question) && value.get(offset + 1) == Some(&question) {
        return Some(Pair::Wildcard);
    }
    let high = hex_digit(value.get(offset).copied())?;
    let low = hex_digit(value.get(offset + 1).copied())?;
    Some(Pair::Byte(high * 16 + low))
}

/// Offset of the next pair, or None when trailing whitespace ends the text.
fn next_pair_offset(value: &[u16], offset: usize) -> Option<usize> {
    let end = offset + 2;
    let mut next = end;
    while next < value.len() && is_js_whitespace(value[next]) {
        next += 1;
    }
    if next == value.len() && next != end {
        None
    } else {
        Some(next)
    }
}

fn count_byte_pairs(value: &[u16], mask: bool) -> Option<usize> {
    let mut count = 0;
    let mut offset = 0;
    while offset < value.len() {
        match read_byte_pair(value, offset)? {
            Pair::Wildcard if mask => return None,
            _ => {}
        }
        count += 1;
        offset = next_pair_offset(value, offset)?;
    }
    (count > 0).then_some(count)
}

/// `validateBytePattern` for `search_bytes`.
fn byte_pattern(input: &Value) -> Vec<Refinement> {
    let pattern = optional_string(input, "pattern")
        .unwrap_or_default()
        .encode_utf16()
        .collect::<Vec<_>>();
    let mask = optional_string(input, "mask").map(|mask| mask.encode_utf16().collect::<Vec<_>>());
    let Some(pattern_count) = count_byte_pairs(&pattern, false) else {
        return vec![Refinement::at(
            &["pattern"],
            "Use hexadecimal byte pairs or ?? wildcards",
        )];
    };
    let mask_count = match &mask {
        None => None,
        Some(mask) => match count_byte_pairs(mask, true) {
            None => {
                return vec![Refinement::at(&["mask"], "Use hexadecimal mask byte pairs")];
            }
            Some(count) => Some(count),
        },
    };
    if mask_count.is_some_and(|count| count != pattern_count) {
        return vec![Refinement::at(
            &["mask"],
            "Mask length must equal pattern length",
        )];
    }
    let mut pattern_offset = 0;
    let mut mask_offset = 0;
    for _ in 0..pattern_count {
        let byte = read_byte_pair(&pattern, pattern_offset);
        let selected = match &mask {
            None => Some(Pair::Byte(255)),
            Some(mask) => read_byte_pair(mask, mask_offset),
        };
        if let (Some(Pair::Byte(_)), Some(Pair::Byte(selected))) = (&byte, &selected)
            && *selected != 0
        {
            return Vec::new();
        }
        pattern_offset = next_pair_offset(&pattern, pattern_offset).unwrap_or(pattern.len());
        if let Some(mask) = &mask {
            mask_offset = next_pair_offset(mask, mask_offset).unwrap_or(mask.len());
        }
    }
    vec![Refinement::at(
        &["pattern"],
        "Pattern must constrain at least one bit",
    )]
}

/// Every refinement of one tool's input, in the original order.
pub(crate) fn issues(name: &str, input: &Value) -> Vec<Refinement> {
    match name {
        "open_binary" => open_binary(input),
        "close_binary" => close_binary(input),
        "binary_session" => binary_session(input),
        "annotate_native_function" => {
            if ["name", "comment", "inline_comment"]
                .iter()
                .any(|key| input.get(*key).is_some())
            {
                Vec::new()
            } else {
                vec![Refinement::at(&[], "Supply at least one annotation change")]
            }
        }
        "inspect_native_data_type" => {
            if input.get("type").is_some() != input.get("address").is_some() {
                Vec::new()
            } else {
                vec![Refinement::at(&[], "Supply exactly one of type or address")]
            }
        }
        "search_bytes" => byte_pattern(input),
        _ => Vec::new(),
    }
}

/// The refinement failure for `contract`, if any refinement fails.
pub(crate) fn check(contract: &ToolContract, input: &Value) -> Option<ToolOutput> {
    let issues = issues(&contract.name, input);
    (!issues.is_empty()).then(|| failure(contract, issues))
}
