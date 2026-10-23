//! Re-parse refinements beyond the advertised JSON Schema.
//!
//! Compatibility owner: `objdumpInputSchema` and `rizinInputSchema` in
//! `src/domain/reverseEngineering.ts`. The MCP adapter already validated the
//! input against the frozen JSON Schema with defaults applied; the TypeScript
//! services re-`safeParse` with these Zod schemas, whose discriminated-union
//! `.strict()` shapes and string refinements the JSON Schema does not fully
//! express. A rejection yields `new AnalysisInputError(operation)` with no
//! issue list, exactly as the services return on `!parsed.success`.
use serde_json::Value;

/// Artifact operations, with `disassemble` excluded from the base shape.
const OBJDUMP_ARTIFACT_OPERATIONS: [&str; 6] = [
    "file_headers",
    "section_headers",
    "symbols",
    "relocations",
    "dwarf",
    "disassemble_all",
];

/// `objdumpInputSchema.safeParse(rawInput).success`.
pub fn objdump_parses(input: &Value) -> bool {
    let Some(object) = input.as_object() else {
        return false;
    };
    let Some(operation) = object.get("operation").and_then(Value::as_str) else {
        return false;
    };
    match operation {
        "architectures" => {
            // `z.strictObject({ operation: z.literal("architectures") })`.
            // The advertised flattened schema makes the server apply the
            // artifact branches' `follow_debug_links: false` default to every
            // call, so that default value is not a caller-supplied key here.
            object.iter().all(|(key, value)| {
                key == "operation" || (key == "follow_debug_links" && value == &Value::Bool(false))
            })
        }
        "disassemble" => {
            // Base shape + optional `symbol`.
            let mut allowed = 0;
            if !nonempty_string(object.get("path")) {
                return false;
            }
            allowed += 1; // path
            allowed += 1; // operation
            if object.contains_key("follow_debug_links") {
                if !object
                    .get("follow_debug_links")
                    .is_some_and(Value::is_boolean)
                {
                    return false;
                }
                allowed += 1;
            }
            if let Some(symbol) = object.get("symbol") {
                if !valid_symbol(symbol) {
                    return false;
                }
                allowed += 1;
            }
            object.len() == allowed
        }
        other if OBJDUMP_ARTIFACT_OPERATIONS.contains(&other) => {
            let mut allowed = 0;
            if !nonempty_string(object.get("path")) {
                return false;
            }
            allowed += 1; // path
            allowed += 1; // operation
            if object.contains_key("follow_debug_links") {
                if !object
                    .get("follow_debug_links")
                    .is_some_and(Value::is_boolean)
                {
                    return false;
                }
                allowed += 1;
            }
            // `.strict()` rejects any other key, including `symbol`.
            object.len() == allowed
        }
        _ => false,
    }
}

/// `rizinInputSchema.safeParse(rawInput).success`.
pub fn rizin_parses(input: &Value) -> bool {
    let Some(object) = input.as_object() else {
        return false;
    };
    if object.len() != 2 {
        return false;
    }
    if !nonempty_string(object.get("path")) {
        return false;
    }
    match object.get("command").and_then(Value::as_str) {
        Some(command) => !command.is_empty() && !command.contains(['\r', '\n', '\u{0000}']),
        None => false,
    }
}

fn nonempty_string(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| !text.is_empty())
}

/// `z.string().min(1).regex(/^[^\x00]*$/u).refine(no lone surrogates)`.
fn valid_symbol(value: &Value) -> bool {
    let Some(symbol) = value.as_str() else {
        return false;
    };
    // `.min(1)` plus the NUL-free pattern. A Rust `&str` is always
    // well-formed UTF-8, so lone surrogates cannot occur.
    !symbol.is_empty() && !symbol.contains('\u{0000}')
}
