//! Read-only WASM projection for caller-supplied bytes or authenticated Evidence.
//!
//! This module deliberately does not invoke WABT, execute a module, or open a
//! path.  The caller owns acquisition and supplies one bounded byte snapshot.
//! The parser keeps raw section and interface observations when a declaration
//! cannot be normalized into a typed value.

use base64::Engine;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

pub const OPERATION: &str = "inspect_wasm_artifact";
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SECTIONS: usize = 10_000;

/// Inspect a bounded byte snapshot or project a matching retained Evidence.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input)?;

    validate_input_fields(object)?;

    if let Some(evidence) = object.get("evidence") {
        if object.len() != 1 || !evidence.is_object() {
            return Err(invalid(
                "Evidence input must contain only a non-empty evidence object",
            ));
        }
        return project_evidence(evidence);
    }

    let path = required_text(object, "path")?.to_owned();
    if path.contains('\0') {
        return Err(invalid("path must not contain NUL bytes"));
    }
    if !Path::new(&path).is_absolute() {
        return Err(invalid("path must be an absolute local filesystem path"));
    }
    let encoded = required_text(object, "bytes_base64")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| invalid(format!("bytes_base64 is invalid: {error}")))?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(resource("WASM bytes exceed the input limit"));
    }
    let digest = digest(&bytes);
    if let Some(declared) = object.get("sha256").and_then(Value::as_str)
        && !declared.eq_ignore_ascii_case(&digest)
    {
        return Err(invalid("sha256 does not match bytes_base64"));
    }

    parse_bytes(path, bytes, digest)
}

/// Adapter-friendly owned entry point for the runtime dispatcher.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    inspect(&input)
}

fn parse_bytes(path: String, bytes: Vec<u8>, sha256: String) -> Result<Value, Failure> {
    if bytes.len() < 8 || &bytes[..4] != b"\0asm" {
        return Err(malformed("WASM magic is missing"));
    }
    if bytes[4..8] != [1, 0, 0, 0] {
        return Err(malformed("Unsupported WASM binary version"));
    }

    let parsed = ModuleParser::new(&bytes).parse()?;
    let interface_state = if parsed.issues.is_empty() {
        "complete"
    } else {
        "partial"
    };
    let limitations = vec![
        "Facts are decoded from caller-supplied bytes; no WABT, target execution, source acquisition or network request is performed.".to_owned(),
        "Unsupported and malformed declarations retain raw bytes and an explicit issue; they are not inferred from neighboring sections.".to_owned(),
        "A complete section walk does not establish runtime behavior, ABI compatibility or original-source identity.".to_owned(),
    ];
    Ok(json!({
        "artifact": {"path": path, "sha256": sha256, "bytes": bytes.len()},
        "validation": "valid",
        "sections": parsed.sections,
        "interface": {"state": interface_state, "entries": parsed.entries, "issues": parsed.issues},
        "imports": parsed.imports,
        "exports": parsed.exports,
        "headers": "",
        "details": "",
        "wat": null,
        "tool_profile": null,
        "runtime_execution": "not-performed",
        "network_fetch": "not-performed",
        "limitations": limitations,
    }))
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    let raw =
        serde_json::value::to_raw_value(value).map_err(|error| integrity(error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| integrity(error.to_string()))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity(
            "captured Evidence operation does not match inspect_wasm_artifact",
        ));
    }
    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(error.to_string()))?;
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| integrity(error.to_string()))?;

    validate_captured_result(&subject, &result)?;

    Ok(json!({
        "evidence_id": record.evidence_id(),
        "subject": subject,
        "result": result,
        "source_evidence": serde_json::from_str::<Value>(record.raw().get())
            .map_err(|error| integrity(error.to_string()))?,
        "provenance": {"source": "authenticated-captured-evidence", "execution": "unknown"},
    }))
}

fn validate_input_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    const ALLOWED: &[&str] = &["path", "bytes_base64", "sha256", "evidence"];
    if let Some(field) = object
        .keys()
        .find(|field| !ALLOWED.contains(&field.as_str()))
    {
        return Err(invalid(format!(
            "unexpected WASM inspection field: {field}"
        )));
    }

    let has_evidence = object.contains_key("evidence");
    let has_bytes = object.contains_key("path") || object.contains_key("bytes_base64");
    if has_evidence && has_bytes {
        return Err(invalid(
            "WASM input cannot combine captured Evidence with byte fields",
        ));
    }
    if !has_evidence && !object.contains_key("path") {
        return Err(invalid("Byte input requires path and bytes_base64"));
    }
    if !has_evidence && !object.contains_key("bytes_base64") {
        return Err(invalid("Byte input requires path and bytes_base64"));
    }
    Ok(())
}

fn validate_captured_result(subject: &Value, result: &Value) -> Result<(), Failure> {
    let subject_object = subject
        .as_object()
        .ok_or_else(|| integrity("captured WASM subject must be an object"))?;
    if subject_object.get("format").and_then(Value::as_str) != Some("file") {
        return Err(integrity("captured WASM subject must identify a file"));
    }

    let result_object = result
        .as_object()
        .ok_or_else(|| integrity("captured WASM result must be an object"))?;
    let artifact = result_object
        .get("artifact")
        .and_then(Value::as_object)
        .ok_or_else(|| integrity("captured WASM result is missing artifact identity"))?;
    let (Some(path), Some(sha256), Some(bytes)) = (
        artifact.get("path").and_then(Value::as_str),
        artifact.get("sha256").and_then(Value::as_str),
        artifact.get("bytes").and_then(Value::as_u64),
    ) else {
        return Err(integrity("captured WASM artifact identity is incomplete"));
    };

    if path.contains('\0') || !Path::new(path).is_absolute() {
        return Err(integrity(
            "captured WASM artifact path is not an absolute local path",
        ));
    }

    if !is_sha256_digest(sha256) {
        return Err(integrity("captured WASM artifact digest is invalid"));
    }

    if bytes > MAX_INPUT_BYTES as u64 {
        return Err(integrity("captured WASM artifact exceeds the input limit"));
    }

    if subject_object.get("path").and_then(Value::as_str) != Some(path)
        || subject_object.get("sha256").and_then(Value::as_str) != Some(sha256)
    {
        return Err(integrity(
            "captured WASM subject does not match artifact identity",
        ));
    }

    if subject_object
        .get("path")
        .and_then(Value::as_str)
        .is_none_or(|subject_path| {
            subject_path.contains('\0') || !Path::new(subject_path).is_absolute()
        })
    {
        return Err(integrity(
            "captured WASM subject path is not an absolute local path",
        ));
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Default)]
struct ParsedModule {
    sections: Vec<Value>,
    entries: Vec<Value>,
    imports: Vec<Value>,
    exports: Vec<Value>,
    issues: Vec<String>,
}

struct ModuleParser<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> ModuleParser<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 8 }
    }

    fn parse(mut self) -> Result<ParsedModule, Failure> {
        let mut parsed = ParsedModule::default();
        while self.cursor < self.bytes.len() {
            if parsed.sections.len() == MAX_SECTIONS {
                return Err(resource("WASM section count exceeds the input limit"));
            }
            let start = self.cursor;
            let id = self.byte()?;
            let payload_len = self.varuint32()? as usize;
            let payload_start = self.cursor;
            let payload_end = payload_start
                .checked_add(payload_len)
                .ok_or_else(|| malformed("WASM section range overflowed"))?;
            if payload_end > self.bytes.len() {
                return Err(malformed("WASM section extends past the supplied bytes"));
            }
            let payload = &self.bytes[payload_start..payload_end];
            self.cursor = payload_end;
            let kind = section_kind(id);
            parsed.sections.push(json!({
                "id": id,
                "kind": kind,
                "start": start,
                "end": payload_end,
                "bytes": payload_end - start,
                "raw_hex": hex(&self.bytes[start..payload_end]),
            }));
            match id {
                0 => parse_custom(payload, &mut parsed)?,
                2 => parse_imports(payload, &mut parsed)?,
                4 => parse_tables(payload, &mut parsed)?,
                5 => parse_memories(payload, &mut parsed)?,
                7 => parse_exports(payload, &mut parsed)?,
                _ => {}
            }
        }
        Ok(parsed)
    }

    fn byte(&mut self) -> Result<u8, Failure> {
        let value = self
            .bytes
            .get(self.cursor)
            .copied()
            .ok_or_else(|| malformed("Unexpected end of WASM section"))?;
        self.cursor += 1;
        Ok(value)
    }

    fn varuint32(&mut self) -> Result<u32, Failure> {
        read_varuint32(self.bytes, &mut self.cursor)
    }
}

fn parse_custom(payload: &[u8], parsed: &mut ParsedModule) -> Result<(), Failure> {
    let mut cursor = 0;
    let name = read_name(payload, &mut cursor)?;
    if cursor > payload.len() {
        return Err(malformed("Custom section name exceeds its payload"));
    }
    let section = parsed.sections.last_mut().expect("section was recorded");
    section["name"] = Value::String(name);
    Ok(())
}

fn parse_imports(payload: &[u8], parsed: &mut ParsedModule) -> Result<(), Failure> {
    let mut cursor = 0;
    let count = bounded_count(read_varuint32(payload, &mut cursor)?)?;
    for index in 0..count {
        let module = read_name(payload, &mut cursor)?;
        let name = read_name(payload, &mut cursor)?;
        let kind = read_byte(payload, &mut cursor)?;
        let descriptor_start = cursor - 1;
        skip_import_descriptor(payload, &mut cursor, kind)?;
        let descriptor = &payload[descriptor_start..cursor];
        let entry = json!({
            "direction": "import", "module": module, "name": name,
            "kind": external_kind(kind), "index": index, "signature": Value::Null,
            "wat_form": format!("import {} {}", module, name), "issue": unknown_kind_issue(kind),
            "raw_descriptor_hex": hex(descriptor),
        });
        if unknown_kind_issue(kind).is_some() {
            parsed
                .issues
                .push(format!("Unsupported import kind 0x{kind:02x}"));
        }
        parsed.entries.push(entry.clone());
        parsed.imports.push(entry);
    }
    ensure_consumed(payload, cursor, "import")
}

fn parse_tables(payload: &[u8], parsed: &mut ParsedModule) -> Result<(), Failure> {
    parse_limits_section(payload, parsed, "table")
}

fn parse_memories(payload: &[u8], parsed: &mut ParsedModule) -> Result<(), Failure> {
    parse_limits_section(payload, parsed, "memory")
}

fn parse_limits_section(
    payload: &[u8],
    parsed: &mut ParsedModule,
    kind: &str,
) -> Result<(), Failure> {
    let mut cursor = 0;
    let count = bounded_count(read_varuint32(payload, &mut cursor)?)?;
    for index in 0..count {
        let flags = read_byte(payload, &mut cursor)?;
        let minimum = read_varuint32(payload, &mut cursor)?;
        let maximum = if flags & 1 != 0 {
            Some(read_varuint32(payload, &mut cursor)?)
        } else {
            None
        };
        let entry = json!({"direction":"definition","module":Value::Null,"name":format!("{kind}#{index}"),"kind":kind,"index":index,"signature":{"kind":kind,"minimum":minimum.to_string(),"maximum":maximum.map(|value| value.to_string()),"flags":flags},"wat_form":null,"issue":if flags & !1 != 0 { Some("Unknown limits flags") } else { None }});
        if flags & !1 != 0 {
            parsed
                .issues
                .push(format!("Unknown {kind} limits flags 0x{flags:02x}"));
        }
        parsed.entries.push(entry);
    }
    ensure_consumed(payload, cursor, kind)
}

fn parse_exports(payload: &[u8], parsed: &mut ParsedModule) -> Result<(), Failure> {
    let mut cursor = 0;
    let count = bounded_count(read_varuint32(payload, &mut cursor)?)?;
    for index in 0..count {
        let name = read_name(payload, &mut cursor)?;
        let kind_byte = read_byte(payload, &mut cursor)?;
        let target = read_varuint32(payload, &mut cursor)?;
        let entry = json!({"direction":"export","module":Value::Null,"name":name,"kind":external_kind(kind_byte),"index":target,"signature":Value::Null,"wat_form":format!("export {}", name),"issue":unknown_kind_issue(kind_byte)});
        if unknown_kind_issue(kind_byte).is_some() {
            parsed
                .issues
                .push(format!("Unsupported export kind 0x{kind_byte:02x}"));
        }
        parsed.entries.push(entry.clone());
        parsed.exports.push(entry);
        let _ = index;
    }
    ensure_consumed(payload, cursor, "export")
}

fn skip_import_descriptor(bytes: &[u8], cursor: &mut usize, kind: u8) -> Result<(), Failure> {
    match kind {
        0 => {
            read_varuint32(bytes, cursor)?;
        }
        1 => {
            read_byte(bytes, cursor)?;
            skip_limits(bytes, cursor)?;
        }
        2 => {
            skip_limits(bytes, cursor)?;
        }
        3 => {
            read_byte(bytes, cursor)?;
            read_byte(bytes, cursor)?;
        }
        _ => {}
    }
    Ok(())
}

fn skip_limits(bytes: &[u8], cursor: &mut usize) -> Result<(), Failure> {
    let flags = read_byte(bytes, cursor)?;
    read_varuint32(bytes, cursor)?;
    if flags & 1 != 0 {
        read_varuint32(bytes, cursor)?;
    }
    Ok(())
}

fn read_name(bytes: &[u8], cursor: &mut usize) -> Result<String, Failure> {
    let length = read_varuint32(bytes, cursor)? as usize;
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| malformed("WASM name length overflowed"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| malformed("WASM name exceeds section payload"))?;
    *cursor = end;
    String::from_utf8(value.to_vec()).map_err(|_| malformed("WASM name is not UTF-8"))
}

fn read_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, Failure> {
    let value = bytes
        .get(*cursor)
        .copied()
        .ok_or_else(|| malformed("WASM payload ended unexpectedly"))?;
    *cursor += 1;
    Ok(value)
}

fn read_varuint32(bytes: &[u8], cursor: &mut usize) -> Result<u32, Failure> {
    let mut value = 0u32;
    for shift in (0..35).step_by(7) {
        let byte = read_byte(bytes, cursor)?;
        if shift == 28 && byte > 0x0f {
            return Err(malformed("WASM varuint32 overflows"));
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(malformed("WASM varuint32 is unterminated"))
}

fn ensure_consumed(bytes: &[u8], cursor: usize, section: &str) -> Result<(), Failure> {
    if cursor == bytes.len() {
        Ok(())
    } else {
        Err(malformed(&format!("Trailing bytes in {section} section")))
    }
}

fn bounded_count(value: u32) -> Result<usize, Failure> {
    let count = usize::try_from(value).map_err(|_| resource("WASM count overflows host size"))?;
    if count > MAX_SECTIONS {
        return Err(resource("WASM declaration count exceeds the input limit"));
    }
    Ok(count)
}

fn section_kind(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "data_count",
        13 => "tag",
        _ => "unknown",
    }
}

fn external_kind(kind: u8) -> &'static str {
    match kind {
        0 => "func",
        1 => "table",
        2 => "memory",
        3 => "global",
        4 => "tag",
        _ => "unknown",
    }
}

fn unknown_kind_issue(kind: u8) -> Option<&'static str> {
    (kind > 4).then_some("Unsupported external kind")
}
fn input_object(input: &Value) -> Result<&Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))
}
fn required_text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("{field} is required")))
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn failure(
    code: &'static str,
    category: &'static str,
    reason: String,
    action: &'static str,
) -> Failure {
    Failure::new(
        code,
        category,
        reason.into(),
        false,
        action.into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}
fn invalid(reason: impl Into<String>) -> Failure {
    failure(
        "invalid_request",
        "invalid_input",
        reason.into(),
        "Provide one bounded WASM byte snapshot or authenticated Evidence.",
    )
}
fn malformed(reason: impl Into<String>) -> Failure {
    failure(
        "analysis_input",
        "invalid_format",
        reason.into(),
        "Provide a valid caller-supplied WASM byte snapshot.",
    )
}
fn resource(reason: impl Into<String>) -> Failure {
    failure(
        "resource_limit",
        "resource_limit",
        reason.into(),
        "Provide a smaller WASM byte snapshot or use retained Evidence.",
    )
}
fn integrity(reason: impl Into<String>) -> Failure {
    failure(
        "integrity_failure",
        "integrity_failure",
        reason.into(),
        "Provide authenticated inspect_wasm_artifact Evidence.",
    )
}
