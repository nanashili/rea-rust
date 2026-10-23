//! Offline producer for `inspect_web_network_capture`.
//!
//! This module owns the file snapshot and the format-neutral projection.  It
//! deliberately does not contact URLs or assign browser/runtime identities.

use base64::Engine;
use flate2::read::DeflateDecoder;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

pub const OPERATION: &str = "inspect_web_network_capture";
pub const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 96 * 1024 * 1024;
pub const MAX_DEPTH: usize = 64;

/// Validate the shared caller boundary without interpreting producer bytes.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web network capture input must be an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "capture_path" | "format" | "record_ordinals" | "sensitive_values"
        ) {
            return Err(invalid(
                "web network capture input contains an unknown field",
            ));
        }
    }
    let path = object
        .get("capture_path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("capture_path must be a non-empty absolute path"))?;
    if !Path::new(path).is_absolute() {
        return Err(invalid("capture_path must be an absolute path"));
    }
    let format = object
        .get("format")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("format must be a string"))?;
    if !matches!(format, "har" | "mitmproxy" | "saz" | "qlog") {
        return Err(invalid("format must be har, mitmproxy, saz or qlog"));
    }
    if let Some(ordinals) = object.get("record_ordinals") {
        let values = ordinals
            .as_array()
            .filter(|values| !values.is_empty())
            .ok_or_else(|| invalid("record_ordinals must be a non-empty array"))?;
        let mut previous = Vec::new();
        for ordinal in values {
            let value = ordinal
                .as_u64()
                .ok_or_else(|| invalid("record_ordinals must contain non-negative integers"))?;
            if previous.contains(&value) {
                return Err(invalid("record_ordinals must be unique"));
            }
            previous.push(value);
        }
    }
    if let Some(values) = object.get("sensitive_values") {
        let values = values
            .as_array()
            .ok_or_else(|| invalid("sensitive_values must be an array"))?;
        if values
            .iter()
            .any(|value| value.as_str().is_none_or(str::is_empty))
        {
            return Err(invalid("sensitive_values must contain non-empty strings"));
        }
    }
    Ok(())
}

/// Retain a producer result after the adapter has completed decoding.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("web network capture result must be an object"));
    }
    Ok(result)
}

#[derive(Clone)]
struct SazEntry {
    path: String,
    kind: &'static str,
    declared_size: usize,
    compressed_size: usize,
    method: u16,
    data_offset: usize,
}

fn inspect_saz(
    path: &str,
    bytes: &[u8],
    digest: String,
    sensitive: &[String],
    selected: Option<&Value>,
) -> Result<Value, Failure> {
    let entries = parse_saz_zip(bytes)?;
    let mut inventory = Vec::new();
    let mut groups: BTreeMap<String, Vec<SazEntry>> = BTreeMap::new();
    let mut group_order = Vec::new();
    for entry in &entries {
        inventory.push(
            serde_json::json!({"path":entry.path,"kind":entry.kind,"bytes":entry.declared_size}),
        );
        if entry.kind != "file" {
            continue;
        }
        if let Some((session, suffix)) = saz_member(&entry.path) {
            if !groups.contains_key(session) {
                group_order.push(session.to_owned());
            }
            groups
                .entry(session.to_owned())
                .or_default()
                .push(entry.clone());
            if suffix == "unknown" {
                return Err(unsupported(
                    "saz",
                    "SAZ contains an unrecognized raw session member",
                ));
            }
        }
    }
    if groups.is_empty() {
        return Err(invalid("Archive contains no SAZ session members"));
    }

    let mut records = Vec::new();
    for (ordinal, session) in group_order.iter().enumerate() {
        let mut source = serde_json::json!({
            "session_id": session,
            "request": Value::Null,
            "response": Value::Null,
            "metadata": Value::Null,
            "websocket": Value::Null,
            "grpc": Value::Null,
        });
        let group = groups
            .get(session)
            .expect("group order is derived from groups");
        for entry in group {
            let member = inflate_saz_entry(bytes, entry)?;
            let value = if entry.path.ends_with("_c.txt") {
                let mut parsed = parse_saz_http(&member, true)?;
                parsed["member"] = Value::String(entry.path.clone());
                parsed
            } else if entry.path.ends_with("_s.txt") {
                let mut parsed = parse_saz_http(&member, false)?;
                parsed["member"] = Value::String(entry.path.clone());
                parsed
            } else if entry.path.ends_with("_m.xml") {
                serde_json::json!({"member":entry.path,"document":parse_saz_xml(&member)?})
            } else if entry.path.ends_with("_w.txt") || entry.path.ends_with("_g.txt") {
                serde_json::json!({"member":entry.path,"messages":saz_bytes_value(&member)})
            } else {
                continue;
            };
            if entry.path.ends_with("_c.txt") {
                source["request"] = value;
            } else if entry.path.ends_with("_s.txt") {
                source["response"] = value;
            } else if entry.path.ends_with("_m.xml") {
                source["metadata"] = value;
            } else if entry.path.ends_with("_w.txt") {
                source["websocket"] = value;
            } else {
                source["grpc"] = value;
            }
        }
        let mut binary_fields = Vec::new();
        let mut redaction_rows = Vec::new();
        let reported = project_saz_json(
            &source,
            "",
            sensitive,
            &mut binary_fields,
            &mut redaction_rows,
            0,
        )?;
        records.push(serde_json::json!({
            "ordinal": ordinal,
            "location": {"kind":"archive-members","members":group.iter().map(|e| e.path.clone()).collect::<Vec<_>>()},
            "reported": reported,
            "binary_fields": binary_fields,
            "numeric_literals": [],
            "redactions": redaction_rows,
            "limitations": []
        }));
    }
    let mut container_binary = Vec::new();
    let mut container_redactions = Vec::new();
    let container_reported = project_saz_json(
        &serde_json::json!({"members":inventory}),
        "",
        sensitive,
        &mut container_binary,
        &mut container_redactions,
        0,
    )?;
    let _ = selected_ordinals(selected, records.len())?;
    Ok(serde_json::json!({
        "format":"saz",
        "artifact":{"path":path,"sha256":digest,"bytes":bytes.len()},
        "runtime_attribution":"unknown",
        "decoder":{"id":"rea-saz-rust","name":"REA bounded SAZ capture decoder","version":"1"},
        "container":{"reported":container_reported,"numeric_literals":[],"redactions":container_redactions,"records_pointer":Value::Null},
        "total_records":records.len(),"records":records,
        "limitations":["Historical inspection is offline and does not contact recorded destinations.","SAZ HTTP fields preserve Latin-1 text and stored body bytes; transfer/content decoding is not performed.","XML is projected as an ordered node tree; WebSocket and gRPC members remain opaque bytes."]
    }))
}

fn parse_saz_zip(bytes: &[u8]) -> Result<Vec<SazEntry>, Failure> {
    let mut offset = 0usize;
    let mut entries = Vec::new();
    let mut names = Vec::new();
    let mut expanded = 0usize;
    while offset + 30 <= bytes.len() && &bytes[offset..offset + 4] == b"PK\x03\x04" {
        let method = u16::from_le_bytes([bytes[offset + 8], bytes[offset + 9]]);
        let flags = u16::from_le_bytes([bytes[offset + 6], bytes[offset + 7]]);
        let compressed =
            u32::from_le_bytes(bytes[offset + 18..offset + 22].try_into().unwrap()) as usize;
        let declared =
            u32::from_le_bytes(bytes[offset + 22..offset + 26].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes([bytes[offset + 26], bytes[offset + 27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[offset + 28], bytes[offset + 29]]) as usize;
        let name_start = offset + 30;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or_else(|| invalid("SAZ member name overflows"))?;
        let data_offset = name_end
            .checked_add(extra_len)
            .ok_or_else(|| invalid("SAZ member header overflows"))?;
        let end = data_offset
            .checked_add(compressed)
            .ok_or_else(|| invalid("SAZ member data overflows"))?;
        if end > bytes.len() {
            return Err(invalid("SAZ member exceeds archive bytes"));
        }
        let name = std::str::from_utf8(&bytes[name_start..name_end])
            .map_err(|_| invalid("SAZ member name is not UTF-8"))?
            .to_owned();
        if !names.iter().all(|known| known != &name) {
            return Err(invalid("SAZ contains duplicate archive member names"));
        }
        names.push(name.clone());
        expanded = expanded
            .checked_add(declared)
            .ok_or_else(|| invalid("SAZ expanded members overflow"))?;
        if expanded > MAX_INPUT_BYTES as usize {
            return Err(invalid(
                "SAZ expanded members exceed the 32 MiB complete-evidence budget",
            ));
        }
        let kind = if name.ends_with('/') {
            "directory"
        } else {
            "file"
        };
        if flags & 1 != 0 {
            return Err(unsupported("saz", "Encrypted SAZ archives are unsupported"));
        }
        if method != 0 && method != 8 {
            return Err(unsupported(
                "saz",
                "SAZ uses an unsupported ZIP compression method",
            ));
        }
        entries.push(SazEntry {
            path: name,
            kind,
            declared_size: declared,
            compressed_size: compressed,
            method,
            data_offset,
        });
        offset = end;
    }
    if entries.is_empty() {
        return Err(invalid("SAZ archive contains no readable ZIP members"));
    }
    Ok(entries)
}

fn saz_member(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("raw/")?;
    let (session, suffix) = rest.split_once('_')?;
    if session.is_empty() || !session.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let kind = match suffix {
        "c.txt" | "s.txt" | "m.xml" | "w.txt" | "g.txt" => suffix,
        _ => "unknown",
    };
    Some((session, kind))
}

fn inflate_saz_entry(bytes: &[u8], entry: &SazEntry) -> Result<Vec<u8>, Failure> {
    let compressed_end = entry
        .data_offset
        .checked_add(entry.compressed_size)
        .ok_or_else(|| invalid("SAZ member data overflows"))?;
    if compressed_end > bytes.len() {
        return Err(invalid("SAZ member exceeds archive bytes"));
    }
    let compressed = &bytes[entry.data_offset..compressed_end];
    let mut output = Vec::with_capacity(entry.declared_size);
    if entry.method == 0 {
        output.extend_from_slice(compressed);
    } else {
        DeflateDecoder::new(Cursor::new(compressed))
            .read_to_end(&mut output)
            .map_err(|e| provider_failure(format!("unable to inflate SAZ member: {e}")))?;
    }
    if output.len() != entry.declared_size {
        return Err(invalid("SAZ member does not match its declared size"));
    }
    Ok(output)
}

fn saz_bytes_value(bytes: &[u8]) -> Value {
    serde_json::json!({"__saz_bytes_base64":base64::engine::general_purpose::STANDARD.encode(bytes)})
}

fn parse_saz_http(bytes: &[u8], request: bool) -> Result<Value, Failure> {
    let (boundary, separator) = if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n")
    {
        (index, 4)
    } else if let Some(index) = bytes.windows(2).position(|w| w == b"\n\n") {
        (index, 2)
    } else {
        return Err(invalid("SAZ HTTP message has no header/body separator"));
    };
    let header_text: String = bytes[..boundary].iter().map(|b| *b as char).collect();
    let lines: Vec<&str> = if separator == 4 {
        header_text.split("\r\n").collect()
    } else {
        header_text.split('\n').collect()
    };
    let first = lines.first().copied().unwrap_or("");
    let mut result = Map::new();
    if request {
        let fields: Vec<&str> = first.split_whitespace().collect();
        if fields.len() != 3 || !fields[2].starts_with("HTTP/") {
            return Err(invalid("SAZ HTTP request start line is malformed"));
        }
        result.insert("method".into(), Value::String(fields[0].into()));
        result.insert("url".into(), Value::String(fields[1].into()));
        result.insert("http_version".into(), Value::String(fields[2].into()));
    } else {
        let mut fields = first.splitn(3, ' ');
        let version = fields.next().unwrap_or("");
        let status = fields.next().unwrap_or("");
        if !version.starts_with("HTTP/")
            || status.len() != 3
            || !status.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(invalid("SAZ HTTP response start line is malformed"));
        }
        result.insert("http_version".into(), Value::String(version.into()));
        result.insert("status".into(), Value::String(status.into()));
        result.insert(
            "reason".into(),
            Value::String(fields.next().unwrap_or("").into()),
        );
    }
    let mut headers: Vec<Value> = Vec::new();
    for line in lines.into_iter().skip(1) {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                let value = last
                    .get_mut("value")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .to_owned()
                    + line;
                last["value"] = Value::String(value);
                continue;
            }
            return Err(invalid("SAZ HTTP header continuation has no field"));
        }
        let delimiter = if line.starts_with(':') {
            line[1..].find(':').map(|i| i + 1)
        } else {
            line.find(':')
        };
        let Some(index) = delimiter else {
            return Err(invalid("SAZ HTTP header is malformed"));
        };
        if index == 0 {
            return Err(invalid("SAZ HTTP header name is malformed"));
        }
        headers.push(serde_json::json!({"name":&line[..index],"value":&line[index+1..]}));
    }
    result.insert("headers".into(), Value::Array(headers));
    result.insert(
        "body".into(),
        saz_bytes_value(&bytes[boundary + separator..]),
    );
    Ok(Value::Object(result))
}

fn project_saz_json(
    value: &Value,
    pointer: &str,
    sensitive: &[String],
    binary: &mut Vec<Value>,
    redactions: &mut Vec<Value>,
    depth: usize,
) -> Result<Value, Failure> {
    if depth > MAX_DEPTH {
        return Err(invalid("SAZ projection exceeds the 64-level nesting limit"));
    }
    if let Some(marker) = value.get("__saz_bytes_base64").and_then(Value::as_str) {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(marker)
            .map_err(|_| invalid("SAZ binary member is not valid Base64"))?;
        let digest = hex_digest(&bytes);
        let hidden = sensitive.iter().any(|literal| {
            marker.contains(literal)
                || digest.contains(literal)
                || bytes
                    .windows(literal.len())
                    .any(|window| window == literal.as_bytes())
        });
        if hidden {
            binary.push(serde_json::json!({"pointer":pointer,"representation":"producer-bytes","state":"redacted","content_base64":null,"bytes":null,"sha256":null}));
            redactions
                .push(serde_json::json!({"pointer":pointer,"reason":"explicit-sensitive-value"}));
            return Ok(Value::Null);
        }
        binary.push(serde_json::json!({"pointer":pointer,"representation":"producer-bytes","state":"retained","content_base64":marker,"bytes":bytes.len(),"sha256":digest}));
        return Ok(String::from_utf8(bytes)
            .map(Value::String)
            .unwrap_or(Value::Null));
    }
    match value {
        Value::String(text) => {
            if sensitive.iter().any(|literal| text.contains(literal)) {
                redactions.push(
                    serde_json::json!({"pointer":pointer,"reason":"explicit-sensitive-value"}),
                );
                Ok(Value::Null)
            } else {
                Ok(value.clone())
            }
        }
        Value::Array(values) => Ok(Value::Array(
            values
                .iter()
                .enumerate()
                .map(|(index, child)| {
                    project_saz_json(
                        child,
                        &format!("{pointer}/{index}"),
                        sensitive,
                        binary,
                        redactions,
                        depth + 1,
                    )
                })
                .collect::<Result<_, _>>()?,
        )),
        Value::Object(values) => {
            let mut output = Map::new();
            for (key, child) in values {
                if sensitive.iter().any(|literal| key.contains(literal)) {
                    redactions.push(serde_json::json!({"pointer":pointer,"reason":"explicit-sensitive-value","scope":"property-name"}));
                    continue;
                }
                output.insert(
                    key.clone(),
                    project_saz_json(
                        child,
                        &format!("{pointer}/{}", escape_pointer(key)),
                        sensitive,
                        binary,
                        redactions,
                        depth + 1,
                    )?,
                );
            }
            Ok(Value::Object(output))
        }
        _ => Ok(value.clone()),
    }
}

fn parse_saz_xml(bytes: &[u8]) -> Result<Value, Failure> {
    let text = if bytes.starts_with(&[0xff, 0xfe]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units)
            .map_err(|_| unsupported("saz", "SAZ metadata UTF-16 is malformed"))?
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units)
            .map_err(|_| unsupported("saz", "SAZ metadata UTF-16 is malformed"))?
    } else {
        std::str::from_utf8(bytes)
            .map_err(|_| unsupported("saz", "SAZ metadata must use UTF-8 or BOM-marked UTF-16"))?
            .to_owned()
    };
    if text.contains("<!DOCTYPE") || text.contains("<!ENTITY") {
        return Err(unsupported("saz", "SAZ metadata DTDs are unsupported"));
    }
    let mut parser = XmlParser {
        text: &text,
        position: 0,
    };
    let document = parser.document()?;
    if document["children"]
        .as_array()
        .and_then(|children| children.iter().find(|child| child["type"] == 1))
        .and_then(|node| node["name"].as_str())
        != Some("Session")
    {
        return Err(invalid("SAZ metadata must have a Session document element"));
    }
    Ok(document)
}

struct XmlParser<'a> {
    text: &'a str,
    position: usize,
}
impl<'a> XmlParser<'a> {
    fn document(&mut self) -> Result<Value, Failure> {
        let mut children = Vec::new();
        while self.position < self.text.len() {
            self.skip_space();
            if self.position >= self.text.len() {
                break;
            }
            if self.text[self.position..].starts_with("<?") {
                self.consume_until("?>")?;
                continue;
            }
            children.push(self.node(0)?);
        }
        Ok(
            serde_json::json!({"name":"#document","type":9,"value":null,"attributes":[],"children":children}),
        )
    }
    fn node(&mut self, depth: usize) -> Result<Value, Failure> {
        if depth > MAX_DEPTH {
            return Err(invalid("SAZ metadata exceeds the 64-level nesting limit"));
        }
        if !self.take("<") {
            return Err(invalid("SAZ metadata is not well-formed XML"));
        }
        if self.take("!--") {
            let start = self.position;
            self.consume_until("-->")?;
            return Ok(
                serde_json::json!({"name":"#comment","type":8,"value":self.text[start..self.position-3],"attributes":[],"children":[]}),
            );
        }
        let name = self.take_name()?;
        let mut attrs = Vec::new();
        loop {
            self.skip_space();
            if self.take("/>") {
                return Ok(
                    serde_json::json!({"name":name,"type":1,"value":null,"attributes":attrs,"children":[]}),
                );
            }
            if self.take(">") {
                break;
            }
            let key = self.take_name()?;
            self.skip_space();
            if !self.take("=") {
                return Err(invalid("SAZ metadata attribute is malformed"));
            }
            self.skip_space();
            let quote = self
                .text
                .as_bytes()
                .get(self.position)
                .copied()
                .ok_or_else(|| invalid("SAZ metadata attribute is malformed"))?
                as char;
            if quote != '\'' && quote != '"' {
                return Err(invalid("SAZ metadata attribute is malformed"));
            }
            self.position += 1;
            let start = self.position;
            while self.position < self.text.len()
                && self.text.as_bytes()[self.position] as char != quote
            {
                self.position += 1;
            }
            if self.position >= self.text.len() {
                return Err(invalid("SAZ metadata attribute is unterminated"));
            }
            let value = self.text[start..self.position].to_owned();
            self.position += 1;
            attrs.push(serde_json::json!({"name":key,"value":value}));
        }
        let mut children = Vec::new();
        loop {
            if self.text[self.position..].starts_with("</") {
                self.position += 2;
                let close = self.take_name()?;
                self.skip_space();
                if !self.take(">") || close != name {
                    return Err(invalid("SAZ metadata closing tag is malformed"));
                }
                break;
            }
            if self.text[self.position..].starts_with("<") {
                children.push(self.node(depth + 1)?);
            } else {
                let start = self.position;
                while self.position < self.text.len()
                    && !self.text[self.position..].starts_with("<")
                {
                    self.position += 1;
                }
                if start < self.position {
                    children.push(serde_json::json!({"name":"#text","type":3,"value":self.text[start..self.position],"attributes":[],"children":[]}));
                }
            }
        }
        Ok(
            serde_json::json!({"name":name,"type":1,"value":null,"attributes":attrs,"children":children}),
        )
    }
    fn take_name(&mut self) -> Result<String, Failure> {
        let start = self.position;
        while self.position < self.text.len() {
            let c = self.text.as_bytes()[self.position] as char;
            if c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-' | '.') {
                self.position += 1;
            } else {
                break;
            }
        }
        if start == self.position {
            return Err(invalid("SAZ metadata element name is malformed"));
        }
        Ok(self.text[start..self.position].to_owned())
    }
    fn take(&mut self, token: &str) -> bool {
        if self.text[self.position..].starts_with(token) {
            self.position += token.len();
            true
        } else {
            false
        }
    }
    fn skip_space(&mut self) {
        while self.position < self.text.len()
            && self.text.as_bytes()[self.position].is_ascii_whitespace()
        {
            self.position += 1;
        }
    }
    fn consume_until(&mut self, token: &str) -> Result<(), Failure> {
        if let Some(index) = self.text[self.position..].find(token) {
            self.position += index + token.len();
            Ok(())
        } else {
            Err(invalid("SAZ metadata is not well-formed XML"))
        }
    }
}

/// Read and project one selected capture.  Format-specific adapters may use
/// this operation as their common bounded JSON path; unsupported binary
/// containers fail explicitly rather than being guessed or replayed.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input.as_object().expect("validated object");
    let path = object["capture_path"].as_str().expect("validated path");
    let format = object["format"].as_str().expect("validated format");
    let sensitive = sensitive_values(object.get("sensitive_values"));
    let bytes = fs::read(path)
        .map_err(|error| provider_failure(format!("unable to read capture: {error}")))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(invalid("capture exceeds the 32 MiB input limit"));
    }
    let digest = hex_digest(&bytes);
    if format == "saz" {
        return inspect_saz(
            path,
            &bytes,
            digest,
            &sensitive,
            object.get("record_ordinals"),
        );
    }
    if format == "mitmproxy" {
        return Err(unsupported(
            format,
            "this native producer has no bounded binary decoder for the selected format",
        ));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| invalid("capture must be valid UTF-8 JSON"))?;
    let source: Value = serde_json::from_str(text)
        .map_err(|error| provider_failure(format!("invalid {format} JSON: {error}")))?;
    if format == "har"
        && source.get("log").and_then(|log| log.get("version"))
            != Some(&Value::String("1.2".into()))
    {
        return Err(unsupported(format, "only HAR 1.2 is supported"));
    }
    if format == "qlog"
        && (source.get("qlog_format").and_then(Value::as_str) != Some("JSON")
            || source.get("qlog_version").and_then(Value::as_str) != Some("0.3"))
    {
        return Err(unsupported(format, "only JSON qlog 0.3 is supported"));
    }

    let projected = Projector::new(&sensitive).value(&source, "", 0)?;
    let records_source = records_for(format, &source)?;
    let mut records = Vec::with_capacity(records_source.len());
    for (ordinal, record) in records_source.iter().enumerate() {
        let pointer = if format == "har" {
            format!("/log/entries/{ordinal}")
        } else {
            format!("/traces/{}/events/{}", 0, ordinal)
        };
        let projected_record = Projector::new(&sensitive).value(record, &pointer, 0)?;
        let record_numbers = numeric_literals(record, &pointer, &sensitive);
        let record_redactions = redactions(record, &pointer, &sensitive);
        records.push(serde_json::json!({
            "ordinal": ordinal,
            "location": {"kind":"json-pointer","pointer":pointer},
            "reported": projected_record,
            "binary_fields": [],
            "numeric_literals": record_numbers,
            "redactions": record_redactions,
            "limitations": ["Native JSON projection preserves observed source structure; producer-specific binary and transport semantics remain unavailable."]
        }));
    }
    // Selection is validated here but applied by the shared Evidence service,
    // which must retain the complete producer sequence for later views.
    let _selected = selected_ordinals(object.get("record_ordinals"), records.len())?;
    let container_numbers = numeric_literals(&source, "", &sensitive);
    let container_redactions = redactions(&source, "", &sensitive);
    let container = projected;
    let mut result = serde_json::json!({
        "format": format,
        "artifact": {"path": path, "sha256": digest, "bytes": bytes.len()},
        "runtime_attribution": "unknown",
        "decoder": {"id":"rea-native-json", "name":"REA bounded JSON capture decoder", "version":"1"},
        "container": {"reported":container,"numeric_literals":container_numbers,"redactions":container_redactions,"records_pointer": if format == "har" {Value::String("/log/entries".into())} else {Value::Null}},
        "total_records": records.len(),
        "records": records,
        "limitations": ["Historical inspection is offline and does not contact recorded destinations.", "Runtime attribution and original producer binary bytes are unknown in this native JSON projection."]
    });
    if format == "qlog" {
        result["qlog"] = qlog_facts(&source, records.len());
    }
    if serde_json::to_vec(&result)
        .map_err(|_| provider_failure("unable to serialize capture result".into()))?
        .len()
        > MAX_OUTPUT_BYTES
    {
        return Err(invalid("capture result exceeds the 96 MiB output limit"));
    }
    Ok(result)
}

fn records_for<'a>(format: &str, source: &'a Value) -> Result<Vec<&'a Value>, Failure> {
    match format {
        "har" => source
            .get("log")
            .and_then(|log| log.get("entries"))
            .and_then(Value::as_array)
            .map(|values| values.iter().collect())
            .ok_or_else(|| invalid("HAR must contain log.entries")),
        "qlog" => source
            .get("traces")
            .and_then(Value::as_array)
            .map(|traces| {
                traces
                    .iter()
                    .flat_map(|trace| {
                        trace
                            .get("events")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                    })
                    .collect()
            })
            .ok_or_else(|| invalid("qlog must contain traces")),
        _ => Err(unsupported(format, "format has no JSON record projection")),
    }
}

fn selected_ordinals(value: Option<&Value>, total: usize) -> Result<Vec<usize>, Failure> {
    let values = value
        .map(|value| value.as_array().expect("validated array"))
        .map(|values| {
            values
                .iter()
                .map(|value| value.as_u64().expect("validated ordinal") as usize)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| (0..total).collect());
    if values.iter().any(|value| *value >= total) {
        return Err(invalid("record ordinal is outside the retained capture"));
    }
    Ok(values)
}

fn sensitive_values(value: Option<&Value>) -> Vec<String> {
    value
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

fn numeric_literals(value: &Value, pointer: &str, sensitive: &[String]) -> Vec<Value> {
    let mut literals = Vec::new();
    collect_numeric_literals(value, pointer, sensitive, &mut literals);
    literals
}

fn collect_numeric_literals(
    value: &Value,
    pointer: &str,
    sensitive: &[String],
    output: &mut Vec<Value>,
) {
    match value {
        Value::Number(number) => {
            let literal = number.to_string();
            if !sensitive.iter().any(|secret| literal.contains(secret)) {
                let producer_type = if number.is_i64() || number.is_u64() {
                    "integer"
                } else {
                    "float"
                };
                output.push(serde_json::json!({
                    "pointer": pointer,
                    "producer_type": producer_type,
                    "literal": literal,
                }));
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_numeric_literals(child, &format!("{pointer}/{index}"), sensitive, output);
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                if sensitive.iter().any(|secret| key.contains(secret)) {
                    continue;
                }
                collect_numeric_literals(
                    child,
                    &format!("{pointer}/{}", escape_pointer(key)),
                    sensitive,
                    output,
                );
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
}

fn redactions(value: &Value, pointer: &str, sensitive: &[String]) -> Vec<Value> {
    let mut output = Vec::new();
    collect_redactions(value, pointer, sensitive, &mut output);
    output
}

fn collect_redactions(value: &Value, pointer: &str, sensitive: &[String], output: &mut Vec<Value>) {
    match value {
        Value::String(text) if sensitive.iter().any(|secret| text.contains(secret)) => {
            output.push(serde_json::json!({
                "pointer": pointer,
                "reason": "explicit-sensitive-value",
            }));
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_redactions(child, &format!("{pointer}/{index}"), sensitive, output);
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                let child_pointer = format!("{pointer}/{}", escape_pointer(key));
                if sensitive.iter().any(|secret| key.contains(secret)) {
                    output.push(serde_json::json!({
                        "pointer": pointer,
                        "reason": "explicit-sensitive-value",
                        "scope": "property-name",
                    }));
                    continue;
                }
                collect_redactions(child, &child_pointer, sensitive, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

struct Projector<'a> {
    sensitive: &'a [String],
}
impl<'a> Projector<'a> {
    fn new(sensitive: &'a [String]) -> Self {
        Self { sensitive }
    }
    fn value(&self, value: &Value, pointer: &str, depth: usize) -> Result<Value, Failure> {
        if depth > MAX_DEPTH {
            return Err(invalid("capture exceeds the 64-level nesting limit"));
        }
        match value {
            Value::String(text) if self.sensitive.iter().any(|literal| text.contains(literal)) => {
                Ok(Value::Null)
            }
            Value::Array(values) => Ok(Value::Array(
                values
                    .iter()
                    .enumerate()
                    .map(|(index, value)| {
                        self.value(value, &format!("{pointer}/{index}"), depth + 1)
                    })
                    .collect::<Result<_, _>>()?,
            )),
            Value::Object(values) => {
                let mut output = Map::new();
                for (key, value) in values {
                    if self.sensitive.iter().any(|literal| key.contains(literal)) {
                        continue;
                    }
                    output.insert(
                        key.clone(),
                        self.value(
                            value,
                            &format!("{pointer}/{}", escape_pointer(key)),
                            depth + 1,
                        )?,
                    );
                }
                Ok(Value::Object(output))
            }
            other => Ok(other.clone()),
        }
    }
}

fn qlog_facts(source: &Value, records: usize) -> Value {
    let traces = source
        .get("traces")
        .and_then(Value::as_array)
        .map(|traces| {
            traces
                .iter()
                .enumerate()
                .map(|(index, trace)| {
                    serde_json::json!({
                        "trace_index": index,
                        "location": {
                            "kind": "json-pointer",
                            "pointer": format!("/traces/{index}"),
                        },
                        "event_count": trace
                            .get("events")
                            .and_then(Value::as_array)
                            .map_or(0, Vec::len),
                        "odcid": null,
                        "vantage_point": null,
                        "incomplete_fact_records": [],
                        "loss_declarations": [],
                        "streams": [],
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            vec![serde_json::json!({
                "trace_index": 0,
                "location": {
                    "kind": "unknown",
                    "reason": "explicit-sensitive-value",
                },
                "event_count": records,
                "odcid": null,
                "vantage_point": null,
                "incomplete_fact_records": [],
                "loss_declarations": [],
                "streams": [],
            })]
        });

    serde_json::json!({
        "profile": "aioquic-1.5.0-json-0.3",
        "scope": "all-recorded-events-before-selection",
        "body_bytes": "not-reported",
        "clock": {
            "unit": "milliseconds",
            "domain": "unix-epoch",
            "basis": "selected-aioquic-profile-not-producer-authentication",
        },
        "traces": traces,
    })
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}
fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a bounded absolute capture path and supported format.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn provider_failure(reason: String) -> Failure {
    Failure::new(
        "provider_error",
        "provider",
        reason,
        true,
        "Retry the offline capture inspection.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn unsupported(format: &str, reason: &str) -> Failure {
    Failure::new(
        "unsupported",
        "unsupported",
        format!("{format}: {reason}"),
        false,
        "Use a supported capture decoder.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
