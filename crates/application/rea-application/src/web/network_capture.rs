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
            "capture_path" | "format" | "record_ordinals" | "sensitive_values" | "detail"
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
        } else if entry.path.starts_with("raw/") {
            return Err(unsupported(
                "saz",
                "SAZ contains an unrecognized raw session member",
            ));
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
        let mut request_url_had_credentials = false;
        for entry in group {
            let member = inflate_saz_entry(bytes, entry)?;
            let value = if entry.path.ends_with("_c.txt") {
                request_url_had_credentials = saz_request_url_has_credentials(&member);
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
        let url_is_explicitly_sensitive = source
            .get("request")
            .and_then(|request| request.get("url"))
            .and_then(Value::as_str)
            .is_some_and(|url| sensitive.iter().any(|literal| url.contains(literal)));
        if request_url_had_credentials && !url_is_explicitly_sensitive {
            redaction_rows.insert(
                0,
                serde_json::json!({
                    "pointer": "/request/url",
                    "reason": "transport-credential",
                }),
            );
        }
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
        "decoder":{"id":"fiddler-saz","name":"REA Fiddler SAZ capture adapter","version":"1;zip.js@2.15.0;xmldom@0.9.12"},
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
        result.insert("url".into(), Value::String(sanitize_saz_url(fields[1])));
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
                    + if separator == 4 { "\r\n" } else { "\n" }
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
        let name = &line[..index];
        if !name.bytes().enumerate().all(|(position, byte)| {
            (position == 0 && byte == b':')
                || byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                        | b'-'
                )
        }) {
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
                if key == "value" && saz_credential_field(values) {
                    redactions.push(serde_json::json!({
                        "pointer": format!("{pointer}/value"),
                        "reason": "transport-credential",
                    }));
                    output.insert(key.clone(), Value::Null);
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

fn saz_credential_field(object: &Map<String, Value>) -> bool {
    let Some(name) = object.get("name").and_then(Value::as_str) else {
        return false;
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    )
}

fn sanitize_saz_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_owned();
    };
    let authority_start = scheme_end + 3;
    let authority_end = url[authority_start..]
        .find(['/', '?', '#'])
        .map(|offset| authority_start + offset)
        .unwrap_or(url.len());
    let authority = &url[authority_start..authority_end];
    let Some(at) = authority.rfind('@') else {
        return url.to_owned();
    };
    format!(
        "{}{}{}",
        &url[..authority_start],
        &authority[at + 1..],
        &url[authority_end..]
    )
}

fn saz_request_url_has_credentials(bytes: &[u8]) -> bool {
    let line_end = bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .or_else(|| bytes.iter().position(|byte| *byte == b'\n'))
        .unwrap_or(bytes.len());
    let first_line = String::from_utf8_lossy(&bytes[..line_end]);
    let Some(url) = first_line.split_whitespace().nth(1) else {
        return false;
    };
    let Some(scheme_end) = url.find("://") else {
        return false;
    };
    let authority_start = scheme_end + 3;
    let authority_end = url[authority_start..]
        .find(['/', '?', '#'])
        .map(|offset| authority_start + offset)
        .unwrap_or(url.len());
    url[authority_start..authority_end].contains('@')
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
    if format == "qlog" {
        validate_qlog(&source)?;
    }

    let projected = Projector::new(&sensitive).value(&source, "", 0)?;
    let records_source = records_for(format, &source)?;
    let mut records = Vec::with_capacity(records_source.len());
    for (ordinal, (pointer, record)) in records_source.iter().enumerate() {
        let projected_record = Projector::new(&sensitive).value(record, &pointer, 0)?;
        let record_numbers = if format == "qlog" {
            qlog_numeric_literals(record, &sensitive)
        } else {
            numeric_literals(record, &pointer, &sensitive)
        };
        let record_redactions = redactions(record, &pointer, &sensitive);
        records.push(serde_json::json!({
            "ordinal": ordinal,
            "location": {"kind":"json-pointer","pointer":pointer},
            "reported": projected_record,
            "binary_fields": [],
            "numeric_literals": record_numbers,
            "redactions": record_redactions,
            "limitations": [if format == "qlog" { "Record ordinal is derived from trace/event source traversal, not global time order. Qlog lengths and FIN do not expose original HTTP body bytes or establish network completeness." } else { "Native JSON projection preserves observed source structure; producer-specific binary and transport semantics remain unavailable." }]
        }));
    }
    // Selection is validated here but applied by the shared Evidence service,
    // which must retain the complete producer sequence for later views.
    let _selected = selected_ordinals(object.get("record_ordinals"), records.len())?;
    let container_numbers = if format == "qlog" {
        Vec::new()
    } else {
        numeric_literals(&source, "", &sensitive)
    };
    let container_redactions = redactions(&source, "", &sensitive);
    let mut container = projected;
    if format == "qlog" {
        if let Some(traces) = container.get_mut("traces").and_then(Value::as_array_mut) {
            for trace in traces {
                if let Some(object) = trace.as_object_mut() {
                    object.insert("events".to_owned(), Value::Null);
                }
            }
        }
    }
    let mut result = serde_json::json!({
        "format": format,
        "artifact": {"path": path, "sha256": digest, "bytes": bytes.len()},
        "runtime_attribution": "unknown",
        "decoder": if format == "qlog" {
            serde_json::json!({"id":"aioquic-qlog-json","name":"REA aioquic qlog capture adapter","version":"aioquic-profile@1.5.0;qlog@0.3;jsonc-parser@3.3.1;lossless-json@4.3.1"})
        } else {
            serde_json::json!({"id":"har-schema/lossless-json","name":"REA HAR capture adapter","version":"har-schema@2.0.0;jsonc-parser@3.3.1;lossless-json@4.3.1"})
        },
        "container": {"reported":container,"numeric_literals":container_numbers,"redactions":container_redactions,"records_pointer": if format == "har" {Value::String("/log/entries".into())} else {Value::Null}},
        "total_records": records.len(),
        "records": records,
        "limitations": ["Historical inspection is offline and does not contact recorded destinations.", "Runtime attribution and original producer binary bytes are unknown in this native JSON projection."]
    });
    if format == "qlog" {
        result["qlog"] = qlog_facts(&source, records.len(), &sensitive);
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

fn records_for<'a>(format: &str, source: &'a Value) -> Result<Vec<(String, &'a Value)>, Failure> {
    match format {
        "har" => source
            .get("log")
            .and_then(|log| log.get("entries"))
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .enumerate()
                    .map(|(index, value)| (format!("/log/entries/{index}"), value))
                    .collect()
            })
            .ok_or_else(|| invalid("HAR must contain log.entries")),
        "qlog" => source
            .get("traces")
            .and_then(Value::as_array)
            .map(|traces| {
                traces
                    .iter()
                    .enumerate()
                    .flat_map(|(trace_index, trace)| {
                        trace
                            .get("events")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .enumerate()
                            .map(move |(event_index, event)| {
                                (format!("/traces/{trace_index}/events/{event_index}"), event)
                            })
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

fn qlog_numeric_literals(value: &Value, sensitive: &[String]) -> Vec<Value> {
    numeric_literals(value, "", sensitive)
        .into_iter()
        .map(|mut literal| {
            literal["producer_type"] = Value::String("json-number".to_owned());
            literal
        })
        .collect()
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
                    if key == "value" && qlog_credential_field(pointer, values) {
                        output.insert(key.clone(), Value::Null);
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

fn qlog_credential_field(pointer: &str, object: &Map<String, Value>) -> bool {
    let Some(name) = object.get("name").and_then(Value::as_str) else {
        return false;
    };
    let header_pointer = pointer.starts_with("/traces/")
        && pointer.contains("/data/frame/headers/")
        && pointer.ends_with("/value");
    header_pointer
        && matches!(
            name.to_ascii_lowercase().as_str(),
            "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
        )
}

fn validate_qlog(source: &Value) -> Result<(), Failure> {
    let traces = source
        .get("traces")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("qlog must contain a traces array"))?;
    for (trace_index, trace) in traces.iter().enumerate() {
        let events = trace
            .get("events")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                invalid(&format!(
                    "qlog trace {trace_index} must contain an events array"
                ))
            })?;
        for (event_index, event) in events.iter().enumerate() {
            let pointer = format!("/traces/{trace_index}/events/{event_index}");
            let object = event
                .as_object()
                .ok_or_else(|| invalid("qlog events must be objects"))?;
            if object.get("name").and_then(Value::as_str).is_none()
                || object
                    .get("time")
                    .and_then(Value::as_f64)
                    .is_none_or(|time| !time.is_finite())
                || !object.get("data").is_some_and(Value::is_object)
            {
                return Err(invalid(&format!(
                    "qlog event at {pointer} must have a name, finite numeric time and object data"
                )));
            }
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let data = object
                .get("data")
                .and_then(Value::as_object)
                .expect("validated data");
            if name == "recovery:packet_lost" {
                validate_qlog_unsigned(
                    data.get("packet_number"),
                    &format!("{pointer}/data/packet_number"),
                )?;
            }
            if matches!(name, "transport:packet_sent" | "transport:packet_received") {
                if let Some(frames) = data.get("frames") {
                    let frames = frames
                        .as_array()
                        .ok_or_else(|| invalid("qlog event frames must be an array"))?;
                    for (frame_index, frame) in frames.iter().enumerate() {
                        if frame.get("frame_type").and_then(Value::as_str) == Some("stream") {
                            validate_qlog_stream_frame(
                                frame,
                                &format!("{pointer}/data/frames/{frame_index}"),
                            )?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_qlog_stream_frame(frame: &Value, pointer: &str) -> Result<(), Failure> {
    let stream_id =
        validate_qlog_unsigned(frame.get("stream_id"), &format!("{pointer}/stream_id"))?;
    let offset = validate_qlog_unsigned(frame.get("offset"), &format!("{pointer}/offset"))?;
    let length = validate_qlog_unsigned(frame.get("length"), &format!("{pointer}/length"))?;
    if let (Some(offset), Some(length)) = (offset, length) {
        if offset
            .checked_add(length)
            .is_none_or(|value| value > ((1u64 << 62) - 1))
        {
            return Err(invalid(
                "qlog stream final offset exceeds the QUIC varint range",
            ));
        }
    }
    if let Some(fin) = frame.get("fin") {
        if !fin.is_null() && !fin.is_boolean() {
            return Err(invalid("qlog STREAM fin must be boolean when reported"));
        }
    }
    let _ = stream_id;
    Ok(())
}

fn validate_qlog_unsigned(value: Option<&Value>, _pointer: &str) -> Result<Option<u64>, Failure> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(number) = value.as_u64() else {
        return Err(invalid(
            "qlog QUIC integer must be a non-negative integer within the 62-bit range",
        ));
    };
    if number > ((1u64 << 62) - 1) {
        return Err(invalid("qlog QUIC integer exceeds the 62-bit range"));
    }
    Ok(Some(number))
}

struct QlogTraceFact {
    event_count: usize,
    odcid: Option<String>,
    vantage_point: Option<String>,
    incomplete: Vec<usize>,
    losses: Vec<Value>,
    streams_in_order: Vec<QlogStreamFact>,
    streams: Vec<Value>,
}

struct QlogStreamFact {
    stream_id: String,
    direction: String,
    contributions: Vec<Value>,
}

impl QlogTraceFact {
    fn new(index: usize, event_count: usize, trace: &Value, sensitive: &[String]) -> Self {
        let common = trace.get("common_fields").and_then(Value::as_object);
        let vantage = trace
            .get("vantage_point")
            .and_then(Value::as_object)
            .and_then(|value| value.get("type"))
            .and_then(Value::as_str)
            .filter(|value| matches!(*value, "client" | "server"))
            .map(str::to_owned);
        let _ = index;
        Self {
            event_count,
            odcid: common
                .and_then(|value| value.get("ODCID"))
                .and_then(Value::as_str)
                .filter(|value| !sensitive.iter().any(|literal| value.contains(literal)))
                .map(str::to_owned),
            vantage_point: vantage,
            incomplete: Vec::new(),
            losses: Vec::new(),
            streams_in_order: Vec::new(),
            streams: Vec::new(),
        }
    }

    fn consume(&mut self, event: &Value, ordinal: usize) {
        let Some(object) = event.as_object() else {
            self.incomplete.push(ordinal);
            return;
        };
        let Some(name) = object.get("name").and_then(Value::as_str) else {
            self.incomplete.push(ordinal);
            return;
        };
        let Some(data) = object.get("data").and_then(Value::as_object) else {
            self.incomplete.push(ordinal);
            return;
        };
        if name == "recovery:packet_lost" {
            let packet_number = data
                .get("packet_number")
                .and_then(Value::as_u64)
                .map(|value| value.to_string());
            let packet_type = data.get("type").and_then(Value::as_str);
            self.losses.push(serde_json::json!({
                "record_ordinal": ordinal,
                "confidence": "observed",
                "packet_number": packet_number.map_or_else(
                    || serde_json::json!({"state":"unknown","reason":"omitted-null-or-redacted"}),
                    |value| serde_json::json!({"state":"reported","value":value}),
                ),
                "packet_type": packet_type,
                "packet_number_space": match packet_type {
                    Some("initial") => "initial",
                    Some("handshake") => "handshake",
                    Some("0RTT") | Some("1RTT") => "application",
                    _ => "unknown",
                },
            }));
        }
        if !matches!(name, "transport:packet_sent" | "transport:packet_received") {
            return;
        }
        let Some(frames) = data.get("frames").and_then(Value::as_array) else {
            self.incomplete.push(ordinal);
            return;
        };
        let direction = if name == "transport:packet_sent" {
            "sent"
        } else {
            "received"
        };
        for (frame_index, frame) in frames.iter().enumerate() {
            let Some(frame_object) = frame.as_object() else {
                self.incomplete.push(ordinal);
                continue;
            };
            if frame_object.get("frame_type").and_then(Value::as_str) != Some("stream") {
                continue;
            }
            let Some(stream_id) = frame_object.get("stream_id").and_then(Value::as_u64) else {
                self.incomplete.push(ordinal);
                continue;
            };
            let Some(offset) = frame_object.get("offset").and_then(Value::as_u64) else {
                self.incomplete.push(ordinal);
                continue;
            };
            let Some(length) = frame_object.get("length").and_then(Value::as_u64) else {
                self.incomplete.push(ordinal);
                continue;
            };
            let stream_index = self.streams_in_order.iter().position(|stream| {
                stream.direction == direction && stream.stream_id == stream_id.to_string()
            });
            let stream = if let Some(index) = stream_index {
                &mut self.streams_in_order[index]
            } else {
                self.streams_in_order.push(QlogStreamFact {
                    stream_id: stream_id.to_string(),
                    direction: direction.to_owned(),
                    contributions: Vec::new(),
                });
                self.streams_in_order
                    .last_mut()
                    .expect("just inserted stream")
            };
            stream.contributions.push(serde_json::json!({
                "record_ordinal": ordinal,
                "frame_index": frame_index,
                "offset": offset.to_string(),
                "length": length.to_string(),
                "fin": frame_object.get("fin").and_then(Value::as_bool),
            }));
        }
    }

    fn finish(&mut self) {
        self.incomplete.sort_unstable();
        self.incomplete.dedup();
        for stream in &mut self.streams_in_order {
            let mut ranges: Vec<(u64, u64)> = stream
                .contributions
                .iter()
                .filter_map(|value| {
                    Some((
                        value.get("offset")?.as_str()?.parse::<u64>().ok()?,
                        value
                            .get("offset")?
                            .as_str()?
                            .parse::<u64>()
                            .ok()?
                            .checked_add(value.get("length")?.as_str()?.parse::<u64>().ok()?)?,
                    ))
                })
                .filter(|(start, end)| start < end)
                .collect();
            ranges.sort_unstable();
            let mut merged: Vec<(u64, u64)> = Vec::new();
            for (start, end) in ranges {
                if let Some(last) = merged.last_mut() {
                    if start <= last.1 {
                        last.1 = last.1.max(end);
                        continue;
                    }
                }
                merged.push((start, end));
            }
            let frame_length_sum: u64 = stream
                .contributions
                .iter()
                .filter_map(|value| value.get("length")?.as_str()?.parse::<u64>().ok())
                .sum();
            let unique_bytes: u64 = merged.iter().map(|(start, end)| end - start).sum();
            let reported_final_sizes: Vec<String> = stream
                .contributions
                .iter()
                .filter(|value| value.get("fin").and_then(Value::as_bool) == Some(true))
                .filter_map(|value| {
                    let offset = value.get("offset")?.as_str()?.parse::<u64>().ok()?;
                    let length = value.get("length")?.as_str()?.parse::<u64>().ok()?;
                    Some(offset.checked_add(length)?.to_string())
                })
                .collect();
            let mut final_sizes = reported_final_sizes;
            final_sizes.sort();
            final_sizes.dedup();
            stream_summary_replace(stream, merged, frame_length_sum, unique_bytes, final_sizes);
        }
        self.streams = self
            .streams_in_order
            .iter()
            .flat_map(|stream| stream.contributions.iter().cloned())
            .collect();
    }
}

fn stream_summary_replace(
    stream: &mut QlogStreamFact,
    ranges: Vec<(u64, u64)>,
    frame_length_sum: u64,
    unique_bytes: u64,
    final_sizes: Vec<String>,
) {
    let contributions = std::mem::take(&mut stream.contributions);
    stream.contributions = vec![serde_json::json!({
        "stream_id": stream.stream_id,
        "direction": stream.direction,
        "confidence": "derived",
        "scope": "observed-stream-frame-ranges",
        "contributions": contributions,
        "covered_ranges": ranges.into_iter().map(|(start,end)| serde_json::json!({"start":start.to_string(),"end":end.to_string()})).collect::<Vec<_>>(),
        "unique_bytes": unique_bytes.to_string(),
        "frame_length_sum": frame_length_sum.to_string(),
        "repeated_bytes": frame_length_sum.saturating_sub(unique_bytes).to_string(),
        "reported_final_sizes": final_sizes,
    })];
}

fn qlog_facts(source: &Value, records: usize, sensitive: &[String]) -> Value {
    let traces = source
        .get("traces")
        .and_then(Value::as_array)
        .map(|traces| {
            traces
                .iter()
                .enumerate()
                .map(|(index, trace)| {
                    let events = trace
                        .get("events")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    let mut fact = QlogTraceFact::new(index, events.len(), trace, sensitive);
                    let base_ordinal = traces
                        .iter()
                        .take(index)
                        .map(|previous| {
                            previous
                                .get("events")
                                .and_then(Value::as_array)
                                .map_or(0, Vec::len)
                        })
                        .sum::<usize>();
                    for (ordinal, event) in events.iter().enumerate() {
                        fact.consume(event, base_ordinal + ordinal);
                    }
                    fact.finish();
                    serde_json::json!({
                        "trace_index": index,
                        "location": {
                            "kind": "json-pointer",
                            "pointer": format!("/traces/{index}"),
                        },
                        "event_count": fact.event_count,
                        "odcid": fact.odcid,
                        "vantage_point": fact.vantage_point,
                        "incomplete_fact_records": fact.incomplete,
                        "loss_declarations": fact.losses,
                        "streams": fact.streams,
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
