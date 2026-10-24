//! MCP tool-result delivery shared by every tool.
//!
//! Compatibility owners: `src/server/toolResult.ts`,
//! `src/server/toolResultEncoding.ts` and the oversized-error recovery in
//! `src/server/EvidenceMcpServer.ts`.
use super::catalog::ToolContract;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use serde_json::{Map, Value, json};
use std::io::{self, Write};

/// The original SDK's stdio receive buffer.
pub const STDIO_DEFAULT_MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024;
/// Node's maximum string length minus the original safety margin.
pub const MCP_RESULT_STRING_LIMIT: usize = 536_870_888 - 1024;

/// Results containing analysis-target text are marked untrusted.
pub fn target_content_meta() -> Value {
    json!({ "provenance": { "untrusted_content": true, "source": "analysis_target" } })
}

/// Bytes of `{"content":[{"type":"text","text":""}],"structuredContent":null}` minus 4.
const RESULT_ENVELOPE_BYTES: usize = 60;
/// Bytes of `{"content":[{"type":"text","text":""}],"isError":true}`.
const ERROR_RESULT_ENVELOPE_BYTES: usize = 54;
/// Bytes of `,"_meta":{...}` added to a delivered result.
const TARGET_CONTENT_META_BYTES: usize = 77;

/// Inventories whose oversized success is delivered as a retained receipt.
const INVENTORY_OPERATIONS: [&str; 2] = ["list_procedures", "list_strings"];

/// `evidenceContinuation`: the first retained page view for paged Evidence.
/// String rows carry typed decoding metadata, so their initial page is smaller.
fn continuation_view(operation: Option<&str>) -> Option<Value> {
    match operation? {
        "analyze_function" => Some(json!({ "kind": "native", "facet": "pseudocode", "offset": 0 })),
        "list_procedures" => Some(json!({
            "kind": "page", "collection": "procedures", "offset": 0, "limit": 256
        })),
        "list_strings" => Some(json!({
            "kind": "page", "collection": "strings", "offset": 0, "limit": 16
        })),
        _ => None,
    }
}

/// Outcome of encoding a result within the wire budget.
pub enum Encoding {
    Fits {
        text: String,
    },
    Exceeds {
        bytes_at_least: usize,
        code_units_at_least: usize,
        constraint: &'static str,
    },
}

// Measure both representations directly from the serializer. In particular,
// rejected results never need an owned JSON string or its escaped copy.
#[derive(Default)]
struct WireSize {
    bytes: usize,
    units: usize,
    escaped_bytes: usize,
    escaped_units: usize,
}

#[cfg(test)]
mod size_tests {
    use super::*;

    #[test]
    fn streaming_sizes_match_owned_encoding_at_budget_boundaries() {
        let controls: String = (0..=255).filter_map(char::from_u32).collect();
        for value in [
            Value::Null,
            json!({}),
            json!([]),
            json!({"control": controls, "unicode": "é中😀\u{2028}\u{2029}", "quote": "\"\\/"}),
            json!({"items": [null, true, false, -0.0, 1e30, u64::MAX, {"a": "b"}]}),
        ] {
            let text = serde_json::to_string(&value).unwrap();
            let escaped = serde_json::to_string(&text).unwrap();
            for structured in [false, true] {
                for target in [false, true] {
                    let base = if structured {
                        RESULT_ENVELOPE_BYTES
                    } else {
                        ERROR_RESULT_ENVELOPE_BYTES
                    } + if target { TARGET_CONTENT_META_BYTES } else { 0 };
                    let bytes = base + if structured { text.len() } else { 0 } + escaped.len() - 2;
                    let units =
                        base + if structured {
                            text.encode_utf16().count()
                        } else {
                            0
                        } + escaped.encode_utf16().count()
                            - 2;
                    assert!(
                        matches!(encode(&value, bytes, structured, target), Encoding::Fits { text: actual } if actual == text)
                    );
                    assert!(
                        matches!(encode(&value, bytes - 1, structured, target), Encoding::Exceeds {
                        bytes_at_least, code_units_at_least, constraint: "receive-buffer",
                    } if bytes_at_least == bytes && code_units_at_least == units)
                    );
                }
            }
        }
    }

    #[test]
    fn size_counter_handles_split_utf8_and_every_control_escape() {
        let text: String = (0..=255)
            .filter_map(char::from_u32)
            .chain("中😀".chars())
            .collect();
        let mut size = WireSize::default();
        for byte in text.bytes() {
            size.write_all(&[byte]).unwrap();
        }
        let escaped = serde_json::to_string(&text).unwrap();
        assert_eq!(size.bytes, text.len());
        assert_eq!(size.units, text.encode_utf16().count());
        assert_eq!(size.escaped_bytes, escaped.len() - 2);
        assert_eq!(size.escaped_units, escaped.encode_utf16().count() - 2);
    }
}

impl Write for WireSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes += bytes.len();
        self.escaped_bytes += bytes.len();
        for &byte in bytes {
            // Count UTF-16 units by UTF-8 leading bytes. This also works if a
            // writer call splits a code point across chunks.
            let units = match byte {
                0x00..=0x7f | 0xc0..=0xef => 1,
                0xf0..=0xf7 => 2,
                _ => 0,
            };
            let escape_extra = match byte {
                b'"' | b'\\' | b'\x08' | b'\t' | b'\n' | b'\x0c' | b'\r' => 1,
                0x00..=0x1f => 5,
                _ => 0,
            };
            self.units += units;
            self.escaped_units += units + escape_extra;
            self.escaped_bytes += escape_extra;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Account for both delivered representations before allocating the reply.
pub fn encode(value: &Value, budget: usize, structured: bool, target_content: bool) -> Encoding {
    let mut size = WireSize::default();
    if serde_json::to_writer(&mut size, value).is_err() {
        size = WireSize::default();
        let _ = size.write(b"null");
    }
    let base = if structured {
        RESULT_ENVELOPE_BYTES
    } else {
        ERROR_RESULT_ENVELOPE_BYTES
    } + if target_content {
        TARGET_CONTENT_META_BYTES
    } else {
        0
    };
    let bytes = base + if structured { size.bytes } else { 0 } + size.escaped_bytes;
    let code_units = base + if structured { size.units } else { 0 } + size.escaped_units;
    if bytes > budget || code_units > MCP_RESULT_STRING_LIMIT {
        return Encoding::Exceeds {
            bytes_at_least: bytes,
            code_units_at_least: code_units,
            constraint: if code_units > MCP_RESULT_STRING_LIMIT {
                "string-length"
            } else {
                "receive-buffer"
            },
        };
    }
    Encoding::Fits {
        text: serde_json::to_string(value).unwrap_or_else(|_| "null".into()),
    }
}

/// Immutable encoding and recovery policy shared by one server.
#[derive(Clone, Copy, Debug)]
pub struct Delivery {
    pub result_budget_bytes: usize,
}

impl Delivery {
    /// Bind the configured maximum response size (default: stdio buffer).
    pub fn new(maximum_response_bytes: Option<usize>) -> Self {
        Self {
            result_budget_bytes: maximum_response_bytes
                .unwrap_or(STDIO_DEFAULT_MAX_BUFFER_SIZE)
                .saturating_sub(1024),
        }
    }

    /// Deliver a plain value (session tools wrap it as `{ result }`).
    pub fn value(&self, value: Value, contract: &ToolContract) -> Value {
        let value = if contract.is_session() {
            json!({ "result": value })
        } else {
            value
        };
        self.success(value, contract, Map::new())
    }

    /// Deliver retained Evidence, or the recording failure.
    pub fn evidence(
        &self,
        evidence: &Evidence,
        contract: &ToolContract,
        recorded: Result<(), AnalysisError>,
    ) -> Value {
        if let Err(error) = recorded {
            return self.error(&error, contract.returns_target_content);
        }
        let mut recovery = Map::new();
        recovery.insert("evidence_id".into(), json!(evidence.id()));
        recovery.insert(
            "evidence_reference".into(),
            json!({ "kind": "retained-evidence", "evidence_id": evidence.id() }),
        );
        if let Some(view) = continuation_view(evidence.value()["operation"].as_str()) {
            recovery.insert(
                "continuation".into(),
                json!({
                    "name": "inspect_analysis_view",
                    "arguments": {
                        "source": { "kind": "retained-evidence", "evidence_id": evidence.id() },
                        "view": view
                    }
                }),
            );
        }
        self.success(evidence.value().clone(), contract, recovery)
    }

    /// `retainedInventoryResult`: a completed inventory remains successful
    /// when its rows require paged delivery through the retained Evidence.
    fn retained_inventory(
        &self,
        value: &Value,
        contract: &ToolContract,
        recovery: &Map<String, Value>,
    ) -> Option<Value> {
        if !INVENTORY_OPERATIONS.contains(&contract.name.as_str())
            || !recovery.contains_key("evidence_reference")
            || !recovery.contains_key("continuation")
        {
            return None;
        }
        let rows = value.get("normalized_result")?.as_array()?;
        let mut receipt = Map::new();
        receipt.insert("operation".into(), json!(contract.name));
        receipt.insert("delivery".into(), json!("retained-inventory"));
        receipt.insert("total_items".into(), json!(rows.len()));
        receipt.insert(
            "message".into(),
            json!("The complete inventory is retained. Call inspect_analysis_view with the continuation arguments to read its rows. Follow coverage.next_offset until every row has been read."),
        );
        for (key, entry) in recovery {
            receipt.insert(key.clone(), entry.clone());
        }
        let receipt = Value::Object(receipt);
        let Encoding::Fits { text } = encode(
            &receipt,
            self.result_budget_bytes,
            true,
            contract.returns_target_content,
        ) else {
            return None;
        };
        let mut result = Map::new();
        if contract.returns_target_content {
            result.insert("_meta".into(), target_content_meta());
        }
        result.insert("content".into(), json!([{ "type": "text", "text": text }]));
        result.insert("structuredContent".into(), receipt);
        Some(Value::Object(result))
    }

    /// Project a typed failure; the structured copy is only a private carrier.
    pub fn error(&self, error: &AnalysisError, target_content: bool) -> Value {
        self.projected_error(error.project(), target_content)
    }

    /// Deliver the original failure with a retained partial Evidence reference.
    pub fn partial_error(
        &self,
        error: &AnalysisError,
        evidence_id: &str,
        recorded: Result<(), AnalysisError>,
        target_content: bool,
    ) -> Value {
        if recorded.is_err() {
            return self.error(error, target_content);
        }
        let mut projected = error.project();
        if let Some(object) = projected.as_object_mut() {
            let details = object
                .entry("details")
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(details) = details.as_object_mut() {
                details.insert(
                    "partial_observation".into(),
                    json!({ "kind": "retained-evidence", "evidence_id": evidence_id }),
                );
            }
        }
        self.projected_error(projected, target_content)
    }

    fn projected_error(&self, projected: Value, target_content: bool) -> Value {
        let structured = json!({ "error": projected });
        let content = match encode(&structured, self.result_budget_bytes, false, target_content) {
            Encoding::Fits { text } => json!([{ "type": "text", "text": text }]),
            Encoding::Exceeds { .. } => json!([]),
        };
        let mut result = Map::new();
        result.insert("content".into(), content);
        result.insert("structuredContent".into(), structured);
        result.insert("isError".into(), json!(true));
        if target_content {
            result.insert("_meta".into(), target_content_meta());
        }
        Value::Object(result)
    }

    fn success(
        &self,
        value: Value,
        contract: &ToolContract,
        recovery: Map<String, Value>,
    ) -> Value {
        match encode(
            &value,
            self.result_budget_bytes,
            true,
            contract.returns_target_content,
        ) {
            Encoding::Fits { text } => {
                let mut result = Map::new();
                if contract.returns_target_content {
                    result.insert("_meta".into(), target_content_meta());
                }
                result.insert("content".into(), json!([{ "type": "text", "text": text }]));
                result.insert("structuredContent".into(), value);
                Value::Object(result)
            }
            Encoding::Exceeds {
                bytes_at_least,
                code_units_at_least,
                constraint,
            } => {
                if let Some(receipt) = self.retained_inventory(&value, contract, &recovery) {
                    return receipt;
                }
                let retained = recovery.contains_key("evidence_reference");
                let advice = if recovery.contains_key("continuation") {
                    "Call inspect_analysis_view with the supplied continuation arguments to read the retained analysis in pages. Follow coverage.next_offset for subsequent pages; reduce the page limit if needed, or export the complete retained Evidence."
                } else if retained {
                    "Export retained evidence to consume the complete analysis, or use complete CLI JSON output."
                } else if constraint == "string-length" {
                    "Use complete CLI JSON output to consume the analysis."
                } else {
                    "Use a larger MCP response budget with a matching client receive buffer, or use complete CLI JSON output to consume the analysis."
                };
                let message = if constraint == "string-length" {
                    format!(
                        "The operation completed, but its complete MCP response exceeds Node's single-string representation limit. {advice}"
                    )
                } else {
                    format!(
                        "The operation completed, but its complete MCP response exceeds the stdio response budget. The analysis result was not truncated. {advice}"
                    )
                };
                let mut limits = Map::new();
                limits.insert("boundary".into(), json!("mcp-response"));
                limits.insert(
                    "default_receive_buffer_bytes".into(),
                    json!(STDIO_DEFAULT_MAX_BUFFER_SIZE),
                );
                limits.insert(
                    "result_budget_bytes".into(),
                    json!(self.result_budget_bytes),
                );
                limits.insert(
                    "max_string_code_units".into(),
                    json!(MCP_RESULT_STRING_LIMIT),
                );
                limits.insert("response_bytes_at_least".into(), json!(bytes_at_least));
                limits.insert(
                    "response_code_units_at_least".into(),
                    json!(code_units_at_least),
                );
                limits.insert("constraint".into(), json!(constraint));
                for (key, value) in &recovery {
                    limits.insert(key.clone(), value.clone());
                }
                let mut error = AnalysisError::resource_constraint(
                    contract.name.clone(),
                    "transport",
                    message,
                    Some(Value::Object(limits)),
                );
                if recovery.contains_key("continuation") {
                    error = error.with_remediation(advice);
                }
                self.error(&error, contract.returns_target_content)
            }
        }
    }

    /// The SDK's text-only tool error (validation failure or thrown handler).
    pub fn sdk_error(&self, message: String, target_content: bool) -> Value {
        let mut result = Map::new();
        result.insert(
            "content".into(),
            json!([{ "type": "text", "text": message }]),
        );
        result.insert("isError".into(), json!(true));
        if target_content {
            result.insert("_meta".into(), target_content_meta());
        }
        Value::Object(result)
    }

    /// Final wire projection of an error result: strip the private carrier and
    /// retain/replace a reply that exceeds the response budget.
    pub fn finalize(
        &self,
        tool: Option<&str>,
        target_content: bool,
        mut result: Value,
        retain: &dyn Fn(&Evidence) -> Result<(), AnalysisError>,
    ) -> Value {
        if result.get("isError") != Some(&Value::Bool(true)) {
            return result;
        }
        let structured = result
            .as_object_mut()
            .and_then(|object| object.remove("structuredContent"));
        let oversized = match &structured {
            Some(structured) => matches!(
                encode(structured, self.result_budget_bytes, false, target_content),
                Encoding::Exceeds { .. }
            ),
            None => serde_json::to_vec(&result)
                .map(|bytes| bytes.len() > self.result_budget_bytes)
                .unwrap_or(false),
        };
        if !oversized {
            if target_content
                && let Some(object) = result.as_object_mut()
                && !object.contains_key("_meta")
            {
                object.insert("_meta".into(), target_content_meta());
            }
            return result;
        }
        let operation = tool.unwrap_or("mcp_tool_error").to_owned();
        let mut original = result.clone();
        if let (Some(object), Some(structured)) = (original.as_object_mut(), &structured) {
            object.insert("structuredContent".into(), structured.clone());
        }
        let evidence = Evidence::create(
            None,
            &EvidenceProvider::new("rea-mcp", "REA MCP delivery", Some("1".into())),
            Observation::new(
                "mcp_tool_error",
                json!({ "tool_name": operation }),
                structured.clone().unwrap_or_else(|| original.clone()),
            )
            .raw(original),
        );
        let retained = match &evidence {
            Ok(evidence) => retain(evidence).map(|()| evidence.id().to_owned()),
            Err(error) => Err(AnalysisError::evidence_integrity(error.to_string())),
        };
        let budget = self.result_budget_bytes;
        let mut limits = Map::new();
        limits.insert("boundary".into(), json!("mcp-response"));
        if let Some(code) = structured
            .as_ref()
            .and_then(|structured| structured["error"]["code"].as_str())
        {
            limits.insert("original_error_code".into(), json!(code));
        }
        limits.insert("result_budget_bytes".into(), json!(budget));
        limits.insert("constraint".into(), json!("receive-buffer"));
        let action = match &retained {
            Ok(evidence_id) => {
                limits.insert(
                    "evidence_reference".into(),
                    json!({ "kind": "retained-evidence", "evidence_id": evidence_id }),
                );
                "Export the retained original error through export_evidence_bundle to a caller-selected path. The connection remains usable."
            }
            Err(error) => {
                limits.insert("retention".into(), json!("failed"));
                limits.insert("retention_error".into(), error.project());
                "Restart REA with a larger REA_MCP_MAX_RESPONSE_BYTES and matching client receive buffer, then retry. The original error could not be retained by this server."
            }
        };
        let failure = AnalysisError::resource_constraint(
            operation,
            "transport",
            "The tool failed, but its complete error response exceeds the MCP response budget.",
            Some(Value::Object(limits)),
        )
        .with_remediation(action);
        let mut replacement = self.error(&failure, target_content);
        if let Some(object) = replacement.as_object_mut() {
            object.remove("structuredContent");
        }
        replacement
    }
}
