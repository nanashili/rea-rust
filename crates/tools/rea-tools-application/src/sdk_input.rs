//! Zod `.trim().min(1)` request semantics the advertised JSON Schema cannot
//! express.
//!
//! The original SDK parses each request with the tool's Zod schema before the
//! handler runs: trimmed text fields are transformed (handlers receive the
//! trimmed value) and whitespace-only text fails with Zod's `too_small`
//! issue, reported as the SDK's text-only validation error. The advertised
//! JSON Schema (`minLength: 1`) admits both, so this module reapplies them.
use rea_mcp::ToolContract;
use rea_mcp::delivery::target_content_meta;
use rea_mcp::schema::{Issue, validation_error_text};
use serde_json::{Value, json};

/// Collects trim issues while normalizing trimmed fields in place.
#[derive(Default)]
pub struct Trimmer {
    issues: Vec<Issue>,
}

impl Trimmer {
    /// Trim one optional (nullable) string field at `path` in place.
    pub fn field(&mut self, value: &mut Value, path: &[String]) {
        let Some(text) = value.as_str() else {
            return;
        };
        let trimmed = js_trim(text);
        if trimmed.is_empty() {
            self.issues.push(Issue {
                path: path.to_vec(),
                message: "Too small: expected string to have >=1 characters".into(),
            });
        }
        if trimmed.len() != text.len() {
            *value = Value::String(trimmed.to_owned());
        }
    }

    /// Trim every string of an array field at `path` in place.
    pub fn each(&mut self, value: &mut Value, path: &[String]) {
        if let Some(items) = value.as_array_mut() {
            for (index, item) in items.iter_mut().enumerate() {
                self.field(item, &extend(path, &[&index.to_string()]));
            }
        }
    }

    /// The SDK validation failure, when any trimmed field became empty.
    pub fn failure(self, contract: &ToolContract) -> Option<Value> {
        if self.issues.is_empty() {
            return None;
        }
        let mut result = serde_json::Map::new();
        result.insert(
            "content".into(),
            json!([{ "type": "text", "text": validation_error_text(&contract.name, &self.issues) }]),
        );
        result.insert("isError".into(), json!(true));
        if contract.returns_target_content {
            result.insert("_meta".into(), target_content_meta());
        }
        Some(Value::Object(result))
    }
}

/// Append path segments.
pub fn extend(path: &[String], parts: &[&str]) -> Vec<String> {
    let mut path = path.to_vec();
    path.extend(parts.iter().map(|part| (*part).to_owned()));
    path
}

/// `String.prototype.trim`: ECMAScript white space and line terminators
/// (Unicode `White_Space` except U+0085, plus U+FEFF).
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(|character: char| {
        (character.is_whitespace() && character != '\u{85}') || character == '\u{FEFF}'
    })
}
