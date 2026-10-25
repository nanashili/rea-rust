//! Named application input boundaries. Adapters consume parsed facts rather
//! than reinterpreting serde errors as caller validation diagnostics.
use crate::{
    apple::asset_catalog_workflow::{
        DEFAULT_LIMIT as ASSET_CATALOG_DEFAULT_LIMIT, MAX_LIMIT as ASSET_CATALOG_MAX_LIMIT,
        Page as AssetCatalogPage,
    },
    apple::keyed_archive::KeyedArchiveSelection,
    interface_builder::types::{
        InterfaceBuilderLimits, MAX_CONNECTIONS, MAX_DOCUMENTS, MAX_OBJECTS,
    },
    ledger::artifact_records::{DetailLevel, Filters, Query, UnknownQuery},
    ledger::bundle_export::Input,
};
use rea_core::failure::InputIssue;
use rea_rust_analysis::{pe, sqlite};
use serde_json::{Map, Value};
use std::fmt;

mod unknown_inputs;

pub use unknown_inputs::{record_unknown, update_unknown};

#[derive(Debug)]
pub struct InputError(pub Vec<InputIssue>);
impl fmt::Display for InputError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, issue) in self.0.iter().enumerate() {
            if index != 0 {
                out.write_str(", ")?;
            }
            if !issue.path.is_empty() {
                write!(out, "{}: ", issue.path.join("."))?;
            }
            out.write_str(&issue.message)?;
        }
        Ok(())
    }
}
impl std::error::Error for InputError {}

/// Caller-selected bounds for a complete PE resource inventory.
#[derive(Clone, Debug)]
pub struct PeResourcesInput {
    pub path: String,
    pub max_file_bytes: usize,
    pub max_entries: usize,
}

#[derive(Clone, Debug)]
pub struct AndroidClassSearchInput {
    pub path: String,
    pub query: String,
}

#[derive(Clone, Debug)]
pub struct AndroidReferenceTraceInput {
    pub path: String,
    pub class_name: String,
    pub method_name: Option<String>,
    pub overload_index: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct KeyedArchiveInput {
    pub path: String,
    pub selection: KeyedArchiveSelection,
}

#[derive(Clone, Debug)]
pub struct InterfaceBuilderInput {
    pub path: String,
    pub target_sha256: String,
    pub limits: InterfaceBuilderLimits,
}

#[derive(Clone, Debug)]
pub struct AssetCatalogPageInput {
    pub page: AssetCatalogPage,
}

#[derive(Clone, Debug)]
pub struct AssetCatalogCliInput {
    pub path: String,
    pub target_sha256: String,
    pub page: AssetCatalogPage,
}

/// Caller-selected SQLite inspection options shared by MCP and CLI adapters.
#[derive(Clone, Debug)]
pub struct SqliteInspectionInput {
    pub path: String,
    pub selection: sqlite::Input,
}

#[derive(Default)]
struct Parser {
    issues: Vec<InputIssue>,
}
impl Parser {
    fn issue(&mut self, path: &[&str], reason: &'static str, message: String) {
        self.issues.push(InputIssue {
            path: path.iter().map(|s| (*s).into()).collect(),
            reason,
            message,
            expected: None,
        });
    }
    fn wrong_type(&mut self, path: &[&str], expected: &'static str, value: Option<&Value>) {
        let received = match value {
            None => "undefined",
            Some(Value::Null) => "null",
            Some(Value::Bool(_)) => "boolean",
            Some(Value::Number(_)) => "number",
            Some(Value::String(_)) => "string",
            Some(Value::Array(_)) => "array",
            Some(Value::Object(_)) => "object",
        };
        self.issue(
            path,
            "invalid_type",
            format!("Invalid input: expected {expected}, received {received}"),
        );
    }
    fn string<'a>(
        &mut self,
        value: Option<&'a Value>,
        path: &[&str],
        required: bool,
        nonempty: bool,
    ) -> Option<&'a str> {
        let text = match value {
            Some(Value::String(text)) => Some(text.as_str()),
            None if !required => None,
            value => {
                self.wrong_type(path, "string", value);
                None
            }
        };
        if nonempty {
            if let Some(text) = text {
                self.nonempty(text, path);
            }
            // The original Standard Schema boundary reports its length check
            // alongside a string type failure for an empty array.
            if matches!(value, Some(Value::Array(items)) if items.is_empty()) {
                self.issue(
                    path,
                    "too_small",
                    "Too small: expected array to have >=1 items".into(),
                );
            }
        }
        text
    }
    fn nonempty(&mut self, text: &str, path: &[&str]) {
        if text.is_empty() {
            self.issue(
                path,
                "too_small",
                "Too small: expected string to have >=1 characters".into(),
            );
        }
    }
    fn enum_string<'a>(
        &mut self,
        value: Option<&'a Value>,
        path: &[&str],
        choices: &[&str],
    ) -> Option<&'a str> {
        match value {
            None => None,
            Some(Value::String(text)) if choices.contains(&text.as_str()) => Some(text),
            Some(Value::String(_)) => {
                self.issue(
                    path,
                    "invalid_value",
                    format!(
                        "Invalid option: expected one of {}",
                        choices
                            .iter()
                            .map(|choice| format!("\"{choice}\""))
                            .collect::<Vec<_>>()
                            .join("|")
                    ),
                );
                None
            }
            value => {
                self.wrong_type(path, "string", value);
                None
            }
        }
    }
    fn safe_integer(
        &mut self,
        value: Option<&Value>,
        path: &[&str],
        default: Option<u64>,
        minimum: u64,
    ) -> Option<u64> {
        const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

        let Some(value) = value else {
            return default;
        };
        let Some(number) = value.as_number() else {
            self.wrong_type(path, "number", Some(value));
            return None;
        };
        let Some(number_as_float) = number.as_f64() else {
            self.issue(path, "invalid_value", "Expected a safe integer".into());
            return None;
        };
        if !number_as_float.is_finite() || number_as_float.fract() != 0.0 {
            self.issue(path, "invalid_value", "Expected an integer".into());
            return None;
        }
        if number_as_float < minimum as f64 {
            self.issue(
                path,
                "too_small",
                format!("Too small: expected number to be >= {minimum}"),
            );
            return None;
        }
        if number_as_float > MAX_SAFE_INTEGER {
            self.issue(
                path,
                "too_big",
                "Too big: expected number to be <= 9007199254740991".into(),
            );
            return None;
        }
        // The schema caps this value at JavaScript's MAX_SAFE_INTEGER, which
        // is exactly representable as f64. The range check above makes this
        // conversion lossless for admitted values.
        Some(number_as_float as u64)
    }
    fn bounded_integer(
        &mut self,
        value: Option<&Value>,
        path: &[&str],
        default: u64,
        minimum: u64,
        maximum: u64,
    ) -> Option<usize> {
        let value = self.safe_integer(value, path, Some(default), minimum)?;
        if value > maximum {
            self.issue(
                path,
                "too_big",
                format!("Too big: expected number to be <= {maximum}"),
            );
            return None;
        }
        usize::try_from(value).ok()
    }
    fn unknown(&mut self, object: &Map<String, Value>, allowed: &[&str], path: &[&str]) {
        let keys: Vec<_> = object
            .keys()
            .filter(|key| !allowed.contains(&key.as_str()))
            .collect();
        if !keys.is_empty() {
            let quoted: Vec<_> = keys
                .iter()
                .map(|key| Value::String((*key).clone()).to_string())
                .collect();
            self.issue(
                path,
                "unrecognized_keys",
                format!(
                    "Unrecognized key{}: {}",
                    if keys.len() == 1 { "" } else { "s" },
                    quoted.join(", ")
                ),
            );
        }
    }
    fn path(&mut self, object: &Map<String, Value>, absolute_message: Option<&str>) -> String {
        let Some(text) = self.string(object.get("path"), &["path"], true, true) else {
            return String::new();
        };
        if text.contains('\0') {
            self.issue(
                &["path"],
                "invalid_format",
                "Local filesystem paths cannot contain NUL".into(),
            );
        }
        if let Some(message) = absolute_message
            && !std::path::Path::new(text).is_absolute()
        {
            self.issue(&["path"], "invalid_value", message.into());
        }
        text.into()
    }
    fn finish<T>(self, value: T) -> Result<T, InputError> {
        if self.issues.is_empty() {
            Ok(value)
        } else {
            Err(InputError(self.issues))
        }
    }
}

/// JavaScript `String.trim()` whitespace, used by the shared Zod input schema.
fn trim_domain(text: &str) -> &str {
    fn is_trim_character(character: char) -> bool {
        matches!(
            character,
            '\u{0009}'..='\u{000D}'
                | '\u{0020}'
                | '\u{00A0}'
                | '\u{1680}'
                | '\u{2000}'..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
        )
    }

    text.trim_matches(is_trim_character)
}

/// Parse the exact residual-unknown listing filters and pagination controls.
pub fn list_unknowns(object: &Map<String, Value>) -> Result<UnknownQuery, InputError> {
    let mut parser = Parser::default();
    let status = parser
        .enum_string(
            object.get("status"),
            &["status"],
            &[
                "open",
                "investigating",
                "blocked",
                "contradicted",
                "resolved",
            ],
        )
        .map(str::to_owned);
    let severity = parser
        .enum_string(
            object.get("severity"),
            &["severity"],
            &["low", "medium", "high", "critical"],
        )
        .map(str::to_owned);
    let domain = parser
        .string(object.get("domain"), &["domain"], false, false)
        .map(|value| trim_domain(value).to_owned());
    if domain.as_deref().is_some_and(str::is_empty) {
        parser.issue(
            &["domain"],
            "too_small",
            "Too small: expected string to have >=1 characters".into(),
        );
    }
    let offset = parser
        .safe_integer(object.get("offset"), &["offset"], Some(0), 0)
        .unwrap_or_default();
    let limit = parser.safe_integer(object.get("limit"), &["limit"], None, 1);
    parser.unknown(
        object,
        &["status", "severity", "domain", "offset", "limit"],
        &[],
    );
    parser.finish(UnknownQuery {
        status,
        severity,
        domain,
        offset,
        limit,
    })
}

/// Parse an exact residual-unknown identity for current-head verification.
pub fn verify_unknown_resolution(object: &Map<String, Value>) -> Result<String, InputError> {
    let mut parser = Parser::default();
    let unknown_id = parser.string(object.get("unknown_id"), &["unknown_id"], true, true);
    if let Some(unknown_id) = unknown_id
        && !unknown_id
            .strip_prefix("unk_")
            .is_some_and(rea_core::evidence::is_sha256)
    {
        parser.issue(
            &["unknown_id"],
            "invalid_format",
            "Expected a unk_ prefixed lowercase sha256 digest".into(),
        );
    }
    parser.unknown(object, &["unknown_id"], &[]);
    parser.finish(unknown_id.unwrap_or_default().to_owned())
}

pub fn inspection(object: &Map<String, Value>) -> Result<String, InputError> {
    let mut parser = Parser::default();
    let path = parser.path(object, None);
    parser.unknown(object, &["path"], &[]);
    parser.finish(path)
}

/// Parse the SQLite snapshot path and optional schema or row selection.
pub fn sqlite_inspection(object: &Map<String, Value>) -> Result<SqliteInspectionInput, InputError> {
    let mut parser = Parser::default();
    let path = parser.path(
        object,
        Some("Expected an absolute filesystem path on this host."),
    );
    let table = parser
        .string(object.get("table"), &["table"], false, false)
        .map(str::to_owned);
    let columns = match object.get("columns") {
        None => None,
        Some(Value::Array(values)) if !values.is_empty() => {
            let mut parsed = Vec::with_capacity(values.len());
            for (index, value) in values.iter().enumerate() {
                match value.as_str() {
                    Some(text) => parsed.push(text.to_owned()),
                    None => {
                        parser.wrong_type(&["columns", &index.to_string()], "string", Some(value))
                    }
                }
            }
            Some(parsed)
        }
        Some(Value::Array(_)) => {
            parser.issue(
                &["columns"],
                "too_small",
                "Too small: expected array to have >=1 items".into(),
            );
            None
        }
        value => {
            parser.wrong_type(&["columns"], "array", value);
            None
        }
    };
    if columns.is_some() && table.is_none() {
        parser.issue(
            &["columns"],
            "custom",
            "columns requires an explicit table selection".into(),
        );
    }
    let schema_scope = parser
        .enum_string(
            object.get("schema_scope"),
            &["schema_scope"],
            &["inventory", "selected_table", "database"],
        )
        .map(str::to_owned);
    if schema_scope.as_deref() == Some("selected_table") && table.is_none() {
        parser.issue(
            &["schema_scope"],
            "custom",
            "selected_table schema scope requires table".into(),
        );
    }
    let row_limit = parser
        .safe_integer(object.get("row_limit"), &["row_limit"], None, 1)
        .and_then(|value| usize::try_from(value).ok());
    if row_limit.is_some() && table.is_none() {
        parser.issue(
            &["row_limit"],
            "custom",
            "row_limit requires an explicit table selection".into(),
        );
    }
    parser.unknown(
        object,
        &["path", "table", "columns", "schema_scope", "row_limit"],
        &[],
    );
    parser.finish(SqliteInspectionInput {
        path,
        selection: sqlite::Input {
            table,
            columns,
            schema_scope,
            row_limit,
        },
    })
}

/// Parse the selected app bundle, target identity, and Interface Builder graph limits.
pub fn interface_builder(object: &Map<String, Value>) -> Result<InterfaceBuilderInput, InputError> {
    let mut parser = Parser::default();
    let path = parser.path(
        object,
        Some("Expected an absolute filesystem path on this host."),
    );
    let target_sha256 = parser.string(object.get("target_sha256"), &["target_sha256"], true, true);
    if let Some(digest) = target_sha256
        && !rea_core::evidence::is_sha256(digest)
    {
        parser.issue(
            &["target_sha256"],
            "invalid_format",
            "Expected 64 lowercase hexadecimal characters".into(),
        );
    }
    let max_documents = parser.bounded_integer(
        object.get("max_documents"),
        &["max_documents"],
        MAX_DOCUMENTS as u64,
        1,
        MAX_DOCUMENTS as u64,
    );
    let max_objects = parser.bounded_integer(
        object.get("max_objects"),
        &["max_objects"],
        MAX_OBJECTS as u64,
        1,
        MAX_OBJECTS as u64,
    );
    let max_connections = parser.bounded_integer(
        object.get("max_connections"),
        &["max_connections"],
        MAX_CONNECTIONS as u64,
        1,
        MAX_CONNECTIONS as u64,
    );

    parser.unknown(
        object,
        &[
            "path",
            "target_sha256",
            "max_documents",
            "max_objects",
            "max_connections",
        ],
        &[],
    );
    parser.finish(InterfaceBuilderInput {
        path,
        target_sha256: target_sha256.unwrap_or_default().to_owned(),
        limits: InterfaceBuilderLimits {
            max_documents: max_documents.unwrap_or(MAX_DOCUMENTS),
            max_objects: max_objects.unwrap_or(MAX_OBJECTS),
            max_connections: max_connections.unwrap_or(MAX_CONNECTIONS),
        },
    })
}

/// Parse the caller-controlled page for active-target MCP asset inspection.
pub fn asset_catalog_page(
    object: &Map<String, Value>,
) -> Result<AssetCatalogPageInput, InputError> {
    let mut parser = Parser::default();
    let page = parse_asset_catalog_page(&mut parser, object);
    parser.unknown(object, &["offset", "limit"], &[]);
    parser.finish(AssetCatalogPageInput { page })
}

/// Parse a standalone CLI asset-catalog request with explicit target identity.
pub fn asset_catalog_cli(object: &Map<String, Value>) -> Result<AssetCatalogCliInput, InputError> {
    let mut parser = Parser::default();
    let path = parser.path(
        object,
        Some("Expected an absolute filesystem path on this host."),
    );
    let target_sha256 = parser.string(object.get("target_sha256"), &["target_sha256"], true, true);
    if let Some(digest) = target_sha256
        && !rea_core::evidence::is_sha256(digest)
    {
        parser.issue(
            &["target_sha256"],
            "invalid_format",
            "Expected 64 lowercase hexadecimal characters".into(),
        );
    }
    let page = parse_asset_catalog_page(&mut parser, object);
    parser.unknown(object, &["path", "target_sha256", "offset", "limit"], &[]);
    parser.finish(AssetCatalogCliInput {
        path,
        target_sha256: target_sha256.unwrap_or_default().to_owned(),
        page,
    })
}

fn parse_asset_catalog_page(parser: &mut Parser, object: &Map<String, Value>) -> AssetCatalogPage {
    let offset = parser
        .safe_integer(object.get("offset"), &["offset"], Some(0), 0)
        .and_then(|value| match usize::try_from(value) {
            Ok(value) => Some(value),
            Err(_) => {
                parser.issue(
                    &["offset"],
                    "too_big",
                    "Offset exceeds the integer range supported by this host".into(),
                );
                None
            }
        });
    let limit = parser.bounded_integer(
        object.get("limit"),
        &["limit"],
        ASSET_CATALOG_DEFAULT_LIMIT as u64,
        1,
        ASSET_CATALOG_MAX_LIMIT as u64,
    );

    AssetCatalogPage {
        offset: offset.unwrap_or_default(),
        limit: limit.unwrap_or(ASSET_CATALOG_DEFAULT_LIMIT),
    }
}

/// Parse the strict path and page selection for keyed archive inspection.
pub fn keyed_archive(object: &Map<String, Value>) -> Result<KeyedArchiveInput, InputError> {
    let mut parser = Parser::default();
    let path = parser.path(
        object,
        Some("Expected an absolute filesystem path on this host."),
    );
    let root = parser
        .string(object.get("root"), &["root"], false, false)
        .map(str::to_owned);
    let offset = parser.safe_integer(object.get("offset"), &["offset"], Some(0), 0);
    let limit = parser.bounded_integer(object.get("limit"), &["limit"], 20_000, 1, 20_000);

    parser.unknown(object, &["path", "root", "offset", "limit"], &[]);
    parser.finish(KeyedArchiveInput {
        path,
        selection: KeyedArchiveSelection {
            root,
            offset: offset
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or_default(),
            limit: limit.unwrap_or(20_000),
        },
    })
}

pub fn android_class_search(
    object: &Map<String, Value>,
) -> Result<AndroidClassSearchInput, InputError> {
    let mut parser = Parser::default();
    let path = parser.path(object, None);
    let query = parser
        .string(object.get("query"), &["query"], true, false)
        .unwrap_or_default()
        .to_owned();

    parser.unknown(object, &["path", "query"], &[]);
    parser.finish(AndroidClassSearchInput { path, query })
}

pub fn android_reference_trace(
    object: &Map<String, Value>,
) -> Result<AndroidReferenceTraceInput, InputError> {
    let mut parser = Parser::default();
    let path = parser.path(object, None);
    let class_name = parser
        .string(object.get("class_name"), &["class_name"], true, true)
        .unwrap_or_default()
        .to_owned();
    let method_name = parser
        .string(object.get("method_name"), &["method_name"], false, true)
        .map(str::to_owned);
    let overload_index = if object.contains_key("overload_index") {
        parser.bounded_integer(
            object.get("overload_index"),
            &["overload_index"],
            0,
            0,
            usize::MAX as u64,
        )
    } else {
        None
    };

    parser.unknown(
        object,
        &["path", "class_name", "method_name", "overload_index"],
        &[],
    );
    parser.finish(AndroidReferenceTraceInput {
        path,
        class_name,
        method_name,
        overload_index,
    })
}

/// Parse the strict PE resource request and its per-call input budgets.
pub fn pe_resources(object: &Map<String, Value>) -> Result<PeResourcesInput, InputError> {
    let mut parser = Parser::default();
    let path = parser.path(
        object,
        Some("Expected an absolute filesystem path on this host."),
    );
    let max_file_bytes = parser.bounded_integer(
        object.get("max_file_bytes"),
        &["max_file_bytes"],
        pe::resources::DEFAULT_FILE_BYTES as u64,
        64,
        pe::resources::MAX_FILE_BYTES as u64,
    );
    let max_entries = parser.bounded_integer(
        object.get("max_entries"),
        &["max_entries"],
        pe::resources::DEFAULT_DIRECTORY_ENTRIES as u64,
        1,
        pe::resources::MAX_DIRECTORY_ENTRIES as u64,
    );
    parser.unknown(object, &["path", "max_file_bytes", "max_entries"], &[]);
    parser.finish(PeResourcesInput {
        path,
        max_file_bytes: max_file_bytes.unwrap_or_default(),
        max_entries: max_entries.unwrap_or_default(),
    })
}

pub fn export(object: &Map<String, Value>) -> Result<Input, InputError> {
    let mut parser = Parser::default();
    let path = parser.path(object, Some("path must be an absolute local filesystem path (for example /tmp/rea/evidence.json or C:\\rea\\evidence.json)"));
    let overwrite = match object.get("overwrite") {
        None => false,
        Some(Value::Bool(value)) => *value,
        value => {
            parser.wrong_type(&["overwrite"], "boolean", value);
            false
        }
    };
    parser.unknown(object, &["path", "overwrite"], &[]);
    parser.finish(Input { path, overwrite })
}

pub fn import(object: &Map<String, Value>) -> Result<String, InputError> {
    let mut parser = Parser::default();
    let path = parser.path(object, Some("path must be an absolute local filesystem path (for example /tmp/evidence.json or C:\\rea\\evidence.json)"));
    parser.unknown(object, &["path"], &[]);
    parser.finish(path)
}

pub fn records(object: &Map<String, Value>) -> Result<Query, InputError> {
    let mut parser = Parser::default();
    let detail = match object.get("detail") {
        None => DetailLevel::Complete,
        Some(Value::String(text)) if text == "complete" => DetailLevel::Complete,
        Some(Value::String(text)) if text == "summary" => DetailLevel::Summary,
        _ => {
            parser.issue(
                &["detail"],
                "invalid_value",
                "Invalid option: expected one of \"complete\"|\"summary\"".into(),
            );
            DetailLevel::Complete
        }
    };
    let filters = match object.get("filters") {
        None => None,
        Some(Value::Object(fields)) => {
            let mut filters = Filters::default();
            for (name, destination, prefix) in [
                ("evidence_id", &mut filters.evidence_id, Some("ev_")),
                ("operation", &mut filters.operation, None),
                ("target_sha256", &mut filters.target_sha256, Some("")),
                (
                    "analysis_profile_digest",
                    &mut filters.analysis_profile_digest,
                    Some(""),
                ),
                ("procedure_address", &mut filters.procedure_address, None),
            ] {
                let path = ["filters", name];
                if let Some(text) = parser.string(fields.get(name), &path, false, prefix.is_none())
                {
                    if let Some(prefix) = prefix
                        && !text
                            .strip_prefix(prefix)
                            .is_some_and(rea_core::evidence::is_sha256)
                    {
                        parser.issue(
                            &path,
                            "invalid_format",
                            if prefix.is_empty() {
                                "Invalid string: must match pattern /^[a-f0-9]{64}$/u".into()
                            } else {
                                "Expected a ev_ prefixed lowercase sha256 digest".into()
                            },
                        );
                    }
                    *destination = Some(text.into());
                }
            }
            parser.unknown(
                fields,
                &[
                    "evidence_id",
                    "operation",
                    "target_sha256",
                    "analysis_profile_digest",
                    "procedure_address",
                ],
                &["filters"],
            );
            Some(filters)
        }
        value => {
            parser.wrong_type(&["filters"], "object", value);
            None
        }
    };
    parser.unknown(object, &["detail", "filters"], &[]);
    parser.finish(Query { detail, filters })
}

#[cfg(test)]
mod tests {
    use super::{
        android_class_search, android_reference_trace, asset_catalog_cli, asset_catalog_page,
        keyed_archive, list_unknowns, pe_resources, verify_unknown_resolution,
    };
    use serde_json::{Map, Value, json};

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().cloned().expect("test input is an object")
    }

    #[test]
    fn asset_catalog_page_defaults_and_preserves_bounded_values() {
        let defaults = asset_catalog_page(&Map::new()).unwrap();
        assert_eq!(defaults.page.offset, 0);
        assert_eq!(defaults.page.limit, 1_000);

        let selected = asset_catalog_page(&object(json!({
            "offset": 9_007_199_254_740_991_u64,
            "limit": 10_000,
        })))
        .unwrap();
        assert_eq!(selected.page.offset, 9_007_199_254_740_991_usize);
        assert_eq!(selected.page.limit, 10_000);
    }

    #[test]
    fn asset_catalog_inputs_reject_invalid_bounds_and_unknown_keys() {
        let error = asset_catalog_page(&object(json!({
            "offset": -1,
            "limit": 10_001,
            "path": "/tmp/app.app",
        })))
        .unwrap_err();
        let paths = error
            .0
            .iter()
            .map(|issue| issue.path.join("."))
            .collect::<Vec<_>>();
        assert!(paths.contains(&"offset".to_owned()));
        assert!(paths.contains(&"limit".to_owned()));
        assert!(paths.contains(&String::new()));
    }

    #[test]
    fn asset_catalog_cli_requires_an_absolute_target_and_lowercase_digest() {
        let accepted = asset_catalog_cli(&object(json!({
            "path": "/Applications/Demo.app/Contents/MacOS/Demo",
            "target_sha256": "a".repeat(64),
        })))
        .unwrap();
        assert_eq!(accepted.path, "/Applications/Demo.app/Contents/MacOS/Demo");
        assert_eq!(accepted.page.offset, 0);
        assert_eq!(accepted.page.limit, 1_000);

        let rejected = asset_catalog_cli(&object(json!({
            "path": "Demo.app/Contents/MacOS/Demo",
            "target_sha256": "A".repeat(64),
            "extra": true,
        })))
        .unwrap_err();
        assert!(
            rejected
                .0
                .iter()
                .any(|issue| issue.path.join(".") == "path")
        );
        assert!(
            rejected
                .0
                .iter()
                .any(|issue| issue.path.join(".") == "target_sha256")
        );
        assert!(rejected.0.iter().any(|issue| issue.path.is_empty()));
    }

    #[test]
    fn unknown_list_defaults_and_matches_javascript_domain_trimming() {
        let parsed = list_unknowns(&object(json!({
            "status": "resolved",
            "severity": "high",
            "domain": " \u{FEFF}abi\u{00A0} ",
            "offset": 4,
            "limit": 2,
        })))
        .unwrap();

        assert_eq!(parsed.status.as_deref(), Some("resolved"));
        assert_eq!(parsed.severity.as_deref(), Some("high"));
        assert_eq!(parsed.domain.as_deref(), Some("abi"));
        assert_eq!(parsed.offset, 4);
        assert_eq!(parsed.limit, Some(2));

        let defaults = list_unknowns(&Map::new()).unwrap();
        assert_eq!(defaults.offset, 0);
        assert_eq!(defaults.limit, None);
    }

    #[test]
    fn unknown_list_rejects_invalid_filters_paging_and_extra_keys() {
        let error = list_unknowns(&object(json!({
            "status": "pending",
            "domain": " \u{FEFF} ",
            "offset": 1.5,
            "limit": 0,
            "unexpected": true,
        })))
        .unwrap_err();

        let paths = error
            .0
            .iter()
            .map(|issue| issue.path.join("."))
            .collect::<Vec<_>>();
        assert!(paths.contains(&"status".to_owned()));
        assert!(paths.contains(&"domain".to_owned()));
        assert!(paths.contains(&"offset".to_owned()));
        assert!(paths.contains(&"limit".to_owned()));
        assert!(paths.contains(&String::new()));
    }

    #[test]
    fn unknown_resolution_requires_a_lowercase_prefixed_digest() {
        let accepted = format!("unk_{}", "a".repeat(64));
        assert_eq!(
            verify_unknown_resolution(&object(json!({ "unknown_id": accepted }))).unwrap(),
            format!("unk_{}", "a".repeat(64))
        );

        let error = verify_unknown_resolution(&object(json!({
            "unknown_id": format!("unk_{}", "A".repeat(64)),
        })))
        .unwrap_err();
        assert!(error.0.iter().any(|issue| issue.reason == "invalid_format"));
    }

    #[test]
    fn pe_resource_input_defaults_and_preserves_selected_budgets() {
        let defaults = pe_resources(&object(json!({"path": "/tmp/application.exe"}))).unwrap();
        assert_eq!(defaults.path, "/tmp/application.exe");
        assert_eq!(defaults.max_file_bytes, 64 * 1024 * 1024);
        assert_eq!(defaults.max_entries, 16_384);

        let selected = pe_resources(&object(json!({
            "path": "/tmp/application.exe",
            "max_file_bytes": 128 * 1024 * 1024,
            "max_entries": 32_000,
        })))
        .unwrap();
        assert_eq!(selected.max_file_bytes, 128 * 1024 * 1024);
        assert_eq!(selected.max_entries, 32_000);
    }

    #[test]
    fn pe_resource_input_rejects_out_of_range_and_unknown_values() {
        let error = pe_resources(&object(json!({
            "path": "/tmp/application.exe",
            "max_file_bytes": 63,
            "max_entries": 65_537,
            "extra": true,
        })))
        .unwrap_err();

        let paths = error
            .0
            .iter()
            .map(|issue| issue.path.join("."))
            .collect::<Vec<_>>();
        assert!(paths.contains(&"max_file_bytes".into()));
        assert!(paths.contains(&"max_entries".into()));
        assert!(paths.contains(&String::new()));
    }

    #[test]
    fn keyed_archive_input_defaults_selection_and_preserves_empty_root_names() {
        let defaults = keyed_archive(&object(json!({"path": "/tmp/archive.plist"}))).unwrap();
        assert_eq!(defaults.path, "/tmp/archive.plist");
        assert_eq!(defaults.selection.root, None);
        assert_eq!(defaults.selection.offset, 0);
        assert_eq!(defaults.selection.limit, 20_000);

        let selected = keyed_archive(&object(json!({
            "path": "/tmp/archive.plist",
            "root": "",
            "offset": 17,
            "limit": 25,
        })))
        .unwrap();
        assert_eq!(selected.selection.root.as_deref(), Some(""));
        assert_eq!(selected.selection.offset, 17);
        assert_eq!(selected.selection.limit, 25);
    }

    #[test]
    fn keyed_archive_input_rejects_invalid_paging_and_unknown_keys() {
        let error = keyed_archive(&object(json!({
            "path": "/tmp/archive.plist",
            "root": null,
            "offset": -1,
            "limit": 20_001,
            "extra": true,
        })))
        .unwrap_err();

        let paths = error
            .0
            .iter()
            .map(|issue| issue.path.join("."))
            .collect::<Vec<_>>();
        assert!(paths.contains(&"root".to_owned()));
        assert!(paths.contains(&"offset".to_owned()));
        assert!(paths.contains(&"limit".to_owned()));
        assert!(paths.contains(&String::new()));
    }

    #[test]
    fn android_class_search_preserves_empty_query_and_rejects_extra_keys() {
        let input = android_class_search(&object(json!({
            "path": "/tmp/application.apk",
            "query": "",
        })))
        .unwrap();

        assert_eq!(input.path, "/tmp/application.apk");
        assert!(input.query.is_empty());

        let error = android_class_search(&object(json!({
            "path": "/tmp/application.apk",
            "query": "Main",
            "unexpected": true,
        })))
        .unwrap_err();
        assert!(
            error
                .0
                .iter()
                .any(|issue| issue.reason == "unrecognized_keys")
        );
    }

    #[test]
    fn android_reference_trace_keeps_optional_selection_and_validates_index() {
        let input = android_reference_trace(&object(json!({
            "path": "/tmp/application.apk",
            "class_name": "example.Main",
        })))
        .unwrap();

        assert_eq!(input.class_name, "example.Main");
        assert_eq!(input.method_name, None);
        assert_eq!(input.overload_index, None);

        let error = android_reference_trace(&object(json!({
            "path": "/tmp/application.apk",
            "class_name": "example.Main",
            "overload_index": -1,
        })))
        .unwrap_err();
        assert!(error.0.iter().any(|issue| issue.path == ["overload_index"]));
    }
}
