//! Direct rusqlite port of `src/sqlite/SqliteDatabaseInspection.ts`.
//!
//! This is a line-by-line reproduction of the TypeScript inspection that the
//! owned worker runs (`SqliteDatabaseWorker.ts` ->
//! `inspectSqliteDatabaseSnapshot`): the same open flags, the same session
//! PRAGMAs/queries in the same order, the same schema/table/column/index/view/
//! trigger/rows projection, the same `typeof`-based text/blob encoding, the
//! same byte/row budgets and the same failure classes.
//!
//! The reader runs against a provider-owned private snapshot copy opened
//! read-only. It never opens the caller's source database.
//!
//! Run-time length limits: the TS worker sets the native `SQLITE_LIMIT_LENGTH`
//! and `SQLITE_LIMIT_SQL_LENGTH` to 16 MiB through `DatabaseSync.limits`. The
//! rusqlite API for those limits lives behind the crate's `limits` cargo
//! feature (and the direct `sqlite3_limit` FFI is unavailable under this
//! crate's `unsafe_code = "forbid"`), so the engine-level length limit is not
//! applied here. The application-level `OutputBudget` and the final
//! complete-evidence size check still bound the reply to 16 MiB. See the
//! `// Isolation deviations` note in the parent module and the requested shared
//! change (enable the `limits` feature) in the final report.
use rusqlite::config::DbConfig;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::Path;

use super::{Inspection, Scope, Selection};

/// `SQLITE_DATABASE_LIMITS.outputBytes` (`SqliteDatabaseLimits.ts`).
pub(crate) const OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// `SQLITE_ROW_LIMIT_DEFAULT` (`sqliteDatabase.ts`).
pub(crate) const ROW_LIMIT_DEFAULT: i64 = 20;

/// `SqliteInspectionFailure` (`SqliteDatabaseLimits.ts`): an internal rejection
/// that retains the failed boundary without returning partial success. The
/// `reason` is one of the exact TypeScript string reasons, which the service
/// layer maps to the frozen `AnalysisError` classes.
#[derive(Debug)]
pub(crate) struct Failure {
    pub reason: FailureReason,
    pub message: String,
}

/// The exact `SqliteInspectionFailure.reason` union, plus the `unavailable`
/// reason the worker surfaces when the run-time limit API is missing, and the
/// `memory`/`output-limit` reasons the worker derives from a native SQLite
/// `errcode` (7 -> memory, 18 -> output-limit, else -> format).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureReason {
    Format,
    Selection,
    ColumnSelection,
    Unsupported,
    Unavailable,
    OutputLimit,
    Memory,
}

impl Failure {
    fn new(reason: FailureReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

/// `DatabaseEncoding` (`SqliteDatabaseInspection.ts` `encodingSchema`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl Encoding {
    fn label(self) -> &'static str {
        match self {
            Self::Utf8 => "UTF-8",
            Self::Utf16Le => "UTF-16le",
            Self::Utf16Be => "UTF-16be",
        }
    }
}

/// `OutputBudget` (`SqliteDatabaseInspection.ts`): count bounded encoded parts
/// against the 16 MiB reply budget. The TS implementation starts at 1024 bytes
/// and adds, per retained value, one byte plus the UTF-8 byte length of each
/// JSON part (keys, string contents with escapes, literals). The exact byte
/// total is not contract-visible, so this reproduction counts the UTF-8 byte
/// length of the value's canonical JSON serialization (the same total number of
/// bytes as the summed parts) and the same `+1`, with the same 1024-byte start,
/// the same 16 MiB threshold and the same failure reason/message.
struct OutputBudget {
    bytes: usize,
}

impl OutputBudget {
    fn new() -> Self {
        Self { bytes: 1024 }
    }

    /// `OutputBudget.retain`.
    fn retain(&mut self, value: &Value) -> Result<(), Failure> {
        self.bytes = self.bytes.saturating_add(1);
        let encoded = serde_json::to_string(value)
            .map_err(|error| Failure::new(FailureReason::Format, error.to_string()))?;
        self.bytes = self.bytes.saturating_add(encoded.len());
        if self.bytes > OUTPUT_BYTES {
            return Err(Failure::new(
                FailureReason::OutputLimit,
                "Complete SQLite evidence exceeds the 16 MiB JSON reply budget; no partial success was returned.",
            ));
        }
        Ok(())
    }

    /// `OutputBudget.beforeDecode`: account for selected string cells before
    /// text/hex expansion. The raw row is the `typeof`-tagged projection, so a
    /// text/blob cell is a `String` whose UTF-8 byte length bounds the eventual
    /// decoded text.
    fn before_decode(&mut self, row: &[RawCell]) -> Result<(), Failure> {
        let mut minimum = self.bytes;
        for value in row {
            if let RawCell::Text(text) = value {
                minimum = minimum.saturating_add(text.len());
            }
        }
        if minimum > OUTPUT_BYTES {
            return Err(Failure::new(
                FailureReason::OutputLimit,
                "Selected cells exceed the 16 MiB reply budget before text/hex expansion.",
            ));
        }
        Ok(())
    }

    /// `OutputBudget.beforeProjection`: `sum(length * 2) + length.len()*64 +
    /// bytes > outputBytes`. The byte lengths are non-negative integers.
    fn before_projection(&mut self, lengths: &[i64]) -> Result<(), Failure> {
        let mut encoded: u128 = (lengths.len() as u128).saturating_mul(64);
        for length in lengths {
            encoded = encoded.saturating_add((*length as u128).saturating_mul(2));
        }
        if encoded.saturating_add(self.bytes as u128) > OUTPUT_BYTES as u128 {
            return Err(Failure::new(
                FailureReason::OutputLimit,
                "Selected row byte lengths exceed the 16 MiB reply budget before hex projection.",
            ));
        }
        Ok(())
    }
}

/// `quoteIdentifier`.
fn quote_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// `missingSelectedTable`.
fn missing_selected_table(name: &str) -> Failure {
    Failure::new(
        FailureReason::Selection,
        format!("Selected ordinary table does not exist with that exact name: {name}"),
    )
}

/// `sqliteIdentifierKey`: SQLite folds only ASCII letters when matching
/// virtual/shadow table names.
fn sqlite_identifier_key(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect()
}

/// `decodeSchemaText`: decode bytes with the database encoding in fatal mode;
/// a malformed sequence is a `format` failure that names the schema element.
fn decode_schema_text(value: &[u8], encoding: Encoding, label: &str) -> Result<String, Failure> {
    let decoded = match encoding {
        Encoding::Utf8 => std::str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|error| error.to_string()),
        Encoding::Utf16Le | Encoding::Utf16Be => decode_utf16(value, encoding == Encoding::Utf16Be),
    };
    decoded.map_err(|cause| {
        Failure::new(
            FailureReason::Format,
            format!(
                "SQLite schema {label} contains malformed {} text: {cause}",
                encoding.label()
            ),
        )
    })
}

/// Fatal UTF-16 decode (`TextDecoder(..., { fatal: true })`). An odd byte
/// length or an unpaired surrogate is an error.
fn decode_utf16(value: &[u8], big_endian: bool) -> Result<String, String> {
    if value.len() % 2 != 0 {
        return Err("odd UTF-16 byte length".to_owned());
    }
    let units = value.chunks_exact(2).map(|pair| {
        if big_endian {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        }
    });
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .map_err(|error| error.to_string())
}

/// Non-fatal UTF-16 decode (`TextDecoder(..., { ignoreBOM: true })`): invalid
/// sequences are replaced with U+FFFD, matching WHATWG decoding for text cells.
fn decode_utf16_lossy(value: &[u8], big_endian: bool) -> String {
    let mut units = Vec::with_capacity(value.len() / 2);
    let mut chunks = value.chunks_exact(2);
    for pair in &mut chunks {
        units.push(if big_endian {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        });
    }
    let mut text: String = char::decode_utf16(units)
        .map(|result| result.unwrap_or('\u{fffd}'))
        .collect();
    if !chunks.remainder().is_empty() {
        text.push('\u{fffd}');
    }
    text
}

/// A raw projected cell, before decoding into the frozen `SqliteValue`. It is
/// the output of the `typeof`-tagged projection and byte-length queries.
#[derive(Debug)]
enum RawCell {
    Null,
    /// A SQLite INTEGER (64-bit) returned unchanged by the `ELSE col` branch.
    Integer(i64),
    /// A SQLite REAL returned unchanged by the `ELSE col` branch.
    Real(f64),
    /// A `'t'`/`'b'` prefixed hex string from the text/blob branches.
    Text(String),
}

/// `cell`: project one raw cell into the frozen `SqliteValue` JSON object.
fn cell(value: &RawCell, encoding: Encoding) -> Result<Value, Failure> {
    match value {
        RawCell::Null => Ok(serde_json::json!({ "type": "null" })),
        RawCell::Integer(value) => {
            Ok(serde_json::json!({ "type": "integer", "value": value.to_string() }))
        }
        RawCell::Real(value) => {
            let real = if value.is_infinite() {
                Value::String(
                    if *value > 0.0 {
                        "Infinity"
                    } else {
                        "-Infinity"
                    }
                    .to_owned(),
                )
            } else if *value == 0.0 && value.is_sign_negative() {
                Value::String("-0".to_owned())
            } else {
                serde_json::Number::from_f64(*value)
                    .map(Value::Number)
                    .unwrap_or(Value::Null)
            };
            Ok(serde_json::json!({ "type": "real", "value": real }))
        }
        RawCell::Text(encoded) => {
            // `value.slice(1).toLowerCase()` then the even-hex check.
            let (tag, rest) = encoded.split_at(encoded.len().min(1));
            let hex = rest.to_ascii_lowercase();
            if hex.len() % 2 != 0
                || !hex
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(Failure::new(
                    FailureReason::Format,
                    "SQLite returned an invalid encoded cell.",
                ));
            }
            match tag {
                "b" => Ok(serde_json::json!({ "type": "blob", "hex": hex })),
                "t" => {
                    let bytes = decode_hex(&hex);
                    let text = match encoding {
                        Encoding::Utf8 => String::from_utf8_lossy(&bytes).into_owned(),
                        Encoding::Utf16Le => decode_utf16_lossy(&bytes, false),
                        Encoding::Utf16Be => decode_utf16_lossy(&bytes, true),
                    };
                    Ok(serde_json::json!({
                        "type": "text",
                        "value": text,
                        "bytes_hex": hex,
                        "encoding": encoding.label(),
                    }))
                }
                _ => Err(Failure::new(
                    FailureReason::Format,
                    "SQLite returned an unknown encoded cell type.",
                )),
            }
        }
    }
}

fn decode_hex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .filter_map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some(((hi << 4) | lo) as u8)
        })
        .collect()
}

/// `PRAGMA main.table_list` row (`tableRow`).
struct TableListEntry {
    name: String,
    kind: String,
    ncol: i64,
    wr: i64,
    strict: i64,
}

/// A visible column fact needed by row selection (`SelectedTableFacts.columns`).
#[derive(Clone)]
struct ColumnFact {
    name: String,
    hidden: i64,
}

/// `SelectedTableFacts`.
struct SelectedTable {
    kind: String,
    columns: Vec<ColumnFact>,
}

/// The parsed `readColumns` output: the frozen column objects (already sorted
/// by `cid`) plus the column facts the row selection needs (same order).
struct Columns {
    values: Vec<Value>,
    facts: Vec<ColumnFact>,
}

/// `readColumns`: expand a table/view's columns through `temp.pragma_table_xinfo`.
fn read_columns(
    conn: &Connection,
    name: &str,
    budget: &mut OutputBudget,
    encoding: Encoding,
    selected_columns: Option<&[String]>,
) -> Result<Columns, Failure> {
    let selection = match selected_columns {
        None => String::new(),
        Some(columns) => {
            let placeholders = columns
                .iter()
                .map(|_| "CAST(? AS BLOB)")
                .collect::<Vec<_>>()
                .join(", ");
            format!(" WHERE CAST(name AS BLOB) IN ({placeholders})")
        }
    };
    let sql = format!(
        "SELECT cid, CAST(name AS BLOB) AS name, CAST(type AS BLOB) AS type, \"notnull\", CAST(dflt_value AS BLOB) AS dflt_value, pk, hidden FROM temp.pragma_table_xinfo(?, 'main'){selection}"
    );
    let mut statement = conn.prepare(&sql).map_err(sqlite_failure)?;
    let mut params: Vec<&dyn rusqlite::ToSql> = vec![&name];
    if let Some(columns) = selected_columns {
        for column in columns {
            params.push(column);
        }
    }
    let mut rows = statement.query(params.as_slice()).map_err(sqlite_failure)?;
    // Collect with the native (rowid) iteration order, then stable-sort by cid.
    let mut collected: Vec<(u64, Value, ColumnFact)> = Vec::new();
    while let Some(row) = rows.next().map_err(sqlite_failure)? {
        let cid = natural(row.get_ref(0).map_err(sqlite_failure)?)?;
        let name_bytes = blob(row.get_ref(1).map_err(sqlite_failure)?)?;
        let type_bytes = blob(row.get_ref(2).map_err(sqlite_failure)?)?;
        let notnull = integer(row.get_ref(3).map_err(sqlite_failure)?)?;
        let dflt = optional_blob(row.get_ref(4).map_err(sqlite_failure)?)?;
        let pk = natural(row.get_ref(5).map_err(sqlite_failure)?)?;
        let hidden = integer(row.get_ref(6).map_err(sqlite_failure)?)?;
        if !(0..=3).contains(&hidden) {
            return Err(Failure::new(
                FailureReason::Format,
                "SQLite returned an unsupported hidden column role.",
            ));
        }
        let name_text = decode_schema_text(&name_bytes, encoding, "column name")?;
        let declared = decode_schema_text(&type_bytes, encoding, "column type")?;
        let default_sql = match dflt {
            None => Value::Null,
            Some(bytes) => Value::String(decode_schema_text(&bytes, encoding, "column default")?),
        };
        let column = serde_json::json!({
            "cid": cid,
            "name": name_text,
            "declared_type": declared,
            "not_null": notnull != 0,
            "default_sql": default_sql,
            "primary_key_position": pk,
            "hidden": hidden,
        });
        budget.retain(&column)?;
        let fact = ColumnFact {
            name: name_text,
            hidden,
        };
        collected.push((cid, column, fact));
    }
    collected.sort_by_key(|(cid, _, _)| *cid);
    let mut values = Vec::with_capacity(collected.len());
    let mut facts = Vec::with_capacity(collected.len());
    for (_, value, fact) in collected {
        values.push(value);
        facts.push(fact);
    }
    Ok(Columns { values, facts })
}

/// Raw schema-scan row values, collected before the metadata-borrowing pass.
struct SchemaRowValues {
    kind: String,
    name: String,
    tbl_name: String,
    rootpage: i64,
    sql: Option<Option<String>>,
}

/// `readSchema`: the exact `table_list` + `sqlite_schema` scan and projection.
#[allow(clippy::too_many_lines)]
fn read_schema(
    conn: &Connection,
    selection: &Selection,
    budget: &mut OutputBudget,
    limitations: &mut Vec<String>,
    encoding: Encoding,
) -> Result<(Value, Option<SelectedTable>), Failure> {
    let scope = selection.scope();
    let selected_name = if scope == Scope::SelectedTable {
        selection.table.clone()
    } else {
        None
    };
    if scope == Scope::SelectedTable && selected_name.is_none() {
        return Err(Failure::new(
            FailureReason::Selection,
            "Selected-table schema scope requires an exact table name.",
        ));
    }
    let mut selected_table: Option<SelectedTable> = None;
    let mut metadata: HashMap<String, TableListEntry> = HashMap::new();
    let mut metadata_order: Vec<String> = Vec::new();
    {
        let mut statement = conn
            .prepare("PRAGMA main.table_list")
            .map_err(sqlite_failure)?;
        let mut rows = statement.query([]).map_err(sqlite_failure)?;
        while let Some(row) = rows.next().map_err(sqlite_failure)? {
            let schema_name: String = row.get(0).map_err(sqlite_failure)?;
            let name: String = row.get(1).map_err(sqlite_failure)?;
            let kind: String = row.get(2).map_err(sqlite_failure)?;
            let ncol = natural(row.get_ref(3).map_err(sqlite_failure)?)? as i64;
            let wr = integer(row.get_ref(4).map_err(sqlite_failure)?)?;
            let strict = integer(row.get_ref(5).map_err(sqlite_failure)?)?;
            if schema_name == "main" {
                metadata_order.push(name.clone());
                metadata.insert(
                    name.clone(),
                    TableListEntry {
                        name,
                        kind,
                        ncol,
                        wr,
                        strict,
                    },
                );
            }
        }
    }

    // `unresolvedVirtualTables`: virtual tables with zero columns.
    let unresolved_virtual: Vec<(String, String)> = metadata_order
        .iter()
        .filter_map(|name| {
            let entry = metadata.get(name)?;
            if entry.kind == "virtual" && entry.ncol == 0 {
                Some((
                    entry.name.clone(),
                    sqlite_identifier_key(&format!("{}_", entry.name)),
                ))
            } else {
                None
            }
        })
        .collect();
    let shadow_parent_of = |name: &str, listed: &TableListEntry| -> Option<String> {
        if listed.kind != "table" {
            return None;
        }
        let identifier = sqlite_identifier_key(name);
        unresolved_virtual
            .iter()
            .find(|(_, prefix)| identifier.starts_with(prefix))
            .map(|(parent, _)| parent.clone())
    };

    let selected = selected_name.as_ref().and_then(|name| metadata.get(name));
    if let Some(name) = &selected_name {
        if selected.is_none() {
            return Err(missing_selected_table(name));
        }
    }
    let selected_shadow_parent = match (&selected_name, selected) {
        (Some(name), Some(listed)) => shadow_parent_of(name, listed),
        _ => None,
    };
    let fold_dependents = selected.map(|entry| entry.kind == "table").unwrap_or(false)
        && selected_shadow_parent.is_none();

    let mut tables: Vec<Value> = Vec::new();
    let mut indexes: Vec<Value> = Vec::new();
    let mut views: Vec<Value> = Vec::new();
    let mut triggers: Vec<Value> = Vec::new();

    let declaration = if scope == Scope::Inventory {
        ""
    } else {
        ", CAST(sql AS BLOB) AS sql"
    };
    let selection_clause = if scope == Scope::SelectedTable {
        format!(
            " WHERE tbl_name = ? COLLATE {}",
            if fold_dependents { "NOCASE" } else { "BINARY" }
        )
    } else {
        String::new()
    };
    let sql = format!(
        "SELECT type, CAST(name AS BLOB) AS name, CAST(tbl_name AS BLOB) AS tbl_name, rootpage{declaration} FROM main.sqlite_schema{selection_clause}"
    );
    let include_sql = scope != Scope::Inventory;

    let mut schema_rows: Vec<SchemaRowValues> = Vec::new();
    {
        let mut statement = conn.prepare(&sql).map_err(sqlite_failure)?;
        let mut rows = if let Some(name) = &selected_name {
            statement.query([name]).map_err(sqlite_failure)?
        } else {
            statement.query([]).map_err(sqlite_failure)?
        };
        while let Some(row) = rows.next().map_err(sqlite_failure)? {
            let kind: String = row.get(0).map_err(sqlite_failure)?;
            if !matches!(kind.as_str(), "table" | "index" | "view" | "trigger") {
                return Err(Failure::new(
                    FailureReason::Format,
                    format!("SQLite schema row has an unexpected type: {kind}"),
                ));
            }
            let name_bytes = blob(row.get_ref(1).map_err(sqlite_failure)?)?;
            let tbl_bytes = blob(row.get_ref(2).map_err(sqlite_failure)?)?;
            let rootpage = natural(row.get_ref(3).map_err(sqlite_failure)?)? as i64;
            let sql = if include_sql {
                match optional_blob(row.get_ref(4).map_err(sqlite_failure)?)? {
                    None => Some(None),
                    Some(bytes) => Some(Some(decode_schema_text(&bytes, encoding, "sql")?)),
                }
            } else {
                None
            };
            let name = decode_schema_text(&name_bytes, encoding, "name")?;
            let tbl_name = decode_schema_text(&tbl_bytes, encoding, "table")?;
            schema_rows.push(SchemaRowValues {
                kind,
                name,
                tbl_name,
                rootpage,
                sql,
            });
        }
    }

    // `triggerTable`: resolve a trigger's stored target by ASCII case folding.
    let mut folded_names: Option<HashMap<String, String>> = None;
    for value in schema_rows {
        match value.kind.as_str() {
            "table" => {
                let listed = match metadata.get(&value.name) {
                    Some(entry) if entry.kind != "view" => entry,
                    _ => {
                        return Err(Failure::new(
                            FailureReason::Format,
                            format!("SQLite schema/table inventory mismatch: {}", value.name),
                        ));
                    }
                };
                let possible_shadow_parent = if Some(&value.name) == selected_name.as_ref() {
                    selected_shadow_parent.clone()
                } else {
                    shadow_parent_of(&value.name, listed)
                };
                let kind = match &possible_shadow_parent {
                    None => listed.kind.clone(),
                    Some(_) => "unknown".to_owned(),
                };
                let column_count = if listed.kind == "virtual" && listed.ncol == 0 {
                    Value::Null
                } else {
                    Value::from(listed.ncol)
                };
                let without_rowid = listed.wr != 0;
                let strict = listed.strict != 0;
                let listed_kind = listed.kind.clone();

                let mut table = Map::new();
                table.insert("name".into(), Value::String(value.name.clone()));
                if scope != Scope::Inventory {
                    table.insert("sql".into(), optional_sql(&value.sql));
                }
                table.insert("root_page".into(), Value::from(value.rootpage));
                table.insert("kind".into(), Value::String(kind.clone()));
                table.insert("without_rowid".into(), Value::Bool(without_rowid));
                table.insert("strict".into(), Value::Bool(strict));
                table.insert("column_count".into(), column_count);
                if let Some(parent) = &possible_shadow_parent {
                    limitations.push(format!(
                        "SQLite could not resolve virtual table {parent}. Table {} may be its shadow table; its kind is unknown and row inspection is unavailable.",
                        value.name
                    ));
                }
                // `budget.retain(table)` runs before column expansion, with the
                // table carrying its still-empty completeness and columns.
                table.insert(
                    "columns_completeness".into(),
                    Value::String("complete".to_owned()),
                );
                table.insert("columns".into(), Value::Array(Vec::new()));
                budget.retain(&Value::Object(table.clone()))?;

                let mut columns_completeness = "complete";
                if scope == Scope::Inventory {
                    columns_completeness = "not_requested";
                }
                let mut columns: Vec<Value> = Vec::new();
                let mut column_facts: Vec<ColumnFact> = Vec::new();
                if listed_kind == "virtual" && scope != Scope::Inventory {
                    columns_completeness = "unsupported";
                    limitations.push(format!(
                        "Virtual table column expansion is not performed: {}. Its complete stored CREATE statement is retained.",
                        value.name
                    ));
                } else if listed_kind != "virtual"
                    && (scope != Scope::Inventory
                        || selection.table.as_deref() == Some(value.name.as_str()))
                {
                    let mut scratch_budget = OutputBudget::new();
                    let column_budget = if scope == Scope::Inventory {
                        &mut scratch_budget
                    } else {
                        &mut *budget
                    };
                    let expanded = read_columns(
                        conn,
                        &value.name,
                        column_budget,
                        encoding,
                        if scope == Scope::Inventory {
                            selection.columns.as_deref()
                        } else {
                            None
                        },
                    )?;
                    column_facts = expanded.facts.clone();
                    if selection.table.as_deref() == Some(value.name.as_str()) {
                        selected_table = Some(SelectedTable {
                            kind: kind.clone(),
                            columns: expanded.facts,
                        });
                    }
                    if scope != Scope::Inventory {
                        columns = expanded.values;
                    }
                }
                if selection.table.as_deref() == Some(value.name.as_str())
                    && selected_table.is_none()
                {
                    selected_table = Some(SelectedTable {
                        kind: kind.clone(),
                        columns: column_facts,
                    });
                }
                table.insert(
                    "columns_completeness".into(),
                    Value::String(columns_completeness.to_owned()),
                );
                table.insert("columns".into(), Value::Array(columns));
                tables.push(Value::Object(table));
            }
            "index" => {
                let mut index = Map::new();
                index.insert("name".into(), Value::String(value.name.clone()));
                index.insert("table".into(), Value::String(value.tbl_name.clone()));
                if scope != Scope::Inventory {
                    index.insert("sql".into(), optional_sql(&value.sql));
                }
                index.insert("root_page".into(), Value::from(value.rootpage));
                let index = Value::Object(index);
                budget.retain(&index)?;
                indexes.push(index);
            }
            "view" => {
                let mut view = Map::new();
                view.insert("name".into(), Value::String(value.name.clone()));
                if scope != Scope::Inventory {
                    view.insert("sql".into(), optional_sql(&value.sql));
                }
                let view = Value::Object(view);
                budget.retain(&view)?;
                views.push(view);
            }
            _ => {
                let table_name = trigger_table(
                    &value.tbl_name,
                    selected_name.as_deref(),
                    &metadata,
                    &metadata_order,
                    &mut folded_names,
                );
                let mut trigger = Map::new();
                trigger.insert("name".into(), Value::String(value.name.clone()));
                trigger.insert("table".into(), Value::String(table_name));
                if scope != Scope::Inventory {
                    trigger.insert("sql".into(), optional_sql(&value.sql));
                }
                let trigger = Value::Object(trigger);
                budget.retain(&trigger)?;
                triggers.push(trigger);
            }
        }
    }

    let schema = serde_json::json!({
        "scope": scope.label(),
        "completeness": "complete",
        "tables": tables,
        "indexes": indexes,
        "views": views,
        "triggers": triggers,
    });
    Ok((schema, selected_table))
}

/// `triggerTable`: the stored target name a trigger refers to.
fn trigger_table(
    written: &str,
    selected_name: Option<&str>,
    metadata: &HashMap<String, TableListEntry>,
    metadata_order: &[String],
    folded: &mut Option<HashMap<String, String>>,
) -> String {
    if let Some(name) = selected_name {
        return name.to_owned();
    }
    if metadata.contains_key(written) {
        return written.to_owned();
    }
    let map = folded.get_or_insert_with(|| {
        metadata_order
            .iter()
            .map(|name| (sqlite_identifier_key(name), name.clone()))
            .collect()
    });
    map.get(&sqlite_identifier_key(written))
        .cloned()
        .unwrap_or_else(|| written.to_owned())
}

/// `include_sql` projection: present only outside inventory scope; `undefined`
/// for inventory (handled by the caller skipping the key); otherwise the stored
/// string or `null`.
fn optional_sql(sql: &Option<Option<String>>) -> Value {
    match sql {
        Some(Some(text)) => Value::String(text.clone()),
        _ => Value::Null,
    }
}

/// `readRows`: sample an ordinary table's rows with the exact projection,
/// byte-length budget, truncation probe and cell encoding.
fn read_rows(
    conn: &Connection,
    selection: &Selection,
    table: Option<&SelectedTable>,
    budget: &mut OutputBudget,
    encoding: Encoding,
) -> Result<Value, Failure> {
    let Some(selected_name) = &selection.table else {
        return Ok(Value::Null);
    };
    let Some(table) = table else {
        return Err(missing_selected_table(selected_name));
    };
    if table.kind == "unknown" {
        return Err(Failure::new(
            FailureReason::Selection,
            format!(
                "SQLite cannot determine whether selected table {selected_name} is a shadow table of an unresolved virtual table. Row inspection requires a confirmed ordinary table."
            ),
        ));
    }
    if table.kind != "table" {
        return Err(Failure::new(
            FailureReason::Selection,
            format!(
                "Rows from {} table {selected_name} are outside the ordinary-table inspection profile.",
                table.kind
            ),
        ));
    }
    let limit = selection.row_limit.unwrap_or(ROW_LIMIT_DEFAULT);
    let visible_columns: Vec<String> = table
        .columns
        .iter()
        .filter(|column| column.hidden != 1)
        .map(|column| column.name.clone())
        .collect();
    let columns = match &selection.columns {
        Some(columns) => columns.clone(),
        None => visible_columns.clone(),
    };
    let available: std::collections::HashSet<&str> =
        visible_columns.iter().map(String::as_str).collect();
    for name in &columns {
        if !available.contains(name.as_str()) {
            return Err(Failure::new(
                FailureReason::ColumnSelection,
                format!(
                    "Selected column does not exist with that exact name in table {selected_name}: {name}"
                ),
            ));
        }
    }
    let projection = columns
        .iter()
        .map(|name| {
            let column = quote_identifier(name);
            format!("CASE typeof({column}) WHEN 'text' THEN 't' || hex(CAST({column} AS BLOB)) WHEN 'blob' THEN 'b' || hex({column}) ELSE {column} END")
        })
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!("main.{} NOT INDEXED", quote_identifier(selected_name));

    let lengths_sql = format!(
        "SELECT {} FROM {source} LIMIT ?",
        columns
            .iter()
            .map(|name| {
                let column = quote_identifier(name);
                format!("CASE typeof({column}) WHEN 'text' THEN length(CAST({column} AS BLOB)) WHEN 'blob' THEN length({column}) ELSE 0 END")
            })
            .collect::<Vec<_>>()
            .join(", ")
    );
    {
        let mut statement = conn.prepare(&lengths_sql).map_err(sqlite_failure)?;
        let mut rows = statement.query([limit]).map_err(sqlite_failure)?;
        while let Some(row) = rows.next().map_err(sqlite_failure)? {
            let mut lengths = Vec::with_capacity(columns.len());
            for index in 0..columns.len() {
                lengths.push(integer(row.get_ref(index).map_err(sqlite_failure)?)?);
            }
            budget.before_projection(&lengths)?;
        }
    }

    let values_sql = format!("SELECT {projection} FROM {source} LIMIT ?");
    let mut values: Vec<Value> = Vec::new();
    {
        let mut statement = conn.prepare(&values_sql).map_err(sqlite_failure)?;
        let mut rows = statement.query([limit]).map_err(sqlite_failure)?;
        while let Some(row) = rows.next().map_err(sqlite_failure)? {
            let mut raw_row = Vec::with_capacity(columns.len());
            for index in 0..columns.len() {
                raw_row.push(raw_cell(row.get_ref(index).map_err(sqlite_failure)?)?);
            }
            budget.before_decode(&raw_row)?;
            let projected = raw_row
                .iter()
                .map(|value| cell(value, encoding))
                .collect::<Result<Vec<_>, _>>()?;
            let projected = Value::Array(projected);
            budget.retain(&projected)?;
            values.push(projected);
        }
    }
    let returned_rows = values.len();

    let truncated_sql = format!("SELECT 1 FROM {source} LIMIT 1 OFFSET ?");
    let truncated = {
        let mut statement = conn.prepare(&truncated_sql).map_err(sqlite_failure)?;
        let mut rows = statement.query([limit]).map_err(sqlite_failure)?;
        rows.next().map_err(sqlite_failure)?.is_some()
    };

    Ok(serde_json::json!({
        "table": selected_name,
        "columns": columns,
        "values": values,
        "row_limit": limit,
        "returned_rows": returned_rows,
        "truncated": truncated,
        "order": "unspecified",
    }))
}

/// Read one raw projected cell from a `ValueRef`.
fn raw_cell(value: ValueRef<'_>) -> Result<RawCell, Failure> {
    match value {
        ValueRef::Null => Ok(RawCell::Null),
        ValueRef::Integer(value) => Ok(RawCell::Integer(value)),
        ValueRef::Real(value) => Ok(RawCell::Real(value)),
        ValueRef::Text(bytes) => std::str::from_utf8(bytes)
            .map(|text| RawCell::Text(text.to_owned()))
            .map_err(|error| Failure::new(FailureReason::Format, error.to_string())),
        ValueRef::Blob(_) => Err(Failure::new(
            FailureReason::Format,
            "SQLite returned an invalid encoded cell.",
        )),
    }
}

/// `natural`: a non-negative integer within the JS safe-integer bound.
fn natural(value: ValueRef<'_>) -> Result<u64, Failure> {
    let value = integer(value)?;
    if value < 0 {
        return Err(Failure::new(
            FailureReason::Format,
            "SQLite returned a negative value where a natural number was expected.",
        ));
    }
    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
    if value > MAX_SAFE_INTEGER {
        return Err(Failure::new(
            FailureReason::Format,
            "SQLite returned an integer beyond the safe-integer bound.",
        ));
    }
    Ok(value as u64)
}

/// Read a SQLite INTEGER, rejecting any other storage class.
fn integer(value: ValueRef<'_>) -> Result<i64, Failure> {
    match value {
        ValueRef::Integer(value) => Ok(value),
        _ => Err(Failure::new(
            FailureReason::Format,
            "SQLite returned a non-integer where an integer was expected.",
        )),
    }
}

/// Read a required BLOB (the `CAST(... AS BLOB)` projection). SQLite casting a
/// TEXT value to BLOB returns the stored bytes; empty/zero-length values arrive
/// as an empty blob.
fn blob(value: ValueRef<'_>) -> Result<Vec<u8>, Failure> {
    match value {
        ValueRef::Blob(bytes) => Ok(bytes.to_vec()),
        ValueRef::Text(bytes) => Ok(bytes.to_vec()),
        _ => Err(Failure::new(
            FailureReason::Format,
            "SQLite returned a non-blob where encoded bytes were expected.",
        )),
    }
}

/// Read a nullable BLOB (`dflt_value`/`sql`).
fn optional_blob(value: ValueRef<'_>) -> Result<Option<Vec<u8>>, Failure> {
    match value {
        ValueRef::Null => Ok(None),
        other => blob(other).map(Some),
    }
}

/// Map a rusqlite error to the worker's reason classification, mirroring
/// `SqliteDatabaseWorker.ts` (`errcode` 7 -> memory, 18 -> output-limit, else
/// -> format).
fn sqlite_failure(error: rusqlite::Error) -> Failure {
    let (reason, message) = match &error {
        rusqlite::Error::SqliteFailure(code, message) => {
            let text = message.clone().unwrap_or_else(|| error.to_string());
            match code.extended_code {
                7 => (FailureReason::Memory, text),
                18 => (FailureReason::OutputLimit, text),
                _ => (FailureReason::Format, text),
            }
        }
        other => (FailureReason::Format, other.to_string()),
    };
    Failure::new(reason, message)
}

/// `inspectSqliteDatabaseSnapshot`: open the private snapshot read-only, set the
/// session PRAGMAs and DQS config, read the version/encoding, and project the
/// schema and selected rows. `on_open` receives the connection's interrupt
/// handle so the caller can bound a long read with the supervised deadline and
/// cancellation.
pub(crate) fn inspect_snapshot(
    snapshot_path: &Path,
    selection: &Selection,
    limitations: Vec<String>,
    on_open: impl FnOnce(rusqlite::InterruptHandle),
) -> Result<Inspection, Failure> {
    // `new DatabaseSync(path, { readOnly: true, allowExtension: false, ... })`.
    // Extension loading is disabled by default and never enabled here.
    let conn = Connection::open_with_flags(
        snapshot_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite_failure)?;
    on_open(conn.get_interrupt_handle());

    // `enableDoubleQuotedStringLiterals: false`: reject DQ string literals in
    // both DML and DDL.
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)
        .map_err(sqlite_failure)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)
        .map_err(sqlite_failure)?;

    // `PRAGMA trusted_schema=OFF; query_only=ON; mmap_size=0;
    // cell_size_check=ON; BEGIN;` in the exact order.
    conn.execute_batch(
        "PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; PRAGMA mmap_size=0; PRAGMA cell_size_check=ON; BEGIN;",
    )
    .map_err(sqlite_failure)?;

    let version: String = conn
        .query_row("SELECT sqlite_version() AS version", [], |row| row.get(0))
        .map_err(sqlite_failure)?;
    let encoding_text: String = conn
        .query_row("PRAGMA encoding", [], |row| row.get(0))
        .map_err(sqlite_failure)?;
    let encoding = match encoding_text.as_str() {
        "UTF-8" => Encoding::Utf8,
        "UTF-16le" => Encoding::Utf16Le,
        "UTF-16be" => Encoding::Utf16Be,
        other => {
            return Err(Failure::new(
                FailureReason::Format,
                format!("SQLite reported an unsupported database encoding: {other}"),
            ));
        }
    };

    let mut limitations = limitations;
    let mut budget = OutputBudget::new();
    let (schema, selected_table) =
        read_schema(&conn, selection, &mut budget, &mut limitations, encoding)?;
    let rows = read_rows(
        &conn,
        selection,
        selected_table.as_ref(),
        &mut budget,
        encoding,
    )?;

    Ok(Inspection {
        engine_version: version,
        database_encoding: encoding.label().to_owned(),
        schema,
        rows,
        limitations,
    })
}

/// Reference every reason variant so the full `SqliteInspectionFailure` union
/// stays represented even though the reader raises `Unsupported`/`Unavailable`
/// only through limitations text or the limit API (unavailable under the
/// current cargo features), exactly as the TypeScript inspection's reason set.
#[allow(dead_code)]
const _REASONS: [FailureReason; 7] = [
    FailureReason::Format,
    FailureReason::Selection,
    FailureReason::ColumnSelection,
    FailureReason::Unsupported,
    FailureReason::Unavailable,
    FailureReason::OutputLimit,
    FailureReason::Memory,
];
