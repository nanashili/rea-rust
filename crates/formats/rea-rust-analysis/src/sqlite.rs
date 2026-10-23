//! Read-only SQLite schema and bounded row inspection.

use rusqlite::{Connection, OpenFlags, types::ValueRef};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, path::Path};

pub const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_ROW_LIMIT: usize = 20;

struct OutputBudget {
    bytes: usize,
}

impl OutputBudget {
    fn new() -> Self {
        Self { bytes: 1024 }
    }
    fn reserve(&mut self, bytes: usize) -> Result<(), Error> {
        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > MAX_OUTPUT_BYTES {
            return Err(Error::Limit(
                "Complete SQLite evidence exceeds the 16 MiB JSON reply budget.".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Input {
    pub table: Option<String>,
    pub columns: Option<Vec<String>>,
    pub schema_scope: Option<String>,
    pub row_limit: Option<usize>,
}

#[derive(Debug)]
pub enum Error {
    Io(String),
    Sqlite(String),
    Selection(String),
    Limit(String),
    Format(String),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s)
            | Self::Sqlite(s)
            | Self::Selection(s)
            | Self::Limit(s)
            | Self::Format(s) => f.write_str(s),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, Serialize)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub enum Value {
    #[serde(rename = "null")]
    Null,
    #[serde(rename = "integer")]
    Integer { value: String },
    #[serde(rename = "real")]
    Real { value: serde_json::Value },
    #[serde(rename = "text")]
    Text {
        value: String,
        bytes_hex: String,
        encoding: String,
    },
    #[serde(rename = "blob")]
    Blob { hex: String },
}
#[derive(Clone, Debug, Serialize)]
pub struct Column {
    pub cid: usize,
    pub name: String,
    pub declared_type: String,
    pub declared_type_status: String,
    pub not_null: bool,
    pub not_null_status: String,
    pub default_sql: Option<String>,
    pub default_status: String,
    pub primary_key_position: usize,
    pub primary_key_status: String,
    pub hidden: usize,
    pub hidden_role: String,
    pub hidden_role_status: String,
    pub source: String,
    pub metadata_status: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Table {
    pub name: String,
    pub sql: Option<String>,
    pub definition_status: String,
    pub source: String,
    pub root_page: usize,
    pub kind: String,
    pub without_rowid: bool,
    pub without_rowid_status: String,
    pub strict: bool,
    pub strict_status: String,
    pub column_count: Option<usize>,
    pub column_count_status: String,
    pub columns_completeness: String,
    pub columns: Vec<Column>,
    pub primary_key_columns: Vec<PrimaryKeyColumn>,
    pub classification_source: String,
    pub virtual_module: Option<String>,
    pub virtual_module_status: String,
    pub virtual_module_source: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct PrimaryKeyColumn {
    pub name: String,
    pub position: usize,
    pub source: String,
    pub status: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct NamedSql {
    pub name: String,
    pub sql: Option<String>,
    pub definition_status: String,
    pub source: String,
    pub columns: Vec<Column>,
    pub columns_completeness: String,
    pub column_count: Option<usize>,
    pub dependencies: Vec<String>,
    pub dependencies_status: String,
    pub dependencies_source: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Trigger {
    pub name: String,
    pub table: String,
    pub table_status: String,
    pub sql: Option<String>,
    pub definition_status: String,
    pub source: String,
    pub timing: String,
    pub event: String,
    pub metadata_status: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Index {
    pub name: String,
    pub table: String,
    pub sql: Option<String>,
    pub root_page: usize,
    pub unique: bool,
    pub partial: bool,
    pub list_sequence: Option<usize>,
    pub partial_status: String,
    pub origin_status: String,
    pub predicate_sql: Option<String>,
    pub predicate_status: String,
    pub predicate_source: String,
    pub origin: Option<String>,
    pub identity: String,
    pub expression_status: String,
    pub expression_columns: Vec<IndexExpression>,
    pub columns: Vec<IndexColumn>,
}
#[derive(Clone, Debug, Serialize)]
pub struct IndexExpression {
    pub seqno: usize,
    pub definition_status: String,
    pub source: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct IndexColumn {
    pub seqno: usize,
    pub cid: i64,
    pub name: Option<String>,
    pub descending: bool,
    pub collation: Option<String>,
    pub key: bool,
    pub identity: String,
    pub order_status: String,
    pub collation_status: String,
    pub role_status: String,
    pub source: String,
    pub metadata_status: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct ForeignKey {
    pub table: String,
    pub id: usize,
    pub seq: usize,
    pub column: Option<String>,
    pub target_table: String,
    pub target_column: Option<String>,
    pub target_column_status: String,
    pub on_update: String,
    pub on_delete: String,
    pub match_name: String,
    pub deferrable: Option<bool>,
    pub source: String,
    pub source_column_status: String,
    pub target_table_status: String,
    pub action_status: String,
    pub match_status: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct UniqueConstraint {
    pub table: String,
    pub index: String,
    pub columns: Vec<String>,
    pub source: String,
    pub status: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Schema {
    pub scope: String,
    pub completeness: String,
    pub tables: Vec<Table>,
    pub indexes: Vec<Index>,
    pub views: Vec<NamedSql>,
    pub triggers: Vec<Trigger>,
    pub foreign_keys: Vec<ForeignKey>,
    pub unique_constraints: Vec<UniqueConstraint>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Rows {
    pub table: String,
    pub columns: Vec<String>,
    pub values: Vec<Vec<Value>>,
    pub row_limit: usize,
    pub returned_rows: usize,
    pub truncated: bool,
    pub order: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub artifact: Artifact,
    pub wal: Option<Artifact>,
    pub engine: Engine,
    pub database_encoding: String,
    pub schema: Schema,
    pub rows: Option<Rows>,
    pub limitations: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Engine {
    pub name: String,
    pub version: String,
}

pub fn inspect(path: &Path, input: &Input) -> Result<Report, Error> {
    let bytes = fs::read(path).map_err(|e| Error::Io(e.to_string()))?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::Limit(
            "SQLite input exceeds the 256 MiB inspection limit.".into(),
        ));
    }
    let mut digest = Sha256::new();
    digest.update(&bytes);
    let artifact = Artifact {
        path: path.display().to_string(),
        sha256: format!("{:x}", digest.finalize()),
        bytes: bytes.len(),
    };
    let wal = sibling_artifact(path, "-wal", bytes.len())?;
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    conn.pragma_update(None, "query_only", true)
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    conn.pragma_update(None, "trusted_schema", false)
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let version: String = conn
        .query_row("SELECT sqlite_version()", [], |r| r.get(0))
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let encoding: String = conn
        .query_row("PRAGMA encoding", [], |r| r.get(0))
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    validate_database_encoding(&encoding)?;
    let scope = input.schema_scope.clone().unwrap_or_else(|| {
        if input.table.is_some() {
            "selected_table".into()
        } else {
            "inventory".into()
        }
    });
    if !matches!(scope.as_str(), "inventory" | "selected_table" | "database") {
        return Err(Error::Selection(format!(
            "Unsupported SQLite schema scope: {scope}"
        )));
    }
    if scope == "selected_table" && input.table.is_none() {
        return Err(Error::Selection(
            "Selected-table schema scope requires an exact table name.".into(),
        ));
    }
    if input.table.is_none() && (input.columns.is_some() || input.row_limit.is_some()) {
        return Err(Error::Selection(
            "columns and row_limit require an explicit table selection.".into(),
        ));
    }
    if input.columns.as_ref().is_some_and(Vec::is_empty) {
        return Err(Error::Selection(
            "columns must contain at least one selected column.".into(),
        ));
    }
    if input.row_limit == Some(0) {
        return Err(Error::Selection(
            "row_limit must be at least 1 when a table is selected.".into(),
        ));
    }
    if input
        .row_limit
        .is_some_and(|limit| limit > i64::MAX as usize)
    {
        return Err(Error::Selection(
            "row_limit exceeds SQLite's supported bound.".into(),
        ));
    }
    let mut budget = OutputBudget::new();
    let schema = read_schema(&conn, &scope, input.table.as_deref(), &mut budget)?;
    let rows = if let Some(table) = input.table.as_deref() {
        let selected = schema
            .tables
            .iter()
            .find(|candidate| candidate.name == table)
            .ok_or_else(|| {
                Error::Selection(format!(
                    "Selected ordinary table does not exist with that exact name: {table}"
                ))
            })?;
        if selected.kind != "table" {
            return Err(Error::Selection(format!(
                "Rows from {} table {table} are outside the ordinary-table inspection profile.",
                selected.kind
            )));
        }
        Some(read_rows(&conn, table, input, &encoding, &mut budget)?)
    } else {
        None
    };
    let report = Report {
        artifact,
        wal,
        engine: Engine {
            name: "SQLite".into(),
            version,
        },
        database_encoding: encoding,
        schema,
        rows,
        limitations: vec![
            "Stored CREATE statements preserve index/view/trigger definitions. Views, triggers, and virtual/shadow table rows are not executed; virtual-table column expansion is unsupported.".into(),
            "Selected rows are a bounded sample with unspecified order.".into(),
        ],
    };
    let encoded = serde_json::to_vec(&report).map_err(|e| Error::Format(e.to_string()))?;
    if encoded.len() > MAX_OUTPUT_BYTES {
        return Err(Error::Limit(
            "Complete SQLite evidence exceeds the 16 MiB JSON reply budget.".into(),
        ));
    }
    Ok(report)
}

fn sibling_artifact(
    path: &Path,
    suffix: &str,
    primary_bytes: usize,
) -> Result<Option<Artifact>, Error> {
    let sibling = Path::new(&format!("{}{}", path.display(), suffix)).to_path_buf();
    if !sibling.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&sibling).map_err(|error| Error::Io(error.to_string()))?;
    if primary_bytes.saturating_add(bytes.len()) > MAX_INPUT_BYTES {
        return Err(Error::Limit(
            "SQLite database and WAL exceed the 256 MiB inspection limit.".into(),
        ));
    }
    let mut digest = Sha256::new();
    digest.update(&bytes);
    Ok(Some(Artifact {
        path: sibling.display().to_string(),
        sha256: format!("{:x}", digest.finalize()),
        bytes: bytes.len(),
    }))
}

fn validate_database_encoding(encoding: &str) -> Result<(), Error> {
    if matches!(encoding, "UTF-8" | "UTF-16le" | "UTF-16be") {
        return Ok(());
    }
    Err(Error::Format(format!(
        "SQLite returned an unsupported database encoding: {encoding}"
    )))
}

#[derive(Clone)]
struct TableInfo {
    kind: String,
    columns: Option<usize>,
    without_rowid: bool,
    strict: bool,
}

fn identifier_key(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_uppercase() {
                (byte + (b'a' - b'A')) as char
            } else {
                byte as char
            }
        })
        .collect()
}

fn table_kind(value: &str) -> &'static str {
    match value {
        "table" => "table",
        "virtual" => "virtual",
        "shadow" => "shadow",
        _ => "unknown",
    }
}

fn table_metadata(conn: &Connection) -> Result<HashMap<String, TableInfo>, Error> {
    let mut statement = conn
        .prepare(
            "SELECT \"schema\", name, type, ncol, wr, strict \
             FROM temp.pragma_table_list
             WHERE \"schema\" = 'main'",
        )
        .map_err(|error| Error::Sqlite(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|error| Error::Sqlite(error.to_string()))?;
    let mut metadata = HashMap::new();
    for row in rows {
        let (name, kind, columns, without_rowid, strict) =
            row.map_err(|error| Error::Sqlite(error.to_string()))?;
        metadata.insert(
            name,
            TableInfo {
                kind: kind.clone(),
                columns: (kind != "virtual" || columns != 0).then_some(columns as usize),
                without_rowid: without_rowid != 0,
                strict: strict != 0,
            },
        );
    }
    Ok(metadata)
}

fn read_schema(
    conn: &Connection,
    scope: &str,
    selected: Option<&str>,
    budget: &mut OutputBudget,
) -> Result<Schema, Error> {
    let metadata = table_metadata(conn)?;
    let virtual_tables = metadata
        .iter()
        .filter(|(_, info)| info.kind == "virtual" && info.columns.is_none())
        .map(|(name, _)| identifier_key(&format!("{name}_")))
        .collect::<Vec<_>>();
    let mut schema = Schema {
        scope: scope.into(),
        completeness: "complete".into(),
        tables: Vec::new(),
        indexes: Vec::new(),
        views: Vec::new(),
        triggers: Vec::new(),
        foreign_keys: Vec::new(),
        unique_constraints: Vec::new(),
    };
    let mut stmt = conn.prepare("SELECT type,name,tbl_name,rootpage,sql FROM sqlite_schema WHERE type IN ('table','index','view','trigger') ORDER BY name").map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    for row in rows {
        let (kind, name, table, root, sql) = row.map_err(|e| Error::Sqlite(e.to_string()))?;
        if scope == "selected_table"
            && selected.is_some_and(|s| identifier_key(&table) != identifier_key(s))
        {
            continue;
        }
        match kind.as_str() {
            "table" => {
                let listed = metadata.get(&name).ok_or_else(|| {
                    Error::Format(format!("SQLite schema/table inventory mismatch: {name}"))
                })?;
                let shadow = listed.kind == "table"
                    && virtual_tables
                        .iter()
                        .any(|prefix| identifier_key(&name).starts_with(prefix));
                let virtual_table = listed.kind == "virtual";
                let columns = if scope == "inventory" || virtual_table {
                    Vec::new()
                } else {
                    read_columns(conn, &name, budget)?
                };
                reserve_schema_text(budget, &name, sql.as_deref())?;
                let definition_status = definition_status(scope, sql.as_deref());
                let (virtual_module, virtual_module_status) =
                    parse_virtual_module(listed.kind.as_str(), scope, sql.as_deref());
                budget.reserve(
                    definition_status.len()
                        + virtual_module.as_deref().map_or(0, str::len)
                        + virtual_module_status.len()
                        + 48,
                )?;
                schema.tables.push(Table {
                    name,
                    sql: if scope == "inventory" { None } else { sql },
                    definition_status,
                    source: "sqlite_schema.sql".into(),
                    root_page: root.max(0) as usize,
                    kind: if shadow {
                        "unknown".into()
                    } else {
                        table_kind(&listed.kind).into()
                    },
                    without_rowid: listed.without_rowid,
                    without_rowid_status: "known".into(),
                    strict: listed.strict,
                    strict_status: "known".into(),
                    column_count: listed.columns,
                    column_count_status: if listed.columns.is_some() {
                        "known"
                    } else {
                        "unknown"
                    }
                    .into(),
                    columns_completeness: if scope == "inventory" {
                        "not_requested"
                    } else if virtual_table {
                        "unsupported"
                    } else {
                        "complete"
                    }
                    .into(),
                    columns,
                    primary_key_columns: Vec::new(),
                    classification_source: "pragma_table_list".into(),
                    virtual_module,
                    virtual_module_status,
                    virtual_module_source: "sqlite_schema.sql".into(),
                });
            }
            "index" => {
                reserve_schema_text(budget, &name, sql.as_deref())?;
                reserve_schema_text(budget, &table, None)?;
                schema.indexes.push(Index {
                    name,
                    table,
                    sql: if scope == "inventory" { None } else { sql },
                    root_page: root.max(0) as usize,
                    unique: false,
                    partial: false,
                    list_sequence: None,
                    partial_status: "unknown".into(),
                    origin_status: "unknown".into(),
                    predicate_sql: None,
                    predicate_status: "unknown".into(),
                    predicate_source: "sqlite_schema.sql".into(),
                    origin: None,
                    identity: "unknown".into(),
                    expression_status: "unknown".into(),
                    expression_columns: Vec::new(),
                    columns: Vec::new(),
                });
            }
            "view" => {
                reserve_schema_text(budget, &name, sql.as_deref())?;
                let definition_status = definition_status(scope, sql.as_deref());
                budget.reserve(definition_status.len() + 24)?;
                let columns = if scope == "inventory" {
                    Vec::new()
                } else {
                    read_columns(conn, &name, budget)?
                };
                let column_count = (scope != "inventory").then_some(columns.len());
                let (dependencies, dependencies_status) = view_dependencies(scope, sql.as_deref());
                for dependency in &dependencies {
                    budget.reserve(dependency.len() + 16)?;
                }
                budget.reserve(dependencies_status.len() + 48)?;
                schema.views.push(NamedSql {
                    name,
                    sql: if scope == "inventory" { None } else { sql },
                    definition_status,
                    source: "sqlite_schema.sql".into(),
                    columns,
                    columns_completeness: if scope == "inventory" {
                        "not_requested"
                    } else {
                        "complete"
                    }
                    .into(),
                    column_count,
                    dependencies,
                    dependencies_status,
                    dependencies_source: "sqlite_schema.sql".into(),
                });
            }
            "trigger" => {
                let resolved_target = metadata
                    .keys()
                    .find(|candidate| identifier_key(candidate) == identifier_key(&table))
                    .cloned();
                let target = selected
                    .map(str::to_owned)
                    .or_else(|| resolved_target.clone())
                    .unwrap_or_else(|| table.clone());
                let target_status = if resolved_target.is_some() {
                    "declared"
                } else {
                    "unknown"
                };
                reserve_schema_text(budget, &name, sql.as_deref())?;
                reserve_schema_text(budget, &target, None)?;
                let definition_status = definition_status(scope, sql.as_deref());
                let (timing, event, metadata_status) = trigger_metadata(if scope == "inventory" {
                    None
                } else {
                    sql.as_deref()
                });
                budget.reserve(
                    definition_status.len()
                        + timing.len()
                        + event.len()
                        + metadata_status.len()
                        + target_status.len()
                        + 24,
                )?;
                schema.triggers.push(Trigger {
                    name,
                    table: target,
                    table_status: target_status.into(),
                    sql: if scope == "inventory" { None } else { sql },
                    definition_status,
                    source: "sqlite_schema.sql".into(),
                    timing,
                    event,
                    metadata_status,
                });
            }
            _ => {}
        }
    }
    if selected.is_some_and(|s| !schema.tables.iter().any(|t| t.name == s)) {
        return Err(Error::Selection(format!(
            "Selected ordinary table does not exist with that exact name: {}",
            selected.unwrap_or_default()
        )));
    }
    for index in &mut schema.indexes {
        let mut pragma = conn
            .prepare(
                "SELECT seq, name, \"unique\", origin, partial \
                 FROM temp.pragma_index_list(?, 'main')",
            )
            .map_err(|error| Error::Sqlite(error.to_string()))?;
        let flags = pragma
            .query_map([index.table.as_str()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? != 0,
                    row.get::<_, i64>(4).unwrap_or(0) != 0,
                    row.get::<_, Option<String>>(3)?,
                ))
            })
            .map_err(|error| Error::Sqlite(error.to_string()))?;
        for flag in flags {
            let (sequence, name, unique, partial, origin) =
                flag.map_err(|error| Error::Sqlite(error.to_string()))?;
            if name == index.name {
                index.unique = unique;
                index.partial = partial;
                index.list_sequence = Some(sequence.max(0) as usize);
                index.partial_status = "known".into();
                index.origin = origin;
                index.origin_status = index_origin_status(index.origin.as_deref()).into();
                break;
            }
        }

        let without_rowid = schema
            .tables
            .iter()
            .find(|table| table.name == index.table)
            .is_some_and(|table| table.without_rowid);
        index.columns = read_index_columns(
            conn,
            &index.name,
            without_rowid,
            scope != "inventory",
            budget,
        )?;
        index.identity = index_identity(index.origin.as_deref());
        let (predicate_sql, predicate_status) = partial_predicate(
            index.partial,
            scope != "inventory",
            if scope == "inventory" {
                None
            } else {
                index.sql.as_deref()
            },
        );
        index.predicate_sql = predicate_sql;
        index.predicate_status = predicate_status;
        index.expression_status = if scope == "inventory" {
            "not_requested"
        } else if index.columns.iter().any(|column| column.cid == -2) {
            "present_unparsed"
        } else {
            "none"
        }
        .into();
        index.expression_columns = index
            .columns
            .iter()
            .filter(|column| column.cid == -2)
            .map(|column| IndexExpression {
                seqno: column.seqno,
                definition_status: if scope == "inventory" {
                    "not_requested"
                } else if index.sql.is_some() {
                    "present_unparsed"
                } else {
                    "unknown"
                }
                .into(),
                source: "pragma_index_xinfo/sqlite_schema.sql".into(),
            })
            .collect();
        budget.reserve(index.identity.len() + index.expression_status.len() + 64)?;
        budget.reserve(index.partial_status.len() + index.origin_status.len() + 32)?;
        budget.reserve(
            index.predicate_sql.as_deref().map_or(0, str::len)
                + index.predicate_status.len()
                + index.predicate_source.len()
                + 32,
        )?;
        for expression in &index.expression_columns {
            budget.reserve(expression.definition_status.len() + expression.source.len() + 32)?;
        }
        if index.unique && index.origin.as_deref() == Some("u") {
            let columns = index
                .columns
                .iter()
                .filter(|column| column.key)
                .filter_map(|column| column.name.clone())
                .collect::<Vec<_>>();
            let status =
                if columns.len() == index.columns.iter().filter(|column| column.key).count() {
                    "complete"
                } else {
                    "unknown_expression_column"
                };
            budget.reserve(index.name.len() + index.table.len() + 128)?;
            for column in &columns {
                budget.reserve(column.len() + 16)?;
            }
            schema.unique_constraints.push(UniqueConstraint {
                table: index.table.clone(),
                index: index.name.clone(),
                columns,
                source: "pragma_index_list/index_xinfo".into(),
                status: status.into(),
            });
        }
    }

    for table in &mut schema.tables {
        let columns = table
            .columns
            .iter()
            .filter(|column| column.primary_key_position > 0)
            .map(|column| PrimaryKeyColumn {
                name: column.name.clone(),
                position: column.primary_key_position,
                source: "pragma_table_xinfo".into(),
                status: "declared".into(),
            })
            .collect::<Vec<_>>();
        for column in &columns {
            budget.reserve(column.name.len() + column.source.len() + column.status.len() + 64)?;
        }
        table.primary_key_columns = columns;
    }
    let tables = schema
        .tables
        .iter()
        .map(|table| table.name.clone())
        .collect::<Vec<_>>();
    for table in tables {
        if scope == "selected_table" && selected != Some(table.as_str()) {
            continue;
        }
        let primary_keys = schema
            .tables
            .iter()
            .map(|candidate| {
                let keys = candidate
                    .columns
                    .iter()
                    .filter(|column| column.primary_key_position > 0)
                    .map(|column| (column.primary_key_position, column.name.clone()))
                    .collect::<HashMap<usize, String>>();
                (candidate.name.clone(), keys)
            })
            .collect::<HashMap<_, _>>();
        let table_sql = schema
            .tables
            .iter()
            .find(|candidate| candidate.name == table)
            .and_then(|candidate| candidate.sql.as_deref());
        let mut foreign = conn
            .prepare(
                "SELECT id, seq, \"table\", \"from\", \"to\", on_update, \
                 on_delete, \"match\" \
                 FROM temp.pragma_foreign_key_list(?, 'main')",
            )
            .map_err(|error| Error::Sqlite(error.to_string()))?;
        let rows = foreign
            .query_map([table.as_str()], |row| {
                let id = row.get::<_, i64>(0)?;
                let seq = row.get::<_, i64>(1)?;
                let target_table = row.get::<_, String>(2)?;
                let target_column = row.get::<_, Option<String>>(4)?;
                let (target_column, target_column_status) = match target_column {
                    Some(column) => (Some(column), "declared"),
                    None => match primary_keys
                        .get(&target_table)
                        .and_then(|keys| keys.get(&(seq as usize + 1)))
                    {
                        Some(column) => (Some(column.clone()), "inferred_primary_key"),
                        None => (None, "unknown"),
                    },
                };
                let target_table_status = if primary_keys.contains_key(&target_table) {
                    "declared"
                } else {
                    "unknown"
                };
                Ok(ForeignKey {
                    table: table.clone(),
                    id: id.max(0) as usize,
                    seq: seq.max(0) as usize,
                    column: row.get(3)?,
                    target_table,
                    target_column,
                    target_column_status: target_column_status.into(),
                    on_update: row.get(5)?,
                    on_delete: row.get(6)?,
                    match_name: row.get(7)?,
                    deferrable: table_sql.and_then(foreign_key_deferrable),
                    source: "pragma_foreign_key_list".into(),
                    source_column_status: if row.get::<_, Option<String>>(3)?.is_some() {
                        "declared"
                    } else {
                        "unknown"
                    }
                    .into(),
                    target_table_status: target_table_status.into(),
                    action_status: "known".into(),
                    match_status: "known".into(),
                })
            })
            .map_err(|error| Error::Sqlite(error.to_string()))?;
        let mut table_foreign_keys = rows
            .map(|row| row.map_err(|error| Error::Sqlite(error.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        table_foreign_keys.sort_by_key(|foreign_key| (foreign_key.id, foreign_key.seq));

        for foreign_key in table_foreign_keys {
            reserve_foreign_key(budget, &foreign_key)?;
            schema.foreign_keys.push(foreign_key);
        }
    }
    Ok(schema)
}

fn read_columns(
    conn: &Connection,
    table: &str,
    budget: &mut OutputBudget,
) -> Result<Vec<Column>, Error> {
    let columns = read_column_metadata(conn, table)?;
    for column in &columns {
        budget.reserve(column_size(column))?;
    }
    Ok(columns)
}

fn read_column_metadata(conn: &Connection, table: &str) -> Result<Vec<Column>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT cid, name, type, \"notnull\", dflt_value, pk, hidden \
             FROM temp.pragma_table_xinfo(?, 'main')",
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map([table], |r| {
            let hidden = r.get::<_, i64>(6)?;
            let (hidden_role, hidden_role_status) = match hidden {
                0 => ("ordinary", "known"),
                1 => ("virtual", "known"),
                2 => ("virtual_generated", "known"),
                3 => ("stored_generated", "known"),
                _ => ("unknown", "unknown"),
            };
            let default_sql = r.get::<_, Option<String>>(4)?;
            let declared_type = r.get::<_, Option<String>>(2)?;
            let primary_key_position = r.get::<_, i64>(5)?;
            let (primary_key_position, primary_key_status) =
                primary_key_position_fact(primary_key_position);
            let (not_null, not_null_status) = boolean_fact(r.get::<_, i64>(3)?);
            Ok(Column {
                cid: r.get::<_, i64>(0)? as usize,
                name: r.get(1)?,
                declared_type_status: if declared_type.is_some() {
                    "declared"
                } else {
                    "absent"
                }
                .into(),
                declared_type: declared_type.unwrap_or_default(),
                not_null,
                not_null_status: not_null_status.into(),
                default_status: default_status(default_sql.as_deref()).into(),
                default_sql,
                primary_key_position: primary_key_position.max(0) as usize,
                primary_key_status: primary_key_status.into(),
                hidden: hidden.max(0) as usize,
                hidden_role: hidden_role.into(),
                hidden_role_status: hidden_role_status.into(),
                source: "pragma_table_xinfo".into(),
                metadata_status: "complete".into(),
            })
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut columns = Vec::new();
    for row in rows {
        let column = row.map_err(|e| Error::Sqlite(e.to_string()))?;
        columns.push(column);
    }
    columns.sort_by_key(|column| column.cid);
    Ok(columns)
}

fn reserve_schema_text(
    budget: &mut OutputBudget,
    primary: &str,
    secondary: Option<&str>,
) -> Result<(), Error> {
    let bytes = primary
        .len()
        .saturating_add(secondary.map_or(0, str::len))
        .saturating_add(128);
    budget.reserve(bytes)
}

fn definition_status(scope: &str, sql: Option<&str>) -> String {
    if scope == "inventory" {
        return "not_requested".into();
    }
    match sql {
        None => "unavailable".into(),
        Some(value) if value.trim().is_empty() => "malformed".into(),
        Some(_) => "available".into(),
    }
}

fn default_status(default_sql: Option<&str>) -> &'static str {
    match default_sql {
        None => "absent",
        Some(value) if value.trim().is_empty() => "malformed",
        Some(_) => "available",
    }
}

fn primary_key_position_fact(position: i64) -> (usize, &'static str) {
    if position < 0 {
        (0, "unknown")
    } else {
        (position as usize, "known")
    }
}

fn boolean_fact(value: i64) -> (bool, &'static str) {
    match value {
        0 => (false, "known"),
        1 => (true, "known"),
        _ => (value != 0, "unknown"),
    }
}

fn view_dependencies(scope: &str, sql: Option<&str>) -> (Vec<String>, String) {
    if scope == "inventory" {
        return (Vec::new(), "not_requested".into());
    }
    let Some(sql) = sql else {
        return (Vec::new(), "unavailable".into());
    };
    let (tokens, malformed_sql) = view_dependency_tokens(sql);
    let mut dependencies = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if !token.eq_ignore_ascii_case("from") && !token.eq_ignore_ascii_case("join") {
            continue;
        }
        let Some(candidate) = tokens.get(index + 1) else {
            return (dependencies, "malformed".into());
        };
        if candidate.eq_ignore_ascii_case("select") {
            return (dependencies, "malformed".into());
        }
        if !dependencies.iter().any(|value: &String| value == candidate) {
            dependencies.push((*candidate).to_owned());
        }
    }
    if malformed_sql {
        return (dependencies, "malformed".into());
    }
    if dependencies.is_empty() {
        (dependencies, "none_proven".into())
    } else {
        (dependencies, "complete".into())
    }
}

fn view_dependency_tokens(sql: &str) -> (Vec<String>, bool) {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let bytes = sql.as_bytes();
    let mut offset = 0;

    while offset < bytes.len() {
        let byte = bytes[offset];
        if let Some(delimiter) = quote {
            if byte == delimiter {
                if bytes.get(offset + 1) == Some(&delimiter) {
                    offset += 2;
                    continue;
                }
                quote = None;
            }
            offset += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`' | b'[') {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
            quote = Some(if byte == b'[' { b']' } else { byte });
            offset += 1;
            continue;
        }
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.') {
            token.push(byte as char);
        } else if !token.is_empty() {
            tokens.push(std::mem::take(&mut token));
        }
        offset += 1;
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    (tokens, quote.is_some())
}

fn parse_virtual_module(kind: &str, scope: &str, sql: Option<&str>) -> (Option<String>, String) {
    if kind != "virtual" {
        return (None, "absent".into());
    }
    if scope == "inventory" {
        return (None, "not_requested".into());
    }
    let Some(sql) = sql else {
        return (None, "unavailable".into());
    };
    let tokens = sql
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    let Some(using_index) = tokens
        .iter()
        .position(|token| token.eq_ignore_ascii_case("using"))
    else {
        return (None, "malformed".into());
    };
    let Some(module) = tokens.get(using_index + 1) else {
        return (None, "malformed".into());
    };
    (Some((*module).to_owned()), "declared".into())
}

fn trigger_metadata(sql: Option<&str>) -> (String, String, String) {
    let Some(sql) = sql else {
        return ("unknown".into(), "unknown".into(), "not_requested".into());
    };
    let tokens = sql
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_uppercase())
        .collect::<Vec<_>>();
    let Some(trigger_index) = tokens.iter().position(|token| token == "TRIGGER") else {
        return ("unknown".into(), "unknown".into(), "malformed".into());
    };
    let after_trigger = &tokens[trigger_index + 1..];
    let (timing, event_start) =
        if let Some(index) = after_trigger.iter().position(|token| token == "INSTEAD") {
            if after_trigger.get(index + 1).map(String::as_str) != Some("OF") {
                return ("unknown".into(), "unknown".into(), "malformed".into());
            }
            ("instead_of", index + 2)
        } else if let Some(index) = after_trigger.iter().position(|token| token == "BEFORE") {
            ("before", index + 1)
        } else if let Some(index) = after_trigger.iter().position(|token| token == "AFTER") {
            ("after", index + 1)
        } else {
            return ("unknown".into(), "unknown".into(), "malformed".into());
        };
    let event = match after_trigger.get(event_start).map(String::as_str) {
        Some("INSERT") => "insert",
        Some("UPDATE") => "update",
        Some("DELETE") => "delete",
        _ => "unknown",
    };
    let status = if timing == "unknown" || event == "unknown" {
        "unknown"
    } else {
        "complete"
    };
    (timing.into(), event.into(), status.into())
}

fn column_size(column: &Column) -> usize {
    column
        .name
        .len()
        .saturating_add(column.declared_type.len())
        .saturating_add(column.declared_type_status.len())
        .saturating_add(column.not_null_status.len())
        .saturating_add(column.default_sql.as_deref().map_or(0, str::len))
        .saturating_add(column.default_status.len())
        .saturating_add(column.primary_key_status.len())
        .saturating_add(column.hidden_role.len())
        .saturating_add(column.hidden_role_status.len())
        .saturating_add(column.source.len())
        .saturating_add(column.metadata_status.len())
        .saturating_add(128)
}

fn reserve_foreign_key(budget: &mut OutputBudget, foreign_key: &ForeignKey) -> Result<(), Error> {
    let bytes = foreign_key.table.len()
        + foreign_key.column.as_deref().map_or(0, str::len)
        + foreign_key.target_table.len()
        + foreign_key.target_column.as_deref().map_or(0, str::len)
        + foreign_key.on_update.len()
        + foreign_key.on_delete.len()
        + foreign_key.match_name.len()
        + foreign_key.target_column_status.len()
        + foreign_key.source.len()
        + foreign_key.source_column_status.len()
        + foreign_key.target_table_status.len()
        + foreign_key.action_status.len()
        + foreign_key.match_status.len()
        + 128;
    budget.reserve(bytes)
}

fn partial_predicate(
    partial: bool,
    metadata_requested: bool,
    sql: Option<&str>,
) -> (Option<String>, String) {
    if !partial {
        return (None, "absent".into());
    }

    if !metadata_requested {
        return (None, "not_requested".into());
    }

    let Some(sql) = sql else {
        return (None, "unavailable".into());
    };

    let Some(where_offset) = find_where_keyword(sql) else {
        return (None, "malformed".into());
    };
    let predicate = sql[where_offset + b"WHERE".len()..].trim();
    if predicate.is_empty() {
        return (None, "malformed".into());
    }
    if sql_has_unterminated_quote(predicate) {
        return (None, "malformed".into());
    }

    (Some(predicate.to_owned()), "present_unparsed".into())
}

fn sql_has_unterminated_quote(sql: &str) -> bool {
    let bytes = sql.as_bytes();
    let mut quote = None;
    let mut offset = 0;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if let Some(delimiter) = quote {
            if byte == delimiter {
                if bytes.get(offset + 1) == Some(&delimiter) {
                    offset += 2;
                    continue;
                }
                quote = None;
            }
            offset += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`' | b'[') {
            quote = Some(if byte == b'[' { b']' } else { byte });
        }
        offset += 1;
    }
    quote.is_some()
}

fn find_where_keyword(sql: &str) -> Option<usize> {
    let bytes = sql.as_bytes();
    let keyword = b"WHERE";
    let mut quote = None;
    let mut offset = 0;

    while offset + keyword.len() <= bytes.len() {
        let byte = bytes[offset];
        if let Some(delimiter) = quote {
            if byte == delimiter {
                if bytes.get(offset + 1) == Some(&delimiter) {
                    offset += 2;
                    continue;
                }
                quote = None;
            }
            offset += 1;
            continue;
        }

        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
            offset += 1;
            continue;
        }

        if bytes[offset..offset + keyword.len()].eq_ignore_ascii_case(keyword)
            && (offset == 0 || !is_sql_identifier_byte(bytes[offset - 1]))
            && (offset + keyword.len() == bytes.len()
                || !is_sql_identifier_byte(bytes[offset + keyword.len()]))
        {
            return Some(offset);
        }
        offset += 1;
    }

    None
}

fn is_sql_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn index_identity(origin: Option<&str>) -> String {
    match origin {
        Some("c") => "created_index".into(),
        Some("u") => "unique_constraint".into(),
        Some("pk") => "primary_key".into(),
        Some(other) => return format!("unknown:{other}"),
        None => "unknown".into(),
    }
}

fn index_origin_status(origin: Option<&str>) -> &'static str {
    match origin {
        Some("c" | "u" | "pk") => "known",
        Some(_) => "unknown",
        None => "unavailable",
    }
}

fn foreign_key_deferrable(sql: &str) -> Option<bool> {
    let normalized = sql.to_ascii_lowercase();
    if normalized.contains("not deferrable") {
        Some(false)
    } else if normalized.contains("deferrable") {
        Some(true)
    } else {
        None
    }
}

fn read_index_columns(
    conn: &Connection,
    index: &str,
    without_rowid: bool,
    metadata_requested: bool,
    budget: &mut OutputBudget,
) -> Result<Vec<IndexColumn>, Error> {
    let mut statement = conn
        .prepare(
            "SELECT seqno, cid, name, \"desc\", coll, key \
             FROM temp.pragma_index_xinfo(?, 'main')",
        )
        .map_err(|error| Error::Sqlite(error.to_string()))?;
    let rows = statement
        .query_map([index], |row| {
            let cid = row.get::<_, i64>(1)?;
            let collation = row.get::<_, Option<String>>(4)?;
            let descending = row.get::<_, i64>(3)? != 0;
            let key = row.get::<_, i64>(5)? != 0;
            Ok(IndexColumn {
                seqno: row.get::<_, i64>(0)? as usize,
                cid,
                name: row.get(2)?,
                descending,
                collation: collation.clone(),
                key,
                identity: match cid {
                    -1 if without_rowid => "primary_key_auxiliary",
                    -1 => "rowid",
                    -2 => "expression",
                    value if value >= 0 => "column",
                    _ => "unknown",
                }
                .into(),
                order_status: if descending {
                    "descending"
                } else {
                    "ascending"
                }
                .into(),
                collation_status: if collation.is_some() {
                    "known"
                } else {
                    "unknown"
                }
                .into(),
                role_status: if key { "key" } else { "auxiliary" }.into(),
                source: "pragma_index_xinfo".into(),
                metadata_status: if metadata_requested {
                    "complete"
                } else {
                    "not_requested"
                }
                .into(),
            })
        })
        .map_err(|error| Error::Sqlite(error.to_string()))?;
    let mut columns = Vec::new();
    for row in rows {
        let column = row.map_err(|error| Error::Sqlite(error.to_string()))?;
        let size = column
            .name
            .as_deref()
            .map_or(0, str::len)
            .saturating_add(column.collation.as_deref().map_or(0, str::len))
            .saturating_add(column.identity.len())
            .saturating_add(column.order_status.len())
            .saturating_add(column.collation_status.len())
            .saturating_add(column.role_status.len())
            .saturating_add(column.source.len())
            .saturating_add(column.metadata_status.len())
            .saturating_add(96);
        budget.reserve(size)?;
        columns.push(column);
    }
    columns.sort_by_key(|column| column.seqno);
    Ok(columns)
}
fn read_rows(
    conn: &Connection,
    table: &str,
    input: &Input,
    encoding: &str,
    budget: &mut OutputBudget,
) -> Result<Rows, Error> {
    let columns = if let Some(requested) = &input.columns {
        validate_requested_columns(conn, table, requested)?;
        requested.clone()
    } else {
        read_column_metadata(conn, table)?
            .into_iter()
            .filter(|c| c.hidden != 1)
            .map(|c| c.name)
            .collect()
    };
    if columns.is_empty() {
        return Err(Error::Selection(
            "Selected table has no visible columns.".into(),
        ));
    }
    budget.reserve(
        columns
            .iter()
            .map(|column| column.len().saturating_add(32))
            .sum(),
    )?;
    let limit = input.row_limit.unwrap_or(DEFAULT_ROW_LIMIT);
    let projection = columns
        .iter()
        .map(|c| {
            let identifier = quote_ident(c);
            format!("CASE typeof({identifier}) WHEN 'text' THEN 't' || hex(CAST({identifier} AS BLOB)) WHEN 'blob' THEN 'b' || hex({identifier}) ELSE {identifier} END")
        })
        .collect::<Vec<_>>()
        .join(",");
    let source = row_source(table);
    let sql = format!("SELECT {} FROM {} LIMIT ?", projection, source);
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mapped = stmt
        .query_map([limit as i64], |row| {
            let mut values = Vec::with_capacity(columns.len());
            for index in 0..columns.len() {
                let raw = row.get_ref(index)?;
                let expansion = match raw {
                    ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
                        bytes.len().saturating_mul(2).saturating_add(64)
                    }
                    _ => 64,
                };
                budget
                    .reserve(expansion)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
                let decoded = value(raw, encoding)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
                values.push(decoded);
            }
            Ok(values)
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let values = mapped
        .map(|r| r.map_err(|e| Error::Sqlite(e.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    let truncated = has_more_rows(conn, table, limit)?;
    Ok(Rows {
        table: table.into(),
        columns,
        returned_rows: values.len(),
        values,
        row_limit: limit,
        truncated,
        order: "unspecified".into(),
    })
}

fn has_more_rows(conn: &Connection, table: &str, limit: usize) -> Result<bool, Error> {
    match conn.query_row(
        &format!("SELECT 1 FROM {} LIMIT 1 OFFSET ?", row_source(table)),
        [limit as i64],
        |_row| Ok(()),
    ) {
        Ok(()) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(error) => Err(Error::Sqlite(error.to_string())),
    }
}

fn validate_requested_columns(
    conn: &Connection,
    table: &str,
    requested: &[String],
) -> Result<(), Error> {
    let available = read_column_metadata(conn, table)?
        .into_iter()
        .filter(|column| column.hidden != 1)
        .collect::<Vec<_>>();
    for name in requested {
        if !available.iter().any(|column| column.name == *name) {
            return Err(Error::Selection(format!(
                "Selected column does not exist with that exact name: {name}"
            )));
        }
    }
    Ok(())
}
fn quote_ident(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn row_source(table: &str) -> String {
    format!("main.{} NOT INDEXED", quote_ident(table))
}

fn value(value: ValueRef<'_>, encoding: &str) -> Result<Value, Error> {
    let decoded = match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(v) => Value::Integer {
            value: v.to_string(),
        },
        ValueRef::Real(v) => Value::Real {
            value: real_json_value(v),
        },
        ValueRef::Text(v) => {
            let text = v.strip_prefix(b"t").and_then(hex_decode);
            let blob = v.strip_prefix(b"b").and_then(hex_decode);
            match (text, blob) {
                (Some(bytes), _) => Value::Text {
                    value: decode_text(&bytes, encoding),
                    bytes_hex: hex(&bytes),
                    encoding: encoding.into(),
                },
                (_, Some(bytes)) => Value::Blob { hex: hex(&bytes) },
                _ => {
                    return Err(Error::Format(
                        "SQLite returned an invalid encoded cell.".into(),
                    ));
                }
            }
        }
        ValueRef::Blob(v) => Value::Blob { hex: hex(v) },
    };
    Ok(decoded)
}

fn real_json_value(value: f64) -> serde_json::Value {
    if value.is_nan() {
        return serde_json::Value::Null;
    }
    if value == f64::INFINITY {
        return serde_json::Value::String("Infinity".into());
    }
    if value == f64::NEG_INFINITY {
        return serde_json::Value::String("-Infinity".into());
    }
    if value == 0.0 && value.is_sign_negative() {
        return serde_json::Value::String("-0".into());
    }
    serde_json::json!(value)
}

fn hex_decode(value: &[u8]) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            let high = (value[index] as char).to_digit(16)? as u8;
            let low = (value[index + 1] as char).to_digit(16)? as u8;
            Some((high << 4) | low)
        })
        .collect()
}
fn decode_text(bytes: &[u8], encoding: &str) -> String {
    match encoding {
        "UTF-16le" | "UTF-16be" => {
            let mut units = Vec::with_capacity(bytes.len() / 2);
            for pair in bytes.chunks_exact(2) {
                units.push(if encoding == "UTF-16le" {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                });
            }
            if bytes.len() % 2 != 0 {
                units.push(0xfffd);
            }
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use rusqlite::types::ValueRef;

    use super::{
        OutputBudget, boolean_fact, decode_text, default_status, has_more_rows,
        index_origin_status, partial_predicate, primary_key_position_fact, read_schema,
        real_json_value, row_source, table_kind, table_metadata, validate_database_encoding, value,
        view_dependencies,
    };

    #[test]
    fn partial_predicate_ignores_where_inside_quoted_literals() {
        let (predicate, status) = partial_predicate(
            true,
            true,
            Some("CREATE INDEX item_filter ON items(name) WHERE note = 'WHERE'"),
        );
        assert_eq!(predicate.as_deref(), Some("note = 'WHERE'"));
        assert_eq!(status, "present_unparsed");
    }

    #[test]
    fn partial_predicate_marks_missing_expression_malformed() {
        let (predicate, status) =
            partial_predicate(true, true, Some("CREATE INDEX item_filter ON items(name)"));
        assert!(predicate.is_none());
        assert_eq!(status, "malformed");
    }

    #[test]
    fn partial_predicate_rejects_unterminated_quoted_expression() {
        let (predicate, status) = partial_predicate(
            true,
            true,
            Some("CREATE INDEX item_filter ON items(name) WHERE note = 'unterminated"),
        );
        assert!(predicate.is_none());
        assert_eq!(status, "malformed");
    }

    #[test]
    fn view_dependencies_preserve_schema_qualified_relations() {
        let (dependencies, status) = view_dependencies(
            "database",
            Some("CREATE VIEW report AS SELECT * FROM main.users JOIN temp.audit"),
        );
        assert_eq!(dependencies, vec!["main.users", "temp.audit"]);
        assert_eq!(status, "complete");
    }

    #[test]
    fn view_dependencies_ignore_quoted_keywords_and_report_unterminated_quotes() {
        let (dependencies, status) = view_dependencies(
            "database",
            Some("CREATE VIEW report AS SELECT 'FROM fake' AS label FROM real_table"),
        );
        assert_eq!(dependencies, vec!["real_table"]);
        assert_eq!(status, "complete");

        let (dependencies, status) = view_dependencies(
            "database",
            Some("CREATE VIEW report AS SELECT * FROM 'unterminated"),
        );
        assert!(dependencies.is_empty());
        assert_eq!(status, "malformed");
    }

    #[test]
    fn row_source_matches_read_only_main_table_profile() {
        assert_eq!(row_source("users"), "main.\"users\" NOT INDEXED");
        assert_eq!(row_source("odd\"name"), "main.\"odd\"\"name\" NOT INDEXED");
    }

    #[test]
    fn table_metadata_enumerates_main_schema_tables() {
        let connection = Connection::open_in_memory().expect("connection");
        connection
            .execute_batch(
                "CREATE TABLE users (id INTEGER PRIMARY KEY);
                 CREATE TEMP TABLE temporary_users (id INTEGER PRIMARY KEY);",
            )
            .expect("main table");

        let metadata = table_metadata(&connection).expect("table metadata");
        let users = metadata.get("users").expect("users metadata");

        assert_eq!(users.kind, "table");
        assert_eq!(users.columns, Some(1));
        assert!(!metadata.contains_key("temporary_users"));
    }

    #[test]
    fn main_schema_foreign_key_pragma_is_schema_qualified() {
        let connection = Connection::open_in_memory().expect("connection");
        connection
            .execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(parent_id INTEGER REFERENCES parent(id));")
            .expect("schema");
        let count: i64 = connection
            .prepare("SELECT count(*) FROM temp.pragma_foreign_key_list(?, 'main')")
            .expect("pragma")
            .query_row(["child"], |row| row.get(0))
            .expect("foreign keys");
        assert_eq!(count, 1);
    }

    #[test]
    fn schema_pragmas_keep_main_metadata_when_temp_table_shadows_name() {
        let connection = Connection::open_in_memory().expect("connection");
        connection
            .execute_batch(
                "CREATE TABLE items (id INTEGER PRIMARY KEY, main_value TEXT);
                 CREATE INDEX items_main_idx ON items(main_value);
                 CREATE TEMP TABLE items (id INTEGER PRIMARY KEY, temp_value TEXT);
                 CREATE INDEX temp.items_temp_idx ON items(temp_value);",
            )
            .expect("schema");

        let schema = read_schema(&connection, "full", None, &mut OutputBudget::new())
            .expect("schema metadata");
        let table = schema
            .tables
            .iter()
            .find(|table| table.name == "items")
            .expect("main table");
        assert_eq!(
            table
                .columns
                .iter()
                .map(|column| column.name.as_str())
                .collect::<Vec<_>>(),
            vec!["id", "main_value"]
        );

        let index = schema
            .indexes
            .iter()
            .find(|index| index.name == "items_main_idx")
            .expect("main index");
        assert_eq!(index.list_sequence, Some(0));
        assert_eq!(
            index
                .columns
                .iter()
                .filter_map(|column| column.name.as_deref())
                .collect::<Vec<_>>(),
            vec!["main_value"]
        );
    }

    #[test]
    fn built_in_schema_pragmas_are_not_shadowed_by_main_tables() {
        let connection = Connection::open_in_memory().expect("connection");
        connection
            .execute_batch(
                "CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT);
                 CREATE INDEX items_value_idx ON items(value);
                 CREATE TABLE pragma_table_list (value TEXT);
                 CREATE TABLE pragma_table_xinfo (value TEXT);
                 CREATE TABLE pragma_index_list (value TEXT);
                 CREATE TABLE pragma_index_xinfo (value TEXT);
                 CREATE TABLE pragma_foreign_key_list (value TEXT);",
            )
            .expect("schema");

        let schema = read_schema(&connection, "full", None, &mut OutputBudget::new())
            .expect("schema metadata");
        let table = schema
            .tables
            .iter()
            .find(|table| table.name == "items")
            .expect("items table");

        assert_eq!(
            table
                .columns
                .iter()
                .map(|column| column.name.as_str())
                .collect::<Vec<_>>(),
            vec!["id", "value"]
        );

        let index = schema
            .indexes
            .iter()
            .find(|index| index.name == "items_value_idx")
            .expect("items index");
        assert_eq!(index.list_sequence, Some(0));
        assert_eq!(
            index
                .columns
                .iter()
                .filter_map(|column| column.name.as_deref())
                .collect::<Vec<_>>(),
            vec!["value"]
        );
    }

    #[test]
    fn real_values_use_json_safe_special_forms() {
        assert_eq!(
            real_json_value(f64::INFINITY),
            serde_json::json!("Infinity")
        );
        assert_eq!(
            real_json_value(f64::NEG_INFINITY),
            serde_json::json!("-Infinity")
        );
        assert_eq!(real_json_value(-0.0), serde_json::json!("-0"));
        assert_eq!(real_json_value(f64::NAN), serde_json::Value::Null);
    }

    #[test]
    fn database_encoding_is_restricted_to_sqlite_text_encodings() {
        for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
            assert!(validate_database_encoding(encoding).is_ok());
        }
        let error = validate_database_encoding("ASCII").expect_err("unsupported encoding");
        assert!(error.to_string().contains("unsupported database encoding"));
    }

    #[test]
    fn malformed_utf16_retains_decoder_replacement() {
        assert_eq!(decode_text(&[0x41], "UTF-16le"), "�");
        assert_eq!(decode_text(&[0x41], "UTF-16be"), "�");
    }

    #[test]
    fn malformed_encoded_cells_fail_closed() {
        let error = value(ValueRef::Text(b"xGG"), "UTF-8").expect_err("invalid cell");
        assert!(error.to_string().contains("invalid encoded cell"));
    }

    #[test]
    fn truncation_probe_propagates_sqlite_errors() {
        let connection = Connection::open_in_memory().expect("connection");
        let error = has_more_rows(&connection, "missing", 0).expect_err("missing table");
        assert!(error.to_string().contains("no such table"));
    }

    #[test]
    fn table_kind_preserves_known_values_and_marks_unknown_values() {
        assert_eq!(table_kind("table"), "table");
        assert_eq!(table_kind("virtual"), "virtual");
        assert_eq!(table_kind("shadow"), "shadow");
        assert_eq!(table_kind("extension_kind"), "unknown");
    }

    #[test]
    fn index_origin_status_distinguishes_unknown_and_unavailable_values() {
        assert_eq!(index_origin_status(Some("c")), "known");
        assert_eq!(index_origin_status(Some("u")), "known");
        assert_eq!(index_origin_status(Some("pk")), "known");
        assert_eq!(index_origin_status(Some("extension_origin")), "unknown");
        assert_eq!(index_origin_status(None), "unavailable");
    }

    #[test]
    fn default_status_distinguishes_absent_available_and_malformed_values() {
        assert_eq!(default_status(None), "absent");
        assert_eq!(default_status(Some("CURRENT_TIMESTAMP")), "available");
        assert_eq!(default_status(Some("   ")), "malformed");
    }

    #[test]
    fn primary_key_position_marks_negative_metadata_unknown() {
        assert_eq!(primary_key_position_fact(2), (2, "known"));
        assert_eq!(primary_key_position_fact(-1), (0, "unknown"));
    }

    #[test]
    fn boolean_fact_marks_non_boolean_metadata_unknown() {
        assert_eq!(boolean_fact(0), (false, "known"));
        assert_eq!(boolean_fact(1), (true, "known"));
        assert_eq!(boolean_fact(2), (true, "unknown"));
    }
}
