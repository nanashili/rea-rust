use rea_rust_analysis::sqlite::{self, Input};
use rusqlite::Connection;

fn fixture() -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("temp database");
    let connection = Connection::open(file.path()).expect("open database");
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON; CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, payload BLOB, name_len INTEGER GENERATED ALWAYS AS (length(name)) STORED, name_upper TEXT GENERATED ALWAYS AS (upper(name)) VIRTUAL); CREATE TABLE unique_users (id INTEGER PRIMARY KEY, email TEXT UNIQUE); CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON UPDATE CASCADE ON DELETE SET NULL) STRICT; CREATE TABLE deferred_posts (id INTEGER PRIMARY KEY, user_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED); CREATE TABLE immediate_posts (id INTEGER PRIMARY KEY, user_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id) NOT DEFERRABLE); CREATE TABLE pairs (left_id INTEGER, right_id INTEGER, PRIMARY KEY (left_id, right_id)); CREATE TABLE pair_links (left_id INTEGER, right_id INTEGER, FOREIGN KEY (left_id, right_id) REFERENCES pairs); CREATE TABLE nodes (id INTEGER PRIMARY KEY, parent_id INTEGER, FOREIGN KEY (parent_id) REFERENCES nodes); CREATE TABLE compact (id INTEGER, value TEXT, PRIMARY KEY (id, value)) WITHOUT ROWID; INSERT INTO users(id, name, payload) VALUES (1, 'Ada', x'0102'); INSERT INTO posts VALUES (1, 1); INSERT INTO compact VALUES (1, 'x'); CREATE INDEX compact_value ON compact(value); CREATE INDEX users_name ON users(name); CREATE INDEX users_composite ON users(name DESC, payload COLLATE BINARY) WHERE id > 0; CREATE INDEX users_expression ON users((length(name))); CREATE VIEW user_names AS SELECT name FROM users; CREATE TRIGGER users_audit AFTER INSERT ON USERS BEGIN SELECT 1; END; CREATE TRIGGER users_update AFTER UPDATE ON USERS BEGIN INSERT INTO users(name) VALUES ('audit'); END;",
        )
        .expect("create schema");
    file
}

#[test]
fn reports_foreign_key_actions_and_index_flags() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: Some("database".into()),
            row_limit: None,
        },
    )
    .expect("inspect");
    let foreign = report
        .schema
        .foreign_keys
        .iter()
        .find(|key| key.table == "posts")
        .expect("foreign key");
    assert_eq!(foreign.target_table, "users");
    assert_eq!(foreign.target_table_status, "declared");
    assert_eq!(foreign.on_update, "CASCADE");
    assert_eq!(foreign.on_delete, "SET NULL");
    assert_eq!(foreign.deferrable, None);
    let index = report
        .schema
        .indexes
        .iter()
        .find(|index| index.name == "users_name")
        .expect("index");
    assert!(!index.unique);
    assert!(!index.partial);
}

#[test]
fn preserves_foreign_key_deferrability_from_declared_sql() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: Some("database".into()),
            row_limit: None,
        },
    )
    .expect("inspect");
    let deferred = report
        .schema
        .foreign_keys
        .iter()
        .find(|key| key.table == "deferred_posts")
        .expect("deferred foreign key");
    assert_eq!(deferred.deferrable, Some(true));
    let immediate = report
        .schema
        .foreign_keys
        .iter()
        .find(|key| key.table == "immediate_posts")
        .expect("immediate foreign key");
    assert_eq!(immediate.deferrable, Some(false));
}

#[test]
fn reports_unique_constraints_only_when_index_metadata_proves_them() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: Some("database".into()),
            row_limit: None,
        },
    )
    .expect("inspect");
    let unique = report
        .schema
        .unique_constraints
        .iter()
        .find(|constraint| constraint.table == "unique_users")
        .expect("unique constraint");
    assert_eq!(unique.columns, vec!["email"]);
    assert_eq!(unique.status, "complete");
    assert_eq!(unique.source, "pragma_index_list/index_xinfo");
}

#[test]
fn serialized_report_retains_extended_schema_contract_fields() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: Some("database".into()),
            row_limit: None,
        },
    )
    .expect("inspect");
    let serialized = serde_json::to_value(report).expect("serialize report");
    assert!(serialized["schema"]["tables"][0]["primary_key_columns"].is_array());
    assert_eq!(
        serialized["schema"]["tables"][0]["classification_source"],
        "pragma_table_list"
    );
    assert!(serialized["schema"]["indexes"][0]["columns"].is_array());
    assert!(serialized["schema"]["indexes"][0]["identity"].is_string());
    assert!(serialized["schema"]["indexes"][0]["expression_status"].is_string());
    assert!(serialized["schema"]["indexes"][0]["expression_columns"].is_array());
    assert!(serialized["schema"]["indexes"][0]["predicate_status"].is_string());
    assert!(serialized["schema"]["indexes"][0]["predicate_source"].is_string());
    assert!(serialized["schema"]["indexes"][0]["list_sequence"].is_number());
    assert!(serialized["schema"]["indexes"][0]["origin_status"].is_string());
    assert!(serialized["schema"]["indexes"][0]["columns"][0]["order_status"].is_string());
    assert!(serialized["schema"]["views"][0]["definition_status"].is_string());
    assert!(serialized["schema"]["triggers"][0]["source"].is_string());
    assert!(serialized["schema"]["foreign_keys"][0]["id"].is_number());
    assert!(serialized["schema"]["foreign_keys"][0]["source"].is_string());
    assert!(serialized["schema"]["foreign_keys"][0]["source_column_status"].is_string());
    assert!(serialized["schema"]["unique_constraints"].is_array());
}

#[test]
fn preserves_foreign_key_order_and_inferred_composite_targets() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: Some("database".into()),
            row_limit: None,
        },
    )
    .expect("inspect");
    let composite = report
        .schema
        .foreign_keys
        .iter()
        .filter(|key| key.table == "pair_links")
        .collect::<Vec<_>>();
    assert_eq!(composite.len(), 2);
    assert_eq!((composite[0].id, composite[0].seq), (0, 0));
    assert_eq!(composite[0].target_column.as_deref(), Some("left_id"));
    assert_eq!(composite[0].target_column_status, "inferred_primary_key");
    assert_eq!(composite[1].target_column.as_deref(), Some("right_id"));
    assert_eq!(composite[1].target_column_status, "inferred_primary_key");
    assert_eq!(composite[0].source, "pragma_foreign_key_list");
    assert_eq!(composite[0].source_column_status, "declared");
    assert_eq!(composite[0].target_table_status, "declared");
    assert_eq!(composite[0].action_status, "known");
    assert_eq!(composite[0].match_status, "known");

    let self_reference = report
        .schema
        .foreign_keys
        .iter()
        .find(|key| key.table == "nodes")
        .expect("self reference");
    assert_eq!(self_reference.target_table, "nodes");
    assert_eq!(self_reference.target_column.as_deref(), Some("id"));
    assert_eq!(self_reference.target_column_status, "inferred_primary_key");
    assert_eq!(self_reference.deferrable, None);
}

#[test]
fn selected_scope_marks_uninspected_foreign_key_targets_unknown() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: Some("posts".into()),
            columns: None,
            schema_scope: Some("selected_table".into()),
            row_limit: Some(1),
        },
    )
    .expect("selected table");
    let foreign = report
        .schema
        .foreign_keys
        .iter()
        .find(|key| key.table == "posts")
        .expect("foreign key");
    assert_eq!(foreign.target_table, "users");
    assert_eq!(foreign.target_table_status, "unknown");
}

#[test]
fn projects_index_xinfo_columns_and_identity() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: Some("database".into()),
            row_limit: None,
        },
    )
    .expect("inspect");

    let composite = report
        .schema
        .indexes
        .iter()
        .find(|index| index.name == "users_composite")
        .expect("composite index");
    assert!(composite.partial);
    assert!(composite.list_sequence.is_some());
    assert_eq!(composite.partial_status, "known");
    assert_eq!(composite.predicate_status, "present_unparsed");
    assert_eq!(composite.predicate_sql.as_deref(), Some("id > 0"));
    assert_eq!(composite.predicate_source, "sqlite_schema.sql");
    assert_eq!(composite.origin_status, "known");
    assert_eq!(composite.origin.as_deref(), Some("c"));
    assert_eq!(composite.columns.len(), 3);
    assert_eq!(
        composite
            .columns
            .iter()
            .map(|column| column.seqno)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(composite.columns[0].seqno, 0);
    assert_eq!(composite.columns[0].name.as_deref(), Some("name"));
    assert!(composite.columns[0].descending);
    assert!(composite.columns[0].key);
    assert_eq!(composite.columns[0].identity, "column");
    assert_eq!(composite.columns[0].order_status, "descending");
    assert_eq!(composite.columns[0].collation.as_deref(), Some("BINARY"));
    assert_eq!(composite.columns[0].collation_status, "known");
    assert_eq!(composite.columns[0].role_status, "key");
    assert_eq!(composite.columns[0].source, "pragma_index_xinfo");
    assert_eq!(composite.columns[2].identity, "rowid");
    assert!(!composite.columns[2].key);
    assert_eq!(composite.columns[2].role_status, "auxiliary");

    let expression = report
        .schema
        .indexes
        .iter()
        .find(|index| index.name == "users_expression")
        .expect("expression index");
    let expression_column = expression.columns.first().expect("expression column");
    assert_eq!(expression.identity, "created_index");
    assert_eq!(expression.expression_status, "present_unparsed");
    assert_eq!(expression.expression_columns.len(), 1);
    assert_eq!(expression.expression_columns[0].seqno, 0);
    assert_eq!(
        expression.expression_columns[0].definition_status,
        "present_unparsed"
    );
    assert_eq!(
        expression.expression_columns[0].source,
        "pragma_index_xinfo/sqlite_schema.sql"
    );
    assert_eq!(expression_column.cid, -2);
    assert_eq!(expression_column.identity, "expression");
    assert!(expression_column.name.is_none());
    assert!(expression.sql.as_deref().unwrap().contains("length(name)"));
}

#[test]
fn inventory_marks_index_xinfo_as_not_requested() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: None,
            row_limit: None,
        },
    )
    .expect("inventory");
    let index = report
        .schema
        .indexes
        .iter()
        .find(|index| index.name == "users_composite")
        .expect("index");
    assert_eq!(index.columns[0].metadata_status, "not_requested");
    assert_eq!(index.expression_status, "not_requested");
    assert_eq!(index.predicate_status, "not_requested");
    assert!(index.predicate_sql.is_none());
}

#[test]
fn preserves_strict_and_without_rowid_facts() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: Some("database".into()),
            row_limit: None,
        },
    )
    .expect("inspect");
    let strict = report
        .schema
        .tables
        .iter()
        .find(|table| table.name == "posts")
        .expect("strict table");
    let compact = report
        .schema
        .tables
        .iter()
        .find(|table| table.name == "compact")
        .expect("without rowid table");
    assert!(strict.strict);
    assert_eq!(strict.strict_status, "known");
    assert_eq!(strict.definition_status, "available");
    assert_eq!(strict.source, "sqlite_schema.sql");
    assert!(compact.without_rowid);
    assert_eq!(compact.without_rowid_status, "known");
    assert_eq!(
        compact
            .primary_key_columns
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>(),
        vec!["id", "value"]
    );
    assert_eq!(compact.primary_key_columns[0].position, 1);
    assert_eq!(compact.primary_key_columns[1].position, 2);
}

#[test]
fn inventory_omits_table_sql_but_preserves_definition_provenance() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: None,
            row_limit: None,
        },
    )
    .expect("inventory");
    let users = report
        .schema
        .tables
        .iter()
        .find(|table| table.name == "users")
        .expect("users table");
    assert!(users.sql.is_none());
    assert_eq!(users.definition_status, "not_requested");
    assert_eq!(users.source, "sqlite_schema.sql");
}

#[test]
fn preserves_virtual_table_module_identity_without_executing_it() {
    let file = tempfile::NamedTempFile::new().expect("temp database");
    let connection = Connection::open(file.path()).expect("open database");
    connection
        .execute_batch("CREATE VIRTUAL TABLE docs USING fts5(content);")
        .expect("create virtual table");
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: Some("database".into()),
            row_limit: None,
        },
    )
    .expect("inspect");
    let docs = report
        .schema
        .tables
        .iter()
        .find(|table| table.name == "docs")
        .expect("virtual table");
    assert_eq!(docs.kind, "virtual");
    assert_eq!(docs.virtual_module.as_deref(), Some("fts5"));
    assert_eq!(docs.virtual_module_status, "declared");
    assert_eq!(docs.virtual_module_source, "sqlite_schema.sql");
    assert_eq!(docs.columns_completeness, "unsupported");
    assert_eq!(docs.column_count_status, "known");
    assert!(docs.columns.is_empty());
}

#[test]
fn does_not_fabricate_rowid_for_without_rowid_secondary_indexes() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: Some("database".into()),
            row_limit: None,
        },
    )
    .expect("inspect");
    let index = report
        .schema
        .indexes
        .iter()
        .find(|index| index.name == "compact_value")
        .expect("without rowid index");
    assert!(
        index
            .columns
            .iter()
            .all(|column| column.identity != "rowid")
    );
}

#[test]
fn links_triggers_to_mixed_case_targets() {
    let file = fixture();
    let inventory = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: None,
            row_limit: None,
        },
    )
    .expect("inventory");
    let trigger = inventory
        .schema
        .triggers
        .iter()
        .find(|trigger| trigger.name == "users_audit")
        .expect("trigger");
    assert_eq!(trigger.table, "users");
    assert_eq!(trigger.table_status, "declared");
    assert!(trigger.sql.is_none());
    assert_eq!(trigger.definition_status, "not_requested");
    assert_eq!(trigger.source, "sqlite_schema.sql");
    assert_eq!(trigger.timing, "unknown");
    assert_eq!(trigger.event, "unknown");
    let view = inventory
        .schema
        .views
        .iter()
        .find(|view| view.name == "user_names")
        .expect("view");
    assert!(view.sql.is_none());
    assert_eq!(view.definition_status, "not_requested");
    assert_eq!(view.source, "sqlite_schema.sql");
    assert_eq!(view.columns_completeness, "not_requested");
    assert_eq!(view.dependencies_status, "not_requested");
    let selected = sqlite::inspect(
        file.path(),
        &Input {
            table: Some("users".into()),
            columns: None,
            schema_scope: Some("selected_table".into()),
            row_limit: None,
        },
    )
    .expect("selected");
    assert_eq!(selected.schema.triggers.len(), 2);
    let insert_trigger = selected
        .schema
        .triggers
        .iter()
        .find(|trigger| trigger.name == "users_audit")
        .expect("insert trigger");
    assert_eq!(insert_trigger.table, "users");
    assert_eq!(insert_trigger.table_status, "declared");
    assert!(insert_trigger.sql.is_some());
    assert_eq!(insert_trigger.definition_status, "available");
    assert_eq!(insert_trigger.timing, "after");
    assert_eq!(insert_trigger.event, "insert");
    assert_eq!(insert_trigger.metadata_status, "complete");
    let update_trigger = selected
        .schema
        .triggers
        .iter()
        .find(|trigger| trigger.name == "users_update")
        .expect("update trigger");
    assert_eq!(update_trigger.timing, "after");
    assert_eq!(update_trigger.event, "update");

    let database = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: Some("database".into()),
            row_limit: None,
        },
    )
    .expect("database schema");
    let view = database
        .schema
        .views
        .iter()
        .find(|view| view.name == "user_names")
        .expect("view definition");
    assert_eq!(view.definition_status, "available");
    assert_eq!(view.source, "sqlite_schema.sql");
    assert_eq!(view.columns_completeness, "complete");
    assert_eq!(view.column_count, Some(1));
    assert_eq!(view.columns[0].name, "name");
    assert_eq!(view.dependencies, vec!["users"]);
    assert_eq!(view.dependencies_status, "complete");
    assert_eq!(view.dependencies_source, "sqlite_schema.sql");
}

#[test]
fn preserves_utf16_text_bytes_and_encoding() {
    for encoding in ["UTF-16le", "UTF-16be"] {
        let file = tempfile::NamedTempFile::new().expect("temp database");
        let connection = Connection::open(file.path()).expect("open database");
        connection.execute_batch(&format!("PRAGMA encoding='{encoding}'; CREATE TABLE words (value TEXT); INSERT INTO words VALUES ('héllo');")).expect("create encoded database");
        let report = sqlite::inspect(
            file.path(),
            &Input {
                table: Some("words".into()),
                columns: None,
                schema_scope: None,
                row_limit: Some(1),
            },
        )
        .expect("inspect");
        assert_eq!(report.database_encoding, encoding);
        let value = &report.rows.expect("rows").values[0][0];
        match value {
            sqlite::Value::Text {
                value,
                encoding: actual,
                bytes_hex,
            } => {
                assert_eq!(value, "héllo");
                assert_eq!(actual, encoding);
                assert!(!bytes_hex.is_empty());
            }
            other => panic!("expected text, got {other:?}"),
        }
    }
}

#[test]
fn rejects_row_projection_before_hex_expansion_budget() {
    let file = tempfile::NamedTempFile::new().expect("temp database");
    let connection = Connection::open(file.path()).expect("open database");
    connection
        .execute_batch("CREATE TABLE payload (value BLOB);")
        .expect("schema");
    let payload = vec![0x5a_u8; 9 * 1024 * 1024];
    connection
        .execute("INSERT INTO payload VALUES (?1)", [&payload])
        .expect("row");
    let error = sqlite::inspect(
        file.path(),
        &Input {
            table: Some("payload".into()),
            columns: None,
            schema_scope: None,
            row_limit: Some(1),
        },
    )
    .expect_err("output budget");
    assert!(error.to_string().contains("16 MiB"));
}

#[test]
fn rejects_oversized_schema_before_report_serialization() {
    let file = tempfile::NamedTempFile::new().expect("temp database");
    let connection = Connection::open(file.path()).expect("open database");
    let default_value = "x".repeat(17 * 1024 * 1024);
    let statement = format!("CREATE TABLE oversized (value TEXT DEFAULT '{default_value}')");
    connection.execute_batch(&statement).expect("schema");

    let error = sqlite::inspect(
        file.path(),
        &Input {
            table: Some("oversized".into()),
            columns: None,
            schema_scope: Some("selected_table".into()),
            row_limit: None,
        },
    )
    .expect_err("output budget");
    assert!(error.to_string().contains("16 MiB"));
}

#[test]
fn reports_schema_and_bounded_rows_without_writing_source() {
    let file = fixture();
    let before = std::fs::metadata(file.path()).expect("metadata").len();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: Some("users".into()),
            columns: Some(vec!["name".into(), "payload".into()]),
            schema_scope: Some("selected_table".into()),
            row_limit: Some(1),
        },
    )
    .expect("inspect");
    assert!(report.limitations.iter().any(|limitation| {
        limitation.contains("virtual-table column expansion is unsupported")
    }));
    assert_eq!(report.schema.tables[0].name, "users");
    let columns = &report.schema.tables[0].columns;
    assert_eq!(
        columns.iter().map(|column| column.cid).collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(columns[0].primary_key_position, 1);
    assert_eq!(columns[0].primary_key_status, "known");
    assert_eq!(columns[0].declared_type_status, "declared");
    assert_eq!(columns[0].not_null_status, "known");
    assert_eq!(columns[0].default_status, "absent");
    assert_eq!(columns[3].hidden, 3);
    assert_eq!(columns[3].hidden_role, "stored_generated");
    assert_eq!(columns[3].hidden_role_status, "known");
    assert_eq!(columns[3].source, "pragma_table_xinfo");
    assert_eq!(columns[3].metadata_status, "complete");
    assert_eq!(columns[4].hidden, 2);
    assert_eq!(columns[4].hidden_role, "virtual_generated");
    assert_eq!(report.schema.indexes[0].table, "users");
    assert_eq!(report.rows.as_ref().expect("rows").returned_rows, 1);
    assert_eq!(
        std::fs::metadata(file.path()).expect("metadata").len(),
        before
    );
}

#[test]
fn default_rows_include_generated_columns() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: Some("users".into()),
            columns: None,
            schema_scope: Some("selected_table".into()),
            row_limit: Some(1),
        },
    )
    .expect("inspect");

    let rows = report.rows.expect("rows");
    assert_eq!(
        rows.columns,
        vec!["id", "name", "payload", "name_len", "name_upper"]
    );
}

#[test]
fn explicit_selection_retains_generated_columns_as_visible() {
    let file = fixture();
    let report = sqlite::inspect(
        file.path(),
        &Input {
            table: Some("users".into()),
            columns: Some(vec!["name_len".into(), "name_upper".into()]),
            schema_scope: Some("selected_table".into()),
            row_limit: Some(1),
        },
    )
    .expect("generated columns are selectable");
    assert_eq!(
        report.rows.expect("rows").columns,
        ["name_len", "name_upper"]
    );
}

#[test]
fn rejects_missing_exact_table() {
    let file = fixture();
    let error = sqlite::inspect(
        file.path(),
        &Input {
            table: Some("Users".into()),
            columns: None,
            schema_scope: None,
            row_limit: None,
        },
    )
    .expect_err("missing table should fail");
    assert!(error.to_string().contains("exact name"));
}

#[test]
fn rejects_unknown_schema_scope() {
    let file = fixture();
    let error = sqlite::inspect(
        file.path(),
        &Input {
            table: None,
            columns: None,
            schema_scope: Some("everything".into()),
            row_limit: None,
        },
    )
    .expect_err("unknown schema scope should fail");
    assert!(
        error
            .to_string()
            .contains("Unsupported SQLite schema scope")
    );
}

#[test]
fn rejects_empty_column_selection() {
    let file = fixture();
    let error = sqlite::inspect(
        file.path(),
        &Input {
            table: Some("users".into()),
            columns: Some(Vec::new()),
            schema_scope: None,
            row_limit: None,
        },
    )
    .expect_err("empty columns should fail validation");
    assert!(
        error
            .to_string()
            .contains("columns must contain at least one selected column")
    );
}

#[test]
fn rejects_missing_exact_selected_column() {
    let file = fixture();
    let error = sqlite::inspect(
        file.path(),
        &Input {
            table: Some("users".into()),
            columns: Some(vec!["Name".into()]),
            schema_scope: Some("selected_table".into()),
            row_limit: Some(1),
        },
    )
    .expect_err("column matching must be exact");
    assert!(error.to_string().contains("exact name"));
}

#[test]
fn rejects_zero_row_limit_before_query_execution() {
    let file = fixture();
    let error = sqlite::inspect(
        file.path(),
        &Input {
            table: Some("users".into()),
            columns: None,
            schema_scope: Some("selected_table".into()),
            row_limit: Some(0),
        },
    )
    .expect_err("zero row limit should be rejected");
    assert!(error.to_string().contains("at least 1"));
}
