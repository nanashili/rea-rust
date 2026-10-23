//! SQLite inspection application boundary and Evidence projection.
use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion};
use rea_core::{
    evidence::{ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject},
    failure::{Detail, Failure},
    json_output,
};
use rea_host::fs::stable_file::{FileAccess, Snapshot};
use rea_rust_analysis::sqlite;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "inspect_sqlite_database";
const PROVIDER: Provider = Provider {
    id: "sqlite",
    name: "REA SQLite database inspector",
    version: None,
};

#[derive(Default)]
pub struct SqliteAnalyzer;

impl ArtifactAnalyzer for SqliteAnalyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = sqlite::MAX_INPUT_BYTES;

    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence_with_input(
            path,
            snapshot,
            sqlite::Input {
                table: None,
                columns: None,
                schema_scope: None,
                row_limit: None,
            },
            None,
        )
    }
}

pub struct SqliteInspection<F: FileAccess> {
    inner: ArtifactInspection<F, SqliteAnalyzer>,
    retained_roots: Arc<std::sync::Mutex<Vec<PathBuf>>>,
}
impl<F: FileAccess> SqliteInspection<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            inner: ArtifactInspection::new(access),
            retained_roots: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
    pub fn with_records(
        access: Arc<F>,
        records: Arc<crate::ledger::artifact_records::ArtifactRecords>,
    ) -> Self {
        Self {
            inner: ArtifactInspection::with_records(access, records),
            retained_roots: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
    pub fn inspect(
        &mut self,
        path: &str,
        cancellation: &rea_core::cancellation::Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect(path, cancellation, completion)
    }
    pub fn inspect_with_input(
        &mut self,
        path: &str,
        input: sqlite::Input,
        cancellation: &rea_core::cancellation::Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        let retained_roots = Arc::clone(&self.retained_roots);
        self.inner.inspect_with(
            path,
            sqlite::MAX_INPUT_BYTES,
            cancellation,
            completion,
            move |path, snapshot, cancellation| {
                if let Some(reason) = cancellation.reason() {
                    return Err(execution(path, format!("cancelled: {reason}")));
                }
                build_evidence_with_input(path, snapshot, input, Some(Arc::clone(&retained_roots)))
            },
        )
    }
    pub fn close(&mut self) -> Result<(), Failure> {
        let result = self.inner.close();
        let cleanup = self.retry_snapshot_cleanup();
        result.and(cleanup)
    }
    pub fn records(&self) -> &Arc<crate::ledger::artifact_records::ArtifactRecords> {
        self.inner.records()
    }

    fn retry_snapshot_cleanup(&self) -> Result<(), Failure> {
        let mut roots = self
            .retained_roots
            .lock()
            .map_err(|_| execution(OPERATION, "snapshot cleanup state is poisoned"))?;
        let mut failed = Vec::new();
        roots.retain(|root| {
            if fs::remove_dir_all(root).is_ok() {
                false
            } else {
                failed.push(root.display().to_string());
                true
            }
        });
        if failed.is_empty() {
            Ok(())
        } else {
            Err(execution(
                OPERATION,
                format!(
                    "SQLite snapshot cleanup remains incomplete: {}",
                    failed.join(", ")
                ),
            ))
        }
    }
}

fn build_evidence_with_input(
    path: &str,
    snapshot: Snapshot,
    input: sqlite::Input,
    retained_roots: Option<Arc<std::sync::Mutex<Vec<PathBuf>>>>,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    verify_inactive_journal(path)?;

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let root = std::env::temp_dir().join(format!("rea-sqlite-{suffix}"));
    fs::create_dir(&root).map_err(|e| execution(path, e.to_string()))?;
    let temporary = root.join("database.sqlite");
    if let Err(error) = fs::write(&temporary, &snapshot.bytes) {
        retain_root(&retained_roots, root);
        return Err(execution(path, error.to_string()));
    }
    let wal = match copy_stable_wal(path, &root, snapshot.bytes.len()) {
        Ok(wal) => wal,
        Err(error) => {
            retain_root(&retained_roots, root);
            return Err(error);
        }
    };

    // The source journal may become active while the database and WAL are
    // being copied. Re-check it before opening the private snapshot so the
    // parser cannot observe a database file set that became unsafe during
    // acquisition.
    if let Err(error) = verify_inactive_journal(path) {
        retain_root(&retained_roots, root);
        return Err(error);
    }

    let parsed = sqlite::inspect(&temporary, &input).map_err(|e| execution(path, e.to_string()));
    if let Err(error) = fs::remove_dir_all(&root) {
        if let Some(retained) = retained_roots {
            if let Ok(mut roots) = retained.lock() {
                roots.push(root);
            }
        }
        return Err(execution(
            path,
            format!("SQLite snapshot cleanup failed: {error}"),
        ));
    }
    let report = parsed?;
    let mut report = report;
    report.artifact.path = path.to_owned();
    report.artifact.sha256 = snapshot.sha256.clone();
    // The parser runs against the private snapshot copy. Rebind the optional
    // WAL identity to the caller-owned file so Evidence remains traceable to
    // the original file set rather than exposing a temporary path.
    report.wal = wal;
    let limitations = report.limitations.clone();
    let subject = Subject::new(path, snapshot.sha256, NativeFormat::Sqlite, None)
        .map_err(|e| execution(path, e.to_string()))?;
    let evidence = ArtifactEvidence::new(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            result: report,
            limitations,
            locations: vec![Location::ArtifactPath { path: path.into() }],
        },
    )
    .map_err(|e| execution(path, e.to_string()))?;
    if json_output::admitted_length(&evidence, sqlite::MAX_OUTPUT_BYTES).is_err() {
        return Err(execution(
            path,
            "Complete SQLite evidence exceeds the output budget.",
        ));
    }
    Ok(Arc::new(evidence))
}

fn verify_inactive_journal(path: &str) -> Result<(), Failure> {
    let journal = Path::new(&format!("{path}-journal")).to_path_buf();
    let metadata = match fs::symlink_metadata(&journal) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(execution(path, error.to_string())),
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(execution(
            path,
            format!(
                "SQLite rollback journal is not a regular file: {}",
                journal.display()
            ),
        ));
    }

    let first = read_journal_prefix(&journal, metadata.len())
        .map_err(|error| execution(path, error.to_string()))?;
    let second = read_journal_prefix(&journal, metadata.len())
        .map_err(|error| execution(path, error.to_string()))?;
    if first != second {
        return Err(execution(
            path,
            "SQLite rollback journal changed while acquiring the inspection snapshot.",
        ));
    }
    if metadata.len() != 0 && (first.len() != 28 || first.iter().any(|byte| *byte != 0)) {
        return Err(execution(
            path,
            format!(
                "SQLite rollback journal may require recovery: {}. Supply a clean offline snapshot; only empty journals or a fully zeroed header are supported.",
                journal.display()
            ),
        ));
    }
    Ok(())
}

fn read_journal_prefix(path: &Path, expected_size: u64) -> std::io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut prefix = Vec::with_capacity(28);
    file.by_ref().take(28).read_to_end(&mut prefix)?;
    if fs::metadata(path)?.len() != expected_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "SQLite rollback journal changed during inspection",
        ));
    }
    Ok(prefix)
}

fn retain_root(retained_roots: &Option<Arc<std::sync::Mutex<Vec<PathBuf>>>>, root: PathBuf) {
    if let Some(retained) = retained_roots {
        if let Ok(mut roots) = retained.lock() {
            roots.push(root);
        }
    }
}

fn copy_stable_wal(
    path: &str,
    root: &Path,
    primary_bytes: usize,
) -> Result<Option<sqlite::Artifact>, Failure> {
    let source = Path::new(&format!("{path}-wal")).to_path_buf();
    if !source.exists() {
        return Ok(None);
    }
    let first = fs::read(&source).map_err(|error| execution(path, error.to_string()))?;
    if primary_bytes.saturating_add(first.len()) > sqlite::MAX_INPUT_BYTES {
        return Err(execution(
            path,
            "SQLite database and WAL exceed the 256 MiB inspection limit.",
        ));
    }
    let target = root.join("database.sqlite-wal");
    fs::write(&target, &first).map_err(|error| execution(path, error.to_string()))?;
    let second = fs::read(&source).map_err(|error| execution(path, error.to_string()))?;
    if first != second {
        return Err(execution(
            path,
            "SQLite WAL changed while acquiring the inspection snapshot.",
        ));
    }
    Ok(Some(sqlite::Artifact {
        path: source.display().to_string(),
        sha256: format!("{:x}", Sha256::digest(&first)),
        bytes: first.len(),
    }))
}

fn execution(path: &str, reason: impl Into<String>) -> Failure {
    Failure::new(
        "execution_failure",
        "execution_failure",
        "Analysis could not complete.".into(),
        false,
        "Review the reported diagnostics and retry with a valid SQLite database.".into(),
        std::collections::BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("provider_id", Detail::Text(PROVIDER.id.into())),
            (
                "diagnostics",
                Detail::Fields(std::collections::BTreeMap::from([
                    ("path", Detail::Text(path.into())),
                    ("reason", Detail::Text(reason.into())),
                ])),
            ),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_host::fs::stable_file::Snapshot;
    use rusqlite::Connection;
    use serde_json::Value;

    #[test]
    fn rejects_active_rollback_journal_fixture() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("database.sqlite");
        fs::write(&database, b"SQLite format 3\0").expect("database fixture");
        let journal = Path::new(&format!("{}-journal", database.display())).to_path_buf();
        fs::write(&journal, [0xD9; 28]).expect("active journal fixture");

        let error =
            verify_inactive_journal(database.to_str().unwrap()).expect_err("active journal");
        let serialized = serde_json::to_value(error).expect("failure serialization");
        assert!(
            serialized["details"]["diagnostics"]["reason"]
                .as_str()
                .expect("diagnostic reason")
                .contains("may require recovery")
        );
    }

    fn fixture() -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temporary database");
        let connection = Connection::open(file.path()).expect("open database");
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON; \
                 CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, name_len INTEGER GENERATED ALWAYS AS (length(name)) STORED, name_upper TEXT GENERATED ALWAYS AS (upper(name)) VIRTUAL); \
                 CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id)) STRICT; \
                 CREATE TABLE compact (id INTEGER, value TEXT, PRIMARY KEY (id, value)) WITHOUT ROWID; \
                 CREATE UNIQUE INDEX users_name_unique ON users(name); \
                 CREATE INDEX users_active ON users(name) WHERE id > 0; \
                 CREATE VIEW user_names AS SELECT name FROM users; \
                 CREATE VIRTUAL TABLE docs USING fts5(content); \
                 CREATE TRIGGER users_audit AFTER INSERT ON USERS BEGIN SELECT 1; END; \
                 CREATE TRIGGER users_update AFTER UPDATE ON USERS BEGIN INSERT INTO users(name) VALUES ('audit'); END;",
            )
            .expect("create schema");
        file
    }

    fn inspect_fixture(file: &tempfile::NamedTempFile, input: sqlite::Input) -> Value {
        let bytes = fs::read(file.path()).expect("read fixture");
        let evidence = build_evidence_with_input(
            file.path().to_str().expect("fixture path"),
            Snapshot {
                bytes,
                sha256: "a".repeat(64),
            },
            input,
            None,
        )
        .expect("build SQLite Evidence");
        serde_json::to_value(&*evidence).expect("serialize Evidence")
    }

    #[test]
    fn evidence_preserves_index_predicates_and_related_schema_provenance() {
        let file = fixture();
        let value = inspect_fixture(
            &file,
            sqlite::Input {
                table: None,
                columns: None,
                schema_scope: Some("database".into()),
                row_limit: None,
            },
        );
        let result = &value["normalized_result"];
        let users = result["schema"]["tables"]
            .as_array()
            .expect("tables")
            .iter()
            .find(|table| table["name"] == "users")
            .expect("users table");
        assert_eq!(users["without_rowid"], false);
        assert_eq!(users["without_rowid_status"], "known");
        assert_eq!(users["strict"], false);
        assert_eq!(users["strict_status"], "known");
        assert_eq!(users["column_count_status"], "known");
        assert_eq!(users["definition_status"], "available");
        assert_eq!(users["source"], "sqlite_schema.sql");
        assert_eq!(users["columns"][0]["hidden"], 0);
        assert_eq!(users["columns"][0]["declared_type_status"], "declared");
        assert_eq!(users["columns"][0]["not_null_status"], "known");
        assert_eq!(users["columns"][0]["primary_key_status"], "known");
        assert_eq!(users["columns"][0]["default_status"], "absent");
        assert_eq!(users["columns"][2]["hidden"], 3);
        assert_eq!(users["columns"][2]["hidden_role"], "stored_generated");
        assert_eq!(users["columns"][3]["hidden"], 2);
        assert_eq!(users["columns"][3]["hidden_role"], "virtual_generated");

        let posts = result["schema"]["tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|table| table["name"] == "posts")
            .expect("strict table");
        assert_eq!(posts["strict"], true);
        assert_eq!(posts["strict_status"], "known");

        let compact = result["schema"]["tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|table| table["name"] == "compact")
            .expect("without rowid table");
        assert_eq!(compact["without_rowid"], true);
        assert_eq!(compact["without_rowid_status"], "known");
        assert_eq!(compact["strict"], false);
        assert_eq!(compact["strict_status"], "known");

        let active = result["schema"]["indexes"]
            .as_array()
            .expect("indexes")
            .iter()
            .find(|index| index["name"] == "users_active")
            .expect("partial index");
        assert_eq!(active["predicate_sql"], "id > 0");
        assert_eq!(active["predicate_status"], "present_unparsed");
        assert_eq!(active["predicate_source"], "sqlite_schema.sql");
        assert_eq!(active["columns"][0]["source"], "pragma_index_xinfo");

        let view = &result["schema"]["views"][0];
        assert_eq!(
            view["sql"],
            "CREATE VIEW user_names AS SELECT name FROM users"
        );
        assert_eq!(view["dependencies"], serde_json::json!(["users"]));
        assert_eq!(view["dependencies_status"], "complete");
        assert_eq!(view["dependencies_source"], "sqlite_schema.sql");

        let virtual_table = result["schema"]["tables"]
            .as_array()
            .expect("tables")
            .iter()
            .find(|table| table["name"] == "docs")
            .expect("virtual table");
        assert_eq!(virtual_table["kind"], "virtual");
        assert_eq!(virtual_table["classification_source"], "pragma_table_list");
        assert_eq!(virtual_table["columns_completeness"], "unsupported");
        assert!(virtual_table["columns"].as_array().unwrap().is_empty());
        assert_eq!(virtual_table["virtual_module"], "fts5");
        assert_eq!(virtual_table["virtual_module_status"], "declared");
        assert_eq!(virtual_table["virtual_module_source"], "sqlite_schema.sql");

        let trigger = &result["schema"]["triggers"][0];
        assert_eq!(trigger["table"], "users");
        assert_eq!(trigger["table_status"], "declared");
        assert_eq!(trigger["source"], "sqlite_schema.sql");
        assert_eq!(trigger["event"], "insert");

        let foreign_key = &result["schema"]["foreign_keys"][0];
        assert_eq!(foreign_key["source"], "pragma_foreign_key_list");
        assert_eq!(foreign_key["table"], "posts");
        assert_eq!(foreign_key["id"], 0);
        assert_eq!(foreign_key["seq"], 0);
        assert_eq!(foreign_key["column"], "user_id");
        assert_eq!(foreign_key["target_table"], "users");
        assert_eq!(foreign_key["target_table_status"], "declared");
        assert_eq!(foreign_key["target_column"], "id");
        assert_eq!(foreign_key["target_column_status"], "declared");
        assert_eq!(foreign_key["action_status"], "known");
        assert_eq!(foreign_key["match_status"], "known");

        assert_eq!(value["locations"][0]["kind"], "artifact-path");
        assert_eq!(
            value["subject"]["local_path"],
            file.path().to_str().unwrap()
        );
    }

    #[test]
    fn inventory_preserves_view_and_trigger_identity_without_sql_execution() {
        let file = fixture();
        let value = inspect_fixture(
            &file,
            sqlite::Input {
                table: None,
                columns: None,
                schema_scope: None,
                row_limit: None,
            },
        );
        let schema = &value["normalized_result"]["schema"];
        let table = schema["tables"]
            .as_array()
            .expect("tables")
            .iter()
            .find(|table| table["name"] == "users")
            .expect("users table");
        assert!(table["sql"].is_null());
        assert_eq!(table["definition_status"], "not_requested");
        assert_eq!(table["source"], "sqlite_schema.sql");
        let view = schema["views"]
            .as_array()
            .expect("views")
            .iter()
            .find(|view| view["name"] == "user_names")
            .expect("view");
        assert!(view["sql"].is_null());
        assert_eq!(view["definition_status"], "not_requested");
        assert_eq!(view["source"], "sqlite_schema.sql");
        assert_eq!(view["columns_completeness"], "not_requested");
        assert_eq!(view["dependencies_status"], "not_requested");

        let trigger = schema["triggers"]
            .as_array()
            .expect("triggers")
            .iter()
            .find(|trigger| trigger["name"] == "users_audit")
            .expect("trigger");
        assert!(trigger["sql"].is_null());
        assert_eq!(trigger["table"], "users");
        assert_eq!(trigger["definition_status"], "not_requested");
        assert_eq!(trigger["source"], "sqlite_schema.sql");
        assert_eq!(trigger["timing"], "unknown");
        assert_eq!(trigger["event"], "unknown");
    }

    #[test]
    fn selected_table_evidence_keeps_only_selected_dependents_and_exact_index_facts() {
        let file = fixture();
        let value = inspect_fixture(
            &file,
            sqlite::Input {
                table: Some("users".into()),
                columns: None,
                schema_scope: Some("selected_table".into()),
                row_limit: Some(1),
            },
        );
        let schema = &value["normalized_result"]["schema"];
        let indexes = schema["indexes"].as_array().expect("indexes");
        assert!(indexes.iter().all(|index| index["table"] == "users"));
        let active = indexes
            .iter()
            .find(|index| index["name"] == "users_active")
            .expect("selected partial index");
        assert_eq!(active["predicate_status"], "present_unparsed");
        assert_eq!(active["predicate_sql"], "id > 0");
        let triggers = schema["triggers"].as_array().expect("triggers");
        assert_eq!(triggers.len(), 2);
        let update_trigger = triggers
            .iter()
            .find(|trigger| trigger["name"] == "users_update")
            .expect("update trigger");
        assert_eq!(update_trigger["table"], "users");
        assert_eq!(update_trigger["event"], "update");
        assert!(schema["foreign_keys"].as_array().unwrap().is_empty());

        let users = schema["tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|table| table["name"] == "users")
            .expect("selected users table");
        assert_eq!(users["columns"][0]["hidden"], 0);
        assert_eq!(users["without_rowid"], false);
    }
}
