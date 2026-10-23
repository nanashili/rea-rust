//! `inspect_sqlite_database`: explicit, service-backed offline SQLite snapshot
//! inspection.
//!
//! Compatibility owners (TypeScript oracle):
//! - `src/server/registerSqliteTools.ts` (contract binding, `createEvidenceToolHandler`),
//! - `src/application/sqlite/SqliteDatabaseService.ts` (input refinements, output
//!   identity validation `matchesSelectedDatabase`, Evidence projection),
//! - `src/sqlite/SqliteDatabaseProvider.ts` + `SqliteDatabaseSnapshot.ts`
//!   (stable snapshot acquisition, WAL/journal checks, limits, failures),
//! - `src/sqlite/SqliteDatabaseInspection.ts` + `SqliteDatabaseWorker.ts` +
//!   `SqliteDatabaseWorkerExecution.ts` + `SqliteDatabaseLimits.ts` +
//!   `SqliteDatabaseFailures.ts` (the snapshot reading, the reply/limit
//!   contract and the exact failure mapping),
//! - `src/domain/sqlite/sqliteDatabase.ts` (the frozen `SqliteDatabase` shape,
//!   `sqliteInspectionParameters`, `sqliteSchemaScope`, `SQLITE_ROW_LIMIT_DEFAULT`).
//!
//! The snapshot reading is a direct rusqlite port of
//! `inspectSqliteDatabaseSnapshot` (see `sqlite::reader`): the exact same open
//! flags, run-time limits, PRAGMAs/queries in the same order, the same
//! schema/row projection and the same byte/row budgets. It runs against a
//! provider-owned private copy, never the caller's source database.
//!
//! Two isolation guarantees of the TypeScript provider are not reproduced here;
//! see the module tail (`// Isolation deviations`) for the precise statement and
//! the shared change that would restore them.
mod reader;

use crate::common::{HostFiles, host_files};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_host::fs::stable_file::{self, IoKind, ReadFailure, ReadIssue, Snapshot};
use rea_mcp::{Registry, SessionResource, ToolContext};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reader::{FailureReason, OUTPUT_BYTES, ROW_LIMIT_DEFAULT as READER_ROW_LIMIT_DEFAULT};

const OPERATION: &str = "inspect_sqlite_database";
/// `SQLITE_PROVIDER_IDENTITY` (`src/domain/sqlite/sqliteDatabase.ts`).
const PROVIDER_ID: &str = "sqlite";
const PROVIDER_NAME: &str = "REA SQLite database inspector";
/// `SQLITE_ROW_LIMIT_DEFAULT` (`src/domain/sqlite/sqliteDatabase.ts`).
const ROW_LIMIT_DEFAULT: u64 = READER_ROW_LIMIT_DEFAULT as u64;
/// `SQLITE_DATABASE_LIMITS` (`src/sqlite/SqliteDatabaseLimits.ts`).
const CONCURRENT_INSPECTIONS: usize = 2;
const INPUT_BYTES: usize = 256 * 1024 * 1024;
/// `SQLITE_DATABASE_LIMITS.timeoutMs`: the supervised 30 s deadline.
const TIMEOUT: Duration = Duration::from_millis(30_000);
/// `javascript_heap_bytes` surfaced by the memory resource constraint.
const JAVASCRIPT_HEAP_BYTES: usize = 256 * 1024 * 1024;

/// The frozen `limitations` text (`SqliteDatabaseInspection.ts`). These are the
/// provider's complete offline-snapshot limitations, authored once here and
/// appended to by the reader for virtual/shadow-table findings.
const LIMITATIONS: &[&str] = &[
    "Inspects an offline stable file set. Filesystem identity checks detect observed acquisition changes; they do not establish an atomic snapshot of an actively changing database. Supply an application-created backup or quiescent database/WAL pair.",
    "The source database and WAL are never opened by SQLite or modified. A private copy may acquire its own WAL-index sidecar and is removed after inspection.",
    "SQLite reports current schema and selected committed rows from its valid database/WAL state. Deleted records, uncommitted or invalid WAL tails, encrypted databases, forensic recovery, and full integrity verification are outside this profile.",
    "Stored CREATE statements preserve index/view/trigger definitions. Views, triggers, and virtual/shadow table rows are not executed; virtual-table column expansion is unsupported.",
    "Selected rows have unspecified order and are a bounded sample. Text display may replace invalid sequences; bytes_hex and encoding preserve SQLite's text byte representation, not original on-disk page offsets.",
    "Resource boundaries: at most two concurrent inspections per provider; combined input 256 MiB per inspection, complete worker JSON 16 MiB, native SQLite value/record and SQL statement lengths 16 MiB, owned-worker JavaScript heap 256 MiB and supervised deadline 30 seconds. These are distinct from total resident memory; an overall native SQLite heap cap is not claimed. Failures return no partial success.",
];

/// `sqliteSchemaScope` result: one owner interprets the omitted scope.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Inventory,
    SelectedTable,
    Database,
}

impl Scope {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::SelectedTable => "selected_table",
            Self::Database => "database",
        }
    }
}

/// Caller-selected options, mirroring `inspectSqliteDatabaseInputSchema`.
pub(crate) struct Selection {
    path: String,
    pub(crate) table: Option<String>,
    pub(crate) columns: Option<Vec<String>>,
    schema_scope: Option<String>,
    pub(crate) row_limit: Option<i64>,
}

impl Selection {
    /// `sqliteSchemaScope(input)`.
    pub(crate) fn scope(&self) -> Scope {
        match self.schema_scope.as_deref() {
            Some("selected_table") => Scope::SelectedTable,
            Some("database") => Scope::Database,
            Some(_) => Scope::Inventory,
            None if self.table.is_some() => Scope::SelectedTable,
            None => Scope::Inventory,
        }
    }
}

/// The reader's `Inspection` (`inspectSqliteDatabaseSnapshot` return): exactly
/// the `engine`/`database_encoding`/`schema`/`rows`/`limitations` fields, as
/// already-projected frozen JSON. The artifact/WAL identity is bound by the
/// provider layer.
pub(crate) struct Inspection {
    engine_version: String,
    database_encoding: String,
    schema: Value,
    rows: Value,
    limitations: Vec<String>,
}

/// Per-session inspection owner (`SqliteDatabaseService`/`SqliteDatabaseProvider`).
///
/// It bounds concurrency to the provider limit and retains snapshot roots whose
/// cleanup failed, so they can be retried at session shutdown. It is created on
/// first use and registered as a `SessionResource` via `own_once`.
#[derive(Default)]
pub(crate) struct SqliteSession {
    inner: Mutex<SqliteState>,
}

#[derive(Default)]
struct SqliteState {
    /// Inspections admitted but not yet completed (`#active`).
    active: usize,
    /// Private snapshot roots whose directory removal failed (`#pendingCleanup`).
    retained_roots: Vec<PathBuf>,
}

impl SessionResource for SqliteSession {
    /// `SqliteDatabaseProvider.close`: retry retained snapshot-root cleanup,
    /// keeping ownership of any root that still cannot be removed.
    fn close(&self) -> Result<(), AnalysisError> {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        retry_retained_roots(&mut state.retained_roots)
    }
}

/// Retry removing retained snapshot roots; return the still-failing ones.
fn retry_retained_roots(retained: &mut Vec<PathBuf>) -> Result<(), AnalysisError> {
    let mut failed = Vec::new();
    retained.retain(|root| {
        if std::fs::remove_dir_all(root).is_ok() {
            false
        } else {
            failed.push(root.display().to_string());
            true
        }
    });
    if failed.is_empty() {
        Ok(())
    } else {
        Err(AnalysisError::capability_unavailable(
            PROVIDER_ID,
            OPERATION,
            format!(
                "SQLite snapshot cleanup remains incomplete: {}",
                failed.join(", ")
            ),
        ))
    }
}

/// `registerSqliteTools`: bind the single contract tool.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle(OPERATION, |context: &ToolContext<'_>, input: Value| {
        inspect(context, input).into()
    });
}

/// `createEvidenceToolHandler` flow for this service tool: fail fast on a
/// pre-admission cancellation, then run the service operation.
fn inspect(context: &ToolContext<'_>, input: Value) -> Result<Evidence, AnalysisError> {
    // `SqliteDatabaseService.inspect`: a pre-cancelled request never reads a database.
    context.check_cancelled()?;
    let selection = parse_input(&input)?;
    let session = context.session.state::<SqliteSession>();
    context.session.own_once(Arc::clone(&session));
    // Admission capacity (`#active.size >= concurrentInspections`).
    {
        let mut state = session.inner.lock().unwrap_or_else(|e| e.into_inner());
        if state.active >= CONCURRENT_INSPECTIONS {
            return Err(capacity_failure(state.active));
        }
        state.active += 1;
    }
    context.progress.report(OPERATION, "started");
    let outcome = run_inspection(context, &session, &selection);
    {
        let mut state = session.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.active = state.active.saturating_sub(1);
    }
    context.progress.report(
        OPERATION,
        if outcome.is_ok() {
            "completed"
        } else {
            "failed"
        },
    );
    outcome
}

/// `AnalysisResourceConstraintError(operation, "capacity", ...)`.
fn capacity_failure(active: usize) -> AnalysisError {
    AnalysisError::resource_constraint(
        OPERATION,
        "capacity",
        "SQLite inspection capacity is occupied. Retry after an active inspection completes.",
        Some(json!({
            "active_inspections": active,
            "max_concurrent_inspections": CONCURRENT_INSPECTIONS,
            "input_bytes_per_inspection": INPUT_BYTES,
        })),
    )
    .with_remediation("Retry after an active SQLite inspection completes.")
}

/// Minimal artifact identity (`artifactSchema`): `path`, `sha256`, `bytes`.
struct Artifact {
    path: String,
    sha256: String,
    bytes: usize,
}

/// Acquire the stable snapshot, run the real read, project and validate it, and
/// build Evidence. Cleanup of the private root is retained for retry on failure.
fn run_inspection(
    context: &ToolContext<'_>,
    session: &SqliteSession,
    selection: &Selection,
) -> Result<Evidence, AnalysisError> {
    context.check_cancelled()?;
    let access = host_files();
    let source = Path::new(&selection.path);
    // Freeze the caller-owned database and sibling WAL into a private root
    // (`captureSqliteDatabaseSnapshot`). The source is never opened by SQLite.
    verify_inactive_journal(&selection.path)?;
    let database = read_stable(&access, source, INPUT_BYTES, &context.cancellation)?;
    let wal = read_wal(
        &access,
        selection,
        database.bytes.len(),
        &context.cancellation,
    )?;
    let root = create_private_root()?;
    let snapshot_copy = root.join("database.snapshot");
    if let Err(error) = std::fs::write(&snapshot_copy, &database.bytes) {
        retain_root(session, root);
        return Err(provider_adapter(&selection.path, error.to_string()));
    }
    if let Some(wal) = &wal {
        if let Err(error) = std::fs::write(root.join("database.snapshot-wal"), &wal.bytes) {
            retain_root(session, root);
            return Err(provider_adapter(&selection.path, error.to_string()));
        }
    }
    // The source journal may become active while the database and WAL are
    // copied; re-check it before the private snapshot is opened.
    if let Err(error) = verify_inactive_journal(&selection.path) {
        retain_root(session, root);
        return Err(error);
    }
    if let Err(error) = context.check_cancelled() {
        retain_root(session, root);
        return Err(error);
    }

    // Run the bounded snapshot read in-process under the supervised deadline and
    // cancellation (the interrupt handle bounds a long query).
    let read = run_snapshot_read(context, &snapshot_copy, selection);

    // Always attempt to remove the private root; retain it for retry if removal
    // fails, exactly as the provider retains failed snapshot-root cleanup.
    if let Err(error) = std::fs::remove_dir_all(&root) {
        retain_root(session, root);
        return Err(cleanup_failure(&selection.path, error.to_string()));
    }
    let inspection = read?;

    // Bind identity to the caller-owned file set and assemble the frozen report.
    let wal_artifact = wal.as_ref().map(|wal| Artifact {
        path: format!("{}-wal", selection.path),
        sha256: wal.sha256.clone(),
        bytes: wal.bytes.len(),
    });
    let database_artifact = Artifact {
        path: selection.path.clone(),
        sha256: database.sha256.clone(),
        bytes: database.bytes.len(),
    };
    let normalized = assemble_report(&inspection, &database_artifact, wal_artifact.as_ref());

    // `matchesSelectedDatabase`: the observed report must keep the selected
    // database/WAL identity, table and row-limit before Evidence is created.
    verify_selected_database(&normalized, selection)?;

    // Enforce the 16 MiB complete-evidence budget (`OutputBudget`/worker reply).
    let encoded = serde_json::to_vec(&normalized)
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
    if encoded.len() > OUTPUT_BYTES {
        return Err(output_limit_constraint(
            "Complete SQLite evidence exceeds the 16 MiB JSON reply budget; no partial success was returned.",
        ));
    }
    build_evidence(
        &normalized,
        selection,
        &inspection.engine_version,
        wal_artifact.as_ref(),
    )
}

/// Run the reader in-process, bounding it with a watchdog thread that fires the
/// connection's interrupt handle when the 30 s deadline passes or cancellation
/// is observed. On interruption the reader's query returns a SQLite error,
/// which is reclassified as the exact cancellation/timeout failure.
fn run_snapshot_read(
    context: &ToolContext<'_>,
    snapshot_copy: &Path,
    selection: &Selection,
) -> Result<Inspection, AnalysisError> {
    let interrupted_for_cancellation = Arc::new(AtomicBool::new(false));
    let interrupted_for_timeout = Arc::new(AtomicBool::new(false));
    let handle_slot: Arc<Mutex<Option<rusqlite::InterruptHandle>>> = Arc::new(Mutex::new(None));
    let stop = Arc::new(AtomicBool::new(false));

    // The watchdog owns clones of the shared flags and the cancellation token.
    let watchdog = {
        let cancellation = context.cancellation.clone();
        let handle_slot = Arc::clone(&handle_slot);
        let stop = Arc::clone(&stop);
        let for_cancel = Arc::clone(&interrupted_for_cancellation);
        let for_timeout = Arc::clone(&interrupted_for_timeout);
        std::thread::spawn(move || {
            let deadline = Instant::now() + TIMEOUT;
            loop {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let now = Instant::now();
                if cancellation.reason().is_some() {
                    for_cancel.store(true, Ordering::SeqCst);
                    if let Some(handle) = handle_slot
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .as_ref()
                    {
                        handle.interrupt();
                    }
                    return;
                }
                if now >= deadline {
                    for_timeout.store(true, Ordering::SeqCst);
                    if let Some(handle) = handle_slot
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .as_ref()
                    {
                        handle.interrupt();
                    }
                    return;
                }
                std::thread::sleep(
                    Duration::from_millis(25).min(deadline.saturating_duration_since(now)),
                );
            }
        })
    };

    let limitations: Vec<String> = LIMITATIONS.iter().map(|text| (*text).to_owned()).collect();
    let result = reader::inspect_snapshot(snapshot_copy, selection, limitations, |handle| {
        *handle_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
    });
    stop.store(true, Ordering::SeqCst);
    let _ = watchdog.join();

    match result {
        Ok(inspection) => Ok(inspection),
        Err(failure) => {
            if interrupted_for_cancellation.load(Ordering::SeqCst) {
                Err(AnalysisError::cancelled(OPERATION))
            } else if interrupted_for_timeout.load(Ordering::SeqCst) {
                Err(timeout_failure())
            } else {
                Err(map_reader_failure(&selection.path, &failure))
            }
        }
    }
}

/// `sqlite::Input` for the reader, from the caller selection.
// (The reader reads the `Selection` directly; no separate input struct.)

/// Assemble the frozen `SqliteDatabase` object from the reader's inspection and
/// the caller-owned artifact/WAL identity (`sqliteDatabaseSchema` shape).
fn assemble_report(inspection: &Inspection, database: &Artifact, wal: Option<&Artifact>) -> Value {
    let artifact = json!({
        "path": database.path,
        "sha256": database.sha256,
        "bytes": database.bytes,
    });
    let wal_value = match wal {
        None => Value::Null,
        Some(wal) => json!({ "path": wal.path, "sha256": wal.sha256, "bytes": wal.bytes }),
    };
    json!({
        "artifact": artifact,
        "wal": wal_value,
        "engine": { "name": "SQLite", "version": inspection.engine_version },
        "database_encoding": inspection.database_encoding,
        "schema": inspection.schema,
        "rows": inspection.rows,
        "limitations": inspection.limitations,
    })
}

// ---------------------------------------------------------------------------
// Input parsing (`inspectSqliteDatabaseInputSchema` superRefine + isAbsolute).
//
// The framework already validated the frozen inputSchema (including the
// `if/then` that requires `table` when `schema_scope` is `selected_table`) and
// applied declared defaults. The refinements the frozen JSON Schema cannot
// express are re-checked here with the exact TS InputIssue path/reason/message:
//   - `row_limit requires an explicit table selection`,
//   - `columns requires an explicit table selection`,
//   - `isAbsolute(path)` on this host.
// ---------------------------------------------------------------------------
fn parse_input(input: &Value) -> Result<Selection, AnalysisError> {
    let object = input
        .as_object()
        .ok_or_else(|| AnalysisError::input(OPERATION, vec![]))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let table = object
        .get("table")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let columns = object
        .get("columns")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        });
    let schema_scope = object
        .get("schema_scope")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let row_limit = object.get("row_limit").and_then(Value::as_i64);
    let mut issues = Vec::new();
    if row_limit.is_some() && table.is_none() {
        issues.push(InputIssue::new(
            &["row_limit"],
            "custom",
            "row_limit requires an explicit table selection",
        ));
    }
    if columns.is_some() && table.is_none() {
        issues.push(InputIssue::new(
            &["columns"],
            "custom",
            "columns requires an explicit table selection",
        ));
    }
    if schema_scope.as_deref() == Some("selected_table") && table.is_none() {
        issues.push(InputIssue::new(
            &["schema_scope"],
            "custom",
            "selected_table schema scope requires table",
        ));
    }
    if !issues.is_empty() {
        return Err(AnalysisError::input(OPERATION, issues));
    }
    if !Path::new(&path).is_absolute() {
        return Err(AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["path"],
                "invalid_format",
                "Expected an absolute filesystem path on this host.",
            )],
        ));
    }
    Ok(Selection {
        path,
        table,
        columns,
        schema_scope,
        row_limit,
    })
}

// ---------------------------------------------------------------------------
// Stable snapshot acquisition (`SqliteDatabaseSnapshot.ts`).
// ---------------------------------------------------------------------------

/// Read a caller-owned file into a stable snapshot, mapping host failures to
/// the provider's error meanings (`sqliteDatabaseFailure`, `missingDatabase`).
fn read_stable(
    access: &Arc<HostFiles>,
    path: &Path,
    maximum: usize,
    cancellation: &Cancellation,
) -> Result<Snapshot, AnalysisError> {
    match stable_file::read(Arc::clone(access), path, maximum, cancellation) {
        Ok(snapshot) => Ok(snapshot),
        Err(failure) => Err(map_read_failure(path, *failure)),
    }
}

/// Read the sibling WAL if present, honoring the combined input budget.
fn read_wal(
    access: &Arc<HostFiles>,
    selection: &Selection,
    primary_bytes: usize,
    cancellation: &Cancellation,
) -> Result<Option<Snapshot>, AnalysisError> {
    let wal_path_string = format!("{}-wal", selection.path);
    let wal_path = Path::new(&wal_path_string);
    match access_exists(access, wal_path) {
        Ok(false) => return Ok(None),
        Ok(true) => {}
        Err(error) => return Err(error),
    }
    let remaining = INPUT_BYTES.saturating_sub(primary_bytes);
    let snapshot = read_stable(access, wal_path, remaining, cancellation)?;
    if primary_bytes.saturating_add(snapshot.bytes.len()) > INPUT_BYTES {
        return Err(file_size_failure(
            &selection.path,
            primary_bytes,
            snapshot.bytes.len(),
        ));
    }
    Ok(Some(snapshot))
}

/// Whether a path resolves to an existing entry (`optionalStat`). A missing
/// sidecar reports `false`.
fn access_exists(access: &Arc<HostFiles>, path: &Path) -> Result<bool, AnalysisError> {
    use rea_host::fs::stable_file::FileAccess;
    match access.lstat(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind == IoKind::NotFound => Ok(false),
        Err(error) => Err(map_file_error(path, error)),
    }
}

/// `AnalysisResourceConstraintError(operation, "file-size", ...)`.
fn file_size_failure(path: &str, primary: usize, wal: usize) -> AnalysisError {
    let total = primary.saturating_add(wal);
    AnalysisError::resource_constraint(
        OPERATION,
        "file-size",
        format!(
            "Selected SQLite database and WAL total {total} bytes, exceeding the combined {INPUT_BYTES}-byte offline snapshot budget: {path}"
        ),
        Some(json!({
            "sqlite_snapshot_input_bytes": INPUT_BYTES,
            "observed_sqlite_snapshot_input_bytes": total.to_string(),
        })),
    )
    .with_remediation(
        "Use the application's supported export workflow to create a consistent, smaller offline SQLite snapshot containing only the relevant data, then inspect that snapshot. REA will not truncate or modify the selected source.",
    )
}

/// `verifyInactiveJournal`: only an empty journal or a fully zeroed 28-byte
/// header is accepted; the file set must not change while it is observed.
fn verify_inactive_journal(path: &str) -> Result<(), AnalysisError> {
    use std::io::Read;
    let journal_string = format!("{path}-journal");
    let journal = Path::new(&journal_string);
    let metadata = match std::fs::symlink_metadata(journal) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(provider_adapter(path, error.to_string())),
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["path"],
                "invalid_format",
                format!("Expected a regular journal without a symlink: {journal_string}"),
            )],
        ));
    }
    let read_prefix = |expected: u64| -> std::io::Result<Vec<u8>> {
        let mut file = std::fs::File::open(journal)?;
        let mut prefix = Vec::with_capacity(28);
        file.by_ref().take(28).read_to_end(&mut prefix)?;
        if std::fs::metadata(journal)?.len() != expected {
            return Err(std::io::Error::other(
                "SQLite rollback journal changed during inspection",
            ));
        }
        Ok(prefix)
    };
    let first = read_prefix(metadata.len())
        .map_err(|error| AnalysisError::artifact_changed(OPERATION, path, error.to_string()))?;
    let second = read_prefix(metadata.len())
        .map_err(|error| AnalysisError::artifact_changed(OPERATION, path, error.to_string()))?;
    if first != second {
        return Err(AnalysisError::artifact_changed(
            OPERATION,
            path,
            format!("SQLite rollback journal changed during inspection: {journal_string}"),
        ));
    }
    if metadata.len() != 0 && (first.len() != 28 || first.iter().any(|byte| *byte != 0)) {
        return Err(AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["path"],
                "invalid_format",
                format!(
                    "Rollback journal may require recovery: {journal_string}. Supply a clean offline snapshot; only empty journals or a fully zeroed header are supported."
                ),
            )],
        ));
    }
    Ok(())
}

/// Create a fresh private snapshot root (`PrivateRuntimeRoot.create`).
fn create_private_root() -> Result<PathBuf, AnalysisError> {
    tempfile::Builder::new()
        .prefix("rea-sqlite-database-")
        .tempdir()
        .map(tempfile::TempDir::keep)
        .map_err(|error| provider_adapter(OPERATION, error.to_string()))
}

/// Retain a snapshot root whose removal failed for shutdown retry.
fn retain_root(session: &SqliteSession, root: PathBuf) {
    let mut state = session.inner.lock().unwrap_or_else(|e| e.into_inner());
    state.retained_roots.push(root);
}

// ---------------------------------------------------------------------------
// Output identity validation (`matchesSelectedDatabase`).
// ---------------------------------------------------------------------------
fn verify_selected_database(
    normalized: &Value,
    selection: &Selection,
) -> Result<(), AnalysisError> {
    if matches_selected_database(normalized, selection) {
        Ok(())
    } else {
        Err(AnalysisError::output(
            OPERATION,
            "SQLite adapter returned malformed data or changed the selected database identity/table/row limit.",
        ))
    }
}

fn matches_selected_database(report: &Value, selection: &Selection) -> bool {
    let path = selection.path.as_str();
    let artifact = &report["artifact"];
    if artifact["path"].as_str() != Some(path) {
        return false;
    }
    match report["wal"].as_null() {
        Some(()) => {}
        None => {
            if report["wal"]["path"].as_str() != Some(&format!("{path}-wal")) {
                return false;
            }
        }
    }
    let expected_scope = selection.scope().label();
    if report["schema"]["scope"].as_str() != Some(expected_scope) {
        return false;
    }
    if expected_scope == "selected_table" {
        let tables = report["schema"]["tables"].as_array();
        let selected = selection.table.as_deref();
        let single = tables
            .is_some_and(|tables| tables.len() == 1 && tables[0]["name"].as_str() == selected);
        let indexes_ok = report["schema"]["indexes"]
            .as_array()
            .is_some_and(|items| items.iter().all(|item| item["table"].as_str() == selected));
        let triggers_ok = report["schema"]["triggers"]
            .as_array()
            .is_some_and(|items| items.iter().all(|item| item["table"].as_str() == selected));
        let no_views = report["schema"]["views"]
            .as_array()
            .is_some_and(|items| items.is_empty());
        if !(single && indexes_ok && triggers_ok && no_views) {
            return false;
        }
    }
    match &selection.table {
        None => report["rows"].is_null(),
        Some(table) => {
            let rows = &report["rows"];
            if rows["table"].as_str() != Some(table.as_str()) {
                return false;
            }
            let expected_limit = selection
                .row_limit
                .map(|limit| limit as u64)
                .unwrap_or(ROW_LIMIT_DEFAULT);
            if rows["row_limit"].as_u64() != Some(expected_limit) {
                return false;
            }
            match &selection.columns {
                None => true,
                Some(columns) => rows["columns"].as_array().is_some_and(|row_columns| {
                    row_columns.len() == columns.len()
                        && row_columns
                            .iter()
                            .zip(columns)
                            .all(|(name, expected)| name.as_str() == Some(expected.as_str()))
                }),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence (`createEvidence` through the service projection).
// ---------------------------------------------------------------------------
fn build_evidence(
    normalized: &Value,
    selection: &Selection,
    sqlite_version: &str,
    wal: Option<&Artifact>,
) -> Result<Evidence, AnalysisError> {
    let sha256 = normalized["artifact"]["sha256"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let subject = SubjectTarget {
        path: selection.path.clone(),
        sha256,
        format: "file".into(),
        architecture: None,
    };
    let provider = EvidenceProvider::new(
        PROVIDER_ID,
        PROVIDER_NAME,
        Some(format!("SQLite {sqlite_version}")),
    );
    let mut locations = vec![json!({ "kind": "artifact-path", "path": selection.path })];
    if let Some(wal) = wal {
        locations.push(json!({ "kind": "artifact-path", "path": wal.path }));
    }
    let limitations = normalized["limitations"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let observation = Observation::new(
        OPERATION,
        inspection_parameters(selection),
        normalized.clone(),
    )
    .confidence("observed")
    .limitations(limitations)
    .locations(locations);
    Evidence::create(Some(&subject), &provider, observation)
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))
}

/// `sqliteInspectionParameters`: preserve explicit caller selections, omitting
/// absent optional values from the parameters object.
fn inspection_parameters(selection: &Selection) -> Value {
    let mut parameters = Map::new();
    parameters.insert("path".into(), Value::String(selection.path.clone()));
    if let Some(table) = &selection.table {
        parameters.insert("table".into(), Value::String(table.clone()));
    }
    if let Some(columns) = &selection.columns {
        parameters.insert(
            "columns".into(),
            Value::Array(columns.iter().cloned().map(Value::String).collect()),
        );
    }
    if let Some(scope) = &selection.schema_scope {
        parameters.insert("schema_scope".into(), Value::String(scope.clone()));
    }
    if let Some(row_limit) = selection.row_limit {
        parameters.insert("row_limit".into(), json!(row_limit));
    }
    Value::Object(parameters)
}

// ---------------------------------------------------------------------------
// Failure mapping (`SqliteDatabaseFailures.ts`, `SqliteDatabaseWorkerExecution.ts`).
// ---------------------------------------------------------------------------

/// Map a `stable_file` read failure to the provider's error meaning.
fn map_read_failure(path: &Path, failure: ReadFailure<HostFiles>) -> AnalysisError {
    let display = path.display().to_string();
    match failure.primary {
        Some(ReadIssue::Cancelled(_)) => AnalysisError::cancelled(OPERATION),
        Some(ReadIssue::InvalidPath) => missing_database(&display),
        Some(ReadIssue::Limit { maximum_bytes }) => AnalysisError::resource_constraint(
            OPERATION,
            "file-size",
            format!(
                "Selected SQLite database exceeds the combined {maximum_bytes}-byte offline snapshot budget: {display}"
            ),
            Some(json!({ "sqlite_snapshot_input_bytes": INPUT_BYTES })),
        ),
        Some(ReadIssue::Changed(stage)) => AnalysisError::artifact_changed(
            OPERATION,
            &display,
            format!("SQLite snapshot file set changed during acquisition ({stage}): {display}"),
        ),
        Some(ReadIssue::Allocation { requested_bytes }) => AnalysisError::resource_constraint(
            OPERATION,
            "memory",
            format!(
                "Could not allocate {requested_bytes} bytes to read the SQLite snapshot: {display}"
            ),
            None,
        ),
        Some(ReadIssue::Io { stage, error }) => map_io_issue(&display, stage, error),
        Some(ReadIssue::InvalidRead) | None => {
            AnalysisError::artifact_changed(OPERATION, &display, "SQLite snapshot read was invalid")
        }
    }
}

/// `missingDatabase`: absence is a caller value to correct.
fn missing_database(path: &str) -> AnalysisError {
    AnalysisError::input(
        OPERATION,
        vec![InputIssue::new(
            &["path"],
            "invalid_value",
            format!("Selected SQLite database does not exist: {path}"),
        )],
    )
}

fn map_io_issue(path: &str, _stage: &str, error: stable_file::FileError) -> AnalysisError {
    map_file_error(Path::new(path), error)
}

/// Map a normalized host `FileError` to the provider's filesystem meanings.
fn map_file_error(path: &Path, error: stable_file::FileError) -> AnalysisError {
    let display = path.display().to_string();
    match error.kind {
        IoKind::NotFound | IoKind::NotDirectory | IoKind::SymlinkLoop | IoKind::NameTooLong => {
            AnalysisError::input(
                OPERATION,
                vec![InputIssue::new(
                    &["path"],
                    "invalid_value",
                    format!(
                        "Selected database file set could not be read ({}): {display}",
                        error.system_code.unwrap_or("io")
                    ),
                )],
            )
        }
        IoKind::AccessDenied => {
            AnalysisError::access_denied(OPERATION, &display, error.system_code.unwrap_or("EACCES"))
        }
        IoKind::Interrupted | IoKind::Other => provider_adapter(&display, error.to_string()),
    }
}

/// Map a reader failure to the provider's error algebra, exactly as
/// `rejectedReply` (`SqliteDatabaseWorkerExecution.ts`) maps the bounded worker
/// reply's `reason`:
///   - `unavailable` -> `AnalysisCapabilityUnavailableError("sqlite", ...)`,
///   - `memory` -> resource constraint `"memory"` with the JS-heap byte fact,
///   - `output-limit` -> resource constraint `"transport"` with the value/
///     record and reply byte facts,
///   - `format`/`unsupported` -> input issue on `path`,
///   - `selection` -> input issue on `table`,
///   - `column-selection` -> input issue on `columns`.
fn map_reader_failure(path: &str, failure: &reader::Failure) -> AnalysisError {
    let _ = path;
    match failure.reason {
        FailureReason::Unavailable => {
            AnalysisError::capability_unavailable(PROVIDER_ID, OPERATION, failure.message.clone())
        }
        FailureReason::Memory => AnalysisError::resource_constraint(
            OPERATION,
            "memory",
            failure.message.clone(),
            Some(json!({ "javascript_heap_bytes": JAVASCRIPT_HEAP_BYTES })),
        ),
        FailureReason::OutputLimit => output_limit_constraint(&failure.message),
        FailureReason::Format | FailureReason::Unsupported => AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["path"],
                "invalid_format",
                failure.message.clone(),
            )],
        ),
        FailureReason::Selection => AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["table"],
                "invalid_format",
                failure.message.clone(),
            )],
        ),
        FailureReason::ColumnSelection => AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["columns"],
                "invalid_format",
                failure.message.clone(),
            )],
        ),
    }
}

/// `output-limit` -> `AnalysisResourceConstraintError(operation, "transport", ...)`.
fn output_limit_constraint(message: &str) -> AnalysisError {
    AnalysisError::resource_constraint(
        OPERATION,
        "transport",
        message,
        Some(json!({
            "sqlite_value_or_record_bytes": OUTPUT_BYTES,
            "worker_reply_bytes": OUTPUT_BYTES,
        })),
    )
}

/// `timeout` -> `AnalysisTimeoutError(operation, timeoutMs, ...)`.
fn timeout_failure() -> AnalysisError {
    AnalysisError::resource_constraint(
        OPERATION,
        "timeout",
        format!(
            "SQLite inspection exceeded the supervised {}-second deadline.",
            TIMEOUT.as_secs()
        ),
        Some(json!({ "sqlite_inspection_timeout_ms": TIMEOUT.as_millis() as u64 })),
    )
}

/// `ProviderAdapterError` for the SQLite provider with diagnostics.
fn provider_adapter(path: &str, reason: impl Into<String>) -> AnalysisError {
    AnalysisError::provider_adapter(PROVIDER_ID, OPERATION).with_diagnostics(
        [
            ("path".to_owned(), Value::String(path.to_owned())),
            ("reason".to_owned(), Value::String(reason.into())),
        ]
        .into_iter()
        .collect(),
    )
}

/// `ProviderCleanupError` surface: a retained-root removal failure.
fn cleanup_failure(path: &str, reason: String) -> AnalysisError {
    AnalysisError::capability_unavailable(
        PROVIDER_ID,
        OPERATION,
        format!("SQLite snapshot cleanup failed for {path}: {reason}"),
    )
}

// ---------------------------------------------------------------------------
// Isolation deviations from the TypeScript provider (documented, not silent).
//
// The TS provider runs `inspectSqliteDatabaseSnapshot` inside an owned Node
// child (`SqliteDatabaseWorkerExecution.ts`): `process.execPath` with
// `--max-old-space-size=256`, a supervised 30 s deadline, a 16 MiB reply file
// and `NODE_OPTIONS` stripped, under the shared owned-process supervisor.
//
// This crate has no worker subcommand reachable through
// `rea_host::process::launcher`, so the bounded read runs IN-PROCESS. Preserved
// in-process: the SQLite run-time value/record and SQL-statement length limits
// (16 MiB via `set_limit`), the 16 MiB complete-evidence budget (`OutputBudget`
// and the final encoded-size check), the row/byte budgets, the read-only/
// `query_only`/`trusted_schema=OFF` posture, the 30 s supervised deadline and
// caller cancellation (a watchdog fires the connection interrupt handle), and
// retained snapshot-root cleanup.
//
// NOT reproduced: (1) a separate OS process address space and process-group /
// Job Object ownership for the reader; (2) the 256 MiB JavaScript-heap cap
// (`--max-old-space-size`) — the native read has no equivalent heap ceiling, so
// the `javascript_heap_bytes` fact on a `memory` failure is carried from the
// contract rather than enforced; (3) crash isolation: a fatal fault in the
// SQLite read would terminate the host process instead of only an owned child.
//
// Requested shared change: add a hidden native worker subcommand launched
// through `rea_host::process::launcher::{OwnedChildProcess, ChildLaunchSpec}`
// that runs `reader::inspect_snapshot` against a snapshot/reply path pair under
// the owned-process supervisor with a memory ceiling and the 30 s deadline.
// That belongs in `native/crates/apps/rea` (the executable entrypoint) and
// `rea-host`/`rea-mcp` plumbing, outside this crate; it would restore all three
// unmet guarantees without changing the observed contract.
// ---------------------------------------------------------------------------
