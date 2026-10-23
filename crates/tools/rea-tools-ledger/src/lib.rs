//! Session Evidence ledger tools.
//!
//! Compatibility owners: `src/server/registerSessionRecordTools.ts`,
//! `src/server/registerBundleComparisonTool.ts` and the session ledger.
use rea_application::{
    binary::rust::Completion, inputs, ledger::artifact_records::DetailLevel,
    ledger::bundle_export::BundleExporter, ledger::bundle_import::BundleImporter,
};
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::bundle_comparison::{self, RecordPair};
use rea_core::evidence::envelope::{EvidenceProvider, Observation};
use rea_mcp::session::record_error;
use rea_mcp::support::{arguments, evidence, input_error};
use rea_mcp::{Registry, Session, SessionResource, ToolContext, ToolOutput};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
type HostFiles = rea_host::fs::unix_file::UnixFiles;
#[cfg(windows)]
type HostFiles = rea_host::fs::windows_file::WindowsFiles;

/// Session-owned bundle exporter retaining failed staging cleanup for retry.
#[derive(Default)]
struct Exports {
    exporter: Mutex<BundleExporter>,
}

impl SessionResource for Exports {
    fn close(&self) -> Result<(), AnalysisError> {
        self.exporter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .close()
            .map_err(AnalysisError::from)
    }
}

/// Session-owned importer retaining failed read cleanup for retry.
struct Imports {
    importer: Mutex<BundleImporter<HostFiles>>,
}

impl Default for Imports {
    fn default() -> Self {
        Self {
            importer: Mutex::new(BundleImporter::new(Arc::new(HostFiles {}))),
        }
    }
}

impl SessionResource for Imports {
    fn close(&self) -> Result<(), AnalysisError> {
        self.importer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .close()
            .map_err(AnalysisError::from)
    }
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, AnalysisError> {
    serde_json::to_value(value).map_err(|error| AnalysisError::output("rea", error.to_string()))
}

fn get_evidence_bundle(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let query = match inputs::records(&arguments(&input)) {
        Ok(query) => query,
        Err(error) => return input_error(context.name(), error).into(),
    };
    if let Err(failure) = query.validate() {
        return AnalysisError::from(failure).into();
    }
    let snapshot = match context.session.records().snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return record_error(error).into(),
    };
    let result = match query.detail {
        DetailLevel::Complete => match snapshot.bundle() {
            Ok(bundle) => to_value(&bundle),
            Err(error) => Err(record_error(error)),
        },
        DetailLevel::Summary => to_value(&snapshot.summary(query.filters.unwrap_or_default())),
    };
    match result {
        Ok(value) => ToolOutput::Value(value),
        Err(error) => error.into(),
    }
}

fn export_evidence_bundle(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let parsed = match inputs::export(&arguments(&input)) {
        Ok(parsed) => parsed,
        Err(error) => return input_error(context.name(), error).into(),
    };
    let snapshot = match context.session.records().snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return record_error(error).into(),
    };
    let exports = context.session.state::<Exports>();
    context.session.own_once::<Exports>(exports.clone());
    let mut exporter = exports
        .exporter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match exporter.export(&snapshot, parsed, &context.cancellation) {
        Ok(receipt) => match to_value(&receipt) {
            Ok(value) => ToolOutput::Value(value),
            Err(error) => error.into(),
        },
        Err(failure) => AnalysisError::from(failure).into(),
    }
}

fn import_evidence_bundle(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let path = match inputs::import(&arguments(&input)) {
        Ok(path) => path,
        Err(error) => return input_error(context.name(), error).into(),
    };
    let imports = context.session.state::<Imports>();
    context.session.own_once::<Imports>(imports.clone());
    let mut importer = imports
        .importer
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match importer.import(
        context.session.records(),
        &path,
        &context.cancellation,
        Completion::Session,
    ) {
        Ok(receipt) => match to_value(&receipt) {
            Ok(value) => ToolOutput::Value(value),
            Err(error) => error.into(),
        },
        Err(failure) => AnalysisError::from(failure).into(),
    }
}

fn list_unknowns(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let query = match inputs::list_unknowns(&arguments(&input)) {
        Ok(query) => query,
        Err(error) => return input_error(context.name(), error).into(),
    };
    let snapshot = match context.session.records().snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return record_error(error).into(),
    };
    match to_value(&snapshot.list_unknowns_page(&query)) {
        Ok(value) => ToolOutput::Value(value),
        Err(error) => error.into(),
    }
}

fn verify_unknown_resolution(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let unknown_id = match inputs::verify_unknown_resolution(&arguments(&input)) {
        Ok(unknown_id) => unknown_id,
        Err(error) => return input_error(context.name(), error).into(),
    };
    let snapshot = match context.session.records().snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return record_error(error).into(),
    };
    match snapshot.verify_unknown_resolution(&unknown_id) {
        Some(check) => match to_value(&check) {
            Ok(value) => ToolOutput::Value(value),
            Err(error) => error.into(),
        },
        None => AnalysisError::unknown_registry("not-found").into(),
    }
}

fn active_subject_raw(session: &Session) -> Option<Box<serde_json::value::RawValue>> {
    session
        .active_subject()
        .and_then(|subject| serde_json::value::to_raw_value(&subject).ok())
}

fn record_unknown(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let parsed = match inputs::record_unknown(&arguments(&input)) {
        Ok(parsed) => parsed,
        Err(error) => return input_error(context.name(), error).into(),
    };
    let subject = active_subject_raw(context.session);
    match context
        .session
        .records()
        .record_unknown(&parsed, subject.as_deref())
    {
        Ok(raw) => match serde_json::from_str(raw.get()) {
            Ok(value) => ToolOutput::Value(value),
            Err(error) => AnalysisError::output(context.name(), error.to_string()).into(),
        },
        Err(error) => record_error(error).into(),
    }
}

fn update_unknown(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let parsed = match inputs::update_unknown(&arguments(&input)) {
        Ok(parsed) => parsed,
        Err(error) => return input_error(context.name(), error).into(),
    };
    let subject = active_subject_raw(context.session);
    match context
        .session
        .records()
        .update_unknown(&parsed, subject.as_deref())
    {
        Ok(raw) => match serde_json::from_str(raw.get()) {
            Ok(value) => ToolOutput::Value(value),
            Err(error) => AnalysisError::output(context.name(), error.to_string()).into(),
        },
        Err(error) => record_error(error).into(),
    }
}

fn compare_bundles(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let left_path = input["left_bundle_path"].as_str().unwrap_or_default();
    let right_path = input["right_bundle_path"].as_str().unwrap_or_default();
    let pairs = input
        .get("record_pairs")
        .and_then(Value::as_array)
        .map(|pairs| {
            pairs
                .iter()
                .map(|pair| RecordPair {
                    left_evidence_id: pair["left_evidence_id"].as_str().unwrap_or_default().into(),
                    right_evidence_id: pair["right_evidence_id"]
                        .as_str()
                        .unwrap_or_default()
                        .into(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut loader = BundleImporter::new(Arc::new(HostFiles {}));
    let load = |loader: &mut BundleImporter<HostFiles>, path: &str| {
        loader
            .load_with_operation(
                path,
                &context.cancellation,
                Completion::OneShot,
                context.name_static(),
            )
            .map_err(AnalysisError::from)
    };
    let left = match load(&mut loader, left_path) {
        Ok(bundle) => bundle,
        Err(error) => return error.into(),
    };
    let right = match load(&mut loader, right_path) {
        Ok(bundle) => bundle,
        Err(error) => return error.into(),
    };
    let _ = loader.close();
    if let Err(error) = context.check_cancelled() {
        return error.into();
    }
    let comparison = match bundle_comparison::compare_bundles(&left, &right, &pairs) {
        Ok(comparison) => comparison,
        Err(error) => return AnalysisError::evidence_integrity(error.to_string()).into(),
    };
    // Retain each distinct source record, left first, before deriving Evidence.
    let mut links = Vec::new();
    for record in left.records().iter().chain(right.records()) {
        if links.iter().any(|id: &String| id == record.evidence_id()) {
            continue;
        }
        if let Err(error) = context.session.record_raw(record.raw()) {
            return error.into();
        }
        links.push(record.evidence_id().to_owned());
    }
    let result = match to_value(&comparison) {
        Ok(result) => result,
        Err(error) => return error.into(),
    };
    let mut parameters = serde_json::Map::new();
    parameters.insert(
        "left_bundle_sha256".into(),
        json!(comparison.left_bundle_sha256),
    );
    parameters.insert(
        "right_bundle_sha256".into(),
        json!(comparison.right_bundle_sha256),
    );
    if let Some(pairs) = input.get("record_pairs") {
        parameters.insert("record_pairs".into(), pairs.clone());
    }
    let observation = Observation::new(context.name(), Value::Object(parameters), result)
        .predicate("rea.bundle-comparison")
        .confidence("derived")
        .authority("analyst-inference")
        .limitations(
            comparison
                .limitations
                .iter()
                .map(|text| (*text).to_owned())
                .collect(),
        )
        .links(links);
    evidence(
        None,
        &EvidenceProvider::new(
            "rea-bundle-comparison",
            "REA Evidence bundle comparison",
            Some("1".into()),
        ),
        observation,
    )
    .into()
}

/// Bind every ledger tool to its exact contract.
pub fn register(registry: &mut Registry) {
    registry.handle("get_evidence_bundle", get_evidence_bundle);
    registry.handle("export_evidence_bundle", export_evidence_bundle);
    registry.handle("import_evidence_bundle", import_evidence_bundle);
    registry.handle("list_unknowns", list_unknowns);
    registry.handle("verify_unknown_resolution", verify_unknown_resolution);
    registry.handle("record_unknown", record_unknown);
    registry.handle("update_unknown", update_unknown);
    registry.handle("compare_bundles", compare_bundles);
}
