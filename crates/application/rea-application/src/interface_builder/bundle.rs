//! Bounded discovery and decoding of compiled Interface Builder archives in an app bundle.
//!
//! The host directory reader owns no-follow traversal and file identity. This
//! workflow owns archive selection, format parsing, coverage, and provenance.

use crate::{
    apple, interface_builder, interface_builder::keyed_archive as interface_builder_keyed_archive,
    interface_builder::nib_view_hierarchy,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rea_core::{
    cancellation::Cancellation,
    evidence::{
        ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject, is_sha256,
    },
    failure::{Detail, Failure},
    json_output,
};
use rea_host::{fs::stable_directory, fs::stable_directory::DirectoryEntryKind};
use rea_rust_analysis::{nib, plist};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub use super::types::{InterfaceBuilderLimits, MAX_CONNECTIONS, MAX_DOCUMENTS, MAX_OBJECTS};

pub const OPERATION: &str = "decode_interface_builder";
const MAX_DIRECTORY_ENTRIES: usize = 100_000;
const MAX_REPORTED_OMISSIONS: usize = 64;
const MAX_AGGREGATE_INPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_AGGREGATE_DECODE_BYTES: usize = 256 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 256 * 1024 * 1024;
const PROVIDER: Provider = Provider {
    id: "rea-artifact-graph",
    name: "REA safe artifact graph provider",
    version: Some("1"),
};
const TOOL_VERSION: &str = "rea-interface-builder/1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    NibArchive,
    BinaryPlist,
    XmlPlist,
    OpenStepPlist,
}

#[derive(Debug, Serialize)]
pub struct ArchiveDocument {
    pub relative_path: String,
    pub archive_sha256: String,
    pub archive_format: ArchiveFormat,
    pub decoded: Value,
    pub projection: Option<interface_builder::InterfaceBuilderProjection>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct OmittedArchive {
    pub relative_path: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct BundleCoverage {
    pub archives_found: usize,
    pub archives_attempted: usize,
    pub archives_decoded: usize,
    pub archives_invalid: usize,
    pub archives_omitted: usize,
    pub omissions_unreported: usize,
    pub input_bytes_examined: usize,
    pub partial: bool,
}

#[derive(Debug, Serialize)]
pub struct InterfaceBuilderBundleReport {
    pub bundle_path: String,
    pub target_sha256: String,
    pub documents: Vec<ArchiveDocument>,
    pub invalid_archives: Vec<String>,
    pub omitted_archives: Vec<OmittedArchive>,
    pub coverage: BundleCoverage,
    pub limits: InterfaceBuilderLimits,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct InterfaceBuilderAnalysis {
    target_sha256: String,
    documents: Vec<InterfaceBuilderDocumentSummary>,
    graph: InvestigationGraph,
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct InterfaceBuilderDocumentSummary {
    relative_path: String,
    archive_sha256: String,
    document_kind: &'static str,
    object_count: usize,
    connection_count: usize,
    hierarchy_complete: bool,
}

#[derive(Debug, Serialize)]
struct InvestigationGraph {
    target_sha256: String,
    provider: InvestigationGraphProvider,
    nodes: Vec<InvestigationNode>,
    edges: Vec<InvestigationEdge>,
    coverage: Vec<InvestigationCoverage>,
    truncated: bool,
}

#[derive(Debug, Serialize)]
struct InvestigationGraphProvider {
    id: &'static str,
    version: &'static str,
    tool_version: &'static str,
}

#[derive(Debug, Serialize)]
struct InvestigationNode {
    id: String,
    kind: &'static str,
    name: String,
    location: Option<InvestigationLocation>,
    attributes: Map<String, Value>,
    evidence: Vec<InvestigationEvidence>,
}

#[derive(Debug, Serialize)]
struct InvestigationLocation {
    address: Option<String>,
    file_offset: Option<u64>,
}

#[derive(Debug, Serialize)]
struct InvestigationEvidence {
    kind: &'static str,
    description: String,
    location: InvestigationLocation,
    artifact_path: String,
    artifact_sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "resolution", rename_all = "snake_case")]
enum InvestigationEdge {
    Observed {
        id: String,
        from: String,
        to: String,
        relation: &'static str,
        evidence: Vec<InvestigationEvidence>,
        limitations: Vec<String>,
    },
    Unresolved {
        id: String,
        from: String,
        to: Option<String>,
        relation: &'static str,
        reason: String,
        evidence: Vec<InvestigationEvidence>,
        limitations: Vec<String>,
    },
}

#[derive(Debug, Serialize)]
struct InvestigationCoverage {
    facet: String,
    status: &'static str,
    reason: Option<String>,
    examined: usize,
    omitted: usize,
}

/// Parsed resource-key facts used by the asset-catalog workflow.
#[derive(Clone, Debug, Default)]
pub struct InterfaceBuilderAssetReferences {
    pub references: Vec<apple::asset_catalog::ResourceReference>,
    pub graph_truncated: bool,
}

#[derive(Debug)]
struct CandidateSelection {
    selected: Vec<stable_directory::DirectoryEntry>,
    omitted_samples: Vec<stable_directory::DirectoryEntry>,
    total: usize,
}

#[derive(Debug)]
struct DecodeSummary {
    document: Option<ArchiveDocument>,
    invalid_reason: Option<String>,
    omitted_reason: Option<String>,
    input_bytes_read: usize,
}

#[derive(Debug)]
struct ArchiveCollection {
    documents: Vec<ArchiveDocument>,
    invalid_archives: Vec<String>,
    omitted_archives: Vec<OmittedArchive>,
    omissions_unreported: usize,
    archives_attempted: usize,
    archives_omitted_during_decode: usize,
    input_bytes_examined: usize,
    decoded_bytes: usize,
}

impl ArchiveCollection {
    fn new() -> Self {
        Self {
            documents: Vec::new(),
            invalid_archives: Vec::new(),
            omitted_archives: Vec::new(),
            omissions_unreported: 0,
            archives_attempted: 0,
            archives_omitted_during_decode: 0,
            input_bytes_examined: 0,
            decoded_bytes: 0,
        }
    }

    fn record_omission(&mut self, relative_path: String, reason: String) {
        record_omission(
            relative_path,
            reason,
            &mut self.omitted_archives,
            &mut self.omissions_unreported,
        );
    }

    fn record_selection_omissions(
        &mut self,
        omitted_samples: Vec<stable_directory::DirectoryEntry>,
        total_omitted: usize,
    ) {
        let reported_count = omitted_samples.len();
        for entry in omitted_samples {
            self.record_omission(entry.path, "max_documents".into());
        }

        self.omissions_unreported = self
            .omissions_unreported
            .saturating_add(total_omitted.saturating_sub(reported_count));
    }

    fn retain_decode_result(
        &mut self,
        relative_path: &str,
        decode: DecodeSummary,
    ) -> Result<(), Failure> {
        self.input_bytes_examined = self
            .input_bytes_examined
            .saturating_add(decode.input_bytes_read);

        if let Some(document) = decode.document {
            self.retain_document(relative_path, document)?;
        } else if let Some(reason) = decode.invalid_reason {
            self.invalid_archives
                .push(format!("{relative_path}: {reason}"));
        } else if let Some(reason) = decode.omitted_reason {
            self.archives_omitted_during_decode += 1;
            self.record_omission(relative_path.to_owned(), reason);
        }

        Ok(())
    }

    fn retain_document(
        &mut self,
        relative_path: &str,
        document: ArchiveDocument,
    ) -> Result<(), Failure> {
        let remaining_decode_bytes = MAX_AGGREGATE_DECODE_BYTES.saturating_sub(self.decoded_bytes);
        match json_output::admitted_length(&document, remaining_decode_bytes) {
            Ok(document_bytes) => {
                self.decoded_bytes = self.decoded_bytes.saturating_add(document_bytes);
                self.documents.push(document);
                Ok(())
            }
            Err(json_output::Error::Limit { .. }) => {
                self.archives_omitted_during_decode += 1;
                self.record_omission(
                    relative_path.to_owned(),
                    "aggregate_decode_budget_exhausted".into(),
                );
                Ok(())
            }
            Err(json_output::Error::Encoding(error)) => {
                Err(bundle_failure(Path::new(relative_path), error.to_string()))
            }
        }
    }
}

/// Inspect all bounded compiled Interface Builder archives below one selected app bundle.
pub fn inspect_bundle(
    bundle_path: &Path,
    target_sha256: String,
    cancellation: &Cancellation,
) -> Result<ArtifactEvidence, Failure> {
    inspect_bundle_with_limits(
        bundle_path,
        target_sha256,
        InterfaceBuilderLimits::default(),
        cancellation,
    )
}

/// Inspect the selected app bundle using the caller's explicit graph limits.
pub fn inspect_bundle_with_limits(
    bundle_path: &Path,
    target_sha256: String,
    limits: InterfaceBuilderLimits,
    cancellation: &Cancellation,
) -> Result<ArtifactEvidence, Failure> {
    let (report, analysis) =
        inspect_bundle_analysis(bundle_path, target_sha256, limits, cancellation)?;
    let subject = Subject::new(
        &report.bundle_path,
        report.target_sha256.clone(),
        NativeFormat::Directory,
        None,
    )
    .map_err(|error| bundle_failure(bundle_path, error.to_string()))?;
    let locations = report
        .documents
        .iter()
        .map(|document| Location::ArtifactPath {
            path: document.relative_path.clone(),
        })
        .collect();
    let evidence = ArtifactEvidence::new_with_parameters(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            limitations: analysis.limitations.clone(),
            result: analysis,
            locations,
        },
        json!({
            "target_sha256": report.target_sha256,
            "max_documents": report.limits.max_documents,
            "max_objects": report.limits.max_objects,
            "max_connections": report.limits.max_connections,
        }),
    )
    .map_err(|error| bundle_failure(bundle_path, error.to_string()))?;

    ensure_evidence_fits_output_limit(bundle_path, &evidence)?;

    Ok(evidence)
}

/// Decode the graph once and return only its recognized asset-key facts.
pub fn inspect_bundle_asset_references(
    bundle_path: &Path,
    target_sha256: String,
    cancellation: &Cancellation,
) -> Result<InterfaceBuilderAssetReferences, Failure> {
    let (_, analysis) = inspect_bundle_analysis(
        bundle_path,
        target_sha256,
        InterfaceBuilderLimits::default(),
        cancellation,
    )?;

    Ok(InterfaceBuilderAssetReferences {
        references: collect_asset_resource_references(&analysis.graph.nodes),
        graph_truncated: analysis.graph.truncated,
    })
}

fn inspect_bundle_analysis(
    bundle_path: &Path,
    target_sha256: String,
    limits: InterfaceBuilderLimits,
    cancellation: &Cancellation,
) -> Result<(InterfaceBuilderBundleReport, InterfaceBuilderAnalysis), Failure> {
    validate_request(bundle_path, &target_sha256, &limits, cancellation)?;

    let reader = open_bundle_reader(bundle_path)?;
    let selection =
        select_bundle_candidates(&reader, bundle_path, limits.max_documents, cancellation)?;
    let selected_count = selection.selected.len();
    let selection_omitted = selection.total.saturating_sub(selected_count);

    let mut collection = ArchiveCollection::new();
    collection.record_selection_omissions(selection.omitted_samples, selection_omitted);
    decode_selected_archives(
        &reader,
        selection.selected,
        &limits,
        cancellation,
        &mut collection,
    )?;

    let report = build_bundle_report(
        bundle_path,
        target_sha256,
        limits,
        selection.total,
        selection_omitted,
        collection,
    );
    let analysis = build_interface_builder_analysis(&report);
    Ok((report, analysis))
}

fn collect_asset_resource_references(
    nodes: &[InvestigationNode],
) -> Vec<apple::asset_catalog::ResourceReference> {
    let mut references = Vec::new();

    for node in nodes.iter().filter(|node| node.kind == "resource") {
        let Some(source) = node.evidence.iter().find(|evidence| {
            !evidence.artifact_path.is_empty() && is_sha256(&evidence.artifact_sha256)
        }) else {
            continue;
        };

        for (field, key) in apple::asset_catalog::apple_resource_key_fields(&node.attributes) {
            references.push(apple::asset_catalog::ResourceReference {
                source_node_id: node.id.clone(),
                source_path: source.artifact_path.clone(),
                source_archive_sha256: source.artifact_sha256.clone(),
                field,
                key,
            });
        }
    }

    references
}

fn open_bundle_reader(bundle_path: &Path) -> Result<stable_directory::DirectoryReader, Failure> {
    stable_directory::DirectoryReader::open(bundle_path)
        .map_err(|error| bundle_failure(bundle_path, error.to_string()))
}

fn select_bundle_candidates(
    reader: &stable_directory::DirectoryReader,
    bundle_path: &Path,
    max_documents: usize,
    cancellation: &Cancellation,
) -> Result<CandidateSelection, Failure> {
    let entries = reader
        .entries(MAX_DIRECTORY_ENTRIES, cancellation)
        .map_err(|error| directory_failure(bundle_path, error))?;
    Ok(select_candidates(entries, max_documents))
}

fn decode_selected_archives(
    reader: &stable_directory::DirectoryReader,
    selected: Vec<stable_directory::DirectoryEntry>,
    limits: &InterfaceBuilderLimits,
    cancellation: &Cancellation,
    collection: &mut ArchiveCollection,
) -> Result<(), Failure> {
    for entry in selected {
        decode_selected_archive(reader, &entry, limits, cancellation, collection)?;
    }

    Ok(())
}

fn decode_selected_archive(
    reader: &stable_directory::DirectoryReader,
    entry: &stable_directory::DirectoryEntry,
    limits: &InterfaceBuilderLimits,
    cancellation: &Cancellation,
    collection: &mut ArchiveCollection,
) -> Result<(), Failure> {
    ensure_active(cancellation)?;

    let remaining_input_bytes =
        MAX_AGGREGATE_INPUT_BYTES.saturating_sub(collection.input_bytes_examined);
    if let Some(reason) = archive_preflight_omission(entry, remaining_input_bytes) {
        collection.archives_omitted_during_decode += 1;
        collection.record_omission(entry.path.clone(), reason);
        return Ok(());
    }

    collection.archives_attempted += 1;
    let decode = decode_entry(reader, entry, remaining_input_bytes, limits, cancellation)?;
    collection.retain_decode_result(&entry.path, decode)
}

fn archive_preflight_omission(
    entry: &stable_directory::DirectoryEntry,
    remaining_input_bytes: usize,
) -> Option<String> {
    if entry.path.len() > 512 {
        return Some("archive_path_exceeds_supported_length".into());
    }

    (entry.identity.bytes > remaining_input_bytes as u64)
        .then(|| "aggregate_decode_budget_exhausted".into())
}

fn build_bundle_report(
    bundle_path: &Path,
    target_sha256: String,
    limits: InterfaceBuilderLimits,
    archives_found: usize,
    selection_omitted: usize,
    collection: ArchiveCollection,
) -> InterfaceBuilderBundleReport {
    let archives_invalid = collection.invalid_archives.len();
    let archives_omitted =
        selection_omitted.saturating_add(collection.archives_omitted_during_decode);
    let graph_projection_partial = collection.documents.iter().any(|document| {
        document
            .projection
            .as_ref()
            .is_some_and(|projection| projection.coverage.partial)
    });
    let partial = archives_omitted > 0 || archives_invalid > 0 || graph_projection_partial;

    let limitations = vec![
        "The graph reflects recognized Interface Builder archive fields and connections; omitted private or unrecognized archive fields remain unknown.".to_owned(),
        "A target-action selector is an Interface Builder observation and does not prove that the binary contains a matching implementation.".to_owned(),
        "Decoded constraints, runtime visibility, dynamic UI creation, and pixel geometry are not inferred from these archives.".to_owned(),
    ];

    let archives_decoded = collection.documents.len();
    InterfaceBuilderBundleReport {
        bundle_path: bundle_path.to_string_lossy().into_owned(),
        target_sha256,
        documents: collection.documents,
        invalid_archives: collection.invalid_archives,
        omitted_archives: collection.omitted_archives,
        coverage: BundleCoverage {
            archives_found,
            archives_attempted: collection.archives_attempted,
            archives_decoded,
            archives_invalid,
            archives_omitted,
            omissions_unreported: collection.omissions_unreported,
            input_bytes_examined: collection.input_bytes_examined,
            partial,
        },
        limits,
        limitations,
    }
}

fn build_interface_builder_analysis(
    report: &InterfaceBuilderBundleReport,
) -> InterfaceBuilderAnalysis {
    let mut graph = GraphAccumulator::new(
        report.target_sha256.clone(),
        report.limits.max_objects,
        report.limits.max_connections.saturating_mul(3),
    );
    let mut documents = Vec::with_capacity(report.documents.len());
    let mut limitations = report.limitations.clone();
    limitations.push(
        "Compiled Interface Builder archives are private serialized object graphs. The decoder reports only recognized keyed-archive objects and connections; unrecognized object classes and fields remain unknown.".to_owned(),
    );

    for document in &report.documents {
        limitations.extend(
            document
                .limitations
                .iter()
                .map(|limitation| format!("{}: {limitation}", document.relative_path)),
        );
        let document_kind = if document.relative_path.contains(".storyboardc/") {
            "storyboard_scene"
        } else {
            "nib"
        };
        let object_count = document
            .projection
            .as_ref()
            .map(|projection| projection.coverage.objects_examined)
            .unwrap_or_default();
        // The connection count folds unresolved connectors back in: they carry
        // no record but are counted as declared connections by the oracle.
        let connection_count = document
            .projection
            .as_ref()
            .map(|projection| {
                projection
                    .coverage
                    .connections_examined
                    .saturating_add(projection.coverage.unresolved_connections)
            })
            .unwrap_or_default();
        let hierarchy_complete = document.projection.as_ref().is_some_and(|projection| {
            projection.coverage.hierarchy_nodes_omitted == 0 && !projection.hierarchy.is_empty()
        });

        documents.push(InterfaceBuilderDocumentSummary {
            relative_path: document.relative_path.clone(),
            archive_sha256: document.archive_sha256.clone(),
            document_kind,
            object_count,
            connection_count,
            hierarchy_complete,
        });
        graph.add_document(document, document_kind);
    }

    // These notices describe NIBArchive decoding only; keyed archives report
    // the same omissions through their coverage facets.
    let has_incomplete_hierarchy = report.documents.iter().any(|document| {
        document.archive_format == ArchiveFormat::NibArchive
            && document
                .projection
                .as_ref()
                .is_some_and(|projection| projection.coverage.hierarchy_nodes_omitted > 0)
    });
    if has_incomplete_hierarchy {
        limitations.push(
            "Some serialized hierarchy links could not be projected within the bounded hierarchy; their parentage remains unknown.".into(),
        );
    }

    let has_unresolved_connections = report.documents.iter().any(|document| {
        document.archive_format == ArchiveFormat::NibArchive
            && document
                .projection
                .as_ref()
                .is_some_and(|projection| projection.coverage.unresolved_connections > 0)
    });
    if has_unresolved_connections {
        limitations.push(
            "Some recognized NIBArchive connectors declare no resolvable owner; they carry no connection evidence and are reported as omissions.".into(),
        );
    }

    if !report.invalid_archives.is_empty() {
        limitations.push(format!(
            "Some Interface Builder archives could not be decoded: {}",
            report
                .invalid_archives
                .iter()
                .take(16)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    for omission in &report.omitted_archives {
        limitations.push(format!(
            "{}: omitted because {}.",
            omission.relative_path,
            omission.reason.replace('_', " ")
        ));
    }
    if report.coverage.omissions_unreported > 0 {
        limitations.push(format!(
            "{} additional omitted archive path(s) and their reasons were not retained; reporting is bounded to {MAX_REPORTED_OMISSIONS} paths.",
            report.coverage.omissions_unreported
        ));
    }

    graph.add_archive_decode_coverage(&report.coverage, &report.omitted_archives);
    graph.add_graph_node_coverage();

    InterfaceBuilderAnalysis {
        target_sha256: report.target_sha256.clone(),
        documents,
        graph: graph.finish(),
        limitations,
    }
}

struct GraphAccumulator {
    target_sha256: String,
    maximum_nodes: usize,
    maximum_connection_edges: usize,
    nodes: Vec<InvestigationNode>,
    node_ids: BTreeSet<String>,
    edges: Vec<InvestigationEdge>,
    coverage: Vec<InvestigationCoverage>,
    omitted_graph_nodes: usize,
    // Per-document edge budgets: hierarchy edges are bounded by the object
    // limit and connection edges by three edges per retained connection.
    hierarchy_edges: usize,
    connection_edges: usize,
    truncated: bool,
}

impl GraphAccumulator {
    fn new(target_sha256: String, maximum_nodes: usize, maximum_connection_edges: usize) -> Self {
        Self {
            target_sha256,
            maximum_nodes,
            maximum_connection_edges,
            nodes: Vec::new(),
            node_ids: BTreeSet::new(),
            edges: Vec::new(),
            coverage: Vec::new(),
            omitted_graph_nodes: 0,
            hierarchy_edges: 0,
            connection_edges: 0,
            truncated: false,
        }
    }

    fn add_document(&mut self, document: &ArchiveDocument, document_kind: &str) {
        self.hierarchy_edges = 0;
        self.connection_edges = 0;
        let root_id = format!("ib:{}:root", json!(document.relative_path));
        let root_kind = if document_kind == "nib" {
            "scene"
        } else {
            "storyboard"
        };
        let mut root_attributes = Map::new();
        root_attributes.insert("document_kind".into(), Value::String(document_kind.into()));
        self.add_node(InvestigationNode {
            id: root_id.clone(),
            kind: root_kind,
            name: document.relative_path.clone(),
            location: None,
            attributes: root_attributes,
            evidence: vec![investigation_evidence(document, "compiled document")],
        });

        let Some(projection) = &document.projection else {
            self.add_document_coverage(document, None);
            return;
        };
        let object_ids = projection
            .objects
            .iter()
            .map(|object| object.id.clone())
            .collect::<BTreeSet<_>>();
        self.add_objects(document, projection);
        self.add_hierarchy(document, projection, &root_id, &object_ids);
        self.add_connections(document, projection);
        self.add_document_coverage(document, Some(projection));
    }

    fn add_objects(
        &mut self,
        document: &ArchiveDocument,
        projection: &interface_builder::InterfaceBuilderProjection,
    ) {
        for object in &projection.objects {
            let mut attributes = object.attributes.clone().into_iter().collect::<Map<_, _>>();
            attributes.insert(
                "interface_builder_object_id".into(),
                Value::String(object.id.clone()),
            );
            attributes.insert(
                "class_name".into(),
                object
                    .class_name
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
            let node = InvestigationNode {
                id: object_graph_id(document, &object.id),
                kind: classify_object(object.class_name.as_deref()),
                name: object.label.clone().unwrap_or_else(|| object.id.clone()),
                location: None,
                attributes,
                evidence: vec![investigation_evidence(
                    document,
                    &format!("object {}", object.id),
                )],
            };
            if !self.add_node(node) {
                break;
            }
        }
    }

    fn add_hierarchy(
        &mut self,
        document: &ArchiveDocument,
        projection: &interface_builder::InterfaceBuilderProjection,
        root_id: &str,
        object_ids: &BTreeSet<String>,
    ) {
        // Each visited node links from its parent (the document root for a
        // top-level node); a child the object table does not carry becomes an
        // `unknown` node keyed by its archive identity.
        let hierarchy_id = |object_id: &str| {
            if object_ids.contains(object_id) {
                object_graph_id(document, object_id)
            } else {
                graph_id(
                    &document.relative_path,
                    "unknown",
                    &json!([object_id]).to_string(),
                )
            }
        };
        for fact in &projection.hierarchy {
            let child_graph_id = hierarchy_id(&fact.child_id);
            if !object_ids.contains(&fact.child_id) {
                let mut attributes = Map::new();
                attributes.insert(
                    "interface_builder_object_id".into(),
                    Value::String(fact.child_id.clone()),
                );
                self.add_node(InvestigationNode {
                    id: child_graph_id.clone(),
                    kind: "unknown",
                    name: fact
                        .child_label
                        .clone()
                        .unwrap_or_else(|| fact.child_id.clone()),
                    location: None,
                    attributes,
                    evidence: vec![investigation_evidence(
                        document,
                        &format!("hierarchy item {}", fact.child_id),
                    )],
                });
            }
            let parent_graph_id = fact
                .parent_id
                .as_deref()
                .map_or_else(|| root_id.to_owned(), hierarchy_id);
            let edge_id = graph_id(
                &document.relative_path,
                "hierarchy",
                &json!([parent_graph_id, child_graph_id]).to_string(),
            );
            self.connect(
                edge_id,
                parent_graph_id,
                Some(child_graph_id),
                "contains",
                document,
                &format!("hierarchy {}", fact.child_id),
                None,
            );
        }
    }

    fn add_connections(
        &mut self,
        document: &ArchiveDocument,
        projection: &interface_builder::InterfaceBuilderProjection,
    ) {
        for (index, connection) in projection.connections.iter().enumerate() {
            let source_id = object_graph_id(document, &connection.source_id);
            if !self.node_ids.contains(&source_id) {
                let mut attributes = Map::new();
                attributes.insert(
                    "interface_builder_object_id".into(),
                    Value::String(connection.source_id.clone()),
                );
                self.add_node(InvestigationNode {
                    id: source_id.clone(),
                    kind: "unknown",
                    name: connection.source_id.clone(),
                    location: None,
                    attributes,
                    evidence: vec![investigation_evidence(
                        document,
                        &format!("connection source {}", connection.source_id),
                    )],
                });
            }
            let destination_id = connection
                .destination_id
                .as_deref()
                .map(|id| object_graph_id(document, id))
                .filter(|id| self.node_ids.contains(id));
            match classify_connection(&connection.relation) {
                "outlet" => {
                    self.add_outlet_connection(document, connection, source_id, destination_id)
                }
                "action" => {
                    self.add_action_connection(document, connection, source_id, destination_id)
                }
                "segue" => self.connect(
                    graph_id(
                        &document.relative_path,
                        "segue",
                        &json!([index]).to_string(),
                    ),
                    source_id,
                    destination_id,
                    "segue_to",
                    document,
                    &format!(
                        "segue {}",
                        connection.label.as_deref().unwrap_or(&connection.id)
                    ),
                    Some("destination_scene_missing"),
                ),
                _ => self.connect(
                    graph_id(
                        &document.relative_path,
                        "unknown-connection",
                        &json!([index]).to_string(),
                    ),
                    source_id,
                    None,
                    "contains",
                    document,
                    &format!(
                        "connection type {}",
                        classify_connection(&connection.relation)
                    ),
                    Some("unsupported_connection_type"),
                ),
            }
        }

        let connection_omissions = projection
            .coverage
            .connections_omitted
            .saturating_add(projection.coverage.unresolved_connections);
        if connection_omissions > 0 {
            self.truncated = true;
        }
    }

    fn add_outlet_connection(
        &mut self,
        document: &ArchiveDocument,
        connection: &interface_builder::ConnectionFact,
        source_id: String,
        destination_id: Option<String>,
    ) {
        let outlet_id = graph_id(
            &document.relative_path,
            "outlet",
            &json!([connection.id]).to_string(),
        );
        self.add_node(InvestigationNode {
            id: outlet_id.clone(),
            kind: "outlet",
            name: connection
                .label
                .clone()
                .unwrap_or_else(|| connection.id.clone()),
            location: None,
            attributes: connection.attributes.clone(),
            evidence: vec![investigation_evidence(
                document,
                &format!("outlet {}", connection.id),
            )],
        });
        self.connect(
            graph_id(
                &document.relative_path,
                "outlet-edge",
                &json!([connection.id, "source"]).to_string(),
            ),
            source_id,
            Some(outlet_id.clone()),
            "contains",
            document,
            &format!("outlet source {}", connection.source_id),
            None,
        );
        self.connect(
            graph_id(
                &document.relative_path,
                "outlet-edge",
                &json!([connection.id, "destination"]).to_string(),
            ),
            outlet_id,
            destination_id,
            "outlet_to",
            document,
            &format!(
                "outlet {}",
                connection.label.as_deref().unwrap_or(&connection.id)
            ),
            Some("destination_object_missing_or_external"),
        );
    }

    fn add_action_connection(
        &mut self,
        document: &ArchiveDocument,
        connection: &interface_builder::ConnectionFact,
        source_id: String,
        destination_id: Option<String>,
    ) {
        let action_id = graph_id(
            &document.relative_path,
            "action",
            &json!([connection.id]).to_string(),
        );
        let destination_value = connection
            .destination_id
            .clone()
            .map(Value::String)
            .unwrap_or(Value::Null);
        let mut attributes = Map::new();
        attributes.insert(
            "selector".into(),
            connection
                .label
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        attributes.insert("destination_id".into(), destination_value.clone());
        attributes.extend(connection.attributes.clone());
        self.add_node(InvestigationNode {
            id: action_id.clone(),
            kind: "action",
            name: connection
                .label
                .clone()
                .unwrap_or_else(|| "unlabeled action".into()),
            location: None,
            attributes,
            evidence: vec![investigation_evidence(
                document,
                &format!("action {}", connection.id),
            )],
        });
        self.connect(
            graph_id(
                &document.relative_path,
                "action-edge",
                &json!([connection.id, "source"]).to_string(),
            ),
            source_id,
            Some(action_id.clone()),
            "target_action",
            document,
            &format!("action source {}", connection.source_id),
            None,
        );

        if let Some(label) = &connection.label {
            let selector_id = graph_id(
                &document.relative_path,
                "selector",
                &json!([connection.destination_id, label]).to_string(),
            );
            let mut selector_attributes = Map::new();
            selector_attributes.insert("destination_id".into(), destination_value);
            self.add_node(InvestigationNode {
                id: selector_id.clone(),
                kind: "objc_selector",
                name: label.clone(),
                location: None,
                attributes: selector_attributes,
                evidence: vec![investigation_evidence(
                    document,
                    &format!("selector {label}"),
                )],
            });
            self.connect(
                graph_id(
                    &document.relative_path,
                    "action-edge",
                    &json!([connection.id, "selector"]).to_string(),
                ),
                action_id.clone(),
                Some(selector_id),
                "target_action",
                document,
                &format!("selector {label}"),
                None,
            );
        }

        self.connect(
            graph_id(
                &document.relative_path,
                "action-edge",
                &json!([connection.id, "destination"]).to_string(),
            ),
            action_id,
            destination_id,
            "target_action",
            document,
            &format!(
                "action destination {}",
                connection.destination_id.as_deref().unwrap_or("missing")
            ),
            Some("destination_object_missing_or_external"),
        );
    }

    fn add_document_coverage(
        &mut self,
        document: &ArchiveDocument,
        projection: Option<&interface_builder::InterfaceBuilderProjection>,
    ) {
        let Some(projection) = projection else {
            self.coverage.push(InvestigationCoverage {
                facet: format!("objects:{}", document.relative_path),
                status: "unsupported",
                reason: Some("archive_projection_unavailable".into()),
                examined: 0,
                omitted: 0,
            });
            return;
        };
        let counts = &projection.coverage;
        self.coverage.push(InvestigationCoverage {
            facet: format!("objects:{}", document.relative_path),
            status: if counts.objects_omitted > 0 {
                "partial"
            } else {
                "complete"
            },
            reason: (counts.objects_omitted > 0).then(|| "object_limit_reached".into()),
            examined: counts.objects_examined,
            omitted: counts.objects_omitted,
        });
        let connection_omitted = counts
            .connections_omitted
            .saturating_add(counts.unresolved_connections);
        self.coverage.push(InvestigationCoverage {
            facet: format!("connections:{}", document.relative_path),
            status: if connection_omitted > 0 {
                "partial"
            } else {
                "complete"
            },
            reason: if counts.connections_omitted > 0 {
                Some("connection_limit_reached".into())
            } else if counts.unresolved_connections > 0 {
                Some("connection_unresolved".into())
            } else {
                None
            },
            examined: counts.connections_examined,
            omitted: connection_omitted,
        });
        self.coverage.push(InvestigationCoverage {
            facet: format!("hierarchy:{}", document.relative_path),
            status: if counts.hierarchy_nodes_examined == 0 {
                "unsupported"
            } else if counts.hierarchy_nodes_omitted > 0 {
                "partial"
            } else {
                "complete"
            },
            reason: if counts.hierarchy_nodes_omitted > 0 {
                Some("hierarchy_limit_reached".into())
            } else if counts.hierarchy_nodes_examined == 0 {
                Some("archive_hierarchy_not_decoded".into())
            } else {
                None
            },
            examined: counts.hierarchy_nodes_examined,
            omitted: counts.hierarchy_nodes_omitted,
        });
        self.coverage.push(InvestigationCoverage {
            facet: format!("classes:{}", document.relative_path),
            status: if counts.classes_examined > 0 {
                "complete"
            } else {
                "unsupported"
            },
            reason: (counts.classes_examined == 0)
                .then(|| "archive_class_table_not_decoded".into()),
            examined: counts.classes_examined,
            omitted: 0,
        });
        self.truncated |= counts.partial;
    }

    fn add_archive_decode_coverage(
        &mut self,
        coverage: &BundleCoverage,
        omissions: &[OmittedArchive],
    ) {
        let reason = if omissions
            .iter()
            .any(|omission| omission.reason == "aggregate_decode_budget_exhausted")
        {
            Some("aggregate_decode_budget_exhausted")
        } else if omissions
            .iter()
            .any(|omission| omission.reason == "max_documents")
        {
            Some("document_limit_reached")
        } else if coverage.archives_omitted > 0 {
            Some("archive_decode_budget_exhausted")
        } else if coverage.archives_invalid > 0 {
            Some("one_or_more_archives_invalid")
        } else {
            None
        };
        let decode_partial = coverage.archives_invalid > 0 || coverage.archives_omitted > 0;
        self.coverage.push(InvestigationCoverage {
            facet: "archive_decode".into(),
            status: if decode_partial {
                "partial"
            } else {
                "complete"
            },
            reason: reason.map(str::to_owned),
            examined: coverage.archives_attempted,
            omitted: coverage.archives_omitted,
        });
        self.truncated |= coverage.partial;
    }

    fn add_graph_node_coverage(&mut self) {
        if self.omitted_graph_nodes == 0 {
            return;
        }
        self.coverage.push(InvestigationCoverage {
            facet: "graph_nodes".into(),
            status: "partial",
            reason: Some("max_objects_reached".into()),
            examined: self.nodes.len(),
            omitted: self.omitted_graph_nodes,
        });
        self.truncated = true;
    }

    fn add_node(&mut self, node: InvestigationNode) -> bool {
        if self.node_ids.contains(&node.id) {
            return true;
        }
        if self.nodes.len() >= self.maximum_nodes {
            self.omitted_graph_nodes += 1;
            self.truncated = true;
            return false;
        }
        self.node_ids.insert(node.id.clone());
        self.nodes.push(node);
        true
    }

    /// Add one edge. A missing source omits the edge; a named endpoint that
    /// was not retained is unresolved because of the object limit; an absent
    /// endpoint is unresolved for the caller's reason.
    #[allow(clippy::too_many_arguments)]
    fn connect(
        &mut self,
        id: String,
        from: String,
        to: Option<String>,
        relation: &'static str,
        document: &ArchiveDocument,
        description: &str,
        missing_reason: Option<&str>,
    ) {
        let is_hierarchy = relation == "contains" && id.contains(":hierarchy:");
        if !self.node_ids.contains(&from) {
            self.truncated = true;
            return;
        }
        let (counter, maximum) = if is_hierarchy {
            (self.hierarchy_edges, self.maximum_nodes)
        } else {
            (self.connection_edges, self.maximum_connection_edges)
        };
        if counter >= maximum {
            self.truncated = true;
            return;
        }
        if is_hierarchy {
            self.hierarchy_edges += 1;
        } else {
            self.connection_edges += 1;
        }
        let evidence = vec![investigation_evidence(document, description)];
        let edge = match to {
            Some(to) if self.node_ids.contains(&to) => InvestigationEdge::Observed {
                id,
                from,
                to,
                relation,
                evidence,
                limitations: Vec::new(),
            },
            to => {
                let reason = if to.is_some() {
                    self.truncated = true;
                    "endpoint_omitted_by_object_limit"
                } else {
                    missing_reason.unwrap_or("destination_unresolved")
                };
                InvestigationEdge::Unresolved {
                    id,
                    from,
                    to: None,
                    relation,
                    reason: reason.into(),
                    evidence,
                    limitations: Vec::new(),
                }
            }
        };
        self.edges.push(edge);
    }

    fn finish(self) -> InvestigationGraph {
        InvestigationGraph {
            target_sha256: self.target_sha256,
            provider: InvestigationGraphProvider {
                id: PROVIDER.id,
                version: PROVIDER.version.unwrap_or("1"),
                tool_version: TOOL_VERSION,
            },
            nodes: self.nodes,
            edges: self.edges,
            coverage: self.coverage,
            truncated: self.truncated,
        }
    }
}

fn object_graph_id(document: &ArchiveDocument, object_id: &str) -> String {
    graph_id(
        &document.relative_path,
        "object",
        &json!([object_id]).to_string(),
    )
}

fn investigation_evidence(document: &ArchiveDocument, description: &str) -> InvestigationEvidence {
    InvestigationEvidence {
        kind: "interface_builder_resource",
        description: description.to_owned(),
        location: empty_location(),
        artifact_path: document.relative_path.clone(),
        artifact_sha256: document.archive_sha256.clone(),
    }
}

fn empty_location() -> InvestigationLocation {
    InvestigationLocation {
        address: None,
        file_offset: None,
    }
}

fn graph_id(path: &str, kind: &str, parts_json: &str) -> String {
    format!("ib:{}:{kind}:{parts_json}", json!(path))
}

fn classify_object(class_name: Option<&str>) -> &'static str {
    let value = class_name.unwrap_or_default().to_ascii_lowercase();
    if value.contains("constraint") {
        "constraint"
    } else if value.contains("layoutguide") {
        "layout_guide"
    } else if value.contains("placeholder")
        || value.contains("firstresponder")
        || value == "uiproxyobject"
    {
        "placeholder"
    } else if value.contains("image") || value.contains("color") || value.contains("font") {
        "resource"
    } else if value.contains("external") {
        "external_object"
    } else if value.contains("viewcontroller") || value.contains("windowcontroller") {
        "view_controller"
    } else if value.contains("button")
        || value.contains("control")
        || value.contains("textfield")
        || value.contains("slider")
        || value.contains("menuitem")
    {
        "control"
    } else if value.contains("view") || value.contains("window") || value.contains("cell") {
        "view"
    } else {
        "unknown"
    }
}

fn classify_connection(relation: &str) -> &'static str {
    let value = relation.to_ascii_lowercase();
    if value.contains("outlet") {
        "outlet"
    } else if value.contains("action") || value.contains("eventconnection") {
        "action"
    } else if value.contains("segue") {
        "segue"
    } else {
        "other"
    }
}

fn ensure_evidence_fits_output_limit(
    bundle_path: &Path,
    evidence: &ArtifactEvidence,
) -> Result<(), Failure> {
    match json_output::admitted_length(evidence, MAX_OUTPUT_BYTES) {
        Ok(_) => Ok(()),
        Err(json_output::Error::Limit { maximum }) => Err(resource_failure(
            bundle_path,
            format!("serialized Interface Builder Evidence exceeds {maximum} bytes"),
        )),
        Err(json_output::Error::Encoding(error)) => {
            Err(bundle_failure(bundle_path, error.to_string()))
        }
    }
}

fn validate_request(
    bundle_path: &Path,
    target_sha256: &str,
    limits: &InterfaceBuilderLimits,
    cancellation: &Cancellation,
) -> Result<(), Failure> {
    ensure_active(cancellation)?;
    if !bundle_path.is_absolute() || bundle_path.to_string_lossy().contains('\0') {
        return Err(input_failure(
            bundle_path,
            "invalid_value",
            "bundle_path must be an absolute local filesystem path".into(),
        ));
    }
    if !is_sha256(target_sha256) {
        return Err(input_failure(
            bundle_path,
            "invalid_format",
            "target_sha256 must be 64 lowercase hexadecimal characters".into(),
        ));
    }
    if limits.max_documents == 0 || limits.max_documents > MAX_DOCUMENTS {
        return Err(input_failure(
            bundle_path,
            "invalid_value",
            format!("max_documents must be between 1 and {MAX_DOCUMENTS}"),
        ));
    }
    if limits.max_objects == 0 || limits.max_objects > MAX_OBJECTS {
        return Err(input_failure(
            bundle_path,
            "invalid_value",
            format!("max_objects must be between 1 and {MAX_OBJECTS}"),
        ));
    }
    if limits.max_connections == 0 || limits.max_connections > MAX_CONNECTIONS {
        return Err(input_failure(
            bundle_path,
            "invalid_value",
            format!("max_connections must be between 1 and {MAX_CONNECTIONS}"),
        ));
    }
    Ok(())
}

fn select_candidates(
    entries: Vec<stable_directory::DirectoryEntry>,
    max_documents: usize,
) -> CandidateSelection {
    let mut candidates = entries
        .into_iter()
        .filter(|entry| {
            entry.kind == DirectoryEntryKind::Regular
                && entry.path.to_ascii_lowercase().ends_with(".nib")
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    let total = candidates.len();
    let omitted_samples = candidates
        .iter()
        .skip(max_documents)
        .take(MAX_REPORTED_OMISSIONS)
        .cloned()
        .collect();
    candidates.truncate(max_documents);

    CandidateSelection {
        selected: candidates,
        omitted_samples,
        total,
    }
}

fn decode_entry(
    reader: &stable_directory::DirectoryReader,
    entry: &stable_directory::DirectoryEntry,
    remaining_input_bytes: usize,
    limits: &InterfaceBuilderLimits,
    cancellation: &Cancellation,
) -> Result<DecodeSummary, Failure> {
    let mut file = reader
        .open_entry(entry, cancellation)
        .map_err(|error| directory_failure(Path::new(&reader.root().canonical_path), error))?;
    let bytes = match file.read_bounded(remaining_input_bytes, cancellation) {
        Ok(bytes) => bytes,
        Err(stable_directory::DirectoryError::LimitBytes { .. }) => {
            return Ok(DecodeSummary {
                document: None,
                invalid_reason: None,
                omitted_reason: Some("aggregate_decode_budget_exhausted".into()),
                input_bytes_read: remaining_input_bytes,
            });
        }
        Err(error) => {
            return Err(directory_failure(
                Path::new(&reader.root().canonical_path),
                error,
            ));
        }
    };
    let sha256 = hex_digest(&bytes);

    if bytes.starts_with(b"NIBArchive") {
        let mut result = decode_nib_archive(entry, &bytes, sha256, limits)?;
        result.input_bytes_read = bytes.len();
        return Ok(result);
    }

    match plist::read_with_provenance(&bytes, entry.path.clone()) {
        Ok(decoded) => {
            let archive_format = plist_format(&bytes);
            let is_keyed_archive = decoded
                .report
                .value
                .get("$archiver")
                .and_then(Value::as_str)
                == Some("NSKeyedArchiver");
            // A keyed archive is projected from its object table; its
            // coverage is carried by the projection, and the decoder's
            // generic plist notices are not document limitations.
            let keyed_projection = if is_keyed_archive {
                interface_builder_keyed_archive::project(
                    entry.path.clone(),
                    &sha256,
                    &decoded.report.value,
                    &decoded.binary_uid_paths,
                    &projection_limits(limits),
                )
            } else {
                None
            };
            let keyed_unprojected = is_keyed_archive && keyed_projection.is_none();
            let mut limitations = if keyed_projection.is_some() {
                Vec::new()
            } else {
                decoded.report.limitations.clone()
            };
            let projection = keyed_projection.unwrap_or_else(|| {
                interface_builder::project_value(
                    entry.path.clone(),
                    &sha256,
                    &decoded.report.value,
                    projection_limits(limits),
                )
            });
            if keyed_unprojected {
                limitations.push(
                    "The NSKeyedArchiver object table or class graph could not be projected; decoded plist data is retained.".into(),
                );
            }

            let decoded_value = serde_json::to_value(decoded.report)
                .map_err(|error| bundle_failure(Path::new(&entry.path), error.to_string()))?;
            Ok(DecodeSummary {
                document: Some(ArchiveDocument {
                    relative_path: entry.path.clone(),
                    archive_sha256: sha256,
                    archive_format,
                    decoded: decoded_value,
                    projection: Some(projection),
                    limitations,
                }),
                invalid_reason: None,
                omitted_reason: None,
                input_bytes_read: bytes.len(),
            })
        }
        Err(plist::Error::InputTooLarge) => Ok(DecodeSummary {
            document: None,
            invalid_reason: None,
            omitted_reason: Some("aggregate_decode_budget_exhausted".into()),
            input_bytes_read: bytes.len(),
        }),
        Err(error) => Ok(DecodeSummary {
            document: None,
            invalid_reason: Some(error.to_string()),
            omitted_reason: None,
            input_bytes_read: bytes.len(),
        }),
    }
}

fn decode_nib_archive(
    entry: &stable_directory::DirectoryEntry,
    bytes: &[u8],
    sha256: String,
    limits: &InterfaceBuilderLimits,
) -> Result<DecodeSummary, Failure> {
    let archive = match nib::decode_nib_archive(bytes) {
        Ok(archive) => archive,
        Err(nib::NibArchiveError::Malformed(reason)) => {
            return Ok(DecodeSummary {
                document: None,
                invalid_reason: Some(reason),
                omitted_reason: None,
                input_bytes_read: 0,
            });
        }
        Err(nib::NibArchiveError::Limit { message, .. }) => {
            return Ok(DecodeSummary {
                document: None,
                invalid_reason: None,
                omitted_reason: Some(message),
                input_bytes_read: 0,
            });
        }
    };

    let decoded = serde_json::to_value(&archive)
        .map_err(|error| bundle_failure(Path::new(&entry.path), error.to_string()))?;
    let nib_projection = nib_projection_value(&archive, limits);
    let mut projection = interface_builder::project_value(
        entry.path.clone(),
        &sha256,
        &nib_projection.value,
        projection_limits(limits),
    );
    apply_nib_projection_coverage(&mut projection, &nib_projection);
    // NIBArchive hierarchy and connector omissions are surfaced once at the
    // bundle level from the projection coverage, matching the oracle. The
    // decoder does not attach per-document limitation strings to the output.
    Ok(DecodeSummary {
        document: Some(ArchiveDocument {
            relative_path: entry.path.clone(),
            archive_sha256: sha256,
            archive_format: ArchiveFormat::NibArchive,
            decoded,
            projection: Some(projection),
            limitations: Vec::new(),
        }),
        invalid_reason: None,
        omitted_reason: None,
        input_bytes_read: 0,
    })
}

fn apply_nib_projection_coverage(
    projection: &mut interface_builder::InterfaceBuilderProjection,
    nib_projection: &NibProjection,
) {
    // Unresolved connectors carry no connection record, so they are an omission
    // rather than an examined connection; the coverage facet and the document
    // connection count fold them in from `unresolved_connections`.
    projection.coverage.unresolved_connections = nib_projection.unresolved_connections;
    projection.coverage.hierarchy_nodes_omitted = projection
        .coverage
        .hierarchy_nodes_omitted
        .saturating_add(nib_projection.omitted_hierarchy);
    projection.coverage.partial = projection.coverage.partial
        || nib_projection.unresolved_connections > 0
        || nib_projection.omitted_hierarchy > 0;
}

fn nib_projection_value(
    archive: &nib::NibArchiveDocument,
    limits: &InterfaceBuilderLimits,
) -> NibProjection {
    let objects_by_id = archive
        .objects
        .iter()
        .map(|object| (u64::from(object.id), object))
        .collect::<BTreeMap<_, _>>();
    let hierarchy_objects = archive
        .objects
        .iter()
        .map(|object| nib_view_hierarchy::NibObject {
            id: u64::from(object.id),
            class_name: object.class_name.clone(),
            values: object.values.clone().into_iter().collect(),
        })
        .collect::<Vec<_>>();
    let mut objects = Map::new();
    let mut connections: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut decoded_strings = BTreeMap::new();
    let mut runtime_classes = BTreeMap::new();
    // Object and connection projection are independent passes over the same
    // objects: a class that both carries authored fields and declares a
    // connection (e.g. NSIBHelpConnector) contributes to both dictionaries.
    for object in &archive.objects {
        let object_id = object.id.to_string();
        let stored_class = normalize_nib_class_name(&object.class_name);
        let class_name = nib_runtime_class(
            object,
            &stored_class,
            &objects_by_id,
            &mut decoded_strings,
            &mut runtime_classes,
        );
        if !is_projection_object(&class_name) {
            continue;
        }

        // The first label-like field that resolves to a string names the
        // object; a label-like field holding another value is skipped.
        let label = object
            .values
            .iter()
            .filter(|(key, _)| contains_label_key(key))
            .find_map(|(_, value)| {
                resolve_nib_field(value, &objects_by_id, &mut decoded_strings)
                    .and_then(|value| value.as_str().map(str::to_owned))
            })
            .unwrap_or_else(|| class_name.clone());

        let mut nib_values = Map::new();
        for (key, value) in &object.values {
            nib_values.insert(
                key.clone(),
                resolve_nib_field(value, &objects_by_id, &mut decoded_strings)
                    .unwrap_or(Value::Null),
            );
        }
        let resource_fields = apple::asset_catalog::apple_resource_key_fields(&nib_values);
        let mut fields = Map::new();
        fields.insert("customClass".into(), json!(class_name));
        fields.insert("label".into(), json!(label));
        fields.insert("objectID".into(), json!(object_id));
        fields.insert("nibValues".into(), Value::Object(nib_values));
        for (name, value) in resource_fields {
            fields.insert(name, Value::String(value));
        }
        objects.insert(object_id, Value::Object(fields));
    }

    // Connections use the stored (serialized) class name: AppKit connectors use
    // NS-prefixed endpoint keys, UIKit runtime connections use UI-prefixed keys.
    let mut unresolved_connections = 0;
    for object in &archive.objects {
        let stored_class = normalize_nib_class_name(&object.class_name);
        if !is_connection_class(&stored_class) {
            continue;
        }
        if !project_nib_connection(
            object,
            &stored_class,
            &objects_by_id,
            &mut decoded_strings,
            &mut connections,
        ) {
            unresolved_connections += 1;
        }
    }

    let retained_ids = objects
        .keys()
        .filter_map(|id| id.parse::<u64>().ok())
        .collect::<BTreeSet<_>>();
    let mut hierarchy_omitted = 0;
    let mut hierarchy_node_count = 0;
    let mut hierarchy_roots = Vec::new();
    let ib_data = archive
        .objects
        .iter()
        .find(|object| normalize_nib_class_name(&object.class_name) == "NSIBObjectData");
    if let Some(root_id) = ib_data
        .and_then(|object| object.values.get("NSRoot"))
        .and_then(nib_reference_from_value)
    {
        if let Some(root) = build_legacy_nib_hierarchy(
            root_id,
            0,
            &BTreeSet::new(),
            &objects_by_id,
            &mut hierarchy_node_count,
            &mut hierarchy_omitted,
            limits.max_objects,
        ) {
            hierarchy_roots.push(root);
        }
    }

    let view_hierarchy = nib_view_hierarchy::project_nib_view_hierarchy(
        &hierarchy_objects,
        &retained_ids,
        || true,
        limits.max_objects,
    );
    let merged_hierarchy = nib_view_hierarchy::merge_nib_hierarchies(
        &mut hierarchy_roots,
        view_hierarchy.hierarchy.as_deref().unwrap_or_default(),
        || true,
        limits.max_objects,
    );
    hierarchy_omitted = hierarchy_omitted
        .saturating_add(view_hierarchy.omitted)
        .saturating_add(merged_hierarchy.omitted);

    let mut classes = Map::new();
    for name in &archive.classes {
        classes.insert(normalize_nib_class_name(name), json!({}));
    }

    NibProjection {
        value: json!({
            "com.apple.ibtool.document.objects": objects,
            "com.apple.ibtool.document.connections": connections,
            "com.apple.ibtool.document.hierarchy": merged_hierarchy.hierarchy,
            "com.apple.ibtool.document.classes": classes,
        }),
        unresolved_connections,
        omitted_hierarchy: hierarchy_omitted,
    }
}

#[derive(Debug)]
struct NibProjection {
    value: Value,
    unresolved_connections: usize,
    omitted_hierarchy: usize,
}

fn normalize_nib_class_name(value: &str) -> String {
    value.trim_end_matches('\0').to_owned()
}

fn nib_runtime_class(
    object: &nib::NibObject,
    stored_class: &str,
    objects_by_id: &BTreeMap<u64, &nib::NibObject>,
    decoded_strings: &mut BTreeMap<u64, Option<String>>,
    runtime_classes: &mut BTreeMap<u64, String>,
) -> String {
    if let Some(class_name) = runtime_classes.get(&u64::from(object.id)) {
        return class_name.clone();
    }

    let class_field = match stored_class {
        "NSClassSwapper" => Some("NSClassName"),
        "UIClassSwapper" => Some("UIClassName"),
        _ => None,
    };
    let resolved = class_field
        .and_then(|field| object.values.get(field))
        .and_then(nib_reference_from_value)
        .and_then(|reference| {
            let target = objects_by_id.get(&reference)?;
            (normalize_nib_class_name(&target.class_name) == "NSString")
                .then(|| decode_nib_string(reference, target, decoded_strings))
                .flatten()
        })
        .unwrap_or_else(|| stored_class.to_owned());

    runtime_classes.insert(u64::from(object.id), resolved.clone());
    resolved
}

fn decode_nib_string(
    object_id: u64,
    object: &nib::NibObject,
    decoded_strings: &mut BTreeMap<u64, Option<String>>,
) -> Option<String> {
    if let Some(value) = decoded_strings.get(&object_id) {
        return value.clone();
    }

    let encoded = object
        .values
        .get("NS.bytes")?
        .as_object()?
        .get("$nib_data_base64")?
        .as_str()?;
    let value = BASE64
        .decode(encoded)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    decoded_strings.insert(object_id, value.clone());
    value
}

fn resolve_nib_field(
    value: &Value,
    objects_by_id: &BTreeMap<u64, &nib::NibObject>,
    decoded_strings: &mut BTreeMap<u64, Option<String>>,
) -> Option<Value> {
    let Some(reference) = nib_reference_from_value(value) else {
        return Some(value.clone());
    };
    let target = objects_by_id.get(&reference)?;
    if normalize_nib_class_name(&target.class_name) == "NSString"
        && let Some(text) = decode_nib_string(reference, target, decoded_strings)
    {
        return Some(Value::String(text));
    }
    Some(json!({"objectID": reference.to_string()}))
}

fn nib_reference_from_value(value: &Value) -> Option<u64> {
    value.as_object()?.get("$nib_object_ref")?.as_u64()
}

fn build_legacy_nib_hierarchy(
    object_id: u64,
    depth: usize,
    ancestors: &BTreeSet<u64>,
    objects_by_id: &BTreeMap<u64, &nib::NibObject>,
    node_count: &mut usize,
    omitted: &mut usize,
    maximum_nodes: usize,
) -> Option<nib_view_hierarchy::NibHierarchyNode> {
    if depth > 32 || ancestors.contains(&object_id) || *node_count >= maximum_nodes {
        *omitted = omitted.saturating_add(1);
        return None;
    }
    let Some(object) = objects_by_id.get(&object_id) else {
        *omitted = omitted.saturating_add(1);
        return None;
    };

    *node_count += 1;
    let mut next_ancestors = ancestors.clone();
    next_ancestors.insert(object_id);
    let mut children = Vec::new();

    for (key, value) in &object.values {
        if !is_hierarchy_key(key) {
            continue;
        }
        let Some(reference) = nib_reference_from_value(value) else {
            continue;
        };
        let Some(target) = objects_by_id.get(&reference) else {
            *omitted = omitted.saturating_add(1);
            continue;
        };

        if is_nib_collection_class(&target.class_name) {
            for member in target.values.values() {
                if let Some(child_id) = nib_reference_from_value(member)
                    && let Some(child) = build_legacy_nib_hierarchy(
                        child_id,
                        depth + 1,
                        &next_ancestors,
                        objects_by_id,
                        node_count,
                        omitted,
                        maximum_nodes,
                    )
                {
                    children.push(child);
                }
            }
        } else if let Some(child) = build_legacy_nib_hierarchy(
            reference,
            depth + 1,
            &next_ancestors,
            objects_by_id,
            node_count,
            omitted,
            maximum_nodes,
        ) {
            children.push(child);
        }
    }

    Some(nib_view_hierarchy::NibHierarchyNode {
        object_id: object_id.to_string(),
        children,
    })
}

fn is_hierarchy_key(key: &str) -> bool {
    // Mirror the oracle regex `(?:subviews|contentview|childviewcontrollers|view)$`.
    let normalized = key.to_ascii_lowercase();
    ["subviews", "contentview", "childviewcontrollers", "view"]
        .iter()
        .any(|suffix| normalized.ends_with(suffix))
}

fn is_nib_collection_class(class_name: &str) -> bool {
    let name = normalize_nib_class_name(class_name).to_ascii_lowercase();
    name.contains("array") || name.contains("set")
}

fn project_nib_connection(
    object: &nib::NibObject,
    class_name: &str,
    objects_by_id: &BTreeMap<u64, &nib::NibObject>,
    decoded_strings: &mut BTreeMap<u64, Option<String>>,
    connections: &mut BTreeMap<String, Vec<Value>>,
) -> bool {
    let ui_class = class_name.starts_with("UIRuntime") && class_name.ends_with("Connection");
    let (source_key, destination_key, label_key) = if ui_class {
        ("UISource", "UIDestination", "UILabel")
    } else {
        ("NSSource", "NSDestination", "NSLabel")
    };
    let source = object
        .values
        .get(source_key)
        .and_then(nib_reference_from_value);
    let Some(source) = source else {
        return false;
    };
    let destination = object
        .values
        .get(destination_key)
        .and_then(nib_reference_from_value);
    let label = object
        .values
        .get(label_key)
        .and_then(|value| resolve_nib_field(value, objects_by_id, decoded_strings))
        .and_then(|value| value.as_str().map(str::to_owned));
    let relation = if class_name.contains("Outlet") {
        "outlet"
    } else if class_name.contains("Control") || class_name.contains("Event") {
        "action"
    } else {
        class_name
    };

    let mut connection = Map::new();
    connection.insert("type".into(), json!(relation));
    connection.insert(
        "destination-id".into(),
        destination
            .map(|id| json!(id.to_string()))
            .unwrap_or(Value::Null),
    );
    connection.insert(
        "label".into(),
        label.map(Value::String).unwrap_or(Value::Null),
    );
    connection.insert("source_id".into(), json!(source.to_string()));
    connection.insert("archive_object_id".into(), json!(object.id.to_string()));
    if let Some(event_mask) = object.values.get("UIEventMask").and_then(Value::as_number) {
        connection.insert("ui_event_mask".into(), Value::Number(event_mask.clone()));
    }
    connections
        .entry(source.to_string())
        .or_default()
        .push(Value::Object(connection));
    true
}

fn is_projection_object(class_name: &str) -> bool {
    // Mirror the oracle exclusion set: the base container and runtime classes,
    // the serialized NSNib connector classes, and UIKit runtime connections are
    // not authored objects. Other connector-bearing classes (e.g.
    // NSIBHelpConnector) still contribute an authored object.
    !matches!(
        class_name,
        "NSObject"
            | "NSIBObjectData"
            | "NSString"
            | "NSMutableString"
            | "NSNumber"
            | "NSArray"
            | "NSMutableArray"
            | "NSSet"
            | "NSMutableSet"
            | "NSDictionary"
            | "NSMutableDictionary"
            | "NSApplication"
    ) && !(class_name.starts_with("NSNib") && class_name.ends_with("Connector"))
        && !is_uikit_runtime_connection_class(class_name)
}

fn is_connection_class(class_name: &str) -> bool {
    class_name.contains("Connector") || is_uikit_runtime_connection_class(class_name)
}

/// UIKit runtime connection classes match `^UIRuntime\w*Connection$`.
fn is_uikit_runtime_connection_class(class_name: &str) -> bool {
    class_name.starts_with("UIRuntime")
        && class_name.ends_with("Connection")
        && class_name
            .get("UIRuntime".len()..class_name.len() - "Connection".len())
            .is_some_and(|middle| {
                middle
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
}

fn contains_label_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "title",
        "label",
        "identifier",
        "accessibility",
        "name",
        "contents",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn projection_limits(limits: &InterfaceBuilderLimits) -> interface_builder::ProjectionLimits {
    interface_builder::ProjectionLimits {
        max_objects: limits.max_objects,
        max_connections: limits.max_connections,
        max_hierarchy_nodes: limits.max_objects,
    }
}
fn plist_format(bytes: &[u8]) -> ArchiveFormat {
    if bytes.starts_with(b"bplist00") {
        ArchiveFormat::BinaryPlist
    } else if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| byte == b'{' || byte == b'(')
    {
        ArchiveFormat::OpenStepPlist
    } else {
        ArchiveFormat::XmlPlist
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn record_omission(
    relative_path: String,
    reason: String,
    reported: &mut Vec<OmittedArchive>,
    unreported: &mut usize,
) {
    if reported.len() < MAX_REPORTED_OMISSIONS {
        reported.push(OmittedArchive {
            relative_path,
            reason,
        });
    } else {
        *unreported = unreported.saturating_add(1);
    }
}

fn ensure_active(cancellation: &Cancellation) -> Result<(), Failure> {
    if let Some(reason) = cancellation.reason() {
        Err(Failure::new(
            "cancelled",
            "cancellation",
            "Interface Builder bundle inspection was cancelled.".into(),
            false,
            "Retry the selected bundle operation.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("reason", Detail::Text(reason.into())),
            ]),
        ))
    } else {
        Ok(())
    }
}

fn directory_failure(path: &Path, error: stable_directory::DirectoryError) -> Failure {
    match error {
        stable_directory::DirectoryError::Cancelled(reason) => Failure::new(
            "cancelled",
            "cancellation",
            "Interface Builder bundle inspection was cancelled.".into(),
            false,
            "Retry the selected bundle operation.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("reason", Detail::Text(reason)),
            ]),
        ),
        stable_directory::DirectoryError::Limit { maximum_entries } => Failure::new(
            "resource_limit",
            "resource_limit",
            "The selected app bundle contains too many directory entries to inspect safely.".into(),
            false,
            "Select a narrower app bundle.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("path", Detail::Text(path.to_string_lossy().into_owned())),
                ("maximum_entries", Detail::Count(maximum_entries as u64)),
            ]),
        ),
        other => bundle_failure(path, other.to_string()),
    }
}

fn input_failure(path: &Path, code: &'static str, reason: String) -> Failure {
    Failure::new(
        code,
        "input_validation",
        "Interface Builder bundle inspection received invalid input.".into(),
        false,
        "Correct the bundle path and target digest, then retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.to_string_lossy().into_owned())),
            ("reason", Detail::Text(reason)),
        ]),
    )
}

fn bundle_failure(path: &Path, reason: String) -> Failure {
    Failure::new(
        "execution_failed",
        "provider_execution",
        "Interface Builder bundle inspection could not complete.".into(),
        true,
        "Check access to the selected local bundle and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.to_string_lossy().into_owned())),
            ("reason", Detail::Text(reason)),
        ]),
    )
}

fn resource_failure(path: &Path, reason: String) -> Failure {
    Failure::new(
        "resource_limit",
        "resource_limit",
        "Interface Builder bundle inspection exceeded a supported resource bound.".into(),
        false,
        "Select a smaller bundle or request a narrower inspection.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.to_string_lossy().into_owned())),
            ("reason", Detail::Text(reason)),
            (
                "maximum_aggregate_input_bytes",
                Detail::Count(MAX_AGGREGATE_INPUT_BYTES as u64),
            ),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn bundle_walk_decodes_plist_archives_and_preserves_provenance() {
        let root = tempfile::tempdir().expect("temporary app bundle");
        let archive_path = root.path().join("Contents/Resources/Main.nib");
        fs::create_dir_all(archive_path.parent().expect("nib parent"))
            .expect("create bundle directories");
        fs::write(
            &archive_path,
            br#"<?xml version="1.0"?><plist version="1.0"><dict><key>com.apple.ibtool.document.objects</key><dict><key>root</key><dict><key>customClass</key><string>NSView</string><key>label</key><string>Main View</string></dict></dict></dict></plist>"#,
        )
        .expect("write XML archive");

        let evidence = inspect_bundle(root.path(), "a".repeat(64), &Cancellation::default())
            .expect("inspect app bundle");
        let report = serde_json::to_value(evidence).expect("Evidence serializes");
        let normalized = &report["normalized_result"];

        assert_eq!(report["operation"], OPERATION);
        assert_eq!(report["subject"]["format"], "directory");
        assert_eq!(normalized["documents"].as_array().unwrap().len(), 1);
        assert_eq!(
            normalized["documents"][0]["relative_path"],
            "Contents/Resources/Main.nib"
        );
        assert_eq!(normalized["target_sha256"], "a".repeat(64));
        assert_eq!(normalized["graph"]["provider"]["id"], "rea-artifact-graph");
        assert!(
            normalized["graph"]["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|node| node["name"] == "Main View")
        );
    }

    #[test]
    fn bundle_walk_projects_xml_keyed_archive_uid_relationships() {
        let root = tempfile::tempdir().expect("temporary app bundle");
        let archive_path = root.path().join("Contents/Resources/Main.nib");
        fs::create_dir_all(archive_path.parent().expect("nib parent"))
            .expect("create bundle directories");
        fs::write(
            &archive_path,
            br#"<?xml version="1.0"?><plist version="1.0"><dict>
                <key>$archiver</key><string>NSKeyedArchiver</string>
                <key>$objects</key><array>
                    <string>$null</string>
                    <dict><key>$class</key><dict><key>CF$UID</key><integer>2</integer></dict><key>objectID</key><string>root-id</string><key>title</key><string>Root</string><key>subviews</key><array><dict><key>CF$UID</key><integer>3</integer></dict></array></dict>
                    <dict><key>$classname</key><string>UIView</string><key>$classes</key><array><string>UIView</string><string>NSObject</string></array></dict>
                    <dict><key>$class</key><dict><key>CF$UID</key><integer>4</integer></dict><key>objectID</key><string>child-id</string><key>title</key><string>Child</string></dict>
                    <dict><key>$classname</key><string>UIButton</string><key>$classes</key><array><string>UIButton</string><string>UIView</string><string>NSObject</string></array></dict>
                </array>
                <key>$top</key><dict><key>root</key><dict><key>CF$UID</key><integer>1</integer></dict></dict>
            </dict></plist>"#,
        )
        .expect("write keyed archive");

        let evidence = inspect_bundle(root.path(), "a".repeat(64), &Cancellation::default())
            .expect("inspect app bundle");
        let report = serde_json::to_value(evidence).expect("Evidence serializes");
        let graph = &report["normalized_result"]["graph"];
        let object_ids = graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|node| node["attributes"]["interface_builder_object_id"].as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(object_ids, BTreeSet::from(["child-id", "root-id"]));
        assert!(
            graph["edges"]
                .as_array()
                .unwrap()
                .iter()
                .any(|edge| { edge["resolution"] == "observed" && edge["relation"] == "contains" })
        );
        assert_eq!(
            report["locations"][0]["path"],
            "Contents/Resources/Main.nib"
        );
    }

    #[test]
    fn archive_selection_is_lexical_and_reports_bounded_omissions() {
        let root = tempfile::tempdir().expect("temporary app bundle");
        for name in ["z.nib", "b.nib", "a.nib"] {
            fs::write(root.path().join(name), b"not a supported archive")
                .expect("write archive candidate");
        }

        let mut entries = stable_directory::DirectoryReader::open(root.path())
            .expect("open bundle")
            .entries(MAX_DIRECTORY_ENTRIES, &Cancellation::default())
            .expect("enumerate bundle");
        entries.retain(|entry| entry.kind == DirectoryEntryKind::Regular);
        let selection = select_candidates(entries, MAX_DOCUMENTS);

        assert_eq!(selection.total, 3);
        assert_eq!(selection.selected[0].path, "a.nib");
        assert_eq!(selection.selected[1].path, "b.nib");
        assert_eq!(selection.selected[2].path, "z.nib");
        assert!(selection.omitted_samples.is_empty());
    }

    #[test]
    fn invalid_target_digest_is_rejected_before_directory_access() {
        let error = inspect_bundle(
            Path::new("/missing/My.app"),
            "ABC".into(),
            &Cancellation::default(),
        )
        .expect_err("invalid digest should fail before opening the path");
        let encoded = serde_json::to_value(error).expect("failure serializes");
        assert_eq!(encoded["code"], "invalid_format");
    }

    #[test]
    fn nib_projection_resolves_class_swappers_strings_connections_and_hierarchy() {
        let archive = nib::NibArchiveDocument {
            format_version: 1,
            coder_version: 1,
            object_count: 8,
            connection_object_count: 1,
            objects: vec![
                nib_object(0, "NSIBObjectData", [("NSRoot", nib_reference(1))]),
                nib_object(1, "NSView", [("NSSubviews", nib_reference(2))]),
                nib_object(2, "NSArray", [("0", nib_reference(3))]),
                nib_object(
                    3,
                    "NSClassSwapper",
                    [
                        ("NSClassName", nib_reference(5)),
                        ("title", nib_reference(6)),
                        ("NSSuperview", nib_reference(1)),
                    ],
                ),
                nib_object(
                    4,
                    "NSNibControlConnector",
                    [
                        ("NSSource", nib_reference(3)),
                        ("NSDestination", Value::Null),
                        ("NSLabel", nib_reference(6)),
                        ("UIEventMask", json!(3)),
                    ],
                ),
                nib_string(5, "FancyButton"),
                nib_string(6, "Open"),
                nib_object(7, "NSObject", []),
            ],
            classes: vec![
                "NSIBObjectData".into(),
                "NSView".into(),
                "NSArray".into(),
                "NSClassSwapper".into(),
                "NSNibControlConnector".into(),
                "NSString".into(),
            ],
            limitations: Vec::new(),
        };

        let limits = InterfaceBuilderLimits::default();
        let projection = nib_projection_value(&archive, &limits);
        let facts = interface_builder::project_value(
            "Main.nib".into(),
            &"a".repeat(64),
            &projection.value,
            projection_limits(&limits),
        );

        let button = facts
            .objects
            .iter()
            .find(|object| object.id == "3")
            .expect("class-swapped view object is projected");
        assert_eq!(button.class_name.as_deref(), Some("FancyButton"));
        assert_eq!(button.label.as_deref(), Some("FancyButton"));
        assert_eq!(button.attributes["nibValues"]["title"], "Open");

        assert_eq!(facts.connections.len(), 1);
        assert_eq!(facts.connections[0].source_id, "3");
        assert_eq!(facts.connections[0].relation, "action");
        assert_eq!(facts.connections[0].label.as_deref(), Some("Open"));
        assert_eq!(facts.connections[0].evidence.archive_path, "Main.nib");

        assert!(
            facts
                .hierarchy
                .iter()
                .any(|link| link.parent_id.as_deref() == Some("1") && link.child_id == "3")
        );
        assert_eq!(projection.unresolved_connections, 0);
        // The button's `NSSuperview` back-reference revisits the root, which
        // the oracle's cycle guard counts as one omitted hierarchy link.
        assert_eq!(projection.omitted_hierarchy, 1);
    }

    #[test]
    fn nib_projection_coverage_includes_unresolved_connections_and_archived_omissions() {
        let limits = InterfaceBuilderLimits::default();
        let mut projection = interface_builder::project_value(
            "Main.nib".into(),
            &"a".repeat(64),
            &json!({}),
            projection_limits(&limits),
        );
        let nib_projection = NibProjection {
            value: json!({}),
            unresolved_connections: 2,
            omitted_hierarchy: 3,
        };

        apply_nib_projection_coverage(&mut projection, &nib_projection);

        // Unresolved connectors are an omission, not an examined connection:
        // the examined count is untouched and they are tracked separately.
        assert_eq!(projection.coverage.connections_examined, 0);
        assert_eq!(projection.coverage.unresolved_connections, 2);
        assert_eq!(projection.coverage.hierarchy_nodes_omitted, 3);
        assert!(projection.coverage.partial);
    }

    fn nib_object<const N: usize>(
        id: u32,
        class_name: &str,
        values: [(&str, Value); N],
    ) -> nib::NibObject {
        nib::NibObject {
            id,
            class_name: class_name.into(),
            values: values
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        }
    }

    fn nib_reference(id: u64) -> Value {
        json!({"$nib_object_ref": id})
    }

    fn nib_string(id: u32, value: &str) -> nib::NibObject {
        nib_object(
            id,
            "NSString",
            [(
                "NS.bytes",
                json!({"$nib_data_base64": BASE64.encode(value)}),
            )],
        )
    }
}
