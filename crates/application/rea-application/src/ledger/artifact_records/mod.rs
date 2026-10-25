//! Session retention for authenticated Evidence records and unknown histories.
use rea_core::failure::{Detail, Failure, InputIssue};
use rea_core::{
    canonical_json,
    evidence::ArtifactEvidence,
    evidence::bundle::{EvidenceBundle, EvidenceBundleError},
    evidence::record::{EvidenceRecord, EvidenceRecordError, EvidenceRecordMetadata},
    residual_unknown::{ResidualUnknown, ResidualUnknownError, validate_histories},
};
use serde::Serialize;
use serde_json::value::RawValue;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

mod unknown_mutation;

pub const OPERATION: &str = "get_evidence_bundle";
#[derive(Default)]
pub enum DetailLevel {
    #[default]
    Complete,
    Summary,
}
#[derive(Default)]
pub struct Query {
    pub detail: DetailLevel,
    pub filters: Option<Filters>,
}
fn invalid_issue(issue: InputIssue) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid. Check the arguments and try again.".into(),
        true,
        "Correct the listed arguments and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("issues", Detail::Issues(vec![issue])),
        ]),
    )
}
impl Query {
    pub fn validate(&self) -> Result<(), Failure> {
        if matches!(self.detail, DetailLevel::Complete) && self.filters.is_some() {
            return Err(invalid_issue(InputIssue {
                path: vec!["filters".into()],
                reason: "invalid_value",
                message:
                    "Record filters require detail: summary; complete returns the canonical bundle."
                        .into(),
                expected: Some("detail: summary"),
            }));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum RecordError {
    Poisoned,
    Conflict,
    UnknownMutation(UnknownMutationFailure),
    Canonical(canonical_json::Error),
    Evidence(EvidenceRecordError),
    Unknown(ResidualUnknownError),
    Bundle(EvidenceBundleError),
    Encoding(serde_json::Error),
}
impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poisoned => f.write_str("Retained Evidence ledger poisoned"),
            Self::Conflict => f.write_str("Conflicting Evidence record or unknown revision"),
            Self::UnknownMutation(reason) => reason.fmt(f),
            Self::Canonical(error) => error.fmt(f),
            Self::Evidence(error) => error.fmt(f),
            Self::Unknown(error) => error.fmt(f),
            Self::Bundle(error) => error.fmt(f),
            Self::Encoding(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for RecordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Evidence(error) => Some(error),
            Self::Unknown(error) => Some(error),
            Self::Bundle(error) => Some(error),
            Self::Encoding(error) => Some(error),
            Self::Conflict | Self::UnknownMutation(_) | Self::Poisoned => None,
        }
    }
}
impl RecordError {
    pub fn into_failure(self) -> Failure {
        self.into_failure_for(OPERATION)
    }

    #[cfg(unix)]
    pub fn into_import_failure(self) -> Failure {
        self.into_failure_for(crate::ledger::bundle_import::OPERATION)
    }

    #[cfg(unix)]
    pub fn into_export_failure(self) -> Failure {
        self.into_failure_for(crate::ledger::bundle_export::OPERATION)
    }

    pub fn into_record_unknown_failure(self) -> Failure {
        self.into_failure_for("record_unknown")
    }

    pub fn into_update_unknown_failure(self) -> Failure {
        self.into_failure_for("update_unknown")
    }

    pub fn into_verify_reconstruction_failure(self) -> Failure {
        self.into_failure_for("verify_reconstruction")
    }

    fn into_failure_for(self, operation: &'static str) -> Failure {
        match self {
            Self::UnknownMutation(reason) => reason.into_failure(operation),
            error => {
                let message =
                    "Evidence is invalid or has changed. Recreate or re-import it, then try again.";
                Failure::new(
                    "evidence_integrity_mismatch",
                    "integrity_mismatch",
                    message.into(),
                    true,
                    message.into(),
                    BTreeMap::from([
                        ("operation", Detail::Text(operation.into())),
                        ("reason", Detail::Text(error.to_string())),
                    ]),
                )
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum UnknownMutationFailure {
    NotFound,
    AlreadyExists,
    RevisionConflict,
    InvalidTransition,
    Integrity,
}

impl fmt::Display for UnknownMutationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "not-found",
            Self::AlreadyExists => "already-exists",
            Self::RevisionConflict => "revision-conflict",
            Self::InvalidTransition => "invalid-transition",
            Self::Integrity => "integrity",
        })
    }
}

impl UnknownMutationFailure {
    fn into_failure(self, operation: &'static str) -> Failure {
        let (code, category, message, retryable, action) = match self {
            Self::NotFound => (
                "execution_failure",
                "execution_failure",
                "The requested residual unknown does not exist in this session.",
                false,
                "Check that the unknown_id belongs to this session, then retry.",
            ),
            Self::AlreadyExists | Self::RevisionConflict => (
                "revision_conflict",
                "execution_failure",
                "Evidence state changed before the update completed.",
                true,
                "Refresh the current state and try again.",
            ),
            Self::InvalidTransition => (
                "execution_failure",
                "execution_failure",
                "The residual unknown could not be updated from its current state.",
                false,
                "Review the current unknown and its Evidence references before retrying.",
            ),
            Self::Integrity => (
                "evidence_integrity_mismatch",
                "integrity_mismatch",
                "Evidence state is invalid or has changed.",
                true,
                "Recreate or re-import the Evidence, then try again.",
            ),
        };
        Failure::new(
            code,
            category,
            message.into(),
            retryable,
            action.into(),
            BTreeMap::from([
                ("operation", Detail::Text(operation.into())),
                ("reason", Detail::Text(self.to_string())),
            ]),
        )
    }
}

#[derive(Default)]
struct Ledger {
    records: BTreeMap<String, Arc<EvidenceRecord>>,
    unknowns: BTreeMap<(String, u64), Arc<ResidualUnknown>>,
}

#[derive(Default)]
pub struct ArtifactRecords {
    ledger: Mutex<Ledger>,
}
impl ArtifactRecords {
    /// Authenticate and retain a complete provider-neutral Evidence record.
    pub fn record_raw(&self, raw: &RawValue) -> Result<(), RecordError> {
        self.record_validated(Arc::new(
            EvidenceRecord::parse(raw).map_err(RecordError::Evidence)?,
        ))
    }

    /// Preserve the first record's display metadata on idempotent recording.
    pub(crate) fn record(&self, evidence: Arc<ArtifactEvidence>) -> Result<(), RecordError> {
        let raw =
            serde_json::value::to_raw_value(evidence.as_ref()).map_err(RecordError::Encoding)?;
        let record = EvidenceRecord::parse(&raw).map_err(RecordError::Evidence)?;
        self.record_validated(Arc::new(record))
    }

    fn record_validated(&self, evidence: Arc<EvidenceRecord>) -> Result<(), RecordError> {
        let mut ledger = self.ledger.lock().map_err(|_| RecordError::Poisoned)?;
        if let Some(existing) = ledger.records.get(evidence.evidence_id()) {
            if Arc::ptr_eq(existing, &evidence)
                || existing.agrees(&evidence).map_err(RecordError::Evidence)?
            {
                return Ok(());
            }
            return Err(RecordError::Conflict);
        }
        ledger
            .records
            .insert(evidence.evidence_id().to_owned(), evidence);
        Ok(())
    }

    /// Validate the complete candidate state, then atomically merge it.
    pub fn import(&self, bundle: EvidenceBundle) -> Result<ImportReceipt, RecordError> {
        let mut ledger = self.ledger.lock().map_err(|_| RecordError::Poisoned)?;
        let plan = ImportPlan::prepare(&ledger, &bundle)?;
        Ok(plan.commit(&mut ledger, bundle))
    }

    /// Take a stable immutable view independently of provider/file execution.
    pub fn snapshot(&self) -> Result<RecordSnapshot, RecordError> {
        let ledger = self.ledger.lock().map_err(|_| RecordError::Poisoned)?;
        Ok(RecordSnapshot {
            records: ledger.records.values().cloned().collect(),
            unknowns: ledger.unknowns.values().cloned().collect(),
        })
    }

    /// Resolve one authenticated retained record without exposing the ledger lock.
    pub fn find_raw(&self, evidence_id: &str) -> Result<Option<Box<RawValue>>, RecordError> {
        let ledger = self.ledger.lock().map_err(|_| RecordError::Poisoned)?;
        ledger
            .records
            .get(evidence_id)
            .map(|record| copy_manifest(record.raw()))
            .transpose()
    }
}

#[derive(Clone, Copy)]
enum RecordMerge {
    Keep,
    Store,
}

struct ImportPlan {
    record_merges: Vec<RecordMerge>,
    unknowns_to_add: Vec<bool>,
    imported: usize,
    unknowns_added: usize,
    metadata_changed: bool,
}

impl ImportPlan {
    fn prepare(ledger: &Ledger, bundle: &EvidenceBundle) -> Result<Self, RecordError> {
        let mut candidate_records = ledger
            .records
            .iter()
            .map(|(id, record)| (id.as_str(), record.as_ref()))
            .collect::<BTreeMap<_, _>>();
        let mut candidate_unknowns = ledger
            .unknowns
            .iter()
            .map(|(key, unknown)| (key.clone(), unknown.as_ref()))
            .collect::<BTreeMap<_, _>>();

        let mut record_merges = Vec::with_capacity(bundle.records().len());
        let mut imported = 0;
        let mut metadata_changed = false;
        for incoming in bundle.records() {
            match candidate_records.get(incoming.evidence_id()).copied() {
                Some(existing) => {
                    if !existing.agrees(incoming).map_err(RecordError::Evidence)? {
                        return Err(RecordError::Conflict);
                    }

                    if canonical_record(existing)? == canonical_record(incoming)? {
                        record_merges.push(RecordMerge::Keep);
                    } else {
                        record_merges.push(RecordMerge::Store);
                        candidate_records.insert(incoming.evidence_id(), incoming);
                        metadata_changed = true;
                    }
                }
                None => {
                    record_merges.push(RecordMerge::Store);
                    candidate_records.insert(incoming.evidence_id(), incoming);
                    imported += 1;
                }
            }
        }

        let mut unknowns_to_add = Vec::with_capacity(bundle.unknowns().len());
        let mut unknowns_added = 0;
        for incoming in bundle.unknowns() {
            let key = (incoming.unknown_id().to_owned(), incoming.revision());
            match candidate_unknowns.get(&key) {
                Some(existing) if existing.revision_digest() != incoming.revision_digest() => {
                    return Err(RecordError::Conflict);
                }
                Some(_) => unknowns_to_add.push(false),
                None => {
                    candidate_unknowns.insert(key, incoming);
                    unknowns_to_add.push(true);
                    unknowns_added += 1;
                }
            }
        }

        validate_histories(
            candidate_unknowns.values().copied(),
            candidate_records.values().copied(),
        )
        .map_err(RecordError::Unknown)?;

        Ok(Self {
            record_merges,
            unknowns_to_add,
            imported,
            unknowns_added,
            metadata_changed,
        })
    }

    fn commit(self, ledger: &mut Ledger, bundle: EvidenceBundle) -> ImportReceipt {
        let (records, unknowns) = bundle.into_parts();

        for (record, merge) in records.into_iter().zip(self.record_merges) {
            if let RecordMerge::Store = merge {
                ledger
                    .records
                    .insert(record.evidence_id().to_owned(), Arc::new(record));
            }
        }

        for (unknown, should_add) in unknowns.into_iter().zip(self.unknowns_to_add) {
            if should_add {
                ledger.unknowns.insert(
                    (unknown.unknown_id().to_owned(), unknown.revision()),
                    Arc::new(unknown),
                );
            }
        }

        ImportReceipt {
            imported: self.imported,
            unknowns_added: self.unknowns_added,
            total: ledger.records.len(),
            metadata_changed: self.metadata_changed,
        }
    }
}

pub struct RecordSnapshot {
    records: Vec<Arc<EvidenceRecord>>,
    unknowns: Vec<Arc<ResidualUnknown>>,
}

/// Filters and paging for current residual-unknown heads.
#[derive(Debug, Default)]
pub struct UnknownQuery {
    /// Exact current status.
    pub status: Option<String>,
    /// Exact current severity.
    pub severity: Option<String>,
    /// Exact current domain after caller-side trimming.
    pub domain: Option<String>,
    /// Zero-based offset in stable unknown ID order.
    pub offset: u64,
    /// Optional maximum number of matching heads.
    pub limit: Option<u64>,
}

/// One stable page of current residual-unknown heads.
#[derive(Serialize)]
pub struct UnknownPage<'a> {
    /// Complete current heads in deterministic ID order.
    pub items: Vec<&'a ResidualUnknown>,
    /// Number of heads matching the filters.
    pub total: usize,
    /// Requested zero-based offset.
    pub offset: u64,
    /// Next page offset, or null when the page is complete.
    pub next_offset: Option<u64>,
}

/// Registry consistency facts for one authenticated current revision.
#[derive(Serialize)]
pub struct UnknownResolutionCheck<'a> {
    /// Whether the current revision is in resolved status.
    pub valid: bool,
    /// Whether the resolution makes an evidence-qualified truth claim.
    #[serde(rename = "truthVerified")]
    pub truth_verified: bool,
    /// Complete authenticated current revision.
    pub unknown: &'a ResidualUnknown,
}

impl RecordSnapshot {
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn unknown_revision_count(&self) -> usize {
        self.unknowns.len()
    }

    /// Return current heads in stable ID order without copying their payloads.
    pub fn list_unknowns_page(&self, query: &UnknownQuery) -> UnknownPage<'_> {
        let heads = self.unknown_heads();
        let mut items = Vec::new();
        let mut total = 0_u64;

        for unknown in heads.values().copied() {
            if !matches_unknown_query(unknown, query) {
                continue;
            }

            let page_index = total.saturating_sub(query.offset);
            if total >= query.offset && query.limit.is_none_or(|limit| page_index < limit) {
                items.push(unknown);
            }
            total = total.saturating_add(1);
        }

        let page_end = query
            .offset
            .saturating_add(u64::try_from(items.len()).unwrap_or(u64::MAX));
        let next_offset = query.limit.filter(|_| page_end < total).map(|_| page_end);
        UnknownPage {
            items,
            total: usize::try_from(total).unwrap_or(usize::MAX),
            offset: query.offset,
            next_offset,
        }
    }

    /// Return resolution validity for one current head, if it exists.
    pub fn verify_unknown_resolution(
        &self,
        unknown_id: &str,
    ) -> Option<UnknownResolutionCheck<'_>> {
        let unknown = self.unknown_heads().remove(unknown_id)?;
        Some(UnknownResolutionCheck {
            valid: unknown.status() == "resolved",
            truth_verified: unknown.truth_verified(),
            unknown,
        })
    }

    fn unknown_heads(&self) -> BTreeMap<&str, &ResidualUnknown> {
        let mut heads = BTreeMap::new();
        for unknown in &self.unknowns {
            let current = heads.get(unknown.unknown_id()).copied();
            if current.is_none_or(|head: &ResidualUnknown| head.revision() < unknown.revision()) {
                heads.insert(unknown.unknown_id(), unknown.as_ref());
            }
        }
        heads
    }

    /// Stream the canonical bundle without copying all retained payloads into
    /// one intermediate JSON document. Only one record is encoded at a time.
    pub fn write_canonical(&self, mut output: impl std::io::Write) -> Result<(), RecordError> {
        let bundle = self.bundle()?;
        let mut bytes = |value: &[u8]| {
            output
                .write_all(value)
                .map_err(|e| RecordError::Canonical(canonical_json::Error::Io(e)))
        };
        bytes(b"{\"artifacts\":")?;
        write_array(&bundle.artifacts, &mut output)?;
        output
            .write_all(b",\"captures\":")
            .map_err(|e| RecordError::Canonical(canonical_json::Error::Io(e)))?;
        write_array(&bundle.captures, &mut output)?;
        output
            .write_all(b",\"environments\":")
            .map_err(|e| RecordError::Canonical(canonical_json::Error::Io(e)))?;
        write_array(&bundle.environments, &mut output)?;
        output
            .write_all(b",\"providers\":")
            .map_err(|e| RecordError::Canonical(canonical_json::Error::Io(e)))?;
        write_array(&bundle.providers, &mut output)?;
        output
            .write_all(b",\"records\":")
            .map_err(|e| RecordError::Canonical(canonical_json::Error::Io(e)))?;
        write_array(&bundle.records, &mut output)?;
        output
            .write_all(b",\"scenarios\":")
            .map_err(|e| RecordError::Canonical(canonical_json::Error::Io(e)))?;
        write_array(&bundle.scenarios, &mut output)?;
        output
            .write_all(b",\"unknowns\":")
            .map_err(|e| RecordError::Canonical(canonical_json::Error::Io(e)))?;
        write_array(&bundle.unknowns, &mut output)?;
        output
            .write_all(b"}")
            .map_err(|e| RecordError::Canonical(canonical_json::Error::Io(e)))
    }

    pub fn bundle(&self) -> Result<Bundle<'_>, RecordError> {
        let mut artifacts = BTreeMap::new();
        let mut providers = BTreeMap::new();
        let mut environments = BTreeMap::new();
        for evidence in &self.records {
            if let Some(value) = evidence.artifact_manifest() {
                let value = copy_manifest(value)?;
                artifacts.insert(value.get().to_owned(), value);
            }
            let provider = copy_manifest(evidence.provider_manifest())?;
            providers.insert(provider.get().to_owned(), provider);
            if let Some(value) = evidence.environment_manifest() {
                let value = copy_manifest(value)?;
                environments.insert(value.get().to_owned(), value);
            }
        }
        Ok(Bundle {
            artifacts: artifacts.into_values().collect(),
            providers: providers.into_values().collect(),
            environments: environments.into_values().collect(),
            scenarios: self
                .records
                .iter()
                .filter_map(|record| record.scenario_manifest())
                .collect(),
            captures: self
                .records
                .iter()
                .filter_map(|record| record.capture_manifest())
                .collect(),
            unknowns: self.unknowns.iter().map(AsRef::as_ref).collect(),
            records: self.records.iter().map(AsRef::as_ref).collect(),
        })
    }

    /// These retained artifact producers do not publish native function dossiers.
    pub fn summary(&self, filters: Filters) -> Summary<'_> {
        let records: Vec<_> = self
            .records
            .iter()
            .filter_map(|evidence| {
                let metadata = evidence.metadata();
                if filters
                    .evidence_id
                    .as_ref()
                    .is_some_and(|v| v != evidence.evidence_id())
                    || filters
                        .operation
                        .as_ref()
                        .is_some_and(|value| !evidence.operation_matches(value))
                    || filters
                        .target_sha256
                        .as_ref()
                        .is_some_and(|v| evidence.subject_sha256() != Some(v.as_str()))
                    || filters.analysis_profile_digest.is_some()
                    || filters.procedure_address.is_some()
                {
                    return None;
                }
                Some(SummaryRecord {
                    metadata,
                    retention: "complete-record",
                    native_dossier: NoDossier {
                        available: false,
                        reason: "different-operation",
                    },
                })
            })
            .collect();
        Summary {
            kind: "evidence-bundle-summary",
            filters,
            total_retained_records: self.records.len(),
            matching_records: records.len(),
            unknown_revisions: self.unknowns.len(),
            records,
        }
    }
}

fn matches_unknown_query(unknown: &ResidualUnknown, query: &UnknownQuery) -> bool {
    query
        .status
        .as_deref()
        .is_none_or(|status| status == unknown.status())
        && query
            .severity
            .as_deref()
            .is_none_or(|severity| severity == unknown.severity())
        && query
            .domain
            .as_deref()
            .is_none_or(|domain| unknown.domain_matches(domain))
}

fn copy_manifest(value: &RawValue) -> Result<Box<RawValue>, RecordError> {
    RawValue::from_string(value.get().to_owned()).map_err(RecordError::Encoding)
}

fn canonical_record(record: &EvidenceRecord) -> Result<Vec<u8>, RecordError> {
    let mut bytes = Vec::new();
    canonical_json::write(record.raw(), &mut bytes).map_err(RecordError::Canonical)?;
    Ok(bytes)
}

#[derive(Serialize)]
pub struct ImportReceipt {
    pub imported: usize,
    pub unknowns_added: usize,
    pub total: usize,
    #[serde(skip_serializing)]
    pub metadata_changed: bool,
}

fn write_array<T: Serialize>(
    values: &[T],
    mut output: impl std::io::Write,
) -> Result<(), RecordError> {
    output
        .write_all(b"[")
        .map_err(|e| RecordError::Canonical(canonical_json::Error::Io(e)))?;
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output
                .write_all(b",")
                .map_err(|e| RecordError::Canonical(canonical_json::Error::Io(e)))?;
        }
        let raw = serde_json::value::to_raw_value(value).map_err(RecordError::Encoding)?;
        canonical_json::write(&raw, &mut output).map_err(RecordError::Canonical)?;
    }
    output
        .write_all(b"]")
        .map_err(|e| RecordError::Canonical(canonical_json::Error::Io(e)))
}

#[derive(Serialize)]
pub struct Bundle<'a> {
    artifacts: Vec<Box<RawValue>>,
    providers: Vec<Box<RawValue>>,
    environments: Vec<Box<RawValue>>,
    scenarios: Vec<&'a RawValue>,
    captures: Vec<&'a RawValue>,
    unknowns: Vec<&'a ResidualUnknown>,
    records: Vec<&'a EvidenceRecord>,
}
#[derive(Default, Serialize)]
pub struct Filters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) evidence_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) analysis_profile_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) procedure_address: Option<String>,
}
#[derive(Serialize)]
pub struct Summary<'a> {
    kind: &'static str,
    filters: Filters,
    total_retained_records: usize,
    matching_records: usize,
    unknown_revisions: usize,
    records: Vec<SummaryRecord<'a>>,
}
#[derive(Serialize)]
struct SummaryRecord<'a> {
    #[serde(flatten)]
    metadata: EvidenceRecordMetadata<'a>,
    retention: &'static str,
    native_dossier: NoDossier,
}
#[derive(Serialize)]
struct NoDossier {
    available: bool,
    reason: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_core::{
        canonical_json,
        evidence::bundle::EvidenceBundle,
        evidence::{Architecture, Location, NativeFormat, Observation, Provider, Subject},
    };
    use serde::Serialize;
    use serde_json::{Value, value::RawValue};

    #[derive(Serialize)]
    struct TestBundle<'a> {
        artifacts: Vec<&'a RawValue>,
        providers: Vec<&'a RawValue>,
        environments: Vec<&'a RawValue>,
        scenarios: Vec<&'a RawValue>,
        captures: Vec<&'a RawValue>,
        unknowns: Vec<&'a RawValue>,
        records: Vec<&'a EvidenceRecord>,
    }

    fn evidence(path: &str, sha256: &str, value: i64) -> EvidenceRecord {
        let subject = Subject::new(
            path,
            sha256.into(),
            NativeFormat::Elf,
            Some(Architecture::X86_64),
        )
        .unwrap();
        let evidence = ArtifactEvidence::new(
            subject,
            Provider {
                id: "rust-auditable",
                name: "REA Rust dependency reader",
                version: Some("1"),
            },
            Observation {
                operation: "inspect_rust_binary",
                result: serde_json::json!({"value": value}),
                limitations: vec!["fixture".into()],
                locations: vec![Location::ArtifactPath { path: path.into() }],
            },
        )
        .unwrap();
        let raw = serde_json::value::to_raw_value(&evidence).unwrap();
        EvidenceRecord::parse(&raw).unwrap()
    }

    #[test]
    fn records_artifact_evidence_with_unpaired_surrogate_text() {
        let path = "/artifacts/lossless-name";
        let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let subject = Subject::new(
            path,
            sha256.into(),
            NativeFormat::Elf,
            Some(Architecture::X86_64),
        )
        .unwrap();
        let name = serde_json::from_str(r#""\ud800""#).unwrap();
        let metadata = rea_rust_analysis::auditable::Metadata {
            section_name: rea_rust_analysis::auditable::SectionName::DepV0,
            file_offset: 275,
            section_bytes: 89,
            compressed_bytes: 89,
            uncompressed_bytes: 93,
            format_version: Some(1),
            packages: vec![rea_rust_analysis::auditable::Package {
                name,
                version: serde_json::from_str(r#""1.0.0""#).unwrap(),
                source: serde_json::from_str(r#""registry""#).unwrap(),
                kind: None,
                dependencies: Vec::new(),
                root: true,
            }],
            root_package_index: Some(0),
            dependency_edges: Vec::new(),
            cyclic_dependency_indices: Vec::new(),
        };
        let evidence = ArtifactEvidence::new(
            subject,
            Provider {
                id: "rust-auditable",
                name: "REA Rust dependency reader",
                version: Some("1"),
            },
            Observation {
                operation: "inspect_rust_binary",
                result: crate::binary::rust::Report {
                    artifact: crate::binary::rust::Artifact {
                        path: path.into(),
                        sha256: sha256.into(),
                        bytes: 364,
                    },
                    image: rea_rust_analysis::image::Image {
                        format: rea_rust_analysis::image::Format::Elf,
                        architecture: "amd64".into(),
                        bits: 64,
                        byte_order: rea_rust_analysis::image::ByteOrder::Little,
                        auditable_metadata: Some(metadata),
                        rustc_commit: None,
                    },
                    limitations: vec!["fixture limitation".into()],
                },
                limitations: vec!["fixture".into()],
                locations: vec![Location::ArtifactPath { path: path.into() }],
            },
        )
        .unwrap();
        let records = ArtifactRecords::default();

        records.record(Arc::new(evidence)).unwrap();

        let snapshot = records.snapshot().unwrap();
        let bundle = snapshot.bundle().unwrap();
        assert_eq!(bundle.records.len(), 1);
        assert!(bundle.records[0].raw().get().contains(r#""name":"\ud800""#));
    }

    fn unknown_revision(
        record: &EvidenceRecord,
        question: &str,
        severity: &str,
        previous_revision_digest: Option<&str>,
        revision: u64,
    ) -> Box<RawValue> {
        let identity = serde_json::json!({
            "domain": "fixture",
            "question": question,
            "scope_digest": null,
        });
        let identity = serde_json::value::to_raw_value(&identity).unwrap();
        let unknown_id = format!("unk_{}", canonical_json::digest_raw(&identity).unwrap());
        let mut value = serde_json::json!({
            "unknown_id": unknown_id,
            "revision": revision,
            "previous_revision_digest": previous_revision_digest,
            "scope_digest": null,
            "question": question,
            "status": "open",
            "severity": severity,
            "domain": "fixture",
            "supporting_evidence_ids": [],
            "contradicting_evidence_ids": [],
            "required_authority": null,
            "required_confidence": "inferred",
            "required_environment": null,
            "recommended_probes": [],
            "relationships": [],
            "resolution": null,
            "mutation_evidence_ids": [record.evidence_id()],
        });
        let unsigned = serde_json::value::to_raw_value(&value).unwrap();
        let revision_digest = canonical_json::digest_raw(&unsigned).unwrap();
        value["revision_digest"] = Value::String(revision_digest);
        serde_json::value::to_raw_value(&value).unwrap()
    }

    fn parse_bundle(records: &[EvidenceRecord], unknowns: &[Box<RawValue>]) -> EvidenceBundle {
        let mut artifacts = BTreeMap::new();
        let mut providers = BTreeMap::new();
        let mut records = records.iter().collect::<Vec<_>>();
        records.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
        for record in &records {
            if let Some(manifest) = record.artifact_manifest() {
                artifacts.insert(manifest.get().to_owned(), manifest);
            }
            let manifest = record.provider_manifest();
            providers.insert(manifest.get().to_owned(), manifest);
        }

        let mut unknowns = unknowns.iter().map(AsRef::as_ref).collect::<Vec<_>>();
        unknowns.sort_by(|left, right| {
            let left: Value = serde_json::from_str(left.get()).unwrap();
            let right: Value = serde_json::from_str(right.get()).unwrap();
            left["unknown_id"]
                .as_str()
                .cmp(&right["unknown_id"].as_str())
                .then_with(|| left["revision"].as_u64().cmp(&right["revision"].as_u64()))
        });

        let bundle = TestBundle {
            artifacts: artifacts.into_values().collect(),
            providers: providers.into_values().collect(),
            environments: Vec::new(),
            scenarios: Vec::new(),
            captures: Vec::new(),
            unknowns,
            records,
        };
        let raw = serde_json::value::to_raw_value(&bundle).unwrap();
        EvidenceBundle::parse(&raw).unwrap()
    }

    fn digest(raw: &RawValue, field: &str) -> String {
        serde_json::from_str::<Value>(raw.get()).unwrap()[field]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn imports_and_exports_complete_unknown_histories() {
        let record = evidence(
            "/artifacts/example",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            42,
        );
        let first = unknown_revision(&record, "Which observation is complete?", "low", None, 1);
        let second = unknown_revision(
            &record,
            "Which observation is complete?",
            "high",
            Some(&digest(&first, "revision_digest")),
            2,
        );
        let records = ArtifactRecords::default();

        let initial = records
            .import(parse_bundle(
                std::slice::from_ref(&record),
                std::slice::from_ref(&first),
            ))
            .unwrap();
        assert_eq!(initial.imported, 1);
        assert_eq!(initial.unknowns_added, 1);
        assert_eq!(initial.total, 1);

        let expanded = records
            .import(parse_bundle(&[record], &[first, second]))
            .unwrap();
        assert_eq!(expanded.imported, 0);
        assert_eq!(expanded.unknowns_added, 1);
        assert_eq!(expanded.total, 1);

        let snapshot = records.snapshot().unwrap();
        let mut bytes = Vec::new();
        snapshot.write_canonical(&mut bytes).unwrap();
        let exported = RawValue::from_string(String::from_utf8(bytes).unwrap()).unwrap();
        let round_trip = EvidenceBundle::parse(&exported).unwrap();

        assert_eq!(round_trip.records().len(), 1);
        assert_eq!(round_trip.unknowns().len(), 2);
        assert_eq!(round_trip.unknowns()[1].revision(), 2);
    }

    #[test]
    fn lists_paginated_current_heads_and_checks_resolution_state() {
        let record = evidence(
            "/artifacts/example",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            42,
        );
        let first = unknown_revision(&record, "Which result is first?", "low", None, 1);
        let second = unknown_revision(&record, "Which result is second?", "high", None, 1);
        let first_id = digest(&first, "unknown_id");
        let second_id = digest(&second, "unknown_id");
        let expected_first_id = first_id.as_str().min(second_id.as_str());
        let records = ArtifactRecords::default();
        records
            .import(parse_bundle(&[record], &[first, second]))
            .unwrap();

        let snapshot = records.snapshot().unwrap();
        let page = snapshot.list_unknowns_page(&UnknownQuery {
            domain: Some("fixture".into()),
            limit: Some(1),
            ..UnknownQuery::default()
        });
        assert_eq!(page.total, 2);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].unknown_id(), expected_first_id);
        assert_eq!(page.next_offset, Some(1));

        let last_page = snapshot.list_unknowns_page(&UnknownQuery {
            offset: 1,
            limit: Some(1),
            ..UnknownQuery::default()
        });
        assert_eq!(last_page.total, 2);
        assert_eq!(last_page.items.len(), 1);
        assert_eq!(last_page.next_offset, None);

        let beyond_end = snapshot.list_unknowns_page(&UnknownQuery {
            offset: 3,
            limit: Some(1),
            ..UnknownQuery::default()
        });
        assert_eq!(beyond_end.total, 2);
        assert!(beyond_end.items.is_empty());
        assert_eq!(beyond_end.next_offset, None);

        let check = snapshot.verify_unknown_resolution(&first_id).unwrap();
        assert!(!check.valid);
        assert!(!check.truth_verified);
        assert_eq!(check.unknown.unknown_id(), first_id);
    }

    #[test]
    fn conflicting_history_does_not_change_the_retained_ledger() {
        let record = evidence(
            "/artifacts/example",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            42,
        );
        let accepted = unknown_revision(&record, "Same question?", "low", None, 1);
        let conflicting = unknown_revision(&record, "Same question?", "high", None, 1);
        let records = ArtifactRecords::default();
        records
            .import(parse_bundle(
                std::slice::from_ref(&record),
                std::slice::from_ref(&accepted),
            ))
            .unwrap();

        let result = records.import(parse_bundle(
            std::slice::from_ref(&record),
            std::slice::from_ref(&conflicting),
        ));

        assert!(matches!(result, Err(RecordError::Conflict)));
        let snapshot = records.snapshot().unwrap();
        assert_eq!(snapshot.record_count(), 1);
        let mut bytes = Vec::new();
        snapshot.write_canonical(&mut bytes).unwrap();
        let exported = RawValue::from_string(String::from_utf8(bytes).unwrap()).unwrap();
        let retained = EvidenceBundle::parse(&exported).unwrap();
        assert_eq!(retained.records().len(), 1);
        assert_eq!(
            retained.unknowns()[0].revision_digest(),
            digest(&accepted, "revision_digest")
        );
    }
}
