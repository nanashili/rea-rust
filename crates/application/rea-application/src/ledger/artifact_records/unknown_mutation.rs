//! Atomic residual-unknown creation and revision updates.
use super::{ArtifactRecords, Ledger, RecordError, UnknownMutationFailure};
use rea_core::{
    canonical_json,
    evidence::record::EvidenceRecord,
    residual_unknown::{ResidualUnknown, ResidualUnknownError, validate_histories},
};
use serde::Serialize;
use serde_json::{Map, Value, value::RawValue};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

const RECORD_OPERATION: &str = "record_unknown";
const UPDATE_OPERATION: &str = "update_unknown";
const SUBJECT_UNAVAILABLE: &str = "Artifact identity is unavailable for this observation.";
const MUTATION_LIMITATION: &str =
    "Registry mutation evidence records analyst intent, not proof of the answer.";

impl ArtifactRecords {
    /// Atomically retain derived Evidence and its supported residual unknown.
    ///
    /// Repeated calls with the same deterministic unknown revision retain the
    /// Evidence idempotently without appending a second mutation record.
    pub fn record_evidence_with_unknown(
        &self,
        evidence_raw: &RawValue,
        input: &RawValue,
    ) -> Result<(), RecordError> {
        let evidence =
            Arc::new(EvidenceRecord::parse(evidence_raw).map_err(RecordError::Evidence)?);
        let mutation = build_mutation_evidence(RECORD_OPERATION, input, None)?;
        let unknown = Arc::new(create_unknown(input, &mutation)?);
        let mut ledger = self.ledger.lock().map_err(|_| RecordError::Poisoned)?;
        let key = (unknown.unknown_id().to_owned(), unknown.revision());

        if let Some(existing) = ledger.unknowns.get(&key) {
            if existing.revision_digest() != unknown.revision_digest() {
                return Err(RecordError::UnknownMutation(
                    UnknownMutationFailure::AlreadyExists,
                ));
            }

            return commit_record(&mut ledger, evidence);
        }

        commit_evidence_mutation(&mut ledger, Some(evidence), mutation, unknown)
    }

    /// Create a stable unknown and append its mutation Evidence atomically.
    pub fn record_unknown(
        &self,
        input: &RawValue,
        target_subject: Option<&RawValue>,
    ) -> Result<Box<RawValue>, RecordError> {
        let mutation = build_mutation_evidence(RECORD_OPERATION, input, target_subject)?;
        let unknown = Arc::new(create_unknown(input, &mutation)?);
        let mut ledger = self.ledger.lock().map_err(|_| RecordError::Poisoned)?;

        if ledger
            .unknowns
            .keys()
            .any(|(unknown_id, _)| unknown_id == unknown.unknown_id())
        {
            return Err(RecordError::UnknownMutation(
                UnknownMutationFailure::AlreadyExists,
            ));
        }

        commit_mutation(&mut ledger, mutation, unknown.clone())?;
        serde_json::value::to_raw_value(unknown.as_ref()).map_err(RecordError::Encoding)
    }

    /// Append one complete replacement revision after exact optimistic matching.
    pub fn update_unknown(
        &self,
        input: &RawValue,
        target_subject: Option<&RawValue>,
    ) -> Result<Box<RawValue>, RecordError> {
        let mutation = build_mutation_evidence(UPDATE_OPERATION, input, target_subject)?;
        let fields = input_fields(input)?;
        let unknown_id = required_string(&fields, "unknown_id")?;
        let expected_revision = required_integer(&fields, "expected_revision")?;
        let mut ledger = self.ledger.lock().map_err(|_| RecordError::Poisoned)?;
        let Some(current) = current_unknown(&ledger, &unknown_id) else {
            return Err(RecordError::UnknownMutation(
                UnknownMutationFailure::NotFound,
            ));
        };
        if current.revision() != expected_revision {
            return Err(RecordError::UnknownMutation(
                UnknownMutationFailure::RevisionConflict,
            ));
        }

        let unknown = Arc::new(update_unknown_revision(current, &fields, &mutation)?);
        commit_mutation(&mut ledger, mutation, unknown.clone())?;
        serde_json::value::to_raw_value(unknown.as_ref()).map_err(RecordError::Encoding)
    }
}

fn build_mutation_evidence(
    operation: &'static str,
    input: &RawValue,
    target_subject: Option<&RawValue>,
) -> Result<EvidenceRecord, RecordError> {
    let fields = input_fields(input)?;
    let parameters = copy_raw(input)?;
    let subject = match target_subject {
        Some(subject) => copy_raw(subject)?,
        None => raw_value(&Value::Null)?,
    };
    let normalized_result = mutation_result(operation, &fields)?;
    let evidence_links = mutation_evidence_links(&fields)?;
    let limitations = if target_subject.is_none() {
        vec![SUBJECT_UNAVAILABLE, MUTATION_LIMITATION]
    } else {
        vec![MUTATION_LIMITATION]
    };
    let unsigned = MutationEvidence {
        subject: &subject,
        provider: RegistryProvider {
            id: "rea-unknown-registry",
            name: "REA residual unknown registry",
            version: "1",
        },
        analysis_profile: None,
        predicate_type: "rea.residual-unknown-mutation",
        operation,
        parameters: &parameters,
        raw_result: None,
        normalized_result,
        confidence: "derived",
        authority: "analyst-inference",
        environment: None,
        limitations,
        relationship_coverage: None,
        locations: Vec::<Value>::new(),
        evidence_links,
    };
    let raw = serde_json::value::to_raw_value(&unsigned).map_err(RecordError::Encoding)?;
    EvidenceRecord::create_unsigned(&raw).map_err(RecordError::Evidence)
}

#[derive(Serialize)]
struct RegistryProvider {
    id: &'static str,
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct MutationEvidence<'a> {
    subject: &'a RawValue,
    provider: RegistryProvider,
    analysis_profile: Option<()>,
    predicate_type: &'static str,
    operation: &'static str,
    parameters: &'a RawValue,
    raw_result: Option<()>,
    normalized_result: Value,
    confidence: &'static str,
    authority: &'static str,
    environment: Option<()>,
    limitations: Vec<&'static str>,
    relationship_coverage: Option<()>,
    locations: Vec<Value>,
    evidence_links: Vec<String>,
}

fn mutation_result(
    operation: &str,
    fields: &BTreeMap<String, Box<RawValue>>,
) -> Result<Value, RecordError> {
    if operation == RECORD_OPERATION {
        let question = required_value(fields, "question")?;
        let required_authority = required_value(fields, "required_authority")?;
        let required_confidence = required_value(fields, "required_confidence")?;
        Ok(serde_json::json!({
            "action": "record",
            "question": question,
            "required_authority": required_authority,
            "required_confidence": required_confidence,
        }))
    } else {
        let status = required_value(fields, "status")?;
        Ok(serde_json::json!({"action": "update", "status": status}))
    }
}

fn mutation_evidence_links(
    fields: &BTreeMap<String, Box<RawValue>>,
) -> Result<Vec<String>, RecordError> {
    let mut links = Vec::new();
    let mut included = BTreeSet::new();
    for key in ["supporting_evidence_ids", "contradicting_evidence_ids"] {
        let values = string_array(required_value(fields, key)?)?;
        append_unique(&mut links, &mut included, values);
    }

    if let Some(resolution) = fields.get("resolution")
        && resolution.get() != "null"
    {
        let resolution_fields = input_fields(resolution)?;
        let evidence_ids = string_array(required_value(&resolution_fields, "evidence_ids")?)?;
        append_unique(&mut links, &mut included, evidence_ids);
    }
    Ok(links)
}

fn append_unique(output: &mut Vec<String>, included: &mut BTreeSet<String>, values: Vec<String>) {
    for value in values {
        if included.insert(value.clone()) {
            output.push(value);
        }
    }
}

fn create_unknown(
    input: &RawValue,
    mutation: &EvidenceRecord,
) -> Result<ResidualUnknown, RecordError> {
    let fields = input_fields(input)?;
    let question = required_string(&fields, "question")?;
    let domain = required_string(&fields, "domain")?;
    let scope_digest = mutation.subject_sha256().map(str::to_owned);
    let comparison_scope = fields.get("comparison_conclusion_scope");
    let normalized_question = normalize_question(&question);

    let identity = UnknownIdentity {
        domain: &domain,
        question: &normalized_question,
        scope_digest: &scope_digest,
        comparison_conclusion_scope: comparison_scope.map(|value| value.as_ref()),
    };
    let identity_raw = serde_json::value::to_raw_value(&identity).map_err(RecordError::Encoding)?;
    let unknown_id = format!(
        "unk_{}",
        canonical_json::digest_raw(&identity_raw).map_err(RecordError::Canonical)?
    );

    let contradicting = sorted_unique(string_array(required_value(
        &fields,
        "contradicting_evidence_ids",
    )?)?);
    let supporting = sorted_unique(string_array(required_value(
        &fields,
        "supporting_evidence_ids",
    )?)?);
    let relationships = sorted_relationships(required_value(&fields, "relationships")?)?;

    let mut revision = Map::new();
    insert(&mut revision, "unknown_id", Value::String(unknown_id));
    insert(&mut revision, "revision", Value::from(1_u64));
    insert(&mut revision, "previous_revision_digest", Value::Null);
    insert(&mut revision, "scope_digest", optional_string(scope_digest));
    insert(
        &mut revision,
        "question",
        Value::String(normalized_question),
    );
    insert(
        &mut revision,
        "status",
        Value::String(
            if contradicting.is_empty() {
                "open"
            } else {
                "contradicted"
            }
            .into(),
        ),
    );
    insert(
        &mut revision,
        "severity",
        value_from_raw(required_value(&fields, "severity")?)?,
    );
    insert(&mut revision, "domain", Value::String(domain));
    if let Some(comparison_scope) = comparison_scope {
        insert(
            &mut revision,
            "comparison_conclusion_scope",
            value_from_raw(comparison_scope)?,
        );
    }
    insert(
        &mut revision,
        "supporting_evidence_ids",
        Value::Array(supporting.into_iter().map(Value::String).collect()),
    );
    insert(
        &mut revision,
        "contradicting_evidence_ids",
        Value::Array(contradicting.into_iter().map(Value::String).collect()),
    );
    insert(
        &mut revision,
        "required_authority",
        value_from_raw(required_value(&fields, "required_authority")?)?,
    );
    insert(
        &mut revision,
        "required_confidence",
        value_from_raw(required_value(&fields, "required_confidence")?)?,
    );
    insert(
        &mut revision,
        "required_environment",
        value_from_raw(required_value(&fields, "required_environment")?)?,
    );
    insert(
        &mut revision,
        "recommended_probes",
        value_from_raw(required_value(&fields, "recommended_probes")?)?,
    );
    insert(&mut revision, "relationships", relationships);
    insert(&mut revision, "resolution", Value::Null);
    insert(
        &mut revision,
        "mutation_evidence_ids",
        Value::Array(vec![Value::String(mutation.evidence_id().to_owned())]),
    );

    authenticated_revision(revision).map_err(RecordError::Unknown)
}

#[derive(Serialize)]
struct UnknownIdentity<'a> {
    domain: &'a str,
    question: &'a str,
    scope_digest: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison_conclusion_scope: Option<&'a RawValue>,
}

fn update_unknown_revision(
    current: &ResidualUnknown,
    input: &BTreeMap<String, Box<RawValue>>,
    mutation: &EvidenceRecord,
) -> Result<ResidualUnknown, RecordError> {
    let mut revision = raw_fields(current.raw()).map_err(RecordError::Unknown)?;
    let current_revision = current.revision();
    if current_revision >= 9_007_199_254_740_991 {
        return Err(RecordError::UnknownMutation(
            UnknownMutationFailure::InvalidTransition,
        ));
    }

    revision.remove("revision_digest");
    replace_json(&mut revision, "revision", Value::from(current_revision + 1))?;
    replace_json(
        &mut revision,
        "previous_revision_digest",
        Value::String(current.revision_digest().to_owned()),
    )?;

    for key in [
        "status",
        "severity",
        "supporting_evidence_ids",
        "contradicting_evidence_ids",
        "required_authority",
        "required_confidence",
        "required_environment",
        "recommended_probes",
        "relationships",
        "resolution",
    ] {
        let raw = required_value(input, key)?;
        let value = if key == "supporting_evidence_ids" || key == "contradicting_evidence_ids" {
            Value::Array(
                sorted_unique(string_array(raw)?)
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            )
        } else if key == "relationships" {
            sorted_relationships(raw)?
        } else {
            value_from_raw(raw)?
        };
        replace_value(&mut revision, key, value)?;
    }

    let current_fields = raw_fields(current.raw()).map_err(RecordError::Unknown)?;
    let existing_mutations =
        string_array(required_value(&current_fields, "mutation_evidence_ids")?)?;
    let mutation_ids = sorted_unique(
        existing_mutations
            .into_iter()
            .chain(std::iter::once(mutation.evidence_id().to_owned()))
            .collect(),
    );
    replace_value(
        &mut revision,
        "mutation_evidence_ids",
        Value::Array(mutation_ids.into_iter().map(Value::String).collect()),
    )?;

    authenticated_revision_raw(revision).map_err(RecordError::Unknown)
}

fn authenticated_revision(
    revision: Map<String, Value>,
) -> Result<ResidualUnknown, ResidualUnknownError> {
    let fields = revision
        .into_iter()
        .map(|(key, value)| {
            serde_json::value::to_raw_value(&value)
                .map(|raw| (key, raw))
                .map_err(ResidualUnknownError::Encoding)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    authenticated_revision_raw(fields)
}

fn authenticated_revision_raw(
    mut fields: BTreeMap<String, Box<RawValue>>,
) -> Result<ResidualUnknown, ResidualUnknownError> {
    let unsigned =
        serde_json::value::to_raw_value(&fields).map_err(ResidualUnknownError::Encoding)?;
    let digest = canonical_json::digest_raw(&unsigned).map_err(ResidualUnknownError::Canonical)?;
    fields.insert(
        "revision_digest".into(),
        serde_json::value::to_raw_value(&digest).map_err(ResidualUnknownError::Encoding)?,
    );
    let revision =
        serde_json::value::to_raw_value(&fields).map_err(ResidualUnknownError::Encoding)?;
    ResidualUnknown::parse(&revision)
}

fn commit_mutation(
    ledger: &mut Ledger,
    mutation: EvidenceRecord,
    unknown: Arc<ResidualUnknown>,
) -> Result<(), RecordError> {
    commit_evidence_mutation(ledger, None, mutation, unknown)
}

fn commit_record(ledger: &mut Ledger, evidence: Arc<EvidenceRecord>) -> Result<(), RecordError> {
    let evidence = match ledger.records.get(evidence.evidence_id()) {
        Some(existing) if existing.agrees(&evidence).map_err(RecordError::Evidence)? => {
            Arc::clone(existing)
        }
        Some(_) => return Err(RecordError::Conflict),
        None => evidence,
    };

    let mut candidate_records = ledger.records.values().cloned().collect::<Vec<_>>();
    if !candidate_records
        .iter()
        .any(|record| record.evidence_id() == evidence.evidence_id())
    {
        candidate_records.push(Arc::clone(&evidence));
    }

    validate_histories(
        ledger.unknowns.values().map(|unknown| unknown.as_ref()),
        candidate_records.iter().map(|record| record.as_ref()),
    )
    .map_err(RecordError::Unknown)?;

    ledger
        .records
        .entry(evidence.evidence_id().to_owned())
        .or_insert(evidence);
    Ok(())
}

fn commit_evidence_mutation(
    ledger: &mut Ledger,
    evidence: Option<Arc<EvidenceRecord>>,
    mutation: EvidenceRecord,
    unknown: Arc<ResidualUnknown>,
) -> Result<(), RecordError> {
    let evidence = evidence
        .map(
            |evidence| match ledger.records.get(evidence.evidence_id()) {
                Some(existing) if existing.agrees(&evidence).map_err(RecordError::Evidence)? => {
                    Ok(Arc::clone(existing))
                }
                Some(_) => Err(RecordError::Conflict),
                None => Ok(evidence),
            },
        )
        .transpose()?;
    let mutation = match ledger.records.get(mutation.evidence_id()) {
        Some(existing) if existing.agrees(&mutation).map_err(RecordError::Evidence)? => {
            Arc::clone(existing)
        }
        Some(_) => {
            return Err(RecordError::UnknownMutation(
                UnknownMutationFailure::Integrity,
            ));
        }
        None => Arc::new(mutation),
    };

    let evidence_id = evidence
        .as_ref()
        .map(|record| record.evidence_id().to_owned());
    let mutation_id = mutation.evidence_id().to_owned();
    let mut candidate_records = ledger.records.values().cloned().collect::<Vec<_>>();
    if let Some(evidence) = &evidence {
        append_record_if_missing(&mut candidate_records, Arc::clone(evidence));
    }
    append_record_if_missing(&mut candidate_records, Arc::clone(&mutation));

    let mut candidate_unknowns = ledger.unknowns.values().cloned().collect::<Vec<_>>();
    candidate_unknowns.push(Arc::clone(&unknown));
    candidate_unknowns.sort_by(|left, right| {
        left.unknown_id()
            .cmp(right.unknown_id())
            .then(left.revision().cmp(&right.revision()))
    });

    validate_histories(
        candidate_unknowns
            .iter()
            .map(|candidate| candidate.as_ref()),
        candidate_records.iter().map(|candidate| candidate.as_ref()),
    )
    .map_err(|_| RecordError::UnknownMutation(UnknownMutationFailure::Integrity))?;

    if let (Some(evidence_id), Some(evidence)) = (evidence_id, evidence) {
        ledger.records.entry(evidence_id).or_insert(evidence);
    }
    ledger.records.entry(mutation_id).or_insert(mutation);
    ledger.unknowns.insert(
        (unknown.unknown_id().to_owned(), unknown.revision()),
        unknown,
    );
    Ok(())
}

fn append_record_if_missing(records: &mut Vec<Arc<EvidenceRecord>>, record: Arc<EvidenceRecord>) {
    if !records
        .iter()
        .any(|candidate| candidate.evidence_id() == record.evidence_id())
    {
        records.push(record);
    }
}

fn current_unknown<'a>(ledger: &'a Ledger, unknown_id: &str) -> Option<&'a ResidualUnknown> {
    ledger
        .unknowns
        .iter()
        .filter(|((candidate, _), _)| candidate == unknown_id)
        .max_by_key(|((_, revision), _)| *revision)
        .map(|(_, unknown)| unknown.as_ref())
}

fn normalize_question(question: &str) -> String {
    let mut normalized = String::with_capacity(question.len());
    let mut pending_space = false;
    for character in question.chars() {
        if is_javascript_whitespace(character) {
            pending_space = !normalized.is_empty();
            continue;
        }
        if pending_space {
            normalized.push(' ');
            pending_space = false;
        }
        normalized.push(character);
    }
    normalized
}

fn is_javascript_whitespace(character: char) -> bool {
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

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn sorted_relationships(raw: &RawValue) -> Result<Value, RecordError> {
    let mut relationships =
        value_from_raw(raw)?
            .as_array()
            .cloned()
            .ok_or(RecordError::UnknownMutation(
                UnknownMutationFailure::InvalidTransition,
            ))?;
    relationships.sort_by(|left, right| {
        left.get("type")
            .and_then(Value::as_str)
            .cmp(&right.get("type").and_then(Value::as_str))
            .then_with(|| {
                left.get("unknown_id")
                    .and_then(Value::as_str)
                    .cmp(&right.get("unknown_id").and_then(Value::as_str))
            })
    });
    Ok(Value::Array(relationships))
}

fn input_fields(raw: &RawValue) -> Result<BTreeMap<String, Box<RawValue>>, RecordError> {
    serde_json::from_str(raw.get()).map_err(RecordError::Encoding)
}

fn raw_fields(raw: &RawValue) -> Result<BTreeMap<String, Box<RawValue>>, ResidualUnknownError> {
    serde_json::from_str(raw.get())
        .map_err(|error| ResidualUnknownError::Invalid(error.to_string()))
}

fn required_string(
    fields: &BTreeMap<String, Box<RawValue>>,
    key: &str,
) -> Result<String, RecordError> {
    let raw = required_value(fields, key)?;
    serde_json::from_str(raw.get()).map_err(RecordError::Encoding)
}

fn required_integer(
    fields: &BTreeMap<String, Box<RawValue>>,
    key: &str,
) -> Result<u64, RecordError> {
    let raw = required_value(fields, key)?;
    serde_json::from_str(raw.get()).map_err(RecordError::Encoding)
}

fn required_value<'a>(
    fields: &'a BTreeMap<String, Box<RawValue>>,
    key: &str,
) -> Result<&'a RawValue, RecordError> {
    fields
        .get(key)
        .map(AsRef::as_ref)
        .ok_or(RecordError::UnknownMutation(
            UnknownMutationFailure::InvalidTransition,
        ))
}

fn string_array(raw: &RawValue) -> Result<Vec<String>, RecordError> {
    serde_json::from_str(raw.get()).map_err(RecordError::Encoding)
}

fn value_from_raw(raw: &RawValue) -> Result<Value, RecordError> {
    serde_json::from_str(raw.get()).map_err(RecordError::Encoding)
}

fn copy_raw(raw: &RawValue) -> Result<Box<RawValue>, RecordError> {
    RawValue::from_string(raw.get().to_owned()).map_err(RecordError::Encoding)
}

fn raw_value(value: &Value) -> Result<Box<RawValue>, RecordError> {
    serde_json::value::to_raw_value(value).map_err(RecordError::Encoding)
}

fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}

fn insert(object: &mut Map<String, Value>, key: &str, value: Value) {
    object.insert(key.to_owned(), value);
}

fn replace_json(
    object: &mut BTreeMap<String, Box<RawValue>>,
    key: &str,
    value: Value,
) -> Result<(), RecordError> {
    let raw = raw_value(&value)?;
    object.insert(key.to_owned(), raw);
    Ok(())
}

fn replace_value(
    object: &mut BTreeMap<String, Box<RawValue>>,
    key: &str,
    value: Value,
) -> Result<(), RecordError> {
    replace_json(object, key, value)
}
