//! Canonical Evidence bundle validation shared by native import and export.
use rea_core::canonical_json;
use rea_core::evidence::bundle::{EvidenceBundle, EvidenceBundleError};
use rea_core::evidence::record::EvidenceRecord;
use rea_core::evidence::{
    Architecture, ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject,
};
use serde::Serialize;
use serde_json::Value;
use serde_json::value::RawValue;

fn record() -> EvidenceRecord {
    let subject = Subject::new(
        "/artifacts/example",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
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
            result: serde_json::json!({"value": 42}),
            limitations: vec!["fixture".into()],
            locations: vec![Location::ArtifactPath {
                path: "/artifacts/example".into(),
            }],
        },
    )
    .unwrap();
    let raw = serde_json::value::to_raw_value(&evidence).unwrap();
    EvidenceRecord::parse(&raw).unwrap()
}

#[derive(Serialize)]
struct Bundle<'a> {
    artifacts: Vec<&'a RawValue>,
    providers: Vec<&'a RawValue>,
    environments: Vec<&'a RawValue>,
    scenarios: Vec<&'a RawValue>,
    captures: Vec<&'a RawValue>,
    unknowns: Vec<&'a RawValue>,
    records: [&'a EvidenceRecord; 1],
}

fn bundle(record: &EvidenceRecord, unknowns: &[Box<RawValue>]) -> Box<RawValue> {
    serde_json::value::to_raw_value(&Bundle {
        artifacts: vec![record.artifact_manifest().unwrap()],
        providers: vec![record.provider_manifest()],
        environments: vec![],
        scenarios: vec![],
        captures: vec![],
        unknowns: unknowns.iter().map(AsRef::as_ref).collect(),
        records: [record],
    })
    .unwrap()
}

fn unknown_revision(
    record: &EvidenceRecord,
    question: &str,
    revision: u64,
    previous_revision_digest: Option<&str>,
    relationships: Vec<Value>,
) -> Box<RawValue> {
    let stable_question = question.split_whitespace().collect::<Vec<_>>().join(" ");
    let identity = serde_json::json!({
        "domain": "fixture",
        "question": stable_question,
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
        "severity": "low",
        "domain": "fixture",
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "required_authority": null,
        "required_confidence": "inferred",
        "required_environment": null,
        "recommended_probes": [],
        "relationships": relationships,
        "resolution": null,
        "mutation_evidence_ids": [record.evidence_id()],
    });
    let unsigned = serde_json::value::to_raw_value(&value).unwrap();
    let revision_digest = canonical_json::digest_raw(&unsigned).unwrap();
    value["revision_digest"] = Value::String(revision_digest);
    serde_json::value::to_raw_value(&value).unwrap()
}

fn unknown_id(unknown: &RawValue) -> String {
    serde_json::from_str::<Value>(unknown.get()).unwrap()["unknown_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn revision_digest(unknown: &RawValue) -> String {
    serde_json::from_str::<Value>(unknown.get()).unwrap()["revision_digest"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn authenticates_records_and_their_canonical_manifests() {
    let source = record();
    let input = bundle(&source, &[]);

    let parsed = EvidenceBundle::parse(&input).unwrap();

    assert_eq!(parsed.records().len(), 1);
    assert_eq!(parsed.records()[0].evidence_id(), source.evidence_id());
}

#[test]
fn rejects_manifest_changes_before_session_admission() {
    let source = record();
    let input = bundle(&source, &[]);
    let mut changed: serde_json::Value = serde_json::from_str(input.get()).unwrap();
    changed["artifacts"][0]["format"] = serde_json::json!("pe");
    let changed = serde_json::value::to_raw_value(&changed).unwrap();

    let Err(error) = EvidenceBundle::parse(&changed) else {
        panic!("changed manifest unexpectedly passed validation");
    };
    assert!(
        matches!(error, EvidenceBundleError::Invalid(_)),
        "{error:?}"
    );
}

#[test]
fn authenticates_and_retains_a_complete_unknown_history() {
    let source = record();
    let first = unknown_revision(&source, "Which  observation is complete?", 1, None, vec![]);
    let second = unknown_revision(
        &source,
        "Which  observation is complete?",
        2,
        Some(&revision_digest(&first)),
        vec![],
    );
    let unknowns = [first, second];
    let input = bundle(&source, &unknowns);

    let parsed = EvidenceBundle::parse(&input).unwrap();

    assert_eq!(parsed.unknowns().len(), 2);
    assert_eq!(parsed.unknowns()[0].revision(), 1);
    assert_eq!(parsed.unknowns()[1].revision(), 2);
}

#[test]
fn rejects_incomplete_unknown_history_and_dependency_cycles() {
    let source = record();
    let first = unknown_revision(&source, "First question?", 1, None, vec![]);
    let second = unknown_revision(
        &source,
        "First question?",
        2,
        Some(&revision_digest(&first)),
        vec![],
    );
    let missing_first = bundle(&source, &[second]);
    assert!(matches!(
        EvidenceBundle::parse(&missing_first),
        Err(EvidenceBundleError::Unknown(_))
    ));

    let first_id = unknown_id(&first);
    let second_id = unknown_id(&unknown_revision(
        &source,
        "Second question?",
        1,
        None,
        vec![],
    ));
    let first_with_edge = unknown_revision(
        &source,
        "First question?",
        1,
        None,
        vec![serde_json::json!({"type": "depends-on", "unknown_id": second_id})],
    );
    let second_with_edge = unknown_revision(
        &source,
        "Second question?",
        1,
        None,
        vec![serde_json::json!({"type": "depends-on", "unknown_id": first_id})],
    );
    let mut cycle = vec![first_with_edge, second_with_edge];
    cycle.sort_by_key(|unknown| unknown_id(unknown));
    let cyclic_bundle = bundle(&source, &cycle);

    assert!(matches!(
        EvidenceBundle::parse(&cyclic_bundle),
        Err(EvidenceBundleError::Unknown(_))
    ));
}

#[test]
fn rejects_noncanonical_record_order() {
    let first = record();
    let second = {
        let subject = Subject::new(
            "/artifacts/other",
            "cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34".into(),
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
                result: serde_json::json!({"value": 7}),
                limitations: vec!["fixture".into()],
                locations: vec![Location::ArtifactPath {
                    path: "/artifacts/other".into(),
                }],
            },
        )
        .unwrap();
        let raw = serde_json::value::to_raw_value(&evidence).unwrap();
        EvidenceRecord::parse(&raw).unwrap()
    };

    let mut records = [&first, &second];
    records.sort_by(|left, right| right.evidence_id().cmp(left.evidence_id()));
    let unsorted = serde_json::json!({
        "artifacts": [first.artifact_manifest().unwrap(), second.artifact_manifest().unwrap()],
        "providers": [first.provider_manifest()],
        "environments": [],
        "scenarios": [],
        "captures": [],
        "unknowns": Value::Array(Vec::new()),
        "records": records,
    });
    let input = serde_json::value::to_raw_value(&unsorted).unwrap();

    assert!(matches!(
        EvidenceBundle::parse(&input),
        Err(EvidenceBundleError::Invalid(message)) if message.contains("canonical order")
    ));
}
