//! Provider-neutral Evidence validation and semantic identity compatibility.
use rea_core::evidence::record::{EvidenceRecord, EvidenceRecordError};
use rea_core::evidence::{
    Architecture, ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject,
};
use rea_core::schema::{IssueKind, Parser, UnknownKeys};
use serde_json::{Value, value::RawValue};

fn artifact_evidence() -> ArtifactEvidence {
    let path = "/artifacts/example";
    let subject = Subject::new(
        path,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
        NativeFormat::Elf,
        Some(Architecture::X86_64),
    )
    .unwrap();
    ArtifactEvidence::new(
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
            locations: vec![Location::ArtifactPath { path: path.into() }],
        },
    )
    .unwrap()
}

fn raw<T: serde::Serialize>(value: &T) -> Box<RawValue> {
    serde_json::value::to_raw_value(value).unwrap()
}

#[test]
fn authenticates_the_complete_artifact_record_envelope() {
    let evidence = artifact_evidence();
    let parsed = EvidenceRecord::parse(&raw(&evidence)).unwrap();

    assert_eq!(parsed.evidence_id(), evidence.evidence_id());
    assert_eq!(
        parsed.subject_sha256(),
        Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(parsed.operation().get(), "\"inspect_rust_binary\"");
}

#[test]
fn validates_file_offset_range_locations() {
    let path = "/artifacts/section";
    let evidence = ArtifactEvidence::new(
        Subject::new(
            path,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            NativeFormat::Elf,
            Some(Architecture::X86_64),
        )
        .unwrap(),
        Provider {
            id: "rust-auditable",
            name: "REA Rust dependency reader",
            version: Some("1"),
        },
        Observation {
            operation: "inspect_rust_binary",
            result: serde_json::json!({"section": ".dep-v0"}),
            limitations: vec!["fixture".into()],
            locations: vec![Location::FileOffsetRange {
                start: 275,
                end: 364,
            }],
        },
    )
    .unwrap();

    let parsed = EvidenceRecord::parse(&raw(&evidence)).unwrap();

    assert_eq!(parsed.evidence_id(), evidence.evidence_id());
}

#[test]
fn display_subject_name_and_path_do_not_change_semantic_identity() {
    let evidence = artifact_evidence();
    let mut changed: Value = serde_json::from_slice(raw(&evidence).get().as_bytes()).unwrap();
    changed["subject"]["name"] = Value::String("renamed elsewhere".into());
    changed["subject"]["local_path"] = Value::String("/another/display/path".into());

    let original = EvidenceRecord::parse(&raw(&evidence)).unwrap();
    let rebound = EvidenceRecord::parse(&raw(&changed)).unwrap();

    assert_eq!(original.evidence_id(), rebound.evidence_id());
    assert!(original.agrees(&rebound).unwrap());
}

#[test]
fn semantic_payload_tampering_is_rejected() {
    let evidence = artifact_evidence();
    let mut changed: Value = serde_json::from_slice(raw(&evidence).get().as_bytes()).unwrap();
    changed["normalized_result"]["value"] = Value::from(43);

    assert!(matches!(
        EvidenceRecord::parse(&raw(&changed)),
        Err(EvidenceRecordError::SemanticIdMismatch)
    ));
}

#[test]
fn envelope_rejects_unknown_fields() {
    let evidence = artifact_evidence();
    let mut changed: Value = serde_json::from_slice(raw(&evidence).get().as_bytes()).unwrap();
    changed["unexpected"] = Value::Bool(true);

    assert!(matches!(
        EvidenceRecord::parse(&raw(&changed)),
        Err(EvidenceRecordError::Shape(_))
    ));
}

#[test]
fn display_subject_can_retain_an_unpaired_surrogate() {
    let evidence = artifact_evidence();
    let source = raw(&evidence).get().replace(
        "\"local_path\":\"/artifacts/example\"",
        "\"local_path\":\"/artifacts/\\ud800\"",
    );
    let source = RawValue::from_string(source).unwrap();

    let parsed = EvidenceRecord::parse(&source).unwrap();

    assert_eq!(parsed.evidence_id(), evidence.evidence_id());
    assert!(parsed.raw().get().contains("\\ud800"));
}

#[test]
fn lone_surrogate_payload_keeps_raw_shape_fallback_for_invalid_sibling() {
    let evidence = artifact_evidence();
    let source = raw(&evidence)
        .get()
        .replace(
            "\"normalized_result\":{\"value\":42}",
            "\"normalized_result\":\"\\ud800\"",
        )
        .replace("\"confidence\":\"observed\"", "\"confidence\":\"invalid\"");
    let source = RawValue::from_string(source).unwrap();

    assert!(matches!(
        EvidenceRecord::parse(&source),
        Err(EvidenceRecordError::Invalid(_))
    ));
}

#[test]
fn escaped_surrogate_text_without_a_json_escape_remains_a_string() {
    let evidence = artifact_evidence();
    let source = raw(&evidence).get().replace(
        "\"normalized_result\":{\"value\":42}",
        "\"normalized_result\":\"\\\\uD800\"",
    );
    let source = RawValue::from_string(source).unwrap();

    assert!(matches!(
        EvidenceRecord::parse(&source),
        Err(EvidenceRecordError::SemanticIdMismatch)
    ));
}

#[test]
fn duplicate_object_keys_follow_json_parse_last_key_wins_semantics() {
    let evidence = artifact_evidence();
    let source = raw(&evidence).get().replace(
        "\"operation\":\"inspect_rust_binary\"",
        "\"operation\":\"wrong\",\"operation\":\"inspect_rust_binary\"",
    );
    let source = RawValue::from_string(source).unwrap();

    let parsed = EvidenceRecord::parse(&source).unwrap();

    assert_eq!(parsed.evidence_id(), evidence.evidence_id());
    assert!(!parsed.raw().get().contains("\"operation\":\"wrong\""));
}

#[test]
fn create_unsigned_normalizes_duplicate_fields_and_preserves_lone_surrogates() {
    let evidence = artifact_evidence();
    let mut source = raw(&evidence).get().to_owned();

    let evidence_id_start = source.find("\"evidence_id\":").unwrap();
    let evidence_id_end = source[evidence_id_start..]
        .find(',')
        .map(|offset| evidence_id_start + offset + 1)
        .unwrap();
    source.replace_range(evidence_id_start..evidence_id_end, "");
    source = source.replace(
        "\"operation\":\"inspect_rust_binary\"",
        "\"operation\":\"wrong\",\"operation\":\"inspect_rust_binary\"",
    );
    source = source.replace(
        "\"local_path\":\"/artifacts/example\"",
        "\"local_path\":\"/artifacts/\\ud800\"",
    );

    let unsigned = RawValue::from_string(source).unwrap();
    let created = EvidenceRecord::create_unsigned(&unsigned).unwrap();

    assert!(created.evidence_id().starts_with("ev_"));
    assert!(created.raw().get().contains("/artifacts/\\ud800"));
    assert!(!created.raw().get().contains("\"operation\":\"wrong\""));
}

#[test]
fn shape_validation_preserves_all_missing_evidence_fields_in_schema_order() {
    let issues = EvidenceRecord::validate_input_shape(&serde_json::json!({})).unwrap_err();
    let paths: Vec<&str> = issues
        .iter()
        .map(|issue| issue.path[0].as_str().unwrap())
        .collect();

    assert_eq!(issues.len(), 16);
    assert_eq!(
        paths,
        vec![
            "evidence_id",
            "subject",
            "provider",
            "analysis_profile",
            "predicate_type",
            "operation",
            "parameters",
            "raw_result",
            "normalized_result",
            "confidence",
            "authority",
            "environment",
            "limitations",
            "relationship_coverage",
            "locations",
            "evidence_links",
        ]
    );
    assert!(
        issues[..9]
            .iter()
            .all(|issue| matches!(issue.kind, IssueKind::InvalidType { .. }))
    );
    assert!(issues[9..].iter().all(|issue| matches!(
        issue.kind,
        IssueKind::InvalidType { .. } | IssueKind::InvalidValue { .. }
    )));
}

#[test]
fn shape_validation_reports_nested_location_constraints_before_deserialization() {
    let evidence = artifact_evidence();
    let mut input: Value = serde_json::from_str(raw(&evidence).get()).unwrap();
    input["locations"] = serde_json::json!([{
        "kind": "file-offset",
        "offset": -1
    }]);

    let issues = EvidenceRecord::validate_input_shape(&input).unwrap_err();

    assert!(issues.iter().any(|issue| {
        issue.path
            == vec![
                Value::String("locations".into()),
                Value::from(0),
                Value::String("offset".into()),
            ]
    }));
}

#[test]
fn shape_validation_accepts_source_optional_diagnostics_and_empty_local_path() {
    let evidence = artifact_evidence();
    let mut input: Value = serde_json::from_str(raw(&evidence).get()).unwrap();
    input["subject"]["local_path"] = Value::String(String::new());
    input["relationship_coverage"] = serde_json::json!({"status": "complete"});

    assert!(EvidenceRecord::validate_input_shape(&input).is_ok());
}

#[test]
fn shape_validation_accepts_partial_relationship_coverage() {
    let evidence = artifact_evidence();
    let mut input: Value = serde_json::from_str(raw(&evidence).get()).unwrap();
    input["relationship_coverage"] = serde_json::json!({
        "status": "partial",
        "limitations": ["Indirect targets are unresolved."],
        "limited_directions": ["callers"],
        "diagnostics": ["Derived from the saved reference inventory."]
    });

    assert!(EvidenceRecord::validate_input_shape(&input).is_ok());
}

#[test]
fn schema_one_of_rejects_multiple_matching_array_branches() {
    let schema = serde_json::json!({
        "oneOf": [
            {"type": "array"},
            {"type": "array"}
        ]
    });
    let parser = Parser::new(&schema, UnknownKeys::Reject);

    assert!(parser.parse(&serde_json::json!([])).is_err());
}

#[test]
fn schema_one_of_rejects_null_when_a_second_branch_also_matches() {
    let schema = serde_json::json!({
        "oneOf": [
            {"type": "null"},
            {}
        ]
    });
    let parser = Parser::new(&schema, UnknownKeys::Reject);

    assert!(parser.parse(&serde_json::Value::Null).is_err());
}

#[test]
fn schema_one_of_accepts_the_single_matching_direction_branch() {
    let schema = serde_json::json!({
        "oneOf": [
            {
                "type": "array",
                "prefixItems": [{"const": "callers"}],
                "minItems": 1,
                "maxItems": 1
            },
            {
                "type": "array",
                "prefixItems": [{"const": "callees"}],
                "minItems": 1,
                "maxItems": 1
            }
        ]
    });
    let parser = Parser::new(&schema, UnknownKeys::Reject);

    assert!(parser.parse(&serde_json::json!(["callers"])).is_ok());
    assert!(parser.parse(&serde_json::json!(["other"])).is_err());
}

#[test]
fn shape_validation_keeps_raw_only_architectures_on_the_raw_variant() {
    let evidence = artifact_evidence();
    let mut detected: Value = serde_json::from_str(raw(&evidence).get()).unwrap();
    detected["subject"]["architecture"] = Value::String("6502".into());

    let detected_issues = EvidenceRecord::validate_input_shape(&detected).unwrap_err();
    assert!(detected_issues.iter().any(|issue| {
        issue.path
            == vec![
                Value::String("subject".into()),
                Value::String("architecture".into()),
            ]
    }));

    detected["subject"]["format"] = Value::String("raw-binary".into());
    assert!(EvidenceRecord::validate_input_shape(&detected).is_ok());
}

#[test]
fn parse_accepts_empty_subject_local_path_when_identity_is_unchanged() {
    let evidence = artifact_evidence();
    let mut input: Value = serde_json::from_str(raw(&evidence).get()).unwrap();
    input["subject"]["local_path"] = Value::String(String::new());

    let parsed = EvidenceRecord::parse(&raw(&input)).unwrap();

    assert_eq!(parsed.evidence_id(), evidence.evidence_id());
}
