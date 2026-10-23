//! Cross-language artifact Evidence identity and envelope compatibility.
use rea_core::evidence::{
    Architecture, ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject,
};

#[test]
fn matches_the_original_rea_artifact_evidence_commitment() {
    #[derive(serde::Serialize)]
    struct ProducerValue<'a> {
        value: &'a std::cell::Cell<u32>,
    }
    let producer = std::cell::Cell::new(42);
    // Golden from createEvidence in the pinned TypeScript runtime, independently
    // evaluated with the same subject/observation rather than this implementation.
    let path = "/artifacts/example";
    let subject = Subject::new(
        path,
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
            result: ProducerValue { value: &producer },
            limitations: vec!["fixture".into()],
            locations: vec![Location::ArtifactPath { path: path.into() }],
        },
    )
    .unwrap();
    assert_eq!(
        evidence.evidence_id(),
        "ev_ea643a5f698ce244587d02938da95c8706e5d6bc9fb7be851654b55015ae6afc"
    );
    // Producer state must not change a committed observation, even when the
    // producer implements interior mutability behind a shared reference.
    producer.set(43);
    let serialized = serde_json::to_value(&evidence).unwrap();
    assert_eq!(serialized["normalized_result"]["value"], 42);
    assert_eq!(serialized["subject"]["name"], "example");
    assert_eq!(serialized["subject"]["local_path"], path);
    assert_eq!(serialized["parameters"]["path"], path);
    for field in [
        "analysis_profile",
        "raw_result",
        "environment",
        "relationship_coverage",
    ] {
        assert!(serialized.get(field).unwrap().is_null());
    }
    assert_eq!(serialized["authority"], "shipped-artifact");
}
