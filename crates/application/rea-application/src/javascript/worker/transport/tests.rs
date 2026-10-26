use base64::Engine;

use super::super::{
    MAX_OUTPUT_BYTES, WorkerLimits, WorkerRequest, analyze_source_with_worker, with_checkpoint,
};
use super::*;

const CHECKPOINT: &[u8] = br#"{"static_analysis":{"facts":[2,1],"text":"\ud800"}}"#;
const SMALL_BODY: &[u8] = br#"{"semantic_ir":null,"semantic_projection":{"micros":7,"order":[2,1]},"semantic_metadata":null,"semantic_failure":null}"#;

fn raw(json: String) -> Box<RawValue> {
    RawValue::from_string(json).expect("test JSON must be valid")
}

fn gzip(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(body).expect("fixture compression writes");
    encoder.finish().expect("fixture compression finishes")
}

fn envelope(payload: &[u8], decoded_bytes: usize) -> serde_json::Value {
    serde_json::json!({
        "protocol": "rea-worker-compressed-v1",
        "version": 1,
        "encoding": "gzip+base64",
        "decoded_bytes": decoded_bytes,
        "payload": BASE64_STANDARD.encode(payload),
    })
}

fn checkpoint_and_terminal(terminal: &[u8]) -> Vec<u8> {
    let mut wire = CHECKPOINT.to_vec();
    wire.push(b'\n');
    wire.extend_from_slice(terminal);
    wire.push(b'\n');
    wire
}

fn compressed_wire(body: &[u8]) -> Vec<u8> {
    let terminal = serde_json::to_vec(&envelope(&gzip(body), body.len())).unwrap();
    checkpoint_and_terminal(&terminal)
}

fn assert_protocol_failure(wire: &[u8], limit: usize, expected: &str) {
    let error = parse_worker_response(wire, limit, || None).expect_err("invalid wire must fail");
    assert!(
        matches!(&error, WorkerFailure::Protocol(reason) if reason.contains(expected)),
        "expected protocol failure containing {expected:?}, got {error}"
    );
}

#[test]
fn compressed_transport_preserves_all_semantic_fields_exactly() {
    let response = WorkerResponse {
        static_analysis: raw(r#"{"facts":[2,1],"text":"\ud800"}"#.to_owned()),
        semantic_ir: Some(raw(r#"{"micros":9,"number":1.0,"negative":-0}"#.to_owned())),
        semantic_projection: Some(raw(format!(
            r#"{{"text":"\ud800","evidence":[{{"id":"a","line":2}},{{"id":"b","line":1}}],"order":[2,1],"padding":"{}"}}"#,
            "x".repeat(COMPRESSED_RESPONSE_THRESHOLD),
        ))),
        semantic_metadata: Some(raw(
            r#"{"evidence":[{"id":"keep","source":"x"}],"nested":{"micros":8}}"#.to_owned(),
        )),
        semantic_failure: Some(WorkerSemanticFailure {
            phase: "partial".to_owned(),
            reason: "retain this explanation".to_owned(),
        }),
    };
    let mut wire = Vec::new();
    write_checkpoint(&mut wire, &response.static_analysis).expect("checkpoint writes");
    write_worker_response(&mut wire, &response, MAX_OUTPUT_BYTES).expect("response writes");
    assert!(wire.len() < COMPRESSED_RESPONSE_THRESHOLD);

    let parsed = parse_worker_response(&wire, MAX_OUTPUT_BYTES, || None)
        .expect("compressed response parses");
    assert_eq!(parsed.static_analysis.get(), response.static_analysis.get());
    for (actual, expected) in [
        (&parsed.semantic_ir, &response.semantic_ir),
        (&parsed.semantic_projection, &response.semantic_projection),
        (&parsed.semantic_metadata, &response.semantic_metadata),
    ] {
        assert_eq!(
            actual.as_deref().map(RawValue::get),
            expected.as_deref().map(RawValue::get)
        );
    }
    let failure = parsed
        .semantic_failure
        .expect("failure explanation retained");
    assert_eq!(failure.phase, "partial");
    assert_eq!(failure.reason, "retain this explanation");
}

#[test]
fn legacy_transport_remains_unchanged_for_small_responses() {
    let wire = br#"{"static_analysis":{"facts":[]},"semantic_ir":null,"semantic_projection":{"value":1},"semantic_metadata":null,"semantic_failure":null}"#;
    let response: WorkerResponse = serde_json::from_slice(wire).unwrap();
    let mut written = Vec::new();
    write_worker_response(&mut written, &response, MAX_OUTPUT_BYTES).expect("response writes");
    assert_eq!(written, wire);

    let parsed = parse_worker_response(wire, MAX_OUTPUT_BYTES, || None).expect("legacy parses");
    assert_eq!(parsed.static_analysis.get(), r#"{"facts":[]}"#);
    assert_eq!(parsed.semantic_projection.unwrap().get(), r#"{"value":1}"#);
}

#[test]
fn decoded_size_admission_checks_declared_and_actual_bytes() {
    let wire = compressed_wire(SMALL_BODY);
    parse_worker_response(&wire, SMALL_BODY.len(), || None).expect("exact limit is accepted");
    assert_protocol_failure(&wire, SMALL_BODY.len() - 1, "decoded bytes");

    let mut declaration = envelope(&gzip(SMALL_BODY), SMALL_BODY.len() + 1);
    let wire = checkpoint_and_terminal(&serde_json::to_vec(&declaration).unwrap());
    assert_protocol_failure(&wire, SMALL_BODY.len() + 1, "expected");

    // An envelope cannot make an oversized valid body admissible by lying.
    let large_body = format!(
        r#"{{"semantic_projection":{{"padding":"{}"}}}}"#,
        "x".repeat(4096)
    );
    declaration = envelope(&gzip(large_body.as_bytes()), 512);
    let wire = checkpoint_and_terminal(&serde_json::to_vec(&declaration).unwrap());
    assert_protocol_failure(&wire, 512, "decoded byte limit");
}

#[test]
fn compressed_transport_rejects_corruption_and_trailing_members() {
    let valid = gzip(SMALL_BODY);
    let mut corrupt_crc = valid.clone();
    let crc_position = corrupt_crc.len() - 8;
    corrupt_crc[crc_position] ^= 1;
    let mut second_member = valid.clone();
    second_member.extend_from_slice(&valid);
    let mut trailing_data = valid.clone();
    trailing_data.extend_from_slice(b"extra");

    for (payload, expected) in [
        (corrupt_crc, "response body"),
        (valid[..valid.len() - 3].to_vec(), "response body"),
        (second_member, "trailing gzip data"),
        (trailing_data, "trailing gzip data"),
    ] {
        let wire = checkpoint_and_terminal(
            &serde_json::to_vec(&envelope(&payload, SMALL_BODY.len())).unwrap(),
        );
        assert_protocol_failure(&wire, MAX_OUTPUT_BYTES, expected);
    }

    let mut invalid_base64 = envelope(&valid, SMALL_BODY.len());
    invalid_base64["payload"] = serde_json::Value::String("not base64!".to_owned());
    let wire = checkpoint_and_terminal(&serde_json::to_vec(&invalid_base64).unwrap());
    assert_protocol_failure(&wire, MAX_OUTPUT_BYTES, "response body");
}

#[test]
fn compressed_transport_rejects_ambiguous_envelopes_and_bodies() {
    let valid = envelope(&gzip(SMALL_BODY), SMALL_BODY.len());
    let replacements = [
        ("protocol", serde_json::Value::Null),
        ("protocol", serde_json::json!("future-protocol")),
        ("version", serde_json::json!(2)),
        ("encoding", serde_json::json!("unknown")),
        ("unexpected", serde_json::json!(true)),
    ];
    for (field, replacement) in replacements {
        let mut changed = valid.clone();
        changed[field] = replacement;
        let wire = checkpoint_and_terminal(&serde_json::to_vec(&changed).unwrap());
        assert_protocol_failure(&wire, MAX_OUTPUT_BYTES, "envelope");
    }

    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("decoded_bytes");
    let wire = checkpoint_and_terminal(&serde_json::to_vec(&missing).unwrap());
    assert_protocol_failure(&wire, MAX_OUTPUT_BYTES, "envelope");

    let terminal = serde_json::to_string(&valid).unwrap();
    let duplicate = terminal.replacen('{', r#"{"protocol":null,"#, 1);
    assert_protocol_failure(
        &checkpoint_and_terminal(duplicate.as_bytes()),
        MAX_OUTPUT_BYTES,
        "duplicate field",
    );

    for body in [
        br#"{"semantic_projection":null,"unexpected":true}"#.as_slice(),
        br#"{"semantic_projection":null,"semantic_projection":{}}"#.as_slice(),
    ] {
        assert_protocol_failure(&compressed_wire(body), MAX_OUTPUT_BYTES, "response body");
    }
}

#[test]
fn compressed_body_must_end_after_its_json_value() {
    let mut whitespace = SMALL_BODY.to_vec();
    whitespace.extend_from_slice(b" \n\r\t");
    let parsed = parse_worker_response(&compressed_wire(&whitespace), MAX_OUTPUT_BYTES, || None)
        .expect("trailing JSON whitespace is valid");
    assert_eq!(
        parsed.semantic_projection.unwrap().get(),
        r#"{"micros":7,"order":[2,1]}"#
    );

    for suffix in [b"{}".as_slice(), b"garbage".as_slice()] {
        let mut body = SMALL_BODY.to_vec();
        body.extend_from_slice(suffix);
        assert_protocol_failure(
            &compressed_wire(&body),
            MAX_OUTPUT_BYTES,
            "trailing characters",
        );
    }

    let omitted = compressed_wire(br#"{"semantic_projection":{"value":1}}"#);
    let parsed = parse_worker_response(&omitted, MAX_OUTPUT_BYTES, || None)
        .expect("omitted optional fields remain absent");
    assert_eq!(parsed.semantic_projection.unwrap().get(), r#"{"value":1}"#);
    assert!(parsed.semantic_ir.is_none());
    assert!(parsed.semantic_metadata.is_none());
    assert!(parsed.semantic_failure.is_none());
}

#[test]
fn checkpoint_is_first_and_cannot_stand_in_for_a_terminal_response() {
    let terminal = serde_json::to_vec(&envelope(&gzip(SMALL_BODY), SMALL_BODY.len())).unwrap();
    assert_protocol_failure(&terminal, MAX_OUTPUT_BYTES, "missing its static checkpoint");
    assert_protocol_failure(CHECKPOINT, MAX_OUTPUT_BYTES, "only a static checkpoint");
    assert!(parse_checkpoint(&terminal).is_none());
    let mut later_checkpoint = terminal.clone();
    later_checkpoint.push(b'\n');
    later_checkpoint.extend_from_slice(CHECKPOINT);
    assert!(parse_checkpoint(&later_checkpoint).is_none());

    let mut extra_frame = CHECKPOINT.to_vec();
    extra_frame.push(b'\n');
    extra_frame.extend_from_slice(&checkpoint_and_terminal(&terminal));
    assert_protocol_failure(&extra_frame, MAX_OUTPUT_BYTES, "unexpected frames");

    let mut invalid_checkpoint = br#"{"static_analysis":{},"unexpected":true}"#.to_vec();
    invalid_checkpoint.push(b'\n');
    invalid_checkpoint.extend_from_slice(&terminal);
    assert_protocol_failure(
        &invalid_checkpoint,
        MAX_OUTPUT_BYTES,
        "invalid static checkpoint",
    );
}

#[test]
fn decode_interruptions_retain_their_cause_and_static_checkpoint() {
    let body = format!(
        r#"{{"semantic_projection":{{"padding":"{}"}}}}"#,
        "x".repeat(512 * 1024)
    );
    let wire = compressed_wire(body.as_bytes());
    for expected in [
        WorkerFailure::Cancelled,
        WorkerFailure::Timeout { timeout_ms: 30_000 },
    ] {
        let mut checks = 0;
        let failure = parse_worker_response(&wire, MAX_OUTPUT_BYTES, || {
            checks += 1;
            (checks > 3).then(|| expected.clone())
        })
        .expect_err("interrupted decode must fail");
        assert_eq!(failure.is_cancelled(), expected.is_cancelled());
        assert_eq!(failure.is_timeout(), expected.is_timeout());
        let partial = with_checkpoint(failure, &wire);
        assert_eq!(
            partial.static_checkpoint().unwrap().get(),
            r#"{"facts":[2,1],"text":"\ud800"}"#
        );
    }
}

#[test]
fn invalid_worker_memory_budgets_fail_before_launch() {
    let request = WorkerRequest {
        max_heap_mb: None,
        node_budget: 1,
        unknown_budget: 1,
        file: None,
        source: "let x = 1;".to_owned(),
        path: None,
    };
    for megabytes in [0, u64::MAX] {
        let failure = analyze_source_with_worker(
            &request,
            &WorkerLimits {
                max_heap_mb: Some(megabytes),
                timeout: std::time::Duration::from_secs(30),
            },
            || false,
        )
        .expect_err("unaddressable memory budget must fail");
        assert!(
            matches!(failure, WorkerFailure::Protocol(reason) if reason.contains("heap budget"))
        );
    }
}
