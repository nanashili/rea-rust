#![cfg(unix)]
//! Public stdio MCP coverage for migrated residual-unknown query tools.
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

struct McpChild {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl McpChild {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rea-native"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
        }
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        writeln!(self.input, "{request}").unwrap();

        let mut line = String::new();
        self.output.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn initialize(&mut self) {
        let response = self.request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "unknown-tools-test", "version": "1"},
            }),
        );
        assert!(response["result"].is_object(), "{response}");
    }

    fn call_tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn list_and_verify_unknown_tools_are_advertised_and_return_session_results() {
    let mut server = McpChild::start();
    server.initialize();

    let listing = server.request(2, "tools/list", json!({}));
    let tools = listing["result"]["tools"].as_array().unwrap();
    for name in [
        "list_unknowns",
        "verify_unknown_resolution",
        "compare_web_captures",
        "compare_web_screenshots",
    ] {
        assert!(
            tools.iter().any(|tool| tool["name"] == name),
            "missing {name}: {listing}"
        );
    }
    let capture_contract = tools
        .iter()
        .find(|tool| tool["name"] == "compare_web_captures")
        .unwrap();
    let expected_capture_contract: Value =
        serde_json::from_str(include_str!("../contracts/compare_web_captures.json")).unwrap();
    assert_eq!(
        capture_contract["inputSchema"],
        expected_capture_contract["inputSchema"]
    );
    let screenshot_contract = tools
        .iter()
        .find(|tool| tool["name"] == "compare_web_screenshots")
        .unwrap();
    let expected_screenshot_contract: Value =
        serde_json::from_str(include_str!("../contracts/compare_web_screenshots.json")).unwrap();
    assert_eq!(
        screenshot_contract["inputSchema"],
        expected_screenshot_contract["inputSchema"]
    );
    let list_contract = tools
        .iter()
        .find(|tool| tool["name"] == "list_unknowns")
        .unwrap();
    assert_eq!(
        list_contract["inputSchema"]["properties"]["offset"]["maximum"],
        9_007_199_254_740_991_u64
    );
    assert_eq!(
        list_contract["outputSchema"]["$defs"]["__schema0"]["properties"]["next_offset"]["anyOf"]
            [1]["type"],
        "null"
    );

    let listed = server.request(
        3,
        "tools/call",
        json!({"name": "list_unknowns", "arguments": {}}),
    );
    assert_eq!(
        listed["result"]["structuredContent"]["result"],
        json!({
            "items": [],
            "total": 0,
            "offset": 0,
            "next_offset": null,
        })
    );
    assert!(listed["result"].get("isError").is_none());

    let captures = server.call_tool(
        6,
        "compare_web_captures",
        json!({
            "before": {"inspection": {"target": {"target_id": "before"}}},
            "after": {"inspection": {"target": {"target_id": "after"}}}
        }),
    );
    assert_eq!(
        captures["result"]["structuredContent"]["result"]["overall_status"],
        "unknown"
    );
    assert!(captures["result"].get("isError").is_none());

    let invalid_screenshot = server.call_tool(
        7,
        "compare_web_screenshots",
        json!({"before": {}, "after": {}}),
    );
    assert_eq!(invalid_screenshot["result"]["isError"], true);

    let invalid = server.request(
        4,
        "tools/call",
        json!({"name": "list_unknowns", "arguments": {"status": "pending"}}),
    );
    assert_eq!(invalid["result"]["isError"], true);
    assert!(
        invalid["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("list_unknowns")
    );

    let missing = server.request(
        5,
        "tools/call",
        json!({
            "name": "verify_unknown_resolution",
            "arguments": {"unknown_id": format!("unk_{}", "0".repeat(64))},
        }),
    );
    assert_eq!(missing["result"]["isError"], true);
    assert!(
        missing["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("not present")
    );
}

#[test]
fn unknown_mutations_preserve_scope_evidence_and_revision_atomicity() {
    let mut server = McpChild::start();
    server.initialize();

    let listing = server.request(2, "tools/list", json!({}));
    let tools = listing["result"]["tools"].as_array().unwrap();
    for name in ["record_unknown", "update_unknown"] {
        assert!(
            tools.iter().any(|tool| tool["name"] == name),
            "missing {name}: {listing}"
        );
    }
    let record_contract = tools
        .iter()
        .find(|tool| tool["name"] == "record_unknown")
        .unwrap();
    let expected_record_contract: Value =
        serde_json::from_str(include_str!("../contracts/record_unknown.json")).unwrap();
    assert_eq!(record_contract, &expected_record_contract);
    assert_eq!(record_contract["annotations"]["readOnlyHint"], false);
    let update_contract = tools
        .iter()
        .find(|tool| tool["name"] == "update_unknown")
        .unwrap();
    let expected_update_contract: Value =
        serde_json::from_str(include_str!("../contracts/update_unknown.json")).unwrap();
    assert_eq!(update_contract, &expected_update_contract);
    assert_eq!(
        update_contract["inputSchema"]["properties"]["expected_revision"]["maximum"],
        9_007_199_254_740_991_u64
    );

    let first = server.call_tool(
        3,
        "record_unknown",
        record_arguments("Does this branch require an external service?"),
    );
    let first_unknown = success_result(&first);
    assert_eq!(first_unknown["revision"], 1);
    assert_eq!(first_unknown["status"], "open");
    assert_eq!(first_unknown["scope_digest"], Value::Null);
    assert_eq!(first_unknown["supporting_evidence_ids"], json!([]));
    assert_eq!(first_unknown["contradicting_evidence_ids"], json!([]));
    assert_eq!(
        first_unknown["mutation_evidence_ids"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let first_id = first_unknown["unknown_id"].as_str().unwrap().to_owned();

    let duplicate = server.call_tool(
        4,
        "record_unknown",
        record_arguments("Does\tthis   branch require an external service?"),
    );
    assert_eq!(failure_code(&duplicate), "revision_conflict");

    let invalid_reference = server.call_tool(5, "record_unknown", {
        let mut arguments = record_arguments("Does a missing Evidence link fail atomically?");
        arguments["supporting_evidence_ids"] = json!([format!("ev_{}", "0".repeat(64))]);
        arguments
    });
    assert_eq!(
        failure_code(&invalid_reference),
        "evidence_integrity_mismatch"
    );

    let extra_field = server.call_tool(6, "record_unknown", {
        let mut arguments = record_arguments("Reject unknown mutation properties.");
        arguments["unexpected"] = json!(true);
        arguments
    });
    assert_eq!(extra_field["result"]["isError"], true);
    assert!(
        extra_field["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("record_unknown")
    );

    let inspection = server.call_tool(
        7,
        "inspect_rust_binary",
        json!({"path": std::env::current_exe().unwrap()}),
    );
    assert!(
        inspection["result"].get("isError").is_none(),
        "{inspection}"
    );
    let inspected_evidence = &inspection["result"]["structuredContent"];
    let target_digest = inspected_evidence["subject"]["digest"]["sha256"]
        .as_str()
        .unwrap()
        .to_owned();

    let second = server.call_tool(
        8,
        "record_unknown",
        record_arguments("Does this branch require an external service?"),
    );
    let second_unknown = success_result(&second);
    let second_id = second_unknown["unknown_id"].as_str().unwrap().to_owned();
    assert_ne!(first_id, second_id);
    assert_eq!(second_unknown["scope_digest"], target_digest);

    let initial_update = server.call_tool(
        9,
        "update_unknown",
        update_arguments(&second_id, 1, "investigating", Value::Null),
    );
    let revision_two = success_result(&initial_update);
    assert_eq!(revision_two["revision"], 2);
    assert_eq!(
        revision_two["previous_revision_digest"],
        second_unknown["revision_digest"]
    );
    assert_eq!(revision_two["status"], "investigating");
    assert_eq!(
        revision_two["mutation_evidence_ids"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let resolution = json!({
        "disposition": "withdrawn",
        "rationale": "This behavior is outside the investigation scope.",
        "evidence_ids": [],
    });
    let resolved_update = server.call_tool(
        10,
        "update_unknown",
        update_arguments(&second_id, 2, "resolved", resolution),
    );
    let revision_three = success_result(&resolved_update);
    assert_eq!(revision_three["revision"], 3);
    assert_eq!(
        revision_three["previous_revision_digest"],
        revision_two["revision_digest"]
    );
    assert_eq!(revision_three["status"], "resolved");
    assert_eq!(revision_three["resolution"]["disposition"], "withdrawn");
    assert_eq!(
        revision_three["mutation_evidence_ids"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    let stale_update = server.call_tool(
        11,
        "update_unknown",
        update_arguments(&second_id, 2, "blocked", Value::Null),
    );
    assert_eq!(failure_code(&stale_update), "revision_conflict");

    let listed = server.call_tool(12, "list_unknowns", json!({}));
    let listed_unknowns = &success_result(&listed)["items"];
    assert_eq!(listed_unknowns.as_array().unwrap().len(), 2);
    assert!(
        listed_unknowns
            .as_array()
            .unwrap()
            .iter()
            .any(|unknown| unknown["unknown_id"] == second_id && unknown["revision"] == 3)
    );

    let verified = server.call_tool(
        13,
        "verify_unknown_resolution",
        json!({"unknown_id": second_id}),
    );
    assert_eq!(success_result(&verified)["valid"], true);
    assert_eq!(success_result(&verified)["truthVerified"], false);

    let bundle = server.call_tool(14, "get_evidence_bundle", json!({}));
    let retained = success_result(&bundle);
    assert_eq!(retained["records"].as_array().unwrap().len(), 5);
    assert_eq!(retained["unknowns"].as_array().unwrap().len(), 4);

    let first_mutation_id = first_unknown["mutation_evidence_ids"][0].as_str().unwrap();
    let first_mutation = retained["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["evidence_id"] == first_mutation_id)
        .unwrap();
    assert_eq!(first_mutation["operation"], "record_unknown");
    assert_eq!(
        first_mutation["predicate_type"],
        "rea.residual-unknown-mutation"
    );
    assert_eq!(first_mutation["subject"], Value::Null);
    assert_eq!(first_mutation["provider"]["id"], "rea-unknown-registry");
    assert_eq!(first_mutation["normalized_result"]["action"], "record");
    assert_eq!(first_mutation["evidence_links"], json!([]));

    let second_mutation_id = second_unknown["mutation_evidence_ids"][0].as_str().unwrap();
    let second_mutation = retained["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["evidence_id"] == second_mutation_id)
        .unwrap();
    assert_eq!(
        second_mutation["subject"]["digest"]["sha256"],
        target_digest
    );
}

fn record_arguments(question: &str) -> Value {
    json!({
        "question": question,
        "severity": "medium",
        "domain": "protocol",
        "required_authority": null,
        "required_confidence": "inferred",
        "required_environment": null,
        "recommended_probes": [],
        "relationships": [],
    })
}

fn update_arguments(
    unknown_id: &str,
    expected_revision: u64,
    status: &str,
    resolution: Value,
) -> Value {
    json!({
        "unknown_id": unknown_id,
        "expected_revision": expected_revision,
        "status": status,
        "severity": "high",
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "required_authority": null,
        "required_confidence": "inferred",
        "required_environment": null,
        "recommended_probes": [],
        "relationships": [],
        "resolution": resolution,
    })
}

fn success_result(response: &Value) -> &Value {
    assert!(response["result"].get("isError").is_none(), "{response}");
    &response["result"]["structuredContent"]["result"]
}

fn failure_code(response: &Value) -> String {
    assert_eq!(response["result"]["isError"], true, "{response}");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("failure should include a text diagnostic");
    let envelope: Value = serde_json::from_str(text).expect("failure text should be JSON");
    envelope["error"]["code"]
        .as_str()
        .expect("failure should include its stable error code")
        .to_owned()
}
