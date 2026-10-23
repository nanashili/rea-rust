#![cfg(unix)]
//! Public stdio MCP coverage for Harmony inventory graph projection.

use rea_core::evidence::record::EvidenceRecord;
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
            .expect("start native MCP server");
        let input = child.stdin.take().expect("MCP stdin");
        let output = BufReader::new(child.stdout.take().expect("MCP stdout"));

        Self {
            child,
            input,
            output,
        }
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        writeln!(
            self.input,
            "{}",
            json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
        )
        .expect("write MCP request");

        let mut line = String::new();
        self.output.read_line(&mut line).expect("read MCP response");
        serde_json::from_str(&line).expect("parse MCP response")
    }

    fn initialize(&mut self) {
        let response = self.request(
            1,
            "initialize",
            json!({
                "protocolVersion":"2025-11-25",
                "capabilities":{},
                "clientInfo":{"name":"harmony-application-graph-test","version":"1"}
            }),
        );
        assert!(response["result"].is_object(), "{response}");
    }

    fn call_tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.request(id, "tools/call", json!({"name":name,"arguments":arguments}))
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn authenticated_inventory_input() -> Value {
    let root_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let root_artifact_id = format!("art_{root_sha256}");
    let code_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let code_artifact_id = format!("art_{code_sha256}");
    let normalized_result = json!({
        "manifest": {
            "manifest_id":"agm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "root_artifact_id":root_artifact_id,
            "root_sha256":root_sha256,
            "root_format":"hap",
            "graph_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "node_count":2,
            "occurrence_count":2,
            "edge_count":0
        },
        "nodes":[
            {"artifact_id":root_artifact_id,"format":"zip","sha256":root_sha256,"size":100,"media_type":null,"architecture":null,"content_state":"materialized","limitations":[]},
            {"artifact_id":code_artifact_id,"format":"file","sha256":code_sha256,"size":1,"media_type":null,"architecture":null,"content_state":"materialized","limitations":[]}
        ],
        "occurrences":[
            {"occurrence_id":"occ_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact_id":root_artifact_id,"parent_occurrence_id":null,"logical_path":".","entry_kind":"directory","artifact_kind":"container","artifact_format":"hap","declared_size":null,"compressed_size":null,"executable":false,"encrypted":false,"hash_status":"verified","source_location":null,"limitations":[]},
            {"occurrence_id":"occ_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","artifact_id":code_artifact_id,"parent_occurrence_id":"occ_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","logical_path":"module.abc","entry_kind":"file","artifact_kind":"unknown","artifact_format":"file","declared_size":1,"compressed_size":null,"executable":false,"encrypted":false,"hash_status":"verified","source_location":null,"limitations":[]}
        ],
        "edges":[],
        "provenance":[],
        "integrity_contradictions":[],
        "coverage":{"scope":"container-entries","status":"complete"},
        "limitations":[]
    });
    let unsigned = json!({
        "subject": {
            "name":"fixture.hap",
            "digest":{"sha256":root_sha256},
            "format":"hap",
            "architecture":null,
            "local_path":"/tmp/fixture.hap"
        },
        "provider":{"id":"rea-artifact-inventory","name":"REA artifact inventory","version":"1"},
        "analysis_profile":null,
        "predicate_type":"rea.artifact-inventory",
        "operation":"inventory_artifact",
        "parameters":{"path":"/tmp/fixture.hap"},
        "raw_result":null,
        "normalized_result":normalized_result,
        "confidence":"observed",
        "authority":"shipped-artifact",
        "environment":null,
        "limitations":[],
        "relationship_coverage":null,
        "locations":[],
        "evidence_links":[]
    });
    let raw = serde_json::value::to_raw_value(&unsigned).expect("unsigned Evidence JSON");
    let record = EvidenceRecord::create_unsigned(&raw).expect("authenticated inventory Evidence");
    let evidence: Value = serde_json::from_str(record.raw().get()).expect("Evidence JSON");

    json!({"inventory_evidence":[evidence]})
}

fn retained_summary(server: &mut McpChild, id: u64) -> Value {
    server.call_tool(id, "get_evidence_bundle", json!({"detail":"summary"}))
}

#[test]
fn project_harmony_application_graph_cli_emits_linked_evidence() {
    let input = authenticated_inventory_input().to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "project-harmony-application-graph",
            input.as_str(),
            "--format",
            "json",
        ])
        .output()
        .expect("run native Harmony graph command");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let evidence: Value = serde_json::from_slice(&output.stdout).expect("projected Evidence JSON");
    assert_eq!(evidence["operation"], "project_harmony_application_graph");
    assert_eq!(evidence["predicate_type"], "rea.harmony-application-graph");
    assert_eq!(evidence["provider"]["id"], "rea-harmony-application");
    assert_eq!(evidence["subject"]["local_path"], "/tmp/fixture.hap");
    assert_eq!(
        evidence["normalized_result"]["components"]["bytecode"][0]["path"],
        "module.abc"
    );
}

#[test]
fn project_harmony_application_graph_advertises_contract_and_retains_linked_evidence() {
    let input = authenticated_inventory_input();
    let source_id = input["inventory_evidence"][0]["evidence_id"]
        .as_str()
        .expect("source Evidence ID")
        .to_owned();
    let mut server = McpChild::start();
    server.initialize();

    let listing = server.request(2, "tools/list", json!({}));
    let tool = listing["result"]["tools"]
        .as_array()
        .expect("tool list")
        .iter()
        .find(|tool| tool["name"] == "project_harmony_application_graph")
        .unwrap_or_else(|| panic!("Harmony graph contract missing from {listing}"));
    let expected: Value = serde_json::from_str(include_str!(
        "../contracts/project_harmony_application_graph.json"
    ))
    .expect("Harmony graph contract is valid JSON");
    assert_eq!(tool, &expected);

    let response = server.call_tool(3, "project_harmony_application_graph", input);
    assert!(response["result"].get("isError").is_none(), "{response}");
    let evidence = &response["result"]["structuredContent"];
    assert_eq!(evidence["operation"], "project_harmony_application_graph");
    assert_eq!(evidence["predicate_type"], "rea.harmony-application-graph");
    assert_eq!(evidence["provider"]["id"], "rea-harmony-application");
    assert_eq!(evidence["authority"], "analyst-inference");
    assert_eq!(evidence["confidence"], "inferred");
    assert_eq!(evidence["subject"]["local_path"], "/tmp/fixture.hap");
    assert_eq!(evidence["evidence_links"], json!([source_id]));
    assert_eq!(
        evidence["normalized_result"]["components"]["bytecode"][0]["path"],
        "module.abc"
    );

    let summary = retained_summary(&mut server, 4);
    let retained = &summary["result"]["structuredContent"]["result"];
    assert_eq!(retained["total_retained_records"], 2);
    let operations = retained["records"]
        .as_array()
        .expect("retained records")
        .iter()
        .filter_map(|record| record["operation"].as_str())
        .collect::<Vec<_>>();
    assert!(operations.contains(&"inventory_artifact"), "{retained}");
    assert!(
        operations.contains(&"project_harmony_application_graph"),
        "{retained}"
    );
}

#[test]
fn project_harmony_application_graph_rejects_modified_inventory_without_retaining_it() {
    let mut input = authenticated_inventory_input();
    input["inventory_evidence"][0]["normalized_result"]["limitations"] =
        json!(["changed after authentication"]);
    let mut server = McpChild::start();
    server.initialize();

    let response = server.call_tool(2, "project_harmony_application_graph", input);
    assert_eq!(response["result"]["isError"], true, "{response}");
    let failure: Value = serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("text failure response"),
    )
    .expect("failure envelope JSON");
    assert_eq!(failure["error"]["code"], "evidence_integrity_mismatch");
    assert_eq!(
        failure["error"]["details"]["operation"],
        "project_harmony_application_graph"
    );

    let summary = retained_summary(&mut server, 3);
    assert_eq!(
        summary["result"]["structuredContent"]["result"]["total_retained_records"],
        0
    );
}
