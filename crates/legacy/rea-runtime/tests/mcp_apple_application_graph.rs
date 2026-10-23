#![cfg(unix)]
//! Public CLI and stdio MCP coverage for Apple inventory graph projection.

use rea_core::{canonical_json, evidence::record::EvidenceRecord};
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
                "clientInfo":{"name":"apple-application-graph-test","version":"1"}
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

struct FixtureEntry {
    path: &'static str,
    kind: &'static str,
    format: &'static str,
    unavailable: bool,
}

fn authenticated_inventory_input() -> Value {
    let root_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let root_artifact_id = artifact_id(root_sha256);
    let entries = [
        FixtureEntry {
            path: "Payload/Mobile.app/Info.plist",
            kind: "file",
            format: "plist",
            unavailable: false,
        },
        FixtureEntry {
            path: "Payload/Mobile.app/Mobile",
            kind: "file",
            format: "mach-o",
            unavailable: false,
        },
        FixtureEntry {
            path: "Payload/Mobile.app/Resources/main.js",
            kind: "file",
            format: "javascript-bundle",
            unavailable: false,
        },
        FixtureEntry {
            path: "Payload/Mobile.app/Frameworks/libsample.dylib",
            kind: "file",
            format: "mach-o",
            unavailable: false,
        },
        FixtureEntry {
            path: "Payload/Mobile.app/Frameworks/Current",
            kind: "symlink",
            format: "file",
            unavailable: false,
        },
        FixtureEntry {
            path: "Payload/Mobile.app/Resources/locked.dylib",
            kind: "file",
            format: "mach-o",
            unavailable: true,
        },
        FixtureEntry {
            path: "Payload/Mobile.app/Contents/Resources/._hidden.dylib",
            kind: "file",
            format: "mach-o",
            unavailable: false,
        },
        FixtureEntry {
            path: "Payload/Mobile.app/PlugIns/Share.appex/Info.plist",
            kind: "file",
            format: "plist",
            unavailable: false,
        },
        FixtureEntry {
            path: "SwiftSupport/iphoneos/libswiftCore.dylib",
            kind: "file",
            format: "mach-o",
            unavailable: false,
        },
    ];

    let mut nodes = vec![artifact_node(root_sha256, "file")];
    let mut occurrences = vec![artifact_occurrence(
        &root_artifact_id,
        ".",
        "file",
        Some(&root_artifact_id),
        "ipa",
        false,
    )];

    for entry in entries {
        if entry.kind == "symlink" || entry.unavailable {
            occurrences.push(artifact_occurrence(
                &root_artifact_id,
                entry.path,
                entry.kind,
                None,
                entry.format,
                entry.unavailable,
            ));
            continue;
        }

        let content_sha256 = digest(&json!({"fixture_path":entry.path}));
        let content_id = artifact_id(&content_sha256);
        let content_format = if matches!(entry.format, "mach-o" | "plist") {
            entry.format
        } else {
            "file"
        };
        nodes.push(artifact_node(&content_sha256, content_format));
        occurrences.push(artifact_occurrence(
            &root_artifact_id,
            entry.path,
            entry.kind,
            Some(&content_id),
            entry.format,
            false,
        ));
    }

    nodes.sort_by(|left, right| {
        left["artifact_id"]
            .as_str()
            .cmp(&right["artifact_id"].as_str())
    });
    occurrences.sort_by(|left, right| {
        left["logical_path"]
            .as_str()
            .cmp(&right["logical_path"].as_str())
    });

    let graph_sha256 = digest(&json!({
        "nodes": nodes,
        "occurrences": occurrences,
        "edges": [],
        "integrity_contradictions": [],
    }));
    let manifest_id = digest(&json!({
        "root_artifact_id": root_artifact_id,
        "graph_sha256": graph_sha256,
    }));
    let normalized_result = json!({
        "manifest": {
            "manifest_id": format!("agm_{manifest_id}"),
            "root_artifact_id": root_artifact_id,
            "root_sha256": root_sha256,
            "root_format": "ipa",
            "graph_sha256": graph_sha256,
            "node_count": nodes.len(),
            "occurrence_count": occurrences.len(),
            "edge_count": 0,
        },
        "nodes": nodes,
        "occurrences": occurrences,
        "edges": [],
        "provenance": [],
        "integrity_contradictions": [],
        "coverage": {"scope":"container-entries","status":"complete"},
        "limitations": [],
    });
    let unsigned = json!({
        "subject": {
            "name":"Mobile.ipa",
            "digest":{"sha256":root_sha256},
            "format":"ipa",
            "architecture":null,
            "local_path":"/tmp/Mobile.ipa"
        },
        "provider":{"id":"rea-artifact-inventory","name":"REA artifact inventory","version":"1"},
        "analysis_profile":null,
        "predicate_type":"rea.artifact-inventory",
        "operation":"inventory_artifact",
        "parameters":{"path":"/tmp/Mobile.ipa"},
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

fn authenticated_inspection_input() -> Value {
    let inventory = authenticated_inventory_input()["inventory_evidence"][0].clone();
    let inventory_id = inventory["evidence_id"]
        .as_str()
        .expect("inventory Evidence ID");
    let inventory_result = &inventory["normalized_result"];
    let manifest = &inventory_result["manifest"];

    let substep_identity = json!({
        "operation":"inventory_artifact",
        "evidence_id":inventory_id,
    });
    let substeps = json!([{
        "substep_id":format!("ais_{}", digest(&substep_identity)),
        "operation":"inventory_artifact",
        "status":"completed",
        "evidence_id":inventory_id,
        "evidence":inventory,
    }]);
    let observation_identity = json!({
        "kind":"root-manifest",
        "subject":manifest["root_artifact_id"],
        "value":manifest,
        "evidence_id":inventory_id,
    });
    let observations = json!([{
        "observation_id":format!("aio_{}", digest(&observation_identity)),
        "kind":"root-manifest",
        "subject":manifest["root_artifact_id"],
        "value":manifest,
        "evidence_id":inventory_id,
    }]);
    let subject = json!({
        "manifest_id":manifest["manifest_id"],
        "root_artifact_id":manifest["root_artifact_id"],
        "root_sha256":manifest["root_sha256"],
        "root_format":manifest["root_format"],
    });
    let semantic = json!({
        "subject":subject,
        "substeps":substeps,
        "observations":observations,
        "hypotheses":[],
        "contradictions":[],
        "unexplored_branches":[],
        "next_probes":[],
        "coverage":{
            "status":"complete-within-substeps",
            "substeps_completed":1,
            "observations_retained":1,
            "observations_omitted":0,
            "hypotheses_retained":0,
            "hypotheses_omitted":0,
            "unexplored_branches_retained":0,
            "unexplored_branches_omitted":0,
            "next_probes_retained":0,
            "next_probes_omitted":0,
        },
        "evidence_links":[inventory_id],
        "limitations":[
            "Inspection derives bounded static hypotheses and next probes; it does not execute the artifact or claim format-specific semantics."
        ],
    });
    let mut normalized_result = semantic.clone();
    normalized_result["inspection_id"] = Value::String(format!("ai_{}", digest(&semantic)));

    let unsigned = json!({
        "subject":inventory["subject"],
        "provider":{
            "id":"rea-artifact-inventory",
            "name":"REA artifact inventory",
            "version":"1",
        },
        "analysis_profile":null,
        "predicate_type":"rea.artifact-inspection",
        "operation":"inspect_artifact",
        "parameters":{"integrity_policy":"stop"},
        "raw_result":null,
        "normalized_result":normalized_result,
        "confidence":"observed",
        "authority":"shipped-artifact",
        "environment":null,
        "limitations":semantic["limitations"],
        "relationship_coverage":null,
        "locations":[],
        "evidence_links":[inventory_id],
    });
    let raw = serde_json::value::to_raw_value(&unsigned).expect("inspection Evidence JSON");
    let record = EvidenceRecord::create_unsigned(&raw).expect("authenticated inspection Evidence");
    let evidence: Value = serde_json::from_str(record.raw().get()).expect("Evidence JSON");

    json!({"inventory_evidence":[evidence]})
}

fn seal_evidence(unsigned: Value) -> Value {
    let raw = serde_json::value::to_raw_value(&unsigned).expect("unsigned Evidence JSON");
    let record = EvidenceRecord::create_unsigned(&raw).expect("valid Evidence");
    serde_json::from_str(record.raw().get()).expect("Evidence JSON")
}

fn reseal_evidence(mut evidence: Value) -> Value {
    let evidence_id = evidence
        .as_object_mut()
        .expect("Evidence object")
        .remove("evidence_id");
    assert!(evidence_id.is_some(), "Evidence ID must be present");
    seal_evidence(evidence)
}

fn artifact_node(sha256: &str, format: &str) -> Value {
    json!({
        "artifact_id": artifact_id(sha256),
        "format": format,
        "sha256": sha256,
        "size": 1,
        "media_type": null,
        "architecture": null,
        "content_state": "materialized",
        "limitations": [],
    })
}

fn artifact_occurrence(
    root_artifact_id: &str,
    path: &str,
    kind: &str,
    content_id: Option<&str>,
    format: &str,
    unavailable: bool,
) -> Value {
    let identity = if path == "." {
        json!({"root":root_artifact_id})
    } else {
        json!({
            "root_artifact_id":root_artifact_id,
            "logical_path":path,
            "entry_kind":kind,
        })
    };
    json!({
        "occurrence_id": format!("occ_{}", digest(&identity)),
        "artifact_id": content_id,
        "parent_occurrence_id": null,
        "logical_path": path,
        "entry_kind": kind,
        "artifact_kind": "resource",
        "artifact_format": format,
        "declared_size": null,
        "compressed_size": null,
        "executable": false,
        "encrypted": false,
        "hash_status": if unavailable || kind == "symlink" { "unavailable" } else { "verified" },
        "source_location": null,
        "limitations": if unavailable { json!(["Fixture content identity is unavailable."]) } else { json!([]) },
    })
}

fn artifact_id(sha256: &str) -> String {
    format!("art_{}", digest(&json!({"sha256":sha256})))
}

fn digest(value: &Value) -> String {
    canonical_json::digest(value).expect("canonical JSON digest")
}

fn retained_summary(server: &mut McpChild, id: u64) -> Value {
    server.call_tool(id, "get_evidence_bundle", json!({"detail":"summary"}))
}

#[test]
fn project_apple_application_graph_cli_preserves_inventory_projection_facts() {
    let input = authenticated_inspection_input();
    let source_id = input["inventory_evidence"][0]["evidence_id"]
        .as_str()
        .expect("source Evidence ID");
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("project-apple-application-graph")
        .arg(input.to_string())
        .args(["--format", "json"])
        .output()
        .expect("run Apple application graph CLI");

    assert!(
        output.status.success(),
        "CLI exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout)
    );
    let evidence: Value = serde_json::from_slice(&output.stdout).expect("projected Evidence JSON");
    let projection = &evidence["normalized_result"];

    assert_eq!(evidence["operation"], "project_apple_application_graph");
    assert_eq!(evidence["predicate_type"], "rea.apple-application-graph");
    assert_eq!(evidence["provider"]["id"], "rea-apple-application");
    assert_eq!(evidence["authority"], "analyst-inference");
    assert_eq!(evidence["confidence"], "inferred");
    assert_eq!(evidence["subject"]["name"], "Mobile.ipa");
    assert_eq!(evidence["subject"]["local_path"], "/tmp/Mobile.ipa");
    assert_eq!(evidence["evidence_links"], json!([source_id]));
    assert_eq!(projection["root_format"], "ipa");
    assert_eq!(projection["platforms"], json!(["ios"]));
    assert_eq!(
        projection["application_roots"],
        json!(["Payload/Mobile.app"])
    );
    assert_eq!(
        projection["bundles"][1],
        json!({
            "path":"Payload/Mobile.app/PlugIns/Share.appex",
            "parent_path":"Payload/Mobile.app",
            "layout":"shallow",
            "role":"app-extension",
            "role_basis":"path-convention",
            "info_plist_path":"Payload/Mobile.app/PlugIns/Share.appex/Info.plist",
            "executable_candidates":[],
            "signing_paths":[],
        })
    );
    assert_eq!(
        projection["components"]["native_libraries"]
            .as_array()
            .expect("native libraries")
            .iter()
            .map(|component| component["path"].as_str().expect("component path"))
            .collect::<Vec<_>>(),
        [
            "Payload/Mobile.app/Frameworks/libsample.dylib",
            "SwiftSupport/iphoneos/libswiftCore.dylib",
        ]
    );
    assert_eq!(
        projection["bridge_candidates"],
        json!([
            {
                "source_path":"Payload/Mobile.app/Resources/main.js",
                "native_path":"Payload/Mobile.app/Frameworks/libsample.dylib",
                "basis":"javascript-and-native-content"
            },
            {
                "source_path":"Payload/Mobile.app/Resources/main.js",
                "native_path":"Payload/Mobile.app/Mobile",
                "basis":"javascript-and-native-content"
            }
        ])
    );
    assert_eq!(
        projection["symlinks"],
        json!(["Payload/Mobile.app/Frameworks/Current"])
    );
    assert_eq!(
        projection["unavailable_components"][0]["path"],
        "Payload/Mobile.app/Resources/locked.dylib"
    );
    assert_eq!(projection["coverage"]["inventory_complete"], true);
    assert_eq!(projection["coverage"]["status"], "partial");
    assert!(
        projection["limitations"]
            .as_array()
            .expect("projection limitations")
            .iter()
            .any(|limitation| {
                limitation
                    .as_str()
                    .is_some_and(|value| value.contains("AppleDouble sidecar entries"))
            })
    );
}

#[test]
fn project_apple_application_graph_is_advertised_and_retained_by_mcp() {
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
        .find(|tool| tool["name"] == "project_apple_application_graph")
        .unwrap_or_else(|| panic!("Apple graph contract missing from {listing}"));
    let expected: Value = serde_json::from_str(include_str!(
        "../contracts/project_apple_application_graph.json"
    ))
    .expect("Apple graph contract is valid JSON");
    assert_eq!(tool, &expected);

    let response = server.call_tool(3, "project_apple_application_graph", input);
    assert!(response["result"].get("isError").is_none(), "{response}");
    let evidence = &response["result"]["structuredContent"];
    assert_eq!(evidence["operation"], "project_apple_application_graph");
    assert_eq!(evidence["provider"]["id"], "rea-apple-application");
    assert_eq!(evidence["authority"], "analyst-inference");
    assert_eq!(evidence["evidence_links"], json!([source_id]));
    assert_eq!(
        evidence["normalized_result"]["bridge_candidate_coverage"]["total_candidates"],
        2
    );

    let summary = retained_summary(&mut server, 4);
    let retained = &summary["result"]["structuredContent"]["result"];
    assert_eq!(retained["total_retained_records"], 2);
    let operations = retained["records"]
        .as_array()
        .expect("retained Evidence records")
        .iter()
        .filter_map(|record| record["operation"].as_str())
        .collect::<Vec<_>>();
    assert!(operations.contains(&"inventory_artifact"), "{retained}");
    assert!(
        operations.contains(&"project_apple_application_graph"),
        "{retained}"
    );
}

#[test]
fn project_apple_application_graph_rejects_modified_authenticated_inventory() {
    let mut input = authenticated_inventory_input();
    input["inventory_evidence"][0]["normalized_result"]["limitations"] =
        json!(["changed after authentication"]);
    let mut server = McpChild::start();
    server.initialize();

    let response = server.call_tool(2, "project_apple_application_graph", input);
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
        "project_apple_application_graph"
    );

    let summary = retained_summary(&mut server, 3);
    assert_eq!(
        summary["result"]["structuredContent"]["result"]["total_retained_records"],
        0
    );
}

#[test]
fn project_apple_application_graph_rejects_unknown_inspection_fields() {
    let mut input = authenticated_inspection_input();
    let mut carrier = input["inventory_evidence"][0].clone();
    carrier["normalized_result"]["unrecognized"] = json!(true);
    let resealed = reseal_evidence(carrier);
    input["inventory_evidence"][0] = resealed;

    let mut server = McpChild::start();
    server.initialize();
    let response = server.call_tool(2, "project_apple_application_graph", input);
    assert_eq!(response["result"]["isError"], true, "{response}");

    let failure: Value = serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("text failure response"),
    )
    .expect("failure envelope JSON");
    assert_eq!(failure["error"]["code"], "invalid_request");
    assert_eq!(
        failure["error"]["details"]["operation"],
        "project_apple_application_graph"
    );
}

#[test]
fn project_apple_application_graph_strips_unknown_nested_inventory_fields() {
    let mut input = authenticated_inventory_input();
    let mut carrier = input["inventory_evidence"][0].clone();
    carrier["normalized_result"]["nodes"][0]["future_hint"] = json!("ignored by source schema");
    input["inventory_evidence"][0] = reseal_evidence(carrier);

    let mut server = McpChild::start();
    server.initialize();
    let response = server.call_tool(2, "project_apple_application_graph", input);

    assert!(
        response["result"]["structuredContent"].is_object(),
        "{response}"
    );
    assert_eq!(
        response["result"]["structuredContent"]["normalized_result"]["coverage"]["inventory_complete"],
        true
    );
}

#[test]
fn project_apple_application_graph_rejects_unknown_inventory_result_fields() {
    let mut input = authenticated_inventory_input();
    let mut carrier = input["inventory_evidence"][0].clone();
    carrier["normalized_result"]["unrecognized"] = json!(true);
    input["inventory_evidence"][0] = reseal_evidence(carrier);

    let mut server = McpChild::start();
    server.initialize();
    let response = server.call_tool(2, "project_apple_application_graph", input);
    assert_eq!(response["result"]["isError"], true, "{response}");
    let failure: Value = serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("text failure response"),
    )
    .expect("failure envelope JSON");
    assert_eq!(failure["error"]["code"], "invalid_request");
    assert_eq!(
        failure["error"]["details"]["operation"],
        "project_apple_application_graph"
    );
}
