#![cfg(unix)]
//! Public CLI and stdio MCP coverage for authenticated reconstruction evaluation.

use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

const OPERATION: &str = "evaluate_reconstruction_coverage";

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
                "clientInfo":{"name":"coverage-test","version":"1"}
            }),
        );
        assert!(response["result"].is_object(), "{response}");
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn missing_inventory_input() -> Value {
    json!({
        "coverage": {
            "evidence_bundle": {
                "artifacts": [],
                "providers": [],
                "environments": [],
                "scenarios": [],
                "captures": [],
                "unknowns": [],
                "records": []
            },
            "artifacts": [],
            "surfaces": [],
            "owners": [],
            "claims": [],
            "verifier_contracts": [],
            "verifier_results": [],
            "residual_unknown_ids": [],
            "contradictions": [],
            "package_proofs": [],
            "boundaries": [{
                "boundary_id": "replacement.cli",
                "title": "CLI replacement",
                "required_surface_ids": ["cli.help"],
                "required_claim_ids": ["claim.cli.help"],
                "required_package_proof_kinds": ["build"],
                "allowed_dispositions": [],
                "allowed_unknown_ids": []
            }]
        },
        "boundary_id": "replacement.cli"
    })
}

#[test]
fn cli_evaluates_a_valid_boundary_with_missing_inventory() {
    let input = missing_inventory_input().to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "evaluate-reconstruction-coverage",
            input.as_str(),
            "--format",
            "json",
        ])
        .output()
        .expect("run native coverage evaluation");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result: Value = serde_json::from_slice(&output.stdout).expect("coverage result JSON");
    assert_eq!(result["boundary_id"], "replacement.cli");
    assert_eq!(result["status"], "partial");
    assert_eq!(result["summary"]["reasons"], 3);
}

#[test]
fn mcp_advertises_source_schema_and_returns_the_evaluation_directly() {
    let mut server = McpChild::start();
    server.initialize();

    let listing = server.request(2, "tools/list", json!({}));
    let tool = listing["result"]["tools"]
        .as_array()
        .expect("tool list")
        .iter()
        .find(|tool| tool["name"] == OPERATION)
        .expect("coverage tool");
    let source: Value = serde_json::from_str(include_str!(
        "../contracts/evaluate_reconstruction_coverage.json"
    ))
    .expect("source contract JSON");
    assert_eq!(tool["inputSchema"], source["inputSchema"]);
    assert_eq!(tool["outputSchema"], source["outputSchema"]);

    let call = server.request(
        3,
        "tools/call",
        json!({"name":OPERATION,"arguments":missing_inventory_input()}),
    );
    assert_ne!(call["result"]["isError"], true);
    assert_eq!(call["result"]["structuredContent"]["status"], "partial");
    assert_eq!(call["result"]["structuredContent"]["summary"]["reasons"], 3);
}
