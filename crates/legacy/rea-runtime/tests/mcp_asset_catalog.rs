#![cfg(unix)]
//! Public stdio MCP coverage for Apple asset-catalog contract selection.

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
                "clientInfo":{"name":"asset-catalog-test","version":"1"}
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

#[test]
fn inspect_asset_catalog_is_advertised_with_the_checked_contract() {
    let mut child = McpChild::start();
    child.initialize();

    let listing = child.request(2, "tools/list", json!({}));
    let contract = listing["result"]["tools"]
        .as_array()
        .expect("tools list")
        .iter()
        .find(|tool| tool["name"] == "inspect_asset_catalog")
        .unwrap_or_else(|| panic!("inspect_asset_catalog missing from {listing}"));
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_asset_catalog.json"))
            .expect("asset catalog contract is valid JSON");

    assert_eq!(contract, &expected);
    assert_eq!(contract["inputSchema"]["required"], json!(null));
    let parameters_reference = contract["outputSchema"]["properties"]["parameters"]["$ref"]
        .as_str()
        .expect("parameters schema reference");
    let parameters_definition = parameters_reference
        .strip_prefix("#/$defs/")
        .expect("parameters reference stays within the schema");
    assert_eq!(
        contract["outputSchema"]["$defs"][parameters_definition],
        json!({"type":"object","additionalProperties":{}})
    );
}

#[test]
fn inspect_asset_catalog_requires_an_active_macho_target() {
    let mut child = McpChild::start();
    child.initialize();

    let response = child.request(
        2,
        "tools/call",
        json!({"name":"inspect_asset_catalog","arguments":{"offset":3}}),
    );

    assert_eq!(response["result"]["isError"], true, "{response}");
    let failure: Value = serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("failure is returned as text"),
    )
    .expect("failure content is canonical JSON");
    assert_eq!(failure["error"]["code"], "unsupported_target");
    assert_eq!(
        failure["error"]["details"]["operation"],
        "inspect_asset_catalog"
    );
}

#[test]
fn inspect_asset_catalog_rejects_unknown_input_fields_before_target_lookup() {
    let mut child = McpChild::start();
    child.initialize();

    let response = child.request(
        2,
        "tools/call",
        json!({"name":"inspect_asset_catalog","arguments":{"path":"/tmp/App.app"}}),
    );

    assert_eq!(response["result"]["isError"], true, "{response}");
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("validation text")
            .contains("Unrecognized key")
    );
}
