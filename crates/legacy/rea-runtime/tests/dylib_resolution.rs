#![cfg(unix)]

//! Public contract coverage for the native dylib-resolution entry point.

use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
};

#[test]
fn cli_help_advertises_explicit_root_dylib_resolution() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("--help")
        .output()
        .expect("run native help");

    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("trace-dylib-resolution INPUT --format json"));
}

#[test]
fn mcp_lists_dylib_resolution_contract() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args(["mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start native MCP");
    let mut input = child.stdin.take().expect("MCP stdin");
    let mut output = BufReader::new(child.stdout.take().expect("MCP stdout"));
    writeln!(input, "{}", json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"dylib-test","version":"1"}}})).unwrap();
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let initialize_response: Value = serde_json::from_str(&line).unwrap();
    assert!(
        initialize_response["result"].is_object(),
        "MCP initialize failed: {initialize_response}"
    );

    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
    )
    .unwrap();
    line.clear();
    output.read_line(&mut line).unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    let tools = response["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("MCP tools/list failed: {response}"));
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "trace_dylib_resolution")
        .unwrap_or_else(|| panic!("trace_dylib_resolution missing from {response}"));
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/trace_dylib_resolution.json"))
            .expect("dylib resolution contract is valid JSON");

    assert_eq!(tool, &expected);
    assert_eq!(tool["outputSchema"]["required"], json!(["result"]));
    assert_eq!(
        tool["outputSchema"]["properties"]["result"]["$ref"],
        "#/$defs/__schema13"
    );
    assert_eq!(
        tool["outputSchema"]["$defs"]["__schema13"]["required"],
        json!([
            "root_path",
            "target_sha256",
            "roots",
            "images",
            "edges",
            "findings",
            "coverage",
            "limitations"
        ])
    );
    let _ = child.kill();
    let _ = child.wait();
}
