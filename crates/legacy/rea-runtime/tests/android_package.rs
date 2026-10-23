#![cfg(unix)]
//! Public MCP contract coverage for Android package Evidence.

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
        let mut process = Command::new(env!("CARGO_BIN_EXE_rea-native"));
        process
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = process.spawn().unwrap();
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
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn android_package_contract_requires_nullable_application_label() {
    let mut server = McpChild::start();
    let initialized = server.request(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "android-package-test", "version": "1"},
        }),
    );
    assert!(initialized["result"].is_object(), "{initialized}");

    let listing = server.request(2, "tools/list", json!({}));
    let contract = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_android_package")
        .unwrap_or_else(|| panic!("Android package contract missing from {listing}"));
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_android_package.json")).unwrap();

    assert_eq!(contract["outputSchema"], expected["outputSchema"]);
    let result_schema = &contract["outputSchema"]["properties"]["result"];
    assert!(
        result_schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "application_label")
    );
    assert_eq!(
        result_schema["properties"]["application_label"]["type"],
        json!(["string", "null"])
    );
}
