#![cfg(unix)]
//! Public stdio MCP coverage for caller-selected Apktool client inspection.
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

struct McpChild {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl McpChild {
    fn start(command: Option<&str>) -> Self {
        let mut process = Command::new(env!("CARGO_BIN_EXE_rea-native"));
        process
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(command) = command {
            process.env("REA_APKTOOL_COMMAND", command);
        }
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

    fn initialize(&mut self) {
        let response = self.request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "apktool-client-test", "version": "1"},
            }),
        );
        assert!(response["result"].is_object(), "{response}");
    }

    fn call_tool(&mut self, id: u64, arguments: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({"name": "inspect_apktool_client", "arguments": arguments}),
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
fn inspect_apktool_client_is_advertised_and_preserves_structured_results() {
    let directory = tempfile::tempdir().unwrap();
    let launcher = directory.path().join("apktool");
    std::fs::write(&launcher, "#!/bin/sh\nprintf '2.9.3-dirty\\n'\n").unwrap();
    let mut permissions = std::fs::metadata(&launcher).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&launcher, permissions).unwrap();
    let launcher = launcher.to_str().unwrap().to_owned();

    let mut server = McpChild::start(Some(&launcher));
    server.initialize();

    let listing = server.request(2, "tools/list", json!({}));
    let contract = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_apktool_client")
        .unwrap_or_else(|| panic!("inspect_apktool_client contract missing from {listing}"));
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_apktool_client.json")).unwrap();
    assert_eq!(contract["inputSchema"], expected["inputSchema"]);
    assert_eq!(contract["outputSchema"], expected["outputSchema"]);

    let response = server.call_tool(3, json!({}));
    assert_eq!(
        response["result"]["structuredContent"]["result"]["client"],
        json!({
            "command": launcher,
            "command_source": "environment",
            "apktool_version": "2.9.3-dirty",
        })
    );
    assert!(response["result"].get("isError").is_none(), "{response}");
    assert_eq!(
        response["result"]["_meta"]["provenance"],
        json!({"untrusted_content": true, "source": "analysis_target"})
    );
}

#[test]
fn inspect_apktool_client_returns_a_structured_failure_for_invalid_configuration() {
    let mut server = McpChild::start(Some("relative/apktool"));
    server.initialize();

    let response = server.call_tool(2, json!({}));
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert_eq!(
        response["result"]["_meta"]["provenance"],
        json!({"untrusted_content": true, "source": "analysis_target"})
    );
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("inspect_apktool_client")
    );
}
