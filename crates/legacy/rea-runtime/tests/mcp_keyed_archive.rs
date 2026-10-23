#![cfg(unix)]
//! Public stdio MCP coverage for caller-selected keyed archive inspection.

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
                "clientInfo":{"name":"keyed-archive-test","version":"1"}
            }),
        );
        assert!(response["result"].is_object(), "{response}");
    }

    fn inspect(&mut self, id: u64, arguments: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({"name":"inspect_keyed_archive","arguments":arguments}),
        )
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_archive() -> tempfile::NamedTempFile {
    let archive = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>$archiver</key><string>NSKeyedArchiver</string>
<key>$objects</key><array><string>$null</string><string>Hello</string></array>
<key>$top</key><dict><key>root</key><dict><key>CF$UID</key><integer>1</integer></dict></dict>
</dict></plist>"#;
    let file = tempfile::NamedTempFile::new().expect("create archive fixture");
    std::fs::write(file.path(), archive).expect("write archive fixture");
    file
}

#[test]
fn inspect_keyed_archive_is_advertised_and_returns_evidence() {
    let archive = write_archive();
    let path = archive.path().to_str().unwrap();
    let mut child = McpChild::start();
    child.initialize();

    let listing = child.request(2, "tools/list", json!({}));
    let contract = listing["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "inspect_keyed_archive")
        .unwrap_or_else(|| panic!("inspect_keyed_archive contract missing from {listing}"));
    let expected_contract: Value =
        serde_json::from_str(include_str!("../contracts/inspect_keyed_archive.json"))
            .expect("keyed archive contract is valid JSON");
    assert_eq!(contract, &expected_contract);
    assert_eq!(
        contract["inputSchema"]["properties"]["root"]["type"],
        json!("string")
    );
    assert_eq!(contract["inputSchema"]["required"], json!(["path"]));

    let response = child.inspect(3, json!({"path": path, "limit": 1}));
    assert_eq!(
        response["result"]["structuredContent"]["subject"]["local_path"],
        path
    );
    assert_eq!(
        response["result"]["structuredContent"]["normalized_result"]["roots"]["root"],
        json!({"CF$UID": 1})
    );
    assert!(response["result"].get("isError").is_none(), "{response}");
}

#[test]
fn inspect_keyed_archive_rejects_unknown_root_and_invalid_input() {
    let archive = write_archive();
    let path = archive.path().to_str().unwrap();
    let mut child = McpChild::start();
    child.initialize();

    let missing_root = child.inspect(2, json!({"path": path, "root": "missing"}));
    assert_eq!(missing_root["result"]["isError"], true, "{missing_root}");
    assert!(
        missing_root["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("inspect_keyed_archive")
    );

    let invalid_input = child.inspect(3, json!({"path": path, "offset": -1}));
    assert_eq!(invalid_input["result"]["isError"], true, "{invalid_input}");
    assert!(
        invalid_input["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("inspect_keyed_archive")
    );

    let null_root = child.inspect(4, json!({"path": path, "root": null}));
    assert_eq!(null_root["result"]["isError"], true, "{null_root}");
    assert!(
        null_root["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("root"),
        "{null_root}"
    );
}
