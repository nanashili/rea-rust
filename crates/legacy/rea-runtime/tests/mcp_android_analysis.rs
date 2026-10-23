#![cfg(unix)]
//! Public stdio MCP coverage for static Android class search and reference tracing.

use serde_json::{Value, json};
use std::{
    fs,
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
                "clientInfo":{"name":"android-analysis-test","version":"1"}
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

fn minimal_apk() -> Vec<u8> {
    let entry_name = b"AndroidManifest.xml";
    let manifest = b"<manifest package=\"example.test\"/>";
    let mut bytes = vec![0; 30];

    bytes[..4].copy_from_slice(b"PK\x03\x04");
    bytes[18..22].copy_from_slice(&(manifest.len() as u32).to_le_bytes());
    bytes[22..26].copy_from_slice(&(manifest.len() as u32).to_le_bytes());
    bytes[26..28].copy_from_slice(&(entry_name.len() as u16).to_le_bytes());
    bytes[28..30].copy_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(entry_name);
    bytes.extend_from_slice(manifest);

    bytes
}

#[test]
fn search_android_classes_returns_evidence_with_caller_parameters() {
    let directory = tempfile::tempdir().unwrap();
    let apk_path = directory.path().join("empty.apk");
    fs::write(&apk_path, minimal_apk()).unwrap();

    let mut server = McpChild::start();
    server.initialize();

    let listing = server.request(2, "tools/list", json!({}));
    let tools = listing["result"]["tools"].as_array().unwrap();
    for name in ["search_android_classes", "trace_android_references"] {
        assert!(
            tools.iter().any(|tool| tool["name"] == name),
            "{name}: {listing}"
        );
    }

    let response = server.call_tool(
        3,
        "search_android_classes",
        json!({"path":apk_path,"query":""}),
    );
    assert!(response["result"].get("isError").is_none(), "{response}");
    let evidence = &response["result"]["structuredContent"];
    assert_eq!(evidence["operation"], "search_android_classes");
    assert_eq!(evidence["parameters"]["query"], "");
    assert_eq!(
        evidence["parameters"]["path"],
        apk_path.to_string_lossy().as_ref()
    );
    assert_eq!(evidence["normalized_result"]["query"], "");
    assert_eq!(evidence["normalized_result"]["total_classes"], 0);
}

#[test]
fn trace_android_references_reports_input_failure_for_invalid_overload_index() {
    let directory = tempfile::tempdir().unwrap();
    let apk_path = directory.path().join("empty.apk");
    fs::write(&apk_path, minimal_apk()).unwrap();

    let mut server = McpChild::start();
    server.initialize();
    let response = server.call_tool(
        2,
        "trace_android_references",
        json!({
            "path":apk_path,
            "class_name":"example.Missing",
            "overload_index":-1
        }),
    );
    assert_eq!(response["result"]["isError"], true, "{response}");
    let message = response["result"]["content"][0]["text"]
        .as_str()
        .expect("failure content is text");
    assert!(message.contains("Input validation error"), "{response}");
    assert!(message.contains("trace_android_references"), "{response}");
    assert!(message.contains("overload_index"), "{response}");
}
