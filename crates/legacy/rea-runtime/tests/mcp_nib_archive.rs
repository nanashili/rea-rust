#![cfg(unix)]
//! Public stdio MCP coverage for static NIBArchive inspection.

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
                "clientInfo":{"name":"nib-archive-test","version":"1"}
            }),
        );
        assert!(response["result"].is_object(), "{response}");
    }

    fn inspect(&mut self, id: u64, arguments: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({"name":"inspect_nib_archive","arguments":arguments}),
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
fn inspect_nib_archive_is_advertised_and_returns_source_evidence() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let path = directory.path().join("Main.nib");
    std::fs::write(&path, minimal_nib_archive()).expect("write NIB archive fixture");

    let mut child = McpChild::start();
    child.initialize();

    let listing = child.request(2, "tools/list", json!({}));
    let contract = listing["result"]["tools"]
        .as_array()
        .expect("tools list")
        .iter()
        .find(|tool| tool["name"] == "inspect_nib_archive")
        .unwrap_or_else(|| panic!("inspect_nib_archive contract missing from {listing}"));
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_nib_archive.json"))
            .expect("NIB archive contract is valid JSON");
    assert_eq!(contract, &expected);
    assert_eq!(contract["inputSchema"]["required"], json!(["path"]));
    assert_eq!(
        contract["inputSchema"]["properties"]["path"]["type"],
        "string"
    );

    let response = child.inspect(
        3,
        json!({"path": path.to_str().expect("temporary path is UTF-8")}),
    );
    let evidence = &response["result"]["structuredContent"];
    for field in contract["outputSchema"]["required"]
        .as_array()
        .expect("Evidence output fields are required")
    {
        let field = field.as_str().expect("required field is a string");
        assert!(evidence.get(field).is_some(), "missing {field}: {response}");
    }
    assert_eq!(evidence["operation"], "inspect_nib_archive", "{response}");
    assert_eq!(evidence["subject"]["format"], "nib");
    assert_eq!(
        evidence["subject"]["local_path"],
        path.to_string_lossy().as_ref()
    );
    assert_eq!(
        evidence["normalized_result"]["objects"][0]["class_name"],
        "Outlet"
    );
    assert!(response["result"].get("isError").is_none(), "{response}");
}

fn minimal_nib_archive() -> Vec<u8> {
    let mut bytes = vec![0u8; 50];
    bytes[..10].copy_from_slice(b"NIBArchive");
    put_u32(&mut bytes, 10, 1);
    put_u32(&mut bytes, 14, 7);
    put_u32(&mut bytes, 18, 1);
    put_u32(&mut bytes, 22, 50);
    put_u32(&mut bytes, 26, 1);
    put_u32(&mut bytes, 30, 53);
    put_u32(&mut bytes, 34, 1);
    put_u32(&mut bytes, 38, 59);
    put_u32(&mut bytes, 42, 1);
    put_u32(&mut bytes, 46, 65);
    bytes.extend_from_slice(&[0x80, 0x80, 0x81]);
    bytes.extend_from_slice(&[0x85, b't', b'i', b't', b'l', b'e']);
    bytes.extend_from_slice(&[0x80, 8, 0x83, b'a', b'b', b'c']);
    bytes.extend_from_slice(&[0x86, 0x80, b'O', b'u', b't', b'l', b'e', b't']);
    bytes
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
