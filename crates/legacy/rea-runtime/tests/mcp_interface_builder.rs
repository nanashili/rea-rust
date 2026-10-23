#![cfg(unix)]
//! Public stdio MCP coverage for compiled Interface Builder bundle inspection.

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
                "clientInfo":{"name":"interface-builder-test","version":"1"}
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
fn decode_interface_builder_is_advertised_and_returns_archive_coverage() {
    let bundle = tempfile::tempdir().expect("temporary app bundle");
    let archive = bundle.path().join("Contents/Resources/Main.nib");
    std::fs::create_dir_all(archive.parent().expect("archive parent"))
        .expect("create bundle resources");
    std::fs::write(
        &archive,
        br#"<?xml version="1.0"?><plist version="1.0"><dict><key>com.apple.ibtool.document.objects</key><dict><key>root</key><dict><key>customClass</key><string>NSView</string><key>label</key><string>Main View</string></dict></dict></dict></plist>"#,
    )
    .expect("write Interface Builder archive");

    let mut child = McpChild::start();
    child.initialize();

    let listing = child.request(2, "tools/list", json!({}));
    let tools = listing["result"]["tools"].as_array().expect("tools list");
    let contract = tools
        .iter()
        .find(|tool| tool["name"] == "decode_interface_builder")
        .unwrap_or_else(|| {
            let names = tools
                .iter()
                .filter_map(|tool| tool["name"].as_str())
                .collect::<Vec<_>>();
            panic!("decode_interface_builder contract missing from tool names {names:?}")
        });
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/decode_interface_builder.json"))
            .expect("Interface Builder contract is valid JSON");
    assert_eq!(contract, &expected);
    assert_eq!(
        contract["inputSchema"]["required"],
        json!(["path", "target_sha256"])
    );

    let response = child.request(
        3,
        "tools/call",
        json!({
            "name":"decode_interface_builder",
            "arguments":{
                "path":bundle.path().to_str().expect("bundle path is UTF-8"),
                "target_sha256":"a".repeat(64),
                "max_documents":1,
                "max_objects":8,
                "max_connections":8
            }
        }),
    );
    let evidence = &response["result"]["structuredContent"];
    for field in contract["outputSchema"]["required"]
        .as_array()
        .expect("report output fields are required")
    {
        let field = field.as_str().expect("required field is a string");
        assert!(evidence.get(field).is_some(), "missing {field}: {response}");
    }
    assert_eq!(evidence["operation"], "decode_interface_builder");
    assert_eq!(evidence["subject"]["format"], "directory");
    assert_eq!(evidence["subject"]["digest"]["sha256"], "a".repeat(64));
    assert_eq!(
        evidence["normalized_result"]["target_sha256"],
        "a".repeat(64)
    );
    assert_eq!(
        evidence["normalized_result"]["documents"][0]["relative_path"],
        "Contents/Resources/Main.nib"
    );
    assert_eq!(evidence["parameters"]["max_objects"], 8);
    assert!(response["result"].get("isError").is_none(), "{response}");
}
