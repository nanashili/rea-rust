#![cfg(unix)]
//! Public CLI and stdio MCP coverage for retained Interface Builder views.

use rea_application::interface_builder;
use rea_core::cancellation::Cancellation;
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
                "clientInfo":{"name":"analysis-view-test","version":"1"}
            }),
        );
        assert!(response["result"].is_object(), "{response}");
    }

    fn call(&mut self, id: u64, parent: Value, view: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({
                "name":"inspect_analysis_view",
                "arguments":{"parent_evidence":parent,"view":view}
            }),
        )
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn parent_evidence() -> Value {
    let bundle = tempfile::tempdir().expect("create temporary app bundle");
    let archive = bundle.path().join("Resources/Main.nib");
    std::fs::create_dir_all(archive.parent().expect("archive parent"))
        .expect("create archive directory");
    std::fs::write(
        archive,
        br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.ibtool.document.objects</key>
            <dict><key>root</key><dict><key>customClass</key><string>NSView</string><key>label</key><string>Main View</string></dict></dict>
        </dict></plist>"#,
    )
    .expect("write nib plist fixture");
    let evidence = interface_builder::bundle::inspect_bundle(
        bundle.path(),
        "a".repeat(64),
        &Cancellation::default(),
    )
    .expect("decode Interface Builder fixture");
    serde_json::to_value(evidence).expect("Evidence JSON")
}

#[test]
fn cli_projects_summary_and_page_from_retained_interface_builder_evidence() {
    let parent = parent_evidence();
    let request = json!({
        "parent_evidence": parent,
        "view": {"kind":"interface-builder","collection":"nodes","limit":1},
    });
    let directory = tempfile::tempdir().expect("create request directory");
    let input = directory.path().join("view.json");
    std::fs::write(&input, serde_json::to_vec(&request).expect("request JSON"))
        .expect("write request");
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("inspect-analysis-view")
        .arg(&input)
        .args(["--format", "json"])
        .output()
        .expect("run analysis view CLI");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let evidence: Value = serde_json::from_slice(&output.stdout).expect("view Evidence JSON");
    assert_eq!(evidence["operation"], "inspect_analysis_view");
    assert_eq!(evidence["normalized_result"]["kind"], "interface-builder");
    assert_eq!(
        evidence["normalized_result"]["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(evidence["normalized_result"]["view"]["offset"], 0);
}

#[test]
fn mcp_projects_a_summary_from_retained_interface_builder_evidence() {
    let parent = parent_evidence();
    let mut server = McpChild::start();
    server.initialize();

    let listing = server.request(2, "tools/list", json!({}));
    let contract = listing["result"]["tools"]
        .as_array()
        .expect("tools list")
        .iter()
        .find(|tool| tool["name"] == "inspect_analysis_view")
        .unwrap_or_else(|| panic!("analysis view contract missing from {listing}"));
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_analysis_view.json"))
            .expect("analysis view contract is valid JSON");
    assert_eq!(contract, &expected);

    let response = server.call(3, parent, json!({"kind":"summary"}));
    let result = &response["result"];
    assert_eq!(
        result["structuredContent"]["operation"],
        "inspect_analysis_view"
    );
    assert_eq!(
        result["structuredContent"]["normalized_result"]["summary"]["available_counts"]["nodes"],
        2
    );
    assert!(result.get("isError").is_none(), "{response}");
}
