#![cfg(unix)]
//! Public CLI and MCP checks for Go build-information Evidence.

#[path = "support/go_binary.rs"]
mod go_fixture;

use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

fn inspect_cli(path: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("inspect-go-binary")
        .arg(path)
        .arg("--json")
        .output()
        .unwrap()
}

fn parsed(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn cli_returns_artifact_bound_go_metadata_and_exact_source_locations() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("go-application");
    fs::write(&path, go_fixture::fixture()).unwrap();

    let output = inspect_cli(&path);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty());

    let evidence = parsed(&output);
    let compatibility_alias = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("inspect-go-binary")
        .arg(&path)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(
        compatibility_alias.status.success(),
        "{compatibility_alias:?}"
    );
    assert_eq!(parsed(&compatibility_alias), evidence);

    let report = &evidence["normalized_result"];
    let build_info = &report["build_info"];
    assert_eq!(evidence["operation"], "inspect_go_binary");
    assert_eq!(evidence["provider"]["id"], "go-build-info");
    assert_eq!(evidence["subject"]["format"], "elf");
    assert_eq!(evidence["subject"]["architecture"], "x86_64");
    assert_eq!(report["artifact"]["path"], path.to_str().unwrap());
    assert_eq!(report["artifact"]["bytes"], 4096);
    assert_eq!(
        report["artifact"]["sha256"],
        evidence["subject"]["digest"]["sha256"]
    );
    assert_eq!(build_info["go_version"], "go1.26.0");
    assert_eq!(build_info["module"]["path"], "github.com/acme/app");
    assert_eq!(build_info["module"]["main"]["version"], "v1.2.3");
    assert_eq!(
        build_info["module"]["dependencies"][0]["path"],
        "github.com/acme/lib"
    );
    assert_eq!(build_info["module"]["dependencies"][0]["version"], "v2.3.4");
    assert_eq!(build_info["module"]["settings"][0]["key"], "GOOS");
    assert_eq!(build_info["module"]["settings"][0]["value"], "linux");
    assert_eq!(
        evidence["locations"],
        json!([
            {"kind": "artifact-path", "path": path},
            {"kind": "file-offset-range", "start": 1024, "end": 1056}
        ])
    );
}

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
            .unwrap();
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
                "clientInfo": {"name": "go-binary-test", "version": "1"},
            }),
        );
        assert!(response["result"].is_object(), "{response}");
    }

    fn call_tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
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
fn mcp_advertises_the_named_contract_and_retains_go_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("go-application");
    fs::write(&path, go_fixture::fixture()).unwrap();

    let mut server = McpChild::start();
    server.initialize();

    let listing = server.request(2, "tools/list", json!({}));
    let tools = listing["result"]["tools"].as_array().unwrap();
    let go_contract = tools
        .iter()
        .find(|tool| tool["name"] == "inspect_go_binary")
        .expect("Go inspection contract should be advertised");
    let expected: Value =
        serde_json::from_str(include_str!("../contracts/inspect_go_binary.json")).unwrap();
    assert_eq!(go_contract, &expected);

    let inspection = server.call_tool(
        3,
        "inspect_go_binary",
        json!({"path": path.to_str().unwrap()}),
    );
    assert!(
        inspection["result"].get("isError").is_none(),
        "{inspection}"
    );
    let evidence = &inspection["result"]["structuredContent"];
    assert_eq!(evidence["operation"], "inspect_go_binary");
    assert_eq!(
        evidence["normalized_result"]["build_info"]["module"]["main"]["version"],
        "v1.2.3"
    );

    let summary = server.call_tool(4, "get_evidence_bundle", json!({"detail": "summary"}));
    let retained = &summary["result"]["structuredContent"]["result"];
    assert_eq!(retained["total_retained_records"], 1);
    assert_eq!(retained["records"][0]["operation"], "inspect_go_binary");
}
