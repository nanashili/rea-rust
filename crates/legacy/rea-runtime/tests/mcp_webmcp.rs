#![cfg(unix)]
//! Public stdio MCP coverage for passive WebMCP discovery.

use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, TcpListener},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    thread,
};
use tungstenite::{Message, accept};

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
                "clientInfo":{"name":"webmcp-test","version":"1"}
            }),
        );
        assert!(response["result"].is_object(), "{response}");
    }

    fn discover(&mut self, id: u64, arguments: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({"name":"discover_webmcp_tools","arguments":arguments}),
        )
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_cdp_server() -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind mock CDP");
    let address = listener.local_addr().expect("mock CDP address");
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept CDP client");
        let mut socket = accept(stream).expect("complete WebSocket handshake");
        let mut methods = Vec::new();

        while let Ok(message) = socket.read() {
            let request: Value = serde_json::from_str(message.to_text().expect("CDP text"))
                .expect("parse CDP request");
            let id = request["id"].as_i64().expect("CDP request id");
            let method = request["method"].as_str().expect("CDP method");
            methods.push(method.to_owned());

            if method == "WebMCP.enable" {
                socket
                    .send(Message::text(
                        json!({
                            "method":"WebMCP.toolsAdded",
                            "params":{"tools":[{
                                "frameId":"frame-1",
                                "name":"search_catalog",
                                "description":"Search the catalog",
                                "inputSchema":{"type":"object","properties":{"query":{"type":"string"}}},
                                "annotations":{"readOnly":true,"untrustedContent":false,"consequential":false,"autosubmit":false}
                            }]}
                        })
                        .to_string(),
                    ))
                    .expect("send WebMCP event");
            }

            let result = match method {
                "Page.getFrameTree" => json!({
                    "frameTree":{"frame":{
                        "id":"frame-1",
                        "loaderId":"loader-1",
                        "url":"https://app.example.test/catalog"
                    }}
                }),
                "Browser.getVersion" => json!({
                    "product":"MockChrome/1",
                    "protocolVersion":"1.3",
                    "revision":"mock-revision",
                    "userAgent":"MockChrome",
                    "jsVersion":"mock-js"
                }),
                _ => json!({}),
            };
            socket
                .send(Message::text(json!({"id":id,"result":result}).to_string()))
                .expect("send CDP response");

            if method == "Page.getFrameTree" && methods.len() >= 5 {
                break;
            }
        }

        methods
    });

    (format!("http://127.0.0.1:{}", address.port()), handle)
}

#[test]
fn discover_webmcp_tools_is_advertised_and_returns_passive_inventory() {
    let (endpoint, server) = start_cdp_server();
    let mut child = McpChild::start();
    child.initialize();

    let listing = child.request(2, "tools/list", json!({}));
    assert!(
        listing["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "discover_webmcp_tools")
    );

    let response = child.discover(
        3,
        json!({
            "cdp_endpoint": endpoint,
            "target_id":"target-1",
            "allowed_origins":["https://app.example.test"],
            "observation_ms":0
        }),
    );
    let result = &response["result"]["structuredContent"]["result"];
    assert!(response["result"].get("isError").is_none(), "{response}");
    assert_eq!(result["status"], "available");
    assert_eq!(result["target"]["target_id"], "target-1");
    assert_eq!(result["tools"]["total"], 1);
    assert_eq!(result["tools"]["items"][0]["name"], "search_catalog");
    assert_eq!(
        result["tools"]["items"][0]["trust"],
        "page-declared-untrusted"
    );

    let methods = server.join().expect("CDP server");
    assert_eq!(
        methods,
        [
            "Page.enable",
            "Page.getFrameTree",
            "Browser.getVersion",
            "WebMCP.enable",
            "Page.getFrameTree"
        ]
    );
    assert!(!methods.iter().any(|method| method == "WebMCP.invokeTool"));
}

#[test]
fn discover_webmcp_tools_validates_browser_level_websocket_scope() {
    let mut child = McpChild::start();
    child.initialize();

    let rejected = child.discover(
        2,
        json!({
            "cdp_endpoint":"ws://192.0.2.1:9222/devtools/browser/browser-id",
            "target_id":"target-1",
            "observation_ms":0
        }),
    );
    assert_eq!(rejected["result"]["isError"], true, "{rejected}");

    let accepted_scope = child.discover(
        3,
        json!({
            "cdp_endpoint":"ws://[::1]:1/devtools/browser/browser-id",
            "target_id":"target-1",
            "observation_ms":0
        }),
    );
    assert_eq!(
        accepted_scope["result"]["isError"], true,
        "{accepted_scope}"
    );
    let failure: Value = serde_json::from_str(
        accepted_scope["result"]["content"][0]["text"]
            .as_str()
            .expect("failure content is text"),
    )
    .expect("failure content is canonical JSON");
    assert_eq!(
        failure["error"]["code"], "provider_unavailable",
        "{accepted_scope}"
    );
    assert_eq!(
        failure["error"]["details"]["operation"], "discover_webmcp_tools",
        "{accepted_scope}"
    );
    assert!(
        !accepted_scope.to_string().contains("invalid_request"),
        "browser-level loopback scope was rejected during input validation: {accepted_scope}"
    );
}
