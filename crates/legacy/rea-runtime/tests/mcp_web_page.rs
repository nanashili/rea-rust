#![cfg(unix)]
//! Public stdio MCP coverage for passive CDP page inspection.

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
                "clientInfo":{"name":"web-page-test","version":"1"}
            }),
        );
        assert!(response["result"].is_object(), "{response}");
    }

    fn inspect(&mut self, id: u64, arguments: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({"name":"inspect_web_page","arguments":arguments}),
        )
    }

    fn inspect_event_listeners(&mut self, id: u64, arguments: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({"name":"inspect_web_event_listeners","arguments":arguments}),
        )
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_cdp_server(changed_after_capture: bool) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind mock CDP");
    let address = listener.local_addr().expect("mock CDP address");
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept CDP client");
        let mut socket = accept(stream).expect("complete WebSocket handshake");
        let mut frame_tree_calls = 0;
        let mut listener_inspection = false;
        while let Ok(message) = socket.read() {
            let request: Value = serde_json::from_str(message.to_text().expect("CDP text"))
                .expect("parse CDP request");
            let id = request["id"].as_i64().expect("CDP request id");
            let method = request["method"].as_str().expect("CDP method");
            listener_inspection |= method == "Runtime.enable";
            let result = match method {
                "Page.getFrameTree" => {
                    frame_tree_calls += 1;
                    let url = if changed_after_capture && frame_tree_calls > 1 {
                        "https://changed.example.test/"
                    } else {
                        "https://app.example.test/"
                    };
                    json!({"frameTree":{"frame":{"id":"frame-1","url":url,"name":"Example"}}})
                }
                "DOM.getDocument" => {
                    json!({"root":{"nodeId":1,"nodeType":9,"nodeName":"#document"}})
                }
                "DOM.enable" => json!({}),
                "DOM.querySelector" => json!({"nodeId":7}),
                "DOM.describeNode" => json!({"node":{"backendNodeId":70}}),
                "DOM.resolveNode" => json!({"object":{"objectId":"root-object"}}),
                "DOMDebugger.getEventListeners" => json!({"listeners":[]}),
                "Runtime.releaseObject" => json!({}),
                "Page.getResourceTree" => json!({"frameTree":{"frame":{},"resources":[]}}),
                "Browser.getVersion" => json!({"product":"Mock/1"}),
                _ => json!({}),
            };
            socket
                .send(Message::text(json!({"id":id,"result":result}).to_string()))
                .expect("send CDP response");
            let page_capture_finished = method == "Browser.getVersion" && !listener_inspection;
            let listener_cleanup_finished = method == "Page.disable" && listener_inspection;
            let target_changed = changed_after_capture && frame_tree_calls > 1;
            if page_capture_finished || listener_cleanup_finished || target_changed {
                break;
            }
        }
    });
    (format!("http://127.0.0.1:{}", address.port()), handle)
}

fn arguments(endpoint: &str, target_id: &str) -> Value {
    json!({"cdp_endpoint":endpoint,"target_id":target_id})
}

fn listener_arguments(endpoint: &str, target_id: &str) -> Value {
    json!({"cdp_endpoint":endpoint,"target_id":target_id,"selector":"#submit"})
}

#[test]
fn inspect_web_page_is_advertised_and_returns_structured_capture() {
    let (endpoint, server) = start_cdp_server(false);
    let mut child = McpChild::start();
    child.initialize();

    let listing = child.request(2, "tools/list", json!({}));
    assert!(
        listing["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "inspect_web_page")
    );

    let response = child.inspect(3, arguments(&endpoint, "target-1"));
    assert_eq!(
        response["result"]["structuredContent"]["result"]["target"]["target_id"],
        "target-1"
    );
    assert!(response["result"].get("isError").is_none(), "{response}");
    server.join().expect("CDP server");
}

#[test]
fn inspect_web_page_rejects_invalid_input_over_stdio() {
    let mut child = McpChild::start();
    child.initialize();

    let response = child.inspect(2, json!({"target_id":"target-1"}));
    assert_eq!(response["result"]["isError"], true, "{response}");
}

#[test]
fn inspect_web_page_reports_selected_target_revalidation_failure() {
    let (endpoint, server) = start_cdp_server(true);
    let mut child = McpChild::start();
    child.initialize();

    let response = child.inspect(2, arguments(&endpoint, "target-1"));
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert!(response["result"].get("structuredContent").is_none());
    let failure: Value = serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("failure content is text"),
    )
    .expect("failure content is canonical JSON");
    assert_eq!(failure["error"]["code"], "target_changed");
    server.join().expect("CDP server");
}

#[test]
fn inspect_web_event_listeners_is_advertised_and_returns_passive_result() {
    let (endpoint, server) = start_cdp_server(false);
    let mut child = McpChild::start();
    child.initialize();

    let listing = child.request(2, "tools/list", json!({}));
    assert!(
        listing["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "inspect_web_event_listeners")
    );

    let response = child.inspect_event_listeners(3, listener_arguments(&endpoint, "target-1"));
    let result = &response["result"]["structuredContent"]["result"];
    assert_eq!(result["target"]["target_id"], "target-1");
    assert_eq!(result["selected_node"]["selector"], "#submit");
    assert_eq!(result["selected_node"]["match"], "found");
    assert_eq!(result["listeners"], json!([]));
    assert!(response["result"].get("isError").is_none(), "{response}");
    server.join().expect("CDP server");
}

#[test]
fn inspect_web_event_listeners_rejects_missing_selector_over_stdio() {
    let mut child = McpChild::start();
    child.initialize();

    let response = child.inspect_event_listeners(2, json!({"target_id":"target-1"}));
    assert_eq!(response["result"]["isError"], true, "{response}");
}
