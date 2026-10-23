#![cfg(unix)]
//! Public stdio MCP coverage for passive Electron target discovery.

use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    thread,
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
                "clientInfo":{"name":"electron-target-test","version":"1"}
            }),
        );
        assert!(response["result"].is_object(), "{response}");
    }

    fn list_electron_targets(&mut self, id: u64, arguments: Value) -> Value {
        self.request(
            id,
            "tools/call",
            json!({"name":"list_electron_targets","arguments":arguments}),
        )
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_cdp_server(
    file_url: String,
    asar_file_url: String,
) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind mock CDP");
    let address = listener.local_addr().expect("mock CDP address");
    let handle = thread::spawn(move || {
        let mut paths = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept HTTP discovery client");
            let path = read_request_path(&mut stream);
            paths.push(path.clone());
            let body = match path.as_str() {
                "/json/version" => json!({
                    "Browser":"Electron/37.0.0",
                    "Protocol-Version":"1.3",
                    "WebKit-Version":"537.36",
                    "User-Agent":"Electron",
                    "V8-Version":"13.7.0",
                    "webSocketDebuggerUrl":format!("ws://{address}/devtools/page/z-page")
                }),
                "/json/list" => json!([
                    {
                        "id":"z-page",
                        "type":"page",
                        "title":"Local file page",
                        "url":file_url.clone(),
                        "attached":false
                    },
                    {
                        "id":"asar-page",
                        "type":"page",
                        "title":"Packaged local file page",
                        "url":asar_file_url,
                        "attached":false,
                        "webSocketDebuggerUrl":format!("ws://{address}/devtools/page/asar-page")
                    },
                    {
                        "id":"a-page",
                        "type":"page",
                        "title":"Missing file page",
                        "url":"file:///tmp/rea-native-electron-missing.html",
                        "webSocketDebuggerUrl":"not a websocket"
                    },
                    {
                        "id":"unconnectable-page",
                        "type":"page",
                        "title":"Local page without a scoped socket",
                        "url":file_url,
                        "attached":false
                    },
                    {
                        "id":"remote-page",
                        "type":"page",
                        "title":"Remote page",
                        "url":"https://example.test/"
                    },
                    {
                        "id":"worker",
                        "type":"worker",
                        "title":"Worker",
                        "url":"file:///tmp/worker.js"
                    }
                ]),
                other => panic!("unexpected CDP request path: {other}"),
            }
            .to_string();
            write_http_response(&mut stream, &body);
        }
        paths
    });

    (format!("http://127.0.0.1:{}", address.port()), handle)
}

fn read_request_path(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read HTTP request");
        request.push(byte[0]);
    }
    let request = String::from_utf8(request).expect("HTTP request is UTF-8");
    request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("HTTP request path")
        .to_owned()
}

fn write_http_response(stream: &mut TcpStream, body: &str) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write HTTP discovery response");
}

fn failure_from_response(response: &Value) -> Value {
    let failure_text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("failure text");
    serde_json::from_str(failure_text).expect("parse failure envelope")
}

#[test]
fn list_electron_targets_returns_authorized_local_and_asar_pages() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let page = directory.path().join("renderer page.html");
    fs::write(&page, b"<html></html>").expect("create renderer page");
    let archive = directory.path().join("packaged app.asar");
    write_asar_archive(
        &archive,
        json!({
            "renderer": {
                "files": {
                    "index.html": {"size": 12, "offset": "0"}
                }
            }
        }),
    );
    let file_url = format!("file://{}", encode_spaces(page.as_path()));
    let asar_file_url = format!(
        "file://{}/renderer/index.html",
        encode_spaces(archive.as_path())
    );
    let (endpoint, server) = start_cdp_server(file_url, asar_file_url);

    let mut child = McpChild::start();
    child.initialize();

    let listing = child.request(2, "tools/list", json!({}));
    assert!(
        listing["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "list_electron_targets")
    );

    let response = child.list_electron_targets(3, json!({"cdp_endpoint":endpoint}));
    assert_eq!(response["result"].get("isError"), None, "{response}");
    let result = &response["result"]["structuredContent"]["result"];
    assert_eq!(result["browser"]["product"], "Electron/37.0.0");
    assert_eq!(result["targets"].as_array().unwrap().len(), 2);
    assert_eq!(result["targets"][0]["target_id"], "asar-page");
    assert_eq!(
        result["targets"][0]["file_path"],
        archive
            .canonicalize()
            .unwrap()
            .join("renderer/index.html")
            .display()
            .to_string()
    );
    assert_eq!(result["targets"][1]["target_id"], "z-page");
    assert_eq!(
        result["targets"][1]["file_path"],
        page.canonicalize().unwrap().display().to_string()
    );
    assert_eq!(result["targets"][1]["attached"], false);
    assert_eq!(result["excluded"]["unsupported_url"], 2);
    assert_eq!(result["excluded"]["non_page"], 1);
    assert_eq!(
        result["limitations"],
        json!([
            "Every local file page exposed by the selected loopback CDP endpoint is eligible for listing.",
            "1 otherwise allowed page target(s) lacked a validated direct CDP WebSocket and were excluded."
        ])
    );

    assert_eq!(
        server.join().expect("CDP server"),
        ["/json/version", "/json/list"]
    );
}

#[test]
fn list_electron_targets_reports_unavailable_endpoint_as_tagged_failure() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve loopback port");
    let address = listener.local_addr().expect("reserved address");
    drop(listener);

    let mut child = McpChild::start();
    child.initialize();

    let response =
        child.list_electron_targets(2, json!({"cdp_endpoint":format!("http://{address}")}));
    assert_eq!(response["result"]["isError"], true, "{response}");

    let failure = failure_from_response(&response);
    assert_eq!(failure["error"]["code"], "provider_unavailable");
    assert_eq!(failure["error"]["retryable"], true);
    assert_eq!(
        failure["error"]["details"]["operation"],
        "list_electron_targets"
    );
}

fn write_asar_archive(path: &Path, files: Value) {
    let encoded_json =
        serde_json::to_vec(&json!({"files": files})).expect("serialize ASAR file tree");
    let json_bytes = u32::try_from(encoded_json.len()).expect("fixture is within u32");
    let header_bytes = json_bytes.checked_add(8).expect("header length");
    let payload_bytes = header_bytes.checked_sub(4).expect("payload length");

    let mut archive = Vec::with_capacity(16 + encoded_json.len());
    archive.extend_from_slice(&4_u32.to_le_bytes());
    archive.extend_from_slice(&header_bytes.to_le_bytes());
    archive.extend_from_slice(&payload_bytes.to_le_bytes());
    archive.extend_from_slice(&json_bytes.to_le_bytes());
    archive.extend_from_slice(&encoded_json);
    fs::write(path, archive).expect("write ASAR header fixture");
}

fn encode_spaces(path: &Path) -> String {
    path.display().to_string().replace(' ', "%20")
}

#[test]
fn list_electron_targets_rejects_unscoped_or_extra_input() {
    let mut child = McpChild::start();
    child.initialize();

    let remote = child.list_electron_targets(2, json!({"cdp_endpoint":"http://192.0.2.10:9222"}));
    assert_eq!(remote["result"]["isError"], true, "{remote}");
    let failure = failure_from_response(&remote);
    assert_eq!(failure["error"]["code"], "invalid_request");
    assert_eq!(
        failure["error"]["details"]["operation"],
        "list_electron_targets"
    );

    let extra = child.list_electron_targets(
        3,
        json!({"cdp_endpoint":"http://127.0.0.1:9222","extra":true}),
    );
    assert_eq!(extra["result"]["isError"], true, "{extra}");
    let failure = failure_from_response(&extra);
    assert_eq!(failure["error"]["code"], "invalid_request");
    assert_eq!(
        failure["error"]["details"]["operation"],
        "list_electron_targets"
    );
}
