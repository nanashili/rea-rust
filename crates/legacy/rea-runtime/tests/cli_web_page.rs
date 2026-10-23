#![cfg(unix)]
//! Public CLI coverage for passive CDP page inspection.

use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, TcpListener},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
};
use tungstenite::{Message, accept};

struct MockCdp {
    endpoint: String,
    methods: Arc<Mutex<Vec<String>>>,
    server: thread::JoinHandle<()>,
}

impl MockCdp {
    fn start(changed_after_capture: bool) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind mock CDP");
        let address = listener.local_addr().expect("mock CDP address");
        let methods = Arc::new(Mutex::new(Vec::new()));
        let recorded_methods = Arc::clone(&methods);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept CDP client");
            let mut socket = accept(stream).expect("complete WebSocket handshake");
            let mut frame_tree_calls = 0;
            let mut listener_inspection = false;

            while let Ok(message) = socket.read() {
                let request: Value = serde_json::from_str(message.to_text().expect("CDP text"))
                    .expect("parse CDP request");
                let id = request["id"].as_i64().expect("CDP request id");
                let method = request["method"].as_str().expect("CDP method");
                recorded_methods
                    .lock()
                    .expect("record CDP method")
                    .push(method.to_owned());
                listener_inspection |= method == "Runtime.enable";

                let result = match method {
                    "Page.getFrameTree" => {
                        frame_tree_calls += 1;
                        let url = if changed_after_capture && frame_tree_calls > 1 {
                            "https://changed.example.test/"
                        } else {
                            "https://app.example.test/"
                        };
                        json!({
                            "frameTree": {
                                "frame": {"id":"frame-1", "url":url, "name":"Example"}
                            }
                        })
                    }
                    "DOM.getDocument" => {
                        json!({"root":{"nodeId":1,"nodeType":9,"nodeName":"#document"}})
                    }
                    "DOM.querySelector" => json!({"nodeId":7}),
                    "DOM.enable" => json!({}),
                    "DOM.describeNode" => json!({"node":{"backendNodeId":70}}),
                    "DOM.resolveNode" => json!({"object":{"objectId":"root-object"}}),
                    "DOMDebugger.getEventListeners" => json!({"listeners":[]}),
                    "Runtime.releaseObject" => json!({}),
                    "Page.getResourceTree" => {
                        json!({"frameTree":{"frame":{"url":"https://app.example.test/"},"resources":[]}})
                    }
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

        Self {
            endpoint: format!("http://127.0.0.1:{}", address.port()),
            methods,
            server,
        }
    }

    fn methods(&self) -> Vec<String> {
        self.methods.lock().expect("read CDP methods").clone()
    }

    fn join(self) {
        self.server.join().expect("mock CDP server");
    }
}

fn run_inspection(cdp: &MockCdp) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "inspect-web-page",
            &cdp.endpoint,
            "target-1",
            "--format",
            "json",
            "--observation-ms",
            "0",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run inspect-web-page")
}

fn run_listener_inspection(cdp: &MockCdp) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .args([
            "inspect-web-event-listeners",
            &cdp.endpoint,
            "target-1",
            "#submit",
            "--format",
            "json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run inspect-web-event-listeners")
}

#[test]
fn cli_inspects_selected_page_without_navigation_or_evaluation() {
    let cdp = MockCdp::start(false);
    let output = run_inspection(&cdp);

    assert!(output.status.success(), "{output:?}");
    let result: Value = serde_json::from_slice(&output.stdout).expect("parse capture");
    assert_eq!(result["target"]["target_id"], "target-1");
    assert_eq!(result["target"]["url"], "https://app.example.test/");

    let methods = cdp.methods();
    assert!(!methods.iter().any(|method| method == "Page.navigate"));
    assert!(!methods.iter().any(|method| method == "Runtime.evaluate"));
    cdp.join();
}

#[test]
fn cli_reports_target_revalidation_failure_without_navigation_or_evaluation() {
    let cdp = MockCdp::start(true);
    let output = run_inspection(&cdp);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let failure: Value = serde_json::from_slice(&output.stdout).expect("parse failure");
    assert_eq!(failure["code"], "target_changed");
    assert_eq!(failure["category"], "target_changed");

    let methods = cdp.methods();
    assert!(!methods.iter().any(|method| method == "Page.navigate"));
    assert!(!methods.iter().any(|method| method == "Runtime.evaluate"));
    cdp.join();
}

#[test]
fn cli_inspects_event_listeners_without_dispatching_or_evaluating() {
    let cdp = MockCdp::start(false);
    let output = run_listener_inspection(&cdp);

    assert!(output.status.success(), "{output:?}");
    let result: Value = serde_json::from_slice(&output.stdout).expect("parse listener report");
    assert_eq!(result["target"]["target_id"], "target-1");
    assert_eq!(result["selected_node"]["selector"], "#submit");
    assert_eq!(result["selected_node"]["match"], "found");
    assert_eq!(result["listeners"], json!([]));

    let methods = cdp.methods();
    assert!(
        methods
            .iter()
            .any(|method| method == "DOMDebugger.getEventListeners")
    );
    for method in [
        "Page.enable",
        "Runtime.enable",
        "Debugger.enable",
        "DOM.enable",
        "Runtime.releaseObjectGroup",
        "DOM.disable",
        "Debugger.disable",
        "Runtime.disable",
        "Page.disable",
    ] {
        assert!(
            methods.iter().any(|observed| observed == method),
            "missing {method}: {methods:?}"
        );
    }
    assert!(!methods.iter().any(|method| method == "Page.navigate"));
    assert!(!methods.iter().any(|method| method == "Runtime.evaluate"));
    cdp.join();
}
