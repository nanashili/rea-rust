#![cfg(unix)]
//! Startup cancellation must not start an uninterruptible inherited stdin read.
use rea_core::cancellation::Cancellation;
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn initialization_response_establishes_readiness_without_notification() {
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_rea-native"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut input = child.0.stdin.take().unwrap();
    let output = child.0.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(output).lines().take(2) {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    writeln!(input, "{}", serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"lifecycle-check","version":"1"}}})).unwrap();
    let initialized: serde_json::Value = serde_json::from_str(
        &receive
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(initialized.get("result").is_some(), "{initialized}");
    // The SDK permits requests after InitializeResult without an initialized
    // gate. Concurrent notification dispatch must not change this readiness.
    writeln!(
        input,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})
    )
    .unwrap();
    let listed: serde_json::Value = serde_json::from_str(
        &receive
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(listed["result"]["tools"].as_array().is_some(), "{listed}");
    drop(input);
    assert!(child.0.wait().unwrap().success());
    reader.join().unwrap();
}

#[test]
fn pre_cancelled_startup_does_not_wait_for_client_input() {
    const CHILD: &str = "REA_MCP_STARTUP_CANCEL_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let cancellation = Cancellation::default();
        cancellation.cancel("startup interrupted");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(rea_runtime::mcp::run(&cancellation));
        runtime.shutdown_background();
        result.unwrap();
        return;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "pre_cancelled_startup_does_not_wait_for_client_input",
        ])
        .env(CHILD, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Hold stdin open. EOF must not accidentally make the cancellation test pass.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut timed_out = false;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            timed_out = true;
            child.kill().unwrap();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!timed_out, "cancelled startup waited for stdin");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn eof_before_initialization_releases_the_stdio_server() {
    let output = Command::new(env!("CARGO_BIN_EXE_rea-native"))
        .arg("mcp")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
