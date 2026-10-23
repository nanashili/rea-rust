//! Lifecycle regressions for one real PTY capture (docs/testing.md).
//!
//! Each test drives `capture::run` against real child processes and checks
//! the published facts and that no owned process or temporary root
//! survives: normal exit, late output after the root exits, cancellation
//! while running and during the finalization interval, a token-owned
//! descendant that left the PTY group, and retry of a failed cleanup.

use super::capture::{self, CaptureHost, RetainedResources};
use super::paths::resolve_runtime_paths;
use super::scenario::Scenario;
use rea_host::process::ownership::OwnershipRelation;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn scenario(overrides: Value) -> Scenario {
    let mut input = json!({
        "executable": "/bin/sh", "arguments": [], "working_directory": "/tmp", "environment": {},
        "filesystem_observation_paths": [], "terminal": {"columns": 40, "rows": 6, "scrollback": 20},
        "events": [], "timeout_ms": 10000, "idle_timeout_ms": 10000, "settle_ms": 100, "finalization_ms": 0,
        "limits": {"output_bytes": 100000, "files": 100, "file_bytes": 100000, "processes": 100, "filesystem_depth": 4},
        "normalization": {"paths": false, "pids": true, "ports": true, "time_bucket_ms": 10, "patterns": []},
    });
    for (key, value) in overrides.as_object().unwrap() {
        input[key] = value.clone();
    }
    Scenario::from_input(&input)
}

fn host_environment() -> HashMap<String, String> {
    HashMap::from([
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("TMPDIR".to_owned(), std::env::temp_dir().to_string_lossy().into_owned()),
    ])
}

fn run_with(scenario: &Scenario, cancel_after: Option<Duration>) -> Result<Value, capture::CaptureFailure> {
    let environment = host_environment();
    let resolved = resolve_runtime_paths(scenario, &environment).unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    if let Some(delay) = cancel_after {
        let flag = Arc::clone(&flag);
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            flag.store(true, Ordering::SeqCst);
        });
    }
    let cancelled = move || flag.load(Ordering::SeqCst);
    let progress = |_: &str, _: String| {};
    capture::run(&resolved, &CaptureHost { environment: &environment, cancelled: &cancelled, progress: &progress })
}

fn frames_text(capture: &Value) -> String {
    capture["frames"].as_array().unwrap().iter().map(|frame| frame["data"].as_str().unwrap()).collect()
}

fn process_alive(pid: i64) -> bool {
    rea_host::process::ownership::list_live_processes().unwrap().iter().any(|process| i64::from(process.pid) == pid)
}

#[test]
fn normal_exit_publishes_a_verified_capture_and_releases_everything() {
    let capture = run_with(&scenario(json!({"arguments": ["-c", "printf out; exit 3"]})), None).unwrap();
    assert_eq!(capture["exit"], json!({"code": 3, "signal": 0, "reason": "exited"}));
    assert_eq!(frames_text(&capture), "out");
    assert_eq!(capture["cleanup"]["owned_process_group"], "verified");
    assert_eq!(capture["cleanup"]["temporary_root"], "removed");
    assert_eq!(capture["rendered_frames"].as_array().unwrap().last().unwrap()["lines"][0], "out");
    assert_eq!(capture["manifest"]["executable_identity"]["state"], "path_metadata_unchanged");
}

#[test]
fn output_still_buffered_when_the_root_exits_is_drained() {
    let capture = run_with(
        // Paced bursts give many read cycles (one 64 KiB read per readiness
        // would otherwise take the whole output in a few frames).
        &scenario(json!({"arguments": ["-c", "i=0; while [ $i -lt 2000 ]; do echo line-$i-xxxxxxxxxxxxxxxxxxxxxxxx; i=$((i+1)); [ $((i % 25)) -eq 0 ] && sleep 0.005; done; exit 0"]})),
        None,
    )
    .unwrap();
    let text = frames_text(&capture);
    assert!(text.ends_with("line-1999-xxxxxxxxxxxxxxxxxxxxxxxx\r\n"), "{}", &text[text.len().saturating_sub(80)..]);
    assert_eq!(text.matches("\r\n").count(), 2000);
    let raw = &capture["truncation_details"]["raw_terminal"];
    assert_eq!(raw["observed_bytes"], raw["retained_bytes"]);
    // Rendered states hit the cumulative output budget; omissions are counted.
    let rendered = &capture["truncation_details"]["rendered_terminal"];
    assert!(rendered["observed_frames"].as_u64() > rendered["retained_frames"].as_u64());
    assert_eq!(capture["truncated"], true);
}

#[test]
fn hung_up_background_output_is_not_invented_and_the_session_settles() {
    // The session leader's exit revokes the terminal for the background job.
    let capture = run_with(&scenario(json!({"arguments": ["-c", "(trap '' HUP; sleep 0.2; echo late) & echo early"], "settle_ms": 1500})), None).unwrap();
    assert_eq!(frames_text(&capture), "early\r\n");
    assert_eq!(capture["settlement"]["state"], "quiesced");
}

#[test]
fn cancellation_while_running_kills_the_group_and_reports_cleanup() {
    let started = Instant::now();
    let failure = run_with(&scenario(json!({"arguments": ["-c", "echo up; sleep 30 & sleep 30"]})), Some(Duration::from_millis(300))).unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(failure.cancelled);
    let report = failure.cleanup_report.unwrap();
    assert_eq!(report["owned_process_group"]["state"], "cleaned", "{report}");
    assert_eq!(report["temporary_root"]["state"], "cleaned");
    let partial = failure.partial_observation.unwrap();
    let root = partial["observations"]["exit"]["value"]["reason"].clone();
    assert_eq!(root, "cancelled");
    assert!(failure.retained.is_none());
}

#[test]
fn cancellation_during_finalization_escalates_at_once() {
    let started = Instant::now();
    let failure = run_with(
        &scenario(json!({
            "arguments": ["-c", "trap '' TERM; while :; do sleep 0.05; done"],
            "timeout_ms": 200, "finalization_ms": 20000,
        })),
        Some(Duration::from_millis(500)),
    )
    .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    assert!(failure.cancelled);
    let partial = failure.partial_observation.unwrap();
    let signals: Vec<_> = partial["observations"]["finalization"]["value"]["signals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|signal| signal["signal"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(signals, ["SIGTERM", "SIGKILL"]);
    assert_eq!(failure.cleanup_report.unwrap()["owned_process_group"]["state"], "cleaned");
}

/// Helper entry point: re-executed test binary that leaves the PTY group.
#[test]
#[ignore = "helper process for token_owned_descendant_outside_the_pty_group_is_swept"]
fn detached_descendant_helper() {
    let _ = rustix::process::setsid();
    println!("detached {}", std::process::id());
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
fn token_owned_descendant_outside_the_pty_group_is_swept() {
    let helper = std::env::current_exe().unwrap();
    let command = format!(
        "'{}' --exact run::tests::detached_descendant_helper --ignored --nocapture --quiet & sleep 0.5; exit 0",
        helper.display()
    );
    let capture = run_with(&scenario(json!({"arguments": ["-c", command], "normalization": {"pids": false, "ports": true, "paths": false, "time_bucket_ms": 10, "patterns": []}})), None).unwrap();
    let text = frames_text(&capture);
    let pid: i64 = text
        .split_whitespace()
        .skip_while(|word| *word != "detached")
        .nth(1)
        .and_then(|pid| pid.parse().ok())
        .unwrap_or_else(|| panic!("helper pid in {text:?}"));
    assert_eq!(capture["cleanup"]["owned_process_group"], "verified");
    // The sweep killed it by run token; give the kernel a moment to reap.
    let deadline = Instant::now() + Duration::from_secs(2);
    while process_alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!process_alive(pid), "detached token-owned descendant {pid} survived");
}

#[test]
fn failed_cleanup_is_retained_and_retry_releases_it() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::Builder::new().prefix("rea-process-").tempdir().unwrap().keep();
    let locked = root.join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("file"), "x").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    let mut retained = RetainedResources {
        pty: None,
        run_id: "retry-test".to_owned(),
        baseline: rea_host::process::ownership::capture_baseline().unwrap(),
        relation: OwnershipRelation::default(),
        temporary_root: Some(root.clone()),
        report: json!({
            "owned_process_group": {"state": "not_required", "reason": null},
            "terminal_renderer": {"state": "not_required", "reason": null},
            "temporary_root": {"state": "unverified", "reason": "temporary root cleanup was not attempted"},
        }),
    };
    assert!(capture::release_retained(&mut retained).is_err());
    assert_eq!(retained.report["temporary_root"]["state"], "failed");
    assert!(root.exists());
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(capture::release_retained(&mut retained).is_ok());
    assert_eq!(retained.report["temporary_root"]["state"], "cleaned");
    assert!(!root.exists());
    // A released owner stays released.
    assert!(capture::release_retained(&mut retained).is_ok());
}

#[test]
fn interactions_after_exit_are_reported_as_target_exited() {
    let capture = run_with(
        &scenario(json!({
            "arguments": ["-c", "echo x"],
            "events": [{"at_ms": 5000, "type": "input", "data": "late", "sensitive": false}],
        })),
        None,
    )
    .unwrap();
    assert_eq!(capture["interaction_events"][0]["outcome"], "target_exited");
    assert_eq!(capture["interaction_events"][0]["data"], "<not-dispatched>");
}
