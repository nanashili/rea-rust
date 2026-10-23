#![cfg(unix)]
//! Actual signal delivery in a separate process protects the Cargo test runner.
use rea_host::command_interrupts::CommandInterrupts;
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    low_level::raise,
};
use std::process::Command;

#[test]
fn interrupts_preserve_first_signal_and_allow_cleanup_to_finish() {
    const CHILD: &str = "REA_INTERRUPT_CONTRACT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "interrupts_preserve_first_signal_and_allow_cleanup_to_finish",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "signal child {:?}: {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    // Removal must affect only this owner's subscriptions, and an old token
    // must not start observing a later command's process signals.
    let previous = CommandInterrupts::install().unwrap();
    let old_token = previous.cancellation().clone();
    assert_eq!(previous.finish(), None);
    for (first, second, reason, code) in [
        (SIGINT, SIGTERM, "SIGINT", 130),
        (SIGTERM, SIGINT, "SIGTERM", 143),
    ] {
        let owner = CommandInterrupts::install().unwrap();
        let artifact = tempfile::NamedTempFile::new().unwrap();
        raise(first).unwrap();
        raise(second).unwrap();
        assert_eq!(owner.cancellation().reason(), Some(reason));
        assert!(!owner.cancellation().cancel("late cancellation"));
        assert!(artifact.as_file().metadata().is_ok());
        // Interrupted execution is still alive and can explicitly finalize its
        // owned resource before reporting the conventional interrupted status.
        artifact.close().unwrap();
        assert_eq!(owner.finish(), Some(code));
        assert_eq!(old_token.reason(), None);
    }
    let owner = CommandInterrupts::install().unwrap();
    owner.cancellation().cancel("earlier request cancellation");
    raise(SIGTERM).unwrap();
    raise(SIGINT).unwrap();
    assert_eq!(
        owner.cancellation().reason(),
        Some("earlier request cancellation")
    );
    assert_eq!(owner.finish(), Some(143));
}
