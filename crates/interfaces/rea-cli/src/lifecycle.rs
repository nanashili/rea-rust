//! Finalization for one-shot CLI commands.
//!
//! The CLI owns the session boundary, so it must close every registered
//! resource before returning a result. A failed owner remains registered by
//! [`rea_mcp::Session::close`]; this module gives that owner one bounded retry
//! and reports any still-live cleanup uncertainty alongside the command result.

use crate::analysis;
use crate::commands::CommandOutput;
use crate::output::{FailureKind, failure_payload};
use rea_core::analysis_error::{AnalysisError, ErrorKind, cleanup};
use rea_mcp::Session;
use serde_json::{Value, value::RawValue};

const CLEANUP_OPERATION: &str = "cli_session_close";

/// Finish a command result after closing its session.
///
/// A successful retry leaves the original result byte-for-byte untouched,
/// including exact JavaScript JSON carried in [`CommandOutput::Raw`]. If an
/// owner remains unresolved after the single retry, the canonical typed
/// cleanup composition is projected through the CLI's existing output helper.
pub(crate) fn finish(
    output: CommandOutput,
    session: &Session,
    failure_kind: FailureKind,
) -> CommandOutput {
    let Some(cleanup_error) = close_with_retry(session) else {
        return output;
    };

    match output {
        CommandOutput::Value(value) => {
            CommandOutput::Value(compose_output(value, failure_kind, cleanup_error))
        }
        CommandOutput::Raw(raw) => {
            CommandOutput::Value(compose_raw_output(raw, failure_kind, cleanup_error))
        }
    }
}

fn close_with_retry(session: &Session) -> Option<AnalysisError> {
    let first_failures = match session.close() {
        Ok(()) => return None,
        Err(failures) => failures,
    };

    let second_failures = match session.close() {
        Ok(()) => return None,
        Err(failures) => failures,
    };

    Some(compose_failures(
        first_failures.into_iter().chain(second_failures).collect(),
    ))
}

fn compose_failures(mut failures: Vec<AnalysisError>) -> AnalysisError {
    let mut composed = failures
        .drain(..1)
        .next()
        .expect("session close returned no failures");

    for failure in failures {
        composed = cleanup::with_cleanup_failure(composed, failure, CLEANUP_OPERATION);
    }

    composed
}

fn compose_output(value: Value, kind: FailureKind, cleanup_error: AnalysisError) -> Value {
    let primary = primary_for_value(&value, kind);
    let composed = cleanup::with_cleanup_failure(primary, cleanup_error, CLEANUP_OPERATION);
    analysis::cleanup_failure(value, composed.project())
}

fn compose_raw_output(
    raw: Box<RawValue>,
    kind: FailureKind,
    cleanup_error: AnalysisError,
) -> Value {
    let source = raw.get().to_owned();
    let value =
        serde_json::from_str::<Value>(&source).unwrap_or_else(|_| Value::String(source.clone()));
    compose_output(value, kind, cleanup_error)
}

fn primary_for_value(value: &Value, kind: FailureKind) -> AnalysisError {
    if let Some(payload) = failure_payload(value, kind) {
        return AnalysisError::from(ErrorKind::Projected {
            projection: payload,
        });
    }

    AnalysisError::output(
        CLEANUP_OPERATION,
        "The command completed, but session cleanup remained incomplete.",
    )
    .retain_partial_observation(value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_mcp::SessionResource;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct RetryingResource {
        attempts: Mutex<u32>,
        fail_attempts: u32,
    }

    impl SessionResource for RetryingResource {
        fn close(&self) -> Result<(), AnalysisError> {
            let mut attempts = self.attempts.lock().expect("attempt counter poisoned");
            *attempts += 1;
            if *attempts <= self.fail_attempts {
                Err(AnalysisError::output("resource", "resource close failed"))
            } else {
                Ok(())
            }
        }
    }

    fn session_with(resource: Arc<RetryingResource>) -> Session {
        let session = Session::new(HashMap::new());
        session.own(resource);
        session
    }

    #[test]
    fn successful_retry_preserves_value_and_releases_owner() {
        let resource = Arc::new(RetryingResource {
            attempts: Mutex::new(0),
            fail_attempts: 1,
        });
        let session = session_with(Arc::clone(&resource));

        let output = finish(
            CommandOutput::Value(json!({"ok": true})),
            &session,
            FailureKind::Inferred,
        );

        assert!(matches!(output, CommandOutput::Value(value) if value == json!({"ok": true})));
        assert_eq!(
            *resource.attempts.lock().expect("attempt counter poisoned"),
            2
        );
        assert!(session.close().is_ok());
    }

    #[test]
    fn mixed_failures_are_reported_after_retry() {
        let first = Arc::new(RetryingResource {
            attempts: Mutex::new(0),
            fail_attempts: 3,
        });
        let second = Arc::new(RetryingResource {
            attempts: Mutex::new(0),
            fail_attempts: 3,
        });
        let session = Session::new(HashMap::new());
        session.own(first.clone());
        session.own(second.clone());

        let output = finish(
            CommandOutput::Value(json!({"ok": true})),
            &session,
            FailureKind::Inferred,
        );
        let CommandOutput::Value(value) = output else {
            panic!("cleanup failure must be a structured value");
        };

        assert_eq!(value["code"], "cleanup_incomplete");
        assert_eq!(value["details"]["cleanup"], "incomplete");
        assert_eq!(value["details"]["partial_observation"], json!({"ok": true}));
        assert_eq!(*first.attempts.lock().expect("attempt counter poisoned"), 2);
        assert_eq!(
            *second.attempts.lock().expect("attempt counter poisoned"),
            2
        );
    }

    #[test]
    fn primary_failure_keeps_primary_and_cleanup_projection() {
        let resource = Arc::new(RetryingResource {
            attempts: Mutex::new(0),
            fail_attempts: 3,
        });
        let session = session_with(resource);

        let output = finish(
            CommandOutput::Value(json!({
                "error": "Analysis failed",
                "code": "unsupported_target",
                "category": "target",
                "message": "target is unsupported"
            })),
            &session,
            FailureKind::Inferred,
        );
        let CommandOutput::Value(value) = output else {
            panic!("cleanup failure must be a structured value");
        };

        assert_eq!(value["error"], "Analysis failed");
        assert_eq!(value["details"]["execution_failure"], "unsupported_target");
        assert_eq!(value["details"]["cleanup"], "incomplete");
    }

    #[test]
    fn raw_exact_payload_is_retained_when_cleanup_fails() {
        let resource = Arc::new(RetryingResource {
            attempts: Mutex::new(0),
            fail_attempts: 3,
        });
        let session = session_with(resource);
        let raw = RawValue::from_string("{\"text\":\"\\ud800\"}".to_owned())
            .expect("raw JSON should be retained");

        let output = finish(CommandOutput::Raw(raw), &session, FailureKind::Inferred);
        let CommandOutput::Value(value) = output else {
            panic!("cleanup failure must be a structured value");
        };

        assert_eq!(value["code"], "cleanup_incomplete");
        assert_eq!(
            value["details"]["partial_observation"],
            "{\"text\":\"\\ud800\"}"
        );
    }
}
