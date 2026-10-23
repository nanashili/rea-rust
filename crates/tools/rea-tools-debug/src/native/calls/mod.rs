//! LLDB call observation (`observe_native_calls`, provider `native-macos`).
//!
//! Compatibility owners: `src/native/NativeMacOSProvider.ts` (`execute`
//! admission and the `observe_native_calls` branch, `close()` tracer and
//! call-target cleanup), `src/native/NativeCallObservation.ts`
//! (`observeNativeCalls`) and `src/native/LldbCallTracer.ts`.

use rea_mcp::Registry;

mod input;
#[cfg(unix)]
mod process;
mod result;
#[cfg(unix)]
mod retained;
#[cfg(unix)]
mod target;
#[cfg(unix)]
mod tracer;

/// Bind this group's tools.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle("observe_native_calls", observe::observe_native_calls);
}

#[cfg(unix)]
mod observe {
    use super::input;
    use super::result::{project, project_limitations};
    use super::target;
    use super::tracer::{CallTracer, TraceRequest};
    use crate::common::{active_target, create_evidence, native_macos_provider, target_subject};
    use rea_core::analysis_error::AnalysisError;
    use rea_mcp::{SessionResource, ToolContext, ToolOutput};
    use serde_json::{Value, json};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const OPERATION: &str = "observe_native_calls";
    const PROVIDER: &str = "native-macos";

    /// Per-session client state: the tracer and the closed flag.
    #[derive(Default)]
    pub(super) struct NativeCallState {
        tracer: CallTracer,
        closed: AtomicBool,
    }

    impl SessionResource for NativeCallState {
        /// `NativeMacOSClient.close`: retry retained tracer cleanup. The
        /// call-target digest descriptor closes on drop, so no
        /// `native-call-target` lease can remain owned here.
        fn close(&self) -> Result<(), AnalysisError> {
            self.closed.store(true, Ordering::SeqCst);
            self.tracer.close()
        }
    }

    /// `execute("observe_native_calls")` through `observeNativeCalls`.
    pub(super) fn observe_native_calls(context: &ToolContext<'_>, parameters: Value) -> ToolOutput {
        let state = context.session.state::<NativeCallState>();
        context.session.own_once(Arc::clone(&state));
        if state.closed.load(Ordering::SeqCst) {
            return AnalysisError::capability_unavailable(
                PROVIDER,
                OPERATION,
                "Native provider client is closed",
            )
            .into();
        }
        if context.cancellation.reason().is_some() {
            return AnalysisError::cancelled(OPERATION).into();
        }
        let target = match active_target(context) {
            Ok(target) => target,
            Err(error) => return error.into(),
        };
        if target.kind != "executable"
            || !matches!(target.format.as_str(), "mach-o" | "mach-o-universal")
        {
            return AnalysisError::capability_unavailable(
                PROVIDER,
                OPERATION,
                "Native call observation launches a Mach-O executable; the active target is not one",
            )
            .into();
        }
        let parsed = match input::parse(&parameters) {
            Ok(parsed) => parsed,
            Err(error) => return error.into(),
        };
        context.progress.report(OPERATION, "started");
        if let Err(error) = target::verify(&target.path, &target.sha256, &context.cancellation) {
            return error.into();
        }
        if context.cancellation.reason().is_some() {
            return AnalysisError::cancelled(OPERATION).into();
        }
        let request = TraceRequest {
            executable: target.path.clone(),
            architecture: target.architecture.clone().unwrap_or_default(),
            expected_sha256: target.sha256.clone(),
            input: parsed,
        };
        let trace = match state.tracer.trace(
            &request,
            context.session.environment(),
            &context.cancellation,
        ) {
            Ok(trace) => trace,
            Err(error) => return error.into(),
        };
        let facts = super::result::TargetFacts {
            path: request.executable.clone(),
            sha256: request.expected_sha256.clone(),
            architecture: request.architecture.clone(),
        };
        if context.cancellation.reason().is_some() {
            return AnalysisError::cancelled(OPERATION)
                .retain_partial_observation(super::result::project_partial(
                    &facts,
                    &request.input,
                    &trace,
                    "cancelled",
                ))
                .into();
        }
        let result = project(&facts, &request.input, &trace);
        let limitations = project_limitations(&facts, &request.input, &trace);
        let subject = target_subject(&target);
        create_evidence(
            OPERATION,
            Some(&subject),
            &native_macos_provider(),
            parameters,
            result,
            limitations,
            vec![json!({ "kind": "artifact-path", "path": target.path })],
        )
        .into()
    }
}

#[cfg(not(unix))]
mod observe {
    use rea_core::analysis_error::AnalysisError;
    use rea_mcp::{ToolContext, ToolOutput};
    use serde_json::Value;

    const LLDB_REQUIREMENT: &str = "LLDB from Xcode or the Command Line Tools is not available";

    /// LLDB call observation is macOS-only; other hosts never launch LLDB.
    pub(super) fn observe_native_calls(
        _context: &ToolContext<'_>,
        _parameters: Value,
    ) -> ToolOutput {
        AnalysisError::capability_unavailable(
            "native-macos",
            "observe_native_calls",
            LLDB_REQUIREMENT,
        )
        .with_user_message(LLDB_REQUIREMENT)
        .into()
    }
}
