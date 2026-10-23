//! Target lifecycle and session status tools.
//!
//! Compatibility owners: `src/server/registerSessionTools.ts`
//! (`registerOpenLifecycleTool`), `registerCloseLifecycleTool.ts`,
//! `registerSessionStatusTool.ts` and `src/server/lifecycleProgress.ts`.
use crate::Registration;
use crate::refine;
use crate::session::OpenOptions;
use crate::status::{
    ClientFeatures, ServerIdentityInput, production_availability_policy, server_identity,
    tool_availability,
};
use crate::target::binary_target_summary;
use rea_core::analysis_error::AnalysisError;
use rea_mcp::support::optional_string;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::Value;
use std::sync::Arc;

pub(crate) fn register(registry: &mut Registry, registration: &Arc<Registration>) {
    let open = Arc::clone(registration);
    registry.handle("open_binary", move |context, input| {
        open_binary(&open, context, &input)
    });
    let close = Arc::clone(registration);
    registry.handle("close_binary", move |context, input| {
        close_binary(&close, context, &input)
    });
    let status = Arc::clone(registration);
    registry.handle("binary_session", move |context, input| {
        binary_session(&status, context, &input)
    });
}

fn owned(input: &Value, key: &str) -> Option<String> {
    optional_string(input, key).map(str::to_owned)
}

fn open_binary(
    registration: &Registration,
    context: &ToolContext<'_>,
    input: &Value,
) -> ToolOutput {
    if let Some(failure) = refine::check(context.contract, input) {
        return failure;
    }
    let state = registration.bind(context.session);
    let options = OpenOptions {
        format_hint: owned(input, "format"),
        architecture: owned(input, "architecture"),
        entry_point: owned(input, "entry_point"),
        provider_id: owned(input, "provider_id"),
        snapshot_path: owned(input, "snapshot_path"),
    };
    let path = optional_string(input, "path").unwrap_or_default();
    match state.open(context.session, path, options, &context.cancellation) {
        Ok(target) => ToolOutput::Value(binary_target_summary(&target)),
        Err(error) => ToolOutput::Failure(error),
    }
}

/// `reportLifecycleEnd`.
fn lifecycle_end(context: &ToolContext<'_>, succeeded: bool) {
    context.progress.report(
        context.name(),
        if succeeded { "completed" } else { "failed" },
    );
}

fn close_binary(
    registration: &Registration,
    context: &ToolContext<'_>,
    input: &Value,
) -> ToolOutput {
    if let Some(failure) = refine::check(context.contract, input) {
        return failure;
    }
    let state = registration.bind(context.session);
    match optional_string(input, "snapshot_path") {
        None => {
            context.progress.report(context.name(), "started");
            let closed = state.close(None);
            lifecycle_end(context, closed.is_ok());
            match closed {
                Ok(()) => ToolOutput::Value(Value::Null),
                Err(error) => ToolOutput::Failure(error),
            }
        }
        Some(path) => {
            let overwrite = input
                .get("overwrite")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            context
                .progress
                .report(context.name(), "saving snapshot; closing provider");
            let closed = state.close_with_snapshot(context.session, path, overwrite);
            lifecycle_end(context, closed.is_ok());
            match closed {
                Ok(saved) => ToolOutput::Value(saved.to_json()),
                Err(error) => ToolOutput::Failure(error),
            }
        }
    }
}

fn binary_session(
    registration: &Registration,
    context: &ToolContext<'_>,
    input: &Value,
) -> ToolOutput {
    if let Some(failure) = refine::check(context.contract, input) {
        return failure;
    }
    let state = registration.bind(context.session);
    let environment = context.session.environment();
    let policy = production_availability_policy(environment);
    let status = match state.status(&context.cancellation) {
        Ok(status) => status,
        Err(error) => return ToolOutput::Failure(error),
    };
    // The connection's negotiated client capabilities are not observable
    // from a tool handler; no client feature is claimed.
    let features = ClientFeatures::default();
    let availability = match tool_availability(&status, &policy, &features) {
        Ok(availability) => availability,
        Err(reason) => return ToolOutput::Failure(AnalysisError::output(context.name(), reason)),
    };
    let identity = server_identity(&ServerIdentityInput {
        started_at: context.session.started_at(),
        expected_package_version: optional_string(input, "expected_package_version"),
        expected_catalog_digest: optional_string(input, "expected_catalog_digest"),
        expected_server_path: optional_string(input, "expected_server_path"),
        client: None,
        protocol_version: None,
        build_commit: context.session.env("REA_BUILD_COMMIT").map(str::to_owned),
        compact_input_schemas: rea_mcp::compact_input_schemas(environment).unwrap_or(false),
        include_output_schemas: rea_mcp::include_output_schemas(environment).unwrap_or(true),
    });
    let Value::Object(mut projected) = status else {
        return ToolOutput::Failure(AnalysisError::output(
            context.name(),
            "session status is not an object",
        ));
    };
    projected.insert("tool_availability".into(), availability);
    projected.insert("client_features".into(), features.to_json());
    projected.insert("server_identity".into(), identity);
    ToolOutput::Value(Value::Object(projected))
}
