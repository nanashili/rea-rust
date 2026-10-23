//! Static artifact inspection tools: `inspect_rust_binary`, `inspect_go_binary`,
//! `inspect_pe_resources` and `inspect_il2cpp_metadata`.
//!
//! Compatibility owners (TypeScript oracle):
//! - `src/server/registerRustTools.ts` + `src/application/rust/RustBinaryService.ts`
//! - `src/server/registerGoTools.ts` + `src/application/go/GoBinaryService.ts`
//! - `src/server/registerPeResourcesTool.ts` + `src/application/binaryDiagnostics/PeResourcesService.ts`
//! - `src/server/registerIl2cppTools.ts` + `src/application/il2cpp/Il2cppMetadataService.ts`
//!
//! All four are service-backed, explicit-`path` Evidence tools (not
//! active-target tools). Each performs a real stable-file inspection through
//! the shared `rea-application` artifact lifecycle. One inspection owner per
//! tool lives in the session state behind a `Mutex`; its retained file-cleanup
//! ownership is retried on the next request and at session close (registered
//! once as a `SessionResource`). `Completion::OneShot` is used so a successful
//! Evidence record is retained exactly once, by the server.

use rea_mcp::Registry;

#[cfg(any(unix, windows))]
mod platform {
    use crate::common::{self, HostFiles};
    use rea_application::artifacts::inspection::Completion;
    use rea_application::{binary::go::GoInspection, binary::rust::RustInspection, il2cpp};
    use rea_core::analysis_error::{AnalysisError, InputIssue};
    use rea_mcp::{Registry, SessionResource, ToolContext, ToolOutput};
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};

    #[cfg(unix)]
    use rea_application::binary::pe_resources::PeResourcesInspection;

    const ABSOLUTE_PATH_MESSAGE: &str = "Expected an absolute filesystem path on this host.";

    /// The static inspection owners held for one session.
    ///
    /// Each analyzer owns its own retained stable-file cleanup across requests.
    /// `close` retries every owner's cleanup and retains those that still fail.
    struct Owners {
        rust: RustInspection<HostFiles>,
        go: GoInspection<HostFiles>,
        #[cfg(unix)]
        pe: PeResourcesInspection<HostFiles>,
        il2cpp: il2cpp::metadata::Il2cppMetadataInspection<HostFiles>,
    }

    impl Default for Owners {
        fn default() -> Self {
            let files = common::host_files();
            Self {
                rust: RustInspection::new(files.clone()),
                go: GoInspection::new(files.clone()),
                #[cfg(unix)]
                pe: PeResourcesInspection::new(files.clone()),
                il2cpp: il2cpp::metadata::Il2cppMetadataInspection::new(files),
            }
        }
    }

    /// Session-owned static inspection state.
    #[derive(Default)]
    pub(crate) struct StaticOwners {
        owners: Mutex<Owners>,
    }

    impl SessionResource for StaticOwners {
        fn close(&self) -> Result<(), AnalysisError> {
            let mut owners = self
                .owners
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Retry every retained owner; retain those whose cleanup still
            // fails so the session can retry again. Report the first failure.
            let mut first_error: Option<AnalysisError> = None;
            let mut record = |result: Result<(), rea_core::failure::Failure>| {
                if let Err(failure) = result
                    && first_error.is_none()
                {
                    first_error = Some(common::adopt_failure(failure));
                }
            };
            record(owners.rust.close());
            record(owners.go.close());
            #[cfg(unix)]
            record(owners.pe.close());
            record(owners.il2cpp.close());
            match first_error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }

    /// Resolve (and register, once) the session's static inspection owners.
    fn owners(context: &ToolContext<'_>) -> Arc<StaticOwners> {
        let state = context.session.state::<StaticOwners>();
        context.session.own_once(state.clone());
        state
    }

    /// Caller-selected absolute `path`.
    ///
    /// The frozen inputSchema already validated `path` as a non-empty string
    /// with defaults applied; the `isAbsolute` refinement that JSON Schema
    /// cannot express is enforced here exactly as the TypeScript services do
    /// (`AnalysisInputError` with issue path `["path"]`, reason
    /// `invalid_format`, message "Expected an absolute filesystem path on this
    /// host.").
    fn absolute_path(context: &ToolContext<'_>, input: &Value) -> Result<String, AnalysisError> {
        let operation = context.name();
        let path = input
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if std::path::Path::new(&path).is_absolute() {
            return Ok(path);
        }
        Err(AnalysisError::input(
            operation,
            vec![InputIssue::new(
                &["path"],
                "invalid_format",
                ABSOLUTE_PATH_MESSAGE,
            )],
        ))
    }

    /// `inspect_rust_binary` — real stable-file Rust dependency inspection.
    pub(crate) fn inspect_rust_binary(context: &ToolContext<'_>, input: Value) -> ToolOutput {
        common::run_service_tool(context, || {
            let path = absolute_path(context, &input)?;
            let state = owners(context);
            let mut owners = state
                .owners
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let evidence = owners
                .rust
                .inspect(&path, &context.cancellation, Completion::OneShot)
                .map_err(common::adopt_failure)?;
            common::adopt_serialized_evidence(&*evidence)
        })
    }

    /// `inspect_go_binary` — real stable-file Go build-information inspection.
    pub(crate) fn inspect_go_binary(context: &ToolContext<'_>, input: Value) -> ToolOutput {
        common::run_service_tool(context, || {
            let path = absolute_path(context, &input)?;
            let state = owners(context);
            let mut owners = state
                .owners
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let evidence = owners
                .go
                .inspect(&path, &context.cancellation, Completion::OneShot)
                .map_err(common::adopt_failure)?;
            common::adopt_serialized_evidence(&*evidence)
        })
    }

    /// `inspect_pe_resources` — real stable-file PE resource-directory inspection.
    #[cfg(unix)]
    pub(crate) fn inspect_pe_resources(context: &ToolContext<'_>, input: Value) -> ToolOutput {
        common::run_service_tool(context, || {
            let path = absolute_path(context, &input)?;
            let object = input.as_object().cloned().unwrap_or_default();
            // `path`, `max_file_bytes` and `max_entries` were already validated
            // against the frozen inputSchema (bounds and defaults applied). The
            // absolute-path refinement is enforced above with the TypeScript
            // reason/message; parse the remaining typed facts here.
            let parsed = rea_application::inputs::pe_resources(&object)
                .map_err(|error| input_error(context.name(), error))?;
            debug_assert_eq!(parsed.path, path);
            let state = owners(context);
            let mut owners = state
                .owners
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let evidence = owners
                .pe
                .inspect(parsed, &context.cancellation, Completion::OneShot)
                .map_err(common::adopt_failure)?;
            common::adopt_serialized_evidence(&*evidence)
        })
    }

    /// `inspect_pe_resources` is unavailable where the portable PE reader is not
    /// compiled (`rea-application::pe_resources` is `#[cfg(unix)]`). The
    /// TypeScript service decodes PE bytes portably; this native host cannot,
    /// so it fails closed with a typed provider-unavailable error rather than
    /// inventing coverage. See the module report for the precise gap.
    #[cfg(not(unix))]
    pub(crate) fn inspect_pe_resources(context: &ToolContext<'_>, _input: Value) -> ToolOutput {
        if let Err(error) = common::admit(context) {
            return error.into();
        }
        AnalysisError::capability_unavailable(
            "rea-pe-resources",
            context.name(),
            "PE resource inspection is not available on this host build. Run this inspection on a host with the portable PE resource reader compiled.",
        )
        .into()
    }

    /// `inspect_il2cpp_metadata` — real stable-file IL2CPP metadata inspection.
    ///
    /// `detail` selects delivery, never decoding coverage: `summary` (the
    /// default) retains the complete Evidence and delivers its
    /// `inspect_analysis_view` summary; `complete` delivers the full record.
    /// The shared `rea-application` reader owns acquisition, decoding,
    /// cancellation, cleanup and the `Il2cppMetadataService` Evidence binding.
    pub(crate) fn inspect_il2cpp_metadata(context: &ToolContext<'_>, input: Value) -> ToolOutput {
        common::run_service_tool(context, || {
            let summary = requested_detail(context, &input)?;
            let path = absolute_path(context, &input)?;
            let provider_input = json!({ "path": path });
            let complete = {
                let state = owners(context);
                let mut owners = state
                    .owners
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                owners
                    .il2cpp
                    .inspect(&provider_input, &context.cancellation, Completion::OneShot)
                    .map_err(common::adopt_failure)?
            };
            let evidence = common::adopt_raw_evidence(&complete)?;
            if summary {
                common::summary_view(context, evidence)
            } else {
                Ok(evidence)
            }
        })
    }

    /// Delivery selection (`detail`): `summary` is the catalog default.
    fn requested_detail(context: &ToolContext<'_>, input: &Value) -> Result<bool, AnalysisError> {
        match input.get("detail") {
            None => Ok(true),
            Some(Value::String(detail)) if detail == "summary" => Ok(true),
            Some(Value::String(detail)) if detail == "complete" => Ok(false),
            Some(_) => Err(AnalysisError::input(
                context.name(),
                vec![InputIssue::new(
                    &["detail"],
                    "invalid_value",
                    "Expected \"complete\" or \"summary\".",
                )],
            )),
        }
    }

    /// Project a legacy application `InputError` into the shared input error.
    #[cfg(unix)]
    fn input_error(operation: &str, error: rea_application::inputs::InputError) -> AnalysisError {
        let issues = error
            .0
            .into_iter()
            .map(|issue| {
                let path: Vec<&str> = issue.path.iter().map(String::as_str).collect();
                InputIssue::new(&path, issue.reason, issue.message)
            })
            .collect();
        AnalysisError::input(operation, issues)
    }

    /// Bind every static-family tool handler.
    pub(crate) fn register(registry: &mut Registry) {
        registry.handle("inspect_rust_binary", inspect_rust_binary);
        registry.handle("inspect_go_binary", inspect_go_binary);
        registry.handle("inspect_pe_resources", inspect_pe_resources);
        registry.handle("inspect_il2cpp_metadata", inspect_il2cpp_metadata);
    }
}

/// Bind every static-family tool to its exact catalog contract.
pub(crate) fn register(registry: &mut Registry) {
    #[cfg(any(unix, windows))]
    platform::register(registry);
    let _ = registry;
}
