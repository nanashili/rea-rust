//! Typed dispatch for offline Android application producers.
//!
//! The runtime adapter owns transport, cancellation, and presentation. This
//! module only selects an application producer for already-retained input.
//! APK parsing, filesystem access, device access, and Evidence persistence
//! remain outside this boundary.

use crate::android_package_handlers;
use rea_application::android;
use rea_application::javascript::graph::json;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Android operations that can be handled from retained JSON facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidOperation {
    InspectPackage,
    InspectClass,
    InspectMethod,
    SearchClasses,
    TraceReferences,
    InspectResource,
    InspectManifestComponent,
    ProjectApplicationGraph,
}

impl AndroidOperation {
    /// Parse the public operation name used by CLI and MCP callers.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            android::package::OPERATION => Ok(Self::InspectPackage),
            android::analysis::CLASS_OPERATION => Ok(Self::InspectClass),
            android::analysis::METHOD_OPERATION => Ok(Self::InspectMethod),
            android::analysis::SEARCH_OPERATION => Ok(Self::SearchClasses),
            android::analysis::TRACE_OPERATION => Ok(Self::TraceReferences),
            android::resource_inspection::OPERATION => Ok(Self::InspectResource),
            android::manifest_component::OPERATION => Ok(Self::InspectManifestComponent),
            android::application_graph::OPERATION => Ok(Self::ProjectApplicationGraph),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the stable public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::InspectPackage => android::package::OPERATION,
            Self::InspectClass => android::analysis::CLASS_OPERATION,
            Self::InspectMethod => android::analysis::METHOD_OPERATION,
            Self::SearchClasses => android::analysis::SEARCH_OPERATION,
            Self::TraceReferences => android::analysis::TRACE_OPERATION,
            Self::InspectResource => android::resource_inspection::OPERATION,
            Self::InspectManifestComponent => android::manifest_component::OPERATION,
            Self::ProjectApplicationGraph => android::application_graph::OPERATION,
        }
    }
}

/// Dispatch one Android operation using retained, provider-produced input.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = AndroidOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch an already-parsed operation without reparsing its name.
pub fn dispatch_typed(operation: AndroidOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        AndroidOperation::InspectPackage
        | AndroidOperation::InspectClass
        | AndroidOperation::InspectMethod
        | AndroidOperation::SearchClasses
        | AndroidOperation::TraceReferences => {
            android_package_handlers::dispatch(operation.name(), input.clone())
        }
        AndroidOperation::InspectResource => android::resource_inspection::inspect(input),
        AndroidOperation::InspectManifestComponent => android::manifest_component::inspect(input),
        AndroidOperation::ProjectApplicationGraph => project_application_graph(input),
    }
}

fn project_application_graph(input: &Value) -> Result<Value, Failure> {
    let graph_input = json::parse(&serde_json::to_string(input).map_err(|error| {
        projection_failure(android::application_graph::OPERATION, error.to_string())
    })?)
    .map_err(|error| {
        projection_failure(android::application_graph::OPERATION, error.to_string())
    })?;
    android::application_graph::validate_input(&graph_input)?;

    android::application_graph::project(&graph_input)
        .map_err(|reason| projection_failure(android::application_graph::OPERATION, reason))
        .and_then(|projection| {
            serde_json::from_str(&projection.stringify()).map_err(|error| {
                projection_failure(
                    android::application_graph::OPERATION,
                    format!(
                        "canonical projection could not cross the legacy JSON boundary: {error}"
                    ),
                )
            })
        })
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Android operation is unknown: {name}"),
        false,
        "Select an offline Android operation supported by the retained-facts handler.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}

fn projection_failure(operation: &str, reason: String) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason,
        false,
        "Provide authenticated Android inventory Evidence with complete page coverage.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}
