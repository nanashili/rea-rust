//! Provider-neutral JavaScript semantic IR wire contract.
//!
//! The application graph has richer internal records.  This module is the
//! stable boundary shape: records that already have a domain owner are typed,
//! and each operation collection retains its source-level fields.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Value, json};

use super::static_analysis::SourceRange;
use crate::javascript::resolution::mode::ModuleResolutionMode;
use crate::javascript::semantic::coverage::SemanticCoverage;
use crate::javascript::semantic::provenance::BindingProvenance;
use crate::javascript::semantic::value_types::{JsString, Primitive, SemanticValue};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticScope {
    pub scope_id: String,
    pub parent_scope_id: Option<String>,
    pub kind: String,
    pub location: SourceRange,
    pub bindings_complete: bool,
    pub binding_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticDefinition {
    pub kind: String,
    pub location: SourceRange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticBinding {
    pub binding_id: String,
    pub scope_id: String,
    pub name: JsString,
    pub kind: String,
    pub mutable: bool,
    pub definitions: Vec<SemanticDefinition>,
    pub value: SemanticValue,
    pub provenance: BindingProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticReference {
    pub name: JsString,
    pub role: String,
    pub location: SourceRange,
    pub binding_id: Option<String>,
    pub resolution: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticReturnSite {
    pub return_site_id: String,
    pub location: SourceRange,
    pub identity_reference_location: Option<SourceRange>,
    pub value: SemanticValue,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticCallable {
    pub callable_id: String,
    pub kind: String,
    pub name: Option<JsString>,
    pub container_scope_id: String,
    pub body_scope_id: Option<String>,
    pub location: SourceRange,
    pub return_sites: Vec<SemanticReturnSite>,
    pub return_coverage: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticCallArgument {
    pub index: usize,
    pub location: SourceRange,
    pub spread: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticCallSite {
    pub call_site_id: String,
    pub kind: String,
    pub caller_callable_id: Option<String>,
    pub location: SourceRange,
    pub callee_location: SourceRange,
    pub resolution: String,
    pub callee_callable_ids: Vec<String>,
    pub arguments: Vec<SemanticCallArgument>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticArgumentFlow {
    pub call_site_id: String,
    pub argument_index: usize,
    pub argument_location: SourceRange,
    pub callable_id: String,
    pub parameter_binding_id: String,
    pub parameter_location: SourceRange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticCallReturnFlow {
    pub call_site_id: String,
    pub callable_id: String,
    pub return_site_id: String,
    pub return_location: SourceRange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticCallResultFlow {
    pub call_site_id: String,
    pub binding_id: String,
    pub definition_location: SourceRange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticClosureCapture {
    pub callable_id: String,
    pub binding_id: String,
    pub reference_location: SourceRange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticProjectedResultBinding {
    pub binding_id: String,
    pub projection_path: Vec<SemanticProjectionPathSegment>,
    pub resolution: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum SemanticProjectionPathSegment {
    String(JsString),
    Number(f64),
    Null,
}

impl<'de> Deserialize<'de> for SemanticProjectionPathSegment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        let text = raw.get();

        match text.as_bytes().first().copied() {
            Some(b'"') => serde_json::from_str::<JsString>(text)
                .map(Self::String)
                .map_err(serde::de::Error::custom),
            Some(b'-' | b'0'..=b'9') => serde_json::from_str::<f64>(text)
                .map(Self::Number)
                .map_err(serde::de::Error::custom),
            Some(b'n') if text == "null" => Ok(Self::Null),
            _ => Err(serde::de::Error::custom(
                "projection path segments must be strings, numbers, or null",
            )),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticFunctionFingerprintComponents {
    pub parameter_arity: usize,
    pub normalized_ast_sha256: String,
    pub control_flow_sha256: String,
    pub relation_shape_sha256: String,
    pub literal_set_sha256: String,
    pub effects: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticPromiseOperation {
    pub promise_id: String,
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub ownership: String,
    pub owner_binding_id: Option<String>,
    pub return_site_id: Option<String>,
    pub source_promise_ids: Vec<String>,
    pub source_resolution: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticFunctionFingerprint {
    pub callable_id: String,
    pub status: String,
    pub components: SemanticFunctionFingerprintComponents,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticEventOperation {
    pub event_id: String,
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub emitter_key: JsString,
    pub emitter_binding_id: Option<String>,
    pub event_name: Option<JsString>,
    pub listener_binding_id: Option<String>,
    pub listener_location: Option<SourceRange>,
    pub resolution: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticTimerOperation {
    pub timer_id: String,
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub handle_binding_id: Option<String>,
    pub projected_result_bindings: Vec<SemanticProjectedResultBinding>,
    pub linked_timer_id: Option<String>,
    pub delay_milliseconds: Option<f64>,
    pub resolution: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticChildProcessSpawn {
    pub process_id: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub result_binding_id: Option<String>,
    pub projected_result_bindings: Vec<SemanticProjectedResultBinding>,
    pub command: Option<JsString>,
    pub argv_count: Option<usize>,
    pub environment_supplied: bool,
    pub stdio_mode: String,
    pub resolution: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticChildProcessInteraction {
    pub interaction_id: String,
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub process_binding_id: Option<String>,
    pub linked_process_ids: Vec<String>,
    pub event_name: Option<JsString>,
    pub signal_name: Option<JsString>,
    pub listener_location: Option<SourceRange>,
    pub resolution: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticConfigurationOperation {
    pub config_id: String,
    pub kind: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub result_binding_id: Option<String>,
    pub key: Option<JsString>,
    pub source_config_id: Option<String>,
    pub value: Primitive,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_resource_limit: Option<crate::javascript::semantic::value_types::ResourceLimit>,
    pub resolution: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticRequestField {
    pub name: JsString,
    pub source_binding_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticRequestOperation {
    pub request_id: String,
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub result_binding_id: Option<String>,
    pub projected_result_bindings: Vec<SemanticProjectedResultBinding>,
    pub linked_request_ids: Vec<String>,
    pub endpoint: Option<String>,
    pub fields: Vec<SemanticRequestField>,
    pub resolution: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticBoundaryOperation {
    pub boundary_id: String,
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub source_binding_id: Option<String>,
    pub result_binding_id: Option<String>,
    pub resolution: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticResourceOperation {
    pub resource_id: String,
    pub kind: String,
    pub method: String,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub result_binding_id: Option<String>,
    pub linked_resource_ids: Vec<String>,
    pub resolution: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SemanticObjectOperationKind {
    Read,
    Write,
    Spread,
    Destructure,
}

impl SemanticObjectOperationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Spread => "spread",
            Self::Destructure => "destructure",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SemanticOperationResolution {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticObjectOperation {
    pub object_operation_id: String,
    pub kind: SemanticObjectOperationKind,
    pub location: SourceRange,
    pub owner_callable_id: Option<String>,
    pub object_binding_id: Option<String>,
    pub target_binding_id: Option<String>,
    pub property_path: Option<Vec<JsString>>,
    pub resolution: SemanticOperationResolution,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticFrontier {
    pub kind: String,
    pub callable_id: Option<String>,
    pub location: SourceRange,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticModuleLink {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_mode: Option<ModuleResolutionMode>,
    pub kind: String,
    pub specifier: Option<JsString>,
    pub imported_name: Option<JsString>,
    pub local_name: Option<JsString>,
    pub exported_name: Option<JsString>,
    pub callable_id: Option<String>,
    pub location: SourceRange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticIr {
    pub schema: String,
    pub scopes: Vec<SemanticScope>,
    pub bindings: Vec<SemanticBinding>,
    pub callables: Vec<SemanticCallable>,
    pub references: Vec<SemanticReference>,
    #[serde(default)]
    pub module_links: Vec<SemanticModuleLink>,
    #[serde(default)]
    pub call_sites: Vec<SemanticCallSite>,
    #[serde(default)]
    pub argument_flows: Vec<SemanticArgumentFlow>,
    #[serde(default)]
    pub call_return_flows: Vec<SemanticCallReturnFlow>,
    #[serde(default)]
    pub call_result_flows: Vec<SemanticCallResultFlow>,
    #[serde(default)]
    pub closure_captures: Vec<SemanticClosureCapture>,
    #[serde(default)]
    pub promise_operations: Vec<SemanticPromiseOperation>,
    #[serde(default)]
    pub event_operations: Vec<SemanticEventOperation>,
    #[serde(default)]
    pub timer_operations: Vec<SemanticTimerOperation>,
    #[serde(default)]
    pub child_process_spawns: Vec<SemanticChildProcessSpawn>,
    #[serde(default)]
    pub child_process_interactions: Vec<SemanticChildProcessInteraction>,
    #[serde(default)]
    pub configuration_operations: Vec<SemanticConfigurationOperation>,
    #[serde(default)]
    pub request_operations: Vec<SemanticRequestOperation>,
    #[serde(default)]
    pub boundary_operations: Vec<SemanticBoundaryOperation>,
    #[serde(default)]
    pub resource_operations: Vec<SemanticResourceOperation>,
    #[serde(default)]
    pub object_operations: Vec<SemanticObjectOperation>,
    #[serde(default)]
    pub function_fingerprints: Vec<SemanticFunctionFingerprint>,
    #[serde(default)]
    pub frontiers: Vec<SemanticFrontier>,
    pub coverage: SemanticCoverage,
    pub limitations: Vec<String>,
}

impl SemanticIr {
    pub fn failed() -> Self {
        Self {
            schema: "JavaScriptSemanticIR".to_owned(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            callables: Vec::new(),
            references: Vec::new(),
            module_links: Vec::new(),
            call_sites: Vec::new(),
            argument_flows: Vec::new(),
            call_return_flows: Vec::new(),
            call_result_flows: Vec::new(),
            closure_captures: Vec::new(),
            promise_operations: Vec::new(),
            event_operations: Vec::new(),
            timer_operations: Vec::new(),
            child_process_spawns: Vec::new(),
            child_process_interactions: Vec::new(),
            configuration_operations: Vec::new(),
            request_operations: Vec::new(),
            boundary_operations: Vec::new(),
            resource_operations: Vec::new(),
            object_operations: Vec::new(),
            function_fingerprints: Vec::new(),
            frontiers: Vec::new(),
            coverage: SemanticCoverage::failed(),
            limitations: vec![
                "JavaScript parsing failed; no semantic absence claim is available.".to_owned(),
                "No JavaScript was executed.".to_owned(),
            ],
        }
    }
}

pub fn primitive_value(value: Primitive) -> SemanticValue {
    SemanticValue::Literal { value }
}

pub fn failed_json() -> Value {
    json!(SemanticIr::failed())
}

#[cfg(test)]
mod tests {
    use super::{SemanticProjectedResultBinding, SemanticProjectionPathSegment};
    use crate::javascript::semantic::value_types::JsString;

    #[test]
    fn projected_result_binding_round_trips_unpaired_utf16_path_segments() {
        let binding = SemanticProjectedResultBinding {
            binding_id: "result".to_owned(),
            projection_path: vec![
                SemanticProjectionPathSegment::String(JsString::from_utf16(vec![0xD800])),
                SemanticProjectionPathSegment::Number(2.0),
                SemanticProjectionPathSegment::Null,
            ],
            resolution: "complete".to_owned(),
        };

        let encoded = serde_json::to_string(&binding).expect("projection binding serializes");
        let decoded: SemanticProjectedResultBinding =
            serde_json::from_str(&encoded).expect("projection binding deserializes");

        assert_eq!(decoded.projection_path.len(), 3);
        assert!(matches!(
            &decoded.projection_path[0],
            SemanticProjectionPathSegment::String(value)
                if value.units() == [0xD800]
        ));
        assert!(matches!(
            decoded.projection_path[1],
            SemanticProjectionPathSegment::Number(value) if value == 2.0
        ));
        assert!(matches!(
            decoded.projection_path[2],
            SemanticProjectionPathSegment::Null
        ));
    }

    #[test]
    fn projection_path_rejects_non_primitive_segments() {
        for input in ["true", "{}", "[]"] {
            let error = serde_json::from_str::<SemanticProjectionPathSegment>(input)
                .expect_err("non-primitive projection segment must be rejected");
            assert!(error.to_string().contains("strings, numbers, or null"));
        }
    }
}
