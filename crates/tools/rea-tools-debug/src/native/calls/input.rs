//! `observe_native_calls` input parsing and the exact bridge config.
//!
//! Compatibility owner: `src/domain/native/nativeCallObservation.ts`
//! (`nativeCallObservationInputSchema`, `nativeCallBreakpointSchema`).
//!
//! The MCP server validates the advertised `inputSchema` and applies declared
//! defaults before the handler runs, exactly like the original Zod parse. The
//! CLI adapter shares the handler, so this re-parses defensively, normalizes
//! optional breakpoint fields to explicit `null`, and builds the JSON the
//! unchanged LLDB bridge expects.

use rea_core::analysis_error::{AnalysisError, InputIssue};
use serde_json::{Map, Value, json};

const OPERATION: &str = "observe_native_calls";

/// Captured target output kept per stream; the rest is counted (`MAX_OUTPUT_BYTES`).
pub(crate) const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;

/// One parsed breakpoint request, normalized to explicit optional nulls.
#[derive(Clone, Debug)]
pub(crate) enum Breakpoint {
    Function {
        name: String,
        module: Option<String>,
    },
    ObjcMethod {
        selector: String,
        class_name: Option<String>,
        method_type: String,
    },
}

impl Breakpoint {
    /// The bridge config object for this breakpoint, with optional fields
    /// normalized to `null` as the original `#run` does.
    fn config(&self) -> Value {
        match self {
            Self::Function { name, module } => json!({
                "kind": "function",
                "name": name,
                "module": module,
            }),
            Self::ObjcMethod {
                selector,
                class_name,
                method_type,
            } => json!({
                "kind": "objc-method",
                "selector": selector,
                "class_name": class_name,
                "method_type": method_type,
            }),
        }
    }

    /// The echoed `request` object committed to the result contract.
    pub(crate) fn request(&self) -> Value {
        self.config()
    }
}

/// Parsed `observe_native_calls` input with declared defaults applied.
#[derive(Clone, Debug)]
pub(crate) struct ObservationInput {
    pub breakpoints: Vec<Breakpoint>,
    pub arguments: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub working_directory: Option<String>,
    pub duration_ms: u64,
    pub max_events: u64,
    pub argument_registers: u64,
    pub backtrace_frames: u64,
}

fn issue(path: &[&str], code: &'static str, message: &str) -> AnalysisError {
    AnalysisError::input(OPERATION, vec![InputIssue::new(path, code, message)])
}

fn no_nul(value: &str, path: &[&str], message: &str) -> Result<(), AnalysisError> {
    if value.contains('\0') {
        return Err(issue(path, "invalid_string", message));
    }
    Ok(())
}

/// `nativeCallObservationInputSchema.safeParse(parameters)`.
///
/// The server already validated the advertised schema; this preserves the
/// original strict-object semantics and default projection for both adapters.
pub(crate) fn parse(parameters: &Value) -> Result<ObservationInput, AnalysisError> {
    let object = parameters
        .as_object()
        .ok_or_else(|| issue(&[], "invalid_type", "Expected an object"))?;

    let breakpoints_value = object
        .get("breakpoints")
        .ok_or_else(|| issue(&["breakpoints"], "invalid_type", "breakpoints is required"))?;
    let breakpoint_items = breakpoints_value.as_array().ok_or_else(|| {
        issue(
            &["breakpoints"],
            "invalid_type",
            "breakpoints must be an array",
        )
    })?;
    if breakpoint_items.is_empty() {
        return Err(issue(
            &["breakpoints"],
            "too_small",
            "At least one breakpoint is required",
        ));
    }
    let breakpoints = breakpoint_items
        .iter()
        .map(parse_breakpoint)
        .collect::<Result<Vec<_>, _>>()?;

    let arguments = match object.get("arguments") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                let text = item.as_str().ok_or_else(|| {
                    issue(&["arguments"], "invalid_type", "arguments must be strings")
                })?;
                no_nul(
                    text,
                    &["arguments"],
                    "Native launch strings cannot contain NUL",
                )?;
                Ok(text.to_owned())
            })
            .collect::<Result<Vec<_>, AnalysisError>>()?,
        Some(_) => {
            return Err(issue(
                &["arguments"],
                "invalid_type",
                "arguments must be an array",
            ));
        }
    };

    let environment = match object.get("environment") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(map)) => parse_environment(map)?,
        Some(_) => {
            return Err(issue(
                &["environment"],
                "invalid_type",
                "environment must be an object",
            ));
        }
    };

    let working_directory = match object.get("working_directory") {
        None | Some(Value::Null) => None,
        Some(Value::String(path)) => {
            no_nul(path, &["working_directory"], "Paths cannot contain NUL")?;
            Some(path.clone())
        }
        Some(_) => {
            return Err(issue(
                &["working_directory"],
                "invalid_type",
                "working_directory must be a string",
            ));
        }
    };

    let duration_ms = bounded_int(object, "duration_ms", 100, 600_000, 10_000)?;
    let max_events = bounded_int(object, "max_events", 1, 100_000, 1_000)?;
    let argument_registers = bounded_int(object, "argument_registers", 0, 8, 4)?;
    let backtrace_frames = bounded_int(object, "backtrace_frames", 0, 64, 0)?;

    Ok(ObservationInput {
        breakpoints,
        arguments,
        environment,
        working_directory,
        duration_ms,
        max_events,
        argument_registers,
        backtrace_frames,
    })
}

fn parse_environment(map: &Map<String, Value>) -> Result<Vec<(String, String)>, AnalysisError> {
    let mut pairs = Vec::with_capacity(map.len());
    for (key, value) in map {
        if key.is_empty() || key.contains('=') || key.contains('\0') {
            return Err(issue(
                &["environment"],
                "invalid_string",
                "Environment names cannot contain '=' or NUL",
            ));
        }
        let text = value.as_str().ok_or_else(|| {
            issue(
                &["environment"],
                "invalid_type",
                "environment values must be strings",
            )
        })?;
        no_nul(
            text,
            &["environment"],
            "Environment values cannot contain NUL",
        )?;
        pairs.push((key.clone(), text.to_owned()));
    }
    Ok(pairs)
}

fn parse_breakpoint(value: &Value) -> Result<Breakpoint, AnalysisError> {
    let object = value.as_object().ok_or_else(|| {
        issue(
            &["breakpoints"],
            "invalid_type",
            "breakpoint must be an object",
        )
    })?;
    match object.get("kind").and_then(Value::as_str) {
        Some("function") => {
            let name = required_native_string(object, "name")?;
            if name.is_empty() {
                return Err(issue(
                    &["breakpoints", "name"],
                    "too_small",
                    "name is required",
                ));
            }
            let module = optional_native_string(object, "module")?;
            if matches!(module.as_deref(), Some("")) {
                return Err(issue(
                    &["breakpoints", "module"],
                    "too_small",
                    "module cannot be empty",
                ));
            }
            Ok(Breakpoint::Function { name, module })
        }
        Some("objc-method") => {
            let selector = required_native_string(object, "selector")?;
            objc_name(&selector, &["breakpoints", "selector"])?;
            let class_name = optional_native_string(object, "class_name")?;
            if let Some(class_name) = &class_name {
                objc_name(class_name, &["breakpoints", "class_name"])?;
            }
            let method_type = match object.get("method_type") {
                None | Some(Value::Null) => "any".to_owned(),
                Some(Value::String(value))
                    if matches!(value.as_str(), "instance" | "class" | "any") =>
                {
                    value.clone()
                }
                Some(_) => {
                    return Err(issue(
                        &["breakpoints", "method_type"],
                        "invalid_enum_value",
                        "method_type must be instance, class or any",
                    ));
                }
            };
            Ok(Breakpoint::ObjcMethod {
                selector,
                class_name,
                method_type,
            })
        }
        _ => Err(issue(
            &["breakpoints", "kind"],
            "invalid_union_discriminator",
            "breakpoint kind must be function or objc-method",
        )),
    }
}

fn required_native_string(
    object: &Map<String, Value>,
    key: &'static str,
) -> Result<String, AnalysisError> {
    let text = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| issue(&["breakpoints", key], "invalid_type", "field is required"))?;
    no_nul(
        text,
        &["breakpoints", key],
        "Native strings cannot contain NUL",
    )?;
    Ok(text.to_owned())
}

fn optional_native_string(
    object: &Map<String, Value>,
    key: &'static str,
) -> Result<Option<String>, AnalysisError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => {
            no_nul(
                text,
                &["breakpoints", key],
                "Native strings cannot contain NUL",
            )?;
            Ok(Some(text.clone()))
        }
        Some(_) => Err(issue(
            &["breakpoints", key],
            "invalid_type",
            "field must be a string",
        )),
    }
}

/// `objcName`: non-empty, no whitespace or square brackets.
fn objc_name(value: &str, path: &[&str]) -> Result<(), AnalysisError> {
    if value.is_empty() {
        return Err(issue(path, "too_small", "Use the bare name"));
    }
    if value
        .chars()
        .any(|ch| ch.is_whitespace() || ch == '[' || ch == ']' || ch == '\0')
    {
        return Err(issue(
            path,
            "invalid_string",
            "Use the bare name without spaces or brackets",
        ));
    }
    Ok(())
}

fn bounded_int(
    object: &Map<String, Value>,
    key: &'static str,
    minimum: i64,
    maximum: i64,
    default: i64,
) -> Result<u64, AnalysisError> {
    let value = match object.get(key) {
        None | Some(Value::Null) => default,
        Some(value) => {
            let number = value.as_i64().filter(|_| value.is_i64() || value.is_u64());
            let Some(number) = number else {
                return Err(issue(&[key], "invalid_type", "Expected an integer"));
            };
            number
        }
    };
    if value < minimum {
        return Err(issue(
            &[key],
            "too_small",
            "Value is below the allowed minimum",
        ));
    }
    if value > maximum {
        return Err(issue(
            &[key],
            "too_big",
            "Value exceeds the allowed maximum",
        ));
    }
    Ok(value as u64)
}

impl ObservationInput {
    /// The exact bridge `config.json` object (`#run` in `LldbCallTracer.ts`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bridge_config(
        &self,
        executable: &str,
        architecture: &str,
        expected_sha256: &str,
        stdout_path: &str,
        stderr_path: &str,
        stdout_capture_path: &str,
        stderr_capture_path: &str,
        result_path: &str,
        pid_path: &str,
        identity_ack_path: &str,
        observation_path: &str,
    ) -> Value {
        let environment = self
            .environment
            .iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect::<Map<String, Value>>();
        json!({
            "executable": executable,
            "architecture": architecture,
            "expected_sha256": expected_sha256,
            "arguments": self.arguments,
            "environment": environment,
            "working_directory": self.working_directory,
            "breakpoints": self.breakpoints.iter().map(Breakpoint::config).collect::<Vec<_>>(),
            "duration_ms": self.duration_ms,
            "max_events": self.max_events,
            "argument_registers": self.argument_registers,
            "backtrace_frames": self.backtrace_frames,
            "max_output_bytes": MAX_OUTPUT_BYTES,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "stdout_capture_path": stdout_capture_path,
            "stderr_capture_path": stderr_capture_path,
            "result_path": result_path,
            "pid_path": pid_path,
            "identity_ack_path": identity_ack_path,
            "observation_path": observation_path,
        })
    }

    /// The `environment` object echoed into the result's `target`.
    pub(crate) fn environment_object(&self) -> Value {
        Value::Object(
            self.environment
                .iter()
                .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                .collect(),
        )
    }

    /// `arguments` echoed into the result's `target`.
    pub(crate) fn arguments_value(&self) -> Value {
        Value::Array(self.arguments.iter().cloned().map(Value::String).collect())
    }
}
