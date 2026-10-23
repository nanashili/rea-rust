//! Validated CDP runtime producer values (`src/browser/execution/CdpRuntimeProtocol.ts`).
//!
//! Each parser accepts exactly what its Zod schema accepts and returns the
//! parsed output (`z.object` strips undeclared keys; `.passthrough()` keeps
//! them). A rejected value is reported by the owning workflow as malformed
//! producer output.
use serde_json::{Map, Value};

pub(super) const FRAME_TREE_MESSAGE: &str = "Malformed Page.getFrameTree result.";

/// `z.number().int().min(0)` as an exact JSON value.
pub(super) fn integer(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    let number = value.as_f64()?;
    (number.is_finite()
        && number >= 0.0
        && number.fract() == 0.0
        && number <= 9_007_199_254_740_991.0)
        .then_some(number as u64)
}

/// `z.number().min(0)`, retained as the producer's JSON number.
pub(super) fn non_negative(value: &Value) -> Option<Value> {
    (value.as_f64()? >= 0.0).then(|| value.clone())
}

fn optional<'a, T>(
    object: &'a Map<String, Value>,
    key: &str,
    parse: impl Fn(&'a Value) -> Option<T>,
) -> Option<Option<T>> {
    match object.get(key) {
        None => Some(None),
        Some(value) => parse(value).map(Some),
    }
}

fn string(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

fn non_empty(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// `contextAuxDataSchema` (passthrough).
pub(super) fn aux_data(value: &Value) -> Option<Value> {
    let object = value.as_object()?;
    optional(object, "frameId", string)?;
    optional(object, "isDefault", Value::as_bool)?;
    optional(object, "type", string)?;
    Some(value.clone())
}

/// `runtimeScriptParsedSchema` output.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Script {
    pub script_id: String,
    pub url: String,
    pub execution_context_id: u64,
    pub start_line: u64,
    pub start_column: u64,
    pub end_line: u64,
    pub end_column: u64,
    pub hash: Option<String>,
    pub source_map_url: Option<String>,
    pub has_source_url: Option<bool>,
    pub script_language: Option<String>,
    pub aux: Option<Value>,
}

pub(super) fn script_parsed(value: &Value) -> Option<Script> {
    let object = value.as_object()?;
    Some(Script {
        script_id: non_empty(object.get("scriptId")?)?,
        url: string(object.get("url")?)?,
        execution_context_id: integer(object.get("executionContextId")?)?,
        start_line: integer(object.get("startLine")?)?,
        start_column: integer(object.get("startColumn")?)?,
        end_line: integer(object.get("endLine")?)?,
        end_column: integer(object.get("endColumn")?)?,
        hash: optional(object, "hash", string)?,
        source_map_url: optional(object, "sourceMapURL", string)?,
        has_source_url: optional(object, "hasSourceURL", Value::as_bool)?,
        script_language: optional(object, "scriptLanguage", string)?,
        aux: optional(object, "executionContextAuxData", aux_data)?,
    })
}

/// `runtimeContextSchema` output: the passthrough `context` object.
pub(super) fn context_created(value: &Value) -> Option<(u64, Value)> {
    let context = value.as_object()?.get("context")?;
    let object = context.as_object()?;
    let id = integer(object.get("id")?)?;
    optional(object, "origin", string)?;
    optional(object, "name", string)?;
    optional(object, "uniqueId", string)?;
    optional(object, "auxData", aux_data)?;
    Some((id, context.clone()))
}

/// The main frame of `runtimeFrameTreeSchema`.
pub(super) struct Frame {
    pub id: String,
    pub url: String,
    pub loader_id: Option<String>,
}

pub(super) fn frame_tree(value: &Value) -> Option<Frame> {
    let frame = value
        .as_object()?
        .get("frameTree")?
        .as_object()?
        .get("frame")?
        .as_object()?;
    Some(Frame {
        id: non_empty(frame.get("id")?)?,
        url: string(frame.get("url")?)?,
        loader_id: optional(frame, "loaderId", string)?,
    })
}

/// One `preciseCoverageSchema` range.
pub(super) struct Range {
    pub start: u64,
    pub end: u64,
    pub count: u64,
}

pub(super) struct CoverageFunction {
    pub name: String,
    pub is_block_coverage: bool,
    pub ranges: Vec<Range>,
}

pub(super) struct CoverageScript {
    pub script_id: String,
    pub url: String,
    pub functions: Vec<CoverageFunction>,
}

pub(super) struct Coverage {
    pub timestamp: Value,
    pub result: Vec<CoverageScript>,
}

pub(super) fn precise_coverage(value: &Value) -> Option<Coverage> {
    let object = value.as_object()?;
    let timestamp = non_negative(object.get("timestamp")?)?;
    let result = object
        .get("result")?
        .as_array()?
        .iter()
        .map(|script| {
            let script = script.as_object()?;
            Some(CoverageScript {
                script_id: non_empty(script.get("scriptId")?)?,
                url: string(script.get("url")?)?,
                functions: script
                    .get("functions")?
                    .as_array()?
                    .iter()
                    .map(|function| {
                        let function = function.as_object()?;
                        Some(CoverageFunction {
                            name: string(function.get("functionName")?)?,
                            is_block_coverage: function.get("isBlockCoverage")?.as_bool()?,
                            ranges: function
                                .get("ranges")?
                                .as_array()?
                                .iter()
                                .map(|range| {
                                    let range = range.as_object()?;
                                    Some(Range {
                                        start: integer(range.get("startOffset")?)?,
                                        end: integer(range.get("endOffset")?)?,
                                        count: integer(range.get("count")?)?,
                                    })
                                })
                                .collect::<Option<Vec<_>>>()?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Coverage { timestamp, result })
}

/// One `runtimeStackSchema` call frame.
pub(super) struct CallFrame {
    pub script_id: String,
    pub url: String,
    pub line: u64,
    pub column: u64,
    pub function_name: String,
}

pub(super) struct Stack {
    pub call_frames: Vec<CallFrame>,
    pub parent: Option<Value>,
    pub parent_id: Option<(String, Option<String>)>,
}

pub(super) fn stack(value: &Value) -> Option<Stack> {
    let object = value.as_object()?;
    let call_frames = object
        .get("callFrames")?
        .as_array()?
        .iter()
        .map(|frame| {
            let frame = frame.as_object()?;
            Some(CallFrame {
                script_id: string(frame.get("scriptId")?)?,
                url: string(frame.get("url")?)?,
                line: integer(frame.get("lineNumber")?)?,
                column: integer(frame.get("columnNumber")?)?,
                function_name: string(frame.get("functionName")?)?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let parent_id = optional(object, "parentId", |value| {
        let parent = value.as_object()?;
        Some((
            string(parent.get("id")?)?,
            optional(parent, "debuggerId", string)?,
        ))
    })?;
    Some(Stack {
        call_frames,
        parent: object.get("parent").cloned(),
        parent_id,
    })
}

/// `runtimeRequestSchema` output.
pub(super) struct Request {
    pub request_id: String,
    pub frame_id: Option<String>,
    pub timestamp: Value,
    pub url: String,
    pub method: String,
    pub initiator: Value,
    pub initiator_type: String,
    pub initiator_stack: Option<Value>,
    pub initiator_url: Option<String>,
    pub initiator_line: Option<u64>,
    pub initiator_column: Option<u64>,
}

pub(super) fn request(value: &Value) -> Option<Request> {
    let object = value.as_object()?;
    let request = object.get("request")?.as_object()?;
    let initiator_value = object.get("initiator")?;
    let initiator = initiator_value.as_object()?;
    Some(Request {
        request_id: non_empty(object.get("requestId")?)?,
        frame_id: optional(object, "frameId", string)?,
        timestamp: non_negative(object.get("timestamp")?)?,
        url: string(request.get("url")?)?,
        method: string(request.get("method")?)?,
        initiator_type: string(initiator.get("type")?)?,
        initiator_stack: initiator.get("stack").cloned(),
        initiator_url: optional(initiator, "url", string)?,
        initiator_line: optional(initiator, "lineNumber", integer)?,
        initiator_column: optional(initiator, "columnNumber", integer)?,
        initiator: initiator_value.clone(),
    })
}

/// One `runtimeListenersSchema` descriptor.
pub(super) struct Listener {
    pub kind: String,
    pub use_capture: bool,
    pub passive: bool,
    pub once: bool,
    pub script_id: String,
    pub line: u64,
    pub column: u64,
}

pub(super) fn listeners(value: &Value) -> Option<Vec<Listener>> {
    value
        .as_object()?
        .get("listeners")?
        .as_array()?
        .iter()
        .map(|listener| {
            let listener = listener.as_object()?;
            Some(Listener {
                kind: string(listener.get("type")?)?,
                use_capture: listener.get("useCapture")?.as_bool()?,
                passive: listener.get("passive")?.as_bool()?,
                once: listener.get("once")?.as_bool()?,
                script_id: string(listener.get("scriptId")?)?,
                line: integer(listener.get("lineNumber")?)?,
                column: integer(listener.get("columnNumber")?)?,
            })
        })
        .collect()
}
