//! Transport-independent MCP request handling plus the stdio transport.
//!
//! Wire behavior follows the original SDK server: legacy protocol-version
//! negotiation, `Tool X not found` as -32602, argument validation failures as
//! text-only tool errors, suppressed replies after cancellation, and
//! per-request progress notifications.
use super::catalog::catalog;
use super::delivery::Delivery;
use super::prompts::{self, CompletionProvider};
use super::registry::{InputValidation, Progress, Registry, ToolContext, ToolOutput};
use super::schema;
use super::session::Session;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json, value::RawValue};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Versions the original SDK negotiates on the 2025-era wire.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 5] = [
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
    "2024-10-07",
];

/// Outbound message sink (one complete JSON-RPC message per call).
pub type Sink = Arc<dyn Fn(&RawValue) + Send + Sync>;

/// Runtime presentation profile selected from the environment.
#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub include_output_schemas: bool,
    /// Advertise compacted input schemas for size-limited clients.
    pub compact_input_schemas: bool,
}

struct Inflight {
    cancellation: Cancellation,
    suppressed: Arc<AtomicBool>,
}

enum ToolArguments {
    Decoded(Value),
    Raw(Box<RawValue>),
}

struct RawCallParams {
    name: Option<String>,
    arguments: Option<Box<RawValue>>,
    meta: Option<Value>,
}

/// One connected MCP server instance.
pub struct Server {
    registry: Arc<Registry>,
    session: Arc<Session>,
    delivery: Delivery,
    profile: Profile,
    completion: Arc<dyn CompletionProvider>,
    inflight: Mutex<HashMap<String, Inflight>>,
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
    sink: Sink,
}

fn id_key(id: &Value) -> String {
    id.to_string()
}

fn error_response(id: &Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

fn result_response(id: &Value, result: Value) -> Value {
    json!({ "result": result, "jsonrpc": "2.0", "id": id })
}

fn raw_result_response(id: &Value, result: &RawValue) -> Box<RawValue> {
    let id = serde_json::to_string(id).unwrap_or_else(|_| "null".into());
    RawValue::from_string(format!(
        "{{\"result\":{},\"jsonrpc\":\"2.0\",\"id\":{id}}}",
        result.get()
    ))
    .expect("JSON-RPC response assembled from validated raw JSON")
}

enum WireResult {
    Value(Value),
    Raw(Box<RawValue>),
}

fn raw_evidence_result(
    evidence: &rea_core::evidence::record::EvidenceRecord,
    contract: &super::catalog::ToolContract,
    recorded: Result<(), AnalysisError>,
) -> Box<RawValue> {
    if let Err(error) = recorded {
        let value = Delivery::new(None).error(&error, contract.returns_target_content);
        return RawValue::from_string(
            serde_json::to_string(&value).expect("delivery error is valid JSON"),
        )
        .expect("delivery error JSON is valid");
    }

    // The typed delivery path uses the serialized Evidence as its text
    // content. Serialize the raw record itself here as well; keeping this
    // text projection raw is what preserves unpaired JavaScript UTF-16 units
    // through the MCP transport.
    let content =
        serde_json::to_string(evidence.raw().get()).expect("Evidence JSON text is valid JSON");
    let target_meta = if contract.returns_target_content {
        ",\"_meta\":{\"provenance\":{\"untrusted_content\":true,\"source\":\"analysis_target\"}}"
    } else {
        ""
    };
    RawValue::from_string(format!(
        "{{\"content\":[{{\"type\":\"text\",\"text\":{content}}}],\"structuredContent\":{}{target_meta}}}",
        evidence.raw().get()
    ))
    .expect("raw Evidence delivery is valid JSON")
}

impl Server {
    pub fn new(
        registry: Arc<Registry>,
        session: Arc<Session>,
        delivery: Delivery,
        profile: Profile,
        completion: Arc<dyn CompletionProvider>,
        sink: Sink,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry,
            session,
            delivery,
            profile,
            completion,
            inflight: Mutex::new(HashMap::new()),
            workers: Mutex::new(Vec::new()),
            sink,
        })
    }

    pub fn session(&self) -> &Arc<Session> {
        &self.session
    }

    fn send(&self, message: &Value) {
        match serde_json::value::to_raw_value(message) {
            Ok(raw) => self.send_raw(&raw),
            Err(error) => {
                eprintln!("REA MCP response encoding failed: {error}");
            }
        }
    }

    fn send_tool_result(&self, id: &Value, result: Value) {
        let response = result_response(id, result);
        match serde_json::value::to_raw_value(&response) {
            Ok(raw) => {
                self.send_raw(&raw);
            }
            Err(_error) => {
                let fallback =
                    error_response(id, -32603, "Tool result could not be encoded as JSON");
                let raw = serde_json::value::to_raw_value(&fallback)
                    .expect("static MCP encoding failure response is valid JSON");
                self.send_raw(&raw);
            }
        }
    }

    fn send_raw(&self, message: &RawValue) {
        (self.sink)(message);
    }

    /// Handle one inbound JSON-RPC message.
    pub fn handle(self: &Arc<Self>, message: Value) {
        let Some(object) = message.as_object() else {
            self.send(&error_response(&Value::Null, -32600, "Invalid Request"));
            return;
        };
        let method = object.get("method").and_then(Value::as_str);
        let id = object.get("id").cloned();
        match (method, id) {
            (Some(method), Some(id)) => self.request(method, id, object.get("params")),
            (Some(method), None) => self.notification(method, object.get("params")),
            _ => {}
        }
    }

    /// Dispatch a request whose arguments must remain raw JSON.
    ///
    /// Returning `false` leaves the message to the ordinary decoded request
    /// path. This keeps protocol behavior unchanged for every operation that
    /// has no exact-input capability.
    fn handle_raw_if_supported(self: &Arc<Self>, text: &str) -> bool {
        let Ok(mut request) = serde_json::from_str::<BTreeMap<String, Box<RawValue>>>(text) else {
            return false;
        };
        let method = request
            .remove("method")
            .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok());
        if method.as_deref() != Some("tools/call") {
            return false;
        }
        let Some(id) = request
            .remove("id")
            .and_then(|raw| serde_json::from_str::<Value>(raw.get()).ok())
        else {
            return false;
        };
        let Some(params) = request.remove("params") else {
            return false;
        };
        let Ok(mut params) = serde_json::from_str::<BTreeMap<String, Box<RawValue>>>(params.get())
        else {
            return false;
        };
        let name = params
            .remove("name")
            .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok());
        let arguments = params.remove("arguments");
        let meta = params
            .remove("_meta")
            .and_then(|raw| serde_json::from_str::<Value>(raw.get()).ok());
        self.call_tool_raw(
            id,
            RawCallParams {
                name,
                arguments,
                meta,
            },
        )
    }

    fn notification(&self, method: &str, params: Option<&Value>) {
        if method == "notifications/cancelled" {
            let Some(request_id) = params.and_then(|params| params.get("requestId")) else {
                return;
            };
            let key = id_key(request_id);
            let inflight = self
                .inflight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(call) = inflight.get(&key) {
                call.suppressed.store(true, Ordering::SeqCst);
                let reason = params
                    .and_then(|params| params.get("reason"))
                    .and_then(Value::as_str)
                    .unwrap_or("MCP request cancelled");
                call.cancellation.cancel(reason.to_owned());
            }
        }
    }

    fn request(self: &Arc<Self>, method: &str, id: Value, params: Option<&Value>) {
        let empty = Value::Object(Map::new());
        let params = params.unwrap_or(&empty);
        let reply = match method {
            "initialize" => Some(result_response(&id, self.initialize(params))),
            "ping" => Some(result_response(&id, json!({}))),
            "tools/list" => Some(result_response(&id, self.list_tools())),
            "tools/call" => {
                self.call_tool(id, params.clone());
                None
            }
            "prompts/list" => Some(result_response(&id, prompts::list())),
            "prompts/get" => Some(
                match prompts::get(
                    params["name"].as_str().unwrap_or_default(),
                    params.get("arguments"),
                ) {
                    Ok(result) => result_response(&id, result),
                    Err(message) => error_response(&id, -32602, message),
                },
            ),
            "completion/complete" => Some(
                match prompts::complete(params, &self.session, self.completion.as_ref()) {
                    Ok(result) => result_response(&id, result),
                    Err(message) => error_response(&id, -32602, message),
                },
            ),
            _ => Some(error_response(&id, -32601, "Method not found")),
        };
        if let Some(reply) = reply {
            self.send(&reply);
        }
    }

    fn initialize(&self, params: &Value) -> Value {
        let requested = params["protocolVersion"].as_str().unwrap_or_default();
        let version = SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .find(|candidate| **candidate == requested)
            .copied()
            .unwrap_or(SUPPORTED_PROTOCOL_VERSIONS[0]);
        let catalog = catalog();
        let mut result = Map::new();
        result.insert("protocolVersion".into(), json!(version));
        result.insert("capabilities".into(), catalog.capabilities.clone());
        result.insert(
            "serverInfo".into(),
            json!({ "name": catalog.server_name, "version": catalog.server_version }),
        );
        if let Some(instructions) = &catalog.instructions {
            result.insert("instructions".into(), json!(instructions));
        }
        Value::Object(result)
    }

    fn list_tools(&self) -> Value {
        json!({
            "tools": catalog()
                .tools
                .iter()
                .map(|tool| {
                    let mut listing = tool.listing(self.profile.include_output_schemas);
                    if self.profile.compact_input_schemas
                        && let Some(object) = listing.as_object_mut()
                        && let Some(schema) = super::catalog::compact_input_schema(&tool.name)
                    {
                        object.insert("inputSchema".into(), schema.clone());
                    }
                    listing
                })
                .collect::<Vec<_>>()
        })
    }

    fn call_tool(self: &Arc<Self>, id: Value, params: Value) {
        let name = params["name"].as_str().unwrap_or_default().to_owned();
        if catalog().tool(&name).is_none() {
            self.send(&error_response(
                &id,
                -32602,
                format!("Tool {name} not found"),
            ));
            return;
        }
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        self.spawn_tool(
            id,
            name,
            ToolArguments::Decoded(arguments),
            params.get("_meta"),
        );
    }

    fn call_tool_raw(self: &Arc<Self>, id: Value, params: RawCallParams) -> bool {
        let name = params.name.unwrap_or_default();
        let Some(contract) = catalog().tool(&name) else {
            self.send(&error_response(
                &id,
                -32602,
                format!("Tool {name} not found"),
            ));
            return true;
        };
        if self.registry.get_raw(&name).is_none() {
            return false;
        }
        let arguments = params.arguments.unwrap_or_else(|| {
            RawValue::from_string("{}".to_owned()).expect("empty object is valid JSON")
        });
        self.spawn_tool(
            id,
            contract.name.clone(),
            ToolArguments::Raw(arguments),
            params.meta.as_ref(),
        );
        true
    }

    fn spawn_tool(
        self: &Arc<Self>,
        id: Value,
        name: String,
        arguments: ToolArguments,
        meta: Option<&Value>,
    ) {
        let Some(contract) = catalog().tool(&name) else {
            self.send(&error_response(
                &id,
                -32602,
                format!("Tool {name} not found"),
            ));
            return;
        };
        let cancellation = Cancellation::default();
        let suppressed = Arc::new(AtomicBool::new(false));
        self.inflight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                id_key(&id),
                Inflight {
                    cancellation: cancellation.clone(),
                    suppressed: Arc::clone(&suppressed),
                },
            );
        let progress = match meta.and_then(|meta| meta.get("progressToken")).cloned() {
            Some(token) => {
                let sink = Arc::clone(&self.sink);
                let last = Arc::new(Mutex::new(None::<Instant>));
                Progress::new(Arc::new(move |sequence, message| {
                    let mut last = last.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    if last.is_some_and(|at| at.elapsed() < Duration::from_millis(100)) {
                        return;
                    }
                    *last = Some(Instant::now());
                    let notification = json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/progress",
                        "params": { "progressToken": token, "progress": sequence, "message": message }
                    });
                    if let Ok(raw) = serde_json::value::to_raw_value(&notification) {
                        sink(&raw);
                    }
                }))
            }
            None => Progress::silent(),
        };
        let server = Arc::clone(self);
        let worker = std::thread::Builder::new()
            .name(format!("rea-tool-{name}"))
            .spawn(move || {
                let contract = catalog().tool(&name).expect("contract exists");
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match arguments {
                        ToolArguments::Decoded(arguments) => {
                            server.execute_raw(contract, arguments, cancellation, progress)
                        }
                        ToolArguments::Raw(arguments) => {
                            server.execute_raw_input(contract, arguments, cancellation, progress)
                        }
                    }))
                    .unwrap_or_else(|panic| {
                        let message = panic
                            .downcast_ref::<String>()
                            .cloned()
                            .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                            .unwrap_or_else(|| "Tool delivery failed".into());
                        WireResult::Value(
                            server
                                .delivery
                                .sdk_error(message, contract.returns_target_content),
                        )
                    });
                server
                    .inflight
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&id_key(&id));
                if !suppressed.load(Ordering::SeqCst) {
                    match result {
                        WireResult::Value(result) => server.send_tool_result(&id, result),
                        WireResult::Raw(result) => {
                            let response = raw_result_response(&id, &result);
                            server.send_raw(&response);
                        }
                    }
                }
            });
        match worker {
            Ok(handle) => {
                let mut workers = self
                    .workers
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                workers.retain(|handle| !handle.is_finished());
                workers.push(handle);
            }
            Err(error) => {
                let message = format!("REA could not start the tool worker: {error}");
                let _ = contract;
                self.send(&result_response(
                    &Value::Null,
                    self.delivery.sdk_error(message, true),
                ));
            }
        }
    }

    fn execute_raw_input(
        &self,
        contract: &'static super::catalog::ToolContract,
        arguments: Box<RawValue>,
        cancellation: Cancellation,
        progress: Progress,
    ) -> WireResult {
        let Some(handler) = self.registry.get_raw(&contract.name) else {
            return WireResult::Value(self.delivery.sdk_error(
                format!("Tool {} does not accept raw input.", contract.name),
                contract.returns_target_content,
            ));
        };
        let context = ToolContext {
            contract,
            session: &self.session,
            cancellation,
            progress,
        };
        let output = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.call_raw(&context, &arguments)
        }));
        match output {
            Ok(output) => self.finish_raw(contract, output),
            Err(panic) => {
                let message = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                    .unwrap_or_else(|| "Tool handler failed".into());
                WireResult::Value(
                    self.delivery
                        .sdk_error(message, contract.returns_target_content),
                )
            }
        }
    }

    /// Validate, dispatch and deliver one tool call.
    pub fn execute(
        &self,
        contract: &'static super::catalog::ToolContract,
        arguments: Value,
        cancellation: Cancellation,
        progress: Progress,
    ) -> Value {
        match self.execute_raw(contract, arguments, cancellation, progress) {
            WireResult::Value(value) => value,
            WireResult::Raw(raw) => serde_json::from_str(raw.get())
                .expect("raw tool result remains valid JSON for the in-process API"),
        }
    }

    fn execute_raw(
        &self,
        contract: &'static super::catalog::ToolContract,
        arguments: Value,
        cancellation: Cancellation,
        progress: Progress,
    ) -> WireResult {
        let target_content = contract.returns_target_content;
        let input = match self.registry.validation(&contract.name) {
            InputValidation::Sdk => {
                match schema::validate_named_contract(
                    &contract.name,
                    contract.input_schema(),
                    &arguments,
                ) {
                    Ok(input) => input,
                    Err(issues) => {
                        return WireResult::Value(self.delivery.sdk_error(
                            schema::validation_error_text(&contract.name, &issues),
                            target_content,
                        ));
                    }
                }
            }
            InputValidation::Application => arguments,
        };
        let Some(handler) = self.registry.get(&contract.name) else {
            let error = AnalysisError::capability_unavailable(
                "rea",
                contract.name.clone(),
                "This operation is not available in the native runtime build.",
            );
            return WireResult::Value(self.finish(contract, ToolOutput::Failure(error)));
        };
        let context = ToolContext {
            contract,
            session: &self.session,
            cancellation,
            progress,
        };
        let output = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.call(&context, input)
        }));
        match output {
            Ok(output) => self.finish_raw(contract, output),
            Err(panic) => {
                let message = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                    .unwrap_or_else(|| "Tool handler failed".into());
                WireResult::Value(self.delivery.sdk_error(message, target_content))
            }
        }
    }

    fn finish(&self, contract: &super::catalog::ToolContract, output: ToolOutput) -> Value {
        match self.finish_raw(contract, output) {
            WireResult::Value(value) => value,
            WireResult::Raw(raw) => serde_json::from_str(raw.get())
                .expect("raw tool result remains valid JSON for the in-process API"),
        }
    }

    fn finish_raw(
        &self,
        contract: &super::catalog::ToolContract,
        output: ToolOutput,
    ) -> WireResult {
        let target_content = contract.returns_target_content;
        let result = match output {
            ToolOutput::Evidence(evidence) => {
                let recorded = self.session.record(&evidence);
                self.delivery.evidence(&evidence, contract, recorded)
            }
            ToolOutput::Value(value) => self.delivery.value(value, contract),
            ToolOutput::Raw(value) => value,
            ToolOutput::RawJson(value) => return WireResult::Raw(value),
            ToolOutput::RawEvidence(evidence) => {
                let recorded = self.session.record_raw(evidence.raw());
                return WireResult::Raw(raw_evidence_result(&evidence, contract, recorded));
            }
            ToolOutput::RawFailure { evidence, error } => {
                let recorded = self.session.record_raw(evidence.raw());
                let result = self.delivery.partial_error(
                    &error,
                    evidence.evidence_id(),
                    recorded,
                    target_content,
                );
                result
            }
            ToolOutput::Failure(error) => {
                let partial_id = error
                    .partial_observation
                    .as_ref()
                    .and_then(|partial| partial.get("evidence_id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                match (partial_id, &error.partial_observation) {
                    (Some(evidence_id), Some(partial)) => {
                        let recorded = serde_json::value::to_raw_value(partial)
                            .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))
                            .and_then(|raw| self.session.record_raw(&raw));
                        self.delivery
                            .partial_error(&error, &evidence_id, recorded, target_content)
                    }
                    _ => self.delivery.error(&error, target_content),
                }
            }
        };
        let session = Arc::clone(&self.session);
        WireResult::Value(self.delivery.finalize(
            Some(&contract.name),
            target_content,
            result,
            &move |evidence| session.record(evidence),
        ))
    }

    /// Cancel every in-flight call, wait for workers, then close the session.
    pub fn shutdown(&self, grace: Duration) {
        for call in self
            .inflight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
        {
            call.suppressed.store(true, Ordering::SeqCst);
            call.cancellation.cancel("MCP transport closed");
        }
        let deadline = Instant::now() + grace;
        let workers = std::mem::take(
            &mut *self
                .workers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for worker in workers {
            while !worker.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
        if let Err(failures) = self.session.close() {
            for failure in failures {
                eprintln!("REA provider cleanup failed during server shutdown: {failure}");
            }
        }
    }
}

/// Serve newline-delimited JSON-RPC over stdin/stdout until EOF.
pub fn serve_stdio(server_factory: impl FnOnce(Sink) -> Arc<Server>) -> i32 {
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let sink: Sink = {
        let stdout = Arc::clone(&stdout);
        Arc::new(move |message: &RawValue| {
            let mut text = message.get().as_bytes().to_vec();
            text.push(b'\n');
            let mut stdout = stdout
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let _ = stdout.write_all(&text);
            let _ = stdout.flush();
        })
    };
    let server = server_factory(Arc::clone(&sink));
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        if server.handle_raw_if_supported(text) {
            continue;
        }
        match serde_json::from_str::<Value>(text) {
            Ok(message) => server.handle(message),
            Err(_) => {
                let error = error_response(&Value::Null, -32700, "Parse error");
                if let Ok(raw) = serde_json::value::to_raw_value(&error) {
                    sink(&raw);
                }
            }
        }
    }
    server.shutdown(Duration::from_secs(10));
    0
}
