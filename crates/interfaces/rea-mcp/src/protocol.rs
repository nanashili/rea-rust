//! Transport-independent MCP request handling plus the stdio transport.
//!
//! Wire behavior follows the original SDK server: legacy protocol-version
//! negotiation, `Tool X not found` as -32602, argument validation failures as
//! text-only tool errors, suppressed replies after cancellation, and
//! per-request progress notifications.
use super::catalog::catalog;
use super::delivery::Delivery;
use super::prompts::{self, CompletionProvider};
use super::registry::{Progress, Registry, ToolContext, ToolOutput};
use super::schema;
use super::session::Session;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
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
pub type Sink = Arc<dyn Fn(&Value) + Send + Sync>;

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
        let progress = match params
            .get("_meta")
            .and_then(|meta| meta.get("progressToken"))
            .cloned()
        {
            Some(token) => {
                let sink = Arc::clone(&self.sink);
                let last = Arc::new(Mutex::new(None::<Instant>));
                Progress::new(Arc::new(move |sequence, message| {
                    let mut last = last.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    if last.is_some_and(|at| at.elapsed() < Duration::from_millis(100)) {
                        return;
                    }
                    *last = Some(Instant::now());
                    sink(&json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/progress",
                        "params": { "progressToken": token, "progress": sequence, "message": message }
                    }));
                }))
            }
            None => Progress::silent(),
        };
        let server = Arc::clone(self);
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        let worker = std::thread::Builder::new()
            .name(format!("rea-tool-{name}"))
            .spawn(move || {
                let contract = catalog().tool(&name).expect("contract exists");
                let result = server.execute(contract, arguments, cancellation, progress);
                server
                    .inflight
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&id_key(&id));
                if !suppressed.load(Ordering::SeqCst) {
                    server.send(&result_response(&id, result));
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

    /// Validate, dispatch and deliver one tool call.
    pub fn execute(
        &self,
        contract: &'static super::catalog::ToolContract,
        arguments: Value,
        cancellation: Cancellation,
        progress: Progress,
    ) -> Value {
        let target_content = contract.returns_target_content;
        let input = match schema::validate(contract.input_schema(), &arguments) {
            Ok(input) => input,
            Err(issues) => {
                return self.delivery.sdk_error(
                    schema::validation_error_text(&contract.name, &issues),
                    target_content,
                );
            }
        };
        let Some(handler) = self.registry.get(&contract.name) else {
            let error = AnalysisError::capability_unavailable(
                "rea",
                contract.name.clone(),
                "This operation is not available in the native runtime build.",
            );
            return self.finish(contract, ToolOutput::Failure(error));
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
            Ok(output) => self.finish(contract, output),
            Err(panic) => {
                let message = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                    .unwrap_or_else(|| "Tool handler failed".into());
                self.delivery.sdk_error(message, target_content)
            }
        }
    }

    fn finish(&self, contract: &super::catalog::ToolContract, output: ToolOutput) -> Value {
        let target_content = contract.returns_target_content;
        let result = match output {
            ToolOutput::Evidence(evidence) => {
                let recorded = self.session.record(&evidence);
                self.delivery.evidence(&evidence, contract, recorded)
            }
            ToolOutput::Value(value) => self.delivery.value(value, contract),
            ToolOutput::Raw(value) => value,
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
        self.delivery.finalize(
            Some(&contract.name),
            target_content,
            result,
            &move |evidence| session.record(evidence),
        )
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
        Arc::new(move |message: &Value| {
            let Ok(mut text) = serde_json::to_vec(message) else {
                return;
            };
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
        match serde_json::from_str::<Value>(text) {
            Ok(message) => server.handle(message),
            Err(_) => sink(&error_response(&Value::Null, -32700, "Parse error")),
        }
    }
    server.shutdown(Duration::from_secs(10));
    0
}
