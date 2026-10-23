//! One owned engine connection and the analysis flow over it.
//!
//! Compatibility owner: `src/android/JadxSession.ts`. The MCP handshake,
//! producer identity checks, `load_apk`, call dispatch (failure classification,
//! the JVM memory `AnalysisResourceConstraintError`) and the retained partial
//! observation and raw result are ported exactly.

use super::analysis::{self, AndroidRequest, ToolCaller};
use super::protocol::{self, BridgeFailure};
use super::release::{
    JADX_BRIDGE_NAME, JADX_BRIDGE_VERSION, JADX_PROVIDER_ID, JADX_PROVIDER_NAME, JADX_REVISION,
    JADX_SHA256, JADX_VERSION,
};
use super::transport::{
    INITIALIZE_PROTOCOL_VERSION, JadxTransport, SUPPORTED_PROTOCOL_VERSIONS, TransportError,
};
use crate::common::errors::capability_unavailable;
use crate::common::evidence::Execution;
use crate::common::target::BinaryTarget;
use rea_core::analysis_error::{AnalysisError, ErrorKind, InputIssue};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{EvidenceProvider, SubjectTarget};
use serde_json::{Value, json};

const CONNECT_TIMEOUT_MS: u64 = 30_000;
const MAX_OPERATION_BYTES: u64 = 32 * 1024 * 1024;

/// One owned engine connection; its wire protocol stays inside this adapter.
pub struct JadxSession {
    pub transport: JadxTransport,
    next_id: u64,
    connected: bool,
    loaded: Option<protocol::JadxLoad>,
    server_name: Option<String>,
    server_version: Option<String>,
    engine_version: Option<String>,
    observed_calls: Vec<Value>,
    partial_context: Option<PartialContext>,
}

struct PartialContext {
    operation: &'static str,
    selected_path: String,
    target_path: String,
    target_sha256: String,
    jar_hash: String,
    bridge_hash: String,
}

/// The inputs to analyze one admitted APK.
pub struct ExecuteContext<'a> {
    pub request: &'a AndroidRequest,
    pub target: &'a BinaryTarget,
    pub snapshot: String,
    pub jar_hash: String,
    pub bridge_hash: String,
    pub timeout_ms: u64,
}

impl JadxSession {
    pub fn new(transport: JadxTransport) -> Self {
        Self {
            transport,
            next_id: 0,
            connected: false,
            loaded: None,
            server_name: None,
            server_version: None,
            engine_version: None,
            observed_calls: Vec::new(),
            partial_context: None,
        }
    }

    /// Whether the selected Java runtime established the bridge protocol.
    pub fn initialized(&self) -> bool {
        self.connected
    }

    fn id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Join owned cleanup even if teardown fails.
    pub fn close(&mut self) -> Result<(), AnalysisError> {
        match self.transport.close() {
            Ok(()) => Ok(()),
            Err(error) => Err(crate::common::errors::provider_cleanup(
                JADX_PROVIDER_ID,
                "close_binary",
                vec![self.transport.run_id.clone()],
                crate::common::errors::object(json!({ "reason": error.message })),
            )),
        }
    }

    /// Facts and upstream replies retained if a later request step fails.
    pub fn partial_observation(&self) -> Option<Value> {
        let context = self.partial_context.as_ref()?;
        Some(json!({
            "provider_id": "jadx",
            "operation": context.operation,
            "target": {
                "selected_path": context.selected_path,
                "path": context.target_path,
                "sha256": context.target_sha256,
                "format": "apk",
            },
            "provider_facts": {
                "jar_sha256": context.jar_hash,
                "bridge_sha256": context.bridge_hash,
                "bridge_name": JADX_BRIDGE_NAME,
                "bridge_version": JADX_BRIDGE_VERSION,
                "server_name": option_str(&self.server_name),
                "server_version": option_str(&self.server_version),
                "engine_version": option_str(&self.engine_version),
            },
            "calls": self.observed_calls,
        }))
    }

    /// Analyze one admitted immutable APK.
    pub fn execute(
        &mut self,
        context: ExecuteContext<'_>,
        cancellation: &Cancellation,
    ) -> Result<Execution, AnalysisError> {
        let operation = context.request.operation;
        self.partial_context = Some(PartialContext {
            operation,
            selected_path: context.request.path.clone(),
            target_path: context.target.path.clone(),
            target_sha256: context.target.sha256.clone(),
            jar_hash: context.jar_hash.clone(),
            bridge_hash: context.bridge_hash.clone(),
        });
        self.observed_calls.clear();
        self.server_name = None;
        self.server_version = None;
        self.engine_version = None;

        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        self.transport.begin_operation();

        if !self.connected {
            self.connect(operation, cancellation)?;
            self.connected = true;
        }

        // Verify producing-bridge identity.
        if self.server_name.as_deref() != Some(JADX_BRIDGE_NAME)
            || self.server_version.as_deref() != Some(JADX_BRIDGE_VERSION)
        {
            return Err(capability_unavailable(
                JADX_PROVIDER_ID,
                operation,
                format!(
                    "Expected {JADX_BRIDGE_NAME} {JADX_BRIDGE_VERSION}; server reported {} {}.",
                    self.server_name.as_deref().unwrap_or("unknown"),
                    self.server_version.as_deref().unwrap_or("unknown")
                ),
                None,
                None,
            ));
        }

        let runtime = {
            let value = self.call_json(
                "rea_jvm_status",
                json!({}),
                context.target,
                operation,
                context.timeout_ms,
                cancellation,
            )?;
            protocol::parse_runtime(&value).map_err(|error| error.into_output(operation))?
        };
        self.engine_version = Some(runtime.engine_reported_version.clone());
        if runtime.engine_reported_version != JADX_VERSION {
            return Err(capability_unavailable(
                JADX_PROVIDER_ID,
                operation,
                format!(
                    "Expected engine {JADX_VERSION}; JAR reported {}.",
                    runtime.engine_reported_version
                ),
                None,
                None,
            ));
        }

        let loaded = match &self.loaded {
            Some(loaded) => loaded.clone(),
            None => {
                let value = self.call_json(
                    "load_apk",
                    json!({ "path": context.snapshot, "threads": 1, "resources": "full" }),
                    context.target,
                    operation,
                    context.timeout_ms,
                    cancellation,
                )?;
                protocol::parse_load(&value).map_err(|error| error.into_output(operation))?
            }
        };
        if loaded.apk_path != context.snapshot {
            return Err(AnalysisError::output(
                operation,
                "JADX loaded a different APK path than the admitted snapshot",
            ));
        }
        self.loaded = Some(loaded.clone());

        let heap_limit_mib = (runtime.max_heap_bytes / (1024 * 1024)) as i64;
        let engine = json!({
            "name": "jadx-headless-mcp",
            "version": runtime.engine_reported_version,
            "artifact_sha256": context.jar_hash,
            "source_revision": if context.jar_hash == JADX_SHA256 { json!(JADX_REVISION) } else { Value::Null },
            "worker_count": 1,
            "heap_limit_mib": if heap_limit_mib == 0 { Value::Null } else { json!(heap_limit_mib) },
        });

        // Dispatch the selected analysis.
        let result = {
            let mut caller = Caller {
                session: self,
                target: context.target,
                operation,
                timeout_ms: context.timeout_ms,
                cancellation,
            };
            analysis::analyze_jadx_request(&mut caller, context.request, &loaded, &engine)?
        };

        let raw_result = json!({
            "server": json!({ "name": self.server_name, "version": self.server_version }),
            "bridge_sha256": context.bridge_hash,
            "jar_sha256": context.jar_hash,
            "loaded": load_value(&loaded),
            "calls": self.observed_calls,
        });

        let provider = EvidenceProvider::new(
            JADX_PROVIDER_ID,
            JADX_PROVIDER_NAME,
            Some(JADX_VERSION.to_owned()),
        );
        let mut execution = Execution::new(result, provider);
        execution.raw_result = Some(raw_result);
        execution.subject = Some(subject_target(context.target));
        execution.limitations = super::release::jadx_limitations();
        execution.locations = if operation == "inspect_android_package" {
            vec![json!({ "kind": "artifact-path", "path": "AndroidManifest.xml" })]
        } else {
            Vec::new()
        };
        Ok(execution)
    }

    /// The SDK 2.3.1 "legacy" connect: initialize, version negotiation and the
    /// initialized notification.
    fn connect(
        &mut self,
        operation: &str,
        cancellation: &Cancellation,
    ) -> Result<(), AnalysisError> {
        self.transport
            .start()
            .map_err(|error| self.transport_error(operation, CONNECT_TIMEOUT_MS, error))?;
        let id = self.id();
        let params = json!({
            "protocolVersion": INITIALIZE_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "rea-android-adapter", "version": "1" },
        });
        let result = self
            .transport
            .request(id, "initialize", params, CONNECT_TIMEOUT_MS, cancellation)
            .map_err(|error| self.transport_error(operation, CONNECT_TIMEOUT_MS, error))?;
        let negotiated = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&negotiated) {
            return Err(AnalysisError::output(
                operation,
                format!("Server's protocol version is not supported: {negotiated}"),
            ));
        }
        let server = result.get("serverInfo");
        self.server_name = server
            .and_then(|info| info.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        self.server_version = server
            .and_then(|info| info.get("version"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        self.transport
            .notify("notifications/initialized", json!({}))
            .map_err(|error| self.transport_error(operation, CONNECT_TIMEOUT_MS, error))?;
        Ok(())
    }

    /// `callTool(name, arguments)`: dispatch, record, classify failures.
    fn call_text(
        &mut self,
        name: &str,
        input: Value,
        target: &BinaryTarget,
        operation: &str,
        timeout_ms: u64,
        cancellation: &Cancellation,
    ) -> Result<String, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        let id = self.id();
        let response = self
            .transport
            .request(
                id,
                "tools/call",
                json!({ "name": name, "arguments": input.clone() }),
                timeout_ms,
                cancellation,
            )
            .map_err(|error| self.transport_error(operation, timeout_ms, error))?;
        self.observed_calls.push(json!({
            "operation": name,
            "input": input,
            "response": response.clone(),
        }));
        let envelope = protocol::parse_envelope(&response, operation)?;
        if envelope.failed {
            if let Some(failure) = protocol::parse_failure(&envelope.text) {
                match failure {
                    BridgeFailure::JvmMemory {
                        memory_area,
                        message,
                        max_heap_bytes,
                    } if name == "load_apk" => {
                        return Err(jvm_memory_error(
                            operation,
                            name,
                            &memory_area,
                            message.as_deref(),
                            max_heap_bytes,
                            target,
                        ));
                    }
                    BridgeFailure::InvalidInput { field, message } => {
                        return Err(AnalysisError::input(
                            operation,
                            vec![InputIssue::new(&[field.as_str()], "invalid_value", message)],
                        ));
                    }
                    _ => {}
                }
            }
            return Err(crate::common::errors::provider_adapter(
                JADX_PROVIDER_ID,
                operation,
                None,
                Some(crate::common::errors::object(json!({
                    "upstream_operation": name,
                    "reason": envelope.text,
                    "target_path": target.path,
                    "target_sha256": target.sha256,
                }))),
            ));
        }
        Ok(envelope.text)
    }

    fn call_json(
        &mut self,
        name: &str,
        input: Value,
        target: &BinaryTarget,
        operation: &str,
        timeout_ms: u64,
        cancellation: &Cancellation,
    ) -> Result<Value, AnalysisError> {
        let text = self.call_text(name, input, target, operation, timeout_ms, cancellation)?;
        protocol::parse_json(&text, operation)
    }

    /// Map a transport error onto the typed failure the caller expects.
    fn transport_error(
        &self,
        operation: &str,
        timeout_ms: u64,
        error: TransportError,
    ) -> AnalysisError {
        match error {
            TransportError::Rpc { code, message } => crate::common::errors::provider_adapter(
                JADX_PROVIDER_ID,
                operation,
                Some(format!("MCP error {code}: {message}")),
                None,
            ),
            TransportError::Protocol(message) => AnalysisError::output(operation, message),
            TransportError::OperationLimit => AnalysisError::output(
                operation,
                format!(
                    "JADX operation output exceeds {MAX_OPERATION_BYTES} bytes; no complete result is available"
                ),
            ),
            TransportError::Closed(message) => crate::common::errors::provider_adapter(
                JADX_PROVIDER_ID,
                operation,
                None,
                Some(crate::common::errors::object(json!({ "reason": message }))),
            ),
            TransportError::Cancelled(_) => AnalysisError::cancelled(operation),
            TransportError::Timeout => AnalysisError::timeout(operation, timeout_ms),
            TransportError::Launch(message) => crate::common::errors::provider_adapter(
                JADX_PROVIDER_ID,
                operation,
                None,
                Some(crate::common::errors::object(json!({ "reason": message }))),
            ),
        }
    }
}

/// Bridge ToolCaller to the owning session.
struct Caller<'s> {
    session: &'s mut JadxSession,
    target: &'s BinaryTarget,
    operation: &'static str,
    timeout_ms: u64,
    cancellation: &'s Cancellation,
}

impl ToolCaller for Caller<'_> {
    fn text(&mut self, name: &str, input: Value) -> Result<String, AnalysisError> {
        self.session.call_text(
            name,
            input,
            self.target,
            self.operation,
            self.timeout_ms,
            self.cancellation,
        )
    }

    fn json(&mut self, name: &str, input: Value) -> Result<Value, AnalysisError> {
        self.session.call_json(
            name,
            input,
            self.target,
            self.operation,
            self.timeout_ms,
            self.cancellation,
        )
    }
}

fn jvm_memory_error(
    operation: &str,
    name: &str,
    memory_area: &str,
    message: Option<&str>,
    max_heap_bytes: u64,
    target: &BinaryTarget,
) -> AnalysisError {
    let reason = format!(
        "The JADX JVM could not allocate memory during {name}{}",
        message.map(|text| format!(": {text}")).unwrap_or_default()
    );
    let remediation = if memory_area == "heap" {
        "Increase REA_JADX_HEAP_MIB (MiB) in the environment that starts REA, within the host or container memory budget. Review JAVA_TOOL_OPTIONS and other JVM heap overrides. The observed heap is this run's limit, not the heap the APK requires."
    } else {
        "Review the JVM allocation failure and the host or container memory limits. The observed maximum heap does not establish which memory region was exhausted; increasing heap alone may not help."
    };
    let mut error = AnalysisError::from(ErrorKind::ResourceConstraint {
        operation: operation.to_owned(),
        resource: "memory".to_owned(),
        reason,
        reported_limits: Some(json!({
            "observed_max_heap_bytes": max_heap_bytes,
            "memory_area": memory_area,
        })),
        remediation_action: Some(remediation.to_owned()),
        retryable: Some(false),
    });
    error.diagnostics = Some(crate::common::errors::object(json!({
        "upstream_operation": name,
        "reason": message,
        "exception_type": "java.lang.OutOfMemoryError",
        "target_path": target.path,
        "target_sha256": target.sha256,
    })));
    error
}

fn subject_target(target: &BinaryTarget) -> SubjectTarget {
    SubjectTarget {
        path: target.path.clone(),
        sha256: target.sha256.clone(),
        format: target.format.clone(),
        architecture: target.architecture.clone(),
    }
}

fn load_value(loaded: &protocol::JadxLoad) -> Value {
    json!({
        "state": "LOADED",
        "apk_path": loaded.apk_path,
        "class_count": loaded.class_count,
        "resource_count": loaded.resource_count,
        "threads": 1,
        "resources": "full",
    })
}

fn option_str(value: &Option<String>) -> Value {
    value.clone().map(Value::String).unwrap_or(Value::Null)
}
