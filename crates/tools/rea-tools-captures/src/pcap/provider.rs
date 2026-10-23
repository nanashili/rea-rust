//! Inspect saved captures through bounded, owned tool processes.
//!
//! Compatibility owner: `src/pcap/PcapProvider.ts`. One admitted inspection at
//! a time, over one stable input copy, with both tools run under the enforced
//! native memory boundary. Retained snapshots and owned commands whose cleanup
//! failed persist across calls until confirmed released.
use crate::errors::{self, map};
use crate::pcap::command::{self, CommandCleanup, Limits, RetainedCommand, RunOptions};
use crate::pcap::configuration::{self, ClientIdentity, ConfigurationFailure, Tool, ToolSelection};
use crate::pcap::evidence::{self, PcapObservation};
use crate::pcap::native_bound::{self, NativeBound};
use crate::pcap::output::{self, CapinfosMetadata};
use crate::pcap::snapshot::{CaptureIdentity, PcapSnapshot};
use crate::process::StopResult;
use crate::resources::AnalysisResources;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, SubjectTarget};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::Mutex;
const OPERATION_CLIENT: &str = evidence::CLIENT;
const OPERATION_CAPTURE: &str = evidence::CAPTURE;
const FIELDS: [&str; 12] = [
    "frame.number",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "dns.flags.response",
    "dns.qry.name",
    "dns.a",
    "dns.aaaa",
    "tls.handshake.extensions_server_name",
    "http.request.full_uri",
];
/// Retained owned command and whether it owns a capture snapshot.
struct RetainedPcapCommand {
    command: RetainedCommand,
    owns_snapshot: bool,
}
/// Provider-owned retained state across calls.
#[derive(Default)]
struct Retention {
    snapshots: Vec<PcapSnapshot>,
    commands: Vec<RetainedPcapCommand>,
}
/// Session-owned pcap provider.
pub struct PcapProvider {
    resources: AnalysisResources,
    retention: Mutex<Retention>,
}
impl Default for PcapProvider {
    fn default() -> Self {
        Self {
            resources: AnalysisResources::new(
                "pcap",
                OPERATION_CAPTURE,
                "A packet summary is already active; retry after it completes.",
                || json!({ "max_concurrent_inspections": 1 }),
            ),
            retention: Mutex::new(Retention::default()),
        }
    }
}
impl rea_mcp::SessionResource for PcapProvider {
    fn close(&self) -> Result<(), AnalysisError> {
        self.close_retention()
    }
}
impl PcapProvider {
    fn lock(&self) -> std::sync::MutexGuard<'_, Retention> {
        self.retention
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    /// Close every retained resource at session end.
    fn close_retention(&self) -> Result<(), AnalysisError> {
        self.resources.close()?;
        let mut retention = self.lock();
        let mut failures: Vec<String> = Vec::new();
        let mut index = 0;
        while index < retention.commands.len() {
            match command::stop_retained(&mut retention.commands[index].command) {
                StopResult::Stopped => {
                    retention.commands.remove(index);
                }
                StopResult::Incomplete { reason } => {
                    failures.push(reason);
                    index += 1;
                }
            }
        }
        let mut index = 0;
        while index < retention.snapshots.len() {
            let still_owned = retention
                .commands
                .iter()
                .any(|retained| retained.owns_snapshot);
            if still_owned {
                index += 1;
                continue;
            }
            match retention.snapshots[index].close() {
                Ok(()) => {
                    retention.snapshots.remove(index);
                }
                Err(error) => {
                    failures.push(format!("Error: {}", error.message));
                    index += 1;
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            let resources = retention
                .snapshots
                .iter()
                .map(|snapshot| snapshot.path.clone())
                .chain(
                    retention
                        .commands
                        .iter()
                        .flat_map(|retained| retained.command.cleanup.resources.clone()),
                )
                .collect();
            Err(errors::provider_cleanup(
                "pcap",
                resources,
                map([("reason", json!("Owned process or snapshot cleanup failed"))]),
                "pcap.close",
            ))
        }
    }
    fn store_retained(&self, retained: Option<RetainedCommand>, owns_snapshot: bool) {
        if let Some(command) = retained {
            self.lock().commands.push(RetainedPcapCommand {
                command,
                owns_snapshot,
            });
        }
    }
    /// Probe both tools' versions without reading a capture.
    fn client(
        &self,
        operation: &str,
        selection: &ToolSelection,
        environment: &HashMap<String, String>,
        cancellation: &Cancellation,
    ) -> Result<(ClientIdentity, Value), ClientError> {
        let tshark_stdout = self.probe_version(
            operation,
            &selection.tshark.command,
            environment,
            cancellation,
        )?;
        let tshark_version = configuration::parse_version(&tshark_stdout, Tool::Tshark)
            .map_err(ClientError::Configuration)?;
        let capinfos_stdout = self.probe_version(
            operation,
            &selection.capinfos.command,
            environment,
            cancellation,
        )?;
        let capinfos_version = configuration::parse_version(&capinfos_stdout, Tool::Capinfos)
            .map_err(ClientError::Configuration)?;
        for (name, version) in [("tshark", &tshark_version), ("capinfos", &capinfos_version)] {
            if version.is_none() {
                return Err(ClientError::Configuration(ConfigurationFailure {
                    code: if name == "tshark" {
                        configuration::FailureCode::TsharkVersionUnresolved
                    } else {
                        configuration::FailureCode::CapinfosVersionUnresolved
                    },
                    message: format!(
                        "The selected {name} command did not report a version. Set REA_{}_COMMAND to its absolute executable path.",
                        name.to_uppercase()
                    ),
                    diagnostics: Vec::new(),
                }));
            }
        }
        let identity = ClientIdentity {
            tshark_version,
            capinfos_version,
        };
        let client = client_object(selection, &identity);
        Ok((identity, client))
    }
    fn probe_version(
        &self,
        operation: &str,
        command: &str,
        environment: &HashMap<String, String>,
        cancellation: &Cancellation,
    ) -> Result<String, ClientError> {
        let mut retained = None;
        let output = command::run_pcap_command(
            RunOptions {
                operation,
                command: command.to_owned(),
                arguments: vec!["--version".to_owned()],
                limits: Limits {
                    timeout_ms: 20_000,
                    max_output_bytes: 64 * 1024,
                },
                environment,
                config_dir: None,
                cancellation,
                input_path: None,
                native_bound: None,
                cwd: None,
            },
            &mut retained,
        )
        .map_err(ClientError::Analysis)?;
        if let Some(retained) = retained {
            return Err(ClientError::Cleanup(self.retain_version_cleanup(
                operation,
                retained,
                &output.stdout,
                &output.stderr,
            )));
        }
        Ok(output.stdout)
    }
    fn retain_version_cleanup(
        &self,
        operation: &str,
        retained: RetainedCommand,
        stdout: &str,
        stderr: &str,
    ) -> AnalysisError {
        let resources = retained.cleanup.resources.clone();
        let reason = retained.cleanup.reason.clone();
        let truncated = retained.cleanup.captured_truncated;
        self.lock().commands.push(RetainedPcapCommand {
            command: retained,
            owns_snapshot: false,
        });
        let diagnostics = map([
            ("reason", json!(reason)),
            (
                "captured_output",
                json!({ "stdout": stdout, "stderr": stderr, "truncated": truncated }),
            ),
        ]);
        errors::provider_cleanup("pcap", resources, diagnostics, operation)
    }
    /// Execute `inspect_pcap_client`.
    pub fn execute_client(
        &self,
        environment: &HashMap<String, String>,
        cancellation: &Cancellation,
    ) -> Result<Evidence, AnalysisError> {
        let parameters = json!({});
        self.resources.run(OPERATION_CLIENT, cancellation, || {
            if cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled(OPERATION_CLIENT));
            }
            let selection = configuration::resolve_tools(environment)
                .map_err(|failure| configuration_error(OPERATION_CLIENT, &failure))?;
            let (identity, client) = self
                .client(OPERATION_CLIENT, &selection, environment, cancellation)
                .map_err(|error| error.into_analysis(OPERATION_CLIENT))?;
            let provider = evidence::provider(identity.tshark_version.clone());
            let built = evidence::create(
                OPERATION_CLIENT,
                &parameters,
                PcapObservation {
                    subject: None,
                    provider,
                    result: json!({ "client": client }),
                    raw_result: None,
                    limitations: Vec::new(),
                    locations: Vec::new(),
                },
            )?;
            if cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled(OPERATION_CLIENT)
                    .retain_partial_observation(built.into_value()));
            }
            Ok(built)
        })
    }
    /// Execute `inspect_pcap_capture`.
    pub fn execute_capture(
        &self,
        path: &str,
        environment: &HashMap<String, String>,
        cancellation: &Cancellation,
    ) -> Result<Evidence, AnalysisError> {
        let parameters = json!({ "path": path });
        self.resources.run(OPERATION_CAPTURE, cancellation, || {
            self.capture_admitted(path, &parameters, environment, cancellation)
        })
    }
    #[allow(clippy::too_many_lines)]
    fn capture_admitted(
        &self,
        path: &str,
        parameters: &Value,
        environment: &HashMap<String, String>,
        cancellation: &Cancellation,
    ) -> Result<Evidence, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(OPERATION_CAPTURE));
        }
        let selection = configuration::resolve_tools(environment)
            .map_err(|failure| configuration_error(OPERATION_CAPTURE, &failure))?;
        let (identity, client) = self
            .client(OPERATION_CAPTURE, &selection, environment, cancellation)
            .map_err(|error| error.into_analysis(OPERATION_CAPTURE))?;
        let provider = evidence::provider(identity.tshark_version.clone());
        let prepared = native_bound::prepare(environment)?;
        let native_limitations = prepared.limitations.clone();
        let native_bound = prepared.native_bound;
        let mut snapshot = PcapSnapshot::create(environment)?;
        let capture_identity = match snapshot.capture(path, cancellation) {
            Ok(identity) => identity,
            Err(error) => {
                let cleanup = snapshot.close();
                return Err(compose_discard_failure(error, cleanup, &snapshot.path));
            }
        };
        let inspected = self.inspect_capture(
            &selection,
            &snapshot,
            path,
            &capture_identity,
            &native_bound,
            &native_limitations,
            &client,
            parameters,
            &provider,
            environment,
            cancellation,
        );
        match inspected {
            Ok(captured) => {
                let result = capture_result_value(&client, path, &capture_identity, &captured);
                let evidence = evidence::create(
                    OPERATION_CAPTURE,
                    parameters,
                    PcapObservation {
                        subject: Some(file_subject(path, &capture_identity)),
                        provider: provider.clone(),
                        result,
                        raw_result: None,
                        limitations: captured.limitations.clone(),
                        locations: vec![json!({ "kind": "artifact-path", "path": path })],
                    },
                )?;
                // Late cancellation after a complete inspection: retain the
                // observation as the cancellation's partial Evidence, then run
                // the same snapshot discard/compose path used for any failure
                // (TS `executeAdmitted`: `if (signal?.aborted && result.ok)`).
                if cancellation.reason().is_some() {
                    let cancelled = AnalysisError::cancelled(OPERATION_CAPTURE)
                        .retain_partial_observation(evidence.into_value());
                    return self.finish_capture_failure(snapshot, cancelled);
                }
                self.finish_capture_success(snapshot, evidence)
            }
            Err(error) => self.finish_capture_failure(snapshot, error),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn inspect_capture(
        &self,
        selection: &ToolSelection,
        snapshot: &PcapSnapshot,
        path: &str,
        identity: &CaptureIdentity,
        native_bound: &NativeBound,
        native_limitations: &[String],
        client: &Value,
        parameters: &Value,
        provider: &EvidenceProvider,
        environment: &HashMap<String, String>,
        cancellation: &Cancellation,
    ) -> Result<CapturedResult, AnalysisError> {
        // capinfos -M -S -- <snapshot>.
        let mut capinfos_retained = None;
        let info = command::run_pcap_command(
            RunOptions {
                operation: OPERATION_CAPTURE,
                command: selection.capinfos.command.clone(),
                arguments: vec!["-M".into(), "-S".into(), "--".into(), snapshot.path.clone()],
                limits: Limits {
                    timeout_ms: 60_000,
                    max_output_bytes: 64 * 1024,
                },
                environment,
                config_dir: Some(snapshot.configuration_path.clone()),
                cancellation,
                input_path: Some(path.to_owned()),
                native_bound: Some(native_bound),
                cwd: None,
            },
            &mut capinfos_retained,
        )?;
        self.store_retained(capinfos_retained.take(), true);
        let metadata = output::parse_capinfos_output(&info.stdout)?;
        if let Some(sha256) = &metadata.sha256
            && *sha256 != identity.sha256
        {
            return Err(AnalysisError::protocol(
                "capinfos SHA256 disagrees with the owned capture snapshot",
            ));
        }
        if let Some(cleanup) = &info.cleanup {
            let partial = evidence::partial_value(
                OPERATION_CAPTURE,
                parameters,
                PcapObservation {
                    subject: Some(file_subject(path, identity)),
                    provider: provider.clone(),
                    result: capinfos_partial_result(client, path, identity, &metadata),
                    raw_result: None,
                    limitations: vec![
                        "capinfos output was parsed from a complete bounded stream, but process-tree cleanup remains unconfirmed; tshark was not run".into(),
                    ],
                    locations: vec![json!({ "kind": "artifact-path", "path": path })],
                },
            );
            return Err(command_cleanup_error(
                OPERATION_CAPTURE,
                Some(snapshot.path.clone()),
                cleanup,
                &info.stdout,
                &info.stderr,
                partial,
            ));
        }
        // tshark -n -r <snapshot> -T json --no-duplicate-keys --temp-dir=... -e ...
        let mut tshark_arguments = vec![
            "-n".to_owned(),
            "-r".to_owned(),
            snapshot.path.clone(),
            "-T".to_owned(),
            "json".to_owned(),
            "--no-duplicate-keys".to_owned(),
            format!("--temp-dir={}", snapshot.configuration_path),
        ];
        for field in FIELDS {
            tshark_arguments.push("-e".to_owned());
            tshark_arguments.push(field.to_owned());
        }
        let mut tshark_retained = None;
        let dissected = command::run_pcap_command(
            RunOptions {
                operation: OPERATION_CAPTURE,
                command: selection.tshark.command.clone(),
                arguments: tshark_arguments,
                limits: Limits {
                    timeout_ms: 300_000,
                    max_output_bytes: output::TSHARK_JSON_MAX_BYTES,
                },
                environment,
                config_dir: Some(snapshot.configuration_path.clone()),
                cancellation,
                input_path: Some(path.to_owned()),
                native_bound: Some(native_bound),
                cwd: None,
            },
            &mut tshark_retained,
        )?;
        self.store_retained(tshark_retained.take(), true);
        let fields = output::parse_tshark_json_output(&dissected.stdout, cancellation)?;
        snapshot.verify(identity, path, cancellation)?;
        if fields.packet_count != metadata.packet_count {
            return Err(AnalysisError::protocol(format!(
                "capinfos counted {} packets but tshark returned {}",
                metadata.packet_count, fields.packet_count
            )));
        }
        let limitations = capture_limitations(native_limitations, &fields);
        let captured = CapturedResult {
            metadata,
            fields,
            capinfos_stderr: info.stderr.clone(),
            tshark_stderr: dissected.stderr.clone(),
            limitations: limitations.clone(),
        };
        if let Some(cleanup) = &dissected.cleanup {
            let full = capture_result_value(client, path, identity, &captured);
            let partial = evidence::partial_value(
                OPERATION_CAPTURE,
                parameters,
                PcapObservation {
                    subject: Some(file_subject(path, identity)),
                    provider: provider.clone(),
                    result: full,
                    raw_result: None,
                    limitations,
                    locations: vec![json!({ "kind": "artifact-path", "path": path })],
                },
            );
            return Err(command_cleanup_error(
                OPERATION_CAPTURE,
                Some(snapshot.path.clone()),
                cleanup,
                &dissected.stdout,
                &dissected.stderr,
                partial,
            ));
        }
        Ok(captured)
    }
    fn finish_capture_success(
        &self,
        mut snapshot: PcapSnapshot,
        evidence: Evidence,
    ) -> Result<Evidence, AnalysisError> {
        if self
            .lock()
            .commands
            .iter()
            .any(|retained| retained.owns_snapshot)
        {
            self.lock().snapshots.push(snapshot);
            return Ok(evidence);
        }
        match snapshot.close() {
            Ok(()) => Ok(evidence),
            Err(error) => {
                let cleanup = errors::provider_cleanup(
                    "pcap",
                    vec![snapshot.path.clone()],
                    map([("reason", json!(format!("Error: {}", error.message)))]),
                    OPERATION_CAPTURE,
                );
                self.lock().snapshots.push(snapshot);
                Err(cleanup.retain_partial_observation(evidence.into_value()))
            }
        }
    }
    fn finish_capture_failure(
        &self,
        mut snapshot: PcapSnapshot,
        error: AnalysisError,
    ) -> Result<Evidence, AnalysisError> {
        if self
            .lock()
            .commands
            .iter()
            .any(|retained| retained.owns_snapshot)
        {
            self.lock().snapshots.push(snapshot);
            return Err(error);
        }
        match snapshot.close() {
            Ok(()) => Err(error),
            Err(close_error) => {
                let cleanup = errors::provider_cleanup(
                    "pcap",
                    vec![snapshot.path.clone()],
                    map([("reason", json!(format!("Error: {}", close_error.message)))]),
                    OPERATION_CAPTURE,
                );
                self.lock().snapshots.push(snapshot);
                Err(errors::with_cleanup_failure(
                    error,
                    cleanup,
                    OPERATION_CAPTURE,
                ))
            }
        }
    }
}
/// Error classification when probing versions.
enum ClientError {
    Analysis(AnalysisError),
    Configuration(ConfigurationFailure),
    Cleanup(AnalysisError),
}
impl ClientError {
    fn into_analysis(self, operation: &str) -> AnalysisError {
        match self {
            Self::Analysis(error) | Self::Cleanup(error) => error,
            Self::Configuration(failure) => configuration_error(operation, &failure),
        }
    }
}
fn configuration_error(operation: &str, failure: &ConfigurationFailure) -> AnalysisError {
    configuration::tool_unavailable(operation, &failure.message)
}
/// `client` object in schema shape order.
fn client_object(selection: &ToolSelection, identity: &ClientIdentity) -> Value {
    let mut object = Map::new();
    object.insert("tshark_command".into(), json!(selection.tshark.command));
    object.insert(
        "tshark_source".into(),
        json!(selection.tshark.source.as_str()),
    );
    object.insert("tshark_version".into(), nullable(&identity.tshark_version));
    object.insert("capinfos_command".into(), json!(selection.capinfos.command));
    object.insert(
        "capinfos_source".into(),
        json!(selection.capinfos.source.as_str()),
    );
    object.insert(
        "capinfos_version".into(),
        nullable(&identity.capinfos_version),
    );
    Value::Object(object)
}
fn nullable(value: &Option<String>) -> Value {
    match value {
        Some(text) => json!(text),
        None => Value::Null,
    }
}
/// Aggregated capture facts before projection.
struct CapturedResult {
    metadata: CapinfosMetadata,
    fields: output::TsharkFields,
    capinfos_stderr: String,
    tshark_stderr: String,
    limitations: Vec<String>,
}
fn file_subject(path: &str, identity: &CaptureIdentity) -> SubjectTarget {
    SubjectTarget {
        path: path.to_owned(),
        sha256: identity.sha256.clone(),
        format: "file".to_owned(),
        architecture: None,
    }
}
fn target_object(path: &str, identity: &CaptureIdentity) -> Value {
    json!({ "path": path, "bytes": identity.bytes, "sha256": identity.sha256 })
}
fn endpoints_array(entries: &[(String, u64)]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|(address, packet_count)| {
                json!({ "address": address, "port": Value::Null, "packet_count": packet_count })
            })
            .collect(),
    )
}
fn dns_array(entries: &[(String, Vec<String>)]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|(query, addresses)| {
                json!({
                    "query": query,
                    "response_addresses": addresses,
                    "response_address_count": addresses.len(),
                })
            })
            .collect(),
    )
}
fn protocol_array(entries: &[(String, u64)]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|(protocol, packet_count)| {
                json!({ "protocol": protocol, "packet_count": packet_count })
            })
            .collect(),
    )
}
fn float_or_null(value: Option<f64>) -> Value {
    match value {
        Some(number) => json!(number),
        None => Value::Null,
    }
}
fn u64_or_null(value: Option<u64>) -> Value {
    match value {
        Some(number) => json!(number),
        None => Value::Null,
    }
}
fn string_or_null(value: &Option<String>) -> Value {
    match value {
        Some(text) => json!(text),
        None => Value::Null,
    }
}
/// Full `inspect_pcap_capture` result in schema shape order.
fn capture_result_value(
    client: &Value,
    path: &str,
    identity: &CaptureIdentity,
    captured: &CapturedResult,
) -> Value {
    let metadata = &captured.metadata;
    let fields = &captured.fields;
    let mut object = Map::new();
    object.insert("client".into(), client.clone());
    object.insert("target".into(), target_object(path, identity));
    object.insert("file_type".into(), json!(metadata.file_type));
    object.insert("encapsulation".into(), json!(metadata.encapsulation));
    object.insert("packet_count".into(), json!(metadata.packet_count));
    object.insert(
        "capture_start".into(),
        string_or_null(&metadata.capture_start),
    );
    object.insert("capture_end".into(), string_or_null(&metadata.capture_end));
    object.insert(
        "capture_duration_seconds".into(),
        float_or_null(metadata.capture_duration_seconds),
    );
    object.insert(
        "snapshot_length".into(),
        u64_or_null(metadata.snapshot_length),
    );
    object.insert("endpoints".into(), endpoints_array(&fields.endpoints));
    object.insert("endpoint_count".into(), json!(fields.endpoint_count));
    object.insert("dns_queries".into(), dns_array(&fields.dns_queries));
    object.insert("dns_query_count".into(), json!(fields.dns_query_count));
    object.insert("tls_sni_values".into(), json!(fields.tls_sni_values));
    object.insert("tls_sni_count".into(), json!(fields.tls_sni_count));
    object.insert(
        "protocol_distribution".into(),
        protocol_array(&fields.protocol_distribution),
    );
    object.insert("protocol_count".into(), json!(fields.protocol_count));
    object.insert("http_request_uris".into(), json!(fields.http_request_uris));
    object.insert(
        "http_request_uri_count".into(),
        json!(fields.http_request_uri_count),
    );
    object.insert(
        "http_uri_redaction_count".into(),
        json!(fields.http_uri_redaction_count),
    );
    object.insert(
        "unattributed_dns_addresses".into(),
        json!(fields.unattributed_dns_addresses),
    );
    object.insert(
        "unattributed_dns_address_count".into(),
        json!(fields.unattributed_dns_address_count),
    );
    object.insert(
        "unattributed_dns_packet_count".into(),
        json!(fields.unattributed_dns_packets),
    );
    object.insert(
        "coverage".into(),
        json!(if fields.partial {
            "partial"
        } else {
            "complete"
        }),
    );
    object.insert(
        "diagnostics".into(),
        json!({
            "capinfos_stderr": captured.capinfos_stderr,
            "tshark_stderr": captured.tshark_stderr,
        }),
    );
    Value::Object(object)
}
/// Partial result after capinfos completes but tshark is not run.
fn capinfos_partial_result(
    client: &Value,
    path: &str,
    identity: &CaptureIdentity,
    metadata: &CapinfosMetadata,
) -> Value {
    json!({
        "client": client,
        "target": target_object(path, identity),
        "stage": "capinfos-complete-tshark-not-run",
        "file_type": metadata.file_type,
        "encapsulation": metadata.encapsulation,
        "packet_count": metadata.packet_count,
        "capture_start": string_or_null(&metadata.capture_start),
        "capture_end": string_or_null(&metadata.capture_end),
        "capture_duration_seconds": float_or_null(metadata.capture_duration_seconds),
        "snapshot_length": u64_or_null(metadata.snapshot_length),
    })
}
/// Build the capture limitations list.
fn capture_limitations(native: &[String], fields: &output::TsharkFields) -> Vec<String> {
    let mut limitations: Vec<String> = native.to_vec();
    limitations.push("Both tools read one owned snapshot; target identity comes from its admitted source descriptor".into());
    limitations.push("DNS address values are associated only with a single question in the same response packet; values may include additional DNS records, not only final resolution answers".into());
    limitations.push("Only bytes present in the saved capture are examined; encryption and capture truncation can hide higher-level fields".into());
    if fields.partial {
        limitations.push("One or more projected categories were capped, credential-bearing URIs were omitted or coalesced, or DNS address attribution remains unresolved; counts retain the examined totals".into());
    }
    if fields.http_uri_redaction_count > 0 {
        limitations.push("HTTP transport credentials were excluded; ambiguous credential spans cause the URI to be omitted".into());
    }
    if fields.unattributed_dns_packets > 0 {
        limitations.push(format!(
            "DNS address attribution was unresolved in {} packet(s); unattributed addresses are retained separately",
            fields.unattributed_dns_packets
        ));
    }
    limitations
}
/// `pcapCommandCleanupError`: a ProviderCleanupError carrying captured output.
fn command_cleanup_error(
    operation: &str,
    snapshot_path: Option<String>,
    cleanup: &CommandCleanup,
    stdout: &str,
    stderr: &str,
    partial: Option<Value>,
) -> AnalysisError {
    let mut resources: Vec<String> = Vec::new();
    if let Some(path) = snapshot_path {
        resources.push(path);
    }
    for resource in &cleanup.resources {
        if !resources.contains(resource) {
            resources.push(resource.clone());
        }
    }
    let diagnostics = map([
        ("reason", json!(cleanup.reason)),
        ("previous_error", Value::Null),
        (
            "captured_output",
            json!({
                "stdout": stdout,
                "stderr": stderr,
                "truncated": cleanup.captured_truncated,
            }),
        ),
    ]);
    let mut error = errors::provider_cleanup("pcap", resources, diagnostics, operation);
    if let Some(partial) = partial {
        error = error.retain_partial_observation(partial);
    }
    error
}
/// Compose a snapshot discard failure with a primary acquisition error.
fn compose_discard_failure(
    primary: AnalysisError,
    cleanup: Result<(), crate::node::FsError>,
    snapshot_path: &str,
) -> AnalysisError {
    match cleanup {
        Ok(()) => primary,
        Err(error) => {
            let cleanup = errors::provider_cleanup(
                "pcap",
                vec![snapshot_path.to_owned()],
                map([("reason", json!(format!("Error: {}", error.message)))]),
                OPERATION_CAPTURE,
            );
            errors::with_cleanup_failure(primary, cleanup, OPERATION_CAPTURE)
        }
    }
}
