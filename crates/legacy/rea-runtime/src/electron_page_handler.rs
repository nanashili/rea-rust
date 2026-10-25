//! Live, read-only Electron page inspection over a caller-selected CDP target.
//!
//! This adapter owns the connected page session and its cleanup. The shared
//! application workflow owns authorization and interpretation of captured CDP
//! facts.

use crate::mcp::{capture_timestamp, discover_electron_targets, websocket_endpoint};
use rea_application::{
    electron,
    electron::observation::{DiscoveredTarget, PageInspection},
    electron::page_inspection::{
        self as electron_page_inspection, ElectronCdpFailure, ElectronCdpFailureKind,
    },
};
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use rea_host::cdp_transport::{
    CdpEventBatch, CdpTransportError, CdpWebSocketTransport, DEFAULT_TIMEOUT,
    MAX_INSPECTION_MESSAGE_BYTES,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Inspect one caller-selected Electron file page and close the session.
pub fn execute(input: Value, cancellation: &Cancellation) -> Result<Value, Failure> {
    let request = electron_page_inspection::validate_input(&input)?;
    ensure_active(cancellation)?;

    let (browser, targets) = discover_electron_targets(&request.cdp_endpoint, cancellation)
        .map_err(bind_page_operation)?;
    let target = selected_target(&targets, &request.target_id)?;

    ensure_target_is_inspectable(target)?;
    ensure_active(cancellation)?;

    let endpoint = websocket_endpoint(&request.cdp_endpoint, &request.target_id)
        .map_err(|reason| invalid_endpoint(&reason))?;
    let transport = CdpWebSocketTransport::connect_with_limits(
        &endpoint,
        Some(&request.target_id),
        DEFAULT_TIMEOUT,
        MAX_INSPECTION_MESSAGE_BYTES,
    )
    .map_err(|error| connect_failure(error))?;
    let mut session = ElectronPageSession::new(transport);

    let started_at = capture_timestamp();
    let inspection = electron_page_inspection::inspect_with_cancellation(
        &input,
        browser,
        target,
        &mut session,
        &started_at,
        &capture_timestamp,
        cancellation,
    );
    let cleanup_errors = session.close();

    finish_inspection(&input, inspection, cleanup_errors, cancellation)
}

fn selected_target<'a>(
    targets: &'a [DiscoveredTarget],
    target_id: &str,
) -> Result<&'a DiscoveredTarget, Failure> {
    targets
        .iter()
        .find(|target| target.id == target_id)
        .ok_or_else(target_not_found)
}

fn ensure_target_is_inspectable(target: &DiscoveredTarget) -> Result<(), Failure> {
    if target.target_type != "page" {
        return Err(target_not_allowed());
    }

    if !target.has_validated_transport {
        return Err(transport_unavailable());
    }

    Ok(())
}

fn finish_inspection(
    input: &Value,
    inspection: Result<PageInspection, Failure>,
    cleanup_errors: Vec<String>,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    let inspection = match inspection {
        Ok(inspection) => inspection,
        Err(mut failure) => {
            if !cleanup_errors.is_empty() {
                failure.detail("cleanup_failures", Detail::Texts(cleanup_errors));
            }
            return Err(failure);
        }
    };

    if let Some(reason) = cancellation.reason() {
        return completed_inspection_cancellation(input, inspection, reason, cleanup_errors);
    }

    if !cleanup_errors.is_empty() {
        return completed_inspection_cleanup_failure(input, inspection, cleanup_errors);
    }

    electron::evidence::page_inspection(input, &inspection)
}

fn completed_inspection_cleanup_failure(
    input: &Value,
    mut inspection: PageInspection,
    cleanup_errors: Vec<String>,
) -> Result<Value, Failure> {
    inspection
        .limitations
        .push("CDP transport cleanup remains incomplete.".into());
    let failure = Failure::new(
        "resource_cleanup_failed",
        "resource_cleanup",
        "Electron page inspection completed, but its CDP session cleanup was incomplete.".into(),
        true,
        "Retry after confirming the selected Electron endpoint is responsive.".into(),
        BTreeMap::from([
            (
                "operation",
                Detail::Text(electron_page_inspection::OPERATION.into()),
            ),
            ("cleanup_failures", Detail::Texts(cleanup_errors)),
        ]),
    );
    Err(retain_completed_observation(failure, input, &inspection))
}

fn completed_inspection_cancellation(
    input: &Value,
    mut inspection: PageInspection,
    reason: &str,
    cleanup_errors: Vec<String>,
) -> Result<Value, Failure> {
    let cleanup_incomplete = !cleanup_errors.is_empty();
    let cleanup_limitation = if cleanup_incomplete {
        "CDP transport cleanup remains incomplete."
    } else {
        "REA closed its CDP transport; this does not imply target shutdown."
    };
    inspection.limitations.push(cleanup_limitation.into());
    let mut details = BTreeMap::from([(
        "operation",
        Detail::Text(electron_page_inspection::OPERATION.into()),
    )]);
    if cleanup_incomplete {
        details.insert("cleanup_failures", Detail::Texts(cleanup_errors));
    }
    let failure = Failure::new(
        "cancelled",
        "cancelled",
        format!("Electron page inspection was cancelled after capture completed: {reason}"),
        false,
        "Retry the passive page inspection if it is still needed.".into(),
        details,
    );
    Err(retain_completed_observation(failure, input, &inspection))
}

fn retain_completed_observation(
    mut failure: Failure,
    input: &Value,
    inspection: &PageInspection,
) -> Failure {
    match electron::evidence::page_inspection(input, inspection) {
        Ok(evidence) => {
            if let Err(error) = failure.retain(&evidence) {
                failure.detail(
                    "partial_observation_failure",
                    Detail::Text(error.to_string()),
                );
            }
        }
        Err(error) => {
            attach_retention_failure(&mut failure, error);
        }
    }

    failure
}

fn attach_retention_failure(primary: &mut Failure, retention_failure: Failure) {
    match serde_json::value::to_raw_value(&retention_failure) {
        Ok(details) => primary.detail("partial_observation_failure", Detail::Raw(details)),
        Err(error) => primary.detail(
            "partial_observation_failure",
            Detail::Text(error.to_string()),
        ),
    }
}

struct ElectronPageSession {
    transport: CdpWebSocketTransport,
    enabled_domains: Vec<&'static str>,
}

impl ElectronPageSession {
    fn new(transport: CdpWebSocketTransport) -> Self {
        Self {
            transport,
            enabled_domains: Vec::new(),
        }
    }

    fn close(&mut self) -> Vec<String> {
        let mut failures = Vec::new();

        for domain in self.enabled_domains.iter().rev().copied() {
            let method = format!("{domain}.disable");
            if let Err(error) = self.transport.request(&method, json!({})) {
                failures.push(format!("{method}: {error}"));
            }
        }

        if let Err(error) = self.transport.close_connection() {
            failures.push(format!("close CDP WebSocket: {error}"));
        }

        failures
    }

    fn request(
        &mut self,
        method: &str,
        params: Value,
        cancellation: &Cancellation,
    ) -> Result<Value, ElectronCdpFailure> {
        let result = self
            .transport
            .request_with_cancellation(method, params, cancellation)
            .map_err(map_transport_failure);

        if result.is_ok() {
            self.record_enabled_domain(method);
        }

        result
    }

    fn record_enabled_domain(&mut self, method: &str) {
        let domain = match method {
            "Page.enable" => Some("Page"),
            "Runtime.enable" => Some("Runtime"),
            "Debugger.enable" => Some("Debugger"),
            _ => None,
        };

        if let Some(domain) = domain
            && !self.enabled_domains.contains(&domain)
        {
            self.enabled_domains.push(domain);
        }
    }
}

impl electron_page_inspection::ElectronPageTransport for ElectronPageSession {
    fn request_page(
        &mut self,
        method: &str,
        params: Value,
        cancellation: &Cancellation,
    ) -> Result<Value, ElectronCdpFailure> {
        self.request(method, params, cancellation)
    }

    fn request_browser(
        &mut self,
        method: &str,
        params: Value,
        cancellation: &Cancellation,
    ) -> Result<Value, ElectronCdpFailure> {
        self.request(method, params, cancellation)
    }

    fn drain_events(&mut self) -> CdpEventBatch {
        self.transport.drain_events()
    }

    fn poll_events(
        &mut self,
        timeout: std::time::Duration,
        cancellation: &Cancellation,
    ) -> Result<(), ElectronCdpFailure> {
        self.transport
            .poll_events(timeout, cancellation)
            .map_err(map_transport_failure)
    }
}

fn map_transport_failure(error: CdpTransportError) -> ElectronCdpFailure {
    let kind = match &error {
        CdpTransportError::Cancelled(_) => ElectronCdpFailureKind::Cancelled,
        CdpTransportError::Timeout => ElectronCdpFailureKind::Timeout,
        CdpTransportError::Protocol { code, .. } => {
            ElectronCdpFailureKind::Protocol { code: *code }
        }
        _ => ElectronCdpFailureKind::Transport,
    };

    ElectronCdpFailure {
        kind,
        message: error.to_string(),
    }
}

fn bind_page_operation(mut failure: Failure) -> Failure {
    failure.detail(
        "operation",
        Detail::Text(electron_page_inspection::OPERATION.into()),
    );
    failure
}

fn ensure_active(cancellation: &Cancellation) -> Result<(), Failure> {
    let Some(reason) = cancellation.reason() else {
        return Ok(());
    };

    Err(Failure::new(
        "cancelled",
        "cancelled",
        format!("Electron page inspection was cancelled: {reason}"),
        false,
        "Retry the passive page inspection if it is still needed.".into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(electron_page_inspection::OPERATION.into()),
        )]),
    ))
}

fn connect_failure(error: CdpTransportError) -> Failure {
    let (code, category, message, retryable) = match error {
        CdpTransportError::Cancelled(reason) => (
            "cancelled",
            "cancelled",
            format!("Electron page inspection was cancelled: {reason}"),
            false,
        ),
        CdpTransportError::Timeout => (
            "timeout",
            "timeout",
            "Connecting to the selected Electron page exceeded its response deadline.".into(),
            true,
        ),
        other => (
            "provider_unavailable",
            "provider_unavailable",
            format!("Unable to connect to the selected Electron page: {other}"),
            true,
        ),
    };

    Failure::new(
        code,
        category,
        message,
        retryable,
        "Check that the selected local Electron endpoint is available, then retry.".into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(electron_page_inspection::OPERATION.into()),
        )]),
    )
}

fn invalid_endpoint(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a local page target and a loopback Electron CDP endpoint.".into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(electron_page_inspection::OPERATION.into()),
        )]),
    )
}

fn target_not_found() -> Failure {
    Failure::new(
        "target_not_found",
        "target_not_found",
        "The selected Electron target was not present in the latest endpoint discovery.".into(),
        false,
        "List Electron targets again and select an available target_id.".into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(electron_page_inspection::OPERATION.into()),
        )]),
    )
}

fn target_not_allowed() -> Failure {
    Failure::new(
        "target_not_allowed",
        "target_not_allowed",
        "The selected Electron target is not an authorized local file page.".into(),
        false,
        "Select a page target whose main document is a local file or regular ASAR member.".into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(electron_page_inspection::OPERATION.into()),
        )]),
    )
}

fn transport_unavailable() -> Failure {
    Failure::new(
        "provider_unavailable",
        "provider_unavailable",
        "The selected Electron target has no validated CDP transport.".into(),
        true,
        "List Electron targets again and retry while the selected endpoint is available.".into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(electron_page_inspection::OPERATION.into()),
        )]),
    )
}

fn cleanup_retention_failure(reason: String) -> Failure {
    Failure::new(
        "evidence_integrity_mismatch",
        "integrity_mismatch",
        "Electron page inspection completed, but its partial observation could not be retained."
            .into(),
        false,
        "Retry the passive page inspection if the selected target remains available.".into(),
        BTreeMap::from([
            (
                "operation",
                Detail::Text(electron_page_inspection::OPERATION.into()),
            ),
            ("reason", Detail::Text(reason)),
        ]),
    )
}
