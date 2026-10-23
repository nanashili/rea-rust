//! Correlated network phases and selected content for one scenario.
//!
//! Compatibility owners: `src/browser/network/PlaywrightScenarioNetwork.ts`
//! and `src/browser/network/PlaywrightNetworkContent.ts`. Request identity is
//! the producer request record (one per CDP request and redirect hop), never
//! URL or receipt adjacency. Content reads are queued here and executed by
//! the driver after the triggering event, like the TypeScript read queue.
use super::input::{Limits, NetworkSelection};
use super::recorder::{Admission, Recorder};
use super::secrets::{Secrets, sha256_hex};
use base64::Engine;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// One producer request (a redirect hop is a new request).
#[derive(Clone, Debug, Default)]
pub(crate) struct RequestRecord {
    pub session: String,
    pub request_id: String,
    pub method: String,
    pub url: String,
    pub resource_type: String,
    /// Provisional request headers in producer order.
    pub headers: Vec<(String, String)>,
    /// Raw `requestWillBeSentExtraInfo` headers, when observed.
    pub raw_headers: Option<Vec<(String, String)>>,
    pub post_data: Option<Vec<u8>>,
    pub redirected_from: Option<usize>,
    pub failure: Option<String>,
    pub response: Option<ResponseRecord>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ResponseRecord {
    pub url: String,
    pub status: u64,
    pub headers: Vec<(String, String)>,
    pub raw_headers: Option<Vec<(String, String)>>,
    /// The body can be read through `Network.getResponseBody`.
    pub readable: bool,
}

#[derive(Clone, Debug)]
struct Transaction {
    id: String,
    redirected_from: Option<String>,
    redirected_state: Option<&'static str>,
    response_sequence: Option<u64>,
    terminal: Option<&'static str>,
    response_scheduled: bool,
    request_observed: bool,
}

/// A queued content read, executed by the driver.
#[derive(Clone, Debug)]
pub(crate) struct ContentJob {
    pub request: usize,
    pub transaction_id: String,
    pub sequence: u64,
    pub phase: &'static str,
    /// A precomputed body state (`not_requested` or `unavailable`).
    pub body: Option<Value>,
}

impl ContentJob {
    /// Only a readable response body is fetched from the browser
    /// (`Network.getResponseBody`); request bytes and precomputed states are
    /// already local, as `postDataBuffer()` is in Playwright.
    pub(crate) fn needs_round_trip(&self, requests: &[RequestRecord]) -> bool {
        self.body.is_none()
            && self.phase == "response"
            && requests[self.request].response.as_ref().is_some_and(|response| response.readable)
    }
}

pub(crate) struct Network {
    pub selection: NetworkSelection,
    limits: Limits,
    transactions: BTreeMap<usize, Transaction>,
    omitted_requests: BTreeSet<usize>,
    omitted_phases: BTreeMap<usize, BTreeSet<String>>,
    total: u64,
    omitted_count: u64,
    first_omitted: u64,
    last_omitted: u64,
    pub jobs: Vec<ContentJob>,
    gaps: Vec<String>,
    accepting: bool,
}

fn credential(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(), "authorization" | "proxy-authorization" | "cookie" | "set-cookie")
}

impl Network {
    pub(crate) fn new(selection: NetworkSelection, limits: Limits) -> Self {
        Self {
            selection,
            limits,
            transactions: BTreeMap::new(),
            omitted_requests: BTreeSet::new(),
            omitted_phases: BTreeMap::new(),
            total: 0,
            omitted_count: 0,
            first_omitted: 0,
            last_omitted: 0,
            jobs: Vec::new(),
            gaps: Vec::new(),
            accepting: true,
        }
    }

    fn gap(&mut self, text: String) {
        if !self.gaps.contains(&text) {
            self.gaps.push(text);
        }
    }

    pub(crate) fn limitations(&self) -> Vec<String> {
        self.gaps.clone()
    }

    /// The next job whose producer data is available. Selected request
    /// header values wait for the raw headers Chromium reports with the
    /// response (or for the failure / capture end), like `headersArray()`.
    /// Take the first ready read; `local_only` skips reads that need a
    /// browser round trip (`ContentJob::needs_round_trip`).
    pub(crate) fn next_job(&mut self, requests: &[RequestRecord], local_only: bool) -> Option<ContentJob> {
        let ready = |job: &ContentJob| {
            let request = &requests[job.request];
            if local_only && job.needs_round_trip(requests) {
                return false;
            }
            job.phase != "request"
                || !self.selection.header_values
                || !self.accepting
                || request.response.is_some()
                || request.failure.is_some()
        };
        let position = self.jobs.iter().position(ready)?;
        Some(self.jobs.remove(position))
    }

    pub(crate) fn omitted_range(&self) -> Value {
        if self.omitted_count == 0 {
            return Value::Null;
        }
        json!({
            "first_transaction_id": format!("request-{}", self.first_omitted),
            "last_transaction_id": format!("request-{}", self.last_omitted),
            "count": self.omitted_count,
            "reason": "max-network-transactions",
        })
    }

    fn content_selected(&self) -> bool {
        self.selection.request_body || self.selection.header_values
    }

    fn transaction(&mut self, requests: &[RequestRecord], index: usize) -> Option<String> {
        if let Some(known) = self.transactions.get(&index) {
            return Some(known.id.clone());
        }
        if self.omitted_requests.contains(&index) {
            return None;
        }
        self.total += 1;
        let id = format!("request-{}", self.total);
        if self.transactions.len() as u64 >= self.limits.max_network_transactions {
            self.omitted_requests.insert(index);
            if self.omitted_count == 0 {
                self.first_omitted = self.total;
            }
            self.last_omitted = self.total;
            self.omitted_count += 1;
            let limit = self.limits.max_network_transactions;
            self.gap(format!("Network collection reached its {limit}-transaction resource budget; omitted transaction IDs are listed in events.omissions.network_transaction_range."));
            return None;
        }
        let predecessor = requests[index].redirected_from;
        let predecessor_id = predecessor.and_then(|item| self.transactions.get(&item)).map(|item| item.id.clone());
        let state = match (predecessor, &predecessor_id) {
            (None, _) => Some("root"),
            (Some(_), None) => Some("unknown"),
            (Some(_), Some(_)) => None,
        };
        self.transactions.insert(
            index,
            Transaction {
                id: id.clone(),
                redirected_from: predecessor_id,
                redirected_state: state,
                response_sequence: None,
                terminal: None,
                response_scheduled: false,
                request_observed: false,
            },
        );
        Some(id)
    }

    fn observe_omitted_phase(&mut self, index: usize, phase: &str) -> bool {
        self.omitted_phases.entry(index).or_default().insert(phase.to_owned())
    }

    fn omit_omitted_phase(&mut self, recorder: &mut Recorder, index: usize, kind: &str) {
        if !self.omitted_requests.contains(&index) || !self.observe_omitted_phase(index, kind) {
            return;
        }
        recorder.omit_event(kind, "max-network-transactions");
    }

    fn omit_omitted_content(&mut self, recorder: &mut Recorder, index: usize, phase: &str) {
        if !self.omitted_requests.contains(&index) || !self.observe_omitted_phase(index, &format!("network-content:{phase}")) {
            return;
        }
        recorder.omit_event("network-content", "max-network-transactions");
    }

    fn metadata_strings(&self, request: &RequestRecord, extra: &[String], response: Option<&ResponseRecord>) -> Vec<String> {
        let mut strings = Vec::new();
        for (name, value) in &request.headers {
            strings.push(name.clone());
            if self.selection.header_values {
                strings.push(value.clone());
            }
        }
        strings.push(request.method.clone());
        strings.push(request.url.clone());
        strings.push(request.resource_type.clone());
        strings.extend(extra.iter().cloned());
        if let Some(response) = response {
            strings.push(response.url.clone());
            for (name, value) in &response.headers {
                strings.push(name.clone());
                if self.selection.header_values {
                    strings.push(value.clone());
                }
            }
        }
        strings
    }

    fn admit_metadata(
        &mut self,
        recorder: &mut Recorder,
        secrets: &Secrets,
        id: &str,
        kind: &str,
        request: &RequestRecord,
        extra: &[String],
        response: Option<&ResponseRecord>,
    ) -> bool {
        let strings = self.metadata_strings(request, extra, response);
        let views: Vec<&str> = strings.iter().map(String::as_str).collect();
        match recorder.admit_text(secrets, kind, &views, true) {
            Admission::Retained(_) => true,
            Admission::Omitted { reason } => {
                recorder.omit_network(id, kind, reason);
                self.gap(format!("Network {kind} metadata was omitted for {id} because {reason} was reached; network coverage is incomplete."));
                false
            }
        }
    }

    fn header_names(secrets: &Secrets, headers: &[(String, String)]) -> Value {
        // `Object.keys(headers())`: lowercased, last duplicate wins.
        let mut names: Vec<String> = Vec::new();
        for (name, _) in headers {
            let lower = name.to_ascii_lowercase();
            if !names.contains(&lower) {
                names.push(lower);
            }
        }
        let mut redacted: Vec<String> = names.iter().map(|name| secrets.redact(name)).collect();
        redacted.sort();
        json!(redacted)
    }

    fn metadata(&self, secrets: &Secrets, request: &RequestRecord, id: &str) -> Vec<(&'static str, Value)> {
        let transaction = self.transactions.values().find(|item| item.id == id).cloned();
        let mut fields: Vec<(&'static str, Value)> = vec![
            ("transaction_id", json!(id)),
            ("redirected_from_transaction_id", json!(transaction.as_ref().and_then(|item| item.redirected_from.clone()))),
        ];
        if let Some(state) = transaction.and_then(|item| item.redirected_state) {
            fields.push(("redirected_from_transaction_state", json!(state)));
        }
        fields.push(("method", json!(secrets.redact(&request.method))));
        fields.push(("url", secrets.sanitize_url(&request.url)));
        fields.push(("resource_type", json!(secrets.redact(&request.resource_type))));
        fields.push(("header_names", Self::header_names(secrets, &request.headers)));
        fields
    }

    fn with_tail(mut fields: Vec<(&'static str, Value)>, kind: &str, status: Value, failure: Value) -> Vec<(&'static str, Value)> {
        fields.push(("kind", json!(kind)));
        fields.push(("status", status));
        fields.push(("failure", failure));
        fields
    }

    pub(crate) fn request(&mut self, recorder: &mut Recorder, secrets: &Secrets, requests: &[RequestRecord], index: usize) {
        if !self.accepting {
            return;
        }
        let Some(id) = self.transaction(requests, index) else {
            self.omit_omitted_phase(recorder, index, "request");
            if self.content_selected() {
                self.omit_omitted_content(recorder, index, "request");
            }
            return;
        };
        if self.transactions.get(&index).is_some_and(|item| item.request_observed) {
            return;
        }
        let request = &requests[index];
        if !self.admit_metadata(recorder, secrets, &id, "request", request, &[], None) {
            return;
        }
        if let Some(item) = self.transactions.get_mut(&index) {
            item.request_observed = true;
        }
        let fields = Self::with_tail(self.metadata(secrets, request, &id), "request", Value::Null, Value::Null);
        match recorder.push("request", fields) {
            Admission::Omitted { reason } => recorder.omit_network(&id, "request", reason),
            Admission::Retained(sequence) => {
                if self.content_selected() {
                    let body = (!self.selection.request_body).then(|| json!({ "state": "not_requested" }));
                    self.jobs.push(ContentJob { request: index, transaction_id: id, sequence, phase: "request", body });
                }
            }
        }
    }

    pub(crate) fn response(&mut self, recorder: &mut Recorder, secrets: &Secrets, requests: &[RequestRecord], index: usize) {
        if !self.accepting {
            return;
        }
        let Some(id) = self.transaction(requests, index) else {
            self.omit_omitted_phase(recorder, index, "response");
            self.observe_omitted_phase(index, "response");
            return;
        };
        let request = &requests[index];
        let Some(response) = request.response.clone() else { return };
        if !self.admit_metadata(recorder, secrets, &id, "response", request, &[], Some(&response)) {
            return;
        }
        let mut fields = self.metadata(secrets, request, &id);
        for field in &mut fields {
            if field.0 == "url" {
                field.1 = secrets.sanitize_url(&response.url);
            }
            if field.0 == "header_names" {
                field.1 = Self::header_names(secrets, &response.headers);
            }
        }
        let fields = Self::with_tail(fields, "response", json!(response.status), Value::Null);
        match recorder.push("response", fields) {
            Admission::Omitted { reason } => recorder.omit_network(&id, "response", reason),
            Admission::Retained(sequence) => {
                if let Some(item) = self.transactions.get_mut(&index) {
                    item.response_sequence = Some(sequence);
                }
            }
        }
    }

    pub(crate) fn finished(&mut self, recorder: &mut Recorder, secrets: &Secrets, requests: &[RequestRecord], index: usize) {
        if !self.accepting {
            return;
        }
        let Some(id) = self.transaction(requests, index) else {
            self.omit_omitted_phase(recorder, index, "request-finished");
            let observed = self.omitted_phases.get(&index).is_some_and(|phases| phases.contains("response"));
            if observed && (self.selection.response_body || self.selection.header_values) {
                self.omit_omitted_content(recorder, index, "response");
            }
            return;
        };
        let request = &requests[index];
        if !self.admit_metadata(recorder, secrets, &id, "request-finished", request, &[], None) {
            return;
        }
        if let Some(item) = self.transactions.get_mut(&index) {
            item.terminal = Some("finished");
        }
        let fields = Self::with_tail(self.metadata(secrets, request, &id), "request-finished", Value::Null, Value::Null);
        match recorder.push("request-finished", fields) {
            Admission::Omitted { reason } => {
                recorder.omit_network(&id, "request-finished", reason);
                if let Some(item) = self.transactions.get_mut(&index) {
                    item.response_scheduled = true;
                }
            }
            Admission::Retained(_) => self.response_content(index, None),
        }
    }

    pub(crate) fn failed(&mut self, recorder: &mut Recorder, secrets: &Secrets, requests: &[RequestRecord], index: usize) {
        if !self.accepting {
            return;
        }
        let Some(id) = self.transaction(requests, index) else {
            self.omit_omitted_phase(recorder, index, "request-failed");
            return;
        };
        if let Some(item) = self.transactions.get_mut(&index) {
            item.terminal = Some("failed");
        }
        let request = &requests[index];
        let failure = request.failure.clone().filter(|text| !text.is_empty()).unwrap_or_else(|| "Unknown request failure".to_owned());
        if !self.admit_metadata(recorder, secrets, &id, "request-failed", request, std::slice::from_ref(&failure), None) {
            return;
        }
        let message = secrets.redact(&failure);
        let fields = Self::with_tail(self.metadata(secrets, request, &id), "request-failed", Value::Null, json!(message));
        match recorder.push("request-failed", fields) {
            Admission::Omitted { reason } => {
                recorder.omit_network(&id, "request-failed", reason);
                if let Some(item) = self.transactions.get_mut(&index) {
                    item.response_scheduled = true;
                }
            }
            Admission::Retained(_) => self.response_content(
                index,
                Some(json!({ "state": "unavailable", "reason": "request-failed", "message": message })),
            ),
        }
    }

    fn response_content(&mut self, index: usize, unavailable: Option<Value>) {
        let Some(transaction) = self.transactions.get_mut(&index) else { return };
        let Some(sequence) = transaction.response_sequence else { return };
        if transaction.response_scheduled || (!self.selection.response_body && !self.selection.header_values) {
            return;
        }
        transaction.response_scheduled = true;
        let body = if self.selection.response_body {
            unavailable
        } else {
            Some(json!({ "state": "not_requested" }))
        };
        let id = transaction.id.clone();
        self.jobs.push(ContentJob { request: index, transaction_id: id, sequence, phase: "response", body });
    }

    /// `finish()`: stop observing and mark unfinished transactions.
    pub(crate) fn finish(&mut self, recorder: &mut Recorder, secrets: &Secrets, requests: &[RequestRecord], cancelled: bool) {
        if !self.accepting {
            return;
        }
        self.accepting = false;
        let indexes: Vec<usize> = self.transactions.keys().copied().collect();
        for index in indexes {
            let Some(transaction) = self.transactions.get(&index).cloned() else { continue };
            if transaction.terminal.is_some() {
                continue;
            }
            let request = &requests[index];
            if !self.admit_metadata(recorder, secrets, &transaction.id, "request-unfinished", request, &[], None) {
                continue;
            }
            self.gap("Some network requests had not completed when capture ended; later activity is unknown.".to_owned());
            let mut fields = Self::with_tail(self.metadata(secrets, request, &transaction.id), "request-unfinished", Value::Null, Value::Null);
            fields.push(("reason", json!(if cancelled { "cancelled" } else { "capture-ended" })));
            match recorder.push("request-unfinished", fields) {
                Admission::Omitted { reason } => {
                    recorder.omit_network(&transaction.id, "request-unfinished", reason);
                    if let Some(item) = self.transactions.get_mut(&index) {
                        item.response_scheduled = true;
                    }
                }
                Admission::Retained(_) => self.response_content(
                    index,
                    Some(json!({
                        "state": "unavailable",
                        "reason": if cancelled { "cancelled" } else { "response-unfinished" },
                        "message": "The response had not finished at the capture cutoff; no body read or refetch was attempted.",
                    })),
                ),
            }
        }
    }

    /// Headers of one phase in producer order (`headersArray`).
    pub(crate) fn headers_value(&self, secrets: &Secrets, headers: &[(String, String)]) -> Value {
        let mut cost: u64 = 0;
        for (name, value) in headers {
            cost += secrets.redaction_cost_of(&format!("{name}{value}")) as u64 + 128;
            if cost > self.limits.max_network_header_allocation_bytes {
                return json!({
                    "state": "unavailable",
                    "message": format!("Headers exceed the {}-byte allocation budget.", self.limits.max_network_header_allocation_bytes),
                });
            }
        }
        let items: Vec<Value> = headers
            .iter()
            .map(|(name, value)| {
                let safe_name = secrets.redact(name);
                let is_credential = credential(name);
                let safe_value = (!is_credential).then(|| String::from_utf8_lossy(&secrets.redact_bytes(value.as_bytes())).into_owned());
                let redacted = is_credential || safe_name != *name || safe_value.as_deref() != Some(value.as_str());
                json!({ "name": safe_name, "value": safe_value, "redacted": redacted })
            })
            .collect();
        json!({ "state": "captured", "items": items })
    }

    /// `captureNetworkBody` after the bytes were read (or not exposed).
    pub(crate) fn body_value(
        &self,
        recorder: &mut Recorder,
        secrets: &Secrets,
        job: &ContentJob,
        headers: &Value,
        observed: Result<Option<Vec<u8>>, String>,
        content_type: Option<&str>,
    ) -> Result<Value, &'static str> {
        let observed = match observed {
            Err(message) => {
                let message = if message.is_empty() { "Network read failed".to_owned() } else { message };
                let message = if secrets.redaction_cost_of(&message) as u64 <= self.limits.max_network_metadata_allocation_bytes {
                    secrets.redact(&message)
                } else {
                    "Network read failed; diagnostic exceeds the allocation budget.".to_owned()
                };
                return Ok(json!({ "state": "unavailable", "reason": "body-read-failed", "message": message }));
            }
            Ok(None) => return Ok(json!({ "state": "not_exposed" })),
            Ok(Some(bytes)) => bytes,
        };
        let length = observed.len() as u64;
        if length > self.limits.max_network_body_bytes {
            return Ok(json!({
                "state": "unavailable",
                "reason": "body-size-limit",
                "message": format!("Playwright materialized the body before its {}-byte retained-body budget was checked.", self.limits.max_network_body_bytes),
                "limit_bytes": self.limits.max_network_body_bytes,
                "observed_bytes": length,
            }));
        }
        let body_cost = secrets.redaction_allocation_cost(observed.len()) as i64;
        let base64_cost = (observed.len() as i64 + 2) / 3 * 4 * 8 + 2;
        let allocation = body_cost.max(base64_cost);
        if allocation as u64 > self.limits.max_network_body_allocation_bytes {
            return Ok(json!({
                "state": "unavailable",
                "reason": "body-allocation-limit",
                "message": "Body redaction exceeds the selected network body allocation budget.",
                "limit_allocation_bytes": self.limits.max_network_body_allocation_bytes,
                "observed_allocation_bytes": allocation,
            }));
        }
        if let Some(content_type) = content_type {
            let cost = secrets.redaction_cost_of(content_type) as u64;
            if cost > self.limits.max_network_header_allocation_bytes {
                return Ok(json!({
                    "state": "unavailable",
                    "reason": "body-allocation-limit",
                    "message": "Content type exceeds the selected network header allocation budget.",
                    "limit_allocation_bytes": self.limits.max_network_header_allocation_bytes,
                    "observed_allocation_bytes": cost,
                }));
            }
        }
        if let Admission::Omitted { reason } = recorder.admit_content_body(
            secrets,
            &job.transaction_id,
            job.sequence,
            job.phase,
            headers,
            length,
            allocation,
            content_type,
        ) {
            return Err(reason);
        }
        let retained = secrets.redact_bytes(&observed);
        let media_type = content_type.map(|value| String::from_utf8_lossy(&secrets.redact_bytes(value.as_bytes())).into_owned());
        Ok(json!({
            "state": "captured",
            // Contract label kept from the TS owner: these are the decoded
            // bytes of `Network.getResponseBody`, which Playwright's
            // `Response.body()` also returns for Chromium (without its
            // refetch fallback, which this owner never performs).
            "representation": if job.phase == "request" { "browser-exposed-request-bytes" } else { "playwright-response-body-bytes" },
            "encoding": "base64",
            "content": base64::engine::general_purpose::STANDARD.encode(&retained),
            "bytes": retained.len(),
            "sha256": sha256_hex(&retained),
            "media_type": media_type,
            "redacted": retained != observed,
        }))
    }

    /// Emit one collected content record.
    pub(crate) fn emit_content(&mut self, recorder: &mut Recorder, job: &ContentJob, headers: Value, body: Result<Value, &'static str>) {
        let body = match body {
            Err(reason) => {
                recorder.omit_network(&job.transaction_id, "network-content", reason);
                return;
            }
            Ok(body) => body,
        };
        let header_unavailable = headers.get("state").and_then(Value::as_str) == Some("unavailable");
        let body_state = body.get("state").and_then(Value::as_str).unwrap_or_default();
        if header_unavailable || body_state == "unavailable" || body_state == "not_exposed" {
            self.gap("Some selected network content was unavailable; per-transaction content states retain the reason.".to_owned());
        }
        let fields: Vec<(&str, Value)> = vec![
            ("kind", json!("network-content")),
            ("transaction_id", json!(job.transaction_id)),
            ("source_event_sequence", json!(job.sequence)),
            ("phase", json!(job.phase)),
            ("headers", headers),
            ("body", body),
        ];
        if let Admission::Omitted { reason } = recorder.push("network-content", fields) {
            recorder.omit_network(&job.transaction_id, "network-content", reason);
        }
    }
}

/// `headersObjectToArray(headers, separator)`.
pub(crate) fn headers_from_object(value: Option<&Value>, split_lines: bool) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if let Some(Value::Object(map)) = value {
        for (name, value) in map {
            let text = match value {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            if split_lines {
                for line in text.split('\n') {
                    headers.push((name.clone(), line.to_owned()));
                }
            } else {
                headers.push((name.clone(), text));
            }
        }
    }
    headers
}

pub(crate) fn header_lookup<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .rev()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[cfg(test)]
mod tests {
    use super::{ContentJob, RequestRecord, ResponseRecord};
    use serde_json::json;

    fn job(phase: &'static str, body: Option<serde_json::Value>) -> ContentJob {
        ContentJob { request: 0, transaction_id: "request-1".into(), sequence: 1, phase, body }
    }

    fn requests(readable: bool) -> Vec<RequestRecord> {
        vec![RequestRecord { response: Some(ResponseRecord { readable, ..ResponseRecord::default() }), ..RequestRecord::default() }]
    }

    #[test]
    fn only_readable_response_bodies_need_a_browser_round_trip() {
        assert!(job("response", None).needs_round_trip(&requests(true)));
        // Request bytes are local, as Playwright's postDataBuffer() is.
        assert!(!job("request", None).needs_round_trip(&requests(true)));
        // Redirect responses are not readable; their state is local.
        assert!(!job("response", None).needs_round_trip(&requests(false)));
        // Precomputed states (`not_requested`, `unavailable`) are local.
        assert!(!job("response", Some(json!({ "state": "not_requested" }))).needs_round_trip(&requests(true)));
    }
}
