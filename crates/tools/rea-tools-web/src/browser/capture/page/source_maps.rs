//! Bounded host fetches for captured source-map declarations.
//!
//! The browser owns the declaration and the application owns source-map
//! interpretation. This module only performs the policy-checked transport and
//! retains response data only within the caller's explicit byte budget.
//! Approved redirects are followed one hop at a time so
//! each resolved URL is checked against the caller's exact origin allow-list.

use super::scripts::SourceMapRequest;
use rea_core::cancellation::Cancellation;
use std::collections::BTreeSet;
use std::io::Read;
use std::time::Duration;
use url::Url;

const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct FetchedSourceMap {
    pub(super) script_key: String,
    pub(super) declared_url: String,
    pub(super) effective_url: String,
    pub(super) bytes: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct SourceMapFetchFailure {
    pub(super) script_key: String,
    pub(super) declared_url: String,
    pub(super) reason: String,
    pub(super) status: &'static str,
}

pub(super) fn fetch(
    requests: &[SourceMapRequest],
    allowed_origins: &BTreeSet<String>,
    cancellation: &Cancellation,
) -> (Vec<FetchedSourceMap>, Vec<SourceMapFetchFailure>) {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(FETCH_TIMEOUT))
        .max_redirects(0)
        .build()
        .new_agent();
    let mut included = Vec::new();
    let mut failures = Vec::new();

    for request in requests {
        if cancellation.reason().is_some() {
            failures.push(failure(request, "cancelled", "fetch_failed"));
            break;
        }
        let Some(url) = checked_url(&request.fetch_url, allowed_origins) else {
            failures.push(failure(
                request,
                "source-map URL was outside the allowed origins or used an unsupported scheme",
                "policy_filtered",
            ));
            continue;
        };
        match fetch_one(&agent, request, url, allowed_origins) {
            Ok(map) => included.push(map),
            Err(reason) => {
                let status = if reason.contains("approved exact origin") {
                    "policy_filtered"
                } else {
                    "fetch_failed"
                };
                failures.push(failure(request, &reason, status));
            }
        }
    }

    (included, failures)
}

fn checked_url(value: &str, allowed_origins: &BTreeSet<String>) -> Option<Url> {
    let url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.username() != "" || url.password().is_some()
    {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    allowed_origins.contains(&origin).then_some(url)
}

fn fetch_one(
    agent: &ureq::Agent,
    request: &SourceMapRequest,
    url: Url,
    allowed_origins: &BTreeSet<String>,
) -> Result<FetchedSourceMap, String> {
    let mut current = url;
    let mut visited = BTreeSet::new();

    loop {
        let current_text = current.as_str().to_owned();
        if !visited.insert(current_text.clone()) {
            return Err("source-map redirect loop detected".to_owned());
        }

        let mut response = agent
            .get(&current_text)
            .header(
                "Accept",
                "application/json, application/source-map+json;q=0.9",
            )
            .config()
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|error| format!("source-map request failed: {error}"))?;

        let status = response.status();
        if matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
            let Some(location) = response.headers().get("location") else {
                return Err(format!("source-map request returned HTTP {status}"));
            };
            let location = location
                .to_str()
                .map_err(|error| format!("source-map redirect location was invalid: {error}"))?;
            let next = current
                .join(location)
                .map_err(|error| format!("source-map redirect location was invalid: {error}"))?;
            if checked_url(next.as_str(), allowed_origins).is_none() {
                return Err("source-map redirect left the approved exact origin".to_owned());
            }
            current = next;
            continue;
        }

        if !status.is_success() {
            return Err(format!("source-map request returned HTTP {status}"));
        }
        if response
            .body()
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES)
        {
            return Err("source-map response exceeded the 64 MiB limit".to_owned());
        }

        let mut bytes = Vec::new();
        response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .reader()
            .read_to_end(&mut bytes)
            .map_err(|error| format!("source-map response could not be read: {error}"))?;
        return Ok(FetchedSourceMap {
            script_key: request.script_key.clone(),
            declared_url: request.declared_url.clone(),
            effective_url: current_text,
            bytes,
        });
    }
}

fn failure(
    request: &SourceMapRequest,
    reason: &str,
    status: &'static str,
) -> SourceMapFetchFailure {
    SourceMapFetchFailure {
        script_key: request.script_key.clone(),
        declared_url: request.declared_url.clone(),
        reason: reason.to_owned(),
        status,
    }
}
