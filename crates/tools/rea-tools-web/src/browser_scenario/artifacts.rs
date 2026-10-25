//! Selected step artifacts captured over CDP.
//!
//! Compatibility owner: `src/browser/PlaywrightScenarioArtifacts.ts` and the
//! Playwright 1.58.2 behaviors it relies on: viewport screenshots with
//! hidden carets and finished/cancelled animations (`screenshotter.js`,
//! `crPage.takeScreenshot`), `Frame.content()`, `locator('html')
//! .ariaSnapshot()`, main-world `page.evaluate` for history and storage, and
//! `context.cookies(url)` filtering (`network.filterCookies`).
use super::driver::{Driver, Scope};
use super::secrets::{Secrets, sha256_hex};
use base64::Engine;
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(crate) const SNAPSHOT_KINDS: [&str; 6] = [
    "screenshot",
    "dom",
    "accessibility",
    "url",
    "history",
    "storage",
];

fn missing(reason: &str) -> Value {
    json!({ "state": "missing", "reason": reason })
}

fn text_artifact(text: String) -> Value {
    json!({
        "state": "captured",
        "value": { "sha256": sha256_hex(text.as_bytes()), "bytes": text.len(), "text": text },
    })
}

/// Artifacts for a step that was not executed or was cancelled.
pub(crate) fn unavailable(requested: &BTreeSet<String>, reason: &str) -> Value {
    let mut artifacts = serde_json::Map::new();
    for kind in SNAPSHOT_KINDS {
        artifacts.insert(
            kind.to_owned(),
            if requested.contains(kind) {
                missing(reason)
            } else {
                json!({ "state": "not_requested" })
            },
        );
    }
    Value::Object(artifacts)
}

fn screenshot(driver: &mut Driver, viewport: Option<(u64, u64)>, scope: &Scope) -> Option<Value> {
    let (width, height) = match viewport {
        Some(size) => size,
        None => {
            let size = driver
                .evaluate_utility("__reaScenario.viewport()", true, false, scope)
                .ok()?;
            let size = size.get("value")?;
            (size.get("width")?.as_u64()?, size.get("height")?.as_u64()?)
        }
    };
    driver
        .evaluate_utility("__reaScenario.prepareScreenshot()", true, false, scope)
        .ok()?;
    let _ = driver.evaluate_utility("document.fonts.ready.then(() => true)", true, true, scope);
    let captured = (|| {
        let metrics = driver
            .main_call("Page.getLayoutMetrics", json!({}), scope)
            .ok()?;
        let viewport = metrics.get("visualViewport")?;
        let scale = viewport.get("scale").and_then(Value::as_f64).unwrap_or(1.0);
        let clip = json!({
            "x": viewport.get("pageX").and_then(Value::as_f64).unwrap_or(0.0),
            "y": viewport.get("pageY").and_then(Value::as_f64).unwrap_or(0.0),
            "width": (width as f64 / scale + 1e-3).floor(),
            "height": (height as f64 / scale + 1e-3).floor(),
            "scale": scale,
        });
        let result = driver
            .main_call(
                "Page.captureScreenshot",
                json!({ "format": "png", "clip": clip, "captureBeyondViewport": false }),
                scope,
            )
            .ok()?;
        base64::engine::general_purpose::STANDARD
            .decode(result.get("data")?.as_str()?)
            .ok()
    })();
    let _ = driver.evaluate_utility("__reaScenario.cleanupScreenshot()", true, false, scope);
    let bytes = captured?;
    Some(json!({
        "state": "captured",
        "value": {
            "sha256": sha256_hex(&bytes),
            "bytes": bytes.len(),
            "media_type": "image/png",
            "data_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
        },
    }))
}

fn utility_text(driver: &mut Driver, expression: &str, scope: &Scope) -> Option<String> {
    let result = driver
        .evaluate_utility(expression, true, false, scope)
        .ok()?;
    result.get("value")?.as_str().map(str::to_owned)
}

fn navigation_type(value: &str) -> &'static str {
    match value {
        "navigate" => "navigate",
        "reload" => "reload",
        "back_forward" => "back_forward",
        "prerender" => "prerender",
        _ => "unknown",
    }
}

const HISTORY: &str = r#"(() => ({
        length: window.history.length,
        navigation_entries: performance.getEntriesByType("navigation").map(
          entry => ({
            type: typeof entry.type === "string" ? entry.type : "unknown",
            name: entry.name
          })
        )
      }))()"#;

const STORAGE: &str = r#"(() => ({
        local_storage: Object.entries(window.localStorage),
        session_storage: Object.entries(window.sessionStorage)
      }))()"#;

fn history(driver: &mut Driver, secrets: &Secrets, scope: &Scope) -> Option<Value> {
    let raw = driver.evaluate_main(HISTORY, scope).ok()?;
    let length = raw.get("length")?.as_u64()?;
    let entries = raw.get("navigation_entries")?.as_array()?;
    let mut navigation = Vec::new();
    for entry in entries {
        let kind = entry.get("type")?.as_str()?;
        let name = entry.get("name")?.as_str()?;
        navigation
            .push(json!({ "type": navigation_type(kind), "name": secrets.sanitize_url(name) }));
    }
    let current = driver.world.current_url();
    Some(json!({
        "state": "captured",
        "value": { "length": length, "current_url": secrets.sanitize_url(&current), "navigation_entries": navigation },
    }))
}

/// `network.filterCookies` for one page URL.
fn cookie_matches(cookie: &Value, url: &url::Url) -> bool {
    let mut domain = cookie
        .get("domain")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if !domain.starts_with('.') {
        domain = format!(".{domain}");
    }
    let hostname = url.host_str().unwrap_or_default();
    if !format!(".{hostname}").ends_with(&domain) {
        return false;
    }
    if !url.path().starts_with(
        cookie
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    ) {
        return false;
    }
    let local = hostname == "localhost" || hostname.ends_with(".localhost");
    !(url.scheme() != "https"
        && !local
        && cookie
            .get("secure")
            .and_then(Value::as_bool)
            .unwrap_or(false))
}

fn pairs(value: Option<&Value>) -> Option<Vec<(String, String)>> {
    value?
        .as_array()?
        .iter()
        .map(|pair| {
            let pair = pair.as_array().filter(|items| items.len() == 2)?;
            Some((pair[0].as_str()?.to_owned(), pair[1].as_str()?.to_owned()))
        })
        .collect()
}

fn storage(
    driver: &mut Driver,
    secrets: &Secrets,
    browser_context: Option<&str>,
    scope: &Scope,
) -> Option<Value> {
    let page = url::Url::parse(&driver.world.current_url()).ok()?;
    let cookies = if matches!(page.scheme(), "http" | "https") {
        let mut params = json!({});
        if let Some(context) = browser_context {
            params["browserContextId"] = json!(context);
        }
        let result = driver
            .call(None, "Storage.getCookies", params, scope)
            .ok()?;
        result
            .get("cookies")?
            .as_array()?
            .iter()
            .filter(|cookie| cookie_matches(cookie, &page))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let raw = driver.evaluate_main(STORAGE, scope).ok()?;
    let local = pairs(raw.get("local_storage"))?;
    let session = pairs(raw.get("session_storage"))?;
    let entry = |name: &str, value: &str| {
        let mut item = serde_json::Map::new();
        item.insert("name".into(), json!(secrets.redact(name)));
        if let Value::Object(fingerprint) = secrets.fingerprint(value) {
            item.extend(fingerprint);
        }
        Value::Object(item)
    };
    let cookies: Vec<Value> = cookies
        .iter()
        .map(|cookie| {
            let text = |key: &str| {
                cookie
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let mut item = serde_json::Map::new();
            item.insert("name".into(), json!(secrets.redact(&text("name"))));
            item.insert("domain".into(), json!(secrets.redact(&text("domain"))));
            item.insert("path".into(), json!(secrets.redact(&text("path"))));
            item.insert(
                "secure".into(),
                json!(
                    cookie
                        .get("secure")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                ),
            );
            item.insert(
                "http_only".into(),
                json!(
                    cookie
                        .get("httpOnly")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                ),
            );
            item.insert(
                "same_site".into(),
                json!(
                    cookie
                        .get("sameSite")
                        .and_then(Value::as_str)
                        .unwrap_or("Lax")
                ),
            );
            if let Value::Object(fingerprint) = secrets.fingerprint(&text("value")) {
                item.extend(fingerprint);
            }
            Value::Object(item)
        })
        .collect();
    Some(json!({
        "state": "captured",
        "value": {
            "cookies": cookies,
            "local_storage": local.iter().map(|(name, value)| entry(name, value)).collect::<Vec<_>>(),
            "session_storage": session.iter().map(|(name, value)| entry(name, value)).collect::<Vec<_>>(),
        },
    }))
}

/// `capturePlaywrightStepArtifacts`.
pub(crate) fn capture(
    driver: &mut Driver,
    secrets: &Secrets,
    requested: &BTreeSet<String>,
    viewport: Option<(u64, u64)>,
    browser_context: Option<&str>,
    scope: &Scope,
) -> Value {
    let wants = |kind: &str| requested.contains(kind);
    let not_requested = || json!({ "state": "not_requested" });
    let screenshot_value = if wants("screenshot") {
        screenshot(driver, viewport, scope).unwrap_or_else(|| missing("screenshot capture failed"))
    } else {
        not_requested()
    };
    let dom = if wants("dom") {
        utility_text(driver, "__reaScenario.content()", scope)
            .map(|text| text_artifact(secrets.redact(&text)))
            .unwrap_or_else(|| missing("DOM capture failed"))
    } else {
        not_requested()
    };
    let accessibility = if wants("accessibility") {
        utility_text(
            driver,
            "__reaScenario.ariaSnapshot(document.documentElement)",
            scope,
        )
        .map(|text| text_artifact(secrets.redact(&text)))
        .unwrap_or_else(|| missing("accessibility capture failed"))
    } else {
        not_requested()
    };
    let url = if wants("url") {
        json!({ "state": "captured", "value": secrets.sanitize_url(&driver.world.current_url()) })
    } else {
        not_requested()
    };
    let history_value = if wants("history") {
        history(driver, secrets, scope).unwrap_or_else(|| missing("history capture failed"))
    } else {
        not_requested()
    };
    let storage_value = if wants("storage") {
        storage(driver, secrets, browser_context, scope)
            .unwrap_or_else(|| missing("storage capture failed"))
    } else {
        not_requested()
    };
    driver.release_objects(scope);
    json!({
        "screenshot": screenshot_value,
        "dom": dom,
        "accessibility": accessibility,
        "url": url,
        "history": history_value,
        "storage": storage_value,
    })
}
