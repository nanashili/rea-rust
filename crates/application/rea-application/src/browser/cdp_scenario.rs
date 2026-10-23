//! Read-only CDP scenario execution for an explicitly connected page target.
//!
//! This adapter translates the provider-neutral scenario actions into bounded
//! CDP commands. It does not discover targets, launch browsers, or attach to
//! a different page: callers must construct the transport for the selected
//! endpoint and target before handing it to this module.

use crate::browser::scenario_actions::{ActionObservation, ScenarioActionPort};
use crate::browser::scenario_events::EventLedger;
use rea_host::cdp_transport::{CdpEventBatch, CdpTransportError, CdpWebSocketTransport};
use serde_json::{Value, json};
use std::thread;
use std::time::{Duration, Instant};

const MAX_SELECTOR_CHARS: usize = 4 * 1024;
const MAX_ACTION_VALUE_CHARS: usize = 4 * 1024;
const MAX_KEY_CHARS: usize = 256;
const MAX_CLICK_COUNT: u64 = 8;
const DEFAULT_ACTION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ACTION_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Minimal command surface used by the scenario adapter and its mock tests.
pub trait CdpCommandPort {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String>;

    fn drain_events(&mut self) -> CdpEventBatch {
        CdpEventBatch::default()
    }
}

impl CdpCommandPort for CdpWebSocketTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        CdpWebSocketTransport::request(self, method, params).map_err(|error| error.to_string())
    }

    fn drain_events(&mut self) -> CdpEventBatch {
        CdpWebSocketTransport::drain_events(self)
    }
}

/// A connected, caller-selected page target with no browser ownership.
pub struct ConnectedCdpScenarioPort<T> {
    transport: T,
    target_id: String,
    start_url: String,
}

impl ConnectedCdpScenarioPort<CdpWebSocketTransport> {
    /// Connect to a WebSocket endpoint whose path and target identity were
    /// selected by the caller. Launch mode is intentionally unsupported here.
    pub fn connect(
        endpoint: &str,
        target_id: &str,
        start_url: &str,
    ) -> Result<Self, CdpTransportError> {
        let transport = CdpWebSocketTransport::connect_for_target(endpoint, target_id)?;
        Ok(Self::from_transport(transport, target_id, start_url))
    }
}

impl<T: CdpCommandPort> ConnectedCdpScenarioPort<T> {
    /// Bind an already-created transport to the exact connect selection in a
    /// scenario request. Launch requests fail closed because this adapter has
    /// no process ownership or launch authority.
    pub fn from_input(input: &Value, transport: T) -> Result<Self, String> {
        let browser = input
            .get("browser")
            .and_then(Value::as_object)
            .ok_or_else(|| "browser scenario input must contain browser".to_owned())?;
        if browser.get("mode").and_then(Value::as_str) != Some("connect") {
            return Err("native CDP scenario adapter supports connect mode only".into());
        }
        let target_id = browser
            .get("target_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "connect mode requires browser.target_id".to_owned())?;
        let start_url = input
            .pointer("/start_url/url")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "browser scenario input must contain start_url.url".to_owned())?;
        Ok(Self::from_transport(transport, target_id, start_url))
    }

    pub fn from_transport(transport: T, target_id: &str, start_url: &str) -> Self {
        Self {
            transport,
            target_id: target_id.to_owned(),
            start_url: start_url.to_owned(),
        }
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Drain transport events into the shared scenario event ledger at the
    /// current step boundary.
    pub fn drain_events(&mut self, step_index: u64, ledger: &mut EventLedger) -> Result<(), String>
    where
        T: CdpCommandPort,
    {
        ledger
            .admit_cdp_batch(step_index, self.transport.drain_events())
            .map_err(|error| {
                serde_json::to_string(&error)
                    .unwrap_or_else(|_| format!("{} failure", error.code()))
            })
    }

    fn command(&mut self, method: &str, params: Value) -> Result<Value, String>
    where
        T: CdpCommandPort,
    {
        self.transport.request(method, params)
    }

    fn observe(&mut self, step_index: u64) -> Result<ActionObservation, String>
    where
        T: CdpCommandPort,
    {
        let result = self.command(
            "Runtime.evaluate",
            json!({
                "expression": "({url: location.href, title: document.title})",
                "returnByValue": true,
            }),
        )?;
        Ok(ActionObservation {
            observation: json!({
                "target_id": self.target_id,
                "step_index": step_index,
                "url": result.get("result").cloned().unwrap_or(result),
            }),
            event_sequence_start: step_index.saturating_add(1),
            event_sequence_end: step_index.saturating_add(1),
        })
    }
    fn action_deadline(&self, action: &Value) -> Instant {
        let timeout = action
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_ACTION_TIMEOUT)
            .min(MAX_ACTION_TIMEOUT);
        Instant::now() + timeout
    }

    fn wait_for_document_state(&mut self, action: &Value) -> Result<(), String> {
        let wait_until = action
            .get("wait_until")
            .and_then(Value::as_str)
            .unwrap_or("load");
        if wait_until == "commit" {
            return Ok(());
        }

        let deadline = self.action_deadline(action);
        let expected = if wait_until == "domcontentloaded" {
            "interactive"
        } else {
            "complete"
        };
        self.poll_until(deadline, |port| {
            let result = port.command(
                "Runtime.evaluate",
                json!({"expression": "document.readyState", "returnByValue": true}),
            )?;
            Ok(result.pointer("/result/value").and_then(Value::as_str) == Some(expected))
        })
    }

    fn wait_for(&mut self, action: &Value) -> Result<(), String> {
        let locator = action
            .get("locator")
            .ok_or_else(|| "wait_for action must include locator".to_owned())?;
        let selector = locator_selector(locator)?;
        let selector_json = serde_json::to_string(&selector).map_err(|error| error.to_string())?;
        let state = action
            .get("state")
            .and_then(Value::as_str)
            .ok_or_else(|| "wait_for action must include state".to_owned())?;
        let expression = match state {
            "attached" => format!("Boolean(document.querySelector({selector_json}))"),
            "detached" => format!("!document.querySelector({selector_json})"),
            "visible" => format!(
                "(() => {{ const e=document.querySelector({selector_json}); if (!e) return false; const s=getComputedStyle(e); const r=e.getBoundingClientRect(); return s.visibility !== 'hidden' && s.display !== 'none' && r.width > 0 && r.height > 0; }})()"
            ),
            "hidden" => format!(
                "(() => {{ const e=document.querySelector({selector_json}); if (!e) return true; const s=getComputedStyle(e); const r=e.getBoundingClientRect(); return s.visibility === 'hidden' || s.display === 'none' || r.width === 0 || r.height === 0; }})()"
            ),
            _ => return Err(format!("unsupported wait_for state: {state}")),
        };
        self.poll_until(self.action_deadline(action), |port| {
            let result = port.command(
                "Runtime.evaluate",
                json!({"expression": expression, "returnByValue": true}),
            )?;
            Ok(result.pointer("/result/value").and_then(Value::as_bool) == Some(true))
        })
    }

    fn wait_for_timeout(&mut self, action: &Value) -> Result<(), String> {
        let duration = action
            .get("duration_ms")
            .and_then(Value::as_u64)
            .ok_or_else(|| "wait_for_timeout action must include duration_ms".to_owned())?;
        let duration = Duration::from_millis(duration).min(MAX_ACTION_TIMEOUT);
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        }
        Ok(())
    }

    fn press(&mut self, action: &Value) -> Result<(), String> {
        let locator = action
            .get("locator")
            .ok_or_else(|| "press action must include locator".to_owned())?;
        let selector = locator_selector(locator)?;
        let selector_json = serde_json::to_string(&selector).map_err(|error| error.to_string())?;
        let key = bounded_action_string(action.get("key"), "press.key", MAX_KEY_CHARS)?;
        let focus = self.command(
            "Runtime.evaluate",
            json!({"expression": format!("(() => {{ const e=document.querySelector({selector_json}); if (!e) return false; e.focus(); return true; }})()"), "returnByValue": true}),
        )?;
        if focus.pointer("/result/value").and_then(Value::as_bool) != Some(true) {
            return Err("press locator did not resolve to an element".to_owned());
        }
        let text = if key.chars().count() == 1 {
            key.as_str()
        } else {
            ""
        };
        self.command(
            "Input.dispatchKeyEvent",
            json!({"type": "keyDown", "key": key}),
        )?;
        if !text.is_empty() {
            self.command(
                "Input.dispatchKeyEvent",
                json!({"type": "char", "text": text}),
            )?;
        }
        self.command(
            "Input.dispatchKeyEvent",
            json!({"type": "keyUp", "key": key}),
        )?;
        Ok(())
    }

    fn poll_until<F>(&mut self, deadline: Instant, mut check: F) -> Result<(), String>
    where
        F: FnMut(&mut Self) -> Result<bool, String>,
    {
        loop {
            if check(self)? {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("browser scenario action timed out".to_owned());
            }
            thread::sleep(POLL_INTERVAL.min(remaining));
        }
    }

    fn click(&mut self, action: &Value) -> Result<(), String> {
        let locator = action
            .get("locator")
            .ok_or_else(|| "click action must include locator".to_owned())?;
        let selector = locator_selector(locator)?;
        let selector_json = serde_json::to_string(&selector).map_err(|error| error.to_string())?;
        let button = action
            .get("button")
            .and_then(Value::as_str)
            .unwrap_or("left");
        if !matches!(button, "left" | "middle" | "right") {
            return Err(format!("click.button is unsupported: {button}"));
        }
        let click_count = action
            .get("click_count")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        if !(1..=MAX_CLICK_COUNT).contains(&click_count) {
            return Err(format!(
                "click.click_count must be between 1 and {MAX_CLICK_COUNT}"
            ));
        }

        let point = self.command(
            "Runtime.evaluate",
            json!({
                "expression": format!(
                    "(() => {{ const e=document.querySelector({selector_json}); if (!e) return null; const r=e.getBoundingClientRect(); return {{x:r.left + r.width / 2, y:r.top + r.height / 2}}; }})()"
                ),
                "returnByValue": true,
            }),
        )?;
        let point = point
            .pointer("/result/value")
            .ok_or_else(|| "click locator did not resolve to an element".to_owned())?;
        let x = point
            .get("x")
            .and_then(Value::as_f64)
            .ok_or_else(|| "click locator did not produce a usable x coordinate".to_owned())?;
        let y = point
            .get("y")
            .and_then(Value::as_f64)
            .ok_or_else(|| "click locator did not produce a usable y coordinate".to_owned())?;
        if !x.is_finite() || !y.is_finite() {
            return Err("click locator produced non-finite coordinates".to_owned());
        }

        self.command(
            "Input.dispatchMouseEvent",
            json!({
                "type": "mouseMoved",
                "x": x,
                "y": y,
            }),
        )?;
        self.command(
            "Input.dispatchMouseEvent",
            json!({
                "type": "mousePressed",
                "x": x,
                "y": y,
                "button": button,
                "clickCount": click_count,
            }),
        )?;
        self.command(
            "Input.dispatchMouseEvent",
            json!({
                "type": "mouseReleased",
                "x": x,
                "y": y,
                "button": button,
                "clickCount": click_count,
            }),
        )?;
        Ok(())
    }
}

impl<T: CdpCommandPort> ScenarioActionPort for ConnectedCdpScenarioPort<T> {
    fn capture_initial(&mut self) -> Result<ActionObservation, String> {
        self.command("Page.enable", json!({}))?;
        self.command("Page.navigate", json!({"url": self.start_url}))?;
        self.observe(0)
    }

    fn execute(&mut self, step_index: u64, action: &Value) -> Result<ActionObservation, String> {
        let action_name = action
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| "scenario action must have a string action".to_owned())?;

        match action_name {
            "goto" => {
                let url = action
                    .pointer("/destination/url")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "goto action must include destination.url".to_owned())?;
                self.command("Page.navigate", json!({"url": url}))?;
                self.wait_for_document_state(action)?;
            }
            "click" => self.click(action)?,
            "press" => self.press(action)?,
            "wait_for" => self.wait_for(action)?,
            "wait_for_timeout" => self.wait_for_timeout(action)?,
            "fill" | "select_option" | "check" | "uncheck" => {
                let expression = action_expression(action_name, action)?;
                self.command(
                    "Runtime.evaluate",
                    json!({"expression": expression, "returnByValue": true}),
                )?;
            }
            other => return Err(format!("unsupported browser scenario action: {other}")),
        }

        self.observe(step_index)
    }
}

fn action_expression(action_name: &str, action: &Value) -> Result<String, String> {
    let locator = action
        .get("locator")
        .ok_or_else(|| format!("{action_name} action must include locator"))?;
    let selector = locator_selector(locator)?;
    let selector_json = serde_json::to_string(&selector).map_err(|error| error.to_string())?;
    let script = match action_name {
        "fill" => {
            let value = action_value(action, "fill.value")?;
            let value_json = serde_json::to_string(&value).map_err(|error| error.to_string())?;
            format!(
                "(() => {{ const e=document.querySelector({selector_json}); if (!e) return false; e.value={value_json}; e.dispatchEvent(new Event('input',{{bubbles:true}})); return true; }})()"
            )
        }
        "select_option" => {
            let value = action_value(action, "select_option.value")?;
            let value_json = serde_json::to_string(&value).map_err(|error| error.to_string())?;
            format!(
                "(() => {{ const e=document.querySelector({selector_json}); if (!e || !(e instanceof HTMLSelectElement)) return false; const value={value_json}; const option=Array.from(e.options).find((candidate) => candidate.value === value || candidate.label === value); if (!option) return false; e.value=option.value; e.dispatchEvent(new Event('input',{{bubbles:true}})); e.dispatchEvent(new Event('change',{{bubbles:true}})); return true; }})()"
            )
        }
        "check" | "uncheck" => format!(
            "(() => {{ const e=document.querySelector({selector_json}); if (!e) return false; e.checked={}; e.dispatchEvent(new Event('change',{{bubbles:true}})); return true; }})()",
            action_name == "check"
        ),
        _ => unreachable!(),
    };
    Ok(script)
}

fn locator_selector(locator: &Value) -> Result<String, String> {
    let selector = match locator.get("kind").and_then(Value::as_str) {
        Some("css") => locator
            .get("selector")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "css locator must include selector".to_owned()),
        Some("test_id") => locator
            .get("value")
            .and_then(Value::as_str)
            .map(|value| format!("[data-testid={:?}]", value))
            .ok_or_else(|| "test_id locator must include value".to_owned()),
        Some("role") => Err("role locators require accessibility-backed resolution".into()),
        _ => Err("locator kind is unsupported".into()),
    }?;
    bounded_string(selector, "locator selector", MAX_SELECTOR_CHARS)
}

fn action_value(action: &Value, field: &str) -> Result<String, String> {
    let value = action
        .pointer("/value/value")
        .and_then(Value::as_str)
        .or_else(|| action.get("value").and_then(Value::as_str))
        .ok_or_else(|| format!("{field} must include a literal value"))?;
    bounded_string(value.to_owned(), field, MAX_ACTION_VALUE_CHARS)
}

fn bounded_action_string(
    value: Option<&Value>,
    field: &str,
    maximum: usize,
) -> Result<String, String> {
    let value = value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} must be a non-empty string"))?;
    bounded_string(value.to_owned(), field, maximum)
}

fn bounded_string(value: String, field: &str, maximum: usize) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("{field} must be non-empty"));
    }
    if value.chars().count() > maximum {
        return Err(format!("{field} exceeds the {maximum}-character limit"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct FakeCdp {
        commands: Vec<(String, Value)>,
        responses: VecDeque<Value>,
    }

    impl CdpCommandPort for FakeCdp {
        fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
            self.commands.push((method.to_owned(), params));
            Ok(self.responses.pop_front().unwrap_or_else(|| {
                json!({
                    "result": {"value": {"url": "https://example.test/", "title": "fixture"}}
                })
            }))
        }
    }

    #[test]
    fn launch_mode_is_rejected_without_process_authority() {
        let input = json!({
            "browser": {"mode": "launch", "executable_path": "/bin/chromium"},
            "start_url": {"url": "https://example.test/"}
        });
        let result = ConnectedCdpScenarioPort::from_input(
            &input,
            FakeCdp {
                commands: Vec::new(),
                responses: VecDeque::new(),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn connected_port_preserves_target_and_uses_selected_start_url() {
        let mut port = ConnectedCdpScenarioPort::from_transport(
            FakeCdp {
                commands: Vec::new(),
                responses: VecDeque::from([
                    json!({}),
                    json!({"result": {"value": {"url": "https://example.test/"}}}),
                ]),
            },
            "tab-7",
            "https://example.test/start",
        );

        let result = port.capture_initial().expect("initial capture");
        assert_eq!(port.target_id(), "tab-7");
        assert_eq!(result.observation["target_id"], "tab-7");
        assert_eq!(port.transport.commands[1].0, "Page.navigate");
        assert_eq!(
            port.transport.commands[1].1["url"],
            "https://example.test/start"
        );
    }

    #[test]
    fn action_translation_keeps_locator_and_rejects_unsupported_roles() {
        let action = json!({
            "action": "fill",
            "locator": {"kind": "css", "selector": "#submit"},
            "value": "x"
        });
        assert!(
            action_expression("fill", &action)
                .expect("click expression")
                .contains("#submit")
        );

        let role = json!({"action": "fill", "locator": {"kind": "role", "role": "button", "name": "Save"}, "value": "x"});
        assert!(action_expression("fill", &role).is_err());
    }

    #[test]
    fn press_translation_accepts_bounded_keys() {
        let action = json!({
            "action": "press",
            "key": "Enter",
            "locator": {"kind": "css", "selector": "#submit"}
        });
        assert_eq!(
            bounded_action_string(action.get("key"), "press.key", MAX_KEY_CHARS)
                .expect("bounded key"),
            "Enter"
        );
    }

    #[test]
    fn select_option_translation_matches_value_or_label_and_dispatches_change() {
        let action = json!({
            "action": "select_option",
            "value": {"source": "literal", "value": "Premium"},
            "locator": {"kind": "css", "selector": "#plan"}
        });
        let expression = action_expression("select_option", &action).expect("select expression");

        assert!(expression.contains("HTMLSelectElement"));
        assert!(expression.contains("candidate.value === value || candidate.label === value"));
        assert!(expression.contains("new Event('change'"));
        assert!(expression.contains("Premium"));
    }

    #[test]
    fn action_translation_rejects_unbounded_selector_and_key_inputs() {
        let selector = "x".repeat(MAX_SELECTOR_CHARS + 1);
        let selector_action = json!({
            "action": "fill",
            "locator": {"kind": "css", "selector": selector},
            "value": "x"
        });
        assert!(action_expression("fill", &selector_action).is_err());

        let key = "K".repeat(MAX_KEY_CHARS + 1);
        let key_action = json!({
            "action": "press",
            "key": key,
            "locator": {"kind": "css", "selector": "#submit"}
        });
        assert!(bounded_action_string(key_action.get("key"), "press.key", MAX_KEY_CHARS).is_err());
    }

    #[test]
    fn click_dispatches_selected_button_and_click_count() {
        let mut port = ConnectedCdpScenarioPort::from_transport(
            FakeCdp {
                commands: Vec::new(),
                responses: VecDeque::from([json!({
                    "result": {"value": {"x": 12.5, "y": 24.0}}
                })]),
            },
            "tab-7",
            "https://example.test/",
        );
        port.execute(
            1,
            &json!({
                "action": "click",
                "button": "right",
                "click_count": 2,
                "locator": {"kind": "css", "selector": "#submit"}
            }),
        )
        .expect("click action");

        assert_eq!(port.transport.commands[1].0, "Input.dispatchMouseEvent");
        assert_eq!(port.transport.commands[2].1["type"], "mousePressed");
        assert_eq!(port.transport.commands[2].1["button"], "right");
        assert_eq!(port.transport.commands[2].1["clickCount"], 2);
        assert_eq!(port.transport.commands[3].1["type"], "mouseReleased");
    }

    #[test]
    fn click_rejects_unbounded_or_unknown_options() {
        let mut port = ConnectedCdpScenarioPort::from_transport(
            FakeCdp {
                commands: Vec::new(),
                responses: VecDeque::new(),
            },
            "tab-7",
            "https://example.test/",
        );
        let action = json!({
            "action": "click",
            "button": "sideways",
            "locator": {"kind": "css", "selector": "#submit"}
        });
        assert!(port.execute(1, &action).is_err());

        let action = json!({
            "action": "click",
            "click_count": MAX_CLICK_COUNT + 1,
            "locator": {"kind": "css", "selector": "#submit"}
        });
        assert!(port.execute(1, &action).is_err());
    }

    #[test]
    fn press_uses_cdp_keyboard_dispatch_after_focusing_locator() {
        let mut port = ConnectedCdpScenarioPort::from_transport(
            FakeCdp {
                commands: Vec::new(),
                responses: VecDeque::from([json!({"result": {"value": true}})]),
            },
            "tab-7",
            "https://example.test/",
        );
        port.execute(
            1,
            &json!({
                "action": "press",
                "key": "Enter",
                "locator": {"kind": "css", "selector": "#submit"}
            }),
        )
        .expect("press action");

        let methods: Vec<_> = port
            .transport
            .commands
            .iter()
            .map(|(method, _)| method.as_str())
            .collect();
        assert_eq!(
            methods,
            vec![
                "Runtime.evaluate",
                "Input.dispatchKeyEvent",
                "Input.dispatchKeyEvent",
                "Runtime.evaluate"
            ]
        );
    }

    #[test]
    fn wait_for_polls_until_requested_state_is_observed() {
        let mut port = ConnectedCdpScenarioPort::from_transport(
            FakeCdp {
                commands: Vec::new(),
                responses: VecDeque::from([
                    json!({"result": {"value": false}}),
                    json!({"result": {"value": true}}),
                ]),
            },
            "tab-7",
            "https://example.test/",
        );
        port.execute(
            1,
            &json!({
                "action": "wait_for",
                "state": "attached",
                "timeout_ms": 1000,
                "locator": {"kind": "css", "selector": "#ready"}
            }),
        )
        .expect("wait_for action");

        assert_eq!(port.transport.commands.len(), 3);
        assert_eq!(port.transport.commands[0].0, "Runtime.evaluate");
        assert_eq!(port.transport.commands[1].0, "Runtime.evaluate");
        assert_eq!(port.transport.commands[2].0, "Runtime.evaluate");
    }
}
