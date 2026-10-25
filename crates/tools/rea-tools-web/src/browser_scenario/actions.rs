//! Declarative scenario actions over CDP input and REA's page helper.
//!
//! Compatibility owners: `src/browser/PlaywrightScenarioActions.ts` and the
//! Playwright 1.58.2 behaviors it delegates to: `page.goto` lifecycle waits,
//! locator strictness, the click retry ladder (visible/enabled/stable, scroll,
//! hit target, mouse events, scheduled navigations), `fill`, `press` (US
//! keyboard layout), `selectOption`, `check`/`uncheck` and `waitFor`. Error
//! text follows Playwright's first line; its call log is reproduced for the
//! steps this owner performs.
use super::driver::{CallError, Driver, Scope};
use super::input::{Action, ActionKind, Locator};
use super::secrets::Secrets;
use serde_json::{Value, json};
use std::sync::OnceLock;
use std::time::Duration;

const KEYBOARD: &str = include_str!("keyboard.json");
/// Playwright's retry back-off between pointer action attempts.
const RETRY_WAITS: [u64; 6] = [0, 20, 100, 100, 500, 500];
const POLL: Duration = Duration::from_millis(20);

/// Why one action did not complete.
#[derive(Debug)]
pub(crate) enum ActionError {
    Interrupted(CallError),
    Message(String),
}

impl From<CallError> for ActionError {
    fn from(error: CallError) -> Self {
        match error {
            CallError::Cancelled | CallError::Deadline => Self::Interrupted(error),
            CallError::Protocol(message) | CallError::Closed(message) => Self::Message(message),
        }
    }
}

struct CallLog {
    method: &'static str,
    lines: Vec<String>,
}

impl CallLog {
    fn new(method: &'static str) -> Self {
        Self {
            method,
            lines: Vec::new(),
        }
    }

    fn log(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
    }

    fn fail(&self, message: &str) -> ActionError {
        let mut text = format!("{}: {message}", self.method);
        if !self.lines.is_empty() {
            text.push_str("\nCall log:\n");
            for line in &self.lines {
                text.push_str(&format!("\x1b[2m{line}\x1b[22m\n"));
            }
        }
        ActionError::Message(text)
    }
}

fn locator_value(locator: &Locator) -> Value {
    match locator {
        Locator::TestId(value) => json!({ "kind": "test_id", "value": value }),
        Locator::Role { role, name } => json!({ "kind": "role", "role": role, "name": name }),
        Locator::Css(selector) => json!({ "kind": "css", "selector": selector }),
    }
}

fn describe(locator: &Locator) -> String {
    let quote = |value: &str| format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"));
    match locator {
        Locator::TestId(value) => format!("getByTestId({})", quote(value)),
        Locator::Role { role, name } => format!(
            "getByRole({}, {{ name: {}, exact: true }})",
            quote(role),
            quote(name)
        ),
        Locator::Css(selector) => format!("locator({})", quote(selector)),
    }
}

fn strict_violation(locator: &Locator, count: u64, previews: &[Value]) -> String {
    let mut message = format!(
        "Error: strict mode violation: {} resolved to {count} elements:\n",
        describe(locator)
    );
    for (index, preview) in previews.iter().enumerate() {
        message.push_str(&format!(
            "    {}) {}\n",
            index + 1,
            preview.as_str().unwrap_or_default()
        ));
    }
    if count > 10 {
        message.push_str("    ...\n");
    }
    message
}

/// A resolved element handle in the utility world.
struct Element {
    object_id: String,
    preview: String,
}

enum Resolution {
    One(Element),
    None,
}

/// Playwright selector-engine syntax that a `css` locator string may carry
/// (`page.locator(selector)`), which this owner does not evaluate.
fn playwright_selector_syntax(selector: &str) -> bool {
    let trimmed = selector.trim_start();
    const ENGINES: [&str; 12] = [
        "text=",
        "css=",
        "xpath=",
        "id=",
        "data-testid=",
        "data-test-id=",
        "data-test=",
        "nth=",
        "visible=",
        "internal:",
        "role=",
        "_react=",
    ];
    const PSEUDOS: [&str; 12] = [
        ":has-text(",
        ":text(",
        ":text-is(",
        ":text-matches(",
        ":visible",
        ":nth-match(",
        ":right-of(",
        ":left-of(",
        ":above(",
        ":below(",
        ":near(",
        ":light(",
    ];
    ENGINES.iter().any(|engine| trimmed.starts_with(engine))
        || trimmed.starts_with("//")
        || trimmed.starts_with("..")
        || trimmed.starts_with('"')
        || selector.contains(">>")
        || PSEUDOS.iter().any(|pseudo| selector.contains(pseudo))
}

fn resolve(
    driver: &mut Driver,
    locator: &Locator,
    log: &CallLog,
    scope: &Scope,
) -> Result<Resolution, ActionError> {
    if let Locator::Css(selector) = locator
        && playwright_selector_syntax(selector)
    {
        return Err(log.fail(&format!(
            "Error: Playwright selector-engine syntax is not supported by REA's native scenario runner: \"{selector}\". Use a plain CSS selector, a test_id locator or a role locator."
        )));
    }
    let expression = format!("__reaScenario.resolve({})", locator_value(locator));
    let object = driver
        .evaluate_utility(&expression, false, false, scope)
        .map_err(|error| match error {
            CallError::Protocol(message) => log.fail(&format!("Error: {message}")),
            other => other.into(),
        })?;
    if object.get("subtype").and_then(Value::as_str) == Some("node") {
        let object_id = object
            .get("objectId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let preview = driver
            .call_on(
                &object_id,
                "function() { return __reaScenario.preview(this); }",
                Vec::new(),
                false,
                scope,
            )?
            .as_str()
            .unwrap_or_default()
            .to_owned();
        return Ok(Resolution::One(Element { object_id, preview }));
    }
    let summary = match object.get("objectId").and_then(Value::as_str) {
        Some(id) => driver.call_on(id, "function() { return this; }", Vec::new(), false, scope)?,
        None => object.get("value").cloned().unwrap_or(Value::Null),
    };
    let count = summary
        .get("count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if count > 1 {
        let previews = summary
            .get("previews")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        return Err(log.fail(&strict_violation(locator, count, &previews)));
    }
    Ok(Resolution::None)
}

/// Wait until the locator resolves to exactly one element.
fn wait_for_element(
    driver: &mut Driver,
    locator: &Locator,
    log: &mut CallLog,
    scope: &Scope,
) -> Result<Element, ActionError> {
    log.log(format!("  - waiting for {}", describe(locator)));
    loop {
        if let Resolution::One(element) = resolve(driver, locator, log, scope)? {
            log.log(format!("    - locator resolved to {}", element.preview));
            return Ok(element);
        }
        driver.release_objects(scope);
        driver.sleep(POLL, scope)?;
    }
}

fn states(
    driver: &mut Driver,
    element: &Element,
    wanted: &[&str],
    log: &CallLog,
    scope: &Scope,
) -> Result<Option<String>, ActionError> {
    let result = driver
        .call_on(
            &element.object_id,
            "function(states) { return __reaScenario.states(this, states); }",
            vec![json!(wanted)],
            true,
            scope,
        )
        .map_err(|error| match error {
            CallError::Protocol(message) => log.fail(&format!("Error: {message}")),
            other => other.into(),
        })?;
    if result.as_str() == Some("ok") {
        return Ok(None);
    }
    Ok(Some(
        result
            .get("missing")
            .and_then(Value::as_str)
            .unwrap_or("notconnected")
            .to_owned(),
    ))
}

fn button_mask(button: &str) -> u64 {
    match button {
        "right" => 2,
        "middle" => 4,
        _ => 1,
    }
}

/// Playwright's pointer retry ladder; returns once the click was issued.
fn click_element(
    driver: &mut Driver,
    locator: &Locator,
    button: &str,
    click_count: u64,
    log: &mut CallLog,
    scope: &Scope,
) -> Result<(), ActionError> {
    let mut element = wait_for_element(driver, locator, log, scope)?;
    let mut attempt = 0usize;
    loop {
        if attempt > 0 {
            let wait = RETRY_WAITS[attempt.min(RETRY_WAITS.len() - 1)];
            if wait > 0 {
                log.log(format!("  - waiting {wait}ms"));
                driver.sleep(Duration::from_millis(wait), scope)?;
            }
            element = match resolve(driver, locator, log, scope)? {
                Resolution::One(element) => element,
                Resolution::None => wait_for_element(driver, locator, log, scope)?,
            };
        }
        attempt += 1;
        log.log(if attempt == 1 {
            "  - attempting click action".to_owned()
        } else {
            "retrying click action".to_owned()
        });
        log.log("    - waiting for element to be visible, enabled and stable");
        match states(
            driver,
            &element,
            &["stable", "visible", "enabled"],
            log,
            scope,
        )? {
            Some(missing) => {
                log.log(format!("    - element is not {missing}"));
                continue;
            }
            None => log.log("    - element is visible, enabled and stable"),
        }
        log.log("    - scrolling into view if needed");
        if driver
            .main_call(
                "DOM.scrollIntoViewIfNeeded",
                json!({ "objectId": element.object_id }),
                scope,
            )
            .is_err()
        {
            log.log("    - element is not visible");
            continue;
        }
        log.log("    - done scrolling");
        let Some((x, y)) = clickable_point(driver, &element, scope)? else {
            log.log("    - element is not visible");
            continue;
        };
        let hit = driver.call_on(
            &element.object_id,
            "function(x, y) { return __reaScenario.hit(this, x, y); }",
            vec![json!(x), json!(y)],
            false,
            scope,
        )?;
        if hit.as_str() != Some("done") {
            let description = hit.get("hit").and_then(Value::as_str).unwrap_or_default();
            log.log(format!("    - {description} intercepts pointer events"));
            continue;
        }
        log.log("    - performing click action");
        let requests = driver.world.navigation_requests;
        let commits = driver.world.commits;
        driver.main_call(
            "Input.dispatchMouseEvent",
            json!({ "type": "mouseMoved", "button": "none", "buttons": 0, "x": x, "y": y, "modifiers": 0, "force": 0 }),
            scope,
        )?;
        let mask = button_mask(button);
        for count in 1..=click_count.max(1) {
            driver.main_call(
                "Input.dispatchMouseEvent",
                json!({ "type": "mousePressed", "button": button, "buttons": mask, "x": x, "y": y, "modifiers": 0, "clickCount": count, "force": 0.5 }),
                scope,
            )?;
            driver.main_call(
                "Input.dispatchMouseEvent",
                json!({ "type": "mouseReleased", "button": button, "buttons": 0, "x": x, "y": y, "modifiers": 0, "clickCount": count, "force": 0 }),
                scope,
            )?;
        }
        log.log("    - click action done");
        wait_for_scheduled_navigations(driver, requests, commits, log, scope)?;
        driver.release_objects(scope);
        return Ok(());
    }
}

/// `_clickablePoint`: the center of the first sizeable content quad.
fn clickable_point(
    driver: &mut Driver,
    element: &Element,
    scope: &Scope,
) -> Result<Option<(f64, f64)>, ActionError> {
    let quads = match driver.main_call(
        "DOM.getContentQuads",
        json!({ "objectId": element.object_id }),
        scope,
    ) {
        Ok(quads) => quads,
        Err(CallError::Protocol(_)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metrics = driver.main_call("Page.getLayoutMetrics", json!({}), scope)?;
    let width = metrics
        .pointer("/cssLayoutViewport/clientWidth")
        .and_then(Value::as_f64)
        .unwrap_or(f64::MAX);
    let height = metrics
        .pointer("/cssLayoutViewport/clientHeight")
        .and_then(Value::as_f64)
        .unwrap_or(f64::MAX);
    for quad in quads
        .get("quads")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let points: Vec<f64> = quad
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_f64)
            .collect();
        if points.len() != 8 {
            continue;
        }
        let clipped: Vec<(f64, f64)> = (0..4)
            .map(|index| {
                (
                    points[index * 2].clamp(0.0, width),
                    points[index * 2 + 1].clamp(0.0, height),
                )
            })
            .collect();
        let mut area = 0.0;
        for index in 0..4 {
            let (x1, y1) = clipped[index];
            let (x2, y2) = clipped[(index + 1) % 4];
            area += (x1 * y2 - x2 * y1) / 2.0;
        }
        if area.abs() <= 0.99 {
            continue;
        }
        let x = clipped.iter().map(|point| point.0).sum::<f64>() / 4.0;
        let y = clipped.iter().map(|point| point.1).sum::<f64>() / 4.0;
        return Ok(Some((x, y)));
    }
    Ok(None)
}

fn wait_for_scheduled_navigations(
    driver: &mut Driver,
    requests: u64,
    commits: u64,
    log: &mut CallLog,
    scope: &Scope,
) -> Result<(), ActionError> {
    log.log("    - waiting for scheduled navigations to finish");
    // `inputActionEpilogue`: one main-session round trip flushes the
    // renderer's navigation requests caused by the input.
    let _ = driver.main_call("Page.enable", json!({}), scope);
    if driver.world.navigation_requests > requests {
        driver.world.navigation_failure = None;
        driver.wait_until(scope, |world| {
            world.commits > commits || world.navigation_failure.is_some() || world.page_closed
        })?;
    }
    log.log("    - navigations have finished");
    Ok(())
}

// ---- Keyboard ------------------------------------------------------------

fn layout() -> &'static Value {
    static LAYOUT: OnceLock<Value> = OnceLock::new();
    LAYOUT.get_or_init(|| serde_json::from_str(KEYBOARD).unwrap_or(Value::Null))
}

const MODIFIERS: [&str; 4] = ["Alt", "Control", "Meta", "Shift"];

fn modifier_mask(pressed: &[String]) -> u64 {
    let mut mask = 0;
    for modifier in pressed {
        mask |= match modifier.as_str() {
            "Alt" => 1,
            "Control" => 2,
            "Meta" => 4,
            "Shift" => 8,
            _ => 0,
        };
    }
    mask
}

fn smart_modifier(key: &str) -> String {
    if key == "ControlOrMeta" {
        return if cfg!(target_os = "macos") {
            "Meta"
        } else {
            "Control"
        }
        .to_owned();
    }
    key.to_owned()
}

fn describe_key(key: &str, pressed: &[String]) -> Result<Value, String> {
    let key = smart_modifier(key);
    let Some(mut description) = layout()
        .pointer("/layout")
        .and_then(|layout| layout.get(&key))
        .cloned()
    else {
        return Err(format!("Unknown key: \"{key}\""));
    };
    if pressed.iter().any(|modifier| modifier == "Shift")
        && let Some(shifted) = description
            .get("shifted")
            .filter(|value| !value.is_null())
            .cloned()
    {
        description = shifted;
    }
    let only_shift = pressed.len() == 1 && pressed[0] == "Shift";
    if pressed.len() > 1 || (!pressed.is_empty() && !only_shift) {
        description["text"] = json!("");
    }
    Ok(description)
}

fn mac_commands(code: &str, pressed: &[String]) -> Vec<Value> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    let mut parts: Vec<String> = ["Shift", "Control", "Alt", "Meta"]
        .iter()
        .filter(|item| pressed.iter().any(|p| p == *item))
        .map(|item| (*item).to_owned())
        .collect();
    parts.push(code.to_owned());
    let shortcut = parts.join("+");
    let commands = match layout()
        .pointer("/mac_commands")
        .and_then(|table| table.get(&shortcut))
    {
        Some(Value::String(command)) => vec![command.clone()],
        Some(Value::Array(commands)) => commands
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    commands
        .into_iter()
        .filter(|command| !command.starts_with("insert"))
        .map(|command| json!(command[..command.len().saturating_sub(1)]))
        .collect()
}

fn split_key(key: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut building = String::new();
    for character in key.chars() {
        if character == '+' && !building.is_empty() {
            keys.push(std::mem::take(&mut building));
        } else {
            building.push(character);
        }
    }
    keys.push(building);
    keys
}

fn key_down(
    driver: &mut Driver,
    key: &str,
    pressed: &mut Vec<String>,
    scope: &Scope,
) -> Result<(), ActionError> {
    let description = describe_key(key, pressed).map_err(ActionError::Message)?;
    let name = description
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if MODIFIERS.contains(&name.as_str()) && !pressed.contains(&name) {
        pressed.push(name.clone());
    }
    let code = description
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let text = description
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let location = description
        .get("location")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    driver.main_call(
        "Input.dispatchKeyEvent",
        json!({
            "type": if text.is_empty() { "rawKeyDown" } else { "keyDown" },
            "modifiers": modifier_mask(pressed),
            "windowsVirtualKeyCode": description.get("keyCodeWithoutLocation").cloned().unwrap_or(json!(0)),
            "code": code,
            "commands": mac_commands(&code, pressed),
            "key": name,
            "text": text,
            "unmodifiedText": text,
            "autoRepeat": false,
            "location": location,
            "isKeypad": location == 3,
        }),
        scope,
    )?;
    Ok(())
}

fn key_up(
    driver: &mut Driver,
    key: &str,
    pressed: &mut Vec<String>,
    scope: &Scope,
) -> Result<(), ActionError> {
    let description = describe_key(key, pressed).map_err(ActionError::Message)?;
    let name = description
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    pressed.retain(|modifier| *modifier != name);
    driver.main_call(
        "Input.dispatchKeyEvent",
        json!({
            "type": "keyUp",
            "modifiers": modifier_mask(pressed),
            "key": name,
            "windowsVirtualKeyCode": description.get("keyCodeWithoutLocation").cloned().unwrap_or(json!(0)),
            "code": description.get("code").cloned().unwrap_or(json!("")),
            "location": description.get("location").cloned().unwrap_or(json!(0)),
        }),
        scope,
    )?;
    Ok(())
}

/// `keyboard.press`.
fn press_key(driver: &mut Driver, key: &str, scope: &Scope) -> Result<(), ActionError> {
    let tokens = split_key(key);
    let (last, modifiers) = tokens
        .split_last()
        .map(|(last, rest)| (last.clone(), rest.to_vec()))
        .unwrap_or_default();
    let mut pressed: Vec<String> = Vec::new();
    for modifier in &modifiers {
        key_down(driver, modifier, &mut pressed, scope)?;
    }
    key_down(driver, &last, &mut pressed, scope)?;
    key_up(driver, &last, &mut pressed, scope)?;
    for modifier in modifiers.iter().rev() {
        key_up(driver, modifier, &mut pressed, scope)?;
    }
    Ok(())
}

// ---- Actions -------------------------------------------------------------

fn goto(
    driver: &mut Driver,
    url: &str,
    wait_until: &str,
    scope: &Scope,
) -> Result<(), ActionError> {
    let log_line = format!("  - navigating to \"{url}\", waiting until \"{wait_until}\"");
    let fail = |message: &str| {
        let mut log = CallLog::new("page.goto");
        log.log(log_line.clone());
        log.fail(message)
    };
    let frame = driver.world.main_frame.clone().unwrap_or_default();
    driver.world.navigation_failure = None;
    let commits = driver.world.commits;
    let response = driver.main_call(
        "Page.navigate",
        json!({ "url": url, "frameId": frame, "referrerPolicy": "unsafeUrl" }),
        scope,
    )?;
    if let Some(error) = response
        .get("errorText")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        return Err(fail(&format!("{error} at {url}")));
    }
    let Some(loader) = response
        .get("loaderId")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        // Same-document navigation commits immediately.
        return Ok(());
    };
    let event = match wait_until {
        "commit" => None,
        "domcontentloaded" => Some("DOMContentLoaded"),
        _ => Some("load"),
    };
    let mut failure = None;
    driver.wait_until(scope, |world| {
        if let Some((request, text)) = &world.navigation_failure
            && *request == loader
        {
            failure = Some(text.clone());
            return true;
        }
        let committed = world.commits > commits && world.loader.as_deref() == Some(loader.as_str());
        match event {
            None => committed,
            Some(name) => {
                committed
                    && world
                        .lifecycle
                        .get(&loader)
                        .is_some_and(|events| events.contains(name))
            }
        }
    })?;
    if let Some(text) = failure {
        return Err(fail(&format!("{text} at {url}")));
    }
    Ok(())
}

/// Execute one admitted declarative action.
pub(crate) fn perform(
    driver: &mut Driver,
    action: &Action,
    secrets: &Secrets,
    scope: &Scope,
) -> Result<(), ActionError> {
    match &action.kind {
        ActionKind::Goto {
            destination,
            wait_until,
        } => goto(driver, &secrets.url(destination), wait_until, scope),
        ActionKind::Click {
            locator,
            button,
            click_count,
        } => {
            let mut log = CallLog::new("locator.click");
            click_element(driver, locator, button, *click_count, &mut log, scope)
        }
        ActionKind::Fill { locator, value } => {
            let value = secrets.value(value);
            let mut log = CallLog::new("locator.fill");
            let mut element = wait_for_element(driver, locator, &mut log, scope)?;
            log.log(format!(
                "    - fill({})",
                serde_json::to_string(&value).unwrap_or_default()
            ));
            log.log("  - attempting fill action");
            let mut attempt = 0usize;
            loop {
                if attempt > 0 {
                    driver.sleep(
                        Duration::from_millis(RETRY_WAITS[attempt.min(RETRY_WAITS.len() - 1)]),
                        scope,
                    )?;
                    if let Resolution::One(next) = resolve(driver, locator, &log, scope)? {
                        element = next;
                    }
                }
                attempt += 1;
                log.log("    - waiting for element to be visible, enabled and editable");
                if states(
                    driver,
                    &element,
                    &["visible", "enabled", "editable"],
                    &log,
                    scope,
                )?
                .is_some()
                {
                    continue;
                }
                let filled = driver
                    .call_on(
                        &element.object_id,
                        "function(value) { return __reaScenario.fill(this, value); }",
                        vec![json!(value)],
                        false,
                        scope,
                    )
                    .map_err(|error| match error {
                        CallError::Protocol(message) => log.fail(&format!("Error: {message}")),
                        other => other.into(),
                    })?;
                match filled.as_str() {
                    Some("error:notconnected") => continue,
                    Some("needsinput") => {
                        if value.is_empty() {
                            press_key(driver, "Delete", scope)?;
                        } else {
                            driver.main_call(
                                "Input.insertText",
                                json!({ "text": value }),
                                scope,
                            )?;
                        }
                    }
                    _ => {}
                }
                driver.release_objects(scope);
                return Ok(());
            }
        }
        ActionKind::Press { locator, key } => {
            let mut log = CallLog::new("locator.press");
            let element = wait_for_element(driver, locator, &mut log, scope)?;
            log.log(format!(
                "  - elementHandle.press({})",
                serde_json::to_string(key).unwrap_or_default()
            ));
            driver.call_on(
                &element.object_id,
                "function() { return __reaScenario.focus(this); }",
                Vec::new(),
                false,
                scope,
            )?;
            let requests = driver.world.navigation_requests;
            let commits = driver.world.commits;
            if let Err(ActionError::Message(message)) =
                press_key(driver, key, scope).map_err(|error| match error {
                    ActionError::Message(message) => ActionError::Message(message),
                    other => other,
                })
            {
                return Err(log.fail(&message));
            }
            wait_for_scheduled_navigations(driver, requests, commits, &mut log, scope)?;
            driver.release_objects(scope);
            Ok(())
        }
        ActionKind::SelectOption { locator, value } => {
            let value = secrets.value(value);
            let mut log = CallLog::new("locator.selectOption");
            let mut element = wait_for_element(driver, locator, &mut log, scope)?;
            log.log("  - attempting select option action");
            loop {
                log.log("    - waiting for element to be visible and enabled");
                if states(driver, &element, &["visible", "enabled"], &log, scope)?.is_none() {
                    let selected = driver
                        .call_on(
                            &element.object_id,
                            "function(value) { return __reaScenario.select(this, value); }",
                            vec![json!(value)],
                            false,
                            scope,
                        )
                        .map_err(|error| match error {
                            CallError::Protocol(message) => log.fail(&format!("Error: {message}")),
                            other => other.into(),
                        })?;
                    if selected.is_array() {
                        driver.release_objects(scope);
                        return Ok(());
                    }
                    if selected.as_str() == Some("error:optionsnotfound") {
                        log.log("    - did not find some options");
                    }
                }
                driver.sleep(POLL, scope)?;
                if let Resolution::One(next) = resolve(driver, locator, &log, scope)? {
                    element = next;
                }
            }
        }
        ActionKind::Check { locator, checked } => {
            let method = if *checked {
                "locator.check"
            } else {
                "locator.uncheck"
            };
            let mut log = CallLog::new(method);
            let element = wait_for_element(driver, locator, &mut log, scope)?;
            let state = |driver: &mut Driver,
                         element: &Element,
                         log: &CallLog|
             -> Result<(bool, bool), ActionError> {
                let result = driver
                    .call_on(
                        &element.object_id,
                        "function() { return __reaScenario.checked(this); }",
                        Vec::new(),
                        false,
                        scope,
                    )
                    .map_err(|error| match error {
                        CallError::Protocol(message) => log.fail(&format!("Error: {message}")),
                        other => other.into(),
                    })?;
                Ok((
                    result
                        .get("checked")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    result
                        .get("radio")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                ))
            };
            let (current, radio) = state(driver, &element, &log)?;
            if current == *checked {
                return Ok(());
            }
            if !*checked && radio {
                return Err(log.fail("Cannot uncheck radio button"));
            }
            // The click resolves the element again, logging as Playwright does.
            let mut click_log = CallLog::new(method);
            click_element(driver, locator, "left", 1, &mut click_log, scope).map_err(|error| {
                match error {
                    ActionError::Message(message) => {
                        ActionError::Message(message.replacen("locator.click", method, 1))
                    }
                    other => other,
                }
            })?;
            let element = match resolve(driver, locator, &click_log, scope)? {
                Resolution::One(element) => element,
                Resolution::None => {
                    return Err(click_log.fail("Element is not attached to the DOM"));
                }
            };
            let (after, _) = state(driver, &element, &click_log)?;
            if after != *checked {
                return Err(click_log.fail("Clicking the checkbox did not change its state"));
            }
            driver.release_objects(scope);
            Ok(())
        }
        ActionKind::WaitFor { locator, state } => {
            let mut log = CallLog::new("locator.waitFor");
            log.log(format!(
                "  - waiting for {} to be {state}",
                describe(locator)
            ));
            loop {
                let summary = driver
                    .evaluate_utility(
                        &format!("__reaScenario.count({})", locator_value(locator)),
                        true,
                        false,
                        scope,
                    )
                    .map_err(|error| match error {
                        CallError::Protocol(message) => log.fail(&format!("Error: {message}")),
                        other => other.into(),
                    })?;
                let summary = summary.get("value").cloned().unwrap_or(Value::Null);
                let count = summary
                    .get("count")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                if count > 1 {
                    let previews = summary
                        .get("previews")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    return Err(log.fail(&strict_violation(locator, count, &previews)));
                }
                let visible = summary
                    .get("visible")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let done = match state.as_str() {
                    "attached" => count == 1,
                    "detached" => count == 0,
                    "visible" => count == 1 && visible,
                    _ => count == 0 || !visible,
                };
                if done {
                    return Ok(());
                }
                driver.sleep(POLL, scope)?;
            }
        }
        ActionKind::WaitForTimeout { duration_ms } => {
            driver.sleep(Duration::from_millis(*duration_ms), scope)?;
            Ok(())
        }
    }
}

/// `page.goto(start_url, { waitUntil: "load" })` for the initial navigation.
pub(crate) fn navigate_start(
    driver: &mut Driver,
    url: &str,
    scope: &Scope,
) -> Result<(), ActionError> {
    goto(driver, url, "load", scope)
}
