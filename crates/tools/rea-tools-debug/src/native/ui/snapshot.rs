//! Helper response validation.
//!
//! Compatibility owners: `responseSchema` in `src/native/NativeUiObservation.ts`
//! and `nativeUiSnapshotSchema` in `src/domain/native/nativeUiObservation.ts`.
//! Every object is strict (unknown keys are rejected), matching `z.strictObject`.
//! The reported reason lists each violated path; it is a diagnostic, not the
//! byte-identical ZodError text.
use base64::Engine as _;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// A validated helper response.
pub enum Response {
    /// `{ ok: true, result }` with a validated snapshot.
    Ok(Value),
    /// `{ ok: false, code, message }`.
    Err { code: String, message: String },
}

/// Malformed helper output.
#[derive(Debug)]
pub struct SnapshotError(Vec<String>);

impl SnapshotError {
    pub fn into_reason(self) -> String {
        format!("Malformed native helper response: {}", self.0.join("; "))
    }
}

struct Check {
    issues: Vec<String>,
}

impl Check {
    fn fail(&mut self, path: &str, message: &str) {
        self.issues.push(format!("{path}: {message}"));
    }
    fn object<'a>(
        &mut self,
        value: &'a Value,
        path: &str,
        keys: &[&str],
    ) -> Option<&'a Map<String, Value>> {
        let Some(map) = value.as_object() else {
            self.fail(path, "expected object");
            return None;
        };
        for key in map.keys() {
            if !keys.contains(&key.as_str()) {
                self.fail(path, &format!("unrecognized key {key:?}"));
            }
        }
        for key in keys {
            if !map.contains_key(*key) {
                self.fail(&format!("{path}.{key}"), "required");
            }
        }
        Some(map)
    }
    fn positive_int(&mut self, value: Option<&Value>, path: &str) {
        if !value
            .and_then(Value::as_f64)
            .is_some_and(|n| n.fract() == 0.0 && n > 0.0 && n <= 9_007_199_254_740_991.0)
        {
            self.fail(path, "expected positive integer");
        }
    }
    fn nonnegative_int(&mut self, value: &Value, path: &str) -> bool {
        let ok = value
            .as_f64()
            .is_some_and(|n| n.fract() == 0.0 && n >= 0.0 && n <= 9_007_199_254_740_991.0);
        if !ok {
            self.fail(path, "expected nonnegative integer");
        }
        ok
    }
    fn string(&mut self, value: Option<&Value>, path: &str) -> Option<String> {
        match value.and_then(Value::as_str) {
            Some(text) => Some(text.to_owned()),
            None => {
                self.fail(path, "expected string");
                None
            }
        }
    }
    fn nullable_string(&mut self, value: Option<&Value>, path: &str) {
        if !matches!(value, Some(Value::Null) | Some(Value::String(_))) {
            self.fail(path, "expected string or null");
        }
    }
    fn bool(&mut self, value: Option<&Value>, path: &str) {
        if !matches!(value, Some(Value::Bool(_))) {
            self.fail(path, "expected boolean");
        }
    }
    fn string_array(&mut self, value: Option<&Value>, path: &str) {
        match value.and_then(Value::as_array) {
            Some(items) => {
                for (index, item) in items.iter().enumerate() {
                    if !item.is_string() {
                        self.fail(&format!("{path}[{index}]"), "expected string");
                    }
                }
            }
            None => self.fail(path, "expected array"),
        }
    }
}

/// `responseSchema.parse(response)`.
pub fn validate_response(response: &Value) -> Result<Response, SnapshotError> {
    let mut check = Check { issues: Vec::new() };
    match response.get("ok") {
        Some(Value::Bool(true)) => {
            if let Some(map) = check.object(response, "response", &["ok", "result"]) {
                if let Some(result) = map.get("result") {
                    validate_snapshot(&mut check, result, "result");
                }
            }
            if check.issues.is_empty() {
                Ok(Response::Ok(response["result"].clone()))
            } else {
                Err(SnapshotError(check.issues))
            }
        }
        Some(Value::Bool(false)) => {
            let map = check.object(response, "response", &["ok", "code", "message"]);
            let code = map.and_then(|m| check.string(m.get("code"), "code"));
            let message = map.and_then(|m| check.string(m.get("message"), "message"));
            match (code, message, check.issues.is_empty()) {
                (Some(code), Some(message), true) => Ok(Response::Err { code, message }),
                _ => Err(SnapshotError(check.issues)),
            }
        }
        _ => Err(SnapshotError(vec![
            "ok: invalid discriminator value".into(),
        ])),
    }
}

fn validate_snapshot(check: &mut Check, value: &Value, path: &str) {
    let Some(map) = check.object(
        value,
        path,
        &["window", "nodes", "truncated", "screenshot", "gaps"],
    ) else {
        return;
    };
    if let Some(window) = map.get("window") {
        let wpath = format!("{path}.window");
        if let Some(w) = check.object(
            window,
            &wpath,
            &["pid", "window_id", "executable", "launch_time", "title"],
        ) {
            check.positive_int(w.get("pid"), &format!("{wpath}.pid"));
            check.positive_int(w.get("window_id"), &format!("{wpath}.window_id"));
            check.string(w.get("executable"), &format!("{wpath}.executable"));
            if !w.get("launch_time").is_some_and(Value::is_number) {
                check.fail(&format!("{wpath}.launch_time"), "expected number");
            }
            check.string(w.get("title"), &format!("{wpath}.title"));
        }
    }
    match map.get("nodes").and_then(Value::as_array) {
        Some(nodes) => {
            for (index, node) in nodes.iter().enumerate() {
                let npath = format!("{path}.nodes[{index}]");
                let Some(n) = check.object(
                    node,
                    &npath,
                    &[
                        "path",
                        "role",
                        "title",
                        "value",
                        "actions",
                        "children_count",
                    ],
                ) else {
                    continue;
                };
                match n.get("path").and_then(Value::as_array) {
                    Some(items) => {
                        for (i, item) in items.iter().enumerate() {
                            check.nonnegative_int(item, &format!("{npath}.path[{i}]"));
                        }
                    }
                    None => check.fail(&format!("{npath}.path"), "expected array"),
                }
                check.nullable_string(n.get("role"), &format!("{npath}.role"));
                check.nullable_string(n.get("title"), &format!("{npath}.title"));
                check.nullable_string(n.get("value"), &format!("{npath}.value"));
                check.string_array(n.get("actions"), &format!("{npath}.actions"));
                match n.get("children_count") {
                    Some(Value::Null) => {}
                    Some(count) => {
                        check.nonnegative_int(count, &format!("{npath}.children_count"));
                    }
                    None => {}
                }
            }
        }
        None => check.fail(&format!("{path}.nodes"), "expected array"),
    }
    check.bool(map.get("truncated"), &format!("{path}.truncated"));
    match map.get("screenshot") {
        Some(Value::Null) | None => {}
        Some(screenshot) => validate_screenshot(check, screenshot, &format!("{path}.screenshot")),
    }
    check.string_array(map.get("gaps"), &format!("{path}.gaps"));
}

fn validate_screenshot(check: &mut Check, value: &Value, path: &str) {
    let Some(s) = check.object(
        value,
        path,
        &["mime_type", "base64", "sha256", "width", "height"],
    ) else {
        return;
    };
    if s.get("mime_type").and_then(Value::as_str) != Some("image/png") {
        check.fail(&format!("{path}.mime_type"), "expected \"image/png\"");
    }
    let base64 = check.string(s.get("base64"), &format!("{path}.base64"));
    if base64.as_ref().is_some_and(|b| b.chars().count() < 4) {
        check.fail(&format!("{path}.base64"), "too short");
    }
    let sha256 = check.string(s.get("sha256"), &format!("{path}.sha256"));
    if sha256.as_ref().is_some_and(|d| {
        d.len() != 64 || !d.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }) {
        check.fail(&format!("{path}.sha256"), "invalid digest");
    }
    check.positive_int(s.get("width"), &format!("{path}.width"));
    check.positive_int(s.get("height"), &format!("{path}.height"));
    // `superRefine`
    let Some(base64) = base64 else { return };
    let Some(bytes) = decode_canonical_base64(&base64) else {
        check.fail(path, "Invalid canonical PNG base64");
        return;
    };
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if sha256.as_deref() != Some(digest.as_str()) {
        check.fail(path, "PNG screenshot digest mismatch");
    }
    let Some((width, height)) = png_header_dimensions(&bytes) else {
        check.fail(path, "Screenshot bytes are not a PNG image");
        return;
    };
    if s.get("width").and_then(Value::as_f64) != Some(f64::from(width))
        || s.get("height").and_then(Value::as_f64) != Some(f64::from(height))
    {
        check.fail(path, "PNG screenshot dimensions mismatch");
    }
}

/// `decodeCanonicalBase64`.
fn decode_canonical_base64(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % 4 != 0 {
        return None;
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let decoded = engine.decode(value).ok()?;
    (engine.encode(&decoded) == value).then_some(decoded)
}

/// `readPngHeaderDimensions` (`src/domain/pngHeader.ts`).
fn png_header_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    const SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
    if bytes.len() < 24
        || bytes[..8] != SIGNATURE
        || bytes[8..12] != [0, 0, 0, 13]
        || &bytes[12..16] != b"IHDR"
    {
        return None;
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
    let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
    (width != 0 && height != 0 && width <= 0x7fff_ffff && height <= 0x7fff_ffff)
        .then_some((width, height))
}
