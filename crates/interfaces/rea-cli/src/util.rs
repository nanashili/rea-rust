//! Small shared helpers.
use serde_json::{Map, Value};

/// Make a caller-selected path absolute without changing which file it names,
/// mirroring `absoluteCallerPath` (POSIX branch) from `filesystem/callerPath.ts`.
/// Interior `.` segments and repeated separators are removed; every `..` is
/// kept for the filesystem to resolve, and a trailing `/` or `/.` becomes one
/// trailing `/`.
pub fn absolute_caller_path(path: &str) -> String {
    #[cfg(windows)]
    {
        if let Ok(absolute) = std::path::absolute(path) {
            return absolute.to_string_lossy().into_owned();
        }
        return path.to_owned();
    }
    #[cfg(not(windows))]
    {
        let absolute = if path.starts_with('/') {
            path.to_owned()
        } else {
            let cwd = std::env::current_dir()
                .ok()
                .and_then(|dir| dir.to_str().map(str::to_owned))
                .unwrap_or_default();
            format!("{cwd}/{path}")
        };
        let segments: Vec<&str> = absolute
            .split('/')
            .filter(|segment| !segment.is_empty() && *segment != ".")
            .collect();
        let directory =
            (absolute.ends_with('/') || absolute.ends_with("/.")) && !segments.is_empty();
        format!(
            "/{}{}",
            segments.join("/"),
            if directory { "/" } else { "" }
        )
    }
}

/// Build a JSON object from `(key, value)` pairs, preserving insertion order.
pub fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_owned(), value);
    }
    Value::Object(map)
}

/// Merge the fields of `projection` under an `error` label, matching the TS
/// `cliError` envelope `{ error: label, ...projection }`.
pub fn labelled(label: &str, projection: Value) -> Value {
    let mut object = Map::new();
    object.insert("error".to_owned(), Value::String(label.to_owned()));
    if let Some(fields) = projection.as_object() {
        for (key, value) in fields {
            object.insert(key.clone(), value.clone());
        }
    }
    Value::Object(object)
}
