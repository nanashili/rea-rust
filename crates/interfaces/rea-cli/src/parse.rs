//! Argv parsing ported from incur's `Parser.parse`.
//!
//! Positional tokens fill the args schema in declaration order (a trailing
//! array key is variadic); `--flag`, `--flag=value`, `--no-flag`, kebab/camel
//! aliases and stacked short flags fill the options schema. Numbers and
//! booleans are coerced from their string tokens before contract validation.
use serde_json::{Map, Value};

/// A fatal argv parse failure (unknown flag, missing value). Surfaces to the
/// caller as the `UNKNOWN` error code, matching incur's `ParseError`.
pub struct ParseFail {
    pub message: String,
}

/// Parsed, uncoerced argv split into positional args and named options.
pub struct Parsed {
    pub args: Value,
    pub options: Value,
}

fn to_kebab(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_uppercase() {
            out.push('-');
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn option_keys(schema: Option<&Value>) -> Vec<String> {
    schema
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .map(|properties| properties.keys().cloned().collect())
        .unwrap_or_default()
}

fn property<'a>(schema: Option<&'a Value>, name: &str) -> Option<&'a Value> {
    schema?.get("properties")?.as_object()?.get(name)
}

fn declared_type(property: &Value) -> Option<&str> {
    property.get("type").and_then(Value::as_str)
}

fn is_boolean(schema: Option<&Value>, name: &str) -> bool {
    property(schema, name).and_then(declared_type) == Some("boolean")
}

fn is_array(schema: Option<&Value>, name: &str) -> bool {
    property(schema, name).and_then(declared_type) == Some("array")
}

/// Normalize a long flag name to its schema key, accepting kebab aliases.
fn normalize_name(raw: &str, known: &[String]) -> Option<String> {
    if known.iter().any(|name| name == raw) {
        return Some(raw.to_owned());
    }
    known.iter().find(|name| to_kebab(name) == raw).cloned()
}

fn set_option(raw: &mut Map<String, Value>, name: &str, value: String, options: Option<&Value>) {
    if is_array(options, name) {
        match raw.get_mut(name) {
            Some(Value::Array(items)) => items.push(Value::String(value)),
            _ => {
                raw.insert(name.to_owned(), Value::Array(vec![Value::String(value)]));
            }
        }
    } else {
        raw.insert(name.to_owned(), Value::String(value));
    }
}

fn alias_to_name(alias: Option<&Value>) -> Vec<(String, String)> {
    alias
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(name, short)| {
                    short.as_str().map(|short| (short.to_owned(), name.clone()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse `argv` against the command's args/options schemas and alias map.
pub fn parse(
    argv: &[String],
    args_schema: Option<&Value>,
    options_schema: Option<&Value>,
    alias: Option<&Value>,
) -> Result<Parsed, ParseFail> {
    let known = option_keys(options_schema);
    let aliases = alias_to_name(alias);
    let short_to_name = |short: &str| {
        aliases
            .iter()
            .find(|(s, _)| s == short)
            .map(|(_, name)| name.clone())
    };

    let mut positionals: Vec<String> = Vec::new();
    let mut raw_options: Map<String, Value> = Map::new();

    let mut index = 0usize;
    while index < argv.len() {
        let token = &argv[index];
        if let Some(rest) = token.strip_prefix("--no-")
            && token.len() > 5
        {
            let name = normalize_name(rest, &known).ok_or_else(|| ParseFail {
                message: format!("Unknown flag: {token}"),
            })?;
            raw_options.insert(name, Value::Bool(false));
            index += 1;
        } else if let Some(rest) = token.strip_prefix("--") {
            if let Some(equals) = rest.find('=') {
                let raw = &rest[..equals];
                let name = normalize_name(raw, &known).ok_or_else(|| ParseFail {
                    message: format!("Unknown flag: --{raw}"),
                })?;
                set_option(
                    &mut raw_options,
                    &name,
                    rest[equals + 1..].to_owned(),
                    options_schema,
                );
                index += 1;
            } else {
                let name = normalize_name(rest, &known).ok_or_else(|| ParseFail {
                    message: format!("Unknown flag: {token}"),
                })?;
                if is_boolean(options_schema, &name) {
                    raw_options.insert(name, Value::Bool(true));
                    index += 1;
                } else {
                    let value = argv.get(index + 1).ok_or_else(|| ParseFail {
                        message: format!("Missing value for flag: {token}"),
                    })?;
                    set_option(&mut raw_options, &name, value.clone(), options_schema);
                    index += 2;
                }
            }
        } else if token.starts_with('-') && token.len() >= 2 {
            let chars: Vec<char> = token[1..].chars().collect();
            for (position, short) in chars.iter().enumerate() {
                let short = short.to_string();
                let name = short_to_name(&short).ok_or_else(|| ParseFail {
                    message: format!("Unknown flag: -{short}"),
                })?;
                let last = position == chars.len() - 1;
                if !last {
                    if is_boolean(options_schema, &name) {
                        raw_options.insert(name, Value::Bool(true));
                    } else {
                        return Err(ParseFail {
                            message: format!(
                                "Non-boolean flag -{short} must be last in a stacked alias"
                            ),
                        });
                    }
                } else if is_boolean(options_schema, &name) {
                    raw_options.insert(name, Value::Bool(true));
                } else {
                    let value = argv.get(index + 1).ok_or_else(|| ParseFail {
                        message: format!("Missing value for flag: -{short}"),
                    })?;
                    set_option(&mut raw_options, &name, value.clone(), options_schema);
                    index += 1;
                }
            }
            index += 1;
        } else {
            positionals.push(token.clone());
            index += 1;
        }
    }

    let mut raw_args: Map<String, Value> = Map::new();
    if let Some(keys) = args_schema
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .map(|properties| properties.keys().cloned().collect::<Vec<_>>())
    {
        for (position, key) in keys.iter().enumerate() {
            if is_array(args_schema, key) {
                let rest: Vec<Value> = positionals[position.min(positionals.len())..]
                    .iter()
                    .map(|value| Value::String(value.clone()))
                    .collect();
                if !rest.is_empty() {
                    raw_args.insert(key.clone(), Value::Array(rest));
                }
                break;
            } else if let Some(value) = positionals.get(position) {
                raw_args.insert(key.clone(), Value::String(value.clone()));
            }
        }
    }

    coerce(&mut raw_options, options_schema);
    coerce(&mut raw_args, args_schema);

    Ok(Parsed {
        args: Value::Object(raw_args),
        options: Value::Object(raw_options),
    })
}

/// Coerce string tokens to the number/boolean types the schema declares.
fn coerce(raw: &mut Map<String, Value>, schema: Option<&Value>) {
    let keys: Vec<String> = raw.keys().cloned().collect();
    for key in keys {
        let Some(property) = property(schema, &key) else {
            continue;
        };
        match declared_type(property) {
            Some("number") | Some("integer") => {
                if let Some(Value::String(text)) = raw.get(&key)
                    && let Some(number) = coerce_number(text)
                {
                    raw.insert(key, number);
                }
            }
            Some("boolean") => {
                if let Some(Value::String(text)) = raw.get(&key) {
                    raw.insert(key, Value::Bool(text == "true"));
                }
            }
            Some("array") => {
                let item_type = property
                    .get("items")
                    .and_then(|items| items.get("type"))
                    .and_then(Value::as_str);
                if matches!(item_type, Some("number") | Some("integer"))
                    && let Some(Value::Array(items)) = raw.get_mut(&key)
                {
                    for item in items.iter_mut() {
                        if let Value::String(text) = item
                            && let Some(number) = coerce_number(text)
                        {
                            *item = number;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn coerce_number(text: &str) -> Option<Value> {
    let parsed: f64 = text.parse().ok()?;
    if !parsed.is_finite() {
        return None;
    }
    if parsed.fract() == 0.0 && parsed.abs() < 9_007_199_254_740_992.0 {
        Some(Value::Number((parsed as i64).into()))
    } else {
        serde_json::Number::from_f64(parsed).map(Value::Number)
    }
}
