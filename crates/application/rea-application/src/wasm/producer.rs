//! Bounded, read-only WASM inspection through the caller-selected WABT profile.

use rea_core::{
    cancellation::Cancellation,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use rea_host::{fs::stable_file, fs::unix_file::UnixFiles};
use serde_json::{Value, json};
use sha2::Digest;
use std::{
    collections::{BTreeMap, HashSet},
    io::Read,
    path::Path,
    process::{Command, Output, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

pub const OPERATION: &str = "inspect_wasm_artifact";
const MAX_INPUT: usize = 8 * 1024 * 1024;
const MAX_OUTPUT: usize = 32 * 1024 * 1024;
const MAX_ASSOCIATED_PATHS: usize = 16;

pub fn inspect(
    input: &Value,
    cancellation: &Cancellation,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("path", "Expected a path"))?;
    validate_local_path(path, "path")?;
    validate_associated_paths(object, "glue_paths")?;
    validate_associated_paths(object, "candidate_paths")?;
    let root = std::env::var("REA_WABT_BIN_DIRECTORY")
        .map_err(|_| unavailable("REA_WABT_BIN_DIRECTORY is not configured"))?;
    if !Path::new(&root).is_absolute() {
        return Err(unavailable("REA_WABT_BIN_DIRECTORY must be absolute"));
    }
    let access = Arc::new(UnixFiles);
    let snapshot = stable_file::read(access, Path::new(path), MAX_INPUT, cancellation)
        .map_err(|_| invalid("path", "Unable to read a stable regular WASM file"))?;
    if snapshot.bytes.len() < 8 || &snapshot.bytes[..4] != b"\0asm" {
        return Err(invalid(
            "path",
            "Selected bytes are not a WebAssembly module",
        ));
    }
    let mut tools = Vec::new();
    for tool in ["wasm-validate", "wasm-objdump", "wasm2wat"] {
        let executable = Path::new(&root).join(tool);
        let version = run_command(&executable, &["--version"], cancellation)?;
        let banner = String::from_utf8_lossy(&version.stdout).into_owned();
        if banner.trim() != "1.0.42" || !version.stderr.is_empty() {
            return Err(unavailable_at(
                &executable,
                "Configured WABT must report version 1.0.42",
            ));
        }
        let tool_bytes = std::fs::read(&executable).map_err(|_| {
            unavailable_at(&executable, "Configured WABT executable could not be read")
        })?;
        tools.push((
            tool.to_owned(),
            executable.to_string_lossy().into_owned(),
            banner,
            sha256_hex(&tool_bytes),
        ));
    }
    let validate = run_command(
        Path::new(&tools[0].1),
        &["--enable-all", path],
        cancellation,
    )?;
    verify_tool(&tools[0].1, &tools[0].3)?;
    verify_snapshot(path, &snapshot.sha256, cancellation)?;
    enforce_output_budget(&validate)?;
    if !validate.status.success() {
        return Err(invalid(
            "path",
            "Selected bytes failed WABT validation with --enable-all",
        ));
    }
    let wat = run_command(
        Path::new(&tools[2].1),
        &["--enable-all", path],
        cancellation,
    )?;
    verify_tool(&tools[2].1, &tools[2].3)?;
    verify_snapshot(path, &snapshot.sha256, cancellation)?;
    enforce_output_budget(&wat)?;
    if !wat.status.success() || !wat.stderr.is_empty() {
        return Err(unavailable_at(
            Path::new(&tools[2].1),
            "WABT returned an invalid decoded WAT response",
        ));
    }
    let wat_text = String::from_utf8_lossy(&wat.stdout).into_owned();
    let objdump = run_command(Path::new(&tools[1].1), &["-h", "-x", path], cancellation)?;
    verify_tool(&tools[1].1, &tools[1].3)?;
    verify_snapshot(path, &snapshot.sha256, cancellation)?;
    enforce_output_budget(&objdump)?;
    if !objdump.status.success() || !objdump.stderr.is_empty() {
        return Err(unavailable_at(
            Path::new(&tools[1].1),
            "WABT returned invalid section output",
        ));
    }
    if wat_text.len().saturating_add(objdump.stdout.len()) > MAX_OUTPUT {
        return Err(resource());
    }
    let forms = extract_module_forms(&wat_text).map_err(|_| {
        unavailable_at(
            Path::new(&tools[2].1),
            "WABT returned malformed decoded WAT forms",
        )
    })?;
    let interface = decode_wabt_interface(&forms).map_err(|_| resource())?;
    let (sections, headers, details) =
        parse_wabt_output(&objdump.stdout, snapshot.bytes.len(), &wat_text).map_err(|_| {
            unavailable_at(
                Path::new(&tools[1].1),
                "WABT returned malformed section output",
            )
        })?;
    let imports = forms
        .iter()
        .filter(|form| form.raw.trim_start().starts_with("(import "))
        .map(|form| form.raw.clone())
        .collect::<Vec<_>>();
    let exports = forms
        .iter()
        .filter(|form| form.raw.trim_start().starts_with("(export "))
        .map(|form| form.raw.clone())
        .collect::<Vec<_>>();
    let candidates = candidate_artifacts(
        object,
        path,
        &snapshot.sha256,
        snapshot.bytes.len(),
        cancellation,
    )?;
    let glue = glue_artifacts(object, &candidates, cancellation)?;
    let report = json!({
        "artifact":{"path":path,"sha256":snapshot.sha256,"bytes":snapshot.bytes.len()},
        "validation":"valid","sections":sections,"interface":interface,
        "imports":imports,"exports":exports,"headers":headers,"details":details,
        "wat":{"text":wat_text,"sha256":sha256_hex(&wat.stdout),"representation":"decoded-wat"},
        "tool_profile":{"source":"https://github.com/WebAssembly/wabt","release":"1.0.42","source_commit":"ff0ef7e0009402740c805a9744c09b05be063e48","commands":tools.iter().map(|(tool,path,banner,sha256)| json!({"tool":tool,"path":path,"sha256":sha256,"version_banner":banner,"arguments":if tool=="wasm-objdump" {json!(["-h","-x","module.wasm"])} else {json!(["--enable-all","module.wasm"])} })).collect::<Vec<_>>(),"timeout_ms":30000,"output_budget_bytes":MAX_OUTPUT},
        "candidates":candidates,"glue":glue,"runtime_execution":"not-performed","network_fetch":"not-performed","limitations":[
            "WAT is a decoded representation, not original source or proof of runtime behavior. Custom annotations may retain payloads, but WAT does not establish original binary layout or round-trip byte identity. Original bytes and objdump output remain authoritative.",
            "Imports and exports retain exact top-level WABT WAT forms. Names remain escaped producer text; unescaped objdump display names are not parsed as unambiguous identifiers.",
            "JavaScript references are AST-observed static literals only. Candidate matches are associations, not proven data flow, URL-to-file identity or runtime loading. Computed references and aliases are not resolved.",
            "No target execution or implicit fetch. WABT tools are trusted caller-supplied executables; SHA-256 identifies their bytes, not publisher authenticity. No OS memory sandbox is claimed.",
            "Each subprocess has a 30-second deadline and 32 MiB combined output budget. Oversized output fails instead of producing truncated success."
        ]
    });
    let unsigned = json!({"subject":{"path":path,"format":"file","sha256":snapshot.sha256},"provider":{"id":"wabt-artifact","name":"REA WABT artifact adapter","version":"wabt@1.0.42"},"analysis_profile":null,"predicate_type":"rea.wasm-artifact","operation":OPERATION,"parameters":object,"raw_result":null,"normalized_result":report,"confidence":"observed","authority":"shipped-artifact","environment":null,"limitations":[],"relationship_coverage":null,"locations":[{"kind":"artifact-path","path":path}],"evidence_links":[]});
    let raw = serde_json::value::to_raw_value(&unsigned)
        .map_err(|e| invalid("result", &e.to_string()))?;
    let evidence =
        EvidenceRecord::create_unsigned(&raw).map_err(|e| invalid("result", &e.to_string()))?;
    Ok(serde_json::value::RawValue::from_string(evidence.raw().get().to_owned()).unwrap())
}

fn validate_local_path(path: &str, field: &str) -> Result<(), Failure> {
    if path.is_empty() || !Path::new(path).is_absolute() {
        return Err(invalid(field, "Expected an absolute local path"));
    }

    Ok(())
}

fn validate_associated_paths(
    input: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    let Some(value) = input.get(field) else {
        return Ok(());
    };
    let paths = value
        .as_array()
        .ok_or_else(|| invalid(field, "Expected an array of paths"))?;
    if paths.len() > MAX_ASSOCIATED_PATHS {
        return Err(invalid(
            field,
            "Too many associated paths; the maximum is 16",
        ));
    }
    for path in paths {
        let path = path
            .as_str()
            .ok_or_else(|| invalid(field, "Expected an array of paths"))?;
        validate_local_path(path, field)?;
    }

    Ok(())
}

fn verify_snapshot(
    path: &str,
    expected_hash: &str,
    cancellation: &Cancellation,
) -> Result<(), Failure> {
    let current = stable_file::read(
        Arc::new(UnixFiles),
        Path::new(path),
        MAX_INPUT,
        cancellation,
    )
    .map_err(|_| invalid("path", "Selected WASM file changed or could not be reread"))?;
    if current.sha256 != expected_hash {
        return Err(invalid(
            "path",
            "Selected WASM file changed during WABT inspection",
        ));
    }
    Ok(())
}

fn verify_tool(path: &str, expected_hash: &str) -> Result<(), Failure> {
    let bytes = std::fs::read(path).map_err(|_| {
        unavailable_at(
            Path::new(path),
            "Configured WABT executable could not be reread",
        )
    })?;
    if sha256_hex(&bytes) != expected_hash {
        return Err(unavailable_at(
            Path::new(path),
            "Configured WABT executable changed during inspection",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
enum WatNode {
    Atom(String),
    String(String),
    List(Vec<WatNode>),
}

#[derive(Clone, Debug)]
struct WatForm {
    raw: String,
    node: WatNode,
}

#[derive(Clone, Debug)]
struct Definition {
    label: Option<String>,
    signature: Option<Value>,
}

const INTERFACE_KINDS: [&str; 5] = ["func", "table", "memory", "global", "tag"];
const MAX_INTERFACE_ENTRIES: usize = 10_000;
const MAX_INTERFACE_REPRESENTATION: usize = 32 * 1024 * 1024;
const VALUE_TYPES: [&str; 7] = ["i32", "i64", "f32", "f64", "v128", "funcref", "externref"];

fn extract_module_forms(wat: &str) -> Result<Vec<WatForm>, ()> {
    if !wat.trim_start().starts_with("(module") {
        return Err(());
    }
    let bytes = wat.as_bytes();
    let mut depth = 0usize;
    let mut closed = false;
    let mut form_start = None;
    let mut quote = false;
    let mut line_comment = false;
    let mut block_comment = 0usize;
    let mut forms = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if line_comment {
            if bytes[index] == b'\n' {
                line_comment = false;
            }
            index += 1;
            continue;
        }
        if block_comment > 0 {
            if bytes.get(index..index + 2) == Some(b"(;") {
                block_comment += 1;
                index += 2;
            } else if bytes.get(index..index + 2) == Some(b";)") {
                block_comment -= 1;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if quote {
            if bytes[index] == b'\\' {
                index = index.saturating_add(2);
            } else {
                quote = bytes[index] != b'"';
                index += 1;
            }
            continue;
        }
        if bytes.get(index..index + 2) == Some(b";;") {
            line_comment = true;
            index += 2;
        } else if bytes.get(index..index + 2) == Some(b"(;") {
            block_comment = 1;
            index += 2;
        } else if bytes[index] == b'"' {
            quote = true;
            index += 1;
        } else if bytes[index] == b'(' {
            if closed {
                return Err(());
            }
            if depth == 1 {
                form_start = Some(index);
            }
            depth += 1;
            index += 1;
        } else if bytes[index] == b')' {
            if depth == 0 {
                return Err(());
            }
            depth -= 1;
            if depth == 1 {
                let start = form_start.take().ok_or(())?;
                let raw = wat[start..=index].to_owned();
                forms.push(WatForm {
                    node: parse_node(&raw).ok_or(())?,
                    raw,
                });
            }
            if depth == 0 {
                closed = true;
            }
            index += 1;
        } else {
            if closed && !bytes[index].is_ascii_whitespace() {
                return Err(());
            }
            index += 1;
        }
    }
    if depth != 0 || quote || block_comment != 0 || !closed {
        return Err(());
    }
    Ok(forms)
}

fn parse_node(text: &str) -> Option<WatNode> {
    let mut parser = WatParser {
        bytes: text.as_bytes(),
        index: 0,
    };
    let node = parser.node()?;
    parser.skip_space();
    (parser.index == parser.bytes.len()).then_some(node)
}

struct WatParser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl WatParser<'_> {
    fn skip_space(&mut self) {
        loop {
            while self
                .bytes
                .get(self.index)
                .is_some_and(u8::is_ascii_whitespace)
            {
                self.index += 1;
            }
            if self.bytes.get(self.index..self.index + 2) == Some(b";;") {
                self.index += 2;
                while self.index < self.bytes.len() && self.bytes[self.index] != b'\n' {
                    self.index += 1;
                }
                continue;
            }
            if self.bytes.get(self.index..self.index + 2) != Some(b"(;") {
                break;
            }
            let mut depth = 1usize;
            self.index += 2;
            while self.index < self.bytes.len() && depth > 0 {
                if self.bytes.get(self.index..self.index + 2) == Some(b"(;") {
                    depth += 1;
                    self.index += 2;
                } else if self.bytes.get(self.index..self.index + 2) == Some(b";)") {
                    depth -= 1;
                    self.index += 2;
                } else {
                    self.index += 1;
                }
            }
        }
    }

    fn node(&mut self) -> Option<WatNode> {
        self.skip_space();
        match *self.bytes.get(self.index)? {
            b'(' => {
                self.index += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_space();
                    match self.bytes.get(self.index) {
                        Some(b')') => {
                            self.index += 1;
                            return Some(WatNode::List(items));
                        }
                        Some(_) => items.push(self.node()?),
                        None => return None,
                    }
                }
            }
            b'"' => self.string().map(WatNode::String),
            _ => {
                let start = self.index;
                while self.bytes.get(self.index).is_some_and(|byte| {
                    !byte.is_ascii_whitespace() && *byte != b')' && *byte != b'('
                }) {
                    self.index += 1;
                }
                (self.index > start).then(|| {
                    WatNode::Atom(
                        String::from_utf8_lossy(&self.bytes[start..self.index]).into_owned(),
                    )
                })
            }
        }
    }

    fn string(&mut self) -> Option<String> {
        self.index += 1;
        let mut output = Vec::new();
        while let Some(byte) = self.bytes.get(self.index).copied() {
            self.index += 1;
            if byte == b'"' {
                return String::from_utf8(output).ok();
            }
            if byte != b'\\' {
                output.push(byte);
                continue;
            }
            let first = *self.bytes.get(self.index)?;
            if self
                .bytes
                .get(self.index + 1)
                .is_some_and(|byte| byte.is_ascii_hexdigit())
                && first.is_ascii_hexdigit()
            {
                let second = self.bytes[self.index + 1];
                output.push((hex(first)? << 4) | hex(second)?);
                self.index += 2;
            } else {
                output.push(match first {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'"' => b'"',
                    b'\\' => b'\\',
                    _ => return None,
                });
                self.index += 1;
            }
        }
        None
    }
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn atom(node: &WatNode) -> Option<&str> {
    match node {
        WatNode::Atom(value) => Some(value),
        _ => None,
    }
}

fn list(node: &WatNode) -> Option<&[WatNode]> {
    match node {
        WatNode::List(items) => Some(items),
        _ => None,
    }
}

fn head(node: &WatNode) -> Option<&str> {
    list(node)?.first().and_then(atom)
}

fn integer(value: &str) -> Option<String> {
    let parsed = if let Some(hex_value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex_value, 16).ok()?
    } else {
        value.parse::<u64>().ok()?
    };
    Some(parsed.to_string())
}

fn values(form: &WatNode, category: &str) -> Option<Vec<String>> {
    let mut result = Vec::new();
    for item in list(form)?.iter().skip(1) {
        let group = list(item)?;
        if group.first().and_then(atom) != Some(category) {
            continue;
        }
        for value in group.iter().skip(1).filter_map(atom) {
            if value.starts_with('$') {
                continue;
            }
            if !VALUE_TYPES.contains(&value) {
                return None;
            }
            result.push(value.to_owned());
        }
    }
    Some(result)
}

fn function_signature(form: &WatNode, kind: &str) -> Option<Value> {
    Some(json!({
        "kind": kind,
        "params": values(form, "param")?,
        "results": values(form, "result")?,
    }))
}

fn typed_signature(
    form: &WatNode,
    type_signatures: &[Option<Value>],
    type_names: &BTreeMap<String, usize>,
    recursive_types: bool,
) -> Option<Value> {
    let parts = list(form)?;
    let kind = atom(parts.first()?)?;
    match kind {
        "func" | "tag" => {
            let reference = parts.iter().skip(1).find_map(|item| {
                let group = list(item)?;
                (group.first().and_then(atom) == Some("type"))
                    .then(|| group.get(1))?
                    .and_then(|node| atom(node))
            });
            let signature = match reference {
                None => function_signature(form, kind),
                Some(reference) if recursive_types => None,
                Some(reference) => {
                    let index = reference
                        .strip_prefix('$')
                        .and_then(|name| type_names.get(&format!("${name}")))
                        .copied()
                        .or_else(|| reference.parse::<usize>().ok());
                    type_signatures.get(index?)?.clone()
                }
            }?;
            (signature.get("kind").and_then(Value::as_str) == Some("func")).then(|| {
                let mut signature = signature;
                signature["kind"] = Value::String(kind.to_owned());
                signature
            })
        }
        "memory" | "table" => {
            let mut page_size = "65536".to_owned();
            for group in parts.iter().skip(1).filter(|item| list(item).is_some()) {
                let declaration = list(group)?;
                if kind != "memory"
                    || declaration.len() != 2
                    || atom(declaration.first()?)? != "pagesize"
                {
                    return None;
                }
                page_size = integer(atom(declaration.get(1)?)?)?;
            }
            let mut tokens = parts
                .iter()
                .skip(1)
                .filter_map(atom)
                .filter(|token| !token.starts_with('$'))
                .collect::<Vec<_>>();
            let address_type = if matches!(tokens.first(), Some(&"i64")) {
                tokens.remove(0);
                "i64"
            } else {
                if matches!(tokens.first(), Some(&"i32")) {
                    tokens.remove(0);
                }
                "i32"
            };
            let minimum = integer(tokens.first().copied()?)?;
            tokens.remove(0);
            let maximum_token = tokens.first().copied();
            let maximum = maximum_token.and_then(integer);
            if maximum.is_some() {
                tokens.remove(0);
            }
            let shared = tokens.first().copied() == Some("shared");
            if shared {
                tokens.remove(0);
            }
            if kind == "memory" && !tokens.is_empty() {
                return None;
            }
            if kind == "memory" {
                Some(
                    json!({"kind":kind,"page_size":page_size,"address_type":address_type,"minimum":minimum,"maximum":maximum,"shared":shared}),
                )
            } else {
                let element = tokens.first().copied()?;
                if !matches!(element, "funcref" | "externref") || tokens.len() != 1 {
                    return None;
                }
                Some(
                    json!({"kind":kind,"address_type":address_type,"minimum":minimum,"maximum":maximum,"shared":shared,"element":element}),
                )
            }
        }
        "global" => {
            let declaration = parts.get(1).and_then(|node| {
                if atom(node).is_some_and(|value| value.starts_with('$')) {
                    parts.get(2)
                } else {
                    Some(node)
                }
            })?;
            let declaration_parts = list(declaration);
            let (value_type, mutable) = if let Some(group) = declaration_parts {
                (atom(group.get(1)?)?, true)
            } else {
                (atom(declaration)?, false)
            };
            VALUE_TYPES
                .contains(&value_type)
                .then(|| json!({"kind":kind,"value_type":value_type,"mutable":mutable}))
        }
        _ => None,
    }
}

fn add_definition(
    node: &WatNode,
    definitions: &mut BTreeMap<String, Vec<Definition>>,
    type_signatures: &[Option<Value>],
    type_names: &BTreeMap<String, usize>,
    recursive_types: bool,
) -> (usize, String, Option<Value>) {
    let raw_kind = head(node).unwrap_or("unknown");
    let kind = if INTERFACE_KINDS.contains(&raw_kind) {
        raw_kind
    } else {
        "unknown"
    };
    let label = list(node)
        .and_then(|parts| parts.get(1))
        .and_then(atom)
        .filter(|value| value.starts_with('$'))
        .map(str::to_owned);
    let signature = typed_signature(node, type_signatures, type_names, recursive_types);
    let space = definitions.entry(kind.to_owned()).or_default();
    let index = space.len();
    space.push(Definition {
        label,
        signature: signature.clone(),
    });
    (index, kind.to_owned(), signature)
}

fn decode_wabt_interface(forms: &[WatForm]) -> Result<Value, ()> {
    let recursive_types = forms.iter().any(|form| head(&form.node) == Some("rec"));
    let mut type_signatures = Vec::new();
    let mut type_names = BTreeMap::new();
    for form in forms.iter().filter(|form| head(&form.node) == Some("type")) {
        let parts = list(&form.node).ok_or(())?;
        if let Some(name) = parts
            .get(1)
            .and_then(atom)
            .filter(|value| value.starts_with('$'))
        {
            type_names.insert(name.to_owned(), type_signatures.len());
        }
        let body = parts.iter().find(|item| list(item).is_some());
        type_signatures.push(body.and_then(|body| {
            (!recursive_types && head(body) == Some("func"))
                .then(|| function_signature(body, "func"))?
        }));
    }
    let mut definitions: BTreeMap<String, Vec<Definition>> = BTreeMap::new();
    let mut entries = Vec::new();
    let mut representation = 0usize;
    for form in forms
        .iter()
        .filter(|form| head(&form.node) == Some("import"))
    {
        if entries.len() >= MAX_INTERFACE_ENTRIES {
            return Ok(partial_interface(
                &entries,
                "Typed interface entry count reached its bounded capacity",
            ));
        }
        let parts = list(&form.node).ok_or(())?;
        let module = match parts.get(1) {
            Some(WatNode::String(value)) => value.clone(),
            _ => return Err(()),
        };
        let name = match parts.get(2) {
            Some(WatNode::String(value)) => value.clone(),
            _ => return Err(()),
        };
        let body = parts.get(3).ok_or(())?;
        let (index, kind, signature) = add_definition(
            body,
            &mut definitions,
            &type_signatures,
            &type_names,
            recursive_types,
        );
        entries.push(json!({"direction":"import","module":module,"name":name,"kind":kind,"index":index,"signature":signature,"wat_form":form.raw,"issue":if signature.is_some(){Value::Null}else{json!("Import type is outside admitted core signature semantics")}}));
        representation = representation.saturating_add(1024 + form.raw.len().saturating_mul(6));
        if representation > MAX_INTERFACE_REPRESENTATION {
            return Ok(partial_interface(
                &entries,
                "Typed interface representation reached its bounded capacity",
            ));
        }
    }
    for form in forms
        .iter()
        .filter(|form| INTERFACE_KINDS.contains(&head(&form.node).unwrap_or("")))
    {
        if entries.len() >= MAX_INTERFACE_ENTRIES {
            return Ok(partial_interface(
                &entries,
                "Typed interface entry count reached its bounded capacity",
            ));
        }
        add_definition(
            &form.node,
            &mut definitions,
            &type_signatures,
            &type_names,
            recursive_types,
        );
    }
    for form in forms
        .iter()
        .filter(|form| head(&form.node) == Some("export"))
    {
        let parts = list(&form.node).ok_or(())?;
        let name = match parts.get(1) {
            Some(WatNode::String(value)) => value.clone(),
            _ => return Err(()),
        };
        let descriptor = list(parts.get(2).ok_or(())?).ok_or(())?;
        let kind = atom(descriptor.first().ok_or(())?).unwrap_or("unknown");
        let kind = if INTERFACE_KINDS.contains(&kind) {
            kind
        } else {
            "unknown"
        };
        let reference = descriptor.get(1).and_then(atom);
        let observed_index = reference.and_then(|reference| {
            let space = definitions.get(kind)?;
            if let Some(label) = reference.strip_prefix('$') {
                space.iter().position(|definition| {
                    definition.label.as_deref() == Some(&format!("${label}"))
                })
            } else {
                reference.parse::<usize>().ok()
            }
        });
        let signature =
            observed_index.and_then(|index| definitions.get(kind)?.get(index)?.signature.clone());
        entries.push(json!({"direction":"export","module":Value::Null,"name":name,"kind":kind,"index":observed_index,"signature":signature,"wat_form":form.raw,"issue":if signature.is_some(){Value::Null}else{json!("Export type/index is outside admitted core signature semantics")}}));
        representation = representation.saturating_add(1024 + form.raw.len().saturating_mul(6));
        if representation > MAX_INTERFACE_REPRESENTATION {
            return Ok(partial_interface(
                &entries,
                "Typed interface representation reached its bounded capacity",
            ));
        }
    }
    Ok(json!({"state":"complete","entries":entries,"issues":[]}))
}

fn partial_interface(entries: &[Value], issue: &str) -> Value {
    json!({"state":"partial","entries":entries,"issues":[issue]})
}

fn candidate_artifacts(
    input: &serde_json::Map<String, Value>,
    selected: &str,
    selected_hash: &str,
    selected_bytes: usize,
    cancellation: &Cancellation,
) -> Result<Vec<Value>, Failure> {
    let mut paths = vec![selected.to_owned()];
    if let Some(values) = input.get("candidate_paths").and_then(Value::as_array) {
        paths.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for path in paths {
        if !seen.insert(path.clone()) {
            continue;
        }
        if cancellation.reason().is_some() {
            return Err(cancelled());
        }
        if path == selected {
            result.push(json!({"path":path,"sha256":selected_hash,"bytes":selected_bytes}));
            continue;
        }
        let snapshot = stable_file::read(
            Arc::new(UnixFiles),
            Path::new(&path),
            MAX_INPUT,
            cancellation,
        )
        .map_err(|_| {
            invalid(
                "candidate_paths",
                "Unable to read a stable candidate artifact",
            )
        })?;
        result.push(json!({"path":path,"sha256":snapshot.sha256,"bytes":snapshot.bytes.len()}));
    }
    Ok(result)
}
fn glue_artifacts(
    input: &serde_json::Map<String, Value>,
    candidates: &[Value],
    cancellation: &Cancellation,
) -> Result<Vec<Value>, Failure> {
    let candidate_paths: Vec<String> = candidates
        .iter()
        .filter_map(|v| v.get("path").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let mut result = Vec::new();
    if let Some(values) = input.get("glue_paths").and_then(Value::as_array) {
        for path in values.iter().filter_map(Value::as_str) {
            if cancellation.reason().is_some() {
                return Err(cancelled());
            }
            let snapshot = stable_file::read(
                Arc::new(UnixFiles),
                Path::new(path),
                MAX_INPUT,
                cancellation,
            )
            .map_err(|_| invalid("glue_paths", "Unable to read a stable glue artifact"))?;
            let source = String::from_utf8(snapshot.bytes.clone())
                .map_err(|_| invalid("glue_paths", "Glue artifact is not UTF-8"))?;
            let references = collect_glue_references(path, &source, &candidate_paths);
            let parse_status = glue_parse_status(&source);
            result.push(json!({"artifact":{"path":path,"sha256":snapshot.sha256,"bytes":snapshot.bytes.len()},"parse_status":parse_status,"references":references}));
        }
    }
    Ok(result)
}

fn collect_glue_references(
    glue_path: &str,
    source: &str,
    candidate_paths: &[String],
) -> Vec<Value> {
    let mut references = Vec::new();

    for (line_index, line) in source.lines().enumerate() {
        for (column, raw_value) in quoted_glue_literals(line) {
            let value = decode_glue_literal(&raw_value);
            let wasm_value = value.split(['?', '#']).next().unwrap_or(value.as_str());
            if !wasm_value.to_ascii_lowercase().ends_with(".wasm") {
                continue;
            }

            let local_target = local_glue_target(glue_path, &value);
            let local_matches: Vec<String> = candidate_paths
                .iter()
                .filter(|candidate| {
                    local_target
                        .as_deref()
                        .is_some_and(|target| normalize_absolute_path(candidate) == target)
                })
                .cloned()
                .collect();

            let basename = wasm_value.rsplit(['/', '\\']).next().unwrap_or(wasm_value);
            let matches = matching_glue_candidates(candidate_paths, &local_matches, basename);
            let association = glue_association(&local_matches, &matches);

            references.push(json!({
                "value": value,
                "line": line_index + 1,
                "column": column,
                "candidate_paths": matches,
                "association": association,
                "evidence_kind": "static-literal"
            }));
        }
    }

    references
}

fn matching_glue_candidates(
    candidate_paths: &[String],
    local_matches: &[String],
    basename: &str,
) -> Vec<String> {
    if !local_matches.is_empty() {
        return local_matches.to_vec();
    }

    candidate_paths
        .iter()
        .filter(|candidate| candidate.rsplit(['/', '\\']).next() == Some(basename))
        .cloned()
        .collect()
}

fn glue_association(local_matches: &[String], matches: &[String]) -> &'static str {
    if !local_matches.is_empty() {
        "local-path-candidate"
    } else if matches.is_empty() {
        "unresolved"
    } else {
        "basename-candidates"
    }
}

fn quoted_glue_literals(line: &str) -> Vec<(usize, String)> {
    let mut literals = Vec::new();
    let mut cursor = 0usize;
    while let Some((start, delimiter)) = line[cursor..]
        .char_indices()
        .find(|(_, character)| matches!(character, '\'' | '"' | '`'))
    {
        let start = cursor + start;
        let mut end = start + delimiter.len_utf8();
        let mut escaped = false;
        while end < line.len() {
            let character = line[end..]
                .chars()
                .next()
                .expect("valid character boundary");
            end += character.len_utf8();
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                literals.push((
                    start,
                    line[start + delimiter.len_utf8()..end - delimiter.len_utf8()].to_owned(),
                ));
                break;
            }
        }
        cursor = end.max(start + delimiter.len_utf8());
    }
    literals
}

fn local_glue_target(glue_path: &str, value: &str) -> Option<String> {
    if value.starts_with('/')
        || value.starts_with("\\\\")
        || value.contains('?')
        || value.contains('#')
        || has_uri_scheme(value)
    {
        return None;
    }
    let parent = Path::new(glue_path).parent()?.to_string_lossy();
    Some(normalize_absolute_path(&format!("{parent}/{value}")))
}

fn has_uri_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    !scheme.is_empty()
        && scheme.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || character == '+'
                || character == '-'
                || character == '.'
        })
}

fn normalize_absolute_path(path: &str) -> String {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect::<Vec<_>>();
    format!("/{}", segments.join("/"))
}

fn decode_glue_literal(raw: &str) -> String {
    let mut decoded = String::with_capacity(raw.len());
    let mut characters = raw.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        match characters.next() {
            Some('n') => decoded.push('\n'),
            Some('r') => decoded.push('\r'),
            Some('t') => decoded.push('\t'),
            Some('\\') => decoded.push('\\'),
            Some(quote @ ('\'' | '"' | '`')) => decoded.push(quote),
            Some('x') => {
                let digits = characters.by_ref().take(2).collect::<String>();
                match decode_hex(&digits).and_then(char::from_u32) {
                    Some(value) => decoded.push(value),
                    None => {
                        decoded.push('\\');
                        decoded.push('x');
                        decoded.push_str(&digits);
                    }
                }
            }
            Some('u') => {
                let mut digits = String::new();
                if characters.clone().next() == Some('{') {
                    characters.next();
                    for character in characters.by_ref() {
                        if character == '}' {
                            break;
                        }
                        digits.push(character);
                    }
                } else {
                    digits = characters.by_ref().take(4).collect();
                }
                match decode_unicode_escape(&digits) {
                    Some(value) => decoded.push(value),
                    None => {
                        decoded.push('\\');
                        decoded.push('u');
                        if !digits.is_empty() {
                            decoded.push_str(&digits);
                        }
                    }
                }
            }
            Some(other) => {
                decoded.push('\\');
                decoded.push(other);
            }
            None => decoded.push('\\'),
        }
    }
    decoded
}

fn decode_hex(digits: &str) -> Option<u32> {
    if digits.is_empty() {
        return None;
    }

    u32::from_str_radix(digits, 16).ok()
}

fn decode_unicode_escape(digits: &str) -> Option<char> {
    char::from_u32(decode_hex(digits)?)
}

fn glue_parse_status(source: &str) -> &'static str {
    let mut stack = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut line_comment = false;
    let mut block_comment = false;
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if line_comment {
            if byte == b'\n' {
                line_comment = false;
            }
            index += 1;
            continue;
        }
        if block_comment {
            if bytes.get(index..index + 2) == Some(b"*/") {
                block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
            index += 1;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"//") {
            line_comment = true;
            index += 2;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"/*") {
            block_comment = true;
            index += 2;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
        } else if matches!(byte, b'{' | b'[' | b'(') {
            stack.push(byte);
        } else if matches!(byte, b'}' | b']' | b')') {
            let expected = match byte {
                b'}' => b'{',
                b']' => b'[',
                _ => b'(',
            };
            if stack.pop() != Some(expected) {
                return "failed";
            }
        }
        index += 1;
    }
    if quote.is_some() || block_comment || !stack.is_empty() {
        "partial"
    } else {
        "complete"
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_INTERFACE_ENTRIES, candidate_artifacts, decode_glue_literal, decode_wabt_interface,
        extract_module_forms, glue_parse_status, local_glue_target, parse_wabt_output,
        quoted_glue_literals, validate_associated_paths, validate_local_path, verify_tool,
    };
    use rea_core::cancellation::Cancellation;
    use serde_json::{Value, json};

    fn decode(wat: &str) -> serde_json::Value {
        let forms = extract_module_forms(wat).expect("valid WAT forms");
        decode_wabt_interface(&forms).expect("typed interface")
    }

    #[test]
    fn resolves_typed_imports_and_exports() {
        let report = decode(
            r#"(module
                (type (;0;) (func (param i32) (result i64)))
                (import "a\22b" "f" (func (;0;) (type 0)))
                (func (;1;) (type 0))
                (export "" (func 1)))"#,
        );
        assert_eq!(report["entries"][0]["module"], "a\"b");
        assert_eq!(report["entries"][0]["signature"]["params"][0], "i32");
        assert_eq!(report["entries"][1]["index"], 1);
        assert_eq!(report["entries"][1]["signature"]["results"][0], "i64");
    }

    #[test]
    fn decodes_memory_table_global_and_tag_signatures() {
        let report = decode(
            r#"(module
                (import "env" "table" (table 1 3 funcref))
                (memory i64 2 4 shared)
                (global (mut i64) (i64.const 1))
                (tag (type 0))
                (type (func (param i32)))
                (export "memory" (memory 0))
                (export "global" (global 0)))"#,
        );
        assert_eq!(report["entries"][0]["signature"]["kind"], "table");
        assert_eq!(report["entries"][1]["signature"]["address_type"], "i64");
        assert_eq!(report["entries"][2]["signature"]["mutable"], true);
        assert_eq!(report["entries"][3]["signature"], serde_json::Value::Null);
    }

    #[test]
    fn preserves_unknown_signatures_for_unsupported_types_and_bad_indices() {
        let report = decode(
            r#"(module
                (func (param (ref null 1)))
                (memory 1 (future-proposal 0))
                (export "bad" (func 99))
                (export "future" (memory 0)))"#,
        );
        assert!(
            report["entries"]
                .as_array()
                .expect("entries")
                .iter()
                .all(|entry| entry["signature"].is_null())
        );
        assert!(report["entries"][0]["issue"].is_string());
    }

    #[test]
    fn skips_nested_and_line_comments_without_losing_forms() {
        let forms = extract_module_forms(
            "(module ;; comment\n (import \"env\" \"f\" (; nested (; comment ;) ;) (func)))",
        )
        .expect("comments are valid WAT");
        assert_eq!(forms.len(), 1);
        assert!(forms[0].raw.starts_with("(import"));
    }

    #[test]
    fn rejects_non_module_and_trailing_wat_output() {
        assert!(extract_module_forms("(instance)").is_err());
        assert!(extract_module_forms("(module) trailing").is_err());
        assert!(extract_module_forms("(module (func)").is_err());
    }

    #[test]
    fn decodes_objdump_section_facts_and_rejects_bad_ranges() {
        let dump = b"\nmodule.wasm:\tfile format wasm 0x1\n\nSections:\n\n     Type start=0x0000000a end=0x0000000c (size=0x00000002) count: 1\n     Custom start=0x0000000e end=0x00000010 (size=0x00000002) \"test\"\n\nSection Details:\n";
        let wat = "(module (@custom \"test\" \"payload\"))";
        let (sections, headers, details) = parse_wabt_output(dump, 0x10, wat).expect("valid dump");
        assert_eq!(sections[0]["kind"], "Type");
        assert_eq!(sections[1]["description"], "\"test\"");
        assert!(headers.contains("Sections:"));
        assert!(details.starts_with("module.wasm:\tfile format wasm 0x1"));
        assert!(details.contains("\nSection Details:"));

        let malformed = String::from_utf8_lossy(dump).replace("end=0x00000010", "end=0x00000011");
        assert!(parse_wabt_output(malformed.as_bytes(), 0x10, wat).is_err());
    }

    #[test]
    fn rejects_section_output_with_an_unexpected_wabt_preamble() {
        let dump = b"\nother.wasm:\tfile format wasm 0x1\n\nSections:\n\n     Type start=0x0000000a end=0x0000000c (size=0x00000002) count: 1\n\nSection Details:\n";
        assert!(parse_wabt_output(dump, 0x0c, "(module)").is_err());
    }

    #[test]
    fn matches_custom_names_using_wabt_display_termination() {
        let dump = b"\nmodule.wasm:\tfile format wasm 0x1\n\nSections:\n\n     Custom start=0x0000000a end=0x0000000c (size=0x00000002) \"test\"\n\nSection Details:\n";
        let wat = "(module (@custom \"test\\00hidden\" \"payload\"))";
        let (sections, _, _) = parse_wabt_output(dump, 0x0c, wat).expect("displayed name");
        assert_eq!(sections[0]["description"], "\"test\"");
    }

    #[test]
    fn validates_decoded_name_section_module_headers() {
        let dump = b"\nmodule.wasm:\tfile format wasm 0x1\nmodule name: <demo>\n\nSections:\n\n     Type start=0x0000000a end=0x0000000c (size=0x00000002) count: 1\n     Custom start=0x0000000e end=0x00000015 (size=0x00000007) \"name\"\n\nSection Details:\n";
        let wat = "(module (@custom \"name\" \"\\00\\05\\04demo\"))";
        assert!(parse_wabt_output(dump, 0x15, wat).is_ok());
        let bad = String::from_utf8_lossy(dump).replace("<demo>", "<other>");
        assert!(parse_wabt_output(bad.as_bytes(), 0x15, wat).is_err());
    }

    #[test]
    fn finds_module_name_after_other_name_subsections() {
        let dump = b"\nmodule.wasm:\tfile format wasm 0x1\nmodule name: <demo>\n\nSections:\n\n     Custom start=0x0000000a end=0x0000000c (size=0x00000002) \"name\"\n\nSection Details:\n";
        let wat = "(module (@custom \"name\" \"\\01\\01\\00\\00\\05\\04demo\"))";
        assert!(parse_wabt_output(dump, 0x0c, wat).is_ok());
    }

    #[test]
    fn accepts_empty_name_subsections_before_module_names() {
        let dump = b"\nmodule.wasm:\tfile format wasm 0x1\nmodule name: <demo>\n\nSections:\n\n     Custom start=0x0000000a end=0x0000000c (size=0x00000002) \"name\"\n\nSection Details:\n";
        let wat = "(module (@custom \"name\" \"\\00\\00\\00\\05\\04demo\"))";
        assert!(parse_wabt_output(dump, 0x0c, wat).is_ok());
    }

    #[test]
    fn rejects_name_metadata_values_that_exceed_wasm_u32() {
        let dump = b"\nmodule.wasm:\tfile format wasm 0x1\n\nSections:\n\n     Custom start=0x0000000a end=0x0000000c (size=0x00000002) \"name\"\n\nSection Details:\n";
        let wat = "(module (@custom \"name\" \"\\80\\80\\80\\80\\10\"))";
        assert!(parse_wabt_output(dump, 0x0c, wat).is_err());
    }

    #[test]
    fn ignores_custom_section_text_inside_wat_comments() {
        let dump = b"\nmodule.wasm:\tfile format wasm 0x1\n\nSections:\n\n     Type start=0x0000000a end=0x0000000c (size=0x00000002) count: 1\n\nSection Details:\n";
        let wat = "(module ;; (@custom \"name\" \"\\00\")\n)";
        assert!(parse_wabt_output(dump, 0x0c, wat).is_ok());
    }

    #[test]
    fn rejects_malformed_name_section_metadata() {
        let dump = b"\nmodule.wasm:\tfile format wasm 0x1\n\nSections:\n\n     Custom start=0x0000000a end=0x0000000c (size=0x00000002) \"name\"\n\nSection Details:\n";
        let wat = "(module (@custom \"name\" \"\\00\"))";
        assert!(parse_wabt_output(dump, 0x0c, wat).is_err());
    }

    #[test]
    fn retains_each_module_name_subsection_in_order() {
        let dump = b"\nmodule.wasm:\tfile format wasm 0x1\nmodule name: <demo>\nmodule name: <second>\n\nSections:\n\n     Custom start=0x0000000a end=0x0000000c (size=0x00000002) \"name\"\n\nSection Details:\n";
        let wat = "(module (@custom \"name\" \"\\00\\05\\04demo\\00\\07\\06second\"))";
        assert!(parse_wabt_output(dump, 0x0c, wat).is_ok());
    }

    #[test]
    fn deduplicates_selected_and_candidate_paths_in_order() {
        let input = json!({"candidate_paths":["module.wasm", "module.wasm"]});
        let candidates = candidate_artifacts(
            input.as_object().expect("object"),
            "module.wasm",
            "hash",
            12,
            &Cancellation::default(),
        )
        .expect("candidate inventory");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0]["path"], "module.wasm");
    }

    #[test]
    fn classifies_glue_parse_status_without_discarding_partial_sources() {
        assert_eq!(glue_parse_status("const wasm = 'module.wasm';"), "complete");
        assert_eq!(
            glue_parse_status("const wasm = { path: 'module.wasm';"),
            "partial"
        );
        assert_eq!(glue_parse_status("const wasm = ]"), "failed");
    }

    #[test]
    fn rejects_a_changed_tool_identity() {
        let error = verify_tool("/dev/null", "not-the-current-digest").expect_err("mismatch");
        assert!(format!("{error:?}").contains("changed"));
    }

    #[test]
    fn retains_multiple_static_literals_on_one_glue_line() {
        assert_eq!(
            quoted_glue_literals("a('first.wasm'); b(`second.wasm`);"),
            vec![(2, "first.wasm".to_owned()), (19, "second.wasm".to_owned())]
        );
    }

    #[test]
    fn decodes_cooked_glue_literal_escapes() {
        assert_eq!(
            decode_glue_literal(r#"module\u002ewasm\x3fdebug\n"#),
            "module.wasm?debug\n"
        );
        assert_eq!(decode_glue_literal(r#"quote\`"#), "quote`");
        assert_eq!(decode_glue_literal(r#"emoji\u{1f600}"#), "emoji😀");
    }

    #[test]
    fn bounds_and_validates_ts_associated_path_inputs() {
        assert!(validate_local_path("/tmp/module.wasm", "path").is_ok());
        assert!(validate_local_path("module.wasm", "path").is_err());

        let paths = (0..17)
            .map(|index| Value::String(format!("/tmp/module-{index}.wasm")))
            .collect::<Vec<_>>();
        let input = json!({"candidate_paths": paths});
        assert!(
            validate_associated_paths(input.as_object().expect("object"), "candidate_paths")
                .is_err()
        );

        let input = json!({"glue_paths":["relative.js"]});
        assert!(
            validate_associated_paths(input.as_object().expect("object"), "glue_paths").is_err()
        );
    }

    #[test]
    fn resolves_relative_glue_references_from_the_glue_directory() {
        assert_eq!(
            local_glue_target("/project/dist/loader.js", "../module.wasm"),
            Some("/project/dist/../module.wasm".to_owned())
        );
        assert_eq!(
            local_glue_target("/project/loader.js", "https://cdn/module.wasm"),
            None
        );
        assert_eq!(
            local_glue_target("/project/loader.js", "module.wasm?cache"),
            None
        );
    }

    #[test]
    fn retains_partial_interface_when_entry_capacity_is_reached() {
        let mut wat = String::from("(module");
        for index in 0..(MAX_INTERFACE_ENTRIES + 1) {
            wat.push_str(&format!(" (import \"env\" \"f{index}\" (func))"));
        }
        wat.push(')');

        let report = decode(&wat);
        assert_eq!(report["state"], "partial");
        assert_eq!(
            report["entries"].as_array().expect("entries").len(),
            MAX_INTERFACE_ENTRIES
        );
        assert_eq!(
            report["issues"][0],
            "Typed interface entry count reached its bounded capacity"
        );
    }
}
fn parse_wabt_output(
    bytes: &[u8],
    artifact_bytes: usize,
    wat_text: &str,
) -> Result<(Vec<Value>, String, String), ()> {
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    let sections_marker = "Sections:\n\n";
    let details_marker = "\nSection Details:\n";
    let mut expected_preamble = "\nmodule.wasm:\tfile format wasm 0x1\n".to_owned();
    for name in wat_debug_module_names(wat_text)? {
        expected_preamble.push_str("module name: <");
        expected_preamble.push_str(name.split('\0').next().unwrap_or(&name));
        expected_preamble.push_str(">\n");
    }
    expected_preamble.push_str("\nSections:\n\n");
    if !text.starts_with(&expected_preamble) {
        return Err(());
    }
    let sections_start = text.find(sections_marker).ok_or(())?;
    let details_start = text[sections_start + sections_marker.len()..]
        .find(details_marker)
        .map(|offset| sections_start + sections_marker.len() + offset)
        .ok_or(())?;
    let mut sections = Vec::new();
    let mut previous_end = 8usize;
    let section_text = &text[sections_start + sections_marker.len()..details_start];
    let custom_names = wat_custom_names(wat_text)?;
    validate_module_name_headers(text, wat_text)?;
    let mut custom_index = 0usize;
    let section_lines = section_text.lines().collect::<Vec<_>>();
    let mut line_index = 0usize;
    while line_index < section_lines.len() {
        let line = section_lines[line_index];
        line_index += 1;
        if line.trim().is_empty() {
            continue;
        }
        let kind = line.split_whitespace().next().ok_or(())?;
        let start = parse_hex_field(line, "start=0x")?;
        let end = parse_hex_field(line, "end=0x")?;
        let bytes_count = parse_hex_field(line, "(size=0x")?;
        let description_start = line.find(") ").ok_or(())? + 2;
        let mut description = line[description_start..].trim().to_owned();
        if kind == "Custom" {
            let expected = custom_names.get(custom_index).ok_or(())?;
            let displayed = expected.split('\0').next().unwrap_or(expected);
            let observed = if description.is_empty() {
                let observed = section_lines.get(line_index).ok_or(())?.trim();
                line_index += 1;
                observed
            } else {
                description.as_str()
            };
            if observed != format!("\"{displayed}\"") {
                return Err(());
            }
            description = observed.to_owned();
            custom_index += 1;
        }
        if end < start
            || end - start != bytes_count
            || end > artifact_bytes
            || start < previous_end.saturating_add(2)
            || start > previous_end.saturating_add(6)
        {
            return Err(());
        }
        previous_end = end;
        sections.push(json!({"kind":kind,"start":start,"end":end,"bytes":bytes_count,"description":description}));
    }
    if custom_index != custom_names.len() {
        return Err(());
    }
    if sections
        .last()
        .and_then(|section| section.get("end"))
        .and_then(Value::as_u64)
        != Some(artifact_bytes as u64)
    {
        return Err(());
    }
    let separator = details_start + 1;
    let details = format!(
        "{}\n{}",
        expected_preamble.trim_start_matches('\n'),
        &text[separator..]
    );
    Ok((sections, text[..separator].to_owned(), details))
}

fn validate_module_name_headers(text: &str, wat: &str) -> Result<(), ()> {
    let expected = wat_debug_module_names(wat)?;
    let displayed = text
        .lines()
        .filter_map(|line| line.strip_prefix("module name: <"))
        .filter_map(|line| line.strip_suffix('>'))
        .collect::<Vec<_>>();
    if expected.len() != displayed.len() {
        return Err(());
    }
    for (expected, displayed) in expected.iter().zip(displayed) {
        if expected.split('\0').next().unwrap_or(expected) != displayed {
            return Err(());
        }
    }
    Ok(())
}

fn wat_debug_module_names(wat: &str) -> Result<Vec<String>, ()> {
    let mut names = Vec::new();
    for (section_name, payload) in wat_custom_sections(wat)? {
        if section_name == "name" {
            let bytes = payload.as_bytes();
            let Some(module_names) = decode_name_modules(bytes) else {
                return Err(());
            };
            names.extend(module_names);
        }
    }
    Ok(names)
}

fn decode_name_modules(bytes: &[u8]) -> Option<Vec<String>> {
    let mut offset = 0usize;
    let mut names = Vec::new();
    while offset < bytes.len() {
        let (subsection, subsection_width) = read_unsigned_leb(bytes.get(offset..)?)?;
        let size_offset = offset.checked_add(subsection_width)?;
        let (size, size_width) = read_unsigned_leb(bytes.get(size_offset..)?)?;
        let start = size_offset.checked_add(size_width)?;
        let end = start.checked_add(size)?;
        let payload = bytes.get(start..end)?;
        if subsection == 0 && size != 0 {
            let (name_length, name_width) = read_unsigned_leb(payload)?;
            let name_start = name_width;
            let name_end = name_start.checked_add(name_length)?;
            if name_end != payload.len() {
                return None;
            }
            names.push(String::from_utf8(payload.get(name_start..name_end)?.to_vec()).ok()?);
            offset = end;
            continue;
        }
        offset = end;
    }
    Some(names)
}

fn read_unsigned_leb(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    for (index, byte) in bytes.iter().copied().take(5).enumerate() {
        if index == 4 && byte > 0x0f {
            return None;
        }
        value |= usize::from(byte & 0x7f).checked_shl((index * 7) as u32)?;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

fn wat_custom_names(wat: &str) -> Result<Vec<String>, ()> {
    Ok(wat_custom_sections(wat)?
        .into_iter()
        .map(|(name, _)| name)
        .collect())
}

fn wat_custom_sections(wat: &str) -> Result<Vec<(String, String)>, ()> {
    let forms = extract_module_forms(wat)?;
    let mut sections = Vec::new();
    for form in forms {
        let Some(parts) = list(&form.node) else {
            continue;
        };
        if atom(parts.first().ok_or(())?) != Some("@custom") {
            continue;
        }
        let Some(WatNode::String(name)) = parts.get(1) else {
            return Err(());
        };
        let Some(WatNode::String(payload)) = parts.get(2) else {
            return Err(());
        };
        sections.push((name.clone(), payload.clone()));
    }
    Ok(sections)
}

fn parse_hex_field(text: &str, marker: &str) -> Result<usize, ()> {
    let start = text
        .find(marker)
        .map(|offset| offset + marker.len())
        .ok_or(())?;
    let end = text[start..]
        .find(|character: char| !character.is_ascii_hexdigit())
        .map(|offset| start + offset)
        .unwrap_or(text.len());
    usize::from_str_radix(&text[start..end], 16).map_err(|_| ())
}
fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(bytes))
}
fn enforce_output_budget(output: &std::process::Output) -> Result<(), Failure> {
    if output.stdout.len().saturating_add(output.stderr.len()) > MAX_OUTPUT {
        Err(resource())
    } else {
        Ok(())
    }
}
#[cfg(not(windows))]
fn run_command(
    path: &Path,
    arguments: &[&str],
    cancellation: &Cancellation,
) -> Result<Output, Failure> {
    let mut child = Command::new(path)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| unavailable_at(path, "Configured WABT executable could not start"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| unavailable_at(path, "WABT stdout pipe could not be created"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| unavailable_at(path, "WABT stderr pipe could not be created"))?;
    let stdout_thread = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take((MAX_OUTPUT + 1) as u64).read_to_end(&mut bytes);
        bytes
    });
    let stderr_thread = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.take((MAX_OUTPUT + 1) as u64).read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if cancellation.reason().is_some() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(cancelled());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(timeout());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|_| unavailable_at(path, "WABT process status could not be read"))?
        {
            break status;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| unavailable_at(path, "WABT stdout reader failed"))?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| unavailable_at(path, "WABT stderr reader failed"))?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(windows)]
fn run_command(
    path: &Path,
    arguments: &[&str],
    cancellation: &Cancellation,
) -> Result<Output, Failure> {
    use rea_host::{
        process::launcher::{ChildLaunchSpec, OwnedChildProcess},
        process::windows::job::WindowsJobLimits,
    };
    use std::os::windows::process::ExitStatusExt;

    let mut child = OwnedChildProcess::launch(ChildLaunchSpec {
        executable: path.to_path_buf(),
        arguments: ChildLaunchSpec::arguments(arguments.iter().copied()),
        working_directory: None,
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        },
    })
    .map_err(|error| {
        unavailable_at(
            path,
            &format!("Owned WABT process could not start: {error:?}"),
        )
    })?;

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if cancellation.reason().is_some() {
            let _ = child.cancel(1);
            return Err(cancelled());
        }
        if Instant::now() >= deadline {
            let _ = child.cancel(1);
            return Err(timeout());
        }
        let output = child.read_output().map_err(|error| {
            unavailable_at(path, &format!("WABT output could not be read: {error:?}"))
        })?;
        if let Some(exit) = child.try_wait().map_err(|error| {
            unavailable_at(
                path,
                &format!("WABT process status could not be read: {error:?}"),
            )
        })? {
            let trailing = child
                .drain_output_with(|| cancellation.reason().is_some())
                .map_err(|error| {
                    unavailable_at(path, &format!("WABT output could not be read: {error:?}"))
                })?;
            if trailing.cancellation_observed {
                return Err(cancelled());
            }
            child.settlement().map_err(|error| {
                unavailable_at(
                    path,
                    &format!("WABT Job settlement could not be observed: {error:?}"),
                )
            })?;
            if !trailing.stdout_closed || !trailing.stderr_closed {
                return Err(unavailable_at(
                    path,
                    "WABT output pipes did not close within the settlement window",
                ));
            }
            let mut stdout = output.stdout;
            stdout.extend(trailing.stdout);
            let mut stderr = output.stderr;
            stderr.extend(trailing.stderr);
            let status = ExitStatusExt::from_raw(exit.code);
            if stdout.len().saturating_add(stderr.len()) > MAX_OUTPUT {
                return Err(resource());
            }
            return Ok(Output {
                status,
                stdout,
                stderr,
            });
        }
        thread::sleep(Duration::from_millis(10));
    }
}
fn invalid(path: &str, message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid. Check the arguments and retry.".into(),
        false,
        "Correct the input and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
fn unavailable(message: &str) -> Failure {
    Failure::new(
        "capability_unavailable",
        "capability_unavailable",
        message.into(),
        true,
        "Configure WABT 1.0.42 and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn unavailable_at(path: &Path, message: &str) -> Failure {
    let mut failure = unavailable(message);
    failure.detail(
        "executable",
        Detail::Text(path.to_string_lossy().into_owned()),
    );
    failure
}
fn resource() -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        "WASM inspection output exceeds its fixed budget.".into(),
        false,
        "Use a smaller artifact.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("maximum_bytes", Detail::Count(MAX_OUTPUT as u64)),
        ]),
    )
}
fn cancelled() -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        "The operation was cancelled before completion.".into(),
        false,
        "Retry the operation if the result is still needed.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn timeout() -> Failure {
    Failure::new(
        "timeout",
        "timeout",
        "Configured WABT exceeded the 30 second deadline.".into(),
        true,
        "Retry after checking the selected WABT installation.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("timeout_ms", Detail::Count(30_000)),
        ]),
    )
}
