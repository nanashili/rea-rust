//! Contract boundary for static website JavaScript module tracing.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleImport {
    pub kind: &'static str,
    pub specifier: Option<String>,
    pub expression: String,
    pub start: SourcePosition,
    pub end: SourcePosition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePosition {
    pub offset: usize,
    pub line: usize,
    pub column: usize,
}

pub const OPERATION: &str = "trace_web_module_imports";

const TRACE_LIMITATIONS: [&str; 8] = [
    "Resolution is derived under the selected importer URL and optional import map; it does not establish that the map was installed in the captured page.",
    "Reported source URLs do not establish an inline script's document base. Select importer_url explicitly when that context differs or is unknown.",
    "Captured candidates retain reported capture metadata; their bytes are not reverified by this trace unless selected as the source.",
    "A resolved URL or captured source does not prove loading, execution, UI causality, or module namespace identity. Execution remains unknown.",
    "Only native ES module syntax is resolved. Bundler module IDs, computed imports, workers and non-HTTP(S) importer contexts are outside this trace.",
    "Source-map declarations do not establish retained map bytes or executed original-source coverage.",
    "Selected application code is parsed as data and never executed.",
    "Manifest, source and import-map limits are 32 MiB, 16 MiB and 4 MiB.",
];

/// Compose a complete trace from provider-retained artifact facts.
///
/// The runtime adapter owns acquisition and optional browser resolution. This
/// application boundary owns identity checks, parser observations, URL/import
/// map interpretation, and captured-candidate matching.
pub fn trace_with_artifacts(
    input: &Value,
    artifacts: &Value,
    resolver_batch: Option<&Value>,
) -> Result<Value, Failure> {
    validate_input(input)?;
    let selected = SelectedArtifacts::from_value(input, artifacts)?;
    let (imports, parser_state, parser_diagnostics) = collect_web_module_imports(&selected.source);
    let resolutions = resolve_imports(
        &imports,
        selected.importer_url(input),
        selected.import_map.as_ref(),
        resolver_batch,
    )?;
    let imports = imports
        .into_iter()
        .zip(resolutions)
        .map(|(reference, resolution)| {
            let captured_candidates = match resolution.get("state").and_then(Value::as_str) {
                Some("resolved") => selected.captured_candidates(
                    resolution
                        .get("url")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ),
                _ => Vec::new(),
            };
            let result = serde_json::json!({
                "kind": reference.kind,
                "specifier": reference.specifier,
                "expression": reference.expression,
                "start": position_json(reference.start),
                "end": position_json(reference.end),
                "resolution": resolution,
                "captured_candidates": captured_candidates,
                "execution": "unknown",
            });
            result
        })
        .collect::<Vec<_>>();
    let resolution_report = resolver_batch.and_then(Value::as_object);
    Ok(serde_json::json!({
        "manifest": selected.manifest_identity,
        "source": {
            "path": selected.source_file.path,
            "sha256": selected.source_file.sha256,
            "bytes": selected.source_file.bytes,
            "script_index": selected.script_index,
            "script": selected.script,
        },
        "importer": {
            "url": selected.importer_url(input),
            "basis": if input.get("importer_url").is_some() { "caller-selected" } else { "reported-source-url" },
        },
        "import_map": selected.import_map_identity(),
        "parser": {
            "state": parser_state,
            "diagnostics": parser_diagnostics,
            "location_units": "UTF-16 offsets and columns; one-based lines",
        },
        "engine": resolution_report.and_then(|report| report.get("engine")).cloned(),
        "imports": imports,
        "diagnostics": resolution_report
            .and_then(|report| report.get("diagnostics"))
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        "limitations": TRACE_LIMITATIONS,
    }))
}

struct SelectedArtifacts {
    manifest_identity: Value,
    manifest: Value,
    source_file: ArtifactFile,
    source: String,
    script_index: usize,
    script: Value,
    import_map: Option<ImportMapArtifact>,
}

struct ArtifactFile {
    path: String,
    sha256: String,
    bytes: usize,
}

struct ImportMapArtifact {
    file: ArtifactFile,
    base_url: String,
    value: Value,
}

impl SelectedArtifacts {
    fn from_value(input: &Value, artifacts: &Value) -> Result<Self, Failure> {
        let object = artifacts
            .as_object()
            .ok_or_else(|| invalid("selected web-script artifacts must be an object"))?;
        let manifest = object
            .get("manifest")
            .ok_or_else(|| invalid("selected web-script artifacts require manifest"))?;
        let manifest_object = manifest
            .as_object()
            .ok_or_else(|| invalid("manifest must be an object"))?;
        let manifest_file = artifact_file(object.get("manifestFile"), "manifestFile")?;
        let source_file = artifact_file(object.get("sourceFile"), "sourceFile")?;
        let source = object
            .get("source")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("selected web-script artifacts require source text"))?
            .to_owned();
        let expected_manifest = input["manifest_path"]
            .as_str()
            .ok_or_else(|| invalid("manifest_path must be a string"))?;
        if manifest_file.path != expected_manifest {
            return Err(invalid(
                "manifest artifact path differs from selected manifest_path",
            ));
        }
        verify_file_contents(&source_file, source.as_bytes(), "source artifact")?;
        let script_index = input["script_index"]
            .as_u64()
            .ok_or_else(|| invalid("script_index must be a non-negative integer"))?
            as usize;
        let script = manifest_object
            .get("scripts")
            .and_then(Value::as_array)
            .and_then(|scripts| scripts.get(script_index))
            .ok_or_else(|| invalid("script_index is outside the captured manifest"))?;
        let content = script
            .get("content")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("selected manifest script has invalid content"))?;
        if content.get("state").and_then(Value::as_str) != Some("exported") {
            return Err(invalid("selected manifest script has no exported content"));
        }
        if content.get("sha256") != Some(&Value::String(source_file.sha256.clone()))
            || content.get("bytes") != Some(&serde_json::json!(source_file.bytes))
        {
            return Err(invalid(
                "selected script identity differs from retained source artifact",
            ));
        }
        let import_map = object
            .get("importMap")
            .filter(|value| !value.is_null())
            .map(ImportMapArtifact::from_value)
            .transpose()?;
        verify_selected_import_map(input, import_map.as_ref())?;
        let manifest_identity = serde_json::json!({
            "path": manifest_file.path,
            "sha256": manifest_file.sha256,
            "bytes": manifest_file.bytes,
            "reported_output_directory": manifest_object["output_directory"].clone(),
            "capture_path": manifest_object["capture_path"].clone(),
            "capture_sha256": manifest_object["capture_sha256"].clone(),
            "capture_kind": manifest_object["capture_kind"].clone(),
            "capture_completeness": manifest_object["capture_completeness"].clone(),
            "source_evidence_id": manifest_object["source_evidence_id"].clone(),
        });
        Ok(Self {
            manifest_identity,
            manifest: manifest.clone(),
            source_file,
            source,
            script_index,
            script: script.clone(),
            import_map,
        })
    }

    fn importer_url(&self, input: &Value) -> String {
        input
            .get("importer_url")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                self.script
                    .get("url")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default()
    }

    fn import_map_identity(&self) -> Value {
        self.import_map.as_ref().map_or(Value::Null, |map| {
            serde_json::json!({
                "path": map.file.path,
                "sha256": map.file.sha256,
                "bytes": map.file.bytes,
                "base_url": map.base_url,
            })
        })
    }

    fn captured_candidates(&self, url: &str) -> Vec<Value> {
        let Some(scripts) = self.manifest.get("scripts").and_then(Value::as_array) else {
            return Vec::new();
        };
        let without_fragment = strip_fragment(url);
        scripts
            .iter()
            .enumerate()
            .filter_map(|(index, script)| {
                let reported = script.get("url").and_then(Value::as_str)?;
                let source_kind = script
                    .get("source")
                    .and_then(|source| source.get("kind"))
                    .and_then(Value::as_str);
                let (matches, kind) = if reported == url {
                    (true, "exact-reported-url")
                } else if source_kind == Some("scenario-response") && reported == without_fragment {
                    (true, "response-url-without-fragment")
                } else {
                    (false, "")
                };
                matches.then(|| {
                    serde_json::json!({
                        "script_index": index,
                        "match": kind,
                        "script": script,
                    })
                })
            })
            .collect()
    }
}

fn verify_selected_import_map(
    input: &Value,
    import_map: Option<&ImportMapArtifact>,
) -> Result<(), Failure> {
    let selected = input.get("import_map");
    match (selected, import_map) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(invalid(
            "artifact import map exists without a caller-selected import_map",
        )),
        (Some(_), None) => Err(invalid(
            "caller-selected import_map is missing from retained artifacts",
        )),
        (Some(selected), Some(actual)) => {
            let selected = selected
                .as_object()
                .ok_or_else(|| invalid("import_map must be an object"))?;
            let path = selected
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("import_map.path must be a string"))?;
            let base_url = selected
                .get("base_url")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("import_map.base_url must be a string"))?;
            if path != actual.file.path || base_url != actual.base_url {
                return Err(invalid(
                    "retained import-map identity differs from caller selection",
                ));
            }
            Ok(())
        }
    }
}

impl ImportMapArtifact {
    fn from_value(value: &Value) -> Result<Self, Failure> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("importMap must be an object or null"))?;
        let file = artifact_file(object.get("file"), "importMap.file")?;
        let base_url = object
            .get("baseUrl")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("importMap.baseUrl must be a string"))?
            .to_owned();
        let map = object
            .get("value")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("importMap.value must be an object"))?;
        if !is_http_url(&base_url) {
            return Err(invalid("importMap.baseUrl must use HTTP or HTTPS"));
        }
        if map
            .get("imports")
            .is_some_and(|imports| !imports.is_object())
        {
            return Err(invalid("importMap.value.imports must be an object"));
        }
        Ok(Self {
            file,
            base_url,
            value: value["value"].clone(),
        })
    }
}

fn artifact_file(value: Option<&Value>, field: &str) -> Result<ArtifactFile, Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(&format!("{field} must be an object")))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid(&format!("{field}.path must be a non-empty string")))?;
    let sha256 = object
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|v| v.len() == 64)
        .ok_or_else(|| invalid(&format!("{field}.sha256 must be a SHA-256 digest")))?;
    let bytes = object
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(&format!("{field}.bytes must be a non-negative integer")))?
        as usize;
    Ok(ArtifactFile {
        path: path.to_owned(),
        sha256: sha256.to_owned(),
        bytes,
    })
}

fn verify_file_contents(file: &ArtifactFile, bytes: &[u8], subject: &str) -> Result<(), Failure> {
    let digest = format!("{:x}", Sha256::digest(bytes));
    if file.bytes != bytes.len() || file.sha256 != digest {
        return Err(invalid(&format!(
            "{subject} bytes or digest differs from retained text"
        )));
    }
    Ok(())
}

fn resolve_imports(
    imports: &[ModuleImport],
    importer_url: String,
    import_map: Option<&ImportMapArtifact>,
    resolver_batch: Option<&Value>,
) -> Result<Vec<Value>, Failure> {
    let supplied = resolver_batch
        .and_then(Value::as_object)
        .and_then(|batch| batch.get("resolutions"))
        .and_then(Value::as_array);
    let mut literal_index = 0;
    imports
        .iter()
        .map(|reference| {
            let Some(specifier) = reference.specifier.as_deref() else {
                return Ok(serde_json::json!({"state": "unknown", "reason": "computed-specifier"}));
            };
            let resolution = supplied.and_then(|values| values.get(literal_index));
            literal_index += 1;
            if let Some(resolution) = resolution {
                return Ok(resolution.clone());
            }
            Ok(resolve_specifier(specifier, &importer_url, import_map))
        })
        .collect()
}

fn resolve_specifier(
    specifier: &str,
    importer_url: &str,
    import_map: Option<&ImportMapArtifact>,
) -> Value {
    if let Some(mapped) = import_map.and_then(|map| mapped_import(specifier, map)) {
        return serde_json::json!({"state": "resolved", "url": mapped});
    }
    if is_http_url(specifier) {
        return serde_json::json!({"state": "resolved", "url": specifier});
    }
    if specifier.starts_with('/') || specifier.starts_with('.') {
        return serde_json::json!({"state": "resolved", "url": join_url(importer_url, specifier)});
    }
    serde_json::json!({"state": "rejected", "message": format!("Failed to resolve module specifier '{specifier}'")})
}

fn mapped_import(specifier: &str, map: &ImportMapArtifact) -> Option<String> {
    let imports = map.value.get("imports")?.as_object()?;
    let (key, target) = imports
        .iter()
        .filter(|(key, _)| {
            *key == specifier || (key.ends_with('/') && specifier.starts_with(key.as_str()))
        })
        .max_by_key(|(key, _)| key.len())?;
    let target = target.as_str()?;
    let suffix = specifier.strip_prefix(key).unwrap_or_default();
    Some(join_url(&map.base_url, &format!("{target}{suffix}")))
}

fn join_url(base: &str, reference: &str) -> String {
    if is_http_url(reference) {
        return reference.to_owned();
    }
    let scheme_end = base.find("://").map_or(0, |index| index + 3);
    let authority_end = base[scheme_end..]
        .find('/')
        .map_or(base.len(), |index| scheme_end + index);
    let origin = &base[..authority_end];
    let base_path = &base[authority_end..];
    let path = if reference.starts_with('/') {
        reference.to_owned()
    } else {
        let directory = base_path.rsplit_once('/').map_or("/", |(head, _)| head);
        format!("{directory}/{reference}")
    };
    let normalized = normalize_path(path.split(['?', '#']).next().unwrap_or(path.as_str()));
    let suffix = reference
        .find(['?', '#'])
        .map_or("", |index| &reference[index..]);
    format!("{origin}{normalized}{suffix}")
}

fn normalize_path(path: &str) -> String {
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            value => segments.push(value),
        }
    }
    format!("/{}", segments.join("/"))
}

fn strip_fragment(url: &str) -> String {
    url.split('#').next().unwrap_or(url).to_owned()
}

fn position_json(position: SourcePosition) -> Value {
    serde_json::json!({"offset": position.offset, "line": position.line, "column": position.column})
}

/// Collect native ES module declarations without executing the selected source.
///
/// This intentionally remains a small lexical parser. It recognizes the
/// declarations needed by the trace contract and preserves computed
/// expressions as unknown rather than guessing their value.
pub fn collect_web_module_imports(source: &str) -> (Vec<ModuleImport>, &'static str, Vec<String>) {
    let lexed = Lexer::new(source).collect();
    if let Some(diagnostic) = lexed.diagnostic {
        return (Vec::new(), "unparseable", vec![diagnostic.to_owned()]);
    }
    let tokens = lexed.tokens;
    let mut imports = Vec::new();
    let mut index = 0;

    while index < tokens.len() {
        let token = &tokens[index];
        let member_access = index > 0 && matches!(tokens[index - 1].text.as_str(), "." | "?.");
        if token.text == "import" && !member_access {
            if let Some(next) = tokens.get(index + 1) {
                if next.text == "(" {
                    if let Some((first, last)) = dynamic_import_argument(&tokens, index) {
                        imports.push(module_import_span("dynamic-import", first, last, source));
                    }
                    index += 1;
                } else if next.text == "." || next.text == "type" {
                    // `import.meta` is metadata access, and `import type` is
                    // erased by TypeScript rather than a runtime dependency.
                } else if let Some(specifier) = static_import_specifier(&tokens, index) {
                    imports.push(module_import("static-import", specifier, source));
                    index += 1;
                }
            }
        } else if token.text == "export" && !member_access {
            let mut cursor = index + 1;
            if tokens
                .get(cursor)
                .is_some_and(|candidate| candidate.text == "type")
            {
                index += 1;
                continue;
            }
            while let Some(candidate) = tokens.get(cursor) {
                if candidate.text == ";" || candidate.text == "import" || candidate.text == "export"
                {
                    break;
                }
                if candidate.text == "from" {
                    if let Some(specifier) = tokens.get(cursor + 1) {
                        if specifier.kind == TokenKind::String {
                            imports.push(module_import("re-export", specifier, source));
                        }
                    }
                    break;
                }
                cursor += 1;
            }
        }
        index += 1;
    }

    imports.sort_by_key(|item| item.start.offset);
    if let Some(diagnostic) = syntax_diagnostic(&tokens) {
        return (Vec::new(), "unparseable", vec![diagnostic.to_owned()]);
    }

    (imports, "parsed", Vec::new())
}

/// Reject the small set of malformed structures that the JavaScript parser
/// cannot recover from while retaining the lexical parser's bounded scope.
fn syntax_diagnostic(tokens: &[Token]) -> Option<&'static str> {
    let mut delimiters = Vec::new();
    for token in tokens {
        let expected = match token.text.as_str() {
            "(" => Some(")"),
            "[" => Some("]"),
            "{" => Some("}"),
            ")" | "]" | "}" => {
                if delimiters.pop() != Some(token.text.as_str()) {
                    return Some("Source could not be parsed; imports are unknown.");
                }
                None
            }
            _ => None,
        };
        if let Some(expected) = expected {
            delimiters.push(expected);
        }
    }
    if !delimiters.is_empty() {
        return Some("Source could not be parsed; imports are unknown.");
    }

    for (index, token) in tokens.iter().enumerate() {
        if token.text == "function" && tokens.get(index + 1).is_some_and(|next| next.text == "{") {
            return Some("Source could not be parsed; imports are unknown.");
        }
    }
    None
}

fn dynamic_import_argument(tokens: &[Token], import_index: usize) -> Option<(&Token, &Token)> {
    let first_index = import_index.checked_add(2)?;
    let first = tokens.get(first_index)?;
    if first.text == ")" {
        return None;
    }

    let mut delimiters = Vec::new();
    let mut last = None;
    for token in tokens.iter().skip(first_index) {
        match token.text.as_str() {
            "(" => delimiters.push(")"),
            "[" => delimiters.push("]"),
            "{" => delimiters.push("}"),
            ")" | "]" | "}" if delimiters.is_empty() => break,
            ")" | "]" | "}" => {
                if delimiters.pop() != Some(token.text.as_str()) {
                    return None;
                }
            }
            "," if delimiters.is_empty() => break,
            _ => {}
        }
        last = Some(token);
    }

    Some((first, last?))
}

fn static_import_specifier(tokens: &[Token], import_index: usize) -> Option<&Token> {
    let next = tokens.get(import_index + 1)?;
    if next.kind == TokenKind::String {
        return Some(next);
    }

    let mut cursor = import_index + 1;
    while let Some(candidate) = tokens.get(cursor) {
        if candidate.text == ";" || candidate.text == "import" || candidate.text == "export" {
            return None;
        }

        if candidate.text == "from" {
            if let Some(specifier) = tokens.get(cursor + 1) {
                if specifier.kind == TokenKind::String {
                    return Some(specifier);
                }
            }
        }

        cursor += 1;
    }

    None
}

fn module_import(kind: &'static str, token: &Token, source: &str) -> ModuleImport {
    module_import_span(kind, token, token, source)
}

fn module_import_span(
    kind: &'static str,
    first: &Token,
    last: &Token,
    source: &str,
) -> ModuleImport {
    let specifier = (first.start == last.start && first.kind == TokenKind::String)
        .then(|| decode_string(&first.text));
    ModuleImport {
        kind,
        specifier,
        expression: source[first.start..last.end].to_owned(),
        start: position(source, first.start),
        end: position(source, last.end),
    }
}

fn position(source: &str, byte_offset: usize) -> SourcePosition {
    let prefix = &source[..byte_offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    SourcePosition {
        offset: prefix.encode_utf16().count(),
        line,
        column: source[column_start..byte_offset].encode_utf16().count(),
    }
}

fn decode_string(raw: &str) -> String {
    let body = raw.get(1..raw.len().saturating_sub(1)).unwrap_or_default();
    let mut decoded = String::with_capacity(body.len());
    let mut characters = body.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }

        let Some(escaped) = characters.next() else {
            decoded.push('\\');
            break;
        };
        match escaped {
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'b' => decoded.push('\u{0008}'),
            'f' => decoded.push('\u{000c}'),
            'v' => decoded.push('\u{000b}'),
            '0' => decoded.push('\0'),
            '\n' => {}
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
            }
            'x' => {
                if let Some(value) = take_hex_digits(&mut characters, 2) {
                    if let Some(character) = char::from_u32(value) {
                        decoded.push(character);
                    }
                }
            }
            'u' => {
                let value = if characters.peek() == Some(&'{') {
                    characters.next();
                    let value = take_braced_hex_digits(&mut characters);
                    value
                } else {
                    take_hex_digits(&mut characters, 4)
                };
                if let Some(value) = value.and_then(char::from_u32) {
                    decoded.push(value);
                }
            }
            other => decoded.push(other),
        }
    }
    decoded
}

fn take_hex_digits<I>(characters: &mut std::iter::Peekable<I>, count: usize) -> Option<u32>
where
    I: Iterator<Item = char>,
{
    let mut value: u32 = 0;
    for _ in 0..count {
        value = value
            .checked_mul(16)?
            .checked_add(characters.next()?.to_digit(16)?)?;
    }
    Some(value)
}

fn take_braced_hex_digits<I>(characters: &mut std::iter::Peekable<I>) -> Option<u32>
where
    I: Iterator<Item = char>,
{
    let mut value = 0;
    let mut digits = 0;
    while let Some(character) = characters.next() {
        if character == '}' {
            return (digits > 0).then_some(value);
        }
        value = value
            .checked_mul(16)?
            .checked_add(character.to_digit(16)?)?;
        digits += 1;
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    Word,
    String,
    Punctuation,
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    text: String,
    start: usize,
    end: usize,
}

struct LexedTokens {
    tokens: Vec<Token>,
    diagnostic: Option<&'static str>,
}

struct Lexer<'a> {
    source: &'a str,
    offset: usize,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str) -> Self {
        Self { source, offset: 0 }
    }

    fn collect(mut self) -> LexedTokens {
        let mut tokens = Vec::new();
        while self.offset < self.source.len() {
            self.skip_space_and_comments();
            if self.offset >= self.source.len() {
                break;
            }
            let start = self.offset;
            let character = self.source[self.offset..]
                .chars()
                .next()
                .expect("offset is inside source");
            if character == '\'' || character == '"' || character == '`' {
                self.offset += 1;
                let quote = character;
                let mut escaped = false;
                while self.offset < self.source.len() {
                    let current = self.source[self.offset..]
                        .chars()
                        .next()
                        .expect("offset is inside source");
                    self.offset += current.len_utf8();
                    if escaped {
                        escaped = false;
                    } else if current == '\\' {
                        escaped = true;
                    } else if current == quote {
                        break;
                    }
                }
                if self.source[..self.offset].chars().last() != Some(quote) {
                    return LexedTokens {
                        tokens: Vec::new(),
                        diagnostic: Some("Source could not be parsed; imports are unknown."),
                    };
                }
                let text = self.source[start..self.offset].to_owned();
                let kind = if quote == '`' && template_has_interpolation(&text) {
                    TokenKind::Punctuation
                } else {
                    TokenKind::String
                };
                tokens.push(Token {
                    kind,
                    text,
                    start,
                    end: self.offset,
                });
            } else if character.is_ascii_alphabetic() || character == '_' || character == '$' {
                self.offset += 1;
                while self.offset < self.source.len() {
                    let current = self.source[self.offset..]
                        .chars()
                        .next()
                        .expect("offset is inside source");
                    if !(current.is_ascii_alphanumeric() || current == '_' || current == '$') {
                        break;
                    }
                    self.offset += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Word,
                    text: self.source[start..self.offset].to_owned(),
                    start,
                    end: self.offset,
                });
            } else {
                self.offset += character.len_utf8();
                tokens.push(Token {
                    kind: TokenKind::Punctuation,
                    text: self.source[start..self.offset].to_owned(),
                    start,
                    end: self.offset,
                });
            }
        }
        LexedTokens {
            tokens,
            diagnostic: None,
        }
    }

    fn skip_space_and_comments(&mut self) {
        loop {
            while self.offset < self.source.len()
                && self.source.as_bytes()[self.offset].is_ascii_whitespace()
            {
                self.offset += 1;
            }
            if self.source[self.offset..].starts_with("//") {
                self.offset += 2;
                while self.offset < self.source.len()
                    && self.source.as_bytes()[self.offset] != b'\n'
                {
                    self.offset += 1;
                }
            } else if self.source[self.offset..].starts_with("/*") {
                self.offset += 2;
                if let Some(end) = self.source[self.offset..].find("*/") {
                    self.offset += end + 2;
                } else {
                    self.offset = self.source.len();
                }
            } else {
                break;
            }
        }
    }
}

fn template_has_interpolation(text: &str) -> bool {
    let mut escaped = false;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\\' {
            escaped = !escaped;
            continue;
        }
        if character == '$' && characters.peek() == Some(&'{') && !escaped {
            return true;
        }
        escaped = false;
    }
    false
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web module trace input must be an object"))?;
    absolute_path(object.get("manifest_path"), "manifest_path")?;

    let script_index = object
        .get("script_index")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("script_index must be a non-negative integer"))?;
    if script_index > usize::MAX as u64 {
        return Err(invalid("script_index is too large"));
    }

    if let Some(importer_url) = object.get("importer_url") {
        let importer_url = importer_url
            .as_str()
            .filter(|url| !url.is_empty())
            .ok_or_else(|| invalid("importer_url must be a non-empty string"))?;
        if !is_http_url(importer_url) {
            return Err(invalid("importer_url must use HTTP or HTTPS"));
        }
    }

    if let Some(import_map) = object.get("import_map") {
        let import_map = import_map
            .as_object()
            .ok_or_else(|| invalid("import_map must be an object"))?;
        absolute_path(import_map.get("path"), "import_map.path")?;
        let base_url = import_map
            .get("base_url")
            .and_then(Value::as_str)
            .filter(|url| !url.is_empty())
            .ok_or_else(|| invalid("import_map.base_url must be a non-empty string"))?;
        if !is_http_url(base_url) {
            return Err(invalid("import_map.base_url must use HTTP or HTTPS"));
        }
    }

    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("web module trace result must be an object"));
    }
    Ok(result)
}

fn absolute_path(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let path = value
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty path")))?;
    if !path.starts_with('/') {
        return Err(invalid(&format!("{field} must be absolute")));
    }
    Ok(())
}

fn is_http_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide an exported JavaScript manifest, a selected script index, and optional HTTP import context.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "manifest_path": "/analysis/exported-scripts/manifest.json",
            "script_index": 0,
            "importer_url": "https://example.test/app.js",
            "import_map": {
                "path": "/analysis/import-map.json",
                "base_url": "https://example.test/app/"
            }
        })
    }

    #[test]
    fn accepts_module_trace_request() {
        validate_input(&input()).expect("valid web module trace input");
        assert!(retain_result(&input(), serde_json::json!({"imports": []})).is_ok());
    }

    #[test]
    fn rejects_relative_manifest_path() {
        let mut invalid_input = input();
        invalid_input["manifest_path"] = serde_json::json!("manifest.json");
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_non_http_import_context() {
        let mut invalid_input = input();
        invalid_input["importer_url"] = serde_json::json!("file:///app.js");
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_negative_script_index() {
        let mut invalid_input = input();
        invalid_input["script_index"] = serde_json::json!(-1);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn collects_static_re_exports_and_dynamic_imports_in_source_order() {
        let source = "import { value } from './dep.js';\nexport { value } from \"./other.js\";\nconst loaded = import(`./lazy.js`);\nconst unknown = import(name);";

        let (imports, state, diagnostics) = collect_web_module_imports(source);

        assert_eq!(state, "parsed");
        assert!(diagnostics.is_empty());
        assert_eq!(imports.len(), 4);
        assert_eq!(imports[0].kind, "static-import");
        assert_eq!(imports[0].specifier.as_deref(), Some("./dep.js"));
        assert_eq!(imports[1].kind, "re-export");
        assert_eq!(imports[1].specifier.as_deref(), Some("./other.js"));
        assert_eq!(imports[2].kind, "dynamic-import");
        assert_eq!(imports[2].specifier.as_deref(), Some("./lazy.js"));
        assert_eq!(imports[3].specifier.as_deref(), None);
        assert_eq!(imports[0].start.line, 1);
        assert_eq!(imports[1].start.line, 2);
    }

    #[test]
    fn ignores_import_words_in_comments_and_preserves_utf16_locations() {
        let source = "// import 'ignored'\nconst text = '😀';\nimport './dep.js';";
        let (imports, _, _) = collect_web_module_imports(source);

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].start.line, 3);
        assert_eq!(imports[0].start.column, 7);
        assert_eq!(
            imports[0].start.offset,
            source[..source.find("'./dep.js'").unwrap()]
                .encode_utf16()
                .count()
        );
    }

    #[test]
    fn recognizes_import_clauses_without_counting_metadata_or_member_calls() {
        let source = "import { value } from './dep.js';\nconst meta = import.meta.url;\nobject.import('./not-a-module-call');";

        let (imports, _, _) = collect_web_module_imports(source);

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].kind, "static-import");
        assert_eq!(imports[0].specifier.as_deref(), Some("./dep.js"));
    }

    #[test]
    fn retains_the_full_expression_for_computed_dynamic_imports() {
        let source = "const loaded = import(prefix + (suffix ?? './fallback.js'));";

        let (imports, _, _) = collect_web_module_imports(source);

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].specifier, None);
        assert_eq!(
            imports[0].expression,
            "prefix + (suffix ?? './fallback.js')"
        );
    }
}
