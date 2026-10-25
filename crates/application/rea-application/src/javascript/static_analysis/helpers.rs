//! Port of `javascriptStaticAnalysisHelpers.ts` (syntax-only helpers).
//!
//! Not ported here: `failedJavaScriptStaticAnalysis` (needs the full static
//! output contract, owned by the orchestrator package H6).
//! Regular expressions with the `iu` flags match ASCII letters plus their
//! Unicode simple case folds (`ſ` for `s`, `K` KELVIN SIGN for `k`), as
//! ECMAScript does.

use std::borrow::Cow;
use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::babel::same;
use super::fingerprint::hex;
use crate::javascript::ast::node::NodeKind;
use crate::javascript::ast::{AstContext, Field, Node};
use crate::javascript::contracts::static_analysis::{
    BundlerRegistration, RuntimeModuleCacheStatus, SourcePoint, SourceRange,
};
use crate::javascript::resolution::syntax::{decode_uri_component, posix_join, posix_relative};
use crate::javascript::resolution::web_url;
use crate::javascript::semantic::ast_values::{
    is_member, js_number_string, runtime_function_parameters, static_property_key,
    static_property_name, unwrapped,
};

/// `JavaScriptOpenReceiverFact`: lexical receiver identities that select
/// static endpoint interpretations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenReceiverFact {
    Window,
    IndexedDb,
    CacheStorage,
    Local,
    LocalIndexedDb,
    LocalCacheStorage,
    Configuration,
    ExtensionState,
}

/// `JavaScriptStaticPathContext`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticPathContext {
    ModuleSpecifier,
    FilesystemExpression,
}

impl StaticPathContext {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModuleSpecifier => "module-specifier",
            Self::FilesystemExpression => "filesystem-expression",
        }
    }
}

/// `JavaScriptStaticStorage["kind"]` values `storageKind` recognizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageKind {
    LocalStorage,
    SessionStorage,
    IndexedDb,
    CacheStorage,
}

impl StorageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalStorage => "local-storage",
            Self::SessionStorage => "session-storage",
            Self::IndexedDb => "indexed-db",
            Self::CacheStorage => "cache-storage",
        }
    }
}

/// `JavaScriptEndpointArgument["kind"]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointKind {
    Endpoint,
    Candidate,
}

/// `JavaScriptEndpointArgument`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointArgument<'a> {
    pub kind: EndpointKind,
    pub value: &'a str,
}

/// Recognized route-construction call suffixes (`STATIC_ROUTE_CALL_NAMES`).
pub const STATIC_ROUTE_CALL_NAMES: [&str; 5] = [
    "route",
    "addRoute",
    "useRoutes",
    "createBrowserRouter",
    "createHashRouter",
];

// ---------------------------------------------------------------------------
// Case-insensitive (`/iu`) ASCII pattern pieces.

/// One character of `/[a-z]/iu`.
fn is_letter_iu(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '\u{17F}' || character == '\u{212A}'
}

/// `character` matches the ASCII letter `pattern` under `/iu`.
fn eq_iu(character: char, pattern: char) -> bool {
    character.eq_ignore_ascii_case(&pattern)
        || (pattern == 's' && character == '\u{17F}')
        || (pattern == 'k' && character == '\u{212A}')
}

/// Whether `text` at char index starts with `pattern` under `/iu`.
fn starts_with_iu(text: &str, pattern: &str) -> bool {
    let mut chars = text.chars();
    pattern
        .chars()
        .all(|expected| chars.next().is_some_and(|actual| eq_iu(actual, expected)))
}

fn contains_iu(text: &str, pattern: &str) -> bool {
    text.char_indices()
        .any(|(index, _)| starts_with_iu(&text[index..], pattern))
}

/// `/(?:webpack|rspack)Chunk/iu`.
fn has_chunk_marker(name: &str) -> bool {
    contains_iu(name, "webpackchunk") || contains_iu(name, "rspackchunk")
}

/// `/^(?:https?|wss?):\/\//iu`.
fn has_http_or_ws_authority(value: &str) -> bool {
    ["http://", "https://", "ws://", "wss://"]
        .iter()
        .any(|prefix| starts_with_iu(value, prefix))
}

/// `/^(?:https?|wss?):/iu`.
fn has_http_or_ws_scheme(value: &str) -> bool {
    ["http:", "https:", "ws:", "wss:"]
        .iter()
        .any(|prefix| starts_with_iu(value, prefix))
}

/// `/^[a-z][a-z0-9+.-]*:/iu`.
fn has_scheme_iu(value: &str) -> bool {
    let mut chars = value.chars();
    if !chars.next().is_some_and(is_letter_iu) {
        return false;
    }
    for character in chars {
        if character == ':' {
            return true;
        }
        if !(is_letter_iu(character) || character.is_ascii_digit() || "+.-".contains(character)) {
            return false;
        }
    }
    false
}

/// `/%(?:2f|5c)/iu` (and friends) over `value`.
fn has_percent_escape(value: &str, escapes: &[&str]) -> bool {
    value.char_indices().any(|(index, character)| {
        character == '%'
            && escapes
                .iter()
                .any(|escape| starts_with_iu(&value[index + 1..], escape))
    })
}

/// ECMAScript `String.prototype.trim` would not change `value`.
fn is_js_trimmed(value: &str) -> bool {
    let js_space = |character: char| {
        matches!(
            character,
            '\t' | '\n' | '\u{B}' | '\u{C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200A}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202F}'
                    | '\u{205F}'
                    | '\u{3000}'
                    | '\u{FEFF}'
        )
    };
    !value.starts_with(js_space) && !value.ends_with(js_space)
}

/// `value.split(/[?#]/u, 1)[0]`.
fn before_query(value: &str) -> &str {
    value.split(['?', '#']).next().unwrap_or("")
}

fn has_control(value: &str) -> bool {
    value.chars().any(|character| (character as u32) < 32)
}

// ---------------------------------------------------------------------------
// Literal readers.

/// `stringValue`: an exact string literal (including a template literal
/// without substitutions), never evaluating an expression.
pub fn string_value<'a>(source: &'a str, node: Option<Node<'a>>) -> Option<&'a str> {
    let node = node?;
    match node.babel_type() {
        "StringLiteral" => node.string_value(),
        "TemplateLiteral" => super::super::semantic::ast_values::unwrapped(source, node)
            .field_list(source, crate::javascript::ast::Field::Quasis)
            .first()
            .copied()
            .flatten()
            .and_then(|quasi| quasi.template_cooked()),
        _ => None,
    }
}

/// `argumentValue`: a string or numeric literal argument.
pub fn argument_value<'a>(source: &'a str, node: Option<Node<'a>>) -> Option<Cow<'a, str>> {
    let node = node?;
    if node.babel_type() == "NumericLiteral" {
        return node
            .numeric_value()
            .map(|value| Cow::Owned(js_number_string(value)));
    }
    string_value(source, Some(node)).map(Cow::Borrowed)
}

/// `prefixedArgument`.
pub fn prefixed_argument<'a>(
    source: &'a str,
    prefix: &str,
    node: Option<Node<'a>>,
) -> Option<String> {
    argument_value(source, node).map(|value| format!("{prefix}{value}"))
}

/// `sourceSlice`.
pub fn source_slice<'a>(context: &AstContext<'a>, node: &Node<'a>) -> &'a str {
    context.slice(node.span())
}

/// `range`: Babel `loc` as the graph source-range shape.
pub fn range(context: &AstContext<'_>, node: &Node<'_>) -> SourceRange {
    let range = context.range(node);
    SourceRange {
        start: SourcePoint {
            line: range.start.line,
            column: range.start.column,
        },
        end: SourcePoint {
            line: range.end.line,
            column: range.end.column,
        },
    }
}

/// `pointForOffset` at a UTF-16 offset: JavaScript line terminators, CRLF
/// as one newline; columns in UTF-16 units.
pub fn point_for_offset(source: &str, offset: usize) -> SourcePoint {
    let mut line = 1u32;
    let mut column = 0u32;
    let mut units = 0usize;
    let mut previous_cr = false;
    for character in source.chars() {
        if units >= offset {
            break;
        }
        if units + character.len_utf16() > offset {
            // The offset splits a surrogate pair: JS keeps the high half.
            column += 1;
            break;
        }
        units += character.len_utf16();
        match character {
            '\n' if previous_cr => {
                // CRLF: the CR already started the line; `\r\n` is one break.
                previous_cr = false;
                continue;
            }
            '\n' | '\u{2028}' | '\u{2029}' => {
                line += 1;
                column = 0;
                previous_cr = false;
            }
            '\r' => {
                line += 1;
                column = 0;
                previous_cr = true;
            }
            other => {
                column += u32::try_from(other.len_utf16()).unwrap_or(1);
                previous_cr = false;
            }
        }
    }
    SourcePoint { line, column }
}

/// `rangeForOffsets` over UTF-16 offsets.
pub fn range_for_offsets(source: &str, start: usize, end: usize) -> SourceRange {
    SourceRange {
        start: point_for_offset(source, start),
        end: point_for_offset(source, end),
    }
}

/// `sourceRangesEqual`.
pub fn source_ranges_equal(left: Option<&SourceRange>, right: &SourceRange) -> bool {
    left == Some(right)
}

/// `sha256Text`: SHA-256 of the UTF-8 text.
pub fn sha256_text(value: &str) -> String {
    hex(&Sha256::digest(value.as_bytes()))
}

const VENDOR_PATTERNS: [(&str, &[&str]); 10] = [
    ("webpack", &["__webpack_require__", "webpackChunk"]),
    ("Rspack", &["__webpack_require__.f", "rspackChunk"]),
    ("Vite", &["__vite__", "import.meta.hot"]),
    ("Rollup", &["ROLLUP_FILE_URL", "import.meta.ROLLUP"]),
    ("esbuild", &["__commonJS", "__esm"]),
    ("React", &["React.createElement", "react/jsx-runtime"]),
    ("Vue", &["__VUE__", "createApp("]),
    ("Next.js", &["__NEXT_DATA__", "/_next/"]),
    ("Angular", &["ɵɵdefineComponent"]),
    ("Svelte", &["svelte/internal"]),
];

/// `detectVendors`: known marker strings, without claiming dependency use.
pub fn detect_vendors(source: &str) -> Vec<&'static str> {
    VENDOR_PATTERNS
        .iter()
        .filter(|(_, patterns)| patterns.iter().any(|pattern| source.contains(pattern)))
        .map(|(name, _)| *name)
        .collect()
}

/// `registrationKey`: the collision-free composite of the semantic content
/// used to deduplicate registrations (`compositeKey` = `JSON.stringify`).
pub fn registration_key(registration: &BundlerRegistration) -> String {
    let status = match registration.runtime_module_cache_status {
        RuntimeModuleCacheStatus::Observed => "observed",
        RuntimeModuleCacheStatus::NotObserved => "not-observed",
    };
    let modules: Vec<serde_json::Value> = registration
        .modules
        .iter()
        .map(|module| serde_json::json!([module.module_key, module.source_sha256]))
        .collect();
    serde_json::json!([
        registration.runtime,
        registration.chunk_keys,
        registration.unknown_chunk_keys.to_string(),
        registration.runtime_require_name,
        status,
        registration.entry_module_keys,
        registration.unknown_entry_module_keys.to_string(),
        registration.async_chunk_keys,
        registration.unknown_async_chunk_keys.to_string(),
        modules,
    ])
    .to_string()
}

/// `sortedUnique`: the last value per key, ordered by key code points.
pub fn sorted_unique<V: Clone>(values: &[V], key: impl Fn(&V) -> String) -> Vec<V> {
    let mut order: Vec<String> = Vec::new();
    let mut last: std::collections::HashMap<String, V> = std::collections::HashMap::new();
    for value in values {
        let key = key(value);
        if !last.contains_key(&key) {
            order.push(key.clone());
        }
        last.insert(key, value.clone());
    }
    order.sort();
    order
        .into_iter()
        .filter_map(|key| last.remove(&key))
        .collect()
}

// ---------------------------------------------------------------------------
// Bundler syntax.

/// `chunkRuntime`: the runtime name of a Webpack/Rspack `push` call.
pub fn chunk_runtime<'a>(cx: &AstContext<'a>, call: &Node<'a>) -> Option<String> {
    let callee = call.field(cx.source(), Field::Callee)?;
    if !is_member(&callee) {
        return None;
    }
    let property = callee.field(cx.source(), Field::Property)?;
    if static_property_name(cx.source(), property, callee.computed()) != "push" {
        return None;
    }
    find_chunk_runtime(cx, callee.field(cx.source(), Field::Object)?)
}

fn find_chunk_runtime<'a>(cx: &AstContext<'a>, node: Node<'a>) -> Option<String> {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.babel_type() == "Identifier" {
            let name = current.identifier_name().unwrap_or("");
            if has_chunk_marker(name) {
                return Some(name.to_owned());
            }
        }
        if is_member(&current) {
            if let Some(property) = current.field(cx.source(), Field::Property) {
                let name = static_property_name(cx.source(), property, current.computed());
                if name
                    .try_to_string()
                    .is_ok_and(|name| has_chunk_marker(&name))
                {
                    return name.try_to_string().ok();
                }
            }
            if let Some(object) = current.field(cx.source(), Field::Object) {
                pending.push(object);
            }
            continue;
        }
        if matches!(
            current.babel_type(),
            "AssignmentExpression" | "LogicalExpression" | "BinaryExpression"
        ) {
            pending.extend(current.field(cx.source(), Field::Right));
            pending.extend(current.field(cx.source(), Field::Left));
            continue;
        }
        let inner = unwrapped(cx.source(), current);
        if !same(&inner, &current) {
            pending.push(inner);
        }
    }
    None
}

/// `moduleFactory`: a literal function factory of one module-table property
/// (`ObjectMethod`, or an `ObjectProperty` whose value is a function).
pub fn module_factory<'a>(cx: &AstContext<'a>, property: &Node<'a>) -> Option<Node<'a>> {
    match property.babel_type() {
        "ObjectMethod" => Some(*property),
        "ObjectProperty" => property.field(cx.source(), Field::Value).filter(|value| {
            matches!(
                value.babel_type(),
                "FunctionExpression" | "ArrowFunctionExpression"
            )
        }),
        _ => None,
    }
}

/// `modulePropertyName`: a literal or explicitly computed module key.
pub fn module_property_name<'a>(cx: &AstContext<'a>, property: &Node<'a>) -> String {
    let start = cx.start(property);
    if !matches!(property.babel_type(), "ObjectMethod" | "ObjectProperty") {
        return format!("[unknown@{start}]");
    }
    if let Some(key) = property
        .field(cx.source(), Field::Key)
        .and_then(|key| static_property_key(cx.source(), key, property.computed()))
    {
        if let Ok(key) = key.try_to_string() {
            return key;
        }
    }
    if property.computed() {
        format!("[computed@{start}]")
    } else {
        format!("[unknown@{start}]")
    }
}

/// `factoryRequireName`: the factory-local require parameter when declared.
pub fn factory_require_name<'a>(cx: &AstContext<'a>, factory: &Node<'a>) -> Option<&'a str> {
    runtime_function_parameters(cx.source(), factory)
        .get(2)
        .filter(|parameter| parameter.babel_type() == "Identifier")
        .and_then(Node::identifier_name)
}

/// `staticArrayValues` result.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StaticValues {
    pub values: Vec<String>,
    pub unknown: u64,
}

/// `staticArrayValues`: unique static literal values of an array.
pub fn static_array_values<'a>(cx: &AstContext<'a>, array: &Node<'a>) -> StaticValues {
    let elements = array.field_list(cx.source(), Field::Elements);
    let found: Vec<String> = elements
        .iter()
        .filter_map(|element| argument_value(cx.source(), *element).map(Cow::into_owned))
        .collect();
    let unknown = (elements.len() - found.len()) as u64;
    let values: BTreeSet<String> = found.into_iter().collect();
    StaticValues {
        values: values.into_iter().collect(),
        unknown,
    }
}

// ---------------------------------------------------------------------------
// Callee names.

/// `calleeName`: a dotted callee name through type-erased wrappers.
pub fn callee_name<'a>(cx: &AstContext<'a>, node: Node<'a>) -> String {
    let mut node = unwrapped(cx.source(), node);
    let mut segments: Vec<String> = Vec::new();
    while is_member(&node) {
        // Dynamic keys retain their syntax identity instead of a name.
        segments.push(member_property_name(cx, &node));
        let Some(object) = node.field(cx.source(), Field::Object) else {
            break;
        };
        node = unwrapped(cx.source(), object);
    }
    let base = if node.babel_type() == "Identifier" {
        node.identifier_name().unwrap_or("").to_owned()
    } else {
        String::new()
    };
    segments.push(base);
    segments.reverse();
    match segments.iter().position(|segment| !segment.is_empty()) {
        Some(first) => segments[first..].join("."),
        None => String::new(),
    }
}

fn member_property_name<'a>(cx: &AstContext<'a>, node: &Node<'a>) -> String {
    let Some(property) = node.field(cx.source(), Field::Property) else {
        return String::new();
    };
    if let Some(key) = static_property_key(cx.source(), property, node.computed())
        && let Ok(key) = key.try_to_string()
    {
        return key;
    }
    if node.computed() {
        let start = cx.start(&property);
        format!("[computed@{start}]")
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Paths.

/// `staticPathResolutionContext`.
pub fn static_path_resolution_context<'a>(
    cx: &AstContext<'a>,
    node: Node<'a>,
) -> StaticPathContext {
    if is_filesystem_path_expression(cx, node) {
        StaticPathContext::FilesystemExpression
    } else {
        StaticPathContext::ModuleSpecifier
    }
}

fn arguments<'a>(cx: &AstContext<'a>, node: &Node<'a>) -> Vec<Option<Node<'a>>> {
    node.field_list(cx.source(), Field::Arguments)
}

fn argument<'a>(cx: &AstContext<'a>, node: &Node<'a>, index: usize) -> Option<Node<'a>> {
    arguments(cx, node).get(index).copied().flatten()
}

fn is_call_or_new(node: &Node<'_>) -> bool {
    matches!(node.babel_type(), "CallExpression" | "NewExpression")
}

fn callee_name_of<'a>(cx: &AstContext<'a>, node: &Node<'a>) -> String {
    node.field(cx.source(), Field::Callee)
        .map(|callee| callee_name(cx, callee))
        .unwrap_or_default()
}

fn is_plus(node: &Node<'_>) -> bool {
    node.babel_type() == "BinaryExpression" && node.operator() == Some("+")
}

/// `staticPath`: a path composed only of inert literal syntax.
pub fn static_path<'a>(cx: &AstContext<'a>, node: Node<'a>) -> Option<String> {
    let node = unwrapped(cx.source(), node);
    if let Some(value) = string_value(cx.source(), Some(node)) {
        return Some(value.to_owned());
    }
    if is_plus(&node) {
        return static_concatenation(cx, node);
    }
    if is_call_or_new(&node) {
        return static_call_path(cx, &node);
    }
    None
}

/// A leading cx directory contributes no text: `__dirname + "/x"` names
/// a file inside it; text without a leading separator stays unknown.
fn static_concatenation<'a>(cx: &AstContext<'a>, node: Node<'a>) -> Option<String> {
    let mut operands = Vec::new();
    let mut current = node;
    while is_plus(&current) {
        operands.push(current.field(cx.source(), Field::Right)?);
        current = unwrapped(cx.source(), current.field(cx.source(), Field::Left)?);
    }
    let anchored = is_directory_path(cx, Some(current));
    if !anchored {
        operands.push(current);
    }
    let mut text = String::new();
    for operand in operands.into_iter().rev() {
        text.push_str(&static_path(cx, operand)?);
    }
    if !anchored {
        return Some(text);
    }
    text.starts_with('/').then(|| posix_join(&[".", &text]))
}

fn ends_with_member(name: &str, member: &str) -> bool {
    name == member || name.ends_with(&format!(".{member}"))
}

fn static_call_path<'a>(cx: &AstContext<'a>, node: &Node<'a>) -> Option<String> {
    let name = callee_name_of(cx, node);
    if ends_with_member(&name, "URL") {
        return if is_file_identity(cx, argument(cx, node, 1)) {
            string_value(cx.source(), argument(cx, node, 0)).map(str::to_owned)
        } else {
            None
        };
    }
    if ends_with_member(&name, "fileURLToPath") {
        return static_file_url_path(cx, node);
    }
    if name.ends_with(".resolve") {
        return if ends_with_member(&name, "win32.resolve") {
            None
        } else {
            static_resolved_path(cx, node)
        };
    }
    if !name.ends_with(".join") && name != "join" {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for argument in arguments(cx, node) {
        if is_directory_identity(cx, argument) {
            // join never resets at an absolute segment.
            parts.push(".".to_owned());
            continue;
        }
        parts.push(static_path(cx, argument?)?);
    }
    if parts.is_empty() {
        return None;
    }
    Some(posix_join(
        &parts.iter().map(String::as_str).collect::<Vec<_>>(),
    ))
}

/// Node `fileURLToPath(url, { windows: false })`.
fn file_url_to_posix_path(url: &web_url::WebUrl) -> Option<String> {
    if url.protocol() != "file:" || !url.hostname().is_empty() {
        return None;
    }
    let pathname = url.pathname();
    if has_percent_escape(pathname, &["2f"]) {
        return None;
    }
    decode_uri_component(pathname)
}

fn static_file_url_path<'a>(cx: &AstContext<'a>, node: &Node<'a>) -> Option<String> {
    let all = arguments(cx, node);
    if all.len() != 1 {
        return None;
    }
    let argument = unwrapped(cx.source(), all[0]?);
    if is_source_file_url(cx, &argument) {
        return source_relative_file_url_path(cx, &argument);
    }
    let value = static_path(cx, argument)?;
    if !starts_with_iu(&value, "file:")
        || !is_js_trimmed(&value)
        || value.contains('\\')
        || has_control(&value)
        || has_percent_escape(before_query(&value), &["2f", "5c"])
    {
        return None;
    }
    let url = web_url::parse(&value, None)?;
    let path = file_url_to_posix_path(&url)?;
    // Drive and UNC paths need an explicit target platform.
    let mut chars = path.chars();
    let drive = chars.next() == Some('/')
        && chars.next().is_some_and(is_letter_iu)
        && chars.next() == Some(':');
    (!drive).then_some(path)
}

/// A known cx-relative URL projected through the file URL decoder.
fn source_relative_file_url_path<'a>(cx: &AstContext<'a>, node: &Node<'a>) -> Option<String> {
    let value = string_value(cx.source(), argument(cx, node, 0))?;
    if before_query(value).is_empty()
        || !is_js_trimmed(value)
        || value.contains('\\')
        || has_control(value)
        || has_scheme_iu(value)
        || value.starts_with("//")
        || has_percent_escape(before_query(value), &["2e", "2f", "5c"])
    {
        return None;
    }
    // A sufficiently deep inert anchor preserves leading parent segments
    // without using this host's cwd.
    let directory = format!("/{}", "cx/".repeat(value.split('/').count() + 1));
    let base = web_url::parse(&format!("file://{directory}entry.js"), None)?;
    let resolved = web_url::parse(value, Some(&base))?;
    let path = file_url_to_posix_path(&resolved)?;
    if value.starts_with('/') {
        return Some(path);
    }
    let relative = posix_relative(&directory, &path);
    let relative = if relative.is_empty() {
        ".".to_owned()
    } else {
        relative
    };
    Some(
        if value.starts_with("./") && relative != "." && !relative.starts_with("../") {
            format!("./{relative}")
        } else {
            relative
        },
    )
}

fn is_source_file_url<'a>(cx: &AstContext<'a>, node: &Node<'a>) -> bool {
    is_call_or_new(node)
        && ends_with_member(&callee_name_of(cx, node), "URL")
        && is_file_identity(cx, argument(cx, node, 1))
}

fn static_resolved_path<'a>(cx: &AstContext<'a>, node: &Node<'a>) -> Option<String> {
    let mut parts: Vec<Option<String>> = Vec::new();
    for argument in arguments(cx, node) {
        if is_directory_identity(cx, argument) {
            parts.push(None);
            continue;
        }
        // Validate every argument, including those before the last anchor.
        parts.push(Some(static_path(cx, argument?)?));
    }
    // Relative-only calls depend on the target process cwd.
    let anchor = parts
        .iter()
        .rposition(|part| part.as_ref().is_none_or(|part| part.starts_with('/')))?;
    let tail: Vec<&str> = parts[anchor..]
        .iter()
        .flatten()
        .map(String::as_str)
        .collect();
    let path = posix_join(&tail);
    Some(if path == "/" {
        path
    } else {
        path.strip_suffix('/').map(str::to_owned).unwrap_or(path)
    })
}

fn is_filesystem_path_expression<'a>(cx: &AstContext<'a>, node: Node<'a>) -> bool {
    let node = unwrapped(cx.source(), node);
    if let Some(value) = string_value(cx.source(), Some(node)) {
        return value.starts_with('/');
    }
    if is_file_identity(cx, Some(node)) || is_directory_identity(cx, Some(node)) {
        return true;
    }
    if is_plus(&node) {
        return node
            .field(cx.source(), Field::Left)
            .is_some_and(|left| is_filesystem_path_expression(cx, left))
            || node
                .field(cx.source(), Field::Right)
                .is_some_and(|right| is_filesystem_path_expression(cx, right));
    }
    if is_call_or_new(&node) {
        let name = callee_name_of(cx, &node);
        let any_argument = || {
            arguments(cx, &node)
                .into_iter()
                .flatten()
                .any(|argument| is_filesystem_path_expression(cx, argument))
        };
        if name.ends_with(".resolve") && static_call_path(cx, &node).is_some() {
            return true;
        }
        if ends_with_member(&name, "URL") {
            return is_file_identity(cx, argument(cx, &node, 1));
        }
        if ends_with_member(&name, "fileURLToPath") {
            return static_file_url_path(cx, &node).is_some() || any_argument();
        }
        return any_argument();
    }
    false
}

fn is_directory_identity<'a>(cx: &AstContext<'a>, node: Option<Node<'a>>) -> bool {
    let node = node.map(|node| unwrapped(cx.source(), node));
    if is_directory_path(cx, node) {
        return true;
    }
    let Some(node) = node.filter(is_call_or_new) else {
        return false;
    };
    ends_with_member(&callee_name_of(cx, &node), "URL")
        && is_file_identity(cx, argument(cx, &node, 1))
}

/// `__dirname` or the dirname of the cx file.
fn is_directory_path<'a>(cx: &AstContext<'a>, node: Option<Node<'a>>) -> bool {
    let Some(node) = node.map(|node| unwrapped(cx.source(), node)) else {
        return false;
    };
    if node.babel_type() == "Identifier" && node.identifier_name() == Some("__dirname") {
        return true;
    }
    node.babel_type() == "CallExpression"
        && ends_with_member(&callee_name_of(cx, &node), "dirname")
        && is_file_identity(cx, argument(cx, &node, 0))
}

/// `isImportMetaUrl`: the expression denotes the current module's URL.
pub fn is_import_meta_url<'a>(cx: &AstContext<'a>, node: Option<Node<'a>>) -> bool {
    let Some(expression) = node.map(|node| unwrapped(cx.source(), node)) else {
        return false;
    };
    if expression.babel_type() != "MemberExpression" {
        return false;
    }
    let Some(object) = expression
        .field(cx.source(), Field::Object)
        .map(|object| unwrapped(cx.source(), object))
    else {
        return false;
    };
    let NodeKind::MetaProperty(meta) = object.kind() else {
        return false;
    };
    meta.meta.name == "import"
        && meta.property.name == "meta"
        && expression
            .field(cx.source(), Field::Property)
            .is_some_and(|property| {
                static_property_name(cx.source(), property, expression.computed()) == "url"
            })
}

fn is_file_identity<'a>(cx: &AstContext<'a>, node: Option<Node<'a>>) -> bool {
    let Some(node) = node.map(|node| unwrapped(cx.source(), node)) else {
        return false;
    };
    if (node.babel_type() == "Identifier" && node.identifier_name() == Some("__filename"))
        || is_import_meta_url(cx, Some(node))
    {
        return true;
    }
    node.babel_type() == "CallExpression"
        && ends_with_member(&callee_name_of(cx, &node), "fileURLToPath")
        && is_file_identity(cx, argument(cx, &node, 0))
}

// ---------------------------------------------------------------------------
// Endpoints and storage.

const XHR_METHODS: [&str; 9] = [
    "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE",
];

const FS_OPEN_FLAGS: [&str; 22] = [
    "a", "a+", "as", "as+", "ax", "ax+", "r", "r+", "rs", "rs+", "sa", "sa+", "sr", "sr+", "w",
    "w+", "wx", "wx+", "xa", "xa+", "xw", "xw+",
];

const BROWSING_CONTEXT_KEYWORDS: [&str; 4] = ["_blank", "_parent", "_self", "_top"];

/// Legacy URL/path shapes that bypass the overloaded lookup exclusions.
fn is_request_url_or_path_literal(value: &str) -> bool {
    has_http_or_ws_authority(value)
        || value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
}

/// Explicit request references, classified after receiver exclusions.
fn is_request_url_reference(value: &str) -> bool {
    if is_request_url_or_path_literal(value) || value.starts_with('?') || value.starts_with('#') {
        return true;
    }
    has_http_or_ws_scheme(value) && web_url::can_parse(value)
}

/// `WINDOW_OPEN_CALL`:
/// `/(?:^|\.)(?:window|self|globalThis|top|parent|opener|frames|document)\.open$/u`.
fn is_window_open_call(name: &str) -> bool {
    let Some(receiver) = name.strip_suffix(".open") else {
        return false;
    };
    let last = receiver.rsplit('.').next().unwrap_or(receiver);
    matches!(
        last,
        "window" | "self" | "globalThis" | "top" | "parent" | "opener" | "frames" | "document"
    )
}

/// `/^[A-Z][A-Z-]*$/u`.
fn is_uppercase_token(method: &str) -> bool {
    let bytes = method.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_uppercase)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || *byte == b'-')
}

/// `xhrOpenUrl`.
fn xhr_open_url<'a>(
    cx: &AstContext<'a>,
    name: &str,
    method_node: Option<Node<'a>>,
    url_node: Option<Node<'a>>,
    receiver: Option<OpenReceiverFact>,
) -> Option<&'a str> {
    use OpenReceiverFact as R;
    let url = string_value(cx.source(), url_node)?;
    if receiver == Some(R::Window) {
        return None;
    }
    let method = string_value(cx.source(), method_node);
    let storage = matches!(
        receiver,
        Some(R::LocalIndexedDb | R::LocalCacheStorage | R::IndexedDb | R::CacheStorage)
    ) || storage_kind(name).is_some();
    let Some(method) = method else {
        let excluded = storage
            || (receiver.is_none() && is_window_open_call(name))
            || FS_OPEN_FLAGS.contains(&url)
            || BROWSING_CONTEXT_KEYWORDS.contains(&url.to_lowercase().as_str());
        return (!excluded).then_some(url);
    };
    let standard = XHR_METHODS.contains(&method.to_uppercase().as_str());
    let local_storage = matches!(receiver, Some(R::LocalIndexedDb | R::LocalCacheStorage));
    (standard || ((!storage || local_storage) && is_uppercase_token(method))).then_some(url)
}

/// `isKeyedCollectionReceiver`.
fn is_keyed_collection_receiver<'a>(cx: &AstContext<'a>, callee: Node<'a>) -> bool {
    let callee = unwrapped(cx.source(), callee);
    if !is_member(&callee) {
        return false;
    }
    let Some(receiver) = callee
        .field(cx.source(), Field::Object)
        .map(|object| unwrapped(cx.source(), object))
    else {
        return false;
    };
    if receiver.babel_type() == "NewExpression" {
        let constructor = receiver
            .field(cx.source(), Field::Callee)
            .map(|callee| unwrapped(cx.source(), callee));
        return constructor.is_some_and(|constructor| {
            constructor.babel_type() == "Identifier"
                && matches!(
                    constructor.identifier_name(),
                    Some(
                        "FormData"
                            | "Headers"
                            | "Map"
                            | "Set"
                            | "URLSearchParams"
                            | "WeakMap"
                            | "WeakSet"
                    )
                )
        });
    }
    if !is_member(&receiver) {
        return false;
    }
    receiver
        .field(cx.source(), Field::Property)
        .is_some_and(|property| {
            let property = static_property_name(cx.source(), property, receiver.computed());
            property == "headers" || property == "headersList" || property == "searchParams"
        })
}

/// `endpointArgument`: classify one literal without treating a generic
/// method name as network identity.
pub fn endpoint_argument<'a>(
    cx: &AstContext<'a>,
    name: &str,
    args: &[Option<Node<'a>>],
    callee: Node<'a>,
    receiver: Option<OpenReceiverFact>,
) -> Option<EndpointArgument<'a>> {
    let arg = |index: usize| args.get(index).copied().flatten();
    let literal = |value: Option<&'a str>| {
        value.map(|value| EndpointArgument {
            kind: EndpointKind::Endpoint,
            value,
        })
    };
    if receiver == Some(OpenReceiverFact::Window) {
        return None;
    }
    if ends_with_member(name, "fetch")
        || name == "WebSocket"
        || ends_with_member(name, "EventSource")
    {
        return literal(string_value(cx.source(), arg(0)));
    }
    if name.ends_with(".open") {
        let value = xhr_open_url(cx, name, arg(0), arg(1), receiver)?;
        let kind = if string_value(cx.source(), arg(0)).is_some() || is_request_url_reference(value)
        {
            EndpointKind::Endpoint
        } else {
            EndpointKind::Candidate
        };
        return Some(EndpointArgument { kind, value });
    }
    let method = ["get", "post", "put", "patch", "delete", "request"]
        .into_iter()
        .find(|candidate| ends_with_member(name, candidate));
    if let Some(method) = method {
        let value = string_value(cx.source(), arg(0))?;
        if (method == "get" || method == "delete")
            && !is_request_url_or_path_literal(value)
            && (is_keyed_collection_receiver(cx, callee)
                || (method == "get"
                    && matches!(
                        receiver,
                        Some(OpenReceiverFact::Configuration | OpenReceiverFact::ExtensionState)
                    )))
        {
            return None;
        }
        let kind = if method != "get" && method != "delete" && is_request_url_reference(value) {
            EndpointKind::Endpoint
        } else {
            EndpointKind::Candidate
        };
        return Some(EndpointArgument { kind, value });
    }
    if ends_with_member(name, "sendBeacon") || ends_with_member(name, "loadURL") {
        return literal(string_value(cx.source(), arg(0)));
    }
    None
}

/// `storageKind`.
pub fn storage_kind(name: &str) -> Option<StorageKind> {
    if name.contains("localStorage.") {
        Some(StorageKind::LocalStorage)
    } else if name.contains("sessionStorage.") {
        Some(StorageKind::SessionStorage)
    } else if name.ends_with("indexedDB.open") {
        Some(StorageKind::IndexedDb)
    } else if name.ends_with("caches.open") {
        Some(StorageKind::CacheStorage)
    } else {
        None
    }
}
