//! Port of `src/native/parsers/otool.ts`.
//!
//! Parses stable fields from `otool -l`, preserving unknown command fields.

use regex::Regex;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::OnceLock;

/// One parsed section (`ParsedSection`).
#[derive(Clone, Debug)]
pub(crate) struct ParsedSection {
    pub segment: String,
    pub name: String,
    pub address: Option<String>,
    pub size: Option<u64>,
    pub file_offset: Option<u64>,
    pub alignment: Option<u64>,
    pub flags: Vec<String>,
}

/// One parsed segment (`ParsedSegment`).
#[derive(Clone, Debug)]
pub(crate) struct ParsedSegment {
    pub name: String,
    pub vm_address: Option<String>,
    pub vm_size: Option<u64>,
    pub file_offset: Option<u64>,
    pub file_size: Option<u64>,
    pub maximum_permissions: Permissions,
    pub initial_permissions: Permissions,
    pub sections: Vec<ParsedSection>,
}

/// Decoded permission bits (`permissions`).
#[derive(Clone, Debug)]
pub(crate) struct Permissions {
    pub read: Option<bool>,
    pub write: Option<bool>,
    pub execute: Option<bool>,
    pub raw: Option<String>,
}

impl Permissions {
    pub(crate) fn to_value(&self) -> Value {
        json!({
            "read": self.read,
            "write": self.write,
            "execute": self.execute,
            "raw": self.raw,
        })
    }
}

/// One parsed load command (`commands[]`).
#[derive(Clone, Debug)]
pub(crate) struct LoadCommand {
    pub index: u64,
    pub kind: String,
    /// `Record<string, string | number | null>` preserving insertion order.
    pub fields: Map<String, Value>,
}

/// One parsed dependency.
#[derive(Clone, Debug)]
pub(crate) struct Dependency {
    pub path: String,
    pub kind: String,
    pub current_version: Option<String>,
    pub compatibility_version: Option<String>,
}

/// One parsed build-metadata record.
#[derive(Clone, Debug)]
pub(crate) struct BuildMetadata {
    pub platform: Option<String>,
    pub minimum_os: Option<String>,
    pub sdk: Option<String>,
    pub tools: Vec<BuildTool>,
}

/// One LC_BUILD_VERSION tool entry.
#[derive(Clone, Debug)]
pub(crate) struct BuildTool {
    pub name: String,
    pub version: String,
}

/// Parsed `otool -l` output (`ParsedLoadCommands` plus header-derived facts).
///
/// The producer also recorded the first LC_UUID string; `inspect_macho`
/// reconciles the slice UUID from the raw LC_UUID load commands and dwarfdump,
/// so that superseded scalar is not re-derived here.
#[derive(Clone, Debug)]
pub(crate) struct ParsedOtool {
    pub word_size: Option<u8>,
    pub endian: Option<String>,
    pub file_type: Option<String>,
    pub flags: Vec<String>,
    pub commands: Vec<LoadCommand>,
    pub segments: Vec<ParsedSegment>,
    pub dependencies: Vec<Dependency>,
    pub entrypoints: Vec<u64>,
    pub builds: Vec<BuildMetadata>,
}

fn dylib_commands(kind: &str) -> bool {
    matches!(
        kind,
        "LC_ID_DYLIB"
            | "LC_LOAD_DYLIB"
            | "LC_LOAD_WEAK_DYLIB"
            | "LC_REEXPORT_DYLIB"
            | "LC_LAZY_LOAD_DYLIB"
            | "LC_LOAD_UPWARD_DYLIB"
    )
}

const DYLIB_FIELDS: &[&str] = &[
    "cmd",
    "cmdsize",
    "name",
    "current version",
    "compatibility version",
];
const DYLIB_ENCODING_FIELDS: &[&str] = &["time stamp", "options"];

fn empty_value_fields(key: &str) -> bool {
    matches!(key, "options" | "segname" | "sectname")
}

fn build_platform_name(value: &str) -> &str {
    match value {
        "1" => "MACOS",
        "2" => "IOS",
        "3" => "TVOS",
        "4" => "WATCHOS",
        "5" => "BRIDGEOS",
        "6" => "MACCATALYST",
        "7" => "IOSSIMULATOR",
        "8" => "TVOSSIMULATOR",
        "9" => "WATCHOSSIMULATOR",
        "10" => "DRIVERKIT",
        "11" => "VISIONOS",
        "12" => "VISIONOSSIMULATOR",
        "13" => "FIRMWARE",
        "14" => "SEPOS",
        "15" => "MACOS_EXCLAVECORE",
        "16" => "MACOS_EXCLAVEKIT",
        "17" => "IOS_EXCLAVECORE",
        "18" => "IOS_EXCLAVEKIT",
        "19" => "TVOS_EXCLAVECORE",
        "20" => "TVOS_EXCLAVEKIT",
        "21" => "WATCHOS_EXCLAVECORE",
        "22" => "WATCHOS_EXCLAVEKIT",
        "23" => "VISIONOS_EXCLAVECORE",
        "24" => "VISIONOS_EXCLAVEKIT",
        other => other,
    }
}

fn build_tool_name(value: &str) -> &str {
    match value {
        "1" => "CLANG",
        "2" => "SWIFT",
        "3" => "LD",
        "4" => "LLD",
        "1024" => "METAL",
        "1025" => "AIRLLD",
        "1026" => "AIRNT",
        "1027" => "AIRNT_PLUGIN",
        "1028" => "AIRPACK",
        "1031" => "GPUARCHIVER",
        "1032" => "METAL_FRAMEWORK",
        other => other,
    }
}

/// `normalizeLineEndings(output)`.
fn normalize_line_endings(output: &str) -> String {
    output.replace("\r\n", "\n")
}

/// `parseOtoolLoadCommands(raw)`. Returns `Err` for the TypeScript `TypeError`
/// cases, which the caller maps to an `AnalysisOutputError`.
pub(crate) fn parse_otool_load_commands(raw: &str) -> Result<ParsedOtool, String> {
    let output = normalize_line_endings(raw);
    let header = parse_header(&output)?.ok_or("otool output is missing the Mach header")?;
    let mut state = LoadCommandState::new(&header.flags);
    for block in split_load_command_blocks(&output) {
        parse_load_command(&block, &mut state)?;
    }
    validate_load_command_framing(&header, &state.commands)?;
    let mut flags = state.flags.into_iter().collect::<Vec<_>>();
    flags.sort();
    Ok(ParsedOtool {
        word_size: header.magic.as_deref().and_then(word_size),
        endian: header.cpu_type.map(cpu_endian).unwrap_or(None),
        file_type: header.file_type,
        flags,
        commands: state.commands,
        segments: state.segments,
        dependencies: state.dependencies,
        entrypoints: state.entrypoints,
        builds: state.builds,
    })
}

/// `WORD_SIZES`.
fn word_size(magic: &str) -> Option<u8> {
    match magic {
        "0xfeedface" | "MH_MAGIC" => Some(32),
        "0xfeedfacf" | "MH_MAGIC_64" => Some(64),
        _ => None,
    }
}

/// `cpuEndian(cpuType)`.
fn cpu_endian(cpu_type: i64) -> Option<String> {
    let family = cpu_type & 0x00ff_ffff;
    if family == 7 || family == 12 {
        return Some("little".to_owned());
    }
    if family == 18 {
        return Some("big".to_owned());
    }
    None
}

struct Header {
    magic: Option<String>,
    cpu_type: Option<i64>,
    file_type: Option<String>,
    flags: Vec<String>,
    command_count: i64,
    command_bytes: i64,
}

fn magic_column_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|\s)magic\s").expect("valid"))
}

/// `parseHeader(output)`.
fn parse_header(output: &str) -> Result<Option<Header>, String> {
    let lines: Vec<String> = split_lines_crlf(output)
        .into_iter()
        .map(|line| line.trim().to_owned())
        .collect();
    let columns_line = lines
        .iter()
        .position(|line| magic_column_re().is_match(line));
    let Some(columns_line) = columns_line else {
        return Ok(None);
    };
    let columns: Vec<String> = split_whitespace(&lines[columns_line]);
    let data_line = lines[columns_line + 1..]
        .iter()
        .find(|line| !line.is_empty());
    let Some(data_line) = data_line else {
        return Ok(None);
    };
    let values: Vec<String> = split_whitespace(data_line);
    let command_count = header_value(&columns, &values, "ncmds");
    let command_bytes = header_value(&columns, &values, "sizeofcmds");
    let (Some(command_count), Some(command_bytes)) = (command_count, command_bytes) else {
        return Err("otool Mach header is missing valid command framing".into());
    };
    let file_type_index = index_of(&columns, "filetype");
    let flags_index = index_of(&columns, "flags");
    let complete = values.len() >= columns.len();
    let file_type_value_index = match (flags_index, file_type_index) {
        (Some(flags_index), Some(file_type_index)) if file_type_index > flags_index => {
            isize::try_from(values.len()).unwrap_or(isize::MAX)
                - (isize::try_from(columns.len()).unwrap_or(0)
                    - isize::try_from(file_type_index).unwrap_or(0))
        }
        _ => file_type_index
            .map(|value| isize::try_from(value).unwrap_or(0))
            .unwrap_or(-1),
    };
    let flags_end = match flags_index {
        Some(flags_index) => {
            isize::try_from(values.len()).unwrap_or(isize::MAX)
                - (isize::try_from(columns.len()).unwrap_or(0)
                    - isize::try_from(flags_index).unwrap_or(0)
                    - 1)
        }
        None => 0,
    };
    let magic_index = index_of(&columns, "magic");
    let file_type = if complete
        && file_type_value_index >= 0
        && (file_type_value_index as usize) < values.len()
    {
        values.get(file_type_value_index as usize).cloned()
    } else {
        None
    };
    let flags = match flags_index {
        Some(flags_index) if complete && (flags_index as isize) < flags_end => values
            [flags_index..flags_end as usize]
            .iter()
            .filter(|value| !value.is_empty())
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    Ok(Some(Header {
        magic: magic_index.and_then(|index| values.get(index).cloned()),
        cpu_type: header_value(&columns, &values, "cputype"),
        file_type,
        flags,
        command_count,
        command_bytes,
    }))
}

/// `headerValue(columns, values, name)`.
fn header_value(columns: &[String], values: &[String], name: &str) -> Option<i64> {
    let index = index_of(columns, name)?;
    let flags_index = index_of(columns, "flags");
    let value_index = match flags_index {
        Some(flags_index) if index > flags_index => {
            // values.length - (columns.length - index)
            let computed = isize::try_from(values.len()).unwrap_or(isize::MAX)
                - (isize::try_from(columns.len()).unwrap_or(0)
                    - isize::try_from(index).unwrap_or(0));
            if computed < 0 {
                return None;
            }
            computed as usize
        }
        _ => index,
    };
    let value = values.get(value_index)?;
    numeric(value)
}

fn index_of(items: &[String], name: &str) -> Option<usize> {
    items.iter().position(|item| item == name)
}

/// `validateLoadCommandFraming(header, commands)`.
fn validate_load_command_framing(header: &Header, commands: &[LoadCommand]) -> Result<(), String> {
    if commands.len() as i64 != header.command_count {
        return Err("otool load-command count does not match the Mach header".into());
    }
    let mut total_bytes: i64 = 0;
    for (expected_index, command) in commands.iter().enumerate() {
        let size = number_field(&command.fields, "cmdsize");
        let valid = command.index == expected_index as u64 && size.is_some_and(|size| size >= 8);
        if !valid {
            return Err("otool load-command sequence or size is invalid".into());
        }
        total_bytes = match total_bytes.checked_add(size.unwrap_or(0)) {
            Some(value) if value <= MAX_SAFE => value,
            _ => return Err("otool load-command byte count is unsafe".into()),
        };
    }
    if total_bytes != header.command_bytes {
        return Err("otool load-command sizes do not match the Mach header".into());
    }
    Ok(())
}

/// Accumulated load-command state (`ParsedLoadCommands`).
struct LoadCommandState {
    commands: Vec<LoadCommand>,
    segments: Vec<ParsedSegment>,
    dependencies: Vec<Dependency>,
    entrypoints: Vec<u64>,
    builds: Vec<BuildMetadata>,
    flags: std::collections::BTreeSet<String>,
}

impl LoadCommandState {
    fn new(header_flags: &[String]) -> Self {
        Self {
            commands: Vec::new(),
            segments: Vec::new(),
            dependencies: Vec::new(),
            entrypoints: Vec::new(),
            builds: Vec::new(),
            flags: header_flags.iter().cloned().collect(),
        }
    }
}

/// `output.split(/(?=^Load command \d+$)/m)`: split before each header line
/// while keeping the delimiter.
fn split_load_command_blocks(output: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?m)^Load command \d+$").expect("valid"));
    let mut boundaries: Vec<usize> = Vec::new();
    for matched in re.find_iter(output) {
        boundaries.push(matched.start());
    }
    if boundaries.is_empty() {
        return vec![output.to_owned()];
    }
    let mut blocks = Vec::new();
    // Leading text before the first header is its own block (matches
    // lookahead split semantics).
    if boundaries[0] > 0 {
        blocks.push(output[..boundaries[0]].to_owned());
    }
    for window in 0..boundaries.len() {
        let start = boundaries[window];
        let end = boundaries.get(window + 1).copied().unwrap_or(output.len());
        blocks.push(output[start..end].to_owned());
    }
    blocks
}

fn load_command_index_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^Load command (\d+)").expect("valid"))
}

/// `parseLoadCommand(block, state)`.
fn parse_load_command(block: &str, state: &mut LoadCommandState) -> Result<(), String> {
    let Some(captures) = load_command_index_re().captures(block) else {
        return Ok(());
    };
    let index: u64 = captures[1]
        .parse()
        .map_err(|_| "otool load-command index is unsafe".to_owned())?;
    if index > MAX_SAFE as u64 {
        return Err("otool load-command index is unsafe".into());
    }
    // block.split(/\n\s*Section\n/)[0]
    let header_block = split_before_section(block)
        .into_iter()
        .next()
        .unwrap_or_else(|| block.to_owned());
    let parsed = parse_fields(&header_block);
    let kind = string_field(&parsed.values, "cmd").ok_or("otool load command is missing cmd")?;
    for key in scalar_fields(&kind) {
        require_unique_field(&parsed, key)?;
    }
    if dylib_commands(&kind) {
        validate_dylib_command_lines(&parsed)?;
    }
    if kind == "LC_LINKER_OPTION" {
        validate_linker_option_lines(&parsed)?;
    }
    state.commands.push(LoadCommand {
        index,
        kind: kind.clone(),
        fields: parsed.values.clone(),
    });
    collect_entrypoint(&kind, &parsed.values, state);
    collect_build(&kind, block, &parsed.values, state)?;
    collect_dependency(&kind, &parsed.values, state);
    collect_segment(&kind, block, &parsed.values, state)?;
    Ok(())
}

/// `validateDylibCommandLines(parsed)`.
fn validate_dylib_command_lines(parsed: &ParsedFields) -> Result<(), String> {
    let encoding_fields: Vec<&str> = DYLIB_ENCODING_FIELDS
        .iter()
        .copied()
        .filter(|key| {
            parsed
                .rows
                .iter()
                .any(|field| field.as_ref().is_some_and(|row| row.0 == *key))
        })
        .collect();
    if encoding_fields.len() != 1 {
        return Err("otool dylib command must contain timestamp or options".into());
    }
    for key in &encoding_fields {
        require_unique_field(parsed, key)?;
    }
    for field in &parsed.rows {
        let allowed = match field {
            Some(row) => {
                DYLIB_FIELDS.contains(&row.0.as_str())
                    || DYLIB_ENCODING_FIELDS.contains(&row.0.as_str())
            }
            None => false,
        };
        if !allowed {
            return Err("otool dylib command contains ambiguous multiline text".into());
        }
    }
    Ok(())
}

/// `validateLinkerOptionLines(parsed)`.
fn validate_linker_option_lines(parsed: &ParsedFields) -> Result<(), String> {
    let count = number_field(&parsed.values, "count");
    let labels: Vec<&str> = parsed
        .rows
        .iter()
        .filter_map(|field| field.as_ref().map(|row| row.0.as_str()))
        .filter(|key| *key != "cmd" && *key != "cmdsize" && *key != "count")
        .collect();
    let valid = match count {
        Some(count) if count >= 0 && labels.len() as i64 == count => labels
            .iter()
            .enumerate()
            .all(|(index, key)| *key == format!("string #{}", index + 1)),
        _ => false,
    };
    if !valid {
        return Err("otool linker-option strings do not match count".into());
    }
    Ok(())
}

/// `scalarFields(kind)`.
fn scalar_fields(kind: &str) -> Vec<&'static str> {
    let common = ["cmd", "cmdsize"];
    if dylib_commands(kind) {
        return DYLIB_FIELDS.to_vec();
    }
    if kind == "LC_LINKER_OPTION" {
        return vec!["cmd", "cmdsize", "count"];
    }
    if kind == "LC_LOAD_DYLINKER" || kind == "LC_ID_DYLINKER" {
        return vec!["cmd", "cmdsize", "name"];
    }
    if kind == "LC_UUID" {
        return vec!["cmd", "cmdsize", "uuid"];
    }
    if kind == "LC_MAIN" {
        return vec!["cmd", "cmdsize", "entryoff"];
    }
    if kind == "LC_BUILD_VERSION" {
        return vec!["cmd", "cmdsize", "platform", "minos", "sdk", "ntools"];
    }
    if kind.starts_with("LC_VERSION_MIN_") {
        return vec!["cmd", "cmdsize", "version", "sdk"];
    }
    if kind == "LC_SEGMENT" || kind == "LC_SEGMENT_64" {
        return vec![
            "cmd", "cmdsize", "segname", "vmaddr", "vmsize", "fileoff", "filesize", "maxprot",
            "initprot", "nsects", "flags",
        ];
    }
    common.to_vec()
}

fn collect_entrypoint(kind: &str, fields: &Map<String, Value>, state: &mut LoadCommandState) {
    if kind != "LC_MAIN" {
        return;
    }
    if let Some(entry) = number_field(fields, "entryoff")
        && entry >= 0
    {
        state.entrypoints.push(entry as u64);
    }
}

fn collect_build(
    kind: &str,
    block: &str,
    fields: &Map<String, Value>,
    state: &mut LoadCommandState,
) -> Result<(), String> {
    if kind == "LC_BUILD_VERSION" {
        let tools = parse_build_tools(block);
        if number_field(fields, "ntools") != Some(tools.len() as i64) {
            return Err("otool build-tool count does not match ntools".into());
        }
        state.builds.push(BuildMetadata {
            platform: string_field(fields, "platform")
                .map(|value| build_platform_name(&value).to_owned()),
            minimum_os: string_field(fields, "minos"),
            sdk: string_field(fields, "sdk"),
            tools,
        });
        return Ok(());
    }
    if let Some(platform) = kind.strip_prefix("LC_VERSION_MIN_") {
        state.builds.push(BuildMetadata {
            platform: if platform.is_empty() {
                None
            } else {
                Some(platform.to_owned())
            },
            minimum_os: string_field(fields, "version"),
            sdk: string_field(fields, "sdk"),
            tools: Vec::new(),
        });
    }
    Ok(())
}

fn collect_dependency(kind: &str, fields: &Map<String, Value>, state: &mut LoadCommandState) {
    // LC_ID_DYLIB names this image itself; it stays a raw load command only.
    if !dylib_commands(kind) || kind == "LC_ID_DYLIB" {
        return;
    }
    state.dependencies.push(Dependency {
        path: strip_offset_suffix(string_field(fields, "name").as_deref()),
        kind: kind.to_owned(),
        current_version: string_field(fields, "current version"),
        compatibility_version: string_field(fields, "compatibility version"),
    });
}

fn collect_segment(
    kind: &str,
    block: &str,
    fields: &Map<String, Value>,
    state: &mut LoadCommandState,
) -> Result<(), String> {
    if kind != "LC_SEGMENT" && kind != "LC_SEGMENT_64" {
        return Ok(());
    }
    let segment = parse_segment(block, fields)?;
    if number_field(fields, "nsects") != Some(segment.sections.len() as i64) {
        return Err("otool segment section count does not match its sections".into());
    }
    state.segments.push(segment);
    Ok(())
}

/// Fields parsed from a block (`ParsedFields`).
struct ParsedFields {
    values: Map<String, Value>,
    rows: Vec<Option<(String, String)>>,
}

fn text_fields(key: &str) -> bool {
    // `^(?:segname|sectname|string #\d+)$`.
    if key == "segname" || key == "sectname" {
        return true;
    }
    if let Some(rest) = key.strip_prefix("string #") {
        return !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit());
    }
    false
}

/// `parseFields(block)`.
fn parse_fields(block: &str) -> ParsedFields {
    let mut rows: Vec<Option<(String, String)>> = Vec::new();
    for raw_line in split_lines_crlf(block).into_iter().skip(1) {
        if !raw_line.trim().is_empty() {
            rows.push(parse_field(&raw_line));
        }
    }
    let mut occurrences: HashMap<String, usize> = HashMap::new();
    for field in rows.iter().flatten() {
        *occurrences.entry(field.0.clone()).or_insert(0) += 1;
    }
    let mut fields = Map::new();
    let mut ordinals: HashMap<String, usize> = HashMap::new();
    for field in rows.iter().flatten() {
        let (key, value) = field;
        let ordinal = ordinals.entry(key.clone()).or_insert(0);
        *ordinal += 1;
        let label = if occurrences.get(key).copied().unwrap_or(0) > 1 {
            format!("{key} #{ordinal}")
        } else {
            key.clone()
        };
        let stored = if text_fields(key) {
            Value::String(value.clone())
        } else {
            match numeric(value) {
                Some(number) => json!(number),
                None => Value::String(value.clone()),
            }
        };
        fields.insert(label, stored);
    }
    ParsedFields {
        values: fields,
        rows,
    }
}

fn string_option_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*(string #[1-9]\d*)(?: (.*))?$").expect("valid"))
}

fn field_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^((?:time stamp)|\S+(?:\s+version)?)(?:\s+(.+))?$").expect("valid")
    })
}

/// `parseField(rawLine)`.
fn parse_field(raw_line: &str) -> Option<(String, String)> {
    if let Some(option) = string_option_re().captures(raw_line) {
        let key = option.get(1)?.as_str().to_owned();
        let value = option
            .get(2)
            .map_or(String::new(), |matched| matched.as_str().to_owned());
        return Some((key, value));
    }
    let line = raw_line.trim();
    let captures = field_re().captures(line)?;
    let key = captures.get(1)?.as_str().to_owned();
    let value = captures
        .get(2)
        .map_or(String::new(), |matched| matched.as_str().trim().to_owned());
    Some((key, value))
}

/// `requireUniqueField(parsed, key)`.
fn require_unique_field(parsed: &ParsedFields, key: &str) -> Result<(), String> {
    let matches: Vec<&(String, String)> = parsed
        .rows
        .iter()
        .filter_map(|field| field.as_ref())
        .filter(|field| field.0 == key)
        .collect();
    let Some(field) = matches.first() else {
        return Err(format!("otool field {key} is missing or repeated"));
    };
    if matches.len() != 1 {
        return Err(format!("otool field {key} is missing or repeated"));
    }
    if field.1.is_empty() && !empty_value_fields(key) {
        return Err(format!("otool field {key} has no value"));
    }
    Ok(())
}

/// `parseSegment(block, fields)`.
fn parse_segment(block: &str, fields: &Map<String, Value>) -> Result<ParsedSegment, String> {
    Ok(ParsedSegment {
        name: macho_name(fields, "segname")?,
        vm_address: hex_field(fields, "vmaddr"),
        vm_size: number_field(fields, "vmsize").and_then(nonnegative),
        file_offset: number_field(fields, "fileoff").and_then(nonnegative),
        file_size: number_field(fields, "filesize").and_then(nonnegative),
        maximum_permissions: permissions(string_field(fields, "maxprot").as_deref()),
        initial_permissions: permissions(string_field(fields, "initprot").as_deref()),
        sections: parse_sections(block)?,
    })
}

/// `parseSections(block)`.
fn parse_sections(block: &str) -> Result<Vec<ParsedSection>, String> {
    // block.split(/(?=\n\s*Section\n)/).slice(1)
    let section_blocks = split_before_section(block);
    let mut sections = Vec::new();
    for section_block in section_blocks.into_iter().skip(1) {
        // parseFields(`Section${sectionBlock}`): prepend `Section` (the first
        // line consumed by parseFields.slice(1) is the leading `\n...Section`).
        let parsed = parse_fields(&format!("Section{section_block}"));
        for key in [
            "sectname", "segname", "addr", "size", "offset", "align", "flags",
        ] {
            require_unique_field(&parsed, key)?;
        }
        let fields = &parsed.values;
        sections.push(ParsedSection {
            segment: macho_name(fields, "segname")?,
            name: macho_name(fields, "sectname")?,
            address: hex_field(fields, "addr"),
            size: number_field(fields, "size").and_then(nonnegative),
            file_offset: number_field(fields, "offset").and_then(nonnegative),
            alignment: section_alignment(string_field(fields, "align").as_deref()),
            flags: string_field(fields, "flags")
                .unwrap_or_default()
                .split_whitespace()
                .map(ToOwned::to_owned)
                .collect(),
        });
    }
    Ok(sections)
}

fn tool_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^tool\s+(.+)$").expect("valid"))
}

fn version_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^version\s+(.+)$").expect("valid"))
}

/// `parseBuildTools(block)`.
fn parse_build_tools(block: &str) -> Vec<BuildTool> {
    let lines: Vec<String> = split_lines_crlf(block)
        .into_iter()
        .map(|line| line.trim().to_owned())
        .collect();
    let mut tools = Vec::new();
    if lines.len() < 2 {
        return tools;
    }
    for index in 0..lines.len() - 1 {
        let tool = tool_line_re()
            .captures(&lines[index])
            .map(|caps| caps[1].to_owned());
        let version = version_line_re()
            .captures(&lines[index + 1])
            .map(|caps| caps[1].to_owned());
        if let (Some(tool), Some(version)) = (tool, version) {
            tools.push(BuildTool {
                name: build_tool_name(&tool).to_owned(),
                version,
            });
        }
    }
    tools
}

/// `permissions(raw)`.
fn permissions(raw: Option<&str>) -> Permissions {
    let Some(raw) = raw else {
        return Permissions {
            read: None,
            write: None,
            execute: None,
            raw: None,
        };
    };
    if let Some(numeric_value) = numeric(raw) {
        return Permissions {
            read: Some(numeric_value & 1 != 0),
            write: Some(numeric_value & 2 != 0),
            execute: Some(numeric_value & 4 != 0),
            raw: Some(raw.to_owned()),
        };
    }
    let bytes = raw.as_bytes();
    if bytes.len() == 3
        && matches!(bytes[0], b'r' | b'-')
        && matches!(bytes[1], b'w' | b'-')
        && matches!(bytes[2], b'x' | b'-')
    {
        return Permissions {
            read: Some(bytes[0] == b'r'),
            write: Some(bytes[1] == b'w'),
            execute: Some(bytes[2] == b'x'),
            raw: Some(raw.to_owned()),
        };
    }
    Permissions {
        read: None,
        write: None,
        execute: None,
        raw: Some(raw.to_owned()),
    }
}

/// `Number.MAX_SAFE_INTEGER`.
const MAX_SAFE: i64 = 9_007_199_254_740_991;

fn numeric_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?:0x[a-fA-F0-9]+|\d+)$").expect("valid"))
}

/// `numeric(value)`: a whole non-negative safe integer or null.
fn numeric(value: &str) -> Option<i64> {
    if !numeric_re().is_match(value) {
        return None;
    }
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        i128::from_str_radix(hex, 16).ok()?
    } else {
        value.parse::<i128>().ok()?
    };
    if parsed >= 0 && parsed <= MAX_SAFE as i128 {
        Some(parsed as i64)
    } else {
        None
    }
}

fn nonnegative(value: i64) -> Option<u64> {
    (value >= 0).then_some(value as u64)
}

/// `machoName(fields, key)`.
fn macho_name(fields: &Map<String, Value>, key: &str) -> Result<String, String> {
    string_field(fields, key).ok_or_else(|| format!("otool field {key} is missing"))
}

/// `stringField(fields, name)`.
fn string_field(fields: &Map<String, Value>, name: &str) -> Option<String> {
    match fields.get(name) {
        Some(Value::String(text)) => Some(text.clone()),
        None | Some(Value::Null) => None,
        Some(Value::Number(number)) => Some(number.to_string()),
        Some(Value::Bool(value)) => Some(value.to_string()),
        Some(other) => Some(other.to_string()),
    }
}

/// `numberField(fields, name)`.
fn number_field(fields: &Map<String, Value>, name: &str) -> Option<i64> {
    match fields.get(name) {
        Some(Value::Number(number)) => number.as_i64(),
        Some(Value::String(text)) => numeric(text),
        _ => None,
    }
}

/// `hexField(fields, name)`.
fn hex_field(fields: &Map<String, Value>, name: &str) -> Option<String> {
    let value = string_field(fields, name)?;
    if !numeric_re().is_match(&value) {
        return None;
    }
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        u128::from_str_radix(hex, 16).ok()?
    } else {
        value.parse::<u128>().ok()?
    };
    Some(format!("0x{parsed:x}"))
}

fn offset_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s+\(offset\s+\d+\)$").expect("valid"))
}

/// `stripOffsetSuffix(value)`.
fn strip_offset_suffix(value: Option<&str>) -> String {
    match value {
        None => "unknown".to_owned(),
        Some(value) => offset_suffix_re().replace(value, "").into_owned(),
    }
}

fn section_alignment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^2\^(\d+)(?:\s+\(\d+\))?$").expect("valid"))
}

/// `sectionAlignment(raw)`.
fn section_alignment(raw: Option<&str>) -> Option<u64> {
    let raw = raw?;
    let exponent_text = section_alignment_re()
        .captures(raw)
        .and_then(|caps| caps.get(1).map(|matched| matched.as_str().to_owned()))
        .unwrap_or_else(|| raw.to_owned());
    let exponent = numeric(&exponent_text)?;
    if exponent > 52 {
        return None;
    }
    Some(1u64 << exponent)
}

/// `block.split(/(?=\n\s*Section\n)/)`: split before each section header while
/// keeping the delimiter at the start of each subsequent block.
fn split_before_section(block: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"\n\s*Section\n").expect("valid"));
    let mut boundaries = Vec::new();
    for matched in re.find_iter(block) {
        boundaries.push(matched.start());
    }
    if boundaries.is_empty() {
        return vec![block.to_owned()];
    }
    let mut blocks = Vec::new();
    blocks.push(block[..boundaries[0]].to_owned());
    for window in 0..boundaries.len() {
        let start = boundaries[window];
        let end = boundaries.get(window + 1).copied().unwrap_or(block.len());
        blocks.push(block[start..end].to_owned());
    }
    blocks
}

/// Split on `\r?\n`, matching JavaScript `split(/\r?\n/u)`.
fn split_lines_crlf(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            let end = if index > start && bytes[index - 1] == b'\r' {
                index - 1
            } else {
                index
            };
            lines.push(text[start..end].to_owned());
            start = index + 1;
        }
        index += 1;
    }
    lines.push(text[start..].to_owned());
    lines
}

fn split_whitespace(line: &str) -> Vec<String> {
    line.split_whitespace().map(ToOwned::to_owned).collect()
}
