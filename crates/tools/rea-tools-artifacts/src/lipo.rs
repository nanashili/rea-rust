//! Port of `src/native/parsers/lipo.ts` and
//! `src/domain/apple/machoCpuIdentity.ts`.
//!
//! Parses `lipo -detailed_info` framing and deterministic slice metadata,
//! preserving the producer's original text while normalizing known CPU names.

use regex::Regex;
use serde_json::{Value, json};
use std::sync::OnceLock;

/// `machoCpuSubtypeBase`: CPU subtype identity shared across capability-flag
/// variations. `CPU_SUBTYPE_CAPABILITY_MASK = 0xff000000`.
fn macho_cpu_subtype_base(cpu_subtype: u64) -> u64 {
    cpu_subtype & !0xff00_0000
}

/// One parsed lipo architecture record (`architectureSchema`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LipoArchitecture {
    pub name: String,
    pub cpu_type: Option<String>,
    pub cpu_subtype: Option<String>,
    pub cpu_type_code: Option<u64>,
    pub cpu_subtype_code: Option<u64>,
    pub cpu_subtype_base: Option<u64>,
    pub capabilities: Option<String>,
    pub file_offset: Option<u64>,
    pub size: Option<u64>,
    pub alignment: Option<u64>,
}

impl LipoArchitecture {
    pub fn to_value(&self) -> Value {
        json!({
            "name": self.name,
            "cpu_type": self.cpu_type,
            "cpu_subtype": self.cpu_subtype,
            "cpu_type_code": self.cpu_type_code,
            "cpu_subtype_code": self.cpu_subtype_code,
            "cpu_subtype_base": self.cpu_subtype_base,
            "capabilities": self.capabilities,
            "file_offset": self.file_offset,
            "size": self.size,
            "alignment": self.alignment,
        })
    }

    fn thin(name: String) -> Self {
        Self {
            name,
            cpu_type: None,
            cpu_subtype: None,
            cpu_type_code: None,
            cpu_subtype_code: None,
            cpu_subtype_base: None,
            capabilities: None,
            file_offset: None,
            size: None,
            alignment: None,
        }
    }
}

/// `LipoOutput`.
pub struct LipoOutput {
    /// `thin` or `fat`.
    pub format: &'static str,
    pub architectures: Vec<LipoArchitecture>,
}

fn thin_architecture_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:^|\r?\n)Non-fat file:[\s\S]* is architecture: (\S+)\s*$").expect("valid")
    })
}

fn field_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(cputype|cpusubtype|capabilities|offset|size|align)\s+(.+)$").expect("valid")
    })
}

/// `parseLipoOutput(output, operandPath)`.
pub fn parse_lipo_output(output: &str, operand_path: Option<&str>) -> Result<LipoOutput, String> {
    // The echoed FAT operand is one value, even when its pathname contains
    // lines.
    let mut output = output.to_owned();
    if let Some(path) = operand_path {
        let header = format!("Fat header in: {path}");
        if let Some(rest) = output.strip_prefix(&header) {
            if let Some(after) = rest.strip_prefix("\r\n") {
                output = after.to_owned();
            } else if let Some(after) = rest.strip_prefix('\n') {
                output = after.to_owned();
            }
        }
    }

    // lipo echoes a thin file's pathname verbatim, including embedded
    // newlines. Match its final architecture field before splitting lines.
    if let Some(captures) = thin_architecture_re().captures(&output) {
        let name = captures[1].to_owned();
        return Ok(LipoOutput {
            format: "thin",
            architectures: vec![LipoArchitecture::thin(name)],
        });
    }

    let mut architectures: Vec<LipoArchitecture> = Vec::new();
    let mut current: Option<Current> = None;

    for raw_line in split_lines(&output) {
        let line = raw_line.trim();
        if line.starts_with("Non-fat file:") {
            flush(&mut current, &mut architectures);
            current = Some(Current::non_fat(line.to_owned()));
            continue;
        }
        if let Some(rest) = line.strip_prefix("architecture ") {
            flush(&mut current, &mut architectures);
            current = Some(Current::architecture(rest.trim().to_owned()));
            continue;
        }
        if let Some(captures) = field_re().captures(line) {
            let key = captures[1].to_owned();
            let value = captures[2].trim().to_owned();
            current.get_or_insert_with(Current::empty).set(&key, value);
        }
    }
    flush(&mut current, &mut architectures);

    if architectures.is_empty() {
        return Err("lipo output contained no architectures".into());
    }
    Ok(LipoOutput {
        format: "fat",
        architectures,
    })
}

/// Split on `\r?\n`, matching JavaScript `split(/\r?\n/u)`.
fn split_lines(text: &str) -> Vec<&str> {
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
            lines.push(&text[start..end]);
            start = index + 1;
        }
        index += 1;
    }
    lines.push(&text[start..]);
    lines
}

/// The accumulating record for one architecture block.
struct Current {
    architecture: Option<String>,
    non_fat: Option<String>,
    cputype: Option<String>,
    cpusubtype: Option<String>,
    capabilities: Option<String>,
    offset: Option<String>,
    size: Option<String>,
    align: Option<String>,
}

impl Current {
    fn empty() -> Self {
        Self {
            architecture: None,
            non_fat: None,
            cputype: None,
            cpusubtype: None,
            capabilities: None,
            offset: None,
            size: None,
            align: None,
        }
    }
    fn non_fat(line: String) -> Self {
        Self {
            non_fat: Some(line),
            ..Self::empty()
        }
    }
    fn architecture(name: String) -> Self {
        Self {
            architecture: Some(name),
            ..Self::empty()
        }
    }
    fn set(&mut self, key: &str, value: String) {
        match key {
            "cputype" => self.cputype = Some(value),
            "cpusubtype" => self.cpusubtype = Some(value),
            "capabilities" => self.capabilities = Some(value),
            "offset" => self.offset = Some(value),
            "size" => self.size = Some(value),
            "align" => self.align = Some(value),
            _ => {}
        }
    }
}

fn flush(current: &mut Option<Current>, architectures: &mut Vec<LipoArchitecture>) {
    let Some(record) = current.take() else {
        return;
    };
    // `current.architecture ?? current["Non-fat file"]`.
    let raw_name = record
        .architecture
        .clone()
        .or_else(|| record.non_fat.clone());
    let Some(raw_name) = raw_name else {
        return;
    };
    let name = if raw_name.contains(" is architecture: ") {
        raw_name
            .rsplit(" is architecture: ")
            .next()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| raw_name.clone())
    } else {
        raw_name
    };
    architectures.push(LipoArchitecture {
        name,
        cpu_type: record.cputype.clone(),
        cpu_subtype: record.cpusubtype.clone(),
        cpu_type_code: cpu_type_code(record.cputype.as_deref()),
        cpu_subtype_code: cpu_subtype_code(
            record.cpusubtype.as_deref(),
            record.capabilities.as_deref(),
        ),
        cpu_subtype_base: cpu_subtype_base(record.cpusubtype.as_deref()),
        capabilities: record.capabilities.clone(),
        file_offset: integer(record.offset.as_deref()),
        size: integer(record.size.as_deref()),
        alignment: alignment(record.align.as_deref()),
    });
}

fn integer(value: Option<&str>) -> Option<u64> {
    let value = value?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| *parsed <= MAX_SAFE)
}

/// `Number.MAX_SAFE_INTEGER`.
const MAX_SAFE: u64 = 9_007_199_254_740_991;

fn cpu_types(name: &str) -> Option<u64> {
    Some(match name {
        "CPU_TYPE_X86" => 7,
        "CPU_TYPE_X86_64" => 0x0100_0007,
        "CPU_TYPE_ARM" => 12,
        "CPU_TYPE_ARM64" => 0x0100_000c,
        "CPU_TYPE_ARM64_32" => 0x0200_000c,
        "CPU_TYPE_POWERPC" => 18,
        "CPU_TYPE_POWERPC64" => 0x0100_0012,
        _ => return None,
    })
}

fn cpu_subtypes(name: &str) -> Option<u64> {
    Some(match name {
        "CPU_SUBTYPE_X86_ALL" => 3,
        "CPU_SUBTYPE_X86_64_ALL" => 3,
        "CPU_SUBTYPE_X86_64_H" => 8,
        "CPU_SUBTYPE_ARM64_ALL" => 0,
        "CPU_SUBTYPE_ARM64_V8" => 1,
        "CPU_SUBTYPE_ARM64E" => 2,
        "CPU_SUBTYPE_ARM64_32_ALL" => 0,
        "CPU_SUBTYPE_ARM64_32_V8" => 1,
        "CPU_SUBTYPE_ARM_V7" => 9,
        "CPU_SUBTYPE_ARM_V7S" => 11,
        "CPU_SUBTYPE_ARM_V7K" => 12,
        "CPU_SUBTYPE_POWERPC_ALL" => 0,
        "CPU_SUBTYPE_POWERPC_970" => 100,
        _ => return None,
    })
}

/// `unsigned32(value)`: accept decimal or `0x` hex within the u32 range.
fn unsigned32(value: &str) -> Option<u64> {
    let decimal = !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
    let hex = (value.starts_with("0x") || value.starts_with("0X"))
        && value.len() > 2
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit());
    let parsed = if decimal {
        value.parse::<u64>().ok()?
    } else if hex {
        u64::from_str_radix(&value[2..], 16).ok()?
    } else {
        return None;
    };
    (parsed <= 0xffff_ffff).then_some(parsed)
}

/// `cpuTypeCode(value)`.
fn cpu_type_code(value: Option<&str>) -> Option<u64> {
    let value = value?;
    unsigned32(value).or_else(|| cpu_types(value))
}

/// `cpuSubtypeCode(value, capabilities)`.
fn cpu_subtype_code(value: Option<&str>, capabilities: Option<&str>) -> Option<u64> {
    let value = value?;
    if let Some(numeric) = unsigned32(value) {
        return Some(numeric);
    }
    let subtype = cpu_subtypes(value)?;
    if value != "CPU_SUBTYPE_ARM64E" {
        // Recent lipo prints an empty capabilities line, even for LIB64 slices.
        let bits = capability_bits(capabilities)?;
        return Some(((bits << 24) | subtype) & 0xffff_ffff);
    }
    let version = ptr_auth_userspace_version(capabilities.unwrap_or(""))?;
    if version > 15 {
        return None;
    }
    Some((0x8000_0000 | (version << 24) | subtype) & 0xffff_ffff)
}

fn ptr_auth_userspace_version(capabilities: &str) -> Option<u64> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"PTR_AUTH_VERSION\s+USERSPACE\s+(\d+)").expect("valid"));
    let captures = re.captures(capabilities)?;
    captures[1].parse::<u64>().ok()
}

/// `cpuSubtypeBase(value)`.
fn cpu_subtype_base(value: Option<&str>) -> Option<u64> {
    let value = value?;
    let subtype = unsigned32(value).or_else(|| cpu_subtypes(value))?;
    Some(macho_cpu_subtype_base(subtype))
}

/// `capabilityBits(capabilities)`.
fn capability_bits(capabilities: Option<&str>) -> Option<u64> {
    if capabilities == Some("CPU_SUBTYPE_LIB64") {
        return Some(0x80);
    }
    let text = capabilities?;
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    if digits.is_empty() || digits.len() > 2 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// `alignment(value)`.
fn alignment(value: Option<&str>) -> Option<u64> {
    let value = value?;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^2\^(\d+)(?: \((\d+)\))?$").expect("valid"));
    if let Some(captures) = re.captures(value) {
        let power: u32 = captures[1].parse().ok()?;
        if power > 52 {
            return None;
        }
        let alignment = 1u64 << power;
        match captures.get(2) {
            None => Some(alignment),
            Some(reported) => {
                (integer(Some(reported.as_str())) == Some(alignment)).then_some(alignment)
            }
        }
    } else {
        integer(Some(value))
    }
}
