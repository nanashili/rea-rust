//! Bounded cargo-auditable zlib/JSON metadata and dependency graph interpretation.
//! The TypeScript compatibility owner is `src/rust/RustAuditableReader.ts`.

use crate::JsonText;
use flate2::{Decompress, FlushDecompress, Status};
use serde::Serialize;
use serde_json::{Value, value::RawValue};
use std::{collections::BTreeMap, fmt};

type Fields<'a> = BTreeMap<String, &'a RawValue>;

struct RawPackage<'a> {
    fields: Fields<'a>,
    dependencies: Option<Vec<Value>>,
}

pub const MAX_SECTION_BYTES: usize = 1024 * 1024;
pub const MAX_INFLATED_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_RATIO: usize = 64;
const MAX_DEPTH: usize = 32;
const MIN_PACKAGE_BYTES: usize =
    br#"{"name":"a","version":"a","source":"a","kind":null,"dependencies":[],"root":true}"#.len();
const MIN_EDGE_BYTES: usize = br#"{"from_index":0,"to_index":0}"#.len();

/// A format, graph or resource failure; no partial success is fabricated.
#[derive(Debug)]
pub enum Error {
    Malformed(&'static str),
    InvalidPackage { index: usize, reason: &'static str },
    InvalidDependency { package: usize, target: usize },
    Resource { stage: &'static str, maximum: usize },
    Compression(flate2::DecompressError),
    Json(serde_json::Error),
    Encoding(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => f.write_str(reason),
            Self::InvalidPackage { index, reason } => write!(f, "package {index}: {reason}"),
            Self::InvalidDependency { package, target } => write!(
                f,
                "dependency {target} from package {package} is outside the package list"
            ),
            Self::Resource { stage, maximum } => write!(f, "{stage} exceeds {maximum} bytes"),
            Self::Compression(error) => write!(f, "invalid zlib stream: {error}"),
            Self::Json(error) => write!(f, "invalid dependency JSON: {error}"),
            Self::Encoding(error) => write!(f, "normalized output encoding failed: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Compression(error) => Some(error),
            Self::Json(error) | Self::Encoding(error) => Some(error),
            _ => None,
        }
    }
}

/// Exact section identity rather than an arbitrary display string.
#[derive(Clone, Copy, Debug, Serialize)]
pub enum SectionName {
    #[serde(rename = ".dep-v0")]
    DepV0,
    #[serde(rename = "__DATA,.dep-v0")]
    MachoDepV0,
}

#[derive(Debug, Serialize)]
pub struct Package {
    pub name: JsonText,
    pub version: JsonText,
    pub source: JsonText,
    pub kind: Option<String>,
    pub dependencies: Vec<usize>,
    pub root: bool,
}

#[derive(Debug, Serialize)]
pub struct Edge {
    pub from_index: usize,
    pub to_index: usize,
}

/// Complete normalized section, preserving package order and unknown revision.
#[derive(Debug, Serialize)]
pub struct Metadata {
    pub section_name: SectionName,
    pub file_offset: u64,
    pub section_bytes: usize,
    pub compressed_bytes: usize,
    pub uncompressed_bytes: usize,
    pub format_version: Option<u32>,
    pub packages: Vec<Package>,
    pub root_package_index: Option<usize>,
    pub dependency_edges: Vec<Edge>,
    pub cyclic_dependency_indices: Vec<usize>,
}

/// Inspect one complete zlib member. Trailing data and concatenated members fail.
///
/// Limits match the existing provider. File ranges must already have been
/// validated by the caller; this owner does not reopen or acquire artifacts.
pub fn read(section_name: SectionName, file_offset: u64, bytes: &[u8]) -> Result<Metadata, Error> {
    if file_offset > 9_007_199_254_740_991 {
        return Err(Error::Malformed(
            "section offset exceeds the existing numeric contract",
        ));
    }
    let inflated = inflate(bytes)?;
    let text = std::str::from_utf8(&inflated)
        .map_err(|_| Error::Malformed("dependency JSON is not valid UTF-8"))?;
    // TextDecoder's default strips one leading UTF-8 BOM.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    admit_depth(text)?;
    let mut document: Fields<'_> = serde_json::from_str(text).map_err(Error::Json)?;
    let format_version = match document.remove("format") {
        None => None,
        Some(value) => Some(
            u32::try_from(
                integer(&serde_json::from_str(value.get()).map_err(Error::Json)?)
                    .ok_or(Error::Malformed("invalid format version"))?,
            )
            .map_err(|_| Error::Malformed("invalid format version"))?,
        ),
    };
    let raw_packages: Vec<&RawValue> = serde_json::from_str(
        document
            .remove("packages")
            .ok_or(Error::Malformed("dependency packages must be an array"))?
            .get(),
    )
    .map_err(Error::Json)?;
    if !document.is_empty() {
        return Err(Error::Malformed("unknown dependency document fields"));
    }
    let mut minimum = raw_packages.len() * MIN_PACKAGE_BYTES + raw_packages.len().saturating_sub(1);
    admit_graph(minimum, 0)?;
    let mut edges = 0;
    let mut records = Vec::with_capacity(raw_packages.len());
    for (index, raw) in raw_packages.into_iter().enumerate() {
        let mut fields: Fields<'_> =
            serde_json::from_str(raw.get()).map_err(|_| Error::InvalidPackage {
                index,
                reason: "package must be an object",
            })?;
        let dependencies: Option<Vec<Value>> = fields
            .remove("dependencies")
            .map(|raw| {
                serde_json::from_str(raw.get()).map_err(|_| Error::InvalidPackage {
                    index,
                    reason: "package dependencies must be an array",
                })
            })
            .transpose()?;
        let count = dependencies.as_ref().map_or(0, Vec::len);
        edges += count;
        minimum += (count * 2).saturating_sub(1);
        admit_graph(minimum, edges)?;
        records.push(RawPackage {
            fields,
            dependencies,
        });
    }
    let packages = records
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            package(value).map_err(|reason| Error::InvalidPackage { index, reason })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut root_package_index = None;
    for (index, package) in packages.iter().enumerate() {
        if package.root && root_package_index.replace(index).is_some() {
            return Err(Error::Malformed(
                "dependency JSON declares more than one root package",
            ));
        }
        for &target in &package.dependencies {
            if target >= packages.len() {
                return Err(Error::InvalidDependency {
                    package: index,
                    target,
                });
            }
        }
    }
    let cyclic_dependency_indices = cycles(&packages);
    let dependency_edges = packages
        .iter()
        .enumerate()
        .flat_map(|(from_index, package)| {
            package.dependencies.iter().map(move |&to_index| Edge {
                from_index,
                to_index,
            })
        })
        .collect();
    let metadata = Metadata {
        section_name,
        file_offset,
        section_bytes: bytes.len(),
        compressed_bytes: bytes.len(),
        uncompressed_bytes: inflated.len(),
        format_version,
        packages,
        root_package_index,
        dependency_edges,
        cyclic_dependency_indices,
    };
    // Count escaped serialization without allocating another full JSON buffer.
    rea_core::json_output::admitted_length(&metadata, MAX_OUTPUT_BYTES).map_err(
        |error| match error {
            rea_core::json_output::Error::Limit { maximum } => Error::Resource {
                stage: "normalized output",
                maximum,
            },
            rea_core::json_output::Error::Encoding(error) => Error::Encoding(error),
        },
    )?;
    Ok(metadata)
}

fn inflate(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.is_empty() {
        return Err(Error::Malformed("dependency section is empty"));
    }
    if bytes.len() > MAX_SECTION_BYTES {
        return Err(Error::Resource {
            stage: "compressed section",
            maximum: MAX_SECTION_BYTES,
        });
    }
    let maximum = MAX_INFLATED_BYTES.min(bytes.len() * MAX_RATIO);
    let mut decoder = Decompress::new(true);
    let mut output = Vec::new();
    let mut scratch = [0_u8; 8192];
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        // One extra byte distinguishes an exact fit from a truncated decode.
        let available = scratch.len().min(maximum - output.len() + 1);
        let status = decoder
            .decompress(
                &bytes[before_in as usize..],
                &mut scratch[..available],
                FlushDecompress::None,
            )
            .map_err(Error::Compression)?;
        let produced = (decoder.total_out() - before_out) as usize;
        if produced > maximum - output.len() {
            return Err(Error::Resource {
                stage: "inflated JSON",
                maximum,
            });
        }
        output.extend_from_slice(&scratch[..produced]);
        if status == Status::StreamEnd {
            if decoder.total_in() != bytes.len() as u64 {
                return Err(Error::Malformed(
                    "dependency section has bytes after the zlib stream",
                ));
            }
            return Ok(output);
        }
        if before_in == decoder.total_in() && produced == 0 {
            return Err(Error::Malformed(
                "dependency section is not a complete zlib stream",
            ));
        }
    }
}

fn admit_depth(text: &str) -> Result<(), Error> {
    let (mut depth, mut quoted, mut escaped) = (0_usize, false, false);
    for byte in text.bytes() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte == b'{' || byte == b'[' {
            depth += 1;
            if depth > MAX_DEPTH {
                return Err(Error::Malformed(
                    "dependency JSON nesting exceeds 32 levels",
                ));
            }
        } else if byte == b'}' || byte == b']' {
            depth = depth.saturating_sub(1);
        }
    }
    Ok(())
}

fn admit_graph(minimum: usize, edges: usize) -> Result<(), Error> {
    if minimum + edges * MIN_EDGE_BYTES + edges.saturating_sub(1) > MAX_OUTPUT_BYTES {
        return Err(Error::Resource {
            stage: "graph expansion",
            maximum: MAX_OUTPUT_BYTES,
        });
    }
    Ok(())
}

fn integer(value: &Value) -> Option<u64> {
    // JSON.parse accepts integer-valued exponent/fraction spellings as numbers.
    if let Some(value) = value.as_u64() {
        return Some(value);
    }
    let value = value.as_f64()?;
    ((0.0..=9_007_199_254_740_991.0).contains(&value) && value.fract() == 0.0)
        .then_some(value as u64)
}

fn string(fields: &mut Fields<'_>, key: &str) -> Result<JsonText, &'static str> {
    let value = fields
        .remove(key)
        .ok_or("required package string is missing")?;
    let text = JsonText::parse(value).map_err(|_| "invalid package string")?;
    if text.as_str() == Some("") {
        Err("package string must not be empty")
    } else {
        Ok(text)
    }
}

fn package(value: RawPackage<'_>) -> Result<Package, &'static str> {
    let mut fields = value.fields;
    let name = string(&mut fields, "name")?;
    let version = string(&mut fields, "version")?;
    let source = string(&mut fields, "source")?;
    let kind = match fields.remove("kind") {
        None => None,
        Some(raw) => {
            let kind: String =
                serde_json::from_str(raw.get()).map_err(|_| "invalid package kind")?;
            if kind != "runtime" && kind != "build" {
                return Err("invalid package kind");
            }
            Some(kind)
        }
    };
    let root = match fields.remove("root") {
        None => false,
        Some(raw) => serde_json::from_str(raw.get())
            .map_err(|_| "package root must be a boolean when present")?,
    };
    let dependencies = match value.dependencies {
        None => Vec::new(),
        Some(indices) => indices
            .into_iter()
            .map(|v| {
                integer(&v)
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or("dependency index must be an unsigned integer")
            })
            .collect::<Result<_, _>>()?,
    };
    if !fields.is_empty() {
        return Err("unknown package fields");
    }
    Ok(Package {
        name,
        version,
        source,
        kind,
        dependencies,
        root,
    })
}

// Iterative Kosaraju traversal: long valid chains must not exhaust the call stack.
fn cycles(packages: &[Package]) -> Vec<usize> {
    let mut seen = vec![false; packages.len()];
    let mut order = Vec::with_capacity(packages.len());
    let mut stack = Vec::new();
    for start in 0..packages.len() {
        if seen[start] {
            continue;
        }
        seen[start] = true;
        stack.push((start, 0));
        while let Some((index, edge)) = stack.last_mut() {
            if let Some(&next) = packages[*index].dependencies.get(*edge) {
                *edge += 1;
                if !seen[next] {
                    seen[next] = true;
                    stack.push((next, 0));
                }
            } else {
                order.push(*index);
                stack.pop();
            }
        }
    }
    let mut reversed = vec![Vec::new(); packages.len()];
    for (from, package) in packages.iter().enumerate() {
        for &to in &package.dependencies {
            reversed[to].push(from);
        }
    }
    seen.fill(false);
    let mut cyclic = vec![false; packages.len()];
    let mut pending = Vec::new();
    let mut component = Vec::new();
    for start in order.into_iter().rev() {
        if seen[start] {
            continue;
        }
        seen[start] = true;
        pending.push(start);
        component.clear();
        while let Some(index) = pending.pop() {
            component.push(index);
            for &next in &reversed[index] {
                if !seen[next] {
                    seen[next] = true;
                    pending.push(next);
                }
            }
        }
        if component.len() > 1 || packages[start].dependencies.contains(&start) {
            for &index in &component {
                cyclic[index] = true;
            }
        }
    }
    cyclic
        .into_iter()
        .enumerate()
        .filter_map(|(index, yes)| yes.then_some(index))
        .collect()
}
