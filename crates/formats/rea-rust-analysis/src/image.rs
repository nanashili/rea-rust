//! Read-only Rust dependency and compiler-path facts from admitted native bytes.
use crate::{auditable, container};
use serde::Serialize;
use std::{collections::HashSet, fmt};

pub use crate::container::{ByteOrder, Error as ContainerError, Format};
pub const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;
const MAX_COMPILER_HASHES: usize = 64;

#[derive(Debug)]
pub enum Error {
    Container(container::Error),
    Metadata(auditable::Error),
    InputLimit,
    CompilerHashLimit,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Container(error) => error.fmt(f),
            Self::Metadata(error) => error.fmt(f),
            Self::InputLimit => f.write_str("selected binary exceeds 256 MiB"),
            Self::CompilerHashLimit => {
                f.write_str("read-only data contains more than 64 distinct compiler paths")
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Container(error) => Some(error),
            Self::Metadata(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CompilerHash {
    pub hash: String,
    pub file_offset: usize,
}
#[derive(Debug, Serialize)]
pub struct CompilerCommit {
    pub evidence_kind: &'static str,
    pub hashes: Vec<CompilerHash>,
}
#[derive(Debug, Serialize)]
pub struct Image {
    pub format: Format,
    pub architecture: String,
    pub bits: u8,
    pub byte_order: ByteOrder,
    pub auditable_metadata: Option<auditable::Metadata>,
    pub rustc_commit: Option<CompilerCommit>,
}

/// Inspect caller-owned bytes without executing, mutating or reopening a target.
/// File stability and Evidence identity remain the owning workflow's obligation.
pub fn read(bytes: &[u8]) -> Result<Image, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::InputLimit);
    }
    let container = container::read(bytes).map_err(Error::Container)?;
    let auditable_metadata = container
        .dependency
        .map(|span| {
            let name = if matches!(container.format, Format::Macho) {
                auditable::SectionName::MachoDepV0
            } else {
                auditable::SectionName::DepV0
            };
            auditable::read(name, span.start as u64, &bytes[span]).map_err(Error::Metadata)
        })
        .transpose()?;
    let mut hashes = Vec::new();
    let mut seen = HashSet::new();
    let finder = memchr::memmem::Finder::new(b"/rustc/");
    for range in container.read_only {
        let region = &bytes[range.clone()];
        let mut cursor = 0;
        while let Some(relative) = finder.find(&region[cursor..]) {
            let index = cursor + relative;
            cursor = index + 1;
            let Some(window) = region.get(index..index + 48) else {
                continue;
            };
            if window[47] != b'/' {
                continue;
            }
            let digits = &window[7..47];
            if !digits
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            {
                continue;
            }
            if seen.contains(digits) {
                continue;
            }
            if seen.len() >= MAX_COMPILER_HASHES {
                return Err(Error::CompilerHashLimit);
            }
            seen.insert(digits);
            // Only unique admitted hashes allocate output text; repetitions
            // borrow source bytes rather than repeatedly allocating strings.
            let hash = std::str::from_utf8(digits)
                .map_err(|_| {
                    Error::Container(container::Error::Malformed("invalid compiler hash"))
                })?
                .to_owned();
            hashes.push(CompilerHash {
                hash,
                file_offset: range.start + index,
            });
        }
    }
    Ok(Image {
        format: container.format,
        architecture: container.architecture,
        bits: container.bits,
        byte_order: container.byte_order,
        auditable_metadata,
        rustc_commit: if hashes.is_empty() {
            None
        } else {
            Some(CompilerCommit {
                evidence_kind: "inferred",
                hashes,
            })
        },
    })
}
