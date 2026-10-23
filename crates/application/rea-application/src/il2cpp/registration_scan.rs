//! Bounded, read-only discovery of 64-bit IL2CPP code-registration roots.
//!
//! This module deliberately stops at evidence.  A registration-shaped byte
//! sequence is reported as a candidate, while uniqueness and runtime meaning
//! remain the caller's responsibility.  Address translation is supplied by
//! the caller so this parser never opens a file or consults a process.

use std::fmt;

pub const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;
/// The public candidate projection retains at most 1,024 candidates.
pub const MAX_CANDIDATES: usize = 1024;
pub const MAX_FIELDS: usize = 32;
pub const MAX_COUNT: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressMapping {
    pub file_offset: usize,
    pub available_bytes: usize,
}

/// Maps a target address to the captured bytes containing that address.
pub trait AddressMapper {
    fn map(&self, address: u64, size: usize) -> Option<AddressMapping>;
}

impl<F> AddressMapper for F
where
    F: Fn(u64, usize) -> Option<AddressMapping>,
{
    fn map(&self, address: u64, size: usize) -> Option<AddressMapping> {
        self(address, size)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataVersion {
    V29,
    V31,
    V39,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerWidth {
    Bits32,
    Bits64,
}

impl PointerWidth {
    fn bytes(self) -> usize {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endianness {
    Little,
    Big,
}

impl MetadataVersion {
    pub fn parse(value: u32) -> Result<Self, ScanError> {
        match value {
            29 => Ok(Self::V29),
            31 => Ok(Self::V31),
            39 => Ok(Self::V39),
            other => Err(ScanError::UnsupportedMetadataVersion(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationState {
    Validated,
    Ambiguous,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldEvidence {
    pub index: usize,
    pub count: u64,
    pub pointer: u64,
    pub pointer_file_offset: Option<usize>,
    pub required_bytes: usize,
    pub valid: bool,
    /// Method-pointer facts decoded from this validated pointer table.
    pub method_pointers: Vec<MethodPointerFact>,
}

/// Source facts for one pointer-table entry retained by the registration scan.
///
/// The slot offset identifies the bytes that produced the pointer. The target
/// offset is populated only when the caller's mapping proves a unique
/// file-backed target, so downstream method-address joins never infer a file
/// location from a virtual address alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodPointerFact {
    pub index: usize,
    pub pointer: u64,
    pub source_file_offset: usize,
    pub target_file_offset: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationCandidate {
    pub root_file_offset: usize,
    pub metadata_version: MetadataVersion,
    pub pointer_width: PointerWidth,
    pub endianness: Endianness,
    pub fields: Vec<FieldEvidence>,
    pub validated_fields: usize,
    pub state: ValidationState,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanReport {
    pub metadata_version: MetadataVersion,
    pub pointer_width: PointerWidth,
    pub endianness: Endianness,
    pub candidates: Vec<RegistrationCandidate>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanError {
    InputTooLarge { actual: usize, maximum: usize },
    UnsupportedMetadataVersion(u32),
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { actual, maximum } => {
                write!(formatter, "input is {actual} bytes; maximum is {maximum}")
            }
            Self::UnsupportedMetadataVersion(version) => {
                write!(formatter, "unsupported IL2CPP metadata version {version}")
            }
        }
    }
}

/// Scan an already-captured 64-bit image using the caller's address mapper.
///
/// The scanner recognizes the common registration layout of a 32-bit count
/// followed by pointer-alignment padding and a native pointer.  It reports
/// every plausible root and intentionally never promotes a candidate to a
/// unique answer merely because it scored well.
pub fn scan<M: AddressMapper>(
    bytes: &[u8],
    metadata_version: u32,
    mapper: &M,
) -> Result<ScanReport, ScanError> {
    scan_with_layout(
        bytes,
        metadata_version,
        PointerWidth::Bits64,
        Endianness::Little,
        mapper,
    )
}

/// Scan an already-captured image with an explicit native layout.
pub fn scan_with_layout<M: AddressMapper>(
    bytes: &[u8],
    metadata_version: u32,
    pointer_width: PointerWidth,
    endianness: Endianness,
    mapper: &M,
) -> Result<ScanReport, ScanError> {
    let version = MetadataVersion::parse(metadata_version)?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(ScanError::InputTooLarge {
            actual: bytes.len(),
            maximum: MAX_INPUT_BYTES,
        });
    }

    let mut candidates = Vec::new();
    let root_alignment = pointer_width.bytes();
    let field_size = root_alignment.saturating_mul(2);
    let last = bytes.len().saturating_sub(field_size);
    let mut offset = 0usize;
    while offset <= last && candidates.len() < MAX_CANDIDATES {
        if let Some(candidate) =
            inspect_root(bytes, offset, version, pointer_width, endianness, mapper)
        {
            candidates.push(candidate);
        }
        offset = offset.saturating_add(root_alignment);
    }
    let candidate_limit_reached = candidates.len() == MAX_CANDIDATES && offset <= last;

    if candidates.len() > 1 {
        for candidate in &mut candidates {
            if candidate.state == ValidationState::Validated {
                candidate.state = ValidationState::Ambiguous;
                candidate
                    .evidence
                    .push("multiple plausible roots were observed".into());
            }
        }
    }

    let mut limitations = vec![
        "Registration-shaped layouts are interpreted using the reported pointer width and byte order.".into(),
        "A mapped pointer proves captured-byte availability, not runtime ownership or use.".into(),
        "Multiple candidates remain ambiguous; this scan does not identify the active registration.".into(),
    ];
    if candidate_limit_reached {
        limitations.push(
            "The candidate limit was reached before the captured byte range was exhausted; additional candidates are unknown.".into(),
        );
    }

    Ok(ScanReport {
        metadata_version: version,
        pointer_width,
        endianness,
        candidates,
        limitations,
    })
}

fn inspect_root<M: AddressMapper>(
    bytes: &[u8],
    root: usize,
    version: MetadataVersion,
    pointer_width: PointerWidth,
    endianness: Endianness,
    mapper: &M,
) -> Option<RegistrationCandidate> {
    let mut fields = Vec::new();
    let mut validated_fields = 0usize;
    let mut nonzero_fields = 0usize;

    for index in 0..MAX_FIELDS {
        let field = match inspect_field(bytes, root, index, pointer_width, endianness, mapper) {
            Some(field) => field,
            None => break,
        };

        if field.pointer != 0 {
            nonzero_fields += 1;
        }
        if field.valid {
            validated_fields += 1;
        }
        fields.push(field);
    }

    // A valid registration may contain empty tables. Keep a root when at least
    // one table has a non-zero pointer, even if the capture ends before the
    // minimum layout is available. The caller can then distinguish a partial
    // candidate from no observation and retain the fields that were decoded.
    if fields.is_empty() || nonzero_fields == 0 {
        return None;
    }

    let minimum_field_count = minimum_fields(version);
    let state = candidate_state(validated_fields, fields.len(), minimum_field_count);
    let evidence = candidate_evidence(state, fields.len(), nonzero_fields, minimum_field_count);

    Some(RegistrationCandidate {
        root_file_offset: root,
        metadata_version: version,
        pointer_width,
        endianness,
        fields,
        validated_fields,
        state,
        evidence,
    })
}

fn inspect_field<M: AddressMapper>(
    bytes: &[u8],
    root: usize,
    index: usize,
    pointer_width: PointerWidth,
    endianness: Endianness,
    mapper: &M,
) -> Option<FieldEvidence> {
    let field_size = pointer_width.bytes().checked_mul(2)?;
    let field_offset = root.checked_add(index.checked_mul(field_size)?)?;
    let count = u64::from(read_u32(bytes, field_offset, endianness)?);
    let pointer_offset = field_offset.checked_add(pointer_width.bytes())?;
    let pointer = read_pointer(bytes, pointer_offset, pointer_width, endianness)?;
    if count > MAX_COUNT {
        return Some(FieldEvidence {
            index,
            count,
            pointer,
            pointer_file_offset: None,
            required_bytes: 0,
            valid: false,
            method_pointers: Vec::new(),
        });
    }

    let required_bytes = checked_required_bytes(count, pointer_width)?;
    let mapping = (count != 0 && pointer != 0)
        .then(|| mapper.map(pointer, required_bytes))
        .flatten();
    let captured_mapping =
        mapping.filter(|value| mapping_covers_capture(*value, required_bytes, bytes.len()));
    let valid = count == 0 || (pointer != 0 && captured_mapping.is_some());

    let method_pointers = if valid && count != 0 {
        captured_mapping
            .into_iter()
            .flat_map(|mapping| {
                (0..count as usize).filter_map(move |index| {
                    let entry_offset = mapping
                        .file_offset
                        .checked_add(index.checked_mul(pointer_width.bytes())?)?;
                    let pointer = read_pointer(bytes, entry_offset, pointer_width, endianness)?;
                    let target_file_offset = (pointer != 0)
                        .then(|| mapper.map(pointer, 1))
                        .flatten()
                        .and_then(|target| {
                            mapping_covers_capture(target, 1, bytes.len())
                                .then_some(target.file_offset)
                        });
                    Some(MethodPointerFact {
                        index,
                        pointer,
                        source_file_offset: entry_offset,
                        target_file_offset,
                    })
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    Some(FieldEvidence {
        index,
        count,
        pointer,
        pointer_file_offset: captured_mapping.map(|value| value.file_offset),
        required_bytes,
        valid,
        method_pointers,
    })
}

fn candidate_state(
    validated_fields: usize,
    field_count: usize,
    minimum_field_count: usize,
) -> ValidationState {
    if field_count < minimum_field_count || validated_fields != field_count {
        ValidationState::Rejected
    } else {
        ValidationState::Validated
    }
}

fn candidate_evidence(
    state: ValidationState,
    field_count: usize,
    nonzero_fields: usize,
    minimum_field_count: usize,
) -> Vec<String> {
    let mut evidence = vec![format!(
        "root contains {field_count} registration-shaped count/pointer fields"
    )];
    if nonzero_fields == 1 {
        evidence.push(
            "root contains one populated table; remaining tables may be empty in this capture"
                .into(),
        );
    }
    if state == ValidationState::Rejected {
        if field_count < minimum_field_count {
            evidence.push(format!(
                "captured root ended after {field_count} fields; at least {minimum_field_count} are required for this metadata version"
            ));
        } else {
            evidence
                .push("at least one required pointer was unavailable in the supplied bytes".into());
        }
    }
    evidence
}

fn mapping_covers_capture(
    mapping: AddressMapping,
    required_bytes: usize,
    capture_len: usize,
) -> bool {
    mapping.available_bytes >= required_bytes
        && mapping
            .file_offset
            .checked_add(required_bytes)
            .is_some_and(|end| end <= capture_len)
}

fn minimum_fields(version: MetadataVersion) -> usize {
    match version {
        MetadataVersion::V29 => 4,
        MetadataVersion::V31 => 4,
        MetadataVersion::V39 => 5,
    }
}

fn checked_required_bytes(count: u64, pointer_width: PointerWidth) -> Option<usize> {
    let bytes = count.checked_mul(pointer_width.bytes() as u64)?;
    usize::try_from(bytes).ok()
}

fn read_u32(bytes: &[u8], offset: usize, endianness: Endianness) -> Option<u32> {
    let data = bytes.get(offset..offset.checked_add(4)?)?;
    Some(match endianness {
        Endianness::Little => u32::from_le_bytes(data.try_into().ok()?),
        Endianness::Big => u32::from_be_bytes(data.try_into().ok()?),
    })
}

fn read_pointer(
    bytes: &[u8],
    offset: usize,
    pointer_width: PointerWidth,
    endianness: Endianness,
) -> Option<u64> {
    if pointer_width == PointerWidth::Bits32 {
        return Some(u64::from(read_u32(bytes, offset, endianness)?));
    }

    let data = bytes.get(offset..offset.checked_add(8)?)?;
    Some(match endianness {
        Endianness::Little => u64::from_le_bytes(data.try_into().ok()?),
        Endianness::Big => u64::from_be_bytes(data.try_into().ok()?),
    })
}
