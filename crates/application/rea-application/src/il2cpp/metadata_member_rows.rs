//! Bounded decoding of the member tables in an IL2CPP metadata artifact.
//!
//! This module intentionally does not discover section offsets or interpret
//! the surrounding metadata header.  The caller supplies section descriptors
//! that have already been selected from the artifact.  Keeping those concerns
//! separate makes it possible to reuse this decoder for captured sections and
//! to validate every range before reading a record.

use std::fmt;

/// Metadata versions whose member record layouts are covered by this parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataVersion {
    V29,
    V31,
    V39,
}

impl TryFrom<u32> for MetadataVersion {
    type Error = UnsupportedMetadataVersion;

    fn try_from(version: u32) -> Result<Self, Self::Error> {
        match version {
            29 => Ok(Self::V29),
            31 => Ok(Self::V31),
            39 => Ok(Self::V39),
            other => Err(UnsupportedMetadataVersion(other)),
        }
    }
}

/// A version number that this decoder does not support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedMetadataVersion(pub u32);

impl fmt::Display for UnsupportedMetadataVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unsupported IL2CPP metadata version {}", self.0)
    }
}

impl std::error::Error for UnsupportedMetadataVersion {}

/// A byte range and optional header-provided row count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SectionDescriptor {
    pub offset: usize,
    pub size: usize,
    pub count: Option<usize>,
}

impl SectionDescriptor {
    pub const fn new(offset: usize, size: usize, count: Option<usize>) -> Self {
        Self {
            offset,
            size,
            count,
        }
    }
}

/// The member sections needed by [`parse_member_rows`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberSectionDescriptors {
    pub fields: SectionDescriptor,
    pub properties: SectionDescriptor,
    pub events: SectionDescriptor,
    pub parameters: SectionDescriptor,
}

/// A row in the IL2CPP field-definition table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldRow {
    pub index: usize,
    pub source_offset: usize,
    pub name_index: u32,
    pub type_index: u32,
    pub custom_attribute_index: u32,
    pub token: u32,
}

/// A row in the IL2CPP property-definition table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PropertyRow {
    pub index: usize,
    pub source_offset: usize,
    pub name_index: u32,
    pub getter_index: i32,
    pub setter_index: i32,
    pub attributes: u32,
    pub token: u32,
}

/// A row in the IL2CPP event-definition table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventRow {
    pub index: usize,
    pub source_offset: usize,
    pub name_index: u32,
    pub type_index: u32,
    pub add_index: i32,
    pub remove_index: i32,
    pub raise_index: i32,
    pub token: u32,
}

/// A row in the IL2CPP parameter-definition table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParameterRow {
    pub index: usize,
    pub source_offset: usize,
    pub name_index: u32,
    pub token: u32,
    pub type_index: u32,
    pub custom_attribute_index: u32,
    pub flags: u32,
}

/// All decoded member rows, retaining each row's original index and offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberRows {
    pub fields: Vec<FieldRow>,
    pub properties: Vec<PropertyRow>,
    pub events: Vec<EventRow>,
    pub parameters: Vec<ParameterRow>,
}

/// Member ranges declared by one type-definition row.
///
/// A start of `-1` is the metadata sentinel for an omitted range.  Other
/// negative starts, and non-empty ranges with a `-1` start, are retained as
/// malformed diagnostics by [`resolve_member_ownership`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypeMemberRanges {
    pub type_index: usize,
    pub field_start: i64,
    pub field_count: usize,
    pub property_start: i64,
    pub property_count: usize,
    pub event_start: i64,
    pub event_count: usize,
    pub parameter_start: i64,
    pub parameter_count: usize,
}

/// The owner claims for one decoded member row.
///
/// An empty owner list means unresolved.  More than one owner preserves a
/// duplicate claim instead of silently choosing whichever type was visited
/// first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowOwnership {
    pub row_index: usize,
    pub owner_type_indices: Vec<usize>,
}

/// A malformed type range retained alongside the ownership result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MalformedMemberRange {
    pub type_index: usize,
    pub member_kind: &'static str,
    pub start: i64,
    pub count: usize,
    pub row_count: usize,
    pub reason: &'static str,
}

/// Ownership results for every member table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberOwnership {
    pub fields: Vec<RowOwnership>,
    pub properties: Vec<RowOwnership>,
    pub events: Vec<RowOwnership>,
    pub parameters: Vec<RowOwnership>,
    pub malformed_ranges: Vec<MalformedMemberRange>,
}

/// A raw accessor method reference and its bounded resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessorReference {
    pub target_index: i32,
    pub resolved_index: Option<usize>,
}

/// Getter/setter references for one property row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PropertyAccessors {
    pub property_index: usize,
    pub getter: AccessorReference,
    pub setter: AccessorReference,
}

/// Add/remove/raise references for one event row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventAccessors {
    pub event_index: usize,
    pub add: AccessorReference,
    pub remove: AccessorReference,
    pub raise: AccessorReference,
}

/// Accessor relationships, retaining unresolved raw method indices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessorRelationships {
    pub properties: Vec<PropertyAccessors>,
    pub events: Vec<EventAccessors>,
}

/// Errors raised while validating a section or decoding a member record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemberRowsError {
    UnsupportedVersion(UnsupportedMetadataVersion),
    SectionOutsideInput {
        section: &'static str,
        offset: usize,
        size: usize,
        input_len: usize,
    },
    SectionSizeOverflow {
        section: &'static str,
        offset: usize,
        size: usize,
    },
    SectionOverlap {
        first_section: &'static str,
        first_offset: usize,
        first_size: usize,
        second_section: &'static str,
        second_offset: usize,
        second_size: usize,
    },
    CountSizeMismatch {
        section: &'static str,
        count: usize,
        size: usize,
        record_size: usize,
    },
    SectionCountModeMismatch {
        section: &'static str,
        version: MetadataVersion,
        count_present: bool,
    },
    TruncatedRecord {
        section: &'static str,
        index: usize,
        offset: usize,
        record_size: usize,
    },
    Cancelled {
        phase: &'static str,
        index: usize,
    },
}

impl fmt::Display for MemberRowsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(error) => error.fmt(formatter),
            Self::SectionOutsideInput { section, .. } => {
                write!(formatter, "{section} section is outside the input")
            }
            Self::SectionSizeOverflow { section, .. } => {
                write!(formatter, "{section} section range overflows")
            }
            Self::SectionOverlap {
                first_section,
                second_section,
                ..
            } => write!(
                formatter,
                "{first_section} section overlaps {second_section} section"
            ),
            Self::CountSizeMismatch { section, .. } => {
                write!(formatter, "{section} section count does not match its size")
            }
            Self::SectionCountModeMismatch {
                section,
                version,
                count_present,
            } => {
                let expected = if *version == MetadataVersion::V39 {
                    "a header count"
                } else {
                    "no header count"
                };
                let actual = if *count_present {
                    "a header count"
                } else {
                    "no header count"
                };
                write!(
                    formatter,
                    "{section} section for metadata version {version:?} has {actual}; expected {expected}"
                )
            }
            Self::TruncatedRecord { section, index, .. } => {
                write!(formatter, "{section} row {index} is truncated")
            }
            Self::Cancelled { phase, index } => {
                write!(
                    formatter,
                    "IL2CPP member {phase} was cancelled at item {index}"
                )
            }
        }
    }
}

impl std::error::Error for MemberRowsError {}

/// Resolve type-declared ranges to member rows without losing ambiguous data.
///
/// Every decoded row receives exactly one result.  Ranges are allowed to
/// overlap so duplicate ownership remains observable, and ranges that point
/// outside a table are recorded as malformed while valid portions from other
/// types continue to resolve.  This is deliberately a relationship pass: it
/// does not rewrite or filter the raw rows returned by [`parse_member_rows`].
/// The retained row indices, rather than vector positions, are used when
/// matching ranges so callers can preserve sparse or reordered source rows.
pub fn resolve_member_ownership(
    rows: &MemberRows,
    type_ranges: &[TypeMemberRanges],
) -> MemberOwnership {
    resolve_member_ownership_cancellable(rows, type_ranges, || false)
        .unwrap_or_else(|_| unreachable!("disabled cancellation cannot be observed"))
}

/// Resolve type-declared ranges while polling a caller-owned cancellation
/// predicate. Cancellation is reported explicitly and never converted into a
/// malformed range diagnostic.
pub fn resolve_member_ownership_cancellable(
    rows: &MemberRows,
    type_ranges: &[TypeMemberRanges],
    mut should_cancel: impl FnMut() -> bool,
) -> Result<MemberOwnership, MemberRowsError> {
    let mut malformed_ranges = Vec::new();

    let fields = resolve_table(
        "field",
        &rows.fields,
        |row| row.index,
        type_ranges,
        |ranges| (ranges.field_start, ranges.field_count),
        &mut malformed_ranges,
        &mut should_cancel,
    )?;
    let properties = resolve_table(
        "property",
        &rows.properties,
        |row| row.index,
        type_ranges,
        |ranges| (ranges.property_start, ranges.property_count),
        &mut malformed_ranges,
        &mut should_cancel,
    )?;
    let events = resolve_table(
        "event",
        &rows.events,
        |row| row.index,
        type_ranges,
        |ranges| (ranges.event_start, ranges.event_count),
        &mut malformed_ranges,
        &mut should_cancel,
    )?;
    let parameters = resolve_table(
        "parameter",
        &rows.parameters,
        |row| row.index,
        type_ranges,
        |ranges| (ranges.parameter_start, ranges.parameter_count),
        &mut malformed_ranges,
        &mut should_cancel,
    )?;

    Ok(MemberOwnership {
        fields,
        properties,
        events,
        parameters,
        malformed_ranges,
    })
}

/// Version-aware ownership entry point for callers that retain the metadata
/// header version alongside the type ranges.
pub fn resolve_member_ownership_for_version(
    version: u32,
    rows: &MemberRows,
    type_ranges: &[TypeMemberRanges],
) -> Result<MemberOwnership, MemberRowsError> {
    MetadataVersion::try_from(version).map_err(MemberRowsError::UnsupportedVersion)?;
    Ok(resolve_member_ownership(rows, type_ranges))
}

/// Version-aware ownership resolution with bounded cancellation polling.
pub fn resolve_member_ownership_for_version_cancellable(
    version: u32,
    rows: &MemberRows,
    type_ranges: &[TypeMemberRanges],
    should_cancel: impl FnMut() -> bool,
) -> Result<MemberOwnership, MemberRowsError> {
    MetadataVersion::try_from(version).map_err(MemberRowsError::UnsupportedVersion)?;
    resolve_member_ownership_cancellable(rows, type_ranges, should_cancel)
}

/// Resolve property and event accessors against a caller-supplied method-row
/// count.  Sentinel values and out-of-range references remain visible as
/// unresolved raw indices; no accessor is silently dropped.
pub fn resolve_accessor_relationships(
    rows: &MemberRows,
    method_count: usize,
) -> AccessorRelationships {
    let resolve = |target_index: i32| AccessorReference {
        target_index,
        resolved_index: usize::try_from(target_index)
            .ok()
            .filter(|index| *index < method_count),
    };

    let properties = rows
        .properties
        .iter()
        .map(|row| PropertyAccessors {
            property_index: row.index,
            getter: resolve(row.getter_index),
            setter: resolve(row.setter_index),
        })
        .collect();
    let events = rows
        .events
        .iter()
        .map(|row| EventAccessors {
            event_index: row.index,
            add: resolve(row.add_index),
            remove: resolve(row.remove_index),
            raise: resolve(row.raise_index),
        })
        .collect();

    AccessorRelationships { properties, events }
}

/// Decode fields, properties, events, and parameters from validated sections.
///
/// Versions 29 and 31 derive row counts from section sizes; version 39 uses
/// the header count and still checks it against the section size.  Record
/// values are retained as raw little-endian integers.  Signed accessor
/// indices preserve the metadata `-1` missing sentinel without turning it
/// into a large unsigned method index.
pub fn parse_member_rows(
    version: MetadataVersion,
    input: &[u8],
    sections: &MemberSectionDescriptors,
) -> Result<MemberRows, MemberRowsError> {
    parse_member_rows_cancellable(version, input, sections, || false)
}

/// Decode member rows while polling a caller-owned cancellation predicate.
/// Cancellation is returned as [`MemberRowsError::Cancelled`] so callers can
/// distinguish it from malformed metadata and preserve lifecycle semantics.
pub fn parse_member_rows_cancellable(
    version: MetadataVersion,
    input: &[u8],
    sections: &MemberSectionDescriptors,
    mut should_cancel: impl FnMut() -> bool,
) -> Result<MemberRows, MemberRowsError> {
    validate_section_count_modes(version, sections)?;
    validate_section_layout(sections, input)?;

    if should_cancel() {
        return Err(MemberRowsError::Cancelled {
            phase: "section decoding",
            index: 0,
        });
    }

    let fields = decode_section(
        "fields",
        sections.fields,
        input,
        16,
        |bytes, index, source_offset| {
            Ok(FieldRow {
                index,
                source_offset,
                name_index: read_u32(bytes, 0),
                type_index: read_u32(bytes, 4),
                custom_attribute_index: read_u32(bytes, 8),
                token: read_u32(bytes, 12),
            })
        },
        &mut should_cancel,
    )?;
    let properties = decode_section(
        "properties",
        sections.properties,
        input,
        20,
        |bytes, index, source_offset| {
            Ok(PropertyRow {
                index,
                source_offset,
                name_index: read_u32(bytes, 0),
                getter_index: read_i32(bytes, 4),
                setter_index: read_i32(bytes, 8),
                attributes: read_u32(bytes, 12),
                token: read_u32(bytes, 16),
            })
        },
        &mut should_cancel,
    )?;
    let events = decode_section(
        "events",
        sections.events,
        input,
        24,
        |bytes, index, source_offset| {
            Ok(EventRow {
                index,
                source_offset,
                name_index: read_u32(bytes, 0),
                type_index: read_u32(bytes, 4),
                add_index: read_i32(bytes, 8),
                remove_index: read_i32(bytes, 12),
                raise_index: read_i32(bytes, 16),
                token: read_u32(bytes, 20),
            })
        },
        &mut should_cancel,
    )?;
    let parameters = decode_section(
        "parameters",
        sections.parameters,
        input,
        20,
        |bytes, index, source_offset| {
            Ok(ParameterRow {
                index,
                source_offset,
                name_index: read_u32(bytes, 0),
                token: read_u32(bytes, 4),
                type_index: read_u32(bytes, 8),
                custom_attribute_index: read_u32(bytes, 12),
                flags: read_u32(bytes, 16),
            })
        },
        &mut should_cancel,
    )?;

    Ok(MemberRows {
        fields,
        properties,
        events,
        parameters,
    })
}

fn validate_section_count_modes(
    version: MetadataVersion,
    sections: &MemberSectionDescriptors,
) -> Result<(), MemberRowsError> {
    let entries = [
        ("fields", sections.fields),
        ("properties", sections.properties),
        ("events", sections.events),
        ("parameters", sections.parameters),
    ];
    let counted_version = version == MetadataVersion::V39;

    for (section, descriptor) in entries {
        let count_present = descriptor.count.is_some();
        if count_present != counted_version {
            return Err(MemberRowsError::SectionCountModeMismatch {
                section,
                version,
                count_present,
            });
        }
    }

    Ok(())
}

/// Convenience entry point for callers that retain the numeric header value.
pub fn parse_member_rows_for_version(
    version: u32,
    input: &[u8],
    sections: &MemberSectionDescriptors,
) -> Result<MemberRows, MemberRowsError> {
    let version =
        MetadataVersion::try_from(version).map_err(MemberRowsError::UnsupportedVersion)?;
    parse_member_rows(version, input, sections)
}

/// Numeric-version entry point for cancellable member-row decoding.
pub fn parse_member_rows_for_version_cancellable(
    version: u32,
    input: &[u8],
    sections: &MemberSectionDescriptors,
    should_cancel: impl FnMut() -> bool,
) -> Result<MemberRows, MemberRowsError> {
    let version =
        MetadataVersion::try_from(version).map_err(MemberRowsError::UnsupportedVersion)?;
    parse_member_rows_cancellable(version, input, sections, should_cancel)
}

fn decode_section<T>(
    section: &'static str,
    descriptor: SectionDescriptor,
    input: &[u8],
    record_size: usize,
    mut decode: impl FnMut(&[u8], usize, usize) -> Result<T, MemberRowsError>,
    should_cancel: &mut impl FnMut() -> bool,
) -> Result<Vec<T>, MemberRowsError> {
    let end = descriptor.offset.checked_add(descriptor.size).ok_or(
        MemberRowsError::SectionSizeOverflow {
            section,
            offset: descriptor.offset,
            size: descriptor.size,
        },
    )?;
    if end > input.len() {
        return Err(MemberRowsError::SectionOutsideInput {
            section,
            offset: descriptor.offset,
            size: descriptor.size,
            input_len: input.len(),
        });
    }

    let count = match descriptor.count {
        Some(count) => count,
        None => row_count(section, descriptor.size, record_size)?,
    };
    validate_count(section, count, descriptor.size, record_size)?;

    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        if should_cancel() {
            return Err(MemberRowsError::Cancelled {
                phase: section,
                index,
            });
        }

        let relative =
            index
                .checked_mul(record_size)
                .ok_or(MemberRowsError::SectionSizeOverflow {
                    section,
                    offset: descriptor.offset,
                    size: descriptor.size,
                })?;
        let start = descriptor.offset.checked_add(relative).ok_or(
            MemberRowsError::SectionSizeOverflow {
                section,
                offset: descriptor.offset,
                size: descriptor.size,
            },
        )?;
        let end = start
            .checked_add(record_size)
            .ok_or(MemberRowsError::SectionSizeOverflow {
                section,
                offset: start,
                size: record_size,
            })?;
        let bytes = input
            .get(start..end)
            .ok_or(MemberRowsError::TruncatedRecord {
                section,
                index,
                offset: start,
                record_size,
            })?;
        rows.push(decode(bytes, index, start)?);
    }
    Ok(rows)
}

fn validate_section_layout(
    sections: &MemberSectionDescriptors,
    input: &[u8],
) -> Result<(), MemberRowsError> {
    let mut ranges = [
        ("fields", sections.fields),
        ("properties", sections.properties),
        ("events", sections.events),
        ("parameters", sections.parameters),
    ];

    for (section, descriptor) in ranges.iter() {
        let end = descriptor.offset.checked_add(descriptor.size).ok_or(
            MemberRowsError::SectionSizeOverflow {
                section: *section,
                offset: descriptor.offset,
                size: descriptor.size,
            },
        )?;
        if end > input.len() {
            return Err(MemberRowsError::SectionOutsideInput {
                section: *section,
                offset: descriptor.offset,
                size: descriptor.size,
                input_len: input.len(),
            });
        }
    }

    ranges.sort_by_key(|(_, descriptor)| descriptor.offset);
    let occupied = ranges
        .into_iter()
        .filter(|(_, descriptor)| descriptor.size > 0)
        .collect::<Vec<_>>();

    for pair in occupied.windows(2) {
        let (first_section, first) = pair[0];
        let (second_section, second) = pair[1];

        let first_end = first.offset + first.size;
        if first_end > second.offset {
            return Err(MemberRowsError::SectionOverlap {
                first_section,
                first_offset: first.offset,
                first_size: first.size,
                second_section,
                second_offset: second.offset,
                second_size: second.size,
            });
        }
    }

    Ok(())
}

fn resolve_table<T>(
    member_kind: &'static str,
    rows: &[T],
    row_index: impl Fn(&T) -> usize + Copy,
    type_ranges: &[TypeMemberRanges],
    range: impl Fn(&TypeMemberRanges) -> (i64, usize),
    malformed_ranges: &mut Vec<MalformedMemberRange>,
    should_cancel: &mut impl FnMut() -> bool,
) -> Result<Vec<RowOwnership>, MemberRowsError> {
    if should_cancel() {
        return Err(MemberRowsError::Cancelled {
            phase: member_kind,
            index: 0,
        });
    }

    let (index_lookup, row_count) =
        RowIndexLookup::new(rows, row_index, member_kind, should_cancel)?;
    let mut owners = vec![Vec::new(); rows.len()];

    for (range_index, type_range) in type_ranges.iter().enumerate() {
        if should_cancel() {
            return Err(MemberRowsError::Cancelled {
                phase: member_kind,
                index: range_index,
            });
        }

        let (start, count) = range(type_range);
        let Some(start_index) = valid_range_start(
            member_kind,
            type_range.type_index,
            start,
            count,
            row_count,
            malformed_ranges,
        ) else {
            continue;
        };
        let end = start_index + count;

        let checked_end = end.min(row_count);
        let expected_rows = checked_end.saturating_sub(start_index);
        let mut present_rows = 0;
        let mut previous_row_index = None;

        for (row_index, position) in index_lookup.matching_range(start_index, end) {
            if should_cancel() {
                return Err(MemberRowsError::Cancelled {
                    phase: member_kind,
                    index: position,
                });
            }

            if previous_row_index != Some(row_index) {
                if row_index < checked_end {
                    present_rows += 1;
                }
                previous_row_index = Some(row_index);
            }

            owners[position].push(type_range.type_index);
        }

        // A decoded table may be sparse when an upstream boundary filters or
        // reorders source rows. Keep valid claims, while preserving the
        // missing portion as an explicit diagnostic.
        if present_rows != expected_rows {
            malformed_ranges.push(MalformedMemberRange {
                type_index: type_range.type_index,
                member_kind,
                start,
                count,
                row_count,
                reason: "range references rows absent from the decoded table",
            });
        }
    }

    Ok(owners
        .into_iter()
        .enumerate()
        .map(|(position, owner_type_indices)| RowOwnership {
            row_index: row_index(&rows[position]),
            owner_type_indices,
        })
        .collect())
}

struct RowIndexLookup<'a, T, F> {
    rows: &'a [T],
    row_index: F,
    reordered_positions: Option<Vec<(usize, usize)>>,
}

impl<'a, T, F> RowIndexLookup<'a, T, F>
where
    F: Fn(&T) -> usize + Copy,
{
    fn new(
        rows: &'a [T],
        row_index: F,
        member_kind: &'static str,
        should_cancel: &mut impl FnMut() -> bool,
    ) -> Result<(Self, usize), MemberRowsError> {
        let mut previous = None;
        let mut is_sorted = true;
        let mut row_count = 0;

        for (position, row) in rows.iter().enumerate() {
            let index = row_index(row);
            if position % 1024 == 0 && should_cancel() {
                return Err(MemberRowsError::Cancelled {
                    phase: member_kind,
                    index: position,
                });
            }

            row_count = row_count.max(index.saturating_add(1));
            if previous.is_some_and(|previous| previous > index) {
                is_sorted = false;
            }
            previous = Some(index);
        }

        if is_sorted {
            if should_cancel() {
                return Err(MemberRowsError::Cancelled {
                    phase: member_kind,
                    index: rows.len(),
                });
            }

            return Ok((
                Self {
                    rows,
                    row_index,
                    reordered_positions: None,
                },
                row_count,
            ));
        }

        let mut indexed_rows = Vec::with_capacity(rows.len());
        for (position, row) in rows.iter().enumerate() {
            if position % 1024 == 0 && should_cancel() {
                return Err(MemberRowsError::Cancelled {
                    phase: member_kind,
                    index: position,
                });
            }
            indexed_rows.push((row_index(row), position));
        }

        if should_cancel() {
            return Err(MemberRowsError::Cancelled {
                phase: member_kind,
                index: rows.len(),
            });
        }
        indexed_rows.sort_unstable();

        if should_cancel() {
            return Err(MemberRowsError::Cancelled {
                phase: member_kind,
                index: rows.len(),
            });
        }

        Ok((
            Self {
                rows,
                row_index,
                reordered_positions: Some(indexed_rows),
            },
            row_count,
        ))
    }

    fn matching_range<'b>(&'b self, start: usize, end: usize) -> RowIndexMatches<'b, T, F>
    where
        'a: 'b,
    {
        match &self.reordered_positions {
            None => {
                let first = self
                    .rows
                    .partition_point(|row| (self.row_index)(row) < start);
                let last = self.rows.partition_point(|row| (self.row_index)(row) < end);
                RowIndexMatches::AlreadySorted {
                    rows: self.rows,
                    row_index: self.row_index,
                    next: first,
                    end: last,
                }
            }
            Some(indexed_rows) => {
                let first = indexed_rows.partition_point(|(index, _)| *index < start);
                let last = indexed_rows.partition_point(|(index, _)| *index < end);
                RowIndexMatches::Reordered {
                    indexed_rows,
                    next: first,
                    end: last,
                }
            }
        }
    }
}

enum RowIndexMatches<'a, T, F> {
    AlreadySorted {
        rows: &'a [T],
        row_index: F,
        next: usize,
        end: usize,
    },
    Reordered {
        indexed_rows: &'a [(usize, usize)],
        next: usize,
        end: usize,
    },
}

impl<T, F> Iterator for RowIndexMatches<'_, T, F>
where
    F: Fn(&T) -> usize + Copy,
{
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::AlreadySorted {
                rows,
                row_index,
                next,
                end,
            } => {
                if *next == *end {
                    return None;
                }

                let position = *next;
                *next += 1;
                Some((row_index(&rows[position]), position))
            }
            Self::Reordered {
                indexed_rows,
                next,
                end,
            } => {
                if *next == *end {
                    return None;
                }

                let value = indexed_rows[*next];
                *next += 1;
                Some(value)
            }
        }
    }
}

fn valid_range_start(
    member_kind: &'static str,
    type_index: usize,
    start: i64,
    count: usize,
    row_count: usize,
    malformed_ranges: &mut Vec<MalformedMemberRange>,
) -> Option<usize> {
    if start == -1 && count == 0 {
        return None;
    }
    if start < 0 {
        malformed_ranges.push(MalformedMemberRange {
            type_index,
            member_kind,
            start,
            count,
            row_count,
            reason: "negative start is not the empty-range sentinel",
        });
        return None;
    }

    let Ok(start_index) = usize::try_from(start) else {
        malformed_ranges.push(MalformedMemberRange {
            type_index,
            member_kind,
            start,
            count,
            row_count,
            reason: "range start cannot be represented as an index",
        });
        return None;
    };
    let Some(end) = start_index.checked_add(count) else {
        malformed_ranges.push(MalformedMemberRange {
            type_index,
            member_kind,
            start,
            count,
            row_count,
            reason: "range end overflows",
        });
        return None;
    };
    if end > row_count {
        malformed_ranges.push(MalformedMemberRange {
            type_index,
            member_kind,
            start,
            count,
            row_count,
            reason: "range extends beyond the decoded rows",
        });

        // The TypeScript decoder treats an empty range beyond the table as
        // invalid rather than as a valid no-op.  There is no valid prefix to
        // retain for that case, so do not let it continue into ownership
        // resolution.  Non-empty ranges still return their valid prefix so
        // callers retain source-backed facts alongside the malformed tail.
        if count == 0 {
            return None;
        }

        // The in-range prefix is still source-backed ownership evidence. Keep
        // it available to callers while retaining the malformed tail as an
        // explicit diagnostic. This also preserves duplicate claims when a
        // second type overlaps the valid prefix.
    }
    Some(start_index)
}

fn row_count(
    section: &'static str,
    size: usize,
    record_size: usize,
) -> Result<usize, MemberRowsError> {
    if size % record_size != 0 {
        return Err(MemberRowsError::CountSizeMismatch {
            section,
            count: size / record_size,
            size,
            record_size,
        });
    }
    Ok(size / record_size)
}

fn validate_count(
    section: &'static str,
    count: usize,
    size: usize,
    record_size: usize,
) -> Result<(), MemberRowsError> {
    if count.checked_mul(record_size) != Some(size) {
        return Err(MemberRowsError::CountSizeMismatch {
            section,
            count,
            size,
            record_size,
        });
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::{FieldRow, MemberRows, TypeMemberRanges, resolve_member_ownership_cancellable};

    #[test]
    fn ownership_preserves_reordered_duplicate_rows_and_missing_range_diagnostics() {
        let rows = MemberRows {
            fields: [2, 0, 0]
                .into_iter()
                .map(|index| FieldRow {
                    index,
                    source_offset: index * 16,
                    name_index: 0,
                    type_index: 0,
                    custom_attribute_index: 0,
                    token: 0,
                })
                .collect(),
            properties: Vec::new(),
            events: Vec::new(),
            parameters: Vec::new(),
        };
        let type_ranges = [
            TypeMemberRanges {
                type_index: 10,
                field_start: 0,
                field_count: 2,
                property_start: -1,
                property_count: 0,
                event_start: -1,
                event_count: 0,
                parameter_start: -1,
                parameter_count: 0,
            },
            TypeMemberRanges {
                type_index: 11,
                field_start: 2,
                field_count: 1,
                property_start: -1,
                property_count: 0,
                event_start: -1,
                event_count: 0,
                parameter_start: -1,
                parameter_count: 0,
            },
        ];

        let ownership = resolve_member_ownership_cancellable(&rows, &type_ranges, || false)
            .expect("valid row tables should resolve");

        assert_eq!(ownership.fields[0].owner_type_indices, vec![11]);
        assert_eq!(ownership.fields[1].owner_type_indices, vec![10]);
        assert_eq!(ownership.fields[2].owner_type_indices, vec![10]);
        assert_eq!(ownership.malformed_ranges.len(), 1);
        assert_eq!(ownership.malformed_ranges[0].type_index, 10);
        assert_eq!(ownership.malformed_ranges[0].member_kind, "field");
        assert_eq!(
            ownership.malformed_ranges[0].reason,
            "range references rows absent from the decoded table"
        );
    }

    #[test]
    fn ownership_reports_cancellation_instead_of_malformed_ranges() {
        let rows = MemberRows {
            fields: Vec::new(),
            properties: Vec::new(),
            events: Vec::new(),
            parameters: Vec::new(),
        };

        let result = resolve_member_ownership_cancellable(&rows, &[], || true);

        assert!(matches!(
            result,
            Err(super::MemberRowsError::Cancelled {
                phase: "field",
                index: 0
            })
        ));
    }
}
