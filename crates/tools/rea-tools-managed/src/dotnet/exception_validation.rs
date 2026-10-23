//! Exception-region extent and instruction-boundary validation.
//!
//! Port of `src/dotnet/ManagedExceptionRegionValidation.ts`. Each clause is
//! retained even when another clause is invalid; the first invalid clause makes
//! the whole section malformed.

use std::collections::BTreeSet;

use super::instruction_decoder::{ExceptionRegionParseResult, ManagedExceptionRegion};

fn clause_flags_issue(region: &ManagedExceptionRegion) -> Option<String> {
    if matches!(region.flags, 0 | 1 | 2 | 4) {
        None
    } else {
        Some(format!(
            "Exception clause has unsupported flags 0x{:x}",
            region.flags
        ))
    }
}

fn method_extent_issue(start: i64, length: i64, il_size: i64, name: &str) -> Option<String> {
    if start <= il_size && length <= il_size - start {
        None
    } else {
        Some(format!(
            "Exception clause {name} range leaves the method IL body"
        ))
    }
}

fn instruction_boundary_issue(
    start: i64,
    length: i64,
    boundaries: &BTreeSet<i64>,
    name: &str,
) -> Option<String> {
    let end = start + length;
    if boundaries.contains(&start) && boundaries.contains(&end) {
        None
    } else {
        Some(format!(
            "Exception clause {name} range does not align with CIL instruction boundaries"
        ))
    }
}

fn filter_ordering_issue(region: &ManagedExceptionRegion, il_size: i64) -> Option<String> {
    if region.flags != 1 {
        return None;
    }
    match region.filter_offset {
        Some(offset) if offset < il_size && offset < region.handler_offset => None,
        _ => Some(
            "Exception clause filter must start before its handler within the method IL body"
                .to_string(),
        ),
    }
}

fn clause_issue(
    region: &ManagedExceptionRegion,
    il_size: i64,
    boundaries: &BTreeSet<i64>,
) -> Option<String> {
    clause_flags_issue(region)
        .or_else(|| method_extent_issue(region.try_offset, region.try_length, il_size, "try"))
        .or_else(|| {
            instruction_boundary_issue(region.try_offset, region.try_length, boundaries, "try")
        })
        .or_else(|| {
            method_extent_issue(
                region.handler_offset,
                region.handler_length,
                il_size,
                "handler",
            )
        })
        .or_else(|| {
            instruction_boundary_issue(
                region.handler_offset,
                region.handler_length,
                boundaries,
                "handler",
            )
        })
        .or_else(|| {
            if region.flags == 1 && region.filter_offset.is_some() {
                instruction_boundary_issue(
                    region.filter_offset.unwrap_or(0),
                    0,
                    boundaries,
                    "filter",
                )
            } else {
                None
            }
        })
        .or_else(|| filter_ordering_issue(region, il_size))
}

/// `validateExceptionRegionRanges(parsed, ilSize, instructionOffsets)`.
pub fn validate_exception_region_ranges(
    parsed: ExceptionRegionParseResult,
    il_size: i64,
    instruction_offsets: &[i64],
) -> ExceptionRegionParseResult {
    if let ExceptionRegionParseResult::Malformed { .. } = parsed {
        return parsed;
    }
    let mut boundaries: BTreeSet<i64> = instruction_offsets.iter().copied().collect();
    boundaries.insert(il_size);
    for region in parsed.regions() {
        if let Some(issue) = clause_issue(region, il_size, &boundaries) {
            let regions = parsed.regions().to_vec();
            return ExceptionRegionParseResult::Malformed { regions, issue };
        }
    }
    parsed
}
