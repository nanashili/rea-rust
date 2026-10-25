//! Bounded byte search over the worker's verified, file-backed image ranges.

use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value, json};

use crate::analysis::image::{self, CoverageRange};
use crate::analysis::{MAX_SEARCH_PATTERN, MAX_SEARCH_RESULTS, numeric};
use crate::protocol::address;
use crate::session::Session;

const DEFAULT_LIMIT: usize = 100;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

struct SearchRequest {
    pattern: Vec<(u8, u8)>,
    lower: u64,
    upper: u64,
    limit: usize,
    cursor: u64,
}

struct RangeWindow {
    start: u64,
    end: u64,
    data_start: usize,
    data_end: usize,
}

struct BlockScan {
    matches: Vec<Value>,
    coverage: Option<Coverage>,
    exhausted: bool,
}

struct Coverage {
    first: u64,
    last: u64,
    bytes: u64,
}

pub(crate) fn search(session: &mut Session, input: Value) -> Result<Value> {
    let request = parse_request(&input)?;
    let (image_bytes, _, slice_offset) = session.decompiler.verified_image()?;
    let ranges = image::coverage_ranges(&image_bytes, slice_offset)?;
    search_ranges(&ranges, &image_bytes, slice_offset, &request)
}

fn search_ranges(
    ranges: &[CoverageRange],
    image_bytes: &[u8],
    slice_offset: u64,
    request: &SearchRequest,
) -> Result<Value> {
    let mut matches = Vec::new();
    let mut searched = Vec::new();
    let mut skipped_uninitialized = Vec::new();
    let mut skipped_not_loaded = Vec::new();
    let mut ordinal = 0_u64;

    for range in ranges {
        let Some(window) = search_window(range, request) else {
            continue;
        };
        if !range.loaded {
            skipped_not_loaded.push(coverage_value(&range.name, window.start, window.end));
            continue;
        }
        if !range.initialized {
            skipped_uninitialized.push(coverage_value(&range.name, window.start, window.end));
            continue;
        }
        let data_window = materialize_window(range, window, slice_offset)?;
        let scan = scan_range(
            range,
            image_bytes,
            data_window,
            &request.pattern,
            request.limit.saturating_sub(matches.len()),
            request.cursor,
            &mut ordinal,
        )?;
        if let Some(coverage) = scan.coverage {
            let mut value = coverage_value(&range.name, coverage.first, coverage.last);
            value["bytes"] = json!(coverage.bytes);
            searched.push(value);
        }
        matches.extend(scan.matches);
        if scan.exhausted || matches.len() == request.limit {
            break;
        }
    }

    let complete = matches.len() < request.limit;
    let searched_bytes = searched
        .iter()
        .filter_map(|block| block.get("bytes").and_then(Value::as_u64))
        .sum::<u64>();
    Ok(json!({
        "matches": matches,
        "searched": {
            "blocks": searched,
            "bytes": searched_bytes,
            "skipped_uninitialized": skipped_uninitialized,
            "skipped_not_loaded": skipped_not_loaded,
        },
        "complete": complete,
        "next_cursor": (!complete).then(|| ordinal.to_string()),
    }))
}

fn parse_request(input: &Value) -> Result<SearchRequest> {
    let object = input
        .as_object()
        .context("search_bytes input must be an object")?;
    reject_unknown_fields(object)?;
    let pattern_text = required_string(object, "pattern")?;
    ensure!(
        pattern_text.len() <= MAX_SEARCH_PATTERN,
        "search pattern is too large"
    );
    let mask = optional_string(object, "mask")?;
    let pattern = parse_pattern(pattern_text, mask.as_deref())?;
    let lower = optional_numeric(object, "start")?.unwrap_or(0);
    let upper = optional_numeric(object, "end")?.unwrap_or(u64::MAX);
    ensure!(lower <= upper, "search bounds are reversed");
    let limit = object
        .get("limit")
        .map(parse_limit)
        .transpose()?
        .unwrap_or(DEFAULT_LIMIT);
    let cursor = optional_string(object, "cursor")?
        .map(|value| value.parse::<u64>().context("invalid search cursor"))
        .transpose()?
        .unwrap_or(0);
    Ok(SearchRequest {
        pattern,
        lower,
        upper,
        limit,
        cursor,
    })
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<()> {
    const FIELDS: &[&str] = &["pattern", "mask", "start", "end", "limit", "cursor"];
    if let Some(field) = object
        .keys()
        .find(|field| !FIELDS.contains(&field.as_str()))
    {
        anyhow::bail!("unknown search_bytes input field: {field}");
    }
    Ok(())
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    object
        .get(field)
        .with_context(|| format!("search_bytes {field} is required"))?
        .as_str()
        .with_context(|| format!("search_bytes {field} must be a string"))
}

fn optional_string(object: &Map<String, Value>, field: &str) -> Result<Option<String>> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("search_bytes {field} must be a string"))
        })
        .transpose()
}

fn optional_numeric(object: &Map<String, Value>, field: &str) -> Result<Option<u64>> {
    optional_string(object, field)?
        .map(|value| numeric(&value))
        .transpose()
}

fn parse_limit(value: &Value) -> Result<usize> {
    let value = value
        .as_u64()
        .context("search_bytes limit must be a positive integer")?;
    ensure!(
        (1..=MAX_SEARCH_RESULTS as u64).contains(&value),
        "invalid search limit"
    );
    usize::try_from(value).context("search limit does not fit host indexing")
}

fn search_window(range: &CoverageRange, request: &SearchRequest) -> Option<RangeWindow> {
    if range.address.is_empty() {
        return None;
    }
    let start = range.address.start.max(request.lower);
    let end = range.address.end.saturating_sub(1).min(request.upper);
    if start > end {
        return None;
    }
    Some(RangeWindow {
        start,
        end,
        data_start: 0,
        data_end: 0,
    })
}

fn materialize_window(
    range: &CoverageRange,
    window: RangeWindow,
    slice_offset: u64,
) -> Result<RangeWindow> {
    let file_offset = range
        .file_offset
        .context("initialized image range has no file offset")?;
    let file_offset = u64::try_from(file_offset).context("file offset exceeds address space")?;
    let relative = file_offset
        .checked_sub(slice_offset)
        .context("image range precedes selected slice")?;
    let start_delta = window
        .start
        .checked_sub(range.address.start)
        .context("search start precedes image range")?;
    let end_delta = window
        .end
        .checked_sub(range.address.start)
        .context("search end precedes image range")?;
    let data_start = usize::try_from(
        relative
            .checked_add(start_delta)
            .context("search start overflows")?,
    )
    .context("search start does not fit host indexing")?;
    let data_end = usize::try_from(
        relative
            .checked_add(end_delta)
            .and_then(|value| value.checked_add(1))
            .context("search end overflows")?,
    )
    .context("search end does not fit host indexing")?;
    Ok(RangeWindow {
        start: window.start,
        end: window.end,
        data_start,
        data_end,
    })
}

fn scan_range(
    range: &CoverageRange,
    image_bytes: &[u8],
    window: RangeWindow,
    pattern: &[(u8, u8)],
    limit: usize,
    cursor: u64,
    ordinal: &mut u64,
) -> Result<BlockScan> {
    let data = image_bytes
        .get(window.data_start..window.data_end)
        .context("image range exceeds verified bytes")?;
    let file_base = range
        .file_offset
        .and_then(|offset| u64::try_from(offset).ok())
        .and_then(|offset| {
            window
                .start
                .checked_sub(range.address.start)
                .and_then(|delta| offset.checked_add(delta))
        });
    scan_block(
        data,
        window.start,
        file_base,
        &range.name,
        pattern,
        limit,
        cursor,
        ordinal,
    )
}

fn scan_block(
    data: &[u8],
    start: u64,
    file_base: Option<u64>,
    segment: &str,
    pattern: &[(u8, u8)],
    limit: usize,
    cursor: u64,
    ordinal: &mut u64,
) -> Result<BlockScan> {
    let candidate_count = data
        .len()
        .checked_sub(pattern.len())
        .and_then(|remaining| remaining.checked_add(1))
        .unwrap_or(0);
    let mut matches = Vec::new();
    let mut first_examined = None;
    let mut last_examined = None;
    for index in 0..candidate_count {
        let current = *ordinal;
        *ordinal = ordinal.checked_add(1).context("search cursor overflows")?;
        if current < cursor {
            continue;
        }
        let index_address = start
            .checked_add(u64::try_from(index).context("search index exceeds address space")?)
            .context("searched range address overflows")?;
        first_examined.get_or_insert(index_address);
        last_examined = Some(
            index_address
                .checked_add(
                    u64::try_from(pattern.len().saturating_sub(1))
                        .context("pattern length exceeds address space")?,
                )
                .context("searched range address overflows")?,
        );
        if !matches_pattern(data, index, pattern) {
            continue;
        }
        let file_offset = file_base
            .and_then(|base| base.checked_add(u64::try_from(index).ok()?))
            .filter(|value| *value <= MAX_SAFE_INTEGER);
        matches.push(json!({
            "address": address(index_address),
            "segment": segment,
            "file_offset": file_offset,
            "procedure": Value::Null,
        }));
        if matches.len() == limit {
            return Ok(BlockScan {
                matches,
                coverage: coverage(first_examined, last_examined),
                exhausted: true,
            });
        }
    }
    Ok(BlockScan {
        matches,
        coverage: coverage(first_examined, last_examined),
        exhausted: false,
    })
}

fn coverage(first: Option<u64>, last: Option<u64>) -> Option<Coverage> {
    let (Some(first), Some(last)) = (first, last) else {
        return None;
    };
    Some(Coverage {
        first,
        last,
        bytes: last.saturating_sub(first).saturating_add(1),
    })
}

fn coverage_value(segment: &str, start: u64, end: u64) -> Value {
    json!({
        "segment": segment,
        "start": address(start),
        "end": address(end),
        "bytes": end.saturating_sub(start).saturating_add(1),
    })
}

fn parse_pattern(pattern: &str, mask: Option<&str>) -> Result<Vec<(u8, u8)>> {
    let values = parse_pairs(pattern, true)
        .context("pattern must contain hexadecimal pairs or ?? wildcards")?;
    let masks = mask
        .map(|value| parse_pairs(value, false).context("mask must contain hexadecimal pairs"))
        .transpose()?;
    if masks
        .as_ref()
        .is_some_and(|value| value.len() != values.len())
    {
        anyhow::bail!("mask length must equal pattern length");
    }
    let pairs = values
        .into_iter()
        .enumerate()
        .map(|(index, (value, wildcard))| {
            let selected = masks.as_ref().map_or(255, |value| value[index].0);
            (value, if wildcard == 0 { 0 } else { selected })
        })
        .collect::<Vec<_>>();
    ensure!(
        pairs.iter().any(|(_, mask)| *mask != 0),
        "pattern must constrain at least one bit"
    );
    Ok(pairs)
}

fn parse_pairs(value: &str, wildcards: bool) -> Option<Vec<(u8, u8)>> {
    let bytes = value.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let pair = if wildcards && bytes.get(index..index + 2) == Some(b"??") {
            (0, 0)
        } else {
            let high = hex(*bytes.get(index)?)?;
            let low = hex(*bytes.get(index + 1)?)?;
            (high << 4 | low, 255)
        };
        result.push(pair);
        index += 2;
        if index == bytes.len() {
            break;
        }
        while bytes
            .get(index)
            .is_some_and(|byte| (*byte as char).is_ascii_whitespace())
        {
            index += 1;
        }
        if index == bytes.len() {
            return None;
        }
    }
    (!result.is_empty()).then_some(result)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn matches_pattern(data: &[u8], index: usize, pattern: &[(u8, u8)]) -> bool {
    pattern
        .iter()
        .enumerate()
        .all(|(offset, (expected, mask))| data[index + offset] & mask == expected & mask)
}

#[cfg(test)]
mod tests {
    use super::{
        CoverageRange, SearchRequest, matches_pattern, materialize_window, parse_pattern,
        parse_request, scan_block, scan_range, search_ranges, search_window,
    };
    use std::ops::Range;

    fn range(start: u64, end: u64, file_offset: usize) -> CoverageRange {
        CoverageRange {
            address: Range { start, end },
            name: ".text".to_owned(),
            file_offset: Some(file_offset),
            initialized: true,
            loaded: true,
        }
    }

    #[test]
    fn scanner_continues_after_a_multi_byte_match_page() {
        let pattern = parse_pattern("aa bb", None).expect("valid pattern");
        let mut ordinal = 0;
        let first = scan_block(
            &[0xaa, 0xbb, 0x00, 0xaa, 0xbb],
            0x1000,
            Some(0x2000),
            ".text",
            &pattern,
            1,
            0,
            &mut ordinal,
        )
        .expect("scan");
        assert_eq!(first.matches[0]["address"], "0x1000");
        assert_eq!(first.coverage.expect("coverage").first, 0x1000);
        assert_eq!(ordinal, 1);

        let mut resumed_ordinal = 0;
        let second = scan_block(
            &[0xaa, 0xbb, 0x00, 0xaa, 0xbb],
            0x1000,
            Some(0x2000),
            ".text",
            &pattern,
            1,
            1,
            &mut resumed_ordinal,
        )
        .expect("scan");
        assert_eq!(second.matches[0]["address"], "0x1003");
        assert_eq!(second.coverage.expect("coverage").first, 0x1001);
    }

    #[test]
    fn scanner_reports_zero_coverage_when_cursor_skips_every_candidate() {
        let pattern = parse_pattern("aa bb", None).expect("valid pattern");
        let mut ordinal = 0;
        let result = scan_block(
            &[0xaa, 0xbb, 0x00],
            0x1000,
            None,
            ".text",
            &pattern,
            1,
            9,
            &mut ordinal,
        )
        .expect("scan");
        assert!(result.matches.is_empty());
        assert!(result.coverage.is_none());
        assert_eq!(ordinal, 2);
    }

    #[test]
    fn scanner_uses_inclusive_bounds_and_actual_segment() {
        let pattern = parse_pattern("aa", None).expect("valid pattern");
        let mut ordinal = 0;
        let result = scan_block(
            &[0x00, 0xaa, 0x00],
            0x3001,
            Some(0x4001),
            ".code",
            &pattern,
            2,
            0,
            &mut ordinal,
        )
        .expect("scan");
        assert_eq!(result.matches[0]["segment"], ".code");
        assert_eq!(result.coverage.expect("coverage").last, 0x3003);
    }

    #[test]
    fn scanner_reads_the_supplied_coverage_range_and_image_bytes() {
        let coverage = range(0x7000, 0x7005, 2);
        let request = SearchRequest {
            pattern: parse_pattern("aa bb", None).expect("valid pattern"),
            lower: 0x7001,
            upper: 0x7004,
            limit: 10,
            cursor: 0,
        };
        let window = search_window(&coverage, &request).expect("range");
        let window = materialize_window(&coverage, window, 0).expect("materialized window");
        let image = [0x00, 0x00, 0x00, 0xaa, 0xbb, 0xaa, 0xbb];
        let mut ordinal = 0;
        let result = scan_range(
            &coverage,
            &image,
            window,
            &request.pattern,
            request.limit,
            request.cursor,
            &mut ordinal,
        )
        .expect("scan");
        assert_eq!(result.matches.len(), 2);
        assert_eq!(result.matches[0]["address"], "0x7001");
        assert_eq!(result.matches[0]["segment"], ".text");
        assert_eq!(result.matches[0]["file_offset"], 3);
    }

    #[test]
    fn scanner_no_match_and_short_ranges_have_exact_coverage() {
        let pattern = parse_pattern("ff ff", None).expect("valid pattern");
        let mut ordinal = 0;
        let result = scan_block(
            &[0x01, 0x02, 0x03],
            0x5000,
            None,
            ".data",
            &pattern,
            1,
            0,
            &mut ordinal,
        )
        .expect("scan");
        assert!(result.matches.is_empty());
        let coverage = result.coverage.expect("coverage");
        assert_eq!(coverage.first, 0x5000);
        assert_eq!(coverage.last, 0x5002);
        assert_eq!(coverage.bytes, 3);

        let mut ordinal = 0;
        let shorter_than_pattern =
            scan_block(&[0xff], 0x5000, None, ".data", &pattern, 1, 0, &mut ordinal)
                .expect("short scan");
        assert!(shorter_than_pattern.matches.is_empty());
        assert!(shorter_than_pattern.coverage.is_none());
        assert_eq!(ordinal, 0);
    }

    #[test]
    fn response_reports_skipped_ranges_and_page_coverage() {
        let uninitialized = CoverageRange {
            address: Range {
                start: 0x2000,
                end: 0x2003,
            },
            name: ".bss".to_owned(),
            file_offset: None,
            initialized: false,
            loaded: true,
        };
        let not_loaded = CoverageRange {
            address: Range {
                start: 0x3000,
                end: 0x3003,
            },
            name: ".unmapped".to_owned(),
            file_offset: None,
            initialized: true,
            loaded: false,
        };
        let loaded = range(0x4000, 0x4004, 0);
        let empty = CoverageRange {
            address: Range {
                start: 0x5000,
                end: 0x5000,
            },
            name: ".empty".to_owned(),
            file_offset: None,
            initialized: true,
            loaded: true,
        };
        let request_value = serde_json::json!({
            "pattern": "aa",
            "limit": 1,
            "start": "0x2000",
            "end": "0x5000",
        });
        let request = parse_request(&request_value).expect("valid request");
        assert!(search_window(&empty, &request).is_none());
        let result = search_ranges(
            &[uninitialized, not_loaded, loaded, empty],
            &[0xaa, 0x00, 0xaa, 0x00],
            0,
            &request,
        )
        .expect("search");
        assert_eq!(result["matches"][0]["address"], "0x4000");
        assert_eq!(result["complete"], false);
        assert_eq!(result["next_cursor"], "1");
        assert_eq!(result["searched"]["blocks"][0]["start"], "0x4000");
        assert_eq!(result["searched"]["blocks"][0]["end"], "0x4000");
        assert_eq!(result["searched"]["blocks"][0]["bytes"], 1);
        assert_eq!(
            result["searched"]["skipped_uninitialized"][0]["segment"],
            ".bss"
        );
        assert_eq!(
            result["searched"]["skipped_not_loaded"][0]["segment"],
            ".unmapped"
        );
    }

    #[test]
    fn request_rejects_provider_only_document_and_wrong_optional_types() {
        assert!(
            parse_request(&serde_json::json!({
                "pattern": "aa",
                "document": "target"
            }))
            .is_err()
        );
        assert!(
            parse_request(&serde_json::json!({
                "pattern": "aa",
                "limit": "1"
            }))
            .is_err()
        );
        assert!(
            parse_request(&serde_json::json!({
                "pattern": "aa",
                "start": 1
            }))
            .is_err()
        );
        assert!(
            parse_request(&serde_json::json!({
                "pattern": "aa",
                "cursor": 1
            }))
            .is_err()
        );
    }

    #[test]
    fn masked_pattern_matches_real_bytes_only_on_selected_bits() {
        let pattern = parse_pattern("48 8b ?? 89", Some("ff f0 00 0f")).expect("valid pattern");
        assert!(matches_pattern(&[0x48, 0x8f, 0xa5, 0x99], 0, &pattern));
        assert!(!matches_pattern(&[0x49, 0x8f, 0xa5, 0x99], 0, &pattern));
    }
}
