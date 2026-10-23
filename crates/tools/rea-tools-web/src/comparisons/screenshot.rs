//! Deterministic PNG screenshot comparison.
//!
//! Compatibility owner: `src/browser/PngVisualDiff.ts` (and the
//! `decodeCanonicalBase64`/artifact-digest refinement from
//! `src/domain/webScreenshot.ts`). This port reproduces the hand-written PNG
//! chunk parser, the Node `zlib.inflateSync` output semantics, the working
//! memory admission estimate, the RGBA pixel metrics and every typed failure.
use base64::Engine;
use flate2::{Decompress, FlushDecompress, Status};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use serde_json::{Map, Value, json};

const OPERATION: &str = "compare_web_screenshots";
const SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
/// `PNG_COMPARISON_WORKING_MEMORY_BYTES`.
const WORKING_MEMORY_BYTES: u128 = 256 * 1024 * 1024;
/// `zlibConstants.Z_DEFAULT_CHUNK`.
const INFLATE_CHUNK_BYTES: u128 = 16 * 1024;

/// A validated input artifact (`before`/`after`).
struct Artifact {
    bytes_declared: u64,
    data_base64: String,
}

struct ParsedPng {
    bytes: Vec<u8>,
    width: u32,
    height: u32,
    channels: u8,
    compressed: Vec<Vec<u8>>,
    transparent_color: Option<[u16; 3]>,
    expected_raw_bytes: u128,
    unfiltered_bytes: u128,
    rgba_bytes: u128,
}

struct DecodedPng {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

/// Either an invalid-format (`TypeError`) or a typed `AnalysisError`.
enum PngError {
    /// Mapped to `AnalysisInputError` with reason `invalid_format`.
    TypeError(&'static str),
    /// Already a typed error (unsupported target / resource constraint).
    Analysis(AnalysisError),
}

/// Compare two validated screenshots and build the diff `normalized_result`.
pub(super) fn compare(input: &Value) -> Result<Value, AnalysisError> {
    let before = artifact(input, "before");
    let after = artifact(input, "after");
    let threshold = input
        .get("channel_threshold")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    compare_png(&before, &after, threshold).map_err(project_error)
}

fn project_error(error: PngError) -> AnalysisError {
    match error {
        PngError::Analysis(error) => error,
        PngError::TypeError(message) => AnalysisError::input(
            OPERATION,
            vec![InputIssue {
                path: Vec::new(),
                reason: "invalid_format",
                message: Some(message.to_owned()),
                expected: None,
                minimum: None,
                maximum: None,
            }],
        ),
    }
}

/// Build an [`Artifact`] from a validated input object.
fn artifact(input: &Value, field: &str) -> Artifact {
    let object = input
        .get(field)
        .and_then(Value::as_object)
        .expect("validated artifact object");
    Artifact {
        bytes_declared: object.get("bytes").and_then(Value::as_u64).unwrap_or(0),
        data_base64: object
            .get("data_base64")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    }
}

fn compare_png(before: &Artifact, after: &Artifact, threshold: u64) -> Result<Value, PngError> {
    admit_encoded_pair(before, after)?;
    let before_plan = parse_png(before, "before")?;
    let after_plan = parse_png(after, "after")?;
    admit_png_pair(&before_plan, &after_plan)?;
    let before_image = decode_png(before_plan)?;
    let after_image = decode_png(after_plan)?;

    let limitations = limitations();

    if before_image.width != after_image.width || before_image.height != after_image.height {
        return Ok(json!({
            "status": "dimension_mismatch",
            "before": dimensions(&before_image),
            "after": dimensions(&after_image),
            "channel_threshold": threshold,
            "compared_pixels": 0,
            "changed_pixels": Value::Null,
            "changed_ratio": Value::Null,
            "maximum_channel_delta": Value::Null,
            "mean_absolute_channel_delta": Value::Null,
            "limitations": limitations,
        }));
    }

    let mut changed_pixels: u64 = 0;
    let mut maximum_delta: u64 = 0;
    let mut total_delta: u64 = 0;
    let mut offset = 0;
    while offset < before_image.rgba.len() {
        let mut changed = false;
        for channel in 0..4 {
            let left = i64::from(before_image.rgba[offset + channel]);
            let right = i64::from(after_image.rgba[offset + channel]);
            let delta = (left - right).unsigned_abs();
            total_delta += delta;
            if delta > maximum_delta {
                maximum_delta = delta;
            }
            if delta > threshold {
                changed = true;
            }
        }
        if changed {
            changed_pixels += 1;
        }
        offset += 4;
    }

    let pixels = u64::from(before_image.width) * u64::from(before_image.height);
    let mean_absolute = (total_delta as f64) / ((pixels * 4) as f64);

    let mut result = Map::new();
    result.insert("before".into(), dimensions(&before_image));
    result.insert("after".into(), dimensions(&after_image));
    result.insert("channel_threshold".into(), json!(threshold));
    result.insert("compared_pixels".into(), json!(pixels));
    result.insert("maximum_channel_delta".into(), json!(maximum_delta));
    result.insert(
        "mean_absolute_channel_delta".into(),
        number_from_f64(mean_absolute),
    );
    result.insert("limitations".into(), Value::Array(limitations));

    if changed_pixels == 0 {
        result.insert("status".into(), json!("identical"));
        result.insert("changed_pixels".into(), json!(0));
        result.insert("changed_ratio".into(), json!(0));
    } else {
        result.insert("status".into(), json!("different"));
        result.insert("changed_pixels".into(), json!(changed_pixels));
        result.insert(
            "changed_ratio".into(),
            number_from_f64((changed_pixels as f64) / (pixels as f64)),
        );
    }
    Ok(Value::Object(result))
}

/// Serialize an f64 as a JSON number, matching `JSON.stringify` for integral
/// values (`0` stays an integer, as the schema's `literal(0)` requires).
fn number_from_f64(value: f64) -> Value {
    if value.is_finite() && value.fract() == 0.0 {
        json!(value as i64)
    } else {
        serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number)
    }
}

fn dimensions(image: &DecodedPng) -> Value {
    json!({ "width": image.width, "height": image.height })
}

fn limitations() -> Vec<Value> {
    vec![
        json!(
            "Pixel comparison does not perform OCR, semantic layout analysis, or perceptual color correction."
        ),
        json!("Only non-interlaced 8-bit RGB and RGBA PNG screenshots are accepted."),
        json!(
            "PNG tRNS transparency is accepted only as a six-byte RGB color key; tRNS on RGBA or with another length is rejected."
        ),
    ]
}

/// `decodeCanonicalBase64` — reject non-canonical base64.
fn decode_canonical_base64(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % 4 != 0 {
        return None;
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let decoded = engine.decode(value).ok()?;
    if engine.encode(&decoded) == value {
        Some(decoded)
    } else {
        None
    }
}

fn admit_encoded_pair(before: &Artifact, after: &Artifact) -> Result<(), PngError> {
    let source_bytes = u128::from(before.bytes_declared) + u128::from(after.bytes_declared);
    if source_bytes > WORKING_MEMORY_BYTES {
        return Err(PngError::Analysis(working_memory_error(
            source_bytes,
            None,
            None,
        )));
    }
    Ok(())
}

struct Header {
    width: u32,
    height: u32,
    color_type: i32,
    bit_depth: u8,
    channels: u8,
    supported: bool,
}

fn parse_header(data: &[u8]) -> Result<Header, PngError> {
    if data.len() != 13 {
        return Err(PngError::TypeError("Invalid PNG header"));
    }
    let width = read_u32_be(data, 0);
    let height = read_u32_be(data, 4);
    let bit_depth = data[8];
    let color_type = i32::from(data[9]);
    let valid_depth = (color_type == 0 && matches!(bit_depth, 1 | 2 | 4 | 8 | 16))
        || (color_type == 2 && matches!(bit_depth, 8 | 16))
        || (color_type == 3 && matches!(bit_depth, 1 | 2 | 4 | 8))
        || (color_type == 4 && matches!(bit_depth, 8 | 16))
        || (color_type == 6 && matches!(bit_depth, 8 | 16));
    if width == 0
        || height == 0
        || width > 0x7fff_ffff
        || height > 0x7fff_ffff
        || !valid_depth
        || data[10] != 0
        || data[11] != 0
        || (data[12] != 0 && data[12] != 1)
    {
        return Err(PngError::TypeError("Invalid PNG header"));
    }
    Ok(Header {
        width,
        height,
        color_type,
        bit_depth,
        channels: if color_type == 6 { 4 } else { 3 },
        supported: bit_depth == 8 && (color_type == 2 || color_type == 6) && data[12] == 0,
    })
}

fn parse_png(artifact: &Artifact, field: &'static str) -> Result<ParsedPng, PngError> {
    let bytes = decode_canonical_base64(&artifact.data_base64)
        .ok_or(PngError::TypeError("Invalid PNG signature"))?;
    if bytes.len() < 8 || bytes[0..8] != SIGNATURE {
        return Err(PngError::TypeError("Invalid PNG signature"));
    }

    let mut offset = 8usize;
    let mut header: Option<Header> = None;
    let mut compressed: Vec<Vec<u8>> = Vec::new();
    let mut saw_end = false;
    let mut saw_palette = false;
    let mut image_data_ended = false;
    let mut palette_entries: u32 = 0;
    let mut transparent_color: Option<[u16; 3]> = None;
    let mut saw_transparency = false;
    let mut unsupported_reason: Option<String> = None;

    while offset < bytes.len() {
        if offset + 12 > bytes.len() {
            return Err(PngError::TypeError("Truncated PNG chunk"));
        }
        let length = read_u32_be(&bytes, offset);
        if length > 0x7fff_ffff {
            return Err(PngError::TypeError("Invalid PNG chunk length"));
        }
        let length = length as usize;
        let type_bytes = &bytes[offset + 4..offset + 8];
        let data_start = offset + 8;
        let data_end = data_start + length;
        if data_end + 4 > bytes.len() {
            return Err(PngError::TypeError("Truncated PNG data"));
        }
        let data = &bytes[data_start..data_end];
        if crc32(&bytes[offset + 4..data_end]) != read_u32_be(&bytes, data_end) {
            return Err(PngError::TypeError("Invalid PNG chunk checksum"));
        }
        if !valid_chunk_type(type_bytes) {
            return Err(PngError::TypeError("Invalid PNG chunk type"));
        }
        let type_str = [type_bytes[0], type_bytes[1], type_bytes[2], type_bytes[3]];

        if &type_str != b"IDAT" && !compressed.is_empty() {
            image_data_ended = true;
        }

        if &type_str == b"IHDR" {
            if offset != 8 || header.is_some() {
                return Err(PngError::TypeError("Invalid PNG header order"));
            }
            header = Some(parse_header(data)?);
        } else if header.is_none() {
            return Err(PngError::TypeError("Invalid PNG header order"));
        } else if &type_str == b"tRNS" {
            let head = header.as_ref().expect("header present");
            if saw_transparency || !compressed.is_empty() {
                return Err(PngError::TypeError("Invalid PNG transparency order"));
            }
            saw_transparency = true;
            if head.color_type == 2 && data.len() == 6 {
                transparent_color = Some([
                    read_u16_be(data, 0),
                    read_u16_be(data, 2),
                    read_u16_be(data, 4),
                ]);
            } else if (head.color_type == 0 && data.len() == 2)
                || (head.color_type == 3
                    && saw_palette
                    && !data.is_empty()
                    && data.len() as u32 <= palette_entries)
            {
                unsupported_reason.get_or_insert_with(|| {
                    "PNG transparency for this color type is not supported.".to_owned()
                });
            } else {
                return Err(PngError::TypeError("Unsupported PNG transparency"));
            }
        } else if &type_str == b"PLTE" {
            let head = header.as_ref().expect("header present");
            let length_u32 = length as u32;
            if saw_palette
                || saw_transparency
                || !compressed.is_empty()
                || length == 0
                || length > 768
                || length % 3 != 0
                || (head.color_type == 3
                    && length_u32 / 3 > 2u32.saturating_pow(u32::from(head.bit_depth)))
                || (head.color_type != 2 && head.color_type != 3 && head.color_type != 6)
            {
                return Err(PngError::TypeError("Invalid PNG palette"));
            }
            saw_palette = true;
            palette_entries = length_u32 / 3;
        } else if &type_str == b"IDAT" {
            if image_data_ended {
                return Err(PngError::TypeError("Nonconsecutive PNG image data"));
            }
            compressed.push(data.to_vec());
        } else if &type_str == b"IEND" {
            if length != 0 || data_end + 4 != bytes.len() {
                return Err(PngError::TypeError("Invalid PNG end chunk"));
            }
            saw_end = true;
            break;
        } else if type_bytes[0].is_ascii_uppercase() {
            unsupported_reason.get_or_insert_with(|| {
                format!("Unsupported critical PNG chunk {}.", latin1(type_bytes))
            });
        }
        offset = data_end + 4;
    }

    let header = match header {
        Some(header) if saw_end && !compressed.is_empty() => header,
        _ => return Err(PngError::TypeError("Incomplete PNG")),
    };
    if header.color_type == 3 && !saw_palette {
        return Err(PngError::TypeError("Missing PNG palette"));
    }
    if let Some(reason) = unsupported_reason {
        return Err(PngError::Analysis(unsupported_target(field, reason)));
    }
    if !header.supported {
        return Err(PngError::Analysis(unsupported_target(
            field,
            "PNG encoding is not supported for pixel comparison.".to_owned(),
        )));
    }

    let pixels = u128::from(header.width) * u128::from(header.height);
    let expected_raw_bytes =
        (u128::from(header.width) * u128::from(header.channels) + 1) * u128::from(header.height);
    Ok(ParsedPng {
        bytes,
        width: header.width,
        height: header.height,
        channels: header.channels,
        compressed,
        transparent_color,
        expected_raw_bytes,
        unfiltered_bytes: pixels * u128::from(header.channels),
        rgba_bytes: pixels * 4,
    })
}

fn valid_chunk_type(type_bytes: &[u8]) -> bool {
    // `/^[A-Za-z]{4}$/` and the reserved-bit check `type[2] === type[2].toUpperCase()`.
    type_bytes.iter().all(u8::is_ascii_alphabetic) && type_bytes[2].is_ascii_uppercase()
}

fn decode_png(plan: ParsedPng) -> Result<DecodedPng, PngError> {
    let expected = plan.expected_raw_bytes;
    let concatenated: Vec<u8> = plan.compressed.concat();
    let raw = inflate_png(&concatenated, expected + 1)?;
    if raw.len() as u128 != expected {
        return Err(PngError::TypeError("Unexpected PNG size"));
    }
    let unfiltered = unfilter(&raw, plan.width, plan.height, plan.channels)?;
    Ok(DecodedPng {
        width: plan.width,
        height: plan.height,
        rgba: expand_rgba(&unfiltered, plan.channels, plan.transparent_color),
    })
}

/// `zlib.inflateSync(compressed, { maxOutputLength })` — a bounded zlib inflate
/// that rejects over-long output exactly like Node (`ERR_BUFFER_TOO_LARGE`) and
/// maps data/buffer errors to the shared `Invalid PNG image data` TypeError.
fn inflate_png(compressed: &[u8], max_output_length: u128) -> Result<Vec<u8>, PngError> {
    let mut decoder = Decompress::new(true);
    let mut output: Vec<u8> = Vec::new();
    let mut scratch = vec![0u8; INFLATE_CHUNK_BYTES as usize];
    let mut input_offset = 0usize;
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let input = &compressed[input_offset.min(compressed.len())..];
        let status = match decoder.decompress(input, &mut scratch, FlushDecompress::None) {
            Ok(status) => status,
            Err(_) => return Err(PngError::TypeError("Invalid PNG image data")),
        };
        let consumed = (decoder.total_in() - before_in) as usize;
        input_offset += consumed;
        let produced = (decoder.total_out() - before_out) as usize;
        output.extend_from_slice(&scratch[..produced]);
        if output.len() as u128 > max_output_length {
            // Node throws ERR_BUFFER_TOO_LARGE once output exceeds the limit.
            return Err(PngError::TypeError("Invalid PNG image data"));
        }
        match status {
            Status::StreamEnd => break,
            Status::BufError => return Err(PngError::TypeError("Invalid PNG image data")),
            Status::Ok => {
                if produced == 0 && consumed == 0 {
                    // No progress and not finished: truncated or corrupt stream.
                    return Err(PngError::TypeError("Invalid PNG image data"));
                }
            }
            Status::BufError => return Err(PngError::TypeError("Invalid PNG image data")),
        }
    }
    Ok(output)
}

fn unfilter(raw: &[u8], width: u32, height: u32, channels: u8) -> Result<Vec<u8>, PngError> {
    let row_bytes = (width as usize) * (channels as usize);
    let mut decoded = vec![0u8; row_bytes * (height as usize)];
    for row in 0..(height as usize) {
        let raw_offset = row * (row_bytes + 1);
        let output_offset = row * row_bytes;
        let filter = raw[raw_offset];
        if filter > 4 {
            return Err(PngError::TypeError("Unsupported PNG filter"));
        }
        for column in 0..row_bytes {
            let source = raw[raw_offset + 1 + column];
            let left = if column >= channels as usize {
                decoded[output_offset + column - channels as usize]
            } else {
                0
            };
            let above = if row > 0 {
                decoded[output_offset + column - row_bytes]
            } else {
                0
            };
            let upper_left = if row > 0 && column >= channels as usize {
                decoded[output_offset + column - row_bytes - channels as usize]
            } else {
                0
            };
            decoded[output_offset + column] = apply_filter(filter, source, left, above, upper_left);
        }
    }
    Ok(decoded)
}

fn apply_filter(filter: u8, source: u8, left: u8, above: u8, upper_left: u8) -> u8 {
    match filter {
        0 => source,
        1 => source.wrapping_add(left),
        2 => source.wrapping_add(above),
        3 => {
            let average = ((u32::from(left) + u32::from(above)) / 2) as u8;
            source.wrapping_add(average)
        }
        4 => source.wrapping_add(paeth(left, above, upper_left)),
        _ => source,
    }
}

fn paeth(left: u8, above: u8, upper_left: u8) -> u8 {
    let prediction = i32::from(left) + i32::from(above) - i32::from(upper_left);
    let left_distance = (prediction - i32::from(left)).abs();
    let above_distance = (prediction - i32::from(above)).abs();
    let upper_left_distance = (prediction - i32::from(upper_left)).abs();
    if left_distance <= above_distance && left_distance <= upper_left_distance {
        left
    } else if above_distance <= upper_left_distance {
        above
    } else {
        upper_left
    }
}

fn expand_rgba(decoded: &[u8], channels: u8, transparent_color: Option<[u16; 3]>) -> Vec<u8> {
    if channels == 4 {
        return decoded.to_vec();
    }
    let mut rgba = vec![0u8; (decoded.len() / channels as usize) * 4];
    let mut source = 0usize;
    let mut target = 0usize;
    while source < decoded.len() {
        rgba[target] = decoded[source];
        rgba[target + 1] = decoded[source + 1];
        rgba[target + 2] = decoded[source + 2];
        // tRNS keys are 16-bit values; values above 255 cannot match samples.
        let transparent = match transparent_color {
            Some(color) => {
                u32::from(decoded[source]) == u32::from(color[0])
                    && u32::from(decoded[source + 1]) == u32::from(color[1])
                    && u32::from(decoded[source + 2]) == u32::from(color[2])
            }
            None => false,
        };
        rgba[target + 3] = if transparent { 0 } else { 255 };
        source += 3;
        target += 4;
    }
    rgba
}

fn admit_png_pair(before: &ParsedPng, after: &ParsedPng) -> Result<(), PngError> {
    let input_bytes = (before.bytes.len() + after.bytes.len()) as u128;
    let estimate = |current: &ParsedPng, retained: Option<&ParsedPng>| -> u128 {
        let compressed_bytes: u128 = current
            .compressed
            .iter()
            .map(|chunk| chunk.len() as u128)
            .sum();
        let rgba_expansion = if current.channels == 3 {
            current.rgba_bytes
        } else {
            0
        };
        input_bytes
            + retained.map_or(0, |plan| plan.rgba_bytes)
            + compressed_bytes
            + inflate_buffer_allowance(current.expected_raw_bytes)
            + current.unfiltered_bytes
            + rgba_expansion
    };
    let estimate_bytes = estimate(before, None).max(estimate(after, Some(before)));
    if estimate_bytes > WORKING_MEMORY_BYTES {
        return Err(PngError::Analysis(working_memory_error(
            estimate_bytes,
            Some(before),
            Some(after),
        )));
    }
    Ok(())
}

fn inflate_buffer_allowance(expected_raw_bytes: u128) -> u128 {
    let chunk_bytes = INFLATE_CHUNK_BYTES;
    let maximum_output_bytes = expected_raw_bytes + 1;
    let round_up_to_chunk = |bytes: u128| -> u128 { bytes.div_ceil(chunk_bytes) * chunk_bytes };
    let rejected_output_chunks = round_up_to_chunk(maximum_output_bytes + chunk_bytes - 1);
    let returned_output_chunks = round_up_to_chunk(maximum_output_bytes);
    let scratch_chunk =
        if expected_raw_bytes % chunk_bytes == 0 || maximum_output_bytes % chunk_bytes == 0 {
            chunk_bytes
        } else {
            0
        };
    let concatenated_output = if maximum_output_bytes > chunk_bytes {
        maximum_output_bytes
    } else {
        0
    };
    let returned_output = returned_output_chunks + scratch_chunk + concatenated_output;
    rejected_output_chunks.max(returned_output)
}

fn working_memory_error(
    estimate_bytes: u128,
    before: Option<&ParsedPng>,
    after: Option<&ParsedPng>,
) -> AnalysisError {
    let dims = |plan: Option<&ParsedPng>| -> Value {
        plan.map_or(
            Value::Null,
            |plan| json!({ "width": plan.width, "height": plan.height }),
        )
    };
    let limits = json!({
        "boundary": "png-screenshot-comparison",
        "estimated_working_memory_bytes": estimate_bytes.to_string(),
        "maximum_working_memory_bytes": WORKING_MEMORY_BYTES as u64,
        "before_dimensions": dims(before),
        "after_dimensions": dims(after),
    });
    AnalysisError::resource_constraint(
        OPERATION,
        "memory",
        "Screenshot comparison exceeds REA's 256 MiB estimated working-memory budget.",
        Some(limits),
    )
    .with_remediation(
        "Compare smaller screenshots or reduce their viewport dimensions before capture.",
    )
}

fn unsupported_target(field: &str, reason: String) -> AnalysisError {
    AnalysisError::unsupported_target(OPERATION, field, reason)
}

fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u16_be(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| byte as char).collect()
}

/// CRC-32 (IEEE 802.3), matching `node:zlib.crc32`.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
