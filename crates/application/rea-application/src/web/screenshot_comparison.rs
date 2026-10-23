//! Deterministic, local-only PNG screenshot comparison.
use base64::Engine;
use flate2::read::ZlibDecoder;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Cursor, Read};

pub const OPERATION: &str = "compare_web_screenshots";
const MAX_MEMORY: u128 = 256 * 1024 * 1024;
const INFLATE_CHUNK: usize = 16 * 1024;
const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

struct Artifact {
    field: &'static str,
    bytes: Vec<u8>,
}
struct Plan {
    width: u32,
    height: u32,
    channels: u8,
    compressed: Vec<u8>,
    transparent: Option<[u16; 3]>,
    expected: u128,
    unfiltered: u128,
    rgba: u128,
}
struct Image {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}
enum PngError {
    Invalid(String),
    Unsupported(String),
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    parse_input(input).map(|_| ())
}

pub fn compare(input: &Value) -> Result<Value, Failure> {
    let (before, after, threshold) = parse_input(input)?;
    admit_encoded(&before, &after)?;
    let before_plan = parse_png(&before).map_err(|error| png_failure(&before, error))?;
    let after_plan = parse_png(&after).map_err(|error| png_failure(&after, error))?;
    admit_decoded(&before, &before_plan, &after, &after_plan)?;
    let before_image = decode_png(before_plan).map_err(|error| png_failure(&before, error))?;
    let after_image = decode_png(after_plan).map_err(|error| png_failure(&after, error))?;
    if before_image.width != after_image.width || before_image.height != after_image.height {
        return Ok(dimension_mismatch(&before_image, &after_image, threshold));
    }
    Ok(compare_pixels(&before_image, &after_image, threshold))
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid(
            "web screenshot comparison result must be an object",
        ));
    }
    Ok(result)
}

fn parse_input(input: &Value) -> Result<(Artifact, Artifact, u8), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web screenshot comparison input must be an object"))?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "before" | "after" | "channel_threshold"))
    {
        return Err(invalid(
            "screenshot comparison accepts only before, after, and channel_threshold",
        ));
    }
    let before = parse_artifact(object.get("before"), "before")?;
    let after = parse_artifact(object.get("after"), "after")?;
    let threshold = object
        .get("channel_threshold")
        .map(|value| {
            value
                .as_u64()
                .filter(|value| *value <= 255)
                .map(|value| value as u8)
                .ok_or_else(|| invalid("channel_threshold must be between 0 and 255"))
        })
        .transpose()?
        .unwrap_or(0);
    Ok((before, after, threshold))
}

fn parse_artifact(value: Option<&Value>, field: &'static str) -> Result<Artifact, Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(&format!("{field} screenshot artifact must be an object")))?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "sha256" | "bytes" | "media_type" | "data_base64"
        )
    }) {
        return Err(invalid(&format!(
            "{field} screenshot artifact contains an unknown field"
        )));
    }
    let digest = required_string(object.get("sha256"), &format!("{field}.sha256"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(&format!(
            "{field}.sha256 must be lowercase SHA-256 hex"
        )));
    }
    let encoded = required_string(object.get("data_base64"), &format!("{field}.data_base64"))?;
    let engine = base64::engine::general_purpose::STANDARD;
    if encoded.is_empty() || !encoded.len().is_multiple_of(4) {
        return Err(invalid(&format!(
            "{field}.data_base64 must be canonical base64"
        )));
    }
    let bytes = engine
        .decode(encoded)
        .map_err(|_| invalid(&format!("{field}.data_base64 must be canonical base64")))?;
    if engine.encode(&bytes) != encoded {
        return Err(invalid(&format!(
            "{field}.data_base64 must be canonical base64"
        )));
    }
    let declared = object
        .get("bytes")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid(&format!("{field}.bytes must be a positive integer")))?;
    if declared != bytes.len() as u64 {
        return Err(invalid(&format!("{field}.bytes must match decoded data")));
    }
    if object.get("media_type").and_then(Value::as_str) != Some("image/png") {
        return Err(invalid(&format!("{field}.media_type must be image/png")));
    }
    if hex_digest(&bytes) != digest {
        return Err(invalid(&format!(
            "{field}.sha256 does not match decoded data"
        )));
    }
    Ok(Artifact { field, bytes })
}

fn required_string<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}
fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_png(artifact: &Artifact) -> Result<Plan, PngError> {
    let data = &artifact.bytes;
    if data.len() < 8 || &data[..8] != SIGNATURE {
        return Err(PngError::Invalid("Invalid PNG signature".into()));
    }
    let mut offset = 8;
    let mut header = None;
    let mut palette = None;
    let mut transparent = None;
    let mut compressed = Vec::new();
    let mut ended = false;
    let mut saw_end = false;
    let mut unsupported = None;
    while offset < data.len() {
        let start = offset;
        let length = read_u32(data, &mut offset)
            .ok_or_else(|| PngError::Invalid("Truncated PNG chunk".into()))?
            as usize;
        if length > 0x7fff_ffff {
            return Err(PngError::Invalid("Invalid PNG chunk length".into()));
        }
        let kind = take(data, &mut offset, 4)
            .ok_or_else(|| PngError::Invalid("Truncated PNG chunk".into()))?;
        if !kind.iter().all(u8::is_ascii_alphabetic) || kind[2].is_ascii_lowercase() {
            return Err(PngError::Invalid("Invalid PNG chunk type".into()));
        }
        let chunk = take(data, &mut offset, length)
            .ok_or_else(|| PngError::Invalid("Truncated PNG data".into()))?;
        let checksum = read_u32(data, &mut offset)
            .ok_or_else(|| PngError::Invalid("Truncated PNG data".into()))?;
        if crc32(&data[start + 4..start + 8 + length]) != checksum {
            return Err(PngError::Invalid("Invalid PNG chunk checksum".into()));
        }
        match kind {
            b"IHDR" if start != 8 || header.is_some() => {
                return Err(PngError::Invalid("Invalid PNG header".into()));
            }
            b"IHDR" => header = Some(parse_header(chunk)?),
            b"PLTE" => {
                let h = header
                    .as_ref()
                    .ok_or_else(|| PngError::Invalid("Invalid PNG header order".into()))?;
                if palette.is_some()
                    || transparent.is_some()
                    || ended
                    || !compressed.is_empty()
                    || chunk.is_empty()
                    || chunk.len() > 768
                    || !chunk.len().is_multiple_of(3)
                    || !matches!(h.color, 2 | 3 | 6)
                {
                    return Err(PngError::Invalid("Invalid PNG palette".into()));
                }
                let entries = chunk.len() / 3;
                if h.color == 3 && entries > (1usize << h.depth) {
                    return Err(PngError::Invalid("Invalid PNG palette".into()));
                }
                palette = Some(entries);
            }
            b"tRNS" => {
                let h = header
                    .as_ref()
                    .ok_or_else(|| PngError::Invalid("Invalid PNG header order".into()))?;
                if transparent.is_some() || ended || !compressed.is_empty() {
                    return Err(PngError::Invalid("Invalid PNG transparency order".into()));
                }
                match h.color {
                    2 if chunk.len() == 6 => {
                        transparent =
                            Some([be16(&chunk[0..2]), be16(&chunk[2..4]), be16(&chunk[4..6])])
                    }
                    0 if chunk.len() == 2 => {
                        unsupported =
                            Some("PNG transparency for this color type is not supported.".into())
                    }
                    3 if palette.is_some()
                        && !chunk.is_empty()
                        && chunk.len() <= palette.unwrap() =>
                    {
                        unsupported =
                            Some("PNG transparency for this color type is not supported.".into())
                    }
                    _ => return Err(PngError::Invalid("Unsupported PNG transparency".into())),
                }
            }
            b"IDAT" => {
                if header.is_none() {
                    return Err(PngError::Invalid("Invalid PNG header order".into()));
                }
                if ended {
                    return Err(PngError::Invalid("Nonconsecutive PNG image data".into()));
                }
                compressed.extend_from_slice(chunk);
            }
            b"IEND" => {
                if !chunk.is_empty() || offset != data.len() {
                    return Err(PngError::Invalid("Invalid PNG end chunk".into()));
                }
                saw_end = true;
                break;
            }
            _ => {
                if kind[0].is_ascii_uppercase() {
                    unsupported = Some(format!(
                        "Unsupported critical PNG chunk {}.",
                        String::from_utf8_lossy(kind)
                    ));
                }
            }
        }
        if kind != b"IDAT" && !compressed.is_empty() {
            ended = true;
        }
    }
    let h = header.ok_or_else(|| PngError::Invalid("Incomplete PNG".into()))?;
    if !saw_end || compressed.is_empty() {
        return Err(PngError::Invalid("Incomplete PNG".into()));
    }
    if h.color == 3 && palette.is_none() {
        return Err(PngError::Invalid("Missing PNG palette".into()));
    }
    if let Some(reason) = unsupported {
        return Err(PngError::Unsupported(reason));
    }
    if !h.supported {
        return Err(PngError::Unsupported(
            "PNG encoding is not supported for pixel comparison.".into(),
        ));
    }
    let row = checked_mul(h.width as u128, h.channels as u128)?;
    let pixels = checked_mul(h.width as u128, h.height as u128)?;
    Ok(Plan {
        width: h.width,
        height: h.height,
        channels: h.channels,
        compressed,
        transparent,
        expected: checked_mul(row + 1, h.height as u128)?,
        unfiltered: checked_mul(row, h.height as u128)?,
        rgba: checked_mul(pixels, 4)?,
    })
}

struct Header {
    width: u32,
    height: u32,
    depth: u8,
    color: u8,
    channels: u8,
    supported: bool,
}
fn parse_header(data: &[u8]) -> Result<Header, PngError> {
    if data.len() != 13 {
        return Err(PngError::Invalid("Invalid PNG header".into()));
    }
    let width = be32(&data[0..4]);
    let height = be32(&data[4..8]);
    let depth = data[8];
    let color = data[9];
    if width == 0 || height == 0 || data[10] != 0 || data[11] != 0 || data[12] > 1 {
        return Err(PngError::Invalid("Invalid PNG header".into()));
    }
    let valid = match color {
        0 => matches!(depth, 1 | 2 | 4 | 8 | 16),
        2 | 4 | 6 => matches!(depth, 8 | 16),
        3 => matches!(depth, 1 | 2 | 4 | 8),
        _ => false,
    };
    if !valid {
        return Err(PngError::Unsupported(
            "PNG encoding is not supported for pixel comparison.".into(),
        ));
    }
    Ok(Header {
        width,
        height,
        depth,
        color,
        channels: if color == 6 { 4 } else { 3 },
        supported: depth == 8 && matches!(color, 2 | 6) && data[12] == 0,
    })
}

fn decode_png(plan: Plan) -> Result<Image, PngError> {
    let expected = usize::try_from(plan.expected)
        .map_err(|_| PngError::Invalid("Invalid PNG image size".into()))?;
    let mut decoder = ZlibDecoder::new(Cursor::new(plan.compressed));
    let mut raw = Vec::new();
    let mut chunk = [0u8; INFLATE_CHUNK];
    loop {
        let count = decoder
            .read(&mut chunk)
            .map_err(|_| PngError::Invalid("Invalid PNG image data".into()))?;
        if count == 0 {
            break;
        }
        if raw.len().saturating_add(count) > expected.saturating_add(1) {
            return Err(PngError::Invalid("Unexpected PNG size".into()));
        }
        raw.extend_from_slice(&chunk[..count]);
    }
    if raw.len() != expected {
        return Err(PngError::Invalid("Unexpected PNG size".into()));
    }
    let decoded = unfilter(
        &raw,
        plan.width as usize,
        plan.height as usize,
        plan.channels,
    )?;
    let rgba = expand_rgba(
        &decoded,
        plan.width as usize,
        plan.height as usize,
        plan.channels,
        plan.transparent,
    );
    Ok(Image {
        width: plan.width,
        height: plan.height,
        rgba,
    })
}
fn unfilter(raw: &[u8], width: usize, height: usize, channels: u8) -> Result<Vec<u8>, PngError> {
    let row = width
        .checked_mul(channels as usize)
        .ok_or_else(|| PngError::Invalid("Invalid PNG image size".into()))?;
    let mut output = vec![
        0;
        row.checked_mul(height)
            .ok_or_else(|| PngError::Invalid("Invalid PNG image size".into()))?
    ];
    for y in 0..height {
        let source = y * (row + 1) + 1;
        let target = y * row;
        let filter = raw[y * (row + 1)];
        if filter > 4 {
            return Err(PngError::Invalid("Unsupported PNG filter".into()));
        }
        for x in 0..row {
            let left = if x >= channels as usize {
                output[target + x - channels as usize]
            } else {
                0
            };
            let above = if y > 0 { output[target - row + x] } else { 0 };
            let upper = if y > 0 && x >= channels as usize {
                output[target - row + x - channels as usize]
            } else {
                0
            };
            let value = raw[source + x];
            output[target + x] = match filter {
                0 => value,
                1 => value.wrapping_add(left),
                2 => value.wrapping_add(above),
                3 => value.wrapping_add(((left as u16 + above as u16) / 2) as u8),
                4 => value.wrapping_add(paeth(left, above, upper)),
                _ => unreachable!(),
            };
        }
    }
    Ok(output)
}
fn paeth(left: u8, above: u8, upper: u8) -> u8 {
    let prediction = left as i32 + above as i32 - upper as i32;
    let distances = [
        (prediction - left as i32).abs(),
        left as i32,
        (prediction - above as i32).abs(),
        above as i32,
        (prediction - upper as i32).abs(),
        upper as i32,
    ];
    if distances[0] <= distances[2] && distances[0] <= distances[4] {
        distances[1] as u8
    } else if distances[2] <= distances[4] {
        distances[3] as u8
    } else {
        distances[5] as u8
    }
}
fn expand_rgba(
    decoded: &[u8],
    width: usize,
    height: usize,
    channels: u8,
    transparent: Option<[u16; 3]>,
) -> Vec<u8> {
    if channels == 4 {
        return decoded.to_vec();
    }
    let mut rgba = Vec::with_capacity(width * height * 4);
    for pixel in decoded.chunks_exact(3) {
        rgba.extend_from_slice(pixel);
        rgba.push(
            transparent
                .map(|key| {
                    if key == [pixel[0] as u16, pixel[1] as u16, pixel[2] as u16] {
                        0
                    } else {
                        255
                    }
                })
                .unwrap_or(255),
        );
    }
    rgba
}

fn compare_pixels(before: &Image, after: &Image, threshold: u8) -> Value {
    let pixels = before.width as u64 * before.height as u64;
    let mut changed = 0;
    let mut maximum = 0;
    let mut total = 0u64;
    for (left, right) in before.rgba.chunks_exact(4).zip(after.rgba.chunks_exact(4)) {
        let mut different = false;
        for (a, b) in left.iter().zip(right) {
            let delta = a.abs_diff(*b);
            maximum = maximum.max(delta);
            total += delta as u64;
            different |= delta > threshold;
        }
        if different {
            changed += 1;
        }
    }
    serde_json::json!({"status": if changed == 0 { "identical" } else { "different" }, "before": {"width": before.width, "height": before.height}, "after": {"width": after.width, "height": after.height}, "channel_threshold": threshold, "compared_pixels": pixels, "changed_pixels": changed, "changed_ratio": changed as f64 / pixels as f64, "maximum_channel_delta": maximum, "mean_absolute_channel_delta": total as f64 / (pixels as f64 * 4.0), "limitations": limitations()})
}
fn dimension_mismatch(before: &Image, after: &Image, threshold: u8) -> Value {
    serde_json::json!({"status":"dimension_mismatch", "before":{"width":before.width,"height":before.height}, "after":{"width":after.width,"height":after.height}, "channel_threshold":threshold,"compared_pixels":0,"changed_pixels":null,"changed_ratio":null,"maximum_channel_delta":null,"mean_absolute_channel_delta":null,"limitations":limitations()})
}
fn limitations() -> [&'static str; 3] {
    [
        "Pixel comparison does not perform OCR, semantic layout analysis, or perceptual color correction.",
        "Only non-interlaced 8-bit RGB and RGBA PNG screenshots are accepted.",
        "PNG tRNS transparency is accepted only as a six-byte RGB color key; tRNS on RGBA or with another length is rejected.",
    ]
}

fn admit_encoded(before: &Artifact, after: &Artifact) -> Result<(), Failure> {
    let estimate = (before.bytes.len() + after.bytes.len()) as u128;
    if estimate > MAX_MEMORY {
        Err(resource_failure("encoded_input", estimate))
    } else {
        Ok(())
    }
}
fn admit_decoded(
    before: &Artifact,
    before_plan: &Plan,
    after: &Artifact,
    after_plan: &Plan,
) -> Result<(), Failure> {
    let input_bytes = (before.bytes.len() + after.bytes.len()) as u128;
    let before_estimate = decoded_memory_estimate(input_bytes, before_plan, None);
    let after_estimate = decoded_memory_estimate(input_bytes, after_plan, Some(before_plan));
    let estimate = before_estimate.max(after_estimate);
    if estimate > MAX_MEMORY {
        Err(resource_failure("decoded_png", estimate))
    } else {
        Ok(())
    }
}

fn decoded_memory_estimate(input_bytes: u128, current: &Plan, retained: Option<&Plan>) -> u128 {
    input_bytes
        + retained.map(|plan| plan.rgba).unwrap_or(0)
        + current.compressed.len() as u128
        + inflate_allowance(current.expected)
        + current.unfiltered
        + if current.channels == 3 {
            current.rgba
        } else {
            0
        }
}
fn inflate_allowance(expected: u128) -> u128 {
    let chunk = INFLATE_CHUNK as u128;
    let maximum = expected + 1;
    let round = |value: u128| value.div_ceil(chunk) * chunk;
    let rejected = round(maximum + chunk - 1);
    let returned = round(maximum)
        + if expected.is_multiple_of(chunk) || maximum.is_multiple_of(chunk) {
            chunk
        } else {
            0
        }
        + if maximum > chunk { maximum } else { 0 };
    rejected.max(returned)
}
fn resource_failure(boundary: &str, estimate: u128) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        "Screenshot comparison exceeds REA's 256 MiB estimated working-memory budget.".into(),
        false,
        "Use smaller screenshots or compare them in separate bounded groups.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("resource", Detail::Text("memory".into())),
            ("boundary", Detail::Text(boundary.into())),
            (
                "estimated_working_memory_bytes",
                Detail::Text(estimate.to_string()),
            ),
            (
                "maximum_working_memory_bytes",
                Detail::Count(MAX_MEMORY as u64),
            ),
        ]),
    )
}
fn png_failure(artifact: &Artifact, error: PngError) -> Failure {
    match error {
        PngError::Invalid(message) => invalid(&format!("{}: {}", artifact.field, message)),
        PngError::Unsupported(message) => Failure::new(
            "unsupported_target",
            "unsupported_target",
            message,
            false,
            "Provide a non-interlaced 8-bit RGB or RGBA PNG.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("field", Detail::Text(artifact.field.into())),
            ]),
        ),
    }
}
fn invalid(reason: &str) -> Failure {
    Failure::new("invalid_request", "invalid_input", reason.to_owned(), false, "Provide two self-identifying PNG artifacts and an optional channel threshold for value-only comparison.".into(), BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]))
}
fn checked_mul(left: u128, right: u128) -> Result<u128, PngError> {
    left.checked_mul(right)
        .ok_or_else(|| PngError::Invalid("Invalid PNG image size".into()))
}
fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}
fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}
fn read_u32(data: &[u8], offset: &mut usize) -> Option<u32> {
    Some(be32(take(data, offset, 4)?))
}
fn take<'a>(data: &'a [u8], offset: &mut usize, length: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(length)?;
    let value = data.get(*offset..end)?;
    *offset = end;
    Some(value)
}
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;
    fn png(width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        for row in pixels.chunks_exact(width as usize * 4) {
            raw.push(0);
            raw.extend_from_slice(row);
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&raw).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut output = SIGNATURE.to_vec();
        let mut header = Vec::with_capacity(13);
        header.extend_from_slice(&width.to_be_bytes());
        header.extend_from_slice(&height.to_be_bytes());
        header.extend_from_slice(&[8, 6, 0, 0, 0]);
        chunk(&mut output, b"IHDR", &header);
        chunk(&mut output, b"IDAT", &compressed);
        chunk(&mut output, b"IEND", &[]);
        output
    }
    fn chunk(output: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        output.extend_from_slice(&(data.len() as u32).to_be_bytes());
        output.extend_from_slice(kind);
        output.extend_from_slice(data);
        output.extend_from_slice(&crc32(&[kind.as_slice(), data].concat()).to_be_bytes());
    }
    fn artifact(bytes: &[u8]) -> Value {
        serde_json::json!({"sha256":hex_digest(bytes),"bytes":bytes.len(),"media_type":"image/png","data_base64":base64::engine::general_purpose::STANDARD.encode(bytes)})
    }
    fn input(before: &[u8], after: &[u8]) -> Value {
        serde_json::json!({"before":artifact(before),"after":artifact(after)})
    }
    #[test]
    fn compares_rgba_pixels() {
        let before = png(1, 1, &[1, 2, 3, 255]);
        let after = png(1, 1, &[1, 4, 3, 255]);
        let result = compare(&input(&before, &after)).unwrap();
        assert_eq!(result["status"], "different");
        assert_eq!(result["changed_pixels"], 1);
        assert_eq!(result["maximum_channel_delta"], 2);
    }
    #[test]
    fn reports_dimension_mismatch() {
        let before = png(1, 1, &[1, 2, 3, 255]);
        let after = png(2, 1, &[1, 2, 3, 255, 0, 0, 0, 255]);
        let result = compare(&input(&before, &after)).unwrap();
        assert_eq!(result["status"], "dimension_mismatch");
        assert!(result["changed_pixels"].is_null());
    }
    #[test]
    fn rejects_bad_checksum() {
        let mut bytes = png(1, 1, &[1, 2, 3, 255]);
        *bytes.last_mut().unwrap() ^= 1;
        assert!(compare(&input(&bytes, &bytes)).is_err());
    }

    #[test]
    fn rejects_palette_after_image_data() {
        let mut bytes = png(1, 1, &[1, 2, 3, 255]);
        let mut palette = Vec::new();
        chunk(&mut palette, b"PLTE", &[1, 2, 3]);
        let iend_start = bytes.len() - 12;
        bytes.splice(iend_start..iend_start, palette);
        assert!(compare(&input(&bytes, &bytes)).is_err());
    }
    #[test]
    fn rejects_noncanonical_digest_and_size() {
        let bytes = png(1, 1, &[1, 2, 3, 255]);
        let mut value = input(&bytes, &bytes);
        value["before"]["sha256"] = serde_json::json!("A".repeat(64));
        assert!(validate_input(&value).is_err());
        value["before"]["sha256"] = serde_json::json!(hex_digest(&bytes));
        value["before"]["bytes"] = serde_json::json!(bytes.len() + 1);
        assert!(validate_input(&value).is_err());
    }
    #[test]
    fn applies_channel_threshold() {
        let before = png(1, 1, &[1, 2, 3, 255]);
        let after = png(1, 1, &[1, 4, 3, 255]);
        let mut value = input(&before, &after);
        value["channel_threshold"] = serde_json::json!(2);
        assert_eq!(compare(&value).unwrap()["status"], "identical");
    }

    #[test]
    fn rejects_unknown_contract_fields() {
        let bytes = png(1, 1, &[1, 2, 3, 255]);
        let mut value = input(&bytes, &bytes);
        value["before"]["extra"] = serde_json::json!(true);
        assert!(validate_input(&value).is_err());
        let mut value = input(&bytes, &bytes);
        value["extra"] = serde_json::json!(true);
        assert!(validate_input(&value).is_err());
    }
}
