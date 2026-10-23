//! Little-endian byte reads with Node `Buffer` semantics.
//!
//! Node's `Buffer.readUInt*LE` throw a `RangeError` when the read leaves the
//! buffer. The managed reader pre-checks ranges before most reads, but a raw
//! out-of-range read still surfaces as an internal failure whose message is
//! preserved, exactly as the TS `catch (cause)` paths treat a `RangeError`.

use super::failure::InternalFailure;

/// `Buffer.readUInt8` with a bounds check.
pub fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, InternalFailure> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| range_error(offset, 1, bytes.len()))
}

/// `Buffer.readInt8`.
pub fn read_i8(bytes: &[u8], offset: usize) -> Result<i8, InternalFailure> {
    Ok(read_u8(bytes, offset)? as i8)
}

/// `Buffer.readUInt16LE`.
pub fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, InternalFailure> {
    let slice = sub(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

/// `Buffer.readUInt32LE`.
pub fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, InternalFailure> {
    let slice = sub(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// `Buffer.readInt32LE`.
pub fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, InternalFailure> {
    Ok(read_u32(bytes, offset)? as i32)
}

/// `Buffer.readBigUInt64LE`.
pub fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, InternalFailure> {
    let slice = sub(bytes, offset, 8)?;
    let mut array = [0u8; 8];
    array.copy_from_slice(slice);
    Ok(u64::from_le_bytes(array))
}

/// `Buffer.readBigInt64LE`.
pub fn read_i64(bytes: &[u8], offset: usize) -> Result<i64, InternalFailure> {
    Ok(read_u64(bytes, offset)? as i64)
}

/// `Buffer.readFloatLE`.
pub fn read_f32(bytes: &[u8], offset: usize) -> Result<f32, InternalFailure> {
    let slice = sub(bytes, offset, 4)?;
    Ok(f32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// `Buffer.readDoubleLE`.
pub fn read_f64(bytes: &[u8], offset: usize) -> Result<f64, InternalFailure> {
    let slice = sub(bytes, offset, 8)?;
    let mut array = [0u8; 8];
    array.copy_from_slice(slice);
    Ok(f64::from_le_bytes(array))
}

fn sub(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], InternalFailure> {
    bytes
        .get(offset..offset + length)
        .ok_or_else(|| range_error(offset, length, bytes.len()))
}

fn range_error(offset: usize, length: usize, buffer_len: usize) -> InternalFailure {
    InternalFailure(format!(
        "The value of \"offset\" is out of range. It must be >= 0 and <= {}. Received {}",
        buffer_len.saturating_sub(length),
        offset
    ))
}
