//! Canonical native address coordinates.
//!
//! Compatibility owners: `addressCoordinate` (`domain/native/addressCoordinate.ts`)
//! and `addressDistance` (`domain/hopperValues.ts`). Offsets are arbitrary
//! precision like the original `BigInt` values.
use num_bigint::{BigInt, BigUint};

/// One parsed canonical address: optional address space and offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coordinate {
    pub space: Option<String>,
    pub offset: BigInt,
}

/// `addressCoordinate`: `0x…` or `space:0x…` with lowercase hex digits.
pub fn coordinate(value: &str) -> Option<Coordinate> {
    let separator = value.rfind(":0x");
    if separator == Some(0) {
        return None;
    }
    let (space, offset) = match separator {
        None => (None, value),
        Some(index) => (Some(value[..index].to_owned()), &value[index + 1..]),
    };
    let digits = offset.strip_prefix("0x")?;
    if digits.is_empty()
        || !digits
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let offset = BigUint::parse_bytes(digits.as_bytes(), 16)?;
    Some(Coordinate {
        space,
        offset: BigInt::from(offset),
    })
}

/// `addressDistance`: bounded byte distance between addresses in one space.
pub fn distance(start: &str, end: &str) -> Option<u64> {
    let left = coordinate(start)?;
    let right = coordinate(end)?;
    if left.space != right.space {
        return None;
    }
    let difference = right.offset - left.offset;
    if difference < BigInt::from(0)
        || difference > BigInt::from(crate::zod::MAX_SAFE_INTEGER as u64)
    {
        return None;
    }
    u64::try_from(difference).ok()
}
