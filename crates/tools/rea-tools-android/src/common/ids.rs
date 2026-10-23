//! Opaque identifiers for owned runs and private directories.
//!
//! These labels name resources in cleanup reports; they never authorize
//! signaling or deletion by themselves.
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn random_u64() -> u64 {
    // RandomState draws process keys from the OS and perturbs them per
    // instance; the counter and clock keep successive values distinct.
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos()),
    );
    hasher.write_u32(std::process::id());
    hasher.finish()
}

/// Lower-case hexadecimal string with `bytes` random bytes.
pub fn random_hex(bytes: usize) -> String {
    let mut text = String::with_capacity(bytes * 2 + 16);
    while text.len() < bytes * 2 {
        text.push_str(&format!("{:016x}", random_u64()));
    }
    text.truncate(bytes * 2);
    text
}

/// RFC 4122 version-4 UUID text, as `crypto.randomUUID()` renders it.
pub fn random_uuid() -> String {
    let high = random_u64();
    let low = random_u64();
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&high.to_be_bytes());
    bytes[8..].copy_from_slice(&low.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
