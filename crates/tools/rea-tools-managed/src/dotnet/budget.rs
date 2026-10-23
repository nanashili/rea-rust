//! Per-inspection representation budget and heap/string/digest caches.
//!
//! Port of `src/dotnet/ManagedDecodeBudget.ts`. The layout owns one budget for
//! the lifetime of the admitted metadata; every inspection facet shares it.

use std::collections::HashMap;

use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::failure::{ManagedReaderFailure, managed_failure};
use crate::common::json::json_string_byte_length;

/// Per-inspection capacity for eagerly retained metadata and its JSON
/// projection: `64 * 1024 * 1024`.
pub const MAX_METADATA_REPRESENTATION_BYTES: i64 = 64 * 1024 * 1024;

/// A decoded #Strings value and the UTF-8 byte count it was read from.
#[derive(Clone)]
pub struct CachedString {
    pub value: String,
    pub encoded_bytes: usize,
}

/// The layout owns decoding capacity and heap identity for all consumers.
pub struct ManagedDecodeBudget {
    remaining: i64,
    transient: i64,
    rows: HashMap<usize, Vec<bool>>,
    strings: HashMap<usize, CachedString>,
    /// SHA-256/SHA-1 digests keyed by `algorithm:byteOffset:byteLength`. The TS
    /// keys by `(ArrayBuffer, offset, length)`; backing bytes are immutable for
    /// the layout, so the range identity is sufficient and stable.
    digests: HashMap<String, String>,
    /// Multiset of prepaid projections, keyed by canonical content. JS keys by
    /// object identity; two equal-but-distinct admitted trees are prepaid and
    /// consumed independently, which a content-keyed count reproduces exactly.
    prepaid: HashMap<String, usize>,
}

impl Default for ManagedDecodeBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagedDecodeBudget {
    pub fn new() -> Self {
        Self {
            remaining: MAX_METADATA_REPRESENTATION_BYTES,
            transient: 0,
            rows: HashMap::new(),
            strings: HashMap::new(),
            digests: HashMap::new(),
            prepaid: HashMap::new(),
        }
    }

    /// `reserve`: admit `bytes` of retained output.
    pub fn reserve(&mut self, bytes: i64, offset: Option<u64>) -> Result<(), ManagedReaderFailure> {
        self.admit(bytes, offset)?;
        self.remaining -= bytes;
        Ok(())
    }

    /// `reserveRow`: retain one bookkeeping reservation per physical row.
    pub fn reserve_row(
        &mut self,
        table: usize,
        row: usize,
        offset: u64,
    ) -> Result<(), ManagedReaderFailure> {
        if let Some(rows) = self.rows.get(&table) {
            if row < rows.len() && rows[row] {
                return Ok(());
            }
        }
        self.reserve(256, Some(offset))?;
        let rows = self.rows.entry(table).or_default();
        if row >= rows.len() {
            rows.resize(row + 1, false);
        }
        rows[row] = true;
        Ok(())
    }

    /// `admitTransient`: bound a decoding allocation that lives until
    /// `releaseTransient`; only retained output is reserved.
    pub fn admit_transient(
        &mut self,
        bytes: i64,
        offset: Option<u64>,
    ) -> Result<(), ManagedReaderFailure> {
        self.admit(bytes, offset)?;
        self.transient += bytes;
        Ok(())
    }

    /// `releaseTransient`: end the current item's decoding bookkeeping.
    pub fn release_transient(&mut self) {
        self.transient = 0;
    }

    fn admit(&self, bytes: i64, offset: Option<u64>) -> Result<(), ManagedReaderFailure> {
        // `Number.isSafeInteger(bytes)` is always true for the i64 values used
        // here; the magnitude check mirrors the TS `bytes > remaining - transient`.
        if bytes < 0 || bytes > self.remaining - self.transient {
            return Err(managed_failure(
                "resource-limit",
                "metadata.representation",
                format!(
                    "Managed metadata exceeds the {} byte representation budget",
                    MAX_METADATA_REPRESENTATION_BYTES
                ),
                offset,
            ));
        }
        Ok(())
    }

    /// `reserveString`: UTF-8 cannot decode to more UTF-16 units than bytes;
    /// JSON uses at most six bytes per unit.
    pub fn reserve_string(
        &mut self,
        encoded_bytes: i64,
        offset: Option<u64>,
    ) -> Result<(), ManagedReaderFailure> {
        self.reserve(encoded_bytes * 6 + 2, offset)
    }

    /// `digest`: cache exact backing-range digests; one `reserve(256)` per new
    /// range. `range_key` is the artifact range (`heaps::range_key`); `None`
    /// is a separately allocated buffer, which is never cached.
    pub fn digest(
        &mut self,
        bytes: &[u8],
        range_key: Option<&str>,
        algorithm: DigestAlgorithm,
    ) -> Result<String, ManagedReaderFailure> {
        let key = range_key.map(|range| format!("{}:{range}", algorithm.name()));
        if let Some(cached) = key.as_ref().and_then(|key| self.digests.get(key)) {
            return Ok(cached.clone());
        }
        self.reserve(256, None)?;
        let digest = match algorithm {
            DigestAlgorithm::Sha256 => format!("{:x}", Sha256::digest(bytes)),
            DigestAlgorithm::Sha1 => format!("{:x}", Sha1::digest(bytes)),
        };
        if let Some(key) = key {
            self.digests.insert(key, digest.clone());
        }
        Ok(digest)
    }

    /// `prepay`: record an admitted projection; its next serialized occurrence
    /// is already charged.
    pub fn prepay(&mut self, value: &Value) {
        let key = prepay_key(value);
        *self.prepaid.entry(key).or_insert(0) += 1;
    }

    /// `consumePrepaid`: spend an admitted projection's charge once.
    pub fn consume_prepaid(&mut self, value: &Value) -> bool {
        let key = prepay_key(value);
        if let Some(count) = self.prepaid.get_mut(&key) {
            if *count > 0 {
                *count -= 1;
                if *count == 0 {
                    self.prepaid.remove(&key);
                }
                return true;
            }
        }
        false
    }

    pub fn cached_string(&self, index: usize) -> Option<&CachedString> {
        self.strings.get(&index)
    }

    pub fn cache_string(&mut self, index: usize, value: String, encoded_bytes: usize) {
        self.strings.insert(
            index,
            CachedString {
                value,
                encoded_bytes,
            },
        );
    }
}

/// Digest algorithms the budget caches.
#[derive(Clone, Copy)]
pub enum DigestAlgorithm {
    Sha256,
    Sha1,
}

impl DigestAlgorithm {
    fn name(self) -> &'static str {
        match self {
            DigestAlgorithm::Sha256 => "sha256",
            DigestAlgorithm::Sha1 => "sha1",
        }
    }
}

/// A stable content key for prepay identity: only `object`/`array` values are
/// ever prepaid (the TS guards `typeof item === "object"`), so scalars never
/// key the multiset. The key is the value's compact JSON form.
fn prepay_key(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Exact UTF-8 JSON bytes of a decoded scalar or key, including escapes.
fn json_bytes(item: &Value) -> i64 {
    match item {
        Value::String(text) => json_string_byte_length(text, None) as i64,
        other => serde_json::to_string(other)
            .unwrap_or_else(|_| "null".to_string())
            .len() as i64,
    }
}

/// `admitManagedProjection`: charge the JSON projection of `value` against
/// `budget`, spending any prepaid charge for an identical admitted sub-tree,
/// then record `value` itself as prepaid.
///
/// Admitting with `budget = None` uses a fresh standalone budget, matching the
/// TS default parameter `new ManagedDecodeBudget()`.
pub fn admit_managed_projection(
    value: &Value,
    budget: Option<&mut ManagedDecodeBudget>,
) -> Result<(), ManagedReaderFailure> {
    let mut standalone = ManagedDecodeBudget::new();
    let budget = match budget {
        Some(budget) => budget,
        None => &mut standalone,
    };
    visit(value, budget)?;
    if value.is_object() || value.is_array() {
        budget.prepay(value);
    }
    Ok(())
}

fn visit(item: &Value, budget: &mut ManagedDecodeBudget) -> Result<(), ManagedReaderFailure> {
    if (item.is_object() || item.is_array()) && budget.consume_prepaid(item) {
        return Ok(());
    }
    match item {
        Value::Array(items) => {
            budget.reserve(items.len() as i64 + 2, None)?;
            for child in items {
                visit(child, budget)?;
            }
        }
        Value::Object(entries) => {
            budget.reserve(2, None)?;
            for (key, child) in entries {
                budget.reserve(json_string_byte_length(key, None) as i64 + 2, None)?;
                visit(child, budget)?;
            }
        }
        scalar => {
            budget.reserve(json_bytes(scalar), None)?;
        }
    }
    Ok(())
}
