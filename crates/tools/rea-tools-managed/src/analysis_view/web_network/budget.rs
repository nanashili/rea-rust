//! Retained/temporary byte accounting for views that group retained records.
//!
//! Compatibility owners: `WebNetworkProjectionAccumulator` and
//! `admitAnalysisViewData` (`analysisViewDataAdmission.ts`). Parsed transport
//! JSON cannot carry cycles, accessors, proxies or prototypes, and its nesting
//! is bounded by the transport parser below `MAX_JSON_DEPTH` (1000), so
//! admission here only charges the representation allowances.
use super::ordering::compare;
use super::routes::{ENTRY_BYTES, text_bytes, text_bytes_of};
use crate::common::view::OPERATION;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};
use std::collections::HashSet;

/// `WEB_NETWORK_CAPTURE_LIMITS.outputBytes`.
pub const OUTPUT_BYTES: usize = 96 * 1024 * 1024;

const MEMBER_BYTES: usize = 256;
const CONTAINER_BYTES: usize = 512;

/// Shared retained and per-record temporary byte budget plus limitations.
pub struct Budget {
    maximum: usize,
    subject: &'static str,
    retained: usize,
    temporary: usize,
    limitations: Vec<String>,
    seen: HashSet<String>,
}

impl Budget {
    pub fn new(subject: &'static str) -> Self {
        Self {
            maximum: OUTPUT_BYTES,
            subject,
            retained: 0,
            temporary: 0,
            limitations: Vec::new(),
            seen: HashSet::new(),
        }
    }

    /// `retain(bytes)`.
    pub fn retain(&mut self, bytes: usize) -> bool {
        if self.retained + self.temporary + bytes > self.maximum {
            return false;
        }
        self.retained += bytes;
        true
    }

    /// Bytes currently retained.
    pub fn retained(&self) -> usize {
        self.retained
    }

    /// `temporary(bytes)`.
    pub fn temporary(&mut self, bytes: usize) -> bool {
        if self.retained + self.temporary + bytes > self.maximum {
            return false;
        }
        self.temporary += bytes;
        true
    }

    /// `releaseTemporary()`.
    pub fn release_temporary(&mut self) {
        self.temporary = 0;
    }

    /// `overBudget()`.
    pub fn over_budget(&self) -> AnalysisError {
        AnalysisError::resource_constraint(
            OPERATION,
            "memory",
            format!(
                "{} retained state and temporary work exceed the projection representation budget.",
                self.subject
            ),
            Some(json!({ "output_bytes": self.maximum })),
        )
    }

    /// `admitCaptureClone(value, { copiedStrings })`.
    pub fn admit_capture_clone(
        &mut self,
        value: &Value,
        copied_strings: bool,
    ) -> Result<(), AnalysisError> {
        self.admit(value, copied_strings)
    }

    /// `admitInlineEvidence(value)`.
    pub fn admit_inline_evidence(&mut self, value: &Value) -> Result<(), AnalysisError> {
        self.admit(value, true)
    }

    fn admit(&mut self, value: &Value, count_strings: bool) -> Result<(), AnalysisError> {
        let mut pending = vec![value];
        while let Some(item) = pending.pop() {
            let mut bytes = MEMBER_BYTES;
            match item {
                Value::String(text) if count_strings => bytes += text_bytes_of(text),
                Value::Array(_) | Value::Object(_) => bytes += CONTAINER_BYTES,
                _ => {}
            }
            if !self.retain(bytes) {
                return Err(self.over_budget());
            }
            match item {
                Value::Array(items) => pending.extend(items.iter().rev()),
                Value::Object(members) => {
                    for (key, member) in members.iter().rev() {
                        if count_strings && !self.retain(text_bytes_of(key)) {
                            return Err(self.over_budget());
                        }
                        pending.push(member);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// `addLimitations(limitations)`.
    pub fn add_limitations<I, S>(&mut self, limitations: I) -> Result<(), AnalysisError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for limitation in limitations {
            let limitation = limitation.into();
            if self.seen.contains(&limitation) {
                continue;
            }
            if !self.retain(ENTRY_BYTES + text_bytes(crate::common::json::js_len(&limitation))) {
                return Err(self.over_budget());
            }
            self.seen.insert(limitation.clone());
            self.limitations.push(limitation);
        }
        Ok(())
    }

    /// `sortedLimitations()`.
    pub fn sorted_limitations(&self) -> Vec<String> {
        let mut sorted = self.limitations.clone();
        sorted.sort_by(|left, right| compare(left, right));
        sorted
    }
}
