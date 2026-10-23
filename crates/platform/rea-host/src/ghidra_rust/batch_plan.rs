//! Bounded selector pages and stable procedure selections for Ghidra batches.
//!
//! The TypeScript provider plans selector resolution incrementally.  Keeping
//! that policy here prevents a caller from materialising an unbounded request
//! or from losing duplicate selector provenance while collapsing the worker's
//! resolved addresses.

use crate::ghidra_rust::protocol::{self as protocol, WorkerFunctionResolution};

const REQUEST_ENVELOPE_RESERVE: usize = 256;
const EMPTY_SELECTOR_PAYLOAD_BYTES: usize = b"{\"selectors\":[]}".len();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedSelector {
    pub index: usize,
    pub selector: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedProcedure {
    pub address: String,
    pub name: String,
    pub indices: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectionError {
    ExtraResult {
        result_index: usize,
        page_len: usize,
    },
    FoundIdentityMissing {
        result_index: usize,
        requested_index: usize,
        selector: String,
    },
}

impl std::fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExtraResult { .. } => {
                formatter.write_str("the worker returned an extra selector result")
            }
            Self::FoundIdentityMissing { .. } => {
                formatter.write_str("a resolved function lacks its identity")
            }
        }
    }
}

impl std::error::Error for SelectionError {}

/// Lazily yields pages bounded by both selector count and request payload.
pub struct SelectorPages<'a> {
    selectors: &'a [String],
    next_index: usize,
    page: Vec<IndexedSelector>,
    payload_bytes: usize,
}

impl<'a> SelectorPages<'a> {
    pub fn new(selectors: &'a [String]) -> Self {
        Self {
            selectors,
            next_index: 0,
            page: Vec::new(),
            payload_bytes: EMPTY_SELECTOR_PAYLOAD_BYTES,
        }
    }

    fn selector_bytes(selector: &str) -> usize {
        serde_json::to_vec(selector)
            .map(|encoded| encoded.len())
            .unwrap_or(usize::MAX)
    }

    fn maximum_payload_bytes() -> usize {
        protocol::MAX_REQUEST_BYTES.saturating_sub(REQUEST_ENVELOPE_RESERVE)
    }

    fn should_yield_before_append(&self, selector_bytes: usize) -> bool {
        if self.page.is_empty() {
            return false;
        }

        let comma_bytes = 1;
        self.page.len() >= protocol::MAX_RESOLUTION_SELECTORS
            || self
                .payload_bytes
                .saturating_add(comma_bytes)
                .saturating_add(selector_bytes)
                > Self::maximum_payload_bytes()
    }
}

impl Iterator for SelectorPages<'_> {
    type Item = Vec<IndexedSelector>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let selector = self.selectors.get(self.next_index)?;
            let selector_bytes = Self::selector_bytes(selector);

            if self.should_yield_before_append(selector_bytes) {
                let page = std::mem::take(&mut self.page);
                self.payload_bytes = EMPTY_SELECTOR_PAYLOAD_BYTES;
                return Some(page);
            }

            let index = self.next_index;
            self.next_index += 1;
            let comma_bytes = usize::from(!self.page.is_empty());
            self.page.push(IndexedSelector {
                index,
                selector: selector.clone(),
            });
            self.payload_bytes = self
                .payload_bytes
                .saturating_add(comma_bytes)
                .saturating_add(selector_bytes);

            if self.next_index == self.selectors.len() {
                return Some(std::mem::take(&mut self.page));
            }
        }
    }
}

/// Collapse duplicate resolved addresses while retaining every selector index.
/// Unresolved results are omitted; the runtime owns recording their failures.
pub fn select_resolved_page(
    page: &[IndexedSelector],
    resolved: &[WorkerFunctionResolution],
) -> Result<Vec<SelectedProcedure>, SelectionError> {
    let mut selected = Vec::<SelectedProcedure>::new();

    for (page_index, result) in resolved.iter().enumerate() {
        let requested = page.get(page_index).ok_or(SelectionError::ExtraResult {
            result_index: page_index,
            page_len: page.len(),
        })?;

        if result.status != "found" {
            continue;
        }

        let address =
            result
                .address
                .clone()
                .ok_or_else(|| SelectionError::FoundIdentityMissing {
                    result_index: page_index,
                    requested_index: requested.index,
                    selector: requested.selector.clone(),
                })?;
        let name = result
            .name
            .clone()
            .ok_or_else(|| SelectionError::FoundIdentityMissing {
                result_index: page_index,
                requested_index: requested.index,
                selector: requested.selector.clone(),
            })?;

        if let Some(existing) = selected.iter_mut().find(|item| item.address == address) {
            existing.indices.push(requested.index);
        } else {
            selected.push(SelectedProcedure {
                address,
                name,
                indices: vec![requested.index],
            });
        }
    }

    Ok(selected)
}
