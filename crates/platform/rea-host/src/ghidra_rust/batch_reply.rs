//! Batch-reply projection and validation for the Rust Ghidra worker.
//!
//! A batch may contain a completed prefix when the worker is interrupted.  We
//! retain that prefix, its per-item errors, and the durability receipt instead
//! of reducing the reply to a single failure string.

use std::collections::HashSet;

use serde_json::{Map, Value};

const MAX_BATCH_SIZE: usize = 64;
const MAX_BATCH_BYTES: usize = 6 * 1024 * 1024;
const MAX_SELECTOR_BYTES: usize = 18;
const MAX_NAME_BYTES: usize = 4 * 1024;
const MAX_PSEUDOCODE_BYTES: usize = 512 * 1024;
const MAX_ERROR_CODE_BYTES: usize = 64;
const MAX_ERROR_MESSAGE_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchItem {
    pub selector: String,
    pub address: Option<String>,
    pub name: Option<String>,
    pub pseudocode: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchItemErrorKind {
    CacheMiss,
    BatchOutputLimit,
    Other,
}

impl BatchItem {
    /// Classify known worker errors without discarding their original code.
    pub fn error_kind(&self) -> Option<BatchItemErrorKind> {
        self.error_code.as_deref().map(|code| match code {
            "CACHE_MISS" => BatchItemErrorKind::CacheMiss,
            "BATCH_OUTPUT_LIMIT" => BatchItemErrorKind::BatchOutputLimit,
            _ => BatchItemErrorKind::Other,
        })
    }

    pub fn is_batch_output_limited(&self) -> bool {
        self.error_kind() == Some(BatchItemErrorKind::BatchOutputLimit)
    }

    pub fn is_cache_miss(&self) -> bool {
        self.error_kind() == Some(BatchItemErrorKind::CacheMiss)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchDurability {
    pub confirmed_addresses: Vec<Option<String>>,
    pub unconfirmed_addresses: Vec<Option<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchFailure {
    pub error_code: String,
    pub error_message: String,
    pub cause_code: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchReply {
    pub items: Vec<BatchItem>,
    pub total: usize,
    pub completed: usize,
    pub inventory_sha256: String,
    pub durability: BatchDurability,
    pub failure: Option<BatchFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchReplyError {
    Invalid(String),
    InventoryMismatch,
    CountMismatch,
    ProcedureMismatch { index: usize },
    DurabilityMismatch,
    OutputLimit,
}

impl std::fmt::Display for BatchReplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::InventoryMismatch => {
                formatter.write_str("batch inventory differs from the frozen inventory")
            }
            Self::CountMismatch => {
                formatter.write_str("batch counts do not describe the returned prefix")
            }
            Self::ProcedureMismatch { index } => write!(
                formatter,
                "batch item {index} differs from the selected procedure"
            ),
            Self::DurabilityMismatch => {
                formatter.write_str("batch durability receipt does not match its items")
            }
            Self::OutputLimit => formatter.write_str("batch output exceeds its bounded budget"),
        }
    }
}

impl std::error::Error for BatchReplyError {}

impl BatchReply {
    /// Parse a worker value while retaining all complete and partial facts.
    pub fn parse(value: &Value) -> Result<Self, BatchReplyError> {
        let object = object(value, "batch reply")?;
        reject_unknown(
            object,
            &[
                "items",
                "total",
                "completed",
                "inventory_sha256",
                "durability",
                "failure",
            ],
        )?;

        let items = array(object, "items", MAX_BATCH_SIZE)?
            .iter()
            .map(parse_item)
            .collect::<Result<Vec<_>, _>>()?;
        let total = count(object, "total")?;
        let completed = count(object, "completed")?;
        let inventory_sha256 = digest(object, "inventory_sha256")?;
        let durability = parse_durability(required(object, "durability")?)?;
        let failure = object.get("failure").map(parse_failure).transpose()?;

        if total > MAX_BATCH_SIZE || completed > MAX_BATCH_SIZE {
            return Err(BatchReplyError::Invalid(
                "batch counts exceed the batch limit".into(),
            ));
        }

        Ok(Self {
            items,
            total,
            completed,
            inventory_sha256,
            durability,
            failure,
        })
    }

    /// Validate ordering, inventory identity, prefix counts, and durability.
    pub fn validate(
        &self,
        expected_inventory: &str,
        procedures: &[(String, String)],
    ) -> Result<(), BatchReplyError> {
        if self.inventory_sha256 != expected_inventory {
            return Err(BatchReplyError::InventoryMismatch);
        }
        let partial = self.failure.is_some();
        if self.total != self.items.len()
            || self.completed != self.items.len()
            || self.items.len() > procedures.len()
            || (!partial && self.items.len() != procedures.len())
        {
            return Err(BatchReplyError::CountMismatch);
        }
        for (index, item) in self.items.iter().enumerate() {
            let Some((address, name)) = procedures.get(index) else {
                return Err(BatchReplyError::ProcedureMismatch { index });
            };
            if item.selector != *address
                || item.address.as_deref() != Some(address)
                || item.name.as_deref() != Some(name)
            {
                return Err(BatchReplyError::ProcedureMismatch { index });
            }
            if item.pseudocode.is_some() {
                if item
                    .pseudocode
                    .as_deref()
                    .map_or(true, |text| text.trim().is_empty())
                    || item.error_code.is_some()
                    || item.error_message.is_some()
                {
                    return Err(BatchReplyError::ProcedureMismatch { index });
                }
            } else if item
                .error_message
                .as_deref()
                .map_or(true, |text| text.trim().is_empty())
            {
                return Err(BatchReplyError::ProcedureMismatch { index });
            }
        }

        self.validate_output_budget()?;
        self.validate_durability()
    }

    fn validate_output_budget(&self) -> Result<(), BatchReplyError> {
        let output_bytes = self.items.iter().try_fold(0usize, |total, item| {
            let value = serde_json::json!({
                "selector": &item.selector,
                "address": &item.address,
                "name": &item.name,
                "pseudocode": &item.pseudocode,
                "error_code": &item.error_code,
                "error_message": &item.error_message,
            });
            let item_bytes = serde_json::to_vec(&value).map_err(|error| {
                BatchReplyError::Invalid(format!("batch item cannot be encoded: {error}"))
            })?;

            Ok(total.saturating_add(item_bytes.len()))
        })?;

        if output_bytes > MAX_BATCH_BYTES {
            return Err(BatchReplyError::OutputLimit);
        }

        Ok(())
    }

    fn validate_durability(&self) -> Result<(), BatchReplyError> {
        let mut pseudocode_addresses = self
            .items
            .iter()
            .filter_map(|item| {
                (item.pseudocode.is_some() || item.is_batch_output_limited())
                    .then_some(item.address.clone())
            })
            .collect::<HashSet<_>>();
        let confirmed = self
            .durability
            .confirmed_addresses
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let unconfirmed = self
            .durability
            .unconfirmed_addresses
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        if confirmed.len() != self.durability.confirmed_addresses.len()
            || unconfirmed.len() != self.durability.unconfirmed_addresses.len()
            || (self.failure.is_none() && !unconfirmed.is_empty())
        {
            return Err(BatchReplyError::DurabilityMismatch);
        }
        for address in &confirmed {
            if address.is_none() || !pseudocode_addresses.remove(address) {
                return Err(BatchReplyError::DurabilityMismatch);
            }
        }
        for address in &unconfirmed {
            if confirmed.contains(address)
                || !pseudocode_addresses.remove(address)
                || self
                    .items
                    .iter()
                    .any(|item| item.address == *address && item.is_batch_output_limited())
            {
                return Err(BatchReplyError::DurabilityMismatch);
            }
        }
        if !pseudocode_addresses.is_empty() {
            return Err(BatchReplyError::DurabilityMismatch);
        }

        Ok(())
    }
}

fn parse_item(value: &Value) -> Result<BatchItem, BatchReplyError> {
    let object = object(value, "batch item")?;
    reject_unknown(
        object,
        &[
            "selector",
            "address",
            "name",
            "pseudocode",
            "error_code",
            "error_message",
        ],
    )?;
    Ok(BatchItem {
        selector: bounded_text(
            required(object, "selector")?,
            MAX_SELECTOR_BYTES,
            "selector",
        )?,
        address: required_optional_address(object, "address")?,
        name: required_optional_text(object, "name", MAX_NAME_BYTES)?,
        pseudocode: required_optional_text(object, "pseudocode", MAX_PSEUDOCODE_BYTES)?,
        error_code: required_optional_text(object, "error_code", MAX_ERROR_CODE_BYTES)?,
        error_message: required_optional_text(object, "error_message", MAX_ERROR_MESSAGE_BYTES)?,
    })
}

fn parse_durability(value: &Value) -> Result<BatchDurability, BatchReplyError> {
    let object = object(value, "durability")?;
    reject_unknown(object, &["confirmed_addresses", "unconfirmed_addresses"])?;
    Ok(BatchDurability {
        confirmed_addresses: array(object, "confirmed_addresses", MAX_BATCH_SIZE)?
            .iter()
            .map(parse_required_address)
            .collect::<Result<_, _>>()?,
        unconfirmed_addresses: array(object, "unconfirmed_addresses", MAX_BATCH_SIZE)?
            .iter()
            .map(parse_required_address)
            .collect::<Result<_, _>>()?,
    })
}

fn parse_failure(value: &Value) -> Result<BatchFailure, BatchReplyError> {
    let object = object(value, "failure")?;
    reject_unknown(object, &["error_code", "error_message", "cause_code"])?;
    let error_code = bounded_text(required(object, "error_code")?, 64, "error_code")?;
    let error_message = bounded_text(
        required(object, "error_message")?,
        MAX_ERROR_MESSAGE_BYTES,
        "error_message",
    )?;
    let cause_code = bounded_text(required(object, "cause_code")?, 64, "cause_code")?;
    if error_code != "BATCH_INTERRUPTED"
        || (cause_code != "WORKER_FAILED" && cause_code != "CACHE_INTEGRITY_FAILED")
    {
        return Err(BatchReplyError::Invalid(
            "batch failure code is invalid".into(),
        ));
    }
    Ok(BatchFailure {
        error_code,
        error_message,
        cause_code,
    })
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, BatchReplyError> {
    value
        .as_object()
        .ok_or_else(|| BatchReplyError::Invalid(format!("{label} must be an object")))
}
fn required<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, BatchReplyError> {
    object
        .get(name)
        .ok_or_else(|| BatchReplyError::Invalid(format!("batch field {name} is required")))
}
fn reject_unknown(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), BatchReplyError> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(BatchReplyError::Invalid(
            "batch reply contains an unknown field".into(),
        ));
    }
    Ok(())
}
fn array<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<&'a Vec<Value>, BatchReplyError> {
    let values = required(object, name)?
        .as_array()
        .ok_or_else(|| BatchReplyError::Invalid(format!("batch field {name} must be an array")))?;
    if values.len() > maximum {
        return Err(BatchReplyError::Invalid(format!(
            "batch field {name} exceeds its limit"
        )));
    }
    Ok(values)
}
fn count(object: &Map<String, Value>, name: &str) -> Result<usize, BatchReplyError> {
    required(object, name)?
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            BatchReplyError::Invalid(format!("batch field {name} must be a non-negative integer"))
        })
}
fn bounded_text(value: &Value, maximum: usize, name: &str) -> Result<String, BatchReplyError> {
    let text = value
        .as_str()
        .ok_or_else(|| BatchReplyError::Invalid(format!("batch field {name} must be text")))?;
    if text.len() > maximum {
        return Err(BatchReplyError::Invalid(format!(
            "batch field {name} exceeds its limit"
        )));
    }
    Ok(text.to_owned())
}
fn required_optional_text(
    object: &Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<Option<String>, BatchReplyError> {
    let value = required(object, name)?;
    if value.is_null() {
        return Ok(None);
    }

    bounded_text(value, maximum, name).map(Some)
}
fn parse_address(value: &Value) -> Result<Option<String>, BatchReplyError> {
    if value.is_null() {
        return Ok(None);
    }
    let text = value
        .as_str()
        .ok_or_else(|| BatchReplyError::Invalid("batch address must be text or null".into()))?;
    if !valid_address(text) {
        return Err(BatchReplyError::Invalid("batch address is invalid".into()));
    }
    Ok(Some(text.to_owned()))
}

fn parse_required_address(value: &Value) -> Result<Option<String>, BatchReplyError> {
    parse_address(value)?
        .ok_or_else(|| BatchReplyError::Invalid("batch durability address must not be null".into()))
        .map(Some)
}
fn required_optional_address(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, BatchReplyError> {
    parse_address(required(object, name)?)
}
fn digest(object: &Map<String, Value>, name: &str) -> Result<String, BatchReplyError> {
    let value = bounded_text(required(object, name)?, 64, name)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BatchReplyError::Invalid(format!(
            "batch field {name} is not a digest"
        )));
    }
    Ok(value)
}
fn valid_address(value: &str) -> bool {
    let Some(digits) = value.strip_prefix("0x") else {
        return false;
    };
    !digits.is_empty()
        && digits.len() <= 16
        && (digits == "0" || !digits.starts_with('0'))
        && digits
            .bytes()
            .all(|byte| (b'0'..=b'9').contains(&byte) || (b'a'..=b'f').contains(&byte))
}
