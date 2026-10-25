use serde::{Deserialize, Serialize};

pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_BATCH_BYTES: usize = 6 * 1024 * 1024;
/// Decompile batch size; one batch keeps every pool thread busy.
pub const MAX_BATCH_SIZE: usize = 1024;
pub const MAX_RESOLUTION_SELECTORS: usize = 64;
pub const MAX_PSEUDOCODE_BYTES: usize = 512 * 1024;
pub const MAX_NAME_BYTES: usize = 4096;
pub const MAX_ADDRESS_BYTES: usize = 18;
pub const MAX_INVENTORY: usize = 1_000_000;
pub const MAX_INVENTORY_NAME_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_FUNCTION_PAGE: usize = 256;
pub const MAX_ALIAS_PAGE: usize = 256;
pub const MAX_TARGET_BYTES: usize = 256 * 1024 * 1024;
pub const DATABASE_CACHE_BYTES: usize = 4 * 1024 * 1024;
pub const WORKER_PROTOCOL_NAME: &str = "rea-ghidra-rust-jsonrpc-lines";
pub const WORKER_PROTOCOL_VERSION: u32 = 2;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Function {
    pub address: String,
    pub name: String,
}

/// One additional loader function symbol at an inventory address. Linkers
/// fold byte-identical functions into one body, so several symbols can name
/// the same entry; the inventory row keeps one primary name per address.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionAlias {
    pub address: String,
    pub name: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Segment {
    pub name: String,
    pub address: String,
    pub end: String,
    pub executable: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchItem {
    pub selector: String,
    pub address: Option<String>,
    pub name: Option<String>,
    pub pseudocode: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl BatchItem {
    pub fn success(function: &Function, pseudocode: String) -> Self {
        Self {
            selector: function.address.clone(),
            address: Some(function.address.clone()),
            name: Some(function.name.clone()),
            pseudocode: Some(pseudocode),
            error_code: None,
            error_message: None,
        }
    }

    pub fn failure(function: &Function, code: &str, message: &str) -> Self {
        let mut message = message.to_owned();
        truncate_utf8(&mut message, MAX_NAME_BYTES);

        Self {
            selector: function.address.clone(),
            address: Some(function.address.clone()),
            name: Some(function.name.clone()),
            pseudocode: None,
            error_code: Some(code.to_owned()),
            error_message: Some(message),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenParams {
    pub path: std::path::PathBuf,
    pub target_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectInstructionParams {
    pub address: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageParams {
    pub offset: usize,
    pub limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchParams {
    pub addresses: Vec<String>,
    #[serde(default)]
    pub cache_only: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveParams {
    pub selectors: Vec<String>,
}

pub fn address(value: u64) -> String {
    format!("0x{value:x}")
}

pub fn parse_address(text: &str) -> Option<u64> {
    let hex = text.strip_prefix("0x")?;
    if hex.is_empty() || hex.len() > 16 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    u64::from_str_radix(hex, 16).ok()
}

pub fn truncate_utf8(text: &mut String, maximum: usize) {
    if text.len() <= maximum {
        return;
    }

    let mut end = maximum;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
}
