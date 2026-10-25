//! Shared Rust owners for REA runtime semantics.

pub mod analysis_error;
pub mod cancellation;
pub mod canonical_json;
pub mod digests;
pub mod evidence;
pub mod failure;
mod js_string;
pub mod json_output;
mod json_text;
pub mod linux_proc;
pub mod residual_unknown;
pub mod schema;
/// Lossless JavaScript string values shared by application and provider code.
pub use js_string::JsString;
pub use json_text::{JsonText, JsonTextError};

#[allow(missing_docs)]
pub mod artifact_inventory;
pub mod artifact_paths;
