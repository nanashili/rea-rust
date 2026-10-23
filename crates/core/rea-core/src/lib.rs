//! Experimental Rust owners for REA runtime semantics.
//!
//! This crate is not wired into the production CLI or MCP runtime.

pub mod analysis_error;
pub mod cancellation;
pub mod canonical_json;
pub mod evidence;
pub mod failure;
pub mod json_output;
mod json_text;
pub mod linux_proc;
pub mod residual_unknown;
pub use json_text::{JsonText, JsonTextError};
