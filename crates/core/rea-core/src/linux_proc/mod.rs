//! Parsers for Linux `/proc` process records.
//!
//! They interpret borrowed record text only; this crate never reads procfs.

pub mod stat;
pub mod status;
pub(crate) mod text;
