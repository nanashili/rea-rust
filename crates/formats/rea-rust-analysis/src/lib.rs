//! Experimental static Rust-artifact interpretation, independent of CLI/MCP.
//! Source bytes and section identity are supplied by the owning container reader.

pub mod android_package;
pub mod auditable;
mod base64;
pub mod binary_layout;
mod container;
pub(crate) use container::{
    Error as ContainerError, PeFormat, ResourceLayout, read_resource_layout,
};
pub mod electron_fuses;
pub mod evm;
pub mod go;
pub mod image;
pub mod macho;
pub mod managed;
pub mod nib;
pub mod pe;
pub mod plist;
pub mod recorded_crash;
pub mod sqlite;
pub use rea_core::JsonText;
