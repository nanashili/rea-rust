//! Shared native application workflows. CLI/MCP adapters select arguments and
//! presentation, not independent interpretations of bytes or Evidence identity.
pub mod adb;
pub mod analysis_view;
pub mod android;
pub mod apktool;
pub mod apple;
pub mod artifacts;
pub mod binary;
pub mod browser;
pub mod client_requirements;
pub mod electron;
pub mod environment;
pub mod evm;
pub mod firmware;
pub mod flutter;
pub mod harmony;
pub mod il2cpp;
#[cfg(unix)]
pub mod inputs;
pub mod interface_builder;
pub mod investigation;
pub mod javascript;
pub mod jeb;
pub mod ledger;
pub mod managed;
pub mod native;
pub mod pcap;
pub mod procedure;
pub mod process;
pub mod reconstruction;
pub mod signals;
pub mod sqlite;
pub mod update_runtime;
pub mod wasm;
pub mod web;
