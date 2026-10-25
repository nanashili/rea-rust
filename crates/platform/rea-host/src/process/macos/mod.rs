//! macOS process descriptor, resource and run-token observation.
pub mod fds;
#[cfg(target_os = "macos")]
pub mod process_table;
pub mod resources;
#[cfg(target_os = "macos")]
pub mod run_token;
