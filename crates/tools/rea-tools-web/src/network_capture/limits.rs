//! Complete historical evidence budgets.
//!
//! Compatibility owner: `WEB_NETWORK_CAPTURE_LIMITS` in
//! `src/domain/webNetworkCapture.ts`. Exceeding a budget returns no partial
//! capture.
/// 32 MiB resident input budget.
pub const CAPTURE_INPUT_BYTES: usize = 32 * 1024 * 1024;
/// 96 MiB reply budget.
pub const CAPTURE_OUTPUT_BYTES: usize = 96 * 1024 * 1024;
/// 64-level complete-evidence nesting budget.
pub const CAPTURE_DEPTH: usize = 64;
