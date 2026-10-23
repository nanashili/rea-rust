//! Native UI output budget and deadline constants.
//!
//! Compatibility owners: `src/native/NativeUiOutputBudget.ts` and
//! `src/native/NativeUiInterruptionControl.ts`.

/// Scenario output is charged at twice the encoded result size before return.
pub const NATIVE_UI_OUTPUT_BUDGET_BYTES: usize = 64 * 1024 * 1024;
/// `NATIVE_UI_OUTPUT_WEIGHT`.
pub const NATIVE_UI_OUTPUT_WEIGHT: usize = 2;
/// Bytes added around a result by the helper's `{ "ok": true, "result": {} }`
/// success JSON response, versus the bare `{}` placeholder result.
pub const NATIVE_UI_HELPER_ENVELOPE_BYTES: usize = {
    // `{"ok":true,"result":{}}`.byteLength - `{}`.byteLength.
    const WRAPPER: &str = "{\"ok\":true,\"result\":{}}";
    const EMPTY: &str = "{}";
    WRAPPER.len() - EMPTY.len()
};
/// Raw helper output is bounded by the scenario's unweighted byte budget.
pub const NATIVE_UI_HELPER_MAX_BUFFER: usize =
    NATIVE_UI_OUTPUT_BUDGET_BYTES + NATIVE_UI_HELPER_ENVELOPE_BYTES;

/// The owned native UI operation deadline (`NATIVE_UI_DEADLINE_MS`).
pub const NATIVE_UI_DEADLINE_MS: u64 = 180_000;
