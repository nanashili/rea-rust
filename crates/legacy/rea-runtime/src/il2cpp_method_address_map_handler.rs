//! Runtime adapter for `map_il2cpp_method_addresses`.
//!
//! The application projection owns token/RID interpretation and exact
//! CodeGenModule identity matching. This adapter forwards retained facts only;
//! it never opens an executable, resolves a target, or guesses an address.

use rea_application::il2cpp;
use rea_core::failure::Failure;
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::method_address_map::OPERATION;

/// Project caller-supplied IL2CPP method tokens onto native pointer slots.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected method-address mapping request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::method_address_map::project(input)
}
