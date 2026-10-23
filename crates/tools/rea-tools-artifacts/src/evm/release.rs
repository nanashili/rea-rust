//! Locked EVMole provider identity, offline budgets and host requirement.
//!
//! Compatibility owner: `src/evm/EvmoleRelease.ts`
//! (`EVMOLE_PROVIDER_IDENTITY`, `EVM_INTERFACE_LIMITS`,
//! `EVM_FILE_SIZE_FAILURE_EXIT`) and the `HOST_REQUIREMENT` /
//! `OPERATION` constants shared by `EvmoleInterfaceProvider.ts` and
//! `EvmInterfaceService.ts`.

/// `OPERATION` in `EvmInterfaceService.ts` / `EvmoleInterfaceProvider.ts`.
pub(crate) const OPERATION: &str = "inspect_evm_interface";

/// `EVMOLE_PROVIDER_IDENTITY.id` in `EvmoleRelease.ts`.
pub(crate) const PROVIDER_ID: &str = "evmole-interface";
/// `EVMOLE_PROVIDER_IDENTITY.name`.
pub(crate) const PROVIDER_NAME: &str = "REA EVM interface adapter";
/// `EVMOLE_PROVIDER_IDENTITY.version` (locked npm/WASM profile).
pub(crate) const PROVIDER_VERSION: &str = "evmole@0.9.3";

/// `HOST_REQUIREMENT` in `EvmoleInterfaceProvider.ts`.
pub(crate) const HOST_REQUIREMENT: &str =
    "Initial real-verified offline EVM interface profile supports Linux x64 only.";

/// `EVM_INTERFACE_LIMITS.inputBytes`.
pub(crate) const INPUT_BYTES: usize = 4 * 1024 * 1024;
/// `EVM_INTERFACE_LIMITS.outputBytes` (the owned worker reply budget).
pub(crate) const OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// `EVM_INTERFACE_LIMITS.addressSpaceBytes` (worker virtual address space).
pub(crate) const ADDRESS_SPACE_BYTES: u64 = 3 * 1024 * 1024 * 1024;
/// `EVM_INTERFACE_LIMITS.timeoutMs` (the owned worker deadline).
pub(crate) const TIMEOUT_MS: u64 = 30_000;
/// The worker CPU-time soft-limit ceiling (`selectEvmWorkerLimits` "Max cpu time").
pub(crate) const CPU_SECONDS: u64 = 30;
