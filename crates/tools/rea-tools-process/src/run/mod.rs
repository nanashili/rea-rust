//! `capture_process_scenario`: one caller-selected command on an owned PTY.
//!
//! Compatibility owners: `src/process/capture/*` and `registerProcessTools`
//! (`src/server/registerSessionTools.ts`). Module ownership:
//! - `scenario`: parsed input, refinements and commitments;
//! - `paths`: runtime path resolution, launch environment, executable sample;
//! - `normalize`: bounded text and sample normalization;
//! - `renderer`: rendered frames over `rea_host::process::terminal`;
//! - `sampler`: process-tree sampling;
//! - `snapshot`: filesystem snapshots and effects;
//! - `capture`: the run lifecycle and resource release;
//! - `result`: capture value, manifest, limitations and unknowns;
//! - `tool`: the MCP handler, Evidence, residual unknowns and retained cleanup.

mod capture;
mod normalize;
mod paths;
mod renderer;
mod result;
mod sampler;
mod scenario;
mod snapshot;
#[cfg(test)]
mod tests;
pub mod tool;
