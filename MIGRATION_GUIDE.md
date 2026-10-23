# Native migration guide for tool families

This guide is the working contract for porting REA's TypeScript runtime
(`src/`) to the native Rust workspace (`native/`). The Rust executable `rea`
(`native/crates/apps/rea`) replaces `scripts/rea.mjs`: `rea mcp` serves stdio
MCP and every other invocation is the CLI. [README.md](README.md) maps the
crate layers under `native/crates/` and the module layout inside each crate.

## Ground rules

- Port behavior exactly. The TypeScript source is the oracle: read the tool's
  contract (`src/contracts/**`), registration (`src/server/register*.ts`),
  application service (`src/application/**`), domain logic (`src/domain/**`)
  and provider adapter (`src/<provider>/**`) before writing Rust.
- The advertised contract is frozen in
  `native/crates/interfaces/rea-mcp/contracts/catalog/mcp-tools.json` (exact `tools/list`
  output, plus `kind`, `returns_target_content`, `effects`, `examples`). Your
  results must satisfy the tool's `outputSchema` there. Never edit the catalog.
- Do not write or run tests. Compile your crate until it has zero errors:
  `CARGO_TARGET_DIR=/tmp/rea-target-<crate> cargo build -p <crate>`
  (a private target directory avoids waiting on other builds).
- Only edit files inside the crate(s) you were assigned. Do not edit
  `rea-mcp`, `rea-core`, `rea-analysis`, `rea` (`native/crates/apps/rea`), the
  workspace `Cargo.toml`, `Cargo.lock` by hand, or another family's crate. If a
  shared change is required, implement a local helper and list the request in
  your final report.
- You may reuse code from `rea-application`, `rea-host`, `rea-rust-analysis`,
  `rea-core` and the legacy `rea-runtime` handlers by calling them (they are
  dependencies) or by copying code into your crate. The legacy native code is
  uneven: verify every reused function against the TypeScript behavior. Many
  legacy handlers use "captured offline" inputs that differ from the public
  contract; the public contract always wins. Uncompiled ("orphaned") ports
  live outside `src/`, in a crate's `orphaned/` directory (for example
  `crates/platform/rea-host/orphaned/ghidra_rust/`); copy any you need into
  your crate rather than wiring them back into their owner.
- Inherit dependencies from the workspace table (`serde.workspace = true`,
  adding only the features you use). A crates.io dependency the table lacks
  may be declared in your own `Cargo.toml` with an exact version (`=x.y.z`),
  only for well-known maintained crates; list it as a requested shared change
  so it moves into `[workspace.dependencies]`. Cargo updates `Cargo.lock`
  itself. Builds may use the network.
- Keep `[lints] workspace = true` (it forbids `unsafe_code`) unless a platform
  API truly needs FFI; then use an explicit `[lints]` table as `rea-tools-android`
  does, isolate the FFI in one module with `// SAFETY:` comments and relax the
  lint for that module only.
- No silent fallbacks, no reduced coverage, no invented capabilities, no new
  execution or mutation authority. Preserve caller inputs, unknowns, provider
  identity and limitations exactly as the original does.

## Framework (crate `rea-mcp`)

```rust
use rea_mcp::{Registry, ToolContext, ToolOutput, Session, SessionResource};
use rea_core::analysis_error::{AnalysisError, ErrorKind, InputIssue, CapturedOutput};
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};

pub fn register(registry: &mut Registry) {
    registry.handle("inspect_rust_binary", |context: &ToolContext<'_>, input: serde_json::Value| {
        // `input` was validated against the frozen inputSchema and has
        // declared defaults applied, exactly like the original Zod parse.
        ToolOutput::Value(serde_json::json!({}))
    });
}
```

- `ToolOutput::Evidence(evidence)` – the server retains it in the session
  ledger and delivers it (the common case: TS `toEvidenceToolResult`).
- `ToolOutput::Value(value)` – plain result (TS `toCallToolResult`). For
  tools whose catalog `kind` is `session`, the server wraps it as
  `{ "result": value }` automatically; return the unwrapped value.
- `ToolOutput::Failure(error)` – a typed failure. If
  `error.partial_observation` is complete Evidence (has `evidence_id`), it is
  retained and referenced exactly as the original partial-error delivery.
- `ToolOutput::Raw(call_tool_result)` – only for exact legacy projections.
- `From<Result<Evidence, AnalysisError>>` and `From<AnalysisError>` exist.

`ToolContext` gives `contract` (catalog entry: `kind`,
`returns_target_content`, schemas), `session`, `cancellation`
(`rea_core::cancellation::Cancellation`; check `reason()` regularly and pass
it to long work) and `progress` (`progress.report(phase, message)`).

`Session` (shared by every call on one connection):
- `session.env("REA_X")` – the environment snapshot taken at startup. Never
  read `std::env` in handlers.
- `session.record(&evidence)` / `record_raw(&raw)` – retain extra Evidence
  (for example source records before a derived comparison).
- `session.evidence(id)` – retained record by Evidence ID (for tools that
  accept `evidence_id` references). `session.retained_records()`,
  `session.export_bundle()`.
- `session.state::<T>()` – per-session family state (`T: Default + Send +
  Sync`), created on first use. Use it for provider sessions, caches, active
  targets.
- `session.own_once(arc_state)` – register a `SessionResource` whose
  `close()` runs at shutdown; return an error to keep ownership for retry.
- `session.active_subject()` – Evidence subject of the open binary target.

Errors: build `AnalysisError` from `ErrorKind` variants that mirror the TS
classes one-to-one (`AnalysisInputError` → `ErrorKind::Input`,
`ProviderAdapterError` → `ErrorKind::ProviderAdapter`, `ArtifactOperationError`
→ `ErrorKind::ArtifactOperation`, `BrowserObservationError` →
`ErrorKind::BrowserObservation`, ...). Code, category, message, retryable,
remediation and details are derived exactly like
`src/domain/analysisErrorProjection.ts`; set `diagnostics`,
`captured_output`, `cleanup`, `partial_observation` and the `with_*`
builders as the TS producer does. `AnalysisError::from(failure)` adopts a
legacy `rea_core::failure::Failure`.

Evidence: `Evidence::create(target, provider, observation)` is an exact port
of TS `createEvidence` (same semantic projection and `ev_` digest). Build the
`Observation` with the same `predicateType`, `operation`, `parameters`,
`result`, `rawResult`, `analysisProfile`, `confidence`, `authority`,
`environment`, `limitations`, `relationshipCoverage`, `locations` and
`evidenceLinks` the TS code passes. Subjects: `SubjectTarget { path, sha256,
format, architecture }`. Helpers live in `rea_mcp::support`.

Processes: launch external tools only through
`rea_host::process::launcher::{OwnedChildProcess, ChildLaunchSpec}` (owned
process group / Windows Job Object; `arguments` is an exact argv vector).
Poll `try_wait`, honor cancellation with `cancel(code)`, bound output, and
retain cleanup failures. Mirror the original timeouts and output limits.

Files: use `rea_host::fs::stable_file` where the TS code used stable artifact
acquisition (identity revalidation), and preserve the TS error mapping.

Deep-analysis providers implement `rea_analysis::{AnalysisProvider,
AnalysisClient}`; the binary session (`rea-tools-binary`) owns selection,
admission, snapshots and Evidence for official/enhanced tools.

The CLI calls the same handlers through `rea_mcp::invoke(...)`, so a tool's
handler is its single implementation for both adapters.

## Report

Finish with: tools implemented, notable TS semantics ported, deviations or
gaps (with reasons), new dependencies, and any requested shared changes.
