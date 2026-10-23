# Native runtime development

`native/` holds REA's Rust workspace (one lockfile, one toolchain pin) and two
independently built components beside it:

- `ghidra-rust-worker/` is the Ghidra provider's worker process. It is a separate
  Cargo workspace with its own lockfile and toolchain, and its sources are pinned
  by the Prism integration manifests in `docs/agents/`, so workspace commands
  never build or format it.
- `windows/` is the existing Node-API addon (C++), built by
  `scripts/build-windows-native.mjs`.

Neither is replaced by the workspace. [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)
is the working contract for porting tool families.

## Layout

```text
native/
├── Cargo.toml        members, shared package metadata, dependency pins and lints
├── Cargo.lock
├── rust-toolchain.toml
└── crates/
    ├── core/         rea-core       Evidence, analysis errors, canonical JSON, cancellation
    │                 rea-analysis   deep-analysis provider contract
    ├── formats/      rea-rust-analysis  bounded static artifact readers
    ├── platform/     rea-host       stable files, staged output, owned processes, transports
    │                 rea-ffi        versioned C ABI for the process-record parsers
    ├── application/  rea-application  shared workflows used by every adapter
    ├── providers/    rea-provider-{ghidra,hopper,ida,kuna}
    ├── interfaces/   rea-mcp        frozen contracts, tool registry, MCP session
    │                 rea-cli        CLI adapter over the same handlers
    ├── tools/        rea-tools-*    tool families registered into rea-mcp
    ├── apps/         rea            production executable and composition root
    └── legacy/       rea-runtime    superseded experimental `rea-native`
```

## Dependency rules

Each crate depends only on crates in earlier groups of the list above:

- `core` crates depend only on each other; `formats` and `platform` depend only
  on `core`.
- `rea-application` builds on `core`, `formats` and `platform`.
- Providers implement `rea-analysis` with `platform` resources. They never see
  tools or interfaces.
- `rea-mcp` owns the registry that tool families register into; `rea-cli` calls
  the same handlers through `rea_mcp::invoke`. `rea-tools-enhanced` is the only
  tool family that depends on another (`rea-tools-binary` owns the binary session
  it extends).
- Only `rea` composes providers and tool families. Nothing depends on
  `rea-runtime`.

## Inside a crate

- Modules are grouped by feature, for example `rea_application::il2cpp::metadata`
  or `rea_host::process::launcher`. Each group's `mod.rs` documents the group and
  declares its children. The legacy `rea-runtime` predates this layout.
- Multi-file modules use `foo/mod.rs` beside `foo/bar.rs`.
- Code under `src/` is part of the module tree. Unwired ports kept for reference
  live in the crate's `orphaned/` directory, laid out as they would be under
  `src/`; to adopt one, move it into `src/` and declare it. The `wip-*` features
  of `rea-tools-managed` are the remaining temporary exception.
- Import a group and qualify its members (`use rea_application::adb;` then
  `adb::client::...`) rather than aliasing leaf modules.

## Manifests

- Members inherit `version`, `edition`, `rust-version`, `license` and `publish`
  from `[workspace.package]`. `rea` keeps its own version, which tracks the npm
  package.
- Every dependency, including workspace crates, is pinned once in
  `[workspace.dependencies]`. Members write `name.workspace = true` and add only
  the features they use.
- `[workspace.lints]` forbids `unsafe_code`. Crates that need FFI or stricter
  documentation (`rea-core`, `rea-ffi`, `rea-host`, `rea-tools-android`) keep an
  explicit `[lints]` table.

## Commands

```sh
cd native
cargo test --workspace --locked --offline
cargo test --workspace --release --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo fmt --all --check
sh crates/platform/rea-ffi/verify-c.sh
```

Offline commands require the pinned toolchain and locked dependencies already
available. The C verifier requires an installed compiler and currently runs on
macOS/Linux; only macOS arm64 has been exercised for the C shared library.

## Status

The native `rea` binary is now the production composition for its migrated
MCP/CLI families and is built from `native/crates/apps/rea`. It does not start
Node or fall back to the TypeScript runtime. `rea mcp doctor` is the parity
inventory: currently 195 of 209 frozen tools have native handlers; the
remaining tools stay advertised but return typed capability-unavailable
results until their owning family is ported.

The native runtime already includes the Rust Ghidra provider, managed static
analysis, artifact/android/capture/ledger/binary/enhanced workflows, offline
web capture/fuse/script tools, JavaScript graph comparison workflows, and
process-capture comparison. Live browser/CDP scenarios, PTY process capture,
Frida, GDB/Rizin sessions, and JavaScript application reconstruction remain
open. See `docs/rust-runtime-migration.md` for the migration gates and
`experiments/analysis-efficiency/rust-runtime-baseline.md` for measured scope.

The native binary is not yet the published release artifact; standalone
GitHub-release packaging and supported Windows/macOS/Linux verification are
still required. The existing `rea-runtime` binary remains a legacy reference
and is not part of the production composition.

<!-- legacy status retained below for historical details -->

## Historical prototype status

These libraries are not wired into the production CLI/MCP runtime. The
experimental `rea-runtime` binary provides `rea-native inspect-rust-binary PATH
--format json`, `rea-native inspect-go-binary PATH --json` (also accepts
`--format json`), `rea-native evidence-import PATH --format json`, `rea-native
evidence-export SOURCE OUTPUT --format json [--overwrite]`, `rea-native compare
LEFT RIGHT --format json` (alias `compare-bundles`), and stdio MCP inspection,
record discovery, bundle export/import, and residual-unknown lifecycle operations.

The standalone command has matched complete original CLI Evidence for one compiled
Mach-O fixture; this does not establish all-format, MCP, provider, persistence or
packaging parity. SIGINT/SIGTERM request cleanup and preserve the first signal's
130/143 exit status. The experimental rea-native mcp command exposes the same
artifact operation over stdio. Real SDK-client checks matched complete Evidence,
including lone UTF-16 metadata. Retained bundle export matches original canonical
bytes, including recovery of transport-oversized observations after their inputs
are removed. Bundle import authenticates and atomically retains complete
residual-unknown histories, and export preserves those revisions. Residual-unknown
listing, resolution verification, creation and update are implemented and tested
through the native MCP session. Remaining operations and full lifecycle/platform
parity are still open. The standalone bundle comparison command matched the
original CLI's complete JSON for identical and one-sided membership comparisons of
a 5.65 MB bundle containing 50,000 packages. Schema-specific validation wording
still differs on malformed input. There is no Node fallback.
See `docs/rust-runtime-migration.md` for the migration gates and
`experiments/analysis-efficiency/rust-runtime-baseline.md` for measured baseline
scope and limitations.
