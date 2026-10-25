# REA (Rust)

A Rust rebuild of [REA](https://github.com/morluto/rea), the local-only
reverse-engineering tool with shared CLI and MCP workflows.

## Why Rust

The original REA runs on Node.js and TypeScript. On real investigations it was
heavy on RAM and system resources: every process paid a Node runtime and module
graph before doing any analysis, and large outputs were built and held as
JavaScript objects. On a developer machine running an agent, a decompiler and
REA side by side, that cost was a recurring problem.

This port keeps REA's tool contracts, Evidence model and session semantics, and
replaces the runtime with a native executable. It does not start Node and has
no TypeScript fallback. The same production composition serves both the CLI and
stdio MCP adapters; the Ghidra provider is packaged as a separate Rust worker.

### Runtime performance

**Rust started faster and used less memory in these tests. Java Ghidra handled
one larger program that Rust Ghidra could not decompile.**

We compared frozen TypeScript and Rust builds on the same Apple M1 Pro on
24 October 2026. These results describe those builds, before the later Rust
optimizations below. Lower times are better; one second is 1,000 milliseconds
(ms). Each row uses seven sessions per version; repeated requests use 56 calls
per version.

| What REA did                                     |   TypeScript |          Rust |
| ------------------------------------------------ | -----------: | ------------: |
| Start, then read build details from a Go program | 0.57 seconds | 0.064 seconds |
| Start, then read a 25,000-package Rust test file | 0.89 seconds |  0.46 seconds |
| Start, run nine Go checks and save results       | 1.15 seconds |  0.33 seconds |
| Repeat a Go check while REA stays running        |       7.3 ms |       16.2 ms |

Startup explains much of the gain in the first three rows. Repeated Go metadata
checks took longer in Rust. For the Go command, typical peak memory was
**351 MiB for TypeScript versus 99 MiB for Rust**. MiB is a memory unit close to
a megabyte; periodic measurements can miss brief spikes.

All 84 metadata/startup runs completed, with the same tested analysis information
and saved results. These were file-reading tasks with files already in the
operating system's cache. Actual AI token costs were not measured. The
[full comparison](experiments/analysis-efficiency/runtime-comparison/README.md)
includes the raw results, exact versions, coverage gaps and reproduction steps.

The [CPU and memory audit](docs/performance.md) compares further Rust optimizations
against this repository's original Rust code, with reproducible benchmarks and
raw measurements.

### Ghidra decompilation

Decompilation turns compiled functions back into C-like code. TypeScript used
Java Ghidra 12.1.4; native REA used Rust Ghidra (`ghidra-decompiler` 2.1.0, based on
Ghidra 12.2).

| Same small C program                           | TypeScript + Java Ghidra | Native + Rust Ghidra |
| ---------------------------------------------- | -----------------------: | -------------------: |
| Start REA and get the first function's code    |             9.43 seconds |         0.39 seconds |
| Start REA and get all three selected functions |             9.47 seconds |         0.43 seconds |
| Request the same function again                |                  10.3 ms |               1.2 ms |
| Peak memory for the complete session           |                1,022 MiB |              214 MiB |

These are middle results from seven sessions per version. Most of the first-code
difference was startup and preparation: once ready, the first decompilation
request took about **16 ms in Java and 15 ms in Rust**. Both returned the three C
functions and passed the checked source facts. Java displayed readable strings
and names where Rust displayed addresses.

**On the larger Go formatter, Java returned all three requested functions;
Rust returned none because of an import-name collision.** That was one final
attempt per engine, following qualification with the same outcome. The failed
Rust attempt is not counted as faster decompilation. Different engine versions,
analysis work and output quality limit the comparison. See the
[Ghidra report](experiments/analysis-efficiency/runtime-comparison/GHIDRA.md)
for code examples, exact timings and retained evidence.

### Native Ghidra worker

Ghidra analysis runs in `ghidra-rust-worker/`, a Rust worker that replaces the
Java Ghidra bridge entirely, so no JVM is required. Observed on
`UnityPlayer.dylib` (124 MB, 178,573 functions): open in 7.5 s, full procedure
inventory (698 pages) in 32.8 s, sampled peak process-family RSS 459 MiB.
Whole-app decompilation of Unity.app (193,191 functions, 4 threads) completes
in about 25 minutes with 193,183 functions decompiled. There is no Java
baseline for these runs in this repository, so they are reported as absolute
numbers rather than a comparison; these are historical observations, not an
8cl comparative benchmark.

## Implementation and verification status

- The catalog contains 209 frozen MCP contracts. The default `rea` build
  registers 200 of them across the ledger, artifact, capture, Android, web,
  managed, application, debug, process, binary and enhanced tool families. A
  build with the optional `frida` feature registers the remaining nine Frida
  contracts as well. The feature-enabled source composition is expected to
  expose all 209 catalog tools; receipt 8cl records a healthy production-stdio
  `rea mcp doctor` inventory with 209 expected and 209 observed tools. The nine
  feature-gated entries are:
  `list_frida_devices`, `list_frida_processes`, `start_frida_session`,
  `load_frida_script`, `resume_frida_session`, `unload_frida_script`,
  `frida_session_status`, `close_frida_session`, and
  `instrument_with_frida`. This source-composition statement is not a claim
  that every bound tool has completed parity verification.
- The nine Frida tools are implemented behind the optional `frida` feature.
  Building that feature requires the pinned Frida development kit through
  `REA_FRIDA_DEVKIT_DIR`; it is therefore disabled in the default feature set.
- JavaScript and Electron analysis are registered in the production composition
  and are available through the native application and web tool families. A
  binding or inventory entry does not by itself establish parity for every
  workflow or provider path; use the public CLI/MCP verification records for
  those claims.
- Prior real-runtime Electron evidence is recorded in the parent migration
  workspace under `docs/verification/electron-native-once-2026-10-16.md` and
  `docs/verification/electron-ipc-listeners-2026-10-16.json`. Those historical
  records retain their stated cleanup and coverage limitations and are not
  included in this standalone Rust repository; they do not establish
  cross-platform release verification. The current inventory audit was on
  macOS arm64.
- Final validation records strict comparison 828/828 exact with zero timeouts,
  workspace run 117 at 1,681 passed, 0 failed and 5 ignored across 94 groups,
  format run 120 passed, clippy run 118 passed with existing warnings, pinned
  `npm run check:fast` typecheck and lint passed, and graph-golden run 101
  passed 138/138 byte-identical checks. Final release 8cl binary SHA-256 is
  `71d356878725edf969e588469001b1e2960d2955083612ef51183246b79a54e2`; the
  package SHA-256 is
  `643e45dd956d47195eed04499a402e3b3b1658479c4de9c934638e345cfc9362`.
  The immutable archive is `.cache/rust-migration/rea-agents-final-8cl.tgz` with
  the same hash. Receipt 8cl covers JavaScript 12/12, ASAR 21/21, mobile 3/3,
  Frida 52 checks across 7 scenarios, HTTP 13/13, MCP registration 11/11,
  accessible setup planning, maintenance 11, and environment SDK verification
  with 19 tools plus malformed, tamper and package-preservation checks.
  Browser proof 8cl passed regular and indexed maps through CLI and MCP;
  resolver proof 8cl passed eight assertions through both adapters.
  CLI proof records 9 exact cases and 8 qualified
  differences, including the pathname-race provenance difference and doctor
  observation/shape differences. Installed CLI 123 and installed MCP 124 also
  passed, including bundled worker identity and explicit Ghidra Rust checks.
  See the [native verification record](docs/verification/native-runtime-migration-2026-10-24.md)
  for the full receipt context.

The release evidence above covers the validated macOS arm64 workflow. Linux,
Windows and other real-provider combinations remain unverified.

[MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) is the implementation and verification
contract for changing native tool families or adding a new one. It does not
replace the per-family runtime records required before making a parity or
release claim.

## Build

From this repository's root, build and run the production binary directly with:

```sh
cargo build --locked --release -p rea
target/release/rea --help
```

When this repository is embedded as `native/` in the parent REA migration
workspace, the parent npm package launcher resolves this executable and never
falls back to the TypeScript runtime. The parent workspace builds its host
artifacts from its own root with:

```sh
npm run build:native
npm pack
```

The equivalent parent-workspace Cargo command is:

```sh
cargo build --manifest-path native/Cargo.toml --locked --release -p rea
```

The standalone Rust repository has no `package.json`, so the npm commands are
available only in that parent workspace. Its package build uses
`CARGO_TARGET_DIR` when set and otherwise uses `native/target`. Release jobs may set `CARGO_TARGET_DIR` to a shared writable
directory when several lanes reuse the same Cargo cache. It clears
`RUSTC_WRAPPER` for this build because the global cache wrapper is not reliable
for this workspace.
Optional native features can be passed through `REA_NATIVE_FEATURES` in the
parent workspace; for example, `REA_NATIVE_FEATURES=frida npm run build:native`
requires the pinned Frida development kit and produces a feature-enabled
artifact.

The artifacts are stored as `native/bin/rea-<platform>-<architecture>` and
`native/bin/rea-ghidra-rust-worker`; the package launcher selects the first and
the Ghidra provider discovers the worker beside it. Set `REA_NATIVE_TARGET` when Cargo is
building a supported cross-compilation target whose binary is available in the
installed Rust toolchain. Each release artifact must be built for its target
before packing; unsupported hosts receive an explicit launcher error rather
than silently selecting another runtime.

The toolchain is pinned in `rust-toolchain.toml`.

## Layout

The repository is one Cargo workspace (one lockfile, one toolchain pin) plus
two independently built components:

- `ghidra-rust-worker/` is the Ghidra provider's worker process, a separate
  Cargo workspace with its own lockfile and toolchain. Workspace commands never
  build or format it.
- `windows/` is the Node-API addon (C++) used by the original runtime.

```text
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
    └── legacy/       rea-runtime    superseded runtime kept for reference
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
  `src/`; to adopt one, move it into `src/` and declare it. Files outside the
  module tree are not production capabilities until they are registered and
  exercised through the public adapter.
- Import a group and qualify its members (`use rea_application::adb;` then
  `adb::client::...`) rather than aliasing leaf modules.

## Manifests

- Members inherit `version`, `edition`, `rust-version`, `license` and `publish`
  from `[workspace.package]`. `rea` keeps its own version, which tracks the
  original npm package.
- Every dependency, including workspace crates, is pinned once in
  `[workspace.dependencies]`. Members write `name.workspace = true` and add only
  the features they use.
- `[workspace.lints]` forbids `unsafe_code`. Crates that need FFI or stricter
  documentation (`rea-core`, `rea-ffi`, `rea-host`, `rea-tools-android`) keep an
  explicit `[lints]` table.

## Development commands

Run these commands from this repository's root:

```sh
cargo test --workspace --locked --offline
cargo test --workspace --release --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo fmt --all --check
sh crates/platform/rea-ffi/verify-c.sh
```

Offline commands require the pinned toolchain and locked dependencies already
available. The C verifier needs an installed compiler and runs on macOS/Linux.

## License

MIT. See [LICENSE](LICENSE). Based on [REA](https://github.com/morluto/rea) by
morluto.
