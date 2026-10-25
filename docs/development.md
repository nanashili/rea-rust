# Development

## Source setup

The Rust workspace currently embeds seven helper files from the parent
checkout's `bridge/` and `scripts/` directories at compile time. A standalone
clone does not contain them yet. Use a checkout of the original REA repository
as the parent directory:

```sh
git clone https://github.com/morluto/rea.git rea-workspace
git -C rea-workspace checkout 833136507dd79d959340b09862a53af344e4f1b3
git clone https://github.com/nanashili/rea-rust.git rea-workspace/rea-rust
cd rea-workspace/rea-rust
cargo build --locked --release -p rea
```

That parent revision contains the helper sources used by the migration:

- `bridge/android/ReaJadxBridge.java`
- `bridge/mitmproxy/capture.py`
- `bridge/native/rea_lldb_tracer.py`
- `bridge/native/ReaNativeUI.swift`
- `bridge/native/NativeUIChildren.swift`
- `scripts/electron-active-hook.cjs`
- `scripts/electron-active-hook-boundaries.cjs`

No npm install is needed to build the Rust executable. The commands in the
[README](../README.md) use Cargo's default target directories; adjust executable
paths if you set `CARGO_TARGET_DIR`.

Rust is pinned in `rust-toolchain.toml`. Use an installed C/C++ compiler for
native dependencies. Provider tools such as LLDB, Swift, JADX, and mitmproxy are
needed only for the workflows that use them.

## Ghidra worker

`ghidra-rust-worker/` has its own Cargo workspace, lockfile, and toolchain pin.
Root workspace commands do not build, test, or format it.

```sh
cargo build --manifest-path ghidra-rust-worker/Cargo.toml --locked --release
cargo fmt --manifest-path ghidra-rust-worker/Cargo.toml -- --check
```

Copy `rea-ghidra-rust-worker` beside `rea`, or set `REA_GHIDRA_RUST_WORKER` to
its absolute path. The worker's [configuration module](../crates/providers/rea-provider-ghidra/src/configuration.rs)
documents cache, timeout, memory, and concurrency settings.

## Frida

The default build excludes Frida. On macOS arm64, the fetch script downloads
the pinned frida-core devkit and verifies its SHA-256:

```sh
eval "$(sh crates/tools/rea-tools-debug/scripts/fetch-frida-devkit.sh --env)"
cargo build --locked --release -p rea --features frida
```

The build uses bindgen and requires libclang. For an existing devkit, set
`REA_FRIDA_DEVKIT_DIR` to the directory containing `frida-core.h` and
`libfrida-core.a`, and add that directory to `BINDGEN_EXTRA_CLANG_ARGS` with
`-I`. The fetch script currently has a pinned download hash for macOS arm64
only.

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --locked
cargo test --locked -p rea-core -p rea-rust-analysis -p rea-mcp
```

Full workspace tests and Clippy's `--all-targets` also compile a test that
embeds a parent-workspace golden fixture:

```text
../.cache/rust-migration/js-graph-golden/golden/utf16-boundary/raw/86464-0000-application-graph.json
```

That fixture is not published in this repository or the parent source checkout.
The full checks below require the original migration workspace with the
fixture present:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked
```

Use `--offline` after the locked dependencies are cached. Existing Clippy
warnings are not treated as errors by the commands above.

## Crate layout

| Directory | Responsibility |
| --- | --- |
| `crates/core/` | Evidence, errors, canonical JSON, cancellation, provider contracts |
| `crates/formats/` | Static artifact readers |
| `crates/platform/` | File and process ownership, transports, C API |
| `crates/application/` | Shared analysis workflows |
| `crates/providers/` | Ghidra, Hopper, IDA, and Kuna adapters |
| `crates/interfaces/` | CLI, MCP registry, schemas, and sessions |
| `crates/tools/` | Tool implementations |
| `crates/apps/rea/` | Production executable and composition |
| `crates/legacy/` | Superseded runtime retained for reference |

Dependencies point inward toward core contracts. Providers do not depend on
tools or interfaces; only `rea` composes the complete runtime. Members inherit
shared package metadata, dependency pins, and lints from the workspace manifest.
Modules are grouped by feature. Unwired code in `orphaned/` is reference
material, not part of the production runtime.

## C API

`rea-ffi` exposes versioned process-record parsers through a C ABI. It is an
experimental embedding interface, separate from the CLI/MCP runtime.

```sh
cargo build --locked --release -p rea-ffi
sh crates/platform/rea-ffi/verify-c.sh
```

The verifier requires macOS or Linux, a C compiler, and cached Rust dependencies.
It builds and runs the ABI assertions and example consumer in a temporary
directory. See the [header](../crates/platform/rea-ffi/include/rea.h) and
[C API notes](../crates/platform/rea-ffi/README.md) for ownership and error handling.
