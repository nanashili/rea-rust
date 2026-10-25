# Development

## Source setup

Clone and build this repository directly:

```sh
git clone https://github.com/nanashili/rea-rust.git
cd rea-rust
cargo build --locked --release -p rea
```

Embedded Java, Python, Swift, and JavaScript helpers live in `bridge/` and
`scripts/`. Building the executable does not require Node.js or the original
TypeScript checkout. The commands in the [README](../README.md) use Cargo's
default target directories; adjust executable paths if you set `CARGO_TARGET_DIR`.

Rust is pinned in `rust-toolchain.toml`. Native dependencies require a C/C++20
compiler. Use GCC 12+ on Linux (`CC=gcc-12 CXX=g++-12 cargo build ...`). On
Windows, install Visual Studio 2022 Build Tools with the Desktop C++ workload,
the MSVC x64 or ARM64 toolchain for your machine, and a Windows 10/11 SDK, then
build from a Developer PowerShell. Provider tools such as LLDB, Swift, JADX, and mitmproxy are needed
only for the workflows that use them.

## Ghidra worker

`ghidra-rust-worker/` has its own Cargo workspace, lockfile, and toolchain pin.
Root workspace commands do not build, test, or format it.

```sh
cargo build --manifest-path ghidra-rust-worker/Cargo.toml --locked --release
cargo fmt --manifest-path ghidra-rust-worker/Cargo.toml -- --check
```

Copy `rea-ghidra-rust-worker` beside `rea` (both use `.exe` on Windows), or set `REA_GHIDRA_RUST_WORKER` to
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

The UTF-16 graph regression fixture is checked into the application crate.
Full workspace checks run from a standalone checkout:

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

## Releases

The [release workflow](../.github/workflows/release.yml) builds six native
archives on pushes and pull requests: macOS, Linux, and Windows on ARM64 and
x86-64. Tagging the commit with `v` followed by the `rea` crate version publishes
a release after every platform passes. Manual workflow runs build downloadable
artifacts without publishing.

Each archive contains the CLI, Ghidra worker, investigation skill, license,
version, and a file digest manifest. The workflow tests the packaged executable
through CLI, MCP, client registration, and Ghidra decompilation before upload.
`SHA256SUMS`, `install.sh`, and `install.ps1` accompany published archives.
Each installer runs `rea --verify-installation` before activation, using the
runtime's own manifest parser to confirm the release identity.

Windows release builds use native x64 and ARM64 MSVC runners and package ZIP
archives (`x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`). Both run the
installer checks and packaged CLI/MCP/Ghidra smoke tests. Run the Windows
installer checks locally with:

```powershell
python scripts/release/test-install-windows.py --target aarch64-pc-windows-msvc
# Use --target x86_64-pc-windows-msvc on x64 Windows.
```

Linux archive and Actions artifact names omit the vendor field (for example,
`rea-rust-x86_64-linux-gnu.tar.gz` and `release-x86_64-linux-gnu`). Cargo builds,
release manifests, and installation identities still use the canonical Rust
targets, such as `x86_64-unknown-linux-gnu`.

To package an existing target build locally, using Python 3.11+:

```sh
python3 scripts/release/package.py --target aarch64-apple-darwin --output-dir dist
python3 scripts/release/smoke.py --archive dist/rea-rust-aarch64-apple-darwin.tar.gz
python3 scripts/release/test-install.py
```

The packager also accepts `--rea` and `--worker` for custom build directories.
Installer tests use local download fixtures; the archive smoke uses the actual
built executables and compiles its own small C analysis target.
