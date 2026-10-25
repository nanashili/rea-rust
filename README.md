# REA

A Rust port of [REA](https://github.com/morluto/rea) for local reverse
engineering from the terminal or an MCP client.

Inspect binaries, decompile functions, analyze JavaScript and Electron apps,
read managed and mobile artifacts, and work with process and browser captures.
The CLI and MCP server use the same tool implementations. The runtime does not
require Node.js.

## Install

Prebuilt releases include `rea`, the MCP server, and the Ghidra worker for
macOS, Linux, and Windows on ARM64 and x86-64. No Node.js, Rust toolchain, or
administrator account is needed.

```sh
curl -fsSL https://github.com/nanashili/rea-rust/releases/latest/download/install.sh -o install-rea.sh
sh install-rea.sh
export PATH="$HOME/.local/bin:$PATH"
rea --version
```

On Windows, run the PowerShell installer from a PowerShell prompt:

```powershell
irm https://github.com/nanashili/rea-rust/releases/latest/download/install.ps1 -OutFile install-rea.ps1
powershell -ExecutionPolicy Bypass -File .\install-rea.ps1
```

The installers verify release checksums and store versioned files in a
per-user directory. They do not edit shell profiles, `PATH`, or MCP settings.
Rerun the installer to update, or set `REA_VERSION` to select a release. See
[installation details](docs/installation.md) for paths, custom locations, and
removal.

## Build from source

Requires the pinned Rust toolchain (1.93.1), Python 3.11+ for release scripts,
and a C/C++20 compiler (GCC 12+ on Linux). This repository contains all embedded
helper sources.

```sh
git clone https://github.com/nanashili/rea-rust.git
cd rea-rust
cargo build --locked --release -p rea
target/release/rea --help
```

### Ghidra decompilation

On macOS, Linux, or Windows, build the Ghidra worker separately and place it
beside `rea`:

```sh
cargo build --manifest-path ghidra-rust-worker/Cargo.toml --locked --release
cp ghidra-rust-worker/target/release/rea-ghidra-rust-worker target/release/
```

In PowerShell, use `Copy-Item ghidra-rust-worker/target/release/rea-ghidra-rust-worker.exe target/release/` for the copy step.

The worker uses the native Ghidra decompiler and requires no JVM. To keep it
elsewhere, set `REA_GHIDRA_RUST_WORKER` to its absolute path.

Frida is an optional build feature. See [Frida setup](docs/development.md#frida).
Other analysis providers and external tools require their own installations.

## CLI

```sh
rea inspect /path/to/program
rea decompile /path/to/program main --provider ghidra-rust
rea inspect-go-binary /path/to/go-program --format json
rea doctor
```

Use `--help` on any command for its arguments and options.

## MCP

Add this to your client's MCP configuration, replacing the executable path:

```json
{
  "mcpServers": {
    "rea": {
      "command": "/absolute/path/to/rea",
      "args": ["mcp"]
    }
  }
}
```

`rea mcp` starts the stdio server. Use the installed executable's absolute path;
MCP clients may have a different `PATH` from your shell. `rea setup` previews
client registrations and skill installation, then asks before applying changes.
Release installs already include the Ghidra worker.

## Status

GitHub Actions builds and smoke-tests macOS and Linux archives on both
architectures, plus Windows ARM64 and x64 archives, before publishing a tagged
release. Musl Linux and Frida-enabled binaries are not provided.
Other analysis providers and external tools require their own installations.

Known behavior differences and test coverage are recorded in the
[migration verification report](docs/verification/native-runtime-migration-2026-10-24.md).

## Benchmarks

The [local application benchmark](docs/benchmarks/local-applications-2026-10-25/README.md)
covers 11 installed macOS applications and Go: 125 samples across 25 workflows,
with elapsed time, CPU, memory, per-call results and documented failures.
The [failure verification rerun](docs/benchmarks/failure-verification-2026-10-25-v2/README.md)
records fixes, repeated measurements, and remaining failures. The
[library assessment](docs/benchmarks/library-assessment-2026-10-25.md) covers
proposed data-structure, string, compression and allocator experiments.

The separate TypeScript/native comparison used frozen builds, measured on an
Apple M1 Pro on 24 October 2026, with warm filesystem caches. Seven sessions per
version; the repeated request row uses 56 calls per version:

| Task | TypeScript | Rust |
| --- | ---: | ---: |
| Start and inspect Go build metadata | 570 ms | 64 ms |
| Repeat a Go metadata request in a running session | 7.3 ms | 16.2 ms |
| Start and decompile the first function in a small C program | 9.43 s | 0.39 s |
| Sampled peak process-family memory during that decompilation session | 1,022 MiB | 214 MiB |

The decompilation comparison used Java Ghidra for TypeScript and Rust Ghidra
for the native build. Rust failed on the larger Go test because of an
import-name collision; Java returned all three requested functions.

See the [runtime comparison](experiments/analysis-efficiency/runtime-comparison/README.md)
and [Ghidra results](experiments/analysis-efficiency/runtime-comparison/GHIDRA.md)
for inputs, raw measurements, output differences, and reproduction steps.
The [performance audit](docs/performance.md) covers later Rust optimizations.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --locked
cargo test --locked -p rea-core -p rea-rust-analysis -p rea-mcp
```

The [development guide](docs/development.md) covers source layout, full workspace
test requirements, the Ghidra worker, and the experimental C API.
See [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) when changing tool behavior and
[the architecture notes](docs/rust-runtime-migration.md) for crate ownership.

## License

[MIT](LICENSE). Based on [REA](https://github.com/morluto/rea) by morluto.
