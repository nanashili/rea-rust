# REA

A Rust port of [REA](https://github.com/morluto/rea) for local reverse
engineering from the terminal or an MCP client.

Inspect binaries, decompile functions, analyze JavaScript and Electron apps,
read managed and mobile artifacts, and work with process and browser captures.
The CLI and MCP server use the same tool implementations. The runtime does not
require Node.js.

## Build

Requires the pinned Rust toolchain (1.93.1) and a C/C++ compiler. Source builds
currently need helper files from the original REA checkout at `../bridge/` and
`../scripts/`; follow the [source setup](docs/development.md#source-setup).

```sh
cargo build --locked --release -p rea
target/release/rea --help
```

### Ghidra decompilation

On macOS or Linux, build the Ghidra worker separately and place it beside `rea`:

```sh
cargo build --manifest-path ghidra-rust-worker/Cargo.toml --locked --release
cp ghidra-rust-worker/target/release/rea-ghidra-rust-worker target/release/
```

The worker uses the native Ghidra decompiler and requires no JVM. To keep it
elsewhere, set `REA_GHIDRA_RUST_WORKER` to its absolute path.

Frida is an optional build feature. See [Frida setup](docs/development.md#frida).
Other analysis providers and external tools require their own installations.

## CLI

```sh
target/release/rea inspect /path/to/program
target/release/rea decompile /path/to/program main --provider ghidra-rust
target/release/rea inspect-go-binary /path/to/go-program --format json
target/release/rea doctor
```

Use `--help` on any command for its arguments and options.

## MCP

Add this to your client's MCP configuration, replacing the executable path:

```json
{
  "mcpServers": {
    "rea": {
      "command": "/absolute/path/to/rea-rust/target/release/rea",
      "args": ["mcp"]
    }
  }
}
```

`rea mcp` starts the stdio server. Keep the Ghidra worker beside the executable,
or set `REA_GHIDRA_RUST_WORKER` in the client's environment.

## Status

The release workflow has been verified on macOS arm64. Linux and Windows
release workflows remain unverified; the Ghidra worker supports macOS and Linux.
Known behavior differences and test coverage are recorded in the
[migration verification report](docs/verification/native-runtime-migration-2026-10-24.md).

## Benchmarks

Frozen TypeScript and Rust builds, measured on an Apple M1 Pro on 24 October
2026, with warm filesystem caches. Seven sessions per version; the repeated
request row uses 56 calls per version:

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
