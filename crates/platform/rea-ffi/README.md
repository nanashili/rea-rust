# Experimental C embedding interface

`rea-ffi` exposes safe `rea-core` process-stat and process-status parsers as
versioned C functions.
It builds a shared library and a static archive, with no third-party dependencies.
It is not packaged or selected by the production REA CLI/MCP runtime.

The public contract is [include/rea.h](include/rea.h). Input and result storage
belong to the caller. The process-stat result contains byte offsets into the
original input, not Rust-owned strings or pointers requiring allocator-specific
deallocation. The process-status result exposes the effective UID only after
validating the complete native `Uid:` row and rejecting duplicates. No process is
acquired, executed or signaled. Unknown lifecycle is distinct from confirmed
terminal state, and neither a lifecycle nor a UID establishes process ownership.

Invalid arguments leave output untouched. Invalid UTF-8 is rejected rather than
decoded lossily. Malformed records return a tagged reason and native field number.
Rust unwind panics are caught; invalid caller pointers, process aborts and other
undefined behavior cannot be made safe by an FFI wrapper. Callers must obey the
header's allocation, alignment, immutability and non-overlap requirements.

## Build and verify

From the repository root on macOS or Linux:

```sh
sh native/crates/platform/rea-ffi/verify-c.sh
```

The script uses the pinned Rust toolchain and an already installed C compiler
(`CC`, default `cc`). It installs nothing. It builds in a private directory,
compiles the C ABI assertions and the example consumer against the actual shared
library, runs them, then removes that directory. C assertions check field layout
through real calls, numeric lifecycle and UID error tags, exact source offsets,
malformed input, UTF-8 failure, output initialization and argument rejection.
The example checks both successful output and a malformed-record diagnostic.

For persistent development artifacts:

```sh
cd native/crates/platform/rea-ffi
cargo build --release --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt --check
```

`examples/inspect_process_stat.c` accepts one quoted stat record and prints the
observed facts; for example, on Linux the caller can supply a saved procfs record.
This is an embedding example, not a replacement REA analysis command.

Verified locally on macOS arm64 with a real C compiler and shared library.
Linux, Windows, C++, static-link distribution and live-process authority are not
verified. These checks do not establish a whole-investigation resource gain.
