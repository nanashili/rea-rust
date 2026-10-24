# CPU and memory audit

An [additional pass](performance-round2.md) measures further improvements against
this first optimized version. The results below retain the first pass measurements.

Baseline: `1cccbf665b82bd6228c3a9272b431b259b9e9c06`.

## Changes

| Path | Cost found | Change |
| --- | --- | --- |
| `rea-core::canonical_json` | Arrays first allocate a vector of borrowed children, then expand every child into pending operations. Objects likewise expand keys, punctuation and values into pending operations. | Borrow each array's unconsumed source and retain an iterator for each active object. Traversal continuations scale with nesting depth; object sorting still requires memory proportional to object width. |
| `rea-core::canonical_json` | Ordinary string values are copied and serialized again; hashing receives many tiny writes. | Write validated strings without escapes directly, and buffer SHA-256 input. Escaped strings still use the lossless decoder. |
| `rea-rust-analysis::plist` | UTF-8 XML is copied twice before parsing, even when almost all of it is comments. | Borrow validated UTF-8 input, including after a UTF-8 BOM. UTF-16 decoding still owns its transcoded output. |
| Plist preflight and Electron fuse scanning | Scalar delimiter and substring searches scan large inputs byte by byte. | Use the existing `memchr` dependency's byte and substring search. |
| `rea-mcp::delivery::encode` | Build JSON and a second escaped JSON string merely to measure the response. Both buffers exist even for rejected responses. | Measure exact bytes, UTF-16 units and second-level escaping with a streaming writer. Allocate the JSON text only for an admitted response. |

Two pre-existing Linux build failures also required small portability fixes:
`libc::stat` timestamp field names in `stable_directory.rs`, and overlapping
`descriptor_observation_source` configurations in `process/observation.rs`.
Neither changes the performance algorithms. Apply these two fixes to a baseline
checkout when building the MCP benchmark on Linux.

## Measurement

Synthetic release workloads isolate the changed paths. These are **not** whole
investigation or Ghidra decompilation benchmarks. No exhaustive claim that every
performance issue is resolved is supported by these measurements.

Environment: Linux x86_64, Intel Xeon Platinum 8573C, a shared virtualized cloud
worker with a four-CPU quota and 16 GiB memory limit. Rust 1.93.1, locked
repository dependencies, release profile (thin LTO, one codegen unit). No
compilation runs alongside the recorded final measurements.

Each workload runs in seven fresh processes per version, alternating version
order. Each process performs five operations. The table uses the median of
per-process average operation times and the median process peak RSS. Operation
time excludes input construction and initial JSON validation. Peak RSS and raw
CPU measurements include process startup, input construction and every iteration;
RSS is the process high-water mark, not incremental allocation volume. OS caches
are warm and were not flushed. Cloud scheduling and allocator behavior can vary.

Inputs:

- `array`: 1,000,001 numeric array entries (about 4 MB).
- `object`: 100,000 reverse-ordered keys with numeric values.
- `string`: 21 MB of ordinary text containing slashes and emoji, without escapes.
- `fuses`: a physically populated 64 MiB ELF-shaped buffer without a fuse sentinel.
- `plist`: 32 MiB XML comment followed by a small string value.
- `delivery-fit`: 350,000 repetitions of text containing quotes, backslashes,
  newlines and emoji; admitted under the 10 MiB response budget.
- `delivery-reject`: 4,000,000 repetitions of the same text; rejected under the
  same budget. Measurement retains the original exact reported sizes.

## Results

| Workload | Before ms/op | After ms/op | Speedup | Before peak MiB | After peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| `array` | 123.25 | 88.32 | 1.40× | 97.37 | 11.38 |
| `object` | 36.93 | 31.43 | 1.18× | 34.91 | 22.41 |
| `string` | 34.53 | 14.43 | 2.39× | 41.27 | 21.22 |
| `fuses` | 64.17 | 4.86 | 13.20× | 65.11 | 65.34 |
| `plist` | 32.42 | 5.58 | 5.81× | 97.41 | 33.36 |
| `delivery-fit` | 20.45 | 9.08 | 2.25× | 12.79 | 11.38 |
| `delivery-reject` | 265.40 | 53.12 | 5.00× | 134.69 | 31.54 |

Fuse-scanning RAM is effectively unchanged: its admitted input dominates memory.
Raw samples and verification outcomes are recorded in `docs/benchmarks/`.

## Reproduction

Build baseline and changed examples in separate checkouts using the same toolchain
and build command. Copy only the benchmark examples from this change into the
baseline (and the two Linux portability fixes for the MCP build). Do not copy the
optimized source files into the baseline.

```sh
cargo build --release --locked -p rea-rust-analysis --example performance
cargo build --release --locked -p rea-mcp --example delivery-performance
# Save each version's executable outside target/ before building the next version.
python3 scripts/benchmark-performance.py /tmp/performance-before /tmp/performance-after \
  --output docs/benchmarks/formats.csv
python3 scripts/benchmark-performance.py /tmp/delivery-before /tmp/delivery-after \
  --workloads delivery-fit delivery-reject --output docs/benchmarks/delivery.csv
cargo test --locked -p rea-core -p rea-rust-analysis -p rea-mcp
cargo test --locked -p rea-host fs::
```

The Linux runner requires Python 3 and `wait4`. It compares canonical digests
between versions and refuses divergent results. For MCP it compares admitted text
lengths or exact rejection size/constraint tuples. Unit tests separately compare
admitted text and complete byte/unit accounting against the original owned-buffer
calculation, including all control-byte escapes and UTF-8 split across writes.

## Verification limits

The attempted full `cargo test --workspace --locked` is blocked by an existing
unconstrained `Err` result type in `crates/legacy/rea-runtime/src/mcp.rs:1192`.
Excluding that superseded crate exposes missing checked-in bridge files referenced
by `rea-tools-debug`: `bridge/native/rea_lldb_tracer.py`, `ReaNativeUI.swift`, and
`NativeUIChildren.swift`. These unrelated source omissions are not replaced with
stubs. The optimized crates (`rea-core`, `rea-rust-analysis`, `rea-mcp`) pass 614 tests;
14 host filesystem tests also pass. Application tests report 397 passing and nine
failing tests in both checkouts, with identical failing test names. A broader host
run reports 89 passing, two ignored and one failing process-cleanup test. That
same process-cleanup test also fails on the baseline in this container. The
baseline checks and exact failing test names are recorded in
`docs/benchmarks/verification.txt`. These failures are not reported as a green
workspace test run.

Repository-wide formatting also reports existing changes outside this patch;
formatting verification is restricted to changed Rust files.

## Remaining costs and scope

- Canonicalization still sorts and owns object keys, and nested `RawValue`
  containers are rescanned when their children are visited. Large, deeply nested
  documents can still cost substantially more than flat input. The existing
  1,000-level depth limit and numeric/UTF-16 compatibility remain in force.
- Accepted MCP responses serialize twice: measurement and text production. The
  input `Value` and admitted output string are still owned. This avoids allocating
  an oversized response but does not make accepted transport output zero-copy.
- Session Evidence is intentionally retained for export, and snapshots clone
  reference-counted owners. Long investigations can grow their ledger. Silently
  evicting records would change the retention contract; disk-backed retention or
  an explicit admission budget needs a separate design and workload measurement.
- Stable-file workflows deliberately retain admitted bytes and verify file
  identity. Their repeated reads are correctness checks, not automatically
  redundant I/O.
- The independently built `ghidra-rust-worker` has bounded database caches and
  decompiler arena recycling already. Its engine, multi-process memory and
  real-binary performance were not benchmarked here. Browser, Android, debugger
  and macOS/Windows live integrations also need their own environments and inputs.
