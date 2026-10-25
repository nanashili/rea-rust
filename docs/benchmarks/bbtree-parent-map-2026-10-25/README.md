# Parent-map comparison: bbtree and REA

The parent-table workload favors compact links over an ordered tree. We did not add bbtree to the REA runtime.

This experiment evaluates [bbtree](https://github.com/XiangpengHao/bbtree) at commit `8adae97a0ed97e5c98fa2790312eb0aec9719846` (package version 0.1.5). Its upstream benchmarks compare ordered maps. Before this change, REA's parent table used `HashMap` for exact identity lookups; it does not need key ordering or concurrent writes.

We replayed the actual Babel-view parent insertions from Postman's `AgentWorker.js` (1,804,243 links) and Figma's `main.js` (887,809 links). Source and trace hashes are in [results.json](results.json). Every map stored 8-byte identity keys and opaque 64-byte values matching REA's `Node` width. The packed variant used the same identity encoded into `u64`, enabling bbtree's automatic inline-key strategy. The compact variant stored each parent value once and used parser node IDs to index child links, with synthesized roles kept separate.

Each fresh process built its table in traversal order, then performed three passes over a deterministic shuffle of the links. Every lookup checked the expected parent identity. All 36 runs passed and released their table allocations. There were three rounds per target and map, reversing map order in the middle round. The experiment used Rust 1.93.1 on macOS arm64. No REA builds or profiler runs overlapped the recorded replay.

Values below are medians. Build and lookup columns are wall milliseconds. Memory is MiB of allocator-requested live bytes attributable to the table; peak includes temporary allocations during growth. A counting allocator was active for all variants and adds instrumentation overhead. These are component measurements, not whole-analysis speedups.

| Target | Table | Build ms | Lookup ms | Retained MiB | Peak requested MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| postman | `std_hash` | 177.45 | 236.77 | 146.00 | 219.00 |
| postman | `fx_hash` | 65.02 | 105.51 | 146.00 | 219.00 |
| postman | `std_btree` | 171.11 | 2287.52 | 235.65 | 235.65 |
| postman | `bbtree` | 74.55 | 1288.11 | 224.74 | 224.74 |
| postman | `bbtree_packed` | 90.37 | 912.75 | 255.11 | 255.11 |
| postman | `compact_parents` | 24.41 | 117.08 | 80.05 | 112.03 |
| figma | `std_hash` | 79.73 | 99.06 | 73.00 | 109.50 |
| figma | `fx_hash` | 30.86 | 43.53 | 73.00 | 109.50 |
| figma | `std_btree` | 80.81 | 922.61 | 115.95 | 115.95 |
| figma | `bbtree` | 35.90 | 535.88 | 110.59 | 110.59 |
| figma | `bbtree_packed` | 41.76 | 414.64 | 125.53 | 125.53 |
| figma | `compact_parents` | 11.58 | 46.45 | 40.00 | 56.00 |

bbtree beat `BTreeMap` here, but its unmodified-key lookup phase took about five times as long as `HashMap` and retained about 54% more memory. Packing keys improved lookup time but increased memory further. `FxHashMap` improved hash-table CPU time without reducing its retained size. Compact links reduced retained table allocation by about 45% on both sources and reduced construction time. The full analyzer must still be measured: AST storage, bindings, fixed-point propagation, projection and serialization are outside this replay.

The full-process elapsed, user/system CPU seconds and peak RSS are also recorded in [results.json](results.json). Those include trace loading, query preparation, table construction, verification and destruction. `/usr/bin/time -l` reports CPU to hundredths of a second on this host. RSS includes the input/query buffers and allocator behavior, so it is different from the table allocation columns. OS caches and unrelated host activity were uncontrolled. Energy, physical disk bytes, hardware counters and agent tokens were not measured.

## Reproduce

The input traces contain little-endian `(child identity, parent identity)` pairs. They omit source text. Generate them from the exact source hashes in the results using the checked-in extractor:

```sh
mkdir -p crates/application/rea-application/examples
cp docs/benchmarks/bbtree-parent-map-2026-10-25/extract-parent-trace.rs crates/application/rea-application/examples/parent_trace.rs
cargo run --locked -p rea-application --example parent_trace -- /path/to/source.js /tmp/parents.trace
rm crates/application/rea-application/examples/parent_trace.rs
```

Build the isolated replay crate, which pins bbtree without changing runtime dependencies:

```sh
cargo build --locked --release --manifest-path docs/benchmarks/bbtree-parent-map-2026-10-25/replay/Cargo.toml
```

Run its `rea-parent-map-bench` executable with `/tmp/parents.trace` and one of `hash`, `fx`, `btree`, `bbtree`, `bbpacked`, or `compact`. Cargo's configured target directory determines the executable location; `cargo metadata --no-deps --format-version 1 --manifest-path docs/benchmarks/bbtree-parent-map-2026-10-25/replay/Cargo.toml` reports it. Repeat in alternating order. On macOS, wrap each invocation in `/usr/bin/time -l` for the full-process metrics.

The replay checks parent identities and storage costs. It does not establish preservation of every AST view field or application-analysis correctness. REA's AST parent regression and application tests validate those separately; real application outcomes belong to the failure-verification report.
