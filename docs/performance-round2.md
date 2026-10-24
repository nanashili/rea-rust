# Second CPU and memory pass

This pass compares against the **first optimized version**, not the original
repository revision. The previous fixes remain in place.

Baseline: first-pass commit [`ed9e97d`](https://github.com/nanashili/rea-rust/commit/ed9e97dcd116c124672742c9bdd2e8baece27305).
The original baseline remains `1cccbf665b82bd6228c3a9272b431b259b9e9c06`.
Both executables use exactly the same extended benchmark example.

## Changes

- **ASCII object keys:** canonical JSON reused UTF-8 text for output but also
  allocated a UTF-16 vector for every key. ASCII keys now compare their existing
  bytes directly; Unicode keys retain UTF-16 ordering. Mixed comparisons still
  compare exact UTF-16 units. This removes one allocation per ASCII key without
  changing duplicate-key handling or lone-surrogate behavior.
- **Plist entity validation:** three independent searches for opaque markup
  rescanned the entire remaining input at each entity. A single forward scan now
  finds ampersands and markup openers, skipping comments, CDATA and processing
  instructions while preserving error offsets.
- **Numeric entity decoding:** each `replace_range` shifted the remaining string.
  Decoding now appends to one output buffer. Named replacements keep their
  original ordered semantics, including references exposed by `&amp;`; absent
  replacements no longer allocate a copy. Ordinary text borrows intermediate
  CDATA/markup stages and allocates only the final decoded string.
- **Typed plist dictionaries:** every unique key scanned all preceding typed
  provenance paths to remove a possible replacement. Only duplicate keys can
  invalidate earlier paths, so unique keys now skip that scan. Replacements still
  remove the replaced key's descendants before recording new provenance.

## Method

Same Linux environment and Rust 1.93.1 release settings as the
[first report](performance.md). Seven fresh processes per version, five operations
per process, alternating version order, with no compilation running alongside.
Peak RSS includes input setup; operation time excludes it. Numbers are synthetic
workloads, not whole-application timings.

- `object`: 100,000 short ASCII keys, retained as a regression workload.
- `object-long-keys`: 100,000 ASCII keys with a 120-byte prefix.
- `plist-entities`: 3,000 repetitions of `&#65;&#x1f600;&amp;lt;`, decoding to
  `A😀<`. A larger initial fixture was discarded because the baseline's quadratic
  behavior made repeated runs impractical; it is not included in the recorded
  samples.
- `plist-text`: a 16 MiB ordinary XML string without escapes or nested markup.
- `plist-dates`: 3,000 distinct dictionary keys with typed date values.

All workloads compare full SHA-256 output digests between versions. Plist timings
include hashing the decoded text, or serialized value for the date dictionary.
The digest cost is present in both versions. This workload extension adds output
verification to the plist benchmark; do not treat the old first-pass plist table
as a direct comparison with these workloads.

## Results

| Workload | Before ms/op | After ms/op | Speedup | Before peak MiB | After peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| `object` | 32.647 | 22.619 | 1.44× | 22.41 | 17.92 |
| `object-long-keys` | 86.610 | 35.450 | 2.44× | 75.05 | 40.05 |
| `plist-entities` | 127.705 | 0.516 | 247.49× | 11.50 | 11.50 |
| `plist-text` | 89.927 | 21.203 | 4.24× | 129.36 | 33.42 |
| `plist-dates` | 32.693 | 6.681 | 4.89× | 11.62 | 11.62 |

Raw samples: [round2.csv](benchmarks/round2.csv).
Small-workload RSS has an approximately 11.5 MiB process-launch measurement
floor; unchanged values there do not establish zero allocation savings.

## Verification and limits

`cargo test --locked -p rea-core -p rea-rust-analysis` passes **616 tests**, including
four new regressions for mixed key ordering, entity-decoding semantics, opaque
markup/error offsets, and nested typed-provenance replacement.

Changed Rust files pass `rustfmt --check`. The broader repository failures and
missing bridge sources documented in the first report remain outside this patch;
no claim of a green full workspace build is made.

This is another measured improvement pass, not an exhaustive resolution of all
performance issues. Non-ASCII keys still need UTF-16 ordering storage. CDATA
sections containing markup still use the existing normalization path, and
repeated duplicate dictionary keys still need provenance removal. The retained
Evidence ledger and external analysis engines need separate workloads and
retention designs as described in the first report.

## Reproduce

Check out first-pass commit `ed9e97dcd116c124672742c9bdd2e8baece27305` to obtain the baseline. Copy this pass's `performance.rs` benchmark example into that checkout;
do not copy the optimized library sources. Build each checkout separately:

```sh
cargo build --release --locked -p rea-rust-analysis --example performance
# Save each checkout's target/release/examples/performance executable.
python3 scripts/benchmark-performance.py /tmp/round2-before /tmp/round2-after \
  --workloads object object-long-keys plist-entities plist-text plist-dates \
  --output docs/benchmarks/round2.csv
cargo test --locked -p rea-core -p rea-rust-analysis
```
