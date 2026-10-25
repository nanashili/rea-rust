# Rust library assessment

Reviewed on 2026-10-25 against the Rust benchmark-fix source at REA commit `b067b8431f317efda7c3b3573933b6d92d79ac62`. This is a source and dependency assessment. The eight libraries below have not been compared in REA performance runs, and this assessment adds no runtime dependencies or backend changes.

`indexmap` is the strongest candidate for graph storage, starting with the fact registry described below. String storage deserves a separate experiment at the `JsString` owner. `zlib-rs` is a relatively contained backend experiment for compressed inputs. The remaining choices need a demonstrated workload or ownership change first. These are proposed priorities, not measured speedups.

| User priority | Library | Current REA use | Assessment |
| ---: | --- | --- | --- |
| 1 | [indexmap](https://github.com/indexmap-rs/indexmap) | Versions 1.9.3 and 2.14.2 occur transitively; graph `Obj` uses an ordered vector. | Start with `OrderedFacts`, then test wide objects. Include small-object overhead and copy-on-write detachment. |
| 2 | [compact_str](https://github.com/ParkMyCar/compact_str) | 0.9.1 is already used through Oxc. REA's `JsString` has its own shared UTF-8/UTF-16 storage. | Test inline UTF-8 storage inside that owner. It cannot replace arbitrary JavaScript strings. |
| 3 | [lasso](https://github.com/Kixiron/lasso) | Absent from the runtime lockfile. | Consider a bounded, analysis-scoped pool for repeated valid UTF-8 names after measuring duplication. |
| 4 | [smallvec](https://github.com/servo/rust-smallvec) | 1.16.3 occurs transitively. | Test short UTF-16 buffers or selected short lists after collecting length distributions. Avoid blanket `Vec` replacement. |
| 5 | [flate2 / zlib-rs](https://github.com/rust-lang/flate2-rs) | `flate2` 1.1.10 currently activates `rust_backend` / `miniz_oxide` and runtime detection. `zlib-rs` 0.6.8 is locked but its backend feature is inactive. | Compare decompression on actual supported compressed artifacts, including malformed and oversized streams. |
| 6 | [aho-corasick](https://github.com/BurntSushi/aho-corasick) | 1.1.5 occurs transitively through regex; inspected literal scanners use `memchr::memmem`. | Use where many fixed patterns scan the same bytes. Single-pattern scanners already have a suitable primitive. |
| 7 | [memmap2](https://github.com/RazrFalcon/memmap2-rs) | Absent from the runtime lockfile. | Defer direct mapping of caller files until immutable backing and its lifecycle have a clear owner. |
| 8 | [mimalloc](https://github.com/microsoft/mimalloc) | Absent. REA wraps `System` in its heap-budget allocator. | Benchmark as a delegate beneath the budget allocator after reducing retained data and repeated work. |

Lockfile presence does not mean REA uses a library at a particular boundary. The dependency observations above come from `Cargo.lock` and `cargo tree --locked`; backend selection was checked with `cargo tree --locked -i flate2 -e features`.

## Ordered graph objects: indexmap

A narrower first candidate is [`OrderedFacts`](../../crates/application/rea-application/src/javascript/graph/semantic_graph.rs). It maintains both `Vec<String>` insertion order and `HashMap<String, Json>` lookup storage. A new identifier is cloned into the order vector, and insertion checks the table before inserting into it. `IndexMap<String, Json>` could give both responsibilities one owner and remove the duplicate identifier allocation. Its valid UTF-8 identifiers avoid the arbitrary JavaScript-key issue below. Review `keys()` consumers, insertion order and move-out behavior when prototyping this change; its current API exposes a key slice.

[`Obj`](../../crates/application/rea-application/src/javascript/graph/json.rs) stores `Arc<Vec<(JsString, Json)>>`. Reads and updates search linearly. Updates retain the original key position, removal retains the relative order of other keys, and clones share contents until mutation. Wide, frequently accessed objects could benefit from a hash index. Small structural objects may pay more for the index than they save.

[IndexMap](https://docs.rs/indexmap/2.14.2/indexmap/map/struct.IndexMap.html) combines indexed entries with hashed key lookup. A compatible prototype needs to preserve more than iteration order:

- Use order-preserving removal (`shift_remove`), and retain an existing key's position on replacement.
- Preserve REA's current order-sensitive object equality. `IndexMap`'s own equality compares entries independently of insertion order; deriving the wrapper's equality would change behavior.
- Keep copy-on-write value semantics. Include shared-object mutation and detachment in the comparison rather than measuring only lookups in an unshared map.
- Keep JavaScript array-index ordering during `stringify` and UTF-16 ordering during canonical serialization. Neither is simply the container's insertion order.
- Preserve lone-surrogate property keys. `JsString` hashes UTF-16 units; a borrowed UTF-8 lookup must use a compatible hash and equality representation. Substituting `Borrow<str>` would lose values that have no valid Rust `str` representation.

First collect object widths and operation counts from completed graph tasks. Replay construction, successful and missing lookups, replacement, spread, removal, iteration and shared mutation with those distributions. Compare the existing vector, `IndexMap`, and a vector that adds an index only for wide objects. Include string hashing, allocations, retained bytes and full graph serialization; do not choose a width threshold from a synthetic lookup test alone.

## String storage: compact_str, lasso and smallvec

[`JsString`](../../crates/core/rea-core/src/js_string.rs) owns exact JavaScript text. It currently has a shared handle, an empty allocation-free representation, UTF-8 or UTF-16 source storage, and lazy derived encodings. Cloning an existing value already shares its storage. Independently constructing equal values can still allocate separately. Hashing and equality can materialize UTF-16 units from UTF-8 input.

Before adding a string dependency, test whether those identity operations can consume exact UTF-16 iterators without retaining a second encoding. Both source variants must use the same hashing and comparison rules, including lone surrogates. This targets a producing-boundary cost that an inline UTF-8 container alone would leave in place.

[`CompactString`](https://github.com/ParkMyCar/compact_str/blob/main/compact_str/README.md) stores up to 24 UTF-8 bytes inline on 64-bit systems and otherwise uses heap storage. Its long-string clone copies text. Replacing REA's shared handle outright could increase the size of every graph value and lose cheap clones. A narrower experiment would put `CompactString` in the existing UTF-8 source variant, preserve shared ownership, and retain the UTF-16 branch. Creating an intermediate `String` before conversion can still incur an allocation, so producer conversion paths belong in the measurement.

[`lasso`](https://github.com/Kixiron/lasso#readme) interns Rust strings into keys and can freeze a mutable pool into read-oriented representations. It can reduce repeated independently owned names, but its `str` interface does not represent arbitrary UTF-16 units. Any REA pool should be bounded and owned by one analysis, use a separate path for non-UTF-8 JavaScript text, and resolve keys back to exact source values before Evidence serialization. An interner key is local storage identity, not a stable symbol or Evidence identifier. A process-global pool would retain names across otherwise completed analyses. Measure the duplicate fraction and pool overhead before adding one, including whether parser-owned names are already shared at the producing boundary.

[`SmallVec`](https://github.com/servo/rust-smallvec#readme) holds a chosen number of elements inline and spills larger collections to the heap. A `SmallVec<[u16; N]>` can preserve exact JavaScript units while avoiding a short buffer allocation. Its inline capacity occupies space in every instance, including empty and spilled values, and can enlarge an enclosing enum. Choose `N` from actual lengths and measure the full owner layout. Short path segments are another possible target. Large `Node` values and bulk graph arrays are poor candidates for an unmeasured blanket conversion.

Evaluate these choices independently before combining them. Record the number of distinct strings, duplicate constructions, byte and UTF-16 lengths, conversion frequency, allocations, retained bytes, clone costs and cleanup after each task. Existing lone-surrogate, canonical digest and Evidence round-trip checks must continue to pass.

## Compressed artifacts: flate2 with zlib-rs

The inspected consumers include APK entries, Rust auditable metadata, Flutter/Dart artifacts and network captures. Examples are [`android_package.rs`](../../crates/formats/rea-rust-analysis/src/android_package.rs), [`auditable.rs`](../../crates/formats/rea-rust-analysis/src/auditable.rs) and [`network_capture.rs`](../../crates/application/rea-application/src/web/network_capture.rs).

The upstream [backend documentation](https://github.com/rust-lang/flate2-rs#backends) offers `zlib-rs` as a performance-oriented Rust implementation using some unsafe code. REA currently requests `rust_backend`. An experiment should explicitly select `zlib-rs` with runtime detection and inspect Cargo's unified features to confirm the effective backend.

Compare actual raw-deflate, zlib and gzip consumers separately. Keep expected decoded bytes, checksums, stream completion, trailing-input behavior, output limits, cancellation and error classification under observation. A backend change cannot make an unbounded output allocation safe. Compression throughput is secondary for these read-oriented workflows. Record decoding CPU and peak memory as well as completed artifact-analysis time; upstream throughput numbers do not establish a REA improvement.

## Signature scanning: aho-corasick

The inspected Electron fuse, Go-header and Rust-path scanners search a single literal using `memchr::memmem`. An automaton is most relevant when several fixed signatures repeatedly traverse the same input. The desktop component reader also performs several path-marker checks, but those short paths do not establish a bottleneck in binary scanning.

The upstream [API documentation](https://docs.rs/aho-corasick/1.1.5/aho_corasick/struct.AhoCorasick.html) describes construction cost, automaton memory and different overlap/leftmost semantics. Build and reuse a bounded automaton for a stable pattern set. Preserve original byte offsets, all required overlapping matches, classification priority, case rules and scan coverage. Streaming needs chunk-boundary handling and cancellation checks; choosing non-overlapping matches for convenience could omit evidence.

Before adoption, compare the existing repeated scans against the exact same pattern set and result oracle. Include automaton construction for one-shot tasks and retained automaton memory for reused tasks.

## Binary input ownership: memmap2

Several format parsers already accept borrowed byte slices, for example [`image::read`](../../crates/formats/rea-rust-analysis/src/image.rs). A mapping could supply such a slice without first filling a full `Vec`, if the input owner and downstream consumers also avoid copying. It would not reduce AST or semantic-graph storage.

The upstream [safety contract](https://docs.rs/memmap2/latest/memmap2/struct.MmapOptions.html#safety) marks all file-backed constructors unsafe because later modification of the backing file can cause undefined behavior. A read-only handle or copy-on-write mapping alone does not prove that another process cannot modify or truncate the file. Installed application files are caller-selected inputs and can change independently of REA.

Any implementation needs an owner that establishes backing stability, retains mappings through all borrowers, preserves source identity and handles cancellation and cleanup. An owned immutable snapshot is one option, but creating it has time, disk and I/O costs that must be counted. Compare existing bounded reads against that complete workflow on supported platforms, including file replacement/truncation behavior and peak process-family RSS. Lower Rust allocator counts alone would miss mapped resident pages.

## Allocator choice: mimalloc

[`worker_memory.rs`](../../crates/apps/rea/src/worker_memory.rs) implements REA's global allocator, accounts for live Rust allocation sizes, and terminates a private JavaScript worker if it exceeds the requested heap budget. It currently delegates allocation, reallocation and deallocation to `System`.

[mimalloc](https://github.com/microsoft/mimalloc) is worth an isolated allocator comparison, but it must sit beneath this accounting layer. Replacing the layer would remove an existing resource constraint. Verify failed allocations, growth and shrink accounting, alignment, deallocation, exact budget exits and parent Evidence after termination. Requested live heap bytes and allocator-resident memory are different measurements.

Pin the Rust binding and the bundled native implementation separately when reporting a result. Compare fresh processes and repeated sessions on macOS, Linux and Windows. Include CPU, peak family RSS and retained memory after cleanup; allocator release policy can change the outcome in either direction. The current macOS measurements do not establish cross-platform allocator behavior.

## Measurement status

No REA timing, CPU, allocation, RSS, token or energy improvement is claimed for these eight choices. The [bbtree parent-map replay](bbtree-parent-map-2026-10-25/README.md) is a separate measured experiment: compact parser-ID links used about 45% less retained table allocation than the former hash map on the two captured AST traces. It does not answer the graph-object, string, decompression or allocator questions above.

For each proposed experiment, compare equivalent completed CLI/MCP tasks and retain result provenance, coverage and partial-failure behavior. Separate fresh-process runs from reused-session runs, record wall and CPU time plus peak process-family memory, and state uncontrolled filesystem-cache and host activity. Include schemas, extra calls and retries when measuring agent tokens. Report unmeasured costs explicitly.
