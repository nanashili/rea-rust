# Large JavaScript analysis: evidence and design

This note records the retained evidence for the large-file investigation. It
separates completed observations from implementation proposals. The Figma
fixture is 3,632,793 bytes; Postman's `AgentWorker.js` is 10,794,503 bytes.
Direct-worker runs use a 30-second deadline, a 1 GiB Rust global-allocator
live-heap policy, and bounded node, unknown, output, and process-family limits.
The allocator policy is separate from sampled RSS and process-family memory;
it is not a ceiling on either. Build34 now has qualified bounded public MCP
and parity receipts, while full-file semantic coverage remains partial.

## Current evidence

Build34 (`a83a333`) is the latest frozen release build. Its direct-worker smoke
completed both bounded final-partial results: Figma in 9.994 s and Postman in
26.696 s. In the paired smoke, all three Figma runs were final partial at
9.02, 9.04, and 9.32 s; all three Postman runs were final partial at 27.42,
29.03, and 27.93 s. The baseline comparison failed 13 cases. These are
bounded smoke measurements, not full-file completion or speedup evidence.

The retained Build34 MCP summary reports both public workflows as
`semantic_partial_completed`, with evidence IDs and no worker-timeout marker;
Figma includes three known integrity warnings under its record-and-continue
policy. Five canonical hashes for both applications equal the Build29
diagnostic hashes. Full-IR parity covers 17 fixtures in three modes (51 cases)
with no differences, and the 17-case worker parity also has no differences.
These receipts qualify bounded behavior and equivalence, not complete semantic
coverage.

A separate Build33 90-second diagnostic completed a partial Postman result in
29.583 s, with 27.730937 s sampled family CPU and 1,355,022,336 bytes sampled
peak RSS.
Its profile at 18–24 seconds was concentrated in
`data_effects::configuration_details` → `builtin_data_effect_method` →
`module_origin_for_expression` → provenance. This is diagnostic evidence, not a
production pass. The earlier 17-fixture comparison set is qualified, but its
large Postman run exited before completion. Chronology, lost raw receipts, and
historical limitations are linked from
[`historical-diagnostics.md`](large-file-worker-2026-10-26/historical-diagnostics.md).

## What is consuming the budget

The observed failures are retention and repeated work problems. The worker
keeps a typed semantic IR and the final graph, and individual records can be
large. Earlier diagnostics reached fingerprint collection and then graph
serialization; changing vector capacity alone did not remove those owners.
Repeated object evaluation, deferred work, and duplicate intermediate data can
exhaust the heap or output budget before useful final evidence is delivered.

The practical order is therefore:

1. Admit only nodes and properties that can affect the requested result.
2. Reuse immutable evidence, callable, fingerprint, and dependency facts.
3. Defer semantic work until a root reaches it, with explicit unknown coverage.
4. Encode the retained result within the transport limit, with a bounded
   decoded-growth policy.

Changing map or vector implementations without reducing those owners does not
address the failure mode.

## Implemented changes and limits

The ownership fixes release discarded Oxc semantic state after static facts are
copied, use a temporary allocator for diagnostic retries, and retain REA-owned
facts with the source AST. Oxc documents its arena allocation model and
`used_bytes` behavior in the [`Allocator` API](https://docs.rs/oxc_allocator/0.133.0/oxc_allocator/struct.Allocator.html#method.used_bytes).

The analysis shares statement-position, dependency, evidence, callable, and
fingerprint work; uses borrowed property selection and provenance; admits
nodes lazily; and projects typed IR records one at a time. The transport codec
keeps the newline-versioned envelope and streams gzip plus base64. Source32
also uses `SmallVec` 1.16.3 for single-child fields, typed syntax predicates,
direct parent indices with a global one-level matcher, and borrowed provenance.
The [`SmallVec` API](https://docs.rs/smallvec/1.16.3/smallvec/struct.SmallVec.html)
documents the inline representation relevant to that change. The typed IR and
final graph still remain resident; the allocator policy is not a materialized
heap guarantee.

Source33 (`60af18d`) short-circuits
`collect_symbolic_read_uncertainty` once its single sticky uncertainty result is
proven, instead of scanning the remaining call inventory. The implementation
is in [`symbolic_reads.rs`](../../crates/application/rea-application/src/javascript/static_analysis/symbolic_reads.rs).
Its mutable state remains local apart from transparent state-lookup caches.
Core and application tests report 744 passed (713 application and 31 core),
zero failed, and one ignored. Build34 is the current runtime evidence; no
separate Source33 speedup claim is made.

Candidate34 (`a83a333e62cd3714cca0b3041b4c134f7cc64a0f`) implements avoiding
repeated configuration discovery, rejecting impossible builtin method names
before provenance work, and extending the sticky-boolean short circuit deeper
into the call path. Tests report 744 passed and one ignored, with the workspace
check passing. Its release build, bounded smoke, public MCP qualification, and
bounded semantic parity are complete; full-file semantic coverage remains
partial.

## Transport implementation and limits

A diagnostic Postman oracle retained 68,791,784 bytes: 49.715 million bytes of
semantic data and 16.071 million bytes of metadata across 105,090 binding
metadata records. One full gzip encoding produced 9,751,191 bytes. The raw
receipt is `build29-large-file-oracle.json`. This explains why lossless
transport encoding is being evaluated, but it is not a runtime result for the
new protocol.

The implemented codec keeps the newline-versioned envelope and uses lossless
gzip plus base64 while applying a native parent decoded-size byte bound. That
bound is a transport policy, not a guarantee about materialized heap use.
The implementation must finish the gzip writer and base64 writer before
emitting padding or a final frame. The relevant primary APIs are flate2's
[`write::GzEncoder`](https://docs.rs/flate2/1.1.10/flate2/write/struct.GzEncoder.html),
the single-member behavior documented for [`bufread::GzDecoder`](https://docs.rs/flate2/1.1.10/flate2/bufread/struct.GzDecoder.html),
flate2's [read-decoder over-read warning](https://docs.rs/flate2/1.1.10/flate2/read/index.html),
and base64's [`EncoderWriter::finish`](https://docs.rs/base64/0.22.1/base64/write/struct.EncoderWriter.html#method.finish).
Malformed-input behavior, decoded-size limits, and any broader coverage claim
remain separate checks; the retained Build34 protocol and bounded parity
receipts are complete.

## Future demand-driven analysis

The longer-term proposal is a demand-driven module or factory index. After the
static checkpoint, retain source offsets, interned names, exports, imports,
`require` sites, top-level effects, and compact reference edges. Analyze a
factory only when a requested root reaches it. Preserve examined and omitted
counts; computed imports, dynamic exports, `eval`, unknown callbacks, spreads,
and unknown property reads must widen conservatively rather than disappear.
Recursive factory groups can use monotone SCC summaries and recompute evicted
derived facts from source-owned data.

This follows the demand-driven interprocedural analysis model
([POPL paper](https://doi.org/10.1145/199448.199461)), Rust's
[query](https://rustc-dev-guide.rust-lang.org/query.html) and
[incremental-query](https://rustc-dev-guide.rust-lang.org/queries/incremental-compilation.html)
designs, Clang's [monotone data-flow worklists](https://clang.llvm.org/docs/DataFlowAnalysisIntro.html),
and LLVM's [compact module summaries](https://llvm.org/docs/doxygen/ModuleSummaryAnalysis_8cpp_source.html).
It remains future work, separate from Candidate34's implemented local
short-circuits.

## Final results

The retained Build34 results are recorded in the
[benchmark report](large-file-worker-2026-10-26/README.md). They establish
bounded MCP and parity behavior with partial semantic coverage. They do not
establish full-file completion, a speedup over TypeScript, or a materialized
heap ceiling.
