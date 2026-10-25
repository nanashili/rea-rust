# Benchmarks

- [Local applications — 25 October 2026](local-applications-2026-10-25/README.md):
  native release build against selected artifacts from 11 installed macOS apps
  and Go. Includes 125 samples, CPU, RSS, elapsed time, output checks, failures,
  charts, raw receipts and reproduction scripts.
- [TypeScript/native runtime comparison — 24 October 2026](../../experiments/analysis-efficiency/runtime-comparison/README.md):
  pinned implementations and equivalent request sequences, including differing
  decompiler providers and incomplete native results.
- [Earlier synthetic Rust measurements](results.md) and
  [round two](round2-results.md): historical scanner/provider microbenchmarks.

Each report describes its own inputs, cache conditions, measured revision and
limits. Compare equivalent completed operations; failed analysis is reported
with its cost and error.
