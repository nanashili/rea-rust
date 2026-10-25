#!/usr/bin/env bash
set -uo pipefail

harness_dir="$(cd "$(dirname "$0")" && pwd)"
rust_binary="${REA_RUST_SEMANTIC_BIN:?set REA_RUST_SEMANTIC_BIN to the isolated Rust harness binary}"
ts_dist="${REA_TS_DIST:-/Users/tihan-nico/Developer/rea-rust-ghidra-prism/dist/domain/javascript}"
comparison_failed=0

for mode in import require compiler-dependent; do
  SEM_MODE="$mode" REA_TS_DIST="$ts_dist" node "$harness_dir/ts-dump.mjs" \
    "$harness_dir/manifest.json" "$harness_dir/ts-$mode.jsonl" || comparison_failed=1
  SEM_MODE="$mode" "$rust_binary" \
    "$harness_dir/manifest.json" "$harness_dir/rust-$mode.jsonl" || comparison_failed=1
  node "$harness_dir/compare.mjs" \
    "$harness_dir/ts-$mode.jsonl" \
    "$harness_dir/rust-$mode.jsonl" \
    "$harness_dir/diff-$mode.json" || comparison_failed=1
done

exit "$comparison_failed"
