# Local application benchmark runner

`run_mcp.py` runs one owned native REA MCP process per workflow sample. It is
intended for read-only application targets such as app bundles, Mach-O files,
Electron ASARs, and selected provider operations. The target is never launched.

Each call writes a JSON receipt under `--work-dir`. Full responses stay there;
they may contain application code and strings. The work directory stores one
shared `tools/list` response as `catalog.json`; workflow receipts record its
hash and tool names. The final `--output` is a compact aggregate receipt and the
adjacent `.csv` contains one process row per workflow sample. A failed call remains in
the receipt and causes a non-zero exit status after all requested samples have
finished.

Plans contain a target and sequential MCP tool cases. Copy
[`example-plan.json`](example-plan.json), replace its target with a supported
thin Mach-O file, and select operations from the measured binary's MCP catalog.
The example selects the first inventory address to demonstrate references;
that address is not necessarily a representative function.

`$target`, `$bundle`, and `$plist` resolve from the plan target. `$procedure`
and `$address` resolve from the first procedure row returned by a preceding
`list_procedures` call. A case may include `"repeat": N`; use the command-line
`--rounds` for independent process repetitions. The default is five rounds.
A case may set `"label": "analysis-pass"` to make repeated operations
identifiable in receipts and summaries; labels do not combine their per-call
measurements.
A case can capture a value for later calls with
`"capture": {"alias": "result.structuredContent.normalized_result.parent_evidence_id"}`.
Subsequent arguments can use `$alias`. `$export_path` is a unique evidence file
inside the workflow's work directory. Workflow-level `input_files` adds
indirectly selected files to provenance hashing.

The runner starts a fresh process for every workflow and round. The runner
creates isolated `HOME`, XDG directories, `REA_CONFIG`, and
`REA_GHIDRA_RUST_CACHE_DIR` below the work directory. Supply the worker with
`--worker`; it is passed through `REA_GHIDRA_RUST_WORKER`.

```sh
python3 scripts/benchmarks/run_mcp.py \
  --plan scripts/benchmarks/example-plan.json \
  --rea /path/to/rea \
  --worker /path/to/rea-ghidra-rust-worker \
  --work-dir /tmp/rea-local-benchmark \
  --output docs/benchmarks/local-applications.json \
  --rounds 5
```

`wait4` user/system CPU and maximum RSS are retained where the host provides
them. `wait4` is OS resource accounting and may include waited descendants; it
is not presented as root-only CPU. Recursive `psutil` CPU and RSS samples
include observed descendants but are lower bounds: a short-lived child can
exit between samples. The report keeps both accounting methods, including
sampled user/system CPU and peak process-family RSS. A configurable 120-second
per-call timeout and 4 GiB sampled family-RSS guard apply by default. Root
shutdown has a separate 15-second deadline.

Use Python 3.11+ and `psutil` (the recorded run used Python 3.13.7 and
`psutil` 7.2.2). The recorded measurement host was macOS; this is not a
Windows profiler validation. Workflow order reverses on even rounds to reduce
fixed-order effects. Filesystem caches and background host activity are
uncontrolled. A sampled RSS guard can overshoot between observations and is
not a kernel memory ceiling.

Capture selected input and executable hashes before and after the run:

```sh
python3 scripts/benchmarks/capture_host.py \
  --plan plan.json --rea /path/to/rea --worker /path/to/rea-ghidra-rust-worker \
  --output before.json
# Run run_mcp.py with the same plan and executables, using a new work directory.
python3 scripts/benchmarks/capture_host.py \
  --plan plan.json --rea /path/to/rea --worker /path/to/rea-ghidra-rust-worker \
  --output after.json
python3 scripts/benchmarks/summarize.py \
  --raw results.json --before before.json --after after.json \
  --output-dir docs/benchmarks/my-run
```

Capture the after manifest even when the runner returns 1 for measured tool
failures. Inspect cleanup fields and sample completeness before interpreting
the report. `capture_host.py` hashes selected files, bundle metadata and the
canonical executable; it does not hash every file in an application bundle.

`audit_results.py --aggregate results.json --work-dir /tmp/my-run --output audit.json`
extracts bounded result counts without publishing source or decompiled text.
`summarize.py` reports time, CPU, RSS, discovery bytes, OS resource counters,
and instrumentation CPU separately. CPU samples are lower bounds, RSS sums
can count shared pages more than once, and harness overhead is not subtracted
from timings. No model token, energy, physical disk-byte, or OS-cold-cache
measurement is inferred from these metrics.

For multiple independent result series, pass `--raw` once per series to
`finalize_coverage.py`; its coverage output keeps each series' source path and
workflow-round completeness separately before combining call rows. Run
`summarize.py` once per aggregate because it produces one report directory per
input. `--coverage` points to an existing coverage map containing the selected
scope and input rationale; the finalizer updates it from the receipts.
Coverage status can therefore be partial when a series is missing receipts or
contains failures. Native candidate qualification is deliberately stricter
than operation coverage: adjacent inventory starts and unwind function-start
records are retained as observed intervals, but do not establish an
independent function extent. Such candidates are reported as degraded rather
than treated as qualified measurements.
