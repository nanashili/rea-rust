# Failure verification — 2026-10-25

This report compares the original local benchmark receipts with a fresh run of the Rust/C migration. It covers the same plans, five rounds, target paths, and catalogs. Caller inputs match except for the recorded Go function selection described below. The raw receipts and machine-readable comparison are kept beside this file.

The runtime was built from source `f2318c6`; binary hashes are in the [build manifest](build.json). The comparison code is in [`compare_failures.py`](../../../scripts/benchmarks/compare_failures.py). The comparison preserves protocol success, provider-reported semantic status, and matched performance as separate facts. The original suite's three successful native-function workflows were not repeated here.

The changes fix universal Mach-O slice loading, instruction and byte-search support, Evidence validation, large bundle scans, native inventory, and PE version parsing. They also reduce JavaScript data copies, accept the verified Figma ASAR signing placeholder, and retain process ownership through cleanup. Full Electron analysis still exceeds the limits below.

## Results

| Series | Receipts | Tool calls | Baseline protocol success | Current protocol success | Task inputs | PE validation |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| Main | 95 / 95 | 1,050 | 40 | 55 | 18 workflows equivalent; `gofmt-deep` excluded | — |
| Inventory | 10 / 10 | 55 | 0 | 10 | Equivalent | — |
| PE resources | 5 / 5 | 15 | 5 | 5 | Equivalent | 5 / 5 matches |

A protocol-success receipt completed every recorded call. It does not prove semantic completeness. Across all three series, 45 baseline receipts and 70 current receipts were protocol-successful. Failed calls fell from 200 to 70 out of 1,120 calls. The main run has 55 protocol-success receipts and 40 receipts with some failed calls; its runner exited with status 1. Inventory and PE runners exited with status 0. All 110 planned receipts were produced.

## Main workflow measurements

Values are after-run median with minimum–maximum across five rounds. Wall and CPU are milliseconds; RSS is MiB. Measurements are shown for every workflow, including workflows with failed calls, but performance comparisons below use only paired successful workflows with equivalent task inputs.

Elapsed time includes process startup, discovery, calls, and shutdown. Sampled family CPU is a lower bound over observed processes; it can miss short-lived children and their final CPU use. Peak RSS is the largest observed simultaneous sum across those processes. Each sample used a fresh process and isolated provider cache; the OS filesystem cache was uncontrolled.

| Workflow | Current status | Wall | Sampled family CPU | Peak RSS |
| --- | --- | ---: | ---: | ---: |
| `chatgpt-electron-static` | failed calls | 30,930.8 [19,218.0–31,737.8] | 30,581.2 [18,814.1–30,900.8] | 4,099.8 [4,097.0–4,132.8] |
| `chrome-native-analysis` | protocol success | 506.7 [491.8–548.0] | 353.6 [344.6–370.1] | 191.3 [181.0–196.4] |
| `discord-electron-static` | failed calls | 15,592.8 [15,589.4–15,683.7] | 15,436.1 [15,347.7–15,438.8] | 590.6 [587.1–598.2] |
| `figma-electron-static` | failed calls | 16,720.4 [16,687.1–16,803.1] | 16,418.9 [16,390.5–16,469.9] | 411.9 [402.0–414.7] |
| `figma-framework-deep` | failed calls | 30,770.0 [30,366.4–32,323.0] | 102,582.2 [98,125.5–105,775.0] | 2,426.0 [2,420.1–2,433.8] |
| `go-toolchain-binary` | protocol success | 323.5 [309.0–335.2] | 173.5 [169.1–182.0] | 173.1 [168.0–178.8] |
| `gofmt-deep` | failed calls | 1,162.6 [1,158.3–1,444.7] | 2,346.8 [2,337.2–2,851.1] | 268.6 [267.9–269.7] |
| `interface-builder-artifact` | protocol success | 4,969.1 [4,476.0–5,783.7] | 4,658.0 [4,285.6–4,817.5] | 193.5 [182.0–196.7] |
| `kiro-electron-static` | failed calls | 89,339.6 [87,883.5–90,568.9] | 79,234.3 [78,076.9–80,911.4] | 4,271.7 [4,149.9–4,329.6] |
| `kiro-node-pty-javascript` | protocol success | 422.4 [407.3–438.3] | 239.0 [230.3–246.0] | 182.2 [180.2–190.4] |
| `openunity-native-analysis` | protocol success | 1,957.9 [1,913.0–2,005.1] | 1,227.5 [1,198.4–1,256.7] | 301.6 [273.6–305.5] |
| `postman-electron-static` | failed calls | 25,587.0 [25,539.4–25,796.0] | 25,284.7 [25,242.5–25,305.3] | 2,359.4 [2,351.7–2,376.0] |
| `session-evidence-roundtrip` | protocol success | 963.5 [939.0–1,054.7] | 582.7 [579.9–601.6] | 206.1 [202.7–216.4] |
| `terminal-static-fast` | protocol success | 317.1 [306.0–351.5] | 174.3 [164.5–181.9] | 175.8 [168.8–177.0] |
| `unity-managed-library` | protocol success | 1,849.1 [1,817.8–1,968.4] | 1,694.4 [1,667.1–1,718.0] | 816.5 [786.0–817.3] |
| `xcode-deep-read-only` | failed calls | 1,572.3 [1,537.4–1,589.8] | 780.1 [773.2–794.5] | 269.8 [265.6–271.6] |
| `xcode-static-artifacts` | protocol success | 26,944.9 [25,411.2–28,354.5] | 24,481.3 [22,953.5–24,841.4] | 755.7 [754.7–778.5] |
| `zed-native-analysis` | protocol success | 10,693.6 [10,659.6–10,948.1] | 9,996.4 [9,958.4–10,142.3] | 1,513.6 [1,496.3–1,525.7] |
| `zed-rust-metadata` | protocol success | 793.8 [785.0–805.7] | 651.7 [647.8–660.8] | 333.9 [333.7–342.7] |

The comparison records the exact per-series metrics in [`comparison.json`](comparison.json). The table above is a compact view of current receipts; the script’s named metric fields should be used for automated analysis.

## Supplemental workflow measurements

The same units and sampling limits apply. All five rounds passed for each workflow.

| Workflow | Wall | Sampled family CPU | Peak RSS |
| --- | ---: | ---: | ---: |
| `gofmt-objdump-headers` | 360.9 [354.9–527.7] | 192.1 [186.4–264.7] | 179.6 [177.9–186.6] |
| `openunity-native-inventory` | 4,493.1 [4,406.9–4,981.7] | 12,339.0 [12,030.8–14,480.2] | 435.4 [430.3–443.7] |
| `unity-pe-resources` | 271.2 [244.9–1,237.4] | 127.7 [117.8–130.1] | 177.1 [167.0–178.7] |

## Matched successful performance

These are the eight main workflows where baseline and current rounds both completed successfully and actual task inputs were equivalent. Export/import paths are treated as run-scoped only when both receipts prove the plan template uses `$export_path`; other argument changes remain mismatches.

| Workflow | Wall baseline → current | Family CPU baseline → current | RSS baseline → current |
| --- | ---: | ---: | ---: |
| `go-toolchain-binary` | 359.3 → 323.5 ms | 202.9 → 173.5 ms | 179.4 → 173.1 MiB |
| `interface-builder-artifact` | 5,177.8 → 4,969.1 ms | 4,937.6 → 4,658.0 ms | 220.0 → 193.5 MiB |
| `kiro-node-pty-javascript` | 469.0 → 422.4 ms | 294.7 → 239.0 ms | 188.4 → 182.2 MiB |
| `openunity-native-analysis` | 2,250.8 → 1,957.9 ms | 1,493.5 → 1,227.5 ms | 303.0 → 301.6 MiB |
| `session-evidence-roundtrip` | 1,061.6 → 963.5 ms | 708.9 → 582.7 ms | 207.6 → 206.1 MiB |
| `unity-managed-library` | 2,140.6 → 1,849.1 ms | 1,971.3 → 1,694.4 ms | 799.8 → 816.5 MiB |
| `zed-native-analysis` | 13,552.2 → 10,693.6 ms | 12,376.6 → 9,996.4 ms | 1,495.8 → 1,513.6 MiB |
| `zed-rust-metadata` | 916.9 → 793.8 ms | 763.2 → 651.7 ms | 340.9 → 333.9 MiB |

These figures are descriptive medians, not controlled performance claims. OS cache state was uncontrolled, and no agent-token measurements were collected.

## Remaining failures

The current main run has 70 failed calls:

- 15 `provider_timeout` failures from `analyze_javascript_application` on the large JavaScript application workflows.
- 10 harness `MemoryError: process-family RSS limit exceeded` failures from the same class of large JavaScript application workflows.
- 45 `unsupported_provider` failures: `procedure_info` (15), `inspect_native_load_image` (10), `resolve_native_call_targets` (5), `resolve_containing_procedure` (5), `trace_feature` (5; nested `resolve_containing_procedure`), and `get_navigation_context` (5; nested `current_address`).

These are observed provider or harness limitations in the recorded receipts. They do not establish that every target or provider context lacks the operation.

The baseline main series contained 185 failed calls, including 115 unsupported-provider failures, 10 provider timeouts, 10 RSS-limit failures, 30 evidence-integrity mismatches, 10 resource-limit failures, 5 artifact-operation failures, and 5 unreadable-output failures. Its inventory series added 15 failed calls. Current receipts contain no evidence-integrity, resource-limit, artifact-operation, or unreadable-output categories.

## Cleanup, provenance, and PE validation

The baseline recorded nine `process.termination_error` cleanup errors (`EPERM`). That field is null in all 110 current receipts, and every `reader_threads_alive` and `remaining_observed_descendants` array is empty. No cleanup residue was observed in this run. These observations do not prove cleanup behavior under every failure or cancellation path.

The independent PE validator ran on all five current rounds. `FileVersion` and `ProductVersion` matched the expected `0.0.0.0` values in all five rounds. The target resource payload was 644 bytes with SHA-256 `e40cab087151f2e6df68e8ee6915bc267354d4e9d067ce6aba4e8cce0eebeb3b`. The validator remains limited to static PE resource inventory and retained payload bytes; it does not parse or execute manifests, decode icons, or observe shell loading.

Selected application-file hashes remained stable between baseline and current runs, and between current before/after manifests. The harness and runtime source changed. All three plans and catalogs matched exactly; each catalog advertised 209 tools. The [before](main-host-before.json) and [after](main-host-after.json) manifests record host state and input hashes; equivalent manifests accompany the supplemental series.

The main structural comparison found one real task-input difference: `gofmt-deep` selected a different function address. Baseline selected the Go `_go:buildid` marker at `0x100001000`; current selected `_internal/abi.BoundsDecode` at `0x100001070`. That workflow is excluded from matched performance. The remaining 18 equivalent workflows retain their literal caller arguments, with only proven run-scoped evidence paths differing.

## Reproduction files

- [Baseline main receipts](../local-applications-2026-10-25-raw.json) · [plan](../local-applications-2026-10-25-plan.json)
- [Baseline inventory receipts](../local-applications-2026-10-25-inventory-raw.json) · [plan](../local-applications-2026-10-25-inventory-plan.json)
- [Baseline PE receipts](../local-applications-2026-10-25-pe-resources-raw.json) · [plan](../local-applications-2026-10-25-pe-resources-plan.json)
- [Current main receipts](main-raw.json) · [current inventory receipts](inventory-raw.json) · [current PE receipts](pe-resources-raw.json)
- [Independent PE validation](pe-version-validation.json)
- [Three-series comparison](comparison.json)
- [Execution manifest](execution.json)
