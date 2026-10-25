# Local application benchmark

Native REA MCP benchmark on `macOS-27.2-arm64-arm-64bit-Mach-O`. Status: **complete**.
This report measures a fresh REA process with isolated REA/provider-cache directories for every workflow sample. Round 1 is the first-round sample; later rounds are later-round samples with a new process. Only repeated labels such as `#2` within one workflow are retained-session repeats. The OS filesystem cache is uncontrolled, so these results make no cold-OS claim.

## Results

| Workflow | Samples | Passed | Failed | Wall median [min–max] (ms) | wait4 CPU median (ms) | Harness CPU median (ms) | Family CPU median (ms) | Peak family RSS median (MiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `figma-framework-native-functions-supplement` | 5 | 5 | 0 | 38552.41 [36192.05–41366.88] | 118506.63 | 21122.66 | 118383.52 | 2445.86 |
| `openunity-native-functions-supplement` | 5 | 5 | 0 | 6093.69 [5867.84–6399.71] | 14617.22 | 3482.72 | 14523.39 | 494.44 |
| `zed-native-functions-supplement` | 5 | 5 | 0 | 88464.22 [82755.55–95089.95] | 260809.95 | 48170.56 | 260689.26 | 3259.08 |

The table includes every attempted workflow, including failed processes, so resource costs are visible even when a workflow did not complete. Use the `successful` metrics in `summary.json` for performance ranking; never rank a failed sample as a successful result.
Run totals: 15 workflow samples (15 successful, 0 failed) and 630 calls (630 successful, 0 failed).

Coverage: 15 receipts, 15 unique workflow/round pairs; expected 15. No missing, duplicate, or unknown workflow-round samples.

Call wall-time medians: discovery 81.67 ms; analysis 8.75 ms.
Measured `tools/list` response bytes: median 3245006.00, minimum 3245006.00, maximum 3245006.00.

## Accounting and limits

`wait4` user/system CPU is OS accounting and may include waited descendants. Family CPU and RSS are recursive 5 ms `psutil` observations, lower bounds that can miss short-lived children. A zero sampled value is reported as unobserved. Host background load was not isolated. MCP catalog response bytes are measured per discovery call and included in discovery time; they are not a fixed estimate.

This is a native-only installed-application benchmark. Targets are selected executables and artifacts, not a recursive analysis of each whole application bundle. It contains no fresh TypeScript comparison and does not claim unmeasured CPU, I/O, energy, or token costs. Raw response bodies and application code stay in the local runner work directory.

## Reproduce

Use the plan and runner documented in [`scripts/benchmarks/README.md`](../../../../scripts/benchmarks/README.md), then summarize with `python3 scripts/benchmarks/summarize.py --raw docs/benchmarks/local-applications-2026-10-25-native-functions-raw.json --before <before.json> --after <after.json> --output-dir docs/benchmarks/local-applications-2026-10-25/native-functions`.

Run UTC: 2026-10-25T14:49:41.222844+00:00 to 2026-10-25T15:00:46.648156+00:00. The aggregate plan hash is a canonical JSON digest; provenance manifests record the plan file-byte hash. Provenance warnings: none.

Generated files: [`summary.json`](summary.json), [`workflows.csv`](workflows.csv), and [`calls.csv`](calls.csv).
