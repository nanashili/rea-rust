# Local application benchmark

Native REA MCP benchmark on `macOS-27.2-arm64-arm-64bit-Mach-O`. Status: **partial**.
This report measures a fresh REA process with isolated REA/provider-cache directories for every workflow sample. Round 1 is the first-round sample; later rounds are later-round samples with a new process. Only repeated labels such as `#2` within one workflow are retained-session repeats. The OS filesystem cache is uncontrolled, so these results make no cold-OS claim.

## Results

| Workflow | Samples | Passed | Failed | Wall median [min–max] (ms) | wait4 CPU median (ms) | Harness CPU median (ms) | Family CPU median (ms) | Peak family RSS median (MiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `chatgpt-electron-static` | 5 | 0 | 5 | 15397.01 [15331.29–15489.05] | 15132.37 | 8038.01 | 15043.21 | 4335.89 |
| `chrome-native-analysis` | 5 | 0 | 5 | 525.24 [521.82–548.69] | 375.68 | 348.30 | 372.03 | 191.59 |
| `discord-electron-static` | 5 | 0 | 5 | 15649.40 [15631.92–15713.89] | 15485.72 | 8247.92 | 15465.78 | 616.19 |
| `figma-electron-static` | 5 | 0 | 5 | 816.38 [786.72–838.69] | 596.47 | 503.74 | 555.10 | 222.36 |
| `figma-framework-deep` | 5 | 0 | 5 | 32823.34 [30906.80–34282.11] | 105924.79 | 17119.89 | 105786.35 | 2441.12 |
| `go-toolchain-binary` | 5 | 5 | 0 | 359.26 [347.51–448.47] | 205.34 | 261.08 | 202.92 | 179.42 |
| `gofmt-deep` | 5 | 0 | 5 | 1511.26 [1487.26–1560.36] | 2686.38 | 876.53 | 2685.17 | 269.48 |
| `interface-builder-artifact` | 5 | 5 | 0 | 5177.85 [5141.53–5558.35] | 4954.82 | 2780.14 | 4937.57 | 220.02 |
| `kiro-electron-static` | 5 | 0 | 5 | 92369.61 [91407.04–92954.18] | 90536.36 | 48127.86 | 84391.17 | 4381.27 |
| `kiro-node-pty-javascript` | 5 | 5 | 0 | 468.97 [457.54–528.11] | 305.45 | 321.01 | 294.74 | 188.38 |
| `openunity-native-analysis` | 5 | 5 | 0 | 2250.83 [2191.97–2261.52] | 1670.81 | 1318.22 | 1493.55 | 303.02 |
| `postman-electron-static` | 5 | 0 | 5 | 28306.49 [28239.34–28332.22] | 28039.79 | 14800.79 | 27961.15 | 3053.23 |
| `session-evidence-roundtrip` | 5 | 5 | 0 | 1061.64 [1047.10–1067.53] | 792.29 | 627.62 | 708.87 | 207.61 |
| `terminal-static-fast` | 5 | 0 | 5 | 321.51 [316.49–347.45] | 168.76 | 240.40 | 167.48 | 178.39 |
| `unity-managed-library` | 5 | 5 | 0 | 2140.57 [2133.82–2164.69] | 1983.00 | 1195.17 | 1971.34 | 799.77 |
| `xcode-deep-read-only` | 5 | 0 | 5 | 1608.39 [1600.57–1654.01] | 974.27 | 934.03 | 878.85 | 260.30 |
| `xcode-static-artifacts` | 5 | 0 | 5 | 9103.42 [9063.97–9699.87] | 8592.53 | 4842.22 | 8423.32 | 274.53 |
| `zed-native-analysis` | 5 | 5 | 0 | 13552.25 [13439.80–14218.88] | 12566.82 | 7179.14 | 12376.61 | 1495.77 |
| `zed-rust-metadata` | 5 | 5 | 0 | 916.88 [899.38–936.95] | 763.91 | 545.74 | 763.16 | 340.92 |

The table includes every attempted workflow, including failed processes, so resource costs are visible even when a workflow did not complete. Use the `successful` metrics in `summary.json` for performance ranking; never rank a failed sample as a successful result.
Run totals: 95 workflow samples (40 successful, 55 failed) and 1050 calls (865 successful, 185 failed).

Coverage: 95 receipts, 95 unique workflow/round pairs; expected 95. No missing, duplicate, or unknown workflow-round samples.

Call wall-time medians: discovery 88.82 ms; analysis 26.41 ms.
Measured `tools/list` response bytes: median 3245006.00, minimum 3245006.00, maximum 3245006.00.

## Accounting and limits

`wait4` user/system CPU is OS accounting and may include waited descendants. Family CPU and RSS are recursive 5 ms `psutil` observations, lower bounds that can miss short-lived children. A zero sampled value is reported as unobserved. Host background load was not isolated. MCP catalog response bytes are measured per discovery call and included in discovery time; they are not a fixed estimate.

This is a native-only installed-application benchmark. Targets are selected executables and artifacts, not a recursive analysis of each whole application bundle. It contains no fresh TypeScript comparison and does not claim unmeasured CPU, I/O, energy, or token costs. Raw response bodies and application code stay in the local runner work directory.

## Reproduce

Use the plan and runner documented in [`scripts/benchmarks/README.md`](../../../scripts/benchmarks/README.md), then summarize with `python3 scripts/benchmarks/summarize.py --raw docs/benchmarks/local-applications-2026-10-25-raw.json --before <before.json> --after <after.json> --output-dir docs/benchmarks/local-applications-2026-10-25`.

Run UTC: 2026-10-25T14:23:56.955064+00:00 to 2026-10-25T14:42:50.285275+00:00. The aggregate plan hash is a canonical JSON digest; provenance manifests record the plan file-byte hash. Provenance warnings: none.

Generated files: [`summary.json`](summary.json), [`workflows.csv`](workflows.csv), and [`calls.csv`](calls.csv).
