# Local application benchmark

Native REA MCP benchmark on `macOS-27.2-arm64-arm-64bit-Mach-O`. Status: **partial**.
This report measures a fresh REA process with isolated REA/provider-cache directories for every workflow sample. Round 1 is the first-round sample; later rounds are later-round samples with a new process. Only repeated labels such as `#2` within one workflow are retained-session repeats. The OS filesystem cache is uncontrolled, so these results make no cold-OS claim.

## Results

| Workflow | Samples | Passed | Failed | Wall median [min–max] (ms) | wait4 CPU median (ms) | Harness CPU median (ms) | Family CPU median (ms) | Peak family RSS median (MiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `chatgpt-electron-static` | 5 | 0 | 5 | 105514.62 [98070.27–122421.60] | 100120.86 | 75148.41 | 99351.17 | 3824.20 |
| `chrome-native-analysis` | 5 | 5 | 0 | 579.23 [517.29–894.93] | 374.67 | 479.50 | 374.33 | 191.45 |
| `discord-electron-static` | 5 | 5 | 0 | 18023.40 [17278.41–35493.78] | 17678.81 | 13424.24 | 17580.91 | 1510.64 |
| `figma-electron-static` | 5 | 0 | 5 | 83110.71 [81198.88–121236.97] | 80033.30 | 59763.23 | 79754.38 | 2028.31 |
| `figma-framework-deep` | 5 | 5 | 0 | 32610.95 [29679.44–43516.10] | 92494.03 | 22328.87 | 92100.79 | 2431.19 |
| `go-toolchain-binary` | 5 | 5 | 0 | 386.42 [337.10–435.35] | 185.33 | 340.59 | 185.18 | 180.72 |
| `gofmt-deep` | 5 | 5 | 0 | 1562.29 [1281.08–1580.22] | 2763.74 | 1108.58 | 2760.84 | 270.34 |
| `interface-builder-artifact` | 5 | 5 | 0 | 5918.83 [4941.21–7413.49] | 5342.58 | 4478.74 | 5314.61 | 188.23 |
| `kiro-electron-static` | 5 | 0 | 5 | 116004.65 [112719.68–121304.86] | 108474.52 | 83644.81 | 97404.81 | 3019.50 |
| `kiro-node-pty-javascript` | 5 | 5 | 0 | 528.49 [421.59–663.47] | 278.00 | 432.70 | 251.41 | 180.88 |
| `openunity-native-analysis` | 5 | 5 | 0 | 2267.66 [2083.39–3600.12] | 1573.20 | 1752.27 | 1294.75 | 300.25 |
| `postman-electron-static` | 5 | 0 | 5 | 28036.97 [26286.26–36523.11] | 27581.47 | 21162.71 | 27500.80 | 2116.62 |
| `session-evidence-roundtrip` | 5 | 5 | 0 | 1131.91 [1041.91–1182.37] | 768.90 | 880.21 | 626.65 | 217.42 |
| `terminal-static-fast` | 5 | 5 | 0 | 372.23 [340.58–997.56] | 184.73 | 316.26 | 184.36 | 178.61 |
| `unity-managed-library` | 5 | 5 | 0 | 1994.96 [1901.47–3018.08] | 1788.58 | 1617.01 | 1778.48 | 787.64 |
| `xcode-deep-read-only` | 5 | 5 | 0 | 2048.61 [1981.60–2575.08] | 1046.02 | 1686.43 | 876.26 | 269.75 |
| `xcode-static-artifacts` | 5 | 5 | 0 | 29410.12 [27222.38–96143.39] | 26920.94 | 21992.72 | 25241.27 | 768.83 |
| `zed-native-analysis` | 5 | 5 | 0 | 12359.29 [11029.22–47780.41] | 11015.62 | 8738.19 | 10628.36 | 1342.70 |
| `zed-rust-metadata` | 5 | 5 | 0 | 909.33 [858.78–920.23] | 698.47 | 722.49 | 695.83 | 342.12 |

The table includes every attempted workflow, including failed processes, so resource costs are visible even when a workflow did not complete. Use the `successful` metrics in `summary.json` for performance ranking; never rank a failed sample as a successful result.
Run totals: 95 workflow samples (75 successful, 20 failed) and 1050 calls (1030 successful, 20 failed).

Coverage: 95 receipts, 95 unique workflow/round pairs; expected 95. No missing, duplicate, or unknown workflow-round samples.

Call wall-time medians: discovery 98.98 ms; analysis 35.28 ms.
Measured `tools/list` response bytes: median 3245604.00, minimum 3245604.00, maximum 3245604.00.

## Accounting and limits

`wait4` user/system CPU is OS accounting and may include waited descendants. Family CPU and RSS are recursive 5 ms `psutil` observations, lower bounds that can miss short-lived children. A zero sampled value is reported as unobserved. Host background load was not isolated. MCP catalog response bytes are measured per discovery call and included in discovery time; they are not a fixed estimate.

This is a native-only installed-application benchmark. Targets are selected executables and artifacts, not a recursive analysis of each whole application bundle. It contains no fresh TypeScript comparison and does not claim unmeasured CPU, I/O, energy, or token costs. Raw response bodies and application code stay in the local runner work directory.

## Reproduce

Use the plan and runner documented in [`scripts/benchmarks/README.md`](../../../../scripts/benchmarks/README.md), then summarize with `python3 scripts/benchmarks/summarize.py --raw /private/tmp/rea-benchmark-fixes/docs/benchmarks/failure-verification-2026-10-25-v2/main-raw.json --before <before.json> --after <after.json> --output-dir /private/tmp/rea-benchmark-fixes/docs/benchmarks/failure-verification-2026-10-25-v2/summary-main`.

Run UTC: 2026-10-25T20:54:13.072991+00:00 to 2026-10-25T21:34:41.514940+00:00. The aggregate plan hash is a canonical JSON digest; provenance manifests record the plan file-byte hash. Provenance warnings: none.

Generated files: [`summary.json`](summary.json), [`workflows.csv`](workflows.csv), and [`calls.csv`](calls.csv).
