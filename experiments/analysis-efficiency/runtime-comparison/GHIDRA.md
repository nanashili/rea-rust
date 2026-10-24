# Ghidra decompilation: Java and Rust

This compares getting C-like code back from the same compiled functions through REA. It uses the original TypeScript REA with Java Ghidra and the frozen native REA with Rust Ghidra. The target programs were read, never run.

**On the small C program, Rust returned the first code about 24 times sooner and used about 79% less memory. On the larger Go program, Rust failed; Java returned the code.**

Lower times and memory figures are better. One second is 1,000 milliseconds (ms).

| What you wait for, on the same small C program       | TypeScript + Java Ghidra | Native + Rust Ghidra |
| ---------------------------------------------------- | -----------------------: | -------------------: |
| Start REA and get the first function's code          |             9.43 seconds |         0.39 seconds |
| Start REA and get all three selected functions       |             9.47 seconds |         0.43 seconds |
| Request the same function again while REA stays open |                  10.3 ms |               1.2 ms |
| Peak memory over the complete session                |                1,022 MiB |              214 MiB |

These are middle results from seven sessions per version. The repeat row uses 56 calls per version. MiB is a memory unit close to a megabyte. Most of the first-answer difference happened during startup and analysis preparation: once ready, the first decompilation request itself took about **16 ms in Java and 15 ms in Rust**.

| Larger real program: Go formatter     | TypeScript + Java Ghidra         | Native + Rust Ghidra |
| ------------------------------------- | -------------------------------- | -------------------- |
| Selected functions returned           | 3 of 3                           | 0 of 3 — failed      |
| Start REA and get the three functions | 40.37 seconds, one final attempt | No completed result  |

The Go result is one final attempt per engine, following an earlier qualification attempt with the same success/failure outcome. It is a coverage finding, not a seven-run timing comparison.

## Did the code look the same?

Both engines returned all three selected C functions. The output preserved the checked calls, constants, branch and global-value addition. These checks cover selected facts from the source; they do not prove that every part of the code is correct.

Java Ghidra produced more readable information in this example. For the leaf function, it showed `"REA_GHIDRA_LEAF_VALUE"` and the global's name. Rust Ghidra showed memory addresses in their place. A faster result can still take more work to understand.

Java Ghidra's output included:

```c
_puts("REA_GHIDRA_LEAF_VALUE");
return param_1 + _rea_ghidra_inventory_global;
```

Rust Ghidra's output for the same function included:

```c
_puts(0x100003c1a);
return param_1 + iRam0000000100008000;
```

The Go formatter exposed a larger limitation: Rust Ghidra failed before returning any of the three requested functions. Java Ghidra returned all three. The Rust error was `Name the import stub at 0x10011d9f2: the name _open is in use`. Its failure time is not a decompilation speed result.

## What should I take from this?

The successful C comparison measures one small program. The larger Go program failed in the Rust engine. These results support a speed comparison for the selected C task, with the readability differences above; they do not establish that Rust Ghidra can replace Java Ghidra for every target.

These are different engine versions: Java Ghidra **12.1.4** on OpenJDK **25.0.2**, and **ghidra-decompiler 2.1.0**, whose own source describes it as a Rust port of Ghidra **12.2**. The Rust engine embeds its language definitions and does not use the installed Java Ghidra. Runtime, engine, analysis coverage and presentation all differ, so this is a comparison of the two REA workflows, not a measurement of language speed alone.

<details>
<summary>Exact measurements, checks, software identities and reproduction</summary>

The seven C pairs ran from **2026-10-24T10:08:52.664664Z to 10:10:06.830160Z**. The final Go pair ran from **10:10:18.973349Z to 10:11:01.222026Z**. All 14 C invocations succeeded; the final Go pair had one success and one incomplete invocation. Each complete C session returned three selected functions plus eight repeat responses, giving 21 selected and 56 repeated responses per engine across the seven sessions.

The C table below shows median (minimum–maximum), in milliseconds. Phase medians are computed independently and should not be subtracted to infer an unmeasured phase.

| C workflow phase                                  |         TypeScript + Java |       Native + Rust |
| ------------------------------------------------- | ------------------------: | ------------------: |
| Startup through full MCP catalog                  |    1146.6 (1024.6–1245.9) | 198.3 (181.7–328.8) |
| Startup through analysis ready and procedure list |   9413.3 (8459.8–10368.8) | 376.9 (355.8–564.8) |
| Startup through first pseudocode response         |   9430.5 (8474.9–10388.5) | 392.2 (371.1–582.1) |
| Startup through three selected functions          |   9465.4 (8490.5–10411.7) | 425.2 (391.1–616.4) |
| First decompilation request, once ready           |       16.33 (14.58–21.50) | 15.37 (10.76–17.51) |
| Complete session, including repeats and shutdown  |   9975.3 (8963.2–11015.0) | 489.0 (453.9–671.2) |
| CPU over complete session, OS-attributed counters | 14975.3 (14176.8–15922.2) | 280.1 (266.9–333.7) |

| C repeated requests and memory                  |      TypeScript + Java |       Native + Rust |
| ----------------------------------------------- | ---------------------: | ------------------: |
| 56 repeats: pooled median and call range, ms    |     10.31 (4.36–22.77) |   1.16 (0.90–11.46) |
| Middle per-session repeat median, ms            |                   8.09 |                1.12 |
| Sampled family peak memory: median (range), MiB | 1021.5 (1006.1–1032.3) | 213.5 (209.9–221.0) |
| Maximum observed processes in the family        |                      4 |                   2 |
| Largest observed sampling gap, ms               |                  109.0 |                91.1 |

The final Go Java session took 40,303.5 ms to first pseudocode, 40,366.9 ms through three functions and 41,537.5 ms through shutdown. Its CPU counter was 72,503.0 ms, sampled family peak memory 1528.5 MiB, and eight repeated requests had a pooled median of 50.19 ms (49.00–57.60). Up to 12 processes were observed; the largest sampling gap was 93.0 ms. Native returned the same import-name collision for all selected and repeated requests. The failed invocation ended after 498.1 ms, with 351.1 ms CPU and 215.6 MiB sampled family peak memory. Those native numbers characterize a failure and are excluded from successful timing ratios. Its largest sampling gap was 44.5 ms and at most two processes were observed.

Post-timing transport estimates for complete C sessions were 703 input / 1,022,615 output heuristic tokens for TypeScript and 705 / 1,057,522 for native (medians). Output includes the full catalogs: 989,654 and 991,815 respectively. This establishes no token saving. Java's successful Go session estimated 689 input / 1,638,046 output; the incomplete native Go exchange was not token-estimated. Actual model usage remains unmeasured.

## Work performed in each run

Each independent invocation starts the frozen public REA MCP server, initializes MCP, retrieves the full tool catalog, opens the target with an explicit provider, and lists procedures to wait for analysis readiness. It then decompiles the same three symbol addresses in both versions, requests the first function another eight times, closes the binary, and shuts down the server through stdin EOF.

The first selected C function is `rea_ghidra_inventory_branch`; the other two are `rea_ghidra_inventory_entry` and `rea_ghidra_inventory_leaf`. Go selections are `main.gofmtMain`, `main.main` and `main.processFile`. Addresses come from the host symbol tools, independently of either provider. The fixture manifest records them.

The C fixture is compiled from the frozen repository's `tests/conformance/ghidra/inventory.c` with `cc -O0 -g -fno-inline`. It is a 51,568-byte arm64 Mach-O with debug information. The Go target is the installed Go 1.26.5 `gofmt`, copied byte-for-byte: 2,952,114 bytes, arm64 Mach-O. Source copies and tool output supply the limited source facts checked by the harness.

The C oracle requires the selected calls, entry constants 35 and 100, the branch's negative path and condition, and the leaf's value-plus-global return. The raw global address is accepted when it matches the independent symbol oracle. Go checks record observed calls and unverified source calls separately; compiler inlining and provider naming prevent a general source-equivalence claim. Repeated output must match the first output within its own session. Pseudocode is never required to match between engines.

## Conditions and limits

All runs use the same Apple M1 Pro, 32 GiB machine on macOS 27.2, on 24 October 2026. No competing builds were detected by the harness. C samples alternate TypeScript/native and native/TypeScript order. Seven independent sessions produce 56 repeated calls per engine. The repeated calls are dependent observations within those sessions.

Every invocation starts a new server and analysis session. Java uses a private ephemeral headless project; native uses a new worker cache directory. The operating system's filesystem cache is warm and is not flushed. Java class/script compilation caches are not forcibly flushed. This does not measure the first run after installation or a reboot. Native decompilation concurrency is explicitly one thread. `REA_CONFIG` points to an absent per-run file, with explicit provider environment settings, so ambient user configuration is not the intended input.

“First code” includes REA startup, full catalog retrieval, provider startup, analysis readiness, procedure listing and the first decompilation. “Three functions” ends after the third response. Individual request timings include MCP transport and response parsing. Repeats reuse the same live session and retained provider work; they are not independent engine-only computations. Whole-session wall time includes all repeats, close and shutdown.

Analysis readiness includes the work chosen by each provider. It does not equalize all analysis passes or procedure inventories. The comparison checks the same three requested functions; it does not establish equal analysis coverage across the whole binary.

CPU is root-server user plus system time from `wait4`, including descendant usage only as attributed by the operating system when children are waited. It is not an independently exact family CPU total. Memory is the sum of concurrent resident memory across the server and recursively observed children, sampled about every 5 ms. It can miss spikes, and shared pages can be counted in multiple processes. Python benchmark-client CPU and memory are excluded. The exact rows record sampling gaps, process counts and root resource counters.

No AI model ran these workflows. Transport text estimates, if present in the receipt, use `tokenx` after timing and are not actual model tokens or bills. Full catalogs are included; real clients may select or cache schemas differently. Linux, Windows, other architectures, stripped targets and other decompilers were not tested.

## Inputs and retained evidence

The runtimes are the same frozen TypeScript and native snapshots as the [metadata comparison](README.md). The new worker is separately frozen and built with `cargo +1.93.1 build --locked --release`. Only the benchmark harness and documentation changed for this addition; the provider was not patched to make the failing Go case pass.

The [raw measurements](results/2026-10-24/ghidra/raw-results.json), [decompiled text and per-run checks](results/2026-10-24/ghidra/invocations.json), [fixture manifest](results/2026-10-24/ghidra/fixtures-manifest.json), [engine identity](results/2026-10-24/ghidra/engine-identity.json) and [provenance](results/2026-10-24/ghidra/provenance.json) preserve the final results. Full MCP transcripts, including complete catalogs and procedure inventories, stay under `.cache/ghidra-decompile-20261024/`; their paths, sizes and SHA-256 digests are recorded in the archive. No target or provider binary is committed.

The final C binary SHA-256 is `cf90f7768723a8dcb992ab86d65d56018b9910104fdf6b31ff96373030e617b4`; Go is `fb5bc1241a2e1a218afb069d7ee5e4269c3fe918a38fc03190fbc9cbb2bb69b1`. The frozen REA binary is `50afe0ca0ec39120c45da65ff1bd47bb5e1dec6199d3d09857e19ad1a12bb0bf`, and the worker is `cf63a0d0c98a814a90d5429c0e29b7c729ad1e5eda678b6c1d3f77f0a1c477c7`. The engine's Cargo checksum and source/embedded-asset hashes are in the engine and preparation receipts. The Java installation manifest applies only to the Java lane.

The early `qualification-1` directory is exploratory and excluded from the final measurements. Its small C binary was rebuilt during oracle preparation and is not the final input. The final C receipt pins the replacement binary and manifest; both measured lanes use that exact final file. The Go binary did not change. Original metadata receipts and their pinned harness files remain unchanged.

## Reproduce

These reports are published in the native repository. The measured scripts
retain their original hashes and expect the original TypeScript checkout as the
working directory, with the native repository at `native/`. Before using the
commands below, copy this benchmark directory to
`experiments/analysis-efficiency/runtime-comparison/` in that TypeScript checkout.
The TypeScript baseline is `833136507dd79d959340b09862a53af344e4f1b3` from
[morluto/rea](https://github.com/morluto/rea). A native-only clone is insufficient.
The Go paths below refer to the measured machine's installed Go 1.26.5 toolchain.
Exact replay also requires the frozen local snapshots identified by the receipts;
the source commits alone do not include the measured uncommitted native changes.

From the repository root, with the original frozen runtime preparation available and the pinned toolchains and providers installed:

```sh
python3 experiments/analysis-efficiency/runtime-comparison/prepare_decompile.py --help
python3 experiments/analysis-efficiency/runtime-comparison/decompile_fixtures.py --help
python3 experiments/analysis-efficiency/runtime-comparison/run_decompile.py --help
python3 experiments/analysis-efficiency/runtime-comparison/archive_decompile.py --help
```

Use a new directory for a reproduction:

```sh
DECOMPILE_PREPARED="$PWD/.cache/ghidra-decompile-reproduction"
RUNTIME_PREPARED="$PWD/.cache/runtime-benchmark-20261024-v2"
BENCH_NODE="$PWD/.cache/toolchains/node-v24.18.0-darwin-arm64/bin/node"

python3 experiments/analysis-efficiency/runtime-comparison/prepare_decompile.py \
  --prepared "$RUNTIME_PREPARED" --output "$DECOMPILE_PREPARED" \
  --ghidra-install-dir /Users/tihan-nico/Developer/Tools/ghidra_12.1.4_PUBLIC --build
python3 experiments/analysis-efficiency/runtime-comparison/decompile_fixtures.py \
  "$DECOMPILE_PREPARED/fixtures"
python3 experiments/analysis-efficiency/runtime-comparison/run_decompile.py \
  --prepared "$DECOMPILE_PREPARED" --output "$DECOMPILE_PREPARED/qualification" \
  --samples 1 --qualification
python3 experiments/analysis-efficiency/runtime-comparison/run_decompile.py \
  --prepared "$DECOMPILE_PREPARED" --output "$DECOMPILE_PREPARED/measured-small" \
  --samples 7 --target small
python3 experiments/analysis-efficiency/runtime-comparison/run_decompile.py \
  --prepared "$DECOMPILE_PREPARED" --output "$DECOMPILE_PREPARED/measured-gofmt" \
  --samples 1 --target gofmt

"$BENCH_NODE" experiments/analysis-efficiency/runtime-comparison/estimate-tokens.mjs \
  "$DECOMPILE_PREPARED/measured-small/results.json"
"$BENCH_NODE" experiments/analysis-efficiency/runtime-comparison/estimate-tokens.mjs \
  "$DECOMPILE_PREPARED/measured-gofmt/results.json"
python3 experiments/analysis-efficiency/runtime-comparison/archive_decompile.py \
  --prepared "$DECOMPILE_PREPARED" \
  --measured "$DECOMPILE_PREPARED/measured-small" \
  --measured "$DECOMPILE_PREPARED/measured-gofmt" \
  --output "$DECOMPILE_PREPARED/archive"
```

Preparation and fixture generation require new output directories. Preserve those inputs after qualification; rebuilding a fixture can change its binary digest even when the source is unchanged. Build before timing, and keep other builds stopped during measurement. Qualification attempts and failures should be retained. The existing metadata `prepare.py`, `fixtures.py` and `run.py` are reused without editing their historical versions.

</details>
