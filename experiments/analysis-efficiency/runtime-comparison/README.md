# REA speed comparison: TypeScript and Rust

**Rust started faster and used less memory in these tests. Rust Ghidra was faster on the small C test, but failed on the larger Go program. TypeScript was faster at repeated Go metadata checks.**

We compared the original TypeScript REA with a frozen copy of the standalone Rust migration on 24 October 2026. Both ran on the same Apple M1 Pro computer with 32 GiB of memory.

## How fast was Ghidra decompilation?

Decompilation turns compiled functions back into C-like code. We tested the real providers: **Java Ghidra 12.1.4 through TypeScript REA**, and **Rust Ghidra (`ghidra-decompiler` 2.1.0, based on Ghidra 12.2) through native REA**.

| Same small C program                        | TypeScript + Java Ghidra | Native + Rust Ghidra |
| ------------------------------------------- | -----------------------: | -------------------: |
| Start REA and get the first function's code |             9.43 seconds |         0.39 seconds |
| Start REA and get three selected functions  |             9.47 seconds |         0.43 seconds |
| Request the same function again             |                  10.3 ms |               1.2 ms |
| Peak memory for the complete session        |                1,022 MiB |              214 MiB |

Rust got the first code about **24 times sooner**, mainly because startup and analysis readiness were faster. Both returned the three C functions and passed the checked source facts. Java showed readable strings and names in places where Rust showed addresses. These figures use seven independent sessions per version and 56 repeated calls per version.

**The larger Go formatter failed in Rust Ghidra: Java returned all three requested functions; Rust returned none because of an import-name collision.** A failed result is not counted as faster decompilation. The [Ghidra report](GHIDRA.md) includes that attempt, code samples, exact timings, CPU/memory, software identities and reproduction steps.

## How fast was metadata reading?

Lower times are better. One second is 1,000 milliseconds (ms).

| What REA did                                               | TypeScript time |     Rust time | Result                            |
| ---------------------------------------------------------- | --------------: | ------------: | --------------------------------- |
| Start, then read build details from a Go program           |    0.57 seconds | 0.064 seconds | Rust took about one ninth as long |
| Start, then read a 25,000-package Rust test file           |    0.89 seconds |  0.46 seconds | Rust took about half as long      |
| Start, run nine Go checks in one session, and save results |    1.15 seconds |  0.33 seconds | Rust took about one third as long |
| Repeat a Go check while REA stays running                  |          7.3 ms |       16.2 ms | Rust took about twice as long     |

Each of the first three rows includes starting REA. Starting the Rust version takes less time, which explains much of its advantage. A session keeps REA running to handle several requests. The last row shows what happens after REA has already started: a repeated Go check took longer in Rust, although both versions finished that check in under two hundredths of a second.

The first three rows use the middle result from seven runs. The last row uses the middle result from 56 repeated calls per version across seven running sessions. Exact times and the fastest and slowest results are available below.

## How much memory did it use?

For the Go command, typical peak memory use was about **351 MiB for TypeScript and 99 MiB for Rust**: roughly **72% less memory in Rust**. MiB is a unit of computer memory, close to a megabyte.

We checked memory repeatedly during each run and used the middle peak result from seven runs. These checks can miss brief spikes, so the figures are observations rather than guaranteed memory limits.

## Did both versions do the same work?

For the metadata tests, the tested analysis results and saved exports contained the same information. We checked their contents, including file identities and all 25,000 Rust package records, rather than treating a successful exit as proof of a correct result. The separate Ghidra tests have the output differences and Go failure described above.

We ran six metadata/startup workflows seven times per version: **84 runs in total, all completed successfully**. There were also 56 repeated Go metadata calls per version inside the seven running sessions.

The Rust build still had gaps: it listed 209 tools but implemented 198, leaving **11 missing tools**. Some tool definitions also differed between versions. These results establish performance for the tasks above; they do not establish that every REA tool works the same way in both versions.

## Does Rust reduce AI token costs?

**These tests did not measure actual AI token usage or bills.** A rough estimate of the text exchanged by the test client showed no token reduction in Rust. Most of that text was the full list of tools and their definitions. A real AI client may load less of that list or reuse it differently.

## What do these tests cover?

The metadata tests cover reading information already stored in files and saving the results. The large Rust input is a generated test file listing 25,000 packages. This measures reading and returning package information; it does not measure decompiling a large Rust application. Real Java and Rust Ghidra decompilation is measured separately in the [Ghidra report](GHIDRA.md).

Files were already in the operating system's cache, so these times do not describe a first run after a reboot. IDA, Hopper and Kuna analysis, live programs, and Linux or Windows performance were not measured.

The technical section contains every measured result, exact software versions, source hashes, limitations, and commands to repeat the tests. The [raw measurements](results/2026-10-24/raw-results.json) are also available directly.

<details>
<summary>Technical details and instructions to repeat the tests</summary>

The following details cover the 84 metadata/startup runs, measured from 2026-10-24T09:45:49.135088Z to 2026-10-24T09:46:39.223960Z, using frozen runtime inputs. This metadata set was repeated after correcting harness cleanup. Only the final set is reported below; the earlier set remains local at `.cache/runtime-benchmark-20261024-v2/archive-initial-measurement`. Ghidra measurements and their separate limits are in [GHIDRA.md](GHIDRA.md).

## Detailed timing results

Seven fresh processes per lane and task, alternating TypeScript/native then native/TypeScript. Values are milliseconds: median (observed minimum–maximum). Ratios divide TypeScript median by native median. The CLI analysis results passed independent fixture checks and complete parsed-JSON equality on all seven pairs; version strings also matched.

| Fresh CLI task                 | Original TypeScript |         Native Rust | Wall ratio |
| ------------------------------ | ------------------: | ------------------: | ---------: |
| Version/startup only           | 547.3 (535.4–567.1) |    56.9 (52.2–62.2) |      9.62× |
| Rust metadata, 1 package       | 551.1 (539.5–566.7) |    54.0 (52.7–60.7) |     10.21× |
| Rust metadata, 25,000 packages | 894.2 (878.3–913.2) | 456.1 (448.5–461.5) |      1.96× |
| Go metadata, real gofmt        | 566.5 (557.7–578.9) |    64.3 (63.3–67.1) |      8.80× |

CLI JSON rendering differs despite equal parsed values. The stress case emitted 4,645,413 stdout bytes in TypeScript and 8,545,810 in native; those writes are included in the measured process lifetime. This establishes no CLI token reduction.

The retained MCP workflow starts a new server, initializes, reads every catalog page, performs nine Go inspections (one first call plus eight repeated calls), retrieves summary and complete retained evidence, exports it, and closes stdin. It makes 12 tool calls. Every inspection is checked against the Go oracle; the export must retain exactly one complete, unchanged Evidence record.

| Fresh MCP workflow                                             | TypeScript median (range), ms | Native median (range), ms |
| -------------------------------------------------------------- | ----------------------------: | ------------------------: |
| Complete retained session                                      |        1148.0 (1145.2–1198.8) |       330.3 (311.2–342.9) |
| Startup through complete catalog discovery within that session |        1037.0 (1033.0–1077.5) |       186.5 (173.9–189.0) |
| Eight repeated Go calls, total                                 |              63.5 (61.4–65.2) |       127.0 (115.5–132.9) |
| Catalog-only server lifetime, characterization                 |        1044.7 (1033.7–1066.4) |       178.8 (174.2–212.7) |

For repeated calls alone, there are eight observations within each of seven independent sessions (56 calls per lane; these are not 56 independent processes):

| Established MCP session | Pooled median/call, ms | Observed call range, ms |
| ----------------------- | ---------------------: | ----------------------: |
| typescript              |                   7.27 |              4.61–13.82 |
| native                  |                  16.21 |              9.21–18.14 |

First Go-call medians were 13.75 ms TypeScript and 14.84 ms native. “Warm” means the same live server after discovery/first inspection; it does not assert a parser-cache hit. Warm-call CPU and memory were not isolated from the complete session.

All 84 measured invocations succeeded. There were 28 exact CLI/version comparison pairs and seven retained-session semantic comparison pairs. For MCP, comparison decodes complete JSON stored inside top-level text content blocks; all fields, arrays, Evidence identities, provenance, unknowns and export data remain compared. Raw MCP structures differ in text-encoded JSON object key order. No mismatching analysis fields were removed to establish equivalence.

Both catalogs advertised the same 209 tool names, but their definitions were unequal: native output schemas include the additional `nib` format enum value. Selected input schemas matched; `export_evidence_bundle` definitions matched. The frozen native default build's [doctor receipt](results/2026-10-24/native-doctor.json) reports **198/209 implemented**, with nine Frida tools and two JavaScript tools missing. Catalog-only measurements are therefore characterization, with no equivalent-catalog or complete-coverage speedup claim. The retained-session comparison establishes only the selected successful workflow.

## CPU and memory

Medians below list **TypeScript / native**. CPU is user plus system time from `wait4` for the waited server process; OS-attributed waited-child usage follows platform semantics. The sampler observed one process in every measured family. Python client CPU is excluded; server CPU may exceed elapsed time because of server threads.

| Task                           |        CPU, ms | Root peak RSS, MiB | Sampled concurrent family peak RSS, MiB |
| ------------------------------ | -------------: | -----------------: | --------------------------------------: |
| Version/startup only           |   778.2 / 49.1 |       346.1 / 98.9 |                            329.4 / 98.8 |
| Rust metadata, 1 package       |   784.7 / 50.1 |      346.5 / 103.4 |                            345.6 / 98.6 |
| Rust metadata, 25,000 packages | 1264.3 / 441.6 |      470.4 / 226.9 |                           470.3 / 226.8 |
| Go metadata, real gofmt        |   800.9 / 60.0 |      350.8 / 106.1 |                            350.6 / 98.8 |
| Catalog discovery              | 1366.8 / 107.0 |      432.6 / 163.1 |                           420.7 / 162.9 |
| Retained MCP session           | 1453.4 / 192.3 |      462.3 / 166.1 |                           462.0 / 165.7 |

Root peak RSS is macOS `wait4.ru_maxrss` in bytes, converted to MiB. Family RSS sums the root and recursively observed descendants at each sample. It is a **sampled lower bound on peak concurrent summed RSS**, can double-count shared pages, and can miss short-lived peaks or descendants. The requested interval was 5 ms; the largest observed sampling gap was 80.5 ms. Root kernel high-water marks and sampled family peaks are separate counters. These figures do not include benchmark-client memory or establish memory bounds for untested provider families. Per-sample counters and all min/max values are in the raw results.

## Transport and token cost

These are **heuristic estimates**, computed after timing with `tokenx@1.3.0`; actual model tokens, billing and total agent task usage were **not measured**. Each complete JSON-RPC request, notification and response is serialized with `JSON.stringify` and counted once. Output includes the full catalog plus tool results, including both text and structured content where returned. Catalog estimates are a subset of output, not an extra charge.

| Workflow         | Lane       | Estimated input tokens | Estimated output tokens | Of output: catalog | Output UTF-8 bytes |
| ---------------- | ---------- | ---------------------: | ----------------------: | -----------------: | -----------------: |
| catalog          | typescript |                     95 |                 989,960 |            989,654 |          3,238,893 |
| catalog          | native     |                     95 |                 992,121 |            991,815 |          3,246,181 |
| retained_session | typescript |                    961 |               1,016,751 |            989,654 |          3,328,205 |
| retained_session | native     |                    961 |               1,018,914 |            991,815 |          3,335,493 |

Counts were identical across the seven samples within each lane/workflow. Full discovery transfers roughly 3.2 MB and dominates this exchange. Native did not reduce transport-token estimates here. A real client may filter tool schemas, truncate output, replay history, cache prompts or make more calls; prompts, schema-selection behavior, model continuations and retries outside this successful harness are unmeasured. CLI model-token cost is unmeasured. Smaller payloads or faster execution alone are not evidence of fewer agent tokens.

## Inputs and provenance

- Host: Apple M1 Pro, MacBookPro18,1, 10 CPU cores, 32 GiB RAM; macOS 27.2 build 26B5101f, arm64. Background desktop apps remained active. The implementation chat paused builds/tests; the runner checked for active compiler/build processes before each timed invocation. The machine was not otherwise isolated.
- Original TypeScript: `git archive` of **833136507dd79d959340b09862a53af344e4f1b3**, tree `df69e47ef6cfc79ca1d3ce97f9dbda7714cca66a`; original `scripts/rea.mjs` against its own newly compiled `dist`. No migration-edited TypeScript source was substituted.
- Native: nested HEAD `1cccbf665b82bd6228c3a9272b431b259b9e9c06`, tree `c561345606117e269092cc4b8e47c26886450b84`, **plus the dirty working-tree snapshot**. Canonical source-manifest SHA-256: `4a1d552b83bddb9cb45d8d95e5716c85a450f8c30cbfe230959153324740be78`. External bridge-support manifest: `20c5ec2c5562514f19733142107f04b0b7b498de7d7391e4687a67efca7db806`. The commit alone cannot reconstruct this uncommitted snapshot; the local frozen files and durable manifests identify it.
- Runtime/toolchain: pinned Node **24.18.0**, npm **11.16.0**, TypeScript **7.0.2**; cargo/rustc **1.93.1**. Node SHA-256: `ee6fb0e015284d83a91e8ec5213f43a157f8a392b58555301682892ba928c04a`. Python 3.13.7, psutil 7.2.2.
- Build: original `npm run compile` after its dependency-install check; native `cargo +1.93.1 build --locked --release -p rea`, release thin LTO, one codegen unit, no optional feature request. Cargo target directory `/tmp/rea-target-shared`; builds were sequential and outside measurements. The produced native binary was copied to the frozen snapshot before timing. Native binary SHA-256: `50afe0ca0ec39120c45da65ff1bd47bb5e1dec6199d3d09857e19ad1a12bb0bf`; 34,643,744 bytes. TypeScript dist-manifest SHA-256: `a2cca143da14a0b8d9a4462d71eb12c0165853e7039e692d3ce3275da59cced8`.
- Dependencies: reused the checkout's `node_modules` by symlink after the original dependency checker passed; recorded lockfiles and all direct installed versions. This was not a clean `npm ci` or a hermetic build. Node, native binary, dependency-lock and every TypeScript dist-file digest were checked before the run. The inherited environment was preserved, with `LC_ALL=C`; no ambient environment dump was saved. `REA_CONFIG` was absent in measured children.
- Fixture oracle revision `runtime-comparison-fixtures-v3`. Real fixture: regular-file copy of Go 1.26.5's `gofmt` (2,952,114 bytes, SHA-256 `fb5bc1241a2e1a218afb069d7ee5e4269c3fe918a38fc03190fbc9cbb2bb69b1`). The installed `go version -m` independently establishes compiler version, `cmd/gofmt` and build settings; the copied target was never executed.
- Synthetic ELF64 fixtures: one and 25,000 auditable dependency packages, deterministic zlib `.dep-v0` at file offset 512. Revision 99 intentionally checks preservation of an unknown format revision. The stress fixture is 139,368 bytes; inflated document 3,088,905 bytes. A separate Python ELF/zlib/JSON reader checks section layout and complete stream; every returned package field, dependency edge, root, revision, artifact digest and size is checked. This stresses metadata parsing/serialization, not decompilation or a representative Rust executable's behavior.

[Provenance](results/2026-10-24/provenance.json), [native source manifest](results/2026-10-24/native-source-manifest.json), [support-file manifest](results/2026-10-24/bridge-support-source-manifest.json), [raw results](results/2026-10-24/raw-results.json), and [protocol transcript hashes](results/2026-10-24/transcript-manifest.json) are retained here. Large raw transcripts, complete original provenance, binaries, fixtures and build logs remain in `.cache/runtime-benchmark-20261024-v2/`; they are not committed. Harness digests used during measurement are embedded in raw results.

## Timing and coverage limits

Each process starts fresh, but the OS filesystem cache was **not flushed**. Qualification warmed artifacts before measurements; these are fresh-process, warm-filesystem results. There is no measured cold-boot/cold-disk lane. Seven observations support the displayed medians and observed ranges, not reliable population p95/p99 claims. No outliers were removed.

Wall time starts immediately before process creation and ends when the child is reaped. CLI output is drained during execution; JSON parsing/oracle checks happen after exit and are excluded. MCP wall time includes Python pipe transport, response decoding, live oracle checks and export read/validation while the server is running. Per-call MCP timers stop after decoding the reply, before the oracle check. Shutdown and full catalog discovery are included in complete-session totals. The runner writes its final transcript files after child exit. CPU and memory counters cover server processes, not the whole client/server machine.

The initial 50,000-package fixture was rejected by both lanes with `resource_constraint`: normalized output exceeded **8,388,608 bytes**. It is a [qualification failure](results/2026-10-24/qualification.json), excluded from successful performance results. Early qualification also corrected invalid complete-bundle filters and relative export paths in the harness. Snapshot preparation corrected exclusion of legitimate nested `src/target` directories and missing external bridge files before the successful build. These were harness preparation issues, not measured runtime failures.

These 84 metadata/startup runs did not exercise real Hopper/Ghidra/IDA/Kuna analysis, decompilation, live process/debugger/Frida activity, browser workflows, network transport, installer/update behavior, or Linux/Windows provider behavior. The separate real Java/Rust Ghidra measurements are in [GHIDRA.md](GHIDRA.md). No target bytes were mutated and no fixture target was executed. A generated SQLite fixture was not selected for timing and establishes no SQLite performance coverage. Historical numbers elsewhere in the migration notes were not reused.

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

From the repository root, with Python 3.13 plus psutil 7.2.2, the pinned Node toolchain and installed locked JS/Rust dependencies available. Pause other builds/tests first. `--output` must be new; preparation never resets the checkout or nested repository. Supply a regular Go binary from an installed Go toolchain.

```bash
BENCH_ROOT="$PWD/.cache/runtime-benchmark-reproduction"
PINNED_NODE="$PWD/.cache/toolchains/node-v24.18.0-darwin-arm64/bin/node"
GOFMT="/opt/homebrew/Cellar/go/1.26.5/libexec/bin/gofmt"

python3 experiments/analysis-efficiency/runtime-comparison/prepare.py \
  --repository "$PWD" --output "$BENCH_ROOT" --node "$PINNED_NODE" \
  --baseline-ref 833136507dd79d959340b09862a53af344e4f1b3 \
  --build-typescript --build-native

python3 experiments/analysis-efficiency/runtime-comparison/run.py \
  --prepared "$BENCH_ROOT" --output "$BENCH_ROOT/qualification" \
  --gofmt "$GOFMT" --samples 1 --probe

python3 experiments/analysis-efficiency/runtime-comparison/run.py \
  --prepared "$BENCH_ROOT" --output "$BENCH_ROOT/measured" \
  --gofmt "$GOFMT" --samples 7

"$PINNED_NODE" experiments/analysis-efficiency/runtime-comparison/estimate-tokens.mjs \
  "$BENCH_ROOT/measured/results.json"

"$BENCH_ROOT/bin/rea" mcp doctor --format json > "$BENCH_ROOT/native-doctor.json"
# An unhealthy doctor exit is expected for this frozen default build's missing tools.
python3 experiments/analysis-efficiency/runtime-comparison/archive.py \
  --prepared "$BENCH_ROOT" --measured "$BENCH_ROOT/measured" \
  --output experiments/analysis-efficiency/runtime-comparison/results/NEW-RUN
```

`--probe` marks qualification and permits concurrent builders; its timings must not be published as performance evidence. A new source snapshot measures the then-current dirty native files, so compare manifest and executable hashes with this report before calling it an exact reproduction. `prepare.py --resume` validates the frozen sources before retrying requested builds. Stop if a measured row fails or an analysis comparison fails; catalog differences must be reviewed separately.

Validation actually performed: successful original dependency check/compile and native release build; independent fixture generation/oracles; complete public-workflow comparisons for all measured samples; successful evidence archiving with comparison/provenance guards; Python syntax compilation; JavaScript syntax/lint and targeted formatting checks. No full repository test suite or real-provider conformance suite was run for this benchmark/documentation change.

</details>
