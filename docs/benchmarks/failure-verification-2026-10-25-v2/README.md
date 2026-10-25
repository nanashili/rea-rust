# 30-second worker verification — 25 October 2026

This run repeats the main, inventory and PE-resource workflows from the [previous verification](../failure-verification-2026-10-25/README.md): 110 receipts over five rounds. At the user's request, the six JavaScript analysis calls use a 30-second worker timeout instead of 15 seconds. All other caller arguments were retained. The three native selected-address workflows (15 receipts) were not repeated. Only Rust source was changed.

## Outcomes

A protocol-success receipt completed every requested call. It does not establish semantic completeness or correct decompilation. Failed attempts remain in the resource measurements.

| Series | Receipts | Calls | Previous → current protocol success | Previous → current failed calls |
| --- | ---: | ---: | ---: | ---: |
| inventory | 10 | 55 | 10 → 10 | 0 → 0 |
| main | 95 | 1,050 | 55 → 75 | 70 → 20 |
| pe-resources | 5 | 15 | 5 → 5 | 0 → 0 |

## Main workflow costs

Values are medians [minimum–maximum] over five fresh processes. Wall and sampled process-family CPU are milliseconds; simultaneous process-family peak RSS is MiB. Elapsed time includes startup, discovery, calls and shutdown. CPU sampling is a lower bound and can miss short-lived children. RSS is a sampled sum, not a kernel-enforced limit.

| Workflow | Protocol success | Wall ms | Family CPU ms | Peak RSS MiB |
| --- | ---: | ---: | ---: | ---: |
| `chatgpt-electron-static` | 0/5 | 105,514.6 [98,070.3–122,421.6] | 99,351.2 [95,835.7–115,813.1] | 3,824.2 [3,581.0–4,033.5] |
| `chrome-native-analysis` | 5/5 | 579.2 [517.3–894.9] | 374.3 [349.8–573.8] | 191.5 [185.9–195.1] |
| `discord-electron-static` | 5/5 | 18,023.4 [17,278.4–35,493.8] | 17,580.9 [17,033.9–30,481.8] | 1,510.6 [1,505.6–1,517.2] |
| `figma-electron-static` | 0/5 | 83,110.7 [81,198.9–121,237.0] | 79,754.4 [78,422.7–110,337.2] | 2,028.3 [2,008.6–2,041.9] |
| `figma-framework-deep` | 5/5 | 32,610.9 [29,679.4–43,516.1] | 92,100.8 [87,467.7–103,164.7] | 2,431.2 [1,781.5–2,437.2] |
| `go-toolchain-binary` | 5/5 | 386.4 [337.1–435.3] | 185.2 [175.3–206.9] | 180.7 [174.8–183.6] |
| `gofmt-deep` | 5/5 | 1,562.3 [1,281.1–1,580.2] | 2,760.8 [2,319.5–2,937.9] | 270.3 [260.7–274.7] |
| `interface-builder-artifact` | 5/5 | 5,918.8 [4,941.2–7,413.5] | 5,314.6 [4,618.4–5,737.2] | 188.2 [187.9–201.3] |
| `kiro-electron-static` | 0/5 | 116,004.6 [112,719.7–121,304.9] | 97,404.8 [96,480.1–99,704.3] | 3,019.5 [2,576.4–3,034.7] |
| `kiro-node-pty-javascript` | 5/5 | 528.5 [421.6–663.5] | 251.4 [224.8–259.7] | 180.9 [177.5–184.6] |
| `openunity-native-analysis` | 5/5 | 2,267.7 [2,083.4–3,600.1] | 1,294.7 [1,240.7–2,012.4] | 300.2 [298.7–302.1] |
| `postman-electron-static` | 0/5 | 28,037.0 [26,286.3–36,523.1] | 27,500.8 [25,522.1–35,496.8] | 2,116.6 [2,102.4–2,130.1] |
| `session-evidence-roundtrip` | 5/5 | 1,131.9 [1,041.9–1,182.4] | 626.6 [603.0–644.6] | 217.4 [216.8–220.4] |
| `terminal-static-fast` | 5/5 | 372.2 [340.6–997.6] | 184.4 [175.7–362.8] | 178.6 [175.3–179.4] |
| `unity-managed-library` | 5/5 | 1,995.0 [1,901.5–3,018.1] | 1,778.5 [1,705.1–1,919.5] | 787.6 [782.3–799.8] |
| `xcode-deep-read-only` | 5/5 | 2,048.6 [1,981.6–2,575.1] | 876.3 [833.3–933.3] | 269.8 [263.7–273.8] |
| `xcode-static-artifacts` | 5/5 | 29,410.1 [27,222.4–96,143.4] | 25,241.3 [24,178.6–56,667.6] | 768.8 [721.0–772.8] |
| `zed-native-analysis` | 5/5 | 12,359.3 [11,029.2–47,780.4] | 10,628.4 [10,141.7–25,697.8] | 1,342.7 [1,340.7–1,377.9] |
| `zed-rust-metadata` | 5/5 | 909.3 [858.8–920.2] | 695.8 [687.2–700.1] | 342.1 [339.2–342.4] |

## Equivalent successful workflows

These comparisons include only workflows whose actual caller inputs matched and whose corresponding rounds succeeded in both builds. JavaScript workflows with the increased timeout are excluded from this table. They describe this host and run; OS cache state and unrelated host activity were uncontrolled.

| Workflow | Wall ms previous → current | Family CPU ms previous → current | RSS MiB previous → current |
| --- | ---: | ---: | ---: |
| `chrome-native-analysis` | 506.7 → 579.2 | 353.6 → 374.3 | 191.3 → 191.5 |
| `go-toolchain-binary` | 323.5 → 386.4 | 173.5 → 185.2 | 173.1 → 180.7 |
| `interface-builder-artifact` | 4,969.1 → 5,918.8 | 4,658.0 → 5,314.6 | 193.5 → 188.2 |
| `openunity-native-analysis` | 1,957.9 → 2,267.7 | 1,227.5 → 1,294.7 | 301.6 → 300.2 |
| `session-evidence-roundtrip` | 963.5 → 1,131.9 | 582.7 → 626.6 | 206.1 → 217.4 |
| `terminal-static-fast` | 317.1 → 372.2 | 174.3 → 184.4 | 175.8 → 178.6 |
| `unity-managed-library` | 1,849.1 → 1,995.0 | 1,694.4 → 1,778.5 | 816.5 → 787.6 |
| `xcode-static-artifacts` | 26,944.9 → 29,410.1 | 24,481.3 → 25,241.3 | 755.7 → 768.8 |
| `zed-native-analysis` | 10,693.6 → 12,359.3 | 9,996.4 → 10,628.4 | 1,513.6 → 1,342.7 |
| `zed-rust-metadata` | 793.8 → 909.3 | 651.7 → 695.8 | 333.9 → 342.1 |

## Recorded failures

| Series | Error category | Calls |
| --- | --- | ---: |
| main | `mcp_timeout:harness` | 2 |
| main | `provider_timeout:timeout` | 10 |
| main | `resource_constraint:resource_constraint` | 8 |

The remaining failing main workflows are `chatgpt-electron-static` (5/5 failed), `figma-electron-static` (5/5 failed), `kiro-electron-static` (5/5 failed), `postman-electron-static` (5/5 failed). 18 failed calls returned a retained partial-Evidence reference. A 30-second budget applies to each source worker; file acquisition, other workers and result handling also contribute to the call. The separate 120-second MCP deadline can therefore be reached first for a whole call.

## Validation

The shape audit used Node `jsonschema` 1.5.0 with schema identifiers and dialect declarations removed. Counts below distinguish checked objects from skipped calls; they do not establish declared-dialect conformance or factual correctness.

| Series | Valid objects | Invalid objects | Validator errors | Failed calls skipped | Successful calls without object payloads |
| --- | ---: | ---: | ---: | ---: | ---: |
| inventory | 35 | 0 | 0 | 0 | 20 |
| main | 840 | 0 | 0 | 20 | 190 |
| pe-resources | 0 | 5 | 0 | 0 | 10 |

All five PE-resource responses from this frozen build fail its advertised output schema: the Rust reader returns thirteen resource fields missing from the catalog's strict `normalized_result` schema. The returned resource/version facts are checked independently below, but this run does not verify a schema fix. The reporting manifest therefore records `validation_failed`.

[Receipt integrity](receipt-integrity.json) reports `passed`: 1011 retained response digests were checked, 107 calls retained a digest without a response, and 2 had no response digest. It also compares aggregate receipts with the retained call files, selected target identities before and after each series, selected input contents against the baseline, and sampled cleanup observations. Those observations cannot rule out descendants missed between samples or changes to unselected bundle files.

## What changed and what remains

The Rust analysis pipeline shares one prepared semantic state between static and semantic producers, retains static results when later analysis is interrupted, and avoids repeated JSON, string and mutation-origin copies. Ambient-write propagation uses indexed, lazy candidates and dependency-directed updates while retaining source order and conservative unknowns.

Parent links now retain each Babel parent view once and index children by parser identity. The static Electron inspector reuses that owned table. The [bbtree comparison](../bbtree-parent-map-2026-10-25/README.md) records the measured reason for choosing compact links; its component savings are not a whole-application speedup claim.

Native procedure facts preserve unknown classification and unavailable locals. Reachable-instruction decoding establishes the reported body instead of guessing its end from the next procedure. Indirect targets and traversal limits remain explicit. Headless navigation, static load-image information, API recovery, dispatch and feature traces retain unsupported or partial coverage where the provider cannot establish the requested fact. A successful envelope for those facts does not mean the underlying capability became complete.

Independent PE resource and version checks, receipt auditing and cleanup observations are recorded beside this report. The byte/procedure regression fixtures do not independently establish every real application's function boundary or decompilation semantics.

## Method and provenance

The caller selected a 30-second JavaScript worker timeout for this run. The 1 GiB worker heap setting, 4 GiB sampled family guard and 120-second MCP timeout were retained. The [interrupted 15-second run](../failure-verification-2026-10-25-15s-interrupted/README.md) is separate and is not a completed five-round comparison. Every round starts a fresh REA process with an isolated provider cache. The OS filesystem cache was not reset; hashing and prior runs can warm it. Repeated calls within a receipt reuse that session. The [runner source comparison](runner-source-comparison.json) verifies that the only runner change is CSV line endings, written after measurements; sampling and call-execution code is unchanged.

The build's base commit is `0173375f35d85d96be62f8aaa4f263a7a14b260e` and its frozen source patch SHA-256 is `463d725548b22f3d1df9df635d22943c838c254343b65f6c4307492aa78d89f2`. Executable hashes are in [build.json](build.json). [Runtime source verification](runtime-source.json) identifies the committed source and verifies it against the frozen build tree outside documentation and benchmark reporting files. The execution manifest binds the receipts to those binaries. Target and toolchain details are in the before/after host manifests. Benchmarks read installed application artifacts without launching or modifying them.

Agent tokens, energy, physical disk bytes, hardware counters and full application correctness were not measured. Catalog and response bytes are not presented as token counts. The full structured responses and source traces remain in the local work directories named by the manifests; public aggregates omit target source and decompiled text.

- [Receipt consistency and cleanup observations](receipt-integrity.json)
- [Execution and build identity](execution.json) · [reporting checks](reporting-execution.json)
- [Comparison, task equivalence and semantic limitations](comparison.json)
- [Main receipts](main-raw.json) · [inventory receipts](inventory-raw.json) · [PE receipts](pe-resources-raw.json)
- [Main metrics](summary-main/report.md) · [inventory metrics](summary-inventory/report.md) · [PE metrics](summary-pe-resources/report.md)
- [Main schema audit](schema-audit-main.json) · [inventory schema audit](schema-audit-inventory.json) · [PE schema audit](schema-audit-pe-resources.json)
- [PE resource checks](pe-resources-validation.json) · [PE version checks](pe-version-validation.json)

Reproduction uses `local-applications-2026-10-25-30s-plan.json` for main workflows and the unchanged inventory and PE-resource plans in `docs/benchmarks/`. Run `scripts/benchmarks/run_mcp.py` against the release executables with `--rounds 5 --call-timeout 120` and a new work directory for each plan. The execution manifest preserves the exact commands, output locations and exit codes from this run.
