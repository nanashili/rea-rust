# Historical diagnostic values

This appendix records retained historical smoke and diagnostic runs. See the
[benchmark README](README.md) for current qualification status and the final
candidate. Direct diagnostic executables are useful for locating allocation
boundaries but are not production performance data.

| Build | Fixture | Result | Elapsed | CPU | Peak family RSS |
| --- | --- | --- | ---: | ---: | ---: |
| 15 | Figma | Candidate exit 122 after one static frame | 12.1709 s profiler | — | 1,081,016,320 B |
| 15 | Postman | 30 s timeout | 30.1184 s profiler | — | 818,380,800 B |
| 16 | Figma | Exit 122 after static checkpoint | 11.9565 s | 8.8336 s | 1,468,989,440 B |
| 16 | Postman | Exit 122 after static checkpoint | 23.2446 s | 18.5746 s | 1,433,010,176 B |
| 17 | Figma | 30 s timeout | 30 s | 12.6711 s | 1,480,556,544 B |
| 17 | Postman | 30 s timeout | 30 s | 15.7909 s | 1,170,210,816 B |
| 18 | Figma | Exit 122, no final result | 11.2268 s | 10.0533 s | 1,392,132,096 B |
| 18 | Postman | Exit 122, no final result | 21.3067 s | 16.7841 s | 1,437,171,712 B |
| 19 | Figma | 48,492,469-byte final projection; receipt invalid at the 8 MiB harness cap | — | — | — |
| 19 | Postman | Exit 122, no final result | — | — | — |
| 20 | Figma | Partial final result at 20k graph bound | 20.057 s | 10.138 s sampled | 1,275,084,800 B sampled |
| 20 | Postman | Exit 122 after static checkpoint | 15.987 s | 13.561 s sampled | 1,432,240,128 B sampled |
| 22 | Figma | Production final projection, partial at 20k graph bound | 23.760 s | 10.644 s sampled | 1,251,442,688 B sampled |
| 22 | Postman | Production exit 122 after static checkpoint | 28.806 s | 24.263 s sampled | 1,347,371,008 B sampled |
| 23 diagnostic | Figma | Diagnostic final projection, partial at 20k graph bound | 28.095 s | 11.417 s sampled | 1,095,843,840 B sampled |
| 23 diagnostic | Postman | Diagnostic exit 122 | 29.315 s | 24.525 s sampled | 1,514,864,640 B sampled |
| 24 diagnostic | Figma | Diagnostic final projection, partial at 20k graph bound | 28.867 s | 11.390 s sampled | 1,058,242,560 B sampled |
| 24 diagnostic | Postman | Diagnostic timeout at 30 s | 30.079 s | 16.401 s sampled | 1,305,591,808 B sampled |
| 25 diagnostic | Figma | Diagnostic final projection, partial at 20k graph bound | 22.955 s | 10.754 s sampled | 657,768,448 B sampled |
| 25 diagnostic | Postman | Diagnostic timeout after static checkpoint | 31.352 s | 23.892 s sampled | 1,289,109,504 B sampled |
| 26 smoke | Figma | Final projection, partial at 20k graph bound | 22.428 s | 10.174 s sampled | 663,715,840 B sampled |
| 26 smoke | Postman | Timeout after static checkpoint | 30.072 s | 27.210 s sampled | 1,420,525,568 B sampled |
| 27 smoke | Figma | Final projection, partial at 20k graph bound | 23.921 s | 9.887 s sampled | 664,813,568 B sampled |
| 27 smoke | Postman | Timeout after static checkpoint | 30.093 s | 26.515 s sampled | 1,468,022,784 B sampled |
| 29 smoke | Figma | Final projection, partial at 20k graph bound | 20.681 s | 10.175 s sampled | 606,912,512 B sampled |
| 29 smoke | Postman | 64 MiB output cap | 29.951 s | 28.325 s sampled | 1,419,919,360 B sampled |
| 32 smoke | Figma | Final projection, partial at 20k graph bound | 9.734 s | 8.244 s sampled | 687,259,648 B sampled |
| 32 smoke | Postman | Final projection, partial at 20k graph bound | 27.578 s | 25.694 s sampled | 1,517,027,328 B sampled |
| 33 smoke | Figma | Final projection, partial at 20k graph bound | 11.464 s | 8.824 s sampled | 643,055,616 B sampled |
| 33 smoke | Postman | Timeout after static checkpoint | 30.105 s | 24.068 s sampled | 1,252,409,344 B sampled |
| 34 smoke | Figma | Final projection, partial at 20k graph bound | 9.994 s | 8.235 s sampled | 641,744,896 B sampled |
| 34 smoke | Postman | Final projection, partial at 20k graph bound | 26.696 s | 25.377 s sampled | 1,476,395,008 B sampled |

CPU and RSS in the smoke rows are sampled family lower bounds, not
process-exit totals. Builds before 29 used approximately 64 KiB process-family
sampling cadence; their CPU and RSS values cannot support timing ratios against
the corrected 50 ms cadence used by Build29. Static checkpoints are not
semantic completion. No row establishes a speed, memory, or semantic-parity
winner.

## Production20 and production22 checks

Production20 reached partial Figma coverage at the 20k graph bound and exited
122 on Postman. Its retained checks covered 17 worker fixtures in import mode
and 51 full-IR comparisons across 17 fixtures in three modes, with no observed
differences. Production22 had the same bounded large-file outcome pattern. The
public MCP workflow still needs an equivalent final-candidate run.

## Diagnostic23 and diagnostic24

These runs used diagnostic executables with the same nominal 30-second, 1 GiB,
20k-node, and 4 GiB family limits. They are not production measurements and
must not be used to claim a source speedup. Diagnostic24's LLDB summary locates
the Postman budget stop at direct semantic IR serialization, in
`JsString` conversion inside `Compound::serialize_field`; LLDB invalidates
timing comparisons. The summary identifies an allocation boundary, not proof
of retained-block ownership.

## Build25 experiment

Build25 is the committed typed record-at-time graph projection at source
revision `94b6938438f77c219033cac6ae6a817c5e796e27`. The source typed IR still
retains individual records and the final graph. Its retained diagnostic Figma
measurement is useful evidence for that implementation, but there is no paired
production comparison or completed Postman diagnostic measurement.

The retained build25 diagnostic receipt is
[`build25-diagnostic-smoke.json`](build25-diagnostic-smoke.json). It used
source revision `94b6938438f77c219033cac6ae6a817c5e796e27` and diagnostic binary
SHA-256 `3eefabc34eedf2a3672678148075ef1faea84b959d2bfa4d5ce55ebbeebbaed7`.
Figma emitted a final partial projection at the 20k graph bound. Postman timed
out after its static frame and did not complete semantic analysis. The smoke
CPU and RSS values are sampled family lower bounds.

An extended LLDB run exited with status 0, but its output was redirected to
`/dev/null` and the budget breakpoint was not hit, so it proves neither protocol
completeness nor timing. The profile windows show semantic work under
`member_mutations`, scope lookup, provenance, and dependency unions; sampling
perturbs execution and is diagnostic only. These observations do not qualify
build25 as a production comparison or establish a speedup.

## Production26 smoke

The retained [production26 smoke receipt](production26-smoke.json) used source
revision `14d63901e81f71254e5396922f1a6dbe3cd15e5a`. Its binary is SHA-256
`1cdfb058f6f75fb9dc30dbdf343d04c9c21ae25434898444614e88be97f9a5be`; the
[build manifest](production26-manifest.json) records the locked toolchain and
artifact identity. Figma emitted a final partial projection at the 20k graph
bound after 22.428 seconds, with 663,715,840 bytes sampled family RSS and
10.174 seconds sampled family CPU. Postman reached the static frame and timed
out after 30.072 seconds, with 1,420,525,568 bytes sampled family RSS and
27.210 seconds sampled family CPU; it did not complete semantic analysis.

The [full-IR parity receipt](production26-full-ir-parity-17case.json) reports
51 comparisons across 17 fixtures and three modes with no differences. The
[worker parity receipt](production26-worker-parity-17case.json) reports 17
import-mode comparisons with no differences. These parity checks cover the
small fixture corpus and do not make the large-file smoke complete or establish
a performance winner. The CPU and RSS values remain sampled family lower
bounds, and production26 is historical while the Postman large-file path is
still being fixed.

## Production27 smoke

The retained [production27 smoke receipt](production27-smoke.json) used source
commit `a643a5eb57072a19b3ef89fd6d9b76c900ab3a7e`. Its candidate binary is
SHA-256 `106e2bbc73490982276f67876cacc6980cb4c04416c171d8b5bbb058148acc10`;
the [build manifest](production27-manifest.json) records the clean source tree
and artifact hashes. Figma emitted a final partial projection at the 20k graph
bound after 23.921 seconds, with 664,813,568 bytes sampled family RSS and
9.887 seconds sampled family CPU. Postman reached the static frame and timed
out after 30.093 seconds, with 1,468,022,784 bytes sampled family RSS and
26.515 seconds sampled family CPU; it did not complete semantic analysis.

The [full-IR parity receipt](production27-full-ir-parity-17case.json) reports
51 comparisons across 17 fixtures and three modes with no differences. The
[worker parity receipt](production27-worker-parity-17case.json) has 17 import-
mode comparisons with no failures or semantic differences: 13 candidates are
complete and 4 are partial (`hoisting`, `with-proto`, `with`, and
`edge-boundaries`). These parity results preserve the reported coverage flags;
they do not make the large-file smoke complete or establish a performance
winner. CPU and RSS remain sampled family lower bounds, and production27 is
historical while the Postman large-file path is still being fixed.

## Production29 corrected-cadence smoke

The retained [Build29 smoke receipt](production29-cadenced-smoke.json) used
source commit `c5c720848bfb86bf2c4445538bf0d8f26f9bf946` and candidate binary
SHA-256 `be4eed9c258331077ea2dbcd2fbd6c667a12ef335cd5095da8ccdc99122319c1`.
The [manifest](production29-manifest.json) records the clean source tree and
artifact hashes. This run used a corrected 50 ms process-family sampling
cadence. Figma emitted a final partial projection at the 20k graph bound after
20.680844 seconds, with 606,912,512 bytes sampled family RSS and 10.175495
seconds sampled family CPU. Postman hit the 64 MiB combined output cap after
29.950535 seconds, with 1,419,919,360 bytes sampled family RSS and 28.325320
seconds sampled family CPU; it did not emit a final projection.

The [fresh full-IR parity receipt](production29-full-ir-parity-17case.json)
reports 51 comparisons across 17 fixtures and three modes with no differences.
The [output-shape diagnostic](production29-output-shape-diagnostic.json) is a
separate exit-0 diagnostic: it observed a 68,791,784-byte final frame and
71,796,522 bytes of combined output under a 192 MiB diagnostic cap, while the
production cap is 64 MiB. It is evidence about output shape and size, not a
completed production workflow or a performance comparison.

A separate Build29 large-file oracle used a 90-second deadline and 192 MiB
combined-output cap. Its canonical response hash is
`c50bce911fc9088e04cdf12f98ec8b91c3ddfcdd7c9c53f2b9271bd94c5d8330`; that
receipt filtered `$.micros` and is retained only as a hash reference. A new
exact helper is required before using it for parity or timing claims.

## Build32 paired run and Build33 smoke

The retained [Build32 paired receipt](historical-build32-paired.json) used
source commit `dd88957c977e91fa74db2816faec6c1dc967d5c0` and three paired
rounds against the earlier baseline. A separate Build32 smoke once completed a
partial Postman projection in 27.578 seconds, but that result did not repeat:
all three paired Postman candidate rounds timed out at the 30-second worker
deadline. The paired Figma candidate completed a partial 20k projection in all
three rounds; its baseline rounds timed out. These are retained failure and
coverage observations, not a stable timing comparison.

The [Build33 smoke receipt](historical-build33-smoke.json) used source commit
`60af18dfcfb449d01467234e93e1afc0e4e170e9`. Figma completed a partial 20k
projection in 11.463881 seconds, with 643,055,616 bytes sampled family RSS and
8.824471 seconds sampled family CPU. Postman timed out after the static frame in
30.105133 seconds, with 1,252,409,344 bytes sampled family RSS and 24.068264
seconds sampled family CPU. The Build33 diagnostic run with a 90-second
deadline completed a partial projection in 29.583 seconds; its profile hotspot
is retained separately as diagnostic evidence and is not a production timing
result.

The Build32 and Build33 smoke CPU and RSS values are sampled family lower
bounds. Static checkpoints and partial projections are not semantic completion;
the repeated Postman timeouts remain part of the historical evidence.

## Build34 paired smoke

The retained [Build34 smoke receipt](historical-build34-smoke.json) used source
commit `a83a333`. Its candidate binary SHA-256 is
`04d076034a205aceaad621e0a73c2d2562e5f170de037e2bbcb77ef4b8589903`. The
single smoke run produced partial final projections for both selected files
under the 20,000-node and 20,000-unknown bounds. The [three-round paired
receipt](historical-build34-paired.json) records candidate Figma wall times of
9.019960, 9.042787, and 9.323163 seconds, and candidate Postman wall times of
27.423221, 29.031288, and 27.925035 seconds. Every candidate result was
partial, not semantically complete. All three baseline Figma rounds timed out;
all three baseline Postman rounds exited 122.

Because the candidate and baseline did not reach equivalent completion states,
these paired runs do not support a speedup ratio. CPU and RSS remain sampled
family lower bounds; the qualified public MCP and parity receipts are documented
below.

## Build34 qualified public MCP and parity

The [qualified MCP summary](qualified-mcp-summary.json) records protocol
success for both workflows with `semantic_partial_completed` coverage. Figma's
analysis call took 14.745796 seconds, with 14.577359 seconds sampled family
CPU and 868,270,080 bytes sampled family RSS. It retained three known native
integrity warnings under record-and-continue; the affected observed bytes are
untrusted. Postman's analysis call took 38.381224 seconds, with 37.956241
seconds sampled family CPU and 2,019,131,392 bytes sampled family RSS. It ran
with archive integrity policy `fail` and had no worker failure or timeout.

The [large-field parity receipt](build34-large-fields-parity.json) reports all
five canonical field hashes equal to the Build29 diagnostic reference. That
reference used a 90-second deadline and 192 MiB capture cap, unlike the
production 30-second and 64 MiB limits, so this is not a performance
comparison. The [full-IR parity receipt](build34-full-ir-parity-17case.json)
reports 51 comparisons across 17 fixtures and three modes with no differences;
the [worker parity receipt](build34-worker-parity-17case.json) reports 17
comparisons with no differences. These results establish bounded protocol and
parity evidence while semantic coverage remains partial at the per-file
20,000-node and 20,000-unknown limits.
