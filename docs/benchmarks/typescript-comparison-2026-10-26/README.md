# TypeScript cross-app diagnostic

Status: diagnostic only. This records individual TypeScript attempts and a
bounded direct-worker comparison. It is not the full public MCP benchmark and
does not establish a speed winner or full semantic parity.

The original attempts used the frozen TypeScript runtime recorded in
[`evidence-manifest.json`](evidence-manifest.json): Node 24.18.0,
`scripts/rea.mjs` SHA-256
`bd0666c21573cd7c04ac63d5bfcbb42ab4da306eef10b8d7d9f295a3c84e4f0e`, and
`dist/mcp/main.js` SHA-256
`ebf186b625ed7b24141b4edae7c0571a5ccf5cb044e440285ab87b619e1845c2`.
The dependency tree was symlinked to the current checkout, so those attempts
are diagnostic rather than a clean historical package reproduction.

## Original application attempts

| Attempt | Outcome | Measurement | Interpretation |
| --- | --- | --- | --- |
| Postman | Provider timeout | 45.546 s; peak family RSS 1,807,695,872 bytes; 4 processes | `provider_timeout`; a separate wrapper shutdown `TypeError` is retained and not folded into the provider result. |
| ChatGPT | Artifact integrity mismatch | 2.8306 s; peak family RSS 543,883,264 bytes; 1 process | Declared and calculated digest differed for an unpacked native companion entry while the bytes were present. |
| Figma | Artifact operation failed | 0.7908 s; peak family RSS 389,758,976 bytes; 1 process | The original receipt contains a generic malformed-ASAR error; a separate header-only follow-up verified the `.codesign` size `-1000` and `size >= 0` schema cause. |
| Kiro, initial | No response | 120 s; no receipt or semantic result | Preserved as a timeout attempt; it is not equivalent to a completed analysis. |
| Kiro, retry | Unreadable output | 40.2927 s; peak family RSS 1,846,853,632 bytes; 4 processes | `ENOSPC` occurred while transferring worker output; no semantic result is claimed. |
| Postman wrapper event | Wrapper shutdown error | No independent analysis timing | Preserved separately from the Postman provider timeout. |

The bounded projection is in [`attempts.json`](attempts.json). Small original
receipts and stdout/stderr artifacts are under [`evidence/`](evidence/), with
source sizes and SHA-256 values in [`evidence-manifest.json`](evidence-manifest.json).

A separate header-only follow-up then read the same Figma archive with Electron
ASAR `getRawHeader` successfully. The TypeScript `AsarListing` projection rejected
its `.codesign` entry because its recorded size is `-1000`, with the captured Zod
path `size >= 0` diagnostic. This follow-up did not run a worker, MCP workflow, or
full application analysis, so it explains the generic original receipt without
changing its outcome. The bounded proof, script, and digests are in
[`figma-header-evidence.json`](figma-header-evidence.json),
[`figma-header-check.mjs`](figma-header-check.mjs), and
[`figma-header-manifest.json`](figma-header-manifest.json).
The copied original attempt manifest remains an immutable record of the
historical run; the derived [`attempts.json`](attempts.json) keeps the original
generic error separate from this follow-up proof.

## Direct-worker comparison

Build12 used Rust executable SHA-256
`53e9b3c7774836adbff6347576228a404ae04d5e06b974fe0026465b2ddfb91f`, the
Rust worker heap flag `--rea-javascript-worker-max-heap-mb=1024`, a 30-second
deadline, and a 4 GiB family RSS cap. The selected final result is
[`results-final.json`](direct-worker-evidence/results-final.json); the runner,
provenance, and earlier attempts are preserved in
[`direct-worker-evidence/`](direct-worker-evidence/).
The later build13 provenance is recorded in
[`build13-manifest.json`](direct-worker-evidence/build13-manifest.json); the
binary itself is not included.

CPU and RSS values below are sampled lower bounds. `cpu_us_final` and
`rss_bytes_final` of zero mean unavailable post-exit values, not measured zero.

| Lane | Runtime | Classification | Elapsed | Sampled CPU | Sampled peak RSS |
| --- | --- | --- | ---: | ---: | ---: |
| Figma (`main.js`) | TypeScript | 30 s native timeout | 30.149 s | 39,699,382 us | 1,186,103,296 B / 1,131.16 MiB |
| Figma (`main.js`) | Rust build12 | Static checkpoint emitted; semantic projection incomplete at 30 s | 30.088 s | 29,754,346 us | 561,741,824 B / 535.72 MiB |
| Postman (`AgentWorker.js`) | TypeScript | 30 s native timeout | 30.177 s | 36,534,345 us | 1,280,901,120 B / 1,221.56 MiB |
| Postman (`AgentWorker.js`) | Rust build12 | Static checkpoint emitted; harness classified exit 122 as native heap exhaustion; no error text | 29.565 s | 22,270,950 us | 1,215,037,440 B / 1,158.75 MiB |

The TypeScript Figma and Postman lanes reached the 30-second deadline. Rust
emitted a static-analysis checkpoint for both lanes, then failed to complete the
remaining semantic projection; the exact post-checkpoint failure stage is
unknown. The Rust Postman lane was classified by the harness as native heap
exhaustion from exit 122 with no error text. These outcomes are not equivalent completed analyses and cannot support a performance
ranking. Background Cargo
activity was ongoing during collection.

Attempt 1 is retained as an invalid comparison because the Rust 1024 MiB heap
flag was missing. Attempt 2 included the flag; its Rust Postman classification
is harness-derived from exit 122 with no error text, so it remains a runtime
outcome rather than semantic evidence. The final results include the same
bounded limitations.

The direct worker is a single analysis-call comparison, not a whole public
benchmark workflow. TypeScript uses a persistent worker process for each source
request; Rust uses one source per worker invocation, so lifecycle costs are not
identical. The runner result does not contain all invocation details
or code-file digests; the report's timeout, heap, RSS, output, and TypeScript
flags are derived metadata from the runner source and are labeled as such in
[`provenance.json`](direct-worker-evidence/provenance.json). The TypeScript
worker entry digest `ede2ca3ca26fa0a01f978a9f18ba79516285e030d8cdb99b3d898cdf58a68cf5`
was inspected after collection, not captured at launch. The runner supplied
20,000 node and unknown budgets per TypeScript request.

The direct harness used a 128 MiB output cap and TypeScript semantic-admission
limit; the public worker policy has a minimum 512 MiB transfer bound. No completed
case hit the diagnostic cap. These limits describe this diagnostic runner and are
not interchangeable with the public worker policy.

## Build13 live ASAR validation

Build13 (`rea` SHA-256
`f3e3803f497d128f2aab5a126c5e0b69864c68bcf2a6f1816c476e5583d972cd`) ran one
public MCP call for each target with the 30-second analysis deadline, 1,024 MiB
worker heap setting, and semantic node/unknown ceilings from the plan.

| Target | Protocol result | Analysis result | Call wall time | Sampled family peak RSS |
| --- | --- | --- | ---: | ---: |
| ChatGPT | Expected `artifact_integrity_mismatch` | Declared digest `5f2f66...d58a1`; observed digest `a91e144...f7f9` | 2.583 s | 1,500,315,648 B |
| Discord | Protocol success | Application and semantic coverage partial; truncated at configured capacity; 20,319 semantic unknowns | 30.114 s | 1,498,464,256 B |

The ChatGPT process exited 0 because the tool returned the expected negative
result; the aggregate runner exited 1 to record that expected failure. Discord
returned a successful protocol response, but its analysis is capacity-limited and
is not full semantic completion. These results validate the build13 regression
cases and do not establish broad application parity or a performance ranking.
The before/after target manifests match byte-for-byte. No observed descendants or
reader threads remained, and termination errors were null.

The bounded aggregate, receipts, call records, plan, and target manifests are in
[`live-asar-evidence/`](live-asar-evidence/), with file digests in
[`live-asar-evidence/provenance-manifest.json`](live-asar-evidence/provenance-manifest.json).

## Retrospective PE schema evidence

The separate build12 PE retrospective used the public catalog SHA-256
`8438129787e13859043d41c93d9c95547f4594173653d769b23d31de24b5c715`.
It found 15 successful receipts, 5 structured payloads validated, and 10
unstructured calls skipped. All 5 structured payloads passed the compatible
shape constraints. This validates output shape only; it does not establish
factual correctness, semantic completeness, or full schema-dialect
conformance. The bounded audit is
[`pe-retrospective-shape-audit.json`](direct-worker-evidence/pe-retrospective-shape-audit.json).

## Findings and limitations

The ChatGPT attempt provides evidence for a Rust ASAR integrity bug: the Rust
reader dropped the archive path and skipped the unpacked companion, while the
matching TypeScript attempt declared and observed the companion digest. The original Figma attempt recorded a generic malformed-ASAR error. A separate
header-only follow-up now provides the `.codesign` size `-1000` and Zod
`size >= 0` diagnosis; it did not run full analysis. These are diagnostic
findings; the build13 live ASAR validation is documented in the Build13 section above.
The synthetic semantic differential is complete.

The Kiro `ENOSPC` result is an environment/resource failure and is not
equivalent to the other application attempts. The Postman wrapper did not
apply the Rust benchmark's 4 GiB family guard. No token measurement was
collected. The Rust build11/v2 30-second workflow baseline remains documented
separately as 20 failures across 110 receipts and is not merged into these
TypeScript attempts.

No completed equivalent end-to-end performance comparison has been established.

The build13 cases cover two checks: one expected ChatGPT integrity rejection and
one Discord analysis response that is partial at its configured capacity. They do
not claim that all large-file or application failures are fixed; broader large-file
optimization remains outside this report.

## Other validation facts

The surrounding validation records report 62 artifact checks passed, 10
host-directory checks passed, 677 application checks passed with 1 ignored,
17 MCP checks passed, and 1 PE producer check passed. The synthetic semantic
differential covered 63 comparisons with zero differences. Clippy completed with
warnings remaining. These facts are validation evidence for their respective
scopes, not proof of whole-application parity.

Release build13 from committed source `7ae9719` completed successfully. Its live
ASAR validation is documented in the Build13 section above.

## Synthetic semantic differential

A separate isolated harness compared 21 synthetic corpus entries in `import`,
`require`, and `compiler-dependent` modes. Each mode compared 21 entries and
reported zero differences:

| Mode | Compared | Differences |
| --- | ---: | ---: |
| import | 21 | 0 |
| require | 21 | 0 |
| compiler-dependent | 21 | 0 |

The bounded reports and synthetic corpus manifest are in
[`semantic-diff-evidence/`](semantic-diff-evidence/). No target application
source, production binary, or full IR is included. The copied `diff-*.json`
files contain only counts and empty-difference results.
All 21 manifest fixtures are included in that directory, with their SHA-256
values in [`fixture-digests.txt`](semantic-diff-evidence/fixture-digests.txt).

This evidence uses the current checkout TypeScript parser SHA-256
`54355ad94379cf8f29488ec14e0439c2260e1ffd0f1686e168fd757e97779955`, not the
frozen full-application TypeScript baseline above. The supplied Rust harness
binary SHA-256 is
`add8dba06ec5bcbd24a47509a39a2350cfebcab97eb35adf14198f3d1f2c366b`; its
source was a dirty `bbbddc...` patch with workspace lock SHA-256
`08dfada42720f557d4a6df04e05bd2f2182059d3ae97b2df65567835448c3a37`.
These are separate provenance identities and should not be collapsed into a
broad TypeScript/Rust parity claim.

The recorded harness run used `/tmp/rea-semantic-diffharness`; its source copy
is preserved at [`src-main.rs`](semantic-diff-evidence/src-main.rs). The bounded
command was:

```sh
cd /tmp/rea-semantic-diffharness
REA_RUST_SEMANTIC_BIN=/tmp/rea-semantic-diffharness/js-full-semantic-diff-release ./run-diff.sh
```

The original isolated Cargo workspace and build output were temporary and are
not included. Live ASAR validation is documented above.
