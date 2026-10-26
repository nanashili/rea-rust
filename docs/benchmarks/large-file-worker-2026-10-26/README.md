# Large JavaScript files

Build34 (`a83a333`) returned final bounded graphs for Figma `main.js`
(3.6 MB) and Postman `AgentWorker.js` (10.8 MB). The [plan](plan.json) uses a
30-second worker deadline, a 1 GiB Rust allocator live-heap limit, 20,000
semantic nodes and unknowns per file, and a 64 MiB encoded output cap. The
allocator limit is not a process RSS limit.

Three serial direct-worker rounds returned final partial projections each time:

| Source | Build34 elapsed, seconds | Earlier Rust baseline |
| --- | --- | --- |
| Figma | 9.02, 9.04, 9.32 | Three 30-second timeouts |
| Postman | 27.42, 29.03, 27.93 | Three exit-122 failures |

Postman has less than one second of margin in the slowest round. Since the
baseline did not finish, these runs do not support a speedup ratio. The
[paired receipt](historical-build34-paired.json) includes sampled family CPU,
RSS, output bytes, coverage, and cleanup results. Both graphs are partial at
the configured bounds; neither is a full-file semantic result.

The public MCP calls also returned semantic partial results and retained
Evidence IDs, with no worker-timeout signal in their limitations:

| MCP analysis call | Wall | Sampled family CPU | Sampled peak family RSS |
| --- | ---: | ---: | ---: |
| Figma | 14.746 s | 14.577 s | 868,270,080 B |
| Postman | 38.381 s | 37.956 s | 2,019,131,392 B |

The MCP call includes archive and result work outside the 30-second worker
deadline. Figma retained three native-integrity warnings under the explicit
record-and-continue policy; Postman used the fail policy. Both are classified
`semantic_partial_completed`, which means the worker returned a bounded graph,
not that semantic coverage is complete.

Use the [historical appendix](historical-diagnostics.md) for retained smoke,
diagnostic, parity, and output-shape evidence. CPU and process-family RSS are
sampled measurements and are separate from Rust allocator or worker-heap
figures. Runs collected with different sampling cadences or harnesses must not
be combined into timing ratios.

The retained [qualified MCP summary](qualified-mcp-summary.json),
[large-field parity](build34-large-fields-parity.json), [full-IR parity](build34-full-ir-parity-17case.json),
and [worker parity](build34-worker-parity-17case.json) receipts contain the
canonical fields and provenance. All five large-field hashes match the Build29
diagnostic reference, but its 90-second/192 MiB limits differ from the
production 30-second/64 MiB limits, so it is not a timing comparator. The 51
full-IR comparisons across 17 fixtures and three modes, and the 17 worker
comparisons, have no differences. These results establish bounded parity
evidence, not a TypeScript speed comparison.
