# Native runtime migration verification

This record captures the native migration checks completed for the source state
on 2026-10-25. It is historical evidence from the parent REA migration
workspace, preserved with the standalone Rust source. Publishing this copy does
not claim that the checks were rerun in this repository.

## Confirmed checks

| Check | Result | Evidence or scope |
| --- | --- | --- |
| Full-profile captures | 9/9 passed | Receipt `8ax` |
| Whole scenarios | 10/10 passed | Receipt `8az` |
| Retained JavaScript views | 18/18 matched on the same authenticated input | Receipt `8av` |
| Real DMG workflows | 4/4 passed | Receipt `8ax` |
| C ABI | Fresh rebuilt release verification passed | Run 90 |
| Ghidra Rust worker | Final installed worker and explicit decompile checks passed | Receipts `8cl`, installed CLI `123`, installed MCP `124` |

The default source feature set registers 200 tools. The optional `frida`
feature supplies the remaining nine contracts. Receipt 8cl records a healthy
production-stdio `rea mcp doctor` inventory with 209 expected and 209 observed
tools, with the binary session healthy.

## Remaining verification

- Linux, Windows, and other real-provider combinations remain unverified.

## Current receipts

| Check | Result | Evidence or scope |
| --- | --- | --- |
| Strict result comparison | 828/828 exact; zero timeouts; no missing, extra or duplicate IDs | Receipt `8cg`; parent-workspace report; native SHA-256 `4e1dd329c5503c3dd9d76ca88d52473871708d09f25a959040b612e61c5dda81` |
| Full workspace completion run | 1,681 passed; 0 failed; 5 ignored across 94 test groups | Workspace run `117` |
| Format check | Passed | Run `120` |
| Clippy | Passed with existing warnings | Run `118`; not warning-free |
| Pinned npm check | Typecheck and lint passed | `npm run check:fast` in parent workspace |
| Graph goldens | 138/138 byte-identical | Run `101` |
| Final release binary | Built successfully; 117,765,952 bytes | Receipt `8cl`; SHA-256 `71d356878725edf969e588469001b1e2960d2955083612ef51183246b79a54e2` |
| Final Ghidra Rust worker | Built successfully; 9,632,000 bytes | Receipt `8cl`; SHA-256 `d8d3055753e28f5613f8c25007f881f25e3bb10930f9cba4caf1eda4c3ac8b29` |
| Final package | 1,856 entries; 60,550,613-byte archive; 155,238,137-byte unpacked payload | Receipt `8cl`; package SHA-256 `643e45dd956d47195eed04499a402e3b3b1658479c4de9c934638e345cfc9362` |
| Final release workflows | JavaScript 12/12, ASAR 21/21, mobile 3/3, Frida 52 checks across 7 scenarios, HTTP 13/13, MCP registration 11/11, accessible setup, maintenance 11, environment SDK 19 tools plus verifier/malformed/tamper/package-preservation checks | Receipt `8cl` |
| Final browser/module proof | Regular and indexed CLI/MCP maps, nested controls and module trace passed | Parent-workspace proof files |
| CLI completion proof | 9 exact cases; 8 qualified differences | Receipt `8cl`; differences include pathname-race provenance, parser diagnostics, rejection details and doctor projections |
| Installed package CLI | Fresh ignore-scripts install, launcher help, MCP EOF, doctor, decompile and explicit Ghidra Rust checks passed | Parent-workspace log for installed CLI `123` |
| Installed package MCP | Fresh install/cache; 209 tools, session lifecycle, worker identity and non-empty batch decompile pseudocode passed | Parent-workspace log for installed MCP `124` |

The final release, package, installed CLI, installed MCP and Ghidra receipts
are complete for the validated macOS arm64 workflow. The CLI completion proof
records qualified differences rather than universal byte parity. Known
differences include SDK output shape, backup naming, native-vs-Node pathname
race coverage, parser diagnostics, richer rejection details, doctor identity
and ordering projections, and the corresponding graph digest difference.
