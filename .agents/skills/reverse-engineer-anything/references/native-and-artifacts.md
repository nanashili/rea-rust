# Native, managed, and packaged artifacts

## Desktop installation directories

When an installation directory is supplied and its runtime is unknown, use
`inspect_desktop_application` with its absolute path. Default MCP summary
delivery retains complete Evidence. Read `files`, `omissions`, `candidates`, `components` or
`next_probes` with `inspect_analysis_view` kind `desktop-application`, selecting
exact paths, batched file/omission IDs or families and only needed fields and pages.
Summary `probe_issues` retains counts and bounded previews. Select files with
`has_issues: true` and fields `path`, `read_status`, `issues` to retrieve exact
failures directly; preview text is display data, while `file_id` selects full facts. Preserve source
coverage, read-range identity and unknowns; directory snapshot identity is not
a digest of every file's contents. Component path markers do not establish
runtime presence. For compact CLI output, use
`inspect-desktop-application PATH --detail summary --evidence_output BUNDLE`.
See [desktop installations](https://github.com/morluto/rea/blob/main/docs/desktop-applications.md).

## Go build metadata

Use `inspect_go_binary` for an explicit local ELF, PE or thin Mach-O when the
question concerns the embedded compiler version, module/dependency versions,
local replacements or build settings. No `open_binary`, Go installation or
target execution is required. The CLI equivalent is `inspect-go-binary PATH`.
Preserve artifact SHA-256, original file ranges, framed module bytes and every
unparsed module-text line. A missing record is an unknown, not proof of a
non-Go binary; observed metadata does not authenticate its claims. Function,
source and type recovery remain a separate native-analysis question.

## IL2CPP metadata

Use `inspect_il2cpp_metadata` for an explicit local Unity `global-metadata.dat`
(versions 29, 31 and 39) when the question concerns assembly images, type or method names,
namespaces or index ranges. No `open_binary`, Unity installation or target
execution is required. The CLI equivalent is `inspect-il2cpp-metadata PATH`.
MCP defaults to counts with complete retained Evidence. Query `sections`,
`images`, `types` or `methods` through `inspect_analysis_view`; use exact names,
batch indices and selected fields. Row indices are scoped by artifact SHA-256
and collection; page offsets count filtered matches. Preserve
artifact SHA-256 and index widths. Unrecognized magic may mean encryption and
is unsupported, not decrypted. Linking names to `GameAssembly` or
`UnityFramework` code addresses remains a separate native-analysis question.
See [IL2CPP metadata](https://github.com/morluto/rea/blob/main/docs/il2cpp-metadata.md).

## Rust dependency metadata

Use `inspect_rust_binary` for an explicit local ELF, PE, or thin Mach-O when
the question concerns the cargo-auditable crate list embedded in `.dep-v0`
(Mach-O: `__DATA,.dep-v0`). No `open_binary`, Rust installation, or target
execution is required. The CLI equivalent is `inspect-rust-binary PATH`.
Preserve artifact SHA-256, package order, dependency indices, and the section
file range. A missing section is null metadata, not proof the binary has no
dependencies. An omitted package kind stays null. A rustc commit hash is
inferred from a read-only `/rustc/<40-hex>/` path and does not by itself
identify the compiler. See [Rust binaries](https://github.com/morluto/rea/blob/main/docs/rust-binaries.md).

## SQLite snapshots

Use `inspect_sqlite_database` with an explicit local database snapshot for its
schema and optional rows from one exact ordinary table. It requires Node.js
24.x >=24.15 or 26+ with the native `DatabaseSync.limits` API. It also consumes the
existing sibling `-wal`; retain both original digests when citing its result.
Default output is a compact inventory; a selected table expands only its own
schema and samples 20 rows. Select `columns` to avoid irrelevant or large cells,
and request `schema_scope: "database"` only for complete schema details.
Choose `row_limit` when a finite sample is useful and keep truncation and
unspecified row order explicit. Virtual tables, shadow tables and views are
schema facts, not row-read targets. REA inspects private copies and leaves
the source files untouched; obtain a coherent quiescent database/WAL snapshot
before inspection. See [SQLite snapshots](https://github.com/morluto/rea/blob/main/docs/sqlite-databases.md).

## Recorded Linux crashes

Use `inspect_recorded_crash` with an explicit Linux x86-64 ELF core path to
inspect historical thread registers, signals, raw notes and original file
ranges. It is independent of the active disassembler target. Source-bound
register values and note bytes are observations; missing notes, signal-thread
association and current executable/library identity remain unknown. PIDs are
historical metadata and never authorize live attach or control.

The optional `include_debugger_context` facet adds mapping candidates through
caller-supplied GDB/pwndbg in an owned core-only session. Display names do not
establish current file identity; zero reported flags leave permissions unknown.
Requested unavailable context fails with setup guidance. See
[recorded crashes](https://github.com/morluto/rea/blob/main/docs/recorded-crashes.md)
for exact upstream profiles, bounds and verification coverage.

## Offline ELF layout

Use `inspect_binary_layout` with an explicit local ELF path for file-backed
sections, symbols, relocations, linkage names, and static mitigation inferences
without opening a disassembler target. When that complete record is already
retained, call `inspect_analysis_view` for a summary, mitigations or linkage
facet, one section or symbol, or a stable page. Do not re-run the decoder to
read a single object.

## Offline WASM

Use `inspect_wasm_artifact` with caller-supplied WABT for selected local bytes.
For counts, validation and WAT identity, select `detail: "summary"` on the first
MCP call. The complete original Evidence stays retained; use
`normalized_result.parent_evidence_id` for exact exports or text pages. Omitted
or complete detail keeps the existing complete result.
For a completed result, use `inspect_analysis_view` with its reported retained
reference for a summary or `view: {kind: "wasm", facet: "exports", offset: 0, limit: 32}`.
Facets also include sections, imports, candidates, glue, WAT, headers, details
and tool profile. Text offsets count UTF-16 code units; follow `next_offset`.
The complete source remains retained after an oversized MCP reply. No target
execution or network acquisition is implied, and WAT is decoded representation.

## Native targets

After `open_binary`, use focused search, procedure, or function tools directly.
Use `binary_overview` when target metadata or inventory context helps answer the
question. Prefer literal search, names, decompilation, callers, callees, and
cross-references. Addresses and recovered pseudocode are analysis observations,
not original source. Provider unavailability and unsupported metadata remain
unknown rather than false.

For a completed `analyze_function` dossier, use `inspect_analysis_view` with
`view: {kind: "native", facet: "value_flow_operations", offset: 0, limit: 32}`
and the exact retained Evidence ID to read selected facts without reanalysis.
Native facets also include procedure, pseudocode, assembly, basic blocks,
comments, callers/callees, references, unresolved calls, referenced strings and
names, the native API record, and value-flow summaries. Pseudocode offsets and limits count UTF-16
code units; use the returned `next_offset` for continuation. Provider limitations
and unavailable facts remain explicit; the complete parent Evidence is retained.

`inspect_macho` on a large framework returns megabytes of imports and exports.
Select `detail: "summary"` for slice identity, UUID and per-collection counts,
then page rows with `view: {kind: "macho", facet: "exports", offset: 0, limit: 64}`
and `normalized_result.parent_evidence_id`. Facets are entrypoints,
architectures, build_metadata, load_commands, dependencies, imports, exports,
segments and provenance. `source_exhaustive: false` means unreturned symbols
may exist.

To see which functions or Objective-C methods a Mach-O actually calls in one
run, use `observe_native_calls` with explicit breakpoints and a bounded
`duration_ms`/`max_events`. It launches a new process under LLDB, so the target
runs and may change files or use the network. Hardened-runtime targets need the
`get-task-allow` entitlement.

Use `binary_session` with no arguments to check the open target, selected
provider, and alignment. Its default `result.tool_availability` carries a
complete inventory grouped by shared facts. Expand each group's `names` and
inherit the inventory-level client requirements unless a group overrides them;
availability, reasons, remediation, modes, and flags remain inline. The
`effects` and `annotations` arrays name true flags from fixed vocabularies, so an
omitted known flag is false. `tools/list` remains the canonical source for full
tool schemas when target or provider state changes.

Provider capability groups carry provider identity and ordered limitations.
Prepend each set's `shared_limitations` to a group's `limitations` to recover the
operation's full ordered list. Candidate capabilities describe possible
providers. Top-level session capabilities describe the current route, and
`analysis_provider_binding` identifies the selected provider.

## Static memory and original file bytes

Where the selected provider offers it, `read_bytes` reads initialized analysis
memory, including loader fixups; it does not read a running process. The Ghidra
provider does not offer `read_bytes`. Check `returned_bytes` and `complete`
before decoding a table. An incomplete read is missing coverage, not a zero-filled
tail. Use `list_segments` to inspect the selected block's initialization and address-space
facts, and retain unavailable facts as unknown.

Use `address_to_file_offset` to anchor one observed address to original file
bytes. A mapping for the first address does not establish a contiguous mapping
for an entire table, and loader fixups can make analysis bytes differ from source
bytes. Keep source ranges and analysis-memory observations separate.

A pointer table can refer to writable slots populated by a constructor rather
than directly to immutable resources. An uninitialized block or an observed zero
does not establish the slot's later runtime value. Follow `xrefs` and the relevant
writer's assembly or pseudocode; distinguish recorded assignments from inferred
execution order. Do not replace unreadable bytes with zeros or conclude that a
resource is absent without the necessary initialization evidence.

## Function bodies and dispatch metadata

ELF virtual addresses are distinct from file offsets; never assume an arbitrary
offset plus image base is an analysis address.

Complete function body ranges use inclusive ends and can contain gaps. Do not
treat the enclosing span as code.
For packed targets, retain the original and separately derived artifact identities;
decompiling an unpacking stub does not recover the unpacked program.

When reading Objective-C dispatch metadata, distinguish class implementation
methods from protocol requirements: class methods report null requirement
flags, while decoded protocol declarations retain required and optional facts.
Property attributes remain raw name/value tokens; use the property's
`atomicity` field for the decoded `N` marker or the default atomic behavior.
Null class/meta flags, ivar counts, atomicity, or read-only values mean the
selected provider did not establish that fact. Symbol names alone do not prove
that a class is a root class or has no ivars.

## Managed PE/CLI

Start with `inspect_managed_artifact`. REA's canonical managed inspection is
execution-free: do not claim it loaded, reflected, executed, or resolved the
assembly. Keep managed/native boundaries and unavailable reconstruction facts
explicit. A bring-your-own reconstruction oracle is separate from the canonical
parser and must not become an implicit setup dependency.

For identity/classification questions, `inspect_managed_artifact` can explicitly
select `detail: "summary"` on the first MCP call. It retains complete metadata
and returns a linked overview with full classification/evidence, nullable
module/MVID, frameworks, metadata coverage/issues/limitations and returned-row
counts. Default complete requests remain unchanged. Read original rows with
`inspect_analysis_view`, source `normalized_result.parent_evidence_id`, and
`view: {kind: "managed", collection: "attributes", offset: 0, limit: 16}`.
Collections are `references`, `resources` and `attributes`. Paging does not
repeat parsing. Returned-row exhaustion
does not prove complete metadata or absence under partial/unavailable coverage;
preserve build-local tokens and their artifact/MVID scope.

`inspect_managed_members` always returns the assembly-wide `member_refs`, even
for one selected type. For questions about a selected type, select
`detail: "summary"` with `type_names`; it returns the selection (with unmatched
names), coverage and per-collection counts. Page rows with
`view: {kind: "managed-members", collection: "call_edges", offset: 0, limit: 64}`
over `types`, `exported_types`, `fields`, `methods`, `member_refs`, `call_edges`,
`field_accesses` or `user_strings`.

### .NET NativeAOT

NativeAOT binaries contain native machine code, so ordinary CIL decompilers
cannot recover the original method bodies. When managed metadata/CIL is absent,
classify that as a native-analysis route rather than claiming source recovery.
Open the native image with the selected deep provider and inspect functions,
strings, calls, and references; describe decompiler output as pseudocode and
inference.

NativeAOT images can be PE/COFF, ELF, or Mach-O executables and shared
libraries. Use file bytes and loader metadata rather than suffixes to identify
them. For packaged apps, inventory/extract with REA's artifact tools and retain
the exact contained image identity. PDB, ELF debug, or dSYM sidecars are
additional evidence only when the provider accepts and matches them.

REA has a built-in read-only snapshot parser for x64 PE targets with .NET 8 RTR
9.1 metadata. Read frozen literals from its report, because `search_strings`
does not include them. Preserve binary identity and distinguish derived
metadata from provider observations. Recovered types and native pseudocode are
not original C# source.

## Packages and extraction

Use `inspect_artifact` for application bundles, archives, ZIP/APK/IPA/MSIX/AppX,
ASAR, or DMG inputs when the artifact graph and findings help answer the
question. It returns the complete artifact graph inline. Cite graph manifest
IDs when using them.

For an IPA or a macOS `.app`, ZIP, or DMG, pass the inventory Evidence to
`project_apple_application_graph`. It reports application roots and nested
bundles by path convention: app extensions, XPC services, frameworks, login
items, system and driver extensions, and plug-ins. It also lists privileged
helpers, launchd plists, symlinks, and each bundle's `info_plist_path` and
executable candidates. Roles are path conventions, not parsed plists; read the
listed plists with `inspect_plist`.

After `open_binary` on a `.app` or Mach-O, use `trace_dylib_resolution` to see
which file each `@rpath`, `@loader_path` and `@executable_path` load reaches for
every executable in the bundle. It also lists missing or weak loads and earlier
`@rpath` candidates that are absent. Narrow large bundles with `roots` or
`architecture`. System paths stay undetermined because the dyld shared cache
provides them.

Use `extract_artifact` when materialized files are needed. It extracts the active
target and accepts optional `integrity_policy`; see the [MCP contracts](https://github.com/morluto/rea/blob/main/docs/mcp-contracts.md).
It materializes all regular files into a fresh temporary directory chosen by
REA. Symlinks and encrypted entries are inventory facts, not extractable files.
The result reports the materialized directory; callers do not choose the
destination. No separate permission grant is needed.

Native DMG traversal automatically uses a read-only mount on supported macOS
hosts, with an owned temporary mount directory and cleanup. It needs no approval
flag. Unsupported hosts or mount failures remain explicit limitations; do not
claim child inventory when only root identity is available. Extraction is a
separate filesystem-writing operation.

No deep provider admits headerless raw images, DOS MZ, or DOS COM files. Report
such targets as unsupported for deep analysis rather than forcing a format;
artifact and firmware tools can still inventory or extract them.

### Ghidra provider scope

The Ghidra provider (`ghidra-rust`) is a locally built worker on macOS and
Linux for thin ELF, PE, and Mach-O executables on x86, x86-64, ARM, and AArch64.
It lists segments and procedures, searches procedure names, resolves names and
procedure addresses, and returns pseudocode (`procedure_pseudo_code`,
`batch_decompile`). It does not provide strings, xrefs, call graphs, assembly,
`read_bytes`/`search_bytes`, `analyze_function`, `binary_overview`,
annotations, or renames, and its functions come from loader symbols and
function-start metadata rather than function discovery. Use Hopper or IDA when
the question needs those operations, and check `binary_session`
`tool_availability` before choosing a tool.

## Offline PE resource inventory

Use `inspect_pe_resources` with an absolute `path`, or
`rea inspect-pe-resources ./selected.exe --json`, for portable PE32/PE32+
resource inspection without opening a native target. Preserve returned Evidence:
type/name/language IDs and UTF-16 names, original directory/data/payload ranges,
code pages, payload hashes and static icon-group references. Same-language icon
resolution is explicit; missing references and size mismatch remain visible.
Other payloads are opaque, and this operation does not decode images or simulate
Windows resource loading. Consult the budgets and supported tree profile in
[offline binary diagnostics](https://github.com/morluto/rea/blob/main/docs/binary-diagnostics.md).

For exact core-module import/export differences, use `compare_wasm_interfaces`
with two complete inspection Evidence records (or current-session retained
references) and explicit scope. Preserve unknown types/duplicate names; static
interface equality is not runtime compatibility. CLI accepts complete inline
Evidence in `rea compare-wasm-interfaces input.json --json`.
