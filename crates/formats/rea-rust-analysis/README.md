# Experimental static Rust analysis

This workspace member ports native-image and dependency-section interpretation
behind `inspect_rust_binary`. `image::read` accepts admitted ELF, PE or thin
Mach-O bytes and returns container identity, dependency metadata and inferred
compiler paths with exact source offsets. `rea-host` owns file acquisition and
`rea-application` creates Evidence for the experimental standalone CLI and stdio
MCP adapter. The current TypeScript production provider remains
authoritative until all compatibility and cutover checks pass.

Native headers are decoded once with checked file spans and a 16 MiB structural
budget. Section selection retains only dependency metadata and read-only ranges;
overlapping ranges are merged in place. Compiler-path search uses a reusable
byte-pattern finder and borrows repeated hash keys rather than allocating text
for each occurrence. These representation choices are not measured speedup claims.

`auditable::read` accepts one admitted `.dep-v0` or `__DATA,.dep-v0` section and
its source file offset. It provides:

- Complete zlib-stream validation, including checksum, truncation and trailing
  member/data rejection. Compressed input is capped at 1 MiB; decompression is
  bounded by the smaller of 8 MiB or 64 times the compressed size.
- UTF-8 and depth validation, strict package fields, preserved unknown format
  revisions, package ordering and duplicate dependency edges. Omitted kind and
  revision remain null rather than acquiring a guessed value.
- Admission against normalized representation expansion before building edges
  or reverse edges; iterative cycle detection avoids recursive stack growth.
- Tagged errors and a counting output writer that checks escaped JSON size
  without allocating another full serialized report.

## JSON text ownership

JSON strings can contain unpaired UTF-16 surrogate escapes accepted by the
existing JavaScript owner. A Rust `String` or `serde_json::Value` cannot represent
those values losslessly. Fields are therefore admitted through borrowed raw JSON
values and normalized into `JsonText`, not decoded through an intermediate Value
tree. Ordinary text remains a String. Unpaired code units remain escaped JSON
and return `None` from `as_str()`; they are not replaced with U+FFFD.

Serialize the typed report directly with `serde_json::to_writer` or `to_string`.
Do not convert it through `serde_json::Value` or invent a display string when
`as_str()` returns None. A future Evidence owner must preserve the same semantic
values through hashing, storage and transport; that integration is not yet done.

## Verification

Run the workspace checks in [the native guide](../README.md). Seven
public-interface tests cover a Node-zlib-produced golden, every truncated prefix
of that member, corrupted/trailing streams, schema errors, null versus omission,
numeric spellings, unknown revisions, dependency cycles, a 20,000-package chain,
resource stops and lossless surrogate serialization. Image tests cover both
widths/endian variants, PE alignment padding, overlapping ranges, long names,
source offsets, inference capacity and structural/malformed-input failures.
A locally compiled Mach-O fixture's complete image facts were compared with the
frozen public CLI baseline and matched, including both inferred compiler-path
offsets. The standalone native CLI subsequently matched the complete Evidence,
including its identifier. These checks do not establish full provider/platform
parity; host lifecycle tests and narrowly scoped timing measurements are separate.

The pinned Rust compression backend is used; no system zlib, compiler or provider
is installed by this library. The separate C interface currently exposes only
process-stat parsing, not this metadata reader.
