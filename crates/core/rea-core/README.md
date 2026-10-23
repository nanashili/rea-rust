# Experimental REA Rust core

This safe Rust crate begins the owned-runtime migration. It is **not** a
replacement executable and is not selected by production CLI/MCP composition.
The existing Ghidra worker remains independent and unchanged.

The first owner parses Linux process identity, relations and lifecycle from a
borrowed stat record without allocating a field array or copying start time.
It preserves the current TypeScript owner's safe-integer range, decimal source
spelling, whitespace rules and partial facts when flags are unreadable. Errors
are tagged instead of being collapsed to an absent result.

The status parser validates all four native UID values before returning the
effective UID. Missing, malformed and duplicate rows remain explicit failures.
Both owners share the numeric and whitespace interpretation in one private module.

Shared owners also preserve lossless UTF-16 JSON text, ECMAScript canonical
commitments, artifact Evidence identity and typed failure projections.
Evidence freezes producer results as lossless JSON before computing identity;
later producer mutation cannot change a committed or serialized observation.
Cancellation supports both ordinary reasons and preallocated atomic triggers without running
application code in a signal handler. Escaped output is counted before allocation.
Serde, SHA-256 and ECMAScript number-formatting dependencies are pinned and locked.

This crate does not read procfs, prove process ownership, signal a target or certify
exit. Native file acquisition and command interrupts live in `rea-host`;
authenticated process supervision and real Linux verification remain unported.

Run with the pinned Rust toolchain:

```sh
cd native/crates/core/rea-core
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt --check
```

The public-interface tests independently specify expected native fields, malformed
input rejection and partial-fact behavior. They do not establish real Linux
process ownership or full CLI/MCP parity. No performance benefit is measured yet.

The separate [C embedding adapter](../../platform/rea-ffi/README.md) exposes process-stat
parsing to a compiled C consumer. The core retains its unsafe-code prohibition;
pointer handling and C layout stay outside it.
