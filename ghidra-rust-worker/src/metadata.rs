use serde_json::{Value, json};

use crate::protocol::*;

// v6: inventory excludes loader symbols outside executable sections and
// saves additional loader names per entry (aliases).
// v7: callees discovered as non-returning from call-site evidence change
// pseudocode.
// v8: v7 could decode non-executable bytes, which corrupted later pseudocode.
// v9: strings, derived references, instruction listings and byte reads.
// v10: authenticate universal artifacts, then analyze a selected architecture slice.
// v11: expose bounded source-backed image mapping and masked byte search.
// v12: expose one structured decoder observation.
// v13: combine these facts with named PE exports in the frozen inventory.
pub const CACHE_ID: &str = "ghidra-rust-268c3a4-v13";

pub fn engine() -> Value {
    json!({
        "provider": "ghidra-rust",
        "engine_version": "2.1.0",
        "engine_revision": "268c3a406d8d964bc00ae2ead4d3e1e1373aaa27",
        "cache_id": CACHE_ID,
        "snapshot_schema": 1,
        "worker_protocol_version": WORKER_PROTOCOL_VERSION,
        "worker_protocol_name": WORKER_PROTOCOL_NAME,
        "host_architecture": std::env::consts::ARCH,
        "inventory_policy": "saved-or-loader-v1",
        "analysis_policy": {
            "strings": "file-backed-data-sections-nul-terminated-utf8-v1",
            "references": "linear-pcode-constant-propagation-v1",
            "image_map": "verified-file-backed-ranges-v1",
            "search_bytes": "masked-file-backed-ranges-v1",
            "inspect_instruction": "decoder-pcode-observation-v1"
        },
        "program_lifecycle": {
            "max_decompile_attempts": crate::program_retention::MAX_DECOMPILE_ATTEMPTS,
            "idle_release_seconds": crate::program_retention::IDLE_RELEASE_AFTER.as_secs()
        },
        "universal_policy": "select-host-architecture",
        "formats": ["Elf", "Pe", "MachO"],
        "architectures": ["I386", "X86_64", "Arm", "Aarch64"],
        "limits": {
            "request_bytes": MAX_REQUEST_BYTES,
            "frame_bytes": MAX_FRAME_BYTES,
            "batch_bytes": MAX_BATCH_BYTES,
            "pseudocode_bytes": MAX_PSEUDOCODE_BYTES,
            "function_name_bytes": MAX_NAME_BYTES,
            "selector_bytes": MAX_NAME_BYTES,
            "address_bytes": MAX_ADDRESS_BYTES,
            "batch_size": MAX_BATCH_SIZE,
            "resolution_selectors": MAX_RESOLUTION_SELECTORS,
            "function_page": MAX_FUNCTION_PAGE,
            "function_alias_page": MAX_ALIAS_PAGE,
            "inventory_functions": MAX_INVENTORY,
            "inventory_name_bytes": MAX_INVENTORY_NAME_BYTES,
            "target_bytes": MAX_TARGET_BYTES,
            "database_cache_bytes": DATABASE_CACHE_BYTES,
            "instructions_per_function": 65_536,
            "string_page": crate::analysis::MAX_STRING_PAGE,
            "string_min_characters": crate::analysis::image::MIN_STRING_CHARACTERS,
            "string_bytes": crate::analysis::image::MAX_STRING_BYTES,
            "reference_page": crate::analysis::MAX_REFERENCE_PAGE,
            "instruction_page": crate::analysis::MAX_INSTRUCTION_PAGE,
            "read_bytes": crate::analysis::image::MAX_READ_BYTES,
            "search_pattern": crate::analysis::MAX_SEARCH_PATTERN,
            "search_results": crate::analysis::MAX_SEARCH_RESULTS,
            "image_map_ranges": 4096
        }
    })
}

pub fn limitations() -> Vec<String> {
    [
        "The inventory is frozen from loader function symbols, named PE exports in executable sections, the entry point, and Mach-O function-start metadata; symbols outside executable sections and forwarded PE exports are excluded. Each entry address has one row with one primary name; other loader symbols or PE export names at that entry (for example identical-code-folded functions) are saved as aliases, listed by function_aliases and accepted as selectors. Decompilation accepts only addresses selected from that saved inventory. The engine may define the one requested symbol when loader metadata omitted it; the worker does not enumerate or queue other functions during a saved selection.",
        "Saved inventory and completed pseudocode persist; the engine has no Program serialization API. A loaded Program is reused for at most 512 actual decompile attempts and released after 30 seconds without decompiler activity. This bounds its lifetime, not process RAM; an in-flight operation is not interrupted for idle eviction.",
        "Mach-O symbol stubs are named from the indirect symbol table, and calls to known non-returning functions (Ghidra's Mach-O, ELF and PE lists plus the Itanium unwinder) end flow. Other non-returning functions are not discovered. An unconditional branch from a function's extent (up to the next inventory entry) to another inventory entry is decompiled as a tail call; conditional tail branches are still followed.",
        "Uncached functions in one batch are decompiled on up to REA_GHIDRA_RUST_DECOMPILE_THREADS Programs in parallel (default 1), each holding its own copy of the target; results are returned in request order. A Program's earlier decompiles can change later output for the same function, so pseudocode depends on decompile history.",
        "The 256 MiB input cap, 32 MiB admitted function-name budget, output caps, and 4 MiB database cache do not enforce a process RAM limit; engine allocations remain unbounded by this protocol.",
        "Function analysis is capped at 65,536 instructions. A single function can exceed the external request deadline; the parent process owns timeout termination.",
        "Section ranges are reported; complete segment permissions and coverage of unindexed functions are unknown.",
        "batch_decompile_inventory is a bounded native paging primitive. A full-engine export requires a separate resumable artifact or job contract.",
        "Saved-state storage has no disk quota or eviction. Corrupt saved state is preserved and requires an operator to repair it or choose a new empty cache directory.",
        "Strings are NUL-terminated printable UTF-8 runs of at least 4 characters in file-backed data and string sections, starting at a section start or after a NUL; runs over 64 KiB, UTF-16 and other encodings, and strings in executable or zero-fill sections are not reported. An empty search does not establish that text is absent from the artifact.",
        "References are derived once per inventory, in parallel, by a linear p-code pass over each function's extent (from its entry to the next inventory entry, inside executable sections) and saved with the inventory. Direct calls, unconditional and conditional branches to other inventory entries, and mapped addresses consumed by loads, stores and other uses after constant propagation through registers are recorded; branches within a function, indirect targets, values passed through memory, and code outside inventory extents are not.",
        "Instruction listings and byte reads are linear: instructions run from the entry to the next inventory entry or the end of the executable section, and bytes come from file-backed section contents without loader fixups.",
        "Universal Mach-O inputs are authenticated as whole files, then the host architecture slice is selected (with a deterministic supported-slice fallback) before analysis; slice selection is read-only.",
        "This is REA's line-delimited JSON-RPC worker protocol over a third-party Rust decompiler; it is not an upstream Ghidra protocol or the Java Ghidra application.",
    ]
    .map(str::to_owned)
    .to_vec()
}
