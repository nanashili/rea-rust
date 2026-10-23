# Native wire contract sources

These declarative JSON contracts are compiled into the Rust adapter. Neither
native builds nor runtime execution reads the Node runtime or cached tool catalog.
Named handlers bind inspection arguments and retained-record queries to their
concrete Rust application results; catalog position never selects an operation.

The inspect_rust_binary, inspect_go_binary, get_evidence_bundle,
export_evidence_bundle, import_evidence_bundle, list_unknowns,
verify_unknown_resolution, record_unknown and update_unknown contracts were
ported from the original named contracts and SDK projections. Their complete
projections are compared to the original SDK's actual tools/list results.
Public-workflow tests validate advertised schemas and actual results with the
real client.

During migration the old production contract remains the compatibility oracle.
The native JSON definition is the native wire source, not a build-time generated
catalog cache. Retire the corresponding old definitions at verified production
cutover; future native catalog/documentation projections should consume these
sources rather than maintain another equivalent schema description.
