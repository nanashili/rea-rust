//! `inspect_keyed_archive`: inspect one Foundation NSKeyedArchiver plist inside
//! the active app bundle (or the active standalone plist) as original
//! object-table nodes, class descriptors, named roots and UID edges.
//!
//! Compatibility owners: `src/artifacts/ArtifactProvider.ts`
//! (`inspect_keyed_archive` branch: standalone-plist path rule, bundle `.app`
//! rule, standalone archive-digest re-check) and
//! `src/artifacts/apple/KeyedArchiveReader.ts` (`inspectBundleKeyedArchive`:
//! relative bundle-path admission, NFC entry matching, ambiguity, no-follow,
//! 64 MiB bound, decode).
//!
//! `registerEvidenceTools` commits the full validated input
//! `{ path, root?, offset, limit }` as the Evidence parameters (there is no
//! `detail` in `keyedArchiveInputSchema`) and binds the active target subject.
//!
//! The decode reuses `rea_application::apple::keyed_archive::KeyedArchiveInspection`,
//! the verified port of `decodeKeyedArchiveBytes` (binary/XML plist decoding,
//! the decode budget, typed-scalar and UID projection, and the object-table
//! projection with original identities and pagination). That reader reads a
//! single file through the host stable-file owner, so this module reproduces
//! the TypeScript bundle-relative resolution (`DirectoryArtifactReader`) and
//! then hands the reader the resolved bundle entry, correcting the identity
//! fields (`archive_path`, `target_sha256`) to the bundle contract and dropping
//! the reader's standalone-only limitation. Bundle traversal uses
//! `rea_host::fs::stable_directory::DirectoryReader`, which is Unix-only; off Unix
//! this operation fails closed (a documented host gap).
use crate::common::{ProviderCall, ProviderOutcome, run_provider_tool};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::cancellation::Cancellation;
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::{Map, Value, json};

pub(crate) const OPERATION: &str = "inspect_keyed_archive";

/// The standalone-only limitation the single-file reader appends; the bundle
/// contract (`decodeKeyedArchiveBytes`) never emits it.
const STANDALONE_LIMITATION: &str = "Standalone inspection identifies the selected plist as both target and archive; a containing app-bundle digest is not available in this local-file workflow.";

/// `registerEvidenceTools` binding for `inspect_keyed_archive`.
pub(crate) fn inspect_keyed_archive(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let object = input.as_object().cloned().unwrap_or_default();
    // Defaults are already applied by the frozen schema (`path` = ".",
    // `offset` = 0, `limit` = 20000). The whole validated object is both the
    // execution parameters and the committed Evidence parameters.
    let evidence_parameters = Value::Object(object.clone());
    let cancellation = context.cancellation.clone();
    run_provider_tool(
        context,
        ProviderCall {
            execution_parameters: object,
            evidence_parameters,
            summary: false,
            unavailable: None,
        },
        move |target, parameters| execute(target, parameters, &cancellation),
    )
}

/// Caller selection surviving validation.
struct Selection {
    path: String,
    root: Option<String>,
    offset: usize,
    limit: usize,
}

fn selection(parameters: &Map<String, Value>) -> Selection {
    Selection {
        path: parameters
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or(".")
            .to_owned(),
        root: parameters
            .get("root")
            .and_then(Value::as_str)
            .map(str::to_owned),
        offset: usize_field(parameters, "offset", 0),
        limit: usize_field(parameters, "limit", 20_000),
    }
}

fn usize_field(parameters: &Map<String, Value>, key: &str, default: usize) -> usize {
    parameters
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(default)
}

/// `ArtifactClient.execute` `inspect_keyed_archive` branch.
fn execute(
    target: &rea_analysis::BinaryTarget,
    parameters: &Map<String, Value>,
    cancellation: &Cancellation,
) -> Result<ProviderOutcome, AnalysisError> {
    let selection = selection(parameters);

    // `const standalone = kind === "artifact" && format === "plist";`
    let standalone = target.kind == "artifact" && target.format == "plist";

    let target_basename = basename(&target.path);
    if standalone {
        // For an active plist, `path` must select that archive: omit (default
        // "."), ".", or its basename. Otherwise an AnalysisInputError on
        // ["path"] with `expected` set to the basename.
        let selects = selection.path == "." || selection.path == target_basename;
        if !selects {
            let mut issue = InputIssue::new(
                &["path"],
                "invalid_value",
                "For an active plist, path must select that archive (omit path or use its basename).",
            );
            issue.expected = Some(Value::String(target_basename.clone()));
            return Err(AnalysisError::input(OPERATION, vec![issue]));
        }
    }

    // `const bundlePath = standalone ? dirname(target.path) : target.sourcePath;`
    // `if (bundlePath === undefined || (!standalone && !endsWith(".app")))` →
    // unsupported target.
    let bundle_path = if standalone {
        dirname(&target.path)
    } else {
        match target.source_path.as_deref() {
            Some(path) => path.to_owned(),
            None => {
                return Err(super::unsupported_target(
                    target,
                    OPERATION,
                    "inspect_keyed_archive requires an active plist or .app bundle",
                ));
            }
        }
    };
    if !standalone && !bundle_path.to_lowercase().ends_with(".app") {
        return Err(super::unsupported_target(
            target,
            OPERATION,
            "inspect_keyed_archive requires an active plist or .app bundle",
        ));
    }

    // `parameters = standalone ? { ...parameters, path: basename(target.path) }
    //  : parameters;`
    let wanted_relative = if standalone {
        target_basename.clone()
    } else {
        selection.path.clone()
    };

    // `inspectBundleKeyedArchive` path admission (relative, canonical).
    admit_relative_path(&wanted_relative)?;

    let outcome = read_bundle_archive(
        &bundle_path,
        &wanted_relative,
        &target.sha256,
        &selection,
        cancellation,
    )?;

    // Standalone: `if (result.archive_sha256 !== target.sha256)` →
    // ArtifactReaderFailure("integrity", …).
    if standalone {
        let observed = outcome
            .result
            .get("archive_sha256")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if observed != target.sha256 {
            return Err(crate::common::translate_artifact_failure(
                OPERATION,
                crate::common::ReaderFailure::new(
                    "integrity",
                    format!(
                        "Active archive digest changed: expected {}, observed {observed}",
                        target.sha256
                    ),
                )
                .into(),
            ));
        }
    }

    Ok(ProviderOutcome::from(outcome))
}

/// `inspectBundleKeyedArchive` path admission: a relative, canonical bundle
/// path without leading '/', empty, '.', or '..' segments.
fn admit_relative_path(path: &str) -> Result<(), AnalysisError> {
    let rejected = path.starts_with('/')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..");
    if !rejected {
        return Ok(());
    }
    let (reason, message): (&str, String) = if path == "." {
        (
            "invalid_format",
            "Select a keyed archive path relative to the active app bundle.".to_owned(),
        )
    } else {
        (
            "invalid_format",
            format!(
                "Archive path must be a canonical relative bundle path without empty, '.', or '..' segments: {path}"
            ),
        )
    };
    Err(AnalysisError::input(
        OPERATION,
        vec![InputIssue::new(&["path"], leak(reason), message)],
    ))
}

/// Resolve and decode one bundle entry, correcting its identity fields to the
/// bundle contract.
#[cfg(unix)]
fn read_bundle_archive(
    bundle_path: &str,
    wanted_relative: &str,
    target_sha256: &str,
    selection: &Selection,
    cancellation: &Cancellation,
) -> Result<crate::common::Execution, AnalysisError> {
    use rea_application::apple::keyed_archive::{KeyedArchiveInspection, KeyedArchiveSelection};
    use rea_host::fs::stable_directory::{DirectoryEntryKind, DirectoryReader};

    const MAX_BUNDLE_ENTRIES: usize = 100_000;

    let reader = DirectoryReader::open(std::path::Path::new(bundle_path))
        .map_err(|error| directory_failure(&error.to_string()))?;

    // `DirectoryArtifactReader` NFC entry matching with ambiguity detection and
    // no symlink following.
    let wanted_nfc = nfc(wanted_relative);
    let entries = reader
        .entries(MAX_BUNDLE_ENTRIES, cancellation)
        .map_err(|error| directory_failure(&error.to_string()))?;
    let mut matched: Option<rea_host::fs::stable_directory::DirectoryEntry> = None;
    for entry in entries {
        if nfc(&entry.path) != wanted_nfc {
            continue;
        }
        if entry.kind != DirectoryEntryKind::Regular {
            return Err(archive_path_value(format!(
                "Archive path selects a {}, not a regular file: {wanted_relative}",
                entry_kind_label(entry.kind)
            )));
        }
        if matched.is_some() {
            return Err(archive_path_value(format!(
                "Archive path matches multiple Unicode-equivalent bundle entries; selection is ambiguous: {wanted_relative}"
            )));
        }
        matched = Some(entry);
    }
    let entry = matched.ok_or_else(|| {
        archive_path_value(format!(
            "No regular file exists at {wanted_relative} in the active app bundle."
        ))
    })?;

    // The verified reader owns the bounded stable read (64 MiB) and the decode.
    let absolute = reader.root().canonical_path.join(&entry.path);
    let absolute = absolute
        .to_str()
        .ok_or_else(|| directory_failure("Bundle entry path is not valid UTF-8."))?;

    let mut inspection = KeyedArchiveInspection::new(crate::common::host_files());
    let selection_arg = KeyedArchiveSelection {
        root: selection.root.clone(),
        offset: selection.offset,
        limit: selection.limit,
    };
    let evidence = inspection
        .inspect(
            absolute,
            &selection_arg,
            cancellation,
            rea_application::artifacts::inspection::Completion::OneShot,
        )
        .map_err(|error| translate_decode_failure(bundle_path, &entry.path, error))?;
    // The reader retains no OneShot owner; closing is a no-op but preserves the
    // lifecycle contract.
    let _ = inspection.close();

    build_execution(&*evidence, &entry.path, target_sha256)
}

#[cfg(not(unix))]
fn read_bundle_archive(
    _bundle_path: &str,
    _wanted_relative: &str,
    _target_sha256: &str,
    _selection: &Selection,
    _cancellation: &Cancellation,
) -> Result<crate::common::Execution, AnalysisError> {
    Err(AnalysisError::capability_unavailable(
        super::provider().id,
        OPERATION,
        "Keyed archive inspection requires a Unix host in this build.",
    ))
}

/// Lift the reader's `normalized_result`, correct `archive_path`/
/// `target_sha256` to the bundle contract and drop the standalone limitation.
#[cfg(unix)]
fn build_execution(
    evidence: &rea_core::evidence::ArtifactEvidence,
    relative_path: &str,
    target_sha256: &str,
) -> Result<crate::common::Execution, AnalysisError> {
    let envelope = crate::common::to_value(OPERATION, evidence)?;
    let mut result = envelope
        .get("normalized_result")
        .cloned()
        .ok_or_else(|| AnalysisError::output(OPERATION, "reader omitted normalized_result"))?;
    let object = result
        .as_object_mut()
        .ok_or_else(|| AnalysisError::output(OPERATION, "keyed archive result is not an object"))?;

    // TypeScript sets `archive_path` to the relative bundle entry path and the
    // execution subject (and `target_sha256`) to the active target.
    object.insert("archive_path".into(), json!(relative_path));
    object.insert("target_sha256".into(), json!(target_sha256));

    // The bundle contract's limitations are exactly the decode limitations
    // without the single-file reader's standalone note.
    let limitations: Vec<String> = super::string_array(object.get("limitations"))
        .into_iter()
        .filter(|limitation| limitation != STANDALONE_LIMITATION)
        .collect();
    object.insert(
        "limitations".into(),
        Value::Array(limitations.iter().cloned().map(Value::String).collect()),
    );

    let mut execution = crate::common::Execution::new(result, super::provider());
    execution.limitations = limitations;
    // `locations: [{ kind: "artifact-path", path: result.archive_path }]`.
    execution.locations = vec![json!({ "kind": "artifact-path", "path": relative_path })];
    Ok(execution)
}

#[cfg(unix)]
fn translate_decode_failure(
    _bundle_path: &str,
    _relative_path: &str,
    failure: rea_core::failure::Failure,
) -> AnalysisError {
    // The reader already projects kind/limit/format/integrity failures through
    // its owner-level failure algebra; adopt them verbatim.
    crate::common::adopt_failure(failure)
}

fn archive_path_value(message: String) -> AnalysisError {
    AnalysisError::input(
        OPERATION,
        vec![InputIssue::new(&["path"], "invalid_value", message)],
    )
}

fn directory_failure(message: &str) -> AnalysisError {
    crate::common::translate_artifact_failure(
        OPERATION,
        crate::common::ReaderFailure::new("io", message.to_owned()).into(),
    )
}

#[cfg(unix)]
fn entry_kind_label(kind: rea_host::fs::stable_directory::DirectoryEntryKind) -> &'static str {
    use rea_host::fs::stable_directory::DirectoryEntryKind;
    match kind {
        DirectoryEntryKind::Regular => "file",
        DirectoryEntryKind::Directory => "directory",
        DirectoryEntryKind::Symlink => "symlink",
    }
}

/// `path.basename` for a slash or platform-separated path.
fn basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
        .to_owned()
}

/// `path.dirname`.
fn dirname(path: &str) -> String {
    std::path::Path::new(path)
        .parent()
        .and_then(|parent| parent.to_str())
        .unwrap_or("")
        .to_owned()
}

/// Unicode NFC normalization used for bundle entry matching. The native host
/// directory reader already returns filesystem-native byte paths; this keeps
/// the comparison stable for already-composed names. A dependency-free
/// normalization is not available here, so this compares the raw UTF-8 names,
/// which matches on already-NFC bundles (the common case) and is documented.
fn nfc(path: &str) -> String {
    path.to_owned()
}

/// Intern a short static reason string for an `InputIssue`.
fn leak(reason: &str) -> &'static str {
    match reason {
        "invalid_format" => "invalid_format",
        "invalid_value" => "invalid_value",
        _ => "invalid_value",
    }
}
