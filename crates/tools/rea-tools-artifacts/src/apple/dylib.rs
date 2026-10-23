//! `trace_dylib_resolution`: trace how dyld would resolve each Mach-O dylib
//! load for the active Mach-O, or for every executable in the active `.app`
//! bundle.
//!
//! Compatibility owners: `src/artifacts/ArtifactProvider.ts`
//! (`traceDylibResolution`: Mach-O/`.app` admission, `rootPath`/
//! `enumerateRoots` from `bundleInfoPlist`, `locations` per image) and
//! `src/artifacts/apple/DylibResolutionReader.ts` (`traceDylibResolution`:
//! input validation, root `realpath`, executable-root enumeration, per-root
//! admission, the dyld trace, per-image digests and the target digest
//! re-check) and `src/domain/apple/dylibResolution.ts` (the deterministic dyld
//! model and the result schema).
//!
//! The real trace reuses `rea_application::apple::dylib_resolution::trace_dylib_loading`
//! (the verified port of `traceDylibLoading`) over a lazily probed,
//! symlink-preserving `rea_host::fs::stable_directory::DirectoryReader` tree view
//! and `rea_rust_analysis::macho` header parsing. Bundle traversal and
//! no-follow file reads are Unix-only; off Unix the operation fails closed
//! (a documented host gap). Nothing is executed: this is pure header parsing.
use crate::common::{ProviderCall, ProviderOutcome, run_provider_tool};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::{Map, Value};

pub(crate) const OPERATION: &str = "trace_dylib_resolution";

/// `registerEvidenceTools` binding for `trace_dylib_resolution`.
pub(crate) fn trace_dylib_resolution(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let object = input.as_object().cloned().unwrap_or_default();
    // `dylibResolutionInputSchema` is `{ roots?, architecture? }` (no `detail`),
    // committed verbatim as the execution and the Evidence parameters.
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

/// `ArtifactClient.traceDylibResolution`.
fn execute(
    target: &rea_analysis::BinaryTarget,
    parameters: &Map<String, Value>,
    cancellation: &Cancellation,
) -> Result<ProviderOutcome, AnalysisError> {
    // `kind !== "executable" || !isMachOFormat(format)` → unsupported target.
    let is_macho = matches!(target.format.as_str(), "mach-o" | "mach-o-universal");
    if target.kind != "executable" || !is_macho {
        return Err(super::unsupported_target(
            target,
            OPERATION,
            "trace_dylib_resolution requires an active Mach-O or .app bundle target",
        ));
    }

    // Only a target opened from an app-bundle directory carries its Info.plist;
    // a regular file whose name ends in .app is a standalone image.
    // `bundle = bundleInfoPlist === undefined ? undefined : sourcePath;`
    let bundle = if crate::common::bundle_info_plist(target).is_some() {
        target.source_path.clone()
    } else {
        None
    };
    // `rootPath = bundle ?? dirname(targetPath); enumerateRoots = bundle !== undefined`.
    let root_path = bundle.clone().unwrap_or_else(|| dirname(&target.path));
    let enumerate_roots = bundle.is_some();

    trace(
        &root_path,
        &target.path,
        &target.sha256,
        enumerate_roots,
        parameters,
        cancellation,
    )
}

#[cfg(unix)]
fn trace(
    root_path: &str,
    target_path: &str,
    target_sha256: &str,
    enumerate_roots: bool,
    parameters: &Map<String, Value>,
    cancellation: &Cancellation,
) -> Result<ProviderOutcome, AnalysisError> {
    unix::trace(
        root_path,
        target_path,
        target_sha256,
        enumerate_roots,
        parameters,
        cancellation,
    )
}

#[cfg(not(unix))]
fn trace(
    _root_path: &str,
    _target_path: &str,
    _target_sha256: &str,
    _enumerate_roots: bool,
    _parameters: &Map<String, Value>,
    _cancellation: &Cancellation,
) -> Result<ProviderOutcome, AnalysisError> {
    Err(AnalysisError::capability_unavailable(
        super::provider().id,
        OPERATION,
        "Dylib resolution tracing requires a Unix host in this build.",
    ))
}

/// `path.dirname`.
fn dirname(path: &str) -> String {
    std::path::Path::new(path)
        .parent()
        .and_then(|parent| parent.to_str())
        .unwrap_or("")
        .to_owned()
}

#[cfg(unix)]
mod unix {
    use super::OPERATION;
    use crate::common::{Execution, ProviderOutcome};
    use rea_application::apple::dyld_paths::{self, PathLookup, TreeEntry, TreeView};
    use rea_application::apple::dylib_resolution::{
        self, DylibResolutionRequest, DylibTreeEntry, DylibTreeView, MachoImageFacts, MachoSlice,
    };
    use rea_core::analysis_error::{AnalysisError, InputIssue};
    use rea_core::cancellation::Cancellation;
    use rea_host::fs::stable_directory::{DirectoryEntryKind, DirectoryError, DirectoryReader};
    use serde_json::{Map, Value, json};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::Path;

    const MAX_IMAGE_BYTES: usize = 256 * 1024 * 1024;
    const MAX_DISCOVERY_ENTRIES: usize = 100_000;

    /// A lazily probed, symlink-preserving view of the analyzed root over a
    /// no-follow `DirectoryReader`. Mirrors `FilesystemTreeView`
    /// (`DylibResolutionReader.ts`).
    struct DirectoryView<'a> {
        reader: &'a DirectoryReader,
        cancellation: &'a Cancellation,
        entries: RefCell<BTreeMap<String, Option<DylibTreeEntry>>>,
        images: RefCell<BTreeMap<String, MachoImageFacts>>,
    }

    impl<'a> DirectoryView<'a> {
        fn new(reader: &'a DirectoryReader, cancellation: &'a Cancellation) -> Self {
            Self {
                reader,
                cancellation,
                entries: RefCell::new(BTreeMap::new()),
                images: RefCell::new(BTreeMap::new()),
            }
        }

        fn read_entry(&self, path: &str) -> Result<Option<DylibTreeEntry>, DirectoryError> {
            if let Some(entry) = self.entries.borrow().get(path) {
                return Ok(entry.clone());
            }
            let resolved = match self.reader.inspect_entry(path, self.cancellation)? {
                None => None,
                Some(entry) => Some(match entry.kind {
                    DirectoryEntryKind::Regular => DylibTreeEntry::File,
                    DirectoryEntryKind::Directory => DylibTreeEntry::Directory,
                    DirectoryEntryKind::Symlink => DylibTreeEntry::Symlink {
                        // Read the real target so intermediate symlinks resolve
                        // exactly as dyld would, matching `readlink` in the
                        // TypeScript tree view.
                        target: self
                            .reader
                            .read_symlink_target(&entry, self.cancellation)
                            .unwrap_or_default(),
                    },
                }),
            };
            self.entries
                .borrow_mut()
                .insert(path.to_owned(), resolved.clone());
            Ok(resolved)
        }

        fn read_image(&self, path: &str) -> Result<MachoImageFacts, DirectoryError> {
            if let Some(facts) = self.images.borrow().get(path) {
                return Ok(facts.clone());
            }
            let facts = match self.reader.inspect_entry(path, self.cancellation)? {
                Some(entry) if entry.kind == DirectoryEntryKind::Regular => {
                    let bytes = self.reader.read_entry_prefix(
                        &entry,
                        MAX_IMAGE_BYTES,
                        self.cancellation,
                    )?;
                    macho_image_facts(&bytes)
                }
                _ => MachoImageFacts::NotMachO,
            };
            self.images
                .borrow_mut()
                .insert(path.to_owned(), facts.clone());
            Ok(facts)
        }
    }

    impl DylibTreeView for DirectoryView<'_> {
        type Error = DirectoryError;
        fn entry(&self, path: &str) -> Result<Option<DylibTreeEntry>, Self::Error> {
            self.read_entry(path)
        }
        fn image(&self, path: &str) -> Result<MachoImageFacts, Self::Error> {
            self.read_image(path)
        }
    }

    impl TreeView for DirectoryView<'_> {
        fn entry(&self, path: &str) -> Option<TreeEntry> {
            // Caller-selected root resolution uses the dyld path resolver; a
            // view error surfaces as `Absent`, the fail-closed outcome.
            match self.read_entry(path) {
                Ok(Some(DylibTreeEntry::File)) => Some(TreeEntry::File),
                Ok(Some(DylibTreeEntry::Directory)) => Some(TreeEntry::Directory),
                Ok(Some(DylibTreeEntry::Symlink { target })) => Some(TreeEntry::Symlink { target }),
                Ok(None) | Err(_) => None,
            }
        }
    }

    pub(super) fn trace(
        root_path: &str,
        target_path: &str,
        target_sha256: &str,
        enumerate_roots: bool,
        parameters: &Map<String, Value>,
        cancellation: &Cancellation,
    ) -> Result<ProviderOutcome, AnalysisError> {
        let selected_roots = selected_roots(parameters)?;
        let architecture = architecture(parameters)?;
        let caller_selected = selected_roots.is_some();

        // `realpath(rootPath)` then a no-follow reader rooted there.
        let reader = DirectoryReader::open(Path::new(root_path))
            .map_err(|error| reader_failure(&error.to_string()))?;
        let canonical_root = reader.root().canonical_path.clone();
        let view = DirectoryView::new(&reader, cancellation);

        // `target = relative(root, realpath(targetPath))`.
        let target_relative = relative_to_root(&canonical_root, target_path)?;

        let (requested, unclassified) = match &selected_roots {
            Some(roots) => (roots.clone(), Vec::new()),
            None if enumerate_roots => executable_roots(&reader, &view, cancellation)?,
            None => (vec![target_relative.clone()], Vec::new()),
        };

        let roots = require_macho_roots(&view, &requested, caller_selected)?;

        let trace = dylib_resolution::trace_dylib_loading(
            &view,
            DylibResolutionRequest {
                roots: &roots,
                unclassified: &unclassified,
                architecture: architecture.as_deref(),
                cancelled: Some(&|| cancellation.reason().is_some()),
            },
        )
        .map_err(|error| reader_failure(&error.to_string()))?;

        // Each digest must describe the same file whose headers were parsed.
        let mut digests: BTreeMap<String, String> = BTreeMap::new();
        for image in &trace.images {
            let digest = sha256_relative(&reader, &image.path, cancellation)?;
            digests.insert(image.path.clone(), digest);
        }
        let target_digest = match digests.get(&target_relative) {
            Some(digest) => digest.clone(),
            None => sha256_relative(&reader, &target_relative, cancellation)?,
        };
        if target_digest != target_sha256 {
            return Err(integrity_failure(format!(
                "Active target digest changed: expected {target_sha256}, observed {target_digest}"
            )));
        }

        let result = trace_value(&trace, root_path, target_sha256, &digests);
        let locations = trace
            .images
            .iter()
            .map(|image| json!({ "kind": "artifact-path", "path": image.path }))
            .collect::<Vec<_>>();
        let mut execution = Execution::new(result, super::super::provider());
        execution.limitations = trace.limitations.clone();
        execution.locations = locations;
        Ok(ProviderOutcome::from(execution))
    }

    /// `parsed.data.roots` (root-relative normalized paths).
    fn selected_roots(
        parameters: &Map<String, Value>,
    ) -> Result<Option<Vec<String>>, AnalysisError> {
        match parameters.get("roots") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Array(items)) => {
                let roots = items
                    .iter()
                    .map(|item| item.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| {
                        AnalysisError::input(
                            OPERATION,
                            vec![InputIssue::new(
                                &["roots"],
                                "invalid_type",
                                "Expected an array of root-relative paths.",
                            )],
                        )
                    })?;
                Ok(Some(roots))
            }
            Some(_) => Err(AnalysisError::input(
                OPERATION,
                vec![InputIssue::new(
                    &["roots"],
                    "invalid_type",
                    "Expected an array of root-relative paths.",
                )],
            )),
        }
    }

    /// `parsed.data.architecture` ∈ {arm64, arm64e, x86_64}.
    fn architecture(parameters: &Map<String, Value>) -> Result<Option<String>, AnalysisError> {
        match parameters.get("architecture") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(name)) if matches!(name.as_str(), "arm64" | "arm64e" | "x86_64") => {
                Ok(Some(name.clone()))
            }
            Some(_) => Err(AnalysisError::input(
                OPERATION,
                vec![InputIssue::new(
                    &["architecture"],
                    "invalid_value",
                    "Expected one of arm64, arm64e or x86_64.",
                )],
            )),
        }
    }

    /// `executableRoots`: every Mach-O in the bundle with an executable slice
    /// is a process root; unparsed Mach-O files become `unclassified`.
    fn executable_roots(
        reader: &DirectoryReader,
        view: &DirectoryView<'_>,
        cancellation: &Cancellation,
    ) -> Result<(Vec<String>, Vec<String>), AnalysisError> {
        let mut roots = Vec::new();
        let mut unclassified = Vec::new();
        let entries = reader
            .entries(MAX_DISCOVERY_ENTRIES, cancellation)
            .map_err(|error| reader_failure(&error.to_string()))?;
        for entry in entries {
            if entry.kind != DirectoryEntryKind::Regular {
                continue;
            }
            match view
                .read_image(&entry.path)
                .map_err(|error| reader_failure(&error.to_string()))?
            {
                MachoImageFacts::Parsed { slices }
                    if slices.iter().any(|slice| slice.file_type == "execute") =>
                {
                    roots.push(entry.path);
                }
                MachoImageFacts::Malformed { .. } | MachoImageFacts::Unsupported { .. } => {
                    unclassified.push(entry.path);
                }
                _ => {}
            }
        }
        roots.sort();
        roots.dedup();
        unclassified.sort();
        unclassified.dedup();
        Ok((roots, unclassified))
    }

    /// `requireMachoRoots`: resolve each root segment-by-segment and require a
    /// regular Mach-O file. A caller-selected root that fails is an input error
    /// on that root; a derived root keeps reporting an artifact failure.
    fn require_macho_roots(
        view: &DirectoryView<'_>,
        roots: &[String],
        caller_selected: bool,
    ) -> Result<Vec<String>, AnalysisError> {
        let mut resolved: Vec<String> = Vec::new();
        for (index, path) in roots.iter().enumerate() {
            let reject = |message: String| -> AnalysisError {
                if caller_selected {
                    let mut issue = InputIssue::new(&["roots"], "invalid_value", message);
                    issue.path = vec![Value::String("roots".to_owned()), json!(index)];
                    AnalysisError::input(OPERATION, vec![issue])
                } else {
                    reader_failure_message(message)
                }
            };
            let lookup = dyld_paths::resolve_tree_path(view, path);
            let file = match lookup {
                PathLookup::File { path } => path,
                PathLookup::Escapes => {
                    return Err(reject(format!(
                        "Root {path} resolves outside the analyzed root"
                    )));
                }
                PathLookup::Absent | PathLookup::NotFile => {
                    return Err(reject(format!(
                        "Root {path} is not a regular file in the analyzed root"
                    )));
                }
            };
            let facts = view
                .read_image(&file)
                .map_err(|error| reader_failure(&error.to_string()))?;
            if matches!(facts, MachoImageFacts::NotMachO) {
                return Err(reject(format!("Root {path} is not a Mach-O image")));
            }
            if !resolved.contains(&file) {
                resolved.push(file);
            }
        }
        Ok(resolved)
    }

    fn sha256_relative(
        reader: &DirectoryReader,
        relative: &str,
        cancellation: &Cancellation,
    ) -> Result<String, AnalysisError> {
        let entry = reader
            .inspect_entry(relative, cancellation)
            .map_err(|error| reader_failure(&error.to_string()))?
            .ok_or_else(|| reader_failure(&format!("Image disappeared: {relative}")))?;
        let mut file = reader
            .open_entry(&entry, cancellation)
            .map_err(|error| reader_failure(&error.to_string()))?;
        file.sha256(cancellation)
            .map_err(|error| reader_failure(&error.to_string()))
    }

    /// `relative(root, realpath(path))` as a slash-separated root-relative path.
    fn relative_to_root(root: &Path, path: &str) -> Result<String, AnalysisError> {
        let canonical =
            std::fs::canonicalize(path).map_err(|error| reader_failure(&error.to_string()))?;
        let relative = canonical
            .strip_prefix(root)
            .map_err(|_| reader_failure("Target path escapes the analyzed root."))?;
        relative
            .to_str()
            .map(|path| path.replace(std::path::MAIN_SEPARATOR, "/"))
            .ok_or_else(|| reader_failure("Target path is not valid UTF-8."))
    }

    fn macho_image_facts(bytes: &[u8]) -> MachoImageFacts {
        match rea_rust_analysis::macho::read(bytes) {
            Ok(image) => MachoImageFacts::Parsed {
                slices: vec![macho_slice(image, bytes.len() as u64)],
            },
            Err(rea_rust_analysis::macho::Error::Malformed(reason)) => MachoImageFacts::Malformed {
                reason: reason.to_owned(),
            },
            Err(rea_rust_analysis::macho::Error::Unsupported(reason))
                if reason == "Input is not a Mach-O image" =>
            {
                MachoImageFacts::NotMachO
            }
            Err(rea_rust_analysis::macho::Error::Unsupported(reason)) => {
                MachoImageFacts::Unsupported {
                    reason: reason.to_owned(),
                }
            }
        }
    }

    fn macho_slice(image: rea_rust_analysis::macho::Image, size: u64) -> MachoSlice {
        let platforms = image
            .build_metadata
            .iter()
            .filter_map(|metadata| metadata.platform)
            .collect::<Vec<_>>();
        let dyld_environment = image
            .dyld_environment
            .iter()
            .filter_map(|record| record.value.clone())
            .collect::<Vec<_>>();
        MachoSlice {
            architecture: image.cpu_name,
            slice_offset: 0,
            slice_size: size,
            cpu_type: image.cpu,
            cpu_subtype: image.cpu_subtype,
            fat_cpu_type: None,
            fat_cpu_subtype: None,
            fat_alignment_exponent: None,
            file_type: image.file_type_name,
            file_type_code: image.file_type,
            platform: platforms.first().copied(),
            platforms,
            install_name: image
                .dylibs
                .iter()
                .find(|record| record.kind == "id")
                .and_then(|record| record.name.clone()),
            dependencies: image
                .dependencies
                .into_iter()
                .map(|dependency| dylib_resolution::MachoDependency {
                    command: dependency_command(dependency.kind).to_owned(),
                    encoding: dependency.encoding.to_owned(),
                    install_name: dependency.path,
                    weak: dependency.weak,
                    upward: dependency.upward,
                    reexport: dependency.reexport,
                    delayed_init: dependency.delayed_init,
                    current_version: dependency.current_version.unwrap_or_default(),
                    compatibility_version: dependency.compatibility_version.unwrap_or_default(),
                })
                .collect(),
            rpaths: image.rpaths,
            dyld_environment,
            code_signature_present: !image.code_signatures.is_empty(),
        }
    }

    fn dependency_command(kind: &str) -> &'static str {
        match kind {
            "weak" => "LC_LOAD_WEAK_DYLIB",
            "reexport" => "LC_REEXPORT_DYLIB",
            "lazy" => "LC_LAZY_LOAD_DYLIB",
            "upward" => "LC_LOAD_UPWARD_DYLIB",
            _ => "LC_LOAD_DYLIB",
        }
    }

    /// Project `DylibTrace` to the frozen `dylibResolutionResultSchema` shape.
    fn trace_value(
        trace: &dylib_resolution::DylibTrace,
        root_path: &str,
        target_sha256: &str,
        digests: &BTreeMap<String, String>,
    ) -> Value {
        let images = trace
            .images
            .iter()
            .map(|image| {
                json!({
                    "path": image.path,
                    "sha256": digests.get(&image.path),
                    "parse_status": image.parse_status,
                    "reason": image.reason,
                    "slices": image.slices.iter().map(slice_summary_value).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        let edges = trace
            .edges
            .iter()
            .map(|edge| {
                json!({
                    "root": edge.root,
                    "architecture": edge.architecture,
                    "loader": edge.loader,
                    "via": edge.via,
                    "command": edge.dependency.command,
                    "encoding": edge.dependency.encoding,
                    "install_name": edge.dependency.install_name,
                    "weak": edge.dependency.weak,
                    "upward": edge.dependency.upward,
                    "reexport": edge.dependency.reexport,
                    "delayed_init": edge.dependency.delayed_init,
                    "current_version": edge.dependency.current_version,
                    "compatibility_version": edge.dependency.compatibility_version,
                    "candidates": edge.candidates.iter().map(candidate_value).collect::<Vec<_>>(),
                    "resolution": {"status": edge.resolution.status, "image": edge.resolution.image},
                    "install_name_matches": edge.install_name_matches,
                    "loader_conditional": edge.loader_conditional,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "root_path": root_path,
            "target_sha256": target_sha256,
            "roots": trace.roots.iter().map(|root| json!({"image": root.image, "architecture": root.architecture})).collect::<Vec<_>>(),
            "images": images,
            "edges": edges,
            "findings": trace.findings.iter().map(|finding| json!({"kind": finding.kind, "edge_index": finding.edge_index, "image": finding.image, "basis": finding.basis, "explanation": finding.explanation})).collect::<Vec<_>>(),
            "coverage": {"status": trace.coverage.status, "unparsed_images": trace.coverage.unparsed_images, "roots_without_architecture": trace.coverage.roots_without_architecture},
            "limitations": trace.limitations,
        })
    }

    fn candidate_value(candidate: &dylib_resolution::DylibCandidate) -> Value {
        json!({
            "path": candidate.path,
            "source": candidate.source,
            "rpath": candidate.rpath,
            "rpath_owner": candidate.rpath_owner,
            "outcome": candidate.outcome,
            "resolved_path": candidate.resolved_path,
        })
    }

    fn slice_summary_value(slice: &dylib_resolution::MachoSliceSummary) -> Value {
        json!({
            "architecture": slice.architecture,
            "slice_offset": slice.slice_offset,
            "slice_size": slice.slice_size,
            "cpu_type": slice.cpu_type,
            "cpu_subtype": slice.cpu_subtype,
            "fat_cpu_type": slice.fat_cpu_type,
            "fat_cpu_subtype": slice.fat_cpu_subtype,
            "fat_alignment_exponent": slice.fat_alignment_exponent,
            "file_type": slice.file_type,
            "file_type_code": slice.file_type_code,
            "platform": slice.platform,
            "platforms": slice.platforms,
            "install_name": slice.install_name,
            "rpaths": slice.rpaths,
            "dyld_environment": slice.dyld_environment,
            "code_signature_present": slice.code_signature_present,
        })
    }

    /// An artifact read failure translated through the shared algebra.
    fn reader_failure(message: &str) -> AnalysisError {
        reader_failure_message(message.to_owned())
    }

    fn reader_failure_message(message: String) -> AnalysisError {
        crate::common::translate_artifact_failure(
            OPERATION,
            crate::common::ReaderFailure::new("io", message).into(),
        )
    }

    fn integrity_failure(message: String) -> AnalysisError {
        crate::common::translate_artifact_failure(
            OPERATION,
            crate::common::ReaderFailure::new("integrity", message).into(),
        )
    }
}
