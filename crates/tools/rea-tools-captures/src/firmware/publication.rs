//! Publish verified regular files and derive explicit extraction-gap rows.
//!
//! Compatibility owner: `src/firmware/FirmwarePublication.ts` and the output
//! tree in `src/artifacts/SafeOutputTree.ts`. The tree is created exclusively,
//! regular files are streamed with digest/size verification, and the result is
//! built in the exact `firmwareResultSchemas.extract_firmware` key order.
use super::files::{EntryKind, FirmwareEntry, Selection};
use super::release::FIRMWARE_LIMITS;
use super::reports::{ByteRange, Coverage, NormalizedUnblob};
use crate::artifact::sha256_hex;
use crate::node;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
const EXTRACT: &str = "extract_firmware";
const MAX_EXTRACTION_DEPTH: u64 = 10;
fn output(reason: impl Into<String>) -> AnalysisError {
    AnalysisError::output(EXTRACT, reason)
}
/// `GAP_CONTINUATIONS`.
fn gap_continuation(kind: GapKind) -> &'static str {
    match kind {
        GapKind::MissingExtractorDependency => {
            "REA installs nothing. Add the named dependency to your own environment and rerun extract_firmware on the same immutable input with a fresh output_directory to re-evaluate the affected region; otherwise it stays unextracted."
        }
        GapKind::UnknownChunkHandler => {
            "If Binwalk is configured with REA_BINWALK_COMMAND, run inspect_firmware_regions on the same input for signature hypotheses. Without configured Binwalk that inspection is unavailable. Alternatively, select a materially narrower range with extract_firmware and a fresh output_directory; the region is not decoded content."
        }
        GapKind::EncryptedChunk => {
            "No static extraction continues past encryption; treat the region as unexamined rather than empty or corrupt."
        }
        GapKind::ExtractorFailure => {
            "The producer retained this chunk's extraction problem in diagnostics. Review the reported failure, then rerun extract_firmware on the same immutable input with a fresh output_directory; the region is not decoded content."
        }
        GapKind::DepthLimited => {
            "Rerun extract_firmware with a higher max_depth (up to 10) and a fresh output_directory to descend into this path."
        }
        GapKind::UnpublishedEntry => {
            "The entry is retained as metadata; only regular files are published, without executable permission bits."
        }
    }
}
const UNNAMED_DEPENDENCY_CONTINUATION: &str = "The producer reported a missing extractor dependency without naming it; its identity is unavailable in this evidence. No specific installation or rerun can be prescribed from this report. Retain the gap as unextracted unless additional provider evidence establishes the dependency. REA installs nothing.";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GapKind {
    MissingExtractorDependency,
    UnknownChunkHandler,
    EncryptedChunk,
    ExtractorFailure,
    DepthLimited,
    UnpublishedEntry,
}
impl GapKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingExtractorDependency => "missing-extractor-dependency",
            Self::UnknownChunkHandler => "unknown-chunk-handler",
            Self::EncryptedChunk => "encrypted-chunk",
            Self::ExtractorFailure => "extractor-failure",
            Self::DepthLimited => "depth-limited",
            Self::UnpublishedEntry => "unpublished-entry",
        }
    }
}
/// One extraction gap row, in schema key order.
struct Gap {
    kind: GapKind,
    input_path: String,
    relative_path: Option<String>,
    handler: Option<String>,
    provider_id: Option<String>,
    range: Option<ByteRange>,
    root_file_range: Option<ByteRange>,
    dependencies: Vec<String>,
    continuation_id: String,
}
impl Gap {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("kind".into(), Value::String(self.kind.as_str().to_owned()));
        map.insert("input_path".into(), Value::String(self.input_path.clone()));
        map.insert("relative_path".into(), nullable_string(&self.relative_path));
        map.insert("handler".into(), nullable_string(&self.handler));
        map.insert("provider_id".into(), nullable_string(&self.provider_id));
        map.insert("range".into(), nullable_range(self.range));
        map.insert(
            "root_file_range".into(),
            nullable_range(self.root_file_range),
        );
        map.insert(
            "dependencies".into(),
            Value::Array(
                self.dependencies
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        map.insert(
            "continuation_id".into(),
            Value::String(self.continuation_id.clone()),
        );
        Value::Object(map)
    }
    fn sort_key(&self) -> String {
        format!(
            "{}\u{0}{}\u{0}{}\u{0}{}",
            self.input_path,
            self.kind.as_str(),
            self.provider_id.clone().unwrap_or_default(),
            self.relative_path.clone().unwrap_or_default()
        )
    }
}
fn nullable_string(value: &Option<String>) -> Value {
    value.clone().map_or(Value::Null, Value::String)
}
fn nullable_range(range: Option<ByteRange>) -> Value {
    range.map_or(Value::Null, ByteRange::to_value)
}
/// Interns recovery instructions, hashing each unique text once (sha256 hex).
struct Continuations {
    by_instruction: Vec<(String, String)>,
    index: std::collections::HashMap<String, String>,
}
impl Continuations {
    fn new() -> Self {
        Self {
            by_instruction: Vec::new(),
            index: std::collections::HashMap::new(),
        }
    }
    fn intern(&mut self, instruction: &str) -> String {
        if let Some(existing) = self.index.get(instruction) {
            return existing.clone();
        }
        let id = sha256_hex(instruction.as_bytes());
        self.index.insert(instruction.to_owned(), id.clone());
        self.by_instruction
            .push((instruction.to_owned(), id.clone()));
        id
    }
}
/// A published or unpublished entry recorded in the result.
struct PublishedFile {
    relative_path: String,
    path: String,
    size: u64,
    sha256: String,
    reported_sha256: Option<String>,
    mime_type: Option<String>,
    analysis_depth: Option<u64>,
}
/// Context passed to `publish`.
pub struct PublishContext<'a> {
    pub output_directory: &'a str,
    pub entries: &'a [FirmwareEntry],
    pub normalized: &'a NormalizedUnblob,
    pub selection: &'a Selection,
    pub max_depth: u64,
    pub engine: &'a Value,
    pub cancellation: &'a Cancellation,
}
/// Outcome of a successful publication.
pub struct Published {
    pub result: Value,
    /// The committed output root (canonical path).
    pub output_root: String,
}
/// `publishFirmwareExtraction`: publish verified files and build the result.
///
/// On any failure the partially written tree is rolled back. A committed tree
/// whose later descriptor cleanup fails is out of scope here (see the provider
/// deviation note); this port commits atomically via `rename`.
pub fn publish(context: &PublishContext<'_>) -> Result<Published, AnalysisError> {
    // Every reported regular file must be materialized.
    let mut materialized: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in context.entries {
        if entry.kind == EntryKind::File {
            materialized.insert(format!("$output/{}", entry.relative_path));
        }
    }
    for path in context.normalized.files.keys() {
        if path != "$input" && !materialized.contains(path) {
            return Err(output(format!(
                "Reported regular file is absent from materialized output: {path}"
            )));
        }
    }
    // Create the destination exclusively under the realpath'd parent.
    let tree = OutputTree::create(context.output_directory)?;
    let publish_result = publish_into(&tree, context);
    match publish_result {
        Ok((files, unpublished, result)) => {
            if context.cancellation.reason().is_some() {
                tree.rollback();
                return Err(AnalysisError::cancelled(EXTRACT));
            }
            match tree.commit() {
                Ok(()) => {
                    let _ = (&files, &unpublished);
                    Ok(Published {
                        result,
                        output_root: tree.output_root.clone(),
                    })
                }
                Err(error) => {
                    tree.rollback();
                    Err(error)
                }
            }
        }
        Err(error) => {
            tree.rollback();
            Err(error)
        }
    }
}
fn publish_into(
    tree: &OutputTree,
    context: &PublishContext<'_>,
) -> Result<(Vec<PublishedFile>, Vec<Value>, Value), AnalysisError> {
    let mut files: Vec<PublishedFile> = Vec::new();
    let mut unpublished: Vec<Value> = Vec::new();
    for entry in context.entries {
        if entry.kind != EntryKind::File {
            let mut map = Map::new();
            map.insert(
                "relative_path".into(),
                Value::String(entry.relative_path.clone()),
            );
            map.insert("kind".into(), Value::String(entry.kind.as_str().to_owned()));
            map.insert("link_target".into(), nullable_string(&entry.link_target));
            unpublished.push(Value::Object(map));
            continue;
        }
        let logical = format!("$output/{}", entry.relative_path);
        let reported = context.normalized.files.get(&logical);
        let sha256 = super::files::hash(&entry.path, context.cancellation).map_err(|error| {
            output(format!(
                "Could not read extracted file {}: {}",
                entry.relative_path,
                error.message()
            ))
        })?;
        let reported_sha = reported.and_then(|facts| facts.sha256.clone());
        let size_mismatch = context
            .normalized
            .sizes
            .get(&logical)
            .is_some_and(|size| *size != entry.size);
        let sha_mismatch = reported_sha
            .as_deref()
            .is_some_and(|reported| reported != sha256);
        if sha_mismatch || size_mismatch {
            return Err(output(format!(
                "Extracted bytes disagree with provider report: {}",
                entry.relative_path
            )));
        }
        let destination = tree.write(&entry.relative_path, &entry.path, &sha256, entry.size)?;
        files.push(PublishedFile {
            relative_path: entry.relative_path.clone(),
            path: destination,
            size: entry.size,
            sha256,
            reported_sha256: reported_sha,
            mime_type: reported.and_then(|facts| facts.mime_type.clone()),
            analysis_depth: reported.map(|facts| facts.depth),
        });
    }
    let (gaps, continuations) =
        extraction_gaps(&unpublished, &files, context.normalized, context.max_depth);
    let published_bytes: u64 = files.iter().map(|file| file.size).sum();
    let coverage = if unpublished.is_empty() {
        context.normalized.coverage
    } else {
        Coverage::Partial
    };
    let result = build_result(
        context.engine,
        context.selection,
        &tree.output_root,
        coverage,
        &files,
        &unpublished,
        context.normalized,
        &gaps,
        &continuations,
        published_bytes,
    );
    Ok((files, unpublished, result))
}
#[allow(clippy::too_many_arguments)]
fn build_result(
    engine: &Value,
    selection: &Selection,
    output_root: &str,
    coverage: Coverage,
    files: &[PublishedFile],
    unpublished: &[Value],
    normalized: &NormalizedUnblob,
    gaps: &[Gap],
    continuations: &Continuations,
    published_bytes: u64,
) -> Value {
    let mut map = Map::new();
    map.insert("engine".into(), engine.clone());
    map.insert("selection".into(), selection_value(selection));
    map.insert(
        "output_directory".into(),
        Value::String(output_root.to_owned()),
    );
    map.insert(
        "coverage".into(),
        Value::String(coverage.as_str().to_owned()),
    );
    map.insert(
        "files".into(),
        Value::Array(files.iter().map(published_file_value).collect()),
    );
    map.insert(
        "unpublished_entries".into(),
        Value::Array(unpublished.to_vec()),
    );
    map.insert(
        "chunks".into(),
        Value::Array(normalized.chunks.iter().map(chunk_value).collect()),
    );
    map.insert(
        "derivations".into(),
        Value::Array(
            normalized
                .derivations
                .iter()
                .map(derivation_value)
                .collect(),
        ),
    );
    map.insert(
        "depth_limited_paths".into(),
        Value::Array(
            normalized
                .depth_limited_paths
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    map.insert(
        "diagnostics".into(),
        Value::Array(normalized.diagnostics.clone()),
    );
    map.insert(
        "extraction_gaps".into(),
        Value::Array(gaps.iter().map(Gap::to_value).collect()),
    );
    map.insert(
        "extraction_continuations".into(),
        Value::Array(
            continuations
                .by_instruction
                .iter()
                .map(|(instruction, id)| {
                    let mut entry = Map::new();
                    entry.insert("id".into(), Value::String(id.clone()));
                    entry.insert("instruction".into(), Value::String(instruction.clone()));
                    Value::Object(entry)
                })
                .collect(),
        ),
    );
    map.insert("published_bytes".into(), Value::from(published_bytes));
    Value::Object(map)
}
fn selection_value(selection: &Selection) -> Value {
    let mut map = Map::new();
    map.insert("offset".into(), Value::from(selection.offset));
    map.insert("length".into(), Value::from(selection.length));
    map.insert("sha256".into(), Value::String(selection.sha256.clone()));
    Value::Object(map)
}
fn published_file_value(file: &PublishedFile) -> Value {
    let mut map = Map::new();
    map.insert(
        "relative_path".into(),
        Value::String(file.relative_path.clone()),
    );
    map.insert("path".into(), Value::String(file.path.clone()));
    map.insert("size".into(), Value::from(file.size));
    map.insert("sha256".into(), Value::String(file.sha256.clone()));
    map.insert(
        "reported_sha256".into(),
        nullable_string(&file.reported_sha256),
    );
    map.insert("mime_type".into(), nullable_string(&file.mime_type));
    map.insert(
        "analysis_depth".into(),
        file.analysis_depth.map_or(Value::Null, Value::from),
    );
    map.insert("runtime_address".into(), Value::Null);
    map.insert("original_file_range".into(), Value::Null);
    Value::Object(map)
}
fn chunk_value(chunk: &super::reports::Chunk) -> Value {
    let mut map = Map::new();
    map.insert("input_path".into(), Value::String(chunk.input_path.clone()));
    map.insert(
        "provider_id".into(),
        Value::String(chunk.provider_id.clone()),
    );
    map.insert("range".into(), chunk.range.to_value());
    map.insert("handler".into(), nullable_string(&chunk.handler));
    map.insert(
        "encrypted".into(),
        chunk.encrypted.map_or(Value::Null, Value::Bool),
    );
    map.insert(
        "root_file_range".into(),
        nullable_range(chunk.root_file_range),
    );
    map.insert(
        "extraction_failed".into(),
        Value::Bool(chunk.extraction_failed),
    );
    Value::Object(map)
}
fn derivation_value(derivation: &super::reports::Derivation) -> Value {
    let mut map = Map::new();
    map.insert(
        "parent_path".into(),
        Value::String(derivation.parent_path.clone()),
    );
    map.insert(
        "child_path".into(),
        Value::String(derivation.child_path.clone()),
    );
    map.insert(
        "provider_blob_id".into(),
        Value::String(derivation.provider_blob_id.clone()),
    );
    map.insert("handler".into(), nullable_string(&derivation.handler));
    map.insert(
        "parent_file_range".into(),
        nullable_range(derivation.parent_file_range),
    );
    Value::Object(map)
}
// ---------------------------------------------------------------------------
// Gap derivation (`extractionGaps`)
// ---------------------------------------------------------------------------
fn depth_continuation(max_depth: u64, published_child_paths: &[String]) -> String {
    if max_depth < MAX_EXTRACTION_DEPTH {
        gap_continuation(GapKind::DepthLimited).to_owned()
    } else if !published_child_paths.is_empty() {
        let joined = published_child_paths
            .iter()
            .map(|path| serde_json::to_string(path).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "This extraction already ran at the lane's maximum depth. To continue, rerun extract_firmware with path set to any eligible published child below this path and a fresh output directory; each child listed here restarts the depth budget: {joined}."
        )
    } else {
        format!(
            "This extraction already ran at the lane's maximum depth, and no published child under this path is both nonempty and within the {}-byte firmware input limit, so the depth budget cannot be restarted from this output. Treat the region below this path as unexamined.",
            FIRMWARE_LIMITS.input_bytes
        )
    }
}
fn nested_unknown_continuation(published: Option<(&str, u64)>) -> String {
    let base = "This unknown chunk was carved from a nested extraction, so its range is relative to the published child named by this gap's input_path, not to the original input.";
    match published {
        Some((_, size)) if size > 0 && size <= FIRMWARE_LIMITS.input_bytes => format!(
            "{base} Run inspect_firmware_regions with path set to that published child for signature hypotheses only if Binwalk is configured with REA_BINWALK_COMMAND. This inspection step is unavailable without configured Binwalk; retain the region as unexamined. Repeating the same whole-child extraction with unchanged handlers would not advance analysis."
        ),
        _ => format!(
            "{base} That published child is not a nonempty file within the {}-byte firmware input limit, so inspect_firmware_regions cannot accept it as a fresh input; treat the region as unexamined.",
            FIRMWARE_LIMITS.input_bytes
        ),
    }
}
fn blank_gap(
    kind: GapKind,
    input_path: String,
    dependencies: Vec<String>,
    continuation_id: String,
) -> Gap {
    Gap {
        kind,
        input_path,
        relative_path: None,
        handler: None,
        provider_id: None,
        range: None,
        root_file_range: None,
        dependencies,
        continuation_id,
    }
}
fn extraction_gaps(
    unpublished: &[Value],
    files: &[PublishedFile],
    normalized: &NormalizedUnblob,
    max_depth: u64,
) -> (Vec<Gap>, Continuations) {
    let mut continuations = Continuations::new();
    let mut gaps: Vec<Gap> = Vec::new();
    // Dependency gaps.
    let chunks_by_key: std::collections::HashMap<(String, String), &super::reports::Chunk> =
        normalized
            .chunks
            .iter()
            .map(|chunk| ((chunk.input_path.clone(), chunk.provider_id.clone()), chunk))
            .collect();
    for row in &normalized.chunk_missing_dependencies {
        let affected = chunks_by_key.get(&(row.input_path.clone(), row.provider_id.clone()));
        let instruction = if row.dependencies.is_empty() {
            UNNAMED_DEPENDENCY_CONTINUATION
        } else {
            gap_continuation(GapKind::MissingExtractorDependency)
        };
        let continuation_id = continuations.intern(instruction);
        let mut gap = blank_gap(
            GapKind::MissingExtractorDependency,
            row.input_path.clone(),
            row.dependencies.clone(),
            continuation_id,
        );
        if let Some(chunk) = affected {
            gap.handler = chunk.handler.clone();
            gap.provider_id = Some(row.provider_id.clone());
            gap.range = Some(chunk.range);
            gap.root_file_range = chunk.root_file_range;
        }
        gaps.push(gap);
    }
    for stage in normalized
        .failed_extraction_stages
        .iter()
        .filter(|stage| stage.kind == super::reports::FailedStageKind::MissingExtractorDependency)
    {
        let instruction = if stage.dependencies.is_empty() {
            UNNAMED_DEPENDENCY_CONTINUATION
        } else {
            gap_continuation(GapKind::MissingExtractorDependency)
        };
        let continuation_id = continuations.intern(instruction);
        let mut gap = blank_gap(
            GapKind::MissingExtractorDependency,
            stage.input_path.clone(),
            stage.dependencies.clone(),
            continuation_id,
        );
        gap.handler = stage.handler.clone();
        gap.provider_id = stage.provider_id.clone();
        gaps.push(gap);
    }
    for row in &normalized.missing_dependencies {
        let instruction = if row.dependencies.is_empty() {
            UNNAMED_DEPENDENCY_CONTINUATION
        } else {
            gap_continuation(GapKind::MissingExtractorDependency)
        };
        let continuation_id = continuations.intern(instruction);
        gaps.push(blank_gap(
            GapKind::MissingExtractorDependency,
            row.input_path.clone(),
            row.dependencies.clone(),
            continuation_id,
        ));
    }
    // extractor-failure stages.
    for stage in normalized
        .failed_extraction_stages
        .iter()
        .filter(|stage| stage.kind == super::reports::FailedStageKind::ExtractorFailure)
    {
        let continuation_id = continuations.intern(
            "The producer retained this extraction stage's failure in diagnostics. Review the stage report and correct the reported cause before rerunning extract_firmware on the same immutable input with a fresh output_directory; this report establishes no byte-region ownership.",
        );
        let mut gap = blank_gap(
            GapKind::ExtractorFailure,
            stage.input_path.clone(),
            Vec::new(),
            continuation_id,
        );
        gap.handler = stage.handler.clone();
        gap.provider_id = stage.provider_id.clone();
        gaps.push(gap);
    }
    // Published files by logical path for nested/depth continuations.
    let published_files: BTreeMap<String, &PublishedFile> = files
        .iter()
        .map(|file| (format!("$output/{}", file.relative_path), file))
        .collect();
    // Chunk gaps.
    let dependency_chunk_keys: std::collections::HashSet<(String, String)> = normalized
        .chunk_missing_dependencies
        .iter()
        .map(|row| (row.input_path.clone(), row.provider_id.clone()))
        .collect();
    // unknown-chunk-handler
    for chunk in normalized
        .chunks
        .iter()
        .filter(|chunk| chunk.handler.is_none())
    {
        let continuation_id = if chunk.input_path.starts_with("$output/") {
            let published = published_files
                .get(&chunk.input_path)
                .map(|file| (file.path.as_str(), file.size));
            continuations.intern(&nested_unknown_continuation(published))
        } else {
            continuations.intern(gap_continuation(GapKind::UnknownChunkHandler))
        };
        gaps.push(chunk_gap(
            GapKind::UnknownChunkHandler,
            chunk,
            continuation_id,
        ));
    }
    // encrypted-chunk
    for chunk in normalized
        .chunks
        .iter()
        .filter(|chunk| chunk.encrypted == Some(true))
    {
        let continuation_id = continuations.intern(gap_continuation(GapKind::EncryptedChunk));
        gaps.push(chunk_gap(GapKind::EncryptedChunk, chunk, continuation_id));
    }
    // extractor-failure chunks
    for chunk in normalized.chunks.iter().filter(|chunk| {
        chunk.extraction_failed
            && chunk.handler.is_some()
            && chunk.encrypted != Some(true)
            && !dependency_chunk_keys
                .contains(&(chunk.input_path.clone(), chunk.provider_id.clone()))
    }) {
        let continuation_id = continuations.intern(gap_continuation(GapKind::ExtractorFailure));
        gaps.push(chunk_gap(GapKind::ExtractorFailure, chunk, continuation_id));
    }
    // depth-limited
    let ceiling_reached =
        max_depth >= MAX_EXTRACTION_DEPTH && !normalized.depth_limited_paths.is_empty();
    let mut re_rootable: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    if ceiling_reached {
        // Iterate published files in sorted logical-path order.
        for (file_path, file) in &published_files {
            if file.size == 0 || file.size > FIRMWARE_LIMITS.input_bytes {
                continue;
            }
            let mut segments: Vec<&str> = file_path.split('/').collect();
            while segments.len() > 1 {
                let ancestor = segments.join("/");
                re_rootable
                    .entry(ancestor)
                    .or_default()
                    .insert(file.path.clone());
                segments.pop();
            }
        }
    }
    let mut depth_continuation_ids: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for input_path in &normalized.depth_limited_paths {
        let continuation_id = if let Some(existing) = depth_continuation_ids.get(input_path) {
            existing.clone()
        } else {
            let children: Vec<String> = re_rootable
                .get(input_path)
                .map(|set| set.iter().cloned().collect())
                .unwrap_or_default();
            let id = continuations.intern(&depth_continuation(max_depth, &children));
            depth_continuation_ids.insert(input_path.clone(), id.clone());
            id
        };
        gaps.push(blank_gap(
            GapKind::DepthLimited,
            input_path.clone(),
            Vec::new(),
            continuation_id,
        ));
    }
    // unpublished-entry
    for entry in unpublished {
        let relative_path = entry
            .get("relative_path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let continuation_id = continuations.intern(gap_continuation(GapKind::UnpublishedEntry));
        let mut gap = blank_gap(
            GapKind::UnpublishedEntry,
            format!("$output/{relative_path}"),
            Vec::new(),
            continuation_id,
        );
        gap.relative_path = Some(relative_path);
        gaps.push(gap);
    }
    gaps.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    (gaps, continuations)
}
fn chunk_gap(kind: GapKind, chunk: &super::reports::Chunk, continuation_id: String) -> Gap {
    Gap {
        kind,
        input_path: chunk.input_path.clone(),
        relative_path: None,
        handler: chunk.handler.clone(),
        provider_id: Some(chunk.provider_id.clone()),
        range: Some(chunk.range),
        root_file_range: chunk.root_file_range,
        dependencies: Vec::new(),
        continuation_id,
    }
}
// ---------------------------------------------------------------------------
// Output tree
// ---------------------------------------------------------------------------
/// A minimal operation-owned output tree: exclusive staging then atomic rename.
struct OutputTree {
    /// Canonical destination the result reports (`outputRoot`).
    output_root: String,
    /// Private staging root, renamed into place on commit.
    staging: String,
    committed: std::cell::Cell<bool>,
}
impl OutputTree {
    /// `SafeOutputTree.create`: realpath the parent, require the destination
    /// absent, and stage writes in a sibling temp directory.
    fn create(output_directory: &str) -> Result<Self, AnalysisError> {
        if !node::is_absolute(output_directory) {
            return Err(reader_failure("Extraction output root must be absolute"));
        }
        let (parent, name) = split_parent(output_directory);
        if name == "." || name == ".." || name.is_empty() {
            return Err(reader_failure("Invalid extraction output root"));
        }
        let parent = node::realpath(&parent)
            .map_err(|_| reader_failure("Extraction output parent is unavailable"))?;
        let canonical_output = node::join(&parent, &name);
        if std::fs::symlink_metadata(&canonical_output).is_ok() {
            return Err(reader_failure("Extraction output root already exists"));
        }
        let staging = node::join(
            &parent,
            &format!(".rea-firmware-stage-{}", node::random_uuid()),
        );
        crate::producer::make_private_directory(&staging)
            .map_err(|error| reader_failure(error.message))?;
        Ok(Self {
            output_root: canonical_output,
            staging,
            committed: std::cell::Cell::new(false),
        })
    }
    /// Stream one regular file into the staging tree with byte/digest checks.
    fn write(
        &self,
        relative_path: &str,
        source: &str,
        sha256: &str,
        bytes: u64,
    ) -> Result<String, AnalysisError> {
        let normalized = normalize_destination(relative_path)?;
        let destination = node::join(
            &self.staging,
            &normalized.replace('/', &std::path::MAIN_SEPARATOR.to_string()),
        );
        if let Some(parent) = std::path::Path::new(&destination).parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                reader_failure(format!("Could not create extraction parent: {error}"))
            })?;
        }
        let content = std::fs::read(source).map_err(|error| {
            reader_failure(format!("Could not read extracted content: {error}"))
        })?;
        if content.len() as u64 != bytes {
            return Err(reader_failure(format!(
                "Extracted content size disagrees with inventory: $output/{relative_path}"
            )));
        }
        if sha256_hex(&content) != sha256 {
            return Err(reader_failure(format!(
                "Extracted content disagrees with inventory: $output/{relative_path}"
            )));
        }
        write_exclusive_nofollow(&destination, &content, 0o600).map_err(|error| {
            reader_failure(format!(
                "Could not exclusively create extraction path: {error}"
            ))
        })?;
        Ok(node::join(
            &self.output_root,
            &normalized.replace('/', &std::path::MAIN_SEPARATOR.to_string()),
        ))
    }
    /// `commit`: rename the staging tree onto the destination atomically.
    fn commit(&self) -> Result<(), AnalysisError> {
        std::fs::rename(&self.staging, &self.output_root).map_err(|error| {
            reader_failure(format!("Could not commit extraction output: {error}"))
        })?;
        self.committed.set(true);
        Ok(())
    }
    /// `rollback`: remove the uncommitted staging tree.
    fn rollback(&self) {
        if !self.committed.get() {
            let _ = std::fs::remove_dir_all(&self.staging);
        }
    }
}
impl Drop for OutputTree {
    fn drop(&mut self) {
        self.rollback();
    }
}
/// Exclusively create a staging file with `O_NOFOLLOW`, matching the
/// `SafeOutputTree` open flags so a symlinked destination component is refused
/// rather than followed. The staging root is private, but the flag preserves
/// the TS refusal semantics exactly on the supported Linux platform.
fn write_exclusive_nofollow(path: &str, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path)?;
    file.write_all(bytes)
}
fn reader_failure(reason: impl Into<String>) -> AnalysisError {
    AnalysisError::output(EXTRACT, reason)
}
/// `normalizeDestinationPath`: reject absolute, `.`/`..`, or empty components.
fn normalize_destination(relative_path: &str) -> Result<String, AnalysisError> {
    if relative_path.is_empty() || node::is_absolute(relative_path) {
        return Err(reader_failure(format!(
            "Invalid extraction path: {relative_path}"
        )));
    }
    let separated = relative_path.replace('\\', "/");
    for segment in separated.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(reader_failure(format!(
                "Invalid extraction path: {relative_path}"
            )));
        }
    }
    Ok(separated)
}
/// Split a path into (parent, basename).
fn split_parent(path: &str) -> (String, String) {
    let path = path.trim_end_matches(std::path::MAIN_SEPARATOR);
    match path.rfind(std::path::MAIN_SEPARATOR) {
        Some(0) => (std::path::MAIN_SEPARATOR.to_string(), path[1..].to_owned()),
        Some(index) => (path[..index].to_owned(), path[index + 1..].to_owned()),
        None => (".".to_owned(), path.to_owned()),
    }
}
