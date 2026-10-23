//! Exclusive multi-file publication, a port of
//! `src/browser/assets/PublishWebScripts.ts` and the output tree in
//! `src/artifacts/SafeOutputTree.ts`. Verified bytes and a manifest are
//! published into one operation-owned directory, rolling back partial work.
use super::capture::{CapturedContent, SelectedCapture};
use super::node;
use super::plan::{self, PlannedWebScript};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

const PLAYWRIGHT_RESPONSE_BODY_PROVENANCE_LIMITATION: &str = "Captured response-body bytes are the result of Playwright's Response.body() API. Playwright may satisfy that API with a credentialed follow-up load of the request URL when CDP has no body, so transaction and event links do not verify that retained bytes came from the original network transaction.";

const LIMITATIONS: [&str; 5] = [
    "Only script bytes retained in this capture are exported. Sources are not refetched or executed, and a response or Debugger source does not prove execution.",
    "Ordinary unambiguous URL paths preserve relative module layouts by origin, including case-distinct spellings. Query variants, exact path collisions, file/directory prefixes, inline sources, and unrepresentable paths are isolated. A case-distinct pair is isolated only when the destination filesystem cannot store both spellings; the record names that pair. Browser module relationships of isolated paths remain unknown.",
    "Local JavaScript analysis does not implement browser import maps, root-relative URL resolution, remote URL loading, or browser runtime behavior. It may strip import queries and fragments; isolated variants are not canonical targets.",
    "Source-map declarations are retained as metadata. No source maps or missing dependencies are fetched or reconstructed.",
    "Scenario response bytes preserve the output of Playwright's Response.body() API; any source-body provenance caveat from the capture is retained in this manifest. Debugger sources are the exposed text encoded as UTF-8. Redacted bytes are exported exactly as retained, and may no longer parse as JavaScript.",
];

const NO_SCRIPTS_LIMITATION: &str = "No script bytes were exportable. Include script sources in inspect_web_page or select response_body in capture_browser_scenario, then capture again.";

/// `ArtifactReaderFailure`: a typed reason and message carried to the export
/// boundary, where it is mapped onto `WebScriptExportError` with the raw
/// caller-selected `output_directory` target.
pub struct ReaderFailure {
    pub reason: &'static str,
    pub message: String,
}

impl ReaderFailure {
    fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

/// Outcome of a successful publication.
pub struct Publication {
    pub manifest: Value,
    pub manifest_path: String,
    pub manifest_sha256: String,
    pub manifest_bytes: usize,
    pub output_root: String,
}

/// `publishWebScripts`.
pub fn publish(
    capture_path: &str,
    output_directory: &str,
    capture_sha256: &str,
    capture: &SelectedCapture,
) -> Result<Publication, ReaderFailure> {
    let planned = plan::plan(&capture.scripts);
    let scenario_response_body_captured = capture.kind == "browser-scenario"
        && capture.scripts.iter().any(|script| {
            script.source.get("kind").and_then(Value::as_str) == Some("scenario-response")
                && matches!(
                    &script.content,
                    CapturedContent::Captured { representation, .. }
                        if representation == "playwright-response-body-bytes"
                            || representation == "browser-decoded-response-bytes"
                )
        });
    let provenance_limitations = if scenario_response_body_captured
        && !capture
            .limitations
            .iter()
            .any(|limitation| limitation == PLAYWRIGHT_RESPONSE_BODY_PROVENANCE_LIMITATION)
    {
        vec![PLAYWRIGHT_RESPONSE_BODY_PROVENANCE_LIMITATION.to_owned()]
    } else {
        Vec::new()
    };

    let tree = OutputTree::create(output_directory)?;
    let result = publish_into(
        &tree,
        capture_path,
        capture_sha256,
        capture,
        &planned,
        &provenance_limitations,
    );
    match result {
        Ok(publication) => {
            tree.commit()?;
            Ok(publication)
        }
        Err(error) => {
            tree.rollback();
            Err(error)
        }
    }
}

fn publish_into(
    tree: &OutputTree,
    capture_path: &str,
    capture_sha256: &str,
    capture: &SelectedCapture,
    planned: &[PlannedWebScript],
    provenance_limitations: &[String],
) -> Result<Publication, ReaderFailure> {
    let mut records: Vec<Value> = Vec::with_capacity(planned.len());
    for (index, item) in planned.iter().enumerate() {
        records.push(publish_planned_script(tree, &capture.scripts[index], item)?);
    }
    let any_exported = records
        .iter()
        .any(|record| record["content"]["state"].as_str() == Some("exported"));

    let analysis_input = if any_exported {
        json!({
            "input_path": node::join(&tree.output_root, "files"),
            "format": "directory",
        })
    } else {
        Value::Null
    };

    let mut limitations: Vec<String> = Vec::new();
    limitations.extend(capture.limitations.iter().cloned());
    limitations.extend(provenance_limitations.iter().cloned());
    limitations.extend(LIMITATIONS.iter().map(|text| (*text).to_owned()));
    if !any_exported {
        limitations.push(NO_SCRIPTS_LIMITATION.to_owned());
    }

    let mut manifest = Map::new();
    manifest.insert("capture_path".into(), json!(capture_path));
    manifest.insert("capture_sha256".into(), json!(capture_sha256));
    manifest.insert("capture_kind".into(), json!(capture.kind));
    manifest.insert(
        "source_evidence_id".into(),
        capture
            .source_evidence_id
            .clone()
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    manifest.insert("capture_completeness".into(), capture.completeness.clone());
    manifest.insert("output_directory".into(), json!(tree.output_root));
    manifest.insert("analysis_input".into(), analysis_input);
    manifest.insert("scripts".into(), Value::Array(records));
    manifest.insert(
        "limitations".into(),
        Value::Array(limitations.into_iter().map(Value::String).collect()),
    );
    let manifest = Value::Object(manifest);

    let serialized = format!("{}\n", to_pretty_two_space(&manifest));
    let bytes = serialized.into_bytes();
    let digest = format!("{:x}", Sha256::digest(&bytes));

    tree.write_raw("manifest.json", &bytes)?;

    Ok(Publication {
        manifest,
        manifest_path: node::join(&tree.output_root, "manifest.json"),
        manifest_sha256: digest,
        manifest_bytes: bytes.len(),
        output_root: tree.output_root.clone(),
    })
}

fn publish_planned_script(
    tree: &OutputTree,
    script: &super::capture::CapturedWebScript,
    item: &PlannedWebScript,
) -> Result<Value, ReaderFailure> {
    let CapturedContent::Captured { bytes, sha256, .. } = &script.content else {
        return Ok(item.record.clone());
    };
    if item.record["content"]["state"].as_str() != Some("exported") {
        return Ok(item.record.clone());
    }
    let relative_path = item.exported_relative_path.clone().unwrap_or_default();
    tree.write_file(&format!("files/{relative_path}"), bytes, sha256)?;
    Ok(item.record.clone())
}

/// Serialize JSON exactly like `JSON.stringify(value, null, 2)`.
fn to_pretty_two_space(value: &Value) -> String {
    let mut output = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"  ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut output, formatter);
    serde::Serialize::serialize(value, &mut serializer).expect("manifest serializes");
    String::from_utf8(output).expect("manifest is UTF-8")
}

/// Operation-owned output tree. Ported from `SafeOutputTree.create`/`write`/`commit`.
struct OutputTree {
    output_root: String,
    staging: String,
    committed: std::cell::Cell<bool>,
}

impl OutputTree {
    fn create(output_directory: &str) -> Result<Self, ReaderFailure> {
        if !node::is_absolute(output_directory) {
            return Err(ReaderFailure::new(
                "path",
                "Extraction output root must be absolute",
            ));
        }
        let (parent, name) = node::split_parent(output_directory);
        if name == "." || name == ".." || name.is_empty() {
            return Err(ReaderFailure::new("path", "Invalid extraction output root"));
        }
        let parent = node::realpath(&parent).map_err(|_| {
            ReaderFailure::new("unavailable", "Extraction output parent is unavailable")
        })?;
        let canonical_output = node::join(&parent, &name);
        if std::fs::symlink_metadata(&canonical_output).is_ok() {
            return Err(ReaderFailure::new(
                "path",
                "Extraction output root already exists",
            ));
        }
        let staging = node::join(&parent, &format!(".rea-write-{}", node::random_uuid()));
        make_private_directory(&staging)?;
        Ok(Self {
            output_root: canonical_output,
            staging,
            committed: std::cell::Cell::new(false),
        })
    }

    fn write_file(
        &self,
        relative_path: &str,
        bytes: &[u8],
        sha256: &str,
    ) -> Result<(), ReaderFailure> {
        if format!("{:x}", Sha256::digest(bytes)) != sha256 {
            return Err(ReaderFailure::new(
                "io",
                format!("Published bytes disagree with inventory: $output/{relative_path}"),
            ));
        }
        self.write_raw(relative_path, bytes)
    }

    fn write_raw(&self, relative_path: &str, bytes: &[u8]) -> Result<(), ReaderFailure> {
        let destination = node::join(
            &self.staging,
            &relative_path.replace('/', &std::path::MAIN_SEPARATOR.to_string()),
        );
        if let Some(parent) = Path::new(&destination).parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                ReaderFailure::new("io", format!("Could not create output parent: {error}"))
            })?;
        }
        write_exclusive_nofollow(&destination, bytes).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                ReaderFailure::new(
                    "path",
                    format!("Destination filesystem cannot store both {relative_path}"),
                )
            } else {
                ReaderFailure::new(
                    "io",
                    format!("Could not exclusively create output path: {error}"),
                )
            }
        })
    }

    fn commit(&self) -> Result<(), ReaderFailure> {
        std::fs::rename(&self.staging, &self.output_root).map_err(|error| {
            ReaderFailure::new("io", format!("Could not commit output: {error}"))
        })?;
        self.committed.set(true);
        Ok(())
    }

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

fn make_private_directory(path: &str) -> Result<(), ReaderFailure> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(false)
            .mode(0o700)
            .create(path)
            .map_err(|error| {
                ReaderFailure::new("io", format!("Could not create staging directory: {error}"))
            })
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path).map_err(|error| {
            ReaderFailure::new("io", format!("Could not create staging directory: {error}"))
        })
    }
}

fn write_exclusive_nofollow(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)
}
