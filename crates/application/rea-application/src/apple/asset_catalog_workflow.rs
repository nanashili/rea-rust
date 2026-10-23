//! Read-only orchestration for compiled Apple asset catalogs.
//!
//! The workflow owns the bundle walk, bounded catalog reads, source identity
//! checks around `assetutil`, and the global projection used by CLI and MCP
//! adapters.  Provider adapters supply bundle entries and `assetutil` output;
//! they do not interpret catalog records.

use rea_core::{
    cancellation::Cancellation,
    evidence::{ArtifactEvidence, Location, Observation, Provider, Subject},
    failure::{Detail, Failure},
    json_output,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

pub const OPERATION: &str = "inspect_asset_catalog";
pub const MAX_CATALOG_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TOTAL_METADATA_BYTES: usize = 64 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 256 * 1024 * 1024;
pub const DEFAULT_LIMIT: usize = 1_000;
pub const MAX_LIMIT: usize = 10_000;
const PROVIDER: Provider = Provider {
    id: "rea-artifact-graph",
    name: "REA safe artifact graph provider",
    version: Some("1"),
};

/// Stable source identity captured by the bundle adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryIdentity {
    pub value: String,
}

/// Entry kinds are deliberately explicit so symlinks and special entries are
/// never accidentally followed as regular catalog files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Debug)]
pub struct CatalogEntry {
    pub path: String,
    pub adapter_path: String,
    pub kind: EntryKind,
    pub declared_size: Option<u64>,
    pub identity: EntryIdentity,
}

/// Bundle ownership and byte access remain with the caller-selected adapter.
pub trait BundleSource {
    fn entries(
        &self,
        bundle_path: &Path,
        cancellation: &Cancellation,
    ) -> Result<Vec<CatalogEntry>, Failure>;

    fn read_entry(
        &self,
        entry: &CatalogEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, Failure>;

    fn current_identity(
        &self,
        entry: &CatalogEntry,
        cancellation: &Cancellation,
    ) -> Result<EntryIdentity, Failure>;
}

/// The provider boundary for `/usr/bin/assetutil --info`.
pub trait Assetutil {
    fn inspect(&self, adapter_path: &Path, cancellation: &Cancellation) -> Result<String, Failure>;
}

pub use crate::apple::asset_catalog::ResourceReference;

#[derive(Clone, Debug)]
pub struct Page {
    pub offset: usize,
    pub limit: usize,
}

impl Page {
    pub fn validate(&self) -> Result<Self, Failure> {
        if self.limit == 0 || self.limit > MAX_LIMIT {
            return Err(invalid(
                "limit",
                format!("Expected an integer from 1 through {MAX_LIMIT}"),
            ));
        }
        Ok(self.clone())
    }
}

impl Default for Page {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: DEFAULT_LIMIT,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CatalogSummary {
    pub path: String,
    pub sha256: String,
    pub record_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CatalogRecord {
    pub catalog_path: String,
    pub catalog_sha256: String,
    pub index: usize,
    pub kind: String,
    pub asset_name: Option<String>,
    pub rendition_name: Option<String>,
    pub metadata: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RenditionMatch {
    pub catalog_path: String,
    pub catalog_sha256: String,
    pub record_index: usize,
    pub rendition_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ResourceKeyMatch {
    pub source_node_id: String,
    pub source_path: String,
    pub source_archive_sha256: String,
    pub field: String,
    pub key: String,
    pub status: String,
    pub renditions: Vec<RenditionMatch>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AssetCatalogResult {
    pub target_sha256: String,
    pub catalogs: Vec<CatalogSummary>,
    pub total_records: usize,
    pub offset: usize,
    pub limit: usize,
    pub records: Vec<CatalogRecord>,
    pub resource_key_matches: Vec<ResourceKeyMatch>,
    pub next_offset: Option<usize>,
    pub truncated: bool,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug)]
struct InspectedCatalog {
    summary: CatalogSummary,
    records: Vec<Map<String, Value>>,
}

pub struct AppleAssetCatalogWorkflow<'a, B, A> {
    bundle: &'a B,
    assetutil: &'a A,
}

impl<'a, B, A> AppleAssetCatalogWorkflow<'a, B, A>
where
    B: BundleSource,
    A: Assetutil,
{
    pub fn new(bundle: &'a B, assetutil: &'a A) -> Self {
        Self { bundle, assetutil }
    }

    pub fn inspect(
        &self,
        bundle_path: &Path,
        target_sha256: String,
        page: Page,
        resource_references: &[ResourceReference],
        cancellation: &Cancellation,
    ) -> Result<AssetCatalogResult, Failure> {
        let page = page.validate()?;
        let (catalogs, uninspected) = self.collect_catalogs(bundle_path, cancellation)?;
        let mut result = project_page(&target_sha256, &catalogs, &page, resource_references);

        if catalogs.is_empty() {
            result.limitations.push(
                "No compiled Assets.car catalog was found among the app bundle's regular files (symlinks are not followed); any resource keys are reported as unmatched.".to_owned(),
            );
        }
        if !uninspected.is_empty() {
            result.limitations.push(format!(
                "Asset catalog entries that are not regular files were not inspected, so resource keys reported as unmatched may resolve there: {}",
                uninspected.join(", "),
            ));
        }
        result.limitations.push(
            "Exact resource-key joins use only recognized image or asset key fields on decoded Interface Builder resource objects; other archive resource references are not inferred.".to_owned(),
        );
        Ok(result)
    }

    /// Build the canonical artifact Evidence used by the CLI and MCP adapters.
    pub fn inspect_evidence(
        &self,
        bundle_path: &Path,
        subject: Subject,
        page: Page,
        parameters: Value,
        resource_references: &[ResourceReference],
        resource_graph_truncated: bool,
        cancellation: &Cancellation,
    ) -> Result<ArtifactEvidence, Failure> {
        let target_sha256 = subject.sha256().to_owned();
        let mut result = self.inspect(
            bundle_path,
            target_sha256,
            page.clone(),
            resource_references,
            cancellation,
        )?;

        if resource_graph_truncated {
            result.limitations.push(
                "Interface Builder resource-key joins may be incomplete because the decoded UI graph was truncated.".to_owned(),
            );
        }

        ensure_active(cancellation)?;
        let locations = result
            .catalogs
            .iter()
            .map(|catalog| Location::ArtifactPath {
                path: catalog.path.clone(),
            })
            .collect();
        let limitations = result.limitations.clone();
        let evidence = ArtifactEvidence::new_with_exact_parameters(
            subject,
            PROVIDER,
            Observation {
                operation: OPERATION,
                limitations,
                result,
                locations,
            },
            parameters,
        )
        .map_err(|error| failure("invalid_evidence", "evidence", error.to_string()))?;

        ensure_evidence_fits_output_limit(&evidence)?;
        ensure_active(cancellation)?;
        Ok(evidence)
    }

    fn collect_catalogs(
        &self,
        bundle_path: &Path,
        cancellation: &Cancellation,
    ) -> Result<(Vec<InspectedCatalog>, Vec<String>), Failure> {
        let entries = self.bundle.entries(bundle_path, cancellation)?;
        let mut catalogs = Vec::new();
        let mut uninspected = Vec::new();
        let mut total_metadata_bytes = 0usize;

        for entry in entries {
            ensure_active(cancellation)?;
            if Path::new(&entry.path)
                .file_name()
                .and_then(|name| name.to_str())
                != Some("Assets.car")
            {
                continue;
            }
            if entry.kind != EntryKind::Regular {
                uninspected.push(format!("{} ({})", entry.path, entry.kind));
                continue;
            }

            let catalog = self.inspect_entry(&entry, cancellation)?;
            total_metadata_bytes = total_metadata_bytes
                .checked_add(catalog.metadata_bytes)
                .ok_or_else(|| {
                    limit("Combined asset catalog metadata exceeds the configured limit")
                })?;
            if total_metadata_bytes > MAX_TOTAL_METADATA_BYTES {
                return Err(limit(format!(
                    "Combined asset catalog metadata exceeds {MAX_TOTAL_METADATA_BYTES} bytes"
                )));
            }
            catalogs.push(catalog.catalog);
        }

        if catalogs.is_empty() && !uninspected.is_empty() {
            return Err(path_error(format!(
                "Asset catalog entries are not regular files and were not inspected: {}",
                uninspected.join(", ")
            )));
        }
        Ok((catalogs, uninspected))
    }

    fn inspect_entry(
        &self,
        entry: &CatalogEntry,
        cancellation: &Cancellation,
    ) -> Result<InspectedEntry, Failure> {
        let bytes = self.read_bounded(entry, cancellation)?;
        let sha256 = sha256_hex(&bytes);
        self.verify_identity(entry, cancellation, "before inspection")?;
        let output = self
            .assetutil
            .inspect(Path::new(&entry.adapter_path), cancellation)?;
        if output.len() > MAX_CATALOG_BYTES {
            return Err(limit(format!(
                "assetutil output exceeds {MAX_CATALOG_BYTES} bytes: {}",
                entry.path
            )));
        }
        self.verify_identity(entry, cancellation, "during inspection")?;
        let after = self.read_bounded(entry, cancellation)?;
        if sha256_hex(&after) != sha256 {
            return Err(integrity(format!(
                "Asset catalog changed during inspection: {}",
                entry.path
            )));
        }

        let value: Value = serde_json::from_str(&output).map_err(|error| {
            format_error(
                "assetutil returned invalid JSON",
                format!("{}: {error}", entry.path),
            )
        })?;
        let records = parse_records(value, &entry.path)?;
        Ok(InspectedEntry {
            metadata_bytes: output.len(),
            catalog: InspectedCatalog {
                summary: CatalogSummary {
                    path: entry.path.clone(),
                    sha256,
                    record_count: records.len(),
                },
                records,
            },
        })
    }

    fn read_bounded(
        &self,
        entry: &CatalogEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, Failure> {
        if entry
            .declared_size
            .is_some_and(|size| size > MAX_CATALOG_BYTES as u64)
        {
            return Err(limit(format!(
                "Asset catalog exceeds {MAX_CATALOG_BYTES} bytes: {}",
                entry.path
            )));
        }
        let bytes = self.bundle.read_entry(entry, cancellation)?;
        ensure_active(cancellation)?;
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err(limit(format!(
                "Asset catalog exceeds byte limit: {}",
                entry.path
            )));
        }
        Ok(bytes)
    }

    fn verify_identity(
        &self,
        entry: &CatalogEntry,
        cancellation: &Cancellation,
        stage: &str,
    ) -> Result<(), Failure> {
        let current = self.bundle.current_identity(entry, cancellation)?;
        if current != entry.identity {
            return Err(integrity(format!(
                "Asset catalog changed {stage}: {}",
                entry.path
            )));
        }
        Ok(())
    }
}

struct InspectedEntry {
    catalog: InspectedCatalog,
    metadata_bytes: usize,
}

fn parse_records(value: Value, path: &str) -> Result<Vec<Map<String, Value>>, Failure> {
    let array = value.as_array().ok_or_else(|| {
        format_error(
            "assetutil output must be a JSON array",
            format!("assetutil returned a non-array for {path}"),
        )
    })?;
    array
        .iter()
        .enumerate()
        .map(|(index, record)| {
            record.as_object().cloned().ok_or_else(|| {
                format_error(
                    "assetutil returned an unsupported record",
                    format!("record {index} in {path} is not a JSON object"),
                )
            })
        })
        .collect()
}

fn project_page(
    target_sha256: &str,
    catalogs: &[InspectedCatalog],
    page: &Page,
    references: &[ResourceReference],
) -> AssetCatalogResult {
    let all = catalogs
        .iter()
        .flat_map(|catalog| {
            catalog.records.iter().enumerate().map(|(index, metadata)| {
                let asset_name = string_field(metadata, "Name");
                let rendition_name = string_field(metadata, "RenditionName");
                CatalogRecord {
                    catalog_path: catalog.summary.path.clone(),
                    catalog_sha256: catalog.summary.sha256.clone(),
                    index,
                    kind: if asset_name.is_some() || rendition_name.is_some() {
                        "rendition".to_owned()
                    } else {
                        "catalog".to_owned()
                    },
                    asset_name,
                    rendition_name,
                    metadata: metadata.clone(),
                }
            })
        })
        .collect::<Vec<_>>();
    let end = page.offset.saturating_add(page.limit).min(all.len());
    let records = if page.offset >= all.len() {
        Vec::new()
    } else {
        all[page.offset..end].to_vec()
    };
    let next_offset = if end < all.len() { Some(end) } else { None };
    let mut by_asset = BTreeMap::<String, Vec<&CatalogRecord>>::new();
    for record in &all {
        if record.kind == "rendition" {
            if let Some(name) = &record.asset_name {
                by_asset.entry(name.clone()).or_default().push(record);
            }
        }
    }
    let resource_key_matches = references
        .iter()
        .map(|reference| {
            let renditions = by_asset
                .get(&reference.key)
                .into_iter()
                .flatten()
                .map(|record| RenditionMatch {
                    catalog_path: record.catalog_path.clone(),
                    catalog_sha256: record.catalog_sha256.clone(),
                    record_index: record.index,
                    rendition_name: record.rendition_name.clone(),
                })
                .collect::<Vec<_>>();
            let status = match renditions.len() {
                0 => "unmatched",
                1 => "matched",
                _ => "ambiguous",
            };
            ResourceKeyMatch {
                source_node_id: reference.source_node_id.clone(),
                source_path: reference.source_path.clone(),
                source_archive_sha256: reference.source_archive_sha256.clone(),
                field: reference.field.clone(),
                key: reference.key.clone(),
                status: status.to_owned(),
                renditions,
            }
        })
        .collect();

    AssetCatalogResult {
        target_sha256: target_sha256.to_owned(),
        catalogs: catalogs.iter().map(|catalog| catalog.summary.clone()).collect(),
        total_records: all.len(),
        offset: page.offset,
        limit: page.limit,
        records,
        resource_key_matches,
        next_offset,
        truncated: page.offset > 0 || next_offset.is_some(),
        limitations: vec![
            "Rendition metadata is reported as emitted by the installed assetutil version; private fields and platform-specific interpretations are not normalized.".to_owned(),
            "Asset catalog inspection does not decode or extract rendition image bytes.".to_owned(),
        ],
    }
}

fn string_field(metadata: &Map<String, Value>, name: &str) -> Option<String> {
    metadata
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn ensure_active(cancellation: &Cancellation) -> Result<(), Failure> {
    cancellation.reason().map_or(Ok(()), |reason| {
        Err(Failure::new(
            "cancelled",
            "cancellation",
            format!("Asset catalog inspection cancelled: {reason}"),
            true,
            "Retry the inspection after cancellation has cleared".to_owned(),
            BTreeMap::new(),
        ))
    })
}

fn ensure_evidence_fits_output_limit(evidence: &ArtifactEvidence) -> Result<(), Failure> {
    match json_output::admitted_length(evidence, MAX_OUTPUT_BYTES) {
        Ok(_) => Ok(()),
        Err(json_output::Error::Limit { maximum }) => Err(limit(format!(
            "serialized asset catalog Evidence exceeds {maximum} bytes"
        ))),
        Err(json_output::Error::Encoding(error)) => Err(failure(
            "provider_output_invalid",
            "format",
            error.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_core::evidence::{Architecture, NativeFormat};
    use std::path::Path;

    struct EmptyBundle;

    impl BundleSource for EmptyBundle {
        fn entries(
            &self,
            _bundle_path: &Path,
            _cancellation: &Cancellation,
        ) -> Result<Vec<CatalogEntry>, Failure> {
            Ok(Vec::new())
        }

        fn read_entry(
            &self,
            entry: &CatalogEntry,
            _cancellation: &Cancellation,
        ) -> Result<Vec<u8>, Failure> {
            Err(Failure::new(
                "unexpected_read",
                "internal",
                format!("Unexpected catalog read for {}", entry.path),
                false,
                "Report this unexpected workflow access.".into(),
                BTreeMap::new(),
            ))
        }

        fn current_identity(
            &self,
            entry: &CatalogEntry,
            _cancellation: &Cancellation,
        ) -> Result<EntryIdentity, Failure> {
            Err(Failure::new(
                "unexpected_identity_check",
                "internal",
                format!("Unexpected identity check for {}", entry.path),
                false,
                "Report this unexpected workflow access.".into(),
                BTreeMap::new(),
            ))
        }
    }

    struct UnexpectedAssetutil;

    impl Assetutil for UnexpectedAssetutil {
        fn inspect(&self, path: &Path, _cancellation: &Cancellation) -> Result<String, Failure> {
            Err(Failure::new(
                "unexpected_assetutil",
                "internal",
                format!("Unexpected assetutil call for {}", path.display()),
                false,
                "Report this unexpected provider invocation.".into(),
                BTreeMap::new(),
            ))
        }
    }

    #[test]
    fn evidence_preserves_selected_macho_and_supplied_parameters() {
        let bundle_path = Path::new("/Applications/Demo.app");
        let subject = Subject::new(
            "/Applications/Demo.app/Contents/MacOS/Demo",
            "a".repeat(64),
            NativeFormat::MachO,
            Some(Architecture::Arm64),
        )
        .expect("valid Mach-O subject");
        let evidence = AppleAssetCatalogWorkflow::new(&EmptyBundle, &UnexpectedAssetutil)
            .inspect_evidence(
                bundle_path,
                subject,
                Page {
                    offset: 2,
                    limit: 10,
                },
                serde_json::json!({"offset": 2}),
                &[],
                false,
                &Cancellation::default(),
            )
            .expect("an empty catalog inventory is an observation");
        let evidence = serde_json::to_value(evidence).expect("Evidence serializes");

        assert_eq!(evidence["subject"]["format"], "mach-o");
        assert_eq!(
            evidence["subject"]["local_path"],
            "/Applications/Demo.app/Contents/MacOS/Demo"
        );
        assert_eq!(evidence["subject"]["architecture"], "arm64");
        assert_eq!(evidence["parameters"], serde_json::json!({"offset": 2}));
        assert_eq!(evidence["normalized_result"]["offset"], 2);
        assert_eq!(evidence["normalized_result"]["limit"], 10);
    }
}

fn failure(code: &'static str, category: &'static str, message: String) -> Failure {
    Failure::new(
        code,
        category,
        message,
        false,
        "Review the reported asset catalog details".to_owned(),
        BTreeMap::from([(
            "operation",
            Detail::Text("inspect_asset_catalog".to_owned()),
        )]),
    )
}

fn invalid(field: &'static str, message: String) -> Failure {
    let mut result = failure("invalid_input", "input", message);
    result.detail("field", Detail::Text(field.to_owned()));
    result
}

fn path_error(message: String) -> Failure {
    failure("invalid_path", "path", message)
}

fn limit(message: impl Into<String>) -> Failure {
    failure("resource_limit", "limit", message.into())
}

fn integrity(message: String) -> Failure {
    failure("source_changed", "integrity", message)
}

fn format_error(category_message: &'static str, message: String) -> Failure {
    failure(
        "provider_output_invalid",
        "format",
        format!("{category_message}: {message}"),
    )
}

impl std::fmt::Display for EntryKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Regular => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::Other => "other",
        })
    }
}
