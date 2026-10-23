//! Application-owned projection of compiled Apple asset catalog metadata.
//!
//! The assetutil adapter is responsible for invoking the installed tool and
//! decoding its JSON. This module owns the stable record shape, pagination,
//! and resource-reference matching used by callers.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;

/// Direct scalar fields that commonly contain an asset resource key.
pub const RESOURCE_KEY_FIELDS: &[&str] = &[
    "image",
    "imageName",
    "image_name",
    "resourceName",
    "resource_name",
    "assetName",
    "asset_name",
    "UIImageName",
    "NSImageName",
];

const LIMITATION_PRIVATE_METADATA: &str = "Rendition metadata is reported as emitted by the installed assetutil version; private fields and platform-specific interpretations are not normalized.";
const LIMITATION_IMAGE_BYTES: &str =
    "Asset catalog inspection does not decode or extract rendition image bytes.";

/// Errors raised while converting assetutil JSON into application records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetCatalogError {
    OutputMustBeArray,
    RecordMustBeObject { index: usize },
    InvalidInput { field: &'static str, reason: String },
}

impl fmt::Display for AssetCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputMustBeArray => formatter.write_str("assetutil output must be a JSON array"),
            Self::RecordMustBeObject { index } => {
                write!(formatter, "assetutil record {index} is not a JSON object")
            }
            Self::InvalidInput { field, reason } => write!(formatter, "invalid {field}: {reason}"),
        }
    }
}

impl std::error::Error for AssetCatalogError {}

/// Return recognized direct string resource references in source order.
pub fn apple_resource_key_fields(attributes: &Map<String, Value>) -> Vec<(String, String)> {
    attributes
        .iter()
        .filter_map(|(field, value)| {
            if !RESOURCE_KEY_FIELDS.contains(&field.as_str()) {
                return None;
            }

            let Value::String(key) = value else {
                return None;
            };
            if key.is_empty() {
                return None;
            }

            Some((field.clone(), key.clone()))
        })
        .collect()
}

/// Parse assetutil output while preserving every JSON-compatible metadata field.
pub fn parse_asset_catalog_records(
    value: &Value,
) -> Result<Vec<Map<String, Value>>, AssetCatalogError> {
    let Value::Array(records) = value else {
        return Err(AssetCatalogError::OutputMustBeArray);
    };

    records
        .iter()
        .enumerate()
        .map(|(index, record)| match record {
            Value::Object(metadata) => Ok(metadata.clone()),
            _ => Err(AssetCatalogError::RecordMustBeObject { index }),
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetCatalog {
    pub path: String,
    pub sha256: String,
    pub records: Vec<Map<String, Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceReference {
    pub source_node_id: String,
    pub source_path: String,
    pub source_archive_sha256: String,
    pub field: String,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetCatalogPageInput {
    pub target_sha256: String,
    pub catalogs: Vec<AssetCatalog>,
    pub offset: usize,
    pub limit: usize,
    #[serde(default)]
    pub resource_references: Vec<ResourceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogSummary {
    pub path: String,
    pub sha256: String,
    pub record_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AssetCatalogRecordKind {
    Catalog,
    Rendition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetCatalogRecord {
    pub catalog_path: String,
    pub catalog_sha256: String,
    pub index: usize,
    pub kind: AssetCatalogRecordKind,
    pub asset_name: Option<String>,
    pub rendition_name: Option<String>,
    pub metadata: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResourceKeyMatchStatus {
    Matched,
    Ambiguous,
    Unmatched,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenditionMatch {
    pub catalog_path: String,
    pub catalog_sha256: String,
    pub record_index: usize,
    pub rendition_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceKeyMatch {
    pub source_node_id: String,
    pub source_path: String,
    pub source_archive_sha256: String,
    pub field: String,
    pub key: String,
    pub status: ResourceKeyMatchStatus,
    pub renditions: Vec<RenditionMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetCatalogPage {
    pub target_sha256: String,
    pub catalogs: Vec<CatalogSummary>,
    pub total_records: usize,
    pub offset: usize,
    pub limit: usize,
    pub records: Vec<AssetCatalogRecord>,
    pub resource_key_matches: Vec<ResourceKeyMatch>,
    pub next_offset: Option<usize>,
    pub truncated: bool,
    pub limitations: Vec<String>,
}

/// Flatten catalogs, match resource references, and apply stable global pagination.
pub fn project_asset_catalog_page(
    input: AssetCatalogPageInput,
) -> Result<AssetCatalogPage, AssetCatalogError> {
    validate_page_input(&input)?;

    let all_records = flatten_catalogs(&input.catalogs);
    let page_end = input
        .offset
        .saturating_add(input.limit)
        .min(all_records.len());
    let records = if input.offset >= all_records.len() {
        Vec::new()
    } else {
        all_records[input.offset..page_end].to_vec()
    };
    let next_offset = if page_end < all_records.len() && input.offset < all_records.len() {
        Some(page_end)
    } else {
        None
    };

    Ok(AssetCatalogPage {
        target_sha256: input.target_sha256,
        catalogs: summarize_catalogs(&input.catalogs),
        total_records: all_records.len(),
        offset: input.offset,
        limit: input.limit,
        records,
        resource_key_matches: match_resource_references(&all_records, &input.resource_references),
        next_offset,
        truncated: input.offset > 0 || page_end < all_records.len(),
        limitations: vec![
            LIMITATION_PRIVATE_METADATA.to_owned(),
            LIMITATION_IMAGE_BYTES.to_owned(),
        ],
    })
}

fn validate_page_input(input: &AssetCatalogPageInput) -> Result<(), AssetCatalogError> {
    validate_sha256("target_sha256", &input.target_sha256)?;
    if input.limit == 0 || input.limit > 10_000 {
        return Err(AssetCatalogError::InvalidInput {
            field: "limit",
            reason: "must be between 1 and 10000".to_owned(),
        });
    }
    for catalog in &input.catalogs {
        if catalog.path.is_empty() {
            return Err(AssetCatalogError::InvalidInput {
                field: "catalog.path",
                reason: "must not be empty".to_owned(),
            });
        }
        validate_sha256("catalog.sha256", &catalog.sha256)?;
    }
    for reference in &input.resource_references {
        validate_non_empty(
            "resource_reference.source_node_id",
            &reference.source_node_id,
        )?;
        validate_non_empty("resource_reference.source_path", &reference.source_path)?;
        validate_sha256(
            "resource_reference.source_archive_sha256",
            &reference.source_archive_sha256,
        )?;
        validate_non_empty("resource_reference.field", &reference.field)?;
        validate_non_empty("resource_reference.key", &reference.key)?;
    }
    Ok(())
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), AssetCatalogError> {
    if value.is_empty() {
        Err(AssetCatalogError::InvalidInput {
            field,
            reason: "must not be empty".to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), AssetCatalogError> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if valid {
        Ok(())
    } else {
        Err(AssetCatalogError::InvalidInput {
            field,
            reason: "must be a lowercase 64-character SHA-256 digest".to_owned(),
        })
    }
}

fn flatten_catalogs(catalogs: &[AssetCatalog]) -> Vec<AssetCatalogRecord> {
    catalogs
        .iter()
        .flat_map(|catalog| {
            catalog.records.iter().enumerate().map(|(index, metadata)| {
                let asset_name = string_field(metadata, "Name");
                let rendition_name = string_field(metadata, "RenditionName");
                let kind = record_kind(asset_name.as_deref(), rendition_name.as_deref());
                AssetCatalogRecord {
                    catalog_path: catalog.path.clone(),
                    catalog_sha256: catalog.sha256.clone(),
                    index,
                    kind,
                    asset_name,
                    rendition_name,
                    metadata: metadata.clone(),
                }
            })
        })
        .collect()
}

fn string_field(metadata: &Map<String, Value>, field: &str) -> Option<String> {
    metadata
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn record_kind(asset_name: Option<&str>, rendition_name: Option<&str>) -> AssetCatalogRecordKind {
    if asset_name.is_some() || rendition_name.is_some() {
        AssetCatalogRecordKind::Rendition
    } else {
        AssetCatalogRecordKind::Catalog
    }
}

fn summarize_catalogs(catalogs: &[AssetCatalog]) -> Vec<CatalogSummary> {
    catalogs
        .iter()
        .map(|catalog| CatalogSummary {
            path: catalog.path.clone(),
            sha256: catalog.sha256.clone(),
            record_count: catalog.records.len(),
        })
        .collect()
}

fn match_resource_references(
    records: &[AssetCatalogRecord],
    references: &[ResourceReference],
) -> Vec<ResourceKeyMatch> {
    references
        .iter()
        .map(|reference| {
            let renditions = records
                .iter()
                .filter(|record| {
                    matches!(record.kind, AssetCatalogRecordKind::Rendition)
                        && record.asset_name.as_deref() == Some(reference.key.as_str())
                })
                .map(|record| RenditionMatch {
                    catalog_path: record.catalog_path.clone(),
                    catalog_sha256: record.catalog_sha256.clone(),
                    record_index: record.index,
                    rendition_name: record.rendition_name.clone(),
                })
                .collect::<Vec<_>>();
            let status = match renditions.len() {
                0 => ResourceKeyMatchStatus::Unmatched,
                1 => ResourceKeyMatchStatus::Matched,
                _ => ResourceKeyMatchStatus::Ambiguous,
            };
            ResourceKeyMatch {
                source_node_id: reference.source_node_id.clone(),
                source_path: reference.source_path.clone(),
                source_archive_sha256: reference.source_archive_sha256.clone(),
                field: reference.field.clone(),
                key: reference.key.clone(),
                status,
                renditions,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn digest(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    #[test]
    fn parses_only_json_objects_and_preserves_metadata() {
        let value = json!([{ "Name": "Icon", "Scale": 2 }, { "opaque": [true, null] }]);

        let records = parse_asset_catalog_records(&value).expect("objects should parse");

        assert_eq!(records[0]["Name"], "Icon");
        assert_eq!(records[1]["opaque"], json!([true, null]));
        assert_eq!(
            parse_asset_catalog_records(&json!(["bad"])),
            Err(AssetCatalogError::RecordMustBeObject { index: 0 })
        );
    }

    #[test]
    fn projects_global_pages_and_resource_match_statuses() {
        let catalog = AssetCatalog {
            path: "Assets.xcassets".to_owned(),
            sha256: digest('a'),
            records: vec![
                serde_json::from_value(json!({"Name": "Icon", "RenditionName": "2x"})).unwrap(),
                serde_json::from_value(json!({"Name": "Icon", "RenditionName": "3x"})).unwrap(),
                serde_json::from_value(json!({"Name": "Other", "RenditionName": "1x"})).unwrap(),
            ],
        };
        let page = project_asset_catalog_page(AssetCatalogPageInput {
            target_sha256: digest('b'),
            catalogs: vec![catalog],
            offset: 1,
            limit: 1,
            resource_references: vec![ResourceReference {
                source_node_id: "node".to_owned(),
                source_path: "Info.plist".to_owned(),
                source_archive_sha256: digest('c'),
                field: "image".to_owned(),
                key: "Icon".to_owned(),
            }],
        })
        .expect("valid page");

        assert_eq!(page.records[0].index, 1);
        assert_eq!(page.next_offset, Some(2));
        assert!(page.truncated);
        assert_eq!(
            page.resource_key_matches[0].status,
            ResourceKeyMatchStatus::Ambiguous
        );
        assert_eq!(page.resource_key_matches[0].renditions.len(), 2);
    }

    #[test]
    fn resource_key_fields_ignore_nested_and_empty_values() {
        let attributes = serde_json::from_value(json!({
            "image": "Icon",
            "asset_name": "",
            "unrecognized": "Other",
            "resourceName": {"value": "Nested"}
        }))
        .unwrap();

        assert_eq!(
            apple_resource_key_fields(&attributes),
            vec![("image".to_owned(), "Icon".to_owned())]
        );
    }
}
