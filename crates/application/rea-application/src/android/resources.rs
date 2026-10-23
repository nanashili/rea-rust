//! Application-owned selection of retained Android resource facts.

use crate::artifacts::inspection::invalid_for;
use rea_core::json_output;
use rea_core::{
    evidence::{ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject},
    failure::Failure,
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::android_package::{self, ResourceEntry, ResourceVariant};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};

pub const OPERATION: &str = "inspect_android_resource";
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const PROVIDER: Provider = Provider {
    id: "android-package-reader",
    name: "REA Android package reader",
    version: Some("1"),
};

#[derive(Debug, Clone, Default)]
pub struct ResourceSelector {
    pub resource_id: Option<String>,
    pub package_id: Option<u32>,
    pub type_id: Option<u32>,
    pub entry_index: Option<u32>,
    pub name: Option<String>,
    pub locale: Option<String>,
    pub region: Option<String>,
    pub density: Option<u16>,
    pub sdk: Option<u16>,
    pub orientation: Option<u8>,
}

#[derive(Debug, Serialize)]
pub struct ResourceInspection {
    pub selector: ResourceSelectorView,
    pub matches: Vec<ResourceMatch>,
    pub packages: Vec<android_package::ResourcePackage>,
    pub pools: Vec<android_package::ResourcePool>,
    pub string_pool: android_package::ResourceStringPool,
    pub resource_paths: Vec<String>,
    pub resource_count: usize,
    pub coverage: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ResourceSelectorView {
    pub resource_id: Option<String>,
    pub package_id: Option<u32>,
    pub type_id: Option<u32>,
    pub entry_index: Option<u32>,
    pub name: Option<String>,
    pub locale: Option<String>,
    pub region: Option<String>,
    pub density: Option<u16>,
    pub sdk: Option<u16>,
    pub orientation: Option<u8>,
}

#[derive(Debug, Serialize)]
pub struct ResourceMatch {
    pub entry: ResourceEntry,
    pub variants: Vec<ResourceVariant>,
    pub parent_id: Option<u32>,
    pub complex_values: Vec<android_package::ResourceComplexValue>,
}

pub fn inspect_android_resource(
    report: &android_package::Report,
    selector: &ResourceSelector,
) -> Result<ResourceInspection, Failure> {
    validate_selector(selector)?;

    let selector_view = ResourceSelectorView {
        resource_id: selector.resource_id.clone(),
        package_id: selector.package_id,
        type_id: selector.type_id,
        entry_index: selector.entry_index,
        name: selector.name.clone(),
        locale: selector.locale.clone(),
        region: selector.region.clone(),
        density: selector.density,
        sdk: selector.sdk,
        orientation: selector.orientation,
    };
    let candidates = report
        .resource_entries
        .iter()
        .filter(|entry| matches_entry(entry, selector))
        .collect::<Vec<_>>();
    if selector.name.is_some()
        && candidates
            .iter()
            .all(|entry| entry.key_name.is_none() && entry.qualified_name.is_none())
    {
        return Err(invalid_for(
            OPERATION,
            "name",
            "Resource names are unavailable in the retained resource symbol facts.".into(),
        ));
    }
    let configured = candidates
        .into_iter()
        .filter(|entry| matches_configuration(&entry.configuration, selector))
        .collect::<Vec<_>>();
    if configured.is_empty() && has_configuration_selector(selector) {
        return Err(invalid_for(
            OPERATION,
            "configuration",
            "No retained resource variant has complete qualifiers matching the exact configuration selector.".into(),
        ));
    }
    let matches = group_resource_matches(&report.resource_variants, configured, selector);
    if matches.is_empty() {
        return Err(invalid_for(
            OPERATION,
            "resource",
            "No retained Android resource matched the exact selector.".into(),
        ));
    }
    if selector.name.is_some() && matches.len() > 1 {
        return Err(invalid_for(
            OPERATION,
            "name",
            "The symbolic resource name is ambiguous across retained resource packages or configurations.".into(),
        ));
    }
    let coverage = resource_coverage(&matches);
    let mut package_ids = matches
        .iter()
        .map(|resource| resource.entry.package_id)
        .collect::<Vec<_>>();
    package_ids.sort_unstable();
    package_ids.dedup();
    let packages = report
        .resource_packages
        .iter()
        .filter(|package| package_ids.binary_search(&package.package_id).is_ok())
        .cloned()
        .collect();
    let pools = report
        .resource_pools
        .iter()
        .filter(|pool| package_ids.binary_search(&pool.package_id).is_ok())
        .cloned()
        .collect();
    Ok(ResourceInspection {
        selector: selector_view,
        matches,
        packages,
        pools,
        string_pool: report.resource_string_pool.clone(),
        resource_paths: report.resource_paths.clone(),
        resource_count: report.resource_count,
        coverage,
    })
}

fn validate_selector(selector: &ResourceSelector) -> Result<(), Failure> {
    for (field, value) in [
        ("resource_id", selector.resource_id.as_deref()),
        ("name", selector.name.as_deref()),
        ("locale", selector.locale.as_deref()),
        ("region", selector.region.as_deref()),
    ] {
        if value.is_some_and(str::is_empty) {
            return Err(invalid_for(
                OPERATION,
                field,
                format!("{field} must be a non-empty string."),
            ));
        }
    }

    let has_identity_selector = selector.resource_id.is_some()
        || selector.name.is_some()
        || selector.package_id.is_some()
        || selector.type_id.is_some()
        || selector.entry_index.is_some();
    if !has_identity_selector {
        return Err(invalid_for(
            OPERATION,
            "selector",
            "At least one resource identity selector is required.".into(),
        ));
    }

    Ok(())
}

fn resource_coverage(matches: &[ResourceMatch]) -> &'static str {
    matches
        .iter()
        .any(|resource| {
            resource.entry.issue.is_some()
                || resource.entry.mapping_issue.is_some()
                || resource
                    .entry
                    .complex_values
                    .iter()
                    .any(|value| value.issue.is_some())
                || resource
                    .variants
                    .iter()
                    .any(|variant| variant.value_issue.is_some() || variant.mapping_issue.is_some())
        })
        .then_some("partial")
        .unwrap_or("complete")
}

fn group_resource_matches(
    resource_variants: &[ResourceVariant],
    entries: Vec<&ResourceEntry>,
    selector: &ResourceSelector,
) -> Vec<ResourceMatch> {
    let mut grouped = BTreeMap::<String, ResourceMatch>::new();
    for entry in entries
        .into_iter()
        .filter(|entry| matches_name(entry, selector.name.as_deref()))
    {
        let resource_id = entry.resource_id.clone();
        let variants = resource_variants
            .iter()
            .filter(|variant| {
                variant.resource_id == resource_id
                    && matches_resource_configuration(&variant.configuration_facts, selector)
            })
            .cloned()
            .collect::<Vec<_>>();
        grouped.entry(resource_id).or_insert_with(|| ResourceMatch {
            parent_id: entry.parent_id,
            complex_values: entry.complex_values.clone(),
            entry: entry.clone(),
            variants,
        });
    }
    grouped.into_values().collect()
}

fn matches_resource_configuration(
    configuration: &android_package::ResourceConfiguration,
    selector: &ResourceSelector,
) -> bool {
    !has_configuration_selector(selector) || matches_configuration(configuration, selector)
}

pub fn build_resource_evidence(
    path: &str,
    snapshot: Snapshot,
    selector: &ResourceSelector,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    let report = android_package::read(&snapshot.bytes)
        .map_err(|error| invalid_for(OPERATION, "invalid_format", error.to_string()))?;
    let selected = inspect_android_resource(&report, selector)?;
    let mut locations = resource_locations(&selected.matches, &selected.packages);
    locations.extend(resource_pool_locations(
        &selected.pools,
        &selected.string_pool,
    ));
    let subject = Subject::new(
        path,
        snapshot.sha256.clone(),
        NativeFormat::AndroidPackage,
        None,
    )
    .map_err(|error| invalid_for(OPERATION, "invalid_format", error.to_string()))?;
    json_output::admitted_length(&selected, MAX_OUTPUT_BYTES)
        .map_err(|error| invalid_for(OPERATION, "resource_constraint", error.to_string()))?;
    let evidence = ArtifactEvidence::new(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            result: selected,
            limitations: report.limitations,
            locations,
        },
    )
    .map_err(|error| invalid_for(OPERATION, "invalid_format", error.to_string()))?;
    Ok(Arc::new(evidence))
}

fn resource_locations(
    matches: &[ResourceMatch],
    packages: &[android_package::ResourcePackage],
) -> Vec<Location> {
    let match_locations = matches
        .iter()
        .flat_map(|resource| {
            std::iter::once(Location::FileOffsetRange {
                start: u64::from(resource.entry.source_offset),
                end: u64::from(resource.entry.source_offset).saturating_add(1),
            })
            .chain(
                resource
                    .complex_values
                    .iter()
                    .map(|value| Location::FileOffsetRange {
                        start: u64::from(value.source_offset),
                        end: u64::from(value.source_offset).saturating_add(1),
                    }),
            )
            .chain(
                resource
                    .variants
                    .iter()
                    .map(|variant| Location::FileOffsetRange {
                        start: u64::from(variant.source_offset),
                        end: u64::from(variant.source_offset).saturating_add(1),
                    }),
            )
        })
        .collect::<Vec<_>>();
    let package_locations = packages.iter().flat_map(|package| {
        std::iter::once(Location::FileOffsetRange {
            start: u64::from(package.source_offset),
            end: u64::from(package.source_offset).saturating_add(1),
        })
        .chain(
            package
                .library_mappings
                .iter()
                .map(|mapping| Location::FileOffsetRange {
                    start: u64::from(mapping.source_range.0),
                    end: u64::from(mapping.source_range.1),
                }),
        )
        .chain(
            package
                .staged_aliases
                .iter()
                .map(|alias| Location::FileOffsetRange {
                    start: u64::from(alias.source_range.0),
                    end: u64::from(alias.source_range.1),
                }),
        )
    });
    match_locations
        .into_iter()
        .chain(package_locations)
        .collect()
}

fn resource_pool_locations(
    pools: &[android_package::ResourcePool],
    string_pool: &android_package::ResourceStringPool,
) -> Vec<Location> {
    let pool_locations =
        pools.iter().flat_map(|pool| {
            std::iter::once(Location::FileOffsetRange {
                start: u64::from(pool.source_offset),
                end: u64::from(pool.source_offset).saturating_add(1),
            })
            .chain(
                pool.entry_source_ranges
                    .iter()
                    .map(|(start, end)| Location::FileOffsetRange {
                        start: u64::from(*start),
                        end: u64::from(*end),
                    }),
            )
            .chain(pool.invalid_utf16_source_offsets.iter().map(|offset| {
                Location::FileOffsetRange {
                    start: u64::from(*offset),
                    end: u64::from(*offset).saturating_add(1),
                }
            }))
        });
    let string_pool_locations =
        std::iter::once(Location::FileOffsetRange {
            start: u64::from(string_pool.source_offset),
            end: u64::from(string_pool.source_offset).saturating_add(1),
        })
        .chain(string_pool.entry_source_ranges.iter().map(|(start, end)| {
            Location::FileOffsetRange {
                start: u64::from(*start),
                end: u64::from(*end),
            }
        }))
        .chain(
            string_pool
                .invalid_utf16_source_offsets
                .iter()
                .map(|offset| Location::FileOffsetRange {
                    start: u64::from(*offset),
                    end: u64::from(*offset).saturating_add(1),
                }),
        );
    pool_locations.chain(string_pool_locations).collect()
}

fn matches_entry(entry: &ResourceEntry, selector: &ResourceSelector) -> bool {
    if let Some(id) = &selector.resource_id {
        if !resource_ids_match(&entry.resource_id, id) {
            return false;
        }
    }
    let Some((package_id, type_id, entry_index)) = parse_resource_id(&entry.resource_id) else {
        return selector.package_id.is_none()
            && selector.type_id.is_none()
            && selector.entry_index.is_none();
    };
    selector.package_id.is_none_or(|value| value == package_id)
        && selector.type_id.is_none_or(|value| value == type_id)
        && selector
            .entry_index
            .is_none_or(|value| value == entry_index)
}

fn matches_name(entry: &ResourceEntry, name: Option<&str>) -> bool {
    name.is_none_or(|expected| {
        let normalized = expected.strip_prefix('@').unwrap_or(expected);
        entry.key_name.as_deref() == Some(expected)
            || entry.key_name.as_deref() == Some(normalized)
            || entry.qualified_name.as_deref() == Some(expected)
            || entry.qualified_name.as_deref() == Some(normalized)
    })
}

fn has_configuration_selector(selector: &ResourceSelector) -> bool {
    selector.locale.is_some()
        || selector.region.is_some()
        || selector.density.is_some()
        || selector.sdk.is_some()
        || selector.orientation.is_some()
}

fn matches_configuration(
    configuration: &android_package::ResourceConfiguration,
    selector: &ResourceSelector,
) -> bool {
    selector
        .locale
        .as_deref()
        .is_none_or(|value| configuration.locale.as_deref() == Some(value))
        && selector
            .region
            .as_deref()
            .is_none_or(|value| configuration.region.as_deref() == Some(value))
        && selector
            .density
            .is_none_or(|value| configuration.density == Some(value))
        && selector
            .sdk
            .is_none_or(|value| configuration.sdk == Some(value))
        && selector
            .orientation
            .is_none_or(|value| configuration.orientation == Some(value))
}

fn parse_resource_id(resource_id: &str) -> Option<(u32, u32, u32)> {
    let resource_id = resource_id.strip_prefix("@").unwrap_or(resource_id);
    let value = resource_id
        .strip_prefix("0x")
        .or_else(|| resource_id.strip_prefix("0X"))?;
    if value.len() != 8 {
        return None;
    }
    let value = u32::from_str_radix(value, 16).ok()?;
    Some((value >> 24, (value >> 16) & 0xff, value & 0xffff))
}

fn resource_ids_match(actual: &str, requested: &str) -> bool {
    actual == requested
        || parse_resource_id(actual).is_some()
            && parse_resource_id(actual) == parse_resource_id(requested)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str) -> ResourceEntry {
        ResourceEntry {
            resource_id: id.into(),
            source_offset: 12,
            ..Default::default()
        }
    }

    #[test]
    fn selects_exact_resource_id_components() {
        let entry = entry("0x7f010002");
        assert!(matches_entry(
            &entry,
            &ResourceSelector {
                package_id: Some(0x7f),
                type_id: Some(1),
                entry_index: Some(2),
                ..Default::default()
            }
        ));
        assert!(!matches_entry(
            &entry,
            &ResourceSelector {
                entry_index: Some(3),
                ..Default::default()
            }
        ));
        assert!(resource_ids_match("@0x7f010002", "0x7F010002"));
        assert!(!resource_ids_match("@0x7f010002", "@0x7f010003"));
    }

    #[test]
    fn symbolic_selection_requires_an_exact_retained_name() {
        let mut entry = entry("0x7f010002");
        entry.key_name = Some("app_name".into());
        assert!(matches_name(&entry, Some("app_name")));
        assert!(!matches_name(&entry, Some("other_name")));
    }

    #[test]
    fn symbolic_selection_accepts_resource_reference_prefix() {
        let mut entry = entry("0x7f010002");
        entry.qualified_name = Some("app:string/app_name".into());

        assert!(matches_name(&entry, Some("app:string/app_name")));
        assert!(matches_name(&entry, Some("@app:string/app_name")));
        assert!(!matches_name(&entry, Some("@app:string/other_name")));
    }

    #[test]
    fn qualified_name_remains_selectable_when_key_name_is_absent() {
        let mut qualified = entry("0x7f010002");
        qualified.qualified_name = Some("app:string/app_name".into());
        let report = android_package::Report {
            resource_entries: vec![qualified],
            ..test_report()
        };

        let inspection = inspect_android_resource(
            &report,
            &ResourceSelector {
                name: Some("app:string/app_name".into()),
                ..Default::default()
            },
        )
        .expect("qualified resource names are retained symbolic identities");

        assert_eq!(inspection.matches.len(), 1);
        assert_eq!(
            inspection.matches[0].entry.qualified_name.as_deref(),
            Some("app:string/app_name")
        );
    }

    #[test]
    fn configuration_selection_does_not_guess_missing_qualifiers() {
        let configuration = android_package::ResourceConfiguration {
            locale: Some("en".into()),
            density: Some(320),
            ..Default::default()
        };
        let selector = ResourceSelector {
            locale: Some("en".into()),
            density: Some(480),
            ..Default::default()
        };
        assert!(!matches_configuration(&configuration, &selector));
        assert!(matches_configuration(
            &configuration,
            &ResourceSelector {
                locale: Some("en".into()),
                density: Some(320),
                ..Default::default()
            }
        ));
    }

    #[test]
    fn groups_configuration_variants_without_marking_them_ambiguous() {
        let mut english = entry("@0x7f010002");
        english.key_name = Some("app_name".into());
        english.configuration.locale = Some("en".into());
        let mut french = english.clone();
        french.configuration.locale = Some("fr".into());
        let variants = vec![
            ResourceVariant {
                resource_id: "@0x7f010002".into(),
                configuration: "en".into(),
                configuration_facts: english.configuration.clone(),
                value: "English".into(),
                ..Default::default()
            },
            ResourceVariant {
                resource_id: "@0x7f010002".into(),
                configuration: "fr".into(),
                configuration_facts: french.configuration.clone(),
                value: "French".into(),
                ..Default::default()
            },
        ];

        let matches = group_resource_matches(
            &variants,
            vec![&english, &french],
            &ResourceSelector {
                name: Some("app_name".into()),
                ..Default::default()
            },
        );

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].variants.len(), 2);
    }

    #[test]
    fn projects_complex_resource_values_for_resource_inspection() {
        let mut bag = entry("@0x7f010002");
        bag.package_id = 0x7f;
        bag.key_name = Some("styleable_attrs".into());
        bag.parent_id = Some(0x7f010001);
        bag.complex_values
            .push(android_package::ResourceComplexValue {
                key: 0x01010000,
                key_resource_id: "@0x01010000".into(),
                value_kind: "integer".into(),
                value_type: Some(0x10),
                value_data: Some(4),
                value_size: None,
                value_res0: None,
                decoded_value: Some("4".into()),
                string_pool_index: None,
                string_pool_source_offset: None,
                reference_id: None,
                source_offset: 32,
                issue: None,
            });
        let report = android_package::Report {
            resource_entries: vec![bag],
            resource_packages: vec![android_package::ResourcePackage {
                package_id: 0x7f,
                name: Some("com.example".into()),
                name_issue: None,
                source_offset: 8,
                library_mappings: vec![android_package::ResourceLibraryMapping {
                    package_id: Some(0x80),
                    package_name: Some("com.lib".into()),
                    source_range: (120, 384),
                    issue: None,
                }],
                staged_aliases: vec![android_package::ResourceStagedAlias {
                    staged_id_raw: Some(0x7f010001),
                    final_id_raw: Some(0x7f010101),
                    staged_id: Some("0x7f010001".into()),
                    final_id: Some("0x7f010101".into()),
                    source_range: (400, 408),
                    issue: Some("staged alias is unresolved".into()),
                }],
            }],
            resource_pools: vec![android_package::ResourcePool {
                package_id: 0x7f,
                package_name: Some("com.example".into()),
                kind: "key".into(),
                strings: vec!["styleable_attrs".into()],
                ..Default::default()
            }],
            resource_string_pool: android_package::ResourceStringPool {
                count: 1,
                strings: vec!["label".into()],
                encoding: "utf-8".into(),
                entry_source_ranges: vec![(24, 30)],
                ..Default::default()
            },
            resource_paths: vec!["res/values/strings.xml".into()],
            ..test_report()
        };

        let inspection = inspect_android_resource(
            &report,
            &ResourceSelector {
                resource_id: Some("0x7F010002".into()),
                ..Default::default()
            },
        )
        .expect("complex resource should be selectable by exact ID");

        assert_eq!(inspection.matches.len(), 1);
        assert_eq!(inspection.matches[0].parent_id, Some(0x7f010001));
        assert_eq!(inspection.matches[0].complex_values.len(), 1);
        assert_eq!(inspection.matches[0].complex_values[0].key, 0x01010000);
        assert_eq!(
            inspection.matches[0].complex_values[0].key_resource_id,
            "@0x01010000"
        );
        assert_eq!(
            inspection.matches[0].complex_values[0].value_kind,
            "integer"
        );
        assert_eq!(inspection.packages.len(), 1);
        assert_eq!(inspection.packages[0].name.as_deref(), Some("com.example"));
        assert_eq!(inspection.packages[0].library_mappings.len(), 1);
        assert_eq!(
            inspection.packages[0].library_mappings[0]
                .package_name
                .as_deref(),
            Some("com.lib")
        );
        assert_eq!(
            inspection.packages[0].library_mappings[0].source_range,
            (120, 384)
        );
        assert_eq!(inspection.packages[0].staged_aliases.len(), 1);
        assert_eq!(
            inspection.packages[0].staged_aliases[0].final_id.as_deref(),
            Some("0x7f010101")
        );
        assert_eq!(
            inspection.packages[0].staged_aliases[0].issue.as_deref(),
            Some("staged alias is unresolved")
        );
        assert_eq!(inspection.pools.len(), 1);
        assert_eq!(inspection.pools[0].strings, vec!["styleable_attrs"]);
        assert_eq!(inspection.string_pool.encoding, "utf-8");
        assert_eq!(inspection.string_pool.entry_source_ranges, vec![(24, 30)]);
        assert_eq!(inspection.string_pool.strings, vec!["label"]);
        assert_eq!(inspection.resource_paths, vec!["res/values/strings.xml"]);
        assert_eq!(inspection.resource_count, 1);
    }

    #[test]
    fn resource_coverage_preserves_partial_unknown_facts() {
        let mut partial_entry = entry("@0x7f010002");
        partial_entry.issue = Some("resource entry is truncated".into());
        assert_eq!(
            resource_coverage(&[ResourceMatch {
                entry: partial_entry,
                variants: Vec::new(),
                parent_id: None,
                complex_values: Vec::new(),
            }]),
            "partial"
        );

        assert_eq!(
            resource_coverage(&[ResourceMatch {
                entry: entry("@0x7f010002"),
                variants: Vec::new(),
                parent_id: None,
                complex_values: Vec::new(),
            }]),
            "complete"
        );
    }

    #[test]
    fn resource_locations_include_complex_map_values() {
        let locations = resource_locations(
            &[ResourceMatch {
                entry: entry("@0x7f010002"),
                variants: Vec::new(),
                parent_id: None,
                complex_values: vec![android_package::ResourceComplexValue {
                    source_offset: 44,
                    ..Default::default()
                }],
            }],
            &[],
        );

        assert_eq!(locations.len(), 2);
        assert!(matches!(
            locations[1],
            Location::FileOffsetRange { start: 44, end: 45 }
        ));
    }

    #[test]
    fn resource_locations_include_library_and_staged_alias_ranges() {
        let locations = resource_locations(
            &[],
            &[android_package::ResourcePackage {
                package_id: 0x7f,
                source_offset: 64,
                library_mappings: vec![android_package::ResourceLibraryMapping {
                    source_range: (120, 384),
                    ..Default::default()
                }],
                staged_aliases: vec![android_package::ResourceStagedAlias {
                    source_range: (400, 408),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        );

        assert_eq!(locations.len(), 3);
        assert!(matches!(
            locations[0],
            Location::FileOffsetRange { start: 64, end: 65 }
        ));
        assert!(matches!(
            locations[1],
            Location::FileOffsetRange {
                start: 120,
                end: 384
            }
        ));
        assert!(matches!(
            locations[2],
            Location::FileOffsetRange {
                start: 400,
                end: 408
            }
        ));
    }

    #[test]
    fn resource_pool_locations_preserve_pool_and_invalid_string_offsets() {
        let locations = resource_pool_locations(
            &[android_package::ResourcePool {
                source_offset: 16,
                entry_source_ranges: vec![(24, 30)],
                invalid_utf16_source_offsets: vec![40],
                ..Default::default()
            }],
            &android_package::ResourceStringPool {
                source_offset: 48,
                entry_source_ranges: vec![(56, 62)],
                invalid_utf16_source_offsets: vec![70],
                ..Default::default()
            },
        );

        assert_eq!(locations.len(), 6);
        assert!(matches!(
            locations[0],
            Location::FileOffsetRange { start: 16, end: 17 }
        ));
        assert!(matches!(
            locations[5],
            Location::FileOffsetRange { start: 70, end: 71 }
        ));
    }

    fn test_report() -> android_package::Report {
        android_package::Report {
            package_name: None,
            version_name: None,
            version_code: None,
            min_sdk: None,
            target_sdk: None,
            max_sdk: None,
            min_sdk_value: None,
            target_sdk_value: None,
            max_sdk_value: None,
            sdk_source_offset: None,
            application_label: None,
            application_name: None,
            application_icon: None,
            application_round_icon: None,
            allow_backup: None,
            extract_native_libs: None,
            uses_cleartext_traffic: None,
            debuggable: None,
            permissions: vec![],
            permission_details: vec![],
            manifest: android_package::TextCoverage {
                status: "complete",
                text: String::new(),
                reported_total_bytes: Some(0),
            },
            class_count: 0,
            class_names: vec![],
            class_name_coverage: android_package::AndroidClassNameCoverage {
                status: "complete",
                reported_total: 0,
                observed_rows: 0,
                unknown_rows: 0,
            },
            resource_count: 1,
            resource_paths: vec![],
            signature_verification: "not_performed",
            signing_blocks: vec![],
            resource_variants: vec![],
            resource_string_pool: Default::default(),
            resource_packages: vec![],
            resource_pools: vec![],
            resource_entries: vec![],
            dex: vec![],
            components: vec![],
            features: vec![],
            supports_screens: Default::default(),
            queries: None,
            uses_libraries: vec![],
            uses_native_libraries: vec![],
            uses_configuration: None,
            limitations: vec![],
        }
    }
}
