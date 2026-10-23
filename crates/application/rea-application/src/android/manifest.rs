//! Application-owned selection of binary Android manifest components.

use crate::artifacts::inspection::invalid_for;
use rea_core::json_output;
use rea_core::{
    evidence::{ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject},
    failure::Failure,
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::android_package::{self, Component};
use serde::Serialize;
use std::sync::Arc;

pub const OPERATION: &str = "inspect_android_manifest_component";
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const PROVIDER: Provider = Provider {
    id: "android-package-reader",
    name: "REA Android package reader",
    version: Some("1"),
};

#[derive(Debug, Serialize)]
pub struct ComponentInspection {
    pub kind: String,
    pub name: String,
    pub component: Component,
    pub manifest: android_package::TextCoverage,
    pub match_count: usize,
}

pub fn inspect_component(
    report: &android_package::Report,
    kind: &str,
    name: &str,
) -> Result<ComponentInspection, Failure> {
    validate_selection(kind, name)?;

    let matches = report
        .components
        .iter()
        .filter(|component| component.kind == kind && component.name == name)
        .collect::<Vec<_>>();
    let Some(component) = matches.first() else {
        return Err(invalid_for(
            OPERATION,
            "component",
            format!("No manifest component matched kind {kind:?} and name {name:?}."),
        ));
    };
    if matches.len() > 1 {
        return Err(invalid_for(
            OPERATION,
            "component",
            format!(
                "Manifest component selection was ambiguous: {kind:?} {name:?} occurs {} times.",
                matches.len()
            ),
        ));
    }
    Ok(ComponentInspection {
        kind: kind.to_owned(),
        name: name.to_owned(),
        component: (*component).clone(),
        manifest: report.manifest.clone(),
        match_count: matches.len(),
    })
}

fn validate_selection(kind: &str, name: &str) -> Result<(), Failure> {
    if kind.is_empty() {
        return Err(invalid_for(
            OPERATION,
            "component",
            "Manifest component kind must be a non-empty string.".into(),
        ));
    }

    if name.is_empty() {
        return Err(invalid_for(
            OPERATION,
            "component",
            "Manifest component name must be a non-empty string.".into(),
        ));
    }

    Ok(())
}

pub fn build_evidence(
    path: &str,
    snapshot: Snapshot,
    kind: &str,
    name: &str,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    let report = android_package::read(&snapshot.bytes)
        .map_err(|error| invalid_for(OPERATION, "invalid_format", error.to_string()))?;
    let selected = inspect_component(&report, kind, name)?;
    let limitations = component_limitations(&report.limitations);
    json_output::admitted_length(&selected, MAX_OUTPUT_BYTES)
        .map_err(|error| invalid_for(OPERATION, "resource_constraint", error.to_string()))?;
    let subject = Subject::new(
        path,
        snapshot.sha256.clone(),
        NativeFormat::AndroidPackage,
        None,
    )
    .map_err(|error| invalid_for(OPERATION, "invalid_format", error.to_string()))?;
    let locations = component_locations(&selected.component);
    let evidence = ArtifactEvidence::new_with_parameters(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            result: selected,
            limitations,
            locations,
        },
        serde_json::json!({ "kind": kind, "name": name }),
    )
    .map_err(|error| invalid_for(OPERATION, "invalid_format", error.to_string()))?;
    Ok(Arc::new(evidence))
}

fn component_locations(component: &Component) -> Vec<Location> {
    std::iter::once(component.source_offset)
        .chain(
            component
                .intent_filters
                .iter()
                .map(|intent_filter| intent_filter.source_offset),
        )
        .map(|offset| Location::FileOffsetRange {
            start: u64::from(offset),
            end: u64::from(offset).saturating_add(1),
        })
        .collect()
}

fn component_limitations(parser_limitations: &[String]) -> Vec<String> {
    let mut limitations = parser_limitations.to_vec();
    limitations.extend([
        "Manifest component facts are static binary manifest observations and do not execute the APK.".into(),
        "Nullable exported and attribute values preserve parser uncertainty and do not infer Android defaults.".into(),
        "Component source offsets are relative to the retained AndroidManifest.xml entry.".into(),
    ]);
    limitations
}

#[cfg(test)]
mod tests {
    use super::{component_limitations, component_locations};
    use rea_core::evidence::Location;
    use rea_rust_analysis::android_package::{Component, IntentFilter};

    #[test]
    fn preserves_parser_limitations_in_component_evidence() {
        let parser_limitations = vec!["manifest text is reconstructed".to_owned()];

        let limitations = component_limitations(&parser_limitations);

        assert_eq!(limitations[0], "manifest text is reconstructed");
        assert!(
            limitations
                .iter()
                .any(|limitation| { limitation.contains("do not execute the APK") })
        );
        assert!(
            limitations
                .iter()
                .any(|limitation| { limitation.contains("do not infer Android defaults") })
        );
        assert!(limitations.iter().any(|limitation| {
            limitation.contains("relative to the retained AndroidManifest.xml")
        }));
    }

    #[test]
    fn retains_component_and_intent_filter_locations() {
        let component = Component {
            kind: "activity".to_owned(),
            name: ".Main".to_owned(),
            exported: None,
            target_activity: None,
            enabled: None,
            permission: None,
            process: None,
            launch_mode: None,
            theme: None,
            source_offset: 12,
            intent_filter_count: 1,
            intent_filters: vec![IntentFilter {
                source_offset: 34,
                ..IntentFilter::default()
            }],
        };

        let locations = component_locations(&component);

        assert_eq!(locations.len(), 2);
        assert!(matches!(
            &locations[0],
            Location::FileOffsetRange { start: 12, end: 13 }
        ));
        assert!(matches!(
            &locations[1],
            Location::FileOffsetRange { start: 34, end: 35 }
        ));
    }
}
