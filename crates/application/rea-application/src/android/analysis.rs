//! Application-owned Android class and method projections.
//!
//! The DEX reader owns byte interpretation. This module owns caller selection
//! and returns only facts belonging to the selected class or method.

use crate::artifacts::inspection::invalid_for;
use rea_core::{
    evidence::{ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject},
    failure::Failure,
    json_output,
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::android_package::{self, DexClass, DexFacts, DexMethod, DexMethodCode};
use serde::Serialize;
use std::sync::Arc;

pub const CLASS_OPERATION: &str = "inspect_android_class";
pub const METHOD_OPERATION: &str = "inspect_android_method";
pub const SEARCH_OPERATION: &str = "search_android_classes";
pub const TRACE_OPERATION: &str = "trace_android_references";
const PROVIDER: Provider = Provider {
    id: "android-package-reader",
    name: "REA Android package reader",
    version: Some("1"),
};
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct ClassInspection {
    pub class_name: String,
    pub dex_entry: String,
    pub dex_descriptor: String,
    pub methods: Vec<ClassMethod>,
    pub fields: Vec<ClassField>,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub inner_classes: Vec<String>,
    pub annotations: Vec<android_package::DexAnnotationAssociation>,
    pub coverage: &'static str,
    pub unknowns: Vec<String>,
}

/// Method inventory fields shared with the JADX class projection.
#[derive(Debug, Serialize)]
pub struct ClassMethod {
    pub name: String,
    pub reported_signature: String,
    pub overload_index: usize,
    pub is_constructor: bool,
    pub dex_descriptor: String,
}

/// Field inventory fields shared with the JADX class projection.
#[derive(Debug, Serialize)]
pub struct ClassField {
    pub name: String,
    pub reported_type: String,
}

#[derive(Debug, Serialize)]
pub struct MethodInspection {
    pub class_name: String,
    pub dex_entry: String,
    pub dex_method_index: usize,
    pub method: DexMethod,
    pub overload_index: usize,
    pub overload_count: usize,
    pub code: Option<DexMethodCode>,
    pub annotations: Vec<android_package::DexAnnotationAssociation>,
    pub call_sites: Vec<android_package::DexCallSite>,
    pub code_item_offset: Option<u32>,
    pub coverage: &'static str,
    pub unknowns: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ClassSearch {
    pub query: String,
    pub total_classes: usize,
    pub matches: Vec<String>,
    pub duplicate_names: Vec<DuplicateClassName>,
    pub coverage: &'static str,
    pub gaps: Vec<String>,
    pub dex_entries: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DuplicateClassName {
    pub name: String,
    pub occurrences: usize,
}

#[derive(Debug, Serialize)]
pub struct ReferenceTrace {
    pub class_name: String,
    pub method_name: Option<String>,
    pub overload_index: Option<usize>,
    pub reported_signature: Option<String>,
    pub dex_descriptor: Option<String>,
    pub total: usize,
    pub references: Vec<ReferenceFact>,
    pub coverage: &'static str,
    pub unknowns: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ReferenceFact {
    pub kind: &'static str,
    pub name: String,
    pub reported_full_name: String,
    pub containing_class: String,
    pub top_class: String,
    pub dex_entry: String,
    pub dex_code_unit_offset: u32,
    pub dex_method_index: u32,
}

/// Parse one stable APK snapshot and commit the selected reference trace as
/// application-owned Evidence. DEX offsets remain in the result because they
/// are offsets in the DEX member, not offsets in the enclosing APK.
pub fn build_trace_evidence(
    path: &str,
    snapshot: Snapshot,
    class_name: &str,
    method_name: Option<&str>,
    overload_index: Option<usize>,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    let report = android_package::read(&snapshot.bytes)
        .map_err(|error| invalid_for(TRACE_OPERATION, "invalid_format", error.to_string()))?;
    let trace = trace_android_references(&report, class_name, method_name, overload_index)?;
    json_output::admitted_length(&trace, MAX_OUTPUT_BYTES)
        .map_err(|error| invalid_for(TRACE_OPERATION, "resource_limit", error.to_string()))?;

    let mut limitations = report.limitations.clone();
    limitations.extend(trace.unknowns.iter().cloned());
    if trace.coverage == "partial" {
        limitations.push("DEX inspection coverage is partial.".into());
    }

    let subject = Subject::new(path, snapshot.sha256, NativeFormat::AndroidPackage, None)
        .map_err(|error| invalid_for(TRACE_OPERATION, "invalid_format", error.to_string()))?;
    let evidence = ArtifactEvidence::new_with_parameters(
        subject,
        PROVIDER,
        Observation {
            operation: TRACE_OPERATION,
            result: trace,
            limitations,
            locations: vec![Location::ArtifactPath {
                path: path.to_owned(),
            }],
        },
        serde_json::json!({
            "class_name": class_name,
            "method_name": method_name,
            "overload_index": overload_index,
        }),
    )
    .map_err(|error| invalid_for(TRACE_OPERATION, "invalid_format", error.to_string()))?;
    Ok(Arc::new(evidence))
}

pub fn build_search_evidence(
    path: &str,
    snapshot: Snapshot,
    query: &str,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    let report = android_package::read(&snapshot.bytes)
        .map_err(|error| invalid_for(SEARCH_OPERATION, "invalid_format", error.to_string()))?;
    let search = search_android_classes(&report, query);
    json_output::admitted_length(&search, MAX_OUTPUT_BYTES)
        .map_err(|error| invalid_for(SEARCH_OPERATION, "resource_limit", error.to_string()))?;

    let mut limitations = report.limitations.clone();
    limitations.extend(search.gaps.iter().cloned());
    if search.coverage == "partial" {
        limitations.push("DEX class-name search coverage is partial.".into());
    }

    let subject = Subject::new(path, snapshot.sha256, NativeFormat::AndroidPackage, None)
        .map_err(|error| invalid_for(SEARCH_OPERATION, "invalid_format", error.to_string()))?;
    let evidence = ArtifactEvidence::new_with_parameters(
        subject,
        PROVIDER,
        Observation {
            operation: SEARCH_OPERATION,
            result: search,
            limitations,
            locations: vec![Location::ArtifactPath {
                path: path.to_owned(),
            }],
        },
        serde_json::json!({ "query": query }),
    )
    .map_err(|error| invalid_for(SEARCH_OPERATION, "invalid_format", error.to_string()))?;

    Ok(Arc::new(evidence))
}

pub fn trace_android_references(
    report: &android_package::Report,
    class_name: &str,
    method_name: Option<&str>,
    overload_index: Option<usize>,
) -> Result<ReferenceTrace, Failure> {
    if method_name.is_none() && overload_index.is_some() {
        return Err(invalid_for(
            TRACE_OPERATION,
            "overload_index",
            "Method name is required when selecting an overload.".into(),
        ));
    }
    let (selected_facts, selected_class) = select_class(report, TRACE_OPERATION, class_name)?;
    let candidates = method_name.map(|name| {
        selected_facts
            .methods
            .iter()
            .filter(|method| {
                same_class(&method.class_descriptor, &selected_class.descriptor)
                    && method.name == name
            })
            .collect::<Vec<_>>()
    });
    let selected_method = if let Some(candidates) = &candidates {
        if candidates.is_empty() {
            return Err(invalid_for(
                TRACE_OPERATION,
                "method_name",
                format!(
                    "Method {class_name}.{name} was not found.",
                    name = method_name.unwrap()
                ),
            ));
        }
        if overload_index.is_none() && candidates.len() > 1 {
            return Err(invalid_for(
                TRACE_OPERATION,
                "overload_index",
                format!(
                    "Select one of {} matching method overloads.",
                    candidates.len()
                ),
            ));
        }
        let index = overload_index.unwrap_or(0);
        Some(candidates.get(index).copied().ok_or_else(|| {
            invalid_for(
                TRACE_OPERATION,
                "overload_index",
                format!(
                    "Index {index} is outside the {} matching overloads.",
                    candidates.len()
                ),
            )
        })?)
    } else {
        None
    };
    let target = selected_method.map(|method| {
        format!(
            "{}->{}{}",
            method.class_descriptor, method.name, method.descriptor
        )
    });
    let mut references = Vec::new();
    let mut unknowns = Vec::new();
    for facts in &report.dex {
        for code in &facts.code {
            let Some(owner) = facts.methods.get(code.method_index as usize) else {
                unknowns.push(format!(
                    "{} has code for an unknown method index.",
                    facts.entry
                ));
                continue;
            };
            for invoke in &code.invokes {
                let Some(invoke_target) = &invoke.target else {
                    unknowns.push(format!("{} has an unresolved invoke target.", facts.entry));
                    continue;
                };
                if target
                    .as_deref()
                    .is_some_and(|value| value != invoke_target)
                    || target.is_none() && !invoke_target.starts_with(&selected_class.descriptor)
                {
                    continue;
                }
                references.push(ReferenceFact {
                    kind: "direct-invoke",
                    name: invoke_target.clone(),
                    reported_full_name: invoke_target.clone(),
                    containing_class: descriptor_to_name(&owner.class_descriptor),
                    top_class: descriptor_to_name(&selected_class.descriptor),
                    dex_entry: facts.entry.clone(),
                    dex_code_unit_offset: invoke.code_unit_offset,
                    dex_method_index: invoke.method_index,
                });
            }
        }
    }
    let coverage = if report.dex.iter().any(|facts| facts.truncated) {
        "partial"
    } else {
        "complete"
    };
    Ok(ReferenceTrace {
        class_name: class_name.to_owned(),
        method_name: method_name.map(str::to_owned),
        overload_index,
        reported_signature: selected_method.map(|method| method.descriptor.clone()),
        dex_descriptor: selected_method.map(|method| method.descriptor.clone()),
        total: references.len(),
        references,
        coverage,
        unknowns,
    })
}

pub fn search_android_classes(report: &android_package::Report, query: &str) -> ClassSearch {
    let mut names = Vec::new();
    let mut total_classes = 0;
    let mut dex_entries = Vec::new();
    let mut gaps = Vec::new();
    for facts in &report.dex {
        dex_entries.push(facts.entry.clone());
        if facts.truncated {
            gaps.push(format!("DEX {} class inventory is truncated.", facts.entry));
        }
        for class in &facts.class_definitions {
            let name = descriptor_to_name(&class.descriptor);
            if !name.contains('$') {
                total_classes += 1;
            }
            if !name.contains('$') && name.contains(query) {
                names.push(name);
            }
        }
    }

    let duplicate_names = duplicate_class_names(&names);
    ClassSearch {
        query: query.to_owned(),
        total_classes,
        matches: names,
        duplicate_names,
        coverage: if gaps.is_empty() {
            "complete"
        } else {
            "partial"
        },
        gaps,
        dex_entries,
    }
}

fn duplicate_class_names(names: &[String]) -> Vec<DuplicateClassName> {
    let mut counts = std::collections::BTreeMap::new();
    for name in names {
        *counts.entry(name.clone()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .filter_map(|(name, occurrences)| {
            (occurrences > 1).then_some(DuplicateClassName { name, occurrences })
        })
        .collect()
}

pub fn inspect_android_class(
    report: &android_package::Report,
    class_name: &str,
) -> Result<ClassInspection, Failure> {
    let (facts, class) = select_class(report, CLASS_OPERATION, class_name)?;
    let descriptor = class.descriptor.clone();
    let annotations = facts
        .annotations
        .iter()
        .filter(|annotation| annotation.owner == descriptor)
        .cloned()
        .collect();

    let methods = class_method_projection(&class.methods);
    let fields = class
        .fields
        .iter()
        .map(|field| ClassField {
            name: field.name.clone(),
            reported_type: field.field_type.clone(),
        })
        .collect();

    Ok(ClassInspection {
        class_name: class_name.to_owned(),
        dex_entry: facts.entry.clone(),
        dex_descriptor: descriptor.clone(),
        methods,
        fields,
        superclass: class.superclass.clone(),
        interfaces: class.interfaces.clone(),
        inner_classes: inner_classes(&descriptor, facts),
        annotations,
        coverage: if facts.truncated {
            "partial"
        } else {
            "complete"
        },
        unknowns: if facts.truncated {
            vec![format!("DEX {} class facts are truncated.", facts.entry)]
        } else {
            Vec::new()
        },
    })
}

fn class_method_projection(methods: &[android_package::DexDeclaredMethod]) -> Vec<ClassMethod> {
    let mut overloads = std::collections::BTreeMap::new();

    methods
        .iter()
        .map(|method| {
            let overload_index = overloads.entry(method.name.clone()).or_insert(0);
            let projected = ClassMethod {
                name: method.name.clone(),
                reported_signature: method.descriptor.clone(),
                overload_index: *overload_index,
                is_constructor: method.name == "<init>",
                dex_descriptor: method.descriptor.clone(),
            };
            *overload_index += 1;
            projected
        })
        .collect()
}

pub fn inspect_android_method(
    report: &android_package::Report,
    class_name: &str,
    method_name: &str,
    overload_index: Option<usize>,
) -> Result<MethodInspection, Failure> {
    let (facts, class) = select_class(report, METHOD_OPERATION, class_name)?;
    let candidates = facts
        .methods
        .iter()
        .enumerate()
        .filter(|(_, method)| {
            same_class(&method.class_descriptor, &class.descriptor) && method.name == method_name
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Err(invalid_for(
            METHOD_OPERATION,
            "method_name",
            format!("Method {class_name}.{method_name} was not found."),
        ));
    }

    let selected_index = overload_index.unwrap_or(0);
    if overload_index.is_none() && candidates.len() > 1 {
        return Err(invalid_for(
            METHOD_OPERATION,
            "overload_index",
            format!(
                "Select one of {} matching method overloads.",
                candidates.len()
            ),
        ));
    }
    let Some((method_index, method)) = candidates.get(selected_index) else {
        return Err(invalid_for(
            METHOD_OPERATION,
            "overload_index",
            format!(
                "Index {selected_index} is outside the {} matching overloads.",
                candidates.len()
            ),
        ));
    };

    let code = facts
        .code
        .iter()
        .find(|code| code.method_index as usize == *method_index)
        .cloned();
    let code_item_offset = code.as_ref().map(|item| item.code_offset);
    let annotations = facts
        .annotations
        .iter()
        .filter(|annotation| annotation.owner == class.descriptor)
        .cloned()
        .collect();

    Ok(MethodInspection {
        class_name: class_name.to_owned(),
        dex_entry: facts.entry.clone(),
        dex_method_index: *method_index,
        method: (*method).clone(),
        overload_index: selected_index,
        overload_count: candidates.len(),
        code,
        annotations,
        call_sites: facts.call_sites.clone(),
        code_item_offset,
        coverage: if facts.truncated {
            "partial"
        } else {
            "complete"
        },
        unknowns: if facts.truncated {
            vec![format!("DEX {} method facts are truncated.", facts.entry)]
        } else {
            Vec::new()
        },
    })
}

fn select_class<'a>(
    report: &'a android_package::Report,
    operation: &'static str,
    class_name: &str,
) -> Result<(&'a DexFacts, &'a DexClass), Failure> {
    let matches = report
        .dex
        .iter()
        .flat_map(|facts| {
            facts
                .class_definitions
                .iter()
                .map(move |class| (facts, class))
        })
        .filter(|(_, class)| same_class(&class.descriptor, class_name))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Err(invalid_for(
            operation,
            "class_name",
            format!("Class {class_name} was not found."),
        )),
        [single] => Ok(*single),
        _ => Err(invalid_for(
            operation,
            "class_name",
            format!("Class {class_name} occurs in multiple DEX files."),
        )),
    }
}

fn same_class(descriptor: &str, requested: &str) -> bool {
    descriptor == requested || descriptor_to_name(descriptor) == requested
}

fn descriptor_to_name(descriptor: &str) -> String {
    descriptor
        .strip_prefix('L')
        .and_then(|value| value.strip_suffix(';'))
        .unwrap_or(descriptor)
        .replace('/', ".")
}

fn inner_classes<'a>(descriptor: &str, facts: &'a DexFacts) -> Vec<String> {
    let prefix = descriptor.strip_suffix(';').unwrap_or(descriptor);
    facts
        .class_definitions
        .iter()
        .filter(|class| {
            class.descriptor.starts_with(prefix)
                && class.descriptor.as_bytes().get(prefix.len()) == Some(&b'$')
        })
        .map(|class| descriptor_to_name(&class.descriptor))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> android_package::Report {
        let mut report = android_package::Report {
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
            class_count: 2,
            class_names: vec![],
            class_name_coverage: android_package::AndroidClassNameCoverage {
                status: "complete",
                reported_total: 0,
                observed_rows: 0,
                unknown_rows: 0,
            },
            resource_count: 0,
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
        };
        report.dex.push(DexFacts {
            class_definitions: vec![DexClass {
                descriptor: "Lcom/example/App;".into(),
                source_offset: 0,
                superclass: None,
                interfaces: vec![],
                fields: vec![],
                methods: vec![],
                static_values: vec![],
            }],
            methods: vec![DexMethod {
                class_descriptor: "Lcom/example/App;".into(),
                name: "run".into(),
                descriptor: "()V".into(),
            }],
            ..DexFacts::default()
        });
        report
    }

    #[test]
    fn selects_dotted_class_names() {
        let selected = inspect_android_class(&report(), "com.example.App").unwrap();
        assert_eq!(selected.class_name, "com.example.App");
        assert_eq!(selected.dex_descriptor, "Lcom/example/App;");
        assert_eq!(selected.dex_entry, "");
        assert_eq!(selected.coverage, "complete");
        assert!(selected.unknowns.is_empty());
    }

    #[test]
    fn exposes_partial_class_coverage_without_inventing_metadata() {
        let mut package = report();
        package.dex[0].truncated = true;

        let selected = inspect_android_class(&package, "Lcom/example/App;").unwrap();

        assert_eq!(selected.coverage, "partial");
        assert_eq!(selected.unknowns.len(), 1);
        assert!(selected.unknowns[0].contains("class facts are truncated"));
    }

    #[test]
    fn reports_missing_method_as_input_failure() {
        let failure =
            inspect_android_method(&report(), "com.example.App", "missing", None).unwrap_err();
        assert_eq!(failure.code(), "invalid_request");
    }

    #[test]
    fn preserves_method_identity_and_code_item_provenance() {
        let mut package = report();
        package.dex[0].entry = "classes.dex".into();
        package.dex[0].code.push(DexMethodCode {
            method_index: 0,
            code_offset: 128,
            ..DexMethodCode::default()
        });

        let selected =
            inspect_android_method(&package, "Lcom/example/App;", "run", Some(0)).unwrap();

        assert_eq!(selected.dex_entry, "classes.dex");
        assert_eq!(selected.dex_method_index, 0);
        assert_eq!(selected.method.descriptor, "()V");
        assert_eq!(selected.code_item_offset, Some(128));
        assert_eq!(selected.coverage, "complete");
    }

    #[test]
    fn method_selection_requires_an_overload_when_ambiguous() {
        let mut package = report();
        package.dex[0].methods.push(DexMethod {
            class_descriptor: "Lcom/example/App;".into(),
            name: "run".into(),
            descriptor: "(I)V".into(),
        });

        let failure = inspect_android_method(&package, "com.example.App", "run", None).unwrap_err();

        assert_eq!(failure.code(), "invalid_request");
    }

    #[test]
    fn method_projection_retains_partial_coverage() {
        let mut package = report();
        package.dex[0].truncated = true;

        let selected = inspect_android_method(&package, "com.example.App", "run", Some(0)).unwrap();

        assert_eq!(selected.coverage, "partial");
        assert_eq!(selected.unknowns.len(), 1);
    }

    #[test]
    fn preserves_case_sensitive_matches_and_duplicate_names() {
        let names = vec!["com.example.App".into(), "com.example.App".into()];
        let duplicates = duplicate_class_names(&names);
        assert_eq!(duplicates[0].name, "com.example.App");
        assert_eq!(duplicates[0].occurrences, 2);
        assert!("App".contains("A"));
        assert!(!"App".contains("a"));
    }

    #[test]
    fn class_search_preserves_duplicates_and_partial_dex_coverage() {
        let mut package = report();
        package.dex[0].entry = "classes.dex".into();
        package.dex[0].truncated = true;
        package.dex[0].class_definitions.push(DexClass {
            descriptor: "Lcom/example/App;".into(),
            source_offset: 0x80,
            superclass: None,
            interfaces: vec![],
            fields: vec![],
            methods: vec![],
            static_values: vec![],
        });
        package.dex[0].class_definitions.push(DexClass {
            descriptor: "Lcom/example/App$Inner;".into(),
            source_offset: 0x90,
            superclass: None,
            interfaces: vec![],
            fields: vec![],
            methods: vec![],
            static_values: vec![],
        });

        let search = search_android_classes(&package, "App");

        assert_eq!(search.query, "App");
        assert_eq!(search.total_classes, 2);
        assert_eq!(search.matches, ["com.example.App", "com.example.App"]);
        assert_eq!(search.duplicate_names[0].occurrences, 2);
        assert_eq!(search.coverage, "partial");
        assert_eq!(search.dex_entries, ["classes.dex"]);
        assert_eq!(search.gaps.len(), 1);
    }

    #[test]
    fn traces_exact_method_references_with_dex_provenance() {
        let mut report = report();
        report.dex[0].methods.push(DexMethod {
            class_descriptor: "Lother/Caller;".into(),
            name: "call".into(),
            descriptor: "()V".into(),
        });
        report.dex[0].code.push(DexMethodCode {
            method_index: 1,
            invokes: vec![android_package::DexInvokeEdge {
                code_unit_offset: 7,
                method_index: 0,
                target: Some("Lcom/example/App;->run()V".into()),
            }],
            ..DexMethodCode::default()
        });

        let trace =
            trace_android_references(&report, "com.example.App", Some("run"), Some(0)).unwrap();

        assert_eq!(trace.total, 1);
        assert_eq!(trace.references[0].containing_class, "other.Caller");
        assert_eq!(trace.references[0].dex_entry, "");
        assert_eq!(trace.references[0].dex_code_unit_offset, 7);
        assert!(trace.unknowns.is_empty());
    }

    #[test]
    fn malformed_snapshot_is_rejected_by_trace_evidence_boundary() {
        let snapshot = Snapshot {
            bytes: b"not an apk".to_vec(),
            sha256: "a".repeat(64),
        };
        let failure =
            build_trace_evidence("/tmp/probe.apk", snapshot, "com.example.App", None, None)
                .unwrap_err();

        assert_eq!(failure.operation(), Some(TRACE_OPERATION));
        assert_eq!(failure.code(), "invalid_request");
    }
}
