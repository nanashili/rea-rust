//! Stable-file APK inspection and Evidence projection.

use crate::android::resources::{self, ResourceSelector};
use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion, invalid_for};
use rea_core::{
    cancellation::Cancellation,
    evidence::{ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject},
    failure::{Detail, Failure, InputIssue},
    json_output,
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::android_package;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

pub const OPERATION: &str = "inspect_android_package";
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const PROVIDER: Provider = Provider {
    id: "android-package-reader",
    name: "REA Android package reader",
    version: Some("1"),
};

#[derive(Default)]
pub struct AndroidPackageAnalyzer;

impl ArtifactAnalyzer for AndroidPackageAnalyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = android_package::MAX_PACKAGE_BYTES;

    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence(path, snapshot)
    }
}

pub struct AndroidPackageInspection<F: rea_host::fs::stable_file::FileAccess> {
    inner: ArtifactInspection<F, AndroidPackageAnalyzer>,
}

impl<F: rea_host::fs::stable_file::FileAccess> AndroidPackageInspection<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            inner: ArtifactInspection::new(access),
        }
    }

    pub fn with_records(
        access: Arc<F>,
        records: Arc<crate::ledger::artifact_records::ArtifactRecords>,
    ) -> Self {
        Self {
            inner: ArtifactInspection::with_records(access, records),
        }
    }

    pub fn records(&self) -> &Arc<crate::ledger::artifact_records::ArtifactRecords> {
        self.inner.records()
    }

    pub fn close(&mut self) -> Result<(), Failure> {
        self.inner.close()
    }

    pub fn inspect(
        &mut self,
        path: &str,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect(path, cancellation, completion)
    }

    /// Inspect an APK and optionally project the retained summary view.
    ///
    /// The summary is derived from the same committed Evidence returned by
    /// the complete inspection, so selecting it never reopens or reparses the
    /// package and keeps the parent Evidence identity available to callers.
    pub fn inspect_with_detail(
        &mut self,
        path: &str,
        detail: AndroidPackageDetail,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Value, Failure> {
        let evidence = self.inspect(path, cancellation, completion)?;
        let complete = serde_json::to_value(evidence.as_ref())
            .map_err(|error| malformed_package(OPERATION, error.to_string()))?;

        match detail {
            AndroidPackageDetail::Complete => Ok(complete),
            AndroidPackageDetail::Summary => {
                let projected = crate::android::package_view::project(
                    &complete,
                    &serde_json::json!({"kind": "summary"}),
                )?;
                serde_json::from_str(projected.get())
                    .map_err(|error| malformed_package(OPERATION, error.to_string()))
            }
        }
    }

    pub fn search_classes(
        &mut self,
        path: &str,
        query: String,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect_with_operation(
            super::analysis::SEARCH_OPERATION,
            path,
            android_package::MAX_PACKAGE_BYTES,
            cancellation,
            completion,
            move |path, snapshot, _| super::analysis::build_search_evidence(path, snapshot, &query),
        )
    }

    pub fn trace_references(
        &mut self,
        path: &str,
        class_name: String,
        method_name: Option<String>,
        overload_index: Option<usize>,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect_with_operation(
            super::analysis::TRACE_OPERATION,
            path,
            android_package::MAX_PACKAGE_BYTES,
            cancellation,
            completion,
            move |path, snapshot, _| {
                super::analysis::build_trace_evidence(
                    path,
                    snapshot,
                    &class_name,
                    method_name.as_deref(),
                    overload_index,
                )
            },
        )
    }

    pub fn inspect_class(
        &mut self,
        path: &str,
        class_name: String,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect_with_operation(
            super::analysis::CLASS_OPERATION,
            path,
            android_package::MAX_PACKAGE_BYTES,
            cancellation,
            completion,
            move |path, snapshot, _| build_class_evidence(path, snapshot, &class_name),
        )
    }

    pub fn inspect_method(
        &mut self,
        path: &str,
        class_name: String,
        method_name: String,
        overload_index: Option<usize>,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect_with_operation(
            super::analysis::METHOD_OPERATION,
            path,
            android_package::MAX_PACKAGE_BYTES,
            cancellation,
            completion,
            move |path, snapshot, _| {
                build_method_evidence(path, snapshot, &class_name, &method_name, overload_index)
            },
        )
    }

    pub fn inspect_resource(
        &mut self,
        path: &str,
        selector: ResourceSelector,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect_with_operation(
            resources::OPERATION,
            path,
            android_package::MAX_PACKAGE_BYTES,
            cancellation,
            completion,
            move |path, snapshot, _| resources::build_resource_evidence(path, snapshot, &selector),
        )
    }

    pub fn inspect_manifest_component(
        &mut self,
        path: &str,
        kind: String,
        name: String,
        cancellation: &Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        self.inner.inspect_with_operation(
            super::manifest::OPERATION,
            path,
            android_package::MAX_PACKAGE_BYTES,
            cancellation,
            completion,
            move |path, snapshot, _| super::manifest::build_evidence(path, snapshot, &kind, &name),
        )
    }
}

/// Delivery selection for the public Android package operation.
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum AndroidPackageDetail {
    Complete,
    Summary,
}

fn build_class_evidence(
    path: &str,
    snapshot: Snapshot,
    class_name: &str,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    let package = android_package::read(&snapshot.bytes)
        .map_err(|error| malformed_package(super::analysis::CLASS_OPERATION, error.to_string()))?;
    let selected = super::analysis::inspect_android_class(&package, class_name)?;
    let mut limitations = package.limitations.clone();
    limitations.extend(selected.unknowns.iter().cloned());
    build_projection_evidence(
        path,
        snapshot,
        super::analysis::CLASS_OPERATION,
        selected,
        serde_json::json!({ "class_name": class_name }),
        limitations,
    )
}

fn build_method_evidence(
    path: &str,
    snapshot: Snapshot,
    class_name: &str,
    method_name: &str,
    overload_index: Option<usize>,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    let package = android_package::read(&snapshot.bytes)
        .map_err(|error| malformed_package(super::analysis::METHOD_OPERATION, error.to_string()))?;
    let selected =
        super::analysis::inspect_android_method(&package, class_name, method_name, overload_index)?;
    let mut limitations = package.limitations.clone();
    limitations.extend(selected.unknowns.iter().cloned());
    build_projection_evidence(
        path,
        snapshot,
        super::analysis::METHOD_OPERATION,
        selected,
        serde_json::json!({
            "class_name": class_name,
            "method_name": method_name,
            "overload_index": overload_index,
        }),
        limitations,
    )
}

fn build_projection_evidence<T: serde::Serialize>(
    path: &str,
    snapshot: Snapshot,
    operation: &'static str,
    projection: T,
    parameters: serde_json::Value,
    additional_limitations: Vec<String>,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    let result = serde_json::json!({
        "path": path,
        "sha256": snapshot.sha256.clone(),
        "projection": projection,
    });
    json_output::admitted_length(&result, MAX_OUTPUT_BYTES)
        .map_err(|error| invalid_for(operation, "resource_constraint", error.to_string()))?;
    let subject = Subject::new(path, snapshot.sha256, NativeFormat::AndroidPackage, None)
        .map_err(|error| invalid_for(operation, "invalid_format", error.to_string()))?;
    let mut limitations = vec![
        "Android class and method facts are static DEX observations and do not execute the APK."
            .into(),
        "Method bodies, annotations, and call sites remain bounded to facts admitted by the APK reader."
            .into(),
    ];
    limitations.extend(additional_limitations);
    let evidence = ArtifactEvidence::new_with_parameters(
        subject,
        PROVIDER,
        Observation {
            operation,
            result,
            limitations,
            locations: vec![Location::ArtifactPath {
                path: path.to_owned(),
            }],
        },
        parameters,
    )
    .map_err(|error| invalid_for(operation, "invalid_format", error.to_string()))?;
    Ok(Arc::new(evidence))
}

#[derive(Serialize)]
struct Report {
    artifact: Artifact,
    #[serde(flatten)]
    package: android_package::Report,
}

#[derive(Serialize)]
struct Artifact {
    path: String,
    sha256: String,
    bytes: usize,
}

fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
    let package = android_package::read(&snapshot.bytes)
        .map_err(|error| malformed_package(OPERATION, error.to_string()))?;
    let limitations = package.limitations.clone();
    let report = Report {
        artifact: Artifact {
            path: path.to_owned(),
            sha256: snapshot.sha256.clone(),
            bytes: snapshot.bytes.len(),
        },
        package,
    };
    json_output::admitted_length(&report, MAX_OUTPUT_BYTES)
        .map_err(|error| invalid_for(OPERATION, "resource_constraint", error.to_string()))?;
    let subject = Subject::new(path, snapshot.sha256, NativeFormat::AndroidPackage, None)
        .map_err(|error| invalid_for(OPERATION, "invalid_format", error.to_string()))?;
    let evidence = ArtifactEvidence::new(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            result: report,
            limitations,
            locations: vec![Location::ArtifactPath {
                path: path.to_owned(),
            }],
        },
    )
    .map_err(|error| invalid_for(OPERATION, "invalid_format", error.to_string()))?;
    Ok(Arc::new(evidence))
}

fn malformed_package(operation: &'static str, reason: String) -> Failure {
    Failure::new(
        "analysis_input",
        "invalid_input",
        "The selected Android package is malformed.".into(),
        false,
        "Provide a valid APK or Android package and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.into())),
            (
                "issues",
                Detail::Issues(vec![InputIssue {
                    path: vec!["path".into()],
                    reason: "invalid_format",
                    message: reason,
                    expected: Some("valid Android package bytes"),
                }]),
            ),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_host::fs::stable_file::{
        CloseOutcome, FileAccess, FileError, Fingerprint, IoKind, Kind,
    };
    use std::io;
    use std::path::Path;

    struct UnusedAccess;

    impl FileAccess for UnusedAccess {
        type Handle = ();

        fn lstat(&self, _path: &Path) -> Result<Fingerprint, FileError> {
            unreachable!("invalid test paths are rejected before filesystem access")
        }

        fn open_regular_candidate(&self, _path: &Path) -> Result<Self::Handle, FileError> {
            unreachable!("invalid test paths are rejected before filesystem access")
        }

        fn stat(&self, _handle: &Self::Handle) -> Result<Fingerprint, FileError> {
            unreachable!("invalid test paths are rejected before filesystem access")
        }

        fn read(&self, _handle: &Self::Handle, _output: &mut [u8]) -> Result<usize, FileError> {
            unreachable!("invalid test paths are rejected before filesystem access")
        }

        fn close(&self, _handle: Self::Handle) -> CloseOutcome<Self::Handle> {
            unreachable!("invalid test paths are rejected before filesystem access")
        }
    }

    struct FailingReadAccess;

    impl FileAccess for FailingReadAccess {
        type Handle = ();

        fn lstat(&self, _path: &Path) -> Result<Fingerprint, FileError> {
            Ok(test_fingerprint())
        }

        fn open_regular_candidate(&self, _path: &Path) -> Result<Self::Handle, FileError> {
            Ok(())
        }

        fn stat(&self, _handle: &Self::Handle) -> Result<Fingerprint, FileError> {
            Ok(test_fingerprint())
        }

        fn read(&self, _handle: &Self::Handle, _output: &mut [u8]) -> Result<usize, FileError> {
            Err(FileError {
                kind: IoKind::AccessDenied,
                system_code: Some("EACCES"),
                source: io::Error::new(io::ErrorKind::PermissionDenied, "injected read failure"),
            })
        }

        fn close(&self, _handle: Self::Handle) -> CloseOutcome<Self::Handle> {
            CloseOutcome::Released
        }
    }

    fn test_fingerprint() -> Fingerprint {
        Fingerprint {
            kind: Kind::Regular,
            device: 1,
            file_id: 2,
            bytes: 1,
            modified_ns: 3,
            changed_ns: 4,
        }
    }

    #[test]
    fn malformed_package_is_projected_as_input_failure() {
        let snapshot = Snapshot {
            bytes: b"not an apk".to_vec(),
            sha256: "a".repeat(64),
        };
        let failure = build_evidence("/tmp/probe.apk", snapshot).unwrap_err();
        assert_eq!(failure.operation(), Some(OPERATION));
        assert_eq!(failure.code(), "analysis_input");
    }

    #[test]
    fn specialized_inspections_preserve_operation_on_path_validation_failures() {
        let mut inspection = AndroidPackageInspection::new(Arc::new(UnusedAccess));
        let cancellation = Cancellation::default();

        let search_failure = inspection
            .search_classes(
                "relative.apk",
                "MainActivity".into(),
                &cancellation,
                Completion::OneShot,
            )
            .unwrap_err();
        assert_eq!(
            search_failure.operation(),
            Some(crate::android::analysis::SEARCH_OPERATION)
        );

        let trace_failure = inspection
            .trace_references(
                "relative.apk",
                "example.MainActivity".into(),
                None,
                None,
                &cancellation,
                Completion::OneShot,
            )
            .unwrap_err();
        assert_eq!(
            trace_failure.operation(),
            Some(crate::android::analysis::TRACE_OPERATION)
        );

        let class_failure = inspection
            .inspect_class(
                "relative.apk",
                "example.MainActivity".into(),
                &cancellation,
                Completion::OneShot,
            )
            .unwrap_err();
        assert_eq!(
            class_failure.operation(),
            Some(crate::android::analysis::CLASS_OPERATION)
        );

        let method_failure = inspection
            .inspect_method(
                "relative.apk",
                "example.MainActivity".into(),
                "onCreate".into(),
                None,
                &cancellation,
                Completion::OneShot,
            )
            .unwrap_err();
        assert_eq!(
            method_failure.operation(),
            Some(crate::android::analysis::METHOD_OPERATION)
        );

        let resource_failure = inspection
            .inspect_resource(
                "relative.apk",
                ResourceSelector {
                    name: Some("app_name".into()),
                    ..ResourceSelector::default()
                },
                &cancellation,
                Completion::OneShot,
            )
            .unwrap_err();
        assert_eq!(resource_failure.operation(), Some(resources::OPERATION));

        let component_failure = inspection
            .inspect_manifest_component(
                "relative.apk",
                "activity".into(),
                "example.MainActivity".into(),
                &cancellation,
                Completion::OneShot,
            )
            .unwrap_err();
        assert_eq!(
            component_failure.operation(),
            Some(crate::android::manifest::OPERATION)
        );
    }

    #[test]
    fn specialized_inspections_preserve_operation_on_read_failures() {
        let mut inspection = AndroidPackageInspection::new(Arc::new(FailingReadAccess));
        let cancellation = Cancellation::default();

        let failure = inspection
            .search_classes(
                "/tmp/probe.apk",
                "MainActivity".into(),
                &cancellation,
                Completion::OneShot,
            )
            .unwrap_err();

        assert_eq!(
            failure.operation(),
            Some(crate::android::analysis::SEARCH_OPERATION)
        );
        assert_eq!(failure.code(), "access_denied");
    }
}
