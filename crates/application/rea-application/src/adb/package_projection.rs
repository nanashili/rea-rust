//! Offline projection of an ADB package observation and selected APK facts.
//!
//! The ADB provider owns device access and `dumpsys` parsing.  This module only
//! combines facts that a caller already selected, so projecting a package can
//! never install, pull, or otherwise access a device.

use rea_rust_analysis::android_package;
use serde::Serialize;

pub const OPERATION: &str = "inspect_adb_package";

/// The fixed fields admitted from `dumpsys package PACKAGE`.
#[derive(Debug, Clone, Serialize)]
pub struct AdbPackageFacts {
    pub client: String,
    pub serial: String,
    pub package_name: String,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub first_install_time: Option<String>,
    pub last_update_time: Option<String>,
    pub installer_package_name: Option<String>,
    pub user_id: Option<i32>,
    pub pkg_flags: Option<String>,
    pub requested_permissions_count: Option<u32>,
    pub coverage: AdbCoverage,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdbCoverage {
    Complete,
    Partial,
}

/// APK facts selected by the caller, normally from `inspect_android_package`.
#[derive(Debug, Clone, Serialize)]
pub struct ApkPackageFacts {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
    pub report: android_package::Report,
}

/// Inputs for [`project`].  Every value is caller supplied and already
/// observed; this type deliberately contains no device handle or path lookup.
#[derive(Debug, Clone)]
pub struct Input {
    pub adb: AdbPackageFacts,
    pub apk: Option<ApkPackageFacts>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Projection {
    pub adb: AdbPackageFacts,
    pub apk: Option<ApkProjection>,
    pub evidence: EvidenceProvenance,
    pub unknowns: Vec<String>,
}

/// Retains the complete Android package report while naming the high-value
/// manifest and resource projections for consumers that do not need to parse
/// the report again.
#[derive(Debug, Clone, Serialize)]
pub struct ApkProjection {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
    pub package_name: Option<String>,
    pub manifest: android_package::TextCoverage,
    pub resources: ResourceProjection,
    pub report: android_package::Report,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceProjection {
    pub count: usize,
    pub paths: Vec<String>,
    pub variants: Vec<android_package::ResourceVariant>,
    pub string_pool: android_package::ResourceStringPool,
    pub packages: Vec<android_package::ResourcePackage>,
    pub pools: Vec<android_package::ResourcePool>,
    pub entries: Vec<android_package::ResourceEntry>,
}

/// Provenance is explicit because ADB facts and APK facts have different
/// owners.  The APK digest remains available even when no APK was selected.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceProvenance {
    pub operation: &'static str,
    pub adb_source: &'static str,
    pub apk_source: Option<&'static str>,
    pub apk_path: Option<String>,
    pub apk_sha256: Option<String>,
}

pub fn project(input: Input) -> Projection {
    let mut unknowns = adb_unknowns(&input.adb);
    let apk = input
        .apk
        .map(|facts| project_apk(facts, &input.adb.package_name, &mut unknowns));
    let evidence = EvidenceProvenance {
        operation: OPERATION,
        adb_source: "adb:dumpsys package",
        apk_source: apk.as_ref().map(|_| "rea:inspect_android_package"),
        apk_path: apk.as_ref().map(|facts| facts.path.clone()),
        apk_sha256: apk.as_ref().map(|facts| facts.sha256.clone()),
    };

    Projection {
        adb: input.adb,
        apk,
        evidence,
        unknowns,
    }
}

fn project_apk(
    facts: ApkPackageFacts,
    adb_package_name: &str,
    unknowns: &mut Vec<String>,
) -> ApkProjection {
    let package_name = facts.report.package_name.clone();
    match package_name.as_deref() {
        None => unknowns.push("APK package identity was unavailable.".into()),
        Some(apk_package_name) if apk_package_name != adb_package_name => unknowns.push(
            format!(
                "Selected APK package identity {apk_package_name} differs from the ADB package {adb_package_name}."
            ),
        ),
        Some(_) => {}
    }

    let resources = ResourceProjection {
        count: facts.report.resource_count,
        paths: facts.report.resource_paths.clone(),
        variants: facts.report.resource_variants.clone(),
        string_pool: facts.report.resource_string_pool.clone(),
        packages: facts.report.resource_packages.clone(),
        pools: facts.report.resource_pools.clone(),
        entries: facts.report.resource_entries.clone(),
    };

    unknowns.extend(facts.report.limitations.iter().cloned());

    ApkProjection {
        path: facts.path,
        sha256: facts.sha256,
        bytes: facts.bytes,
        package_name,
        manifest: facts.report.manifest.clone(),
        resources,
        report: facts.report,
    }
}

fn adb_unknowns(facts: &AdbPackageFacts) -> Vec<String> {
    let mut unknowns = Vec::new();
    if facts.version_name.is_none() {
        unknowns.push("ADB did not report versionName.".into());
    }
    if facts.version_code.is_none() {
        unknowns.push("ADB did not report versionCode.".into());
    }
    if facts.requested_permissions_count.is_none() {
        unknowns.push("ADB did not establish a complete requested-permissions inventory.".into());
    }
    if matches!(facts.coverage, AdbCoverage::Partial) {
        unknowns.push("ADB package coverage is partial.".into());
    }
    unknowns
}
