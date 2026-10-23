//! Offline composition for `inspect_adb_package`.
//!
//! The ADB package projection and APK reader own their respective parsing. This
//! module only joins caller-selected, authenticated facts and records identity
//! mismatches for a later host adapter; it never queries or pulls from a device.

use crate::adb::package_projection::{AdbCoverage, AdbPackageFacts, ApkPackageFacts};
use rea_core::failure::{Detail, Failure};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_adb_package";

#[derive(Clone, Debug)]
pub struct Input {
    pub requested_serial: String,
    pub requested_package_name: String,
    pub requested_user_id: Option<i32>,
    pub adb: AdbPackageFacts,
    pub apk: Option<ApkPackageFacts>,
    pub installed_state: InstalledState,
    pub evidence: Vec<AuthenticatedEvidence>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstalledState {
    Confirmed,
    Unavailable,
    Unknown,
}

/// Evidence is authenticated by the caller before it reaches this joiner.
/// The joiner still checks its subject identity so unrelated records cannot be
/// silently attached to this package result.
#[derive(Clone, Debug, Serialize)]
pub struct AuthenticatedEvidence {
    pub evidence_id: String,
    pub operation: String,
    pub serial: String,
    pub package_name: String,
    pub authenticated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Projection {
    pub client: String,
    pub serial: String,
    pub package_name: String,
    pub user_id: Option<i32>,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub first_install_time: Option<String>,
    pub last_update_time: Option<String>,
    pub installer_package_name: Option<String>,
    pub pkg_flags: Option<String>,
    pub requested_permissions_count: Option<u32>,
    pub coverage: AdbCoverage,
    pub installed_state: InstalledState,
    pub apk: Option<ApkPackageFacts>,
    pub evidence: Vec<AuthenticatedEvidence>,
    pub evidence_links: Vec<String>,
    pub mismatches: Vec<IdentityMismatch>,
    pub unknowns: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityMismatch {
    pub field: String,
    pub requested: String,
    pub observed: String,
}

pub fn project(input: Input) -> Result<Projection, Failure> {
    validate_serial(&input.requested_serial, "requested_serial")?;
    validate_package_name(&input.requested_package_name, "requested_package_name")?;
    validate_serial(&input.adb.serial, "adb.serial")?;
    validate_package_name(&input.adb.package_name, "adb.package_name")?;
    if let Some(version_code) = &input.adb.version_code {
        if !is_signed_decimal(version_code) {
            return Err(invalid("adb.version_code must be a signed decimal string"));
        }
    }
    validate_evidence(
        &input.evidence,
        &input.requested_serial,
        &input.requested_package_name,
    )?;

    let mut mismatches = Vec::new();
    compare_identity(
        &mut mismatches,
        "serial",
        &input.requested_serial,
        &input.adb.serial,
    );
    compare_identity(
        &mut mismatches,
        "package_name",
        &input.requested_package_name,
        &input.adb.package_name,
    );
    if let Some(requested_user_id) = input.requested_user_id {
        if input.adb.user_id != Some(requested_user_id) {
            mismatches.push(IdentityMismatch {
                field: "user_id".into(),
                requested: requested_user_id.to_string(),
                observed: input
                    .adb
                    .user_id
                    .map_or_else(|| "unknown".into(), |value| value.to_string()),
            });
        }
    }

    let mut unknowns = Vec::new();
    if matches!(input.installed_state, InstalledState::Unknown) {
        unknowns.push("Installed package state was not established.".into());
    }
    if input.adb.version_name.is_none() {
        unknowns.push("Installed package version name is unknown.".into());
    }
    if input.adb.version_code.is_none() {
        unknowns.push("Installed package version code is unknown.".into());
    }
    if input.adb.first_install_time.is_none() {
        unknowns.push("Installed package first-install time is unknown.".into());
    }
    if input.adb.last_update_time.is_none() {
        unknowns.push("Installed package last-update time is unknown.".into());
    }
    if input.adb.installer_package_name.is_none() {
        unknowns.push("Installed package installer identity is unknown.".into());
    }
    if input.adb.pkg_flags.is_none() {
        unknowns.push("Installed package flags are unknown.".into());
    }
    if input.adb.user_id.is_none() {
        unknowns.push("Installed package user identity is unknown.".into());
    }
    if input.adb.requested_permissions_count.is_none() {
        unknowns.push("Requested permissions count is unknown.".into());
    }
    if matches!(input.adb.coverage, AdbCoverage::Partial) {
        unknowns.push("Installed package coverage is partial.".into());
    }

    if let Some(apk) = &input.apk {
        if let Some(apk_package_name) = &apk.report.package_name {
            compare_identity(
                &mut mismatches,
                "apk_package_name",
                &input.requested_package_name,
                apk_package_name,
            );
        } else {
            unknowns.push("Selected APK package identity is unknown.".into());
        }
        unknowns.extend(apk.report.limitations.iter().cloned());
    }

    let evidence_links = input
        .evidence
        .iter()
        .map(|evidence| evidence.evidence_id.clone())
        .collect();

    Ok(Projection {
        client: input.adb.client.clone(),
        serial: input.adb.serial.clone(),
        package_name: input.adb.package_name.clone(),
        user_id: input.adb.user_id,
        version_name: input.adb.version_name.clone(),
        version_code: input.adb.version_code.clone(),
        first_install_time: input.adb.first_install_time.clone(),
        last_update_time: input.adb.last_update_time.clone(),
        installer_package_name: input.adb.installer_package_name.clone(),
        pkg_flags: input.adb.pkg_flags.clone(),
        requested_permissions_count: input.adb.requested_permissions_count,
        coverage: input.adb.coverage,
        installed_state: input.installed_state,
        apk: input.apk,
        evidence: input.evidence,
        evidence_links,
        mismatches,
        unknowns,
    })
}

fn validate_evidence(
    evidence: &[AuthenticatedEvidence],
    serial: &str,
    package_name: &str,
) -> Result<(), Failure> {
    if evidence.is_empty() {
        return Err(invalid("authenticated package Evidence must not be empty"));
    }

    let mut evidence_ids = BTreeSet::new();
    for item in evidence {
        if item.evidence_id.is_empty() || item.operation.is_empty() {
            return Err(invalid(
                "authenticated package Evidence requires an id and operation",
            ));
        }
        if !evidence_ids.insert(&item.evidence_id) {
            return Err(invalid("authenticated package Evidence ids must be unique"));
        }
        if !item.authenticated {
            return Err(invalid(
                "package Evidence must be authenticated before joining",
            ));
        }
        if item.operation != OPERATION {
            return Err(invalid(
                "package Evidence operation does not match inspect_adb_package",
            ));
        }
        if item.serial != serial || item.package_name != package_name {
            return Err(invalid(
                "package Evidence subject does not match the requested target",
            ));
        }
    }
    Ok(())
}

fn compare_identity(
    mismatches: &mut Vec<IdentityMismatch>,
    field: &str,
    requested: &str,
    observed: &str,
) {
    if requested != observed {
        mismatches.push(IdentityMismatch {
            field: field.into(),
            requested: requested.into(),
            observed: observed.into(),
        });
    }
}

fn validate_serial(value: &str, field: &str) -> Result<(), Failure> {
    if value.is_empty() || value.len() > 256 {
        return Err(invalid(&format!("{field} must be between 1 and 256 bytes")));
    }
    if value.chars().any(|character| {
        character.is_whitespace() || character == '\0' || character == '"' || character == '\''
    }) {
        return Err(invalid(&format!(
            "{field} cannot contain whitespace, NUL, or quotes"
        )));
    }
    Ok(())
}

fn validate_package_name(value: &str, field: &str) -> Result<(), Failure> {
    if value.is_empty() || value.len() > 256 {
        return Err(invalid(&format!("{field} must be between 1 and 256 bytes")));
    }

    for segment in value.split('.') {
        let mut characters = segment.chars();
        let Some(first) = characters.next() else {
            return Err(invalid(&format!(
                "{field} must contain Java identifier segments"
            )));
        };
        if !first.is_ascii_alphabetic()
            || characters.any(|character| !character.is_ascii_alphanumeric() && character != '_')
        {
            return Err(invalid(&format!(
                "{field} must be dot-separated Java identifiers"
            )));
        }
    }
    Ok(())
}

fn is_signed_decimal(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty() && digits.chars().all(|character| character.is_ascii_digit())
}

fn invalid(message: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide caller-selected authenticated package Evidence and retained ADB/APK facts.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
