//! Ownership facts for the packaged REA runtime.
//!
//! The executable path is the only authority used here.  A working directory,
//! `PATH`, and package-manager environment variables can describe a different
//! installation, so they are deliberately excluded from discovery.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const PACKAGE_NAME: &str = "rea-agents";

/// A package root whose manifest and launcher layout were verified together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageIdentity {
    pub package_root: PathBuf,
    pub manifest_path: PathBuf,
    pub launcher_path: PathBuf,
    pub native_bin_path: PathBuf,
    pub version: String,
}

/// Why package ownership could not be established from an executable path.
#[derive(Debug)]
pub enum PackageIdentityError {
    ExecutablePath(String),
    NotFound { executable: PathBuf },
    InvalidManifest { path: PathBuf, detail: String },
    Filesystem { path: PathBuf, detail: String },
}

impl std::fmt::Display for PackageIdentityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExecutablePath(detail) => {
                write!(formatter, "could not determine executable path: {detail}")
            }
            Self::NotFound { executable } => write!(
                formatter,
                "no owned rea-agents package found above {}",
                executable.display()
            ),
            Self::InvalidManifest { path, detail } => write!(
                formatter,
                "invalid package manifest {}: {detail}",
                path.display()
            ),
            Self::Filesystem { path, detail } => {
                write!(formatter, "could not inspect {}: {detail}", path.display())
            }
        }
    }
}

impl std::error::Error for PackageIdentityError {}

#[derive(Deserialize)]
struct PackageManifest {
    name: Option<String>,
    version: Option<String>,
}

/// Discover and verify the package root that contains `executable`.
pub fn discover_package_root(executable: &Path) -> Result<PackageIdentity, PackageIdentityError> {
    let canonical_executable =
        fs::canonicalize(executable).map_err(|error| PackageIdentityError::Filesystem {
            path: executable.to_path_buf(),
            detail: error.to_string(),
        })?;

    let mut candidate = canonical_executable.parent();
    while let Some(directory) = candidate {
        if let Some(identity) = inspect_candidate(directory)? {
            return Ok(identity);
        }
        candidate = directory.parent();
    }

    Err(PackageIdentityError::NotFound {
        executable: canonical_executable,
    })
}

/// Discover the package owning this process's executable.
pub fn discover_current_package_root() -> Result<PackageIdentity, PackageIdentityError> {
    let executable = std::env::current_exe()
        .map_err(|error| PackageIdentityError::ExecutablePath(error.to_string()))?;
    discover_package_root(&executable)
}

fn inspect_candidate(directory: &Path) -> Result<Option<PackageIdentity>, PackageIdentityError> {
    let manifest_path = directory.join("package.json");
    if !manifest_path.is_file() {
        return Ok(None);
    }

    let manifest_bytes =
        fs::read(&manifest_path).map_err(|error| PackageIdentityError::Filesystem {
            path: manifest_path.clone(),
            detail: error.to_string(),
        })?;
    let manifest: PackageManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        PackageIdentityError::InvalidManifest {
            path: manifest_path.clone(),
            detail: error.to_string(),
        }
    })?;
    if manifest.name.as_deref() != Some(PACKAGE_NAME) {
        return Ok(None);
    }

    let version = manifest
        .version
        .ok_or_else(|| PackageIdentityError::InvalidManifest {
            path: manifest_path.clone(),
            detail: "version is missing".to_owned(),
        })?;
    if !is_valid_semver(&version) {
        return Err(PackageIdentityError::InvalidManifest {
            path: manifest_path.clone(),
            detail: format!("version is not valid SemVer: {version}"),
        });
    }

    let launcher_path = directory.join("scripts/rea.mjs");
    let native_bin_path = directory.join("native/bin");
    if !launcher_path.is_file() || !native_bin_path.is_dir() {
        return Ok(None);
    }

    Ok(Some(PackageIdentity {
        package_root: directory.to_path_buf(),
        manifest_path,
        launcher_path,
        native_bin_path,
        version,
    }))
}

fn is_valid_semver(version: &str) -> bool {
    if version.is_empty() || version.chars().any(char::is_whitespace) {
        return false;
    }

    let (without_build, build) = match version.split_once('+') {
        Some((prefix, suffix)) => (prefix, Some(suffix)),
        None => (version, None),
    };
    if let Some(build) = build {
        if !valid_identifiers(build, false) {
            return false;
        }
    }

    let (core, prerelease) = match without_build.split_once('-') {
        Some((prefix, suffix)) => (prefix, Some(suffix)),
        None => (without_build, None),
    };
    let components: Vec<_> = core.split('.').collect();
    if components.len() != 3
        || components
            .iter()
            .any(|part| !valid_numeric_identifier(part))
    {
        return false;
    }
    prerelease.is_none_or(|value| valid_identifiers(value, true))
}

fn valid_identifiers(value: &str, reject_leading_zeroes: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
                && (!reject_leading_zeroes
                    || !identifier
                        .chars()
                        .all(|character| character.is_ascii_digit())
                    || identifier == "0"
                    || !identifier.starts_with('0'))
        })
}

fn valid_numeric_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| character.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("fixture directory");
        fs::create_dir_all(root.path().join("native/bin")).expect("native bin");
        fs::create_dir_all(root.path().join("scripts")).expect("scripts");
        fs::write(
            root.path().join("package.json"),
            r#"{"name":"rea-agents","version":"6.7.0"}"#,
        )
        .expect("manifest");
        fs::write(root.path().join("scripts/rea.mjs"), "#!/usr/bin/env node\n").expect("launcher");
        fs::write(root.path().join("native/bin/rea-test"), "binary").expect("executable");
        root
    }

    #[test]
    fn accepts_packaged_native_bin_executable() {
        let root = fixture();
        let identity =
            discover_package_root(&root.path().join("native/bin/rea-test")).expect("owned package");
        let expected_root = fs::canonicalize(root.path()).expect("fixture root should resolve");
        assert_eq!(identity.package_root, expected_root);
        assert_eq!(identity.version, "6.7.0");
    }

    #[test]
    fn rejects_same_layout_with_foreign_manifest() {
        let root = fixture();
        fs::write(
            root.path().join("package.json"),
            r#"{"name":"other-package"}"#,
        )
        .expect("foreign manifest");
        let error = discover_package_root(&root.path().join("native/bin/rea-test"))
            .expect_err("foreign package must not be owned");
        assert!(matches!(error, PackageIdentityError::NotFound { .. }));
    }

    #[test]
    fn rejects_missing_or_invalid_manifest_version() {
        let root = fixture();
        for version in ["", "6.07.0", "6.7", "6.7.0-", "6.7.0-01"] {
            let manifest = format!(r#"{{"name":"rea-agents","version":"{version}"}}"#);
            fs::write(root.path().join("package.json"), manifest).expect("manifest");
            let error = discover_package_root(&root.path().join("native/bin/rea-test"))
                .expect_err("invalid version must not establish ownership");
            assert!(matches!(
                error,
                PackageIdentityError::InvalidManifest { .. }
            ));
        }
    }

    #[test]
    fn accepts_semver_prerelease_and_build_metadata() {
        let root = fixture();
        fs::write(
            root.path().join("package.json"),
            r#"{"name":"rea-agents","version":"6.7.0-rc.1+build.42"}"#,
        )
        .expect("manifest");
        let identity =
            discover_package_root(&root.path().join("native/bin/rea-test")).expect("valid version");
        assert_eq!(identity.version, "6.7.0-rc.1+build.42");
    }

    #[cfg(unix)]
    #[test]
    fn resolves_symlinked_executable_to_owned_package() {
        use std::os::unix::fs::symlink;
        let root = fixture();
        let link = root.path().join("rea-link");
        symlink(root.path().join("native/bin/rea-test"), &link).expect("symlink");
        let identity = discover_package_root(&link).expect("owned package");
        let expected_root = fs::canonicalize(root.path()).expect("fixture root should resolve");
        assert_eq!(identity.package_root, expected_root);
    }
}
