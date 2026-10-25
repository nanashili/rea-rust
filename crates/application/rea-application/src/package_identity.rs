//! Ownership facts for the packaged REA runtime.
//!
//! The executable path is the only authority used here.  A working directory,
//! `PATH`, and package-manager environment variables can describe a different
//! installation, so they are deliberately excluded from discovery.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const PACKAGE_NAME: &str = "rea-agents";
const RELEASE_NAME: &str = "rea-rust";
const RELEASE_SCHEMA_VERSION: u64 = 1;
#[cfg(windows)]
const RELEASE_EXECUTABLE: &str = "bin/rea.exe";
#[cfg(not(windows))]
const RELEASE_EXECUTABLE: &str = "bin/rea";
#[cfg(windows)]
const RELEASE_WORKER: &str = "bin/rea-ghidra-rust-worker.exe";
#[cfg(not(windows))]
const RELEASE_WORKER: &str = "bin/rea-ghidra-rust-worker";

/// The distribution that owns an executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageInstallationKind {
    /// The historical npm or Bun package layout.
    NodePackage,
    /// A GitHub release archive installed by the native installer.
    StandaloneRelease,
}

/// A package root whose manifest and launcher layout were verified together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageIdentity {
    pub package_root: PathBuf,
    pub manifest_path: PathBuf,
    pub launcher_path: Option<PathBuf>,
    pub native_bin_path: PathBuf,
    pub version: String,
    pub installation_kind: PackageInstallationKind,
    pub target: Option<String>,
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
                "no owned REA installation found above {}",
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

#[derive(Deserialize)]
struct ReleaseManifest {
    name: Option<String>,
    schema_version: Option<u64>,
    version: Option<String>,
    target: Option<String>,
    source_commit: Option<String>,
    files: Option<std::collections::BTreeMap<String, String>>,
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
        if let Some(identity) = inspect_candidate(directory, &canonical_executable)? {
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

/// Verify that an executable belongs to the standalone release being installed.
///
/// This is intentionally limited to release identity. Archive integrity is
/// checked by the installer before this function is called.
pub fn verify_standalone_release(
    executable: &Path,
    expected_version: &str,
) -> Result<PackageIdentity, PackageIdentityError> {
    let identity = discover_package_root(executable)?;
    if identity.installation_kind != PackageInstallationKind::StandaloneRelease {
        return Err(PackageIdentityError::InvalidManifest {
            path: identity.manifest_path,
            detail: "executable belongs to a Node package, not a standalone release".to_owned(),
        });
    }

    if identity.version != expected_version {
        return Err(PackageIdentityError::InvalidManifest {
            path: identity.manifest_path,
            detail: format!(
                "version does not match the executable: expected {expected_version}, found {}",
                identity.version
            ),
        });
    }

    let expected_target =
        expected_release_target().ok_or_else(|| PackageIdentityError::InvalidManifest {
            path: identity.manifest_path.clone(),
            detail: "this executable target is not supported by standalone releases".to_owned(),
        })?;
    if identity.target.as_deref() != Some(expected_target) {
        return Err(PackageIdentityError::InvalidManifest {
            path: identity.manifest_path,
            detail: format!(
                "target does not match the executable: expected {expected_target}, found {}",
                identity.target.as_deref().unwrap_or("missing")
            ),
        });
    }

    Ok(identity)
}

fn expected_release_target() -> Option<&'static str> {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => Some("aarch64-apple-darwin"),
        ("x86_64", "macos") => Some("x86_64-apple-darwin"),
        ("aarch64", "linux") if cfg!(target_env = "gnu") => Some("aarch64-unknown-linux-gnu"),
        ("x86_64", "linux") if cfg!(target_env = "gnu") => Some("x86_64-unknown-linux-gnu"),
        ("x86_64", "windows") if cfg!(target_env = "msvc") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}

fn inspect_candidate(
    directory: &Path,
    executable: &Path,
) -> Result<Option<PackageIdentity>, PackageIdentityError> {
    let manifest_path = directory.join("package.json");
    if manifest_path.is_file() {
        return inspect_node_package(directory, manifest_path);
    }

    inspect_standalone_release(directory, executable)
}

fn inspect_node_package(
    directory: &Path,
    manifest_path: PathBuf,
) -> Result<Option<PackageIdentity>, PackageIdentityError> {
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
        launcher_path: Some(launcher_path),
        native_bin_path,
        version,
        installation_kind: PackageInstallationKind::NodePackage,
        target: None,
    }))
}

fn inspect_standalone_release(
    directory: &Path,
    executable: &Path,
) -> Result<Option<PackageIdentity>, PackageIdentityError> {
    let manifest_path = directory.join("release.json");
    if !manifest_path.is_file() {
        return Ok(None);
    }

    let manifest_bytes =
        fs::read(&manifest_path).map_err(|error| PackageIdentityError::Filesystem {
            path: manifest_path.clone(),
            detail: error.to_string(),
        })?;
    let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        PackageIdentityError::InvalidManifest {
            path: manifest_path.clone(),
            detail: error.to_string(),
        }
    })?;
    validate_release_manifest(&manifest, &manifest_path)?;

    let native_bin_path = directory.join("bin");
    let expected_executable = directory.join(RELEASE_EXECUTABLE);
    let worker = directory.join(RELEASE_WORKER);
    if !expected_executable.is_file() || !worker.is_file() || executable != expected_executable {
        return Ok(None);
    }

    Ok(Some(PackageIdentity {
        package_root: directory.to_path_buf(),
        manifest_path,
        launcher_path: None,
        native_bin_path,
        version: manifest.version.clone().expect("validated release version"),
        installation_kind: PackageInstallationKind::StandaloneRelease,
        target: manifest.target,
    }))
}

fn validate_release_manifest(
    manifest: &ReleaseManifest,
    path: &Path,
) -> Result<(), PackageIdentityError> {
    let invalid = |detail: String| PackageIdentityError::InvalidManifest {
        path: path.to_path_buf(),
        detail,
    };
    if manifest.name.as_deref() != Some(RELEASE_NAME) {
        return Err(invalid("name must be `rea-rust`".to_owned()));
    }
    if manifest.schema_version != Some(RELEASE_SCHEMA_VERSION) {
        return Err(invalid("schema_version must be 1".to_owned()));
    }
    let version = manifest
        .version
        .as_deref()
        .ok_or_else(|| invalid("version is missing".to_owned()))?;
    if !is_valid_semver(version) {
        return Err(invalid(format!("version is not valid SemVer: {version}")));
    }
    let target = manifest
        .target
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("target is missing".to_owned()))?;
    if target.contains('/') || target.contains('\\') {
        return Err(invalid("target must be a platform triple".to_owned()));
    }
    let source_commit = manifest
        .source_commit
        .as_deref()
        .ok_or_else(|| invalid("source_commit is missing".to_owned()))?;
    if source_commit.len() != 40 || !source_commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "source_commit must be a 40-character hexadecimal commit".to_owned(),
        ));
    }
    let files = manifest
        .files
        .as_ref()
        .ok_or_else(|| invalid("files is missing".to_owned()))?;
    for required in [RELEASE_EXECUTABLE, RELEASE_WORKER] {
        if !files.contains_key(required) {
            return Err(invalid(format!("files is missing {required}")));
        }
    }
    for (relative, digest) in files {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid(format!(
                "files.{relative} must be a SHA-256 digest"
            )));
        }
        let path = Path::new(relative);
        if relative.is_empty()
            || path == Path::new(".")
            || path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(invalid(format!("files contains unsafe path {relative}")));
        }
    }
    Ok(())
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

    fn standalone_fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("fixture directory");
        fs::create_dir_all(root.path().join("bin")).expect("bin directory");
        fs::write(root.path().join(RELEASE_EXECUTABLE), "binary").expect("rea executable");
        fs::write(root.path().join(RELEASE_WORKER), "worker").expect("worker executable");
        fs::write(
            root.path().join("release.json"),
            standalone_fixture_manifest(),
        )
        .expect("release manifest");
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
        assert_eq!(
            identity.installation_kind,
            PackageInstallationKind::NodePackage
        );
    }

    #[test]
    fn accepts_standalone_release_layout() {
        let root = standalone_fixture();
        let identity =
            discover_package_root(&root.path().join(RELEASE_EXECUTABLE)).expect("release");

        assert_eq!(
            identity.package_root,
            fs::canonicalize(root.path()).expect("root")
        );
        assert_eq!(identity.version, "6.7.0");
        assert_eq!(identity.target.as_deref(), Some("aarch64-apple-darwin"));
        assert_eq!(identity.launcher_path, None);
        assert_eq!(
            identity.installation_kind,
            PackageInstallationKind::StandaloneRelease
        );
    }

    #[test]
    fn accepts_standalone_release_through_symlink() {
        let root = standalone_fixture();
        let link = root.path().join("rea-link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.path().join(RELEASE_EXECUTABLE), &link).expect("symlink");
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(root.path().join(RELEASE_EXECUTABLE), &link)
            .expect("symlink");

        let identity = discover_package_root(&link).expect("release through symlink");
        assert_eq!(
            identity.installation_kind,
            PackageInstallationKind::StandaloneRelease
        );
    }

    #[test]
    fn rejects_standalone_release_with_unexpected_version() {
        let root = standalone_fixture_for_current_target();
        let error = verify_standalone_release(&root.path().join(RELEASE_EXECUTABLE), "6.7.1")
            .expect_err("unexpected version must not verify");
        assert!(matches!(
            error,
            PackageIdentityError::InvalidManifest { .. }
        ));
    }

    #[cfg(any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "x86_64", target_os = "windows", target_env = "msvc")
    ))]
    #[test]
    fn rejects_standalone_release_with_unexpected_target() {
        let root = standalone_fixture_for_current_target();
        let current_target = expected_release_target().expect("supported test target");
        let wrong_target = if current_target == "x86_64-unknown-linux-gnu" {
            "aarch64-apple-darwin"
        } else {
            "x86_64-unknown-linux-gnu"
        };
        let manifest = fs::read_to_string(root.path().join("release.json")).expect("manifest");
        fs::write(
            root.path().join("release.json"),
            manifest.replace(current_target, wrong_target),
        )
        .expect("manifest update");
        let error = verify_standalone_release(&root.path().join(RELEASE_EXECUTABLE), "6.7.0")
            .expect_err("unexpected target must not verify");
        assert!(matches!(
            error,
            PackageIdentityError::InvalidManifest { .. }
        ));
    }

    fn standalone_fixture_for_current_target() -> tempfile::TempDir {
        let root = standalone_fixture();
        let Some(target) = expected_release_target() else {
            return root;
        };
        let manifest = fs::read_to_string(root.path().join("release.json")).expect("manifest");
        let updated = manifest.replace("aarch64-apple-darwin", target);
        fs::write(root.path().join("release.json"), updated).expect("manifest update");
        root
    }

    #[test]
    fn rejects_standalone_release_with_invalid_manifest_identity() {
        let root = standalone_fixture();
        for replacement in [
            r#""name":"rea-agents""#,
            r#""schema_version":2"#,
            r#""source_commit":"short""#,
        ] {
            let manifest = fs::read_to_string(root.path().join("release.json")).expect("manifest");
            let updated = match replacement {
                r#""name":"rea-agents""# => {
                    manifest.replace("\"name\":\"rea-rust\"", "\"name\":\"rea-agents\"")
                }
                r#""schema_version":2"# => {
                    manifest.replace("\"schema_version\":1", "\"schema_version\":2")
                }
                r#""source_commit":"short""# => {
                    manifest.replace("0123456789012345678901234567890123456789", "short")
                }
                _ => unreachable!("all replacements are handled explicitly"),
            };
            fs::write(root.path().join("release.json"), updated).expect("manifest update");
            let error = discover_package_root(&root.path().join(RELEASE_EXECUTABLE))
                .expect_err("invalid release manifest");
            assert!(matches!(
                error,
                PackageIdentityError::InvalidManifest { .. }
            ));
            fs::write(
                root.path().join("release.json"),
                standalone_fixture_manifest(),
            )
            .expect("restore manifest");
        }
        let manifest = fs::read_to_string(root.path().join("release.json")).expect("manifest");
        let digest_key = format!(
            "\"{RELEASE_EXECUTABLE}\":\"0123456789012345678901234567890123456789012345678901234567890123\""
        );
        let updated = manifest.replace(&digest_key, &format!("\"{RELEASE_EXECUTABLE}\":\"short\""));
        fs::write(root.path().join("release.json"), updated).expect("manifest update");
        let error = discover_package_root(&root.path().join(RELEASE_EXECUTABLE))
            .expect_err("invalid file digest must be rejected");
        assert!(matches!(
            error,
            PackageIdentityError::InvalidManifest { .. }
        ));
    }

    fn standalone_fixture_manifest() -> String {
        let mut files = serde_json::Map::new();
        files.insert(
            RELEASE_EXECUTABLE.to_owned(),
            serde_json::Value::String(
                "0123456789012345678901234567890123456789012345678901234567890123".to_owned(),
            ),
        );
        files.insert(
            RELEASE_WORKER.to_owned(),
            serde_json::Value::String(
                "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_owned(),
            ),
        );

        serde_json::json!({
            "name": "rea-rust",
            "schema_version": 1,
            "version": "6.7.0",
            "target": "aarch64-apple-darwin",
            "source_commit": "0123456789012345678901234567890123456789",
            "files": files,
        })
        .to_string()
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
