//! Read-only update-runtime facts shared by native adapters.
//!
//! This module owns package-manager identity and release-metadata parsing.  It
//! deliberately does not spawn a package manager, download a release, install
//! files, or modify integration configuration.  An adapter that has the
//! authority to perform those effects may use these facts to construct its
//! own lifecycle operation.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

pub const PACKAGE_NAME: &str = "rea-agents";
pub const UPDATE_COMMAND_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub const BUN_LATEST_VERSION_COMMAND: [&str; 5] =
    ["bun", "info", PACKAGE_NAME, "dist-tags.latest", "--json"];

/// Global npm installation that owns the running package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmInstallation {
    pub manager: Manager,
    pub prefix: PathBuf,
    pub package_root: PathBuf,
}

/// Bun global installation that owns the running package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BunInstallation {
    pub manager: Manager,
    pub global_directory: PathBuf,
    pub package_root: PathBuf,
}

/// Package managers recognized by the update runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Manager {
    Npm,
    Bun,
}

/// Global installation identity without conflating an unknown installation
/// with a package-manager installation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "manager", rename_all = "lowercase")]
pub enum UpdateInstallation {
    Npm {
        prefix: PathBuf,
        package_root: PathBuf,
    },
    Bun {
        global_directory: PathBuf,
        package_root: PathBuf,
    },
}

impl UpdateInstallation {
    pub fn manager(&self) -> Manager {
        match self {
            Self::Npm { .. } => Manager::Npm,
            Self::Bun { .. } => Manager::Bun,
        }
    }

    pub fn package_root(&self) -> &Path {
        match self {
            Self::Npm { package_root, .. } | Self::Bun { package_root, .. } => package_root,
        }
    }
}

/// Why a release lookup failed before a version could be compared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "kebab-case")]
pub enum ReleaseLookupFailure {
    Unavailable(String),
    UnsupportedPackageManager(String),
    InvalidMetadata(String),
}

/// Minimal read-only filesystem queries needed for npm ownership detection.
pub trait NpmInstallationHost {
    fn canonical_path(&self, path: &Path) -> Result<PathBuf, String>;
    fn global_root(&self) -> Result<PathBuf, String>;
    fn global_prefix(&self) -> Result<PathBuf, String>;
}

/// Minimal read-only filesystem queries needed for Bun ownership detection.
pub trait BunInstallationHost {
    fn canonical_path(&self, path: &Path) -> Result<PathBuf, String>;
    fn is_file(&self, path: &Path) -> Result<bool, String>;
}

/// Locate an npm installation while preserving canonical identity.
pub fn detect_npm_installation(
    package_root: &Path,
    host: &dyn NpmInstallationHost,
) -> Option<UpdateInstallation> {
    let canonical_package_root = host.canonical_path(package_root).ok()?;
    if let Ok(npm_root) = host.global_root() {
        let global_package_root = host.canonical_path(&npm_root.join(PACKAGE_NAME)).ok();
        if global_package_root.as_ref() == Some(&canonical_package_root) {
            let prefix = host.global_prefix().ok()?;
            if !prefix.as_os_str().is_empty() {
                return Some(UpdateInstallation::Npm {
                    prefix,
                    package_root: canonical_package_root,
                });
            }
        }
    }

    let node_modules = canonical_package_root.parent()?;
    let library = node_modules.parent()?;
    let package_name_matches = canonical_package_root
        .file_name()
        .and_then(|name| name.to_str())
        == Some(PACKAGE_NAME);
    let node_modules_matches =
        node_modules.file_name().and_then(|name| name.to_str()) == Some("node_modules");
    let library_matches = library.file_name().and_then(|name| name.to_str()) == Some("lib");
    if !(package_name_matches && node_modules_matches && library_matches) {
        return None;
    }

    Some(UpdateInstallation::Npm {
        prefix: library.parent()?.to_path_buf(),
        package_root: canonical_package_root,
    })
}

/// Resolve Bun's global project directory using Bun's documented precedence.
pub fn bun_global_directory(
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    home: &Path,
) -> PathBuf {
    let selected = first_nonempty(environment, "BUN_INSTALL_GLOBAL_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            first_nonempty(environment, "BUN_INSTALL")
                .map(|root| PathBuf::from(root).join("install").join("global"))
        })
        .or_else(|| {
            first_nonempty(environment, "XDG_CACHE_HOME").map(|root| {
                PathBuf::from(root)
                    .join(".bun")
                    .join("install")
                    .join("global")
            })
        })
        .unwrap_or_else(|| home.join(".bun").join("install").join("global"));
    resolve_against(selected, cwd)
}

/// Identify the running package as Bun's global installation.
pub fn detect_bun_installation(
    package_root: &Path,
    global_directory: &Path,
    host: &dyn BunInstallationHost,
) -> Option<UpdateInstallation> {
    let canonical_package_root = host.canonical_path(package_root).ok()?;
    let global_package_root = host
        .canonical_path(&global_directory.join("node_modules").join(PACKAGE_NAME))
        .ok()?;
    if canonical_package_root != global_package_root
        || !host
            .is_file(&global_directory.join("package.json"))
            .unwrap_or(false)
    {
        return None;
    }
    Some(UpdateInstallation::Bun {
        global_directory: global_directory.to_path_buf(),
        package_root: canonical_package_root,
    })
}

/// Parse npm 11 and npm 12 forms of `dist-tags.latest --json`.
pub fn parse_npm_latest_version(metadata: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(metadata).map_err(|error| error.to_string())?;
    let version = value
        .as_str()
        .or_else(|| value.as_array().and_then(|items| (items.len() == 1).then(|| items[0].as_str()).flatten()))
        .filter(|version| !version.is_empty())
        .ok_or_else(|| "Invalid npm release metadata: expected a version string or a single-element version array.".to_owned())?;
    Ok(version.to_owned())
}

/// Classify command output without deciding whether an adapter may execute it.
pub fn npm_release_lookup(
    response: Result<String, String>,
) -> Result<String, ReleaseLookupFailure> {
    let metadata = response.map_err(ReleaseLookupFailure::Unavailable)?;
    parse_npm_latest_version(&metadata).map_err(ReleaseLookupFailure::InvalidMetadata)
}

/// Build the exact package-manager install command for a verified identity.
pub fn update_install_command(installation: &UpdateInstallation, version: &str) -> Vec<String> {
    let release = format!("{PACKAGE_NAME}@{version}");
    match installation {
        UpdateInstallation::Npm { prefix, .. } => vec![
            "npm".into(),
            "install".into(),
            "--global".into(),
            "--ignore-scripts".into(),
            "--prefix".into(),
            prefix.to_string_lossy().into_owned(),
            release,
        ],
        UpdateInstallation::Bun { .. } => vec![
            "bun".into(),
            "add".into(),
            "--global".into(),
            "--ignore-scripts".into(),
            release,
        ],
    }
}

fn first_nonempty<'a>(environment: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    environment
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn resolve_against(path: PathBuf, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    let mut resolved = cwd.to_path_buf();
    for component in path.components() {
        match component {
            Component::Prefix(value) => resolved.push(value.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(value) => resolved.push(value),
            Component::RootDir => {}
        }
    }
    resolved
}
