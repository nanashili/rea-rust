//! Ownership-aware lifecycle for the bundled skill.

use crate::maintenance_client_transaction::{
    ClientTransactionError, PreparedClientChange, apply_transaction,
};
use crate::maintenance_clients::{
    ClientConfigurationFormat, ClientRegistrationTarget, ClientResolutionContext,
    canonical_client_skill_directories,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const SKILL_NAME: &str = "reverse-engineer-anything";
pub const MANAGED_FILES: &[&str] = &[
    "SKILL.md",
    "references/connection-and-recovery.md",
    "references/native-and-artifacts.md",
    "references/javascript-applications.md",
    "references/android-applications.md",
    "references/runtime-observation.md",
    "references/evidence-workflows.md",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillDestination {
    pub client: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillIssue {
    pub path: PathBuf,
    pub kind: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillIdentity {
    pub installed: bool,
    pub canonical: bool,
    pub version: Option<String>,
    pub tool_count: Option<u64>,
    pub issues: Vec<SkillIssue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillAction {
    pub client: String,
    pub path: PathBuf,
    pub status: String,
    pub detail: String,
    pub files: Vec<SkillFileAction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillFileAction {
    pub relative_path: String,
    pub status: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillRollbackFailure {
    pub path: PathBuf,
    pub operation: String,
    pub detail: String,
}

#[derive(Debug)]
pub enum SkillError {
    Source {
        path: PathBuf,
        source: io::Error,
    },
    Install {
        path: PathBuf,
        source: io::Error,
    },
    Transaction {
        path: PathBuf,
        reason: String,
        rollback_failures: Vec<SkillRollbackFailure>,
        recovery_paths: Vec<PathBuf>,
    },
    UnknownClient {
        client: String,
    },
}

impl std::fmt::Display for SkillError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source { path, source } => {
                write!(
                    formatter,
                    "cannot read bundled skill at {}: {source}",
                    path.display()
                )
            }
            Self::Install { path, source } => {
                write!(
                    formatter,
                    "cannot install skill at {}: {source}",
                    path.display()
                )
            }
            Self::Transaction {
                path,
                reason,
                rollback_failures,
                recovery_paths,
            } => {
                write!(
                    formatter,
                    "skill transaction failed at {}: {reason}",
                    path.display()
                )?;
                if !rollback_failures.is_empty() {
                    write!(formatter, "; rollback failures: ")?;
                    for (index, failure) in rollback_failures.iter().enumerate() {
                        if index > 0 {
                            write!(formatter, ", ")?;
                        }
                        write!(formatter, "{} ({})", failure.path.display(), failure.detail)?;
                    }
                }
                if !recovery_paths.is_empty() {
                    write!(
                        formatter,
                        "; recovery backups retained at {}",
                        recovery_paths
                            .iter()
                            .map(|path| path.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )?;
                }
                Ok(())
            }
            Self::UnknownClient { client } => write!(formatter, "unknown skill client: {client}"),
        }
    }
}

impl std::error::Error for SkillError {}

pub fn skill_destinations(
    context: &ClientResolutionContext,
    clients: Option<&[String]>,
) -> Result<Vec<SkillDestination>, SkillError> {
    let mut destinations = BTreeMap::<PathBuf, String>::new();
    for (client, directory) in
        canonical_client_skill_directories(context, clients).map_err(|error| match error {
            crate::maintenance_clients::ClientSkillDirectoryError::UnknownClient { client } => {
                SkillError::UnknownClient { client }
            }
        })?
    {
        destinations.entry(directory).or_insert(client);
    }
    Ok(destinations
        .into_iter()
        .map(|(directory, client)| SkillDestination {
            client,
            path: directory.join(SKILL_NAME),
        })
        .collect())
}

pub fn read_bundle(source_root: &Path) -> Result<BTreeMap<String, Vec<u8>>, SkillError> {
    let mut files = BTreeMap::new();
    for relative in MANAGED_FILES {
        let path = source_root.join(relative);
        let bytes = fs::read(&path).map_err(|source| SkillError::Source {
            path: path.clone(),
            source,
        })?;
        files.insert((*relative).to_owned(), bytes);
    }
    Ok(files)
}

pub fn inspect_skill(path: &Path, bundle: &BTreeMap<String, Vec<u8>>) -> SkillIdentity {
    let manifest = path.join("SKILL.md");
    let mut identity = SkillIdentity {
        installed: false,
        canonical: true,
        version: None,
        tool_count: None,
        issues: Vec::new(),
    };
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return identity,
        Err(error) => {
            identity.issues.push(issue(path, "unreadable", error));
            return identity;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        identity.issues.push(SkillIssue {
            path: path.to_owned(),
            kind: if metadata.file_type().is_symlink() {
                "symbolic_link"
            } else {
                "not_directory"
            }
            .into(),
            detail: "skill path is not a regular directory".into(),
        });
        return identity;
    }
    for relative in MANAGED_FILES {
        let target = path.join(relative);
        match fs::symlink_metadata(&target) {
            Ok(value) if value.file_type().is_symlink() || !value.is_file() => {
                identity.issues.push(SkillIssue {
                    path: target,
                    kind: "not_regular_file".into(),
                    detail: "managed path is not a regular file".into(),
                });
                identity.canonical = false;
            }
            Ok(_) => match fs::read(&target) {
                Ok(actual) => {
                    identity.installed = true;
                    if bundle
                        .get(*relative)
                        .is_none_or(|expected| *expected != actual)
                    {
                        identity.canonical = false;
                    }
                }
                Err(error) => {
                    identity.issues.push(issue(&target, "unreadable", error));
                    identity.canonical = false;
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => identity.canonical = false,
            Err(error) => {
                identity.issues.push(issue(&target, "unreadable", error));
                identity.canonical = false;
            }
        }
    }
    if let Ok(content) = fs::read_to_string(&manifest) {
        if !is_owned_manifest(&content) {
            identity.canonical = false;
        }
        identity.version = metadata_value(&content, "version");
        identity.tool_count = metadata_value(&content, "tool_count").and_then(|v| v.parse().ok());
    }
    identity
}

pub fn install_skill(
    source_root: &Path,
    destinations: &[SkillDestination],
) -> Result<Vec<SkillAction>, SkillError> {
    let bundle = read_bundle(source_root)?;
    let mut actions = Vec::new();
    let mut changes = Vec::new();
    let mut changed_destinations = Vec::new();

    for destination in destinations {
        let inspection = inspect_skill(&destination.path, &bundle);
        let manifest_owned = fs::read_to_string(destination.path.join("SKILL.md"))
            .ok()
            .is_some_and(|content| is_owned_manifest(&content));
        if !inspection.issues.is_empty() || (inspection.installed && !manifest_owned) {
            return Err(SkillError::Transaction {
                path: destination.path.clone(),
                reason: if !inspection.issues.is_empty() {
                    "destination is not a safe directory".into()
                } else {
                    "existing managed files are not proven REA-owned".into()
                },
                rollback_failures: Vec::new(),
                recovery_paths: Vec::new(),
            });
        }

        let mut destination_changed = false;
        for relative in MANAGED_FILES {
            let target = destination.path.join(relative);
            validate_managed_parent(&destination.path, &target)?;
            let expected = bundle.get(*relative).expect("bundle entry");
            let original = read_skill_file(&target)?;
            if original.as_deref() == Some(expected.as_slice()) {
                continue;
            }
            destination_changed = true;
            let transaction_target = registration_target(&target, &destination.client);
            let expected_sha256 = original.as_deref().map(sha256_hex);
            changes.push(PreparedClientChange::configure(
                transaction_target,
                expected_sha256,
                original,
                expected.clone(),
            ));
        }

        if destination_changed {
            changed_destinations.push(destination);
        } else {
            actions.push(action(
                destination,
                "unchanged",
                "managed files already match the bundled skill",
            ));
        }
    }

    if changes.is_empty() {
        return Ok(actions);
    }

    let report = apply_transaction(&changes, true).map_err(transaction_error)?;
    if let Some(primary_failure) = report.primary_failure {
        let recovery_paths = report
            .items
            .iter()
            .filter_map(|item| item.recovery_path.as_ref().or(item.backup_path.as_ref()))
            .cloned()
            .collect();
        let rollback_failures = report
            .cleanup_failures
            .into_iter()
            .map(|detail| SkillRollbackFailure {
                path: PathBuf::new(),
                operation: "rollback".into(),
                detail,
            })
            .collect();
        return Err(SkillError::Transaction {
            path: changed_destinations
                .first()
                .map_or_else(PathBuf::new, |destination| destination.path.clone()),
            reason: primary_failure,
            rollback_failures,
            recovery_paths,
        });
    }

    for destination in changed_destinations {
        actions.push(action(
            destination,
            "installed",
            "bundled skill files installed atomically",
        ));
    }
    Ok(actions)
}

fn read_skill_file(path: &Path) -> Result<Option<Vec<u8>>, SkillError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(SkillError::Transaction {
                path: path.to_owned(),
                reason: "managed path is not a regular file".into(),
                rollback_failures: Vec::new(),
                recovery_paths: Vec::new(),
            })
        }
        Ok(_) => fs::read(path)
            .map(Some)
            .map_err(|source| SkillError::Install {
                path: path.to_owned(),
                source,
            }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(SkillError::Install {
            path: path.to_owned(),
            source,
        }),
    }
}

fn validate_managed_parent(root: &Path, target: &Path) -> Result<(), SkillError> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| SkillError::Transaction {
            path: target.to_owned(),
            reason: "managed path escaped skill root".into(),
            rollback_failures: Vec::new(),
            recovery_paths: Vec::new(),
        })?;
    let mut current = root.to_owned();
    let components = relative.components().collect::<Vec<_>>();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(SkillError::Transaction {
                    path: current,
                    reason: "managed parent is not a regular directory".into(),
                    rollback_failures: Vec::new(),
                    recovery_paths: Vec::new(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(SkillError::Install {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn registration_target(path: &Path, client: &str) -> ClientRegistrationTarget {
    ClientRegistrationTarget {
        id: format!("skill:{client}:{}", path.display()),
        display_name: SKILL_NAME.to_owned(),
        path: path.to_owned(),
        evidence_paths: vec![path.to_owned()],
        marker_path: path.to_owned(),
        format: ClientConfigurationFormat::Json,
        server_key: "mcpServers",
        config_path_error: None,
        quit_before_setup: false,
        manual_registration: false,
    }
}

fn transaction_error(error: ClientTransactionError) -> SkillError {
    SkillError::Transaction {
        path: PathBuf::new(),
        reason: error.to_string(),
        rollback_failures: Vec::new(),
        recovery_paths: error
            .recovery_path()
            .map(|path| vec![path.to_owned()])
            .unwrap_or_default(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn uninstall_skill(destinations: &[SkillDestination]) -> Vec<SkillAction> {
    destinations.iter().map(uninstall_destination).collect()
}

fn uninstall_destination(destination: &SkillDestination) -> SkillAction {
    let manifest = destination.path.join("SKILL.md");
    let manifest_content = match fs::read_to_string(&manifest) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return action(
                destination,
                "retained",
                "skill ownership could not be established",
            );
        }
        Err(error) => {
            return action(
                destination,
                "failed",
                &format!("skill manifest could not be read: {error}"),
            );
        }
    };
    if !is_owned_manifest(&manifest_content) {
        return action(destination, "retained", "skill manifest is not REA-owned");
    }

    let mut files = Vec::new();
    let mut failed = false;
    let mut retained = false;

    for relative in MANAGED_FILES {
        let target = destination.path.join(relative);
        let file_action = if *relative == "SKILL.md" {
            SkillFileAction {
                relative_path: (*relative).to_owned(),
                status: "pending".into(),
                detail: "owned manifest is removed after managed references".into(),
            }
        } else {
            remove_managed_file(&target, relative)
        };
        failed |= file_action.status == "failed";
        retained |= file_action.status == "retained";
        files.push(file_action);
    }

    if failed {
        return action_with_files(
            destination,
            "failed",
            "one or more REA-owned managed files could not be removed",
            files,
        );
    }
    if retained {
        return action_with_files(
            destination,
            "retained",
            "user or foreign managed paths were preserved",
            files,
        );
    }

    let manifest_action = remove_owned_manifest(&manifest);
    failed |= manifest_action.status == "failed";
    files[0] = manifest_action;
    if failed {
        return action_with_files(
            destination,
            "failed",
            "the owned manifest could not be removed",
            files,
        );
    }

    let directory_failures = remove_owned_directories(&destination.path);
    if !directory_failures.is_empty() {
        return action_with_files(destination, "failed", &directory_failures.join(" "), files);
    }

    action_with_files(
        destination,
        "removed",
        "REA-owned managed files removed; user files preserved",
        files,
    )
}

fn remove_managed_file(target: &Path, relative: &str) -> SkillFileAction {
    let result = match fs::symlink_metadata(target) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return SkillFileAction {
                relative_path: relative.to_owned(),
                status: "skipped".into(),
                detail: "managed file was absent".into(),
            };
        }
        Err(error) if error.kind() == io::ErrorKind::NotADirectory => {
            return SkillFileAction {
                relative_path: relative.to_owned(),
                status: "retained".into(),
                detail: "managed path parent is not a directory".into(),
            };
        }
        Err(error) => Err(("failed", error.to_string())),
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            Err(("retained", "managed path is not a regular file".into()))
        }
        Ok(_) => fs::remove_file(target)
            .map(|()| ("removed", "REA-owned managed file removed".into()))
            .or_else(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    Ok(("skipped", "managed file disappeared before removal".into()))
                } else {
                    Err(("failed", error.to_string()))
                }
            }),
    };

    match result {
        Ok((status, detail)) | Err((status, detail)) => SkillFileAction {
            relative_path: relative.to_owned(),
            status: status.into(),
            detail,
        },
    }
}

fn remove_owned_manifest(manifest: &Path) -> SkillFileAction {
    match fs::remove_file(manifest) {
        Ok(()) => SkillFileAction {
            relative_path: "SKILL.md".into(),
            status: "removed".into(),
            detail: "REA-owned manifest removed".into(),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => SkillFileAction {
            relative_path: "SKILL.md".into(),
            status: "skipped".into(),
            detail: "owned manifest disappeared before removal".into(),
        },
        Err(error) => SkillFileAction {
            relative_path: "SKILL.md".into(),
            status: "failed".into(),
            detail: format!("manifest could not be removed: {error}"),
        },
    }
}

fn remove_owned_directories(root: &Path) -> Vec<String> {
    [root.join("references"), root.to_owned()]
        .into_iter()
        .filter_map(|directory| match fs::remove_dir(&directory) {
            Ok(()) => None,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::DirectoryNotEmpty
                        | io::ErrorKind::NotADirectory
                ) =>
            {
                None
            }
            Err(error) => Some(format!("{}: {error}", directory.display())),
        })
        .collect()
}

fn action(destination: &SkillDestination, status: &str, detail: &str) -> SkillAction {
    action_with_files(destination, status, detail, Vec::new())
}

fn action_with_files(
    destination: &SkillDestination,
    status: &str,
    detail: &str,
    files: Vec<SkillFileAction>,
) -> SkillAction {
    SkillAction {
        client: destination.client.clone(),
        path: destination.path.clone(),
        status: status.into(),
        detail: detail.into(),
        files,
    }
}

fn issue(path: &Path, kind: &str, error: io::Error) -> SkillIssue {
    SkillIssue {
        path: path.to_owned(),
        kind: kind.into(),
        detail: error.to_string(),
    }
}
fn is_owned_manifest(content: &str) -> bool {
    content.starts_with("---\nname: reverse-engineer-anything\n")
        || content.starts_with("---\r\nname: reverse-engineer-anything\r\n")
}
fn metadata_value(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&format!("{key}: "))
            .map(|value| value.trim_matches('"').to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn bundle(root: &Path) {
        for relative in MANAGED_FILES {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().expect("managed file parent")).expect("bundle parent");
            let content = if *relative == "SKILL.md" {
                "---\nname: reverse-engineer-anything\n  version: \"test\"\n"
                    .as_bytes()
                    .to_vec()
            } else {
                format!("canonical {relative}\n").into_bytes()
            };
            fs::write(path, content).expect("bundle file");
        }
    }

    #[test]
    fn install_is_idempotent_and_uninstall_preserves_user_files() {
        let root = tempdir().expect("fixture root");
        let source = root.path().join("source");
        bundle(&source);
        let destination = root
            .path()
            .join("home/.agents/skills/reverse-engineer-anything");
        let destinations = vec![SkillDestination {
            client: "shared".into(),
            path: destination.clone(),
        }];
        fs::create_dir_all(destination.parent().expect("destination parent")).expect("parent");
        fs::write(destination.with_extension("rea.tmp"), b"foreign temporary")
            .expect("stale temporary");

        let first = install_skill(&source, &destinations).expect("first install");
        assert_eq!(first[0].status, "installed");
        let second = install_skill(&source, &destinations).expect("second install");
        assert_eq!(second[0].status, "unchanged");
        assert_eq!(
            fs::read(destination.with_extension("rea.tmp")).expect("stale temporary remains"),
            b"foreign temporary"
        );

        fs::write(destination.join("user-not-managed.md"), "keep").expect("user file");
        let result = uninstall_skill(&destinations);
        assert_eq!(result[0].status, "removed");
        assert!(destination.join("user-not-managed.md").is_file());
        assert!(!destination.join("SKILL.md").exists());
        assert!(
            result[0]
                .files
                .iter()
                .all(|file| file.status == "removed" || file.status == "skipped")
        );
    }

    #[test]
    fn install_rejects_existing_foreign_regular_managed_files() {
        let root = tempdir().expect("fixture root");
        let source = root.path().join("source");
        bundle(&source);
        let destination = root
            .path()
            .join("home/.agents/skills/reverse-engineer-anything");
        fs::create_dir_all(destination.join("references")).expect("destination");
        fs::write(destination.join("SKILL.md"), "foreign manifest").expect("foreign manifest");
        fs::write(
            destination.join("references/connection-and-recovery.md"),
            "foreign content",
        )
        .expect("foreign managed file");

        let error = install_skill(
            &source,
            &[SkillDestination {
                client: "shared".into(),
                path: destination.clone(),
            }],
        )
        .expect_err("foreign managed directory must not be overwritten");
        assert!(error.to_string().contains("not proven REA-owned"));
        assert_eq!(
            fs::read_to_string(destination.join("references/connection-and-recovery.md"))
                .expect("foreign content remains"),
            "foreign content"
        );
    }

    #[test]
    fn later_foreign_destination_fails_before_any_destination_is_written() {
        let root = tempdir().expect("fixture root");
        let source = root.path().join("source");
        bundle(&source);
        let first_path = root.path().join("first/reverse-engineer-anything");
        let second_path = root.path().join("second/reverse-engineer-anything");
        fs::create_dir_all(second_path.join("references")).expect("second destination");
        fs::write(second_path.join("SKILL.md"), "foreign manifest").expect("foreign manifest");
        fs::write(
            second_path.join("references/connection-and-recovery.md"),
            "foreign content",
        )
        .expect("foreign content");

        let error = install_skill(
            &source,
            &[
                SkillDestination {
                    client: "first".into(),
                    path: first_path.clone(),
                },
                SkillDestination {
                    client: "second".into(),
                    path: second_path,
                },
            ],
        )
        .expect_err("foreign later destination must fail preflight");
        assert!(error.to_string().contains("not proven REA-owned"));
        assert!(!first_path.exists());
    }

    #[test]
    fn unknown_selected_client_is_an_explicit_error() {
        let context = ClientResolutionContext::new(
            "/tmp/rea-test-home",
            "/tmp/rea-test-cwd",
            crate::maintenance_clients::ClientPlatform::Macos,
            BTreeMap::new(),
        );
        let error = skill_destinations(&context, Some(&["future-client".to_owned()]))
            .expect_err("unknown client must not be silently omitted");
        assert!(error.to_string().contains("future-client"));
    }

    #[test]
    fn uninstall_retains_foreign_and_mixed_managed_paths() {
        let root = tempdir().expect("fixture root");
        let foreign = root.path().join("foreign");
        fs::create_dir_all(&foreign).expect("foreign root");
        fs::write(foreign.join("SKILL.md"), "---\nname: someone-else\n").expect("foreign manifest");
        let foreign_result = uninstall_skill(&[SkillDestination {
            client: "foreign".into(),
            path: foreign,
        }]);
        assert_eq!(foreign_result[0].status, "retained");

        let mixed = root.path().join("mixed");
        fs::create_dir_all(mixed.join("references")).expect("mixed root");
        fs::write(
            mixed.join("SKILL.md"),
            "---\nname: reverse-engineer-anything\n",
        )
        .expect("owned manifest");
        fs::write(mixed.join("references/user.md"), "keep").expect("user reference");
        fs::write(mixed.join("references/connection-and-recovery.md"), "owned")
            .expect("owned reference");
        let mixed_result = uninstall_skill(&[SkillDestination {
            client: "mixed".into(),
            path: mixed.clone(),
        }]);
        assert_eq!(mixed_result[0].status, "removed");
        assert!(mixed.join("references/user.md").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn install_rejects_symlinked_skill_root_and_uninstall_retains_symlinked_file() {
        use std::os::unix::fs::symlink;
        let root = tempdir().expect("fixture root");
        let source = root.path().join("source");
        bundle(&source);
        let target = root.path().join("actual");
        fs::create_dir_all(&target).expect("actual root");
        let link = root.path().join("link");
        symlink(&target, &link).expect("root symlink");
        let error = install_skill(
            &source,
            &[SkillDestination {
                client: "shared".into(),
                path: link,
            }],
        )
        .expect_err("symlink root must be rejected");
        assert!(error.to_string().contains("safe directory"));

        let owned = root.path().join("owned");
        fs::create_dir_all(&owned).expect("owned root");
        fs::write(
            owned.join("SKILL.md"),
            "---\nname: reverse-engineer-anything\n",
        )
        .expect("owned manifest");
        fs::write(owned.join("foreign-target"), "keep").expect("target");
        symlink(owned.join("foreign-target"), owned.join("references")).expect("managed symlink");
        let result = uninstall_skill(&[SkillDestination {
            client: "shared".into(),
            path: owned,
        }]);
        assert_eq!(result[0].status, "retained");
    }

    #[cfg(unix)]
    #[test]
    fn install_rejects_symlinked_managed_parent() {
        use std::os::unix::fs::symlink;

        let root = tempdir().expect("fixture root");
        let source = root.path().join("source");
        bundle(&source);
        let destination = root
            .path()
            .join("home/.agents/skills/reverse-engineer-anything");
        fs::create_dir_all(&destination).expect("destination");
        let references_target = root.path().join("foreign-references");
        fs::create_dir_all(&references_target).expect("foreign references");
        symlink(&references_target, destination.join("references")).expect("references symlink");

        let error = install_skill(
            &source,
            &[SkillDestination {
                client: "shared".into(),
                path: destination,
            }],
        )
        .expect_err("managed symlink parent must be rejected");
        assert!(error.to_string().contains("managed parent"));
    }
}
