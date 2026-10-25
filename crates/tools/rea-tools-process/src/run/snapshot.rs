//! Bounded before/after filesystem snapshots and effect classification.
//!
//! Compatibility owners: `snapshotRoots` and `hashFile`
//! (`FilesystemSnapshot.ts`) and `classifyFilesystemEffects`
//! (`ProcessFilesystemEffects.ts`). Symlinks are never followed; a file is
//! hashed only while its opened descriptor still matches the listed state;
//! every omission keeps its reason and remaining budget.

use super::scenario::Scenario;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const UNAVAILABLE_CODES: [&str; 7] = [
    "EACCES", "EISDIR", "ELOOP", "ENOTDIR", "ENOENT", "EPERM", "ESTALE",
];

/// One snapshot (`ProcessFilesystemSnapshot`).
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub files: Vec<Value>,
    pub truncated: bool,
    pub complete_roots: Vec<String>,
    pub coverage: Value,
}

/// Node `error.code` for an OS error.
pub fn system_code(error: &io::Error) -> Option<&'static str> {
    Some(match error.raw_os_error()? {
        libc::EACCES => "EACCES",
        libc::EISDIR => "EISDIR",
        libc::ELOOP => "ELOOP",
        libc::ENOTDIR => "ENOTDIR",
        libc::ENOENT => "ENOENT",
        libc::EPERM => "EPERM",
        libc::ESTALE => "ESTALE",
        libc::EINVAL => "EINVAL",
        libc::EEXIST => "EEXIST",
        libc::EBUSY => "EBUSY",
        libc::EMFILE => "EMFILE",
        libc::EIO => "EIO",
        _ => return None,
    })
}

fn unavailable_code(error: &io::Error) -> Option<&'static str> {
    system_code(error).filter(|code| UNAVAILABLE_CODES.contains(code))
}

fn same_identity(before: &Metadata, after: &Metadata, directory: bool) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && if directory {
            after.is_dir()
        } else {
            after.file_type().is_symlink()
        }
}

fn same_file_state(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.is_file()
        && after.is_file()
        && before.mode() == after.mode()
        && before.size() == after.size()
        && (before.mtime(), before.mtime_nsec()) == (after.mtime(), after.mtime_nsec())
        && (before.ctime(), before.ctime_nsec()) == (after.ctime(), after.ctime_nsec())
}

enum Hash {
    Hashed(String),
    Omitted {
        reason: &'static str,
        system_code: Option<&'static str>,
    },
}

fn changed() -> Hash {
    Hash::Omitted {
        reason: "file_changed_or_short_read",
        system_code: None,
    }
}

/// `hashFile`.
fn hash_file(path: &Path, expected: &Metadata, max_bytes: u64) -> Result<Hash, String> {
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) => {
            return match unavailable_code(&error) {
                Some(code) => Ok(Hash::Omitted {
                    reason: "file_unavailable",
                    system_code: Some(code),
                }),
                None => Err(format!("{}: {error}", path.display())),
            };
        }
    };
    let read = |mut file: &File| -> io::Result<Hash> {
        let stats = file.metadata()?;
        if !same_file_state(expected, &stats) || stats.size() > max_bytes {
            return Ok(changed());
        }
        let mut hash = Sha256::new();
        let mut buffer = vec![0_u8; (64 * 1024).min(max_bytes.max(1) as usize)];
        let mut position = 0;
        while position < stats.size() {
            let wanted = buffer.len().min((stats.size() - position) as usize);
            let count = file.read(&mut buffer[..wanted])?;
            if count == 0 {
                return Ok(changed());
            }
            hash.update(&buffer[..count]);
            position += count as u64;
        }
        let after = file.metadata()?;
        if !same_file_state(&stats, &after) {
            return Ok(changed());
        }
        Ok(Hash::Hashed(format!("{:x}", hash.finalize())))
    };
    match read(&file) {
        Ok(hash) => Ok(hash),
        Err(error) => match unavailable_code(&error) {
            Some(code) => Ok(Hash::Omitted {
                reason: "file_unavailable",
                system_code: Some(code),
            }),
            None => Err(format!("{}: {error}", path.display())),
        },
    }
}

fn lstat_if_present(
    path: &Path,
    previously_observed_root: bool,
) -> Result<Option<Metadata>, String> {
    match fs::symlink_metadata(path) {
        Ok(stats) => Ok(Some(stats)),
        Err(error) => match system_code(&error) {
            Some("ENOENT") => Ok(None),
            Some("ENOTDIR") if previously_observed_root => Ok(None),
            _ => Err(format!("{}: {error}", path.display())),
        },
    }
}

/// A follow-up read that cannot turn observed metadata into absence.
fn entry_observation<T>(
    read: io::Result<T>,
) -> Result<Result<T, (&'static str, Option<&'static str>)>, String> {
    match read {
        Ok(value) => Ok(Ok(value)),
        Err(error) => match system_code(&error) {
            Some(code) if UNAVAILABLE_CODES.contains(&code) || code == "EINVAL" => {
                Ok(Err(("entry_unavailable", Some(code))))
            }
            _ => Err(error.to_string()),
        },
    }
}

/// UTF-16 code-unit order, JavaScript's default `Array#sort`.
fn utf16_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

struct Walk<'a> {
    scenario: &'a Scenario,
    previous: BTreeSet<String>,
    entries: Vec<Value>,
    complete_roots: Vec<String>,
    remaining_bytes: u64,
    pending_names: u64,
    truncated: bool,
    enumeration_reasons: Vec<&'static str>,
    enumeration_omissions: Vec<Value>,
    hash_omissions: Vec<Value>,
}

fn file_type(stats: &Metadata) -> &'static str {
    if stats.is_file() {
        "file"
    } else if stats.is_dir() {
        "directory"
    } else if stats.file_type().is_symlink() {
        "symlink"
    } else {
        "other"
    }
}

impl Walk<'_> {
    fn reason(&mut self, reason: &'static str) {
        if !self.enumeration_reasons.contains(&reason) {
            self.enumeration_reasons.push(reason);
        }
    }

    fn omit(
        &mut self,
        path: String,
        reason: &'static str,
        system_code: Option<&'static str>,
    ) -> bool {
        self.truncated = true;
        self.reason(reason);
        self.enumeration_omissions
            .push(json!({"path": path, "reason": reason, "system_code": system_code}));
        false
    }

    fn entry(
        &mut self,
        path: String,
        kind: &str,
        stats: &Metadata,
        sha256: Option<String>,
        target: Option<String>,
    ) {
        self.entries.push(json!({
            "path": path, "type": kind, "mode": stats.mode(), "size": stats.size(),
            "sha256": sha256, "symlink_target": target,
        }));
    }

    fn record_file(&mut self, path: String, stats: &Metadata, outcome: Hash) {
        let sha256 = match outcome {
            Hash::Hashed(sha256) => {
                self.remaining_bytes -= stats.size();
                Some(sha256)
            }
            Hash::Omitted {
                reason,
                system_code,
            } => {
                self.truncated = true;
                self.hash_omissions.push(json!({
                    "path": path, "size_bytes": stats.size(), "remaining_budget_bytes": self.remaining_bytes,
                    "reason": reason, "system_code": system_code,
                }));
                None
            }
        };
        self.entry(path, "file", stats, sha256, None);
    }

    fn visit(
        &mut self,
        root: &Path,
        alias: &str,
        path: &Path,
        depth: u64,
        admitted: Option<Metadata>,
    ) -> Result<bool, String> {
        let files = self.scenario.files;
        let depth_limit = self.scenario.filesystem_depth;
        if self.entries.len() as u64 >= files || depth > depth_limit {
            self.truncated = true;
            if self.entries.len() as u64 >= files {
                self.reason("files_limit");
            }
            if depth > depth_limit {
                self.reason("depth_limit");
            }
            return Ok(false);
        }
        let stats = match admitted {
            Some(stats) => stats,
            None => match lstat_if_present(path, self.previous.contains(&format!("{alias}:.")))? {
                Some(stats) => stats,
                None => return Ok(true),
            },
        };
        let relative = path
            .strip_prefix(root)
            .ok()
            .map(|relative| relative.to_string_lossy().into_owned())
            .filter(|relative| !relative.is_empty())
            .unwrap_or_else(|| ".".to_owned());
        let entry_path = format!("{alias}:{relative}");
        if stats.file_type().is_symlink() {
            let target = match entry_observation(fs::read_link(path))? {
                Ok(target) => target,
                Err((reason, code)) => return Ok(self.omit(entry_path, reason, code)),
            };
            let after = match entry_observation(fs::symlink_metadata(path))? {
                Ok(after) => after,
                Err((reason, code)) => return Ok(self.omit(entry_path, reason, code)),
            };
            if !same_identity(&stats, &after, false) {
                return Ok(self.omit(entry_path, "identity_changed", None));
            }
            self.entry(
                entry_path,
                "symlink",
                &stats,
                None,
                Some(target.to_string_lossy().into_owned()),
            );
            return Ok(true);
        }
        if stats.is_file() {
            if self.remaining_bytes < stats.size() {
                self.record_file(
                    entry_path,
                    &stats,
                    Hash::Omitted {
                        reason: "file_bytes_budget",
                        system_code: None,
                    },
                );
            } else {
                let outcome = hash_file(path, &stats, self.remaining_bytes)?;
                self.record_file(entry_path, &stats, outcome);
            }
            return Ok(true);
        }
        let kind = file_type(&stats);
        self.entry(entry_path.clone(), kind, &stats, None, None);
        if kind != "directory" {
            return Ok(true);
        }
        let remaining_entries =
            files.saturating_sub(self.entries.len() as u64 + self.pending_names);
        let directory = match fs::read_dir(path) {
            Ok(directory) => directory,
            Err(error) => {
                let Some(code) = unavailable_code(&error) else {
                    return Err(format!("{}: {error}", path.display()));
                };
                self.truncated = true;
                self.reason("directory_unavailable");
                self.enumeration_omissions.push(json!({"path": entry_path, "reason": "directory_unavailable", "system_code": code}));
                return Ok(false);
            }
        };
        let mut complete = true;
        let mut children: Vec<String> = Vec::new();
        for child in directory {
            let child = child.map_err(|error| format!("{}: {error}", path.display()))?;
            if children.len() as u64 >= remaining_entries || depth >= depth_limit {
                self.truncated = true;
                complete = false;
                if children.len() as u64 >= remaining_entries {
                    self.reason("files_limit");
                }
                if depth >= depth_limit {
                    self.reason("depth_limit");
                }
                break;
            }
            children.push(child.file_name().to_string_lossy().into_owned());
            self.pending_names += 1;
        }
        let after = match entry_observation(fs::symlink_metadata(path))? {
            Ok(after) if same_identity(&stats, &after, true) => after,
            Ok(_) => {
                self.pending_names -= children.len() as u64;
                return Ok(self.omit(entry_path, "identity_changed", None));
            }
            Err((reason, code)) => {
                self.pending_names -= children.len() as u64;
                return Ok(self.omit(entry_path, reason, code));
            }
        };
        let _ = after;
        children.sort_by(|left, right| utf16_cmp(left, right));
        for child in children {
            self.pending_names -= 1;
            if !self.visit(root, alias, &path.join(&child), depth + 1, None)? {
                complete = false;
            }
        }
        Ok(complete)
    }
}

/// `snapshotRoots`.
pub fn snapshot_roots(
    scenario: &Scenario,
    previous: Option<&Snapshot>,
) -> Result<Snapshot, String> {
    let mut walk = Walk {
        scenario,
        previous: previous
            .map(|previous| {
                previous
                    .files
                    .iter()
                    .filter_map(|file| file["path"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        entries: Vec::new(),
        complete_roots: Vec::new(),
        remaining_bytes: scenario.file_bytes,
        pending_names: 0,
        truncated: false,
        enumeration_reasons: Vec::new(),
        enumeration_omissions: Vec::new(),
        hash_omissions: Vec::new(),
    };
    for (index, root) in scenario.filesystem_observation_paths.iter().enumerate() {
        let alias = format!("root_{index}");
        let root = PathBuf::from(root);
        let previously = walk.previous.contains(&format!("{alias}:."));
        let Some(admitted) = lstat_if_present(&root, previously)
            .map_err(|error| format!("Process filesystem snapshot failed: {error}"))?
        else {
            walk.complete_roots.push(alias);
            continue;
        };
        if walk
            .visit(&root, &alias, &root, 0, Some(admitted))
            .map_err(|error| format!("Process filesystem snapshot failed: {error}"))?
        {
            walk.complete_roots.push(alias);
        }
    }
    let coverage = json!({
        "files_limit": scenario.files,
        "depth_limit": scenario.filesystem_depth,
        "enumeration_truncated": walk.complete_roots.len() != scenario.filesystem_observation_paths.len(),
        "enumeration_reasons": walk.enumeration_reasons,
        "enumeration_omissions": walk.enumeration_omissions,
        "hash_budget_bytes": scenario.file_bytes,
        "hashed_bytes": scenario.file_bytes - walk.remaining_bytes,
        "hash_omissions": walk.hash_omissions,
    });
    Ok(Snapshot {
        files: walk.entries,
        truncated: walk.truncated,
        complete_roots: walk.complete_roots,
        coverage,
    })
}

fn unobserved_absence(
    path: &str,
    phase: &str,
    complete_roots: &BTreeSet<&str>,
    files: &HashMap<&str, &Value>,
) -> Option<String> {
    let alias = &path[..path.find(':').unwrap_or(0)];
    if !complete_roots.contains(alias) {
        return Some(format!(
            "The {phase} snapshot did not exhaust path enumeration under {alias}; absence remains unknown."
        ));
    }
    let root_path = format!("{alias}:.");
    if path != root_path
        && files
            .get(root_path.as_str())
            .is_some_and(|file| file["type"] == "symlink")
    {
        return Some(format!(
            "The {phase} snapshot did not follow the symbolic link at {root_path}; descendant absence remains unknown."
        ));
    }
    let mut index = path.rfind('/');
    while let Some(end) = index.filter(|end| *end > 0) {
        let parent = &path[..end];
        if files
            .get(parent)
            .is_some_and(|file| file["type"] == "symlink")
        {
            return Some(format!(
                "The {phase} snapshot did not follow the symbolic link at {parent}; descendant absence remains unknown."
            ));
        }
        index = path[..end].rfind('/');
    }
    None
}

/// `classifyFilesystemEffects`.
pub fn classify_effects(before: &Snapshot, after: &Snapshot) -> Vec<Value> {
    let by_path = |snapshot: &Snapshot| -> HashMap<String, Value> {
        snapshot
            .files
            .iter()
            .filter_map(|file| Some((file["path"].as_str()?.to_owned(), file.clone())))
            .collect()
    };
    let before_files = by_path(before);
    let after_files = by_path(after);
    let before_ref: HashMap<&str, &Value> = before_files
        .iter()
        .map(|(path, file)| (path.as_str(), file))
        .collect();
    let after_ref: HashMap<&str, &Value> = after_files
        .iter()
        .map(|(path, file)| (path.as_str(), file))
        .collect();
    let before_roots: BTreeSet<&str> = before.complete_roots.iter().map(String::as_str).collect();
    let after_roots: BTreeSet<&str> = after.complete_roots.iter().map(String::as_str).collect();
    let mut paths: Vec<&str> = before_ref
        .keys()
        .chain(after_ref.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    paths.sort_by(|left, right| utf16_cmp(left, right));
    paths
        .into_iter()
        .map(|path| {
            let before_file = before_ref.get(path).copied();
            let after_file = after_ref.get(path).copied();
            let reason = match (before_file, after_file) {
                (None, _) => unobserved_absence(path, "before", &before_roots, &before_ref),
                (Some(_), None) => unobserved_absence(path, "after", &after_roots, &after_ref),
                _ => None,
            };
            let state = |file: Option<&Value>| file.cloned().unwrap_or(Value::Null);
            if let Some(reason) = reason {
                return json!({"path": path, "status": "unknown", "before": state(before_file), "after": state(after_file), "reason": reason});
            }
            match (before_file, after_file) {
                (None, Some(after)) => json!({"path": path, "status": "created", "before": null, "after": after}),
                (Some(before), None) => json!({"path": path, "status": "deleted", "before": before, "after": null}),
                (Some(before), Some(after)) => {
                    let metadata_changed = ["type", "mode", "size", "symlink_target"].iter().any(|key| before[*key] != after[*key]);
                    if !metadata_changed && before["type"] == "file" && after["type"] == "file" && (before["sha256"].is_null() || after["sha256"].is_null()) {
                        return json!({
                            "path": path, "status": "unknown", "before": before, "after": after,
                            "reason": "A file content hash is unavailable in at least one snapshot; matching metadata does not establish unchanged contents.",
                        });
                    }
                    let status = if metadata_changed || before["sha256"] != after["sha256"] { "modified" } else { "unchanged" };
                    json!({"path": path, "status": status, "before": before, "after": after})
                }
                (None, None) => unreachable!("each path comes from one snapshot"),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario(root: &Path, files: u64, file_bytes: u64) -> Scenario {
        Scenario::from_input(&json!({
            "executable": "/bin/true", "arguments": [], "working_directory": "/", "environment": {},
            "filesystem_observation_paths": [root.to_string_lossy()], "terminal": {"columns": 80, "rows": 24, "scrollback": 0},
            "events": [], "timeout_ms": 1000, "idle_timeout_ms": 1000, "settle_ms": 0, "finalization_ms": 0,
            "limits": {"output_bytes": 100, "files": files, "file_bytes": file_bytes, "processes": 10, "filesystem_depth": 4},
            "normalization": {"paths": false, "pids": true, "ports": true, "time_bucket_ms": 10, "patterns": []},
        }))
    }

    #[test]
    fn classifies_created_deleted_modified_and_symlinks() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("gone.txt"), "old\n").unwrap();
        fs::write(root.path().join("keep.txt"), "keep\n").unwrap();
        let scenario = scenario(root.path(), 100, 1000);
        let before = snapshot_roots(&scenario, None).unwrap();
        fs::remove_file(root.path().join("gone.txt")).unwrap();
        fs::write(root.path().join("keep.txt"), "changed\n").unwrap();
        fs::create_dir(root.path().join("sub")).unwrap();
        fs::write(root.path().join("sub/new.txt"), "data\n").unwrap();
        std::os::unix::fs::symlink("keep.txt", root.path().join("link")).unwrap();
        let after = snapshot_roots(&scenario, Some(&before)).unwrap();
        let effects: Vec<_> = classify_effects(&before, &after)
            .into_iter()
            .map(|effect| {
                format!(
                    "{}={}",
                    effect["path"].as_str().unwrap(),
                    effect["status"].as_str().unwrap()
                )
            })
            .collect();
        assert_eq!(
            effects,
            [
                "root_0:.=modified",
                "root_0:gone.txt=deleted",
                "root_0:keep.txt=modified",
                "root_0:link=created",
                "root_0:sub=created",
                "root_0:sub/new.txt=created"
            ]
        );
        assert_eq!(after.coverage["hashed_bytes"], 13);
    }

    #[test]
    fn budgets_produce_explicit_omissions_and_unknown_effects() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("a"), "0123456789").unwrap();
        fs::write(root.path().join("b"), "x").unwrap();
        let scenario = scenario(root.path(), 2, 5);
        let snapshot = snapshot_roots(&scenario, None).unwrap();
        assert!(snapshot.truncated);
        assert_eq!(snapshot.coverage["enumeration_truncated"], true);
        assert_eq!(
            snapshot.coverage["enumeration_reasons"],
            json!(["files_limit"])
        );
        assert_eq!(
            snapshot.coverage["hash_omissions"][0]["reason"],
            "file_bytes_budget"
        );
        let effects = classify_effects(&snapshot, &snapshot);
        assert!(effects.iter().any(|effect| effect["status"] == "unknown"));
    }
}
