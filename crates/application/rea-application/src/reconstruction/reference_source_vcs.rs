//! Read-only Git metadata for a caller-selected source tree.
//!
//! This deliberately implements only local ref resolution. It never invokes
//! Git or contacts a remote. Metadata entries are read without following their
//! final symlink component through `SourceTreeReader`; explicitly resolved
//! gitdir and commondir roots are then admitted as independent directories.

use super::reference_source_reader::SourceTreeReader;
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use rea_host::fs::stable_directory::DirectoryEntryKind;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

const MAX_METADATA_BYTES: usize = 64 * 1024;

pub fn read(root: &Path, cancellation: &Cancellation) -> Result<Value, Failure> {
    match read_inner(root, cancellation) {
        Ok(value) => Ok(value),
        Err(VcsError::Unknown) => Ok(unknown()),
        Err(VcsError::Failure(failure)) => Err(failure),
    }
}

#[derive(Debug)]
enum VcsError {
    Unknown,
    Failure(Failure),
}

type VcsResult<T> = Result<T, VcsError>;

fn read_inner(root: &Path, cancellation: &Cancellation) -> VcsResult<Value> {
    if cancellation.reason().is_some() {
        return Ok(unknown());
    }

    let repository = find_repository(root, cancellation)?;
    let Some(repository) = repository else {
        return Ok(json!({"kind":"none","head":null,"dirty":null}));
    };
    let git_entry = fs::symlink_metadata(repository.join(".git")).map_err(|_| VcsError::Unknown)?;
    let gitdir = if git_entry.is_dir() {
        repository.join(".git")
    } else if git_entry.is_file() {
        parse_gitdir_file(&repository, cancellation)?
    } else {
        return Ok(unknown());
    };
    let head = resolve_head(&gitdir, cancellation)?;
    Ok(json!({"kind":"git","head":head,"dirty":null}))
}

fn find_repository(root: &Path, cancellation: &Cancellation) -> VcsResult<Option<PathBuf>> {
    let mut current = root.to_path_buf();
    loop {
        if cancellation.reason().is_some() {
            return Err(VcsError::Unknown);
        }
        match fs::symlink_metadata(current.join(".git")) {
            Ok(_) => return Ok(Some(current)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(VcsError::Unknown),
        }
        if !current.pop() {
            return Ok(None);
        }
    }
}

fn parse_gitdir_file(repository: &Path, cancellation: &Cancellation) -> VcsResult<PathBuf> {
    let reader = SourceTreeReader::open(repository).map_err(|_| VcsError::Unknown)?;
    let entry = reader
        .inspect_entry(".git", cancellation)
        .map_err(map_directory_error)?
        .filter(|entry| entry.kind == DirectoryEntryKind::Regular)
        .ok_or(VcsError::Unknown)?;
    let bytes = reader
        .read_entry_with_limit(&entry, MAX_METADATA_BYTES, cancellation)
        .map_err(map_directory_error)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| VcsError::Unknown)?;
    let pointer = text.trim_end_matches(['\r', '\n']);
    let path = pointer
        .strip_prefix("gitdir: ")
        .filter(|path| !path.is_empty())
        .ok_or(VcsError::Unknown)?;
    let path = Path::new(path);
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        repository.join(path)
    })
}

fn resolve_head(gitdir: &Path, cancellation: &Cancellation) -> VcsResult<String> {
    let git_reader = SourceTreeReader::open(gitdir).map_err(|_| VcsError::Unknown)?;
    let commondir = read_optional_text(&git_reader, "commondir", cancellation)?
        .map(|value| gitdir.join(value.trim()))
        .unwrap_or_else(|| gitdir.to_path_buf());
    let head = read_required_text(&git_reader, "HEAD", cancellation)?;
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref: ") {
        if !valid_ref(reference) {
            return Err(VcsError::Unknown);
        }
        let private = ["refs/bisect/", "refs/rewritten/", "refs/worktree/"]
            .iter()
            .any(|prefix| reference.starts_with(prefix));
        let ref_root = if private { gitdir } else { &commondir };
        resolve_ref(ref_root, reference, cancellation, 0)
    } else if valid_hash(head) {
        Ok(head.to_owned())
    } else {
        Err(VcsError::Unknown)
    }
}

fn resolve_ref(
    gitdir: &Path,
    reference: &str,
    cancellation: &Cancellation,
    depth: usize,
) -> VcsResult<String> {
    if depth >= 16 || !valid_ref(reference) {
        return Err(VcsError::Unknown);
    }
    let reader = SourceTreeReader::open(gitdir).map_err(|_| VcsError::Unknown)?;
    if let Some(value) = read_optional_text(&reader, reference, cancellation)? {
        let value = value.trim();
        if valid_hash(value) {
            return Ok(value.to_owned());
        }
        if let Some(symbolic) = value.strip_prefix("ref: ") {
            return resolve_ref(gitdir, symbolic, cancellation, depth + 1);
        }
        return Err(VcsError::Unknown);
    }
    let packed = read_optional_text(&reader, "packed-refs", cancellation)?;
    let packed = packed.ok_or(VcsError::Unknown)?;
    for line in packed.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        let Some((hash, name)) = line.split_once(' ') else {
            return Err(VcsError::Unknown);
        };
        if name == reference {
            return valid_hash(hash)
                .then(|| hash.to_owned())
                .ok_or(VcsError::Unknown);
        }
    }
    Err(VcsError::Unknown)
}

fn read_required_text(
    reader: &SourceTreeReader,
    path: &str,
    cancellation: &Cancellation,
) -> VcsResult<String> {
    read_optional_text(reader, path, cancellation)?.ok_or(VcsError::Unknown)
}

fn read_optional_text(
    reader: &SourceTreeReader,
    path: &str,
    cancellation: &Cancellation,
) -> VcsResult<Option<String>> {
    let Some(entry) = reader
        .inspect_entry(path, cancellation)
        .map_err(map_directory_error)?
    else {
        return Ok(None);
    };
    if entry.kind != DirectoryEntryKind::Regular {
        return Err(VcsError::Unknown);
    }
    let bytes = reader
        .read_entry_with_limit(&entry, MAX_METADATA_BYTES, cancellation)
        .map_err(map_directory_error)?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| VcsError::Unknown)
}

fn map_directory_error(error: rea_host::fs::stable_directory::DirectoryError) -> VcsError {
    if matches!(
        error,
        rea_host::fs::stable_directory::DirectoryError::Cleanup { .. }
    ) {
        VcsError::Failure(Failure::new(
            "reference_source_io",
            "execution_failure",
            format!("Git metadata cleanup failed: {error}"),
            true,
            "Check source permissions and retry.".into(),
            std::collections::BTreeMap::from([(
                "operation",
                Detail::Text("import_reference_source".into()),
            )]),
        ))
    } else {
        VcsError::Unknown
    }
}

fn valid_ref(reference: &str) -> bool {
    if !reference.starts_with("refs/") || reference.ends_with('/') || reference.contains("@{") {
        return false;
    }
    reference.split('/').skip(1).all(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && !component.starts_with('.')
            && !component.ends_with(".lock")
            && !component.contains("..")
            && !component.ends_with('.')
            && component.bytes().all(|byte| {
                !byte.is_ascii_control()
                    && !matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
            })
    })
}

fn valid_hash(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn unknown() -> Value {
    json!({"kind":"unknown","head":null,"dirty":null})
}

#[cfg(test)]
mod tests {
    use super::read;
    use rea_core::cancellation::Cancellation;
    use serde_json::json;
    use std::fs;

    #[test]
    fn resolves_loose_head_from_nearest_repository() {
        let temporary = tempfile::tempdir().expect("create temporary repository");
        let repository = temporary.path();
        fs::create_dir_all(repository.join(".git/refs/heads")).expect("create git metadata");
        fs::write(repository.join(".git/HEAD"), b"ref: refs/heads/main\n").expect("write HEAD");
        fs::write(
            repository.join(".git/refs/heads/main"),
            b"0123456789abcdef0123456789abcdef01234567\n",
        )
        .expect("write branch ref");
        let nested = repository.join("src");
        fs::create_dir(&nested).expect("create nested source directory");

        assert_eq!(
            read(&nested, &Cancellation::default()).expect("read vcs"),
            json!({
                "kind": "git",
                "head": "0123456789abcdef0123456789abcdef01234567",
                "dirty": null
            })
        );
    }

    #[test]
    fn resolves_packed_head_and_reports_malformed_metadata_as_unknown() {
        let temporary = tempfile::tempdir().expect("create temporary repository");
        let git = temporary.path().join(".git");
        fs::create_dir_all(&git).expect("create git directory");
        fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").expect("write HEAD");
        fs::write(
            git.join("packed-refs"),
            b"# pack-refs with: peeled fully-peeled\n0123456789abcdef0123456789abcdef01234567 refs/heads/main\n",
        )
        .expect("write packed refs");
        assert_eq!(
            read(temporary.path(), &Cancellation::default()).expect("read vcs"),
            json!({
                "kind": "git",
                "head": "0123456789abcdef0123456789abcdef01234567",
                "dirty": null
            })
        );

        fs::write(git.join("HEAD"), b"ref: refs/heads/../main\n").expect("corrupt HEAD");
        assert_eq!(
            read(temporary.path(), &Cancellation::default()).expect("read vcs"),
            json!({"kind":"unknown","head":null,"dirty":null})
        );
    }

    #[test]
    fn follows_bounded_symbolic_ref_chain() {
        let temporary = tempfile::tempdir().expect("create temporary repository");
        let git = temporary.path().join(".git");
        fs::create_dir_all(git.join("refs/heads")).expect("create refs");
        fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").expect("write HEAD");
        fs::write(git.join("refs/heads/main"), b"ref: refs/heads/release\n")
            .expect("write symbolic branch");
        fs::write(
            git.join("refs/heads/release"),
            b"abcdef0123456789abcdef0123456789abcdef01\n",
        )
        .expect("write target branch");

        assert_eq!(
            read(temporary.path(), &Cancellation::default()).expect("read vcs"),
            json!({
                "kind": "git",
                "head": "abcdef0123456789abcdef0123456789abcdef01",
                "dirty": null
            })
        );
    }

    #[test]
    fn resolves_worktree_gitdir_and_keeps_private_refs_local() {
        let temporary = tempfile::tempdir().expect("create temporary worktree");
        let repository = temporary.path().join("repo");
        let common = temporary.path().join("common.git");
        let worktree = repository.join("checkout");
        fs::create_dir_all(&worktree).expect("create worktree");
        fs::create_dir_all(common.join("refs/heads")).expect("create common refs");
        fs::create_dir_all(common.join("worktrees/checkout/refs/worktree"))
            .expect("create private refs");
        fs::write(
            worktree.join(".git"),
            b"gitdir: ../../common.git/worktrees/checkout\n",
        )
        .expect("write gitdir pointer");
        let gitdir = common.join("worktrees/checkout");
        fs::write(gitdir.join("HEAD"), b"ref: refs/worktree/private\n").expect("write HEAD");
        fs::write(gitdir.join("commondir"), b"../..\n").expect("write commondir");
        fs::write(
            gitdir.join("refs/worktree/private"),
            b"fedcba9876543210fedcba9876543210fedcba98\n",
        )
        .expect("write private ref");

        assert_eq!(
            read(&worktree, &Cancellation::default()).expect("read vcs"),
            json!({
                "kind": "git",
                "head": "fedcba9876543210fedcba9876543210fedcba98",
                "dirty": null
            })
        );
    }
}
