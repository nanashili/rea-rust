//! Electron app-bundle / framework path admission.
//!
//! Compatibility owner: `src/electron/ElectronFusePath.ts`
//! (`resolveElectronFuseTarget` and its helpers). Admits a regular executable,
//! a macOS `.app` bundle, or an `Electron Framework` binary reached through
//! `Versions/Current` without leaving the framework. Path arithmetic follows
//! Node's POSIX `path` semantics on this host.
use std::fs;
use std::io;

const FRAMEWORK_NAME: &str = "Electron Framework.framework";
const BINARY_NAME: &str = "Electron Framework";
const MAX_SYMLINK_HOPS: u32 = 32;
const SEP: char = '/';

/// A selected path is not an admitted Electron bundle or regular file.
pub struct PathFailure {
    /// `invalid_value` or `invalid_format`.
    pub reason: &'static str,
    pub message: String,
}

impl PathFailure {
    fn value(message: impl Into<String>) -> Self {
        Self {
            reason: "invalid_value",
            message: message.into(),
        }
    }
    fn format(message: impl Into<String>) -> Self {
        Self {
            reason: "invalid_format",
            message: message.into(),
        }
    }
}

/// Resolution failure: either a typed path rejection or a host IO error.
pub enum ResolveError {
    Path(PathFailure),
    /// A raw host IO error with its errno-like code (ENOENT, EACCES, ...).
    Io {
        code: Option<&'static str>,
        error: io::Error,
    },
}

impl From<PathFailure> for ResolveError {
    fn from(failure: PathFailure) -> Self {
        Self::Path(failure)
    }
}

/// The resolved regular file and the caller-selected path.
pub struct ResolvedTarget {
    pub selected_path: String,
    pub resolved_path: String,
}

fn io_error(error: io::Error) -> ResolveError {
    ResolveError::Io {
        code: errno_code(&error),
        error,
    }
}

fn errno_code(error: &io::Error) -> Option<&'static str> {
    match error.raw_os_error() {
        Some(2) => Some("ENOENT"),
        Some(20) => Some("ENOTDIR"),
        Some(62) => Some("ELOOP"),
        Some(63) => Some("ENAMETOOLONG"),
        Some(13) => Some("EACCES"),
        Some(1) => Some("EPERM"),
        _ => None,
    }
}

fn is_missing(error: &io::Error) -> bool {
    matches!(errno_code(error), Some("ENOENT") | Some("ENOTDIR"))
}

/// `lstat` (no symlink follow).
fn lstat(path: &str) -> Result<fs::Metadata, io::Error> {
    fs::symlink_metadata(path)
}

/// Admit and resolve the fuse target to a regular file path.
pub fn resolve_target(selected_path: &str) -> Result<ResolvedTarget, ResolveError> {
    let metadata = lstat(selected_path).map_err(io_error)?;
    let file = if metadata.file_type().is_symlink() {
        resolve_framework_symlink(selected_path)?
    } else if metadata.is_file() {
        if framework_root_of(selected_path).is_none() {
            selected_path.to_owned()
        } else {
            resolve_framework_symlink(selected_path)?
        }
    } else if metadata.is_dir() {
        resolve_bundle_binary(selected_path)?
    } else {
        return Err(PathFailure::format(format!(
            "Expected a regular file or Electron app bundle: {selected_path}"
        ))
        .into());
    };
    Ok(ResolvedTarget {
        selected_path: selected_path.to_owned(),
        resolved_path: file,
    })
}

fn resolve_framework_symlink(selected_path: &str) -> Result<String, ResolveError> {
    let root = framework_root_of(selected_path).ok_or_else(|| {
        PathFailure::format(format!(
            "Expected a regular file without a symlink: {selected_path}"
        ))
    })?;
    require_framework_root(&root, selected_path)?;
    let relative = relative_inside(&root, selected_path).ok_or_else(|| {
        PathFailure::value(format!(
            "Framework symlink escapes {FRAMEWORK_NAME}: {selected_path}"
        ))
    })?;
    require_file(resolve_inside(&root, &relative)?, selected_path)
}

fn resolve_bundle_binary(selected_path: &str) -> Result<String, ResolveError> {
    let directory = resolve_directory_suffix(selected_path)?;
    let name = basename(&directory);
    if name == FRAMEWORK_NAME {
        resolve_known_binary(&directory, selected_path)
    } else if name.ends_with(".app") {
        let root = append_path(&directory, &["Contents", "Frameworks", FRAMEWORK_NAME]);
        resolve_known_binary(&root, selected_path)
    } else {
        Err(PathFailure::format(format!(
            "Expected an Electron .app bundle, {FRAMEWORK_NAME} directory, or executable file: {selected_path}"
        ))
        .into())
    }
}

/// Reduce directory suffixes only when doing so preserves filesystem selection.
fn resolve_directory_suffix(selected_path: &str) -> Result<String, ResolveError> {
    let mut path = selected_path.to_owned();
    let mut pending: Vec<String> = Vec::new();
    loop {
        let name = basename(&path);
        if !name.is_empty() {
            while path.ends_with(SEP) {
                path.pop();
            }
        }
        if name == "." || name == ".." {
            pending.push(name);
            path = dirname(&path);
            continue;
        }
        let Some(component) = pending.pop() else {
            return Ok(path);
        };
        if component == "." {
            continue;
        }
        let metadata = lstat(&path).map_err(io_error)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(PathFailure::value(format!(
                "A bundle path ending in '..' requires a real directory before each parent segment: {selected_path}"
            ))
            .into());
        }
        path = dirname(&path);
    }
}

/// `root` is the framework directory for both an `.app` and a framework selection.
fn resolve_known_binary(root: &str, bundle: &str) -> Result<String, ResolveError> {
    require_framework_root(root, bundle)?;
    for candidate in [
        BINARY_NAME.to_owned(),
        format!("Versions/Current/{BINARY_NAME}"),
        format!("Versions/A/{BINARY_NAME}"),
    ] {
        let selected = resolve_inside(root, &candidate)?;
        match selected {
            WalkResult::File(path) => return require_file(WalkResult::File(path), bundle),
            WalkResult::Absent => {}
            other => return Err(path_walk_failure(other, bundle).into()),
        }
    }
    Err(PathFailure::value(format!(
        "Electron Framework binary was not found inside {bundle}."
    ))
    .into())
}

enum WalkResult {
    File(String),
    Absent,
    Escapes,
    NotFile,
    Loop,
}

fn resolve_inside(root: &str, relative_path: &str) -> Result<WalkResult, ResolveError> {
    let mut pending: Vec<String> = relative_path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
        .collect();
    let mut resolved: Vec<String> = Vec::new();
    let mut hops: u32 = 0;
    let mut last: Option<&str> = None;
    let mut file_found = false;
    while !pending.is_empty() {
        let segment = pending.remove(0);
        if segment == "." {
            continue;
        }
        if segment == ".." {
            if resolved.is_empty() {
                return Ok(WalkResult::Escapes);
            }
            resolved.pop();
            last = Some("directory");
            continue;
        }
        let mut parts: Vec<&str> = resolved.iter().map(String::as_str).collect();
        parts.push(&segment);
        let absolute = append_path(root, &parts);
        if !is_path_within_root(root, &absolute) {
            return Ok(WalkResult::Escapes);
        }
        let metadata = match lstat(&absolute) {
            Ok(metadata) => metadata,
            Err(error) if is_missing(&error) => return Ok(WalkResult::Absent),
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink() {
            hops += 1;
            if hops > MAX_SYMLINK_HOPS {
                return Ok(WalkResult::Loop);
            }
            let target = fs::read_link(&absolute).map_err(io_error)?;
            let target = target.to_string_lossy();
            if is_absolute(&target) {
                return Ok(WalkResult::Escapes);
            }
            let mut new_segments: Vec<String> = target
                .split('/')
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect();
            new_segments.append(&mut pending);
            pending = new_segments;
            continue;
        }
        if metadata.is_dir() {
            resolved.push(segment);
            last = Some("directory");
            continue;
        }
        if !metadata.is_file() || !pending.is_empty() {
            return Ok(WalkResult::NotFile);
        }
        resolved.push(segment);
        file_found = true;
        last = Some("file");
    }
    if last != Some("file") || !file_found {
        return Ok(WalkResult::NotFile);
    }
    let parts: Vec<&str> = resolved.iter().map(String::as_str).collect();
    let file_path = append_path(root, &parts);
    if is_path_within_root(root, &file_path) {
        Ok(WalkResult::File(file_path))
    } else {
        Ok(WalkResult::Escapes)
    }
}

/// Validate the app-parent chain equally for app, framework, and binary selection.
fn require_framework_root(root: &str, selected_path: &str) -> Result<(), ResolveError> {
    let frameworks = dirname(root);
    let contents = dirname(&frameworks);
    let app = dirname(&contents);
    if basename(&frameworks) == "Frameworks"
        && basename(&contents) == "Contents"
        && basename(&app).ends_with(".app")
    {
        require_real_directories(
            &dirname(&app),
            &[
                basename(&app),
                "Contents".into(),
                "Frameworks".into(),
                FRAMEWORK_NAME.into(),
            ],
            selected_path,
        )
    } else {
        require_real_directories(&dirname(root), &[basename(root)], selected_path)
    }
}

/// Each named directory below `anchor` must be a real directory.
fn require_real_directories(
    anchor: &str,
    segments: &[String],
    selected_path: &str,
) -> Result<(), ResolveError> {
    let mut current = anchor.to_owned();
    for segment in segments {
        current = append_path(&current, &[segment]);
        let metadata = match lstat(&current) {
            Ok(metadata) => metadata,
            Err(error) if is_missing(&error) => {
                return Err(PathFailure::value(format!(
                    "Electron Framework binary was not found inside {selected_path}."
                ))
                .into());
            }
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(path_walk_failure(WalkResult::Escapes, selected_path).into());
        }
        if !metadata.is_dir() {
            return Err(path_walk_failure(WalkResult::NotFile, selected_path).into());
        }
    }
    Ok(())
}

fn require_file(walk: WalkResult, selected_path: &str) -> Result<String, ResolveError> {
    match walk {
        WalkResult::File(path) => Ok(path),
        WalkResult::Absent => Err(PathFailure::value(format!(
            "Electron Framework symlink target was not found: {selected_path}"
        ))
        .into()),
        other => Err(path_walk_failure(other, selected_path).into()),
    }
}

fn path_walk_failure(kind: WalkResult, path: &str) -> PathFailure {
    match kind {
        WalkResult::Escapes => PathFailure::value(format!(
            "Framework symlink escapes {FRAMEWORK_NAME}: {path}"
        )),
        WalkResult::Loop => {
            PathFailure::value(format!("Framework symlink hop limit exceeded: {path}"))
        }
        _ => PathFailure::value(format!(
            "Electron Framework path is not a regular file: {path}"
        )),
    }
}

fn framework_root_of(path: &str) -> Option<String> {
    let mut current = dirname(path);
    while basename(&current) != FRAMEWORK_NAME {
        let parent = dirname(&current);
        if parent == current {
            return None;
        }
        current = parent;
    }
    Some(current)
}

fn relative_inside(root: &str, path: &str) -> Option<String> {
    let prefix = if root.ends_with(SEP) {
        root.to_owned()
    } else {
        format!("{root}{SEP}")
    };
    if !path.starts_with(&prefix) {
        return None;
    }
    let value = &path[prefix.len()..];
    if value.is_empty() {
        None
    } else {
        Some(value.split(SEP).collect::<Vec<_>>().join("/"))
    }
}

// --- Node POSIX path helpers (macOS `sep` is `/`) ---

fn append_path(parent: &str, segments: &[&str]) -> String {
    let joined = segments.join(&SEP.to_string());
    if parent.ends_with(SEP) {
        format!("{parent}{joined}")
    } else {
        format!("{parent}{SEP}{joined}")
    }
}

fn is_absolute(path: &str) -> bool {
    path.starts_with(SEP)
}

/// Node `path.posix.basename`: trailing slashes stripped, last segment returned.
fn basename(path: &str) -> String {
    let trimmed = path.trim_end_matches(SEP);
    if trimmed.is_empty() {
        return String::new();
    }
    match trimmed.rsplit_once(SEP) {
        Some((_, last)) => last.to_owned(),
        None => trimmed.to_owned(),
    }
}

/// Node `path.posix.dirname`.
fn dirname(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let has_root = path.starts_with(SEP);
    let trimmed = path.trim_end_matches(SEP);
    if trimmed.is_empty() {
        // Path is all slashes.
        return SEP.to_string();
    }
    match trimmed.rsplit_once(SEP) {
        Some((head, _)) => {
            if head.is_empty() {
                SEP.to_string()
            } else {
                head.to_owned()
            }
        }
        None => {
            if has_root {
                SEP.to_string()
            } else {
                ".".to_owned()
            }
        }
    }
}

/// `isPathWithinRoot`: lexical containment test (callers resolve symlinks first).
fn is_path_within_root(root: &str, path: &str) -> bool {
    match relative_path(root, path) {
        Some(value) => {
            value.is_empty() || (value != ".." && !value.starts_with("../") && !is_absolute(&value))
        }
        None => false,
    }
}

/// Node `path.posix.relative(from, to)` for already-absolute, NUL-free inputs.
fn relative_path(from: &str, to: &str) -> Option<String> {
    let from_abs = is_absolute(from);
    let to_abs = is_absolute(to);
    if from_abs != to_abs {
        // Mixed absolute/relative: our inputs are always absolute here, so
        // treat a mismatch as not contained.
        return Some("..".to_owned());
    }
    let from_parts: Vec<&str> = from
        .split(SEP)
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    let to_parts: Vec<&str> = to
        .split(SEP)
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    let mut common = 0;
    while common < from_parts.len()
        && common < to_parts.len()
        && from_parts[common] == to_parts[common]
    {
        common += 1;
    }
    let mut out: Vec<String> = Vec::new();
    for _ in common..from_parts.len() {
        out.push("..".to_owned());
    }
    for part in &to_parts[common..] {
        out.push((*part).to_owned());
    }
    Some(out.join("/"))
}
