//! Resolve an `.app` bundle directory to its declared program file.
//!
//! Ports `src/application/AppBundleExecutable.ts` (`resolveAppBundleExecutable`
//! and its helpers) and `src/domain/localPath.ts` (`isPathWithinRoot`). The
//! `CFBundleExecutable` decode reuses `rea_rust_analysis::plist::read`, which
//! parses binary and XML property lists and drops `__proto__`, matching the TS
//! decode path.

use std::fs;
use std::path::{Component, Path, PathBuf};

use super::BinaryTargetError;

/// A resolved bundle program file and the Info.plist that declared it.
pub(crate) struct ResolvedAppBundle {
    pub executable: String,
    pub info_plist: Option<String>,
}

#[derive(Clone, Copy)]
struct BundleLayout {
    plist: &'static [&'static str],
    programs: &'static [&'static str],
    programs_label: &'static str,
}

const BUNDLE_LAYOUTS: &[BundleLayout] = &[
    BundleLayout {
        plist: &["Contents", "Info.plist"],
        programs: &["Contents", "MacOS"],
        programs_label: "Contents/MacOS",
    },
    BundleLayout {
        plist: &["Info.plist"],
        programs: &[],
        programs_label: "the bundle root",
    },
];

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The Node `error.code` text for a filesystem failure, used for the TS
/// absence / permission classification.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Code {
    Enoent,
    Enotdir,
    Eacces,
    Eperm,
    Other,
}

fn code_of(error: &std::io::Error) -> Code {
    if let Some(errno) = error.raw_os_error() {
        return errno_code(errno);
    }
    match error.kind() {
        std::io::ErrorKind::NotFound => Code::Enoent,
        std::io::ErrorKind::PermissionDenied => Code::Eacces,
        _ => Code::Other,
    }
}

#[cfg(unix)]
fn errno_code(errno: i32) -> Code {
    match errno {
        2 => Code::Enoent,
        20 => Code::Enotdir,
        13 => Code::Eacces,
        1 => Code::Eperm,
        _ => Code::Other,
    }
}

#[cfg(not(unix))]
fn errno_code(errno: i32) -> Code {
    match errno {
        2 | 3 => Code::Enoent,
        5 => Code::Eacces,
        267 => Code::Enotdir,
        _ => Code::Other,
    }
}

fn code_text(code: Code) -> Option<&'static str> {
    match code {
        Code::Enoent => Some("ENOENT"),
        Code::Enotdir => Some("ENOTDIR"),
        Code::Eacces => Some("EACCES"),
        Code::Eperm => Some("EPERM"),
        Code::Other => None,
    }
}

fn is_absence(code: Code) -> bool {
    matches!(code, Code::Enoent | Code::Enotdir)
}

fn is_permission_denied(code: Code) -> bool {
    matches!(code, Code::Eacces | Code::Eperm)
}

fn permission_system_code(code: Code) -> Option<&'static str> {
    match code {
        Code::Eacces => Some("EACCES"),
        Code::Eperm => Some("EPERM"),
        _ => None,
    }
}

/// TS `codeDescription`: ` (${code})` when a system code is present.
fn code_description(error: &std::io::Error) -> String {
    match code_text(code_of(error)) {
        Some(text) => format!(" ({text})"),
        None => String::new(),
    }
}

fn join_components(root: &Path, components: &[&str]) -> PathBuf {
    components
        .iter()
        .fold(root.to_path_buf(), |path, component| path.join(component))
}

/// Build a bundle error, attaching EACCES/EPERM as the TS `systemCode`.
fn bundle_error(
    path: impl Into<String>,
    reason: impl Into<String>,
    code: Code,
) -> BinaryTargetError {
    BinaryTargetError::new(path, reason).with_system_code(permission_system_code(code))
}

/// TS `resolveAppBundleExecutable(path)`.
pub(crate) fn resolve_app_bundle_executable(
    path: &str,
) -> Result<ResolvedAppBundle, BinaryTargetError> {
    let bundle = Path::new(path);
    match resolve_inner(bundle) {
        Ok(Some(resolved)) => return Ok(resolved),
        Ok(None) => {}
        Err(error) => return Err(error),
    }
    Err(BinaryTargetError::new(
        path,
        format!("app Info.plist is missing or no supported bundle layout was found: {path}"),
    ))
}

fn resolve_inner(bundle: &Path) -> Result<Option<ResolvedAppBundle>, BinaryTargetError> {
    if let Some(layout) = present_layout(bundle)? {
        return Ok(Some(resolve_layout_executable(bundle, layout)?));
    }
    if let Some(wrapped) = wrapped_bundle(bundle)? {
        if let Some(layout) = present_layout(&wrapped)? {
            return Ok(Some(resolve_layout_executable(&wrapped, layout)?));
        }
    }
    Ok(None)
}

/// TS `presentLayout` + `layoutPlistPresent`.
fn present_layout(bundle: &Path) -> Result<Option<BundleLayout>, BinaryTargetError> {
    for layout in BUNDLE_LAYOUTS {
        let plist = join_components(bundle, layout.plist);
        match fs::metadata(&plist) {
            Ok(metadata) if metadata.is_file() => return Ok(Some(*layout)),
            Ok(_) => continue,
            Err(error) => {
                let code = code_of(&error);
                if is_absence(code) {
                    continue;
                }
                if is_permission_denied(code) {
                    let plist = path_to_string(&plist);
                    return Err(bundle_error(
                        plist.clone(),
                        format!("permission denied inspecting app Info.plist {plist}"),
                        code,
                    ));
                }
                return Err(generic_bundle_error(bundle, &error));
            }
        }
    }
    Ok(None)
}

/// TS `wrappedBundle`: the single `.app` subdirectory inside `Wrapper`.
fn wrapped_bundle(bundle: &Path) -> Result<Option<PathBuf>, BinaryTargetError> {
    let wrapper = bundle.join("Wrapper");
    let metadata = match fs::symlink_metadata(&wrapper) {
        Ok(metadata) => metadata,
        Err(error) => {
            if is_absence(code_of(&error)) {
                return Ok(None);
            }
            return Err(generic_bundle_error(bundle, &error));
        }
    };
    if !metadata.is_dir() {
        return Ok(None);
    }
    let entries = fs::read_dir(&wrapper).map_err(|error| generic_bundle_error(bundle, &error))?;
    let mut app: Option<PathBuf> = None;
    for entry in entries {
        let entry = entry.map_err(|error| generic_bundle_error(bundle, &error))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.to_lowercase().ends_with(".app") {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| generic_bundle_error(bundle, &error))?;
        if !file_type.is_dir() {
            continue;
        }
        if app.is_some() {
            return Ok(None);
        }
        app = Some(wrapper.join(entry.file_name()));
    }
    Ok(app)
}

fn generic_bundle_error(path: &Path, error: &std::io::Error) -> BinaryTargetError {
    let code = code_of(error);
    let path = path_to_string(path);
    bundle_error(path.clone(), error_reason(code, &path), code)
}

/// TS `errorReason(cause, path)`.
fn error_reason(code: Code, path: &str) -> String {
    if is_permission_denied(code) {
        format!("permission denied accessing app bundle path {path}")
    } else if is_absence(code) {
        format!("app bundle path is missing: {path}")
    } else {
        format!("could not inspect app bundle path {path}")
    }
}

/// TS `resolveLayoutExecutable(bundle, layout)`.
fn resolve_layout_executable(
    bundle: &Path,
    layout: BundleLayout,
) -> Result<ResolvedAppBundle, BinaryTargetError> {
    let plist_path = join_components(bundle, layout.plist);
    let plist_path_string = path_to_string(&plist_path);

    let plist_bytes = match fs::read(&plist_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            let code = code_of(&error);
            let reason = if is_permission_denied(code) {
                format!("permission denied reading app Info.plist {plist_path_string}")
            } else if is_absence(code) {
                format!("app Info.plist is missing: {plist_path_string}")
            } else {
                format!(
                    "could not read app Info.plist {plist_path_string}{}",
                    code_description(&error)
                )
            };
            return Err(bundle_error(plist_path_string, reason, code));
        }
    };

    // Decode CFBundleExecutable. The native plist reader handles binary and XML
    // plists and omits `__proto__`, matching the TS decode semantics. Its
    // failures map onto the TS malformed/unsupported reason (no system code).
    let name = match decode_executable_name(&plist_bytes, &plist_path_string) {
        Ok(name) => name,
        Err(reason) => {
            return Err(BinaryTargetError::new(
                plist_path_string.clone(),
                format!(
                    "app Info.plist is malformed, unsupported, or lacks CFBundleExecutable: {plist_path_string} ({reason})"
                ),
            ));
        }
    };

    if !is_safe_executable_name(&name) {
        return Err(BinaryTargetError::new(
            path_to_string(bundle),
            "app has an unsafe CFBundleExecutable",
        ));
    }

    let programs = join_components(bundle, layout.programs);
    let executable = programs.join(&name);
    let executable_string = path_to_string(&executable);

    // realpath(bundle)
    let canonical_bundle = match fs::canonicalize(bundle) {
        Ok(path) => path,
        Err(error) => {
            let bundle_string = path_to_string(bundle);
            let code = code_of(&error);
            return Err(bundle_error(
                bundle_string.clone(),
                error_reason(code, &bundle_string),
                code,
            ));
        }
    };

    // The remaining realpath checks share one failure reason shape over the
    // program file, matching the TS inner try/catch.
    let canonical_programs = match fs::canonicalize(&programs) {
        Ok(path) => path,
        Err(error) => return Err(program_file_error(&executable_string, &error)),
    };
    if !is_path_within_root(&canonical_bundle, &canonical_programs) {
        return Err(BinaryTargetError::new(
            path_to_string(bundle),
            format!("app program directory leaves {}", layout.programs_label),
        ));
    }
    let canonical_executable = match fs::canonicalize(&executable) {
        Ok(path) => path,
        Err(error) => return Err(program_file_error(&executable_string, &error)),
    };
    if !is_path_within_root(&canonical_programs, &canonical_executable) {
        return Err(BinaryTargetError::new(
            path_to_string(bundle),
            format!("app program file leaves {}", layout.programs_label),
        ));
    }
    Ok(ResolvedAppBundle {
        executable: path_to_string(&canonical_executable),
        info_plist: Some(plist_path_string),
    })
}

fn program_file_error(executable: &str, error: &std::io::Error) -> BinaryTargetError {
    let code = code_of(error);
    let reason = if is_permission_denied(code) {
        format!("permission denied resolving app program file {executable}")
    } else if is_absence(code) {
        format!("app program file is missing: {executable}")
    } else {
        format!("could not resolve app program file {executable}")
    };
    bundle_error(executable, reason, code)
}

/// Decode `CFBundleExecutable` from the Info.plist bytes.
fn decode_executable_name(bytes: &[u8], source_path: &str) -> Result<String, String> {
    let report = rea_rust_analysis::plist::read(bytes, source_path.to_string())
        .map_err(|error| error.to_string())?;
    report
        .bundle
        .executable
        .ok_or_else(|| "CFBundleExecutable is missing".to_string())
}

/// TS `isSafeExecutableName`.
fn is_safe_executable_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('\0')
        && !name
            .chars()
            .any(|character| character == '/' || character == '\\')
}

/// TS `isPathWithinRoot(root, path)` using lexical `path.relative` semantics.
fn is_path_within_root(root: &Path, path: &Path) -> bool {
    match lexical_relative(root, path) {
        None => false,
        Some(relative) => {
            relative.as_os_str().is_empty()
                || (relative != Path::new("..")
                    && !relative.starts_with("..")
                    && relative.is_relative())
        }
    }
}

/// A lexical `relative(from, to)` on already-canonical absolute paths.
fn lexical_relative(from: &Path, to: &Path) -> Option<PathBuf> {
    let from_components: Vec<Component> = from.components().collect();
    let to_components: Vec<Component> = to.components().collect();
    let mut common = 0usize;
    while common < from_components.len()
        && common < to_components.len()
        && from_components[common] == to_components[common]
    {
        common += 1;
    }
    if common == 0 && !from_components.is_empty() && !to_components.is_empty() {
        let first_matches = matches!(
            (from_components.first(), to_components.first()),
            (Some(Component::RootDir), Some(Component::RootDir))
        );
        if !first_matches {
            return None;
        }
    }
    let mut result = PathBuf::new();
    for _ in common..from_components.len() {
        result.push("..");
    }
    for component in &to_components[common..] {
        result.push(component.as_os_str());
    }
    Some(result)
}
