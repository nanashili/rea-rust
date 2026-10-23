//! Resolve an Apple application bundle to its declared executable.
//!
//! This boundary reads only `Info.plist` metadata and resolves the resulting
//! path. It does not execute the bundle or infer an executable from directory
//! contents when the declaration is absent.

use rea_rust_analysis::plist;
use std::{
    fs,
    path::{Path, PathBuf},
};

const MACOS_PLIST: &[&str] = &["Contents", "Info.plist"];
const MACOS_PROGRAMS: &[&str] = &["Contents", "MacOS"];
const IOS_PLIST: &[&str] = &["Info.plist"];
const IOS_PROGRAMS: &[&str] = &[];

#[derive(Clone, Copy)]
struct BundleLayout {
    plist: &'static [&'static str],
    programs: &'static [&'static str],
    label: &'static str,
}

const LAYOUTS: &[BundleLayout] = &[
    BundleLayout {
        plist: MACOS_PLIST,
        programs: MACOS_PROGRAMS,
        label: "Contents/MacOS",
    },
    BundleLayout {
        plist: IOS_PLIST,
        programs: IOS_PROGRAMS,
        label: "the bundle root",
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedAppBundle {
    pub executable: PathBuf,
    pub info_plist: PathBuf,
}

/// Resolve one caller-selected app bundle using its `CFBundleExecutable`.
pub fn resolve(path: &Path) -> Result<ResolvedAppBundle, String> {
    if let Some(layout) = present_layout(path)? {
        return resolve_layout(path, layout);
    }

    let Some(wrapped) = single_wrapped_app(path)? else {
        return Err(missing_layout(path));
    };
    let Some(layout) = present_layout(&wrapped)? else {
        return Err(missing_layout(path));
    };
    resolve_layout(&wrapped, layout)
}

fn present_layout(bundle: &Path) -> Result<Option<BundleLayout>, String> {
    for layout in LAYOUTS {
        let plist = join_components(bundle, layout.plist);
        match fs::metadata(&plist) {
            Ok(metadata) if metadata.is_file() => return Ok(Some(*layout)),
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_reason("inspecting app Info.plist", &plist, error)),
        }
    }
    Ok(None)
}

fn single_wrapped_app(bundle: &Path) -> Result<Option<PathBuf>, String> {
    let wrapper = bundle.join("Wrapper");
    let metadata = match fs::symlink_metadata(&wrapper) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_reason("inspecting app Wrapper", &wrapper, error)),
    };
    if !metadata.is_dir() {
        return Ok(None);
    }

    let mut candidate = None;
    for entry in
        fs::read_dir(&wrapper).map_err(|error| io_reason("listing app Wrapper", &wrapper, error))?
    {
        let entry = entry.map_err(|error| io_reason("reading app Wrapper", &wrapper, error))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.to_ascii_lowercase().ends_with(".app") {
            continue;
        }
        let entry_type = entry
            .file_type()
            .map_err(|error| io_reason("inspecting wrapped app", &entry.path(), error))?;
        if !entry_type.is_dir() {
            continue;
        }
        if candidate.is_some() {
            return Ok(None);
        }
        candidate = Some(entry.path());
    }
    Ok(candidate)
}

fn resolve_layout(bundle: &Path, layout: BundleLayout) -> Result<ResolvedAppBundle, String> {
    let plist_path = join_components(bundle, layout.plist);
    let bytes = fs::read(&plist_path)
        .map_err(|error| io_reason("reading app Info.plist", &plist_path, error))?;
    let report = plist::read(&bytes, plist_path.to_string_lossy().into_owned())
        .map_err(|error| format!("app Info.plist is malformed or unsupported: {error}"))?;
    let name = report.bundle.executable.ok_or_else(|| {
        format!(
            "app Info.plist lacks CFBundleExecutable: {}",
            plist_path.display()
        )
    })?;
    if !is_safe_executable_name(&name) {
        return Err("app has an unsafe CFBundleExecutable".into());
    }

    let programs = join_components(bundle, layout.programs);
    let executable = programs.join(&name);
    let canonical_bundle = fs::canonicalize(bundle)
        .map_err(|error| io_reason("resolving app bundle", bundle, error))?;
    let canonical_programs = fs::canonicalize(&programs)
        .map_err(|error| io_reason("resolving app program directory", &programs, error))?;
    if !canonical_programs.starts_with(&canonical_bundle) {
        return Err(format!("app program directory leaves {}", layout.label));
    }
    let canonical_executable = fs::canonicalize(&executable)
        .map_err(|error| io_reason("resolving app program file", &executable, error))?;
    if !canonical_executable.starts_with(&canonical_programs) {
        return Err(format!("app program file leaves {}", layout.label));
    }

    Ok(ResolvedAppBundle {
        executable: canonical_executable,
        info_plist: plist_path,
    })
}

fn join_components(root: &Path, components: &[&str]) -> PathBuf {
    components
        .iter()
        .fold(root.to_path_buf(), |path, component| path.join(component))
}

fn is_safe_executable_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|character| matches!(character, '/' | '\\' | '\0'))
}

fn missing_layout(path: &Path) -> String {
    format!(
        "app Info.plist is missing or no supported bundle layout was found: {}",
        path.display()
    )
}

fn io_reason(stage: &str, path: &Path, error: std::io::Error) -> String {
    format!("could not {stage} {}: {error}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn resolves_macos_layout_from_plist() {
        let root = tempdir().unwrap();
        let bundle = root.path().join("Example.app");
        let programs = bundle.join("Contents/MacOS");
        fs::create_dir_all(&programs).unwrap();
        fs::write(bundle.join("Contents/Info.plist"), xml_plist("Example")).unwrap();
        fs::write(programs.join("Example"), b"mach-o").unwrap();

        let resolved = resolve(&bundle).unwrap();

        assert_eq!(
            resolved.executable,
            fs::canonicalize(programs.join("Example")).unwrap()
        );
        assert_eq!(resolved.info_plist, bundle.join("Contents/Info.plist"));
    }

    #[test]
    fn rejects_executable_path_escape() {
        let root = tempdir().unwrap();
        let outside = root.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        let bundle = root.path().join("Example.app");
        fs::create_dir_all(&bundle).unwrap();
        fs::write(bundle.join("Info.plist"), xml_plist("../outside")).unwrap();

        let error = resolve(&bundle).unwrap_err();

        assert_eq!(error, "app has an unsafe CFBundleExecutable");
    }

    #[test]
    fn resolves_single_wrapper_app() {
        let root = tempdir().unwrap();
        let bundle = root.path().join("Example.app");
        let wrapped = bundle.join("Wrapper/Payload.app");
        let programs = wrapped.join("Contents/MacOS");
        fs::create_dir_all(&programs).unwrap();
        fs::write(wrapped.join("Contents/Info.plist"), xml_plist("Payload")).unwrap();
        fs::write(programs.join("Payload"), b"mach-o").unwrap();

        let resolved = resolve(&bundle).unwrap();

        assert_eq!(
            resolved.executable,
            fs::canonicalize(programs.join("Payload")).unwrap()
        );
    }

    fn xml_plist(executable: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleExecutable</key><string>{executable}</string></dict></plist>"
        )
    }
}
