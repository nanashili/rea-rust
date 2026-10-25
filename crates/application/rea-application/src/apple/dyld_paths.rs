//! Path semantics used while resolving dyld-style search paths.
//!
//! The tree is deliberately supplied by a caller.  This keeps resolution
//! independent from a filesystem and lets callers preserve their own evidence
//! and ownership rules around the image tree.

use std::collections::VecDeque;

use crate::apple::dylib_resolution::MachoSlice;

const MAX_SYMLINK_HOPS: usize = 32;

/// A directory entry in a caller-owned dylib tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TreeEntry {
    Directory,
    File,
    Symlink { target: String },
}

/// The read-only view needed by [`resolve_tree_path`].
pub trait TreeView {
    /// Return the entry at a root-relative path, or `None` when it is absent.
    fn entry(&self, path: &str) -> Option<TreeEntry>;
}

/// The result of resolving a root-relative path in a tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathLookup {
    File { path: String },
    Absent,
    Escapes,
    NotFile,
}

/// Resolve a root-relative path one component at a time.
///
/// Symlinks are followed inside the root, `..` applies to the resolved parent,
/// and an escape above the root or through an absolute link stops resolution.
pub fn resolve_tree_path<V: TreeView>(view: &V, input: &str) -> PathLookup {
    let mut pending = segments_of(input).into_iter().collect::<VecDeque<_>>();
    let mut resolved = Vec::new();
    let mut last = None;
    let mut symlink_hops = 0;

    while let Some(segment) = pending.pop_front() {
        if segment == "." {
            continue;
        }

        if segment == ".." {
            if resolved.pop().is_none() {
                return PathLookup::Escapes;
            }
            last = Some(TreeEntry::Directory);
            continue;
        }

        let path = resolved
            .iter()
            .chain(std::iter::once(&segment))
            .cloned()
            .collect::<Vec<_>>()
            .join("/");
        let Some(entry) = view.entry(&path) else {
            return PathLookup::Absent;
        };

        if let TreeEntry::Symlink { target } = &entry {
            symlink_hops += 1;
            if symlink_hops > MAX_SYMLINK_HOPS {
                return PathLookup::Absent;
            }
            if target.starts_with('/') {
                return PathLookup::Escapes;
            }
            prepend_segments(&mut pending, segments_of(target));
            continue;
        }

        if matches!(entry, TreeEntry::File) && !pending.is_empty() {
            return PathLookup::Absent;
        }

        resolved.push(segment);
        last = Some(entry);
    }

    match last {
        Some(TreeEntry::File) => PathLookup::File {
            path: resolved.join("/"),
        },
        _ => PathLookup::NotFile,
    }
}

fn prepend_segments(pending: &mut VecDeque<String>, segments: Vec<String>) {
    for segment in segments.into_iter().rev() {
        pending.push_front(segment);
    }
}

fn segments_of(path: &str) -> Vec<String> {
    let mut segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    // A trailing slash requires a directory, like a final dot component.
    if path.ends_with('/') {
        segments.push(".".to_owned());
    }

    segments
}

/// Return the directory portion of a slash-separated path.
pub fn directory_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(directory, _)| directory)
}

/// Join a directory and a relative remainder without introducing extra slashes.
pub fn join_path(directory: &str, rest: &str) -> String {
    match (directory.is_empty(), rest.is_empty()) {
        (true, _) => rest.to_owned(),
        (_, true) => directory.to_owned(),
        (false, false) => format!("{directory}/{rest}"),
    }
}

/// Select the first image slice that dyld can load for a process slice.
///
/// An x86_64h process accepts a generic x86_64 slice as a fallback.  arm64e
/// requires matching the CPU type and the subtype identity after removing
/// capability flags; those flags describe ABI features rather than a
/// different base architecture.
pub fn compatible_slice<'a>(
    slices: &'a [MachoSlice],
    process: &MachoSlice,
) -> Option<&'a MachoSlice> {
    let architectures: &[&str] = if process.architecture == "x86_64h" {
        &["x86_64h", "x86_64"]
    } else {
        &[process.architecture.as_str()]
    };

    architectures.iter().find_map(|architecture| {
        slices.iter().find(|slice| {
            slice.architecture == **architecture
                && (process.architecture != "arm64e"
                    || (slice.cpu_type == process.cpu_type
                        && cpu_subtype_base(slice.cpu_subtype)
                            == cpu_subtype_base(process.cpu_subtype)))
        })
    })
}

fn cpu_subtype_base(subtype: u32) -> u32 {
    subtype & 0x00ff_ffff
}

/// Context for expanding one dyld path prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpansionContext {
    pub owner_directory: String,
    pub executable: Option<String>,
}

/// The scope of an expanded dyld path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expansion {
    Target { path: String },
    Outside { path: String },
    Undetermined { path: String },
}

/// Expand `@executable_path` or `@loader_path` relative to an owning image.
pub fn expand_prefix(raw: &str, context: &ExpansionContext) -> Expansion {
    if let Some(rest) = raw.strip_prefix("@loader_path") {
        if rest.is_empty() {
            return Expansion::Target {
                path: context.owner_directory.clone(),
            };
        }
        if let Some(rest) = rest.strip_prefix('/') {
            return Expansion::Target {
                path: join_path(&context.owner_directory, rest),
            };
        }
    }

    if let Some(rest) = raw.strip_prefix("@executable_path") {
        if rest.is_empty() || rest.starts_with('/') {
            let Some(executable) = &context.executable else {
                return Expansion::Undetermined {
                    path: raw.to_owned(),
                };
            };
            let remainder = rest.strip_prefix('/').unwrap_or("");
            return Expansion::Target {
                path: join_path(directory_of(executable), remainder),
            };
        }
    }

    if raw.starts_with('/') {
        Expansion::Outside {
            path: raw.to_owned(),
        }
    } else {
        Expansion::Undetermined {
            path: raw.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        Expansion, ExpansionContext, PathLookup, TreeEntry, TreeView, directory_of, expand_prefix,
        join_path, resolve_tree_path,
    };

    struct Fixture {
        entries: BTreeMap<String, TreeEntry>,
    }

    impl TreeView for Fixture {
        fn entry(&self, path: &str) -> Option<TreeEntry> {
            self.entries.get(path).cloned()
        }
    }

    fn fixture(entries: &[(&str, TreeEntry)]) -> Fixture {
        Fixture {
            entries: entries
                .iter()
                .map(|(path, entry)| ((*path).to_owned(), entry.clone()))
                .collect(),
        }
    }

    #[test]
    fn resolves_symlinks_and_real_parent_components() {
        let view = fixture(&[
            ("Frameworks", TreeEntry::Directory),
            (
                "Frameworks/Current",
                TreeEntry::Symlink {
                    target: "V2".into(),
                },
            ),
            ("Frameworks/V2", TreeEntry::Directory),
            ("Frameworks/V2/lib.dylib", TreeEntry::File),
        ]);

        assert_eq!(
            resolve_tree_path(&view, "Frameworks/Current/../V2/lib.dylib"),
            PathLookup::File {
                path: "Frameworks/V2/lib.dylib".into()
            }
        );
    }

    #[test]
    fn distinguishes_absent_escape_and_non_file() {
        let view = fixture(&[("dir", TreeEntry::Directory), ("file", TreeEntry::File)]);

        assert_eq!(resolve_tree_path(&view, "missing"), PathLookup::Absent);
        assert_eq!(resolve_tree_path(&view, "../file"), PathLookup::Escapes);
        assert_eq!(resolve_tree_path(&view, "dir"), PathLookup::NotFile);
        assert_eq!(resolve_tree_path(&view, "file/child"), PathLookup::Absent);
    }

    #[test]
    fn trailing_slash_requires_a_directory() {
        let view = fixture(&[("dir", TreeEntry::Directory), ("file", TreeEntry::File)]);

        assert_eq!(resolve_tree_path(&view, "dir/"), PathLookup::NotFile);
        assert_eq!(resolve_tree_path(&view, "file/"), PathLookup::Absent);
    }

    #[test]
    fn expands_known_prefixes_and_classifies_unknown_paths() {
        let context = ExpansionContext {
            owner_directory: "Frameworks/A.framework".into(),
            executable: Some("App.app/MacOS/App".into()),
        };

        assert_eq!(
            expand_prefix("@loader_path/lib.dylib", &context),
            Expansion::Target {
                path: "Frameworks/A.framework/lib.dylib".into()
            }
        );
        assert_eq!(
            expand_prefix("@executable_path/../Frameworks", &context),
            Expansion::Target {
                path: "App.app/MacOS/../Frameworks".into()
            }
        );
        assert_eq!(
            expand_prefix("/usr/lib/lib.dylib", &context),
            Expansion::Outside {
                path: "/usr/lib/lib.dylib".into()
            }
        );
        assert_eq!(
            expand_prefix("relative/lib.dylib", &context),
            Expansion::Undetermined {
                path: "relative/lib.dylib".into()
            }
        );
    }

    #[test]
    fn prefix_names_must_match_the_complete_variable() {
        let context = ExpansionContext {
            owner_directory: "Frameworks".into(),
            executable: None,
        };

        assert_eq!(
            expand_prefix("@loader_path_suffix", &context),
            Expansion::Undetermined {
                path: "@loader_path_suffix".into()
            }
        );
        assert_eq!(
            expand_prefix("@executable_path_suffix", &context),
            Expansion::Undetermined {
                path: "@executable_path_suffix".into()
            }
        );
        assert_eq!(
            expand_prefix("@executable_path/lib.dylib", &context),
            Expansion::Undetermined {
                path: "@executable_path/lib.dylib".into()
            }
        );
    }

    #[test]
    fn path_helpers_match_dyld_join_rules() {
        assert_eq!(directory_of("App.app/MacOS/App"), "App.app/MacOS");
        assert_eq!(directory_of("App"), "");
        assert_eq!(join_path("", "rest"), "rest");
        assert_eq!(join_path("dir", ""), "dir");
        assert_eq!(join_path("dir", "rest"), "dir/rest");
    }
}
