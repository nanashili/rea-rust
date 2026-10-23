//! Bounded TypeScript source candidates for explicit emitted JavaScript paths.
//!
//! This module projects a runtime filename into possible TypeScript source
//! identities. It does not inspect the filesystem, resolve directories or
//! packages, or claim that any candidate exists. Callers retain loader
//! precedence and source-map evidence separately.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateKind {
    Implementation,
    Declaration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    pub path: String,
    pub kind: CandidateKind,
}

const EMITTED_SUFFIXES: &[(&str, &[(&str, CandidateKind)])] = &[
    (
        ".js",
        &[
            (".ts", CandidateKind::Implementation),
            (".tsx", CandidateKind::Implementation),
            (".d.ts", CandidateKind::Declaration),
        ],
    ),
    (
        ".mjs",
        &[
            (".mts", CandidateKind::Implementation),
            (".d.mts", CandidateKind::Declaration),
        ],
    ),
    (
        ".cjs",
        &[
            (".cts", CandidateKind::Implementation),
            (".d.cts", CandidateKind::Declaration),
        ],
    ),
    (
        ".jsx",
        &[
            (".tsx", CandidateKind::Implementation),
            (".d.ts", CandidateKind::Declaration),
        ],
    ),
];

/// Return TypeScript counterparts for an explicit emitted filename.
///
/// The source path gates the projection to TypeScript-family imports. The
/// emitted suffix is removed by byte length so a basename such as `.js` is
/// handled without relying on a platform path extension parser.
pub fn candidates(source_path: &str, emitted_path: &str) -> Vec<Candidate> {
    if !is_typescript_source_path(source_path) {
        return Vec::new();
    }

    let Some((emitted_suffix, source_suffixes)) = EMITTED_SUFFIXES
        .iter()
        .find(|(suffix, _)| emitted_path.ends_with(suffix))
    else {
        return Vec::new();
    };

    let stem_end = emitted_path.len() - emitted_suffix.len();
    let stem = &emitted_path[..stem_end];
    source_suffixes
        .iter()
        .map(|(suffix, kind)| Candidate {
            path: format!("{}{}", stem, suffix),
            kind: *kind,
        })
        .collect()
}

fn is_typescript_source_path(path: &str) -> bool {
    [".ts", ".tsx", ".mts", ".cts"]
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::{CandidateKind, candidates};

    #[test]
    fn projects_node_next_suffixes_in_order() {
        assert_eq!(
            candidates("src/index.ts", "dist/index.js"),
            vec![
                super::Candidate {
                    path: "dist/index.ts".into(),
                    kind: CandidateKind::Implementation,
                },
                super::Candidate {
                    path: "dist/index.tsx".into(),
                    kind: CandidateKind::Implementation,
                },
                super::Candidate {
                    path: "dist/index.d.ts".into(),
                    kind: CandidateKind::Declaration,
                },
            ]
        );
        assert_eq!(
            candidates("src/index.mts", "dist/index.mjs"),
            vec![
                super::Candidate {
                    path: "dist/index.mts".into(),
                    kind: CandidateKind::Implementation,
                },
                super::Candidate {
                    path: "dist/index.d.mts".into(),
                    kind: CandidateKind::Declaration,
                },
            ]
        );
    }

    #[test]
    fn preserves_dotfile_stems_and_rejects_non_typescript_sources() {
        assert_eq!(
            candidates(".config.ts", ".js"),
            vec![
                super::Candidate {
                    path: ".ts".into(),
                    kind: CandidateKind::Implementation,
                },
                super::Candidate {
                    path: ".tsx".into(),
                    kind: CandidateKind::Implementation,
                },
                super::Candidate {
                    path: ".d.ts".into(),
                    kind: CandidateKind::Declaration,
                },
            ]
        );
        assert!(candidates("src/index.js", "dist/index.js").is_empty());
        assert!(candidates("src/index.ts", "dist/index.json").is_empty());
    }
}
