//! Parser mode for one source path.
//!
//! Single owner for the path rules of `parserPluginsForPath`,
//! `runtimeSourceTypeForPath` and `isExplicitModuleSourcePath` in
//! `src/domain/javascript/javascriptSourceParser.ts`. All suffix checks are
//! ASCII case-insensitive, matching the `/iu` regular expressions there.

use oxc_span::SourceType;

/// Grammar selected by the path (Babel plugin set equivalent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JavaScriptGrammar {
    /// `.js/.jsx/.mjs/.cjs`: JavaScript with JSX, no TypeScript.
    JavaScriptJsx,
    /// `.ts/.cts/.mts`: TypeScript without JSX.
    TypeScript,
    /// `.d.ts/.d.mts/.d.cts`: ambient TypeScript declarations, no JSX.
    TypeScriptDeclaration,
    /// `.tsx` and unknown paths: TypeScript with JSX.
    TypeScriptJsx,
}

/// Runtime source type selected by the path (`runtimeSourceTypeForPath`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathSourceType {
    /// `.cjs`.
    CommonJs,
    /// `.mjs/.mts` (including `.d.mts`).
    Module,
    /// Every other path, including an absent path.
    Unambiguous,
}

/// Complete parser mode derived from an optional source path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParserMode {
    pub grammar: JavaScriptGrammar,
    pub source_type: PathSourceType,
    /// Babel `disallowAmbiguousJSXLike` (`.mts`). oxc has no such option; the
    /// TypeScript grammar without JSX already rejects JSX, so this is recorded
    /// for the differential report rather than forwarded.
    pub disallow_ambiguous_jsx_like: bool,
}

fn ends_with_ignore_ascii_case(path: &str, suffix: &str) -> bool {
    path.len() >= suffix.len()
        && path.is_char_boundary(path.len() - suffix.len())
        && path[path.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn ends_with_any(path: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().any(|suffix| ends_with_ignore_ascii_case(path, suffix))
}

/// `.mjs` and `.mts` explicitly select module mode.
pub fn is_explicit_module_source_path(path: Option<&str>) -> bool {
    ends_with_any(path.unwrap_or(""), &[".mjs", ".mts"])
}

impl ParserMode {
    /// Port of `parserPluginsForPath` plus `runtimeSourceTypeForPath`.
    pub fn for_path(path: Option<&str>) -> Self {
        let text = path.unwrap_or("");
        let grammar = if ends_with_any(text, &[".js", ".jsx", ".mjs", ".cjs"]) {
            JavaScriptGrammar::JavaScriptJsx
        } else if ends_with_any(text, &[".d.ts", ".d.mts", ".d.cts"]) {
            JavaScriptGrammar::TypeScriptDeclaration
        } else if ends_with_any(text, &[".ts", ".cts", ".mts"]) {
            JavaScriptGrammar::TypeScript
        } else {
            JavaScriptGrammar::TypeScriptJsx
        };
        let source_type = if ends_with_ignore_ascii_case(text, ".cjs") {
            PathSourceType::CommonJs
        } else if is_explicit_module_source_path(path) {
            PathSourceType::Module
        } else {
            PathSourceType::Unambiguous
        };
        Self {
            grammar,
            source_type,
            disallow_ambiguous_jsx_like: grammar != JavaScriptGrammar::JavaScriptJsx
                && ends_with_ignore_ascii_case(text, ".mts"),
        }
    }

    /// oxc source type for the grammar with the given module kind applied.
    pub(super) fn oxc_source_type(self, kind: OxcModuleKind) -> SourceType {
        let base = match self.grammar {
            JavaScriptGrammar::JavaScriptJsx => SourceType::jsx(),
            JavaScriptGrammar::TypeScript => SourceType::ts(),
            JavaScriptGrammar::TypeScriptDeclaration => SourceType::d_ts(),
            JavaScriptGrammar::TypeScriptJsx => SourceType::tsx(),
        };
        match kind {
            OxcModuleKind::Module => base.with_module(true),
            OxcModuleKind::Unambiguous => base.with_unambiguous(true),
            OxcModuleKind::CommonJs => base.with_commonjs(true),
        }
    }
}

/// Module kind requested from oxc for one parse attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OxcModuleKind {
    Module,
    Unambiguous,
    CommonJs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirrors_parser_plugins_for_path() {
        let cases = [
            (None, JavaScriptGrammar::TypeScriptJsx, PathSourceType::Unambiguous),
            (Some("a.JS"), JavaScriptGrammar::JavaScriptJsx, PathSourceType::Unambiguous),
            (Some("a.cjs"), JavaScriptGrammar::JavaScriptJsx, PathSourceType::CommonJs),
            (Some("a.mjs"), JavaScriptGrammar::JavaScriptJsx, PathSourceType::Module),
            (Some("a.ts"), JavaScriptGrammar::TypeScript, PathSourceType::Unambiguous),
            (Some("a.cts"), JavaScriptGrammar::TypeScript, PathSourceType::Unambiguous),
            (Some("a.mts"), JavaScriptGrammar::TypeScript, PathSourceType::Module),
            (Some("a.d.ts"), JavaScriptGrammar::TypeScriptDeclaration, PathSourceType::Unambiguous),
            (Some("a.d.mts"), JavaScriptGrammar::TypeScriptDeclaration, PathSourceType::Module),
            (Some("a.tsx"), JavaScriptGrammar::TypeScriptJsx, PathSourceType::Unambiguous),
            (Some("bundle.vue"), JavaScriptGrammar::TypeScriptJsx, PathSourceType::Unambiguous),
        ];
        for (path, grammar, source_type) in cases {
            let mode = ParserMode::for_path(path);
            assert_eq!((mode.grammar, mode.source_type), (grammar, source_type), "{path:?}");
        }
        assert!(ParserMode::for_path(Some("a.d.mts")).disallow_ambiguous_jsx_like);
        assert!(!ParserMode::for_path(Some("a.mjs")).disallow_ambiguous_jsx_like);
    }
}
