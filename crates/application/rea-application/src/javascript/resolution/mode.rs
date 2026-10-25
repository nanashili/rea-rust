//! Loader-mode evidence for source-level module references and relative
//! specifier syntax.
//!
//! Compatibility owners: `javascriptModuleResolutionMode.ts` and
//! `javascriptModuleSpecifier.ts`.
use serde::{Deserialize, Serialize};

use super::syntax::posix_extname;

/// Loader evidence retained for a source-level module reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleResolutionMode {
    Import,
    Require,
    CompilerDependent,
}

impl ModuleResolutionMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Require => "require",
            Self::CompilerDependent => "compiler-dependent",
        }
    }
}

/// Source syntax that owns a module reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleReferenceKind {
    StaticImport,
    DynamicImport,
    Require,
}

/// `moduleResolutionModeForJavaScriptReference`: derive mode only when
/// syntax or an explicit source format owns it.
pub fn module_resolution_mode_for_reference(
    source_path: &str,
    reference_kind: ModuleReferenceKind,
    explicit_mode: Option<ModuleResolutionMode>,
) -> ModuleResolutionMode {
    if let Some(mode) = explicit_mode {
        return mode;
    }
    match reference_kind {
        ModuleReferenceKind::Require => return ModuleResolutionMode::Require,
        ModuleReferenceKind::DynamicImport => return ModuleResolutionMode::Import,
        ModuleReferenceKind::StaticImport => {}
    }
    // `String#toLowerCase` is full Unicode lowercasing; the compared
    // extensions are ASCII, and no non-ASCII character lowercases to ASCII
    // except U+212A KELVIN SIGN (to `k`), which no compared extension holds.
    match posix_extname(source_path).to_lowercase().as_str() {
        ".cjs" | ".cts" => ModuleResolutionMode::Require,
        ".mts" => ModuleResolutionMode::Import,
        ".ts" | ".tsx" => ModuleResolutionMode::CompilerDependent,
        _ => ModuleResolutionMode::Import,
    }
}

/// `isRelativeJavaScriptModuleSpecifier`: relative module syntax differs
/// from an arbitrary dot-prefixed filename.
pub fn is_relative_module_specifier(value: &str) -> bool {
    value == "." || value == ".." || value.starts_with("./") || value.starts_with("../")
}
