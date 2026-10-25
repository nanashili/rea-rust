//! Exact package-private import-alias lookup.
//!
//! Node resolves `#` specifiers against the importer's enclosing package
//! `imports` map; this module owns the specifier and exact-key rules.
//! Condition, array and null target selection stay with the shared package
//! target machinery. Wildcard keys, recursive `#` targets and external
//! package targets remain explicit unknowns.
//!
//! Compatibility owner: `javascriptPackageImportAliases.ts`.
use serde_json::Value;

use super::syntax::js_own_keys;

/// How one `#` specifier participates in exact import-alias lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageImportSpecifier<'a> {
    Invalid,
    Pattern,
    Exact { key: &'a str },
}

/// Outcome of looking up one exact `#` key in a package `imports` value.
#[derive(Clone, Debug, PartialEq)]
pub enum PackageImportLookup<'a> {
    UndefinedMap,
    MissingKey {
        declared: Vec<&'a str>,
    },
    PatternUnresolved {
        declared: Vec<&'a str>,
    },
    Found {
        target: &'a Value,
        declared: Vec<&'a str>,
    },
}

/// How a selected string target is interpreted for package-private imports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageImportTargetKind {
    Relative,
    Invalid,
    Recursive,
    ExternalPackage,
}

/// Classify a `#` specifier before any package-scope walk. `#` and names
/// ending in `/` are invalid; wildcard expansion remains unsupported.
pub fn classify_package_import_specifier(specifier: &str) -> PackageImportSpecifier<'_> {
    if specifier == "#" || specifier.ends_with('/') {
        return PackageImportSpecifier::Invalid;
    }
    if specifier.contains('*') {
        return PackageImportSpecifier::Pattern;
    }
    PackageImportSpecifier::Exact { key: specifier }
}

/// True when an `imports` key is a pattern rather than an exact alias.
pub fn is_package_import_pattern_key(key: &str) -> bool {
    key.contains('*') || key.ends_with('/')
}

/// Look up one exact key. A miss stays pattern-unresolved when the map has
/// pattern keys rather than claiming the specifier is undefined. `imports`
/// is `None` when the property is absent.
pub fn lookup_exact_package_import<'a>(
    imports: Option<&'a Value>,
    key: &str,
) -> PackageImportLookup<'a> {
    let Some(Value::Object(map)) = imports else {
        return PackageImportLookup::UndefinedMap;
    };
    let declared = js_own_keys(map);
    if let Some(target) = map.get(key)
        && !is_package_import_pattern_key(key)
    {
        return PackageImportLookup::Found { target, declared };
    }
    if declared
        .iter()
        .any(|key| is_package_import_pattern_key(key))
    {
        PackageImportLookup::PatternUnresolved { declared }
    } else {
        PackageImportLookup::MissingKey { declared }
    }
}

/// Classify a selected string import target. Only package-local `./` paths
/// resolve as files; parent-relative, absolute and URL targets are invalid.
pub fn classify_package_import_target(target: &str) -> PackageImportTargetKind {
    if target.starts_with("./") {
        return PackageImportTargetKind::Relative;
    }
    if target.starts_with("../") || target.starts_with('/') || super::web_url::can_parse(target) {
        return PackageImportTargetKind::Invalid;
    }
    if target.starts_with('#') {
        return PackageImportTargetKind::Recursive;
    }
    PackageImportTargetKind::ExternalPackage
}
