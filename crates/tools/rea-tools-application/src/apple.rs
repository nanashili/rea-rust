//! Execution-free Apple application inventory projection.
//!
//! Compatibility owners: `src/domain/apple/appleApplication.ts`,
//! `src/domain/apple/appleBundleAnatomy.ts` and
//! `src/application/apple/AppleApplicationService.ts`.
use crate::inventory::ParsedInventorySet;
use crate::projection::{
    self, CandidateGroup, Entry, InventoryProjection, ends_with_ci, format_of, last_segment,
    path_of,
};
use crate::rejection::Rejection;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "project_apple_application_graph";

pub const PROJECTION: InventoryProjection = InventoryProjection {
    operation: OPERATION,
    predicate_type: "rea.apple-application-graph",
    provider: ("rea-apple-application", "REA Apple application workflows"),
    fixed_subject_format: None,
    project,
};

const ROOT_FORMATS: [&str; 4] = ["ipa", "directory", "zip", "dmg"];
const BUNDLE_EXTENSIONS: [&str; 10] = [
    ".app",
    ".appex",
    ".xpc",
    ".framework",
    ".systemextension",
    ".dext",
    ".bundle",
    ".plugin",
    ".qlgenerator",
    ".mdimporter",
];

/// `projectAppleApplication`.
fn project(parsed: &ParsedInventorySet) -> Result<Value, Rejection> {
    let inventory = &parsed.inventory;
    let root_format = inventory.root_format();
    if !ROOT_FORMATS.contains(&root_format) {
        return Err(Rejection::type_error(format!(
            "Apple application projection requires IPA, directory, ZIP, or DMG inventory Evidence (got {root_format})"
        )));
    }
    let entries = projection::entries(inventory)?;
    let inventoried = projection::file_components(&entries);
    let subject_name = parsed.evidence[0]["subject"]["name"]
        .as_str()
        .unwrap_or_default();
    let tree = Tree::index(&entries);
    let roots = application_roots(&tree, subject_name, root_format);
    let bundles = detect_bundles(&tree, &roots);
    let (all, unattributed) = attribute(inventoried, &roots, root_format);
    let unavailable_files: Vec<Value> = entries
        .iter()
        .filter(|entry| matches!(entry.kind.as_str(), "file" | "slice"))
        .filter_map(|entry| entry.unavailable.clone())
        .collect();
    let (unavailable, unavailable_unattributed) = attribute(unavailable_files, &roots, root_format);
    let components = classify(&entries, &all, &roots);
    let runtime_families = runtime_families(&all);
    let native = deduplicate(
        components["executables"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(
                components["native_libraries"]
                    .as_array()
                    .into_iter()
                    .flatten(),
            )
            .cloned()
            .collect(),
    );
    let scripts: Vec<Value> = components["javascript"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let (bridges, bridge_coverage) = bridge_candidates(&scripts, &native, &roots);
    let uninventoried_image = root_format == "dmg" && inventory.occurrences.len() == 1;
    let inventory_complete = inventory.has_complete_coverage("container-entries");
    let complete = inventory_complete && !uninventoried_image;
    let mut limitations = inventory.limitations.clone();
    limitations.extend(projection_limitations(&LimitationFacts {
        complete: inventory_complete,
        uninventoried_image,
        roots: &roots,
        bundles: &bundles,
        sidecars: entries.iter().any(|entry| is_sidecar(&entry.path)),
        symlinks: entries.iter().any(|entry| entry.kind == "symlink"),
        unattributed: unattributed + unavailable_unattributed,
        unavailable: !unavailable.is_empty(),
        bridge_coverage: &bridge_coverage,
    }));
    let mut symlinks: Vec<String> = entries
        .iter()
        .filter(|entry| entry.kind == "symlink")
        .map(|entry| entry.path.clone())
        .collect();
    symlinks.sort();
    let status = if complete && unavailable.is_empty() && bridge_coverage["status"] == "complete" {
        "complete-within-inventory"
    } else {
        "partial"
    };
    let result = json!({
        "root_sha256": inventory.root_sha256(),
        "root_format": root_format,
        "platforms": platforms(&bundles),
        "source_evidence_ids": projection::source_ids(parsed),
        "application_roots": roots,
        "bundles": bundles,
        "components": components,
        "unavailable_components": unavailable,
        "symlinks": symlinks,
        "runtime_families": runtime_families,
        "bridge_candidates": bridges,
        "bridge_candidate_coverage": bridge_coverage,
        "coverage": { "status": status, "inventory_complete": inventory.complete },
        "limitations": limitations,
    });
    projection::identified(result, "aap", "Apple application projection")
}

/// AppleDouble metadata written beside archived files (`._name`, `__MACOSX/`).
fn is_sidecar(path: &str) -> bool {
    path.split('/').any(|segment| segment == "__MACOSX") || last_segment(path).starts_with("._")
}

fn is_within(path: &str, root: &str) -> bool {
    root == "."
        || path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// English case fold used only for Apple's fixed anatomy vocabulary.
fn anatomy_name_is(actual: &str, expected: &str) -> bool {
    actual.to_lowercase() == expected.to_lowercase()
}

/// Directory entry that folds to one vocabulary word; the exact spelling wins.
fn anatomy_child<'a>(names: impl Iterator<Item = &'a String>, expected: &str) -> Option<&'a str> {
    let mut exact = None;
    let mut folded: Option<&str> = None;
    for name in names {
        if name == expected {
            exact = Some(name.as_str());
        } else if anatomy_name_is(name, expected)
            && folded.is_none_or(|current| name.as_str() < current)
        {
            folded = Some(name.as_str());
        }
    }
    exact.or(folded)
}

/// Whether `path`'s tail matches anatomy vocabulary; `*` matches one segment.
fn anatomy_tail_matches(path: &str, expected: &[&str]) -> bool {
    let actual: Vec<&str> = path.split('/').collect();
    if actual.len() < expected.len() {
        return false;
    }
    let tail = &actual[actual.len() - expected.len()..];
    expected.iter().zip(tail).all(|(name, segment)| {
        !segment.is_empty() && (*name == "*" || anatomy_name_is(segment, name))
    })
}

fn is_mach_o_format(format: &str) -> bool {
    matches!(format, "mach-o" | "mach-o-universal")
}

/// Directory identity kept apart from authenticated file content.
struct Tree {
    directories: BTreeMap<String, BTreeSet<String>>,
    files: BTreeMap<String, BTreeMap<String, Value>>,
}

impl Tree {
    fn index(entries: &[Entry]) -> Self {
        let mut directories: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut files: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
        for entry in entries {
            if is_sidecar(&entry.path) {
                continue;
            }
            let segments: Vec<&str> = entry.path.split('/').collect();
            let mut parent = String::new();
            for (index, segment) in segments.iter().enumerate() {
                let leaf = index == segments.len() - 1;
                if !leaf || entry.kind == "directory" {
                    directories
                        .entry(parent.clone())
                        .or_default()
                        .insert((*segment).to_owned());
                } else if entry.kind == "file"
                    && let Some(component) = &entry.component
                {
                    files
                        .entry(parent.clone())
                        .or_default()
                        .insert((*segment).to_owned(), component.clone());
                }
                parent = join(&parent, segment);
            }
        }
        Self { directories, files }
    }

    fn directory_paths(&self) -> Vec<String> {
        self.directories
            .iter()
            .flat_map(|(parent, names)| names.iter().map(move |name| join(parent, name)))
            .collect()
    }

    fn named_directory(&self, directory: &str, expected: &str) -> Option<String> {
        let names = self.directories.get(directory)?;
        anatomy_child(names.iter(), expected).map(|name| join(directory, name))
    }

    fn named_file(&self, directory: &str, expected: &str) -> Option<String> {
        let names = self.files.get(directory)?;
        anatomy_child(names.keys(), expected).map(|name| join(directory, name))
    }

    /// Files directly inside one directory, by path.
    fn direct_files(&self, directory: &str) -> Vec<&Value> {
        let mut files: Vec<&Value> = self
            .files
            .get(directory)
            .map(|files| files.values().collect())
            .unwrap_or_default();
        files.sort_by(|left, right| path_of(left).cmp(path_of(right)));
        files
    }
}

fn join(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_owned()
    } else {
        format!("{directory}/{name}")
    }
}

fn directory_of(bundle: &str) -> &str {
    if bundle == "." { "" } else { bundle }
}

/// Outermost iOS (`Payload/X.app`) and macOS (`X.app/Contents/…`) roots.
fn application_roots(tree: &Tree, subject_name: &str, subject_format: &str) -> Vec<String> {
    if subject_format == "directory" && ends_with_ci(subject_name, ".app") {
        return vec![".".to_owned()];
    }
    let mut found = BTreeSet::new();
    for path in tree.directory_paths() {
        let segments: Vec<&str> = path.split('/').collect();
        if anatomy_name_is(segments[0], "Payload")
            && let Some(app) = segments.get(1)
            && ends_with_ci(app, ".app")
        {
            found.insert(format!("{}/{app}", segments[0]));
            continue;
        }
        let index = segments.iter().enumerate().position(|(position, segment)| {
            ends_with_ci(segment, ".app")
                && anatomy_name_is(
                    segments.get(position + 1).copied().unwrap_or_default(),
                    "Contents",
                )
        });
        if let Some(index) = index {
            found.insert(segments[..=index].join("/"));
        }
    }
    let roots: Vec<String> = found.into_iter().collect();
    roots
        .iter()
        .filter(|root| {
            !roots
                .iter()
                .any(|other| other != *root && is_within(root, other))
        })
        .cloned()
        .collect()
}

fn detect_bundles(tree: &Tree, roots: &[String]) -> Vec<Value> {
    let mut paths: BTreeSet<String> = roots.iter().cloned().collect();
    for path in tree.directory_paths() {
        let name = last_segment(&path);
        if BUNDLE_EXTENSIONS
            .iter()
            .any(|extension| ends_with_ci(name, extension))
            && roots.iter().any(|root| is_within(&path, root))
        {
            paths.insert(path);
        }
    }
    paths
        .iter()
        .map(|path| {
            let layout = bundle_layout(path, tree);
            json!({
                "path": path,
                "parent_path": enclosing_bundle(path, &paths),
                "layout": layout,
                "role": if roots.contains(path) { "application" } else { bundle_role(path) },
                "role_basis": "path-convention",
                "info_plist_path": info_plist_path(path, layout, tree),
                "executable_candidates": executable_candidates(path, layout, tree),
                "signing_paths": signing_paths(path, layout, tree),
            })
        })
        .collect()
}

fn enclosing_bundle(path: &str, bundles: &BTreeSet<String>) -> Option<String> {
    if path == "." {
        return None;
    }
    let segments: Vec<&str> = path.split('/').collect();
    for length in (1..segments.len()).rev() {
        let candidate = segments[..length].join("/");
        if bundles.contains(&candidate) {
            return Some(candidate);
        }
    }
    bundles.contains(".").then(|| ".".to_owned())
}

fn bundle_layout(bundle: &str, tree: &Tree) -> &'static str {
    let directory = directory_of(bundle);
    if tree.named_directory(directory, "Contents").is_some() {
        "macos-deep"
    } else if tree.named_directory(directory, "Versions").is_some() {
        "versioned-framework"
    } else {
        "shallow"
    }
}

fn bundle_role(bundle: &str) -> &'static str {
    let segments: Vec<&str> = bundle.split('/').collect();
    let name = segments.last().copied().unwrap_or_default().to_lowercase();
    let container = if segments.len() >= 2 {
        segments[segments.len() - 2]
    } else {
        ""
    };
    let grandparent = if segments.len() >= 3 {
        segments[segments.len() - 3]
    } else {
        ""
    };
    if name.ends_with(".appex") {
        return "app-extension";
    }
    if name.ends_with(".xpc") {
        return "xpc-service";
    }
    if name.ends_with(".framework") {
        return "framework";
    }
    if name.ends_with(".systemextension") {
        return "system-extension";
    }
    if name.ends_with(".dext") {
        return "driver-extension";
    }
    if name.ends_with(".bundle") {
        if anatomy_name_is(container, "PlugIns") {
            return "plug-in";
        }
        return if anatomy_name_is(container, "Resources") {
            "resource-bundle"
        } else {
            "bundle"
        };
    }
    if !name.ends_with(".app") {
        return "plug-in";
    }
    if anatomy_name_is(container, "LoginItems") && anatomy_name_is(grandparent, "Library") {
        return "login-item";
    }
    if anatomy_name_is(container, "Helpers") {
        return "helper-application";
    }
    "nested-application"
}

/// Content directories; `Versions/Current` is a symlink outside the inventory.
fn content_directories(bundle: &str, layout: &str, tree: &Tree) -> Vec<String> {
    let directory = directory_of(bundle);
    match layout {
        "macos-deep" => tree
            .named_directory(directory, "Contents")
            .into_iter()
            .collect(),
        "shallow" => vec![directory.to_owned()],
        _ => {
            let Some(versions) = tree.named_directory(directory, "Versions") else {
                return Vec::new();
            };
            let mut found: Vec<String> = tree
                .directories
                .get(&versions)
                .into_iter()
                .flatten()
                .filter(|version| !anatomy_name_is(version, "Current"))
                .map(|version| join(&versions, version))
                .collect();
            found.sort();
            found
        }
    }
}

fn info_plist_path(bundle: &str, layout: &str, tree: &Tree) -> Option<String> {
    let directories = content_directories(bundle, layout, tree);
    if directories.len() != 1 {
        return None;
    }
    let directory = &directories[0];
    let parent = if layout == "versioned-framework" {
        tree.named_directory(directory, "Resources")?
    } else {
        directory.clone()
    };
    tree.named_file(&parent, "Info.plist")
}

fn executable_candidates(bundle: &str, layout: &str, tree: &Tree) -> Vec<String> {
    content_directories(bundle, layout, tree)
        .iter()
        .flat_map(|directory| {
            let executable_directory = if layout == "macos-deep" {
                tree.named_directory(directory, "MacOS")
            } else {
                Some(directory.clone())
            };
            executable_directory
                .map(|directory| tree.direct_files(&directory))
                .unwrap_or_default()
        })
        .filter(|component| is_mach_o_format(format_of(component)))
        .map(|component| path_of(component).to_owned())
        .collect()
}

fn signing_paths(bundle: &str, layout: &str, tree: &Tree) -> Vec<String> {
    let mut paths: Vec<String> = content_directories(bundle, layout, tree)
        .iter()
        .flat_map(|directory| {
            [
                tree.named_directory(directory, "_CodeSignature")
                    .and_then(|signature| tree.named_file(&signature, "CodeResources")),
                tree.named_file(directory, "embedded.provisionprofile"),
                tree.named_file(directory, "embedded.mobileprovision"),
            ]
        })
        .flatten()
        .collect();
    paths.sort();
    paths
}

/// Platforms of application roots whose layout was observed, not assumed.
fn platforms(bundles: &[Value]) -> Vec<&'static str> {
    let mut found = BTreeSet::new();
    for bundle in bundles {
        if bundle["role"] != "application" {
            continue;
        }
        if bundle["layout"] == "macos-deep" {
            found.insert("macos");
        } else if bundle["layout"] == "shallow" && !bundle["info_plist_path"].is_null() {
            found.insert("ios");
        }
    }
    found.into_iter().collect()
}

/// `attributeComponents`: sidecars are never components; non-IPA roots keep
/// only components inside an application root.
fn attribute(inventoried: Vec<Value>, roots: &[String], root_format: &str) -> (Vec<Value>, usize) {
    let visible: Vec<Value> = inventoried
        .into_iter()
        .filter(|component| !is_sidecar(path_of(component)))
        .collect();
    if root_format == "ipa" {
        return (visible, 0);
    }
    let total = visible.len();
    let all: Vec<Value> = visible
        .into_iter()
        .filter(|component| roots.iter().any(|root| is_within(path_of(component), root)))
        .collect();
    let unattributed = total - all.len();
    (all, unattributed)
}

fn is_native_library(path: &str) -> bool {
    ends_with_ci(path, ".dylib") || ends_with_ci(path, ".so")
}

fn launchd_domain(path: &str) -> Option<&'static str> {
    if anatomy_tail_matches(path, &["Contents", "Library", "LaunchAgents", "*"]) {
        Some("agent")
    } else if anatomy_tail_matches(path, &["Contents", "Library", "LaunchDaemons", "*"]) {
        Some("daemon")
    } else {
        None
    }
}

fn classify(entries: &[Entry], all: &[Value], roots: &[String]) -> Value {
    let within_app = |path: &str| roots.iter().any(|root| is_within(path, root));
    let matching = |predicate: &dyn Fn(&str) -> bool| -> Vec<Value> {
        entries
            .iter()
            .filter(|entry| {
                entry.kind == "file"
                    && entry.component.is_some()
                    && !is_sidecar(&entry.path)
                    && within_app(&entry.path)
                    && predicate(&entry.path)
            })
            .filter_map(|entry| entry.component.clone())
            .collect()
    };
    let pick = |predicate: &dyn Fn(&Value) -> bool| -> Vec<Value> {
        all.iter()
            .filter(|component| predicate(component))
            .cloned()
            .collect()
    };
    let launchd_plists: Vec<Value> = matching(&|path| path.ends_with(".plist"))
        .into_iter()
        .filter_map(|mut component| {
            let domain = launchd_domain(path_of(&component))?;
            component["domain"] = Value::String(domain.to_owned());
            Some(component)
        })
        .collect();
    json!({
        "bundle_metadata": pick(&|c| anatomy_name_is(last_segment(path_of(c)), "Info.plist")),
        "executables": pick(&|c| {
            is_mach_o_format(format_of(c)) && (within_app(path_of(c)) || !is_native_library(path_of(c)))
        }),
        "frameworks": pick(&|c| path_of(c).contains(".framework/")),
        "native_libraries": pick(&|c| is_native_library(path_of(c))),
        "javascript": pick(&|c| format_of(c) == "javascript-bundle"),
        "signing": pick(&|c| {
            let path = path_of(c);
            let name = last_segment(path);
            anatomy_tail_matches(path, &["_CodeSignature", "CodeResources"])
                || anatomy_name_is(name, "embedded.mobileprovision")
                || anatomy_name_is(name, "embedded.provisionprofile")
        }),
        "privileged_helpers": matching(&|path| {
            anatomy_tail_matches(path, &["Contents", "Library", "LaunchServices", "*"])
        }),
        "launchd_plists": launchd_plists,
        "helpers": matching(&|path| anatomy_tail_matches(path, &["Contents", "Helpers", "*"])),
    })
}

/// `deduplicateComponents`: last component per path, ordered by path.
fn deduplicate(values: Vec<Value>) -> Vec<Value> {
    let mut by_path: BTreeMap<String, Value> = BTreeMap::new();
    for value in values {
        by_path.insert(path_of(&value).to_owned(), value);
    }
    by_path.into_values().collect()
}

fn runtime_families(all: &[Value]) -> Vec<&'static str> {
    let mut families = BTreeSet::new();
    if all.iter().any(|c| is_mach_o_format(format_of(c))) {
        families.insert("native");
    }
    if all
        .iter()
        .any(|c| projection::is_swift_runtime_library(path_of(c)))
    {
        families.insert("swift-objective-c");
    }
    if all.iter().any(|c| format_of(c) == "javascript-bundle") {
        families.insert("javascript");
    }
    for component in all {
        if let Some(convention) = projection::native_runtime_convention(path_of(component)) {
            families.insert(convention);
        }
    }
    families.into_iter().collect()
}

/// Pair scripts and native code within matching application-root groups.
fn bridge_candidates(scripts: &[Value], native: &[Value], roots: &[String]) -> (Vec<Value>, Value) {
    let owner = |path: &str| roots.iter().find(|root| is_within(path, root)).cloned();
    let mut script_groups: Vec<(Option<String>, Vec<&Value>)> = Vec::new();
    for script in scripts {
        let root = owner(path_of(script));
        match script_groups.last_mut() {
            Some((last, left)) if *last == root => left.push(script),
            _ => script_groups.push((root, vec![script])),
        }
    }
    let mut native_by_root: BTreeMap<Option<String>, Vec<&Value>> = BTreeMap::new();
    for item in native {
        native_by_root
            .entry(owner(path_of(item)))
            .or_default()
            .push(item);
    }
    let groups: Vec<CandidateGroup<'_>> = script_groups
        .into_iter()
        .map(|(root, left)| CandidateGroup {
            left,
            right: native_by_root.get(&root).cloned().unwrap_or_default(),
        })
        .collect();
    projection::cartesian_candidates(&groups, |source_path, item| {
        let basis = match projection::native_runtime_convention(path_of(item)) {
            Some("react-native") => "react-native-convention",
            Some("flutter") => "flutter-convention",
            Some("unity") => "unity-convention",
            _ => "javascript-and-native-content",
        };
        json!({ "source_path": source_path, "native_path": path_of(item), "basis": basis })
    })
}

struct LimitationFacts<'a> {
    complete: bool,
    uninventoried_image: bool,
    roots: &'a [String],
    bundles: &'a [Value],
    sidecars: bool,
    symlinks: bool,
    unattributed: usize,
    unavailable: bool,
    bridge_coverage: &'a Value,
}

fn projection_limitations(facts: &LimitationFacts<'_>) -> Vec<String> {
    let mut limitations = Vec::new();
    if !facts.complete {
        limitations.push("Source inventory coverage is partial; absence is unknown.".to_owned());
    }
    if facts.uninventoried_image {
        limitations.push(
            "The DMG's contents were not inventoried on this host; bundle absence is unknown."
                .to_owned(),
        );
    }
    if facts.roots.is_empty() {
        limitations.push("No application bundle (Payload/*.app or *.app/Contents) was present in the supplied inventory pages.".to_owned());
    }
    if facts.bundles.iter().any(|bundle| {
        bundle["layout"] == "versioned-framework" && bundle["info_plist_path"].is_null()
    }) {
        limitations.push("A versioned framework has several version directories or no Versions/*/Resources/Info.plist; the Info.plist that Versions/Current selects is unknown because symlink targets are not inventoried.".to_owned());
    }
    if facts.symlinks {
        limitations.push("Symlinks are reported by path only; their targets are not inventoried, so bundles are reported at their real paths.".to_owned());
    }
    if facts.unattributed > 0 {
        limitations.push(format!(
            "{} inventoried entries outside every application root are not attributed to the application.",
            facts.unattributed
        ));
    }
    if facts.sidecars {
        limitations.push("AppleDouble sidecar entries (._* files and __MACOSX/) describe neighbouring files and are excluded from bundle roles.".to_owned());
    }
    if facts.bridge_coverage["status"] == "partial" {
        limitations.push(format!(
            "Bridge candidate pairs exceeded the projection safety budget; {} hypotheses are omitted. Component arrays still include every component from the supplied inventory pages.",
            facts.bridge_coverage["omitted_candidates"]
        ));
    }
    if facts.unavailable {
        limitations.push("Some inventoried files have no authenticated content identity. Their paths and limitations are retained in unavailable_components; component absence is unknown.".to_owned());
    }
    limitations.extend([
        "Bundle roles follow path conventions. Read each info_plist_path with inspect_plist for CFBundleExecutable, identifiers, and declared services.".to_owned(),
        "Bundle identifiers and signing claims require dedicated plist and CMS parsing; this projection reports only exact paths and hashes.".to_owned(),
        "Runtime families are inferred from inventory formats and bounded framework path conventions, not observed runtime loading.".to_owned(),
        "Generic framework and dylib paths do not establish Swift or Objective-C; this inventory projection does not decode language metadata.".to_owned(),
        "Bridge candidates are path-based hypotheses, not observed runtime calls.".to_owned(),
        "A bridge basis is inferred from the native path and is repeated for every managed component.".to_owned(),
    ]);
    limitations
}
