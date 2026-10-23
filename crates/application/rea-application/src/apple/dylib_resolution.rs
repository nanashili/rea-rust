//! Read-only, bounded modelling of dyld's load-path search.
//!
//! The module deliberately contains no Mach-O parser.  Callers provide the
//! parsed image facts and a root-relative tree view, which keeps path policy
//! separate from byte interpretation and makes this workflow easy to reuse by
//! CLI and MCP adapters.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::apple::dyld_paths::compatible_slice as select_compatible_slice;

const LIMITATIONS: &[&str] = &[
    "LC_LAZY_LOAD_DYLIB dependencies are resolved but not traversed, because dyld loads them only on first use.",
    "Slices are matched by dyld's graded architectures (an x86_64h process also loads x86_64). arm64e processes that disable pointer authentication can also load arm64 slices; that fallback is not modeled.",
    "Absolute install names and rpaths are outside the analyzed root and are not evaluated, including /System and /usr/lib libraries that the dyld shared cache usually provides.",
    "Leaf and relative install names depend on dyld fallback paths, DYLD_* variables, and the working directory; they are undetermined.",
    "Load order follows dyld's dependents-first traversal in load-command order. An image reached through several chains is resolved once per process, with the rpath stack and conditionality of the first chain; a later @rpath request whose install name matches an already loaded image reuses it.",
    "@loader_path uses each image's symlink-resolved path within the analyzed root.",
    "Code-signing checks that can reject a found image, such as library validation and the hardened runtime, are not evaluated.",
    "Dylib compatibility versions are not compared. Apple's linker documentation describes a load-time rejection when an image's compatibility version is older than the loader requires, but dyld on macOS 26 was observed to load such an image.",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachoDependency {
    pub command: String,
    pub encoding: String,
    pub install_name: String,
    pub weak: bool,
    pub upward: bool,
    pub reexport: bool,
    pub delayed_init: bool,
    pub current_version: String,
    pub compatibility_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachoSlice {
    pub architecture: String,
    pub slice_offset: u64,
    pub slice_size: u64,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub fat_cpu_type: Option<u32>,
    pub fat_cpu_subtype: Option<u32>,
    pub fat_alignment_exponent: Option<u8>,
    pub file_type: String,
    pub file_type_code: u32,
    pub platform: Option<u32>,
    pub platforms: Vec<u32>,
    pub install_name: Option<String>,
    pub dependencies: Vec<MachoDependency>,
    pub rpaths: Vec<String>,
    pub dyld_environment: Vec<String>,
    pub code_signature_present: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachoImageFacts {
    Parsed { slices: Vec<MachoSlice> },
    Malformed { reason: String },
    Unsupported { reason: String },
    NotMachO,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DylibTreeEntry {
    File,
    Directory,
    Symlink { target: String },
}

pub trait DylibTreeView {
    type Error: std::error::Error + Send + Sync + 'static;

    fn entry(&self, path: &str) -> Result<Option<DylibTreeEntry>, Self::Error>;
    fn image(&self, path: &str) -> Result<MachoImageFacts, Self::Error>;
}

#[derive(Debug)]
pub enum TraceError<E> {
    View(E),
    Cancelled,
}

impl<E: std::fmt::Display> std::fmt::Display for TraceError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::View(error) => write!(formatter, "dylib tree view failed: {error}"),
            Self::Cancelled => formatter.write_str("dylib resolution cancelled"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DylibCandidate {
    pub path: String,
    pub source: String,
    pub rpath: Option<String>,
    pub rpath_owner: Option<String>,
    pub outcome: String,
    pub resolved_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DylibResolution {
    pub status: String,
    pub image: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DylibEdge {
    pub root: String,
    pub architecture: String,
    pub loader: String,
    pub via: Vec<String>,
    pub dependency: MachoDependency,
    pub candidates: Vec<DylibCandidate>,
    pub resolution: DylibResolution,
    pub install_name_matches: Option<bool>,
    pub loader_conditional: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DylibImage {
    pub path: String,
    pub parse_status: String,
    pub reason: Option<String>,
    pub slices: Vec<MachoSliceSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachoSliceSummary {
    pub architecture: String,
    pub slice_offset: u64,
    pub slice_size: u64,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub fat_cpu_type: Option<u32>,
    pub fat_cpu_subtype: Option<u32>,
    pub fat_alignment_exponent: Option<u8>,
    pub file_type: String,
    pub file_type_code: u32,
    pub platform: Option<u32>,
    pub platforms: Vec<u32>,
    pub install_name: Option<String>,
    pub rpaths: Vec<String>,
    pub dyld_environment: Vec<String>,
    pub code_signature_present: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DylibFinding {
    pub kind: String,
    pub edge_index: Option<usize>,
    pub image: Option<String>,
    pub basis: String,
    pub explanation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DylibTrace {
    pub roots: Vec<TracedRoot>,
    pub images: Vec<DylibImage>,
    pub edges: Vec<DylibEdge>,
    pub findings: Vec<DylibFinding>,
    pub coverage: Coverage,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TracedRoot {
    pub image: String,
    pub architecture: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Coverage {
    pub status: String,
    pub unparsed_images: Vec<String>,
    pub roots_without_architecture: Vec<String>,
}

pub struct DylibResolutionRequest<'a> {
    pub roots: &'a [String],
    pub unclassified: &'a [String],
    pub architecture: Option<&'a str>,
    pub cancelled: Option<&'a dyn Fn() -> bool>,
}

struct LoadedImage {
    slice: MachoSlice,
    chain: Vec<String>,
    conditional: bool,
}

#[derive(Clone)]
struct DyldSearchOverride {
    phase: OverridePhase,
    scope: OverrideScope,
    variable: String,
    value: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OverridePhase {
    Override,
    Fallback,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OverrideScope {
    Library,
    Framework,
    Prefix,
    All,
}

struct Context<'a, V: DylibTreeView> {
    view: &'a V,
    root: String,
    identity: MachoSlice,
    executable: Option<String>,
    search_overrides: Vec<DyldSearchOverride>,
    environment_roots: &'a mut BTreeSet<String>,
    loaded: BTreeMap<String, LoadedImage>,
    by_install_name: BTreeMap<String, String>,
    images: BTreeMap<String, MachoImageFacts>,
}

pub fn trace_dylib_loading<V: DylibTreeView>(
    view: &V,
    request: DylibResolutionRequest<'_>,
) -> Result<DylibTrace, TraceError<V::Error>> {
    let mut images = BTreeMap::new();
    for path in request.unclassified {
        let facts = image_facts(view, &mut images, path)?;
        images.insert(path.clone(), facts);
    }

    let mut roots = Vec::new();
    let mut root_slices = Vec::new();
    let mut edges = Vec::new();
    let mut roots_without_architecture = Vec::new();
    let mut environment_roots = BTreeSet::new();

    for root in request.roots {
        check_cancelled(request.cancelled)?;
        let facts = image_facts(view, &mut images, root)?;
        let MachoImageFacts::Parsed { slices } = &facts else {
            continue;
        };
        let selected: Vec<_> = slices
            .iter()
            .filter(|slice| {
                request
                    .architecture
                    .is_none_or(|wanted| wanted == slice.architecture)
            })
            .cloned()
            .collect();
        if selected.is_empty() {
            roots_without_architecture.push(root.clone());
        }
        for root_slice in selected {
            let executable = (root_slice.file_type == "execute").then(|| root.clone());
            let search_overrides = if executable.is_some() {
                embedded_dyld_overrides(&root_slice.dyld_environment, &root_slice.platforms)
            } else {
                Vec::new()
            };
            if search_overrides
                .iter()
                .any(|setting| setting.variable == "DYLD_INSERT_LIBRARIES")
            {
                environment_roots.insert(root.clone());
            }
            roots.push(TracedRoot {
                image: root.clone(),
                architecture: root_slice.architecture.clone(),
            });
            root_slices.push((root.clone(), root_slice.clone()));
            let mut context = Context {
                view,
                root: root.clone(),
                identity: root_slice.clone(),
                executable,
                search_overrides,
                environment_roots: &mut environment_roots,
                loaded: BTreeMap::new(),
                by_install_name: BTreeMap::new(),
                images: images.clone(),
            };
            edges.extend(trace_process(&mut context, root_slice, request.cancelled)?);
            images.extend(context.images);
        }
    }

    let unparsed_images: Vec<_> = images
        .iter()
        .filter_map(|(path, facts)| {
            (!matches!(
                facts,
                MachoImageFacts::Parsed { .. } | MachoImageFacts::NotMachO
            ))
            .then_some(path.clone())
        })
        .collect();
    let findings = derive_findings(&edges, &root_slices);
    let image_list = images
        .into_iter()
        .filter_map(|(path, facts)| image_summary(path, facts))
        .collect();
    let mut limitations = LIMITATIONS
        .iter()
        .map(|item| (*item).to_owned())
        .collect::<Vec<_>>();
    if !environment_roots.is_empty() {
        limitations.push(format!(
            "Roots {} request applicable image-selection inputs through LC_DYLD_ENVIRONMENT that are not modeled; affected dependencies or inserted images remain uncertain.",
            environment_roots.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(DylibTrace {
        roots,
        images: image_list,
        edges,
        findings,
        coverage: Coverage {
            status: if unparsed_images.is_empty()
                && roots_without_architecture.is_empty()
                && environment_roots.is_empty()
            {
                "complete"
            } else {
                "partial"
            }
            .into(),
            unparsed_images,
            roots_without_architecture,
        },
        limitations,
    })
}

fn trace_process<V: DylibTreeView>(
    context: &mut Context<'_, V>,
    root_slice: MachoSlice,
    cancelled: Option<&dyn Fn() -> bool>,
) -> Result<Vec<DylibEdge>, TraceError<V::Error>> {
    context.loaded.insert(
        context.root.clone(),
        LoadedImage {
            slice: root_slice.clone(),
            chain: vec![context.root.clone()],
            conditional: false,
        },
    );
    if let Some(name) = &root_slice.install_name {
        if name.starts_with("@rpath/") {
            context
                .by_install_name
                .insert(name.clone(), context.root.clone());
        }
    }
    let mut pending = VecDeque::from([context.root.clone()]);
    let mut edges = Vec::new();
    while let Some(loader) = pending.pop_back() {
        check_cancelled(cancelled)?;
        let Some(current) = context.loaded.get(&loader) else {
            continue;
        };
        let dependencies = current.slice.dependencies.clone();
        let current_chain = current.chain.clone();
        let current_conditional = current.conditional;
        let mut created = Vec::new();
        for dependency in dependencies {
            let edge = resolve_dependency(
                context,
                &loader,
                &current_chain,
                current_conditional,
                dependency,
            )?;
            if edge.dependency.command == "LC_LAZY_LOAD_DYLIB" {
                edges.push(edge);
                continue;
            }
            if let Some(image) = edge.resolution.image.clone() {
                if !context.loaded.contains_key(&image) {
                    let slice = compatible_slice(context.images.get(&image), &context.identity);
                    if let Some(slice) = slice {
                        let conditional =
                            current_conditional || edge.resolution.status == "conditional";
                        let install_name = slice.install_name.clone();
                        context.loaded.insert(
                            image.clone(),
                            LoadedImage {
                                slice,
                                chain: [current_chain.clone(), vec![image.clone()]].concat(),
                                conditional,
                            },
                        );
                        if let Some(name) = install_name {
                            if name.starts_with("@rpath/") {
                                context
                                    .by_install_name
                                    .entry(name)
                                    .or_insert_with(|| image.clone());
                            }
                        }
                        created.push(image);
                    }
                }
            }
            edges.push(edge);
        }
        pending.extend(created.into_iter().rev());
    }
    Ok(edges)
}

fn resolve_dependency<V: DylibTreeView>(
    context: &mut Context<'_, V>,
    loader: &str,
    chain: &[String],
    loader_conditional: bool,
    dependency: MachoDependency,
) -> Result<DylibEdge, TraceError<V::Error>> {
    let already_loaded = dependency
        .install_name
        .starts_with("@rpath/")
        .then(|| {
            context
                .by_install_name
                .get(&dependency.install_name)
                .cloned()
        })
        .flatten();
    let mut candidates = Vec::new();
    if let Some(path) = already_loaded.clone() {
        candidates.push(DylibCandidate {
            path: dependency.install_name.clone(),
            source: "already-loaded".into(),
            rpath: None,
            rpath_owner: None,
            outcome: "resolved".into(),
            resolved_path: Some(path),
        });
    } else {
        for (path, source, rpath, owner, scope) in
            candidate_templates(context, loader, &dependency.install_name)
        {
            let candidate = evaluate_candidate(context, path, source, rpath, owner, scope)?;
            let done = candidate.outcome == "resolved";
            candidates.push(candidate);
            if done {
                break;
            }
        }
    }
    let modeled = resolution(&candidates);
    let search_override_applies = already_loaded.is_none()
        && has_applicable_dyld_overrides(
            &context.search_overrides,
            &dependency.install_name,
            modeled.image.is_some(),
        );
    if search_override_applies {
        context.environment_roots.insert(context.root.clone());
    }
    let searched = if search_override_applies {
        DylibResolution {
            status: if modeled.image.is_some() {
                "conditional"
            } else {
                "undetermined"
            }
            .into(),
            image: modeled.image,
        }
    } else {
        modeled
    };
    let mut resolution = searched;
    if already_loaded.as_ref().is_some_and(|path| {
        context
            .loaded
            .get(path)
            .is_some_and(|loaded| loaded.conditional)
    }) && resolution.status == "resolved"
    {
        resolution.status = "conditional".into();
    }
    let image = resolution
        .image
        .as_ref()
        .and_then(|path| context.images.get(path));
    let slice = compatible_slice(image, &context.identity);
    Ok(DylibEdge {
        root: context.root.clone(),
        architecture: context.identity.architecture.clone(),
        loader: loader.into(),
        via: chain.to_vec(),
        install_name_matches: slice.and_then(|loaded| {
            loaded
                .install_name
                .as_ref()
                .map(|name| name == &dependency.install_name)
        }),
        dependency,
        candidates,
        resolution,
        loader_conditional,
    })
}

fn candidate_templates<V: DylibTreeView>(
    context: &Context<'_, V>,
    loader: &str,
    name: &str,
) -> Vec<(String, String, Option<String>, Option<String>, Scope)> {
    if !name.starts_with("@rpath/") {
        let (path, scope) = expand_prefix(name, loader, context.executable.as_deref());
        return vec![(
            path,
            if name.starts_with("@executable_path") {
                "executable_path"
            } else if name.starts_with("@loader_path") {
                "loader_path"
            } else {
                "literal"
            }
            .into(),
            None,
            None,
            scope,
        )];
    }
    let rest = &name["@rpath/".len()..];
    let owners = context
        .loaded
        .get(loader)
        .map(|loaded| loaded.chain.clone())
        .unwrap_or_else(|| vec![loader.into()]);
    owners
        .into_iter()
        .rev()
        .flat_map(|owner| {
            let owner_for_rpath = owner.clone();
            context
                .loaded
                .get(&owner)
                .into_iter()
                .flat_map(move |loaded| {
                    let owner_for_candidate = owner_for_rpath.clone();
                    loaded.slice.rpaths.iter().map(move |rpath| {
                        let (base, scope) = expand_prefix(
                            rpath,
                            &owner_for_candidate,
                            context.executable.as_deref(),
                        );
                        let path = append_rpath_suffix(&base, rest, scope);
                        (
                            path,
                            "rpath".into(),
                            Some(rpath.clone()),
                            Some(owner_for_candidate.clone()),
                            scope,
                        )
                    })
                })
        })
        .collect()
}

fn append_rpath_suffix(base: &str, rest: &str, scope: Scope) -> String {
    if matches!(scope, Scope::Outside) {
        return format!("{}/{rest}", base.trim_end_matches('/'));
    }
    if base.is_empty() {
        rest.to_owned()
    } else {
        format!("{base}/{rest}")
    }
}

#[derive(Clone, Copy)]
enum Scope {
    Inside,
    Outside,
    Undetermined,
}

fn expand_prefix(value: &str, loader: &str, executable: Option<&str>) -> (String, Scope) {
    if value.starts_with('/') {
        return (value.to_owned(), Scope::Outside);
    }

    let (base, rest) = if value == "@loader_path" {
        (parent(loader), "")
    } else if let Some(rest) = value.strip_prefix("@loader_path/") {
        (parent(loader), rest)
    } else if value == "@executable_path" {
        let Some(executable) = executable else {
            return (value.to_owned(), Scope::Undetermined);
        };
        (parent(executable), "")
    } else if let Some(rest) = value.strip_prefix("@executable_path/") {
        let Some(executable) = executable else {
            return (value.to_owned(), Scope::Undetermined);
        };
        (parent(executable), rest)
    } else {
        return (value.to_owned(), Scope::Undetermined);
    };

    let path = if base.is_empty() {
        rest.to_owned()
    } else if rest.is_empty() {
        base
    } else {
        format!("{base}/{rest}")
    };
    (path, Scope::Inside)
}

fn parent(path: &str) -> String {
    path.rsplit_once('/')
        .map_or_else(String::new, |(parent, _)| parent.to_owned())
}

fn evaluate_candidate<V: DylibTreeView>(
    context: &mut Context<'_, V>,
    path: String,
    source: String,
    rpath: Option<String>,
    owner: Option<String>,
    scope: Scope,
) -> Result<DylibCandidate, TraceError<V::Error>> {
    let base = DylibCandidate {
        path: path.clone(),
        source,
        rpath,
        rpath_owner: owner,
        outcome: String::new(),
        resolved_path: None,
    };
    if matches!(scope, Scope::Outside) {
        return Ok(DylibCandidate {
            outcome: "outside-target".into(),
            ..base
        });
    }
    if matches!(scope, Scope::Undetermined) {
        return Ok(DylibCandidate {
            outcome: "undetermined".into(),
            ..base
        });
    }
    let resolved_path = match resolve_tree_path(context.view, &path)? {
        TreePathLookup::File(path) => path,
        TreePathLookup::Escapes => {
            return Ok(DylibCandidate {
                outcome: "escapes-target".into(),
                ..base
            });
        }
        TreePathLookup::Absent | TreePathLookup::NotFile => {
            return Ok(DylibCandidate {
                outcome: "absent".into(),
                ..base
            });
        }
    };
    let facts = image_facts(context.view, &mut context.images, &resolved_path)?;
    let outcome = match &facts {
        MachoImageFacts::Parsed { .. } => match compatible_slice(Some(&facts), &context.identity) {
            None => "architecture-missing",
            Some(slice) if slice.file_type_code != 6 => "not-loadable",
            Some(slice) => match platform_loadability(
                &context.identity.platforms,
                &slice.platforms,
                slice.file_type_code,
                &context.identity.architecture,
            ) {
                PlatformLoadability::Compatible => "resolved",
                PlatformLoadability::Incompatible => "platform-mismatch",
                PlatformLoadability::Unknown => "undetermined",
            },
        },
        MachoImageFacts::Malformed { .. } => "malformed",
        MachoImageFacts::Unsupported { .. } => "unsupported",
        MachoImageFacts::NotMachO => "not-mach-o",
    };
    Ok(DylibCandidate {
        outcome: outcome.into(),
        resolved_path: Some(resolved_path),
        ..base
    })
}

pub(crate) enum TreePathLookup {
    File(String),
    Absent,
    Escapes,
    NotFile,
}

pub(crate) fn resolve_tree_path<V: DylibTreeView>(
    view: &V,
    input: &str,
) -> Result<TreePathLookup, TraceError<V::Error>> {
    const MAX_SYMLINK_HOPS: usize = 32;

    let mut pending = input
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
        .collect::<VecDeque<_>>();
    if input.ends_with('/') {
        pending.push_back(".".into());
    }

    let mut resolved = Vec::<String>::new();
    let mut last_is_file = false;
    let mut symlink_hops = 0usize;

    while let Some(segment) = pending.pop_front() {
        match segment.as_str() {
            "." => continue,
            ".." => {
                if resolved.pop().is_none() {
                    return Ok(TreePathLookup::Escapes);
                }
                last_is_file = false;
                continue;
            }
            _ => {}
        }

        let entry_path = join_root_relative(&resolved, &segment);
        let Some(entry) = view.entry(&entry_path).map_err(TraceError::View)? else {
            return Ok(TreePathLookup::Absent);
        };
        match entry {
            DylibTreeEntry::Symlink { target } => {
                symlink_hops += 1;
                if symlink_hops > MAX_SYMLINK_HOPS {
                    return Ok(TreePathLookup::Absent);
                }
                if target.starts_with('/') {
                    return Ok(TreePathLookup::Escapes);
                }
                for target_segment in target
                    .split('/')
                    .filter(|target_segment| !target_segment.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                {
                    pending.push_front(target_segment);
                }
            }
            DylibTreeEntry::File if !pending.is_empty() => {
                return Ok(TreePathLookup::Absent);
            }
            DylibTreeEntry::File => {
                resolved.push(segment);
                last_is_file = true;
            }
            DylibTreeEntry::Directory => {
                resolved.push(segment);
                last_is_file = false;
            }
        }
    }

    if last_is_file {
        Ok(TreePathLookup::File(resolved.join("/")))
    } else {
        Ok(TreePathLookup::NotFile)
    }
}

fn join_root_relative(parent: &[String], child: &str) -> String {
    if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{}/{child}", parent.join("/"))
    }
}

fn resolution(candidates: &[DylibCandidate]) -> DylibResolution {
    let mut external = false;
    for candidate in candidates {
        if candidate.outcome == "resolved" {
            return DylibResolution {
                status: if external { "conditional" } else { "resolved" }.into(),
                image: candidate.resolved_path.clone(),
            };
        }
        if matches!(
            candidate.outcome.as_str(),
            "outside-target" | "escapes-target" | "unsupported" | "undetermined"
        ) {
            external = true;
        }
    }
    DylibResolution {
        status: if external {
            "undetermined"
        } else {
            "unresolved"
        }
        .into(),
        image: None,
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PlatformLoadability {
    Compatible,
    Incompatible,
    Unknown,
}

fn platform_loadability(
    process: &[u32],
    image: &[u32],
    file_type: u32,
    architecture: &str,
) -> PlatformLoadability {
    if process.is_empty() || image.is_empty() {
        return PlatformLoadability::Unknown;
    }
    let outcomes: Vec<_> = process
        .iter()
        .map(|platform| image_loadability(*platform, image, file_type, architecture))
        .collect();
    if outcomes
        .iter()
        .all(|outcome| *outcome == PlatformLoadability::Compatible)
    {
        PlatformLoadability::Compatible
    } else if outcomes
        .iter()
        .all(|outcome| *outcome == PlatformLoadability::Incompatible)
    {
        PlatformLoadability::Incompatible
    } else {
        PlatformLoadability::Unknown
    }
}

fn image_loadability(
    process: u32,
    image: &[u32],
    file_type: u32,
    architecture: &str,
) -> PlatformLoadability {
    if image.contains(&process) {
        return PlatformLoadability::Compatible;
    }
    if (process == 6 && image.contains(&1))
        || (process == 2 && (image.contains(&6) || image.contains(&11)))
        || (process == 7 && image.contains(&12))
        || (process == 1 && file_type == 2 && image.contains(&6))
    {
        return PlatformLoadability::Compatible;
    }
    if (process == 2 && image.contains(&1) && architecture.starts_with("arm64"))
        || ([7, 8, 9].contains(&process) && image.contains(&1))
    {
        return PlatformLoadability::Unknown;
    }
    if (1..=12).contains(&process) && image.iter().all(|platform| (1..=12).contains(platform)) {
        PlatformLoadability::Incompatible
    } else {
        PlatformLoadability::Unknown
    }
}

fn compatible_slice<'a>(
    facts: Option<&'a MachoImageFacts>,
    identity: &MachoSlice,
) -> Option<MachoSlice> {
    let Some(MachoImageFacts::Parsed { slices }) = facts else {
        return None;
    };
    select_compatible_slice(slices, identity).cloned()
}

fn image_facts<V: DylibTreeView>(
    view: &V,
    cache: &mut BTreeMap<String, MachoImageFacts>,
    path: &str,
) -> Result<MachoImageFacts, TraceError<V::Error>> {
    if let Some(facts) = cache.get(path) {
        return Ok(facts.clone());
    }
    let facts = view.image(path).map_err(TraceError::View)?;
    cache.insert(path.into(), facts.clone());
    Ok(facts)
}

fn image_summary(path: String, facts: MachoImageFacts) -> Option<DylibImage> {
    let (parse_status, reason, slices) = match facts {
        MachoImageFacts::Parsed { slices } => (
            "parsed",
            None,
            slices.into_iter().map(slice_summary).collect(),
        ),
        MachoImageFacts::Malformed { reason } => ("malformed", Some(reason), Vec::new()),
        MachoImageFacts::Unsupported { reason } => ("unsupported", Some(reason), Vec::new()),
        MachoImageFacts::NotMachO => return None,
    };
    Some(DylibImage {
        path,
        parse_status: parse_status.into(),
        reason,
        slices,
    })
}

fn slice_summary(slice: MachoSlice) -> MachoSliceSummary {
    MachoSliceSummary {
        architecture: slice.architecture,
        slice_offset: slice.slice_offset,
        slice_size: slice.slice_size,
        cpu_type: slice.cpu_type,
        cpu_subtype: slice.cpu_subtype,
        fat_cpu_type: slice.fat_cpu_type,
        fat_cpu_subtype: slice.fat_cpu_subtype,
        fat_alignment_exponent: slice.fat_alignment_exponent,
        file_type: slice.file_type,
        file_type_code: slice.file_type_code,
        platform: slice.platform,
        platforms: slice.platforms,
        install_name: slice.install_name,
        rpaths: slice.rpaths,
        dyld_environment: slice.dyld_environment,
        code_signature_present: slice.code_signature_present,
    }
}

fn embedded_dyld_overrides(environment: &[String], platforms: &[u32]) -> Vec<DyldSearchOverride> {
    environment
        .iter()
        .filter_map(|setting| {
            let (variable, value) = setting.split_once('=')?;
            let effect = override_effect(variable, value)?;
            if variable == "DYLD_ROOT_PATH"
                && !platforms.is_empty()
                && platforms.iter().all(|platform| (1..=12).contains(platform))
                && !platforms
                    .iter()
                    .any(|platform| [7, 8, 9, 12].contains(platform))
            {
                return None;
            }
            Some(DyldSearchOverride {
                phase: effect.0,
                scope: effect.1,
                variable: variable.to_owned(),
                value: value.to_owned(),
            })
        })
        .collect()
}

fn override_effect(variable: &str, value: &str) -> Option<(OverridePhase, OverrideScope)> {
    match variable {
        "DYLD_LIBRARY_PATH" => Some((OverridePhase::Override, OverrideScope::Library)),
        "DYLD_FRAMEWORK_PATH" => Some((OverridePhase::Override, OverrideScope::Framework)),
        "DYLD_FALLBACK_LIBRARY_PATH" => Some((OverridePhase::Fallback, OverrideScope::Library)),
        "DYLD_FALLBACK_FRAMEWORK_PATH" => Some((OverridePhase::Fallback, OverrideScope::Framework)),
        "DYLD_VERSIONED_LIBRARY_PATH" | "DYLD_VERSIONED_FRAMEWORK_PATH" | "DYLD_IMAGE_SUFFIX"
            if value.chars().any(|character| character != ':') =>
        {
            Some((OverridePhase::Override, OverrideScope::All))
        }
        "DYLD_INSERT_LIBRARIES" if !value.is_empty() => {
            Some((OverridePhase::Override, OverrideScope::All))
        }
        "DYLD_ROOT_PATH" | "DYLD_OVERLAY_PATH" if !value.is_empty() => {
            Some((OverridePhase::Override, OverrideScope::Prefix))
        }
        _ => None,
    }
}

fn has_applicable_dyld_overrides(
    overrides: &[DyldSearchOverride],
    install_name: &str,
    ordinary_search_found_image: bool,
) -> bool {
    let framework = is_framework_install_name(install_name, overrides);
    overrides.iter().any(|setting| {
        let phase_applies =
            setting.phase == OverridePhase::Override || !ordinary_search_found_image;
        let scope_applies = match setting.scope {
            OverrideScope::All => true,
            OverrideScope::Library => !framework,
            OverrideScope::Framework => framework,
            OverrideScope::Prefix => !install_name.starts_with('@'),
        };
        phase_applies && scope_applies
    })
}

fn is_framework_install_name(name: &str, overrides: &[DyldSearchOverride]) -> bool {
    let Some(separator) = name.rfind(".framework/") else {
        return false;
    };
    let framework = name[..separator].rsplit('/').next().unwrap_or_default();
    let leaf = name.rsplit('/').next().unwrap_or_default();
    leaf == framework
        || overrides.iter().any(|setting| {
            setting.variable == "DYLD_IMAGE_SUFFIX"
                && leaf == format!("{framework}{}", setting.value)
        })
}

fn derive_findings(edges: &[DylibEdge], roots: &[(String, MachoSlice)]) -> Vec<DylibFinding> {
    let mut findings = Vec::new();
    for (index, edge) in edges.iter().enumerate() {
        if edge.resolution.status == "unresolved" {
            findings.push(unresolved_finding(edge, index));
        }

        let resolved_at = edge
            .candidates
            .iter()
            .position(|candidate| candidate.outcome == "resolved");
        if let Some(resolved_at) = resolved_at {
            let earlier = edge.candidates[..resolved_at]
                .iter()
                .filter(|candidate| candidate.source == "rpath" && candidate.outcome == "absent")
                .map(|candidate| candidate.path.as_str())
                .collect::<Vec<_>>();
            if !earlier.is_empty() {
                let paths = earlier.join(", ");
                let resolved = edge
                    .resolution
                    .image
                    .as_deref()
                    .unwrap_or(&edge.dependency.install_name);
                let mut explanation = format!(
                    "The modeled dyld search checks {paths} before {resolved}. A compatible Mach-O placed at an earlier modeled path could take precedence over that fallback, subject to unmodeled search inputs and code-signing library validation; library validation is not evaluated here (see inspect_signature)."
                );
                append_conditional_explanation(&mut explanation, edge);
                findings.push(DylibFinding {
                    kind: "earlier-rpath-candidate-absent".into(),
                    edge_index: Some(index),
                    image: Some(edge.loader.clone()),
                    basis: "derived".into(),
                    explanation,
                });
            }
        }
    }

    for (image, slice) in roots {
        if slice.dyld_environment.is_empty() {
            continue;
        }
        let explanation = if slice.file_type == "execute" {
            format!(
                "{image} ({}) sets dyld environment variables through LC_DYLD_ENVIRONMENT ({}); any image-selection overrides they request are not modeled. Diagnostic settings alone do not alter resolution.",
                slice.architecture,
                slice.dyld_environment.join(", ")
            )
        } else {
            format!(
                "{image} ({}) contains LC_DYLD_ENVIRONMENT ({}). Dyld reads these commands only from the main executable; entries in this non-executable root are observations and do not alter resolution.",
                slice.architecture,
                slice.dyld_environment.join(", ")
            )
        };
        findings.push(DylibFinding {
            kind: "dyld-environment-present".into(),
            edge_index: None,
            image: Some(image.clone()),
            basis: "derived".into(),
            explanation,
        });
    }
    findings
}

fn unresolved_finding(edge: &DylibEdge, index: usize) -> DylibFinding {
    let dependency_kind = match edge.dependency.command.as_str() {
        "LC_LAZY_LOAD_DYLIB" => "lazily loaded ",
        _ if edge.dependency.weak => "weak dependency ",
        _ => "",
    };
    let missing = format!(
        "No candidate for {dependency_kind}{} exists in the analyzed root",
        edge.dependency.install_name
    );
    let when = if edge.loader_conditional {
        format!(". {} loads only conditionally; if it loads, ", edge.loader)
    } else {
        "; ".into()
    };
    let (kind, consequence) = match edge.dependency.command.as_str() {
        "LC_LAZY_LOAD_DYLIB" => (
            "lazy-load-unresolved",
            "dyld loads it on first use, which would fail unless the image is supplied elsewhere.",
        ),
        _ if edge.dependency.weak => ("weak-load-unresolved", "dyld continues without it."),
        _ => (
            "required-load-unresolved",
            "dyld would fail to load this required dependency unless the image is supplied elsewhere.",
        ),
    };
    let consequence = if edge.dependency.command == "LC_LAZY_LOAD_DYLIB" {
        consequence.to_owned()
    } else if edge.dependency.weak {
        consequence.to_owned()
    } else {
        format!(
            "dyld would fail to load this required dependency for {} ({}) unless the image is supplied elsewhere.",
            edge.root, edge.architecture
        )
    };
    DylibFinding {
        kind: kind.into(),
        edge_index: Some(index),
        image: Some(edge.loader.clone()),
        basis: "derived".into(),
        explanation: format!("{missing}{when}{consequence}"),
    }
}

fn append_conditional_explanation(explanation: &mut String, edge: &DylibEdge) {
    if edge.loader_conditional {
        explanation.push_str(
            " This loader loads only conditionally; if it never loads, this search never occurs.",
        );
    }
    if edge.resolution.status == "conditional" {
        explanation.push_str(
            " Unmodeled environment overrides or earlier unknown candidates may take precedence; placing an image at this rpath does not establish which image dyld will load.",
        );
    }
}

fn check_cancelled<E>(cancelled: Option<&dyn Fn() -> bool>) -> Result<(), TraceError<E>> {
    if cancelled.is_some_and(|check| check()) {
        Err(TraceError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    struct View {
        entries: BTreeMap<String, DylibTreeEntry>,
        images: BTreeMap<String, MachoImageFacts>,
    }
    impl DylibTreeView for View {
        type Error = Infallible;
        fn entry(&self, path: &str) -> Result<Option<DylibTreeEntry>, Self::Error> {
            Ok(self.entries.get(path).cloned())
        }
        fn image(&self, path: &str) -> Result<MachoImageFacts, Self::Error> {
            Ok(self
                .images
                .get(path)
                .cloned()
                .unwrap_or(MachoImageFacts::NotMachO))
        }
    }

    fn slice(dependencies: Vec<MachoDependency>, rpaths: Vec<String>) -> MachoSlice {
        MachoSlice {
            architecture: "arm64".into(),
            slice_offset: 0,
            slice_size: 1,
            cpu_type: 1,
            cpu_subtype: 2,
            fat_cpu_type: None,
            fat_cpu_subtype: None,
            fat_alignment_exponent: None,
            file_type: "execute".into(),
            file_type_code: 2,
            platform: Some(1),
            platforms: vec![1],
            install_name: None,
            dependencies,
            rpaths,
            dyld_environment: Vec::new(),
            code_signature_present: false,
        }
    }

    #[test]
    fn rpath_resolution_keeps_earlier_absent_candidate() {
        let dependency = MachoDependency {
            command: "LC_LOAD_DYLIB".into(),
            encoding: "dylib_command".into(),
            install_name: "@rpath/lib.dylib".into(),
            weak: false,
            upward: false,
            reexport: false,
            delayed_init: false,
            current_version: String::new(),
            compatibility_version: String::new(),
        };
        let root = slice(
            vec![dependency],
            vec!["@loader_path/missing".into(), "@loader_path/lib".into()],
        );
        let mut dylib = slice(Vec::new(), Vec::new());
        dylib.file_type = "dylib".into();
        dylib.file_type_code = 6;
        let view = View {
            entries: [
                ("lib".into(), DylibTreeEntry::Directory),
                ("lib/lib.dylib".into(), DylibTreeEntry::File),
            ]
            .into_iter()
            .collect(),
            images: [
                (
                    "root".into(),
                    MachoImageFacts::Parsed { slices: vec![root] },
                ),
                (
                    "lib/lib.dylib".into(),
                    MachoImageFacts::Parsed {
                        slices: vec![dylib],
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };
        let trace = trace_dylib_loading(
            &view,
            DylibResolutionRequest {
                roots: &["root".into()],
                unclassified: &[],
                architecture: None,
                cancelled: None,
            },
        )
        .unwrap();
        assert_eq!(trace.edges[0].resolution.status, "resolved");
        assert_eq!(trace.edges[0].candidates.len(), 2);
        assert!(trace.findings.iter().any(|finding| {
            finding.kind == "earlier-rpath-candidate-absent" && finding.basis == "derived"
        }));
    }

    #[test]
    fn relative_rpath_is_undetermined_until_dyld_prefix_is_known() {
        let dependency = dependency("@rpath/lib.dylib", "LC_LOAD_DYLIB");
        let root = slice(vec![dependency], vec!["Frameworks".into()]);
        let view = View {
            entries: BTreeMap::new(),
            images: [(
                "root".into(),
                MachoImageFacts::Parsed { slices: vec![root] },
            )]
            .into_iter()
            .collect(),
        };

        let trace = trace(&view, &["root"], None);

        assert_eq!(trace.edges[0].candidates[0].outcome, "undetermined");
        assert_eq!(trace.edges[0].resolution.status, "undetermined");
        assert!(trace.findings.is_empty());
    }

    #[test]
    fn resolves_symlinks_segment_by_segment_inside_the_root() {
        let view = View {
            entries: [
                ("Frameworks".into(), DylibTreeEntry::Directory),
                (
                    "Frameworks/Current.dylib".into(),
                    DylibTreeEntry::Symlink {
                        target: "../Versions/A.dylib".into(),
                    },
                ),
                ("Versions".into(), DylibTreeEntry::Directory),
                ("Versions/A.dylib".into(), DylibTreeEntry::File),
            ]
            .into_iter()
            .collect(),
            images: BTreeMap::new(),
        };

        assert!(matches!(
            resolve_tree_path(&view, "Frameworks/Current.dylib"),
            Ok(TreePathLookup::File(path)) if path == "Versions/A.dylib"
        ));
    }

    #[test]
    fn absolute_symlink_target_is_an_escape() {
        let view = View {
            entries: [(
                "outside.dylib".into(),
                DylibTreeEntry::Symlink {
                    target: "/System/Library/libSystem.dylib".into(),
                },
            )]
            .into_iter()
            .collect(),
            images: BTreeMap::new(),
        };

        assert!(matches!(
            resolve_tree_path(&view, "outside.dylib"),
            Ok(TreePathLookup::Escapes)
        ));
    }

    #[test]
    fn x86_64h_process_accepts_the_generic_x86_64_slice() {
        let mut process = slice(Vec::new(), Vec::new());
        process.architecture = "x86_64h".into();
        let mut generic = process.clone();
        generic.architecture = "x86_64".into();
        let facts = MachoImageFacts::Parsed {
            slices: vec![generic.clone()],
        };

        assert_eq!(compatible_slice(Some(&facts), &process), Some(generic));
    }

    #[test]
    fn embedded_inserted_library_setting_keeps_coverage_partial() {
        let mut root = slice(Vec::new(), Vec::new());
        root.dyld_environment = vec!["DYLD_INSERT_LIBRARIES=Injected.dylib".into()];
        let view = View {
            entries: BTreeMap::new(),
            images: [(
                "root".into(),
                MachoImageFacts::Parsed { slices: vec![root] },
            )]
            .into_iter()
            .collect(),
        };

        let trace = trace(&view, &["root"], None);

        assert_eq!(trace.coverage.status, "partial");
        assert!(trace.findings.iter().any(|finding| {
            finding.kind == "dyld-environment-present" && finding.edge_index.is_none()
        }));
        assert!(
            trace
                .limitations
                .iter()
                .any(|limitation| limitation.contains("inserted images remain uncertain"))
        );
    }

    fn dependency(install_name: &str, command: &str) -> MachoDependency {
        MachoDependency {
            command: command.into(),
            encoding: "dylib_command".into(),
            install_name: install_name.into(),
            weak: command == "LC_LOAD_WEAK_DYLIB",
            upward: false,
            reexport: false,
            delayed_init: false,
            current_version: String::new(),
            compatibility_version: String::new(),
        }
    }

    fn trace(view: &View, roots: &[&str], architecture: Option<&str>) -> DylibTrace {
        let roots = roots
            .iter()
            .map(|root| (*root).to_owned())
            .collect::<Vec<_>>();
        trace_dylib_loading(
            view,
            DylibResolutionRequest {
                roots: &roots,
                unclassified: &[],
                architecture,
                cancelled: None,
            },
        )
        .expect("the in-memory tree view is infallible")
    }
}
