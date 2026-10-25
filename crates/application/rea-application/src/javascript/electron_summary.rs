//! Electron boundary summary owned by the completed JavaScript analysis.
//!
//! Compatibility owner: `src/application/javascript/ElectronBoundaryAnalysis.ts`.
//! This module only counts retained analysis facts and asks the artifact path
//! resolver about utility and native-addon targets; it never infers missing
//! findings from absent source data.

use std::collections::{HashMap, HashSet};

use super::graph::json::{Json, Obj};
use super::resolution::artifact_path::{
    ResolutionContext, ResolveInput, ResolverFile, ResolverFileText, RuntimePathKind,
    resolve_artifact_path,
};
use super::resolution::mode::ModuleResolutionMode;
use super::semantic::value_types::JsString;

/// Summarize the Electron findings retained in one completed analysis.
pub fn summarize_electron_boundaries(analysis: &Json, directory_paths: &HashSet<JsString>) -> Json {
    let files = analysis.at("files").arr();
    let file_lookup = resolver_files(files);
    let file_kinds = file_kinds(files);
    let javascript = files
        .iter()
        .filter(|entry| !entry.at("javascript").is_null())
        .map(|entry| entry.at("javascript"))
        .collect::<Vec<_>>();

    let windows = javascript
        .iter()
        .flat_map(|value| value.at("electron").at("browser_windows").arr());
    let bridges = javascript
        .iter()
        .flat_map(|value| value.at("electron").at("context_bridge_apis").arr());
    let validations = javascript
        .iter()
        .flat_map(|value| value.at("electron").at("sender_validations").arr());
    let utilities = files.iter().flat_map(|entry| {
        entry
            .at("javascript")
            .at("electron")
            .at("utility_processes")
            .arr()
            .iter()
            .map(move |finding| (entry.at("file"), finding))
    });
    let native_bindings = files.iter().flat_map(|entry| {
        entry
            .at("javascript")
            .at("electron")
            .at("native_addon_bindings")
            .arr()
            .iter()
            .map(move |finding| (entry.at("file"), finding))
    });

    let records = collect_ipc_records(files);
    let pairings = classify_pairings(&records);
    let literal_channels = records
        .iter()
        .filter_map(|record| record.finding.get("channel"))
        .filter(|channel| !channel.is_null())
        .map(Json::stringify)
        .collect::<HashSet<_>>();

    let utility_values = utilities.collect::<Vec<_>>();
    let native_values = native_bindings.collect::<Vec<_>>();
    let resolved_utilities = utility_values
        .iter()
        .filter(|(file, finding)| {
            let context = finding
                .get("module_resolution_context")
                .and_then(Json::as_str)
                .map(context_for)
                .unwrap_or(ResolutionContext::ModuleSpecifier);
            finding
                .get("module_path")
                .and_then(Json::as_js_string)
                .is_some_and(|specifier| {
                    resolves_to_file(
                        file,
                        specifier,
                        context,
                        RuntimePathKind::NodeEntrypoint,
                        None,
                        &file_lookup,
                        directory_paths,
                        &file_kinds,
                        None,
                    )
                })
        })
        .count();
    let resolved_native = native_values
        .iter()
        .filter(|(file, finding)| {
            let Some(specifier) = finding.get("specifier").and_then(Json::as_js_string) else {
                return false;
            };
            resolves_to_file(
                file,
                specifier,
                ResolutionContext::ModuleSpecifier,
                RuntimePathKind::ExactFile,
                finding
                    .get("module_kind")
                    .and_then(Json::as_str)
                    .and_then(module_mode),
                &file_lookup,
                directory_paths,
                &file_kinds,
                Some("native-addon"),
            )
        })
        .count();

    Obj::new()
        .with("browser_windows", windows.count())
        .with(
            "explicit_web_preferences",
            javascript
                .iter()
                .flat_map(|value| value.at("electron").at("browser_windows").arr())
                .map(|window| window.at("web_preferences").arr().len())
                .sum::<usize>(),
        )
        .with(
            "preload_entrypoints",
            javascript
                .iter()
                .flat_map(|value| value.at("electron").at("browser_windows").arr())
                .filter(|window| !window.at("preload_path").is_null())
                .count(),
        )
        .with("context_bridge_apis", bridges.count())
        .with(
            "exposed_api_members",
            javascript
                .iter()
                .flat_map(|value| value.at("electron").at("context_bridge_apis").arr())
                .map(|bridge| bridge.at("members").arr().len())
                .sum::<usize>(),
        )
        .with(
            "ipc",
            Obj::new()
                .with("operations", records.len())
                .with("literal_channels", literal_channels.len())
                .with(
                    "dynamic_channel_operations",
                    records
                        .iter()
                        .filter(|record| record.finding.at("channel").is_null())
                        .count(),
                )
                .with(
                    "renderer_transmissions",
                    records
                        .iter()
                        .filter(|record| is_renderer_transmission(record))
                        .count(),
                )
                .with(
                    "renderer_listeners",
                    records
                        .iter()
                        .filter(|record| {
                            record.finding.at("side").str() == "renderer"
                                && record.finding.at("mode").str() == "listen"
                        })
                        .count(),
                )
                .with(
                    "main_handlers",
                    records
                        .iter()
                        .filter(|record| is_main_handler(record))
                        .count(),
                )
                .with(
                    "paired_renderer_transmissions",
                    pairings
                        .iter()
                        .filter(|(_, candidates)| candidates.len() == 1)
                        .count(),
                )
                .with(
                    "ambiguous_renderer_transmissions",
                    pairings
                        .iter()
                        .filter(|(_, candidates)| candidates.len() > 1)
                        .count(),
                )
                .with(
                    "unpaired_literal_renderer_transmissions",
                    pairings
                        .iter()
                        .filter(|(record, candidates)| {
                            candidates.is_empty() && !record.finding.at("channel").is_null()
                        })
                        .count(),
                ),
        )
        .with("sender_validation_observations", validations.count())
        .with("utility_processes", utility_values.len())
        .with("resolved_utility_entrypoints", resolved_utilities)
        .with("native_addon_bindings", native_values.len())
        .with("resolved_native_addon_bindings", resolved_native)
        .into()
}

#[derive(Clone)]
struct IpcRecord {
    key: JsString,
    finding: Json,
}

fn collect_ipc_records(files: &[Json]) -> Vec<IpcRecord> {
    let mut records = files
        .iter()
        .flat_map(|entry| {
            let path = entry.at("file").at("path").text().clone();
            entry
                .at("javascript")
                .at("electron")
                .at("ipc")
                .arr()
                .iter()
                .map(move |finding| IpcRecord {
                    key: ipc_record_key(&path, finding),
                    finding: finding.clone(),
                })
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.key.compare_code_points(&right.key));
    records
}

fn ipc_record_key(path: &JsString, finding: &Json) -> JsString {
    let channel = match finding.get("channel").filter(|value| !value.is_null()) {
        Some(value) => value.text().clone(),
        None => finding.at("channel_expression").text().clone(),
    };
    let mut identity = JsString::join(
        [
            path.clone(),
            point_key(finding.at("location").at("start")),
            finding.at("side").text().clone(),
            finding.at("operation").text().clone(),
            channel,
            JsString::from(finding.at("handler_location").stringify()),
        ],
        "\0",
    );
    if let Some(location) = finding.get("invocation_location") {
        identity = identity
            .concat_str("\0")
            .concat(&point_key(location.at("start")));
    }
    identity
}

fn point_key(point: &Json) -> JsString {
    JsString::from(format!(
        "{}:{}",
        point.at("line").num(),
        point.at("column").num()
    ))
}

fn is_renderer_transmission(record: &IpcRecord) -> bool {
    record.finding.at("side").str() == "renderer"
        && matches!(record.finding.at("mode").str(), "send" | "invoke")
}

fn is_main_handler(record: &IpcRecord) -> bool {
    record.finding.at("side").str() == "main"
        && matches!(record.finding.at("mode").str(), "listen" | "handle")
}

fn compatible_modes(transmission: &Json, handler: &Json) -> bool {
    if transmission.at("mode").str() == "invoke" {
        handler.at("mode").str() == "handle"
    } else if transmission.at("operation").str() == "send-to-host" {
        false
    } else {
        transmission.at("mode").str() == "send" && handler.at("mode").str() == "listen"
    }
}

fn classify_pairings(records: &[IpcRecord]) -> Vec<(&IpcRecord, Vec<&IpcRecord>)> {
    let handlers = records
        .iter()
        .filter(|record| is_main_handler(record))
        .collect::<Vec<_>>();
    records
        .iter()
        .filter(|record| {
            is_renderer_transmission(record)
                && record.finding.at("operation").str() != "send-to-host"
        })
        .map(|transmission| {
            let candidates = if transmission.finding.at("channel").is_null() {
                Vec::new()
            } else {
                handlers
                    .iter()
                    .copied()
                    .filter(|handler| {
                        handler.finding.at("channel") == transmission.finding.at("channel")
                            && compatible_modes(&transmission.finding, &handler.finding)
                    })
                    .collect()
            };
            (transmission, candidates)
        })
        .collect()
}

fn resolver_files(files: &[Json]) -> HashMap<JsString, ResolverFile> {
    files
        .iter()
        .filter_map(|entry| {
            let file = entry.at("file");
            let path = file.at("path").as_js_string()?.clone();
            let text = file.at("text");
            let text = if text.at("included").as_bool() == Some(true) {
                text.at("value")
                    .as_js_string()
                    .and_then(|value| value.try_to_string().ok())
                    .map_or_else(
                        || ResolverFileText::Excluded("invalid-utf8".into()),
                        ResolverFileText::Included,
                    )
            } else {
                ResolverFileText::Excluded("outside-analysis-scope".into())
            };
            Some((
                path,
                ResolverFile {
                    container_sha256: file.at("container_sha256").str().into(),
                    text,
                },
            ))
        })
        .collect()
}

fn file_kinds(files: &[Json]) -> HashMap<JsString, String> {
    files
        .iter()
        .filter_map(|entry| {
            let file = entry.at("file");
            Some((
                file.at("path").as_js_string()?.clone(),
                file.at("kind").str().to_owned(),
            ))
        })
        .collect()
}

fn module_mode(value: &str) -> Option<ModuleResolutionMode> {
    match value {
        "import" => Some(ModuleResolutionMode::Import),
        "require" => Some(ModuleResolutionMode::Require),
        "compiler-dependent" => Some(ModuleResolutionMode::CompilerDependent),
        _ => None,
    }
}

fn context_for(value: &str) -> ResolutionContext {
    match value {
        "filesystem-expression" => ResolutionContext::FilesystemExpression,
        _ => ResolutionContext::ModuleSpecifier,
    }
}

fn resolve_path(
    file: &Json,
    specifier: &JsString,
    context: ResolutionContext,
    runtime_path_kind: RuntimePathKind,
    module_kind: Option<ModuleResolutionMode>,
    files: &HashMap<JsString, ResolverFile>,
    directory_paths: &HashSet<JsString>,
) -> Option<String> {
    let source_path = file.at("path").as_js_string()?.try_to_string().ok()?;
    let declared_path = specifier.try_to_string().ok()?;
    resolve_artifact_path(&ResolveInput {
        declared_path: &declared_path,
        source_path: &source_path,
        context,
        files,
        directory_paths: Some(directory_paths),
        unanalyzed_files: None,
        html_base_href: None,
        module_kind,
        runtime_path_kind: Some(runtime_path_kind),
    })
    .resolved_path
}

fn resolves_to_file(
    file: &Json,
    specifier: &JsString,
    context: ResolutionContext,
    runtime_path_kind: RuntimePathKind,
    module_kind: Option<ModuleResolutionMode>,
    files: &HashMap<JsString, ResolverFile>,
    directory_paths: &HashSet<JsString>,
    file_kinds: &HashMap<JsString, String>,
    expected_kind: Option<&str>,
) -> bool {
    resolve_path(
        file,
        specifier,
        context,
        runtime_path_kind,
        module_kind,
        files,
        directory_paths,
    )
    .is_some_and(|path| {
        file_kinds
            .get(&JsString::from(path))
            .is_some_and(|kind| expected_kind.is_none_or(|expected| kind == expected))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::javascript::graph::json::parse;

    fn position(line: usize, column: usize) -> Json {
        Obj::new().with("line", line).with("column", column).into()
    }

    fn ipc(line: usize, side: &str, mode: &str, operation: &str, channel: Json) -> Json {
        Obj::new()
            .with("location", Obj::new().with("start", position(line, 0)))
            .with("side", side)
            .with("mode", mode)
            .with("operation", operation)
            .with("channel", channel)
            .with("channel_expression", "channel")
            .with("handler_location", Json::Null)
            .into()
    }

    fn file(path: &str, kind: &str, javascript: Json) -> Json {
        Obj::new()
            .with(
                "file",
                Obj::new()
                    .with("path", path)
                    .with("kind", kind)
                    .with("container_sha256", "container")
                    .with("text", Obj::new().with("included", true).with("value", "")),
            )
            .with("javascript", javascript)
            .into()
    }

    fn fixture() -> Json {
        let surrogate_channel = Json::String(JsString::from_utf16(vec![0xd800]));
        let electron = Obj::new()
            .with(
                "browser_windows",
                vec![
                    Obj::new()
                        .with("web_preferences", vec![Json::Null, Json::Null])
                        .with("preload_path", "preload.js")
                        .into(),
                ],
            )
            .with(
                "context_bridge_apis",
                vec![
                    Obj::new()
                        .with("members", vec![Json::Null, Json::Null, Json::Null])
                        .into(),
                ],
            )
            .with("sender_validations", vec![Json::Null, Json::Null])
            .with(
                "utility_processes",
                vec![
                    Obj::new()
                        .with("module_path", "./worker.js")
                        .with("module_resolution_context", "module-specifier")
                        .into(),
                ],
            )
            .with(
                "native_addon_bindings",
                vec![
                    Obj::new()
                        .with("specifier", "./addon.node")
                        .with("module_kind", "require")
                        .into(),
                ],
            )
            .with(
                "ipc",
                vec![
                    ipc(1, "renderer", "send", "send", surrogate_channel.clone()),
                    ipc(2, "renderer", "invoke", "invoke", "invoke".into()),
                    ipc(3, "renderer", "invoke", "invoke", Json::Null),
                    ipc(4, "renderer", "send", "send-to-host", "host".into()),
                    ipc(5, "renderer", "send", "send", "solo".into()),
                    ipc(6, "main", "listen", "listen", surrogate_channel.clone()),
                    ipc(7, "main", "listen", "listen", surrogate_channel),
                    ipc(8, "main", "handle", "handle", "invoke".into()),
                ],
            );

        Obj::new()
            .with(
                "files",
                vec![
                    file(
                        "main.js",
                        "javascript",
                        Obj::new().with("electron", electron).into(),
                    ),
                    file(
                        "worker.js",
                        "javascript",
                        Obj::new().with("electron", Obj::new()).into(),
                    ),
                    file("addon.node", "native-addon", Json::Null),
                ],
            )
            .into()
    }

    #[test]
    fn summary_matches_completed_electron_facts_and_resolves_targets() {
        let summary = summarize_electron_boundaries(&fixture(), &HashSet::new());
        let expected = Obj::new()
            .with("browser_windows", 1usize)
            .with("explicit_web_preferences", 2usize)
            .with("preload_entrypoints", 1usize)
            .with("context_bridge_apis", 1usize)
            .with("exposed_api_members", 3usize)
            .with(
                "ipc",
                Obj::new()
                    .with("operations", 8usize)
                    .with("literal_channels", 4usize)
                    .with("dynamic_channel_operations", 1usize)
                    .with("renderer_transmissions", 5usize)
                    .with("renderer_listeners", 0usize)
                    .with("main_handlers", 3usize)
                    .with("paired_renderer_transmissions", 1usize)
                    .with("ambiguous_renderer_transmissions", 1usize)
                    .with("unpaired_literal_renderer_transmissions", 1usize),
            )
            .with("sender_validation_observations", 2usize)
            .with("utility_processes", 1usize)
            .with("resolved_utility_entrypoints", 1usize)
            .with("native_addon_bindings", 1usize)
            .with("resolved_native_addon_bindings", 1usize);

        assert_eq!(summary, Json::from(expected));
    }

    #[test]
    fn ipc_sorting_preserves_lone_surrogate_channel_identity() {
        let fixture = fixture();
        let files = fixture.at("files").arr();
        let records = collect_ipc_records(files);

        assert_eq!(records.len(), 8);
        assert!(records.iter().any(|record| {
            record
                .finding
                .at("channel")
                .as_js_string()
                .is_some_and(|channel| channel.units() == [0xd800])
        }));
    }

    #[test]
    fn utf16_graph_golden_uses_the_real_analysis_envelope() {
        let golden = parse(include_str!(
            "../../../../../../.cache/rust-migration/js-graph-golden/golden/utf16-boundary/raw/86464-0000-application-graph.json"
        ))
        .expect("the checked-in UTF-16 graph corpus must parse");
        let summary =
            summarize_electron_boundaries(golden.at("input").at("analysis"), &HashSet::new());

        let expected = Obj::new()
            .with("browser_windows", 0usize)
            .with("explicit_web_preferences", 0usize)
            .with("preload_entrypoints", 0usize)
            .with("context_bridge_apis", 1usize)
            .with("exposed_api_members", 1usize)
            .with(
                "ipc",
                Obj::new()
                    .with("operations", 2usize)
                    .with("literal_channels", 2usize)
                    .with("dynamic_channel_operations", 0usize)
                    .with("renderer_transmissions", 2usize)
                    .with("renderer_listeners", 0usize)
                    .with("main_handlers", 0usize)
                    .with("paired_renderer_transmissions", 0usize)
                    .with("ambiguous_renderer_transmissions", 0usize)
                    .with("unpaired_literal_renderer_transmissions", 2usize),
            )
            .with("sender_validation_observations", 0usize)
            .with("utility_processes", 0usize)
            .with("resolved_utility_entrypoints", 0usize)
            .with("native_addon_bindings", 0usize)
            .with("resolved_native_addon_bindings", 0usize);

        assert_eq!(summary, Json::from(expected));
        let channel = golden
            .at("input")
            .at("analysis")
            .at("files")
            .arr()
            .iter()
            .find_map(|entry| {
                entry
                    .at("javascript")
                    .at("electron")
                    .at("ipc")
                    .arr()
                    .first()
            })
            .and_then(|finding| finding.at("channel").as_js_string())
            .expect("the UTF-16 IPC channel is retained");
        assert_eq!(channel.units(), [0xd800]);
    }
}
