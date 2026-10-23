//! `createCatalogDigests` / `createCatalogIdentity`
//! (`src/catalogIdentity.ts`) ported over the frozen catalog
//! (`rea_mcp::catalog()`), digesting with `rea_core::canonical_json`
//! (RFC 8785, the native owner of canonical digests — equivalent to the TS
//! `canonicalize` package).
//!
//! The per-tool projection mirrors `createToolCatalog`: name, title,
//! surface (kind), description, effects, returns_target_content, annotations,
//! input_schema (full or compact profile) and output_schema (always present;
//! `output_schema_profile` labels the enclosing `tools` object). Prompts come
//! from the frozen catalog. The combined digest uses `CLI_COMMAND_NAMES` in
//! TS insertion order (copied below); the frozen `cli-commands.json` is sorted
//! alphabetically, which would change the order-sensitive combined digest.

use rea_core::canonical_json;
use serde_json::{Map, Value, json};
use std::sync::OnceLock;

/// `CLI_COMMAND_NAMES` = `Object.values(CLI_COMMANDS)` in declaration order
/// (`src/cliCommandNames.ts`). The frozen catalog exposes the same names
/// sorted alphabetically, so the order-sensitive combined digest requires the
/// TS insertion order reproduced here.
const CLI_COMMAND_NAMES_TS_ORDER: [&str; 157] = [
    "inspect-packet-fields",
    "inspect-packet-capture",
    "inspect-signal-decoders",
    "decode-signal-recording",
    "compare-wasm-interfaces",
    "inspect-wasm-artifact",
    "inspect-sqlite-database",
    "inspect-evm-interface",
    "inspect-web-network-capture",
    "observe-web-execution",
    "inspect-web-event-listeners",
    "trace-web-source-location",
    "trace-web-module-imports",
    "analyze",
    "inspect",
    "decompile",
    "setup",
    "doctor",
    "uninstall",
    "update",
    "xrefs",
    "trace",
    "trace-native-ui-action",
    "inspect-native-dispatch-metadata",
    "capabilities",
    "providers",
    "function",
    "annotate-native-function",
    "inspect-native-api",
    "instructions",
    "search",
    "import-reference-source",
    "inspect-artifact",
    "extract-artifact",
    "decode-interface-builder",
    "inspect-keyed-archive",
    "trace-dylib-resolution",
    "inspect-native-data-type",
    "inspect-native-load-image",
    "read-bytes",
    "search-bytes",
    "address-to-file-offset",
    "trace-native-values",
    "inspect-native-instruction",
    "resolve-native-call-targets",
    "inspect-asset-catalog",
    "inspect-managed-artifact",
    "inspect-recorded-crash",
    "inspect-binary-layout",
    "list-cutter-sessions",
    "cutter-command",
    "inspect-with-objdump",
    "list-objdump-architectures",
    "execute-rizin-command",
    "debug-with-gdb",
    "debug-with-rizin",
    "inspect-desktop-application",
    "inspect-go-binary",
    "inspect-il2cpp-metadata",
    "inspect-rust-binary",
    "inspect-pe-resources",
    "inspect-analysis-view",
    "list-frida-devices",
    "list-frida-processes",
    "instrument-with-frida",
    "inspect-evidence-bundle",
    "inspect-firmware-regions",
    "extract-firmware",
    "inspect-android-package",
    "inspect-pcap-client",
    "inspect-pcap-capture",
    "identify-flutter-build",
    "inspect-dart-aot",
    "inspect-apktool-client",
    "decode-android-resources",
    "inspect-adb-client",
    "list-adb-devices",
    "inspect-adb-device",
    "list-adb-packages",
    "pull-adb-package",
    "read-adb-logcat",
    "inspect-adb-package",
    "pull-adb-file",
    "push-adb-file",
    "capture-adb-screen",
    "list-adb-processes",
    "list-adb-directory",
    "list-adb-features",
    "list-adb-services",
    "inspect-adb-display",
    "inspect-adb-window",
    "read-adb-setting",
    "collect-adb-bugreport",
    "resolve-adb-packages",
    "install-adb-package",
    "uninstall-adb-package",
    "start-adb-app",
    "start-adb-activity",
    "stop-adb-app",
    "search-android-classes",
    "inspect-android-class",
    "inspect-android-method",
    "trace-android-references",
    "inspect-jeb-client",
    "open-jeb-project",
    "list-jeb-units",
    "decompile-jeb-item",
    "inspect-managed-members",
    "inspect-managed-native-boundaries",
    "compare-managed-members",
    "verify-managed-native-boundaries",
    "import-managed-reconstruction",
    "project-managed-application-graph",
    "observe-native-ui",
    "observe-native-calls",
    "capture-native-ui-scenario",
    "inspect-macho",
    "inspect-signature",
    "list-architectures",
    "inspect-plist",
    "demangle-swift",
    "evidence-import",
    "evidence-export",
    "environment-serve",
    "environment-export",
    "compare",
    "capture-process",
    "compare-process-captures",
    "list-browser-targets",
    "inspect-web-page",
    "analyze-web-bundle",
    "export-web-scripts",
    "recover-javascript-sources",
    "observe-web-session",
    "discover-webmcp-tools",
    "compare-web-captures",
    "capture-web-screenshot",
    "compare-web-screenshots",
    "capture-browser-scenario",
    "list-electron-targets",
    "inspect-electron-page",
    "inspect-electron-fuses",
    "capture-electron-scenario",
    "list-javascript-runtime-targets",
    "observe-javascript-runtime",
    "analyze-javascript-application",
    "reconcile-javascript-runtime",
    "trace-application-feature",
    "trace-javascript-semantics",
    "compare-application-versions",
    "compare-source-to-bundle",
    "compare-javascript-export-shapes",
    "build-reconstruction-obligation-ledger",
    "evaluate-reconstruction-coverage",
    "project-android-application-graph",
    "project-apple-application-graph",
    "project-harmony-application-graph",
];

/// Digests of the catalog for one presentation profile.
#[derive(Clone)]
pub(crate) struct CatalogDigests {
    pub tools_sha256: String,
    pub prompts_sha256: String,
    pub combined_sha256: String,
}

impl CatalogDigests {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "tools_sha256": self.tools_sha256,
            "prompts_sha256": self.prompts_sha256,
            "combined_sha256": self.combined_sha256,
        })
    }
}

/// Catalog counts (`createCatalogIdentity().counts`).
pub(crate) fn catalog_counts() -> Value {
    let catalog = rea_mcp::catalog();
    json!({
        "cli_commands": CLI_COMMAND_NAMES_TS_ORDER.len(),
        "mcp_tools": catalog.tools.len(),
        "mcp_prompts": catalog.prompts.len(),
    })
}

/// The per-tool digest projection (`createToolCatalog`), sorted by name in
/// Unicode code-point order.
fn tool_catalog(compact_input_schemas: bool) -> Vec<Value> {
    let catalog = rea_mcp::catalog();
    let mut tools: Vec<Value> = catalog
        .tools
        .iter()
        .map(|contract| {
            let advertised = &contract.advertised;
            let input_schema = if compact_input_schemas {
                rea_mcp::catalog::compact_input_schema(&contract.name)
                    .cloned()
                    .unwrap_or(Value::Null)
            } else {
                advertised
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or(Value::Null)
            };
            let mut object = Map::new();
            object.insert("name".to_owned(), Value::String(contract.name.clone()));
            object.insert(
                "title".to_owned(),
                advertised.get("title").cloned().unwrap_or(Value::Null),
            );
            object.insert("surface".to_owned(), Value::String(contract.kind.clone()));
            object.insert(
                "description".to_owned(),
                advertised
                    .get("description")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            object.insert("effects".to_owned(), contract.effects.clone());
            object.insert(
                "returns_target_content".to_owned(),
                Value::Bool(contract.returns_target_content),
            );
            object.insert(
                "annotations".to_owned(),
                advertised
                    .get("annotations")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            object.insert("input_schema".to_owned(), input_schema);
            object.insert(
                "output_schema".to_owned(),
                advertised
                    .get("outputSchema")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            Value::Object(object)
        })
        .collect();

    tools.sort_by(|left, right| {
        super::inventory::compare_unicode_code_points(
            left["name"].as_str().unwrap_or(""),
            right["name"].as_str().unwrap_or(""),
        )
    });
    tools
}

/// The prompt digest projection (`createPromptCatalog`), sorted by name.
fn prompt_catalog() -> Vec<Value> {
    let catalog = rea_mcp::catalog();
    let mut prompts: Vec<Value> = catalog
        .prompts
        .iter()
        .map(|prompt| {
            json!({
                "name": prompt.name,
                "title": prompt.title,
                "description": prompt.description,
                "objective": prompt.objective,
                "arguments": prompt_arguments(prompt),
                "steps": prompt_steps(prompt),
            })
        })
        .collect();
    prompts.sort_by(|left, right| {
        super::inventory::compare_unicode_code_points(
            left["name"].as_str().unwrap_or(""),
            right["name"].as_str().unwrap_or(""),
        )
    });
    prompts
}

/// `contract.arguments`: an object keyed by argument name, preserving the
/// frozen contract's description/required/completion fields.
fn prompt_arguments(prompt: &rea_mcp::catalog::PromptContract) -> Value {
    let mut map = Map::new();
    for argument in &prompt.arguments {
        let mut entry = Map::new();
        entry.insert(
            "description".to_owned(),
            Value::String(argument.description.clone()),
        );
        entry.insert("required".to_owned(), Value::Bool(argument.required));
        if let Some(completion) = &argument.completion {
            entry.insert("completion".to_owned(), Value::String(completion.clone()));
        }
        map.insert(argument.name.clone(), Value::Object(entry));
    }
    Value::Object(map)
}

/// `contract.steps`: an ordered list of `{ tools, instruction }`.
fn prompt_steps(prompt: &rea_mcp::catalog::PromptContract) -> Value {
    Value::Array(
        prompt
            .steps
            .iter()
            .map(|step| {
                json!({
                    "tools": step.tools,
                    "instruction": step.instruction,
                })
            })
            .collect(),
    )
}

fn digest(value: &Value) -> String {
    canonical_json::digest(value).expect("catalog projection is canonical JSON")
}

/// `createCatalogDigests` for one profile.
///
/// `output_schema_profile` is `"full"` when output schemas are included,
/// `"off"` otherwise; it only labels the enclosing `tools` object (the per-tool
/// `output_schema` field is always present, matching TS `createToolCatalog`).
fn compute_digests(compact_input_schemas: bool, include_output_schemas: bool) -> CatalogDigests {
    let output_schema_profile = if include_output_schemas {
        "full"
    } else {
        "off"
    };
    let tools = json!({
        "output_schema_profile": output_schema_profile,
        "catalog": tool_catalog(compact_input_schemas),
    });
    let prompts = Value::Array(prompt_catalog());
    let cli: Vec<Value> = CLI_COMMAND_NAMES_TS_ORDER
        .iter()
        .map(|name| Value::String((*name).to_owned()))
        .collect();

    let tools_sha256 = digest(&tools);
    let prompts_sha256 = digest(&prompts);
    let combined_sha256 = digest(&json!({
        "cli": cli,
        "tools": tools,
        "prompts": prompts,
    }));

    CatalogDigests {
        tools_sha256,
        prompts_sha256,
        combined_sha256,
    }
}

/// Catalog digests for one presentation profile, cached per profile so the
/// canonicalization cost is paid once (TS records the default digests once).
pub(crate) fn catalog_digests(
    compact_input_schemas: bool,
    include_output_schemas: bool,
) -> CatalogDigests {
    // Four profile combinations: (compact?, output?).
    static CACHE: [OnceLock<CatalogDigests>; 4] = [
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
    ];
    let index = (usize::from(compact_input_schemas) << 1) | usize::from(include_output_schemas);
    CACHE[index]
        .get_or_init(|| compute_digests(compact_input_schemas, include_output_schemas))
        .clone()
}
