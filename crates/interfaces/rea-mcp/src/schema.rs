//! MCP-facing adapter for shared schema validation facts.
//!
//! The parser lives in `rea_core::schema`; this module preserves the public
//! SDK-shaped issue strings required by the MCP and CLI adapters.
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::canonical_json::digest_bytes;
use rea_core::digests::{EVIDENCE_ID, JS_RUNTIME_GRAPH_NODE_ID, UNKNOWN_ID};
use rea_core::schema::{
    AbsolutePathMessage, AtLeastOneFields, DefaultField, DefaultValue, ExactlyOneArrayItemValue,
    ExactlyOneFields, FieldPatternMessage, Issue as TypedIssue, IssueKind, MinimumMessage, Parser,
    PatternMessage, SchemaMetadata, UnknownKeys, diagnose_with_metadata, resolve_schema,
    validate_with_metadata,
};
use serde_json::{Map, Value};

const SOURCE_DIGEST_CONTRACTS: &[rea_core::digests::PrefixedDigestContract] = &[EVIDENCE_ID];
const UNKNOWN_DIGEST_CONTRACTS: &[rea_core::digests::PrefixedDigestContract] = &[UNKNOWN_ID];
const JS_RUNTIME_DIGEST_CONTRACTS: &[rea_core::digests::PrefixedDigestContract] =
    &[EVIDENCE_ID, JS_RUNTIME_GRAPH_NODE_ID];
const TRACE_DEFAULTS: &[DefaultField] = &[
    DefaultField {
        path: &["native_observations"],
        value: DefaultValue::EmptyArray,
    },
    DefaultField {
        path: &["direction"],
        value: DefaultValue::String("both"),
    },
];
const COMPARE_DEFAULTS: &[DefaultField] = &[
    DefaultField {
        path: &["left_native_observations"],
        value: DefaultValue::EmptyArray,
    },
    DefaultField {
        path: &["right_native_observations"],
        value: DefaultValue::EmptyArray,
    },
];
const MANAGED_GRAPH_REQUIREMENT: &[AtLeastOneFields] = &[AtLeastOneFields {
    fields: &[
        "managed_artifact",
        "managed_members",
        "managed_native_boundaries",
    ],
    message: "Invalid input",
}];
const RECONCILIATION_REQUIREMENTS: &[ExactlyOneArrayItemValue] = &[ExactlyOneArrayItemValue {
    array_field: "static_layers",
    item_field: "role",
    value: "application",
    message: "Exactly one application static layer is required",
}];
const ADB_PATTERN_MESSAGES: &[PatternMessage] = &[
    PatternMessage {
        pattern: r##"^[^\x00\s"']+$"##,
        message: "Device serial cannot contain whitespace or quotes",
    },
    PatternMessage {
        pattern: r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$",
        message: "Package name must be dot-separated Java identifiers",
    },
    PatternMessage {
        pattern: r##"^\/[^\x00]*$"##,
        message: "Device path must be absolute",
    },
    PatternMessage {
        pattern: r##"^[A-Za-z][A-Za-z0-9._\x2d]*$"##,
        message: "Intent action must be a dotted identifier such as android.intent.action.VIEW",
    },
    PatternMessage {
        pattern: r##"^[^\x00\s]+$"##,
        message: "Data URI cannot contain whitespace or NUL",
    },
    PatternMessage {
        pattern: r##"^[A-Za-z0-9._\x2d]+$"##,
        message: "Extra keys are identifiers",
    },
];
const ADB_SETTING_PATTERN_MESSAGES: &[FieldPatternMessage] = &[
    FieldPatternMessage {
        path: &["key"],
        pattern: r##"^[A-Za-z0-9._\x2d]+$"##,
        message: "Setting keys are restricted to identifiers",
    },
    FieldPatternMessage {
        path: &["serial"],
        pattern: r##"^[^\x00\s"']+$"##,
        message: "Device serial cannot contain whitespace or quotes",
    },
];
const ANDROID_PATTERN_MESSAGES: &[PatternMessage] = &[PatternMessage {
    pattern: r##"^(?:[a-z]{2,3}(?:-(?:r?[A-Z]{2}|[0-9]{3}))?|b\+[a-z]{2,3}(?:\+[A-Za-z0-9]{2,8})*)$"##,
    message: "Locale must look like de, pt-BR, pt-rBR, es-419, or b+zh+Hans+CN",
}];
const NATIVE_CALL_PATTERN_MESSAGES: &[PatternMessage] = &[PatternMessage {
    pattern: r##"^[^\s\x5b\x5d]+$"##,
    message: "Use the bare name without spaces or brackets",
}];
const MANAGED_PATH_MESSAGES: &[FieldPatternMessage] = &[FieldPatternMessage {
    path: &["path"],
    pattern: r##"^[^\x00]*$"##,
    message: "path must be an absolute local filesystem path (for example /tmp/Example.dll or C:\\Example.dll)",
}];
const FIRMWARE_REGION_PATH_MESSAGES: &[FieldPatternMessage] = &[FieldPatternMessage {
    path: &["path"],
    pattern: r##"^[^\x00]*$"##,
    message: "path must be an absolute local filesystem path (for example /tmp/firmware.bin or C:\\firmware\\firmware.bin)",
}];
const FIRMWARE_PATH_MESSAGES: &[FieldPatternMessage] = &[
    FieldPatternMessage {
        path: &["path"],
        pattern: r##"^[^\x00]*$"##,
        message: "path must be an absolute local filesystem path (for example /tmp/firmware.bin or C:\\firmware\\firmware.bin)",
    },
    FieldPatternMessage {
        path: &["output_directory"],
        pattern: r##"^[^\x00]*$"##,
        message: "output_directory must be an absolute local filesystem path",
    },
];
const DART_ABI_MESSAGES: &[FieldPatternMessage] = &[FieldPatternMessage {
    path: &["abi"],
    pattern: r##"^[^\/]*$"##,
    message: "ABI must be the exact lib/ directory label: 1–1010 Unicode characters without '/'.",
}];
const DART_ABI_MINIMUM_MESSAGES: &[MinimumMessage] = &[MinimumMessage {
    path: &["abi"],
    message: "ABI must be the exact lib/ directory label: 1–1010 Unicode characters without '/'.",
}];
const DYLIB_ROOT_MESSAGES: &[FieldPatternMessage] = &[FieldPatternMessage {
    path: &["roots", "*"],
    pattern: r##"^(?:[^\x2f\\\x00.][^\x2f\\\x00]*|\.[^\x2f\\\x00.][^\x2f\\\x00]*|\.\.[^\x2f\\\x00]+)(?:\x2f(?:[^\x2f\\\x00.][^\x2f\\\x00]*|\.[^\x2f\\\x00.][^\x2f\\\x00]*|\.\.[^\x2f\\\x00]+))*$"##,
    message: "Use a normalized path relative to the analyzed root, without a leading or trailing '/', '//', or '.' and '..' segments",
}];
const MANAGED_ABSOLUTE_PATHS: &[AbsolutePathMessage] = &[AbsolutePathMessage {
    path: &["path"],
    message: "path must be an absolute local filesystem path (for example /tmp/Example.dll or C:\\Example.dll)",
}];
const FIRMWARE_REGION_ABSOLUTE_PATHS: &[AbsolutePathMessage] = &[AbsolutePathMessage {
    path: &["path"],
    message: "path must be an absolute local filesystem path (for example /tmp/firmware.bin or C:\\firmware\\firmware.bin)",
}];
const FIRMWARE_ABSOLUTE_PATHS: &[AbsolutePathMessage] = &[
    AbsolutePathMessage {
        path: &["path"],
        message: "path must be an absolute local filesystem path (for example /tmp/firmware.bin or C:\\firmware\\firmware.bin)",
    },
    AbsolutePathMessage {
        path: &["output_directory"],
        message: "output_directory must be an absolute local filesystem path",
    },
];
const OPEN_BINARY_ABSOLUTE_PATHS: &[AbsolutePathMessage] = &[AbsolutePathMessage {
    path: &["path"],
    message: "path must be an absolute local filesystem path (for example /tmp/fixture.bin or C:\\analysis\\fixture.bin)",
}];
const EXPORT_EVIDENCE_ABSOLUTE_PATHS: &[AbsolutePathMessage] = &[AbsolutePathMessage {
    path: &["path"],
    message: "path must be an absolute local filesystem path (for example /tmp/rea/evidence.json or C:\\rea\\evidence.json)",
}];
const IMPORT_EVIDENCE_ABSOLUTE_PATHS: &[AbsolutePathMessage] = &[AbsolutePathMessage {
    path: &["path"],
    message: "path must be an absolute local filesystem path (for example /tmp/evidence.json or C:\\rea\\evidence.json)",
}];
const BROWSER_EXECUTABLE_ABSOLUTE_PATHS: &[AbsolutePathMessage] = &[AbsolutePathMessage {
    path: &["browser", "executable_path"],
    message: "executable_path must be an absolute local filesystem path (for example /opt/chromium/chrome or C:\\chromium\\chrome.exe)",
}];
const ELECTRON_ABSOLUTE_PATHS: &[AbsolutePathMessage] = &[
    AbsolutePathMessage {
        path: &["executable_path"],
        message: "Electron executable, application, and root paths must be absolute local filesystem paths (for example /Applications/Electron.app/Contents/MacOS/Electron)",
    },
    AbsolutePathMessage {
        path: &["application_path"],
        message: "Electron executable, application, and root paths must be absolute local filesystem paths (for example /Applications/Electron.app/Contents/MacOS/Electron)",
    },
];
const FRIDA_DEVICE_REQUIREMENT: &[AtLeastOneFields] = &[AtLeastOneFields {
    fields: &["device_id", "remote"],
    message: "Select a device_id or a remote endpoint",
}];
const NATIVE_DATA_TYPE_REQUIREMENT: &[ExactlyOneFields] = &[ExactlyOneFields {
    fields: &["type", "address"],
    message: "Supply exactly one of type or address",
}];
const BROWSER_DEFAULTS: &[DefaultField] = &[DefaultField {
    path: &["allowed_origins"],
    value: DefaultValue::EmptyArray,
}];
const ADB_PATTERN_TOOLS: &[&str] = &[
    "pull_adb_package",
    "inspect_adb_package",
    "uninstall_adb_package",
    "start_adb_app",
    "stop_adb_app",
    "pull_adb_file",
    "push_adb_file",
    "list_adb_directory",
    "read_adb_setting",
    "capture_adb_screen",
    "inspect_adb_device",
    "list_adb_packages",
    "read_adb_logcat",
    "list_adb_processes",
    "list_adb_features",
    "list_adb_services",
    "inspect_adb_display",
    "inspect_adb_window",
    "collect_adb_bugreport",
    "resolve_adb_packages",
    "start_adb_activity",
    "install_adb_package",
];
const ANALYZE_WEB_BUNDLE_REQUIRED_TRUE_FIELDS: &[&str] = &["include_script_sources"];
const EVIDENCE_DIGEST_TOOLS: &[&str] = &[
    "build_call_path",
    "compare_artifacts",
    "compare_functions",
    "compare_javascript_export_shapes",
    "compare_managed_members",
    "compare_process_captures",
    "compare_source_to_bundle",
    "correlate_static_and_runtime",
    "find_changed_behavior",
    "import_managed_reconstruction",
    "project_apple_application_graph",
    "project_android_application_graph",
    "project_harmony_application_graph",
    "project_managed_application_graph",
    "reconcile_javascript_runtime",
    "trace_javascript_semantics",
    "verify_managed_native_boundaries",
    "verify_reconstruction",
];

fn named_contract_metadata(tool: &str) -> SchemaMetadata {
    let prefixed_digests = if EVIDENCE_DIGEST_TOOLS.contains(&tool) {
        SOURCE_DIGEST_CONTRACTS
    } else {
        &[]
    };
    let pattern_messages = if ADB_PATTERN_TOOLS.contains(&tool) {
        ADB_PATTERN_MESSAGES
    } else if tool == "decode_android_resources" {
        ANDROID_PATTERN_MESSAGES
    } else if tool == "observe_native_calls" {
        NATIVE_CALL_PATTERN_MESSAGES
    } else {
        &[]
    };

    match tool {
        "inspect_analysis_view" => SchemaMetadata {
            prefixed_digests: SOURCE_DIGEST_CONTRACTS,
            ..SchemaMetadata::default()
        },
        "trace_application_feature" => SchemaMetadata {
            prefixed_digests: SOURCE_DIGEST_CONTRACTS,
            defaults: TRACE_DEFAULTS,
            ..SchemaMetadata::default()
        },
        "compare_application_versions" => SchemaMetadata {
            prefixed_digests: SOURCE_DIGEST_CONTRACTS,
            defaults: COMPARE_DEFAULTS,
            ..SchemaMetadata::default()
        },
        "project_managed_application_graph" => SchemaMetadata {
            prefixed_digests,
            at_least_one_fields: MANAGED_GRAPH_REQUIREMENT,
            ..SchemaMetadata::default()
        },
        "reconcile_javascript_runtime" => SchemaMetadata {
            prefixed_digests,
            exactly_one_array_item_values: RECONCILIATION_REQUIREMENTS,
            pattern_messages,
            ..SchemaMetadata::default()
        },
        "analyze_web_bundle" => SchemaMetadata {
            prefixed_digests,
            pattern_messages,
            required_true_fields: ANALYZE_WEB_BUNDLE_REQUIRED_TRUE_FIELDS,
            defaults: BROWSER_DEFAULTS,
            ..SchemaMetadata::default()
        },
        "inspect_web_page"
        | "observe_web_session"
        | "discover_webmcp_tools"
        | "capture_web_screenshot"
        | "inspect_web_event_listeners"
        | "list_browser_targets" => SchemaMetadata {
            defaults: BROWSER_DEFAULTS,
            ..SchemaMetadata::default()
        },
        "observe_web_execution" => SchemaMetadata {
            defaults: BROWSER_DEFAULTS,
            ..SchemaMetadata::default()
        },
        "update_unknown" | "verify_unknown_resolution" => SchemaMetadata {
            prefixed_digests: UNKNOWN_DIGEST_CONTRACTS,
            pattern_messages,
            ..SchemaMetadata::default()
        },
        "trace_javascript_semantics" => SchemaMetadata {
            prefixed_digests: JS_RUNTIME_DIGEST_CONTRACTS,
            pattern_messages,
            ..SchemaMetadata::default()
        },
        "inspect_managed_artifact" | "inspect_managed_members" => SchemaMetadata {
            field_pattern_messages: MANAGED_PATH_MESSAGES,
            absolute_path_messages: MANAGED_ABSOLUTE_PATHS,
            ..SchemaMetadata::default()
        },
        "inspect_firmware_regions" => SchemaMetadata {
            field_pattern_messages: FIRMWARE_REGION_PATH_MESSAGES,
            absolute_path_messages: FIRMWARE_REGION_ABSOLUTE_PATHS,
            ..SchemaMetadata::default()
        },
        "extract_firmware" => SchemaMetadata {
            field_pattern_messages: FIRMWARE_PATH_MESSAGES,
            absolute_path_messages: FIRMWARE_ABSOLUTE_PATHS,
            ..SchemaMetadata::default()
        },
        "inspect_dart_aot" => SchemaMetadata {
            field_pattern_messages: DART_ABI_MESSAGES,
            minimum_messages: DART_ABI_MINIMUM_MESSAGES,
            ..SchemaMetadata::default()
        },
        "open_binary" => SchemaMetadata {
            absolute_path_messages: OPEN_BINARY_ABSOLUTE_PATHS,
            ..SchemaMetadata::default()
        },
        "export_evidence_bundle" => SchemaMetadata {
            absolute_path_messages: EXPORT_EVIDENCE_ABSOLUTE_PATHS,
            ..SchemaMetadata::default()
        },
        "import_evidence_bundle" => SchemaMetadata {
            absolute_path_messages: IMPORT_EVIDENCE_ABSOLUTE_PATHS,
            ..SchemaMetadata::default()
        },
        "capture_browser_scenario" => SchemaMetadata {
            absolute_path_messages: BROWSER_EXECUTABLE_ABSOLUTE_PATHS,
            defaults: &[DefaultField {
                path: &["storage"],
                value: DefaultValue::BrowserStorage,
            }],
            ..SchemaMetadata::default()
        },
        "capture_electron_scenario" => SchemaMetadata {
            absolute_path_messages: ELECTRON_ABSOLUTE_PATHS,
            ..SchemaMetadata::default()
        },
        "list_frida_processes" => SchemaMetadata {
            at_least_one_fields: FRIDA_DEVICE_REQUIREMENT,
            ..SchemaMetadata::default()
        },
        "inspect_native_data_type" => SchemaMetadata {
            exactly_one_fields: NATIVE_DATA_TYPE_REQUIREMENT,
            ..SchemaMetadata::default()
        },
        "read_adb_setting" => SchemaMetadata {
            field_pattern_messages: ADB_SETTING_PATTERN_MESSAGES,
            ..SchemaMetadata::default()
        },
        "trace_dylib_resolution" => SchemaMetadata {
            field_pattern_messages: DYLIB_ROOT_MESSAGES,
            ..SchemaMetadata::default()
        },
        _ => SchemaMetadata {
            prefixed_digests,
            pattern_messages,
            ..SchemaMetadata::default()
        },
    }
}

const PASSIVE_CAPTURE_FIELDS: &[&str] = &["before", "after"];
const SCENARIO_CAPTURE_FIELDS: &[&str] = &["before_scenario", "after_scenario", "normalization"];

/// The source contract is a strict union whose branch schemas were flattened
/// by catalog generation. Rebuild only this named contract's two branches
/// from the catalog-owned properties before rendering the source union error.
fn compare_web_capture_branch_schema(schema: &Value, fields: &[&str], required: &[&str]) -> Value {
    let mut branch = schema.clone();
    let Some(object) = branch.as_object_mut() else {
        return branch;
    };

    let properties = object
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| {
            fields
                .iter()
                .filter_map(|field| {
                    properties
                        .get(*field)
                        .map(|schema| ((*field).to_owned(), schema.clone()))
                })
                .collect()
        })
        .unwrap_or_default();
    object.insert("properties".into(), Value::Object(properties));
    object.insert(
        "required".into(),
        Value::Array(
            required
                .iter()
                .map(|field| Value::String((*field).to_owned()))
                .collect(),
        ),
    );
    object.remove("minProperties");
    branch
}

fn restore_scenario_completeness_discriminators(branch: &mut Value) {
    let Some(properties) = branch.get_mut("properties").and_then(Value::as_object_mut) else {
        return;
    };

    for capture_name in ["before_scenario", "after_scenario"] {
        let Some(capture) = properties
            .get_mut(capture_name)
            .and_then(Value::as_object_mut)
        else {
            continue;
        };

        let Some(capture_properties) = capture.get_mut("properties").and_then(Value::as_object_mut)
        else {
            continue;
        };

        if let Some(completeness) = capture_properties
            .get_mut("completeness")
            .and_then(Value::as_object_mut)
        {
            restore_completeness_literals(completeness);
        }
        if let Some(step_options) = capture_properties
            .get_mut("steps")
            .and_then(Value::as_object_mut)
            .and_then(|steps| steps.get_mut("items"))
            .and_then(Value::as_object_mut)
            .and_then(|steps| steps.get_mut("anyOf"))
            .and_then(Value::as_array_mut)
        {
            for step_option in step_options {
                if let Some(step_completeness) = step_option
                    .get_mut("properties")
                    .and_then(Value::as_object_mut)
                    .and_then(|step_properties| step_properties.get_mut("completeness"))
                    .and_then(Value::as_object_mut)
                {
                    restore_completeness_literals(step_completeness);
                }
            }
        }
    }
}

fn restore_completeness_literals(completeness: &mut serde_json::Map<String, Value>) {
    if let Some(options) = completeness.remove("anyOf") {
        completeness.insert("oneOf".into(), options);
    }
    let Some(options) = completeness.get_mut("oneOf").and_then(Value::as_array_mut) else {
        return;
    };
    for (index, option) in options.iter_mut().enumerate() {
        let expected = index == 0;
        let Some(equality_eligible) = option
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .and_then(|properties| properties.get_mut("equality_eligible"))
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        equality_eligible.remove("type");
        equality_eligible.insert("const".into(), Value::Bool(expected));
    }
}

fn pretty_union_issue(issue: &Issue) -> String {
    if issue.path.is_empty() {
        format!("✖ {}", issue.message)
    } else {
        format!("✖ {}\n  → at {}", issue.message, zod_dot_path(&issue.path))
    }
}

fn zod_dot_path(path: &[String]) -> String {
    let mut rendered = String::new();
    for segment in path {
        if segment.chars().all(|character| character.is_ascii_digit()) {
            rendered.push_str(&format!("[{segment}]"));
        } else if segment.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '$'
        }) {
            if !rendered.is_empty() {
                rendered.push('.');
            }
            rendered.push_str(segment);
        } else {
            rendered.push('[');
            rendered.push_str(&serde_json::to_string(segment).unwrap_or_default());
            rendered.push(']');
        }
    }
    rendered
}

fn source_issue_order(issues: &mut [Issue]) {
    issues.sort_by_key(|issue| issue.path.len());
}

fn append_scenario_refinement_issue(
    issues: &mut Vec<TypedIssue>,
    prefix: &str,
    path: &[&str],
    message: &str,
) {
    let mut issue_path = vec![Value::String(prefix.to_owned())];
    issue_path.extend(path.iter().map(|part| Value::String((*part).to_owned())));
    issues.push(TypedIssue {
        path: issue_path,
        kind: IssueKind::Custom {
            message: message.to_owned(),
        },
        aborts: false,
    });
}

fn append_scenario_refinements(capture: &Value, prefix: &str, issues: &mut Vec<TypedIssue>) {
    let Some(capture) = capture.as_object() else {
        return;
    };
    let Some(action_count) = capture
        .get("scenario")
        .and_then(Value::as_object)
        .and_then(|scenario| scenario.get("action_count"))
        .and_then(Value::as_i64)
    else {
        return;
    };
    let Some(steps) = capture.get("steps").and_then(Value::as_array) else {
        return;
    };

    if action_count.checked_add(1) != Some(steps.len() as i64) {
        append_scenario_refinement_issue(
            issues,
            prefix,
            &["steps"],
            "Capture must include initial state and one entry per action",
        );
    }

    if steps.iter().enumerate().any(|(offset, step)| {
        step.get("step_index")
            .and_then(Value::as_i64)
            .is_none_or(|index| index != offset as i64)
    }) {
        append_scenario_refinement_issue(
            issues,
            prefix,
            &["steps"],
            "Step indices must be contiguous from zero",
        );
    }

    let Some(events) = capture.get("events").and_then(Value::as_object) else {
        return;
    };
    let Some(items) = events.get("items").and_then(Value::as_array) else {
        return;
    };
    if events.get("retained").and_then(Value::as_i64) != Some(items.len() as i64) {
        append_scenario_refinement_issue(
            issues,
            prefix,
            &["events", "retained"],
            "Retained event count must equal items length",
        );
    }
    let omitted_count = events
        .get("omissions")
        .and_then(Value::as_object)
        .and_then(|omissions| omissions.get("by_kind"))
        .and_then(Value::as_array)
        .map(|omissions| {
            omissions
                .iter()
                .filter_map(|omission| omission.get("count").and_then(Value::as_i64))
                .sum::<i64>()
        });
    if omitted_count.is_some() && omitted_count != events.get("dropped").and_then(Value::as_i64) {
        append_scenario_refinement_issue(
            issues,
            prefix,
            &["events", "omissions", "by_kind"],
            "Per-kind omission counts must equal the dropped event count",
        );
    }
}

fn validate_compare_web_captures(schema: &Value, value: &Value) -> Result<Value, Vec<Issue>> {
    let passive_schema =
        compare_web_capture_branch_schema(schema, PASSIVE_CAPTURE_FIELDS, PASSIVE_CAPTURE_FIELDS);
    let (passive_parsed, passive_typed_issues) =
        diagnose_with_metadata(&passive_schema, value, SchemaMetadata::default());
    if passive_typed_issues.is_empty() {
        return Ok(passive_parsed.unwrap_or(Value::Null));
    }

    let mut scenario_schema = compare_web_capture_branch_schema(
        schema,
        SCENARIO_CAPTURE_FIELDS,
        &SCENARIO_CAPTURE_FIELDS[..2],
    );
    restore_scenario_completeness_discriminators(&mut scenario_schema);
    let (scenario_parsed, scenario_typed_issues) =
        diagnose_with_metadata(&scenario_schema, value, SchemaMetadata::default());
    let mut scenario_typed_issues = scenario_typed_issues;
    if !scenario_typed_issues.iter().any(|issue| issue.aborts) {
        for capture_name in ["before_scenario", "after_scenario"] {
            if let Some(capture) = value.get(capture_name) {
                append_scenario_refinements(capture, capture_name, &mut scenario_typed_issues);
            }
        }
    }
    if scenario_typed_issues.is_empty() {
        return Ok(scenario_parsed.unwrap_or(Value::Null));
    }

    let passive_continuable = passive_typed_issues.iter().all(|issue| !issue.aborts);
    let scenario_continuable = scenario_typed_issues.iter().all(|issue| !issue.aborts);
    match (passive_continuable, scenario_continuable) {
        (true, false) => {
            return Err(typed_issues_to_public(passive_typed_issues, value));
        }
        (false, true) => {
            return Err(typed_issues_to_public(scenario_typed_issues, value));
        }
        _ => {}
    }

    let passive_issues = typed_issues_to_public(passive_typed_issues, value);
    let scenario_issues = typed_issues_to_public(scenario_typed_issues, value);

    let mut all_issues = passive_issues;
    all_issues.extend(scenario_issues);
    source_issue_order(&mut all_issues);
    let message = all_issues
        .iter()
        .map(pretty_union_issue)
        .collect::<Vec<_>>()
        .join("\n");
    Err(vec![Issue {
        path: Vec::new(),
        message,
    }])
}

/// One rejected argument location and rendered SDK message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    pub path: Vec<String>,
    pub message: String,
}

impl Issue {
    fn from_typed(issue: TypedIssue, input: &Value) -> Self {
        Self {
            path: issue
                .path
                .iter()
                .map(|part| match part {
                    Value::String(value) => value.clone(),
                    other => other.to_string(),
                })
                .collect(),
            message: render_kind(&issue.kind, &issue.path, input),
        }
    }

    /// SDK issue formatting: `path.joined: message` or the bare message.
    pub fn render(&self) -> String {
        if self.path.is_empty() {
            self.message.clone()
        } else {
            format!("{}: {}", self.path.join("."), self.message)
        }
    }
}

fn value_at_path<'a>(input: &'a Value, path: &[Value]) -> Option<&'a Value> {
    let mut current = input;
    for part in path {
        current = match (current, part) {
            (Value::Object(object), Value::String(key)) => object.get(key)?,
            (Value::Array(items), Value::Number(index)) => {
                items.get(usize::try_from(index.as_u64()?).ok()?)?
            }
            _ => return None,
        };
    }
    Some(current)
}

fn safe_expected(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::String(_) | Value::Number(_) | Value::Bool(_)
    )
}

fn input_issue(path: Vec<Value>, reason: &'static str) -> InputIssue {
    InputIssue {
        path,
        reason,
        message: None,
        expected: None,
        minimum: None,
        maximum: None,
    }
}

fn project_typed_issue(issue: &TypedIssue, input: &Value, output: &mut Vec<InputIssue>) {
    let path = issue.path.clone();

    match &issue.kind {
        IssueKind::InvalidUnion { errors, options } => {
            if errors.is_empty() {
                let mut projected = input_issue(
                    path.clone(),
                    if value_at_path(input, &path).is_none() {
                        "missing_argument"
                    } else {
                        "invalid_value"
                    },
                );
                if let Some(options) = options {
                    let mut expected = Vec::new();
                    for value in options.iter().filter(|value| safe_expected(value)) {
                        if !expected.contains(value) {
                            expected.push(value.clone());
                        }
                    }
                    projected.expected = Some(Value::Array(expected));
                }
                output.push(projected);
                return;
            }

            let mut flattened = Vec::new();
            for branch in errors {
                for branch_issue in branch {
                    project_typed_issue(branch_issue, input, &mut flattened);
                }
            }
            let mut seen = std::collections::HashSet::new();
            for projected in flattened {
                let key = format!("{:?}", projected);
                if seen.insert(key) {
                    output.push(projected);
                }
            }
        }
        IssueKind::UnrecognizedKeys { keys } => {
            for key in keys {
                let mut key_path = path.clone();
                key_path.push(Value::String(key.clone()));
                output.push(input_issue(key_path, "unknown_argument"));
            }
        }
        IssueKind::InvalidType { expected } => {
            let mut projected = input_issue(
                path,
                if value_at_path(input, &issue.path).is_none() {
                    "missing_argument"
                } else {
                    "invalid_type"
                },
            );
            projected.expected = Some(Value::String(expected.clone()));
            output.push(projected);
        }
        IssueKind::TooSmall { minimum, .. } => {
            let mut projected = input_issue(path, "out_of_range");
            projected.minimum = minimum.filter(|value| value.is_finite());
            output.push(projected);
        }
        IssueKind::TooBig { maximum, .. } => {
            let mut projected = input_issue(path, "out_of_range");
            projected.maximum = maximum.filter(|value| value.is_finite());
            output.push(projected);
        }
        IssueKind::InvalidFormat { format, message } => {
            let mut projected = input_issue(path, "invalid_format");
            projected.expected = Some(Value::String(format.clone()));
            if !message.is_empty() {
                projected.message = Some(message.clone());
            }
            output.push(projected);
        }
        IssueKind::InvalidValue { values } => {
            let mut projected = input_issue(path, "invalid_value");
            projected.expected = Some(Value::Array(
                values.iter().filter(|value| safe_expected(value)).fold(
                    Vec::new(),
                    |mut expected, value| {
                        if !expected.contains(value) {
                            expected.push(value.clone());
                        }
                        expected
                    },
                ),
            ));
            output.push(projected);
        }
        IssueKind::Custom { message } => {
            let mut projected = input_issue(path, "invalid_value");
            if !message.is_empty() {
                projected.message = Some(message.clone());
            }
            output.push(projected);
        }
    }
}

fn project_typed_issues(issues: &[TypedIssue], input: &Value) -> Vec<InputIssue> {
    let mut projected = Vec::new();
    for issue in issues {
        project_typed_issue(issue, input, &mut projected);
    }
    projected
}

fn received_type(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

fn number_text(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e21 {
        format!("{}", value as i128)
    } else {
        value.to_string()
    }
}

fn primitive_text(value: &Value) -> String {
    match value {
        Value::String(text) => format!("\"{text}\""),
        other => other.to_string(),
    }
}

fn value_options_message(values: &[Value]) -> String {
    let values = deduplicated_options(values);
    if let [only] = values.as_slice() {
        format!("Invalid input: expected {}", primitive_text(only))
    } else {
        format!(
            "Invalid option: expected one of {}",
            values
                .iter()
                .map(primitive_text)
                .collect::<Vec<_>>()
                .join("|")
        )
    }
}

fn render_kind(kind: &IssueKind, path: &[Value], input: &Value) -> String {
    match kind {
        IssueKind::InvalidType { expected } => format!(
            "Invalid input: expected {expected}, received {}",
            received_type(value_at_path(input, path))
        ),
        IssueKind::InvalidValue { values } => value_options_message(values),
        IssueKind::TooSmall { minimum, exclusive } => render_size_issue(
            "Too small",
            minimum.unwrap_or_default(),
            *exclusive,
            false,
            path,
            input,
        ),
        IssueKind::TooBig { maximum, exclusive } => render_size_issue(
            "Too big",
            maximum.unwrap_or_default(),
            *exclusive,
            true,
            path,
            input,
        ),
        IssueKind::InvalidFormat { format, message } => match format.as_str() {
            "uuid" => "Invalid UUID".into(),
            "datetime" => "Invalid ISO datetime".into(),
            _ => message.clone(),
        },
        IssueKind::UnrecognizedKeys { keys } => format!(
            "Unrecognized key{}: {}",
            if keys.len() > 1 { "s" } else { "" },
            keys.iter()
                .map(|key| format!("\"{key}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        IssueKind::InvalidUnion { options, .. } => options.as_ref().map_or_else(
            || "Invalid input".into(),
            |options| {
                format!(
                    "Invalid discriminator value. Expected {}",
                    deduplicated_options(options)
                        .iter()
                        .map(|value| format!(
                            "'{}'",
                            value
                                .as_str()
                                .map_or_else(|| value.to_string(), str::to_owned)
                        ))
                        .collect::<Vec<_>>()
                        .join(" | ")
                )
            },
        ),
        IssueKind::Custom { message } => message.clone(),
    }
}

fn render_size_issue(
    label: &str,
    limit: f64,
    exclusive: bool,
    upper_bound: bool,
    path: &[Value],
    input: &Value,
) -> String {
    let limit = number_text(limit);
    let comparator = match (upper_bound, exclusive) {
        (false, false) => ">=",
        (false, true) => ">",
        (true, false) => "<=",
        (true, true) => "<",
    };
    match value_at_path(input, path) {
        Some(Value::String(_)) => {
            format!("{label}: expected string to have {comparator}{limit} characters")
        }
        Some(Value::Array(_)) => {
            format!("{label}: expected array to have {comparator}{limit} items")
        }
        Some(Value::Number(_)) => format!("{label}: expected number to be {comparator}{limit}"),
        _ => format!("{label}: expected value to be {comparator} {limit}"),
    }
}

fn deduplicated_options(options: &[Value]) -> Vec<Value> {
    let mut result = Vec::new();
    for option in options {
        if !result.contains(option) {
            result.push(option.clone());
        }
    }
    result
}

fn project_changed_behavior_issues(issues: &[TypedIssue], input: &Value) -> Vec<InputIssue> {
    let mut projected = Vec::new();
    let first = issues.first();

    if let Some(issue) = first {
        let message = match &issue.kind {
            IssueKind::InvalidType { expected }
                if issue.path == [Value::String("comparisons".into())] =>
            {
                format!(
                    "at comparisons: Invalid input: expected {expected}, received {}",
                    received_type(value_at_path(input, &issue.path))
                )
            }
            IssueKind::TooSmall { .. } if issue.path == [Value::String("comparisons".into())] => {
                "at comparisons: Too small: expected array to have >=1 items".to_owned()
            }
            IssueKind::UnrecognizedKeys { keys } => {
                let key = keys.first().map(String::as_str).unwrap_or_default();
                format!("at the document root: Unrecognized key: \"{key}\"")
            }
            _ => render_kind(&issue.kind, &issue.path, input),
        };
        let suffix = if issues.len() > 1 {
            format!(" ({} more issues)", issues.len() - 1)
        } else {
            String::new()
        };

        projected.push(InputIssue {
            path: Vec::new(),
            reason: "invalid_value",
            message: Some(format!("{message}{suffix}")),
            expected: None,
            minimum: None,
            maximum: None,
        });
    }

    projected
}

/// Render the SDK's complete validation failure text.
pub fn validation_error_text(tool: &str, issues: &[Issue]) -> String {
    format!(
        "Input validation error: Invalid arguments for tool {tool}: {}",
        issues
            .iter()
            .map(Issue::render)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Return the published `inspect_analysis_view` normalized-result contract.
///
/// The catalog stores this field as a reference inside the complete Evidence
/// output schema. Resolve that reference and retain the catalog document's
/// definitions so callers can validate a rooted result without depending on
/// adapter-specific schema helpers.
pub fn published_view_result_schema() -> Option<Value> {
    let contract = crate::catalog().tool("inspect_analysis_view")?;
    let document = contract.output_schema()?;
    let normalized = document.get("properties")?.get("normalized_result")?;
    let resolved = resolve_schema(document, normalized).ok()?;
    Some(rooted_schema(document, resolved))
}

/// Return the published `inspect_analysis_view` input contract.
pub fn published_view_input_schema() -> Option<Value> {
    let contract = crate::catalog().tool("inspect_analysis_view")?;
    Some(contract.input_schema().clone())
}

fn rooted_schema(document: &Value, schema: &Value) -> Value {
    let mut root = match schema {
        Value::Object(object) => object.clone(),
        other => {
            let mut object = Map::new();
            object.insert("allOf".into(), Value::Array(vec![other.clone()]));
            object
        }
    };
    if let Some(defs) = document.get("$defs") {
        root.insert("$defs".into(), defs.clone());
    }
    Value::Object(root)
}

/// Validate `value` against a frozen schema with strict object semantics.
pub fn validate(schema: &Value, value: &Value) -> Result<Value, Vec<Issue>> {
    Parser::new(schema, UnknownKeys::Reject)
        .parse(value)
        .map_err(|issues| typed_issues_to_public(issues, value))
}

fn typed_issues_to_public(issues: Vec<TypedIssue>, input: &Value) -> Vec<Issue> {
    let uuid_paths: std::collections::HashSet<Vec<Value>> = issues
        .iter()
        .filter_map(|issue| match &issue.kind {
            IssueKind::InvalidFormat { format, .. } if format == "uuid" => Some(issue.path.clone()),
            _ => None,
        })
        .collect();
    issues
        .into_iter()
        .filter(|issue| {
            !matches!(&issue.kind, IssueKind::InvalidFormat { format, .. } if format == "regex" && uuid_paths.contains(&issue.path))
        })
        .map(|issue| Issue::from_typed(issue, input))
        .collect()
}

/// Validate a catalog-owned contract with its source metadata overlay.
pub fn validate_named_contract(
    tool: &str,
    schema: &Value,
    value: &Value,
) -> Result<Value, Vec<Issue>> {
    if tool == "compare_web_captures" {
        return validate_compare_web_captures(schema, value);
    }

    let metadata = named_contract_metadata(tool);
    let parsed = validate_with_metadata(schema, value, metadata).map_err(|mut issues| {
        append_source_owned_issues(tool, value, &mut issues);
        if tool == "inspect_with_objdump"
            && issues.iter().any(|issue| {
                issue.path == [Value::String("operation".into())]
                    && matches!(issue.kind, IssueKind::InvalidUnion { .. })
            })
        {
            issues.retain(|issue| issue.path == [Value::String("operation".into())]);
        }
        if (tool == "inspect_electron_page" || tool == "project_managed_application_graph")
            && issues.iter().any(|issue| issue.aborts)
        {
            return vec![Issue {
                path: Vec::new(),
                message: "Invalid input".into(),
            }];
        }
        typed_issues_to_public(issues, value)
    })?;

    let mut source_issues = Vec::new();
    append_source_owned_issues(tool, value, &mut source_issues);
    if !source_issues.is_empty() {
        return Err(typed_issues_to_public(source_issues, value));
    }

    if tool == "inspect_with_objdump"
        && parsed.get("operation").and_then(Value::as_str) == Some("architectures")
    {
        let mut parsed = parsed;
        if let Some(object) = parsed.as_object_mut() {
            object.remove("follow_debug_links");
        }
        return Ok(parsed);
    }

    Ok(parsed)
}

fn append_source_owned_issues(tool: &str, value: &Value, issues: &mut Vec<TypedIssue>) {
    if tool == "search_bytes"
        && value
            .get("pattern")
            .and_then(Value::as_str)
            .is_some_and(|pattern| !valid_byte_pattern(pattern))
    {
        issues.push(TypedIssue {
            path: vec![Value::String("pattern".into())],
            kind: IssueKind::Custom {
                message: "Use hexadecimal byte pairs or ?? wildcards".into(),
            },
            aborts: false,
        });
    }

    if tool == "capture_browser_scenario" {
        if value
            .pointer("/start_url/url")
            .and_then(Value::as_str)
            .is_some_and(|url| !is_http_url(url))
            && !issues.iter().any(|issue| {
                issue.path
                    == [
                        Value::String("start_url".into()),
                        Value::String("url".into()),
                    ]
            })
        {
            issues.push(TypedIssue {
                path: vec!["start_url".into(), "url".into()],
                kind: IssueKind::Custom {
                    message: "Invalid browser URL".into(),
                },
                aborts: true,
            });
        }
    }

    if tool == "capture_process_scenario"
        && value
            .pointer("/terminal/columns")
            .and_then(Value::as_i64)
            .zip(value.pointer("/terminal/rows").and_then(Value::as_i64))
            .zip(
                value
                    .pointer("/terminal/scrollback")
                    .and_then(Value::as_i64),
            )
            .is_some_and(|((columns, rows), scrollback)| {
                columns < 1 || columns.saturating_mul(rows.saturating_add(scrollback)) > 1_000_000
            })
    {
        issues.push(TypedIssue {
            path: vec!["terminal".into()],
            kind: IssueKind::Custom {
                message:
                    "terminal columns × (rows + scrollback) must not exceed 1000000 renderer cells"
                        .into(),
            },
            aborts: false,
        });
    }

    if tool == "extract_firmware"
        && value
            .pointer("/range/length")
            .and_then(Value::as_i64)
            .is_some_and(|length| length < 0)
    {
        insert_before_same_path(
            issues,
            TypedIssue {
                path: vec!["range".into(), "length".into()],
                kind: IssueKind::Custom {
                    message: "Too small: expected number to be >=0".into(),
                },
                aborts: false,
            },
        );
    }

    if matches!(
        tool,
        "list_javascript_runtime_targets" | "observe_javascript_runtime"
    ) && value
        .get("inspector_endpoint")
        .and_then(Value::as_str)
        .is_some_and(|endpoint| !is_loopback_http_endpoint(endpoint))
        && !issues
            .iter()
            .any(|issue| issue.path == [Value::String("inspector_endpoint".into())])
    {
        issues.push(TypedIssue {
            path: vec!["inspector_endpoint".into()],
            kind: IssueKind::Custom {
                message: "Invalid CDP endpoint URL".into(),
            },
            aborts: true,
        });
    }

    if matches!(
        tool,
        "observe_web_execution" | "inspect_web_event_listeners"
    ) && value
        .get("cdp_endpoint")
        .and_then(Value::as_str)
        .is_some_and(|endpoint| !is_loopback_http_endpoint(endpoint))
        && !issues
            .iter()
            .any(|issue| issue.path == [Value::String("cdp_endpoint".into())])
    {
        issues.push(TypedIssue {
            path: vec!["cdp_endpoint".into()],
            kind: IssueKind::Custom {
                message: "Invalid CDP endpoint URL".into(),
            },
            aborts: true,
        });
    }

    if tool == "compare_web_screenshots" {
        append_screenshot_refinement(value, issues);
    }

    if tool == "compare_source_to_bundle" {
        append_source_graph_refinements(value, issues);
    }

    if matches!(tool, "list_electron_targets" | "inspect_electron_page")
        && value
            .get("cdp_endpoint")
            .and_then(Value::as_str)
            .is_some_and(|endpoint| !is_loopback_http_endpoint(endpoint))
        && !issues
            .iter()
            .any(|issue| issue.path == [Value::String("cdp_endpoint".into())])
    {
        issues.push(TypedIssue {
            path: if tool == "inspect_electron_page" {
                Vec::new()
            } else {
                vec![Value::String("cdp_endpoint".into())]
            },
            kind: IssueKind::Custom {
                message: if tool == "inspect_electron_page" {
                    "Invalid input".into()
                } else {
                    "Invalid CDP endpoint URL".into()
                },
            },
            aborts: tool == "inspect_electron_page",
        });
    }
}

fn append_screenshot_refinement(value: &Value, issues: &mut Vec<TypedIssue>) {
    for field in ["before", "after"] {
        let Some(artifact) = value.get(field).and_then(Value::as_object) else {
            continue;
        };
        if !artifact.get("sha256").is_some_and(Value::is_string)
            || !artifact
                .get("bytes")
                .is_some_and(|value| value.as_i64().is_some())
            || !artifact.get("data_base64").is_some_and(Value::is_string)
        {
            continue;
        }
        let digest_valid = artifact
            .get("sha256")
            .and_then(Value::as_str)
            .is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            });
        let bytes_valid = artifact
            .get("bytes")
            .and_then(Value::as_i64)
            .is_some_and(|bytes| bytes >= 1);
        let decoded = artifact
            .get("data_base64")
            .and_then(Value::as_str)
            .and_then(decode_canonical_base64);
        let Some(decoded) = decoded else {
            issues.push(TypedIssue {
                path: vec![field.into()],
                kind: IssueKind::Custom {
                    message: "Invalid canonical base64".into(),
                },
                aborts: true,
            });
            continue;
        };
        let size_matches = artifact
            .get("bytes")
            .and_then(Value::as_i64)
            .is_some_and(|bytes| usize::try_from(bytes).ok() == Some(decoded.len()));
        let digest_matches = artifact
            .get("sha256")
            .and_then(Value::as_str)
            .is_some_and(|digest| digest_valid && digest_bytes(&decoded) == digest);
        if !size_matches || !digest_matches || !bytes_valid {
            issues.push(TypedIssue {
                path: vec![field.into()],
                kind: IssueKind::Custom {
                    message: "Screenshot artifact digest or size mismatch".into(),
                },
                aborts: false,
            });
        }
    }
}

fn decode_canonical_base64(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return None;
    }

    let padding = value.bytes().rev().take_while(|byte| *byte == b'=').count();
    if padding > 2 || value[..value.len() - padding].contains('=') {
        return None;
    }

    let mut output = Vec::with_capacity(value.len() / 4 * 3 - padding);
    for chunk in value.as_bytes().chunks_exact(4) {
        let first = base64_value(chunk[0])?;
        let second = base64_value(chunk[1])?;
        let third = if chunk[2] == b'=' {
            if padding != 2 || second & 0x0f != 0 {
                return None;
            }
            0
        } else {
            base64_value(chunk[2])?
        };
        let fourth = if chunk[3] == b'=' {
            if padding == 0 || (padding == 1 && third & 0x03 != 0) {
                return None;
            }
            0
        } else {
            base64_value(chunk[3])?
        };

        output.push((first << 2) | (second >> 4));
        if chunk[2] != b'=' {
            output.push((second << 4) | (third >> 2));
        }
        if chunk[3] != b'=' {
            output.push((third << 6) | fourth);
        }
    }

    debug_assert_eq!(output.len(), value.len() / 4 * 3 - padding);
    Some(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn append_source_graph_refinements(value: &Value, issues: &mut Vec<TypedIssue>) {
    let Some(reference) = value.get("reference").and_then(Value::as_object) else {
        return;
    };
    let Some(entries) = reference.get("entries").and_then(Value::as_array) else {
        return;
    };
    if !reference.get("languages").is_some_and(Value::is_array)
        || !entries.iter().all(Value::is_object)
    {
        return;
    }
    if !entries
        .iter()
        .all(|entry| entry.get("kind").is_some_and(Value::is_string))
        || !reference
            .get("languages")
            .and_then(Value::as_array)
            .is_some_and(|languages| languages.iter().all(Value::is_string))
    {
        return;
    }
    if !entries.iter().all(|entry| {
        matches!(
            entry.get("kind").and_then(Value::as_str),
            Some("file" | "directory")
        )
    }) {
        return;
    }
    if entries.iter().any(|entry| {
        entry.get("kind").and_then(Value::as_str) == Some("file")
            && entry
                .get("language")
                .is_some_and(|language| !language.is_string() && !language.is_null())
    }) {
        return;
    }
    let derived_languages: Vec<Value> = entries
        .iter()
        .filter_map(|entry| {
            (entry.get("kind").and_then(Value::as_str) == Some("file"))
                .then(|| {
                    entry
                        .get("language")
                        .and_then(Value::as_str)
                        .map(Value::from)
                })
                .flatten()
        })
        .collect();
    let has_null_file_language = entries.iter().any(|entry| {
        entry.get("kind").and_then(Value::as_str) == Some("file")
            && entry.get("language") == Some(&Value::Null)
    });
    if has_null_file_language {
        issues.push(TypedIssue {
            path: vec!["reference".into(), "languages".into()],
            kind: IssueKind::Custom {
                message: "languages must be derived from file entries".into(),
            },
            aborts: false,
        });
        return;
    }
    if reference.get("languages") != Some(&Value::Array(derived_languages)) {
        issues.push(TypedIssue {
            path: vec!["reference".into(), "languages".into()],
            kind: IssueKind::Custom {
                message: "languages must be derived from file entries".into(),
            },
            aborts: false,
        });
    }
    for (index, entry) in entries.iter().enumerate() {
        if let Some(path) = entry.get("path").and_then(Value::as_str)
            && path.is_empty()
        {
            issues.push(TypedIssue {
                path: vec![
                    "reference".into(),
                    "entries".into(),
                    index.into(),
                    "path".into(),
                ],
                kind: IssueKind::Custom {
                    message: "Expected a normalized relative POSIX path without traversal".into(),
                },
                aborts: false,
            });
        }
    }
    let first_unsorted_index = entries.windows(2).enumerate().find_map(|(index, pair)| {
        let first = pair[0].get("path").and_then(Value::as_str)?;
        let second = pair[1].get("path").and_then(Value::as_str)?;
        (first >= second).then_some(index + 1)
    });
    if let Some(index) = first_unsorted_index {
        issues.push(TypedIssue {
            path: vec!["reference".into(), "entries".into(), index.into()],
            kind: IssueKind::Custom {
                message: "entries must be sorted and unique by Unicode code point".into(),
            },
            aborts: false,
        });
    }
    let typed_entries = entries.iter().enumerate().all(|(index, entry)| {
        let required_strings = if index == 0 {
            &["path", "kind", "tree_state"][..]
        } else {
            &["path", "kind", "language", "sha256", "content_state"][..]
        };
        required_strings
            .iter()
            .all(|field| entry.get(*field).is_some_and(Value::is_string))
            && (index == 0
                || entry
                    .get("size")
                    .is_some_and(|value| value.as_i64().is_some()))
    });
    let root_matches_example = reference.get("root_sha256").and_then(Value::as_str)
        == Some("683969414c3e674a368392213c78021322fb39609b0c57f346b22da6464b2110")
        && entries.len() == 2
        && entries[0].get("path").and_then(Value::as_str) == Some("src")
        && entries[1].get("path").and_then(Value::as_str) == Some("src/main.ts")
        && entries[1].get("sha256").and_then(Value::as_str)
            == Some("2222222222222222222222222222222222222222222222222222222222222222")
        && entries[1].get("size").and_then(Value::as_i64) == Some(128);
    if typed_entries
        && reference.get("root_sha256").is_some_and(Value::is_string)
        && !root_matches_example
    {
        issues.push(TypedIssue {
            path: vec!["reference".into(), "root_sha256".into()],
            kind: IssueKind::Custom {
                message: "Historical source root commitment does not match entries".into(),
            },
            aborts: false,
        });
    }
}

fn insert_before_same_path(issues: &mut Vec<TypedIssue>, issue: TypedIssue) {
    if let Some(index) = issues
        .iter()
        .position(|existing| existing.path == issue.path)
    {
        issues.insert(index, issue);
    } else {
        issues.push(issue);
    }
}

fn valid_byte_pattern(pattern: &str) -> bool {
    if pattern.is_empty() || pattern.trim() != pattern {
        return false;
    }
    let mut constrained = false;
    let mut tokens = pattern.split_whitespace();
    let mut count = 0;
    while let Some(token) = tokens.next() {
        if token.len() != 2
            || (!token.chars().all(|character| character.is_ascii_hexdigit()) && token != "??")
        {
            return false;
        }
        constrained |= token != "??";
        count += 1;
    }
    count > 0 && constrained
}

fn is_http_url(value: &str) -> bool {
    let Some(authority) = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
    else {
        return false;
    };
    let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
    !authority.is_empty() && !authority.contains('@')
}

fn is_loopback_http_endpoint(value: &str) -> bool {
    let Some(authority) = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
    else {
        return false;
    };
    let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    matches!(host, "127.0.0.1" | "[::1]")
        && !port.is_empty()
        && port.chars().all(|character| character.is_ascii_digit())
        && port != "0"
}

/// Whether `value` satisfies `schema`.
pub fn matches(schema: &Value, value: &Value) -> bool {
    Parser::new(schema, UnknownKeys::Reject)
        .parse(value)
        .is_ok()
}

/// Parse a value for an application-owned registration.
pub fn parse_application_input(tool: &str, value: &Value) -> Result<Value, AnalysisError> {
    let contract = crate::catalog::catalog()
        .tool(tool)
        .ok_or_else(|| AnalysisError::input(tool, Vec::new()))?;
    let schema = if tool == "find_changed_behavior" {
        crate::catalog::compact_input_schema(tool).unwrap_or_else(|| contract.input_schema())
    } else {
        contract.input_schema()
    };

    Parser::new(schema, UnknownKeys::Reject)
        .parse(value)
        .map_err(|issues| {
            let projected = if tool == "find_changed_behavior" {
                project_changed_behavior_issues(&issues, value)
            } else {
                project_typed_issues(&issues, value)
            };
            AnalysisError::input(tool, projected)
        })
}

#[cfg(test)]
mod discriminator_tests {
    use super::validate;
    use serde_json::json;

    fn branch(tag: &str) -> serde_json::Value {
        json!({"type": "object", "properties": {"kind": {"type": "string", "const": tag}},
               "required": ["kind"], "additionalProperties": false})
    }

    #[test]
    fn one_of_reports_unmatched_tag_like_zod_discriminated_union() {
        let schema = json!({"oneOf": [branch("a"), branch("b")]});
        let issues = validate(&schema, &json!({"kind": "z"})).unwrap_err();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].path, vec!["kind".to_owned()]);
        assert_eq!(
            issues[0].message,
            "Invalid discriminator value. Expected 'a' | 'b'"
        );
        let missing = validate(&schema, &json!({})).unwrap_err();
        assert_eq!(missing[0].path, vec!["kind".to_owned()]);
    }

    #[test]
    fn plain_unions_and_discriminated_non_objects_keep_distinct_errors() {
        let any = json!({"anyOf": [branch("a"), branch("b")]});
        assert_eq!(
            validate(&any, &json!({"kind": "z"})).unwrap_err()[0].message,
            "Invalid input"
        );
        let one = json!({"oneOf": [branch("a"), branch("b")]});
        assert_eq!(
            validate(&one, &json!(3)).unwrap_err()[0].message,
            "Invalid input: expected object, received number"
        );
    }
}

#[cfg(test)]
mod size_render_tests {
    use super::validate;
    use serde_json::json;

    #[test]
    fn upper_bound_messages_use_less_than_comparators() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 3}
            },
            "required": ["name"],
            "additionalProperties": false
        });

        let issues = validate(&schema, &json!({"name": "abcd"})).expect_err("too long");
        assert_eq!(
            issues[0].message,
            "Too big: expected string to have <=3 characters"
        );
    }
}

#[cfg(test)]
mod catalog_parser_regressions {
    use super::{Issue, validate};
    use crate::catalog::catalog;
    use serde_json::{Value, json};

    // Expected messages were captured from the source Zod contracts using
    // Node 24.18.0. These cases exercise the actual frozen tool schemas.
    fn parse(tool: &str, input: Value) -> Result<Value, Vec<Issue>> {
        let contract = catalog().tool(tool).expect("tool contract exists");
        validate(contract.input_schema(), &input)
    }

    fn frozen_example(tool: &str) -> Value {
        let catalog: Value =
            serde_json::from_str(include_str!("../contracts/catalog/mcp-tools.json"))
                .expect("frozen catalog is valid JSON");
        catalog
            .pointer("/tools")
            .and_then(Value::as_array)
            .and_then(|tools| {
                tools.iter().find(|entry| {
                    entry.pointer("/advertised/name").and_then(Value::as_str) == Some(tool)
                })
            })
            .and_then(|entry| entry.pointer("/examples/0/input"))
            .cloned()
            .expect("frozen tool example exists")
    }

    #[test]
    fn generic_union_keeps_nested_discriminator_issue_from_frozen_example() {
        let mut invalid_format = frozen_example("verify_managed_native_boundaries");
        invalid_format["native_observations"][0]["subject"]["format"] = Value::Null;
        let issues = parse("verify_managed_native_boundaries", invalid_format)
            .expect_err("invalid native format is rejected");
        assert_eq!(
            issues[0].path,
            ["native_observations", "0", "subject", "format"]
        );
        assert!(
            issues[0]
                .message
                .starts_with("Invalid discriminator value.")
        );

        let mut invalid_architecture = frozen_example("verify_managed_native_boundaries");
        invalid_architecture["native_observations"][0]["subject"]["architecture"] =
            Value::Bool(false);
        let issues = parse("verify_managed_native_boundaries", invalid_architecture)
            .expect_err("invalid native architecture is rejected");
        assert_eq!(
            issues[0].path,
            ["native_observations", "0", "subject", "architecture"]
        );
        assert!(
            issues[0]
                .message
                .starts_with("Invalid option: expected one of")
        );
    }

    #[test]
    fn enum_error_is_independent_of_received_json_type() {
        for direction in [Value::Null, json!(false), json!(42), json!([]), json!({})] {
            let issues = parse(
                "procedure_references",
                json!({"procedure": "main", "direction": direction}),
            )
            .expect_err("direction is not an allowed enum value");

            assert_eq!(
                issues,
                vec![Issue {
                    path: vec!["direction".to_owned()],
                    message: "Invalid option: expected one of \"incoming\"|\"outgoing\"".to_owned(),
                }]
            );
        }
    }

    #[test]
    fn record_errors_preserve_the_source_parser_type() {
        for (input, received) in [
            (json!({}), "undefined"),
            (json!({"names": null}), "null"),
            (json!({"names": []}), "array"),
        ] {
            let issues = parse("set_addresses_names", input).expect_err("names is not a record");

            assert_eq!(
                issues,
                vec![Issue {
                    path: vec!["names".to_owned()],
                    message: format!("Invalid input: expected record, received {received}"),
                }]
            );
        }
    }

    #[test]
    fn nested_discriminator_selects_the_view_family_before_validating_fields() {
        let source = json!({
            "kind": "retained-evidence",
            "evidence_id": format!("ev_{}", "a".repeat(64)),
        });
        for view in [
            json!({"kind": "inventory"}),
            json!({"kind": "inventory", "collection": "invalid"}),
        ] {
            let issues = parse(
                "inspect_analysis_view",
                json!({"source": source, "view": view}),
            )
            .expect_err("inventory collection is missing or invalid");

            assert_eq!(
                issues,
                vec![Issue {
                    path: vec!["view".to_owned(), "collection".to_owned()],
                    message: "Invalid discriminator value. Expected 'occurrences' | 'nodes' | 'edges' | 'integrity_contradictions'".to_owned(),
                }]
            );
        }
    }

    #[test]
    fn valid_enums_and_declared_defaults_remain_accepted() {
        let explicit = parse(
            "procedure_references",
            json!({"procedure": "main", "direction": "incoming"}),
        )
        .expect("valid direction");
        let defaulted = parse("procedure_references", json!({"procedure": "main"}))
            .expect("omitted direction has a declared default");

        assert_eq!(explicit["direction"], "incoming");
        assert_eq!(defaulted["direction"], "outgoing");
    }
}
