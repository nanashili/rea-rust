//! Static analysis output contract (`javascriptStaticAnalysisTypes.ts`).
use serde::{Deserialize, Serialize};

use crate::javascript::semantic::value_types::{JsString, Primitive};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePoint {
    pub line: u32,
    pub column: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRange {
    pub start: SourcePoint,
    pub end: SourcePoint,
}

impl From<crate::javascript::parser::SourcePosition> for SourcePoint {
    fn from(point: crate::javascript::parser::SourcePosition) -> Self {
        Self {
            line: point.line,
            column: point.column,
        }
    }
}

impl From<crate::javascript::parser::SourceRange> for SourceRange {
    fn from(range: crate::javascript::parser::SourceRange) -> Self {
        Self {
            start: range.start.into(),
            end: range.end.into(),
        }
    }
}
pub const JAVASCRIPT_AST_FINGERPRINT_ALGORITHM: &str = "babel-ast-v3";

macro_rules! string_enum { ($name:ident { $($variant:ident => $value:literal),+ $(,)? }, $rename:literal) => {
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = $rename)] pub enum $name { $($variant),+ }
}; }
string_enum!(PathContext { ModuleSpecifier => "module-specifier", FilesystemExpression => "filesystem-expression" }, "kebab-case");
string_enum!(ReferenceKind { StaticImport => "static-import", DynamicImport => "dynamic-import", Require => "require", Worker => "worker", ServiceWorker => "service-worker" }, "kebab-case");
string_enum!(Bundler { Webpack => "webpack", Rspack => "rspack", Esbuild => "esbuild" }, "lowercase");
string_enum!(RuntimeModuleCacheStatus { Observed => "observed", NotObserved => "not-observed" }, "kebab-case");
string_enum!(EndpointKind { Route => "route", Network => "network" }, "kebab-case");
string_enum!(StorageKind { LocalStorage => "local-storage", SessionStorage => "session-storage", IndexedDb => "indexed-db", CacheStorage => "cache-storage", Sqlite => "sqlite" }, "kebab-case");
string_enum!(Role { Preload => "preload", Renderer => "renderer" }, "lowercase");
string_enum!(ParseStatus { Complete => "complete", Partial => "partial", Failed => "failed" }, "lowercase");
string_enum!(OptionsStatus { ObjectLiteral => "object-literal", Dynamic => "dynamic", Missing => "missing" }, "kebab-case");

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticReference {
    pub module_key: Option<String>,
    pub location: SourceRange,
    pub kind: ReferenceKind,
    /// Exact JavaScript text value; `JsString` preserves unpaired UTF-16 units.
    pub specifier: Option<JsString>,
    pub expression: Option<JsString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_runtime: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticEndpoint {
    pub module_key: Option<String>,
    pub location: SourceRange,
    pub kind: EndpointKind,
    /// Exact JavaScript endpoint value, including lone surrogates.
    pub value: JsString,
    pub mechanism: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpretation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_runtime: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticStorage {
    pub module_key: Option<String>,
    pub location: SourceRange,
    pub kind: StorageKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpretation: Option<String>,
    /// Exact JavaScript storage name when statically known.
    pub name: Option<JsString>,
    pub mechanism: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_runtime: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundlerModule {
    pub module_key: String,
    pub factory_require_name: Option<String>,
    pub source_sha256: String,
    pub exports: Vec<JsString>,
    pub location: SourceRange,
    pub structural_fingerprint_sha256: String,
    pub structural_fingerprint_algorithm: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundlerRegistration {
    pub bundler: Bundler,
    pub runtime: String,
    pub chunk_keys: Vec<String>,
    pub unknown_chunk_keys: u64,
    pub runtime_require_name: Option<String>,
    pub runtime_module_cache_status: RuntimeModuleCacheStatus,
    pub entry_module_keys: Vec<String>,
    pub unknown_entry_module_keys: u64,
    pub async_chunk_keys: Vec<String>,
    pub unknown_async_chunk_keys: u64,
    pub modules: Vec<BundlerModule>,
    pub location: SourceRange,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolePath {
    pub module_key: Option<String>,
    pub location: SourceRange,
    pub role: Role,
    /// Exact JavaScript path value; filesystem resolution is represented by
    /// `resolution_context` rather than by lossy Unicode conversion.
    pub path: JsString,
    pub resolution_context: PathContext,
    pub mechanism: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_runtime: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMapUrl {
    pub declared_url: JsString,
    pub location: SourceRange,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticValue {
    pub status: String,
    pub value: Primitive,
    /// Source expression retained exactly in JavaScript UTF-16 units.
    pub expression: Option<JsString>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebPreference {
    pub name: JsString,
    pub value: StaticValue,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserWindow {
    pub module_key: Option<String>,
    pub location: SourceRange,
    pub options_status: OptionsStatus,
    pub web_preferences_status: OptionsStatus,
    pub web_preferences: Vec<WebPreference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_sources: Option<Vec<SourceRange>>,
    pub preload_path: Option<JsString>,
    pub preload_resolution_context: Option<PathContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_runtime: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBridgeApi {
    pub module_key: Option<String>,
    pub location: SourceRange,
    pub world: String,
    pub world_id: Option<StaticValue>,
    pub api_status: OptionsStatus,
    pub members: Vec<JsString>,
    pub unknown_members: u64,
    pub api_key: Option<JsString>,
    pub api_key_expression: Option<JsString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_runtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_basis: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcFinding {
    pub module_key: Option<String>,
    pub location: SourceRange,
    pub side: String,
    pub operation: String,
    pub mode: String,
    pub handler_kind: Option<String>,
    pub handler_location: Option<SourceRange>,
    pub channel: Option<JsString>,
    pub channel_expression: Option<JsString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_runtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_basis: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation_location: Option<SourceRange>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderValidation {
    pub module_key: Option<String>,
    pub location: SourceRange,
    pub subject: String,
    pub mechanism: String,
    pub expected: StaticValue,
    pub enforcement: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_runtime: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtilityProcess {
    pub module_key: Option<String>,
    pub location: SourceRange,
    pub service_name: Option<String>,
    pub module_path: Option<String>,
    pub module_resolution_context: Option<PathContext>,
    pub module_expression: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_runtime: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAddonBinding {
    pub module_key: Option<String>,
    pub location: SourceRange,
    pub specifier: JsString,
    pub binding_kind: String,
    pub module_kind: String,
    pub members: Vec<JsString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_access: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_member_access: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_runtime: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallPathStep {
    pub kind: String,
    pub label: String,
    pub location: SourceRange,
    pub module_key: Option<String>,
    pub module_runtime: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallPathCondition {
    pub expression: JsString,
    pub location: SourceRange,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallPath {
    pub entry_kind: String,
    pub entry: JsString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_path: Option<Vec<JsString>>,
    pub channel: Option<JsString>,
    pub terminal: String,
    pub resolution: String,
    pub steps: Vec<CallPathStep>,
    pub conditions: Vec<CallPathCondition>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectronFindings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_paths: Option<Vec<CallPath>>,
    pub browser_windows: Vec<BrowserWindow>,
    pub context_bridge_apis: Vec<ContextBridgeApi>,
    pub ipc: Vec<IpcFinding>,
    pub sender_validations: Vec<SenderValidation>,
    pub utility_processes: Vec<UtilityProcess>,
    pub native_addon_bindings: Vec<NativeAddonBinding>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticAnalysis {
    pub parse_status: ParseStatus,
    pub parse_error_count: u64,
    pub visited_ast_nodes: u64,
    pub references: Vec<StaticReference>,
    pub endpoints: Vec<StaticEndpoint>,
    pub storage: Vec<StaticStorage>,
    pub bundler_registrations: Vec<BundlerRegistration>,
    pub role_paths: Vec<RolePath>,
    pub source_map_urls: Vec<SourceMapUrl>,
    pub vendors: Vec<String>,
    pub electron: ElectronFindings,
    pub limitations: Vec<String>,
}
