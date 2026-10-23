//! Audited engine release, bridge identity and remediation strings.
//!
//! Compatibility owner: `src/android/JadxRelease.ts`. The embedded bridge
//! source is a distinct REA artifact from the producing engine JAR.

/// Audited upstream engine version.
pub const JADX_VERSION: &str = "0.7.1";
/// Audited engine Git revision (unmodified submodule).
pub const JADX_REVISION: &str = "5844800a486d2248fa949b74c9896285f5b54de2";
/// Audited engine JAR SHA-256.
pub const JADX_SHA256: &str = "6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75";

/// REA metadata bridge identity (distinct from the engine).
pub const JADX_BRIDGE_NAME: &str = "rea-jadx-bridge";
pub const JADX_BRIDGE_VERSION: &str = "4";

/// Producing engine identity for Evidence and the product catalog.
pub const JADX_PROVIDER_ID: &str = "jadx";
pub const JADX_PROVIDER_NAME: &str = "JADX headless";

/// Whole-operation deadline used when `REA_JADX_OPERATION_TIMEOUT_MS` is unset.
pub const DEFAULT_JADX_OPERATION_TIMEOUT_MS: u64 = 120_000;

/// Remediation when `REA_JADX_MCP_JAR` is missing or not an absolute path.
pub fn jar_configuration_remediation() -> String {
    format!(
        "Set REA_JADX_MCP_JAR to the absolute path of a caller-supplied jadx-headless-mcp {JADX_VERSION} JAR. REA does not download or install it."
    )
}

/// Remediation when the selected Java runtime cannot satisfy the JADX bridge.
pub const JADX_JAVA_RUNTIME_REMEDIATION: &str = "Select a full JDK including jdk.compiler via JAVA_HOME or PATH, then verify it with java --list-modules. REA does not install Java.";

/// Remediation when a JADX JVM resource override is malformed.
pub const JADX_JVM_OPTIONS_REMEDIATION: &str = "Set REA_JADX_HEAP_MIB to a positive integer (heap size in MiB) and REA_JADX_ACTIVE_PROCESSOR_COUNT to a positive integer within the JVM's signed 32-bit range.";

/// Remediation when the JADX operation deadline override is malformed.
pub fn operation_timeout_remediation() -> String {
    format!(
        "Set REA_JADX_OPERATION_TIMEOUT_MS to a decimal millisecond count from 1 to 2147483647, or unset it to keep the {DEFAULT_JADX_OPERATION_TIMEOUT_MS} ms default."
    )
}

/// Remediation when the host cannot run the Android JADX subprocess.
pub const JADX_UNSUPPORTED_HOST_REMEDIATION: &str =
    "Use Linux, macOS, or Windows x64 with its bundled native controls for Android JADX analysis.";

/// Remediation when the Windows native backend cannot take process ownership.
pub const JADX_WINDOWS_NATIVE_REMEDIATION: &str = "Use a matching current Windows x64 REA package with its bundled native controls. The native failure above identifies the failed constraint; Java installation or registration changes cannot enable a missing native backend.";

/// Remediation when the Java module-listing probe cannot establish the runtime.
pub const JADX_JAVA_PROBE_REMEDIATION: &str = "Verify the selected Java launcher with java --list-modules: it must start promptly and emit a concise module listing including a parseable java.base version. REA does not install Java.";

/// Audited engine coverage, kept outside portable Android semantics.
pub fn jadx_limitations() -> Vec<String> {
    vec![
        "Static decompiler observations do not establish runtime behavior; the APK is never executed.".to_owned(),
        "Method signatures use provider display types; DEX prototypes come from frozen JADX metadata. Display names may be aliases, and overload indices are local to this engine and artifact.".to_owned(),
        "Class inventories use parsed metadata before code generation, including synthetic members that may be omitted from decompiled source. Source positions remain unknown.".to_owned(),
        "Incoming reference totals count JADX using nodes. Direct invoke entries within a using method report raw DEX code-unit offsets and method indexes, but coverage is limited to those nodes and directly matched invokes; it does not establish every possible dynamic or reflective call site.".to_owned(),
        "Manifest summary fields are extracted by the upstream engine; decoded XML is retained for verification. APK signatures, split APKs, native libraries and Android runtime capture are not verified by this provider.".to_owned(),
    ]
}
