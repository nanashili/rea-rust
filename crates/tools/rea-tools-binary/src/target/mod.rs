//! Port of `src/application/BinaryTargetResolver.ts` and its transitive
//! dependencies: classify and admit a readable local target before a provider
//! is selected, producing a [`rea_analysis::BinaryTarget`].
//!
//! The TypeScript runtime is the behavioral oracle. This module mirrors the
//! inputs, outputs, error codes, messages, ordering, limits and cancellation
//! checkpoints of:
//!   - `src/application/BinaryTargetResolver.ts`
//!   - `src/application/AppBundleExecutable.ts`
//!   - `src/application/MipsElfMetadata.ts` (+ `MipsElfSharedLoad`, `MipsGnuAttributes`)
//!   - `src/domain/binaryTarget.ts`, `binaryTargetTypes.ts`, `elfFixedHeader.ts`
//!   - `src/domain/dosMz.ts`, `dosCom.ts`, `rawBinary.ts`, `peMachine.ts`
//!   - `src/domain/apple/machoContainer.ts`, `appleArchiveFormat.ts`, `jvmClassFile.ts`
//!   - `src/domain/zipPackageFormat.ts`
//!   - `src/filesystem/RegularFile.ts`, `OwnedRegularFile.ts`, `callerPath.ts`
//!   - `src/domain/configurationErrors.ts`
//!   - `src/application/binary/BinaryTargetSummary.ts`
mod appbundle;
mod elf;
mod fs_target;
mod header;
mod macho;
mod mips;
mod pe;
mod plist_probe;
mod raw;
pub(crate) use fs_target::{FsError, NodeCode};
pub(crate) use raw::raw_binary_selection_error;
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value};
/// Options for resolving a local binary target and its stable identity.
#[derive(Clone, Debug, Default)]
pub(crate) struct TargetOptions {
    /// executable | database | archive | artifact
    pub target_kind: Option<String>,
    /// dos-com | raw-binary
    pub format_hint: Option<String>,
    pub architecture: Option<String>,
    pub entry_point: Option<String>,
}
/// The Node `process.arch` name for the architecture this build targets.
///
/// Mirrors `process.arch`: aarch64 -> "arm64", x86_64 -> "x64",
/// x86 -> "ia32", arm -> "arm", otherwise `std::env::consts::ARCH`.
pub(crate) fn host_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        "x86" => "ia32",
        "arm" => "arm",
        other => other,
    }
}
/// Exact `binaryTargetSummary`: keys path, format, kind, sha256, architecture
/// (null when absent), plus `entry_point` only for raw-binary, in that order.
pub(crate) fn binary_target_summary(target: &rea_analysis::BinaryTarget) -> Value {
    let mut object = Map::new();
    object.insert("path".into(), Value::String(target.path.clone()));
    object.insert("format".into(), Value::String(target.format.clone()));
    object.insert("kind".into(), Value::String(target.kind.clone()));
    object.insert("sha256".into(), Value::String(target.sha256.clone()));
    object.insert(
        "architecture".into(),
        match &target.architecture {
            Some(architecture) => Value::String(architecture.clone()),
            None => Value::Null,
        },
    );
    if target.format == "raw-binary" {
        if let Some(entry) = target.metadata.get("entryPoint") {
            object.insert("entry_point".into(), entry.clone());
        }
    }
    Value::Object(object)
}
/// A `BinaryTargetError` under construction, preserving the OS cause.
pub(crate) struct BinaryTargetError {
    path: String,
    reason: String,
    constraint: Option<&'static str>,
    system_code: Option<&'static str>,
}
impl BinaryTargetError {
    pub(crate) fn new(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            reason: reason.into(),
            constraint: None,
            system_code: None,
        }
    }
    pub(crate) fn with_constraint(mut self, constraint: &'static str) -> Self {
        self.constraint = Some(constraint);
        self
    }
    /// Carry the OS read-permission code, matching TS `readPermissionCode`:
    /// only EACCES / EPERM are retained as `systemCode`.
    fn with_permission_cause(mut self, code: Option<NodeCode>) -> Self {
        self.system_code = match code {
            Some(NodeCode::Eacces) => Some("EACCES"),
            Some(NodeCode::Eperm) => Some("EPERM"),
            _ => None,
        };
        self
    }
    /// Set the retained `systemCode` directly (EACCES / EPERM only).
    pub(crate) fn with_system_code(mut self, code: Option<&'static str>) -> Self {
        self.system_code = match code {
            Some("EACCES") => Some("EACCES"),
            Some("EPERM") => Some("EPERM"),
            _ => None,
        };
        self
    }
    fn into_analysis_error(self) -> AnalysisError {
        AnalysisError::from(ErrorKind::BinaryTarget {
            path: self.path,
            reason: self.reason,
            constraint: self.constraint.map(str::to_owned),
            system_code: self.system_code.map(str::to_owned),
        })
    }
}
/// Internal result for the resolution body: a target, a typed binary-target
/// error, or a cancellation.
enum Resolution {
    Ok(Box<rea_analysis::BinaryTarget>),
    Rejected(BinaryTargetError),
    Cancelled,
}
/// Resolve and classify a readable local target before a provider is selected.
///
/// FAT Mach-O inputs select only a host-compatible architecture. Unsupported
/// or ambiguous inputs are returned as typed [`AnalysisError`]s.
pub(crate) fn parse_binary_target(
    input: &str,
    options: &TargetOptions,
    cancellation: &Cancellation,
) -> Result<rea_analysis::BinaryTarget, AnalysisError> {
    // TS: const candidate = absoluteCallerPath(input, { cwd });
    let candidate = match fs_target::absolute_caller_path(input) {
        Ok(candidate) => candidate,
        Err(error) => {
            // process.cwd() failures surface as filesystem failures on the
            // caller path; there is no TS equivalent branch, so classify as a
            // read failure of the raw input (closest faithful behavior).
            return Err(classify_candidate_io(input, &error).into_analysis_error());
        }
    };
    match resolve_body(input, &candidate, options, cancellation) {
        Resolution::Ok(target) => Ok(*target),
        Resolution::Rejected(error) => Err(error.into_analysis_error()),
        Resolution::Cancelled => Err(AnalysisError::cancelled("resolve_binary_target")),
    }
}
fn classify_candidate_io(path: &str, error: &FsError) -> BinaryTargetError {
    let reason = target_failure_reason(error.code, &error.message);
    BinaryTargetError::new(path, reason).with_permission_cause(Some(error.code))
}
/// TS `targetFailureReason`.
fn target_failure_reason(code: NodeCode, detail: &str) -> String {
    match code {
        NodeCode::Enoent | NodeCode::Enotdir => {
            format!("target does not exist or a path component is not a directory: {detail}")
        }
        NodeCode::Eacces | NodeCode::Eperm => {
            format!("permission denied while reading target: {detail}")
        }
        NodeCode::Eisdir => format!("target is a directory, not a readable file: {detail}"),
        NodeCode::Enotfile => "target is not a regular file".to_string(),
        NodeCode::Eloop => format!("target changed while being opened: {detail}"),
        NodeCode::Other(code) => format!("target could not be read ({code}): {detail}"),
    }
}
include!("resolve.rs");
