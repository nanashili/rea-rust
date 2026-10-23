//! `inspect_asset_catalog`: inspect compiled `Assets.car` metadata in the
//! active Apple `.app` bundle.
//!
//! Compatibility owners: `src/artifacts/ArtifactProvider.ts`
//! (`inspectAssetCatalog`: `.app` bundle admission, `analyzeAppleAssetCatalogs`
//! call, `locations` per catalog), `src/artifacts/apple/
//! AppleAssetCatalogAnalysis.ts` (the macOS `assetutil` walk, the bundle
//! Interface Builder resource-key join, the off-macOS unavailable gate) and
//! `src/domain/apple/appleAssetCatalog.ts` (page bounds and projection).
//!
//! The real inspection reuses `rea_application::apple::asset_catalog_workflow`
//! over the real macOS host boundary `rea_host::apple_asset_catalog`
//! (no-follow bundle walk, bounded catalog reads, source-identity checks around
//! the `/usr/bin/assetutil --info` child under a 60 s deadline and output
//! bound) and the verified Interface Builder resource-key join. Off macOS the
//! route reports the capability unavailable with the exact reason, exactly as
//! `artifactCapabilities(platform)` / the provider's unavailable branch does.
use crate::common::{ProviderCall, ProviderOutcome, run_provider_tool};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::{Map, Value};

pub(crate) const OPERATION: &str = "inspect_asset_catalog";

/// Reason reported on a non-macOS host (route capability-unavailable).
const UNAVAILABLE: &str = "Apple asset catalogs require macOS assetutil.";

/// `registerEvidenceTools` binding for `inspect_asset_catalog`.
pub(crate) fn inspect_asset_catalog(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let object = input.as_object().cloned().unwrap_or_default();
    // `appleAssetCatalogInputSchema` has only `{ offset, limit }` (defaults
    // applied), which is both the execution and the Evidence parameters.
    let evidence_parameters = Value::Object(object.clone());
    let cancellation = context.cancellation.clone();

    // The route reports the capability unavailable off macOS before any read.
    let unavailable = if cfg!(target_os = "macos") {
        None
    } else {
        Some(UNAVAILABLE)
    };

    run_provider_tool(
        context,
        ProviderCall {
            execution_parameters: object,
            evidence_parameters,
            summary: false,
            unavailable,
        },
        move |target, parameters| execute(target, parameters, &cancellation),
    )
}

/// `ArtifactClient.inspectAssetCatalog`.
fn execute(
    target: &rea_analysis::BinaryTarget,
    parameters: &Map<String, Value>,
    cancellation: &Cancellation,
) -> Result<ProviderOutcome, AnalysisError> {
    // `kind !== "executable" || sourcePath === undefined ||
    //  !sourcePath.endsWith(".app")` → unsupported target.
    let bundle_path = super::admit_app_bundle(
        target,
        OPERATION,
        "inspect_asset_catalog requires an active .app bundle target",
    )?;
    inspect(target, bundle_path, parameters, cancellation)
}

fn usize_field(parameters: &Map<String, Value>, key: &str, default: usize) -> usize {
    parameters
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(default)
}

#[cfg(target_os = "macos")]
fn inspect(
    target: &rea_analysis::BinaryTarget,
    bundle_path: &str,
    parameters: &Map<String, Value>,
    cancellation: &Cancellation,
) -> Result<ProviderOutcome, AnalysisError> {
    use host::{AssetCatalogAdapter, AssetutilAdapter};
    use rea_application::apple::asset_catalog_workflow::{AppleAssetCatalogWorkflow, Page};
    use rea_application::interface_builder;
    use rea_core::evidence::{NativeFormat, Subject};
    use rea_host::apple_asset_catalog::AssetCatalogBundle;

    let page = Page {
        offset: usize_field(parameters, "offset", 0),
        limit: usize_field(
            parameters,
            "limit",
            rea_application::apple::asset_catalog_workflow::DEFAULT_LIMIT,
        ),
    };

    // The active target subject is a bundle directory; `bindExecutionTarget`
    // replaces it with the admitted target subject, so only the result,
    // limitations and locations are lifted from this reader envelope.
    let subject = Subject::new(
        bundle_path,
        target.sha256.clone(),
        NativeFormat::Directory,
        None,
    )
    .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;

    let bundle = AssetCatalogBundle::open(std::path::Path::new(bundle_path))
        .map_err(|error| host::host_failure(&error))?;
    let root_path = bundle.root_path().to_owned();

    // The bundle Interface Builder graph supplies resource keys for the join.
    let asset_references = interface_builder::bundle::inspect_bundle_asset_references(
        &root_path,
        target.sha256.clone(),
        cancellation,
    )
    .map_err(crate::common::adopt_failure)?;

    let adapter = AssetCatalogAdapter::new(bundle);
    let assetutil = AssetutilAdapter::default();
    let evidence = AppleAssetCatalogWorkflow::new(&adapter, &assetutil)
        .inspect_evidence(
            &root_path,
            subject,
            page,
            Value::Object(parameters.clone()),
            &asset_references.references,
            asset_references.graph_truncated,
            cancellation,
        )
        .map_err(crate::common::adopt_failure)?;

    super::outcome_from_artifact_evidence(OPERATION, &evidence)
}

#[cfg(not(target_os = "macos"))]
fn inspect(
    _target: &rea_analysis::BinaryTarget,
    _bundle_path: &str,
    _parameters: &Map<String, Value>,
    _cancellation: &Cancellation,
) -> Result<ProviderOutcome, AnalysisError> {
    // The route already reports unavailability before execute runs; this is
    // only reachable if the gate is bypassed.
    Err(crate::common::route_capability_unavailable(
        OPERATION,
        UNAVAILABLE,
    ))
}

/// macOS host composition copied from the legacy runtime
/// `apple_asset_catalog_host`, which is not a dependency of this crate. The
/// adapters bridge the real `rea_host::apple_asset_catalog` bundle and
/// `assetutil` child to the `rea_application` workflow traits.
#[cfg(target_os = "macos")]
mod host {
    use rea_application::apple::asset_catalog_workflow::{
        Assetutil, BundleSource, CatalogEntry, EntryIdentity, EntryKind,
    };
    use rea_core::cancellation::Cancellation;
    use rea_core::failure::{Detail, Failure};
    use rea_host::apple_asset_catalog::{
        AssetCatalogBundle, AssetCatalogEntry, AssetCatalogEntryKind, AssetCatalogHostError,
        AssetutilCommand,
    };
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::Mutex;

    pub(super) struct AssetCatalogAdapter {
        bundle: AssetCatalogBundle,
        entries: Mutex<BTreeMap<(String, String), AssetCatalogEntry>>,
    }

    impl AssetCatalogAdapter {
        pub(super) fn new(bundle: AssetCatalogBundle) -> Self {
            Self {
                bundle,
                entries: Mutex::new(BTreeMap::new()),
            }
        }

        fn host_entry(&self, entry: &CatalogEntry) -> Result<AssetCatalogEntry, Failure> {
            self.entries
                .lock()
                .map_err(|_| adapter_failure("Asset catalog entry owner was poisoned."))?
                .get(&(entry.path.clone(), entry.identity.value.clone()))
                .cloned()
                .ok_or_else(|| changed_entry(&entry.path))
        }
    }

    impl BundleSource for AssetCatalogAdapter {
        fn entries(
            &self,
            bundle_path: &Path,
            cancellation: &Cancellation,
        ) -> Result<Vec<CatalogEntry>, Failure> {
            if bundle_path != self.bundle.root_path() {
                return Err(adapter_failure(
                    "Asset catalog workflow changed its admitted bundle root.",
                ));
            }
            let host_entries = self
                .bundle
                .entries(cancellation)
                .map_err(|e| host_failure(&e))?;
            let mut owned_entries = self
                .entries
                .lock()
                .map_err(|_| adapter_failure("Asset catalog entry owner was poisoned."))?;
            owned_entries.clear();
            let mut entries = Vec::with_capacity(host_entries.len());
            for host_entry in host_entries {
                let identity = host_identity(&host_entry);
                let adapter_path = host_entry
                    .adapter_path
                    .to_str()
                    .ok_or_else(|| adapter_failure("Asset catalog path is not valid UTF-8."))?
                    .to_owned();
                let entry = CatalogEntry {
                    path: host_entry.path.clone(),
                    adapter_path,
                    kind: entry_kind(host_entry.kind),
                    declared_size: host_entry.declared_size,
                    identity: identity.clone(),
                };
                owned_entries.insert((entry.path.clone(), identity.value), host_entry);
                entries.push(entry);
            }
            Ok(entries)
        }

        fn read_entry(
            &self,
            entry: &CatalogEntry,
            cancellation: &Cancellation,
        ) -> Result<Vec<u8>, Failure> {
            let host_entry = self.host_entry(entry)?;
            self.bundle
                .read_entry(&host_entry, cancellation)
                .map_err(|e| host_failure(&e))
        }

        fn current_identity(
            &self,
            entry: &CatalogEntry,
            cancellation: &Cancellation,
        ) -> Result<EntryIdentity, Failure> {
            let host_entry = self.host_entry(entry)?;
            let current = self
                .bundle
                .current_identity(&host_entry, cancellation)
                .map_err(|e| host_failure(&e))?;
            Ok(EntryIdentity {
                value: fingerprint_identity(current),
            })
        }
    }

    #[derive(Default)]
    pub(super) struct AssetutilAdapter {
        command: AssetutilCommand,
    }

    impl Assetutil for AssetutilAdapter {
        fn inspect(
            &self,
            adapter_path: &Path,
            cancellation: &Cancellation,
        ) -> Result<String, Failure> {
            self.command
                .inspect(adapter_path, cancellation)
                .map_err(|e| host_failure(&e))
        }
    }

    fn host_identity(entry: &AssetCatalogEntry) -> EntryIdentity {
        EntryIdentity {
            value: fingerprint_identity(entry.identity),
        }
    }

    fn fingerprint_identity(fingerprint: rea_host::fs::stable_file::Fingerprint) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}",
            fingerprint.device,
            fingerprint.file_id,
            fingerprint.bytes,
            fingerprint.modified_ns,
            fingerprint.changed_ns,
            match fingerprint.kind {
                rea_host::fs::stable_file::Kind::Regular => "regular",
                rea_host::fs::stable_file::Kind::Directory => "directory",
                rea_host::fs::stable_file::Kind::Symlink => "symlink",
                rea_host::fs::stable_file::Kind::Other => "other",
            },
        )
    }

    fn entry_kind(kind: AssetCatalogEntryKind) -> EntryKind {
        match kind {
            AssetCatalogEntryKind::Regular => EntryKind::Regular,
            AssetCatalogEntryKind::Directory => EntryKind::Directory,
            AssetCatalogEntryKind::Symlink => EntryKind::Symlink,
            AssetCatalogEntryKind::Other => EntryKind::Other,
        }
    }

    /// `host_failure` from the legacy runtime: project the host error to the
    /// operation's `Failure`, which the adapter adopts into an `AnalysisError`.
    pub(super) fn host_failure(error: &AssetCatalogHostError) -> Failure {
        let (code, category, message, retryable, action): (_, _, String, _, String) = match error {
            AssetCatalogHostError::Unavailable(message) => (
                "provider_unavailable",
                "provider_unavailable",
                message.clone(),
                true,
                "Use macOS with its system assetutil provider and retry.".to_owned(),
            ),
            AssetCatalogHostError::Cancelled(message) => (
                "cancelled",
                "cancellation",
                message.clone(),
                true,
                "Retry the inspection after cancellation has cleared.".to_owned(),
            ),
            AssetCatalogHostError::Limit(message) => (
                "resource_limit",
                "limit",
                message.clone(),
                false,
                "Select an app bundle whose catalogs and metadata fit the reported limits."
                    .to_owned(),
            ),
            AssetCatalogHostError::Changed(message) => (
                "source_changed",
                "integrity",
                message.clone(),
                true,
                "Wait for the selected app bundle to become stable, then retry.".to_owned(),
            ),
            AssetCatalogHostError::Failed(message) | AssetCatalogHostError::Io(message) => (
                "provider_failed",
                "execution",
                message.clone(),
                true,
                "Check local read access and the system assetutil provider, then retry.".to_owned(),
            ),
        };
        Failure::new(
            code,
            category,
            message,
            retryable,
            action,
            BTreeMap::from([("operation", Detail::Text(super::OPERATION.to_owned()))]),
        )
    }

    fn adapter_failure(message: &str) -> Failure {
        Failure::new(
            "internal_state_error",
            "internal",
            message.to_owned(),
            false,
            "Restart the native REA process and retry.".to_owned(),
            BTreeMap::from([("operation", Detail::Text(super::OPERATION.to_owned()))]),
        )
    }

    fn changed_entry(path: &str) -> Failure {
        Failure::new(
            "source_changed",
            "integrity",
            format!("Asset catalog entry identity is no longer owned: {path}"),
            true,
            "Wait for the selected bundle to become stable, then retry.".to_owned(),
            BTreeMap::from([
                ("operation", Detail::Text(super::OPERATION.to_owned())),
                ("path", Detail::Text(path.to_owned())),
            ]),
        )
    }
}
