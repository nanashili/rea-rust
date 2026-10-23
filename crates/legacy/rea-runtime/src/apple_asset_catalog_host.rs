//! Runtime composition for read-only macOS asset-catalog inspection.
//!
//! The host module owns no-follow bundle access and `assetutil` supervision;
//! the application workflow owns catalog interpretation and Evidence.

use rea_application::{
    apple::asset_catalog_workflow::{
        AppleAssetCatalogWorkflow, Assetutil, BundleSource, CatalogEntry, EntryIdentity, EntryKind,
        Page,
    },
    interface_builder,
};
use rea_core::{
    cancellation::Cancellation,
    evidence::ArtifactEvidence,
    evidence::Subject,
    failure::{Detail, Failure},
};
use rea_host::apple_asset_catalog::{
    AssetCatalogBundle, AssetCatalogEntry, AssetCatalogEntryKind, AssetCatalogHostError,
    AssetutilCommand,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
    sync::Mutex,
};

/// Inspect the `.app` containing a selected Mach-O and verify its exact digest.
pub fn inspect_selected_target(
    target_path: &Path,
    target_subject: Subject,
    page: Page,
    parameters: Value,
    cancellation: &Cancellation,
) -> Result<ArtifactEvidence, Failure> {
    let bundle_path = containing_app_bundle(target_path).ok_or_else(|| {
        unsupported_target(
            "Asset catalog inspection requires an active Mach-O inside a .app bundle.",
            target_path,
        )
    })?;
    let relative_target_path = target_path.strip_prefix(&bundle_path).map_err(|_| {
        unsupported_target("Selected Mach-O is outside the .app bundle.", target_path)
    })?;
    let relative_target_path = relative_target_path.to_str().ok_or_else(|| {
        invalid_path(
            "Selected Mach-O path inside the .app bundle is not valid UTF-8.",
            target_path,
        )
    })?;
    if relative_target_path.is_empty()
        || Path::new(relative_target_path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid_path(
            "Selected Mach-O path is not a safe bundle-relative path.",
            target_path,
        ));
    }

    let bundle = AssetCatalogBundle::open(&bundle_path).map_err(host_failure)?;
    let observed_sha256 = bundle
        .sha256_relative_path(relative_target_path, cancellation)
        .map_err(host_failure)?;
    if observed_sha256 != target_subject.sha256() {
        return Err(target_digest_mismatch(
            target_path,
            target_subject.sha256(),
            &observed_sha256,
        ));
    }

    inspect_open_bundle(bundle, target_subject, page, parameters, cancellation)
}

fn inspect_open_bundle(
    bundle: AssetCatalogBundle,
    target_subject: Subject,
    page: Page,
    parameters: Value,
    cancellation: &Cancellation,
) -> Result<ArtifactEvidence, Failure> {
    let root_path = bundle.root_path().to_owned();
    let asset_references = interface_builder::bundle::inspect_bundle_asset_references(
        &root_path,
        target_subject.sha256().to_owned(),
        cancellation,
    )?;

    let adapter = AssetCatalogAdapter::new(bundle);
    let assetutil = AssetutilAdapter::default();
    AppleAssetCatalogWorkflow::new(&adapter, &assetutil).inspect_evidence(
        &root_path,
        target_subject,
        page,
        parameters,
        &asset_references.references,
        asset_references.graph_truncated,
        cancellation,
    )
}

struct AssetCatalogAdapter {
    bundle: AssetCatalogBundle,
    entries: Mutex<BTreeMap<(String, String), AssetCatalogEntry>>,
}

impl AssetCatalogAdapter {
    fn new(bundle: AssetCatalogBundle) -> Self {
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
            return Err(invalid_path(
                "Asset catalog workflow changed its admitted bundle root.",
                bundle_path,
            ));
        }

        let host_entries = self.bundle.entries(cancellation).map_err(host_failure)?;
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
                .ok_or_else(|| {
                    invalid_path(
                        "Asset catalog path is not valid UTF-8.",
                        &host_entry.adapter_path,
                    )
                })?
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
            .map_err(host_failure)
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
            .map_err(host_failure)?;
        Ok(EntryIdentity {
            value: fingerprint_identity(current),
        })
    }
}

struct AssetutilAdapter {
    command: AssetutilCommand,
}

impl Default for AssetutilAdapter {
    fn default() -> Self {
        Self {
            command: AssetutilCommand::default(),
        }
    }
}

impl Assetutil for AssetutilAdapter {
    fn inspect(&self, adapter_path: &Path, cancellation: &Cancellation) -> Result<String, Failure> {
        self.command
            .inspect(adapter_path, cancellation)
            .map_err(host_failure)
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

fn containing_app_bundle(target_path: &Path) -> Option<PathBuf> {
    target_path
        .ancestors()
        .find(|ancestor| is_app_bundle(ancestor))
        .map(Path::to_owned)
}

fn is_app_bundle(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
}

fn host_failure(error: AssetCatalogHostError) -> Failure {
    let (code, category, message, retryable, action) = match error {
        AssetCatalogHostError::Unavailable(message) => (
            "provider_unavailable",
            "provider_unavailable",
            message,
            true,
            "Use macOS with its system assetutil provider and retry.".to_owned(),
        ),
        AssetCatalogHostError::Cancelled(message) => (
            "cancelled",
            "cancellation",
            message,
            true,
            "Retry the inspection after cancellation has cleared.".to_owned(),
        ),
        AssetCatalogHostError::Limit(message) => (
            "resource_limit",
            "limit",
            message,
            false,
            "Select an app bundle whose catalogs and metadata fit the reported limits.".to_owned(),
        ),
        AssetCatalogHostError::Changed(message) => (
            "source_changed",
            "integrity",
            message,
            true,
            "Wait for the selected app bundle to become stable, then retry.".to_owned(),
        ),
        AssetCatalogHostError::Failed(message) | AssetCatalogHostError::Io(message) => (
            "provider_failed",
            "execution",
            message,
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
        BTreeMap::from([(
            "operation",
            Detail::Text("inspect_asset_catalog".to_owned()),
        )]),
    )
}

fn unsupported_target(message: &str, path: &Path) -> Failure {
    Failure::new(
        "unsupported_target",
        "unsupported_target",
        message.to_owned(),
        false,
        "Select a Mach-O executable inside a local .app bundle.".to_owned(),
        BTreeMap::from([
            (
                "operation",
                Detail::Text("inspect_asset_catalog".to_owned()),
            ),
            ("path", Detail::Text(path.to_string_lossy().into_owned())),
        ]),
    )
}

fn invalid_path(message: &str, path: &Path) -> Failure {
    Failure::new(
        "invalid_path",
        "path",
        message.to_owned(),
        false,
        "Select a readable app bundle path without symlinked target components.".to_owned(),
        BTreeMap::from([
            (
                "operation",
                Detail::Text("inspect_asset_catalog".to_owned()),
            ),
            ("path", Detail::Text(path.to_string_lossy().into_owned())),
        ]),
    )
}

fn adapter_failure(message: &str) -> Failure {
    Failure::new(
        "internal_state_error",
        "internal",
        message.to_owned(),
        false,
        "Restart the native REA process and retry.".to_owned(),
        BTreeMap::from([(
            "operation",
            Detail::Text("inspect_asset_catalog".to_owned()),
        )]),
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
            (
                "operation",
                Detail::Text("inspect_asset_catalog".to_owned()),
            ),
            ("path", Detail::Text(path.to_owned())),
        ]),
    )
}

fn target_digest_mismatch(path: &Path, expected: &str, observed: &str) -> Failure {
    Failure::new(
        "evidence_integrity_mismatch",
        "integrity_mismatch",
        "The selected Mach-O changed after inspection; asset catalog evidence was not created."
            .to_owned(),
        true,
        "Reinspect the selected Mach-O in the app bundle, then retry.".to_owned(),
        BTreeMap::from([
            (
                "operation",
                Detail::Text("inspect_asset_catalog".to_owned()),
            ),
            ("path", Detail::Text(path.to_string_lossy().into_owned())),
            ("expected_sha256", Detail::Text(expected.to_owned())),
            ("observed_sha256", Detail::Text(observed.to_owned())),
        ]),
    )
}
