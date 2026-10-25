//! Read-only DMG child reader.
//!
//! Compatibility owner: `src/artifacts/NativeDmgArtifactReader.ts`. The
//! adapter verifies and attaches through `hdiutil`, constrains the mount to a
//! REA-created directory, delegates traversal to the anchored directory
//! reader, and detaches every device it acquired during close.

use crate::artifact_graph::directory_reader::DirectoryArtifactReader;
use crate::artifact_reader::{
    ArtifactEntry, ArtifactReader, ArtifactTraversalOmission, ReaderFailure,
};
use crate::native_command::{self, CommandCleanup, FailureReason};
use rea_core::JsString;
use rea_core::cancellation::Cancellation;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const DETACH_SETTLE_DELAYS: [Duration; 3] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_millis(1_000),
];

pub(crate) struct NativeDmgArtifactReader {
    path: String,
    cleanup: Arc<CommandCleanup>,
    mount_root: Option<String>,
    devices: Vec<String>,
    baseline_devices: HashSet<String>,
    ownership_uncertainty: Option<String>,
    directory: Option<DirectoryArtifactReader>,
    entries: HashMap<String, ArtifactEntry>,
    provenance: Vec<Value>,
    closed: bool,
}

impl NativeDmgArtifactReader {
    pub(crate) fn new(path: impl Into<String>, cleanup: Arc<CommandCleanup>) -> Self {
        Self {
            path: path.into(),
            cleanup,
            mount_root: None,
            devices: Vec::new(),
            baseline_devices: HashSet::new(),
            ownership_uncertainty: None,
            directory: None,
            entries: HashMap::new(),
            provenance: Vec::new(),
            closed: false,
        }
    }

    fn ensure_attached(&mut self, cancellation: &Cancellation) -> Result<(), ReaderFailure> {
        if self.closed {
            return Err(ReaderFailure::new("unavailable", "DMG reader is closed"));
        }
        if self.directory.is_some() {
            return Ok(());
        }
        if cancellation.reason().is_some() {
            return Err(ReaderFailure::new("cancelled", "DMG operation cancelled"));
        }
        if !cfg!(target_os = "macos") {
            return Err(ReaderFailure::new(
                "unavailable",
                "Native DMG traversal is available only on macOS",
            ));
        }
        let root = create_mount_root()?;
        self.mount_root = Some(root.clone());
        self.verify_and_capture_baseline(cancellation)?;

        let attached = self.attach_image(cancellation, &root);
        let attached = match attached {
            Ok(value) => value,
            Err(failure) => {
                // hdiutil can report a non-zero exit after it has already
                // attached part of an image. Reconcile its bounded failure
                // capture with a fresh inventory before taking ownership of
                // any device.
                let capture = failure
                    .capture
                    .as_ref()
                    .map(|capture| capture.stdout.clone());
                let primary = hdiutil_failure(failure);
                let cleanup_failure = self.reconcile_failed_attach(capture.as_deref());
                return Err(merge_cleanup_failure(primary, cleanup_failure));
            }
        };
        let parsed = self.reconcile_attached_output(&attached.stdout, cancellation, &root)?;
        self.provenance.push(command(&attached, &["read", "mount"]));
        self.directory = Some(DirectoryArtifactReader::new(&parsed.mount_point));
        Ok(())
    }

    fn verify_and_capture_baseline(
        &mut self,
        cancellation: &Cancellation,
    ) -> Result<(), ReaderFailure> {
        let verify = native_command::run(
            &self.cleanup,
            cancellation,
            "hdiutil",
            &["verify".into(), self.path.clone()],
            false,
        )
        .map_err(|failure| {
            merge_cleanup_failure(hdiutil_failure(failure), self.cleanup_mount_root())
        })?;
        self.provenance.push(command(&verify, &["read"]));

        let baseline = native_command::run(
            &self.cleanup,
            cancellation,
            "hdiutil",
            &["info".into(), "-plist".into()],
            false,
        )
        .map_err(|failure| {
            merge_cleanup_failure(hdiutil_failure(failure), self.cleanup_mount_root())
        })?;
        self.provenance.push(command(&baseline, &["read"]));
        self.baseline_devices = parse_info_output(&baseline.stdout)
            .map(|info| info.all_devices().into_iter().collect())
            .map_err(|failure| merge_cleanup_failure(failure, self.cleanup_mount_root()))?;
        Ok(())
    }

    fn attach_image(
        &self,
        cancellation: &Cancellation,
        root: &str,
    ) -> Result<native_command::NativeCommandCapture, native_command::NativeCommandFailure> {
        native_command::run(
            &self.cleanup,
            cancellation,
            "hdiutil",
            &[
                "attach".into(),
                "-readonly".into(),
                "-nobrowse".into(),
                "-plist".into(),
                "-mountroot".into(),
                root.to_owned(),
                self.path.clone(),
            ],
            false,
        )
    }

    fn reconcile_attached_output(
        &mut self,
        output: &str,
        cancellation: &Cancellation,
        root: &str,
    ) -> Result<AttachResult, ReaderFailure> {
        let parsed = match parse_attach_output(output, root) {
            Ok(parsed) => parsed,
            Err(failure) => {
                let cleanup_failure = self.reconcile_failed_attach(Some(output));
                return Err(merge_cleanup_failure(failure, cleanup_failure));
            }
        };
        self.devices = parsed.devices.clone();
        let info = match self.read_info(cancellation) {
            Ok(info) => info,
            Err(failure) => {
                self.ownership_uncertainty =
                    Some("hdiutil attachment could not be reconciled after info failed".into());
                let cleanup_failure = self.cleanup_after_failed_attach();
                return Err(merge_cleanup_failure(failure, cleanup_failure));
            }
        };
        match resolve_ownership(&info, Some(&parsed), true, root, &self.baseline_devices) {
            Ownership::Owned(devices) => self.devices = devices,
            Ownership::None => {
                self.devices.clear();
                return Err(ReaderFailure::new(
                    "path",
                    "hdiutil did not mount a new image beneath the owned root",
                ));
            }
            Ownership::Unknown(reason) => {
                self.devices
                    .retain(|device| !self.baseline_devices.contains(device));
                self.ownership_uncertainty = Some(reason.clone());
                return Err(ReaderFailure::new(
                    "unavailable",
                    format!("DMG attachment ownership is uncertain: {reason}"),
                ));
            }
        }
        Ok(parsed)
    }

    fn detach_devices(&mut self) -> Option<ReaderFailure> {
        let mut first_failure = None;
        let devices = std::mem::take(&mut self.devices);
        let mut remaining_devices = Vec::new();

        for device in devices.into_iter().rev() {
            let mut detached = false;
            let mut device_failure = None;

            for delay in std::iter::once(Duration::ZERO).chain(DETACH_SETTLE_DELAYS) {
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }

                let cancellation = Cancellation::default();
                match native_command::run(
                    &self.cleanup,
                    &cancellation,
                    "hdiutil",
                    &["detach".into(), device.clone()],
                    false,
                ) {
                    Ok(capture) => {
                        self.provenance.push(command(&capture, &["mount"]));
                        detached = true;
                        break;
                    }
                    Err(error) => {
                        let translated = hdiutil_failure(error);
                        if let Some(attached) = self.device_is_attached(&device) {
                            if !attached {
                                detached = true;
                                break;
                            }
                        }
                        device_failure.get_or_insert(translated);
                    }
                }
            }

            if !detached {
                remaining_devices.push(device);

                if first_failure.is_none() {
                    first_failure = device_failure;
                }
            }
        }

        remaining_devices.reverse();
        self.devices = remaining_devices;
        first_failure
    }

    /// Reconcile a failed detach against hdiutil's current inventory. A
    /// detach may return an error after the device has already disappeared;
    /// only a positive inventory observation keeps ownership retained.
    fn device_is_attached(&mut self, device: &str) -> Option<bool> {
        let cancellation = Cancellation::default();
        let capture = native_command::run(
            &self.cleanup,
            &cancellation,
            "hdiutil",
            &["info".into(), "-plist".into()],
            false,
        )
        .ok()?;
        self.provenance.push(command(&capture, &["read"]));
        let info = parse_info_output(&capture.stdout).ok()?;
        Some(info.all_devices().iter().any(|attached| attached == device))
    }

    fn read_info(&mut self, cancellation: &Cancellation) -> Result<DmgInfo, ReaderFailure> {
        let capture = native_command::run(
            &self.cleanup,
            cancellation,
            "hdiutil",
            &["info".into(), "-plist".into()],
            false,
        )
        .map_err(hdiutil_failure)?;
        self.provenance.push(command(&capture, &["read"]));
        parse_info_output(&capture.stdout)
    }

    fn reconcile_failed_attach(&mut self, attach_output: Option<&str>) -> Option<ReaderFailure> {
        let parsed_attach = attach_output
            .and_then(|output| parse_attach_output(output, self.mount_root.as_deref()?).ok());
        if let Some(parsed) = parsed_attach.as_ref() {
            self.devices = parsed.devices.clone();
        }

        let info = match self.read_info(&Cancellation::default()) {
            Ok(info) => info,
            Err(failure) => {
                self.ownership_uncertainty =
                    Some("hdiutil attachment could not be reconciled after attach failure".into());
                return Some(failure);
            }
        };
        match resolve_ownership(
            &info,
            parsed_attach.as_ref(),
            parsed_attach.is_some(),
            self.mount_root.as_deref().unwrap_or_default(),
            &self.baseline_devices,
        ) {
            Ownership::Owned(devices) => {
                self.devices = devices;
                self.ownership_uncertainty = None;
                self.cleanup_after_failed_attach()
            }
            Ownership::None => {
                self.devices.clear();
                self.ownership_uncertainty = None;
                self.cleanup_after_failed_attach()
            }
            Ownership::Unknown(reason) => {
                self.devices
                    .retain(|device| !self.baseline_devices.contains(device));
                self.ownership_uncertainty = Some(reason);
                None
            }
        }
    }

    fn cleanup_after_failed_attach(&mut self) -> Option<ReaderFailure> {
        if self.ownership_uncertainty.is_some() {
            return None;
        }
        let detach_failure = self.detach_devices();
        let root_failure = if detach_failure.is_none() {
            self.cleanup_mount_root()
        } else {
            None
        };
        merge_failure_options(detach_failure, root_failure)
    }

    fn reconcile_retained_attachment(&mut self) -> Option<ReaderFailure> {
        let info = match self.read_info(&Cancellation::default()) {
            Ok(info) => info,
            Err(failure) => return Some(failure),
        };
        match resolve_ownership(
            &info,
            None,
            false,
            self.mount_root.as_deref().unwrap_or_default(),
            &self.baseline_devices,
        ) {
            Ownership::Owned(devices) => {
                self.devices = devices;
                self.ownership_uncertainty = None;
                None
            }
            Ownership::None => {
                self.devices.clear();
                self.ownership_uncertainty = None;
                None
            }
            Ownership::Unknown(reason) => {
                self.ownership_uncertainty = Some(reason.clone());
                Some(ReaderFailure::new(
                    "unavailable",
                    format!("DMG attachment ownership remains uncertain: {reason}"),
                ))
            }
        }
    }

    fn cleanup_mount_root(&mut self) -> Option<ReaderFailure> {
        let Some(root) = self.mount_root.clone() else {
            return None;
        };
        match fs::remove_dir_all(&root) {
            Ok(()) => {
                self.mount_root = None;
                None
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.mount_root = None;
                None
            }
            Err(error) => Some(ReaderFailure::new(
                "io",
                format!("Could not remove DMG mount root {root}: {error}"),
            )),
        }
    }
}

impl ArtifactReader for NativeDmgArtifactReader {
    fn format(&self) -> &'static str {
        "file"
    }

    fn entries(
        &mut self,
        cancellation: &Cancellation,
        omissions: &mut Vec<ArtifactTraversalOmission>,
    ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
        self.ensure_attached(cancellation)?;
        let directory = self
            .directory
            .as_mut()
            .ok_or_else(|| ReaderFailure::new("unavailable", "DMG is not attached"))?;
        let mut inner_omissions = Vec::new();
        let inner = ArtifactReader::entries(directory, cancellation, &mut inner_omissions)?;
        let prefix = Path::new(&self.path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("image.dmg");
        omissions.extend(
            inner_omissions
                .into_iter()
                .map(|omission| ArtifactTraversalOmission {
                    path: JsString::from(format!("{prefix}/{}", omission.path)),
                    kind: omission.kind,
                }),
        );
        self.entries.clear();
        let mut output = Vec::with_capacity(inner.len());
        for entry in inner {
            let key = format!("dmg:{}", entry.adapter_key);
            let wrapped = ArtifactEntry {
                path: JsString::from(format!("{prefix}/{}", entry.path)),
                adapter_key: JsString::from(key.clone()),
                ..entry.clone()
            };
            self.entries.insert(key, entry);
            output.push(wrapped);
        }
        Ok(output)
    }

    fn open(
        &mut self,
        entry: &ArtifactEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, ReaderFailure> {
        self.ensure_attached(cancellation)?;
        let inner = self
            .entries
            .get(entry.adapter_key.as_str().unwrap_or_default())
            .cloned()
            .ok_or_else(|| {
                ReaderFailure::new(
                    "integrity",
                    "DMG entry metadata does not match this reader's inventory",
                )
            })?;
        let directory = self
            .directory
            .as_mut()
            .ok_or_else(|| ReaderFailure::new("unavailable", "DMG is not attached"))?;
        ArtifactReader::open(directory, &inner, cancellation)
    }

    fn close(&mut self) -> Result<(), ReaderFailure> {
        self.closed = true;
        let directory_result = self.directory.take().map_or(Ok(()), |mut directory| {
            ArtifactReader::close(&mut directory)
        });
        let reconciliation_result = if self.ownership_uncertainty.is_some() {
            self.reconcile_retained_attachment()
        } else {
            None
        };
        let detach_result = if self.ownership_uncertainty.is_some() {
            None
        } else {
            self.detach_devices()
        };
        let root_result = if self.ownership_uncertainty.is_some() {
            Some(
                ReaderFailure::new(
                    "unavailable",
                    self.ownership_uncertainty
                        .clone()
                        .unwrap_or_else(|| "DMG attachment ownership remains unknown".into()),
                )
                .with_cleanup(
                    "DMG attachment ownership remains unresolved",
                    self.mount_root
                        .iter()
                        .map(|root| format!("DMG mount root {root}"))
                        .collect(),
                ),
            )
        } else if detach_result.is_some() {
            Some(
                ReaderFailure::new(
                    "unavailable",
                    "DMG mount root retained because device detachment failed",
                )
                .with_cleanup(
                    "DMG mount root retained for cleanup retry",
                    self.mount_root
                        .iter()
                        .map(|root| format!("DMG mount root {root}"))
                        .collect(),
                ),
            )
        } else {
            self.cleanup_mount_root()
        };

        let mut failure = directory_result.err();
        for cleanup_failure in [reconciliation_result, detach_result, root_result]
            .into_iter()
            .flatten()
        {
            failure = Some(match failure {
                Some(primary) => primary.with_cleanup_failure(cleanup_failure),
                None => cleanup_failure,
            });
        }

        if let Some(failure) = failure {
            return Err(failure);
        }
        Ok(())
    }
}

fn create_mount_root() -> Result<String, ReaderFailure> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "rea-dmg-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).map_err(|error| {
        ReaderFailure::new(
            "io",
            format!(
                "Could not create DMG mount root {}: {error}",
                root.display()
            ),
        )
    })?;
    let canonical = match fs::canonicalize(&root) {
        Ok(canonical) => canonical,
        Err(error) => {
            let primary = ReaderFailure::new(
                "io",
                format!(
                    "Could not resolve DMG mount root {}: {error}",
                    root.display()
                ),
            );
            let cleanup = match fs::remove_dir_all(&root) {
                Ok(()) => None,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(cleanup_error) => Some(ReaderFailure::new(
                    "io",
                    format!(
                        "Could not remove incomplete DMG mount root {}: {cleanup_error}",
                        root.display()
                    ),
                )),
            };
            return Err(merge_cleanup_failure(primary, cleanup));
        }
    };
    Ok(canonical.to_string_lossy().into_owned())
}

struct AttachResult {
    devices: Vec<String>,
    mount_point: String,
    entities: Vec<DmgEntity>,
}

#[derive(Clone, Debug, Deserialize)]
struct DmgEntity {
    #[serde(rename = "dev-entry")]
    device: String,
    #[serde(rename = "mount-point")]
    mount_point: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct DmgImage {
    #[serde(rename = "system-entities")]
    entities: Vec<DmgEntity>,
}

#[derive(Clone, Debug, Deserialize)]
struct DmgInfo {
    images: Vec<DmgImage>,
}

impl DmgInfo {
    fn all_devices(&self) -> Vec<String> {
        self.images
            .iter()
            .flat_map(|image| image.entities.iter().map(|entity| entity.device.clone()))
            .collect()
    }
}

enum Ownership {
    Owned(Vec<String>),
    None,
    Unknown(String),
}

fn parse_attach_output(xml: &str, root: &str) -> Result<AttachResult, ReaderFailure> {
    let entities = parse_plist_entities(xml, "system-entities")?;
    let devices = top_level_devices(&entities);
    let mount_point = entities.iter().find_map(|entity| {
        entity
            .mount_point
            .as_deref()
            .filter(|mount| is_below_root(root, mount))
    });
    let mount_point = mount_point.ok_or_else(|| {
        ReaderFailure::new(
            "unavailable",
            "hdiutil did not mount a new image beneath the owned root",
        )
    })?;
    if devices.is_empty() {
        return Err(ReaderFailure::new(
            "format",
            "hdiutil returned no attached devices",
        ));
    }
    Ok(AttachResult {
        devices,
        mount_point: mount_point.to_owned(),
        entities,
    })
}

fn parse_info_output(xml: &str) -> Result<DmgInfo, ReaderFailure> {
    let value = rea_rust_analysis::plist::read(xml.as_bytes(), "hdiutil".into())
        .map_err(|error| ReaderFailure::new("format", format!("Malformed hdiutil plist: {error}")))?
        .value;
    serde_json::from_value(value)
        .map_err(|error| ReaderFailure::new("format", format!("Malformed hdiutil plist: {error}")))
}

fn parse_plist_entities(xml: &str, key: &str) -> Result<Vec<DmgEntity>, ReaderFailure> {
    let value = rea_rust_analysis::plist::read(xml.as_bytes(), "hdiutil".into())
        .map_err(|error| ReaderFailure::new("format", format!("Malformed hdiutil plist: {error}")))?
        .value;
    let entities = value
        .get(key)
        .cloned()
        .ok_or_else(|| ReaderFailure::new("format", format!("hdiutil plist has no {key}")))?;
    serde_json::from_value(entities)
        .map_err(|error| ReaderFailure::new("format", format!("Malformed hdiutil {key}: {error}")))
}

fn top_level_devices(entities: &[DmgEntity]) -> Vec<String> {
    let devices: Vec<String> = entities
        .iter()
        .map(|entity| entity.device.clone())
        .collect();
    devices
        .iter()
        .filter(|device| !devices.iter().any(|parent| is_child_disk(parent, device)))
        .cloned()
        .collect()
}

fn is_child_disk(parent: &str, device: &str) -> bool {
    is_top_level_disk(parent)
        && device
            .strip_prefix(parent)
            .and_then(|suffix| suffix.strip_prefix('s'))
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
}

fn is_top_level_disk(device: &str) -> bool {
    let Some(number) = device.strip_prefix("/dev/disk") else {
        return false;
    };
    !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_below_root(root: &str, path: &str) -> bool {
    let root = Path::new(root);
    let path = Path::new(path);
    path.starts_with(root) && path != root
}

fn resolve_ownership(
    info: &DmgInfo,
    attach: Option<&AttachResult>,
    attach_returned: bool,
    root: &str,
    baseline: &HashSet<String>,
) -> Ownership {
    let rooted: Vec<&DmgImage> = info
        .images
        .iter()
        .filter(|image| {
            image.entities.iter().any(|entity| {
                entity
                    .mount_point
                    .as_deref()
                    .is_some_and(|mount| is_below_root(root, mount))
            })
        })
        .collect();
    if rooted.len() > 1 {
        return Ownership::Unknown(
            "multiple hdiutil image groups report mounts beneath the owned root".into(),
        );
    }
    if let Some(image) = rooted.first() {
        return ownership_for_entities(&image.entities, root, baseline);
    }
    if attach_returned {
        if let Some(attach) = attach {
            let ownership = ownership_for_entities(&attach.entities, root, baseline);
            if !matches!(ownership, Ownership::None) {
                return ownership;
            }
        }
    }
    if info
        .all_devices()
        .iter()
        .any(|device| !baseline.contains(device))
    {
        Ownership::Unknown("hdiutil lists devices absent from the pre-attach baseline, but none is tied uniquely to the owned root".into())
    } else {
        Ownership::None
    }
}

fn ownership_for_entities(
    entities: &[DmgEntity],
    root: &str,
    baseline: &HashSet<String>,
) -> Ownership {
    let has_root_mount = entities.iter().any(|entity| {
        entity
            .mount_point
            .as_deref()
            .is_some_and(|mount| is_below_root(root, mount))
    });
    let has_outside_mount = entities.iter().any(|entity| {
        entity
            .mount_point
            .as_deref()
            .is_some_and(|mount| !is_below_root(root, mount))
    });
    let devices = top_level_devices(entities);
    let overlaps_baseline = entities
        .iter()
        .any(|entity| baseline.contains(&entity.device));
    if has_root_mount {
        if has_outside_mount {
            return Ownership::Unknown(
                "the image group contains a mount outside the owned root".into(),
            );
        }
        if overlaps_baseline {
            return Ownership::Unknown(
                "the image group includes a device present before attachment".into(),
            );
        }
        if devices.is_empty() {
            return Ownership::Unknown(
                "the owned mount group contains no detachable device".into(),
            );
        }
        return Ownership::Owned(devices);
    }
    if entities.is_empty() {
        Ownership::Unknown(
            "hdiutil attach succeeded without reporting device ownership facts".into(),
        )
    } else if entities
        .iter()
        .any(|entity| !baseline.contains(&entity.device))
    {
        Ownership::Unknown(
            "the attach result reports new devices without a mount beneath the owned root".into(),
        )
    } else {
        Ownership::None
    }
}

fn merge_cleanup_failure(primary: ReaderFailure, cleanup: Option<ReaderFailure>) -> ReaderFailure {
    match cleanup {
        Some(cleanup) => primary.with_cleanup_failure(cleanup),
        None => primary,
    }
}

fn merge_failure_options(
    first: Option<ReaderFailure>,
    second: Option<ReaderFailure>,
) -> Option<ReaderFailure> {
    match (first, second) {
        (Some(primary), Some(cleanup)) => Some(primary.with_cleanup_failure(cleanup)),
        (Some(failure), None) | (None, Some(failure)) => Some(failure),
        (None, None) => None,
    }
}

fn command(capture: &native_command::NativeCommandCapture, effects: &[&str]) -> Value {
    serde_json::json!({"tool": capture.tool, "arguments": capture.arguments, "tool_version": capture.tool_version, "executable_sha256": capture.executable_sha256, "exit_code": capture.exit_code, "effects": effects})
}

fn hdiutil_failure(failure: native_command::NativeCommandFailure) -> ReaderFailure {
    let reason = match failure.reason {
        FailureReason::Cancelled => "cancelled",
        FailureReason::NonzeroExit => "format",
        FailureReason::Io => "io",
        _ => "unavailable",
    };
    ReaderFailure::new(
        reason,
        failure
            .detail
            .unwrap_or_else(|| "hdiutil operation failed".to_owned()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entity(device: &str, mount_point: Option<&str>) -> DmgEntity {
        DmgEntity {
            device: device.to_owned(),
            mount_point: mount_point.map(str::to_owned),
        }
    }

    fn image(entities: Vec<DmgEntity>) -> DmgInfo {
        DmgInfo {
            images: vec![DmgImage { entities }],
        }
    }

    #[test]
    fn attach_plist_decodes_escaped_and_numeric_mount_path() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict><key>system-entities</key><array>
              <dict><key>dev-entry</key><string>/dev/disk42</string></dict>
              <dict><key>dev-entry</key><string>/dev/disk42s1</string>
                <key>mount-point</key><string>/tmp/rea&amp;root/vol&#x2F;one</string></dict>
            </array></dict></plist>"#;

        let parsed = parse_attach_output(plist, "/tmp/rea&root").expect("valid attach plist");

        assert_eq!(parsed.devices, vec!["/dev/disk42"]);
        assert_eq!(parsed.mount_point, "/tmp/rea&root/vol/one");
    }

    #[test]
    fn ownership_rejects_baseline_overlap_and_outside_mounts() {
        let baseline = HashSet::from(["/dev/disk42".to_owned()]);
        let overlap = image(vec![
            entity("/dev/disk42", None),
            entity("/dev/disk42s1", Some("/tmp/rea-root/volume")),
        ]);
        let outside = image(vec![
            entity("/dev/disk43", None),
            entity("/dev/disk43s1", Some("/tmp/rea-root/volume")),
            entity("/dev/disk43s2", Some("/Volumes/foreign")),
        ]);

        assert!(matches!(
            resolve_ownership(&overlap, None, false, "/tmp/rea-root", &baseline),
            Ownership::Unknown(_)
        ));
        assert!(matches!(
            resolve_ownership(&outside, None, false, "/tmp/rea-root", &HashSet::new()),
            Ownership::Unknown(_)
        ));
    }

    #[test]
    fn ownership_rejects_multiple_rooted_image_groups() {
        let info = DmgInfo {
            images: vec![
                DmgImage {
                    entities: vec![
                        entity("/dev/disk42", None),
                        entity("/dev/disk42s1", Some("/tmp/rea-root/one")),
                    ],
                },
                DmgImage {
                    entities: vec![
                        entity("/dev/disk43", None),
                        entity("/dev/disk43s1", Some("/tmp/rea-root/two")),
                    ],
                },
            ],
        };

        assert!(matches!(
            resolve_ownership(&info, None, false, "/tmp/rea-root", &HashSet::new()),
            Ownership::Unknown(_)
        ));
    }

    #[test]
    fn ownership_rejects_unrelated_new_devices_without_owned_mount() {
        let info = image(vec![entity("/dev/disk44", None)]);

        assert!(matches!(
            resolve_ownership(&info, None, false, "/tmp/rea-root", &HashSet::new()),
            Ownership::Unknown(_)
        ));
    }

    #[test]
    fn ownership_accepts_one_new_image_group_under_owned_root() {
        let info = image(vec![
            entity("/dev/disk45", None),
            entity("/dev/disk45s1", Some("/tmp/rea-root/volume")),
        ]);

        assert!(matches!(
            resolve_ownership(&info, None, false, "/tmp/rea-root", &HashSet::new()),
            Ownership::Owned(devices) if devices == vec!["/dev/disk45"]
        ));
    }

    #[test]
    fn mount_root_ownership_is_retained_when_cleanup_fails() {
        let path =
            std::env::temp_dir().join(format!("rea-dmg-cleanup-test-{}", std::process::id()));
        fs::write(&path, b"not a directory").expect("create cleanup probe");

        let mut reader =
            NativeDmgArtifactReader::new("/tmp/image.dmg", Arc::new(CommandCleanup::default()));
        reader.mount_root = Some(path.to_string_lossy().into_owned());

        assert!(reader.cleanup_mount_root().is_some());
        assert_eq!(reader.mount_root.as_deref(), path.to_str());

        fs::remove_file(path).expect("remove cleanup probe");
    }
}
