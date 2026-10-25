//! Hopper setup planning and the verified package-install boundary.
//!
//! The application layer owns release identity and the order of verification.
//! Platform hosts own network, package-manager, bundle, and filesystem effects.
//! Keeping those effects behind a host makes dry-run and approval behaviour
//! deterministic and lets adapters use fixture hosts without touching a user
//! installation.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use base64::Engine;
use rea_core::cancellation::Cancellation;
use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess};
use rea_host::process::windows::job::WindowsJobLimits;
use serde_json::{Value, json};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;

pub const HOPPER_RELEASES_URL: &str =
    "https://www.hopperapp.com/include/files-api.php?request=releases&public=true";
pub const HOPPER_PUBLIC_KEY_URL: &str = "https://www.hopperapp.com/hopper-public-key.asc";
pub const HOPPER_DOWNLOAD_PREFIX: &str = "https://www.hopperapp.com:443/downloader/public/";
pub const HOPPER_LINUX_PRIMARY_FINGERPRINT: &str = "7C2D73BAFAF5B9A710A69DA1A26DF815099B1BCD";
pub const HOPPER_DOWNLOAD_BYTES: usize = 100_000_000;
const HOPPER_PUBLISHER_TEAM: &str = "2AMA2753NF";
const HOPPER_MAC_BUNDLE_ID: &str = "com.cryptic-apps.hopper-web-4";
const HOPPER_MAC_APPLICATION_NAME: &str = "Hopper Disassembler.app";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopperPlatform {
    MacOs,
    LinuxDeb,
    LinuxRpm,
    LinuxArch,
}

impl HopperPlatform {
    pub fn feed_key(self) -> &'static str {
        match self {
            Self::LinuxDeb => "Ubuntu / Mint",
            Self::LinuxRpm => "Fedora",
            Self::LinuxArch => "Arch",
            Self::MacOs => "OS X",
        }
    }

    pub fn suffix(self) -> &'static str {
        match self {
            Self::LinuxDeb => "-Linux-demo.deb",
            Self::LinuxRpm => "-Linux-demo.rpm",
            Self::LinuxArch => "-Linux-demo.pkg.tar.xz",
            Self::MacOs => ".dmg",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::MacOs => "macOS",
            Self::LinuxDeb => "Linux (deb)",
            Self::LinuxRpm => "Linux (rpm)",
            Self::LinuxArch => "Linux (Arch)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopperRelease {
    pub version: String,
    pub filename: String,
    pub file_length: usize,
    pub file_hash: String,
    pub main_exe_hash: String,
    pub signature: Option<String>,
    pub public: bool,
    pub beta: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HopperInstallError {
    ReleaseMetadata(String),
    Download(String),
    Integrity(String),
    PublisherVerification(String),
    Cancelled(String),
    Installation(String),
    InstallationCommitted { launcher: String, detail: String },
    InstallationPartial(String),
}

impl HopperInstallError {
    fn reason(&self) -> &'static str {
        match self {
            Self::ReleaseMetadata(_) => "release_metadata",
            Self::Download(_) => "download",
            Self::Integrity(_) => "integrity",
            Self::PublisherVerification(_) => "publisher_verification_failed",
            Self::Cancelled(_) => "cancelled",
            Self::Installation(_) => "installation",
            Self::InstallationCommitted { .. } => "cleanup_failed",
            Self::InstallationPartial(_) => "installation_partial",
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::ReleaseMetadata(message)
            | Self::Download(message)
            | Self::Integrity(message)
            | Self::PublisherVerification(message)
            | Self::Cancelled(message)
            | Self::Installation(message) => message,
            Self::InstallationCommitted { detail, .. } => detail,
            Self::InstallationPartial(message) => message,
        }
    }
}

/// Effects supplied by the platform owner. `install_verified` must be a
/// transaction: it stages the package, commits only after launcher validation,
/// and retains any failed cleanup for a later retry.
pub trait HopperInstallHost {
    fn fetch(&mut self, url: &str, max_bytes: usize) -> Result<Vec<u8>, HopperInstallError>;
    fn verify_publisher(
        &mut self,
        platform: HopperPlatform,
        package: &[u8],
        release: &HopperRelease,
    ) -> Result<(), HopperInstallError>;
    fn install_verified(
        &mut self,
        platform: HopperPlatform,
        package: &[u8],
        release: &HopperRelease,
        replace_existing: bool,
    ) -> Result<String, HopperInstallError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopperInstallRequest {
    pub platform: HopperPlatform,
    pub replace_existing: bool,
    pub approved: bool,
}

enum HopperInstallationResult {
    Installed(String),
    InstalledWithCleanup { launcher: String, detail: String },
}

/// Production host for the approved Hopper setup transaction.
///
/// The host deliberately invokes only the platform tools disclosed by
/// [`hopper_setup_plan`]. Temporary files are created below the system temp
/// directory and are removed on every return path; a failed replacement keeps
/// its backup beside the destination for recovery rather than deleting it.
pub struct SystemHopperInstallHost {
    home: PathBuf,
    environment: BTreeMap<String, String>,
    cancellation: Cancellation,
}

impl SystemHopperInstallHost {
    pub fn new(
        home: impl Into<PathBuf>,
        environment: BTreeMap<String, String>,
        cancellation: Cancellation,
    ) -> Self {
        Self {
            home: home.into(),
            environment,
            cancellation,
        }
    }

    fn ensure_active(&self) -> Result<(), HopperInstallError> {
        self.cancellation.reason().map_or(Ok(()), |reason| {
            Err(HopperInstallError::Cancelled(reason.to_owned()))
        })
    }

    fn environment_pairs(&self) -> Vec<(OsString, OsString)> {
        self.environment
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect()
    }

    fn run_process(
        &self,
        executable: &str,
        arguments: &[&str],
        error_kind: fn(String) -> HopperInstallError,
        observe_cancellation: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), HopperInstallError> {
        if observe_cancellation {
            self.ensure_active()?;
        }

        let spec = ChildLaunchSpec {
            executable: PathBuf::from(executable),
            arguments: ChildLaunchSpec::arguments(arguments.iter().copied()),
            working_directory: None,
            protocol_stdin: false,
            limits: WindowsJobLimits {
                memory_bytes: None,
                cpu_seconds: None,
            },
        };
        let environment = self.environment_pairs();
        let mut child = OwnedChildProcess::launch_with_environment(spec, &environment, 256 * 1024)
            .map_err(|error| error_kind(format!("{executable} could not start: {error}")))?;
        let output = child
            .drain_output_with(|| observe_cancellation && self.cancellation.reason().is_some())
            .map_err(|error| {
                error_kind(format!("{executable} output could not be read: {error}"))
            })?;

        if observe_cancellation && self.cancellation.reason().is_some() {
            let cleanup = child.cancel(130).err();
            let reason = self.cancellation.reason().unwrap_or("cancelled");
            let suffix = cleanup
                .map(|error| format!("; process cleanup failed: {error}"))
                .unwrap_or_default();
            return Err(HopperInstallError::Cancelled(format!(
                "{executable} cancelled: {reason}{suffix}"
            )));
        }

        let exit = child
            .wait()
            .map_err(|error| error_kind(format!("{executable} could not settle: {error}")))?;
        if exit.code != 0 {
            return Err(error_kind(format!(
                "{executable} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok((output.stdout, output.stderr))
    }

    fn run_checked(&self, executable: &str, arguments: &[&str]) -> Result<(), HopperInstallError> {
        self.run_process(
            executable,
            arguments,
            HopperInstallError::Installation,
            true,
        )?;
        Ok(())
    }

    fn run_verification(
        &self,
        executable: &str,
        arguments: &[&str],
    ) -> Result<(), HopperInstallError> {
        self.run_process(
            executable,
            arguments,
            HopperInstallError::PublisherVerification,
            true,
        )?;
        Ok(())
    }

    fn run_cleanup(&self, executable: &str, arguments: &[&str]) -> Result<(), HopperInstallError> {
        self.run_process(
            executable,
            arguments,
            HopperInstallError::Installation,
            false,
        )?;
        Ok(())
    }

    fn run_capture(
        &self,
        executable: &str,
        arguments: &[&str],
    ) -> Result<String, HopperInstallError> {
        let (stdout, _) = self.run_process(
            executable,
            arguments,
            HopperInstallError::PublisherVerification,
            true,
        )?;
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }

    fn detach_mount(&self, mount: &Path) -> Result<(), HopperInstallError> {
        self.run_cleanup(
            "hdiutil",
            &["detach", mount.to_str().unwrap_or_default(), "-force"],
        )
    }

    fn finish_with_cleanup<T>(
        &self,
        result: Result<T, HopperInstallError>,
        cleanup: Result<(), HopperInstallError>,
    ) -> Result<T, HopperInstallError> {
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup)) => Err(HopperInstallError::Installation(format!(
                "operation succeeded but mount cleanup failed: {}",
                cleanup.message()
            ))),
            (Err(HopperInstallError::InstallationCommitted { launcher, detail }), Err(cleanup)) => {
                Err(HopperInstallError::InstallationCommitted {
                    launcher,
                    detail: format!("{detail}; mount cleanup failed: {}", cleanup.message()),
                })
            }
            (Err(error), Err(cleanup)) => Err(HopperInstallError::Installation(format!(
                "{}; mount cleanup failed: {}",
                error.message(),
                cleanup.message()
            ))),
        }
    }

    fn finish_install_with_cleanup(
        &self,
        result: Result<String, HopperInstallError>,
        cleanup: Result<(), HopperInstallError>,
    ) -> Result<String, HopperInstallError> {
        match (result, cleanup) {
            (Ok(launcher), Ok(())) => Ok(launcher),
            (Err(error), Ok(())) => Err(error),
            (Ok(launcher), Err(cleanup)) => Err(HopperInstallError::InstallationCommitted {
                launcher,
                detail: format!(
                    "installation committed but cleanup failed: {}",
                    cleanup.message()
                ),
            }),
            (Err(error), Err(cleanup)) => Err(HopperInstallError::Installation(format!(
                "{}; mount cleanup failed: {}",
                error.message(),
                cleanup.message()
            ))),
        }
    }

    fn run_package_manager(
        &self,
        executable: &str,
        arguments: &[&str],
    ) -> Result<(), HopperInstallError> {
        let uid = self.run_capture("id", &["-u"])?;
        if uid.trim() == "0" {
            return self.run_checked(executable, arguments);
        }
        let mut elevated = Vec::with_capacity(arguments.len() + 1);
        elevated.push(executable);
        elevated.extend(arguments.iter().copied());
        self.run_checked("sudo", &elevated)
    }

    fn mac_destination(&self) -> PathBuf {
        self.home
            .join("Applications")
            .join(HOPPER_MAC_APPLICATION_NAME)
    }

    fn linux_destination(platform: HopperPlatform) -> &'static str {
        match platform {
            HopperPlatform::LinuxDeb | HopperPlatform::LinuxRpm | HopperPlatform::LinuxArch => {
                "/opt/hopper/bin/Hopper"
            }
            HopperPlatform::MacOs => "",
        }
    }
}

impl HopperInstallHost for SystemHopperInstallHost {
    fn fetch(&mut self, url: &str, max_bytes: usize) -> Result<Vec<u8>, HopperInstallError> {
        self.ensure_active()?;
        let mut response = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(120)))
            .max_redirects(0)
            .build()
            .new_agent()
            .get(url)
            .header("Accept", "application/json, application/octet-stream")
            .config()
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|error| {
                HopperInstallError::Download(format!("Hopper download failed: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(HopperInstallError::Download(format!(
                "Hopper download returned HTTP {}",
                response.status()
            )));
        }
        if response
            .body()
            .content_length()
            .is_some_and(|size| size > max_bytes as u64)
        {
            return Err(HopperInstallError::Download(
                "Hopper response exceeded the configured byte limit".to_owned(),
            ));
        }
        let mut bytes = Vec::new();
        response
            .body_mut()
            .with_config()
            .limit(max_bytes as u64)
            .reader()
            .read_to_end(&mut bytes)
            .map_err(|error| {
                HopperInstallError::Download(format!("Hopper response could not be read: {error}"))
            })?;
        self.ensure_active()?;
        Ok(bytes)
    }

    fn verify_publisher(
        &mut self,
        platform: HopperPlatform,
        package: &[u8],
        release: &HopperRelease,
    ) -> Result<(), HopperInstallError> {
        self.ensure_active()?;
        let root = tempfile::Builder::new()
            .prefix("rea-hopper-verify-")
            .tempdir()
            .map_err(|error| HopperInstallError::PublisherVerification(error.to_string()))?;
        let package_path = root.path().join("hopper.package");
        fs::write(&package_path, package)
            .map_err(|error| HopperInstallError::PublisherVerification(error.to_string()))?;
        match platform {
            HopperPlatform::MacOs => {
                let mount = root.path().join("mounted");
                fs::create_dir(&mount).map_err(|error| {
                    HopperInstallError::PublisherVerification(error.to_string())
                })?;
                self.run_checked(
                    "hdiutil",
                    &[
                        "attach",
                        "-readonly",
                        "-nobrowse",
                        "-mountpoint",
                        mount.to_str().unwrap_or_default(),
                        package_path.to_str().unwrap_or_default(),
                    ],
                )?;
                let result = (|| {
                    let bundle =
                        find_hopper_bundle(&mount, HopperInstallError::PublisherVerification)?;
                    self.run_verification(
                        "codesign",
                        &[
                            "--verify",
                            "--deep",
                            "--strict",
                            "--verbose=2",
                            bundle.to_str().unwrap_or_default(),
                        ],
                    )?;
                    let requirement = format!(
                        "identifier \"{HOPPER_MAC_BUNDLE_ID}\" and anchor apple generic and certificate leaf[subject.OU] = \"{HOPPER_PUBLISHER_TEAM}\""
                    );
                    self.run_verification(
                        "codesign",
                        &[
                            "--verify",
                            "--strict",
                            &format!("-R{requirement}"),
                            bundle.to_str().unwrap_or_default(),
                        ],
                    )
                })();
                let cleanup = self.detach_mount(&mount);
                self.finish_with_cleanup(result, cleanup)
            }
            HopperPlatform::LinuxDeb | HopperPlatform::LinuxRpm | HopperPlatform::LinuxArch => {
                let signature = release.signature.as_deref().ok_or_else(|| {
                    HopperInstallError::PublisherVerification(
                        "Linux release omitted its detached signature".to_owned(),
                    )
                })?;
                let signature_path = root.path().join("hopper.asc");
                let key_path = root.path().join("hopper-public-key.asc");
                let signature_bytes = base64::engine::general_purpose::STANDARD
                    .decode(signature)
                    .map_err(|error| {
                        HopperInstallError::PublisherVerification(error.to_string())
                    })?;
                fs::write(&signature_path, signature_bytes).map_err(|error| {
                    HopperInstallError::PublisherVerification(error.to_string())
                })?;
                let key = self.fetch(HOPPER_PUBLIC_KEY_URL, 64 * 1024)?;
                fs::write(&key_path, key).map_err(|error| {
                    HopperInstallError::PublisherVerification(error.to_string())
                })?;
                self.run_verification(
                    "gpg",
                    &[
                        "--batch",
                        "--no-auto-key-retrieve",
                        "--homedir",
                        root.path().to_str().unwrap_or_default(),
                        "--import",
                        key_path.to_str().unwrap_or_default(),
                    ],
                )?;
                let status = self.run_capture(
                    "gpg",
                    &[
                        "--batch",
                        "--no-auto-key-retrieve",
                        "--homedir",
                        root.path().to_str().unwrap_or_default(),
                        "--status-fd=1",
                        "--verify",
                        signature_path.to_str().unwrap_or_default(),
                        package_path.to_str().unwrap_or_default(),
                    ],
                )?;
                if !status.contains(HOPPER_LINUX_PRIMARY_FINGERPRINT) {
                    return Err(HopperInstallError::PublisherVerification(
                        "Linux package signature did not resolve to REA's pinned Hopper publisher"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }

    fn install_verified(
        &mut self,
        platform: HopperPlatform,
        package: &[u8],
        release: &HopperRelease,
        replace_existing: bool,
    ) -> Result<String, HopperInstallError> {
        self.ensure_active()?;
        let root = tempfile::Builder::new()
            .prefix("rea-hopper-install-")
            .tempdir()
            .map_err(|error| HopperInstallError::Installation(error.to_string()))?;
        let archive = root.path().join("hopper.package");
        fs::write(&archive, package)
            .map_err(|error| HopperInstallError::Installation(error.to_string()))?;
        match platform {
            HopperPlatform::MacOs => self.install_macos(&archive, release, replace_existing),
            HopperPlatform::LinuxDeb | HopperPlatform::LinuxRpm | HopperPlatform::LinuxArch => {
                let executable = match platform {
                    HopperPlatform::LinuxDeb => "apt-get",
                    HopperPlatform::LinuxRpm => "dnf",
                    HopperPlatform::LinuxArch => "pacman",
                    HopperPlatform::MacOs => unreachable!(),
                };
                let archive_text = archive.to_string_lossy().into_owned();
                let args: Vec<&str> = if matches!(platform, HopperPlatform::LinuxDeb) {
                    vec!["install", "-y", &archive_text]
                } else if matches!(platform, HopperPlatform::LinuxRpm) {
                    vec!["install", "-y", &archive_text]
                } else {
                    vec!["-U", "--noconfirm", &archive_text]
                };
                self.run_package_manager(executable, &args)?;
                if let Err(error) = self.ensure_active() {
                    return Err(HopperInstallError::InstallationPartial(format!(
                        "Hopper package manager may have committed before cancellation: {}",
                        error.message()
                    )));
                }
                let launcher = Self::linux_destination(platform).to_owned();
                if let Err(error) =
                    verify_launcher_digest(Path::new(&launcher), &release.main_exe_hash)
                {
                    return Err(HopperInstallError::InstallationPartial(format!(
                        "Hopper package manager committed but launcher verification failed: {}",
                        error.message()
                    )));
                }
                Ok(launcher)
            }
        }
    }
}

impl SystemHopperInstallHost {
    fn install_macos(
        &self,
        archive: &Path,
        release: &HopperRelease,
        replace_existing: bool,
    ) -> Result<String, HopperInstallError> {
        let root = tempfile::Builder::new()
            .prefix("rea-hopper-mount-")
            .tempdir()
            .map_err(|error| HopperInstallError::Installation(error.to_string()))?;
        let mount = root.path().join("mounted");
        fs::create_dir(&mount)
            .map_err(|error| HopperInstallError::Installation(error.to_string()))?;
        self.run_checked(
            "hdiutil",
            &[
                "attach",
                "-readonly",
                "-nobrowse",
                "-mountpoint",
                mount.to_str().unwrap_or_default(),
                archive.to_str().unwrap_or_default(),
            ],
        )?;
        let destination = self.mac_destination();
        let result = (|| {
            let source = find_hopper_bundle(&mount, HopperInstallError::Installation)?;
            if destination.exists() && !replace_existing {
                return Err(HopperInstallError::Installation(format!(
                    "{HOPPER_MAC_APPLICATION_NAME} already exists; rerun with replacement approval"
                )));
            }
            let parent = destination.parent().ok_or_else(|| {
                HopperInstallError::Installation(
                    "Hopper destination has no parent directory".to_owned(),
                )
            })?;
            fs::create_dir_all(parent)
                .map_err(|error| HopperInstallError::Installation(error.to_string()))?;
            let stage_root = tempfile::Builder::new()
                .prefix(".rea-hopper-stage-")
                .tempdir_in(parent)
                .map_err(|error| HopperInstallError::Installation(error.to_string()))?;
            let stage = stage_root.path().join("new.app");
            let backup = stage_root.path().join("previous.app");
            self.run_checked(
                "ditto",
                &[
                    source.to_str().unwrap_or_default(),
                    stage.to_str().unwrap_or_default(),
                ],
            )?;
            let staged_launcher = stage.join("Contents/MacOS/hopper");
            verify_launcher_digest(&staged_launcher, &release.main_exe_hash)?;
            if destination.exists() {
                fs::rename(&destination, &backup)
                    .map_err(|error| HopperInstallError::Installation(error.to_string()))?;
            }
            if let Err(error) = fs::rename(&stage, &destination) {
                if backup.exists() {
                    if let Err(rollback) = fs::rename(&backup, &destination) {
                        let retained_root = stage_root.keep();
                        return Err(HopperInstallError::Installation(format!(
                            "installation commit failed: {error}; rollback failed: {rollback}; retained backup is owned by {}",
                            retained_root.display()
                        )));
                    }
                }
                return Err(HopperInstallError::Installation(error.to_string()));
            }
            if backup.exists() {
                if let Err(error) = fs::remove_dir_all(&backup) {
                    let retained_root = stage_root.keep();
                    return Err(HopperInstallError::InstallationCommitted {
                        launcher: destination
                            .join("Contents/MacOS/hopper")
                            .to_string_lossy()
                            .into_owned(),
                        detail: format!(
                            "installation committed but retained backup cleanup failed at {}: {error}",
                            retained_root.display()
                        ),
                    });
                }
            }
            let launcher = destination
                .join("Contents/MacOS/hopper")
                .to_string_lossy()
                .into_owned();
            let stage_root_path = stage_root.path().to_owned();
            if let Err(error) = stage_root.close() {
                return Err(HopperInstallError::InstallationCommitted {
                    launcher,
                    detail: format!(
                        "installation committed but staging cleanup failed at {}: {error}",
                        stage_root_path.display()
                    ),
                });
            }
            Ok(launcher)
        })();
        let cleanup = self.detach_mount(&mount);
        self.finish_install_with_cleanup(result, cleanup)
    }
}

fn verify_launcher_digest(path: &Path, expected: &str) -> Result<(), HopperInstallError> {
    let bytes = fs::read(path).map_err(|error| {
        HopperInstallError::Integrity(format!(
            "installed Hopper launcher could not be read: {error}"
        ))
    })?;
    let actual = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != expected {
        return Err(HopperInstallError::Integrity(
            "installed Hopper launcher SHA-256 did not match the official release identity"
                .to_owned(),
        ));
    }
    Ok(())
}

fn find_hopper_bundle(
    mount: &Path,
    error_kind: fn(String) -> HopperInstallError,
) -> Result<PathBuf, HopperInstallError> {
    let entries = fs::read_dir(mount).map_err(|error| {
        error_kind(format!(
            "mounted Hopper image could not be inspected: {error}"
        ))
    })?;

    let mut candidates = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            error_kind(format!(
                "mounted Hopper image entry could not be read: {error}"
            ))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            error_kind(format!(
                "mounted Hopper bundle type could not be read: {error}"
            ))
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if file_type.is_dir() && name.starts_with("Hopper") && name.ends_with(".app") {
            candidates.push(entry.path());
        }
    }

    candidates.sort();
    candidates.into_iter().next().ok_or_else(|| {
        error_kind("mounted Hopper image did not contain a Hopper application bundle".to_owned())
    })
}

/// Build the complete no-side-effect plan shown before setup approval.
pub fn hopper_setup_plan(
    platform: HopperPlatform,
    cache_directory: Option<&Path>,
    existing_launcher: Option<&Path>,
) -> Value {
    let cache = cache_directory
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<REA cache>/hopper-releases/<launcher-sha256>".to_owned());
    json!({
        "id": "install_hopper",
        "kind": "install_hopper",
        "label": "Hopper deep-analysis provider",
        "platform": platform.label(),
        "approved": false,
        "external": true,
        "networkOrigins": [HOPPER_RELEASES_URL, HOPPER_PUBLIC_KEY_URL, HOPPER_DOWNLOAD_PREFIX],
        "integrity": {
            "release": "official public channel metadata",
            "package": "declared byte length and SHA-1",
            "launcher": "declared main executable SHA-256",
            "linuxPublisher": HOPPER_LINUX_PRIMARY_FINGERPRINT,
            "macPublisher": "Developer ID Application: Cryptic Apps (2AMA2753NF)"
        },
        "cacheDirectory": cache,
        "existingLauncher": existing_launcher.map(|path| path.to_string_lossy().into_owned()),
        "replacement": "same-volume staged transaction with retained cleanup failure",
        "remediation": "Review this plan and rerun with --yes before any network, package-manager, or application mutation."
    })
}

/// Execute an approved install. Release parsing and byte identity are checked
/// before the platform host receives any package bytes for mutation.
pub fn install_hopper(request: &HopperInstallRequest, host: &mut dyn HopperInstallHost) -> Value {
    if !request.approved {
        return json!({
            "status": "needs_confirmation",
            "reason": "approval_required",
            "plan": hopper_setup_plan(request.platform, None, None),
            "remediation": "Rerun with --yes after reviewing the disclosed Hopper installation plan."
        });
    }

    let result = (|| {
        let feed_bytes = host.fetch(HOPPER_RELEASES_URL, HOPPER_DOWNLOAD_BYTES)?;
        let feed: Value = serde_json::from_slice(&feed_bytes)
            .map_err(|error| HopperInstallError::ReleaseMetadata(error.to_string()))?;
        let release = parse_release(feed.get(request.platform.feed_key()), request.platform)?;
        let package = host.fetch(
            &release.filename,
            HopperDownloadLimit::for_release(&release),
        )?;
        verify_package(&package, &release)?;
        host.verify_publisher(request.platform, &package, &release)?;
        let installation = host.install_verified(
            request.platform,
            &package,
            &release,
            request.replace_existing,
        );
        let installation = match installation {
            Ok(launcher) => HopperInstallationResult::Installed(launcher),
            Err(HopperInstallError::InstallationCommitted { launcher, detail }) => {
                HopperInstallationResult::InstalledWithCleanup { launcher, detail }
            }
            Err(error) => return Err(error),
        };
        Ok::<_, HopperInstallError>((release, installation))
    })();

    match result {
        Ok((release, HopperInstallationResult::Installed(launcher))) => json!({
            "status": "installed",
            "version": release.version,
            "package": release.filename,
            "packageSha1": release.file_hash,
            "launcherSha256": release.main_exe_hash,
            "launcherPath": launcher,
            "publisher": match request.platform {
                HopperPlatform::MacOs => "Developer ID Application: Cryptic Apps (2AMA2753NF)",
                HopperPlatform::LinuxDeb | HopperPlatform::LinuxRpm | HopperPlatform::LinuxArch => HOPPER_LINUX_PRIMARY_FINGERPRINT,
            },
        }),
        Ok((release, HopperInstallationResult::InstalledWithCleanup { launcher, detail })) => {
            json!({
                "status": "installed",
                "cleanup": "pending",
                "cleanupDetail": detail,
                "version": release.version,
                "package": release.filename,
                "packageSha1": release.file_hash,
                "launcherSha256": release.main_exe_hash,
                "launcherPath": launcher,
                "publisher": match request.platform {
                    HopperPlatform::MacOs => "Developer ID Application: Cryptic Apps (2AMA2753NF)",
                    HopperPlatform::LinuxDeb | HopperPlatform::LinuxRpm | HopperPlatform::LinuxArch => HOPPER_LINUX_PRIMARY_FINGERPRINT,
                },
            })
        }
        Err(HopperInstallError::InstallationPartial(detail)) => json!({
            "status": "partial",
            "reason": "installation_partial",
            "detail": detail,
            "remediation": "Inspect the package-manager state and Hopper launcher before retrying; REA could not prove that the committed installation matches the selected release.",
        }),
        Err(error) => json!({
            "status": "failed",
            "reason": error.reason(),
            "detail": error.message(),
            "remediation": "No package is accepted until release identity, publisher, and launcher verification succeed. Review the diagnostic and retry after correcting the underlying failure."
        }),
    }
}

struct HopperDownloadLimit;
impl HopperDownloadLimit {
    fn for_release(release: &HopperRelease) -> usize {
        release.file_length.min(HOPPER_DOWNLOAD_BYTES)
    }
}

fn parse_release(
    value: Option<&Value>,
    platform: HopperPlatform,
) -> Result<HopperRelease, HopperInstallError> {
    let object = value.and_then(Value::as_object).ok_or_else(|| {
        HopperInstallError::ReleaseMetadata(format!(
            "Hopper feed omitted {} release metadata",
            platform.feed_key()
        ))
    })?;
    let string = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let version = string("version").ok_or_else(|| {
        HopperInstallError::ReleaseMetadata("release version is missing".to_owned())
    })?;
    let filename = string("filename").ok_or_else(|| {
        HopperInstallError::ReleaseMetadata("release filename is missing".to_owned())
    })?;
    let download_path = filename.strip_prefix(HOPPER_DOWNLOAD_PREFIX);
    if !filename.starts_with(HOPPER_DOWNLOAD_PREFIX)
        || !download_path.is_some_and(|path| path.starts_with("Hopper-"))
        || !filename.ends_with(platform.suffix())
        || filename
            .chars()
            .any(|character| matches!(character, '?' | '#' | '@'))
    {
        return Err(HopperInstallError::ReleaseMetadata(
            "release is outside Hopper's official public channel".to_owned(),
        ));
    }
    let file_length = string("file_length")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0 && *value <= HOPPER_DOWNLOAD_BYTES)
        .ok_or_else(|| {
            HopperInstallError::ReleaseMetadata("release file length is invalid".to_owned())
        })?;
    let file_hash = string("file_hash")
        .filter(|value| {
            value.len() == 40
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| {
            HopperInstallError::ReleaseMetadata("release SHA-1 is invalid".to_owned())
        })?;
    let main_exe_hash = string("main_exe_hash")
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| {
            HopperInstallError::ReleaseMetadata("release launcher SHA-256 is invalid".to_owned())
        })?;
    let public = string("public").as_deref() == Some("1");
    let beta = string("beta").as_deref() == Some("1");
    if !public || beta {
        return Err(HopperInstallError::ReleaseMetadata(
            "release is not the public stable Hopper channel".to_owned(),
        ));
    }
    let signature = string("signature");
    if matches!(
        platform,
        HopperPlatform::LinuxDeb | HopperPlatform::LinuxRpm | HopperPlatform::LinuxArch
    ) {
        let encoded = signature.as_deref().ok_or_else(|| {
            HopperInstallError::ReleaseMetadata(
                "Linux release omitted its detached publisher signature".to_owned(),
            )
        })?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| {
                HopperInstallError::ReleaseMetadata(
                    "Linux release publisher signature is not valid base64".to_owned(),
                )
            })?;
    }
    Ok(HopperRelease {
        version,
        filename,
        file_length,
        file_hash,
        main_exe_hash,
        signature,
        public,
        beta,
    })
}

fn verify_package(package: &[u8], release: &HopperRelease) -> Result<(), HopperInstallError> {
    if package.len() != release.file_length {
        return Err(HopperInstallError::Integrity(format!(
            "package length {} did not match declared {}",
            package.len(),
            release.file_length
        )));
    }
    let digest = Sha1::digest(package);
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != release.file_hash.to_ascii_lowercase() {
        return Err(HopperInstallError::Integrity(
            "package SHA-1 did not match the official release identity".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_core::cancellation::Cancellation;

    #[test]
    fn plan_discloses_identity_and_approval_boundary() {
        let plan = hopper_setup_plan(HopperPlatform::LinuxDeb, None, None);
        assert_eq!(plan["id"], "install_hopper");
        assert_eq!(plan["approved"], false);
        assert_eq!(
            plan["integrity"]["linuxPublisher"],
            HOPPER_LINUX_PRIMARY_FINGERPRINT
        );
    }

    #[test]
    fn rejects_wrong_public_channel() {
        let feed = json!({"Ubuntu / Mint": {"version":"6.6.0","filename":"https://example.test/Hopper.deb","file_length":"1","file_hash":"0000000000000000000000000000000000000000","main_exe_hash":"0000000000000000000000000000000000000000000000000000000000000000","public":"1","beta":"0"}});
        let error = parse_release(feed.get("Ubuntu / Mint"), HopperPlatform::LinuxDeb)
            .expect_err("channel must be rejected");
        assert!(matches!(error, HopperInstallError::ReleaseMetadata(_)));
    }

    #[test]
    fn launcher_digest_rejects_tampered_artifact() {
        let directory = tempfile::tempdir().expect("temporary fixture directory");
        let launcher = directory.path().join("hopper");
        fs::write(&launcher, b"fixture launcher").expect("write launcher fixture");
        let error = verify_launcher_digest(
            &launcher,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect_err("tampered launcher must be rejected");
        assert!(matches!(error, HopperInstallError::Integrity(_)));
    }

    #[test]
    fn system_host_honours_cancellation_before_network_or_process_effects() {
        let directory = tempfile::tempdir().expect("temporary fixture directory");
        let cancellation = Cancellation::default();
        cancellation.cancel("fixture cancellation");
        let mut host =
            SystemHopperInstallHost::new(directory.path(), BTreeMap::new(), cancellation);

        let error = host
            .fetch("https://fixture.invalid/hopper.json", 1024)
            .expect_err("cancelled host must not fetch");
        assert!(matches!(error, HopperInstallError::Cancelled(_)));
    }
}
