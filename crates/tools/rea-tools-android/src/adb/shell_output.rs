//! Parsers for fixed observation commands run through `adb shell`.
//!
//! Compatibility owner: `src/adb/AdbShellOutput.ts`. Unparseable lines are
//! retained rather than dropped.
use std::sync::OnceLock;

fn split_lines(text: &str) -> Vec<&str> {
    text.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect()
}

fn is_safe_integer(value: f64) -> bool {
    value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0
}

/// One process row of `ps -A`.
#[derive(Clone, Debug)]
pub struct AdbProcessEntry {
    pub user: String,
    pub pid: i64,
    pub ppid: Option<i64>,
    pub rss: Option<i64>,
    pub state: Option<String>,
    pub name: String,
}

pub struct ProcessListOutput {
    pub columns: Option<String>,
    pub processes: Vec<AdbProcessEntry>,
    pub unparsed_lines: Vec<String>,
}

fn process_line_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$")
            .unwrap()
    })
}

fn header_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^USER\s+PID\s+PPID\b").unwrap())
}

fn parse_safe_i64(text: &str) -> Option<i64> {
    text.parse::<f64>()
        .ok()
        .filter(|value| is_safe_integer(*value))
        .map(|value| value as i64)
}

/// `parseProcessListOutput(stdout)`.
pub fn parse_process_list_output(stdout: &str) -> ProcessListOutput {
    let mut processes = Vec::new();
    let mut unparsed_lines = Vec::new();
    let mut columns = None;
    for raw_line in split_lines(stdout) {
        let line = raw_line.trim_end();
        if line.is_empty() {
            continue;
        }
        if header_regex().is_match(line) {
            columns = Some(line.trim().to_owned());
            continue;
        }
        let Some(captures) = process_line_regex().captures(line) else {
            unparsed_lines.push(line.to_owned());
            continue;
        };
        processes.push(AdbProcessEntry {
            user: captures[1].to_owned(),
            pid: captures[2].parse::<i64>().unwrap_or(0),
            ppid: parse_safe_i64(&captures[3]),
            rss: parse_safe_i64(&captures[5]),
            state: Some(captures[8].to_owned()),
            name: captures[9].trim().to_owned(),
        });
    }
    ProcessListOutput {
        columns,
        processes,
        unparsed_lines,
    }
}

/// One feature of `pm list features`.
#[derive(Clone, Debug)]
pub struct AdbFeatureEntry {
    pub name: String,
    pub version: Option<i64>,
}

pub struct FeatureListOutput {
    pub features: Vec<AdbFeatureEntry>,
    pub unparsed_lines: Vec<String>,
}

fn feature_line_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^feature:([^=\s]+)(?:=(0x[0-9a-fA-F]+|\d+))?$").unwrap())
}

fn parse_feature_version(text: &str) -> Option<i64> {
    if let Some(hex) = text.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else {
        parse_safe_i64(text)
    }
}

/// `parseFeatureListOutput(stdout)`.
pub fn parse_feature_list_output(stdout: &str) -> FeatureListOutput {
    let mut features = Vec::new();
    let mut unparsed_lines = Vec::new();
    for raw_line in split_lines(stdout) {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(captures) = feature_line_regex().captures(line) else {
            unparsed_lines.push(line.to_owned());
            continue;
        };
        let version = captures
            .get(2)
            .and_then(|m| parse_feature_version(m.as_str()));
        features.push(AdbFeatureEntry {
            name: captures[1].to_owned(),
            version,
        });
    }
    FeatureListOutput {
        features,
        unparsed_lines,
    }
}

/// One binder service of `service list`.
#[derive(Clone, Debug)]
pub struct AdbServiceEntry {
    pub name: String,
    pub interface: Option<String>,
}

pub struct ServiceListOutput {
    pub services: Vec<AdbServiceEntry>,
    pub unparsed_lines: Vec<String>,
}

fn service_line_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"^\s*(?:\d+\s+)?([A-Za-z0-9._$/-]+):\s*\[([^\]]*)\]\s*$").unwrap()
    })
}

fn found_services_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^Found \d+ services:").unwrap())
}

/// `parseServiceListOutput(stdout)`.
pub fn parse_service_list_output(stdout: &str) -> ServiceListOutput {
    let mut services = Vec::new();
    let mut unparsed_lines = Vec::new();
    for raw_line in split_lines(stdout) {
        let line = raw_line.trim_end();
        let trimmed = line.trim();
        if trimmed.is_empty() || found_services_regex().is_match(trimmed) {
            continue;
        }
        let Some(captures) = service_line_regex().captures(line) else {
            if !trimmed.is_empty() {
                unparsed_lines.push(trimmed.to_owned());
            }
            continue;
        };
        let interface = if &captures[2] == "" {
            None
        } else {
            Some(captures[2].to_owned())
        };
        services.push(AdbServiceEntry {
            name: captures[1].to_owned(),
            interface,
        });
    }
    ServiceListOutput {
        services,
        unparsed_lines,
    }
}

/// A width/height pair.
#[derive(Clone, Copy, Debug)]
pub struct Size {
    pub width: i64,
    pub height: i64,
}

/// `parseWmSizeOutput(stdout)`.
pub fn parse_wm_size_output(stdout: &str) -> (Option<Size>, Option<Size>) {
    fn size_regex() -> &'static regex::Regex {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^Physical size:\s+(\d+)x(\d+)$").unwrap())
    }
    fn override_regex() -> &'static regex::Regex {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^Override size:\s+(\d+)x(\d+)$").unwrap())
    }
    let mut physical = None;
    let mut override_size = None;
    for line in split_lines(stdout) {
        let trimmed = line.trim();
        if let Some(captures) = size_regex().captures(trimmed) {
            physical = Some(Size {
                width: captures[1].parse().unwrap_or(0),
                height: captures[2].parse().unwrap_or(0),
            });
        }
        if let Some(captures) = override_regex().captures(trimmed) {
            override_size = Some(Size {
                width: captures[1].parse().unwrap_or(0),
                height: captures[2].parse().unwrap_or(0),
            });
        }
    }
    (physical, override_size)
}

/// `parseWmDensityOutput(stdout)`.
pub fn parse_wm_density_output(stdout: &str) -> (Option<i64>, Option<i64>) {
    fn physical_regex() -> &'static regex::Regex {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^Physical density:\s+(\d+)$").unwrap())
    }
    fn override_regex() -> &'static regex::Regex {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^Override density:\s+(\d+)$").unwrap())
    }
    fn bare_regex() -> &'static regex::Regex {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^(\d+)$").unwrap())
    }
    let mut physical = None;
    let mut override_density = None;
    let mut bare = None;
    for line in split_lines(stdout) {
        let trimmed = line.trim();
        if let Some(captures) = physical_regex().captures(trimmed) {
            physical = captures[1].parse().ok();
        }
        if let Some(captures) = override_regex().captures(trimmed) {
            override_density = captures[1].parse().ok();
        }
        if bare.is_none()
            && let Some(captures) = bare_regex().captures(trimmed)
        {
            bare = captures[1].parse().ok();
        }
    }
    (physical.or(bare), override_density)
}

/// One focus declaration.
#[derive(Clone, Debug)]
pub struct FocusDeclaration {
    pub field: &'static str,
    pub value: Option<String>,
    pub raw_line: String,
}

/// A focus context, scoped to a display or unscoped.
#[derive(Clone, Debug)]
pub struct FocusContext {
    pub scope: &'static str,
    pub display_id: Option<String>,
    pub header_line: Option<String>,
    pub declarations: Vec<FocusDeclaration>,
}

/// Parsed window focus observation (before client/serial/source attachment).
pub struct WindowFocusObservation {
    pub focused_window: Option<String>,
    pub focused_app: Option<String>,
    pub focus_summary: &'static str,
    pub focus_contexts: Vec<FocusContext>,
    pub observed_lines: Vec<String>,
}

fn display_id_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^Display:\s+mDisplayId=(-?[0-9]+)(?:\s|$)").unwrap())
}

/// `parseWindowFocusOutput(stdout)`.
pub fn parse_window_focus_output(stdout: &str) -> WindowFocusObservation {
    let mut contexts: Vec<FocusContext> = Vec::new();
    let mut observed_lines = Vec::new();
    let mut current: Option<usize> = None;
    for line in split_lines(stdout) {
        let trimmed = line.trim();
        if trimmed.starts_with("Display:") {
            let display_id = display_id_regex()
                .captures(trimmed)
                .map(|caps| caps[1].to_owned());
            contexts.push(FocusContext {
                scope: "display",
                display_id,
                header_line: Some(line.to_owned()),
                declarations: Vec::new(),
            });
            current = Some(contexts.len() - 1);
            observed_lines.push(line.to_owned());
            continue;
        }
        let field = if trimmed.starts_with("mCurrentFocus=") {
            Some("mCurrentFocus")
        } else if trimmed.starts_with("mFocusedApp=") {
            Some("mFocusedApp")
        } else {
            None
        };
        let Some(field) = field else {
            continue;
        };
        if current.is_none() {
            contexts.push(FocusContext {
                scope: "unscoped",
                display_id: None,
                header_line: None,
                declarations: Vec::new(),
            });
            current = Some(contexts.len() - 1);
        }
        let value_text = trimmed[field.len() + 1..].trim();
        let value = if value_text == "null" {
            None
        } else {
            Some(value_text.to_owned())
        };
        let index = current.unwrap();
        contexts[index].declarations.push(FocusDeclaration {
            field,
            value,
            raw_line: line.to_owned(),
        });
        observed_lines.push(line.to_owned());
    }
    let single = contexts.len() == 1;
    let windows: Vec<&FocusDeclaration> = if single {
        contexts[0]
            .declarations
            .iter()
            .filter(|d| d.field == "mCurrentFocus")
            .collect()
    } else {
        Vec::new()
    };
    let apps: Vec<&FocusDeclaration> = if single {
        contexts[0]
            .declarations
            .iter()
            .filter(|d| d.field == "mFocusedApp")
            .collect()
    } else {
        Vec::new()
    };
    let declared = contexts.iter().any(|c| !c.declarations.is_empty());
    let summary = if !declared {
        "unavailable"
    } else if single && windows.len() <= 1 && apps.len() <= 1 {
        "single_context"
    } else {
        "ambiguous"
    };
    let focused_window = if summary == "single_context" {
        windows.first().and_then(|d| d.value.clone())
    } else {
        None
    };
    let focused_app = if summary == "single_context" {
        apps.first().and_then(|d| d.value.clone())
    } else {
        None
    };
    WindowFocusObservation {
        focused_window,
        focused_app,
        focus_summary: summary,
        focus_contexts: contexts,
        observed_lines,
    }
}

/// Projected `dumpsys package PACKAGE` facts.
#[derive(Clone, Debug, Default)]
pub struct AdbPackageDetails {
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub first_install_time: Option<String>,
    pub last_update_time: Option<String>,
    pub installer_package_name: Option<String>,
    pub user_id: Option<i64>,
    pub pkg_flags: Option<String>,
    pub requested_permissions: Option<i64>,
}

fn detail_line_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^\s+([A-Za-z][A-Za-z0-9_]*)=(.*)$").unwrap())
}

fn permission_entry_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^\s{2,}[A-Za-z0-9._]+(?:: restricted=true)?$").unwrap())
}

fn leading_signed_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^(-?\d+)").unwrap())
}

fn leading_unsigned_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^(\d+)").unwrap())
}

/// `parseDumpsysPackageOutput(stdout)`.
pub fn parse_dumpsys_package_output(stdout: &str) -> AdbPackageDetails {
    let mut details = AdbPackageDetails::default();
    let mut in_permissions = false;
    let mut has_permissions_section = false;
    let mut permissions = 0i64;
    let mut parsed_package_available: Option<bool> = None;
    for line in split_lines(stdout) {
        if line.trim().starts_with("requested permissions:") {
            has_permissions_section = true;
            in_permissions = true;
            continue;
        }
        if in_permissions && permission_entry_regex().is_match(line) {
            permissions += 1;
            continue;
        }
        in_permissions = false;
        let Some(captures) = detail_line_regex().captures(line) else {
            continue;
        };
        let key = &captures[1];
        let value = captures[2].trim();
        match key {
            "pkg" if parsed_package_available.is_none() => {
                if value == "null" {
                    parsed_package_available = Some(false);
                } else if value.starts_with("Package{") && value.ends_with('}') {
                    parsed_package_available = Some(true);
                }
            }
            "versionName" if details.version_name.is_none() => {
                details.version_name = if value.is_empty() {
                    None
                } else {
                    Some(value.to_owned())
                };
            }
            "versionCode" if details.version_code.is_none() => {
                if let Some(captures) = leading_signed_regex().captures(value) {
                    details.version_code = Some(captures[1].to_owned());
                }
            }
            "firstInstallTime" if details.first_install_time.is_none() => {
                details.first_install_time = if value.is_empty() {
                    None
                } else {
                    Some(value.to_owned())
                };
            }
            "lastUpdateTime" if details.last_update_time.is_none() => {
                details.last_update_time = if value.is_empty() {
                    None
                } else {
                    Some(value.to_owned())
                };
            }
            "installerPackageName" if details.installer_package_name.is_none() => {
                details.installer_package_name = if value.is_empty() {
                    None
                } else {
                    Some(value.to_owned())
                };
            }
            "userId" if details.user_id.is_none() => {
                if let Some(captures) = leading_unsigned_regex().captures(value) {
                    details.user_id = captures[1].parse().ok();
                }
            }
            "pkgFlags" if details.pkg_flags.is_none() => {
                details.pkg_flags = if value.is_empty() {
                    None
                } else {
                    Some(value.to_owned())
                };
            }
            _ => {}
        }
    }
    details.requested_permissions = match parsed_package_available {
        Some(false) => None,
        _ if has_permissions_section => Some(permissions),
        Some(true) => Some(0),
        _ => None,
    };
    details
}

/// `parseSettingsGetOutput(stdout)`.
pub fn parse_settings_get_output(stdout: &str) -> (Option<String>, bool) {
    let trimmed = strip_one_trailing_newline(stdout);
    if trimmed == "null" {
        (None, true)
    } else {
        (Some(trimmed.to_owned()), false)
    }
}

fn strip_one_trailing_newline(text: &str) -> &str {
    if let Some(stripped) = text.strip_suffix('\n') {
        stripped.strip_suffix('\r').unwrap_or(stripped)
    } else {
        text
    }
}

/// `parseBugreportCopiedPath(stdout)`.
pub fn parse_bugreport_copied_path(stdout: &str) -> Option<String> {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"(?m)^Bug report copied to (.+?)\r?$").unwrap());
    re.captures(stdout.trim()).map(|caps| caps[1].to_owned())
}

/// `packageChangeFailureReason(output)`.
pub fn package_change_failure_reason(output: &str) -> Option<String> {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"Failure \[([^\]]+)\]").unwrap());
    re.captures(output).map(|caps| caps[1].to_owned())
}

/// Verdict of `adb install`/`adb uninstall` output.
pub struct PackageChangeOutput {
    pub status: &'static str,
    pub reason: Option<String>,
}

/// `parsePackageChangeOutput(stdout)`.
pub fn parse_package_change_output(stdout: &str) -> PackageChangeOutput {
    static SUCCESS: OnceLock<regex::Regex> = OnceLock::new();
    let success = SUCCESS.get_or_init(|| regex::Regex::new(r"(?m)^Success$").unwrap());
    let text = stdout.trim();
    if success.is_match(text) {
        return PackageChangeOutput {
            status: "success",
            reason: None,
        };
    }
    let reason = package_change_failure_reason(text).or_else(|| {
        if text.is_empty() {
            None
        } else {
            Some(text.chars().take(512).collect())
        }
    });
    PackageChangeOutput {
        status: "failure",
        reason,
    }
}

/// `parseResolveActivityOutput(stdout)`.
pub fn parse_resolve_activity_output(stdout: &str) -> Option<String> {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let no_activity = RE.get_or_init(|| regex::Regex::new(r"(?i)^No activity found$").unwrap());
    let lines: Vec<String> = split_lines(stdout)
        .into_iter()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty() && !no_activity.is_match(line))
        .collect();
    lines.last().cloned()
}

/// Parsed `am start -W` report.
pub struct AmStartOutput {
    pub status: &'static str,
    pub started_activity: Option<String>,
    pub activity: Option<String>,
    pub reported_status: Option<String>,
    pub reason: Option<String>,
}

/// `parseAmStartOutput(stdout, stderr)`.
pub fn parse_am_start_output(stdout: &str, stderr: &str) -> AmStartOutput {
    let normalized_stdout = stdout.replace("\r\n", "\n");
    let normalized_stderr = stderr.replace("\r\n", "\n");

    let starting_re =
        regex::Regex::new(r"(?m)^Starting:[ \t]+Intent[ \t]*\{(.*)\}[ \t]*$").unwrap();
    let started_activity = starting_re
        .captures(&normalized_stdout)
        .map(|caps| caps[1].trim().to_owned());

    let activity_re = regex::Regex::new(r"(?m)^Activity:[ \t]*(.*)$").unwrap();
    let activity = activity_re
        .captures(&normalized_stdout)
        .map(|caps| caps[1].trim().to_owned())
        .filter(|value| !value.is_empty());

    let status_re = regex::Regex::new(r"(?m)^Status:[ \t]*(.*)$").unwrap();
    let statuses: Vec<String> = status_re
        .captures_iter(&normalized_stdout)
        .map(|caps| caps[1].trim().to_owned())
        .collect();
    let non_ok_status = statuses
        .iter()
        .find(|status| status.to_lowercase() != "ok")
        .cloned();
    let reported_status = non_ok_status.clone().or_else(|| statuses.first().cloned());

    let error_re = regex::Regex::new(r"(?i)^(?:Error|Exception)(?::|\b)(.*)$").unwrap();
    let mut error_reason: Option<String> = None;
    'outer: for stream in [&normalized_stdout, &normalized_stderr] {
        for line in stream.split('\n') {
            let line = line.trim();
            if let Some(captures) = error_re.captures(line) {
                let captured = captures.get(1).map(|m| m.as_str().trim().to_owned());
                error_reason = match captured {
                    Some(text) if !text.is_empty() => Some(text),
                    _ => Some(line.to_owned()),
                };
                break 'outer;
            }
        }
    }

    let status_reason = match non_ok_status.as_deref() {
        Some("") => Some("am start reported an empty status".to_owned()),
        None => None,
        Some(status) => Some(format!("am start reported status: {status}")),
    };

    let warning_re = regex::Regex::new(r"(?m)^Warning:").unwrap();
    let reason = error_reason.clone().or_else(|| {
        status_reason.clone().or_else(|| {
            let trimmed = normalized_stdout.trim();
            if warning_re.is_match(trimmed) {
                Some(trimmed.chars().take(512).collect())
            } else {
                None
            }
        })
    });

    if error_reason.is_some() || non_ok_status.is_some() {
        return AmStartOutput {
            status: "refused",
            started_activity,
            activity,
            reported_status,
            reason: Some(
                reason.unwrap_or_else(|| "am start did not report a successful launch".to_owned()),
            ),
        };
    }
    if started_activity.is_some() {
        return AmStartOutput {
            status: "started",
            started_activity,
            activity,
            reported_status,
            reason: None,
        };
    }
    let text = format!("{normalized_stdout}\n{normalized_stderr}");
    let text = text.trim();
    AmStartOutput {
        status: "refused",
        started_activity,
        activity,
        reported_status,
        reason: Some(reason.unwrap_or_else(|| {
            if text.is_empty() {
                "am start returned no activity".to_owned()
            } else {
                text.chars().take(512).collect()
            }
        })),
    }
}

/// `parsePngDimensions(bytes)`.
pub fn parse_png_dimensions(bytes: &[u8]) -> (Option<u32>, Option<u32>) {
    const SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    if bytes.len() < 24 || bytes[0..8] != SIGNATURE {
        return (None, None);
    }
    let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    (Some(width), Some(height))
}
