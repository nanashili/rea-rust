//! Classify an observed `--version` banner against the audited release line.
//!
//! Compatibility owner: `src/firmware/FirmwareVersion.ts`.
use super::release::{BINWALK_RELEASE, UNBLOB_RELEASE};
/// Caller-supplied firmware engine selected by the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Binwalk,
    Unblob,
}
impl Engine {
    pub fn id(self) -> &'static str {
        match self {
            Self::Binwalk => "binwalk",
            Self::Unblob => "unblob",
        }
    }
    /// `firmwareEngineLabel`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Binwalk => "Binwalk",
            Self::Unblob => "Unblob",
        }
    }
    fn release_version(self) -> &'static str {
        match self {
            Self::Binwalk => BINWALK_RELEASE.version,
            Self::Unblob => UNBLOB_RELEASE.version,
        }
    }
}
struct ReleaseNumber {
    major: u64,
    minor: u64,
    #[allow(dead_code)]
    patch: u64,
    suffix: String,
    token: String,
}
/// `/^(\d+)\.(\d+)\.(\d+)([-+][0-9A-Za-z.-]+)?$/u`.
fn parse_token(token: &str) -> Option<ReleaseNumber> {
    // Split the optional suffix beginning at the first `-` or `+`.
    let (core, suffix) = match token.find(['-', '+']) {
        Some(index) => (&token[..index], token[index..].to_owned()),
        None => (token, String::new()),
    };
    // The suffix body must be non-empty and contain only [0-9A-Za-z.-].
    if !suffix.is_empty() {
        let body = &suffix[1..];
        if body.is_empty()
            || !body
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        {
            return None;
        }
    }
    let mut parts = core.split('.');
    let major = parse_segment(parts.next()?)?;
    let minor = parse_segment(parts.next()?)?;
    let patch = parse_segment(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    // Number.isSafeInteger: each segment at most 2^53 - 1.
    if [major, minor, patch]
        .iter()
        .any(|part| *part > 9_007_199_254_740_991)
    {
        return None;
    }
    Some(ReleaseNumber {
        major,
        minor,
        patch,
        suffix,
        token: token.to_owned(),
    })
}
fn parse_segment(segment: &str) -> Option<u64> {
    if segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    segment.parse::<u64>().ok()
}
fn verified_release(engine: Engine) -> ReleaseNumber {
    parse_token(engine.release_version()).expect("FIRMWARE_RELEASES version is a release number")
}
/// `firmwareReleaseLine`, such as `Binwalk 3.1.x`.
pub fn release_line(engine: Engine) -> String {
    let verified = verified_release(engine);
    format!("{} {}.{}.x", engine.label(), verified.major, verified.minor)
}
/// Admission of one observed `--version` banner.
#[derive(Clone, Debug)]
pub enum Admission {
    Verified { version: String },
    Compatible { version: String, limitation: String },
    Unsupported { message: String },
    Unresolved { message: String },
}
fn version_token(engine: Engine, banner: &str) -> Option<String> {
    match engine {
        Engine::Binwalk => banner.strip_prefix("binwalk ").map(str::to_owned),
        Engine::Unblob => Some(banner.to_owned()),
    }
}
/// `admitFirmwareVersion`.
pub fn admit(engine: Engine, banner: &str) -> Admission {
    let token = version_token(engine, banner);
    let parsed = token.as_deref().and_then(parse_token);
    let verified = verified_release(engine);
    let accepted = format!(
        "accepted releases are {} (verified with {})",
        release_line(engine),
        verified.token
    );
    let Some(parsed) = parsed else {
        let displayed = if banner.is_empty() { "missing" } else { banner };
        return Admission::Unresolved {
            message: format!("Unsupported tool version {displayed}; {accepted}."),
        };
    };
    if parsed.major != verified.major || parsed.minor != verified.minor {
        return Admission::Unsupported {
            message: format!("Unsupported tool version {banner}; {accepted}."),
        };
    }
    if parsed.token == verified.token {
        return Admission::Verified {
            version: parsed.token,
        };
    }
    let line = format!("{}.{}.x", verified.major, verified.minor);
    let _ = &parsed.suffix;
    Admission::Compatible {
        limitation: format!(
            "This session uses {} {}. The report parser is verified against {}; other {} builds are accepted and the observed version is reported.",
            engine.label(),
            parsed.token,
            verified.token,
            line
        ),
        version: parsed.token,
    }
}
