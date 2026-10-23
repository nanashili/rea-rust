//! Admission of one observed `wakaru --version` banner.
//!
//! Compatibility owner: `src/javascript/recovery/WakaruVersion.ts`.
//!
//! The TS uses `semver.valid`/`satisfies(token, "^1.13.0")`. That range is
//! `>=1.13.0 <2.0.0` over strict `X.Y.Z` releases; this module reproduces that
//! exact classification without a new crate dependency because the only
//! reachable call site is the Linux execution path.

use crate::javascript_recovery::release::{WAKARU_ACCEPTED_RANGE, WAKARU_RELEASE_VERSION};

/// Admission of one observed `wakaru --version` banner.
pub enum WakaruVersionAdmission {
    Verified { version: String },
    Compatible { version: String, limitation: String },
    Unsupported { message: String },
}

/// Caller-facing accepted releases, naming the verified build.
pub fn wakaru_release_line() -> String {
    format!("Wakaru {WAKARU_ACCEPTED_RANGE} (verified with {WAKARU_RELEASE_VERSION})")
}

/// A strict `major.minor.patch` release with no pre-release or build metadata,
/// matching `semver.valid(token) === token`.
fn parse_release(token: &str) -> Option<(u64, u64, u64)> {
    let mut parts = token.split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    let patch = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let parse_core = |part: &str| -> Option<u64> {
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        if !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        part.parse::<u64>().ok()
    };
    Some((parse_core(major)?, parse_core(minor)?, parse_core(patch)?))
}

/// `satisfies(token, "^1.13.0")`: `>=1.13.0 <2.0.0`.
fn satisfies_accepted((major, minor, patch): (u64, u64, u64)) -> bool {
    major == 1 && (minor, patch) >= (13, 0)
}

/// Classify a `wakaru <version>` banner against the accepted release range.
pub fn admit_wakaru_version(banner: &str) -> WakaruVersionAdmission {
    let token = banner.strip_prefix("wakaru ");
    let admitted = token.and_then(parse_release);
    match admitted {
        Some(release) if satisfies_accepted(release) => {
            let token = token.unwrap_or_default();
            if token == WAKARU_RELEASE_VERSION {
                WakaruVersionAdmission::Verified {
                    version: token.to_owned(),
                }
            } else {
                WakaruVersionAdmission::Compatible {
                    version: token.to_owned(),
                    limitation: format!(
                        "This session uses Wakaru {token}. The report parser is verified against {WAKARU_RELEASE_VERSION}; other {WAKARU_ACCEPTED_RANGE} releases are accepted and the observed version is reported."
                    ),
                }
            }
        }
        _ => {
            let reported = if banner.is_empty() { "missing" } else { banner };
            WakaruVersionAdmission::Unsupported {
                message: format!(
                    "Unsupported Wakaru version {reported}; accepted releases are {}",
                    wakaru_release_line()
                ),
            }
        }
    }
}
