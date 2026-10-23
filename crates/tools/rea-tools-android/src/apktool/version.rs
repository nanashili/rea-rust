//! Apktool `--version` interpretation.
//!
//! Compatibility owner: `parseApktoolVersionOutput` in
//! `src/apktool/ApktoolConfiguration.ts`. The first non-empty trimmed line is
//! parsed with node-semver semantics; CVE advisory limitations are disclosed
//! for versions predating the upstream fixes, and the minimum supported
//! version is 2.7.0.

/// A semantic version parsed with node-semver's loose acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Dot-separated prerelease identifiers (empty when none).
    pub prerelease: Vec<Identifier>,
    /// Dot-separated build-metadata identifiers (empty when none).
    pub build: Vec<String>,
}

/// One prerelease identifier: numeric identifiers order below alphanumeric ones.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Identifier {
    Numeric(u64),
    Alphanumeric(String),
}

impl Identifier {
    fn parse(text: &str) -> Self {
        if !text.is_empty()
            && text.bytes().all(|byte| byte.is_ascii_digit())
            && (text.len() == 1 || !text.starts_with('0'))
        {
            if let Ok(value) = text.parse::<u64>() {
                return Self::Numeric(value);
            }
        }
        Self::Alphanumeric(text.to_owned())
    }
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

impl SemVer {
    /// `semver.parse(line)`: a strict `major.minor.patch` core with optional
    /// `-prerelease` and `+build`, tolerating a leading `v` and surrounding
    /// whitespace as node-semver does.
    pub fn parse(input: &str) -> Option<Self> {
        let text = input.trim();
        let text = text.strip_prefix('v').unwrap_or(text);
        let text = text.strip_prefix('=').unwrap_or(text).trim_start();

        let (core_and_pre, build) = match text.split_once('+') {
            Some((head, tail)) => (head, Some(tail)),
            None => (text, None),
        };
        let (core, prerelease) = match core_and_pre.split_once('-') {
            Some((head, tail)) => (head, Some(tail)),
            None => (core_and_pre, None),
        };

        let mut parts = core.split('.');
        let major = parse_numeric(parts.next()?)?;
        let minor = parse_numeric(parts.next()?)?;
        let patch = parse_numeric(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }

        let prerelease = match prerelease {
            None => Vec::new(),
            Some(text) => {
                let mut identifiers = Vec::new();
                for segment in text.split('.') {
                    if !is_identifier(segment) {
                        return None;
                    }
                    identifiers.push(Identifier::parse(segment));
                }
                identifiers
            }
        };
        let build = match build {
            None => Vec::new(),
            Some(text) => {
                let mut identifiers = Vec::new();
                for segment in text.split('.') {
                    if !is_identifier(segment) {
                        return None;
                    }
                    identifiers.push(segment.to_owned());
                }
                identifiers
            }
        };

        Some(Self {
            major,
            minor,
            patch,
            prerelease,
            build,
        })
    }

    /// `compareMain`: order by the version core, ignoring prerelease and build.
    pub fn compare_main(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }

    /// `compare`: the core order, then node-semver's prerelease precedence
    /// (a version with a prerelease is lower than the same core without one).
    pub fn compare(&self, other: &Self) -> std::cmp::Ordering {
        let main = self.compare_main(other);
        if main != std::cmp::Ordering::Equal {
            return main;
        }
        compare_prerelease(&self.prerelease, &other.prerelease)
    }
}

fn parse_numeric(segment: &str) -> Option<u64> {
    if segment.is_empty() || (segment.len() > 1 && segment.starts_with('0')) {
        return None;
    }
    if !segment.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    segment.parse().ok()
}

fn compare_prerelease(left: &[Identifier], right: &[Identifier]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (left.is_empty(), right.is_empty()) {
        (true, true) => return Ordering::Equal,
        // No prerelease outranks any prerelease.
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        (false, false) => {}
    }
    let mut index = 0;
    loop {
        match (left.get(index), right.get(index)) {
            (None, None) => return Ordering::Equal,
            // The shorter prerelease set is lower when it is a prefix.
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(a), Some(b)) => {
                let order = compare_identifier(a, b);
                if order != Ordering::Equal {
                    return order;
                }
            }
        }
        index += 1;
    }
}

fn compare_identifier(left: &Identifier, right: &Identifier) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (left, right) {
        (Identifier::Numeric(a), Identifier::Numeric(b)) => a.cmp(b),
        // Numeric identifiers always have lower precedence than alphanumeric ones.
        (Identifier::Numeric(_), Identifier::Alphanumeric(_)) => Ordering::Less,
        (Identifier::Alphanumeric(_), Identifier::Numeric(_)) => Ordering::Greater,
        (Identifier::Alphanumeric(a), Identifier::Alphanumeric(b)) => a.cmp(b),
    }
}

/// The supported launcher identity (`ApktoolClientIdentity`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIdentity {
    pub version: String,
    pub supports_documented_version: bool,
    pub limitations: Vec<String>,
}

/// Either a recognized version or an unrecognized one with the reported line.
pub enum VersionOutcome {
    Recognized(ClientIdentity),
    Unrecognized { reported_version: Option<String> },
}

/// `parseApktoolVersionOutput(stdout, platform)`.
pub fn parse_version_output(stdout: &str, platform: &str) -> VersionOutcome {
    let line = stdout
        .split('\n')
        .map(|entry| entry.trim_end_matches('\r').trim())
        .find(|entry| !entry.is_empty());
    let Some(line) = line else {
        return VersionOutcome::Unrecognized {
            reported_version: None,
        };
    };
    let Some(parsed) = SemVer::parse(line) else {
        return VersionOutcome::Unrecognized {
            reported_version: Some(line.to_owned()),
        };
    };

    // Debian's exact -dirty marker denotes a downstream release build; preserve
    // the reported spelling and compare only the core for that one case.
    let downstream_release = parsed.prerelease.len() == 1
        && parsed.prerelease[0] == Identifier::Alphanumeric("dirty".to_owned())
        && parsed.build.is_empty();
    let at_least = |release: &str| -> bool {
        let release = SemVer::parse(release).expect("static release literal parses");
        let order = if downstream_release {
            parsed.compare_main(&release)
        } else {
            parsed.compare(&release)
        };
        order != std::cmp::Ordering::Less
    };

    let mut limitations = Vec::new();
    let disclose = |fix: &str, advisory: &str, slug: &str| -> String {
        format!(
            "Reported apktool version {} predates the upstream {fix} fix for {advisory} (decoded resource paths could escape the output directory). Verify the selected decoder's patches before decoding untrusted APKs; launcher version alone does not establish engine contents or downstream backports. https://github.com/iBotPeaches/Apktool/security/advisories/{slug}",
            json_string(line)
        )
    };
    if !at_least("2.9.2") {
        limitations.push(disclose("2.9.2", "CVE-2024-21633", "GHSA-2hqv-2xv4-5h5w"));
    }
    if platform == "win32" && !at_least("2.9.3") {
        limitations.push(disclose(
            "2.9.3",
            "GHSA-vgwr-4w3p-xmjv on Windows",
            "GHSA-vgwr-4w3p-xmjv",
        ));
    }
    if parsed.major == 3 && parsed.minor == 0 && !at_least("3.0.2") {
        let mut message = disclose("3.0.2", "CVE-2026-39973", "GHSA-m8mh-x359-vm8m");
        if parsed.patch == 0 {
            message.push_str(
                " Inclusion of the 3.0.0 release line is source-derived; the advisory lists 3.0.1.",
            );
        }
        limitations.push(message);
    }

    VersionOutcome::Recognized(ClientIdentity {
        version: line.to_owned(),
        supports_documented_version: at_least("2.7.0"),
        limitations,
    })
}

/// `JSON.stringify(line)`: quote and escape a string exactly as JS does for the
/// characters Apktool version lines can contain.
pub fn json_string(value: &str) -> String {
    serde_json::Value::String(value.to_owned()).to_string()
}
