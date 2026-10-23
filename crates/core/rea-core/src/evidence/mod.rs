//! Artifact-bound Evidence. Semantic identity excludes only display-subject fields.
pub mod bundle;
pub mod bundle_comparison;
pub mod envelope;
pub mod record;
use crate::canonical_json;
use serde::Serialize;
use serde_json::value::RawValue;
use std::{fmt, path::Path};

/// Exact canonical SHA-256 spelling shared by subjects and record selectors.
/// Validation does not lowercase or otherwise rewrite caller-selected identity.
pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Native formats used by static artifact inspections.
#[derive(Clone, Copy, Debug, Serialize)]
pub enum NativeFormat {
    /// SQLite database.
    #[serde(rename = "sqlite")]
    Sqlite,
    /// ELF image.
    #[serde(rename = "elf")]
    Elf,
    /// PE image.
    #[serde(rename = "pe")]
    Pe,
    /// Thin Mach-O image.
    #[serde(rename = "mach-o")]
    MachO,
    /// Android application package.
    #[serde(rename = "apk")]
    AndroidPackage,
    /// EVM bytecode carrier.
    #[serde(rename = "evm")]
    Evm,
    /// Property-list document.
    #[serde(rename = "plist")]
    Plist,
    /// Compiled Interface Builder archive.
    #[serde(rename = "nib")]
    Nib,
    /// Local application bundle directory.
    #[serde(rename = "directory")]
    Directory,
}
/// Detected architecture vocabulary, distinct from provider display aliases.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    /// 32-bit x86.
    X86,
    /// 64-bit x86.
    #[serde(rename = "x86_64")]
    X86_64,
    /// ARM.
    Arm,
    /// AArch64.
    Arm64,
    /// MIPS family.
    Mips,
    /// RISC-V family.
    Riscv,
    /// PowerPC family.
    Powerpc,
    /// Hexagon DSP family.
    Hexagon,
}
/// Exact provider identity; migration does not silently substitute a provider.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Provider {
    /// Stable lookup identity.
    pub id: &'static str,
    /// Caller-visible name.
    pub name: &'static str,
    /// Source version or explicit unknown.
    pub version: Option<&'static str>,
}
#[derive(Debug, Serialize)]
struct Digest {
    sha256: String,
}
/// Admitted native subject with exact caller-selected path spelling.
#[derive(Debug, Serialize)]
pub struct Subject {
    name: String,
    digest: Digest,
    format: NativeFormat,
    architecture: Option<Architecture>,
    local_path: String,
}
impl Subject {
    /// Artifact lookup digest, independent of display path/name.
    pub fn sha256(&self) -> &str {
        &self.digest.sha256
    }
    /// Bind an absolute path and lower-case SHA-256 without resolving symlinks.
    ///
    /// # Errors
    /// Rejects nonabsolute/NUL paths and malformed digest text.
    pub fn new(
        path: &str,
        sha256: String,
        format: NativeFormat,
        architecture: Option<Architecture>,
    ) -> Result<Self, BuildError> {
        if !Path::new(path).is_absolute() || path.contains('\0') {
            return Err(BuildError::InvalidSubject(
                "expected an absolute NUL-free path",
            ));
        }
        if !is_sha256(&sha256) {
            return Err(BuildError::InvalidSubject("invalid SHA-256 digest"));
        }
        let name = Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("artifact")
            .to_owned();
        Ok(Self {
            name,
            digest: Digest { sha256 },
            format,
            architecture,
            local_path: path.to_owned(),
        })
    }
}
/// Source-linked locations for native artifact observations.
#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
pub enum Location {
    /// Exact admitted local path.
    #[serde(rename = "artifact-path")]
    ArtifactPath {
        /// Caller-selected spelling.
        path: String,
    },
    /// Half-open byte range.
    #[serde(rename = "file-offset-range")]
    FileOffsetRange {
        /// First included byte.
        start: u64,
        /// First excluded byte.
        end: u64,
    },
}
/// Typed facts and their retained coverage/limitations.
pub struct Observation<Result> {
    /// Named operation, never catalog position.
    pub operation: &'static str,
    /// Provider-validated facts.
    pub result: Result,
    /// Exact coverage and uncertainty statements.
    pub limitations: Vec<String>,
    /// Ordered source locations.
    pub locations: Vec<Location>,
}
#[derive(Debug, Serialize)]
struct Body {
    provider: Provider,
    analysis_profile: Option<()>,
    predicate_type: &'static str,
    operation: &'static str,
    parameters: Box<RawValue>,
    raw_result: Option<()>,
    normalized_result: Box<RawValue>,
    confidence: &'static str,
    authority: &'static str,
    environment: Option<()>,
    limitations: Vec<String>,
    relationship_coverage: Option<()>,
    locations: Vec<Location>,
    evidence_links: Vec<()>,
}
/// Immutable artifact Evidence. Its identity is constructed only by this owner.
#[derive(Debug, Serialize)]
pub struct ArtifactEvidence {
    evidence_id: String,
    subject: Subject,
    #[serde(flatten)]
    body: Body,
}
#[derive(Serialize)]
struct SemanticSubject<'a> {
    digest: &'a Digest,
    format: NativeFormat,
    architecture: Option<Architecture>,
}
#[derive(Serialize)]
struct Semantic<'a> {
    subject: SemanticSubject<'a>,
    #[serde(flatten)]
    body: &'a Body,
}

/// Borrowed discovery facts without copying or decoding the analysis payload.
#[derive(Serialize)]
pub struct RecordMetadata<'a> {
    /// Canonical observation identity.
    pub evidence_id: &'a str,
    /// Original admitted subject and display metadata.
    pub subject: &'a Subject,
    /// Producer identity.
    pub provider: Provider,
    /// Named producer operation.
    pub operation: &'static str,
    /// Observation confidence.
    pub confidence: &'static str,
    /// Observation authority.
    pub authority: &'static str,
    /// Artifact observations have no analysis profile.
    pub analysis_profile_digest: Option<()>,
    /// Number of producer limitations.
    pub limitation_count: usize,
}

/// Subject admission or semantic commitment failed.
#[derive(Debug)]
pub enum BuildError {
    /// Invalid subject/provider facts.
    InvalidSubject(&'static str),
    /// Operation-specific parameters are malformed.
    InvalidParameters(&'static str),
    /// Producer facts could not be frozen as lossless JSON.
    Encoding(serde_json::Error),
    /// Failed canonical commitment.
    Canonical(canonical_json::Error),
}
impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSubject(reason) => f.write_str(reason),
            Self::InvalidParameters(reason) => f.write_str(reason),
            Self::Encoding(error) => error.fmt(f),
            Self::Canonical(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Encoding(error) => Some(error),
            _ => None,
        }
    }
}
impl ArtifactEvidence {
    /// Commit observed, shipped-artifact facts with no profile or raw result.
    ///
    /// # Errors
    /// Invalid identity or failed canonicalization returns a tagged failure.
    /// The application must admit serialization size before calling this owner.
    pub fn new<Result: Serialize>(
        subject: Subject,
        provider: Provider,
        observation: Observation<Result>,
    ) -> std::result::Result<Self, BuildError> {
        Self::new_with_parameters(subject, provider, observation, serde_json::Map::new())
    }

    /// Commit artifact Evidence with operation-specific admitted parameters.
    ///
    /// The path remains owned by the Subject. Additional parameters must be a
    /// JSON object without a competing `path` value.
    ///
    /// # Errors
    /// Invalid identity or failed serialization/canonicalization returns a
    /// tagged failure.
    pub fn new_with_parameters<Result: Serialize, Parameters: Serialize>(
        subject: Subject,
        provider: Provider,
        observation: Observation<Result>,
        parameters: Parameters,
    ) -> std::result::Result<Self, BuildError> {
        let parameters = match serde_json::to_value(parameters).map_err(BuildError::Encoding)? {
            serde_json::Value::Object(mut additional) => {
                if additional.contains_key("path") {
                    return Err(BuildError::InvalidParameters(
                        "additional Evidence parameters cannot replace the subject path",
                    ));
                }
                let mut values = serde_json::Map::new();
                values.insert(
                    "path".into(),
                    serde_json::Value::String(subject.local_path.clone()),
                );
                values.append(&mut additional);
                serde_json::Value::Object(values)
            }
            _ => {
                return Err(BuildError::InvalidParameters(
                    "additional Evidence parameters must be an object",
                ));
            }
        };
        Self::new_with_exact_parameters(subject, provider, observation, parameters)
    }

    /// Commit artifact Evidence with the caller's exact operation parameters.
    ///
    /// This is for operations whose input is already bound to an active
    /// subject and therefore does not take or imply a `path` parameter.
    ///
    /// # Errors
    /// Invalid identity, a non-object parameter value, or failed
    /// serialization/canonicalization returns a tagged error.
    pub fn new_with_exact_parameters<Result: Serialize, Parameters: Serialize>(
        subject: Subject,
        provider: Provider,
        observation: Observation<Result>,
        parameters: Parameters,
    ) -> std::result::Result<Self, BuildError> {
        if provider.id.is_empty() || provider.name.is_empty() {
            return Err(BuildError::InvalidSubject("empty provider identity"));
        }
        let parameters = match serde_json::to_value(parameters).map_err(BuildError::Encoding)? {
            serde_json::Value::Object(parameters) => {
                serde_json::value::to_raw_value(&serde_json::Value::Object(parameters))
                    .map_err(BuildError::Encoding)?
            }
            _ => {
                return Err(BuildError::InvalidParameters(
                    "Evidence parameters must be an object",
                ));
            }
        };
        let body = Body {
            provider,
            analysis_profile: None,
            predicate_type: "rea.analysis",
            operation: observation.operation,
            parameters,
            raw_result: None,
            // Freeze once before computing identity. Serialize alone does not
            // imply immutability: a producer may contain Cells or borrowed state.
            normalized_result: serde_json::value::to_raw_value(&observation.result)
                .map_err(BuildError::Encoding)?,
            confidence: "observed",
            authority: "shipped-artifact",
            environment: None,
            limitations: observation.limitations,
            relationship_coverage: None,
            locations: observation.locations,
            evidence_links: Vec::new(),
        };
        let semantic = Semantic {
            subject: SemanticSubject {
                digest: &subject.digest,
                format: subject.format,
                architecture: subject.architecture,
            },
            body: &body,
        };
        let evidence_id = format!(
            "ev_{}",
            canonical_json::digest(&semantic).map_err(BuildError::Canonical)?
        );
        Ok(Self {
            evidence_id,
            subject,
            body,
        })
    }
    /// Stable semantic commitment.
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }
    /// Borrow the exact admitted target subject for later session-bound Evidence.
    pub fn subject(&self) -> &Subject {
        &self.subject
    }
    /// Project immutable metadata without inspecting normalized results.
    pub fn metadata(&self) -> RecordMetadata<'_> {
        RecordMetadata {
            evidence_id: &self.evidence_id,
            subject: &self.subject,
            provider: self.body.provider,
            operation: self.body.operation,
            confidence: self.body.confidence,
            authority: self.body.authority,
            analysis_profile_digest: None,
            limitation_count: self.body.limitations.len(),
        }
    }
    /// Canonical artifact manifest, excluding local display fields.
    pub fn artifact_manifest(&self) -> impl Serialize + '_ {
        SemanticSubject {
            digest: &self.subject.digest,
            format: self.subject.format,
            architecture: self.subject.architecture,
        }
    }
    /// Compare full semantic content, not just its digest or JSON field order.
    ///
    /// # Errors
    /// Canonical encoding failures remain explicit rather than becoming equality.
    pub fn agrees(&self, other: &Self) -> Result<bool, canonical_json::Error> {
        fn bytes(record: &ArtifactEvidence) -> Result<Vec<u8>, canonical_json::Error> {
            let value = serde_json::value::to_raw_value(&Semantic {
                subject: SemanticSubject {
                    digest: &record.subject.digest,
                    format: record.subject.format,
                    architecture: record.subject.architecture,
                },
                body: &record.body,
            })
            .map_err(canonical_json::Error::Json)?;
            let mut bytes = Vec::new();
            canonical_json::write(&value, &mut bytes)?;
            Ok(bytes)
        }
        if self.evidence_id != other.evidence_id {
            return Ok(false);
        }
        Ok(bytes(self)? == bytes(other)?)
    }
}
