//! Provider-neutral path planning, a direct port of
//! `src/domain/webScriptExportPlan.ts`. Safe URL layouts are preserved only
//! when every captured path is unambiguous.
use super::capture::{CapturedContent, CapturedWebScript};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use url::Url;

/// One planned file, or an explicit missing source with no filesystem effect.
pub struct PlannedWebScript {
    pub record: Value,
    /// The `relative_path` when the planned content is exported.
    pub exported_relative_path: Option<String>,
}

fn hash(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn reserved_segment(part: &str) -> bool {
    // `^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)` case-insensitive.
    let lower = part.to_ascii_lowercase();
    let base = lower.split('.').next().unwrap_or(&lower);
    matches!(base, "con" | "prn" | "aux" | "nul")
        || matches!(base.as_bytes(), [b'c', b'o', b'm', d] if (b'1'..=b'9').contains(d))
        || matches!(base.as_bytes(), [b'l', b'p', b't', d] if (b'1'..=b'9').contains(d))
}

fn portable_segment(part: &str) -> bool {
    !part.is_empty()
        && part
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_~.-".contains(character))
}

struct Candidate {
    path: Option<String>,
    reason: Option<String>,
}

/// `candidatePath`.
fn candidate_path(script: &CapturedWebScript) -> Candidate {
    let Ok(url) = Url::parse(&script.url) else {
        return Candidate {
            path: None,
            reason: Some("Source has no absolute HTTP URL (for example an inline script).".into()),
        };
    };
    if url.scheme() != "http" && url.scheme() != "https" {
        return Candidate {
            path: None,
            reason: Some("Source URL scheme has no local module layout mapping.".into()),
        };
    }
    let pathname = url.path();
    let parts: Vec<&str> = pathname
        .strip_prefix('/')
        .unwrap_or(pathname)
        .split('/')
        .collect();
    let ends_js =
        pathname.ends_with(".js") || pathname.ends_with(".mjs") || pathname.ends_with(".cjs");
    let bad_part = parts.iter().any(|part| {
        !portable_segment(part)
            || *part == "."
            || *part == ".."
            || part.ends_with('.')
            || reserved_segment(part)
    });
    if !ends_js || bad_part {
        return Candidate {
            path: None,
            reason: Some("URL path is not an ordinary portable JavaScript module path.".into()),
        };
    }
    let origin = url.origin().ascii_serialization();
    let reason = if url_declares_query_or_fragment(&url)
        || !url.username().is_empty()
        || url.password().is_some_and(|password| !password.is_empty())
    {
        Some("URL query, fragment, or credentials cannot select a canonical local module.".into())
    } else {
        None
    };
    Candidate {
        path: Some(format!("origins/{}/{}", hash(&origin), parts.join("/"))),
        reason,
    }
}

/// `urlDeclaresQueryOrFragment`: query or fragment spelled, including empty.
fn url_declares_query_or_fragment(url: &Url) -> bool {
    let href = url.as_str();
    href.contains('?') || href.contains('#')
}

/// `conflictingPaths`: register every exact prefix so repeated paths, or a
/// file that is also a directory prefix, isolate every affected source.
fn conflicting_paths(candidates: &[Candidate]) -> HashSet<usize> {
    struct Entry {
        indices: Vec<usize>,
        files: Vec<usize>,
    }
    let mut prefixes: HashMap<String, Entry> = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let Some(path) = &candidate.path else {
            continue;
        };
        let parts: Vec<&str> = path.split('/').collect();
        for position in 0..parts.len() {
            let spelling = parts[..=position].join("/");
            let entry = prefixes.entry(spelling).or_insert_with(|| Entry {
                indices: Vec::new(),
                files: Vec::new(),
            });
            entry.indices.push(index);
            if position == parts.len() - 1 {
                entry.files.push(index);
            }
        }
    }
    let mut conflicts = HashSet::new();
    for entry in prefixes.values() {
        if entry.files.len() > 1
            || (!entry.files.is_empty() && entry.indices.len() > entry.files.len())
        {
            for index in &entry.indices {
                conflicts.insert(*index);
            }
        }
    }
    conflicts
}

/// `planWebScriptExport`.
pub fn plan(scripts: &[CapturedWebScript]) -> Vec<PlannedWebScript> {
    let candidates: Vec<Candidate> = scripts.iter().map(candidate_path).collect();
    let conflicts = conflicting_paths(&candidates);
    scripts
        .iter()
        .enumerate()
        .map(|(index, script)| {
            let CapturedContent::Captured {
                sha256,
                media_type,
                redacted,
                representation,
                bytes,
            } = &script.content
            else {
                let CapturedContent::Unavailable { reason, message } = &script.content else {
                    unreachable!("content is captured or unavailable");
                };
                return PlannedWebScript {
                    record: serde_json::json!({
                        "source": script.source,
                        "url": script.url,
                        "content": { "state": "unavailable", "reason": reason, "message": message },
                    }),
                    exported_relative_path: None,
                };
            };
            let candidate = &candidates[index];
            let reason: Value = if conflicts.contains(&index) {
                Value::String(
                    "Captured paths collide by content version or file/directory prefix.".into(),
                )
            } else {
                candidate
                    .reason
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null)
            };
            let path = if conflicts.contains(&index) {
                None
            } else {
                candidate.path.clone()
            };
            let (relative_path, layout) = match &path {
                Some(path) => (path.clone(), "url-path"),
                None => (
                    format!(
                        "isolated/source-{}-{}.js",
                        index + 1,
                        hash(&serde_json::to_string(&script.source).unwrap_or_default())
                    ),
                    "isolated",
                ),
            };
            PlannedWebScript {
                record: serde_json::json!({
                    "source": script.source,
                    "url": script.url,
                    "content": {
                        "state": "exported",
                        "relative_path": relative_path,
                        "layout": layout,
                        "layout_reason": reason,
                        "sha256": sha256,
                        "bytes": bytes.len(),
                        "media_type": media_type,
                        "redacted": redacted,
                        "representation": representation,
                    },
                }),
                exported_relative_path: Some(relative_path),
            }
        })
        .collect()
}
