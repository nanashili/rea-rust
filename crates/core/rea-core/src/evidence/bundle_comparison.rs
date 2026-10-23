//! Deterministic, evidence-qualified comparison of authenticated bundle contents.

use crate::{evidence::bundle::EvidenceBundle, residual_unknown::ResidualUnknown};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

const ONE_SIDED_RECORD_LIMITATION: &str = "EvidenceBundle has no inventory completeness marker; one-sided membership may reflect incomplete capture.";
const ONE_SIDED_HISTORY_LIMITATION: &str = "EvidenceBundle has no inventory completeness marker; one-sided history membership remains unknown.";
const BUNDLE_LIMITATION: &str =
    "EvidenceBundle has no inventory completeness marker; one-sided membership remains unknown.";

/// Explicitly pair records that represent an observation across bundle versions.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecordPair {
    /// Evidence ID in the left bundle.
    pub left_evidence_id: String,
    /// Evidence ID in the right bundle.
    pub right_evidence_id: String,
}

/// Invalid explicit pairing supplied to a bundle comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleComparisonError {
    /// The pair names an Evidence ID absent from the left bundle.
    MissingLeftEvidence(String),
    /// The pair names an Evidence ID absent from the right bundle.
    MissingRightEvidence(String),
    /// At least one Evidence ID was paired more than once.
    NonBijectivePairs,
}

impl fmt::Display for BundleComparisonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLeftEvidence(id) => {
                write!(
                    formatter,
                    "Explicit pair references missing left evidence {id}"
                )
            }
            Self::MissingRightEvidence(id) => {
                write!(
                    formatter,
                    "Explicit pair references missing right evidence {id}"
                )
            }
            Self::NonBijectivePairs => {
                formatter.write_str("Explicit evidence pairs must be one-to-one")
            }
        }
    }
}

impl std::error::Error for BundleComparisonError {}

/// Deterministic comparison result with unresolved membership kept explicit.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct BundleComparison {
    /// Overall comparison state.
    pub status: &'static str,
    /// Canonical SHA-256 digest of the left bundle.
    pub left_bundle_sha256: String,
    /// Canonical SHA-256 digest of the right bundle.
    pub right_bundle_sha256: String,
    /// Totals grouped by Evidence and residual-unknown history semantics.
    pub summary: ComparisonSummary,
    /// Classified differences, sorted by their stable comparison key.
    pub changes: Vec<BundleChange>,
    /// Limitations that apply to the whole comparison.
    pub limitations: Vec<&'static str>,
}

/// Aggregate counts for a bundle comparison.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct ComparisonSummary {
    /// Identical records or explicitly paired identical identities.
    pub records_unchanged: usize,
    /// Reserved for a bundle format with an inventory completeness marker.
    pub records_added: usize,
    /// Reserved for a bundle format with an inventory completeness marker.
    pub records_removed: usize,
    /// Explicitly paired records with different Evidence identities.
    pub records_changed: usize,
    /// Histories with identical authenticated revision sequences.
    pub unknowns_unchanged: usize,
    /// Reserved for a bundle format with an inventory completeness marker.
    pub unknowns_added: usize,
    /// Reserved for a bundle format with an inventory completeness marker.
    pub unknowns_removed: usize,
    /// Histories where one authenticated revision sequence strictly extends the other.
    pub unknowns_advanced: usize,
    /// Histories whose authenticated revision sequences diverge.
    pub unknowns_diverged: usize,
    /// Changes whose conclusion is unresolved or contradictory.
    pub unresolved: usize,
}

/// One Evidence or residual-unknown history comparison.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct BundleChange {
    /// Kind of compared entity.
    pub entity: &'static str,
    /// Stable Evidence ID, unknown ID, or explicit pair key.
    pub key: String,
    /// Classification of the observed membership or history relation.
    pub classification: &'static str,
    /// Strength of the conclusion supported by this bundle format.
    pub conclusion_kind: &'static str,
    /// Evidence IDs supporting the left side of this change.
    pub left_evidence_ids: Vec<String>,
    /// Evidence IDs supporting the right side of this change.
    pub right_evidence_ids: Vec<String>,
    /// Latest or identity digest from the left side, when present.
    pub left_digest: Option<String>,
    /// Latest or identity digest from the right side, when present.
    pub right_digest: Option<String>,
    /// Limits on the inference available for this change.
    pub limitations: Vec<&'static str>,
}

/// Compare two validated bundles, applying only caller-supplied record pairs.
pub fn compare_bundles(
    left: &EvidenceBundle,
    right: &EvidenceBundle,
    pairs: &[RecordPair],
) -> Result<BundleComparison, BundleComparisonError> {
    let (mut changes, mut summary) = compare_records(left, right, pairs)?;
    let (unknown_changes, unknown_summary) = compare_unknowns(left, right);
    changes.extend(unknown_changes);
    add_unknown_summary(&mut summary, unknown_summary);
    changes.sort_by(compare_changes);

    summary.unresolved = changes
        .iter()
        .filter(|change| change.conclusion_kind != "observed_change")
        .count();

    let limitations = if changes.iter().any(|change| !change.limitations.is_empty()) {
        vec![BUNDLE_LIMITATION]
    } else {
        Vec::new()
    };
    let status = if summary.unresolved > 0 {
        "unknown"
    } else if changes.is_empty() {
        "unchanged"
    } else {
        "changed"
    };

    Ok(BundleComparison {
        status,
        left_bundle_sha256: left.canonical_sha256().to_owned(),
        right_bundle_sha256: right.canonical_sha256().to_owned(),
        summary,
        changes,
        limitations,
    })
}

fn compare_records(
    left: &EvidenceBundle,
    right: &EvidenceBundle,
    pairs: &[RecordPair],
) -> Result<(Vec<BundleChange>, ComparisonSummary), BundleComparisonError> {
    let left_ids = left
        .records()
        .iter()
        .map(|record| record.evidence_id())
        .collect::<std::collections::BTreeSet<_>>();
    let right_ids = right
        .records()
        .iter()
        .map(|record| record.evidence_id())
        .collect::<std::collections::BTreeSet<_>>();
    let mut paired_left = std::collections::BTreeSet::new();
    let mut paired_right = std::collections::BTreeSet::new();
    let mut changes = Vec::new();
    let mut changed = 0;

    for pair in pairs {
        if !left_ids.contains(pair.left_evidence_id.as_str()) {
            return Err(BundleComparisonError::MissingLeftEvidence(
                pair.left_evidence_id.clone(),
            ));
        }
        if !right_ids.contains(pair.right_evidence_id.as_str()) {
            return Err(BundleComparisonError::MissingRightEvidence(
                pair.right_evidence_id.clone(),
            ));
        }
        if !paired_left.insert(pair.left_evidence_id.as_str())
            || !paired_right.insert(pair.right_evidence_id.as_str())
        {
            return Err(BundleComparisonError::NonBijectivePairs);
        }

        if pair.left_evidence_id == pair.right_evidence_id {
            continue;
        }

        changed += 1;
        changes.push(BundleChange {
            entity: "evidence",
            key: format!("pair:{}:{}", pair.left_evidence_id, pair.right_evidence_id),
            classification: "changed",
            conclusion_kind: "observed_change",
            left_evidence_ids: vec![pair.left_evidence_id.clone()],
            right_evidence_ids: vec![pair.right_evidence_id.clone()],
            left_digest: Some(pair.left_evidence_id[3..].to_owned()),
            right_digest: Some(pair.right_evidence_id[3..].to_owned()),
            limitations: Vec::new(),
        });
    }

    let common = left_ids
        .iter()
        .filter(|id| {
            right_ids.contains(**id) && !paired_left.contains(**id) && !paired_right.contains(**id)
        })
        .count();
    let removed = left_ids
        .iter()
        .filter(|id| {
            !paired_left.contains(**id)
                && (!right_ids.contains(**id) || paired_right.contains(**id))
        })
        .copied()
        .collect::<Vec<_>>();
    let added = right_ids
        .iter()
        .filter(|id| {
            !paired_right.contains(**id) && (!left_ids.contains(**id) || paired_left.contains(**id))
        })
        .copied()
        .collect::<Vec<_>>();

    for id in removed {
        changes.push(one_sided_record_change(id, "left"));
    }
    for id in added {
        changes.push(one_sided_record_change(id, "right"));
    }

    Ok((
        changes,
        ComparisonSummary {
            records_unchanged: common + pairs.len() - changed,
            records_changed: changed,
            ..ComparisonSummary::default()
        },
    ))
}

fn one_sided_record_change(id: &str, side: &'static str) -> BundleChange {
    let is_left = side == "left";
    let digest = id.strip_prefix("ev_").map(str::to_owned);
    BundleChange {
        entity: "evidence",
        key: id.to_owned(),
        classification: "unknown",
        conclusion_kind: "unresolved_branch",
        left_evidence_ids: if is_left {
            vec![id.to_owned()]
        } else {
            Vec::new()
        },
        right_evidence_ids: if is_left {
            Vec::new()
        } else {
            vec![id.to_owned()]
        },
        left_digest: if is_left { digest.clone() } else { None },
        right_digest: if is_left { None } else { digest },
        limitations: vec![ONE_SIDED_RECORD_LIMITATION],
    }
}

fn compare_unknowns(
    left: &EvidenceBundle,
    right: &EvidenceBundle,
) -> (Vec<BundleChange>, ComparisonSummary) {
    let left_histories = histories(left.unknowns());
    let right_histories = histories(right.unknowns());
    let unknown_ids = left_histories
        .keys()
        .chain(right_histories.keys())
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let mut changes = Vec::new();
    let mut summary = ComparisonSummary::default();

    for id in unknown_ids {
        let left_history = left_histories.get(id).map(Vec::as_slice);
        let right_history = right_histories.get(id).map(Vec::as_slice);
        let (Some(left_history), Some(right_history)) = (left_history, right_history) else {
            changes.push(unknown_change(id, "unknown", left_history, right_history));
            continue;
        };

        let left_digests = revision_digests(left_history);
        let right_digests = revision_digests(right_history);
        if left_digests == right_digests {
            summary.unknowns_unchanged += 1;
            continue;
        }

        let advanced = is_strict_prefix(&left_digests, &right_digests)
            || is_strict_prefix(&right_digests, &left_digests);
        let classification = if advanced {
            summary.unknowns_advanced += 1;
            "history_advanced"
        } else {
            summary.unknowns_diverged += 1;
            "history_diverged"
        };
        changes.push(unknown_change(
            id,
            classification,
            Some(left_history),
            Some(right_history),
        ));
    }

    (changes, summary)
}

fn histories(unknowns: &[ResidualUnknown]) -> BTreeMap<&str, Vec<&ResidualUnknown>> {
    let mut histories = BTreeMap::new();
    for unknown in unknowns {
        histories
            .entry(unknown.unknown_id())
            .or_insert_with(Vec::new)
            .push(unknown);
    }
    histories
}

fn revision_digests<'a>(history: &[&'a ResidualUnknown]) -> Vec<&'a str> {
    history
        .iter()
        .map(|unknown| unknown.revision_digest())
        .collect()
}

fn is_strict_prefix(shorter: &[&str], longer: &[&str]) -> bool {
    shorter.len() < longer.len() && longer.starts_with(shorter)
}

fn unknown_change(
    id: &str,
    classification: &'static str,
    left: Option<&[&ResidualUnknown]>,
    right: Option<&[&ResidualUnknown]>,
) -> BundleChange {
    let (conclusion_kind, limitation) = match classification {
        "history_diverged" => ("contradiction", None),
        "history_advanced" => ("observed_change", None),
        _ => ("unresolved_branch", Some(ONE_SIDED_HISTORY_LIMITATION)),
    };
    BundleChange {
        entity: "residual_unknown",
        key: id.to_owned(),
        classification,
        conclusion_kind,
        left_evidence_ids: history_evidence_ids(left.unwrap_or_default()),
        right_evidence_ids: history_evidence_ids(right.unwrap_or_default()),
        left_digest: latest_digest(left),
        right_digest: latest_digest(right),
        limitations: limitation.into_iter().collect(),
    }
}

fn history_evidence_ids(history: &[&ResidualUnknown]) -> Vec<String> {
    history
        .iter()
        .flat_map(|unknown| unknown.referenced_evidence_ids())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn latest_digest(history: Option<&[&ResidualUnknown]>) -> Option<String> {
    history
        .and_then(|revisions| revisions.last())
        .map(|unknown| unknown.revision_digest().to_owned())
}

fn add_unknown_summary(summary: &mut ComparisonSummary, unknowns: ComparisonSummary) {
    summary.unknowns_unchanged = unknowns.unknowns_unchanged;
    summary.unknowns_advanced = unknowns.unknowns_advanced;
    summary.unknowns_diverged = unknowns.unknowns_diverged;
}

fn compare_changes(left: &BundleChange, right: &BundleChange) -> std::cmp::Ordering {
    (
        left.entity,
        left.key.as_str(),
        left.classification,
        left.left_digest.as_deref().unwrap_or(""),
        left.right_digest.as_deref().unwrap_or(""),
    )
        .cmp(&(
            right.entity,
            right.key.as_str(),
            right.classification,
            right.left_digest.as_deref().unwrap_or(""),
            right.right_digest.as_deref().unwrap_or(""),
        ))
}
