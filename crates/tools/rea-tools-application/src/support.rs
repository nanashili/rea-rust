//! Shared delivery helpers mirroring `recordSessionEvidenceSources` and
//! `recordResult` in `src/server/registerApplicationTools/helpers.ts`.
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::Evidence;
use rea_mcp::{Session, ToolOutput};
use serde_json::Value;

/// `recordSessionEvidenceSources`: record each source in order, stopping at
/// the first session rejection.
pub fn record_sources(session: &Session, sources: &[Value]) -> Result<(), AnalysisError> {
    for source in sources {
        let raw = serde_json::value::to_raw_value(source)
            .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
        session.record_raw(&raw)?;
    }
    Ok(())
}

/// Deliver derived Evidence after its sources were recorded.
pub fn deliver(
    session: &Session,
    sources: &[Value],
    evidence: Result<Evidence, AnalysisError>,
) -> ToolOutput {
    let evidence = match evidence {
        Ok(evidence) => evidence,
        Err(error) => return ToolOutput::Failure(error),
    };
    if let Err(error) = record_sources(session, sources) {
        return ToolOutput::Failure(error);
    }
    ToolOutput::Evidence(evidence)
}

/// `recordResult(..., unknownKind)`: record the sources, then retain the
/// derived Evidence atomically with its residual unknown when one applies.
pub fn deliver_with_unknown(
    session: &Session,
    sources: &[Value],
    evidence: Result<Evidence, AnalysisError>,
    unknown: impl FnOnce(&Evidence) -> Option<Value>,
) -> ToolOutput {
    let evidence = match evidence {
        Ok(evidence) => evidence,
        Err(error) => return ToolOutput::Failure(error),
    };
    if let Err(error) = record_sources(session, sources) {
        return ToolOutput::Failure(error);
    }
    if let Some(unknown) = unknown(&evidence) {
        let integrity =
            |error: serde_json::Error| AnalysisError::evidence_integrity(error.to_string());
        let recorded = evidence.to_raw().map_err(integrity).and_then(|raw| {
            let unknown = serde_json::value::to_raw_value(&unknown).map_err(integrity)?;
            session
                .records()
                .record_evidence_with_unknown(&raw, &unknown)
                .map_err(rea_mcp::session::record_error)
        });
        if let Err(error) = recorded {
            return ToolOutput::Failure(error);
        }
    }
    ToolOutput::Evidence(evidence)
}

/// `unknownRegistration(evidence, kind)` in
/// `src/server/registerApplicationTools/helpers.ts`.
pub fn comparison_unknown(evidence: &Evidence, kind: &str) -> Value {
    let id = evidence.id();
    let question = match kind {
        "application-version-comparison" => {
            "Which application entities remain unmatched or ambiguous across these versions?"
        }
        "source-to-bundle-comparison" => {
            "Which historical source files remain unmatched or ambiguously mapped to the shipped bundle?"
        }
        _ => {
            "Which selected JavaScript export return shapes remain dynamic, incomplete, or ambiguously paired?"
        }
    };
    let mut probes = vec![serde_json::json!({
        "operation": "analyze_javascript_application",
        "rationale": "Repeat static reconstruction with complete artifacts and source maps when available.",
    })];
    if kind == "application-version-comparison" {
        probes.push(serde_json::json!({
            "operation": "reconcile_javascript_runtime",
            "rationale": "Add passive runtime Evidence without promoting it to static fact.",
        }));
    }
    serde_json::json!({
        "question": format!("{question} (comparison {id})"),
        "severity": "medium",
        "domain": kind,
        "supporting_evidence_ids": [id],
        "contradicting_evidence_ids": [],
        "required_authority": "shipped-artifact",
        "required_confidence": "observed",
        "required_environment": null,
        "recommended_probes": probes,
        "relationships": [],
    })
}
