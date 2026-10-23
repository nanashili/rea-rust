//! One finite document-scoped window (`src/browser/execution/CdpExecutionWindow.ts`).
use super::iso_now;
use rea_core::analysis_error::AnalysisError;
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EndReason {
    WindowElapsed,
    DocumentChanged,
    TargetTerminated,
}

impl EndReason {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::WindowElapsed => "window_elapsed",
            Self::DocumentChanged => "document_changed",
            Self::TargetTerminated => "target_terminated",
        }
    }
}

pub(super) struct Window {
    frame_id: String,
    pub armed_at: Option<String>,
    pub ended_at: Option<String>,
    pub reason: Option<EndReason>,
    failure: Option<AnalysisError>,
}

impl Window {
    pub(super) fn new(frame_id: String) -> Self {
        Self {
            frame_id,
            armed_at: None,
            ended_at: None,
            reason: None,
            failure: None,
        }
    }

    /// `ingest`: collection ends on a main-document replacement.
    pub(super) fn ingest(&mut self, event: &Value) {
        let method = event.get("method").and_then(Value::as_str);
        if matches!(
            method,
            Some("Target.detachedFromTarget" | "Inspector.targetCrashed")
        ) {
            self.end(EndReason::TargetTerminated);
            return;
        }
        if !self.active() {
            return;
        }
        let params = event.get("params");
        if method == Some("Runtime.executionContextsCleared") {
            self.end(EndReason::DocumentChanged);
        }
        if method == Some("Page.frameNavigated") {
            if let Some(frame) = params
                .and_then(Value::as_object)
                .and_then(|params| params.get("frame"))
            {
                if frame
                    .as_object()
                    .is_some_and(|frame| !frame.contains_key("parentId"))
                {
                    self.end(EndReason::DocumentChanged);
                }
            }
        }
        if method == Some("Page.frameDetached")
            && params
                .and_then(Value::as_object)
                .and_then(|params| params.get("frameId"))
                .and_then(Value::as_str)
                == Some(self.frame_id.as_str())
        {
            self.end(EndReason::DocumentChanged);
        }
    }

    /// `active`.
    pub(super) fn active(&self) -> bool {
        self.armed_at.is_some() && self.reason.is_none() && self.ended_at.is_none()
    }

    /// `start`: arm at this point.
    pub(super) fn arm(&mut self) {
        self.armed_at = Some(iso_now());
    }

    pub(super) fn end(&mut self, reason: EndReason) {
        if self.reason.is_some() || self.failure.is_some() {
            return;
        }
        self.reason = Some(reason);
        self.ended_at = Some(iso_now());
    }

    pub(super) fn fail(&mut self, error: AnalysisError) {
        if self.reason.is_some() || self.failure.is_some() {
            return;
        }
        self.failure = Some(error);
        self.ended_at = Some(iso_now());
    }

    pub(super) fn check(&self) -> Result<(), AnalysisError> {
        self.failure.clone().map_or(Ok(()), Err)
    }
}
