//! Admission-release state for streamable HTTP exchanges.

/// Whether admission is held until dispatch or until the response finishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionLifetime {
    Dispatch,
    Response,
}

/// Tracks the independent completion signals used to release one admission slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeState {
    lifetime: AdmissionLifetime,
    dispatched: bool,
    input_ended: bool,
    response_ended: bool,
    pending_cleanups: usize,
    cleanup_failed: bool,
}

impl ExchangeState {
    pub const fn new(lifetime: AdmissionLifetime) -> Self {
        Self {
            lifetime,
            dispatched: false,
            input_ended: false,
            response_ended: false,
            pending_cleanups: 0,
            cleanup_failed: false,
        }
    }

    /// Record route completion and whether the incoming body still needs draining.
    pub fn dispatch_settled(&mut self, has_unread_body: bool, connection_destroyed: bool) {
        self.dispatched = true;
        if !has_unread_body || connection_destroyed {
            self.input_ended = true;
        }
    }

    pub fn input_ended(&mut self) {
        self.input_ended = true;
    }

    pub fn response_ended(&mut self) {
        self.response_ended = true;
    }

    pub fn cleanup_started(&mut self) {
        self.pending_cleanups += 1;
    }

    pub fn cleanup_finished(&mut self, succeeded: bool) {
        self.pending_cleanups = self.pending_cleanups.saturating_sub(1);
        self.cleanup_failed |= !succeeded;
    }

    /// Whether the owner may release its admission slot.
    pub const fn can_release(&self) -> bool {
        self.dispatched
            && self.input_ended
            && match self.lifetime {
                AdmissionLifetime::Dispatch => true,
                AdmissionLifetime::Response => {
                    self.response_ended && self.pending_cleanups == 0 && !self.cleanup_failed
                }
            }
    }
}

#[cfg(test)]
mod tests {
    use super::{AdmissionLifetime, ExchangeState};

    #[test]
    fn dispatch_lifetime_releases_after_input_ends() {
        let mut exchange = ExchangeState::new(AdmissionLifetime::Dispatch);
        exchange.dispatch_settled(true, false);
        assert!(!exchange.can_release());

        exchange.input_ended();
        assert!(exchange.can_release());
    }

    #[test]
    fn response_lifetime_waits_for_response_and_cleanup() {
        let mut exchange = ExchangeState::new(AdmissionLifetime::Response);
        exchange.dispatch_settled(true, false);
        exchange.cleanup_started();
        exchange.input_ended();
        exchange.response_ended();
        assert!(!exchange.can_release());

        exchange.cleanup_finished(true);
        assert!(exchange.can_release());
    }

    #[test]
    fn failed_cleanup_keeps_response_admission_blocked() {
        let mut exchange = ExchangeState::new(AdmissionLifetime::Response);
        exchange.dispatch_settled(false, false);
        exchange.response_ended();
        exchange.cleanup_started();
        exchange.cleanup_finished(false);

        assert!(!exchange.can_release());
    }
}
