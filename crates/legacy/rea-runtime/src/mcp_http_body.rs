//! Connection cleanup decisions for partially consumed HTTP request bodies.

/// The request body state needed after a response has been selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestBodyState {
    /// Whether the request advertised a body through either framing header.
    pub content_length_present: bool,
    pub transfer_encoding_present: bool,
    /// Whether the transport has observed the end of the incoming stream.
    pub readable_ended: bool,
}

impl RequestBodyState {
    /// Construct a body state from the headers and stream completion flag.
    pub const fn new(
        content_length_present: bool,
        transfer_encoding_present: bool,
        readable_ended: bool,
    ) -> Self {
        Self {
            content_length_present,
            transfer_encoding_present,
            readable_ended,
        }
    }

    /// Whether an unread body remains attached to the request connection.
    pub const fn has_unread_body(self) -> bool {
        (self.content_length_present || self.transfer_encoding_present) && !self.readable_ended
    }

    /// Whether the response writer must close the connection after replying.
    pub const fn should_close_connection(self) -> bool {
        self.has_unread_body()
    }
}

#[cfg(test)]
mod tests {
    use super::RequestBodyState;

    #[test]
    fn closes_after_early_response_to_content_length_body() {
        let state = RequestBodyState::new(true, false, false);

        assert!(state.has_unread_body());
        assert!(state.should_close_connection());
    }

    #[test]
    fn closes_after_early_response_to_chunked_body() {
        let state = RequestBodyState::new(false, true, false);

        assert!(state.has_unread_body());
        assert!(state.should_close_connection());
    }

    #[test]
    fn keeps_connection_when_body_is_absent_or_consumed() {
        for state in [
            RequestBodyState::new(false, false, false),
            RequestBodyState::new(true, false, true),
            RequestBodyState::new(false, true, true),
        ] {
            assert!(!state.has_unread_body());
            assert!(!state.should_close_connection());
        }
    }
}
