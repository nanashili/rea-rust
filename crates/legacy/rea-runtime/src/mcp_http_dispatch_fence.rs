//! Session dispatch fencing for late callbacks during HTTP shutdown.

use std::sync::atomic::{AtomicBool, Ordering};

/// Prevents callbacks that cross a session-close boundary from reaching MCP.
#[derive(Debug, Default)]
pub struct DispatchFence {
    open: AtomicBool,
}

impl DispatchFence {
    /// Create a fence that permits dispatch.
    pub const fn new() -> Self {
        Self {
            open: AtomicBool::new(true),
        }
    }

    /// Whether a callback may dispatch into the current session.
    pub fn permits_dispatch(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    /// Close the fence; repeated calls are harmless.
    pub fn close(&self) {
        self.open.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::DispatchFence;

    #[test]
    fn permits_callbacks_until_the_session_closes() {
        let fence = DispatchFence::new();

        assert!(fence.permits_dispatch());
        fence.close();
        assert!(!fence.permits_dispatch());
    }

    #[test]
    fn repeated_close_does_not_reopen_dispatch() {
        let fence = DispatchFence::new();

        fence.close();
        fence.close();

        assert!(!fence.permits_dispatch());
    }
}
