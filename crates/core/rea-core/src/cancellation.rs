//! Shared first-reason cancellation, independent of a transport or async runtime.
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default, Debug)]
struct State {
    winner: AtomicUsize,
    dynamic: OnceLock<String>,
    static_reasons: &'static [&'static str],
}

/// A cloneable request cancellation identity whose first reason is immutable.
#[derive(Clone, Default, Debug)]
pub struct Cancellation(Arc<State>);
impl Cancellation {
    /// Predeclare reasons that may be recorded without allocation or locking.
    /// The ordinary dynamic cancellation path remains available.
    pub fn with_static_reasons(reasons: &'static [&'static str]) -> Self {
        Self(Arc::new(State {
            static_reasons: reasons,
            ..State::default()
        }))
    }
    /// Prepare a signal-safe trigger outside the signal handler.
    pub fn static_trigger(&self, reason: &str) -> Option<StaticTrigger> {
        self.0
            .static_reasons
            .iter()
            .position(|candidate| *candidate == reason)
            .map(|index| StaticTrigger {
                state: self.0.clone(),
                tag: index + 1,
            })
    }
    /// Record the first cancellation reason. Later callers cannot replace it.
    pub fn cancel(&self, reason: impl Into<String>) -> bool {
        self.0.dynamic.set(reason.into()).is_ok()
            && self
                .0
                .winner
                .compare_exchange(0, usize::MAX, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }
    /// The original reason, or None when cancellation has not been requested.
    pub fn reason(&self) -> Option<&str> {
        match self.0.winner.load(Ordering::Acquire) {
            0 => None,
            usize::MAX => self.0.dynamic.get().map(String::as_str),
            tag => self.0.static_reasons.get(tag - 1).copied(),
        }
    }
}

/// A preallocated reason identity. Recording it performs only a lock-free atomic
/// compare/exchange; no formatting, allocation, locks, or destruction occurs.
#[derive(Clone, Debug)]
pub struct StaticTrigger {
    state: Arc<State>,
    tag: usize,
}
impl StaticTrigger {
    /// Record this reason if no other cancellation has won.
    pub fn cancel(&self) -> bool {
        self.state
            .winner
            .compare_exchange(0, self.tag, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}
