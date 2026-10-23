//! Serialized provider turns whose waiting callers remain cancellable.
//!
//! Compatibility owner: the promise-tail serialization in the original
//! providers (`waitForTurn`): a queued caller observes its own cancellation
//! while waiting, and a turn is released on every exit path.
use rea_core::cancellation::Cancellation;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// One-at-a-time admission for a provider's expensive work.
#[derive(Debug, Default)]
pub struct Turnstile {
    busy: Mutex<bool>,
    released: Condvar,
}

/// Held for the duration of one serialized operation.
#[derive(Debug)]
pub struct Turn<'a> {
    turnstile: &'a Turnstile,
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let mut busy = lock(&self.turnstile.busy);
        *busy = false;
        drop(busy);
        self.turnstile.released.notify_one();
    }
}

fn lock(mutex: &Mutex<bool>) -> MutexGuard<'_, bool> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Turnstile {
    /// Wait for the turn; returns the first cancellation reason instead when
    /// the caller cancels while queued.
    pub fn acquire(&self, cancellation: &Cancellation) -> Result<Turn<'_>, String> {
        let mut busy = lock(&self.busy);
        loop {
            if let Some(reason) = cancellation.reason() {
                return Err(reason.to_owned());
            }
            if !*busy {
                *busy = true;
                return Ok(Turn { turnstile: self });
            }
            busy = self
                .released
                .wait_timeout(busy, Duration::from_millis(20))
                .map(|(guard, _)| guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner().0);
        }
    }

    /// Wait for the turn without cancellation (shutdown joins active work).
    pub fn acquire_uncancellable(&self) -> Turn<'_> {
        let mut busy = lock(&self.busy);
        while *busy {
            busy = self
                .released
                .wait(busy)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        *busy = true;
        Turn { turnstile: self }
    }

    /// Take the turn only if it is free now.
    pub fn try_acquire(&self) -> Option<Turn<'_>> {
        let mut busy = lock(&self.busy);
        if *busy {
            return None;
        }
        *busy = true;
        Some(Turn { turnstile: self })
    }
}
