//! Owned child processes and read-only process observation.

pub mod affinity;
pub mod handle_count;
pub mod io_counters;
pub mod launcher;
pub mod linux;
pub mod macos;
pub mod nice;
pub mod observation;
#[cfg(unix)]
pub mod ownership;
pub mod priority;
#[cfg(unix)]
pub mod pty;
pub mod scheduler;
pub mod terminal;
pub mod windows;
