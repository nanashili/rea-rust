//! One-shot command signal ownership. Handlers only record a preallocated reason;
//! application execution and final cleanup remain on their ordinary call path.
use rea_core::cancellation::Cancellation;
use signal_hook::{
    SigId,
    consts::{SIGINT, SIGTERM},
    low_level,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub struct CommandInterrupts {
    cancellation: Cancellation,
    registrations: Vec<SigId>,
    exit: Arc<AtomicUsize>,
}
impl CommandInterrupts {
    pub fn install() -> io::Result<Self> {
        let mut owner = Self {
            cancellation: Cancellation::with_static_reasons(&["SIGINT", "SIGTERM"]),
            registrations: Vec::new(),
            exit: Arc::new(AtomicUsize::new(0)),
        };
        for (signal, reason, exit) in [(SIGINT, "SIGINT", 130), (SIGTERM, "SIGTERM", 143)] {
            let trigger = owner
                .cancellation
                .static_trigger(reason)
                .ok_or_else(|| io::Error::other("missing declared interrupt reason"))?;
            let recorded_exit = owner.exit.clone();
            // SAFETY: the closure invokes only lock-free AtomicUsize CASs on
            // already allocated Arc targets. It neither allocates nor locks.
            // Both supported signals are catchable; registration is owned here.
            let registration = unsafe {
                low_level::register(signal, move || {
                    if recorded_exit
                        .compare_exchange(0, exit, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        trigger.cancel();
                    }
                })
            }?;
            owner.registrations.push(registration);
        }
        Ok(owner)
    }
    pub fn cancellation(&self) -> &Cancellation {
        &self.cancellation
    }
    /// Stop observing interrupts only AFTER operation/finalization/output settles.
    /// Later signals cannot replace the winning signal's conventional exit code.
    pub fn finish(mut self) -> Option<u8> {
        self.unregister();
        match self.exit.load(Ordering::Acquire) {
            0 => None,
            code => Some(code as u8),
        }
    }
    fn unregister(&mut self) {
        for registration in self.registrations.drain(..) {
            low_level::unregister(registration);
        }
    }
}
impl Drop for CommandInterrupts {
    fn drop(&mut self) {
        self.unregister();
    }
}
