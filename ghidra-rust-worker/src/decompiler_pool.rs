//! Bounded set of decompiler Programs for one admitted target.
//!
//! A Program is single-threaded engine state, so parallel decompilation uses
//! one Program per thread. The pool owns every Program: it verifies the target
//! image once, builds Programs from that verified copy, applies the loader
//! facts each Program needs, and releases Programs after a bounded number of
//! decompile attempts or idle time.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, ensure};

use ghidra_decompiler::program::Program;

use crate::decompiler_facts::DecompilerFacts;
use crate::program_retention::ProgramRetention;
use crate::target::load_program;

/// Highest accepted thread count; each thread owns one full Program.
pub(crate) const MAX_DECOMPILE_THREADS: usize = 64;

/// The verified target image and the facts derived from it.
struct Image {
    bytes: Arc<Vec<u8>>,
    facts: Arc<DecompilerFacts>,
}

pub(crate) struct DecompilerPool {
    path: PathBuf,
    target_sha256: String,
    language: String,
    threads: usize,
    image: Option<Image>,
    slots: Vec<Option<ProgramRetention>>,
}

/// One decompile result and whether it was produced (not deadline-skipped).
pub(crate) enum Outcome {
    Decompiled(ghidra_decompiler::error::Result<String>),
    Deadline,
}

impl DecompilerPool {
    pub(crate) fn new(path: PathBuf, target_sha256: String, language: String, threads: usize) -> Self {
        let threads = threads.clamp(1, MAX_DECOMPILE_THREADS);
        Self {
            path,
            target_sha256,
            language,
            threads,
            image: None,
            slots: (0..threads).map(|_| None).collect(),
        }
    }

    /// Read and verify the target once; later Programs use this copy, so
    /// every Program is bound to the admitted digest.
    fn image(&mut self) -> Result<&Image> {
        if self.image.is_none() {
            let bytes = crate::target_file::read(&self.path, &self.target_sha256)?;
            let file = object::File::parse(bytes.as_slice())
                .context("Parse the admitted target for decompiler facts")?;
            let facts = DecompilerFacts::read(&file)?;
            self.image = Some(Image {
                bytes: Arc::new(bytes),
                facts: Arc::new(facts),
            });
        }
        Ok(self.image.as_ref().expect("image was just admitted"))
    }

    /// The verified target bytes and their decompiler facts, for analyses
    /// that build their own Programs from the same admitted copy.
    pub(crate) fn verified_image(&mut self) -> Result<(Arc<Vec<u8>>, Arc<DecompilerFacts>)> {
        let image = self.image()?;
        Ok((Arc::clone(&image.bytes), Arc::clone(&image.facts)))
    }

    pub(crate) fn threads(&self) -> usize {
        self.threads
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Run `read` on the first retained Program, building it if needed. The
    /// closure must only read the Program (disassembly, p-code); it does not
    /// count as a decompile attempt.
    pub(crate) fn with_program<T>(
        &mut self,
        starts: &[u64],
        read: impl FnOnce(&Program, &DecompilerFacts) -> T,
    ) -> Result<T> {
        let image = self.image()?;
        let (bytes, facts) = (Arc::clone(&image.bytes), Arc::clone(&image.facts));
        if self.slots[0].is_none() {
            self.slots[0] = Some(build_program(&self.path, &bytes, &facts, &self.language, starts)?);
        }
        let retained = self.slots[0].as_mut().expect("program was just built");
        Ok(read(retained.program(), &facts))
    }

    /// Decompile `jobs` (`(caller index, entry address)`) on up to
    /// `self.threads` Programs. `on_result` runs on the calling thread in
    /// completion order; `stop` requests that no further jobs start.
    pub(crate) fn decompile(
        &mut self,
        jobs: &[(usize, u64)],
        starts: &[u64],
        deadline: Instant,
        mut on_result: impl FnMut(usize, Outcome) -> Result<()>,
    ) -> Result<()> {
        if jobs.is_empty() {
            return Ok(());
        }
        let threads = self.threads.min(jobs.len());
        let image = self.image()?;
        let bytes = Arc::clone(&image.bytes);
        let facts = Arc::clone(&image.facts);
        let path = self.path.clone();
        let language = self.language.clone();
        let mut programs: Vec<Option<ProgramRetention>> =
            self.slots.iter_mut().take(threads).map(Option::take).collect();
        let cursor = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        let (sender, receiver) = mpsc::channel::<Result<(usize, Outcome)>>();
        let mut first_error = None;

        let returned = std::thread::scope(|scope| {
            let handles = programs
                .iter_mut()
                .map(|slot| {
                    let mut retained = slot.take();
                    let sender = sender.clone();
                    let (cursor, stop, bytes, facts) = (&cursor, &stop, &bytes, &facts);
                    let (path, language) = (&path, &language);
                    std::thread::Builder::new()
                        .name("rea-ghidra-decompile".to_owned())
                        .spawn_scoped(scope, move || {
                            while !stop.load(Ordering::Acquire) {
                                let index = cursor.fetch_add(1, Ordering::AcqRel);
                                let Some(&(caller, entry)) = jobs.get(index) else {
                                    break;
                                };
                                if Instant::now() >= deadline {
                                    if sender.send(Ok((caller, Outcome::Deadline))).is_err() {
                                        break;
                                    }
                                    continue;
                                }
                                if retained.as_ref().is_some_and(ProgramRetention::decompile_attempts_exhausted) {
                                    retained = None;
                                }
                                if retained.is_none() {
                                    match build_program(path, bytes, facts, language, starts) {
                                        Ok(program) => retained = Some(program),
                                        Err(error) => {
                                            stop.store(true, Ordering::Release);
                                            let _ = sender.send(Err(error));
                                            break;
                                        }
                                    }
                                }
                                let program = retained.as_mut().expect("program was just built");
                                let result = program.decompile(entry, starts, facts);
                                if sender.send(Ok((caller, Outcome::Decompiled(result)))).is_err() {
                                    break;
                                }
                            }
                            retained
                        })
                })
                .collect::<std::io::Result<Vec<_>>>();
            drop(sender);
            let handles = match handles {
                Ok(handles) => handles,
                Err(error) => {
                    stop.store(true, Ordering::Release);
                    first_error = Some(anyhow!(error).context("Start a decompiler thread"));
                    Vec::new()
                }
            };
            for message in receiver {
                if first_error.is_some() {
                    continue;
                }
                let delivered = message.and_then(|(caller, outcome)| on_result(caller, outcome));
                if let Err(error) = delivered {
                    stop.store(true, Ordering::Release);
                    first_error = Some(error);
                }
            }
            handles
                .into_iter()
                .map(|handle| handle.join())
                .collect::<Vec<_>>()
        });

        // A thread that panicked outside the engine's own guard loses its
        // Program; the others are kept for reuse.
        let mut panicked = false;
        for (slot, joined) in self.slots.iter_mut().zip(returned) {
            match joined {
                Ok(program) => *slot = program,
                Err(_) => panicked = true,
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        ensure!(!panicked, "A decompiler thread stopped unexpectedly");
        Ok(())
    }

    pub(crate) fn time_until_idle_release(&self, now: Instant) -> Option<Duration> {
        self.slots
            .iter()
            .flatten()
            .map(|program| program.time_until_idle_release(now))
            .min()
    }

    pub(crate) fn release_at_safe_point(&mut self, now: Instant) {
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|program| program.should_release(now)) {
                slot.take();
            }
        }
        // The verified image only serves Program construction.
        if self.slots.iter().all(Option::is_none) {
            self.image = None;
        }
    }

    pub(crate) fn discard(&mut self) {
        for slot in &mut self.slots {
            slot.take();
        }
        self.image = None;
    }
}

fn build_program(
    path: &Path,
    bytes: &Arc<Vec<u8>>,
    facts: &DecompilerFacts,
    language: &str,
    starts: &[u64],
) -> Result<ProgramRetention> {
    let mut program = load_program(path, bytes.as_ref().clone())?;
    ensure!(program.language_id() == language, "Saved language changed");
    facts.apply(&mut program, starts)?;
    Ok(ProgramRetention::new(program))
}
