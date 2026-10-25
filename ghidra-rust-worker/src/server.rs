use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

use crate::configuration::Configuration;
use crate::metadata;
use crate::session::Session;
use crate::transport::{Progress, Transport, read_request};

enum Incoming {
    Request(crate::protocol::Request),
    Closed,
    Failed(anyhow::Error),
    ReaderStopped,
    Idle,
}

struct Worker {
    configuration: Configuration,
    session: Option<Session>,
}

pub fn run() -> Result<()> {
    let mut worker = Worker {
        configuration: Configuration::load()?,
        session: None,
    };
    let requests = spawn_request_reader()?;
    let stdout = std::io::stdout();
    let mut transport = Transport::new(stdout.lock());

    loop {
        let event = receive_request(&requests, worker.program_idle_wait(Instant::now()));
        let request = match event {
            Incoming::Request(request) => request,
            Incoming::Idle => {
                worker.release_program_at_safe_point(Instant::now());
                continue;
            }
            Incoming::Closed => {
                return worker.checkpoint_after_input_closed();
            }
            Incoming::Failed(error) => {
                return Err(worker.checkpoint_after_input_failure(error));
            }
            Incoming::ReaderStopped => {
                let error = anyhow::anyhow!("Worker input reader stopped unexpectedly");
                return Err(worker.checkpoint_after_input_failure(error));
            }
        };

        worker.release_program_at_safe_point(Instant::now());
        let result = worker.dispatch(&request.method, request.params, &mut transport);
        worker.release_program_at_safe_point(Instant::now());
        match result {
            Ok(reply) => {
                transport.reply(request.id, reply)?;
                if request.method == "close" {
                    return Ok(());
                }
            }
            Err(error) => transport.failure(request.id, &error)?,
        }
    }
}

fn spawn_request_reader() -> Result<Receiver<Result<Option<crate::protocol::Request>>>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader_thread = thread::Builder::new()
        .name("rea-ghidra-worker-input".to_owned())
        .spawn(move || {
            let stdin = std::io::stdin();
            let mut input = stdin.lock();
            loop {
                let request = read_request(&mut input);
                let finished = !matches!(&request, Ok(Some(_)));
                if sender.send(request).is_err() || finished {
                    return;
                }
            }
        })
        .context("Start the bounded worker input reader")?;
    // The reader may be blocked on stdin when the worker receives `close`.
    // Joining it would make shutdown wait for another input frame.
    drop(reader_thread);
    Ok(receiver)
}

fn receive_request(
    receiver: &Receiver<Result<Option<crate::protocol::Request>>>,
    idle_wait: Option<Duration>,
) -> Incoming {
    let received = match idle_wait {
        Some(timeout) => match receiver.recv_timeout(timeout) {
            Ok(request) => request,
            Err(RecvTimeoutError::Timeout) => return Incoming::Idle,
            Err(RecvTimeoutError::Disconnected) => return Incoming::ReaderStopped,
        },
        None => match receiver.recv() {
            Ok(request) => request,
            Err(_) => return Incoming::ReaderStopped,
        },
    };

    match received {
        Ok(Some(request)) => Incoming::Request(request),
        Ok(None) => Incoming::Closed,
        Err(error) => Incoming::Failed(error),
    }
}

impl Worker {
    fn program_idle_wait(&self, now: Instant) -> Option<Duration> {
        self.session.as_ref()?.time_until_program_idle_release(now)
    }

    fn release_program_at_safe_point(&mut self, now: Instant) {
        if let Some(session) = &mut self.session {
            session.release_program_at_safe_point(now);
        }
    }

    fn checkpoint_after_input_closed(&self) -> Result<()> {
        if let Some(session) = &self.session {
            session
                .cache
                .checkpoint()
                .context("Checkpoint after input closed")?;
        }
        Ok(())
    }

    fn checkpoint_after_input_failure(&self, original: anyhow::Error) -> anyhow::Error {
        let Some(session) = &self.session else {
            return original;
        };
        match session.cache.checkpoint() {
            Ok(()) => original.context("Worker input failed after cache checkpoint"),
            Err(recovery) => original.context(format!(
                "Worker input failed; cache checkpoint also failed: {recovery:#}"
            )),
        }
    }

    fn dispatch(
        &mut self,
        method: &str,
        params: Value,
        progress: &mut impl Progress,
    ) -> Result<Value> {
        match method {
            "info" => {
                empty_params(&params)?;
                Ok(self.info())
            }
            "open" => {
                ensure!(self.session.is_none(), "One target is permitted per worker");
                let session = Session::open(
                    &self.configuration,
                    serde_json::from_value(params)?,
                    progress,
                )?;
                self.session = Some(session);
                Ok(self.info())
            }
            "functions" => self.prepared()?.functions(serde_json::from_value(params)?),
            "function_aliases" => self.prepared()?.aliases(serde_json::from_value(params)?),
            "resolve_functions" => self.prepared()?.resolve(serde_json::from_value(params)?),
            "segments" => {
                empty_params(&params)?;
                Ok(self.prepared()?.segments())
            }
            "image_map" => {
                empty_params(&params)?;
                self.prepared()?.image_map()
            }
            "search_bytes" => self.prepared()?.search_bytes(params),
            "batch_decompile" => {
                let timeout = self.configuration.timeout_ms;
                self.prepared()?
                    .batch(serde_json::from_value(params)?, timeout, progress)
            }
            "batch_decompile_inventory" => {
                let timeout = self.configuration.timeout_ms;
                self.prepared()?
                    .inventory_batch(serde_json::from_value(params)?, timeout, progress)
            }
            "strings" => self.prepared()?.strings(serde_json::from_value(params)?),
            "references_to" => self
                .prepared()?
                .references_to(serde_json::from_value(params)?, progress),
            "references_from" => self
                .prepared()?
                .references_from(serde_json::from_value(params)?, progress),
            "instructions" => self
                .prepared()?
                .instructions(serde_json::from_value(params)?),
            "inspect_instruction" => self
                .prepared()?
                .inspect_instruction(serde_json::from_value(params)?),
            "read_bytes" => self.prepared()?.read_bytes(serde_json::from_value(params)?),
            "checkpoint" => {
                empty_params(&params)?;
                self.prepared()?.cache.checkpoint()?;
                Ok(json!({ "saved": true }))
            }
            "close" => {
                empty_params(&params)?;
                let saved = self.session.is_some();
                if let Some(session) = &self.session {
                    session.cache.checkpoint()?;
                }
                self.session = None;
                Ok(json!({ "saved": saved, "closed": true }))
            }
            _ => bail!("Unsupported worker method: {method}"),
        }
    }

    fn prepared(&mut self) -> Result<&mut Session> {
        self.session
            .as_mut()
            .context("Open one target before requesting saved analysis")
    }

    fn info(&self) -> Value {
        let mut info = json!({
            "engine": metadata::engine(),
            "provider": "ghidra-rust",
            "worker_protocol_version": crate::protocol::WORKER_PROTOCOL_VERSION,
            "worker_protocol_name": crate::protocol::WORKER_PROTOCOL_NAME,
            "cache_id": metadata::CACHE_ID,
            "snapshot_schema": 1,
            "worker_sha256": self.configuration.worker_sha256,
            "config_identity": self.configuration.identity,
            "inventory_frozen": self.session.is_some(),
            "memory_limit_mib": null,
            "timeout_ms": self.configuration.timeout_ms,
            "capabilities": [
                "info", "open", "functions", "function_aliases", "segments", "image_map", "search_bytes", "batch_decompile",
                "resolve_functions", "batch_decompile_inventory", "strings", "references_to",
                "references_from", "instructions", "inspect_instruction", "read_bytes", "checkpoint", "close"
            ]
        });
        if let Some(session) = &self.session {
            info.as_object_mut().expect("Object literal").extend(
                session
                    .prepared_info()
                    .as_object()
                    .expect("Object literal")
                    .clone(),
            );
        }
        info
    }
}

fn empty_params(params: &Value) -> Result<()> {
    ensure!(
        params.as_object().is_some_and(|object| object.is_empty()),
        "Expected empty parameters"
    );
    Ok(())
}
