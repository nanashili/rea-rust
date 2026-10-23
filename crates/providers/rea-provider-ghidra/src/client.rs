//! One target-bound Rust Ghidra client: serial admission, input validation,
//! operation dispatch and execution provenance.
//!
//! Compatibility owners: `src/ghidra-rust/GhidraRustClient.ts`,
//! `GhidraRustExecution.ts`, `GhidraRustOperations.ts` and
//! `GhidraRustInputs.ts`.
use crate::batch::{self, BatchOptions, Item};
use crate::configuration::Configuration;
use crate::identity::{Operation, PROVIDER_ID, identity, limitations};
use crate::inventory::Inventory;
use crate::profile::profile_matches;
use crate::protocol::parse_segments;
use crate::selectors;
use crate::session::Session;
use crate::worker::{Control, Interruption, Worker, cache_integrity_failed};
use rea_analysis::{AnalysisClient, AnalysisExecution, BinaryTarget, ExecutionOptions};
use rea_core::analysis_error::cleanup::{cleanup_root, with_cleanup_failure};
use rea_core::analysis_error::{AnalysisError, ErrorKind, InputIssue};
use serde_json::{Map, Value, json};
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

const MAX_BATCH_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_BATCH_SELECTORS: usize = 1_000_000;
const MAX_SELECTOR_BYTES: usize = 4096;

/// One completed provider read.
struct Observation {
    result: Value,
    raw_result: Option<Value>,
    relationship_coverage: Option<Value>,
    references_truncated: Option<bool>,
}

impl From<crate::analysis::Read> for Observation {
    fn from(read: crate::analysis::Read) -> Self {
        Self {
            result: read.result,
            raw_result: None,
            relationship_coverage: read.relationship_coverage,
            references_truncated: read.references_truncated,
        }
    }
}

/// `GhidraRustClient`: admit one operation at a time and join active work
/// before releasing ownership.
pub(crate) struct Client {
    target: BinaryTarget,
    configuration: Configuration,
    profile: Option<Value>,
    session: Session,
    inventory: Inventory,
    analysis: crate::analysis::Analysis,
    shutdown: Arc<AtomicBool>,
    active: Mutex<bool>,
    idle: Condvar,
    closed: AtomicBool,
}

struct ActiveGuard<'a>(&'a Client);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        *self
            .0
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
        self.0.idle.notify_all();
    }
}

fn failure_kind(kind: &str) -> Map<String, Value> {
    let mut diagnostics = Map::new();
    diagnostics.insert("failure_kind".into(), json!(kind));
    diagnostics
}

fn is_cancellation(failure: &AnalysisError) -> bool {
    matches!(cleanup_root(failure).kind, ErrorKind::Cancelled { .. })
}

impl Client {
    pub(crate) fn new(
        target: BinaryTarget,
        configuration: Configuration,
        environment: Vec<(OsString, OsString)>,
        profile: Option<Value>,
        run_id: &str,
    ) -> Self {
        let worker = Arc::new(Worker::new(
            configuration.clone(),
            environment,
            run_id.to_owned(),
        ));
        let session = Session::new(
            Arc::clone(&worker),
            target.clone(),
            configuration.clone(),
            profile.clone(),
        );
        Self {
            target,
            configuration,
            profile,
            session,
            inventory: Inventory::default(),
            analysis: crate::analysis::Analysis::default(),
            shutdown: Arc::new(AtomicBool::new(false)),
            active: Mutex::new(false),
            idle: Condvar::new(),
            closed: AtomicBool::new(false),
        }
    }

    fn worker(&self) -> &Worker {
        &self.session.worker
    }

    fn matching_profile(&self) -> bool {
        profile_matches(self.profile.as_ref(), &self.configuration, &self.target)
    }

    /// `GhidraRustExecution.run`.
    fn run(
        &self,
        operation: Operation,
        input: Map<String, Value>,
        options: &ExecutionOptions,
    ) -> Result<AnalysisExecution, AnalysisError> {
        let control = Control::new(
            options.cancellation.clone(),
            Arc::clone(&self.shutdown),
            self.configuration.timeout_ms,
            options.progress.clone(),
            options.selector_from_provider,
        );
        if operation != Operation::Health && !self.matching_profile() {
            return Err(self
                .session
                .failure("The operation requires the selected Rust worker profile."));
        }
        match self.dispatch(operation, &input, &control) {
            Err(failure) => Err(self.failure(operation.name(), failure, &control)),
            Ok(observation) => {
                let execution = self.observation(observation);
                self.finish(operation.name(), &input, execution, &control)
            }
        }
    }

    /// `#observation`: bind the read to its target, profile and limitations.
    fn observation(&self, observation: Observation) -> AnalysisExecution {
        let mut execution = AnalysisExecution::new(observation.result, identity());
        if self.matching_profile() {
            execution.analysis_profile = self.profile.clone();
        }
        execution.raw_result = observation.raw_result;
        execution.relationship_coverage = observation.relationship_coverage;
        execution.references_truncated = observation.references_truncated;
        let mut retained = limitations();
        if let Some(info) = self.session.info() {
            retained.extend(info.limitations.iter().cloned());
        }
        execution.limitations = retained;
        execution.subject = Some(self.target.subject());
        execution
    }

    /// `#finish`: a late interruption or worker failure keeps the completed
    /// observation as partial Evidence.
    fn finish(
        &self,
        operation: &str,
        input: &Map<String, Value>,
        execution: AnalysisExecution,
        control: &Control,
    ) -> Result<AnalysisExecution, AnalysisError> {
        let evidence = || {
            execution
                .evidence(operation, Value::Object(input.clone()), "observed")
                .ok()
                .map(rea_core::evidence::envelope::Evidence::into_value)
        };
        if let Some(mut interruption) = control.error(operation, None) {
            if let Some(evidence) = evidence() {
                interruption = interruption.retain_partial_observation(evidence);
            }
            if matches!(interruption.kind, ErrorKind::CapabilityUnavailable { .. }) {
                return Err(interruption);
            }
            return Err(self.worker().invalidate(interruption));
        }
        if let Some(mut failure) = self.worker().failure() {
            if let Some(evidence) = evidence() {
                failure = failure.retain_partial_observation(evidence);
            }
            return Err(self.worker().invalidate(failure));
        }
        Ok(execution)
    }

    /// `#failure`: cleanup time must not replace an already observed
    /// substantive failure.
    fn failure(&self, operation: &str, failure: AnalysisError, control: &Control) -> AnalysisError {
        let interruption = control.error(operation, Some(&failure));
        let cancelled = is_cancellation(&failure);
        if cancelled
            && let Some(interruption) = &interruption
            && matches!(interruption.kind, ErrorKind::CapabilityUnavailable { .. })
        {
            return if failure.is_cleanup_incomplete() {
                with_cleanup_failure(interruption.clone(), failure, operation)
            } else {
                interruption.clone()
            };
        }
        let deadline_cancellation =
            cancelled && control.interruption() == Some(Interruption::Timeout);
        let mut failure = failure;
        if failure.tag() == "ProviderAdapterError" && self.worker().started() {
            failure = self.worker().invalidate(failure);
        }
        if !deadline_cancellation {
            return failure;
        }
        let Some(timeout) = control.error(operation, Some(&failure)) else {
            return failure;
        };
        if failure.is_cleanup_incomplete() {
            with_cleanup_failure(timeout, failure, operation)
        } else {
            timeout
        }
    }

    /// `GhidraRustOperations.dispatch`.
    fn dispatch(
        &self,
        operation: Operation,
        input: &Map<String, Value>,
        control: &Control,
    ) -> Result<Observation, AnalysisError> {
        let read = |result: Value| Observation {
            result,
            raw_result: None,
            relationship_coverage: None,
            references_truncated: None,
        };
        let (session, inventory) = (&self.session, &self.inventory);
        match operation {
            Operation::ListSegments => self.segments(control),
            Operation::Health => self.health(control).map(read),
            Operation::ListDocuments => Ok(read(json!([self.target.path]))),
            Operation::CurrentDocument => Ok(read(json!(self.target.path))),
            Operation::ListProcedures => self.inventory.list(&self.session, control).map(read),
            Operation::BatchDecompile => self.batch(input, control).map(read),
            Operation::SearchProcedures => self
                .inventory
                .search(&self.session, input, control)
                .map(read),
            Operation::ProcedureAddress => {
                let procedure = input
                    .get("procedure")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                selectors::resolve(&self.session, procedure, control).map(read)
            }
            Operation::AddressName => {
                selectors::address_name(&self.session, input, control).map(read)
            }
            Operation::ProcedurePseudoCode => {
                let procedure = input
                    .get("procedure")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                self.pseudocode(procedure, control).map(read)
            }
            Operation::ListStrings => self.analysis.list_strings(session, control).map(read),
            Operation::SearchStrings => self
                .analysis
                .search_strings(session, input, control)
                .map(read),
            Operation::Xrefs => {
                crate::analysis::xrefs(session, input, control).map(Observation::from)
            }
            Operation::ProcedureCallers => {
                crate::analysis::callers(session, inventory, input, control).map(Observation::from)
            }
            Operation::ProcedureCallees => {
                crate::analysis::callees(session, inventory, input, control).map(Observation::from)
            }
            Operation::ProcedureReferences => {
                crate::analysis::procedure_references(session, inventory, input, control)
                    .map(Observation::from)
            }
            Operation::ProcedureAssembly => {
                crate::analysis::assembly(session, inventory, input, control).map(Observation::from)
            }
            Operation::ReadFunctionInstructions => {
                crate::analysis::instructions(session, inventory, input, control)
                    .map(Observation::from)
            }
            Operation::ReadBytes => {
                crate::analysis::read_bytes(session, input, control).map(Observation::from)
            }
        }
    }

    fn batch(&self, input: &Map<String, Value>, control: &Control) -> Result<Value, AnalysisError> {
        let addresses = input
            .get("addresses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let result = batch::execute(
            &self.session,
            &addresses,
            BatchOptions {
                operation: "batch_decompile",
                cache_only: false,
            },
            control,
        )?;
        Ok(result.project())
    }

    fn segments(&self, control: &Control) -> Result<Observation, AnalysisError> {
        self.session.prepare(control)?;
        let reply = self
            .worker()
            .request("segments", json!({}), Some(control))?;
        let page = parse_segments(&reply).map_err(|_| {
            self.session
                .failure("The worker returned invalid object-file sections.")
        })?;
        let result = page
            .items
            .iter()
            .map(|section| {
                json!({
                    "name": section.name,
                    "start": section.address,
                    "end": section.end,
                    "readable": null,
                    "writable": null,
                    "executable": null,
                    "permissions": {
                        "available": false,
                        "reason": "The Rust worker reports object-file sections without memory-protection facts.",
                    },
                    "provenance": "ghidra-rust-object-file-section",
                    "sections": [],
                })
            })
            .collect::<Vec<_>>();
        Ok(Observation {
            result: Value::Array(result),
            raw_result: Some(reply),
            relationship_coverage: None,
            references_truncated: None,
        })
    }

    fn health(&self, control: &Control) -> Result<Value, AnalysisError> {
        if let Some(failure) = self.worker().failure() {
            return Err(failure);
        }
        if self.session.info().is_none() {
            let mut health = Map::new();
            health.insert("provider".into(), json!(PROVIDER_ID));
            health.insert("prepared".into(), json!(false));
            for (key, value) in self.worker().diagnostics() {
                health.insert(key, value);
            }
            return Ok(Value::Object(health));
        }
        let info = self.session.observe(control)?;
        let mut health = info.raw.as_object().cloned().unwrap_or_default();
        for (key, value) in self.worker().diagnostics() {
            health.insert(key, value);
        }
        Ok(Value::Object(health))
    }

    fn pseudocode(&self, selector: &str, control: &Control) -> Result<Value, AnalysisError> {
        let result = batch::execute(
            &self.session,
            &[selector.to_owned()],
            BatchOptions {
                operation: "procedure_pseudo_code",
                cache_only: false,
            },
            control,
        )?;
        match result.items.into_iter().next() {
            None => Err(self
                .session
                .failure("The native single-function batch returned no result.")),
            Some(Item::Ok { pseudocode, .. }) => Ok(json!(pseudocode)),
            Some(Item::Error { error, .. }) => Err(error),
        }
    }

    /// `#admissionFailure`.
    fn admission_failure(
        &self,
        operation: &str,
        options: &ExecutionOptions,
    ) -> Option<AnalysisError> {
        if options.cancellation.reason().is_some() {
            return Some(
                AnalysisError::cancelled(operation).with_diagnostics(failure_kind("cancelled")),
            );
        }
        if self.closed.load(Ordering::SeqCst) {
            return Some(
                self.session
                    .failure("The Rust provider client has been closed."),
            );
        }
        None
    }
}

fn issue(path: &str, reason: &'static str, message: impl Into<String>) -> InputIssue {
    let path = if path.is_empty() {
        Vec::new()
    } else {
        vec![path]
    };
    InputIssue::new(&path, reason, message)
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Field rules of one operation input (the tool contract's input schema).
#[derive(Clone, Copy)]
enum Field {
    String {
        required: bool,
        min: usize,
    },
    Boolean {
        default: bool,
    },
    Mode,
    /// A positive integer with a default (`read_bytes.length`).
    Positive {
        default: u64,
    },
    /// `incoming` or `outgoing`, default `outgoing`.
    Direction,
}

fn operation_fields(operation: Operation) -> &'static [(&'static str, Field)] {
    const DOCUMENT: (&str, Field) = (
        "document",
        Field::String {
            required: false,
            min: 0,
        },
    );
    const OPTIONAL_ADDRESS: (&str, Field) = (
        "address",
        Field::String {
            required: false,
            min: 0,
        },
    );
    const PROCEDURE: (&str, Field) = (
        "procedure",
        Field::String {
            required: true,
            min: 0,
        },
    );
    match operation {
        Operation::Health | Operation::ListDocuments | Operation::CurrentDocument => &[],
        Operation::ListSegments | Operation::ListProcedures => &[DOCUMENT],
        Operation::SearchProcedures => &[
            (
                "pattern",
                Field::String {
                    required: true,
                    min: 1,
                },
            ),
            ("mode", Field::Mode),
            ("case_sensitive", Field::Boolean { default: false }),
            DOCUMENT,
        ],
        Operation::ProcedurePseudoCode | Operation::ProcedureAddress => &[
            (
                "procedure",
                Field::String {
                    required: true,
                    min: 0,
                },
            ),
            DOCUMENT,
        ],
        Operation::AddressName => &[
            DOCUMENT,
            (
                "address",
                Field::String {
                    required: false,
                    min: 0,
                },
            ),
        ],
        Operation::BatchDecompile => &[],
        Operation::ListStrings => &[DOCUMENT, OPTIONAL_ADDRESS],
        Operation::SearchStrings => &[
            (
                "pattern",
                Field::String {
                    required: true,
                    min: 1,
                },
            ),
            ("mode", Field::Mode),
            ("case_sensitive", Field::Boolean { default: false }),
            DOCUMENT,
        ],
        Operation::Xrefs => &[DOCUMENT, OPTIONAL_ADDRESS],
        Operation::ProcedureCallers
        | Operation::ProcedureCallees
        | Operation::ProcedureAssembly
        | Operation::ReadFunctionInstructions => &[PROCEDURE, DOCUMENT],
        Operation::ProcedureReferences => &[PROCEDURE, ("direction", Field::Direction), DOCUMENT],
        Operation::ReadBytes => &[
            (
                "address",
                Field::String {
                    required: true,
                    min: 1,
                },
            ),
            ("length", Field::Positive { default: 256 }),
            DOCUMENT,
        ],
    }
}

/// `admitBatchInput`: bound retained selectors before schema parsing.
fn admit_batch_input(addresses: Option<&Value>) -> Result<(), AnalysisError> {
    let Some(addresses) = addresses.and_then(Value::as_array) else {
        return Ok(());
    };
    let capacity = || {
        AnalysisError::from(ErrorKind::ResourceConstraint {
            operation: "batch_decompile".to_owned(),
            resource: "capacity".to_owned(),
            reason: "The batch selectors exceed the retained input budget. Select a smaller inventory range.".to_owned(),
            reported_limits: Some(json!({
                "maximum_selectors": MAX_BATCH_SELECTORS,
                "maximum_serialized_input_bytes": MAX_BATCH_INPUT_BYTES,
            })),
            remediation_action: None,
            retryable: Some(false),
        })
    };
    if addresses.len() > MAX_BATCH_SELECTORS {
        return Err(capacity());
    }
    let mut bytes = 2_usize;
    for selector in addresses {
        let Some(selector) = selector.as_str() else {
            continue;
        };
        if selector.encode_utf16().count() > MAX_SELECTOR_BYTES {
            continue;
        }
        bytes += serde_json::to_string(selector).map_or(0, |text| text.len()) + 1;
        if bytes > MAX_BATCH_INPUT_BYTES {
            return Err(capacity());
        }
    }
    Ok(())
}

/// `parseGhidraRustInput`: validate the selected operation without changing
/// a caller's target selector.
fn parse_input(
    operation: Operation,
    parameters: &Map<String, Value>,
    target_path: &str,
) -> Result<Map<String, Value>, AnalysisError> {
    let name = operation.name();
    if operation == Operation::BatchDecompile {
        admit_batch_input(parameters.get("addresses"))?;
    }
    let mut issues = Vec::new();
    let mut input = Map::new();
    if operation == Operation::BatchDecompile {
        for key in parameters.keys().filter(|key| key.as_str() != "addresses") {
            issues.push(issue(
                "",
                "unknown_argument",
                format!("Unrecognized key: \"{key}\""),
            ));
        }
        match parameters.get("addresses") {
            None => {
                input.insert("addresses".into(), json!([]));
            }
            Some(Value::Array(addresses)) => {
                if addresses.len() > MAX_BATCH_SELECTORS {
                    issues.push(issue(
                        "addresses",
                        "out_of_range",
                        format!("Too big: expected array to have <={MAX_BATCH_SELECTORS} items"),
                    ));
                }
                for (index, selector) in addresses.iter().enumerate() {
                    match selector.as_str() {
                        Some(selector) if selector.len() <= MAX_SELECTOR_BYTES => {}
                        Some(_) => issues.push(InputIssue {
                            path: vec![json!("addresses"), json!(index)],
                            reason: "out_of_range",
                            message: Some(format!(
                                "Too big: expected string to have <={MAX_SELECTOR_BYTES} characters"
                            )),
                            expected: None,
                            minimum: None,
                            maximum: Some(MAX_SELECTOR_BYTES as f64),
                        }),
                        None => issues.push(InputIssue {
                            path: vec![json!("addresses"), json!(index)],
                            reason: "invalid_type",
                            message: Some(format!(
                                "Invalid input: expected string, received {}",
                                type_name(selector)
                            )),
                            expected: Some(json!("string")),
                            minimum: None,
                            maximum: None,
                        }),
                    }
                }
                input.insert("addresses".into(), Value::Array(addresses.clone()));
            }
            Some(other) => issues.push(issue(
                "addresses",
                "invalid_type",
                format!(
                    "Invalid input: expected array, received {}",
                    type_name(other)
                ),
            )),
        }
    } else {
        let fields = operation_fields(operation);
        for key in parameters.keys() {
            if !fields.iter().any(|(field, _)| field == key) {
                issues.push(issue(
                    "",
                    "unknown_argument",
                    format!("Unrecognized key: \"{key}\""),
                ));
            }
        }
        for (key, field) in fields {
            let value = parameters.get(*key);
            match (field, value) {
                (Field::String { required: true, .. }, None) => issues.push(issue(
                    key,
                    "missing_argument",
                    "Invalid input: expected string, received undefined",
                )),
                (Field::String { .. }, None) => {}
                (Field::String { min, .. }, Some(Value::String(text))) => {
                    if text.encode_utf16().count() < *min {
                        issues.push(issue(
                            key,
                            "out_of_range",
                            format!("Too small: expected string to have >={min} characters"),
                        ));
                    }
                    input.insert((*key).to_owned(), Value::String(text.clone()));
                }
                (Field::String { .. }, Some(other)) => issues.push(issue(
                    key,
                    "invalid_type",
                    format!(
                        "Invalid input: expected string, received {}",
                        type_name(other)
                    ),
                )),
                (Field::Boolean { default }, None) => {
                    input.insert((*key).to_owned(), json!(default));
                }
                (Field::Boolean { .. }, Some(Value::Bool(flag))) => {
                    input.insert((*key).to_owned(), json!(flag));
                }
                (Field::Boolean { .. }, Some(other)) => issues.push(issue(
                    key,
                    "invalid_type",
                    format!(
                        "Invalid input: expected boolean, received {}",
                        type_name(other)
                    ),
                )),
                (Field::Mode, None) => {
                    input.insert((*key).to_owned(), json!("literal"));
                }
                (Field::Mode, Some(Value::String(mode)))
                    if mode == "literal" || mode == "regex" =>
                {
                    input.insert((*key).to_owned(), json!(mode));
                }
                (Field::Mode, Some(_)) => issues.push(issue(
                    key,
                    "invalid_value",
                    "Invalid option: expected one of \"literal\"|\"regex\"",
                )),
                (Field::Positive { default }, None) => {
                    input.insert((*key).to_owned(), json!(default));
                }
                (Field::Positive { .. }, Some(value)) => match value.as_u64() {
                    Some(number) if number >= 1 => {
                        input.insert((*key).to_owned(), json!(number));
                    }
                    _ => issues.push(issue(
                        key,
                        "invalid_type",
                        "Invalid input: expected a positive integer",
                    )),
                },
                (Field::Direction, None) => {
                    input.insert((*key).to_owned(), json!("outgoing"));
                }
                (Field::Direction, Some(Value::String(direction)))
                    if direction == "incoming" || direction == "outgoing" =>
                {
                    input.insert((*key).to_owned(), json!(direction));
                }
                (Field::Direction, Some(_)) => issues.push(issue(
                    key,
                    "invalid_value",
                    "Invalid option: expected one of \"incoming\"|\"outgoing\"",
                )),
            }
        }
    }
    if !issues.is_empty() {
        return Err(AnalysisError::input(name, issues));
    }
    if let Some(document) = input.get("document").and_then(Value::as_str)
        && document != target_path
    {
        let mut diagnostics = Map::new();
        diagnostics.insert("requested_document".into(), json!(document));
        diagnostics.insert("bound_document".into(), json!(target_path));
        return Err(AnalysisError::input_message(
            name,
            "This Rust session is bound to a different document. Explicitly open the requested target first.",
            Vec::new(),
        )
        .with_diagnostics(diagnostics));
    }
    Ok(input)
}

impl AnalysisClient for Client {
    fn supports_operation(&self, operation: &str) -> bool {
        Operation::parse(operation).is_some()
    }

    fn execute(
        &self,
        operation: &str,
        parameters: &Map<String, Value>,
        options: &ExecutionOptions,
    ) -> Result<AnalysisExecution, AnalysisError> {
        let Some(declared) = Operation::parse(operation) else {
            return Err(AnalysisError::capability_unavailable(
                PROVIDER_ID,
                operation,
                "This Rust worker does not implement this operation.",
            ));
        };
        if let Some(refusal) = self.admission_failure(operation, options) {
            return Err(refusal);
        }
        {
            let mut active = self
                .active
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if *active {
                return Err(AnalysisError::from(ErrorKind::ResourceConstraint {
                    operation: operation.to_owned(),
                    resource: "capacity".to_owned(),
                    reason: "One request already owns this Rust worker session.".to_owned(),
                    reported_limits: Some(json!({ "concurrent_requests": 1 })),
                    remediation_action: None,
                    retryable: None,
                }));
            }
            *active = true;
        }
        let _active = ActiveGuard(self);
        let input = parse_input(declared, parameters, &self.target.path)?;
        self.run(declared, input, options)
    }

    fn execute_if_ready(
        &self,
        operation: &str,
        parameters: &Map<String, Value>,
        options: &ExecutionOptions,
    ) -> Option<Result<AnalysisExecution, AnalysisError>> {
        (operation == "health" || self.session.info().is_some())
            .then(|| self.execute(operation, parameters, options))
    }

    fn operation_health(&self) -> Option<Value> {
        let failure = self.worker().failure();
        let active = *self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = if failure.is_some() {
            "unreachable"
        } else if active {
            "busy"
        } else if self.worker().started() {
            "idle"
        } else {
            "not_started"
        };
        let retry_action = match &failure {
            Some(failure) if !cache_integrity_failed(failure) => json!("restart_provider"),
            _ => Value::Null,
        };
        Some(json!({
            "state": state,
            "stage": null,
            "retryAction": retry_action,
            "exitCode": self.worker().exit_code(),
            "requests": [],
        }))
    }

    fn runtime_lineage(&self) -> Vec<Value> {
        self.worker()
            .lineage()
            .map(|observation| {
                vec![json!({ "provider": identity().to_json(), "observation": observation })]
            })
            .unwrap_or_default()
    }

    fn close(&self, _retain_document: bool) -> Result<(), AnalysisError> {
        self.closed.store(true, Ordering::SeqCst);
        self.shutdown.store(true, Ordering::SeqCst);
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *active {
            active = self
                .idle
                .wait(active)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        drop(active);
        self.worker().close()
    }
}
