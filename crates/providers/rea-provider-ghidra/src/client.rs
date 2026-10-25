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
use crate::native_instruction;
use crate::profile::profile_matches;
use crate::protocol::{Procedure, parse_segments};
use crate::selectors;
use crate::session::Session;
use crate::static_routes;
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
const UNAVAILABLE_BODY_REASON: &str =
    "Reachable body ranges are unavailable for this procedure projection.";

fn canonical_address(value: &str) -> Option<String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    (!digits.is_empty()
        && digits.len() <= 16
        && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then(|| u64::from_str_radix(digits, 16).ok())
    .flatten()
    .map(|value| format!("0x{value:x}"))
}

fn address_number(value: &str) -> Option<u64> {
    let canonical = canonical_address(value)?;
    u64::from_str_radix(canonical.strip_prefix("0x")?, 16).ok()
}

#[derive(Clone, Copy)]
struct WorkerBodyRange {
    start: u64,
    end: u64,
}

struct WorkerFunctionBody {
    complete: bool,
    ranges: Vec<WorkerBodyRange>,
    total_bytes: u64,
    basicblock_count: u64,
}

impl WorkerFunctionBody {
    fn span_bytes(&self) -> Option<u64> {
        let first = self.ranges.first()?;
        let last = self.ranges.last()?;
        last.end.checked_sub(first.start)?.checked_add(1)
    }
}

fn parse_worker_function_body(
    body: &Value,
    entry: u64,
) -> Result<WorkerFunctionBody, &'static str> {
    let complete = body
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or("worker body completeness is missing")?;
    let raw_ranges = body
        .get("ranges")
        .and_then(Value::as_array)
        .ok_or("worker body ranges are missing")?;
    let mut ranges: Vec<WorkerBodyRange> = Vec::with_capacity(raw_ranges.len());
    let mut total_from_ranges = 0_u64;
    for raw_range in raw_ranges {
        let start_text = raw_range
            .get("start")
            .and_then(Value::as_str)
            .ok_or("worker body range start is invalid")?;
        let end_text = raw_range
            .get("end")
            .and_then(Value::as_str)
            .ok_or("worker body range end is invalid")?;
        if canonical_address(start_text).as_deref() != Some(start_text)
            || canonical_address(end_text).as_deref() != Some(end_text)
        {
            return Err("worker body range address is not canonical");
        }
        let start = address_number(start_text).ok_or("worker body range start is invalid")?;
        let end = address_number(end_text).ok_or("worker body range end is invalid")?;
        if end < start {
            return Err("worker body range is reversed");
        }
        if let Some(previous) = ranges.last()
            && start <= previous.end.saturating_add(1)
        {
            return Err("worker body ranges are not ordered and disjoint");
        }
        total_from_ranges = total_from_ranges
            .checked_add(
                end.checked_sub(start)
                    .ok_or("worker body range overflows")?,
            )
            .and_then(|total| total.checked_add(1))
            .ok_or("worker body byte count overflows")?;
        ranges.push(WorkerBodyRange { start, end });
    }
    let total_bytes = body
        .get("total_bytes")
        .and_then(Value::as_u64)
        .ok_or("worker body byte count is missing")?;
    let basicblock_count = body
        .get("basicblock_count")
        .and_then(Value::as_u64)
        .ok_or("worker body block count is missing")?;
    if total_bytes != total_from_ranges {
        return Err("worker body byte count does not match ranges");
    }
    let body_address = body
        .get("address")
        .and_then(Value::as_str)
        .ok_or("worker body address is missing")?;
    if address_number(body_address) != Some(entry)
        || canonical_address(body_address).as_deref() != Some(body_address)
    {
        return Err("worker body address does not match its requested entry");
    }
    if complete {
        if ranges.is_empty()
            || !ranges
                .iter()
                .any(|range| (range.start..=range.end).contains(&entry))
        {
            return Err("complete worker body does not contain its entry");
        }
        if basicblock_count == 0 {
            return Err("complete worker body has no basic blocks");
        }
    }
    Ok(WorkerFunctionBody {
        complete,
        ranges,
        total_bytes,
        basicblock_count,
    })
}

fn body_ranges_json(body: &WorkerFunctionBody) -> Vec<Value> {
    body.ranges
        .iter()
        .map(|range| {
            json!({
                "start": format!("0x{:x}", range.start),
                "end": format!("0x{:x}", range.end),
            })
        })
        .collect()
}

fn address_is_in_segments(segments: &Value, requested: u64) -> Result<bool, &'static str> {
    let items = segments
        .get("items")
        .and_then(Value::as_array)
        .ok_or("worker segments are malformed")?;
    let mut contained = false;
    for segment in items {
        let start = segment
            .get("address")
            .and_then(Value::as_str)
            .and_then(address_number)
            .ok_or("worker segment start is invalid")?;
        let end = segment
            .get("end")
            .and_then(Value::as_str)
            .and_then(address_number)
            .ok_or("worker segment end is invalid")?;
        if start > end {
            return Err("worker segment range is reversed");
        }
        contained |= (start..end).contains(&requested);
    }
    Ok(contained)
}

struct WorkerImageMapping {
    section: String,
    start: String,
    end: String,
    start_value: u64,
    length: u64,
    initialized: bool,
    loaded: bool,
    file_offset: Option<u64>,
}

impl WorkerImageMapping {
    fn to_json(&self) -> Value {
        json!({
            "block": self.section,
            "start": self.start,
            "end": self.end,
            "address_space": "ram",
            "initialized": self.initialized,
            "loaded": self.loaded,
            "overlay": false,
            "length": self.length,
            "source_file_index": Value::Null,
            "file_offset": self.file_offset,
            "sha256": Value::Null
        })
    }
}

fn parse_worker_image_mapping(value: &Value) -> Result<WorkerImageMapping, &'static str> {
    let object = value
        .as_object()
        .ok_or("worker image mapping is not an object")?;
    let section = object
        .get("section")
        .and_then(Value::as_str)
        .filter(|section| !section.is_empty())
        .ok_or("worker image mapping section is missing")?;
    let start = object
        .get("start")
        .and_then(Value::as_str)
        .ok_or("worker image mapping start is missing")?;
    let end = object
        .get("end")
        .and_then(Value::as_str)
        .ok_or("worker image mapping end is missing")?;
    if canonical_address(start).as_deref() != Some(start)
        || canonical_address(end).as_deref() != Some(end)
    {
        return Err("worker image mapping address is not canonical");
    }
    let start_value = address_number(start).ok_or("worker image mapping start is invalid")?;
    let end_value = address_number(end).ok_or("worker image mapping end is invalid")?;
    let length = object
        .get("length")
        .and_then(Value::as_u64)
        .ok_or("worker image mapping length is missing")?;
    let expected_length = end_value
        .checked_sub(start_value)
        .and_then(|length| length.checked_add(1))
        .ok_or("worker image mapping range is reversed")?;
    if length != expected_length {
        return Err("worker image mapping length does not match its inclusive range");
    }
    let initialized = object
        .get("initialized")
        .and_then(Value::as_bool)
        .ok_or("worker image mapping initialized flag is missing")?;
    let loaded = object
        .get("loaded")
        .and_then(Value::as_bool)
        .ok_or("worker image mapping loaded flag is missing")?;
    let file_offset = object
        .get("file_offset")
        .ok_or("worker image mapping file offset is missing")?
        .as_u64();
    if !object
        .get("file_offset")
        .is_some_and(|value| value.is_null() || value.is_u64())
    {
        return Err("worker image mapping file offset is invalid");
    }
    Ok(WorkerImageMapping {
        section: section.to_owned(),
        start: start.to_owned(),
        end: end.to_owned(),
        start_value,
        length,
        initialized,
        loaded,
        file_offset,
    })
}

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

fn procedure_identity(procedure: &Procedure) -> Value {
    json!({
        "address": procedure.address,
        "name": procedure.name,
        "classification": null,
        "body": {
            "available": false,
            "reason": UNAVAILABLE_BODY_REASON,
        }
    })
}

fn function_identity(procedure: &Procedure) -> Value {
    let mut identity = procedure_identity(procedure);
    if let Value::Object(fields) = &mut identity {
        fields.insert("signature".into(), Value::Null);
        fields.insert("locals".into(), Value::Array(Vec::new()));
    }
    identity
}

fn related_procedure_identities(
    procedures: &[Procedure],
    result: &Value,
) -> (Vec<Value>, Vec<String>) {
    let mut identities = Vec::new();
    let mut unresolved = Vec::new();
    for address in result
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        match procedures.iter().find(|item| item.address == address) {
            Some(procedure) => identities.push(procedure_identity(procedure)),
            None => unresolved.push(address.to_owned()),
        }
    }
    (identities, unresolved)
}

fn relationship_coverage(
    callers: &crate::analysis::Read,
    callees: &crate::analysis::Read,
    unresolved: &[String],
) -> Value {
    let mut limitations = Vec::new();
    let mut diagnostics = Vec::new();
    for read in [callers, callees] {
        if let Some(coverage) = &read.relationship_coverage {
            limitations.extend(
                coverage["limitations"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned),
            );
            diagnostics.extend(
                coverage["diagnostics"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned),
            );
        }
    }
    if !unresolved.is_empty() {
        limitations.push(format!(
            "{} relationship target(s) were outside the frozen procedure inventory and remain unresolved.",
            unresolved.len()
        ));
        diagnostics.push(format!(
            "Unresolved relationship addresses: {}.",
            unresolved.join(", ")
        ));
    }
    limitations.sort();
    limitations.dedup();
    diagnostics.sort();
    diagnostics.dedup();
    json!({
        "status": "partial",
        "limitations": limitations,
        "limited_directions": ["callers", "callees"],
        "diagnostics": diagnostics,
    })
}

enum PseudocodeFacet {
    Available(String),
    Unavailable { reason: String },
}

fn normalize_assembly(result: &Value) -> Result<Vec<String>, AnalysisError> {
    result
        .as_str()
        .ok_or_else(|| {
            AnalysisError::output(
                "analyze_function",
                "The provider returned a non-string assembly result.",
            )
        })
        .map(|assembly| assembly.lines().map(str::to_owned).collect())
}

fn project_pseudocode_facet(facet: &PseudocodeFacet) -> Value {
    match facet {
        PseudocodeFacet::Available(_) => json!({"available": true}),
        PseudocodeFacet::Unavailable { reason } => {
            json!({"available": false, "reason": reason})
        }
    }
}

fn compose_function_dossier(
    procedure: &Procedure,
    pseudocode: &PseudocodeFacet,
    assembly: Vec<String>,
    callers: Vec<Value>,
    callees: Vec<Value>,
    limitations: Vec<String>,
) -> Value {
    let pseudocode_text = match pseudocode {
        PseudocodeFacet::Available(text) => text.clone(),
        PseudocodeFacet::Unavailable { .. } => String::new(),
    };
    json!({
        "procedure": function_identity(procedure),
        "pseudocode": pseudocode_text,
        "assembly": assembly,
        "comments": [],
        "callers": callers,
        "callees": callees,
        "incoming_references": [],
        "outgoing_references": [],
        "referenced_strings": [],
        "referenced_names": [],
        "basic_blocks": [],
        "native_api": null,
        "native_value_flow": null,
        "facet_availability": {
            "pseudocode": project_pseudocode_facet(pseudocode),
            "assembly": {"available": true},
            "comments": {"available": false, "reason": "The worker does not retain comments."},
            "callers": {"available": true},
            "callees": {"available": true},
            "references": {"available": false, "reason": "Function reference projection is not composed into this dossier."},
            "strings_names": {"available": false, "reason": "Function string and name projections are not retained by this worker."},
            "cfg": {"available": false, "reason": "The worker does not recover a control-flow graph."}
        },
        "limitations": limitations
    })
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
            Operation::ListNames => self.inventory.list_names(&self.session, control).map(read),
            Operation::AnalyzeFunction => self.analyze_function(input, control),
            Operation::AddressToFileOffset => {
                static_routes::address_to_file_offset(&self.session, input, control).map(read)
            }
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
            Operation::InspectNativeInstruction => {
                crate::native_instruction::inspect(session, input, control).map(Observation::from)
            }
            Operation::ProcedureInfo => self.procedure_info(input, control),
            Operation::ResolveContainingProcedure => {
                self.resolve_containing_procedure(input, control)
            }
            Operation::ResolveNativeCallTargets => self.resolve_native_call_targets(input, control),
            Operation::InspectNativeLoadImage => self.inspect_native_load_image(control),
            Operation::CurrentAddress => self.current_address(control),
            Operation::GetNavigationContext => self.navigation_context(input, control),
            Operation::ReadBytes => {
                crate::analysis::read_bytes(session, input, control).map(Observation::from)
            }
            Operation::SearchBytes => {
                self.session.prepare(control)?;
                let mut worker_input = input.clone();
                worker_input.remove("document");
                for key in ["start", "end"] {
                    if let Some(value) = worker_input.get_mut(key) {
                        let Some(text) = value.as_str() else {
                            return Err(self
                                .session
                                .failure("The byte-search address bound must be hexadecimal."));
                        };
                        let normalized = normalize_hex_address(text).ok_or_else(|| {
                            self.session
                                .failure("The byte-search address bound must be hexadecimal.")
                        })?;
                        *value = Value::String(normalized);
                    }
                }
                self.session
                    .worker
                    .request("search_bytes", Value::Object(worker_input), Some(control))
                    .map(read)
            }
        }
    }

    fn procedure_info(
        &self,
        input: &Map<String, Value>,
        control: &Control,
    ) -> Result<Observation, AnalysisError> {
        let selector = input
            .get("procedure")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let page = selectors::resolve_page(
            &self.session,
            &[selector.to_owned()],
            control,
            "procedure_info",
        )?;
        let item = page.first().ok_or_else(|| {
            self.session
                .failure("The worker omitted a procedure selector result.")
        })?;
        let (Some(address), Some(name)) = (&item.address, &item.name) else {
            return Err(selectors::selector_error(
                "procedure_info",
                item.status,
                control.selector_from_provider,
            ));
        };
        let body = self.function_body(address, control)?;
        let entry = address_number(address).ok_or_else(|| {
            self.session
                .failure("The worker returned an invalid procedure address.")
        })?;
        let parsed = parse_worker_function_body(&body, entry)
            .map_err(|reason| self.session.failure(reason))?;
        if !parsed.complete {
            return Err(AnalysisError::capability_unavailable(
                PROVIDER_ID,
                "procedure_info",
                "The worker could not recover complete reachable body ranges for this procedure.",
            ));
        }
        let ranges = body_ranges_json(&parsed);
        let length = parsed.total_bytes;
        let basicblock_count = parsed.basicblock_count;
        let result = json!({
            "name": name,
            "entrypoint": address,
            "basicblock_count": basicblock_count,
            "length": length,
            "signature": null,
            "locals": null,
            "classification": {
                "external": null,
                "thunk": null,
                "thunk_target": null,
                "provenance": "ghidra-rust-sleigh-cfg"
            },
            "body": {
                "available": true,
                "provenance": "ghidra-rust-sleigh-cfg",
                "ranges": ranges,
                "total_bytes": length,
                "span_bytes": parsed
                    .span_bytes()
                    .ok_or_else(|| {
                        self.session
                            .failure("The worker returned invalid procedure body ranges.")
                    })?,
                "non_contiguous": parsed.ranges.len() > 1,
                "contains_entry": true
            }
        });
        Ok(Observation {
            result,
            raw_result: None,
            relationship_coverage: None,
            references_truncated: None,
        })
    }

    fn function_body(&self, address: &str, control: &Control) -> Result<Value, AnalysisError> {
        self.session.prepare(control)?;
        self.session.worker.request(
            "function_body",
            json!({ "address": address }),
            Some(control),
        )
    }

    fn resolve_containing_procedure(
        &self,
        input: &Map<String, Value>,
        control: &Control,
    ) -> Result<Observation, AnalysisError> {
        let address = input
            .get("address")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let requested = canonical_address(address)
            .ok_or_else(|| self.session.failure("The address must be hexadecimal."))?;
        let requested_value = address_number(&requested).ok_or_else(|| {
            self.session
                .failure("The address is outside the worker address range.")
        })?;
        self.session.prepare(control)?;
        let segments = self
            .session
            .worker
            .request("segments", json!({}), Some(control))?;
        let in_segment = address_is_in_segments(&segments, requested_value)
            .map_err(|reason| self.session.failure(reason))?;
        if !in_segment {
            return Ok(Observation {
                result: json!({
                    "query_address": requested,
                    "found": false,
                    "procedure": null,
                    "reason": "outside_segments"
                }),
                raw_result: None,
                relationship_coverage: None,
                references_truncated: None,
            });
        }
        let procedures = self.inventory.read(&self.session, control)?;
        let mut containing = procedures
            .iter()
            .find(|item| address_number(&item.address) == Some(requested_value));
        for item in procedures.iter().rev() {
            if containing.is_some() {
                break;
            }
            let item_address = address_number(&item.address).ok_or_else(|| {
                self.session
                    .failure("The worker returned an invalid procedure address.")
            })?;
            if item_address > requested_value {
                continue;
            }
            let body = self.function_body(&item.address, control)?;
            let item_entry = address_number(&item.address).ok_or_else(|| {
                self.session
                    .failure("The worker returned an invalid procedure address.")
            })?;
            let parsed = parse_worker_function_body(&body, item_entry)
                .map_err(|reason| self.session.failure(reason))?;
            if !parsed.complete {
                continue;
            }
            if parsed
                .ranges
                .iter()
                .any(|range| (range.start..=range.end).contains(&requested_value))
            {
                containing = Some(item);
                break;
            }
            if containing.is_some() {
                break;
            }
        }
        let result = match containing {
            Some(item) => json!({
                "query_address": requested,
                "found": true,
                "procedure": procedure_identity(item)
            }),
            None => {
                return Err(AnalysisError::capability_unavailable(
                    PROVIDER_ID,
                    "resolve_containing_procedure",
                    "The worker could not prove that this mapped address is outside every recovered procedure body.",
                ));
            }
        };
        Ok(Observation {
            result,
            raw_result: None,
            relationship_coverage: None,
            references_truncated: None,
        })
    }

    fn resolve_native_call_targets(
        &self,
        input: &Map<String, Value>,
        control: &Control,
    ) -> Result<Observation, AnalysisError> {
        let instruction = native_instruction::inspect(&self.session, input, control)?.result;
        let call_site = instruction.get("address").cloned().unwrap_or(Value::Null);
        let procedure = instruction.get("procedure").cloned().unwrap_or(Value::Null);
        let references = instruction
            .get("references")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut grouped: std::collections::BTreeMap<String, Vec<Value>> =
            std::collections::BTreeMap::new();
        for reference in references {
            if reference.get("call") != Some(&Value::Bool(true)) {
                continue;
            }
            if let Some(address) = reference.get("target_address").and_then(Value::as_str) {
                grouped
                    .entry(address.to_owned())
                    .or_default()
                    .push(reference);
            }
        }
        let is_call = instruction
            .get("flow")
            .and_then(|v| v.get("kind"))
            .and_then(Value::as_str)
            == Some("call");
        let computed = instruction
            .get("flow")
            .and_then(|flow| flow.get("computed"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ambiguous = grouped.len() > 1;
        let targets = grouped
            .into_iter()
            .map(|(address, references)| {
                let procedure = references
                    .iter()
                    .find_map(|reference| reference.get("target_procedure").cloned())
                    .unwrap_or(Value::Null);
                json!({
                    "address": address,
                    "procedure": procedure,
                    "status": if ambiguous { "candidate" } else if computed { "resolved-indirect" } else { "direct" },
                    "basis": "provider-reference",
                    "references": references
                })
            })
            .collect::<Vec<_>>();
        let status = if instruction.get("status").and_then(Value::as_str) != Some("decoded") {
            "unavailable"
        } else if !is_call {
            "not-call"
        } else if targets.is_empty() {
            "unresolved"
        } else if ambiguous {
            "ambiguous"
        } else if computed {
            "resolved-indirect"
        } else {
            "direct"
        };
        let mechanism = if !is_call {
            "unavailable"
        } else if computed {
            "computed"
        } else {
            "direct"
        };
        let result = json!({
            "call_site": call_site,
            "procedure": procedure,
            "status": status,
            "mechanism": mechanism,
            "targets": targets,
            "limitations": [
                "Targets are static provider call-reference observations; a resolved reference is not proof of runtime execution.",
                "Objective-C, Swift, vtable and closure mechanisms are not identified by this reference-only boundary."
            ]
        });
        Ok(Observation {
            result,
            raw_result: None,
            relationship_coverage: None,
            references_truncated: None,
        })
    }

    fn inspect_native_load_image(&self, control: &Control) -> Result<Observation, AnalysisError> {
        let info = self.session.prepare(control)?;
        let image = self
            .session
            .worker
            .request("image_map", json!({}), Some(control))?;
        let ranges = image
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                self.session
                    .failure("The worker returned malformed image mappings.")
            })?;
        let mut image_base: Option<(u64, String)> = None;
        let mut mappings = Vec::with_capacity(ranges.len());
        for range in ranges {
            let mapping =
                parse_worker_image_mapping(range).map_err(|reason| self.session.failure(reason))?;
            if image_base
                .as_ref()
                .is_none_or(|(value, _)| mapping.start_value < *value)
            {
                image_base = Some((mapping.start_value, mapping.start.clone()));
            }
            mappings.push(mapping.to_json());
        }
        let image_base = image_base
            .map(|(_, address)| address)
            .unwrap_or_else(|| "unknown".to_owned());
        let observations = json!({
            "executable_format": self.target.format,
            "language_id": info.raw.get("language").and_then(Value::as_str).unwrap_or("unknown"),
            "compiler_spec_id": "unknown",
            "image_base": image_base,
            "default_address_space": "ram",
            "source_files": [],
            "mappings": mappings,
            "relocations": [],
            "entry_points": [],
            "entry_context": []
        });
        let result = json!({
            "status": "unsupported",
            "reason": "The Rust worker preserves native image mappings but does not expose Ghidra load-image relocation semantics for this target.",
            "observations": observations,
            "limitations": ["Load-image relocation and source-file provenance are unavailable from the Rust worker."]
        });
        Ok(Observation {
            result,
            raw_result: None,
            relationship_coverage: None,
            references_truncated: None,
        })
    }

    fn current_address(&self, _control: &Control) -> Result<Observation, AnalysisError> {
        Err(AnalysisError::capability_unavailable(
            PROVIDER_ID,
            "current_address",
            "The Rust provider has no UI cursor or current address.",
        ))
    }

    fn navigation_context(
        &self,
        _input: &Map<String, Value>,
        _control: &Control,
    ) -> Result<Observation, AnalysisError> {
        Err(AnalysisError::capability_unavailable(
            PROVIDER_ID,
            "get_navigation_context",
            "The Rust provider has no UI navigation context.",
        ))
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

    fn pseudocode_for_dossier(
        &self,
        address: &str,
        control: &Control,
    ) -> Result<PseudocodeFacet, AnalysisError> {
        match self.pseudocode(address, control) {
            Ok(value) => {
                let pseudocode = value.as_str().map(str::to_owned).ok_or_else(|| {
                    self.session
                        .failure("The provider returned a non-string pseudocode result.")
                })?;
                Ok(PseudocodeFacet::Available(pseudocode))
            }
            Err(error) if error.tag() == "AnalysisOutputError" => {
                Ok(PseudocodeFacet::Unavailable {
                    reason: error.message().to_owned(),
                })
            }
            Err(error) => Err(error),
        }
    }

    /// Compose the provider-neutral function dossier from the worker's
    /// validated inventory, pseudocode, assembly and relationship reads.
    /// The worker deliberately does not recover function bodies, so the
    /// dossier preserves that fact as an explicit unavailable body facet.
    fn analyze_function(
        &self,
        input: &Map<String, Value>,
        control: &Control,
    ) -> Result<Observation, AnalysisError> {
        let selector = input
            .get("procedure")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let address = selectors::resolve(&self.session, selector, control)?;
        let procedures = self.inventory.read(&self.session, control)?;
        let procedure = procedures
            .iter()
            .find(|item| item.address == address)
            .ok_or_else(|| {
                self.session
                    .failure("The resolved procedure is absent from the frozen inventory.")
            })?;
        let procedure_input =
            Map::from_iter([(String::from("procedure"), json!(procedure.address))]);

        let assembly =
            crate::analysis::assembly(&self.session, &self.inventory, &procedure_input, control)?;
        let caller_read =
            crate::analysis::callers(&self.session, &self.inventory, &procedure_input, control)?;
        let callee_read =
            crate::analysis::callees(&self.session, &self.inventory, &procedure_input, control)?;
        let pseudocode = self.pseudocode_for_dossier(&procedure.address, control)?;
        let mut dossier_limitations = vec![
            "Function bodies, CFG blocks, comments, referenced strings and names are unavailable from the Rust worker.".to_owned(),
            "Callers and callees are derived from the worker's linear p-code reference pass; indirect calls and calls through memory remain unresolved.".to_owned(),
        ];
        if let PseudocodeFacet::Unavailable { reason } = &pseudocode {
            dossier_limitations.push(format!(
                "Pseudocode is unavailable for this inventory entry: {reason}"
            ));
        }
        let assembly_lines = normalize_assembly(&assembly.result)?;
        let (callers, unresolved_callers) =
            related_procedure_identities(&procedures, &caller_read.result);
        let (callees, unresolved_callees) =
            related_procedure_identities(&procedures, &callee_read.result);
        let mut unresolved = unresolved_callers;
        unresolved.extend(unresolved_callees);
        let result = compose_function_dossier(
            procedure,
            &pseudocode,
            assembly_lines,
            callers,
            callees,
            dossier_limitations,
        );
        Ok(Observation {
            result,
            raw_result: None,
            relationship_coverage: Some(relationship_coverage(
                &caller_read,
                &callee_read,
                &unresolved,
            )),
            references_truncated: None,
        })
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

fn normalize_hex_address(value: &str) -> Option<String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if digits.is_empty()
        || digits.len() > 16
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    u64::from_str_radix(digits, 16)
        .ok()
        .map(|value| format!("0x{value:x}"))
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
    const REQUIRED_ADDRESS: (&str, Field) = (
        "address",
        Field::String {
            required: true,
            min: 1,
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
        Operation::Health
        | Operation::ListDocuments
        | Operation::CurrentDocument
        | Operation::InspectNativeLoadImage
        | Operation::GetNavigationContext
        | Operation::CurrentAddress => &[],
        Operation::ListSegments | Operation::ListProcedures | Operation::ListNames => &[DOCUMENT],
        Operation::AnalyzeFunction => &[PROCEDURE, DOCUMENT],
        Operation::AddressToFileOffset => &[
            DOCUMENT,
            (
                "address",
                Field::String {
                    required: true,
                    min: 1,
                },
            ),
        ],
        Operation::SearchBytes => &[
            (
                "pattern",
                Field::String {
                    required: true,
                    min: 1,
                },
            ),
            (
                "mask",
                Field::String {
                    required: false,
                    min: 1,
                },
            ),
            (
                "start",
                Field::String {
                    required: false,
                    min: 1,
                },
            ),
            (
                "end",
                Field::String {
                    required: false,
                    min: 1,
                },
            ),
            ("limit", Field::Positive { default: 100 }),
            (
                "cursor",
                Field::String {
                    required: false,
                    min: 1,
                },
            ),
            DOCUMENT,
        ],
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
        Operation::ProcedureInfo => &[PROCEDURE, DOCUMENT],
        Operation::ResolveContainingProcedure => &[REQUIRED_ADDRESS, DOCUMENT],
        Operation::ResolveNativeCallTargets => &[REQUIRED_ADDRESS, DOCUMENT],
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
        Operation::InspectNativeInstruction => &[
            (
                "address",
                Field::String {
                    required: true,
                    min: 1,
                },
            ),
            DOCUMENT,
        ],
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

#[cfg(test)]
mod address_tests {
    use super::{
        address_number, canonical_address, parse_worker_function_body, parse_worker_image_mapping,
    };
    use crate::protocol::Procedure;
    use serde_json::json;

    #[test]
    fn canonicalizes_hex_addresses_without_panicking_on_short_input() {
        assert_eq!(canonical_address("0X000A"), Some("0xa".to_owned()));
        assert_eq!(address_number("0x000A"), Some(10));
        assert_eq!(address_number("0xffffffffffffffff"), Some(u64::MAX));
    }

    #[test]
    fn rejects_non_hex_and_missing_prefix_addresses() {
        assert_eq!(canonical_address("a"), None);
        assert_eq!(address_number("0x"), None);
        assert_eq!(address_number("0x10000000000000000"), None);
        assert_eq!(address_number("0x12xz"), None);
    }

    #[test]
    fn inventory_entry_identity_remains_known_when_body_is_unavailable() {
        let procedure = Procedure {
            address: "0x10".to_owned(),
            name: "entry".to_owned(),
        };
        let identity = super::procedure_identity(&procedure);
        assert_eq!(identity["address"], "0x10");
        assert_eq!(identity["name"], "entry");
        assert_eq!(identity["body"]["available"], false);
        assert_eq!(
            identity["body"]["reason"],
            "Reachable body ranges are unavailable for this procedure projection."
        );
    }

    #[test]
    fn rejects_inconsistent_complete_worker_body_facts() {
        let base = |ranges, total| {
            json!({
                "address": "0x10",
                "complete": true,
                "ranges": ranges,
                "total_bytes": total,
                "basicblock_count": 1
            })
        };
        assert!(
            parse_worker_function_body(
                &base(vec![json!({"start": "0x10", "end": "0x13"})], 3),
                0x10
            )
            .is_err()
        );
        assert!(
            parse_worker_function_body(
                &base(
                    vec![
                        json!({"start": "0x20", "end": "0x23"}),
                        json!({"start": "0x10", "end": "0x13"})
                    ],
                    8
                ),
                0x20
            )
            .is_err()
        );
        assert!(
            parse_worker_function_body(
                &base(vec![json!({"start": "0x10", "end": "0x13"})], 4),
                0x20
            )
            .is_err()
        );

        let body = json!({
            "address": "0x10",
            "complete": true,
            "ranges": [
                {"start": "0x10", "end": "0x13"},
                {"start": "0x20", "end": "0x23"}
            ],
            "total_bytes": 8,
            "basicblock_count": 2
        });
        let parsed = parse_worker_function_body(&body, 0x10).expect("valid body");
        assert_eq!(parsed.span_bytes(), Some(0x14));
    }

    #[test]
    fn rejects_inconsistent_image_mapping_length_and_file_offset() {
        let mut mapping = json!({
            "section": ".text",
            "start": "0x10",
            "end": "0x13",
            "length": 3,
            "initialized": true,
            "loaded": true,
            "file_offset": null
        });
        assert!(parse_worker_image_mapping(&mapping).is_err());
        mapping["length"] = json!(4);
        assert!(parse_worker_image_mapping(&mapping).is_ok());
        mapping["file_offset"] = json!("0");
        assert!(parse_worker_image_mapping(&mapping).is_err());
    }
}
