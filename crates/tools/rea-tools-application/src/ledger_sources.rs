//! Facts the obligation ledger reads from authenticated source Evidence.
//!
//! Compatibility owners: `parseApplicationGraphEvidence` in
//! `src/application/javascript/JavaScriptApplicationEvidenceGraph.ts` and
//! `parseProcessCapture` in `src/domain/process/processCaptureParsing.ts`.
//!
//! The envelope rules (operation, predicate, provider, authority and
//! confidence, subject identity, link containment, application layer) are
//! ported exactly. The complete JavaScript application-analysis, runtime
//! reconciliation, managed-graph and process-capture result schemas have no
//! native owner yet; this module validates the structure of every field the
//! ledger reads and rejects anything else that is missing or mistyped. A
//! record that satisfies these checks but violates a deeper original
//! invariant is not rejected here.
use serde_json::Value;

/// `ApplicationGraphEvidenceSource` facts used by candidate generation.
pub struct ApplicationSource<'a> {
    pub graph: &'a Value,
    pub root_artifact_sha256: &'a str,
    pub semantic_graph: Option<&'a Value>,
}

/// `parseApplicationGraphEvidence(evidence)`; `None` is the original's
/// input-validation failure.
pub fn parse_application_graph_evidence(evidence: &Value) -> Option<ApplicationSource<'_>> {
    let result = &evidence["normalized_result"];
    match evidence["operation"].as_str()? {
        "analyze_javascript_application" => {
            require(
                evidence,
                "rea.javascript-application-analysis",
                "rea-javascript-application",
                "REA JavaScript application analyzer",
            )?;
            if evidence["authority"] != "shipped-artifact" || evidence["confidence"] != "derived" {
                return None;
            }
            let root = result["root_artifact_sha256"]
                .as_str()
                .filter(|value| is_digest(value))?;
            let format = result["format"].as_str()?;
            let input_path = result["input_path"].as_str()?;
            let subject = &evidence["subject"];
            if subject.is_null()
                || subject["digest"]["sha256"].as_str() != Some(root)
                || subject["format"].as_str() != Some(format)
                || subject["local_path"].as_str() != Some(input_path)
            {
                return None;
            }
            let graph = valid_graph(&result["graph"])?;
            // The analysis result schema requires its semantic companion.
            let semantic = Some(&result["semantic_graph"])
                .filter(|semantic| valid_semantic_graph(semantic, graph, root))?;
            Some(ApplicationSource {
                graph,
                root_artifact_sha256: root,
                semantic_graph: Some(semantic),
            })
        }
        "reconcile_javascript_runtime" => {
            require(
                evidence,
                "rea.javascript-runtime-reconciliation",
                "rea-javascript-runtime-reconciliation",
                "REA JavaScript runtime reconciliation",
            )?;
            inferred_envelope(evidence)?;
            let layer = result["static_layers"]
                .as_array()?
                .iter()
                .find(|layer| layer["role"] == "application")?;
            Some(ApplicationSource {
                graph: valid_graph(&result["graph"])?,
                root_artifact_sha256: layer["root_artifact_sha256"]
                    .as_str()
                    .filter(|value| is_digest(value))?,
                semantic_graph: None,
            })
        }
        "project_managed_application_graph" => {
            require(
                evidence,
                "rea.managed-application-graph",
                "rea-dotnet-workflows",
                "REA managed-code workflows",
            )?;
            inferred_envelope(evidence)?;
            Some(ApplicationSource {
                graph: valid_graph(&result["graph"])?,
                root_artifact_sha256: result["root_artifact_sha256"]
                    .as_str()
                    .filter(|value| is_digest(value))?,
                semantic_graph: None,
            })
        }
        _ => None,
    }
}

/// The structural result checks of `parseApplicationGraphEvidence` alone
/// (graph and semantic commitments and bindings), for callers that report
/// the envelope rules with their own issue paths.
pub fn parse_application_graph_evidence_unchecked(
    evidence: &Value,
) -> Option<ApplicationSource<'_>> {
    let result = &evidence["normalized_result"];
    match evidence["operation"].as_str()? {
        "analyze_javascript_application" => {
            let root = result["root_artifact_sha256"]
                .as_str()
                .filter(|value| is_digest(value))?;
            result["format"].as_str()?;
            result["input_path"].as_str()?;
            let graph = valid_graph(&result["graph"])?;
            let semantic = Some(&result["semantic_graph"])
                .filter(|semantic| valid_semantic_graph(semantic, graph, root))?;
            Some(ApplicationSource {
                graph,
                root_artifact_sha256: root,
                semantic_graph: Some(semantic),
            })
        }
        "reconcile_javascript_runtime" => {
            let layer = result["static_layers"]
                .as_array()?
                .iter()
                .find(|layer| layer["role"] == "application");
            Some(ApplicationSource {
                graph: valid_graph(&result["graph"])?,
                root_artifact_sha256: layer
                    .and_then(|layer| layer["root_artifact_sha256"].as_str())
                    .filter(|value| is_digest(value))
                    .unwrap_or_default(),
                semantic_graph: None,
            })
        }
        "project_managed_application_graph" => Some(ApplicationSource {
            graph: valid_graph(&result["graph"])?,
            root_artifact_sha256: result["root_artifact_sha256"]
                .as_str()
                .filter(|value| is_digest(value))?,
            semantic_graph: None,
        }),
        _ => None,
    }
}

fn require(
    evidence: &Value,
    predicate: &str,
    provider_id: &str,
    provider_name: &str,
) -> Option<()> {
    let provider = &evidence["provider"];
    (evidence["predicate_type"] == predicate
        && provider["id"] == provider_id
        && provider["name"] == provider_name
        && provider["version"] == "1")
        .then_some(())
}

/// Runtime reconciliation and managed graphs: analyst inference whose result
/// links stay within the envelope's links.
fn inferred_envelope(evidence: &Value) -> Option<()> {
    if evidence["authority"] != "analyst-inference" || evidence["confidence"] != "inferred" {
        return None;
    }
    let envelope: Vec<&Value> = evidence["evidence_links"].as_array()?.iter().collect();
    let links = evidence["normalized_result"]["evidence_links"].as_array()?;
    links
        .iter()
        .all(|link| link.is_string() && envelope.contains(&link))
        .then_some(())
}

/// `"<prefix>" + digestCanonicalValue(value without <id_field>)`.
fn commitment(value: &Value, id_field: &str, prefix: &str) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let mut semantic = object.clone();
    let Some(declared) = semantic.remove(id_field) else {
        return false;
    };
    rea_core::canonical_json::digest(&Value::Object(semantic))
        .is_ok_and(|digest| declared.as_str() == Some(format!("{prefix}{digest}").as_str()))
}

/// `jag_node_` / `jsrg_node_` identifier over `{ kind, identity }`.
fn node_commitment(node: &Value, prefix: &str) -> bool {
    rea_core::canonical_json::digest(
        &serde_json::json!({ "kind": node["kind"], "identity": node["identity"] }),
    )
    .is_ok_and(|digest| node["node_id"].as_str() == Some(format!("{prefix}{digest}").as_str()))
}

/// The JavaScript Application Graph identifier commitments
/// (`checkGraphInvariants`): graph, node, observation and edge identifiers
/// and edge and root endpoints.
fn graph_commitments(graph: &Value) -> bool {
    let nodes = graph["nodes"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let node_ids: std::collections::HashSet<&str> = nodes
        .iter()
        .filter_map(|node| node["node_id"].as_str())
        .collect();
    commitment(graph, "graph_id", "jag_")
        && nodes.iter().all(|node| {
            node_commitment(node, "jag_node_")
                && node["observations"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .all(|observation| {
                        let mut semantic = observation.as_object().cloned().unwrap_or_default();
                        let declared = semantic.remove("observation_id");
                        semantic.insert("node_id".into(), node["node_id"].clone());
                        rea_core::canonical_json::digest(&Value::Object(semantic)).is_ok_and(
                            |digest| {
                                declared.as_ref().and_then(Value::as_str)
                                    == Some(format!("jag_observation_{digest}").as_str())
                            },
                        )
                    })
        })
        && graph["edges"].as_array().is_some_and(|edges| {
            edges.iter().all(|edge| {
                commitment(edge, "edge_id", "jag_edge_")
                    && edge["source_node_id"]
                        .as_str()
                        .is_some_and(|id| node_ids.contains(id))
                    && edge["target_node_id"]
                        .as_str()
                        .is_some_and(|id| node_ids.contains(id))
                    && edge["source_node_id"] != edge["target_node_id"]
            })
        })
        && graph["root_node_ids"].as_array().is_some_and(|roots| {
            !roots.is_empty()
                && roots
                    .iter()
                    .all(|root| root.as_str().is_some_and(|id| node_ids.contains(id)))
        })
}

fn valid_graph(graph: &Value) -> Option<&Value> {
    let prefixed = graph["graph_id"]
        .as_str()
        .is_some_and(|id| id.starts_with("jag_"))
        && graph_commitments(graph);
    let nodes = graph["nodes"]
        .as_array()
        .filter(|nodes| !nodes.is_empty())?;
    let nodes_valid = nodes.iter().all(|node| {
        node["node_id"].is_string()
            && node["kind"].is_string()
            && node["observations"].as_array().is_some_and(|observations| {
                !observations.is_empty()
                    && observations.iter().all(|observation| {
                        observation["observation_id"].is_string()
                            && (observation["label"].is_null() || observation["label"].is_string())
                            && valid_graph_evidence(&observation["evidence"])
                    })
            })
    });
    let coverage = matches!(
        graph["coverage"]["status"].as_str(),
        Some("complete" | "partial" | "unknown" | "unavailable")
    );
    (prefixed && nodes_valid && coverage).then_some(graph)
}

/// The semantic companion's commitments and its bindings to the containing
/// application analysis (`checkApplicationBindingsSteps`).
fn valid_semantic_graph(
    graph: &Value,
    application_graph: &Value,
    root_artifact_sha256: &str,
) -> bool {
    let context_ids: std::collections::HashSet<&str> = graph["evidence_contexts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|context| context["context_id"].as_str())
        .collect();
    let application_node_ids: std::collections::HashSet<&str> = application_graph["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|node| node["node_id"].as_str())
        .collect();
    commitment(graph, "graph_id", "jsrg_")
        && graph["application_graph_id"] == application_graph["graph_id"]
        && graph["root_artifact_sha256"].as_str() == Some(root_artifact_sha256)
        && graph["evidence_contexts"]
            .as_array()
            .is_some_and(|contexts| {
                contexts.iter().all(|context| {
                    context["context_id"].is_string()
                        && commitment(context, "context_id", "jsrg_evidence_")
                        && valid_graph_evidence(context)
                })
            })
        && graph["nodes"].as_array().is_some_and(|nodes| {
            nodes.iter().all(|node| {
                node_commitment(node, "jsrg_node_")
                    && node["evidence"]["context_id"]
                        .as_str()
                        .is_some_and(|id| context_ids.contains(id))
                    && node["application_node_ids"].as_array().is_some_and(|ids| {
                        ids.iter().all(|id| {
                            id.as_str()
                                .is_some_and(|id| application_node_ids.contains(id))
                        })
                    })
                    && node["node_id"].is_string()
                    && node["kind"].is_string()
                    && (node["label"].is_null() || node["label"].is_string())
                    && node["identity"]["artifact_sha256"]
                        .as_str()
                        .is_some_and(is_digest)
                    && node["application_node_ids"]
                        .as_array()
                        .is_some_and(|ids| ids.iter().all(Value::is_string))
                    && node["evidence"]["context_id"].is_string()
            })
        })
}

fn valid_graph_evidence(evidence: &Value) -> bool {
    evidence["authority"].is_string()
        && evidence["state"].is_string()
        && evidence["evidence_ids"]
            .as_array()
            .is_some_and(|ids| ids.iter().all(Value::is_string))
}

/// Process capture facts the ledger reads (`ProcessCapture`).
pub struct ProcessCaptureFacts<'a> {
    pub exit_code: Option<f64>,
    pub exit_signal_present: bool,
    pub exit_reason: &'a str,
    pub executable_sha256: Option<&'a str>,
    pub full_scenario_sha256: &'a str,
    pub residual_unknowns: Vec<(&'a str, &'a str)>,
    pub truncated: bool,
}

/// `parseProcessCapture` for the fields the ledger reads.
pub fn parse_process_capture(capture: &Value) -> Result<ProcessCaptureFacts<'_>, String> {
    let invalid = |path: &str, expected: &str| {
        format!("Invalid process capture: {path}: expected {expected}")
    };
    let exit = &capture["exit"];
    let integer_or_null = |value: &Value| {
        value.is_null() || value.as_f64().is_some_and(|number| number.fract() == 0.0)
    };
    if !integer_or_null(&exit["code"]) {
        return Err(invalid("exit.code", "an integer or null"));
    }
    if !integer_or_null(&exit["signal"]) {
        return Err(invalid("exit.signal", "an integer or null"));
    }
    let exit_reason = exit["reason"]
        .as_str()
        .filter(|reason| matches!(*reason, "exited" | "timeout" | "idle_timeout"))
        .ok_or_else(|| invalid("exit.reason", "exited, timeout, or idle_timeout"))?;
    let manifest = &capture["manifest"];
    let executable_sha256 = match &manifest["executable_sha256"] {
        Value::Null => None,
        Value::String(value) if is_digest(value) => Some(value.as_str()),
        _ => {
            return Err(invalid(
                "manifest.executable_sha256",
                "a SHA-256 digest or null",
            ));
        }
    };
    let full_scenario_sha256 = manifest["full_scenario_sha256"]
        .as_str()
        .filter(|value| is_digest(value))
        .ok_or_else(|| invalid("manifest.full_scenario_sha256", "a SHA-256 digest"))?;
    if !capture["settlement"].is_object() {
        return Err(invalid("settlement", "an object"));
    }
    let truncated = capture["truncated"]
        .as_bool()
        .ok_or_else(|| invalid("truncated", "a boolean"))?;
    let residual_unknowns = capture["residual_unknowns"]
        .as_array()
        .ok_or_else(|| invalid("residual_unknowns", "an array"))?
        .iter()
        .map(
            |unknown| match (unknown["scope"].as_str(), unknown["reason"].as_str()) {
                (Some(scope), Some(reason)) => Ok((scope, reason)),
                _ => Err(invalid("residual_unknowns", "scope and reason strings")),
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    let issues = process_capture_issues(capture);
    if !issues.is_empty() {
        return Err(format!(
            "Invalid process capture: {}",
            issues
                .iter()
                .map(|(path, message)| format!("{path}: {message}"))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    Ok(ProcessCaptureFacts {
        exit_code: exit["code"].as_f64(),
        exit_signal_present: !exit["signal"].is_null(),
        exit_reason,
        executable_sha256,
        full_scenario_sha256,
        residual_unknowns,
        truncated,
    })
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// `collectProcessCaptureIssues` (`src/domain/process/processCaptureValidation.ts`):
/// commitments and cross-field invariants, as `(path, message)` pairs.
fn process_capture_issues(capture: &Value) -> Vec<(String, String)> {
    let mut issues = Vec::new();
    let mut require = |condition: bool, path: &str, message: &str| {
        if !condition {
            issues.push((path.to_owned(), message.to_owned()));
        }
    };
    let manifest = &capture["manifest"];
    // validateCommitments
    require(
        manifest["scenario"].get("executable_sha256") == manifest.get("selected_executable_sha256"),
        "manifest.selected_executable_sha256",
        "selected executable commitment does not match the scenario projection",
    );
    let identity = &manifest["executable_identity"];
    require(
        if identity["state"] == "path_metadata_unchanged" {
            manifest["executable_sha256"] == manifest["selected_executable_sha256"]
                && identity["reason"].is_null()
        } else {
            manifest["executable_sha256"].is_null() && !identity["reason"].is_null()
        },
        "manifest.executable_identity",
        "launch identity and executable digest do not agree",
    );
    for (field, value) in [
        ("full_scenario_sha256", &manifest["scenario"]),
        (
            "comparison_contract_sha256",
            &manifest["comparison_contract"],
        ),
        ("normalization_sha256", &capture["normalization"]),
    ] {
        let digest = rea_core::canonical_json::digest(value).ok();
        require(
            digest.is_some() && manifest[field].as_str() == digest.as_deref(),
            &format!("manifest.{field}"),
            "commitment does not match its canonical value",
        );
    }
    // validateOrdering
    let list = |field: &str| {
        capture[field]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
    };
    let number = |value: &Value| value.as_f64().unwrap_or(f64::NAN);
    for name in ["frames", "rendered_frames", "interaction_events"] {
        require(
            list(name)
                .iter()
                .enumerate()
                .all(|(index, item)| number(&item["sequence"]) == index as f64),
            name,
            "sequence values must be contiguous from zero",
        );
    }
    let ordered = |values: Vec<f64>| values.windows(2).all(|pair| pair[1] >= pair[0]);
    for name in ["frames", "rendered_frames", "process_samples"] {
        require(
            ordered(
                list(name)
                    .iter()
                    .map(|item| number(&item["at_ms"]))
                    .collect(),
            ),
            name,
            "timestamps must be ordered",
        );
    }
    require(
        ordered(
            list("interaction_events")
                .iter()
                .map(|item| number(&item["dispatched_at_ms"]))
                .collect(),
        ),
        "interaction_events",
        "dispatch timestamps must be ordered",
    );
    // validateEventJournal
    let journal = list("event_journal");
    if !journal.is_empty() {
        let size = |collection: &str| -> f64 {
            match collection {
                "lifecycle" => 2.0,
                "frames"
                | "rendered_frames"
                | "interaction_events"
                | "process_samples"
                | "filesystem_checkpoints" => list(collection).len() as f64,
                _ => f64::NAN,
            }
        };
        let mut references = std::collections::HashSet::new();
        for (position, entry) in journal.iter().enumerate() {
            require(
                number(&entry["capture_order"]) == position as f64,
                &format!("event_journal.{position}.capture_order"),
                "capture order must be contiguous from zero",
            );
            let collection = entry["collection"].as_str().unwrap_or_default();
            require(
                number(&entry["index"]) < size(collection),
                &format!("event_journal.{position}.index"),
                "journal reference is outside its capture collection",
            );
            let reference = format!("{collection}:{}", js_number(&entry["index"]));
            require(
                !references.contains(&reference),
                &format!("event_journal.{position}"),
                "journal references must be unique",
            );
            references.insert(reference);
        }
        let expected = [
            "frames",
            "rendered_frames",
            "interaction_events",
            "process_samples",
            "filesystem_checkpoints",
        ]
        .iter()
        .map(|name| list(name).len())
        .sum::<usize>()
            + 2;
        require(
            journal.len() == expected,
            "event_journal",
            "nonempty journal must reference every captured observation",
        );
    }
    // validateLifecycle
    let checkpoints = list("filesystem_checkpoints");
    require(
        checkpoints
            .iter()
            .map(|checkpoint| checkpoint["name"].as_str().unwrap_or_default())
            .collect::<Vec<_>>()
            .join(",")
            == "before,after_settlement",
        "filesystem_checkpoints",
        "capture must include initial and final filesystem snapshots",
    );
    require(
        ordered(
            checkpoints
                .iter()
                .map(|checkpoint| number(&checkpoint["at_ms"]))
                .collect(),
        ),
        "filesystem_checkpoints",
        "filesystem snapshot times must be ordered",
    );
    let truncated = capture["truncated"] == true;
    require(
        !checkpoints
            .iter()
            .any(|checkpoint| checkpoint["truncated"] == true)
            || truncated,
        "truncated",
        "filesystem snapshot truncation must propagate to the capture",
    );
    let exit = &capture["exit"];
    require(
        exit["reason"] == "exited" || exit["code"].is_null(),
        "exit",
        "deadline termination cannot declare a normal exit code",
    );
    if let Some(issue) = finalization_consistency_issue(
        exit,
        &manifest["scenario"],
        &manifest["comparison_contract"],
    ) {
        require(false, "exit", issue);
    }
    // validateCoverage
    let details = &capture["truncation_details"];
    let process = &details["process"];
    require(
        number(&process["retained_samples"]) == list("process_samples").len() as f64
            && number(&process["retained_samples"]) <= number(&process["sample_limit"])
            && process["sampling_partial"].as_bool()
                == Some(
                    process["sample_limit_reached"] == true
                        || number(&process["sampling_failures"]) > 0.0,
                )
            && (number(&process["sampling_failures"]) == 0.0)
                == process["first_sampling_failure"].is_null(),
        "truncation_details.process",
        "sampling coverage must agree with retained samples and observed failures",
    );
    require(
        truncated == has_capture_truncation(details),
        "truncation_details",
        "aggregate truncation must match producer coverage",
    );
    let utf8 = |value: &Value| value.as_str().map(str::len).unwrap_or(0) as f64;
    let raw_bytes: f64 = list("frames")
        .iter()
        .map(|frame| {
            if frame["raw_data"].is_string() {
                utf8(&frame["raw_data"])
            } else {
                utf8(&frame["data"])
            }
        })
        .sum();
    let rendered_bytes: f64 = list("rendered_frames")
        .iter()
        .map(|frame| {
            utf8(&frame["serialized_state"])
                + frame["lines"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(utf8)
                    .sum::<f64>()
        })
        .sum();
    for (name, count, bytes) in [
        ("raw_terminal", list("frames").len() as f64, raw_bytes),
        (
            "rendered_terminal",
            list("rendered_frames").len() as f64,
            rendered_bytes,
        ),
    ] {
        let retention = &details[name];
        let retained_frames = number(&retention["retained_frames"]);
        let observed_frames = number(&retention["observed_frames"]);
        let retained_bytes = number(&retention["retained_bytes"]);
        let observed_bytes = number(&retention["observed_bytes"]);
        let unknown = retention["unknown_size_frames"].as_f64().unwrap_or(0.0);
        require(
            retained_frames == count
                && observed_frames >= count
                && retained_bytes == bytes
                && observed_bytes >= retained_bytes
                && (observed_frames > count || observed_bytes == retained_bytes)
                && retained_bytes <= number(&retention["budget_bytes"])
                && unknown <= observed_frames - retained_frames,
            &format!("truncation_details.{name}"),
            "retained observations and budget accounting do not agree",
        );
    }
    let normalized = &details["normalized_terminal"];
    if normalized.is_object() {
        let output_bytes = &manifest["scenario"]["limits"]["output_bytes"];
        let budget_valid = manifest["scenario"]["limits"].is_object()
            && output_bytes.as_f64().is_some_and(|value| {
                value.fract() == 0.0 && value > 0.0 && value <= 9_007_199_254_740_991.0
            });
        require(
            budget_valid,
            "manifest.scenario.limits.output_bytes",
            "committed process scenario must include an explicit valid output_bytes budget",
        );
        let retained: f64 = list("frames")
            .iter()
            .map(|frame| utf8(&frame["data"]))
            .sum();
        if budget_valid {
            require(
                number(&normalized["budget_bytes"]) == number(output_bytes)
                    && number(&normalized["retained_bytes"]) == retained
                    && number(&normalized["retained_bytes"]) <= number(&normalized["budget_bytes"])
                    && number(&normalized["omitted_frames"])
                        <= number(&details["raw_terminal"]["observed_frames"])
                            - number(&details["raw_terminal"]["retained_frames"]),
                "truncation_details.normalized_terminal",
                "normalized terminal retention must agree with the committed budget and retained frames",
            );
        }
    }
    for (name, files_field, checkpoint) in [
        ("filesystem_before", "files_before", checkpoints.first()),
        ("filesystem_after", "files_after", checkpoints.get(1)),
    ] {
        let coverage = &details[name];
        let files = list(files_field);
        let mut unhashed: std::collections::HashMap<&str, &Value> =
            std::collections::HashMap::new();
        for file in files
            .iter()
            .filter(|file| file["type"] == "file" && file["sha256"].is_null())
        {
            unhashed.insert(file["path"].as_str().unwrap_or_default(), file);
        }
        let mut entry_types: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::new();
        for file in files {
            entry_types.insert(
                file["path"].as_str().unwrap_or_default(),
                file["type"].as_str().unwrap_or_default(),
            );
        }
        let hash_omissions = coverage["hash_omissions"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        let omission_paths: std::collections::HashSet<&str> = hash_omissions
            .iter()
            .map(|omission| omission["path"].as_str().unwrap_or_default())
            .collect();
        require(
            hash_omissions.len() == unhashed.len()
                && omission_paths.len() == unhashed.len()
                && hash_omissions.iter().all(|omission| {
                    unhashed
                        .get(omission["path"].as_str().unwrap_or_default())
                        .is_some_and(|file| {
                            number(&file["size"]) == number(&omission["size_bytes"])
                        })
                        && number(&omission["remaining_budget_bytes"])
                            <= number(&coverage["hash_budget_bytes"])
                        && if omission["reason"] == "file_unavailable" {
                            !omission["system_code"].is_null()
                        } else {
                            omission["system_code"].is_null()
                        }
                }),
            &format!("truncation_details.{name}.hash_omissions"),
            "every retained regular file without a digest must have one matching omission reason",
        );
        let enumeration_omissions = coverage["enumeration_omissions"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        let reasons: Vec<&str> = coverage["enumeration_reasons"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let unique_paths: std::collections::HashSet<&str> = enumeration_omissions
            .iter()
            .map(|omission| omission["path"].as_str().unwrap_or_default())
            .collect();
        require(
            unique_paths.len() == enumeration_omissions.len()
                && (!reasons.contains(&"entry_unavailable")
                    || enumeration_omissions
                        .iter()
                        .any(|omission| omission["reason"] == "entry_unavailable"))
                && enumeration_omissions.iter().all(|omission| {
                    let reason = omission["reason"].as_str().unwrap_or_default();
                    let entry_type = entry_types
                        .get(omission["path"].as_str().unwrap_or_default())
                        .copied();
                    reasons.contains(&reason)
                        && if reason == "directory_unavailable" {
                            entry_type == Some("directory") && !omission["system_code"].is_null()
                        } else {
                            (entry_type.is_none() || entry_type == Some("directory"))
                                && if reason == "entry_unavailable" {
                                    !omission["system_code"].is_null()
                                } else {
                                    omission["system_code"].is_null()
                                }
                        }
                }),
            &format!("truncation_details.{name}.enumeration_omissions"),
            "every enumeration omission must identify an unavailable entry or retained directory, with a matching reason and system error only for unavailable reads",
        );
        let hashed: f64 = files
            .iter()
            .filter(|file| file["type"] == "file" && !file["sha256"].is_null())
            .map(|file| number(&file["size"]))
            .sum();
        require(
            number(&coverage["hashed_bytes"]) == hashed
                && number(&coverage["hashed_bytes"]) <= number(&coverage["hash_budget_bytes"])
                && files.len() as f64 <= number(&coverage["files_limit"]),
            &format!("truncation_details.{name}"),
            "filesystem budget accounting does not match retained observations",
        );
        let enumeration_truncated = coverage["enumeration_truncated"] == true;
        require(
            enumeration_truncated == !reasons.is_empty()
                && checkpoint.map(|checkpoint| &checkpoint["truncated"])
                    == Some(&Value::Bool(
                        enumeration_truncated
                            || !enumeration_omissions.is_empty()
                            || !hash_omissions.is_empty(),
                    )),
            &format!("truncation_details.{name}"),
            "filesystem checkpoint truncation must match enumeration and digest coverage",
        );
    }
    issues
}

/// `hasCaptureTruncation`.
fn has_capture_truncation(details: &Value) -> bool {
    let number = |value: &Value| value.as_f64().unwrap_or(0.0);
    let omitted = |retention: &Value| {
        number(&retention["observed_frames"]) > number(&retention["retained_frames"])
    };
    let filesystem = |coverage: &Value| {
        coverage["enumeration_truncated"] == true
            || coverage["enumeration_omissions"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
            || coverage["hash_omissions"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
    };
    omitted(&details["raw_terminal"])
        || omitted(&details["rendered_terminal"])
        || number(&details["normalized_terminal"]["omitted_frames"]) > 0.0
        || number(&details["rendered_terminal"]["unknown_size_frames"]) > 0.0
        || filesystem(&details["filesystem_before"])
        || filesystem(&details["filesystem_after"])
        || details["process"]["sampling_partial"] == true
}

/// `finalizationConsistencyIssue` for a complete capture.
fn finalization_consistency_issue(
    exit: &Value,
    scenario: &Value,
    comparison: &Value,
) -> Option<&'static str> {
    if scenario.is_object()
        && comparison.is_object()
        && scenario.get("finalization_ms") != comparison.get("finalization_ms")
    {
        return Some("comparison_contract finalization_ms must match the committed scenario");
    }
    let finalization = &exit["finalization"];
    let reason = exit["reason"].as_str().unwrap_or_default();
    if finalization.is_null() {
        let committed = scenario["finalization_ms"].as_f64();
        return (matches!(reason, "timeout" | "idle_timeout")
            && committed.is_some_and(|value| value > 0.0))
        .then_some(
            "a deadline exit under a committed finalization_ms requires finalization evidence",
        );
    }
    if reason == "exited" {
        return Some("finalization requires a deadline exit reason");
    }
    let signals = finalization["signals"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let Some(first) = signals.first().filter(|first| first["signal"] == "SIGTERM") else {
        return Some("finalization signals must start with SIGTERM");
    };
    let kills: Vec<usize> = signals
        .iter()
        .enumerate()
        .filter(|(_, signal)| signal["signal"] == "SIGKILL")
        .map(|(index, _)| index)
        .collect();
    if kills.len() > 1
        || kills
            .first()
            .is_some_and(|index| *index != signals.len() - 1)
    {
        return Some("finalization may contain at most one final SIGKILL");
    }
    let sent = |signal: &Value| signal["sent_at_ms"].as_f64().unwrap_or(f64::NAN);
    if !signals
        .windows(2)
        .all(|pair| sent(&pair[1]) >= sent(&pair[0]))
    {
        return Some("finalization signal attempt times must not decrease");
    }
    if signals
        .iter()
        .filter(|signal| signal["signal"] == "SIGTERM")
        .count()
        != 1
    {
        return Some("finalization must attempt SIGTERM exactly once");
    }
    let requested = finalization["requested_ms"].as_f64().unwrap_or(f64::NAN);
    if signals
        .iter()
        .find(|signal| signal["signal"] == "SIGKILL")
        .is_some_and(|kill| sent(kill) < requested && reason != "cancelled")
    {
        return Some("finalization SIGKILL cannot precede the requested interval");
    }
    if finalization["elapsed_ms"].is_null() {
        return Some("finalization requires an observed elapsed_ms");
    }
    if !finalization["exit_code"].is_null()
        && !exit["signal"].is_null()
        && exit["signal"].as_f64() != Some(0.0)
    {
        return Some("finalization exit_code requires an exit not caused by a signal");
    }
    let last = signals.last().map(sent).unwrap_or_else(|| sent(first));
    if finalization["elapsed_ms"]
        .as_f64()
        .is_some_and(|elapsed| elapsed < last)
    {
        return Some("finalization elapsed_ms cannot precede the last signal attempt");
    }
    if scenario.is_object() && scenario["finalization_ms"].as_f64() != Some(requested) {
        return Some("finalization must match the committed finalization_ms");
    }
    None
}

/// `String(number)` for an integer journal index.
fn js_number(value: &Value) -> String {
    match value.as_f64() {
        Some(number) if number.fract() == 0.0 && number.abs() < 1e21 => {
            format!("{}", number as i64)
        }
        Some(number) => number.to_string(),
        None => "undefined".into(),
    }
}
