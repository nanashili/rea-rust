//! `processCaptureShapeSchema` (`src/domain/process/processCapture.ts`) and
//! the coverage schemas of `processCaptureCoverage.ts`.
use crate::shape::{
    Shape, array, datetime, integer, nonempty_string, nonnegative, nullable, object, optional,
    positive, required, sha256, strict, string,
};

const EVENT_COLLECTIONS: &[&str] = &[
    "frames",
    "rendered_frames",
    "interaction_events",
    "lifecycle",
    "process_samples",
    "filesystem_checkpoints",
];

fn file_state_fields(kind: Shape, sha: Shape, symlink: Shape) -> Shape {
    object(vec![
        required("path", string()),
        required("mode", nonnegative()),
        required("size", nonnegative()),
        required("type", kind),
        required("sha256", sha),
        required("symlink_target", symlink),
    ])
}

fn file_state() -> Shape {
    Shape::Union {
        key: "type",
        branches: vec![
            (
                &["file"],
                file_state_fields(Shape::Literal("file"), nullable(sha256()), Shape::Null),
            ),
            (
                &["symlink"],
                file_state_fields(Shape::Literal("symlink"), Shape::Null, string()),
            ),
            (
                &["directory", "other"],
                file_state_fields(
                    Shape::Enum(&["directory", "other"]),
                    Shape::Null,
                    Shape::Null,
                ),
            ),
        ],
    }
}

fn file_effect() -> Shape {
    let effect = |status: Shape, before: Shape, after: Shape, reason: bool| {
        let mut fields = vec![
            required("path", string()),
            required("status", status),
            required("before", before),
            required("after", after),
        ];
        if reason {
            fields.push(required("reason", nonempty_string()));
        }
        object(fields)
    };
    Shape::Union {
        key: "status",
        branches: vec![
            (
                &["created"],
                effect(Shape::Literal("created"), Shape::Null, file_state(), false),
            ),
            (
                &["deleted"],
                effect(Shape::Literal("deleted"), file_state(), Shape::Null, false),
            ),
            (
                &["modified", "unchanged"],
                effect(
                    Shape::Enum(&["modified", "unchanged"]),
                    file_state(),
                    file_state(),
                    false,
                ),
            ),
            (
                &["unknown"],
                effect(
                    Shape::Literal("unknown"),
                    nullable(file_state()),
                    nullable(file_state()),
                    true,
                ),
            ),
        ],
    }
}

fn byte_retention() -> Shape {
    strict(vec![
        required("budget_bytes", nonnegative()),
        required("observed_bytes", nonnegative()),
        required("retained_bytes", nonnegative()),
        required("observed_frames", nonnegative()),
        required("retained_frames", nonnegative()),
        optional("unknown_size_frames", nonnegative()),
    ])
}

const OMISSION_REASONS: &[&str] = &[
    "identity_changed",
    "directory_unavailable",
    "entry_unavailable",
];

fn filesystem_coverage() -> Shape {
    strict(vec![
        required("files_limit", nonnegative()),
        required("depth_limit", nonnegative()),
        required("enumeration_truncated", Shape::Bool),
        required(
            "enumeration_reasons",
            array(Shape::Enum(&[
                "files_limit",
                "depth_limit",
                "identity_changed",
                "directory_unavailable",
                "entry_unavailable",
            ])),
        ),
        required(
            "enumeration_omissions",
            array(strict(vec![
                required("path", string()),
                required("reason", Shape::Enum(OMISSION_REASONS)),
                required("system_code", nullable(string())),
            ])),
        ),
        required("hash_budget_bytes", nonnegative()),
        required("hashed_bytes", nonnegative()),
        required(
            "hash_omissions",
            array(strict(vec![
                required("path", string()),
                required("size_bytes", nonnegative()),
                required("remaining_budget_bytes", nonnegative()),
                required(
                    "reason",
                    Shape::Enum(&[
                        "file_bytes_budget",
                        "file_changed_or_short_read",
                        "file_unavailable",
                    ]),
                ),
                required("system_code", nullable(string())),
            ])),
        ),
    ])
}

fn truncation_details() -> Shape {
    strict(vec![
        required("raw_terminal", byte_retention()),
        required("rendered_terminal", byte_retention()),
        optional(
            "normalized_terminal",
            strict(vec![
                required("budget_bytes", nonnegative()),
                required("retained_bytes", nonnegative()),
                required("omitted_frames", nonnegative()),
            ]),
        ),
        required("filesystem_before", filesystem_coverage()),
        required("filesystem_after", filesystem_coverage()),
        required(
            "process",
            strict(vec![
                required("sample_limit", nonnegative()),
                required("sampling_partial", Shape::Bool),
                required("retained_samples", nonnegative()),
                required("sample_limit_reached", Shape::Bool),
                required("sampling_failures", nonnegative()),
                required("first_sampling_failure", nullable(string())),
                required("coverage", Shape::Literal("sampled")),
            ]),
        ),
    ])
}

/// `normalizationSchema` (`processScenario.ts`).
pub fn normalization() -> Shape {
    object(vec![
        required("paths", Shape::Bool),
        required("pids", Shape::Bool),
        required("ports", Shape::Bool),
        required("time_bucket_ms", positive()),
        required(
            "patterns",
            array(object(vec![
                required("pattern", string()),
                required("replacement", string()),
            ])),
        ),
    ])
}

fn finalization() -> Shape {
    strict(vec![
        required("requested_ms", positive()),
        required("elapsed_ms", nullable(nonnegative())),
        required("exit_code", nullable(nonnegative())),
        required(
            "signals",
            Shape::Array {
                item: Box::new(strict(vec![
                    required("signal", Shape::Enum(&["SIGTERM", "SIGKILL"])),
                    required("sent_at_ms", nonnegative()),
                    required(
                        "delivery",
                        Shape::Enum(&["signaled", "gone", "identity-changed", "unverified"]),
                    ),
                    optional("reason", nonempty_string()),
                ])),
                min: Some(1),
            },
        ),
    ])
}

fn manifest() -> Shape {
    strict(vec![
        required("rea_version", nonempty_string()),
        required("provider_version", nonempty_string()),
        required("platform", nonempty_string()),
        required("architecture", nonempty_string()),
        required("pty_backend", Shape::Literal("node-pty")),
        required("started_at", datetime()),
        required("completed_at", datetime()),
        required("scenario", Shape::Record),
        required("comparison_contract", Shape::Record),
        required("full_scenario_sha256", sha256()),
        required("comparison_contract_sha256", sha256()),
        required("selected_executable_sha256", nullable(sha256())),
        required("executable_sha256", nullable(sha256())),
        required(
            "executable_identity",
            strict(vec![
                required(
                    "state",
                    Shape::Enum(&["path_metadata_unchanged", "unknown"]),
                ),
                required("reason", nullable(string())),
            ]),
        ),
        required("normalization_sha256", sha256()),
    ])
}

/// The exact serialized capture shape.
pub fn capture() -> Shape {
    strict(vec![
        required("manifest", manifest()),
        required("normalization", normalization()),
        required(
            "frames",
            array(object(vec![
                required("sequence", nonnegative()),
                required("at_ms", nonnegative()),
                required("data", string()),
                optional("raw_data", string()),
            ])),
        ),
        required(
            "rendered_frames",
            array(object(vec![
                required("sequence", nonnegative()),
                required("at_ms", nonnegative()),
                required("columns", positive()),
                required("rows", positive()),
                required("cursor_x", nonnegative()),
                required("cursor_y", nonnegative()),
                required("active_buffer", Shape::Enum(&["normal", "alternate"])),
                required("lines", array(string())),
                required("serialized_state", string()),
            ])),
        ),
        required(
            "interaction_events",
            array(object(vec![
                required("sequence", nonnegative()),
                required("scheduled_at_ms", nonnegative()),
                required("dispatched_at_ms", nonnegative()),
                required("type", Shape::Enum(&["input", "resize", "signal"])),
                required("data", string()),
                required(
                    "outcome",
                    Shape::Enum(&["dispatched", "target_exited", "failed"]),
                ),
            ])),
        ),
        required(
            "exit",
            object(vec![
                required("code", nullable(integer())),
                required("signal", nullable(integer())),
                required(
                    "reason",
                    Shape::Enum(&["exited", "timeout", "idle_timeout"]),
                ),
                optional("finalization", finalization()),
            ]),
        ),
        required(
            "settlement",
            Shape::Union {
                key: "state",
                branches: vec![
                    (
                        &["quiesced"],
                        object(vec![
                            required("state", Shape::Literal("quiesced")),
                            required("elapsed_ms", nonnegative()),
                            required("cleanup_outcome", Shape::Literal("not_required")),
                        ]),
                    ),
                    (
                        &["alive_at_deadline", "unverifiable"],
                        object(vec![
                            required("state", Shape::Enum(&["alive_at_deadline", "unverifiable"])),
                            required("elapsed_ms", nonnegative()),
                            required("cleanup_outcome", Shape::Enum(&["cleaned", "failed"])),
                        ]),
                    ),
                ],
            },
        ),
        required(
            "process_samples",
            array(object(vec![
                required("at_ms", nonnegative()),
                required("pid", positive()),
                required("parent_pid", nonnegative()),
                required("command", string()),
                required("process_group_id", nullable(positive())),
                required("session_id", nullable(nonnegative())),
            ])),
        ),
        required(
            "filesystem_checkpoints",
            array(object(vec![
                required("name", Shape::Enum(&["before", "after_settlement"])),
                required("at_ms", nonnegative()),
                required("files", array(file_state())),
                required("effects", array(file_effect())),
                required("truncated", Shape::Bool),
            ])),
        ),
        required(
            "event_journal",
            array(object(vec![
                required("capture_order", nonnegative()),
                required("collection", Shape::Enum(EVENT_COLLECTIONS)),
                required("index", nonnegative()),
            ])),
        ),
        required("files_before", array(file_state())),
        required("files_after", array(file_state())),
        required("filesystem_effects", array(file_effect())),
        required("truncated", Shape::Bool),
        required("truncation_details", truncation_details()),
        required("limitations", array(string())),
        required(
            "residual_unknowns",
            array(object(vec![
                required(
                    "scope",
                    Shape::Enum(&[
                        "terminal",
                        "interaction",
                        "exit",
                        "process",
                        "filesystem",
                        "cleanup",
                        "network",
                        "environment",
                    ]),
                ),
                required("reason", string()),
            ])),
        ),
        required(
            "cleanup",
            object(vec![
                required("owned_process_group", Shape::Literal("verified")),
                required("temporary_root", Shape::Literal("removed")),
                optional(
                    "unverified_processes",
                    array(strict(vec![
                        required("pid", positive()),
                        required("reason", string()),
                    ])),
                ),
            ]),
        ),
    ])
}
