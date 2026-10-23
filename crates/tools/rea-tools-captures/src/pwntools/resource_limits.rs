//! Bounded owned failure-evidence reads: limit reports and reserved markers.
//!
//! Compatibility owner: `src/native/pwntools/PwntoolsResourceLimits.ts`. A
//! bare launcher exit code is insufficient; only bounded owned reports under
//! the private root establish a resource classification.
use crate::artifact;
use crate::node;
use crate::process::CommandFailure;
use crate::pwntools::release;
use serde_json::{Map, Value};

/// Actual limits reported by the bridge after lowering inherited soft limits.
pub fn parse_limits(text: &str) -> Option<Value> {
    let value: Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    // z.strictObject: exactly the three declared keys, each a bounded nonneg int.
    if object.len() != 3 {
        return None;
    }
    let field = |key: &str, maximum: u64| -> Option<u64> {
        let number = object.get(key)?.as_u64()?;
        (number <= maximum).then_some(number)
    };
    let address_space_bytes = field("address_space_bytes", release::ADDRESS_SPACE_BYTES)?;
    let cpu_seconds = field("cpu_seconds", release::CPU_SECONDS)?;
    let file_size_bytes = field("file_size_bytes", release::OUTPUT_BYTES)?;
    // Preserve the schema declaration order.
    let mut ordered = Map::new();
    ordered.insert(
        "address_space_bytes".into(),
        Value::from(address_space_bytes),
    );
    ordered.insert("cpu_seconds".into(), Value::from(cpu_seconds));
    ordered.insert("file_size_bytes".into(), Value::from(file_size_bytes));
    Some(Value::Object(ordered))
}

/// A missing or invalid report leaves limits unknown and retains its read failure.
#[derive(Clone, Debug, Default)]
pub struct LimitReport {
    pub limits: Option<Value>,
    pub failure: Option<String>,
}

/// Reserved resource marker read from the private `resource.failure` file.
#[derive(Clone, Debug, Default)]
pub struct Marker {
    pub resource: Option<String>,
    pub failure: Option<String>,
}

/// Private failure-branch evidence read from the owned runtime root.
#[derive(Clone, Debug, Default)]
pub struct FailureEvidence {
    pub limits: Option<LimitReport>,
    pub marker: Option<Marker>,
}

/// Read only bounded owned reports (`readPwntoolsFailureEvidence`). Unverified
/// reserved statuses stay unclassified.
pub fn read_failure_evidence(
    failure: Option<&CommandFailure>,
    root_path: Option<&str>,
) -> FailureEvidence {
    let mut evidence = FailureEvidence::default();
    let (snapshot, root) = match (failure, root_path) {
        (Some(failure), Some(root)) => match failure.snapshot.as_ref() {
            Some(snapshot) => (snapshot, root),
            None => return evidence,
        },
        _ => return evidence,
    };

    let exit = snapshot.exit_code;
    let signal = snapshot.signal.as_deref();

    // Reserved marker: process ended with the exact reserved exit and no signal.
    if signal.is_none()
        && (exit == Some(release::MEMORY_FAILURE_EXIT)
            || exit == Some(release::FILE_SIZE_FAILURE_EXIT))
    {
        evidence.marker = Some(read_marker(
            root,
            exit == Some(release::MEMORY_FAILURE_EXIT),
        ));
    }

    // Limit report: SIGXCPU/SIGXFSZ or a reserved exit without signal.
    let limit_applies = matches!(signal, Some("SIGXCPU") | Some("SIGXFSZ"))
        || (signal.is_none()
            && (exit == Some(release::FILE_SIZE_FAILURE_EXIT)
                || exit == Some(release::MEMORY_FAILURE_EXIT)));
    if limit_applies {
        evidence.limits = Some(read_limits(root));
    }
    evidence
}

fn read_marker(root: &str, memory: bool) -> Marker {
    let path = node::join(root, "resource.failure");
    match artifact::read_stable_uncancelled(&path, 1) {
        Ok(snapshot) => {
            let expected: &[u8] = if memory { b"M" } else { b"F" };
            if snapshot.bytes == expected {
                Marker {
                    resource: Some(if memory {
                        "memory".into()
                    } else {
                        "file-size".into()
                    }),
                    failure: None,
                }
            } else {
                Marker {
                    resource: None,
                    failure: Some(
                        "Private bridge failure marker does not match the observed exit status."
                            .into(),
                    ),
                }
            }
        }
        Err(error) => Marker {
            resource: None,
            failure: Some(error.message()),
        },
    }
}

fn read_limits(root: &str) -> LimitReport {
    let path = node::join(root, "limits.json");
    match artifact::read_stable_uncancelled(&path, 4096) {
        Ok(snapshot) => match std::str::from_utf8(&snapshot.bytes)
            .ok()
            .and_then(parse_limits)
        {
            Some(limits) => LimitReport {
                limits: Some(limits),
                failure: None,
            },
            None => LimitReport {
                limits: None,
                failure: Some("Owned resource limit report is invalid.".into()),
            },
        },
        Err(error) => LimitReport {
            limits: None,
            failure: Some(error.message()),
        },
    }
}
