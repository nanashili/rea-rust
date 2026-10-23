//! Bounded Linux resource-limit policy for owned child process launches.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxResourceLimits {
    pub address_space_bytes: u64,
    pub file_bytes: u64,
    pub cpu_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceLimitError {
    MissingOrAmbiguousRow(&'static str),
    MalformedRow(&'static str),
    InvalidValue(&'static str),
}

impl std::fmt::Display for ResourceLimitError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingOrAmbiguousRow(row) => {
                write!(output, "missing or ambiguous inherited limit: {row}")
            }
            Self::MalformedRow(row) => write!(output, "malformed inherited limit: {row}"),
            Self::InvalidValue(row) => write!(output, "invalid inherited limit value: {row}"),
        }
    }
}

impl std::error::Error for ResourceLimitError {}

/// Clamp configured limits to both inherited soft and hard ceilings.
pub fn clamp_linux_resource_limits(
    configured: LinuxResourceLimits,
    report: &str,
) -> Result<LinuxResourceLimits, ResourceLimitError> {
    Ok(LinuxResourceLimits {
        address_space_bytes: clamp_one(
            configured.address_space_bytes,
            "Max address space",
            report,
        )?,
        file_bytes: clamp_one(configured.file_bytes, "Max file size", report)?,
        cpu_seconds: clamp_one(configured.cpu_seconds, "Max cpu time", report)?,
    })
}

fn clamp_one(configured: u64, row: &'static str, report: &str) -> Result<u64, ResourceLimitError> {
    let matches: Vec<_> = report
        .lines()
        .filter(|line| line.starts_with(&format!("{row} ")))
        .collect();
    if matches.len() != 1 {
        return Err(ResourceLimitError::MissingOrAmbiguousRow(row));
    }
    let values: Vec<_> = matches[0][row.len()..].split_whitespace().collect();
    if values.len() != 3 {
        return Err(ResourceLimitError::MalformedRow(row));
    }
    let mut ceiling = configured;
    for value in values.iter().take(2) {
        if *value == "unlimited" {
            continue;
        }
        let parsed = value
            .parse::<u64>()
            .map_err(|_| ResourceLimitError::InvalidValue(row))?;
        ceiling = ceiling.min(parsed);
    }
    Ok(ceiling)
}

/// Construct a bounded `prlimit` argument vector without changing the command.
pub fn prlimit_argument_vector(limits: LinuxResourceLimits, command: &str) -> Vec<String> {
    vec![
        format!(
            "--as={}:{}",
            limits.address_space_bytes, limits.address_space_bytes
        ),
        format!("--fsize={}:{}", limits.file_bytes, limits.file_bytes),
        format!("--cpu={}:{}", limits.cpu_seconds, limits.cpu_seconds),
        "--core=0:0".into(),
        "--".into(),
        command.into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str =
        "Max address space 100 200 bytes\nMax file size 300 400 bytes\nMax cpu time 5 6 seconds\n";

    #[test]
    fn clamps_soft_and_hard_limits() {
        let limits = clamp_linux_resource_limits(
            LinuxResourceLimits {
                address_space_bytes: 1_000,
                file_bytes: 1_000,
                cpu_seconds: 10,
            },
            REPORT,
        )
        .unwrap();
        assert_eq!(
            limits,
            LinuxResourceLimits {
                address_space_bytes: 100,
                file_bytes: 300,
                cpu_seconds: 5
            }
        );
    }

    #[test]
    fn unlimited_preserves_configured_limit() {
        let report = "Max address space unlimited unlimited bytes\nMax file size unlimited unlimited bytes\nMax cpu time unlimited unlimited seconds\n";
        let configured = LinuxResourceLimits {
            address_space_bytes: 9,
            file_bytes: 8,
            cpu_seconds: 7,
        };
        assert_eq!(
            clamp_linux_resource_limits(configured, report),
            Ok(configured)
        );
    }

    #[test]
    fn partial_setup_failure_is_explicit() {
        let error = clamp_linux_resource_limits(
            LinuxResourceLimits {
                address_space_bytes: 1,
                file_bytes: 1,
                cpu_seconds: 1,
            },
            "Max address space 1 1 bytes\n",
        )
        .unwrap_err();
        assert_eq!(
            error,
            ResourceLimitError::MissingOrAmbiguousRow("Max file size")
        );
    }

    #[test]
    fn argument_vector_pins_both_ceilings() {
        let args = prlimit_argument_vector(
            LinuxResourceLimits {
                address_space_bytes: 1,
                file_bytes: 2,
                cpu_seconds: 3,
            },
            "worker",
        );
        assert_eq!(args[0], "--as=1:1");
        assert_eq!(args[3], "--core=0:0");
        assert_eq!(args[5], "worker");
    }
}
