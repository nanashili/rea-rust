//! Establish the enforced native capture memory boundary.
//!
//! Compatibility owner: `src/pcap/PcapNativeBound.ts`. Linux uses util-linux
//! prlimit with inherited-ceiling clamping; Windows uses an owned Job Object
//! committed-memory limit; other hosts are unsupported with the exact message.
use crate::errors;
use crate::limits::{self, LinuxLimits};
use crate::node::{self, AccessMode};
use rea_core::analysis_error::AnalysisError;
use std::collections::HashMap;

const OPERATION: &str = "inspect_pcap_capture";
const PRLIMIT_COMMAND_ENV: &str = "REA_TSHARK_PRLIMIT_COMMAND";

/// Limiter wrapping for a bounded capture command.
#[derive(Clone, Debug, Default)]
pub struct NativeBound {
    /// POSIX limiter command and its leading argv; `None` on Windows.
    pub limiter: Option<(String, Vec<String>)>,
    /// Windows Job Object committed-memory limit in bytes; `None` on POSIX.
    pub memory_limit_bytes: Option<u64>,
}

/// Prepared native bound and its exact limitation wording.
pub struct Prepared {
    pub native_bound: NativeBound,
    pub limitations: Vec<String>,
}

/// `preparePcapNativeBound`.
pub fn prepare(environment: &HashMap<String, String>) -> Result<Prepared, AnalysisError> {
    if cfg!(windows) {
        return Ok(Prepared {
            native_bound: NativeBound {
                limiter: None,
                memory_limit_bytes: Some(1024 * 1024 * 1024),
            },
            limitations: vec![
                "Each owned Windows tool tree has a 1 GiB Job Object committed-memory limit; this is not a machine-wide quota.".into(),
            ],
        });
    }
    if !cfg!(target_os = "linux") {
        let reason = "Packet summaries require an enforceable native memory bound: Linux with util-linux prlimit, or Windows with owned Job Objects. This host's capture boundary remains unsupported.";
        return Err(errors::capability(
            "pcap",
            OPERATION,
            reason,
            Some(reason.to_owned()),
        ));
    }

    let configured = environment
        .get(PRLIMIT_COMMAND_ENV)
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| "/usr/bin/prlimit".to_owned());

    let prepare_result = (|| -> Result<Prepared, PrepareError> {
        if !node::is_absolute(&configured) {
            return Err(PrepareError::Plain(format!(
                "{PRLIMIT_COMMAND_ENV} must be absolute."
            )));
        }
        let limiter =
            node::realpath(&configured).map_err(|error| PrepareError::Plain(error.message))?;
        node::access(&limiter, AccessMode::Execute)
            .map_err(|error| PrepareError::Plain(error.message))?;
        let configured_limits = LinuxLimits {
            address_space_bytes: 1024 * 1024 * 1024,
            file_bytes: 64 * 1024 * 1024,
            cpu_seconds: 300,
        };
        let limits = limits::read_linux_limits(configured_limits).map_err(PrepareError::Plain)?;
        let arguments = vec![
            format!("--as={0}:{0}", limits.address_space_bytes),
            format!("--fsize={0}:{0}", limits.file_bytes),
            format!("--cpu={0}:{0}", limits.cpu_seconds),
            "--core=0:0".into(),
            "--".into(),
        ];
        let limitations = vec![format!(
            "Linux prlimit preserves stricter inherited ceilings: {} bytes of per-process address space, {} bytes per file and {} CPU seconds; core dumps are disabled. These are not aggregate machine quotas.",
            limits.address_space_bytes, limits.file_bytes, limits.cpu_seconds
        )];
        Ok(Prepared {
            native_bound: NativeBound {
                limiter: Some((limiter, arguments)),
                memory_limit_bytes: None,
            },
            limitations,
        })
    })();

    prepare_result.map_err(|error| match error {
        PrepareError::Plain(detail) => {
            let reason = "Cannot establish the selected Linux resource limiter before processing capture bytes.";
            errors::capability(
                "pcap",
                OPERATION,
                reason,
                Some(format!(
                    "{reason} ({detail}) Check that {PRLIMIT_COMMAND_ENV} (default /usr/bin/prlimit) names an absolute, executable util-linux prlimit."
                )),
            )
        }
    })
}

enum PrepareError {
    Plain(String),
}
