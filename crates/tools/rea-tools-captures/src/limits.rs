//! Per-process ceilings inherited by an owned Linux producer.
//!
//! Compatibility owner: `src/process/LinuxResourceLimits.ts`.
use serde_json::{Map, Value, json};
use std::io::Read;

/// Per-process ceilings applied through util-linux prlimit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxLimits {
    pub address_space_bytes: u64,
    pub file_bytes: u64,
    pub cpu_seconds: u64,
}

impl LinuxLimits {
    /// `{ address_space_bytes, file_bytes, cpu_seconds }` in declaration order.
    pub fn to_map(self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert(
            "address_space_bytes".into(),
            json!(self.address_space_bytes),
        );
        map.insert("file_bytes".into(), json!(self.file_bytes));
        map.insert("cpu_seconds".into(), json!(self.cpu_seconds));
        map
    }
}

/// Bound the resident input copy and retained text before allocation/collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProducerLimits {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub command_timeout_ms: u64,
    pub address_space_bytes: u64,
    pub file_bytes: u64,
    pub cpu_seconds: u64,
}

/// `BOUNDED_PRODUCER_LIMITS`.
pub const BOUNDED_PRODUCER_LIMITS: ProducerLimits = ProducerLimits {
    input_bytes: 32 * 1024 * 1024,
    output_bytes: 4 * 1024 * 1024,
    command_timeout_ms: 30_000,
    address_space_bytes: 1024 * 1024 * 1024,
    file_bytes: 64 * 1024 * 1024,
    cpu_seconds: 30,
};

impl ProducerLimits {
    pub fn linux(self) -> LinuxLimits {
        LinuxLimits {
            address_space_bytes: self.address_space_bytes,
            file_bytes: self.file_bytes,
            cpu_seconds: self.cpu_seconds,
        }
    }

    /// `{ ...LIMITS, ...effectiveLimits }` with the original key order.
    pub fn report(self, effective: LinuxLimits) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("input_bytes".into(), json!(self.input_bytes));
        map.insert("output_bytes".into(), json!(self.output_bytes));
        map.insert("command_timeout_ms".into(), json!(self.command_timeout_ms));
        map.insert(
            "address_space_bytes".into(),
            json!(effective.address_space_bytes),
        );
        map.insert("file_bytes".into(), json!(effective.file_bytes));
        map.insert("cpu_seconds".into(), json!(effective.cpu_seconds));
        map
    }
}

/// Pin soft and hard ceilings together, then hand the producer argv to the limiter.
pub fn prlimit_arguments(limits: LinuxLimits, command: &str) -> Vec<String> {
    vec![
        format!("--as={0}:{0}", limits.address_space_bytes),
        format!("--fsize={0}:{0}", limits.file_bytes),
        format!("--cpu={0}:{0}", limits.cpu_seconds),
        "--core=0:0".into(),
        "--".into(),
        command.to_owned(),
    ]
}

const ROWS: [&str; 3] = ["Max address space", "Max file size", "Max cpu time"];

/// Never raise either inherited soft policy or hard ceiling.
pub fn clamp(configured: LinuxLimits, report: &str) -> Result<LinuxLimits, String> {
    let values = [
        configured.address_space_bytes,
        configured.file_bytes,
        configured.cpu_seconds,
    ];
    let mut effective = values;
    for (index, row) in ROWS.iter().enumerate() {
        let prefix = format!("{row} ");
        let matches = report
            .split('\n')
            .filter(|line| line.starts_with(&prefix))
            .collect::<Vec<_>>();
        let tokens = matches
            .first()
            .map(|line| line[row.len()..].split_whitespace().collect::<Vec<_>>());
        let Some(tokens) = tokens.filter(|tokens| matches.len() == 1 && tokens.len() == 3) else {
            return Err(format!("Cannot establish inherited Linux limit: {row}"));
        };
        let mut ceiling = u128::from(values[index]);
        for token in &tokens[..2] {
            if *token == "unlimited" {
                continue;
            }
            if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("Invalid inherited Linux limit: {row}"));
            }
            let value = token.parse::<u128>().unwrap_or(u128::MAX);
            if value < ceiling {
                ceiling = value;
            }
        }
        effective[index] = ceiling as u64;
    }
    Ok(LinuxLimits {
        address_space_bytes: effective[0],
        file_bytes: effective[1],
        cpu_seconds: effective[2],
    })
}

/// Read the trusted kernel report with a fixed allocation before spawning.
pub fn read_linux_limits(configured: LinuxLimits) -> Result<LinuxLimits, String> {
    let path = "/proc/self/limits";
    let mut file = std::fs::File::open(path)
        .map_err(|error| crate::node::FsError::from_io(&error, "open", path).message)?;
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut filled = 0;
    // A single positional read at offset zero, as the original owner.
    loop {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => {
                filled += count;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(crate::node::FsError::from_io(&error, "read", path).message);
            }
        }
    }
    if filled == buffer.len() {
        return Err("Inherited Linux limits exceed the report budget.".into());
    }
    clamp(configured, &String::from_utf8_lossy(&buffer[..filled]))
}
