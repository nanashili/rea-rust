//! One owned native UI helper runtime per observation/scenario.
//!
//! Compatibility owners: `src/native/NativeUiHelperRuntime.ts`
//! (`createNativeUiHelperRuntime`), `src/process/PrivateRuntimeRoot.ts`
//! (`mkdtemp`/`rm`) and `src/process/snapshotEnvironment.ts`.
//!
//! Each runtime lazily compiles one Swift helper into a private `mkdtemp`
//! root, keeps swiftc's intermediate objects inside that removable root, runs
//! the helper from there, and removes the root on close. A removal failure
//! stays retryable and keeps the owner reachable, exactly like the TypeScript
//! `AnalysisCleanupLease`.
//!
//! Deviation from TypeScript: the release binary is not inside the repository,
//! so both Swift sources are embedded with `include_bytes!` and written into
//! the private root (`main.swift` and `NativeUIChildren.swift`) instead of
//! symlinking `main.swift` to a repo path. The compile argv, `TMPDIR`
//! override, timeouts and stop signals are otherwise identical.
use super::budget::NATIVE_UI_HELPER_MAX_BUFFER;
use super::exec::{ExecFailure, ExecFailureCode, ExecOptions, exec_file_output};
use rea_core::cancellation::Cancellation;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// `../../bridge/native/ReaNativeUI.swift` (compiled as `main.swift`).
const REA_NATIVE_UI_SWIFT: &[u8] =
    include_bytes!("../../../../../../bridge/native/ReaNativeUI.swift");
/// `../../bridge/native/NativeUIChildren.swift`.
const NATIVE_UI_CHILDREN_SWIFT: &[u8] =
    include_bytes!("../../../../../../bridge/native/NativeUIChildren.swift");

/// A failure observed while compiling or invoking the Swift helper.
#[derive(Debug)]
pub enum HelperError {
    /// The caller or the owned 180 s deadline aborted the work.
    Cancelled,
    /// The compile or helper exceeded its own timeout.
    Timeout,
    /// The helper could not be prepared or produced malformed output.
    Adapter { reason: String },
}

/// Lazily compiled, owned native UI helper runtime.
#[derive(Debug)]
pub struct NativeUiHelperRuntime {
    environment: HashMap<String, String>,
    inner: Mutex<RuntimeState>,
}

#[derive(Debug, Default)]
struct RuntimeState {
    /// The private `mkdtemp` root, once created.
    root: Option<String>,
    /// The compiled helper executable path, once prepared.
    executable: Option<String>,
    /// Whether the root has already been removed.
    closed: bool,
}

impl NativeUiHelperRuntime {
    /// `createNativeUiHelperRuntime(environment)`: snapshot the selected
    /// environment; the deadline and private root are established lazily.
    pub fn new(environment: HashMap<String, String>) -> Self {
        Self {
            environment,
            inner: Mutex::new(RuntimeState::default()),
        }
    }

    /// `resources()`: the private root while it exists.
    pub fn resources(&self) -> Vec<String> {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match &state.root {
            Some(root) if !state.closed => vec![root.clone()],
            _ => Vec::new(),
        }
    }

    /// Whether cleanup has already released this runtime (`cleanupLease.released`).
    pub fn released(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .closed
    }

    /// `invoke(parameters, signal)`: compile on first use, then run the helper
    /// with the scenario byte budget and SIGTERM stop signal. The returned
    /// value is the parsed JSON helper response.
    pub fn invoke(
        &self,
        parameters: &Value,
        cancellation: &Cancellation,
    ) -> Result<Value, HelperError> {
        let executable = self.prepare(cancellation)?;
        let request = serde_json::to_string(parameters).map_err(|error| HelperError::Adapter {
            reason: error.to_string(),
        })?;
        let options = ExecOptions {
            timeout: Duration::from_millis(30_000),
            max_buffer: NATIVE_UI_HELPER_MAX_BUFFER,
            stop_signal: libc::SIGTERM,
            environment: &self.environment,
            cwd: None,
        };
        let output =
            exec_file_output(&executable, &[request], &options, cancellation).map_err(classify)?;
        serde_json::from_str::<Value>(&output.stdout).map_err(|error| HelperError::Adapter {
            reason: format!("Native helper returned invalid JSON: {error}"),
        })
    }

    /// Compile the helper into the private root exactly once.
    fn prepare(&self, cancellation: &Cancellation) -> Result<String, HelperError> {
        {
            let state = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(executable) = &state.executable {
                return Ok(executable.clone());
            }
        }
        let (root, executable) = self.compile(cancellation)?;
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Another serialized caller may have compiled while this one worked;
        // operations are serialized per session, so this is defensive only.
        if let Some(existing) = &state.executable {
            // Remove the just-compiled duplicate root.
            let _ = std::fs::remove_dir_all(&root);
            return Ok(existing.clone());
        }
        state.root = Some(root);
        state.executable = Some(executable.clone());
        Ok(executable)
    }

    /// `prepare(signal)`: `mkdtemp`, embed both Swift sources and compile.
    fn compile(&self, cancellation: &Cancellation) -> Result<(String, String), HelperError> {
        let parent = tmpdir(&self.environment);
        let root = tempfile::Builder::new()
            .prefix("rea-native-ui-")
            .rand_bytes(6)
            .tempdir_in(&parent)
            .map_err(|error| HelperError::Adapter {
                reason: error.to_string(),
            })?
            .keep()
            .to_string_lossy()
            .into_owned();
        let output = join(&root, "observer");
        let main = join(&root, "main.swift");
        let children = join(&root, "NativeUIChildren.swift");
        let compiler_temporary = join(&root, "tmp");
        let write = |path: &str, bytes: &[u8]| -> Result<(), HelperError> {
            std::fs::write(path, bytes).map_err(|error| HelperError::Adapter {
                reason: error.to_string(),
            })
        };
        if let Err(error) = (|| {
            write(&main, REA_NATIVE_UI_SWIFT)?;
            write(&children, NATIVE_UI_CHILDREN_SWIFT)?;
            std::fs::create_dir(&compiler_temporary).map_err(|error| HelperError::Adapter {
                reason: error.to_string(),
            })
        })() {
            let _ = std::fs::remove_dir_all(&root);
            return Err(error);
        }

        // Keep swiftc's intermediate objects inside the removable root.
        let mut environment = self.environment.clone();
        environment.insert("TMPDIR".to_owned(), compiler_temporary.clone());
        let arguments = vec![
            "swiftc".to_owned(),
            "-module-cache-path".to_owned(),
            join(&root, "modules"),
            children.clone(),
            main.clone(),
            "-o".to_owned(),
            output.clone(),
        ];
        let options = ExecOptions {
            timeout: Duration::from_millis(60_000),
            max_buffer: 1024 * 1024,
            // `SWIFTC_INTERRUPT` in `DarwinProcessRunTokenReader.ts`.
            stop_signal: libc::SIGINT,
            environment: &environment,
            cwd: None,
        };
        match exec_file_output("/usr/bin/xcrun", &arguments, &options, cancellation) {
            Ok(_) => Ok((root, output)),
            Err(failure) => {
                let _ = std::fs::remove_dir_all(&root);
                Err(classify(failure))
            }
        }
    }

    /// `close()`: remove the private root; a removal failure stays retryable.
    pub fn close(&self) -> Result<(), String> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closed {
            return Ok(());
        }
        let Some(root) = state.root.clone() else {
            state.closed = true;
            return Ok(());
        };
        match std::fs::remove_dir_all(&root) {
            Ok(()) => {
                state.closed = true;
                state.executable = None;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                state.closed = true;
                state.executable = None;
                Ok(())
            }
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Map an `exec_file_output` failure to the native-UI helper failure classes.
fn classify(failure: ExecFailure) -> HelperError {
    match failure.code {
        ExecFailureCode::Cancelled => HelperError::Cancelled,
        ExecFailureCode::Timeout => HelperError::Timeout,
        ExecFailureCode::OutputLimit | ExecFailureCode::Spawn | ExecFailureCode::Process => {
            HelperError::Adapter {
                reason: failure.message,
            }
        }
    }
}

/// `os.tmpdir()` from the selected environment (`snapshotEnvironment`).
fn tmpdir(environment: &HashMap<String, String>) -> String {
    let lookup = |key: &str| {
        environment
            .get(key)
            .filter(|value| !value.is_empty())
            .cloned()
    };
    let mut path = lookup("TMPDIR")
        .or_else(|| lookup("TMP"))
        .or_else(|| lookup("TEMP"))
        .unwrap_or_else(|| "/tmp".to_owned());
    if path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    path
}

/// `path.join(directory, name)` for single-segment joins.
fn join(directory: &str, name: &str) -> String {
    if directory.ends_with('/') {
        format!("{directory}{name}")
    } else {
        format!("{directory}/{name}")
    }
}
