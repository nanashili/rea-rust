//! Provider-owned private runtime directories.
//!
//! Compatibility owner: `src/process/PrivateRuntimeRoot.ts`. POSIX `mkdtemp`
//! establishes owner-only access atomically; close removes the directory and
//! keeps a failed removal retryable.
use crate::node;
use std::collections::HashMap;

/// One private temporary runtime root.
#[derive(Debug)]
pub struct RuntimeRoot {
    path: String,
    closed: bool,
}

impl RuntimeRoot {
    /// `mkdtemp(join(os.tmpdir(), prefix))`.
    pub fn create(
        prefix: &str,
        environment: &HashMap<String, String>,
    ) -> Result<Self, std::io::Error> {
        let parent = node::tmpdir(environment);
        Self::create_in(&parent, prefix)
    }

    /// `mkdtemp(join(parent, prefix))`.
    pub fn create_in(parent: &str, prefix: &str) -> Result<Self, std::io::Error> {
        let directory = tempfile::Builder::new()
            .prefix(prefix)
            .rand_bytes(6)
            .tempdir_in(parent)?;
        let path = directory.keep().to_string_lossy().into_owned();
        Ok(Self {
            path,
            closed: false,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// `rm(path, { recursive: true, force: true })`; failure stays retryable.
    pub fn close(&mut self) -> Result<(), node::FsError> {
        if self.closed {
            return Ok(());
        }
        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => {
                self.closed = true;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.closed = true;
                Ok(())
            }
            Err(error) => Err(node::FsError::from_io(&error, "rm", &self.path)),
        }
    }
}

impl Drop for RuntimeRoot {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.close();
        }
    }
}
