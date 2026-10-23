//! Private provider-owned runtime directories.
//!
//! Compatibility owners: `src/process/PrivateRuntimeRoot.ts` and
//! `src/android/JadxWorkspaceRoot.ts`. POSIX roots are created atomically
//! with owner-only mode (as `mkdtemp`); Windows roots are created with a
//! protected owner-only DACL installed at creation (see `windows_private`).
//! The owning REA process removes the root; a failed removal keeps the
//! owner so a later close retries it.
use std::io;
use std::path::{Path, PathBuf};

use super::ids;

/// One private runtime root and its idempotent removal.
#[derive(Debug)]
pub struct PrivateRoot {
    path: PathBuf,
    removed: bool,
}

impl PrivateRoot {
    /// Allocate a new private directory `<parent>/<prefix><random>`.
    pub fn create(parent: &Path, prefix: &str) -> io::Result<Self> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            #[cfg(unix)]
            let name = format!("{prefix}{}", ids::random_hex(3));
            #[cfg(windows)]
            let name = format!("{prefix}{}", ids::random_hex(16));
            let path = parent.join(name);
            match create_private_directory(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        removed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists && attempts < 16 => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the root recursively. A failed attempt is not cached, so a later
    /// call retries the removal.
    pub fn close(&mut self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.removed = true;
        Ok(())
    }

    pub fn is_removed(&self) -> bool {
        self.removed
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        // Owners close explicitly and keep failed roots; this only covers an
        // owner discarded by an unexpected unwind.
        if !self.removed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(windows)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    super::windows_private::create_private_directory(path)
}
