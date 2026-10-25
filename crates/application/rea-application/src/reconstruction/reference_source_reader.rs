//! Stable, bounded reads for files admitted by reference-source traversal.
//!
//! The host directory reader owns the admitted root handle, traversal, and
//! identity checks. The application layer adds only import policy and output
//! semantics on top of those admitted entries.

use rea_core::cancellation::Cancellation;
use rea_host::fs::stable_directory;
use std::path::Path;

/// Maximum bytes retained for one historical source file.
pub const MAX_SOURCE_FILE_BYTES: usize = 64 * 1024 * 1024;

/// A handle-relative, read-only source-tree admission.
///
/// The directory reader owns the admitted root handle and exposes only
/// identity-checked entries to import code.  Keeping this wrapper here makes
/// it difficult for consumers to fall back to pathname traversal accidentally.
pub struct SourceTreeReader {
    reader: stable_directory::DirectoryReader,
}

impl SourceTreeReader {
    pub fn open(path: &Path) -> Result<Self, stable_directory::DirectoryError> {
        stable_directory::DirectoryReader::open(path).map(|reader| Self { reader })
    }

    pub fn root(&self) -> &stable_directory::DirectoryRoot {
        self.reader.root()
    }

    pub fn entries(
        &self,
        maximum_entries: usize,
        cancellation: &Cancellation,
    ) -> Result<Vec<stable_directory::DirectoryEntry>, stable_directory::DirectoryError> {
        self.reader.entries(maximum_entries, cancellation)
    }

    pub fn entries_filtered<F>(
        &self,
        maximum_entries: usize,
        cancellation: &Cancellation,
        should_descend: F,
    ) -> Result<Vec<stable_directory::DirectoryEntry>, stable_directory::DirectoryError>
    where
        F: Fn(&stable_directory::DirectoryEntry) -> bool,
    {
        self.reader
            .entries_filtered(maximum_entries, cancellation, should_descend)
    }

    pub fn read_entry_bounded(
        &self,
        entry: &stable_directory::DirectoryEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, stable_directory::DirectoryError> {
        self.reader
            .read_entry_bounded(entry, MAX_SOURCE_FILE_BYTES, cancellation)
    }

    pub fn read_entry_with_limit(
        &self,
        entry: &stable_directory::DirectoryEntry,
        maximum_bytes: usize,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, stable_directory::DirectoryError> {
        self.reader
            .read_entry_bounded(entry, maximum_bytes, cancellation)
    }

    /// Inspect one admitted relative path without following its final component.
    pub fn inspect_entry(
        &self,
        relative_path: &str,
        cancellation: &Cancellation,
    ) -> Result<Option<stable_directory::DirectoryEntry>, stable_directory::DirectoryError> {
        self.reader.inspect_entry(relative_path, cancellation)
    }

    pub fn read_symlink_target(
        &self,
        entry: &stable_directory::DirectoryEntry,
        cancellation: &Cancellation,
    ) -> Result<String, stable_directory::DirectoryError> {
        self.reader.read_symlink_target(entry, cancellation)
    }

    pub fn revalidate_entry(
        &self,
        entry: &stable_directory::DirectoryEntry,
        cancellation: &Cancellation,
    ) -> Result<(), stable_directory::DirectoryError> {
        self.reader.revalidate_entry(entry, cancellation)
    }
}
