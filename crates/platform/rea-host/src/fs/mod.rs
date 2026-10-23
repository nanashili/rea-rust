//! Filesystem ownership: stable file and directory acquisition, staged publication
//! and caller path spelling.

#[cfg(unix)]
pub mod caller_path;
pub mod stable_directory;
pub mod stable_file;
#[cfg(unix)]
pub mod staged_output;
#[cfg(unix)]
pub mod unix_file;
#[cfg(windows)]
pub mod windows_file;
