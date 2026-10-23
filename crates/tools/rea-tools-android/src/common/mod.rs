//! Shared native mechanics for the Android-family providers: environment
//! snapshot facts, owned processes, stable files, target admission, private
//! workspaces, serialized turns and error composition.
pub mod env;
pub mod errors;
pub mod evidence;
pub mod files;
pub mod ids;
pub mod process;
pub mod target;
pub mod turnstile;
#[cfg(windows)]
mod windows_private;
pub mod workspace;
pub mod zip;
