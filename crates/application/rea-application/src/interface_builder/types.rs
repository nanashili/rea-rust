//! Platform-neutral limits for Interface Builder bundle inspection inputs.

use serde::Serialize;

pub const MAX_DOCUMENTS: usize = 64;
pub const MAX_OBJECTS: usize = 20_000;
pub const MAX_CONNECTIONS: usize = 40_000;

/// Caller-selected graph bounds for one compiled Interface Builder inspection.
#[derive(Clone, Debug, Serialize)]
pub struct InterfaceBuilderLimits {
    pub max_documents: usize,
    pub max_objects: usize,
    pub max_connections: usize,
}

impl Default for InterfaceBuilderLimits {
    fn default() -> Self {
        Self {
            max_documents: MAX_DOCUMENTS,
            max_objects: MAX_OBJECTS,
            max_connections: MAX_CONNECTIONS,
        }
    }
}
