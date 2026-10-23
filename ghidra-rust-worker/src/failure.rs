use std::fmt::{self, Display, Formatter};

use anyhow::Error;

#[derive(Debug)]
struct CacheIntegrityFailure;

impl Display for CacheIntegrityFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "saved cache integrity failed; preserve this cache and do not retry automatically; repair it or configure a new empty cache directory",
        )
    }
}

pub fn cache_integrity(error: impl Into<Error>) -> Error {
    let error = error.into();
    if error.is::<CacheIntegrityFailure>() {
        error
    } else {
        error.context(CacheIntegrityFailure)
    }
}

pub fn code(error: &Error) -> &'static str {
    if error.is::<CacheIntegrityFailure>() {
        "CACHE_INTEGRITY_FAILED"
    } else {
        "WORKER_FAILED"
    }
}
