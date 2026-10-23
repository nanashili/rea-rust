//! Count escaped JSON before allocating its serialized representation.
use serde::Serialize;
use std::{
    fmt,
    io::{self, Write},
};

/// Serialization failure distinct from a representation budget refusal.
#[derive(Debug)]
pub enum Error<E = serde_json::Error> {
    /// The exact JSON encoding exceeds its admitted maximum.
    Limit {
        /// Maximum permitted serialized bytes.
        maximum: usize,
    },
    /// A serializer failed independently of the budget.
    Encoding(E),
}
impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit { maximum } => write!(f, "JSON output exceeds {maximum} bytes"),
            Self::Encoding(error) => error.fmt(f),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(error) => Some(error),
            _ => None,
        }
    }
}
struct Counter {
    remaining: usize,
    exceeded: bool,
}
impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(remaining) = self.remaining.checked_sub(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("JSON output limit"));
        };
        self.remaining = remaining;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
/// Return the exact serialized size without retaining a second JSON buffer.
///
/// # Errors
/// Distinguishes output capacity from an unrelated encoder failure.
pub fn admitted_length<T: Serialize>(value: &T, maximum: usize) -> Result<usize, Error> {
    admitted_encoding_length(maximum, |writer| serde_json::to_writer(writer, value))
}

/// Count a complete streaming representation, including transport envelopes and
/// repeated escaping, before allocating or delivering its encoded buffer.
///
/// # Errors
/// Distinguishes the shared byte budget from the encoder's original error type.
pub fn admitted_encoding_length<E>(
    maximum: usize,
    encode: impl FnOnce(&mut dyn Write) -> Result<(), E>,
) -> Result<usize, Error<E>> {
    let mut counter = Counter {
        remaining: maximum,
        exceeded: false,
    };
    let encoded = encode(&mut counter);
    if counter.exceeded {
        return Err(Error::Limit { maximum });
    }
    encoded.map_err(Error::Encoding)?;
    Ok(maximum - counter.remaining)
}
