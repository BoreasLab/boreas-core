//! Status values returned by every entry point and the shared boundary guard.

use std::panic::{AssertUnwindSafe, catch_unwind};

use boreas_core::api::{ConfigError, StartError};

/// Result of one call across the C boundary.
///
/// `Ok` is zero, so `if (boreas_tunnel_start(...))` tests for failure.
/// [`Self::Unrecognised`] preserves forward compatibility with the core's
/// `#[non_exhaustive]` error sums.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Status {
    /// The call succeeded; any out-parameter was written.
    Ok = 0,
    /// A required pointer was null.
    NullArgument = 1,
    /// A string argument was not valid UTF-8.
    NotUtf8 = 2,
    /// The configuration cannot describe a valid tunnel. Nothing was built.
    Config = 3,
    /// Stored certificate authority material is missing, corrupt, or mismatched.
    /// Generate it again and ask the user to trust the new root.
    Authority = 4,
    /// An egress could not be built from its configuration.
    Egress = 5,
    /// The connection ceiling cannot cover every inspected port. Raise it.
    Termination = 6,
    /// The datapath rejected the supplied configuration.
    Datapath = 7,
    /// A required socket could not be opened through the bypass.
    Io = 8,
    /// The tunnel has stopped. Its handle remains valid to free.
    Stopped = 9,
    /// An output buffer was too small. No bytes past its end were written; the
    /// out-parameter carries the required length.
    BufferTooSmall = 10,
    /// A panic was caught at this boundary, indicating a Boreas defect.
    /// The handle may be in a partial state; free it and do not reuse it.
    Panic = 11,
    /// A failure variant this ABI predates. The core's error sum is
    /// `#[non_exhaustive]`, so an older shim cannot name every failure.
    Unrecognised = 12,
}

impl From<StartError> for Status {
    fn from(error: StartError) -> Self {
        match error {
            StartError::Config(_) => Self::Config,
            StartError::Authority(_) => Self::Authority,
            StartError::Egress(_) => Self::Egress,
            StartError::Datapath(_) => Self::Datapath,
            StartError::Io(_) => Self::Io,
            StartError::Termination(_) => Self::Termination,
            _ => Self::Unrecognised,
        }
    }
}

impl From<ConfigError> for Status {
    fn from(_: ConfigError) -> Self {
        Self::Config
    }
}

/// Converts a Rust panic into [`Status::Panic`] at the C boundary.
///
/// A panic reaching an `extern "C"` frame aborts the process, so every entry
/// point uses this guard. `AssertUnwindSafe` is valid because a handle that
/// reports [`Status::Panic`] may only be freed.
pub fn boundary<F: FnOnce() -> Status>(work: F) -> Status {
    catch_unwind(AssertUnwindSafe(work)).unwrap_or(Status::Panic)
}

/// Borrows a `*const T`, or returns [`Status::NullArgument`].
///
/// # Safety
///
/// `pointer`, when non-null, must be aligned and point at a live, initialised
/// `T` for the duration of the call.
macro_rules! borrow {
    ($pointer:expr) => {
        match unsafe { $pointer.as_ref() } {
            Some(value) => value,
            None => return $crate::Status::NullArgument,
        }
    };
}

/// Mutable counterpart to [`borrow`] for out-parameters.
///
/// # Safety
///
/// As [`borrow`], and no other reference to the same `T` may be live.
macro_rules! borrow_mut {
    ($pointer:expr) => {
        match unsafe { $pointer.as_mut() } {
            Some(value) => value,
            None => return $crate::Status::NullArgument,
        }
    };
}

pub(crate) use {borrow, borrow_mut};

#[cfg(test)]
mod tests {
    use super::*;

    /// Zero is success, so `if (call(...))` reads as "if it failed".
    #[test]
    fn success_is_zero_and_nothing_else_is() {
        assert_eq!(Status::Ok as i32, 0);
        for status in [
            Status::NullArgument,
            Status::NotUtf8,
            Status::Config,
            Status::Authority,
            Status::Egress,
            Status::Termination,
            Status::Datapath,
            Status::Io,
            Status::Stopped,
            Status::BufferTooSmall,
            Status::Panic,
            Status::Unrecognised,
        ] {
            assert_ne!(status as i32, 0, "{status:?}");
        }
    }

    /// An unwind here must become a status rather than abort the host process.
    #[test]
    fn a_panic_becomes_a_status_rather_than_an_unwind() {
        assert_eq!(boundary(|| panic!("a defect")), Status::Panic);
        assert_eq!(boundary(|| Status::Ok), Status::Ok);
        // A non-string payload is also caught; formatting it would add another
        // panic point and provides no useful C-facing value.
        assert_eq!(
            boundary(|| std::panic::panic_any(7_u32)),
            Status::Panic,
            "the payload type must not matter"
        );
    }
}
