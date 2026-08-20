//! What every entry point returns, and the one combinator they are written in.

use std::panic::{AssertUnwindSafe, catch_unwind};

use boreas_core::api::{ConfigError, StartError};

/// The result of one call across the boundary.
///
/// **`Ok` is zero**, so the C idiom `if (boreas_tunnel_start(...)) { … }`
/// tests for failure. Every other variant names something the host can act on
/// — except [`Self::Unrecognised`], which exists because the core's own error
/// sum is `#[non_exhaustive]` and this ABI has to keep compiling against a
/// core that grew a variant it predates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Status {
    /// The call succeeded and any out-parameter has been written.
    Ok = 0,
    /// A required pointer was null. Always a bug in the caller.
    NullArgument = 1,
    /// A string argument was not valid UTF-8.
    NotUtf8 = 2,
    /// The configuration describes a tunnel that cannot exist. Nothing was
    /// built and nothing needs cleaning up.
    Config = 3,
    /// The certificate authority could not be opened: stored material was lost,
    /// corrupted, or is not two halves of one authority. Generate afresh and
    /// ask the user to trust the new root.
    Authority = 4,
    /// An egress could not be built from its configuration.
    Egress = 5,
    /// The local terminator cannot serve every inspected port under the
    /// connection ceiling it was given. Raise it.
    Termination = 6,
    /// The datapath refused the combination it was handed.
    Datapath = 7,
    /// A socket the tunnel needs could not be opened through the bypass.
    Io = 8,
    /// The tunnel has stopped. Its handle is still valid to free, and every
    /// other call on it will keep answering this.
    Stopped = 9,
    /// An output buffer was too small. Nothing was written past its end; the
    /// out-parameter carries the length that would have been needed.
    BufferTooSmall = 10,
    /// **A panic was caught at this boundary.** Always a defect in Boreas: no
    /// input is supposed to be able to produce one. The tunnel's state is
    /// whatever the failed call left, so treat the handle as unusable, free it,
    /// and report this.
    Panic = 11,
    /// A failure this ABI predates. The core's error sum is
    /// `#[non_exhaustive]`, so a shim older than the core it links can meet a
    /// variant it has no name for; saying so is better than mapping it onto a
    /// neighbour and sending the host after the wrong cause.
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

/// The only way a C caller enters this crate.
///
/// **Catching is not defensive programming here; it is the difference between
/// a failed call and a dead application.** A panic that reaches an
/// `extern "C"` frame aborts the process. Since Rust 1.81 that abort is
/// defined behaviour rather than undefined, which makes it predictable and no
/// less fatal: the host is a phone application whose VPN is one feature, and a
/// malformed packet must not be able to close it.
///
/// `AssertUnwindSafe` is honest rather than convenient. What it asserts is that
/// observing state left behind by a panic is acceptable — and it is, because
/// the only thing the caller may do with a [`Status::Panic`] handle is free it.
/// That is written into the variant's own documentation, which is what makes
/// the assertion a contract rather than a wish.
pub fn boundary<F: FnOnce() -> Status>(work: F) -> Status {
    catch_unwind(AssertUnwindSafe(work)).unwrap_or(Status::Panic)
}

/// Borrows a `*const T` as a reference, or answers [`Status::NullArgument`].
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

/// The mutable half of [`borrow`], for out-parameters.
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

    /// The C idiom this enum is shaped for: zero is success, so
    /// `if (call(...))` reads as "if it failed".
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

    /// **The property the whole boundary rests on.** An unwind that escaped
    /// here would abort the host's application rather than fail one call.
    #[test]
    fn a_panic_becomes_a_status_rather_than_an_unwind() {
        assert_eq!(boundary(|| panic!("a defect")), Status::Panic);
        assert_eq!(boundary(|| Status::Ok), Status::Ok);
        // A panic carrying a non-string payload is caught just the same: the
        // payload is deliberately dropped, because there is nothing a C caller
        // could do with it and formatting it here would be a second place to
        // panic.
        assert_eq!(
            boundary(|| std::panic::panic_any(7_u32)),
            Status::Panic,
            "the payload type must not matter"
        );
    }
}
