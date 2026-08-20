//! `VpnService.protect(int)`, reached from a Tokio worker thread.
//!
//! **This is the one obligation that cannot be a C function pointer.** The
//! device is a file descriptor, which crosses as an integer and needs no JVM;
//! the bypass is a *method on a Java object*, and Boreas has to call it from
//! whichever thread is dialling. That means attaching to the JVM from a thread
//! the JVM never created, which is what this module exists to do — and it is
//! why `jni` is a dependency on exactly one target.
//!
//! Everything else stays in [`crate::seam`]: this produces a
//! [`BoreasBypass`](crate::BoreasBypass) vtable and hands it to the same code
//! Windows uses. There is deliberately no second tunnel implementation.

use std::{
    ffi::c_void,
    sync::{Arc, OnceLock},
};

use jni::{Env, JavaVM, jni_sig, jni_str, objects::JObject, refs::Global, sys::jint};

use crate::seam::{BoreasBypass, BoreasSocket};

/// The VM, cached at load time.
///
/// **`JNI_OnLoad` is the only place this can be had reliably.** A thread the
/// JVM never created has no `JNIEnv` and no way to find one; what it can do is
/// attach to a `JavaVM` it was handed earlier, and the loader is when that
/// happens. Reaching for it later would work only from threads that already
/// have an env, which is precisely the set of threads this is not for.
static VM: OnceLock<JavaVM> = OnceLock::new();

/// Called by the runtime linker when `System.loadLibrary` maps this object.
///
/// # Safety
///
/// Called by the JVM, with the contract `JNI_OnLoad` documents.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut c_void,
) -> jint {
    // The raw pointer rather than `jni::JavaVM`: the wrapper has no guaranteed
    // layout, so naming it in an `extern "system"` signature would be
    // describing an ABI Rust does not promise to keep.
    //
    // SAFETY: the JVM's contract for `JNI_OnLoad` is that this is the live VM.
    let vm = unsafe { JavaVM::from_raw(vm) };
    // A second load is not an error; the first VM is the one that stays.
    let _ = VM.set(vm);
    jni::sys::JNI_VERSION_1_6
}

/// The `VpnService` this tunnel protects sockets through.
///
/// A global reference rather than a local one: a local reference is valid only
/// for the frame that made it, and this outlives every frame by design.
struct Service(Global<JObject<'static>>);

/// Why a socket was not excluded.
///
/// **Its own sum rather than a borrowed `jni::errors::Error` variant**, because
/// two of these are not JNI failures at all: one is a library that was loaded
/// without its loader running, and one is a descriptor this platform cannot
/// have produced. Both would have to be dressed up as something else to reuse
/// that enum, and a caller reading the log would be sent after the wrong thing.
#[derive(Debug)]
enum Refused {
    /// `JNI_OnLoad` never ran, so there is no VM to attach to. The library was
    /// not loaded through `System.loadLibrary`.
    NoVm,
    /// A descriptor outside the Java `int` range. The socket type is 64-bit for
    /// Windows' sake; narrowing it silently would protect a descriptor nobody
    /// holds and report success.
    NotADescriptor,
    /// The JVM refused, or `protect` threw.
    Jvm(jni::errors::Error),
}

impl From<jni::errors::Error> for Refused {
    fn from(error: jni::errors::Error) -> Self {
        Self::Jvm(error)
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoVm => f.write_str("JNI_OnLoad never ran: load through System.loadLibrary"),
            Self::NotADescriptor => f.write_str("a socket outside the Java int range"),
            Self::Jvm(error) => write!(f, "VpnService.protect failed: {error}"),
        }
    }
}

impl Refused {
    /// The code a C caller sees. **Distinct per cause**, because the three are
    /// three different bugs in three different places: a library loaded the
    /// wrong way, a platform that handed over a socket it cannot have made, and
    /// a `VpnService` that said no. One shared `-1` would send whoever reads the
    /// log after any of them.
    const fn code(&self) -> i32 {
        match self {
            Self::NoVm => -2,
            Self::NotADescriptor => -3,
            Self::Jvm(_) => -1,
        }
    }
}

impl Service {
    /// Calls `VpnService.protect(int)` from whatever thread is dialling.
    ///
    /// **The attachment is the point of this module.** A Tokio worker is a
    /// thread the JVM never created, so it has no `Env` and no way to find one;
    /// `attach_current_thread` is what gives it one. In `jni` 0.22 that call
    /// takes a callback and owns the whole protocol around it — it attaches
    /// permanently (cheap on every later call from the same worker), stashes
    /// and restores any exception that was already pending, and returns a
    /// thrown one as [`jni::errors::Error::CaughtJavaException`] rather than
    /// leaving it pending to break the next unrelated JNI call.
    fn protect(&self, socket: BoreasSocket) -> Result<bool, Refused> {
        // A file descriptor on Android is an `int`, and the wider type this
        // crate carries for Windows' sake narrows back here.
        let fd = jint::try_from(socket).map_err(|_| Refused::NotADescriptor)?;
        let vm = VM.get().ok_or(Refused::NoVm)?;
        vm.attach_current_thread(|env: &mut Env| self.call(env, fd))
    }

    fn call(&self, env: &mut Env<'_>, fd: jint) -> Result<bool, Refused> {
        Ok(env
            .call_method(
                self.0.as_obj(),
                jni_str!("protect"),
                jni_sig!((fd: jint) -> bool),
                &[jni::objects::JValue::Int(fd)],
            )?
            .z()?)
    }
}

/// # Safety
///
/// `context` must be a leaked `Arc<Service>` from [`bypass_for`].
unsafe extern "C" fn protect(context: *mut c_void, socket: BoreasSocket) -> i32 {
    // SAFETY: the caller's contract. Borrowed rather than reclaimed, because
    // `release` is what reclaims.
    let service = unsafe { &*context.cast::<Service>() };
    match service.protect(socket) {
        Ok(true) => 0,
        // A plain `false` is the `VpnService` declining, which is the same
        // outcome as a throw: the socket is not excluded, so using it would
        // send tunnel traffic back through the tunnel.
        Ok(false) => -1,
        Err(refused) => refused.code(),
    }
}

/// # Safety
///
/// `context` must be a leaked `Arc<Service>`, and this consumes it.
unsafe extern "C" fn release(context: *mut c_void) {
    // SAFETY: the caller's contract. Dropping the last reference drops the
    // `GlobalRef`, which is what tells the JVM the object may be collected.
    drop(unsafe { Arc::from_raw(context.cast::<Service>()) });
}

/// Builds a bypass vtable over a `VpnService`, for a `Java_…` function the
/// host wrote.
///
/// **A C entry point rather than a `Java_…` one**, and that is a scope
/// decision rather than an oversight: a `Java_…` symbol encodes the package
/// and class it belongs to, and those are the host's to choose. So this takes
/// the two things any JNI frame already has — its `JNIEnv` and the object —
/// and hands back a vtable [`boreas_tunnel_start`](crate::boreas_tunnel_start)
/// accepts. The glue that names a class stays in the host, where the name is
/// known; the part that cannot be written outside Rust is here.
///
/// The vtable owns one reference to the service. `boreas_tunnel_start` calls
/// its `release` exactly once, on success and on failure alike, so a caller
/// that hands it over never has to unwind this by hand.
///
/// # Safety
///
/// `env` must be the live `JNIEnv` of the calling frame, `service` a valid
/// local or global reference to a `VpnService`, and `out` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boreas_android_bypass(
    env: *mut jni::sys::JNIEnv,
    service: jni::sys::jobject,
    out: *mut BoreasBypass,
) -> crate::Status {
    crate::boundary(|| {
        if env.is_null() || service.is_null() || out.is_null() {
            return crate::Status::NullArgument;
        }
        // SAFETY: the caller's contract is that this is the calling frame's
        // env, which is exactly what `EnvUnowned` is for.
        let mut unowned = unsafe { jni::EnvUnowned::from_raw(env) };
        let made = unowned.with_env(|env: &mut Env| {
            // SAFETY: the caller's contract covers the reference's validity,
            // and it is borrowed only for the length of this frame.
            let service = unsafe { JObject::from_raw(env, service) };
            let global = env.new_global_ref(&service)?;
            Ok::<_, jni::errors::Error>(Arc::new(Service(global)))
        });
        // `with_env` catches a panic as well as an exception, so all three
        // outcomes arrive here rather than one of them escaping into a JNI
        // frame that cannot survive it.
        let jni::Outcome::Ok(service) = made.into_outcome() else {
            return crate::Status::Egress;
        };
        // SAFETY: `out` was checked non-null and the caller promised it is
        // writable.
        unsafe {
            out.write(BoreasBypass {
                context: Arc::into_raw(service).cast::<c_void>().cast_mut(),
                protect: Some(protect),
                release: Some(release),
            });
        }
        crate::Status::Ok
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A descriptor that is not a Java `int` is refused rather than
    /// truncated.** The socket type is 64-bit for Windows' sake, and a silent
    /// narrowing here would protect a descriptor nobody holds and report
    /// success — an unprotected socket that works perfectly until the tunnel
    /// comes up.
    #[test]
    fn a_descriptor_outside_the_java_int_range_is_not_truncated() {
        assert!(jint::try_from(BoreasSocket::from(i32::MAX) + 1).is_err());
        assert_eq!(jint::try_from(BoreasSocket::from(7_i32)), Ok(7));
    }

    /// Every refusal reports a code of its own, and none of them is success.
    #[test]
    fn each_refusal_is_told_apart_from_the_others() {
        let codes = [Refused::NoVm.code(), Refused::NotADescriptor.code()];
        assert!(codes.iter().all(|code| *code < 0), "none is success");
        assert_ne!(codes[0], codes[1], "and none is mistaken for another");
        assert!(!Refused::NoVm.to_string().is_empty());
    }
}
