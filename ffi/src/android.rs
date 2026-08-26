//! JNI access to `VpnService.protect(int)` from Tokio worker threads.
//!
//! The device crosses as a file descriptor, but bypass protection is a method
//! on a Java object. This module attaches dialling threads to the JVM, builds a
//! [`BoreasBypass`](crate::BoreasBypass) vtable, and leaves the shared tunnel
//! implementation in [`crate::seam`].

use std::{
    ffi::c_void,
    sync::{Arc, OnceLock},
};

use jni::{Env, JavaVM, jni_sig, jni_str, objects::JObject, refs::Global, sys::jint};

use crate::seam::{BoreasBypass, BoreasSocket};

/// VM cached during library loading.
///
/// `JNI_OnLoad` receives the VM before worker threads need to attach. A worker
/// has no `JNIEnv` until it attaches to this cached VM.
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
    // Keep the ABI parameter raw; the Rust wrapper's layout is not an extern ABI.
    //
    // SAFETY: the JVM's contract for `JNI_OnLoad` is that this is the live VM.
    let vm = unsafe { JavaVM::from_raw(vm) };
    // Retain the first VM if the library is loaded more than once.
    let _ = VM.set(vm);
    jni::sys::JNI_VERSION_1_6
}

/// `VpnService` used to protect tunnel sockets.
///
/// The global reference outlives the JNI frame that created it.
struct Service(Global<JObject<'static>>);

/// Reason a socket was not excluded.
///
/// The sum distinguishes loader state, descriptor validity, and JVM refusal;
/// only the last is a JNI error.
#[derive(Debug)]
enum Refused {
    /// No VM was cached because `JNI_OnLoad` did not run.
    NoVm,
    /// The socket does not fit Java's `int`; narrowing would protect another fd.
    NotADescriptor,
    /// The JVM refused or `protect` threw.
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
    /// Error code exposed to C. Each refusal has a distinct cause and code.
    const fn code(&self) -> i32 {
        match self {
            Self::NoVm => -2,
            Self::NotADescriptor => -3,
            Self::Jvm(_) => -1,
        }
    }
}

impl Service {
    /// Calls `VpnService.protect(int)` from the dialling thread.
    ///
    /// `attach_current_thread` supplies the worker's `Env` and converts Java
    /// exceptions into a Rust error before the next JNI operation.
    fn protect(&self, socket: BoreasSocket) -> Result<bool, Refused> {
        // Android file descriptors are ints; the shared socket type is wider.
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
        // `false` leaves the socket in the tunnel, so it is a refusal.
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

/// Builds a bypass vtable over a `VpnService` for host-owned JNI glue.
///
/// This is a C entry point rather than a `Java_…` symbol because the host owns
/// the package and class name. The vtable holds one global service reference;
/// `boreas_tunnel_start` releases it exactly once after taking ownership.
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
        // Convert panic and Java-exception outcomes before returning to JNI.
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

    /// A socket outside Java's `int` range is refused rather than truncated.
    #[test]
    fn a_descriptor_outside_the_java_int_range_is_not_truncated() {
        assert!(jint::try_from(BoreasSocket::from(i32::MAX) + 1).is_err());
        assert_eq!(jint::try_from(BoreasSocket::from(7_i32)), Ok(7));
    }

    /// Each refusal has a distinct negative code.
    #[test]
    fn each_refusal_is_told_apart_from_the_others() {
        let codes = [Refused::NoVm.code(), Refused::NotADescriptor.code()];
        assert!(codes.iter().all(|code| *code < 0), "none is success");
        assert_ne!(codes[0], codes[1], "and none is mistaken for another");
        assert!(!Refused::NoVm.to_string().is_empty());
    }
}
