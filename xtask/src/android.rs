//! The Android cross-build, as types.
//!
//! Four bugs reached CI from the shell script this replaces, and each one was a
//! value of the wrong kind flowing somewhere that accepted it. What follows is
//! organised around making each of them fail to compile.
//!
//! | What went wrong | What forbids it here |
//! | --- | --- |
//! | A Rust target used where the NDK's triple belongs | [`RustTarget`] and [`NdkTriple`] are different types |
//! | `CC` named without `CXX`, so C++ built for the host | [`Compiler`] has no constructor that yields one without the other |
//! | An environment variable pointing at a file that is not there | [`Ndk::open`] and [`Ndk::compiler`] are the only ways in, and both check |
//! | A local shadowing the function it then tried to call | a `PathBuf` is not callable |
//!
//! The last one is the cheapest and the most embarrassing: a Python local named
//! `toolchain` shadowed a function named `toolchain`, and the first thing CI did
//! was `TypeError: 'PosixPath' object is not callable`. It is here only as a
//! reminder of what a type checker is for.

use std::{
    fmt,
    path::{Path, PathBuf},
};

/// What Gradle, the Play Store, and `src/main/jniLibs/<abi>/` call an
/// architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GradleAbi(&'static str);

/// What `cargo --target` takes, and what names the directory under `target/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustTarget(&'static str);

/// What the NDK names its compiler wrappers after.
///
/// **Separate from [`RustTarget`] because the two are independently defined,
/// not because they currently differ.** They agree on every ABI shipped today,
/// and that is a coincidence of which three those are: `armeabi-v7a` was
/// `armv7-linux-androideabi` to Rust and `armv7a-linux-androideabi` to the NDK
/// — one letter, in the one position where a wrong guess is a missing file at
/// link time. It was dropped for reach, not for that; nothing stops the next
/// ABI diverging the same way, and `the_two_triples_are_not_one_type` keeps the
/// case on file.
///
/// > **Note:** For 32-bit ARM, the compiler is prefixed with
/// > `armv7a-linux-androideabi`, but the binutils tools are prefixed with
/// > `arm-linux-androideabi`.
/// >
/// > — [Use the NDK with other build
/// > systems](https://developer.android.com/ndk/guides/other_build_systems),
/// > accessed 2026-08-24
///
/// The binutils half of that note is why the archiver is `llvm-ar`: the unified
/// tool takes no triple, so the second naming split has nowhere to go wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdkTriple(&'static str);

macro_rules! name_newtype {
    ($($t:ty),*) => {$(
        impl $t {
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                self.0
            }
        }

        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0)
            }
        }
    )*};
}
name_newtype!(GradleAbi, RustTarget, NdkTriple);

/// One architecture, under all three of its names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Abi {
    pub gradle: GradleAbi,
    pub rust: RustTarget,
    pub ndk: NdkTriple,
}

/// The ABIs this project ships, and the only values of [`Abi`] that exist: the
/// fields are public but the type is only ever read from here, so a value of
/// this type is the proof that the NDK has a toolchain for it.
///
/// **`armeabi-v7a` is deliberately absent.** Google requires 64-bit for each
/// 32-bit architecture shipped and nothing in the other direction — "for each
/// native 32-bit architecture you support you must include the corresponding
/// 64-bit architecture" — so omitting it is compliant. It is also where the
/// platform is going: 16 KB pages, mandatory for API 35 and above, exist only
/// on arm64, so a 32-bit ARM device cannot run a current Android at all. What
/// remains is a shrinking tail of Android Go class handsets, which is not the
/// hardware that terminates TLS and rewrites HTML under a memory budget.
pub const ABIS: [Abi; 3] = [
    Abi {
        gradle: GradleAbi("arm64-v8a"),
        rust: RustTarget("aarch64-linux-android"),
        ndk: NdkTriple("aarch64-linux-android"),
    },
    Abi {
        gradle: GradleAbi("x86"),
        rust: RustTarget("i686-linux-android"),
        ndk: NdkTriple("i686-linux-android"),
    },
    Abi {
        gradle: GradleAbi("x86_64"),
        rust: RustTarget("x86_64-linux-android"),
        ndk: NdkTriple("x86_64-linux-android"),
    },
];

impl Abi {
    /// The ABI a caller named, or nothing.
    ///
    /// The one boundary an untrusted string crosses. Everything downstream
    /// takes an `Abi`, so no other function has to consider a name the NDK does
    /// not have.
    #[must_use]
    pub fn find(name: &str) -> Option<&'static Self> {
        ABIS.iter().find(|abi| abi.gradle.as_str() == name)
    }

    /// `CC_x86_64_linux_android`, and the other lower-cased spellings the `cc`
    /// crate reads.
    fn env_suffix(self) -> String {
        self.rust.as_str().replace('-', "_")
    }
}

/// The minimum Android API the shipped library is built against.
///
/// 26 is the floor `VpnService.Builder.setMetered` needs. A level the NDK ships
/// no wrapper for is not refused here — it is refused by [`Ndk::compiler`],
/// which looks for the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiLevel(u32);

impl ApiLevel {
    pub const MIN: Self = Self(26);
}

impl fmt::Display for ApiLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The three host directories the NDK ships prebuilt toolchains for. A closed
/// set, so a host outside it is a refusal at the one place that names them
/// rather than a path that does not exist four steps later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostTag {
    Linux,
    Darwin,
    Windows,
}

impl HostTag {
    pub fn current() -> Result<Self, NdkError> {
        match std::env::consts::OS {
            "linux" => Ok(Self::Linux),
            "macos" => Ok(Self::Darwin),
            "windows" => Ok(Self::Windows),
            _ => Err(NdkError::UnsupportedHost),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux-x86_64",
            Self::Darwin => "darwin-x86_64",
            Self::Windows => "windows-x86_64",
        }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NdkError {
    #[error("the NDK ships no prebuilt toolchain for this host")]
    UnsupportedHost,
    #[error("not an NDK: no {0} under it")]
    NotAnNdk(PathBuf),
    #[error("the NDK has no {0}; it may be too old for API level {1}")]
    NoCompiler(PathBuf, ApiLevel),
}

/// An NDK installation whose CMake toolchain file is present.
///
/// **The constructor is the check.** A value of this type cannot name a
/// directory that is not an NDK, so nothing downstream re-tests it and no
/// environment variable can be emitted pointing at one.
#[derive(Debug, Clone)]
pub struct Ndk {
    root: PathBuf,
    host: HostTag,
}

impl Ndk {
    pub fn open(root: PathBuf, host: HostTag) -> Result<Self, NdkError> {
        let ndk = Self { root, host };
        let toolchain = ndk.toolchain_file();
        if toolchain.is_file() {
            Ok(ndk)
        } else {
            Err(NdkError::NotAnNdk(toolchain))
        }
    }

    /// The NDK's own CMake toolchain file, which the wrapper below includes.
    #[must_use]
    pub fn toolchain_file(&self) -> PathBuf {
        self.root.join("build/cmake/android.toolchain.cmake")
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn bin(&self) -> PathBuf {
        self.root
            .join("toolchains/llvm/prebuilt")
            .join(self.host.as_str())
            .join("bin")
    }

    /// The compilers for one ABI, if the NDK actually has them.
    ///
    /// Both wrappers are required. That is the whole point: BoringSSL's
    /// `crypto/` is 329 C++ files and no C files, and a build that named `CC`
    /// alone let CMake resolve C++ to the host's compiler and produced a
    /// `libcrypto.a` full of x86-64 objects — which nothing noticed until the
    /// final link, and `cargo check` never links.
    pub fn compiler(&self, abi: &Abi, api: ApiLevel) -> Result<Compiler, NdkError> {
        let bin = self.bin();
        let triple = abi.ndk.as_str();
        let cc = bin.join(format!("{triple}{api}-clang"));
        let cxx = bin.join(format!("{triple}{api}-clang++"));
        let ar = bin.join("llvm-ar");
        for tool in [&cc, &cxx, &ar] {
            if !tool.is_file() {
                return Err(NdkError::NoCompiler(tool.clone(), api));
            }
        }
        Ok(Compiler { cc, cxx, ar })
    }

    /// A CMake toolchain file that turns testing off and then defers to the
    /// NDK's own.
    ///
    /// **`BUILD_TESTING` is what this exists for.** It defaults on, so CMake
    /// descends into googletest and Google Benchmark in order to build neither
    /// — `boring-sys` asks only for the `crypto` and `ssl` targets. Benchmark
    /// then probes for a regex backend, writes the answer with
    /// `CACHE BOOL "" FORCE`, and returns early on `if(DEFINED ...)` ever
    /// after; `boring-sys` runs CMake once per target, and the second pass
    /// re-runs those probes over a cache its own `-DCMAKE_C_COMPILER` just
    /// invalidated, where they fail. A build that never configures Benchmark
    /// cannot fail in Benchmark.
    ///
    /// Setting `CMAKE_TOOLCHAIN_FILE` is the only seam: `boring-sys` skips its
    /// whole CMake configuration on seeing one. `FORCE`, because a toolchain
    /// file is re-read for every `try_compile` and Benchmark writes its own
    /// answers with `FORCE` too.
    #[must_use]
    pub fn cmake_wrapper(&self, abi: &Abi, api: ApiLevel) -> String {
        let toolchain = self.toolchain_file();
        format!(
            "# Generated by `cargo xtask android-env`. Do not edit.\n\
             set(BUILD_TESTING OFF CACHE BOOL \"\" FORCE)\n\
             set(ANDROID_ABI \"{abi}\" CACHE STRING \"\" FORCE)\n\
             set(ANDROID_PLATFORM \"android-{api}\" CACHE STRING \"\" FORCE)\n\
             include(\"{toolchain}\")\n",
            abi = abi.gradle,
            toolchain = toolchain.display(),
        )
    }
}

/// The compilers for one ABI, all of which exist.
///
/// There is no constructor but [`Ndk::compiler`], so a `Compiler` in hand is
/// the proof that a C++ compiler was found — and [`BuildEnvironment`] takes one
/// rather than a pair of paths, so an environment naming `CC` without `CXX` is
/// not a bug to be caught but a value that cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiler {
    cc: PathBuf,
    cxx: PathBuf,
    ar: PathBuf,
}

/// Everything a cross build for one ABI needs, and nothing else.
///
/// [`Self::assignments`] returns a fixed-size array, so the number of variables
/// is part of the signature: adding or dropping one is a type error at every
/// call site rather than a line quietly missing from `$GITHUB_ENV`.
#[derive(Debug, Clone)]
pub struct BuildEnvironment {
    abi: &'static Abi,
    compiler: Compiler,
    ndk_root: PathBuf,
    wrapper: PathBuf,
}

impl BuildEnvironment {
    #[must_use]
    pub fn new(abi: &'static Abi, compiler: Compiler, ndk: &Ndk, wrapper: PathBuf) -> Self {
        Self {
            abi,
            compiler,
            ndk_root: ndk.root().to_owned(),
            wrapper,
        }
    }

    /// The `key=value` lines a CI step appends to `$GITHUB_ENV`.
    ///
    /// The compiler is also the linker: the NDK's wrapper is what knows the
    /// sysroot and the runtime, and invoking a bare `ld` misses both.
    #[must_use]
    pub fn assignments(&self) -> [(String, String); 6] {
        let lower = self.abi.env_suffix();
        let upper = lower.to_uppercase();
        let path = |p: &Path| p.display().to_string();
        [
            (format!("CC_{lower}"), path(&self.compiler.cc)),
            (format!("CXX_{lower}"), path(&self.compiler.cxx)),
            (format!("AR_{lower}"), path(&self.compiler.ar)),
            (
                format!("CARGO_TARGET_{upper}_LINKER"),
                path(&self.compiler.cc),
            ),
            // `boring-sys` reads this to locate the NDK's CMake toolchain file.
            // Naming it explicitly is what stops a runner with more than one
            // NDK installed from handing BoringSSL a different installation
            // than the compilers above came from.
            ("ANDROID_NDK_HOME".to_owned(), path(&self.ndk_root)),
            // Target-scoped, which is the form both `boring-sys` and `cmake-rs`
            // read. See `Ndk::cmake_wrapper` for what it buys.
            (
                format!("CMAKE_TOOLCHAIN_FILE_{}", self.abi.rust),
                path(&self.wrapper),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abi(name: &str) -> &'static Abi {
        Abi::find(name).expect("a name from the table")
    }

    /// **Why [`RustTarget`] and [`NdkTriple`] stay two types now that no shipped
    /// ABI distinguishes them.**
    ///
    /// Every row below agrees, and a maintainer reading only the table would be
    /// right to ask why one string needs two names for it. This is the answer,
    /// kept as a fixture rather than as a comment: `armeabi-v7a`, which this
    /// project shipped until it was dropped for reach, disagreed. Merging the
    /// types would compile today and silently mis-name a compiler the day
    /// anything like it is added back.
    #[test]
    fn the_two_triples_are_not_one_type() {
        assert!(
            ABIS.iter().all(|a| a.rust.as_str() == a.ndk.as_str()),
            "a shipped ABI now distinguishes them; say so here rather than \
             leaving this test asserting the opposite of the table"
        );

        // The case on file. One letter, and the NDK's own documentation is why:
        // "For 32-bit ARM, the compiler is prefixed with
        // `armv7a-linux-androideabi`, but the binutils tools are prefixed with
        // `arm-linux-androideabi`."
        let armv7 = Abi {
            gradle: GradleAbi("armeabi-v7a"),
            rust: RustTarget("armv7-linux-androideabi"),
            ndk: NdkTriple("armv7a-linux-androideabi"),
        };
        assert_ne!(armv7.rust.as_str(), armv7.ndk.as_str());
        assert!(Abi::find("armeabi-v7a").is_none(), "dropped, not hidden");
    }

    /// The table is the domain: a name outside it has no `Abi` to become.
    #[test]
    fn only_the_shipped_abis_exist() {
        assert_eq!(ABIS.len(), 3);
        assert!(Abi::find("arm64").is_none());
        assert!(
            Abi::find("aarch64-linux-android").is_none(),
            "that is a target, not an ABI"
        );
        for expected in ["arm64-v8a", "x86", "x86_64"] {
            assert_eq!(abi(expected).gradle.as_str(), expected);
        }
    }

    #[test]
    fn an_ndk_is_refused_unless_its_toolchain_file_is_there() {
        let scratch = tempdir("not-an-ndk");
        let error = Ndk::open(scratch.clone(), HostTag::Linux).expect_err("empty directory");
        assert!(matches!(error, NdkError::NotAnNdk(_)));
    }

    #[test]
    fn a_compiler_requires_both_halves_to_exist() {
        let root = fake_ndk("half", &[Half::C]);
        let ndk = Ndk::open(root, HostTag::Linux).expect("toolchain file written");
        let error = ndk
            .compiler(abi("arm64-v8a"), ApiLevel::MIN)
            .expect_err("no clang++");
        match error {
            NdkError::NoCompiler(path, _) => {
                assert!(path.to_string_lossy().ends_with("clang++"), "{path:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// Every ABI, end to end: the environment names six variables, every tool
    /// lives under the one NDK, and the wrapper turns testing off.
    #[test]
    fn every_abi_yields_a_complete_environment_from_one_ndk() {
        let root = fake_ndk("complete", &[Half::C, Half::Cxx]);
        let ndk = Ndk::open(root.clone(), HostTag::Linux).expect("an NDK");
        for abi in &ABIS {
            let compiler = ndk
                .compiler(abi, ApiLevel::MIN)
                .unwrap_or_else(|e| panic!("{}: {e}", abi.gradle));
            let wrapper = root.join(format!("{}.cmake", abi.gradle));
            let env = BuildEnvironment::new(abi, compiler, &ndk, wrapper.clone());
            let keys: Vec<_> = env.assignments().map(|(k, _)| k).into_iter().collect();
            assert_eq!(
                keys,
                [
                    format!("CC_{}", abi.env_suffix()),
                    format!("CXX_{}", abi.env_suffix()),
                    format!("AR_{}", abi.env_suffix()),
                    format!("CARGO_TARGET_{}_LINKER", abi.env_suffix().to_uppercase()),
                    "ANDROID_NDK_HOME".to_owned(),
                    format!("CMAKE_TOOLCHAIN_FILE_{}", abi.rust),
                ]
            );

            // One NDK, every tool. A build that mixes a cross compiler with a
            // host one produces objects that only disagree at the final link.
            for (key, value) in env.assignments() {
                if key.starts_with("CC_") || key.starts_with("CXX_") || key.starts_with("AR_") {
                    assert!(
                        Path::new(&value).starts_with(&root),
                        "{key} escapes the NDK: {value}"
                    );
                }
            }

            let cmake = ndk.cmake_wrapper(abi, ApiLevel::MIN);
            assert!(cmake.contains("set(BUILD_TESTING OFF CACHE BOOL \"\" FORCE)"));
            assert!(cmake.contains(&format!("set(ANDROID_ABI \"{}\"", abi.gradle)));
            assert!(cmake.contains("android-26"));
            assert!(cmake.contains("android.toolchain.cmake"));
        }
    }

    /// The wrapper names the *Gradle* ABI, which is what the NDK's own
    /// toolchain file expects — not the Rust target and not the compiler
    /// triple. `arm64-v8a` proves it: its Gradle name shares no substring with
    /// `aarch64-linux-android`.
    #[test]
    fn the_wrapper_names_the_gradle_abi() {
        let root = fake_ndk("wrapper", &[Half::C, Half::Cxx]);
        let ndk = Ndk::open(root, HostTag::Linux).expect("an NDK");
        let cmake = ndk.cmake_wrapper(abi("arm64-v8a"), ApiLevel::MIN);
        assert!(cmake.contains("\"arm64-v8a\""), "{cmake}");
        assert!(!cmake.contains("aarch64"), "{cmake}");
    }

    // --- fixtures ------------------------------------------------------

    enum Half {
        C,
        Cxx,
    }

    fn tempdir(label: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("boreas-xtask-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        path
    }

    /// An NDK with the right shape and empty files where the tools go. Nothing
    /// here compiles anything; what is under test is which paths are looked
    /// for and what is emitted, which is where every shipped bug lived.
    fn fake_ndk(label: &str, halves: &[Half]) -> PathBuf {
        let root = tempdir(label);
        let toolchain = root.join("build/cmake/android.toolchain.cmake");
        std::fs::create_dir_all(toolchain.parent().expect("has a parent")).expect("mkdir");
        std::fs::write(&toolchain, "").expect("write");

        let bin = root.join("toolchains/llvm/prebuilt/linux-x86_64/bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        std::fs::write(bin.join("llvm-ar"), "").expect("write");
        for abi in &ABIS {
            for half in halves {
                let name = match half {
                    Half::C => format!("{}{}-clang", abi.ndk, ApiLevel::MIN),
                    Half::Cxx => format!("{}{}-clang++", abi.ndk, ApiLevel::MIN),
                };
                std::fs::write(bin.join(name), "").expect("write");
            }
        }
        root
    }
}
