//! Typed Android cross-build configuration.
//!
//! The former shell pipeline allowed four mismatched values to reach CI. These
//! types make each mismatch fail at construction or compilation.
//!
//! | What went wrong | What forbids it here |
//! | --- | --- |
//! | A Rust target used where the NDK's triple belongs | [`RustTarget`] and [`NdkTriple`] are different types |
//! | `CC` named without `CXX`, so C++ built for the host | [`Compiler`] has no constructor that yields one without the other |
//! | An environment variable pointing at a file that is not there | [`Ndk::open`] and [`Ndk::compiler`] are the only ways in, and both check |
//! | A local shadowing the function it then tried to call | a `PathBuf` is not callable |
//!
//! The shadowing failure was a Python `TypeError` before any build work began.
//! A typed pipeline makes that class of mistake unrepresentable.

use std::{
    fmt,
    path::{Path, PathBuf},
};

/// Architecture name used by Gradle and `src/main/jniLibs/<abi>/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GradleAbi(&'static str);

/// Architecture name accepted by `cargo --target` and used under `target/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustTarget(&'static str);

/// Triple used in NDK compiler wrapper names.
///
/// This stays separate from [`RustTarget`] because the names are independently
/// defined. They currently match for shipped ABIs, but `armeabi-v7a` previously
/// used `armv7-linux-androideabi` for Rust and
/// `armv7a-linux-androideabi` for the NDK. The test
/// `the_two_triples_are_not_one_type` preserves that distinction.
///
/// > **Note:** For 32-bit ARM, the compiler is prefixed with
/// > `armv7a-linux-androideabi`, but the binutils tools are prefixed with
/// > `arm-linux-androideabi`.
/// >
/// > — [Use the NDK with other build
/// > systems](https://developer.android.com/ndk/guides/other_build_systems),
/// > accessed 2026-08-24
///
/// The unified `llvm-ar` takes no triple, so binutils naming does not enter the
/// archiver configuration.
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

/// One architecture represented by all three naming systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Abi {
    pub gradle: GradleAbi,
    pub rust: RustTarget,
    pub ndk: NdkTriple,
}

/// ABIs shipped by this project.
///
/// `armeabi-v7a` is absent: the release requires a corresponding 64-bit ABI for
/// each shipped 32-bit ABI, and current 16 KB page support is arm64-only.
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
    /// Resolves a Gradle ABI name to a shipped ABI.
    ///
    /// This is the boundary for untrusted names; downstream code receives only
    /// an ABI from the table.
    #[must_use]
    pub fn find(name: &str) -> Option<&'static Self> {
        ABIS.iter().find(|abi| abi.gradle.as_str() == name)
    }

    fn env_suffix(self) -> String {
        self.rust.as_str().replace('-', "_")
    }
}

/// Minimum Android API for the shipped library.
///
/// API 26 is required by `VpnService.Builder.setMetered`; compiler availability
/// for a selected level is checked by [`Ndk::compiler`].
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

/// Host directories supported by the NDK's prebuilt toolchains.
///
/// A closed set rejects unsupported hosts before path construction.
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

/// NDK installation with a present CMake toolchain file.
///
/// Construction validates the installation, so downstream environment values
/// cannot name an unchecked root.
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

    /// Returns the complete compiler toolset for one ABI, if present.
    ///
    /// Both C and C++ wrappers are required. Naming only `CC` can make CMake
    /// compile BoringSSL C++ sources with the host compiler.
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

    /// Returns a wrapper that disables tests before including the NDK toolchain.
    ///
    /// `boring-sys` needs only `crypto` and `ssl`; disabling `BUILD_TESTING`
    /// avoids configuring their unrelated test and benchmark targets. Forced
    /// cache entries keep the values stable across repeated CMake probes.
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

/// Existing compiler paths for one ABI.
///
/// [`Ndk::compiler`] is the only constructor, so a `Compiler` proves that all
/// required tools exist. [`BuildEnvironment`] receives it as one value rather
/// than independent `CC` and `CXX` paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiler {
    cc: PathBuf,
    cxx: PathBuf,
    ar: PathBuf,
}

/// Inputs required for one ABI cross-build.
///
/// [`Self::assignments`] returns a fixed-size array, so its variable count is
/// checked at every call site.
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

    /// Returns the `key=value` lines appended to `$GITHUB_ENV`.
    ///
    /// The NDK compiler wrapper also links, supplying its sysroot and runtime.
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
            // `boring-sys` uses this to select the same NDK as the compilers.
            ("ANDROID_NDK_HOME".to_owned(), path(&self.ndk_root)),
            // Target-scoped form consumed by `boring-sys` and `cmake-rs`.
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

    /// Keeps [`RustTarget`] and [`NdkTriple`] distinct despite current matches.
    ///
    /// The former `armeabi-v7a` row used different Rust and NDK triples. Merging
    /// the types would make a future mismatch compile and mis-name a compiler.
    #[test]
    fn the_two_triples_are_not_one_type() {
        assert!(
            ABIS.iter().all(|a| a.rust.as_str() == a.ndk.as_str()),
            "a shipped ABI now distinguishes them; say so here rather than \
             leaving this test asserting the opposite of the table"
        );

        // Former 32-bit ARM naming differed by one character between compiler
        // and Rust triples.
        let armv7 = Abi {
            gradle: GradleAbi("armeabi-v7a"),
            rust: RustTarget("armv7-linux-androideabi"),
            ndk: NdkTriple("armv7a-linux-androideabi"),
        };
        assert_ne!(armv7.rust.as_str(), armv7.ndk.as_str());
        assert!(Abi::find("armeabi-v7a").is_none(), "dropped, not hidden");
    }

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

            // Every tool must come from the same NDK as the selected ABI.
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

    /// The test checks path validation and emitted configuration, not compilation.
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
