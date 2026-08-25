//! The build pipeline, typed.
//!
//! The decisions live in [`android`] and [`release`] and are pure: every input
//! arrives as an argument, so every branch is pinned by a test on fixed values.
//! This file is the shell that gathers an environment, runs `git`, writes
//! files, and renders output — and it is deliberately the only place that does.
//!
//! ```text
//! cargo xtask abis                    every Android ABI, one per line
//! cargo xtask android-target <abi>    the Rust target triple for one
//! cargo xtask android-env <abi>       the cross toolchain, as key=value
//! cargo xtask resolve                 what this event publishes, as key=value
//! ```
//!
//! **This replaced two Python scripts, and the reason is in the commit that
//! preceded it.** One shipped `TypeError: 'PosixPath' object is not callable`
//! to CI, from a local shadowing the function below it; the other emitted `CC`
//! without `CXX` and built a third of BoringSSL for the wrong architecture.
//! Neither is expressible here — see [`android`] for which type forbids which.

#![deny(unsafe_code)]

mod android;
mod release;

use std::{
    error::Error,
    fmt::Write as _,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use android::{Abi, ApiLevel, BuildEnvironment, HostTag, Ndk};
use release::{Event, Publish, Sha, Stamp, Version};

type Fallible = Result<String, Box<dyn Error>>;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();

    // Four commands, each taking at most one argument. A dependency for this
    // would be a dependency for a `match`.
    let outcome = match borrowed.as_slice() {
        ["abis"] => Ok(abis()),
        ["android-target", abi] => android_target(abi),
        ["android-env", abi] => android_env(abi),
        ["resolve"] => resolve(),
        other => Err(usage(other).into()),
    };

    match outcome {
        Ok(rendered) => {
            print!("{rendered}");
            ExitCode::SUCCESS
        }
        Err(complaint) => {
            eprintln!("xtask: {complaint}");
            ExitCode::FAILURE
        }
    }
}

fn usage(given: &[&str]) -> String {
    format!(
        "unrecognised command {given:?}\n\
         usage: cargo xtask abis\n\
         \x20      cargo xtask android-target <abi>\n\
         \x20      cargo xtask android-env <abi>\n\
         \x20      cargo xtask resolve"
    )
}

/// The repository root: one level above this crate, which is where Cargo put
/// it and where the workspace manifest is.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is a workspace member one level under the root")
        .to_owned()
}

// ----------------------------------------------------------------- android

/// Every ABI, which is what the release workflow's matrix is built from. The
/// list lives in one place and CI reads it rather than repeating it.
fn abis() -> String {
    let mut rendered = String::new();
    for abi in &android::ABIS {
        let _ = writeln!(rendered, "{}", abi.gradle);
    }
    rendered
}

fn named(name: &str) -> Result<&'static Abi, String> {
    Abi::find(name).ok_or_else(|| {
        let offered: Vec<&str> = android::ABIS.iter().map(|a| a.gradle.as_str()).collect();
        format!("no such ABI '{name}'; the NDK has {}", offered.join(", "))
    })
}

fn android_target(name: &str) -> Fallible {
    Ok(format!("{}\n", named(name)?.rust))
}

/// The cross toolchain for one ABI, as lines for `$GITHUB_ENV`.
///
/// Writes the CMake wrapper as a side effect, because the environment has to
/// name it and a path to a file nobody wrote is the class of bug this crate
/// exists to end.
fn android_env(name: &str) -> Fallible {
    let abi = named(name)?;
    let (host, root) = (HostTag::current()?, ndk_root()?);

    let ndk = Ndk::open(root, host)?;
    let compiler = ndk.compiler(abi, ApiLevel::MIN)?;

    let wrapper = repo_root()
        .join("target/xtask/android")
        .join(format!("{}.cmake", abi.gradle));
    std::fs::create_dir_all(wrapper.parent().expect("has a parent"))?;
    std::fs::write(&wrapper, ndk.cmake_wrapper(abi, ApiLevel::MIN))?;

    Ok(assignments(
        &BuildEnvironment::new(abi, compiler, &ndk, wrapper).assignments(),
    ))
}

/// Where the NDK is, preferring the variable a GitHub runner sets to the
/// newest one it has.
fn ndk_root() -> Result<PathBuf, String> {
    ["ANDROID_NDK_LATEST_HOME", "ANDROID_NDK_HOME", "ANDROID_NDK"]
        .into_iter()
        .find_map(|name| std::env::var_os(name).map(PathBuf::from))
        .ok_or_else(|| "no NDK: set ANDROID_NDK_LATEST_HOME or ANDROID_NDK_HOME".to_owned())
}

// ----------------------------------------------------------------- release

/// What this event publishes.
///
/// Reads the event from the variables GitHub already sets, so the workflow
/// plumbs nothing: `GITHUB_REF_TYPE` is `tag` exactly when a tag was pushed.
fn resolve() -> Fallible {
    let event = match std::env::var("GITHUB_REF_TYPE").as_deref() {
        Ok("tag") => Event::Release {
            tag: std::env::var("GITHUB_REF_NAME")?,
        },
        _ => Event::Push,
    };

    let manifest = std::fs::read_to_string(repo_root().join("Cargo.toml"))?;
    let declared = release::manifest_version(&manifest)
        .ok_or("Cargo.toml declares no [package] version this can read")?;

    let sha = match std::env::var("GITHUB_SHA") {
        Ok(full) => Sha::parse(&full).ok_or_else(|| format!("GITHUB_SHA is not hex: {full}"))?,
        Err(_) => head()?,
    };

    let publish = release::resolve(&event, declared, released()?, Stamp::now(), sha)?;
    Ok(outputs(&publish))
}

/// Every release tag in the repository. Anything that is not one — a
/// pre-release included — is dropped here, at the boundary, so the algebra
/// never sees a string.
fn released() -> Result<Vec<Version>, Box<dyn Error>> {
    Ok(git(&["tag", "--list", "v*"])?
        .lines()
        .filter_map(|line| Version::parse_tag(line.trim()))
        .collect())
}

fn head() -> Result<Sha, Box<dyn Error>> {
    let full = git(&["rev-parse", "HEAD"])?;
    Sha::parse(full.trim()).ok_or_else(|| format!("HEAD is not hex: {full}").into())
}

fn git(arguments: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(repo_root())
        .output()?;
    if output.status.success() {
        Ok(String::from_utf8(output.stdout)?)
    } else {
        Err(format!(
            "git {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into())
    }
}

fn outputs(publish: &Publish) -> String {
    assignments(&[
        ("tag".to_owned(), publish.tag()),
        ("version".to_owned(), publish.version().to_string()),
        ("prerelease".to_owned(), publish.is_prerelease().to_string()),
    ])
}

/// `key=value` lines, which is the one shape GitHub Actions reads for both
/// `$GITHUB_ENV` and `$GITHUB_OUTPUT`. The caller redirects; this never opens
/// either file, so running a command by hand prints rather than writes.
fn assignments(pairs: &[(String, String)]) -> String {
    let mut rendered = String::new();
    for (key, value) in pairs {
        let _ = writeln!(rendered, "{key}={value}");
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The matrix in the release workflow is written by hand; this is what
    /// stops it drifting from the table.
    #[test]
    fn the_abi_list_is_the_table() {
        assert_eq!(abis(), "arm64-v8a\nx86\nx86_64\n");
    }

    #[test]
    fn an_unknown_abi_names_the_ones_that_exist() {
        let complaint = named("arm64").expect_err("not an ABI");
        assert!(complaint.contains("arm64-v8a"), "{complaint}");
    }

    #[test]
    fn every_abi_resolves_to_its_rust_target() {
        assert_eq!(
            android_target("arm64-v8a").expect("in the table"),
            "aarch64-linux-android\n"
        );
    }

    /// The rendering CI consumes, pinned. A stray space either side of `=` is
    /// a variable that silently does not take effect.
    #[test]
    fn assignments_are_bare_key_equals_value_lines() {
        let rendered = assignments(&[
            ("A".to_owned(), "1".to_owned()),
            ("B".to_owned(), "/a path/x".to_owned()),
        ]);
        assert_eq!(rendered, "A=1\nB=/a path/x\n");
    }

    #[test]
    fn the_repository_root_is_where_the_manifest_is() {
        assert!(repo_root().join("Cargo.toml").is_file());
        assert!(repo_root().join("src/lib.rs").is_file());
    }
}
