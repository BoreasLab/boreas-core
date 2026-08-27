//! The build pipeline, typed.
//!
//! [`android`] and [`release`] contain pure decisions over typed inputs. This
//! file gathers the environment, runs `git`, writes files, and renders output.
//!
//! ```text
//! cargo xtask abis                    every Android ABI, one per line
//! cargo xtask android-target <abi>    the Rust target triple for one
//! cargo xtask android-env <abi>       the cross toolchain, as key=value
//! cargo xtask resolve                 what this event publishes, as key=value
//! ```
//!

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

    // Four commands take at most one argument, so a match replaces a parser
    // dependency.
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

/// The workspace root, one level above this crate.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is a workspace member one level under the root")
        .to_owned()
}

// ----------------------------------------------------------------- android

/// ABI names used by the release workflow matrix.
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
/// Writes the CMake wrapper because the emitted environment names its path; a
/// missing wrapper would surface later as a linker error.
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

/// Selects the newest NDK path available in runner variables.
fn ndk_root() -> Result<PathBuf, String> {
    ["ANDROID_NDK_LATEST_HOME", "ANDROID_NDK_HOME", "ANDROID_NDK"]
        .into_iter()
        .find_map(|name| std::env::var_os(name).map(PathBuf::from))
        .ok_or_else(|| "no NDK: set ANDROID_NDK_LATEST_HOME or ANDROID_NDK_HOME".to_owned())
}

// ----------------------------------------------------------------- release

/// What this event publishes.
///
/// `GITHUB_SHA` and `GITHUB_REF_NAME` are parsed here, so
/// [`release::resolve`] receives typed values and no longer handles input
/// refusal.
///
/// The tag is the sole release-version source.
fn resolve() -> Fallible {
    let event = match std::env::var("GITHUB_REF_TYPE").as_deref() {
        // A tag ref identifies a release; other refs use Push.
        Ok("tag") => {
            let name = std::env::var("GITHUB_REF_NAME")?;
            let version = Version::parse_tag(&name).ok_or_else(|| {
                format!("'{name}' is not a release tag; releases are vMAJOR.MINOR.PATCH")
            })?;
            Event::Release(version)
        }
        _ => Event::Push,
    };

    let sha = match std::env::var("GITHUB_SHA") {
        Ok(full) => Sha::parse(&full).ok_or_else(|| format!("GITHUB_SHA is not hex: {full}"))?,
        Err(_) => head()?,
    };

    Ok(outputs(&release::resolve(
        event,
        released()?,
        Stamp::now(),
        sha,
    )))
}

/// Reads release tags, ignoring pre-release tags before the pure resolver.
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

/// Formats the `key=value` lines used by `$GITHUB_ENV` and `$GITHUB_OUTPUT`.
/// The caller redirects stdout; this function never opens either file.
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

    /// The release matrix matches the ABI table.
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

    /// GitHub Actions consumes bare `key=value` lines.
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
