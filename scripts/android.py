#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""The Android ABI table: one place that knows all three names for one target.

Gradle, Rust, and the NDK each have their own name for the same architecture,
and they do not all agree. `armeabi-v7a` is `armv7-linux-androideabi` to Rust
and `armv7a-linux-androideabi` to the NDK's clang wrapper — one letter apart, in
the one position where a wrong guess produces "no such file" at link time on one
ABI out of four. Deriving either name from the other works for three of them,
passes review, and breaks the 32-bit build.

> **Note:** For 32-bit ARM, the compiler is prefixed with
> `armv7a-linux-androideabi`, but the binutils tools are prefixed with
> `arm-linux-androideabi`. For other architectures, the prefixes are the same
> for all tools.
>
> — [Use the NDK with other build
> systems](https://developer.android.com/ndk/guides/other_build_systems),
> accessed 2026-08-24

The binutils half of that note is why the archiver below is `llvm-ar` rather
than a prefixed one: the unified tool takes no triple, so the second naming
split has nowhere to go wrong.

**`CXX` is not optional and its absence is silent.** BoringSSL's `crypto/` is
329 C++ files and no C files, so a cross build that names `CC` and not `CXX`
compiles the C++ half with the *host* compiler and produces a `libcrypto.a`
full of host objects. Nothing complains until the final link, which
`cargo check` never performs — so the whole arrangement can look correct
through a green CI run and fail the first time anything actually links it.
That is what this table's `--env` exists to make impossible.

    scripts/android.py --abis                   every ABI name, one per line
    scripts/android.py --target arm64-v8a       the Rust target triple
    scripts/android.py --env arm64-v8a          CC/AR/linker, as `key=value`
    scripts/android.py --toolchain arm64-v8a    write a CMake toolchain file
    scripts/android.py --selftest               this module's doctests

`--env` writes the lines `cargo` reads to find a cross toolchain, for appending
to `$GITHUB_ENV`. It verifies the compiler exists before naming it, because an
environment variable pointing at nothing fails three minutes later as a linker
error that names neither this script nor the missing file.

**BoringSSL's test tree cannot cross-compile, and `boring-sys` configures it
anyway.** `BUILD_TESTING` defaults on, so CMake descends into Google Benchmark
purely to build nothing — `boring-sys` asks only for the `crypto` and `ssl`
targets. Benchmark then probes for a regex backend with `try_compile`, writes
the answer with `CACHE BOOL "" FORCE`, and returns early on `if(DEFINED ...)`
ever after. `boring-sys` runs CMake twice, once per target, and its explicit
`-DCMAKE_C_COMPILER` disagrees with whatever `android.toolchain.cmake` installs
— so the second configure invalidates the cache, re-runs the probes in a
half-reset tree, and fails. A build that cannot fail is a build that never
configures Benchmark, which is what `--toolchain` is for: `boring-sys` skips its
own CMake setup entirely when `CMAKE_TOOLCHAIN_FILE` is set, so a file that
turns testing off and then includes the NDK's own is the one seam available.

**Run it through `uv`.** The PEP 723 block above is the whole environment.
"""

from __future__ import annotations

import argparse
import contextlib
import doctest
import enum
import io
import os
import platform
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple


class Exit(enum.IntEnum):
    """Exit statuses, as a closed sum rather than scattered integers."""

    OK = 0
    ERROR = 1
    UNKNOWN_ABI = 2


class Abi(NamedTuple):
    """One architecture, under all three of its names.

    `gradle` is the name the Play Store and `jniLibs/` use, `rust` is what
    `cargo --target` takes and what names the output directory, and `clang` is
    the NDK's toolchain triple, which prefixes the compiler wrapper.
    """

    gradle: str
    rust: str
    clang: str


#: The four ABIs the NDK supports, keyed by the name Gradle and the Play Store
#: use — which is also the directory name inside `src/main/jniLibs/`.
#:
#: The triples are quoted from the NDK's own table; see the module docstring.
ABIS: dict[str, Abi] = {
    "arm64-v8a": Abi("arm64-v8a", "aarch64-linux-android", "aarch64-linux-android"),
    "armeabi-v7a": Abi(
        "armeabi-v7a", "armv7-linux-androideabi", "armv7a-linux-androideabi"
    ),
    "x86": Abi("x86", "i686-linux-android", "i686-linux-android"),
    "x86_64": Abi("x86_64", "x86_64-linux-android", "x86_64-linux-android"),
}

#: The minimum API level the shipped library is built against.
#:
#: 26 is the floor `VpnService.Builder.setMetered` needs, and the oldest the
#: NDK's prebuilt sysroots still carry a clang wrapper for. Raising it drops
#: devices; lowering it does not compile.
DEFAULT_API = 26

#: The host directories the NDK ships prebuilt toolchains for. Any other host
#: has no toolchain to point at, which `compiler` reports as a missing file
#: rather than by guessing.
ROOT = Path(__file__).resolve().parent.parent

HOST_TAGS = {
    "Linux": "linux-x86_64",
    "Darwin": "darwin-x86_64",
    "Windows": "windows-x86_64",
}


def build_environment(
    abi: Abi, compiler: Path, ndk: Path, wrapper: Path
) -> dict[str, str]:
    """Every variable a cross build for `abi` needs, and no others.

    `cc` and `cargo` spell the same target differently — one lower-cased with
    underscores, the other upper-cased — so both spellings are derived here
    rather than written out per ABI.

    >>> ndk = Path("/ndk")
    >>> clang = ndk / "bin/armv7a-linux-androideabi26-clang"
    >>> env = build_environment(ABIS["armeabi-v7a"], clang, ndk, Path("/wrap.cmake"))
    >>> env["CC_armv7_linux_androideabi"]
    '/ndk/bin/armv7a-linux-androideabi26-clang'
    >>> env["CXX_armv7_linux_androideabi"]
    '/ndk/bin/armv7a-linux-androideabi26-clang++'
    >>> env["CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER"]
    '/ndk/bin/armv7a-linux-androideabi26-clang'
    >>> env["AR_armv7_linux_androideabi"]
    '/ndk/bin/llvm-ar'

    `ANDROID_NDK_HOME` is here because `boring-sys` reads it to find
    `build/cmake/android.toolchain.cmake`, and a runner that has more than one
    NDK installed can otherwise point it at a different one than the compilers
    above came from.

    >>> env["ANDROID_NDK_HOME"]
    '/ndk'

    And `CMAKE_TOOLCHAIN_FILE`, target-scoped, is what `boring-sys` and
    `cmake-rs` both read — see this module's header for why the wrapper exists
    rather than the NDK's own file being named directly.

    >>> env["CMAKE_TOOLCHAIN_FILE_armv7-linux-androideabi"]
    '/wrap.cmake'

    **The law this table exists to keep: one NDK, every tool.** A build that
    mixes a cross compiler with a host C++ compiler produces object files that
    only disagree at the final link.

    >>> tools = [env[key] for key in env if key.startswith(("CC_", "CXX_", "AR_"))]
    >>> all(tool.startswith(env["ANDROID_NDK_HOME"]) for tool in tools)
    True

    The compiler is also the linker: the NDK's wrapper is what knows the
    sysroot and the runtime, and invoking bare `ld` misses both.
    """
    lower = abi.rust.replace("-", "_")
    upper = lower.upper()
    return {
        f"CC_{lower}": str(compiler),
        # BoringSSL is C++. Omitting this is the bug that builds `libcrypto.a`
        # for the host and is not detectable until something links.
        f"CXX_{lower}": f"{compiler}++",
        f"AR_{lower}": str(compiler.parent / "llvm-ar"),
        f"CARGO_TARGET_{upper}_LINKER": str(compiler),
        "ANDROID_NDK_HOME": str(ndk),
        # Target-scoped: `boring-sys` skips its whole CMake configuration when
        # it sees this, which is exactly what makes the wrapper effective.
        f"CMAKE_TOOLCHAIN_FILE_{abi.rust}": str(wrapper),
    }


def compiler(ndk: Path, abi: Abi, api: int, host: str) -> Path:
    """Where the NDK keeps the clang wrapper for `abi` at `api`.

    >>> path = compiler(Path("/ndk"), ABIS["arm64-v8a"], 26, "Linux")
    >>> str(path)
    '/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang'

    The 32-bit ARM row is the one this function exists for: the wrapper is
    named after the *NDK's* triple, not Rust's.

    >>> compiler(Path("/ndk"), ABIS["armeabi-v7a"], 26, "Linux").name
    'armv7a-linux-androideabi26-clang'

    A host the NDK ships no toolchain for is an error, not a guess.

    >>> compiler(Path("/ndk"), ABIS["x86"], 26, "Plan9")
    Traceback (most recent call last):
    ValueError: the NDK ships no prebuilt toolchain for Plan9
    """
    tag = HOST_TAGS.get(host)
    if tag is None:
        raise ValueError(f"the NDK ships no prebuilt toolchain for {host}")
    return ndk / "toolchains/llvm/prebuilt" / tag / "bin" / f"{abi.clang}{api}-clang"


def ndk_toolchain_file(ndk: Path) -> Path:
    """The CMake toolchain file `boring-sys` hands to BoringSSL's build.

    >>> str(ndk_toolchain_file(Path("/ndk")))
    '/ndk/build/cmake/android.toolchain.cmake'
    """
    return ndk / "build/cmake/android.toolchain.cmake"


def toolchain(abi: Abi, ndk: Path, api: int) -> str:
    """A CMake toolchain file wrapping the NDK's.

    Two lines of intent and one `include`. `BUILD_TESTING` is what this exists
    for; the rest is what `boring-sys` would have supplied had it not skipped
    its own configuration on seeing `CMAKE_TOOLCHAIN_FILE` set.

    `FORCE`, because Benchmark writes its own answers with `FORCE` and a
    toolchain file is re-read for every `try_compile` — a plain `set` would be
    overwritten by the first probe it is meant to prevent.

    >>> print(toolchain(ABIS["arm64-v8a"], Path("/ndk"), 26))
    ... # doctest: +NORMALIZE_WHITESPACE
    # Generated by scripts/android.py. Do not edit.
    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
    set(ANDROID_ABI "arm64-v8a" CACHE STRING "" FORCE)
    set(ANDROID_PLATFORM "android-26" CACHE STRING "" FORCE)
    include("/ndk/build/cmake/android.toolchain.cmake")

    The ABI is the Gradle name, which is also what the NDK's own toolchain file
    expects — not the Rust target, and not the compiler triple.

    >>> 'ANDROID_ABI "armeabi-v7a"' in toolchain(ABIS["armeabi-v7a"], Path("/n"), 21)
    True
    """
    return "\n".join(
        [
            "# Generated by scripts/android.py. Do not edit.",
            'set(BUILD_TESTING OFF CACHE BOOL "" FORCE)',
            f'set(ANDROID_ABI "{abi.gradle}" CACHE STRING "" FORCE)',
            f'set(ANDROID_PLATFORM "android-{api}" CACHE STRING "" FORCE)',
            f'include("{ndk_toolchain_file(ndk)}")',
        ]
    )


def lookup(name: str) -> Abi:
    """The ABI called `name`, or a refusal naming what is on offer.

    >>> lookup("x86_64").rust
    'x86_64-linux-android'
    >>> lookup("arm64")
    Traceback (most recent call last):
    KeyError: "no such ABI 'arm64'; the NDK has arm64-v8a, armeabi-v7a, x86, x86_64"
    """
    try:
        return ABIS[name]
    except KeyError:
        offered = ", ".join(ABIS)
        raise KeyError(f"no such ABI {name!r}; the NDK has {offered}") from None


def smoke() -> int:
    """Run `main` end to end for every ABI against a fabricated NDK.

    **The doctests above cover the table; this covers the half that touches a
    filesystem and an argument parser.** That half is where a shadowed name or
    a mistyped key actually lives — and a `--selftest` that proves the pure
    core while `--env` cannot run at all is a green check reporting nothing.

    Nothing is compiled here. What is asserted is that every ABI produces a
    complete environment and a wrapper that turns testing off, which is exactly
    what a CI step consumes.
    """
    bin_dir = Path("toolchains/llvm/prebuilt") / HOST_TAGS[platform.system()] / "bin"
    failures = 0

    with tempfile.TemporaryDirectory() as scratch:
        ndk = Path(scratch)
        (ndk / bin_dir).mkdir(parents=True)
        ndk_toolchain_file(ndk).parent.mkdir(parents=True)
        ndk_toolchain_file(ndk).touch()
        (ndk / bin_dir / "llvm-ar").touch()
        for abi in ABIS.values():
            for suffix in ("clang", "clang++"):
                (ndk / bin_dir / f"{abi.clang}{DEFAULT_API}-{suffix}").touch()

        for name, abi in ABIS.items():
            emitted = io.StringIO()
            with contextlib.redirect_stdout(emitted):
                status = main(["--env", name, "--ndk", str(ndk)])
            printed = dict(
                line.split("=", 1) for line in emitted.getvalue().splitlines()
            )
            expected = {
                f"CC_{abi.rust.replace('-', '_')}",
                f"CXX_{abi.rust.replace('-', '_')}",
                f"AR_{abi.rust.replace('-', '_')}",
                f"CARGO_TARGET_{abi.rust.replace('-', '_').upper()}_LINKER",
                "ANDROID_NDK_HOME",
                f"CMAKE_TOOLCHAIN_FILE_{abi.rust}",
            }
            wrapper = Path(printed.get(f"CMAKE_TOOLCHAIN_FILE_{abi.rust}", os.devnull))
            for complaint, ok in [
                (f"{name}: --env exited {status}", status == Exit.OK),
                (f"{name}: emitted {set(printed)}", set(printed) == expected),
                (f"{name}: no wrapper at {wrapper}", wrapper.is_file()),
                (
                    f"{name}: wrapper does not disable testing",
                    wrapper.is_file() and "BUILD_TESTING OFF" in wrapper.read_text(),
                ),
            ]:
                if not ok:
                    print(f"android: {complaint}", file=sys.stderr)
                    failures += 1

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    what = parser.add_mutually_exclusive_group(required=True)
    what.add_argument("--abis", action="store_true", help="every ABI name")
    what.add_argument("--target", metavar="ABI", help="the Rust target triple")
    what.add_argument(
        "--env", metavar="ABI", help="CC/AR/linker assignments for $GITHUB_ENV"
    )
    what.add_argument(
        "--selftest", action="store_true", help="run this module's doctests and exit"
    )
    parser.add_argument(
        "--api", type=int, default=DEFAULT_API, help="Android API level"
    )
    parser.add_argument(
        "--ndk",
        type=Path,
        default=None,
        help="NDK root; defaults to $ANDROID_NDK_LATEST_HOME, then $ANDROID_NDK_HOME",
    )
    arguments = parser.parse_args(argv)

    # A flag rather than a `python -m doctest` invocation, so the tests run
    # under the interpreter the PEP 723 block pins.
    if arguments.selftest:
        results = doctest.testmod(
            verbose=False, optionflags=doctest.IGNORE_EXCEPTION_DETAIL
        )
        failures = smoke()
        print(
            f"android: {results.attempted} doctests, {results.failed} failed; "
            f"{len(ABIS)} ABIs smoke-tested, {failures} failed",
            file=sys.stderr,
        )
        return Exit.ERROR if results.failed or failures else Exit.OK

    if arguments.abis:
        print("\n".join(ABIS))
        return Exit.OK

    try:
        abi = lookup(arguments.target or arguments.env)
    except KeyError as refusal:
        print(refusal.args[0], file=sys.stderr)
        return Exit.UNKNOWN_ABI

    if arguments.target:
        print(abi.rust)
        return Exit.OK

    root = arguments.ndk or Path(
        os.environ.get("ANDROID_NDK_LATEST_HOME")
        or os.environ.get("ANDROID_NDK_HOME")
        or ""
    )
    if not root.name:
        print("no NDK: set --ndk or ANDROID_NDK_LATEST_HOME", file=sys.stderr)
        return Exit.ERROR

    try:
        clang = compiler(root, abi, arguments.api, platform.system())
    except ValueError as refusal:
        print(refusal.args[0], file=sys.stderr)
        return Exit.ERROR

    # Checked before they are named. An environment variable pointing at
    # nothing fails minutes later as a linker error mentioning neither this
    # script nor the file it could not find — and the C++ wrapper is checked
    # alongside the C one precisely because its absence is the failure that
    # otherwise reaches the final link disguised as an architecture mismatch.
    for required in (clang, Path(f"{clang}++"), ndk_toolchain_file(root)):
        if not required.is_file():
            print(f"missing from the NDK: {required}", file=sys.stderr)
            return Exit.ERROR

    # Written where the build can find it and the repository never sees it.
    wrapper = ROOT / "target" / "android" / f"{abi.gradle}.cmake"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text(toolchain(abi, root, arguments.api) + "\n")

    for key, value in build_environment(abi, clang, root, wrapper).items():
        print(f"{key}={value}")
    return Exit.OK


if __name__ == "__main__":
    sys.exit(main())
