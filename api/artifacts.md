# Getting the binaries

You do not build Boreas. You download it, check it is what it claims to be, and
unpack it into your project.

Every binary is built by GitHub Actions from a commit on `main`, signed with
build provenance, and attached to a release at
[BoreasLab/boreas-core](https://github.com/BoreasLab/boreas-core/releases).

## Why you do not build it yourself

Not a policy — an arithmetic. The core links BoringSSL through `boring-sys` and
compiles C in `ring`, so producing one artefact needs a full C toolchain
targeting that platform:

- **The Windows DLL can only be built on Windows**, against MSVC. There is no
  cross-compile from Linux or macOS worth maintaining.
- **The Android shared objects need the NDK**, one clang per ABI, and produce
  four files that must agree about the API level they were built for.

Reproducing that on four machines is four chances to ship a binary nobody else
can reproduce. One builder, attested, is the whole point.

## The two kinds of release

| | Tag | Cut by | Marked |
| --- | --- | --- | --- |
| **Release** | `v0.4.2` | a human, deliberately | Latest |
| **Pre-release** | `v0.4.3-dev.2026-08-24.11-30-00.a1b2c3d4e5f6` | every push to `main` | Pre-release |

A pre-release is named for the patch that **has not happened yet**, stamped with
the build time and the commit it was built from. That is not decoration: both
tags are valid SemVer, and SemVer sorts a pre-release *below* the release sharing
its version — so `v0.4.3-dev.…` comes after `v0.4.2` and before `v0.4.3`, and a
tool that sorts tags gets "newest" right without knowing any of this.

The stamp reads `yyyy-mm-dd.hh-mm-ss`, zero-padded, in UTC. Fixed widths are what
make later builds sort later.

**Which to use.** During integration, a pre-release: it tracks `main` and you get
a fix the day it lands. Pin the exact tag — never "latest pre-release" — so your
build is reproducible and an ABI change is something you adopt rather than
something that happens to you. For anything you ship, a release.

Because pre-releases are marked as such, `gh release download` with no tag gives
you the newest **release** and never a pre-release. That is deliberate.

## What is in them

Two archives per release, each laid out the way your build system already
expects, so unpacking is a copy and never a rename.

```
boreas-0.4.2-android.tar.gz
  jniLibs/arm64-v8a/libboreas.so
  jniLibs/armeabi-v7a/libboreas.so
  jniLibs/x86/libboreas.so
  jniLibs/x86_64/libboreas.so
  include/boreas.h

boreas-0.4.2-windows.zip
  runtimes/win-x64/native/boreas.dll
  runtimes/win-arm64/native/boreas.dll
  include/boreas.h
```

`jniLibs/<abi>/` is Gradle's source set: copy it over `src/main/jniLibs/`.
`runtimes/<rid>/native/` is the layout .NET resolves a native dependency from.

`boreas.h` ships in both. Neither Kotlin nor C# includes it, but it is the source
of truth your declarations are written against — and `BOREAS_ABI_VERSION` in it
is the number your startup check compares. A binary without its header is a
binary you cannot check anything about.

Android binaries are built against **API level 26**, which is the floor
`VpnService.Builder.setMetered` needs.

`SHA256SUMS` covers both archives.

## Fetching one

```sh
gh release download v0.4.2 --repo BoreasLab/boreas-core --pattern 'boreas-*-android.tar.gz'
```

Or without `gh`, from the predictable URL:

```sh
curl -fLO https://github.com/BoreasLab/boreas-core/releases/download/v0.4.2/boreas-0.4.2-android.tar.gz
```

Pre-release tags contain no characters that need escaping in a URL.

## Checking it

Two checks, and they answer different questions.

**The checksum answers "did this arrive intact".**

```sh
gh release download v0.4.2 --repo BoreasLab/boreas-core --pattern 'SHA256SUMS'
sha256sum --check --ignore-missing SHA256SUMS
```

**Provenance answers "was this built by that workflow, from that commit".** Every
archive carries a SLSA build provenance attestation, signed at build time. This
is the one that means something: a checksum only proves the file matches a list
that came from the same place the file did.

```sh
gh attestation verify boreas-0.4.2-android.tar.gz --repo BoreasLab/boreas-core
```

It prints the workflow and the commit the archive was built from. **Do this in
CI, not just once by hand** — an artefact fetched on every build is a
supply-chain edge, and this is the check that guards it.

## Checking it is the right one, at runtime

The header's `BOREAS_ABI_VERSION` is what your code was compiled against.
`boreas_abi_version()` is what the library you loaded actually implements. They
are the same number when the two shipped together and different when an
installer went wrong.

Compare them at startup, before anything else, and refuse to run on a mismatch.
A stale library otherwise reads every field at the wrong offset and behaves
inexplicably; there is no later moment at which that is cheap to notice.

See [abi.md](abi.md#layout-guarantees) for what an ABI bump means for you, and
[stability.md](stability.md) for what will and will not change under one.

## When a build is missing

The android and windows jobs do not stop for each other, so a release can carry
one archive and not the other. That is a build failure, not a decision — tell us
rather than working around it.
