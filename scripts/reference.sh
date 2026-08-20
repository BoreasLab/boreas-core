#!/usr/bin/env bash
# Fetches the pinned sing-box reference binary and prints its path.
#
# `tests/interop.rs` is the only check that Boreas's proxy protocols
# interoperate with a decoder Boreas did not write. It needs a binary, and
# a binary fetched from the internet is untrusted input like any other — so
# the version and the digest are both pinned here, and a mismatch is a
# failure rather than a warning.
#
# Stdout is the path and nothing else, so a caller can do:
#
#     BOREAS_SINGBOX=$(scripts/reference.sh) cargo test --test interop
#
# Assumes bash 4+, GNU coreutils (`sha256sum`), `curl`, and `tar`. Diagnostics
# go to stderr; the digests cover both architectures the project is developed
# on, so this is the same script CI and a contributor run.
set -euo pipefail

readonly VERSION=1.13.19
readonly BASE=https://github.com/SagerNet/sing-box/releases/download

# Digest of the release tarball, per architecture. An architecture absent from
# this table is a failure rather than an unverified download: the point of the
# table is that nothing arrives unchecked.
digest_for() {
  case "$1" in
  amd64) printf 'ef88a9e577d474210867bd708933d042e9b70106529df2656182c9db90106aa1\n' ;;
  arm64) printf '7fe3597a95a3c5ad67477b1d7653b9ce097e0be7c676758eba1fcf558f353d57\n' ;;
  *) return 1 ;;
  esac
}

# The release's name for this machine's architecture.
architecture() {
  case "$(uname -m)" in
  x86_64) printf 'amd64\n' ;;
  aarch64 | arm64) printf 'arm64\n' ;;
  *) return 1 ;;
  esac
}

main() {
  local cache="${BOREAS_REFERENCE_DIR:-${TMPDIR:-/tmp}/boreas-reference}"
  local arch
  arch=$(architecture) ||
    { echo "unsupported architecture: $(uname -m)" >&2; exit 1; }

  local name="sing-box-${VERSION}-linux-${arch}"
  local binary="${cache}/${name}/sing-box"

  # Idempotent: a cached binary of the pinned version is the answer, so a
  # re-run costs nothing and CI can cache the directory.
  if [[ -x ${binary} ]]; then
    printf '%s\n' "${binary}"
    return 0
  fi

  local expected
  expected=$(digest_for "${arch}")

  # Bracket: the download lands in a scratch directory that goes away on any
  # exit, so a failed verification cannot leave a half-trusted tarball behind.
  local scratch
  scratch=$(mktemp -d)
  # shellcheck disable=SC2064  # expand `scratch` now: the trap must not depend
  # on a variable a later failure could have rebound.
  trap "rm -rf '${scratch}'" EXIT

  echo "fetching ${name}" >&2
  curl --fail --silent --show-error --location \
    --output "${scratch}/release.tar.gz" \
    "${BASE}/v${VERSION}/${name}.tar.gz"

  printf '%s  %s\n' "${expected}" "${scratch}/release.tar.gz" |
    sha256sum --check --status ||
    { echo "digest mismatch for ${name}: refusing to run it" >&2; exit 1; }

  tar --extract --gzip --file "${scratch}/release.tar.gz" \
    --directory "${scratch}" "${name}/sing-box"

  # Publish atomically, so a concurrent run either sees no binary or a whole
  # verified one, never a partially extracted file.
  mkdir -p "${cache}"
  mv "${scratch}/${name}" "${cache}/${name}.$$"
  mv "${cache}/${name}.$$" "${cache}/${name}"

  printf '%s\n' "${binary}"
}

main "$@"
