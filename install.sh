#!/bin/sh
# h9b installer — zero dependency, POSIX sh, verifies SHA-256 before install.
#
#   curl -fsSL https://h9b.apizen.my.id/i | sh
#   curl -fsSL https://h9b.apizen.my.id/i | sh -s -- --version 0.2.0
#
# No-install mode — nothing is written outside a temp dir that is deleted on exit:
#
#   curl -fsSL https://h9b.apizen.my.id/i | sh -s -- activate H9B-XXXXX-XXXXX-XXXXX-XXX
#   curl -fsSL https://h9b.apizen.my.id/i | sh -s -- apply
#
# Any bare argument implies no-install: the binary is fetched to a temp dir, run
# with those arguments, then removed. The licence config still lands in ~/.h9b so
# the key survives; only the executable is thrown away.
#
# Env overrides:
#   H9B_MIRROR  primary download base (default https://h9b.apizen.my.id/dl)
#   H9B_BASE    release base URL used as fallback (default https://github.com/<org>/<repo>/releases)
#   H9B_DIR     install dir (default $HOME/.local/bin on unix, %LOCALAPPDATA%\h9b on windows)
set -eu

VERSION="${H9B_VERSION:-latest}"
REPO="${H9B_REPO:-naufalmng/hermes-9router-bypasser}"
# Our own server is the primary source. GitHub's asset CDN is unreliable on
# Indonesian consumer links — it establishes a connection and then delivers
# nothing — so releases are the fallback, not the default.
MIRROR="${H9B_MIRROR:-https://h9b.apizen.my.id/dl}"
RELEASES="${H9B_BASE:-https://github.com/$REPO/releases}"
MODE=install
RUNARGS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --base)    RELEASES="$2"; shift 2 ;;
    --mirror)  MIRROR="$2"; shift 2 ;;
    --ephemeral|--no-install|--tmp) MODE=ephemeral; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    --) shift; RUNARGS="$*"; MODE=ephemeral; break ;;
    # A bare argument means "run this, do not install me" — the shortest path for
    # someone who only wants to apply a patch once and be done.
    *) RUNARGS="$*"; MODE=ephemeral; break ;;
  esac
done

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux)  os=linux ;;
  darwin) os=darwin ;;
  mingw*|msys*|cygwin*) os=windows ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac

machine=$(uname -m)
case "$machine" in
  x86_64)  arch="amd64" ;;
  amd64)   arch="amd64" ;;
  aarch64) arch="arm64" ;;
  arm64)   arch="arm64" ;;
  *) echo "unsupported arch: $machine" >&2; exit 1 ;;
esac

ext=""
[ "$os" = "windows" ] && ext=".exe"
asset="h9b-${os}-${arch}${ext}"

mirror_url="$MIRROR/$asset"
mirror_sums="$MIRROR/SHA256SUMS"
if [ "$VERSION" = "latest" ]; then
  rel_url="$RELEASES/latest/download/$asset"
  rel_sums="$RELEASES/latest/download/SHA256SUMS"
else
  rel_url="$RELEASES/download/v$VERSION/$asset"
  rel_sums="$RELEASES/download/v$VERSION/SHA256SUMS"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "  fetching $asset ($VERSION)"

# Timeouts are not optional. A customer on a flaky link would otherwise sit at a
# silent hang forever — the first version of this script had no timeout and did
# exactly that on GitHub's asset CDN. --speed-limit/--speed-time matter more than
# --max-time here: the failure we actually hit was a connection that established
# fine and then delivered nothing, which only a stall detector aborts quickly.
fetch() { # fetch <url> <out>
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 20 --max-time 180 \
      --speed-limit 1024 --speed-time 20 \
      --retry 4 --retry-delay 2 --retry-connrefused "$1" -o "$2"
  else
    wget -q --timeout=20 --tries=4 -O "$2" "$1"
  fi
}

# Track where the binary came from: the checksum must come from the same source,
# or a version skew between mirror and release would look like a tampered file.
used_mirror=1
fetch "$mirror_url" "$tmp/h9b" || {
  echo "  mirror failed, trying releases" >&2
  used_mirror=0
  fetch "$rel_url" "$tmp/h9b" || { echo "download failed: $mirror_url and $rel_url" >&2; exit 1; }
}
if [ "$used_mirror" = "1" ]; then
  fetch "$mirror_sums" "$tmp/SHA256SUMS" 2>/dev/null || true
else
  fetch "$rel_sums" "$tmp/SHA256SUMS" 2>/dev/null ||
    fetch "$mirror_sums" "$tmp/SHA256SUMS" 2>/dev/null || true
fi

if [ -s "$tmp/SHA256SUMS" ]; then
  want=$(grep " $asset\$" "$tmp/SHA256SUMS" | awk '{print $1}')
  if [ -n "$want" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      got=$(sha256sum "$tmp/h9b" | awk '{print $1}')
    else
      got=$(shasum -a 256 "$tmp/h9b" | awk '{print $1}')
    fi
    if [ "$want" != "$got" ]; then
      echo "checksum mismatch — refusing to install" >&2
      echo "  expected $want" >&2
      echo "  got      $got" >&2
      exit 1
    fi
    echo "  checksum ok"
  fi
else
  echo "  WARNING: no SHA256SUMS published for this release" >&2
fi

chmod +x "$tmp/h9b" 2>/dev/null || true

# No-install path. The binary lives in $tmp and the EXIT trap deletes it, so the
# only thing left behind is ~/.h9b (the licence), which is what has to survive.
# Exit code is propagated verbatim: `apply` returns non-zero when verification
# says BELUM SELESAI, and a caller in a script must see that.
if [ "$MODE" = "ephemeral" ]; then
  if [ -z "$RUNARGS" ]; then
    echo "  fetched (not installed)" >&2
    echo "  usage: ... | sh -s -- <h9b command> [args]" >&2
    exit 2
  fi
  echo "  running: h9b $RUNARGS"
  echo
  # Capture the status explicitly rather than relying on `set -e`: the EXIT trap
  # must still fire, and the caller must see h9b's own exit code.
  rc=0
  # shellcheck disable=SC2086  # deliberate word splitting of the arg list
  "$tmp/h9b" $RUNARGS || rc=$?
  exit $rc
fi

if [ "$os" = "windows" ]; then
  dir="${H9B_DIR:-${LOCALAPPDATA:-$HOME/AppData/Local}/h9b}"
else
  dir="${H9B_DIR:-$HOME/.local/bin}"
fi
mkdir -p "$dir"
mv -f "$tmp/h9b" "$dir/h9b$ext"

echo "  installed -> $dir/h9b$ext"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "  NOTE: $dir is not on PATH" ;;
esac

echo
echo "next:"
echo "  h9b activate H9B-XXXXX-XXXXX-XXXXX-XXX"
echo "  h9b apply          # satu kali jalan, ditutup verifikasi: SELESAI / BELUM SELESAI"
