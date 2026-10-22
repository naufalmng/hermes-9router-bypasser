#!/bin/sh
# h9b installer — zero dependency, POSIX sh, verifies SHA-256 before install.
#
#   curl -fsSL https://h9b.apizen.my.id/i | sh
#   curl -fsSL https://h9b.apizen.my.id/i | sh -s -- --version 0.1.0
#
# Env overrides:
#   H9B_BASE   release base URL (default https://github.com/<org>/<repo>/releases/download)
#   H9B_DIR    install dir (default $HOME/.local/bin on unix, %LOCALAPPDATA%\h9b on windows)
set -eu

VERSION="${H9B_VERSION:-latest}"
REPO="${H9B_REPO:-naufalmng/hermes-9router-bypasser}"
BASE="${H9B_BASE:-https://github.com/$REPO/releases}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --base)    BASE="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
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

if [ "$VERSION" = "latest" ]; then
  url="$BASE/latest/download/$asset"
  sums_url="$BASE/latest/download/SHA256SUMS"
else
  url="$BASE/download/v$VERSION/$asset"
  sums_url="$BASE/download/v$VERSION/SHA256SUMS"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "  fetching $asset ($VERSION)"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tmp/h9b" || { echo "download failed: $url" >&2; exit 1; }
  curl -fsSL "$sums_url" -o "$tmp/SHA256SUMS" 2>/dev/null || true
else
  wget -qO "$tmp/h9b" "$url" || { echo "download failed: $url" >&2; exit 1; }
  wget -qO "$tmp/SHA256SUMS" "$sums_url" 2>/dev/null || true
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

if [ "$os" = "windows" ]; then
  dir="${H9B_DIR:-${LOCALAPPDATA:-$HOME/AppData/Local}/h9b}"
else
  dir="${H9B_DIR:-$HOME/.local/bin}"
fi
mkdir -p "$dir"
chmod +x "$tmp/h9b" 2>/dev/null || true
mv -f "$tmp/h9b" "$dir/h9b$ext"

echo "  installed -> $dir/h9b$ext"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "  NOTE: $dir is not on PATH" ;;
esac

echo
echo "next:"
echo "  h9b activate H9B-XXXXX-XXXXX-XXXXX-XXX"
echo "  h9b apply"
