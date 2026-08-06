#!/bin/sh
# install.sh — download and install the `qw` CLI from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/agarwalvivek29/quickwit-cli/main/install.sh | sh
#
# Environment overrides:
#   QW_VERSION   pin a version, e.g. v0.2.0 or 0.2.0   (default: latest release)
#   BINDIR       install directory                     (default: /usr/local/bin, else ~/.local/bin)
#   GITHUB_TOKEN used for the release API call to dodge unauthenticated rate limits
#
# POSIX sh; needs curl (or wget) and tar.
set -eu

REPO="agarwalvivek29/quickwit-cli"
BINARY="qw"

info() { printf '  %s\n' "$*" >&2; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- fetch helper: `fetch <url>` writes body to stdout ------------------------
if command -v curl >/dev/null 2>&1; then
  fetch() {
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" "$1"
    else
      curl -fsSL "$1"
    fi
  }
  download() { curl -fsSL -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch()    { wget -qO- "$1"; }
  download() { wget -qO "$2" "$1"; }
else
  err "need curl or wget installed"
fi

command -v tar >/dev/null 2>&1 || err "need tar installed"

# --- detect platform ----------------------------------------------------------
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux)  os=linux ;;
  darwin) os=darwin ;;
  *) err "unsupported OS: $os (prebuilt binaries: linux, darwin)" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) err "unsupported architecture: $arch (prebuilt binaries: amd64, arm64)" ;;
esac

# --- resolve version ----------------------------------------------------------
tag="${QW_VERSION:-}"
if [ -z "$tag" ]; then
  info "resolving latest release..."
  tag=$(fetch "https://api.github.com/repos/$REPO/releases/latest" \
        | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name" *: *"([^"]+)".*/\1/')
  [ -n "$tag" ] || err "could not determine the latest release (set QW_VERSION to pin one)"
fi
case "$tag" in v*) ver="${tag#v}" ;; *) ver="$tag"; tag="v$tag" ;; esac

# --- download + verify + install ----------------------------------------------
asset="${BINARY}_${ver}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

info "downloading $asset ($tag)..."
download "$base/$asset" "$tmp/$asset" || err "download failed: $base/$asset"

# Best-effort checksum verification against the release's checksums.txt.
if download "$base/checksums.txt" "$tmp/checksums.txt" 2>/dev/null; then
  sum=""
  if command -v sha256sum >/dev/null 2>&1; then sum=$(sha256sum "$tmp/$asset" | awk '{print $1}');
  elif command -v shasum   >/dev/null 2>&1; then sum=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}'); fi
  if [ -n "$sum" ]; then
    grep -q "$sum" "$tmp/checksums.txt" || err "checksum mismatch for $asset"
    info "checksum ok"
  fi
fi

tar -xzf "$tmp/$asset" -C "$tmp"
[ -f "$tmp/$BINARY" ] || err "archive did not contain a '$BINARY' binary"
chmod +x "$tmp/$BINARY"

# Pick an install dir: honor BINDIR, else /usr/local/bin, else ~/.local/bin.
dir="${BINDIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ] || [ "$(id -u)" = 0 ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir" 2>/dev/null || true

if [ -w "$dir" ]; then
  mv "$tmp/$BINARY" "$dir/$BINARY"
elif command -v sudo >/dev/null 2>&1; then
  info "installing to $dir (needs sudo)..."
  sudo mv "$tmp/$BINARY" "$dir/$BINARY"
else
  err "cannot write to $dir; re-run with BINDIR=\$HOME/.local/bin or as root"
fi

info "installed $BINARY $tag -> $dir/$BINARY"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) info "note: $dir is not on your PATH — add:  export PATH=\"$dir:\$PATH\"" ;;
esac
"$dir/$BINARY" --version 2>/dev/null || true
