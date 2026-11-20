#!/usr/bin/env bash
# Reproducible release build: the same tag gives the same archive bytes on any
# machine with the same Rust version, whatever directory it's built in.
#   .github/release-build.sh <target> <out-dir>
set -euo pipefail
target=$1
out=$2
root=$(cd "$(dirname "$0")/.." && pwd)
# Git Bash on Windows: use D:/a/... paths, which both bash and native tools (cargo, rustc) accept
if command -v cygpath >/dev/null 2>&1; then root=$(cygpath -m "$root"); fi
cd "$root"
version="v$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
# building a tagged commit: the tag must name the same version (catches a missed bump)
if tag=$(git describe --tags --exact-match 2>/dev/null) && [ "$tag" != "$version" ] && [ -z "$(git status --porcelain -- Cargo.toml)" ]; then
    echo "release-build: tag $tag doesn't match Cargo.toml version $version" >&2
    exit 1
fi
# fixed timestamp (the commit's) and no machine paths in the binary
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
cargo_home=${CARGO_HOME:-$HOME/.cargo}
remap="--remap-path-prefix=$root=/parvez --remap-path-prefix=$cargo_home=/cargo"
if command -v cygpath >/dev/null 2>&1; then
    # rustc records C:\... paths on Windows
    cargo_home=$(cygpath -m "$cargo_home")
    remap="--remap-path-prefix=$(cygpath -w "$root")=/parvez --remap-path-prefix=$(cygpath -w "$cargo_home")=/cargo $remap"
fi
export RUSTFLAGS="$remap ${RUSTFLAGS:-}"
export CARGO_TARGET_DIR="$root/target/release-build"
cargo build --release --locked --target "$target"
name="parvez-$version-$target"
stage=$(mktemp -d)
mkdir "$stage/$name"
exe=parvez
case "$target" in *windows*) exe=parvez.exe ;; esac
cp "$CARGO_TARGET_DIR/$target/release/$exe" LICENSE README.md SECURITY.md "$stage/$name/"
mkdir -p "$out"
out=$(cd "$out" && pwd)
# deterministic archive: sorted names, fixed owner, modes and mtime, no gzip timestamp
# (GNU tar; on macOS that's `gtar` from Homebrew)
tar=tar
command -v gtar >/dev/null && tar=gtar
"$tar" --sort=name --owner=0 --group=0 --numeric-owner --mode='u=rwX,go=rX' --mtime="@$SOURCE_DATE_EPOCH" \
    --format=gnu -C "$stage" -cf - "$name" | gzip -n -9 > "$out/$name.tar.gz"
rm -rf "$stage"
if command -v sha256sum >/dev/null; then (cd "$out" && sha256sum "$name.tar.gz"); else (cd "$out" && shasum -a 256 "$name.tar.gz"); fi
