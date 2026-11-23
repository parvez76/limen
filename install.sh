#!/bin/sh
# Limen installer.
#
#   curl -fsSL https://parvez76.github.io/limen/install.sh | sh
#
# Downloads the release for this OS and CPU, checks it against the release's
# SHA256SUMS (and its GitHub build attestation when the `gh` CLI is installed),
# installs `limen` to ~/.limen/bin and adds that to PATH. Limen builds your
# programs with the Rust toolchain; if it's missing, the installer offers to
# set it up with the official rustup installer.
#
# Options (after `sh -s --` when piping):
#   -y, --yes          don't ask; install Rust if it's missing
#   --no-rust          never install Rust
#   --no-modify-path   don't edit shell profiles
# Environment:
#   LIMEN_VERSION     a release tag such as v0.17.0 (default: the latest)
#   LIMEN_HOME        install location (default: ~/.limen)
set -eu

REPO="parvez76/limen"
LEGACY_REPO="parvez76/project-parvez"
DOWNLOAD_BASE="${LIMEN_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download}"
LATEST_URL="${LIMEN_LATEST_URL:-https://github.com/$REPO/releases/latest}"
LIMEN_HOME="${LIMEN_HOME:-$HOME/.limen}"
YES=0
RUST=ask
MODIFY_PATH=1

say() { printf 'limen-install: %s\n' "$*"; }
die() { printf 'limen-install: error: %s\n' "$*" >&2; exit 1; }

for arg in "$@"; do
    case "$arg" in
        -y|--yes) YES=1 ;;
        --no-rust) RUST=no ;;
        --no-modify-path) MODIFY_PATH=0 ;;
        -h|--help) sed -n '2,20p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $arg" ;;
    esac
done

need() { command -v "$1" >/dev/null 2>&1 || die "this installer needs \`$1\`"; }
need curl
need tar
need uname
need mktemp

# ---- platform -------------------------------------------------------------
os=$(uname -s)
arch=$(uname -m)
case "$os/$arch" in
    Linux/x86_64|Linux/amd64) target=x86_64-unknown-linux-musl ;;
    Linux/aarch64|Linux/arm64) target=aarch64-unknown-linux-musl ;;
    Darwin/arm64|Darwin/aarch64) target=aarch64-apple-darwin ;;
    *) die "no prebuilt Limen for $os/$arch yet. Build it from source:
    cargo install --git https://github.com/$REPO --locked" ;;
esac

# ---- version --------------------------------------------------------------
version="${LIMEN_VERSION:-}"
if [ -z "$version" ]; then
    # /releases/latest redirects to /releases/tag/<tag>
    url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$LATEST_URL") || die "could not reach GitHub to find the latest release"
    version=${url##*/}
fi
case "$version" in
    v[0-9]*) ;;
    *) die "unexpected release tag \"$version\"" ;;
esac

# ---- download and verify ---------------------------------------------------
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
archive="limen-$version-$target.tar.gz"
say "downloading Limen $version for $target"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$archive" "$DOWNLOAD_BASE/$version/$archive" 2>/dev/null \
    || curl -fsSL -o "$tmp/$archive" "$DOWNLOAD_BASE/$version/$archive" \
    || die "download failed: $DOWNLOAD_BASE/$version/$archive"
curl -fsSL -o "$tmp/SHA256SUMS" "$DOWNLOAD_BASE/$version/SHA256SUMS" || die "could not download SHA256SUMS"

expected=$(awk -v f="$archive" '$2 == f || $2 == "*"f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || die "$archive is not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/$archive" | awk '{print $1}')
else
    actual=$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')
fi
[ "$actual" = "$expected" ] || die "checksum mismatch for $archive (expected $expected, got $actual). Nothing was installed."
say "checksum OK"

if command -v gh >/dev/null 2>&1; then
    # releases before the rename (v0.16.0, v0.17.0) were attested as parvez76/project-parvez
    if gh attestation verify "$tmp/$archive" --repo "$REPO" >/dev/null 2>&1 \
        || gh attestation verify "$tmp/$archive" --repo "$LEGACY_REPO" >/dev/null 2>&1; then
        say "build attestation OK (built by $REPO's release workflow)"
    else
        die "the GitHub build attestation for $archive did not verify. Nothing was installed."
    fi
else
    say "tip: install the GitHub CLI (gh) and the installer also checks the build attestation"
fi

# ---- install ----------------------------------------------------------------
tar -xzf "$tmp/$archive" -C "$tmp"
src="$tmp/limen-$version-$target/limen"
[ -f "$src" ] || die "the archive has no limen binary"
mkdir -p "$LIMEN_HOME/bin"
cp "$src" "$LIMEN_HOME/bin/limen.new"
chmod 755 "$LIMEN_HOME/bin/limen.new"
mv -f "$LIMEN_HOME/bin/limen.new" "$LIMEN_HOME/bin/limen"
say "installed $("$LIMEN_HOME/bin/limen" --version) to $LIMEN_HOME/bin"

# ---- PATH -------------------------------------------------------------------
cat > "$LIMEN_HOME/env" <<EOF
# Added by the Limen installer
case ":\${PATH}:" in
    *:"$LIMEN_HOME/bin":*) ;;
    *) export PATH="$LIMEN_HOME/bin:\$PATH" ;;
esac
EOF
line=". \"$LIMEN_HOME/env\""
if [ "$MODIFY_PATH" = 1 ]; then
    for rc in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
        case "$rc" in
            */.profile) ;;                    # always: login shells read it
            *) [ -f "$rc" ] || continue ;;    # only shells the user has
        esac
        if ! grep -qsF "$line" "$rc"; then
            printf '\n%s\n' "$line" >> "$rc"
        fi
    done
    if [ -d "$HOME/.config/fish" ]; then
        mkdir -p "$HOME/.config/fish/conf.d"
        printf 'fish_add_path -g "%s/bin"\n' "$LIMEN_HOME" > "$HOME/.config/fish/conf.d/limen.fish"
    fi
fi

# ---- Rust -------------------------------------------------------------------
have_cargo() { command -v cargo >/dev/null 2>&1 || [ -x "$HOME/.cargo/bin/cargo" ]; }
if ! have_cargo; then
    say "Limen builds your programs with the Rust toolchain, which isn't installed."
    if [ "$RUST" = ask ] && [ "$YES" = 0 ]; then
        if (: </dev/tty) 2>/dev/null; then    # a terminal we can really open, even when piped
            printf 'limen-install: install Rust now with the official installer (rustup.rs)? [Y/n] ' > /dev/tty
            read -r answer < /dev/tty || answer=n
            case "$answer" in [nN]*) RUST=no ;; *) RUST=yes ;; esac
        else
            RUST=no
        fi
    elif [ "$RUST" = ask ]; then
        RUST=yes
    fi
    if [ "$RUST" = yes ]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
            || die "installing Rust failed; see https://rustup.rs"
        say "Rust installed"
    else
        say "install Rust later with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    fi
fi

# Rust links programs with the system's C linker, which rustup doesn't install
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
    say "Rust also needs a C linker (\`cc\`), which isn't installed. Install it with:"
    if [ "$os" = Darwin ]; then
        echo "    xcode-select --install"
    elif command -v apt-get >/dev/null 2>&1; then
        echo "    sudo apt-get install -y build-essential"
    elif command -v dnf >/dev/null 2>&1; then
        echo "    sudo dnf install -y gcc"
    elif command -v apk >/dev/null 2>&1; then
        echo "    sudo apk add build-base"
    elif command -v pacman >/dev/null 2>&1; then
        echo "    sudo pacman -S --needed base-devel"
    elif command -v zypper >/dev/null 2>&1; then
        echo "    sudo zypper install -y gcc"
    else
        echo "    your distribution's gcc or clang package"
    fi
fi

echo
say "done. Open a new terminal (or run: . \"$LIMEN_HOME/env\"), then:"
echo "    limen doctor          # check the setup"
echo "    limen new hello       # start a project"
echo "    limen upgrade         # later: update to the newest release"
