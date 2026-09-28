#!/usr/bin/env bash
# Builds release binaries (nulld, null-wallet-rpc, null-desktop) and packs
# one archive per target into dist/, with SHA256SUMS.
#
#   scripts/dist.sh                         # Linux and Windows, from Linux
#   scripts/dist.sh aarch64-apple-darwin    # any target the host can build
#
# With cargo-zigbuild installed (pip install ziglang cargo-zigbuild), builds
# go through Zig: Linux binaries then need only glibc 2.28, and Windows
# builds need no MinGW. Without it, plain `cargo build` is used, which
# suits native builds such as CI's macOS and Windows runners. macOS
# targets need a Mac: Apple's SDK is not available elsewhere.
set -euo pipefail

cd "$(dirname "$0")/.."

# The oldest glibc the Linux builds may require: 2018 and later distros.
GLIBC=2.28
DEFAULT_TARGETS=(x86_64-unknown-linux-gnu x86_64-pc-windows-gnu)
BINARIES=(nulld null-wallet-rpc null-desktop)

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
DIST=dist

zigbuild_available() {
    cargo zigbuild --help >/dev/null 2>&1
}

# Builds every binary for one target.
build() {
    local target=$1
    rustup target add "$target" >/dev/null 2>&1 || true
    if zigbuild_available && [[ $target != *apple* && $target != *msvc* ]]; then
        local zig_target=$target
        [[ $target == *linux-gnu ]] && zig_target=$target.$GLIBC
        cargo zigbuild --release --locked -p null-node -p null-desktop --target "$zig_target"
    else
        cargo build --release --locked -p null-node -p null-desktop --target "$target"
    fi
}

# Packs one target's binaries and docs: .zip for Windows, .tar.gz elsewhere.
package() {
    local target=$1
    local name=null-$VERSION-$target
    local stage=$DIST/$name
    local exe=""
    [[ $target == *windows* ]] && exe=.exe
    rm -rf "$stage"
    mkdir -p "$stage"
    for binary in "${BINARIES[@]}"; do
        cp "target/$target/release/$binary$exe" "$stage/"
    done
    cp README.md "$stage/"
    cp docs/desktop.md "$stage/DESKTOP.md"
    (
        cd "$DIST"
        if [[ -n $exe ]]; then
            rm -f "$name.zip"
            if command -v zip >/dev/null; then
                zip -qr "$name.zip" "$name"
            else
                7z a -tzip "$name.zip" "$name" >/dev/null
            fi
        else
            tar -czf "$name.tar.gz" "$name"
        fi
    )
    rm -rf "$stage"
    echo "packed $DIST/$name"
}

checksums() {
    (
        cd "$DIST"
        shopt -s nullglob
        local archives=(null-*.tar.gz null-*.zip)
        if command -v sha256sum >/dev/null; then
            sha256sum "${archives[@]}" > SHA256SUMS
        else
            shasum -a 256 "${archives[@]}" > SHA256SUMS # macOS
        fi
    )
    echo "wrote $DIST/SHA256SUMS"
}

main() {
    local targets=("$@")
    [[ ${#targets[@]} -eq 0 ]] && targets=("${DEFAULT_TARGETS[@]}")
    mkdir -p "$DIST"
    for target in "${targets[@]}"; do
        build "$target"
        package "$target"
    done
    checksums
}

main "$@"
