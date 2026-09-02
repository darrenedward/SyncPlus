#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

command -v cargo >/dev/null 2>&1 || {
    echo "cargo is required to build the SyncPlus package" >&2
    exit 1
}
command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required to build the SyncPlus package" >&2
    exit 1
}
command -v dpkg-architecture >/dev/null 2>&1 || {
    echo "dpkg-architecture is required to build the SyncPlus package" >&2
    exit 1
}

package_id=$(cargo pkgid --package syncplus)
version=${SYNCPLUS_PACKAGE_VERSION:-${package_id##*#}}
case "$version" in
    ''|*[!0-9A-Za-z.+:~_-]*)
        echo "SyncPlus version is not a valid Debian version: $version" >&2
        exit 1
        ;;
esac

architecture=$(dpkg-architecture -qDEB_HOST_ARCH)
case "$architecture" in
    ''|*[!0-9A-Za-z_-]*)
        echo "Unsupported Debian architecture value: $architecture" >&2
        exit 1
        ;;
esac

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
case "$SOURCE_DATE_EPOCH" in
    ''|*[!0-9]*)
        echo "SOURCE_DATE_EPOCH must be an unsigned integer" >&2
        exit 1
        ;;
esac
export SOURCE_DATE_EPOCH

cargo_home=${CARGO_HOME:-${HOME:-}/.cargo}
case "$cargo_home" in
    /*)
        ;;
    *)
        echo "CARGO_HOME must be an absolute path when set" >&2
        exit 1
        ;;
esac
RUSTFLAGS="--remap-path-prefix=$ROOT=. --remap-path-prefix=$cargo_home=/.cargo"
export RUSTFLAGS

build_root="$ROOT/target/debian"
staging="$build_root/syncplus"
package_path="$build_root/syncplus_${version}_${architecture}.deb"
rm -rf "$staging" "$package_path"
mkdir -p "$staging/DEBIAN"

cargo build --locked --release --package syncplus >/dev/null

install -Dm0755 target/release/syncplus \
    "$staging/usr/bin/syncplus"
install -Dm0755 packaging/bin/syncplus-scheduler-register \
    "$staging/usr/bin/syncplus-scheduler-register"
install -Dm0755 packaging/bin/syncplus-scheduler-unregister \
    "$staging/usr/bin/syncplus-scheduler-unregister"
install -Dm0644 packaging/syncplus.desktop \
    "$staging/usr/share/applications/syncplus.desktop"
install -Dm0644 packaging/icons/syncplus.svg \
    "$staging/usr/share/icons/hicolor/scalable/apps/syncplus.svg"
install -Dm0644 packaging/systemd/syncplus-background.service \
    "$staging/usr/lib/systemd/user/syncplus-background.service"
install -Dm0644 packaging/systemd/syncplus-background.timer \
    "$staging/usr/lib/systemd/user/syncplus-background.timer"
install -Dm0644 packaging/help/index.md \
    "$staging/usr/share/syncplus/help/index.md"
install -Dm0644 README.md \
    "$staging/usr/share/doc/syncplus/README.md"

printf '%s\n' \
    'Package: syncplus' \
    "Version: $version" \
    'Section: utils' \
    'Priority: optional' \
    "Architecture: $architecture" \
    'Maintainer: SyncPlus maintainers <maintainers@syncplus.invalid>' \
    'Depends: libc6, libgcc-s1, libstdc++6, rsync, openssh-client' \
    'Suggests: systemd' \
    'Description: Safety-first Linux file synchronization' \
    ' SyncPlus provides reviewed, verified, and recoverable local and SSH synchronization.' \
    >"$staging/DEBIAN/control"

find "$staging" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
dpkg-deb --build --root-owner-group "$staging" "$package_path" >/dev/null
printf '%s\n' "$package_path"
