#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required for the Debian packaging test" >&2
    exit 1
}
command -v sha256sum >/dev/null 2>&1 || {
    echo "sha256sum is required for the Debian packaging test" >&2
    exit 1
}

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/syncplus-deb-test.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
case "$SOURCE_DATE_EPOCH" in
    ''|*[!0-9]*)
        echo "SOURCE_DATE_EPOCH must be an unsigned integer" >&2
        exit 1
        ;;
esac
export SOURCE_DATE_EPOCH

first_package=$(./packaging/build-deb.sh)
first_digest=$(sha256sum "$first_package" | awk '{print $1}')
second_package=$(./packaging/build-deb.sh)
second_digest=$(sha256sum "$second_package" | awk '{print $1}')
test "$first_digest" = "$second_digest"

extract_root="$TEST_ROOT/root"
dpkg-deb --extract "$second_package" "$extract_root"

for path in \
    usr/bin/syncplus \
    usr/bin/syncplus-scheduler-register \
    usr/bin/syncplus-scheduler-unregister \
    usr/share/applications/syncplus.desktop \
    usr/share/icons/hicolor/scalable/apps/syncplus.svg \
    usr/share/syncplus/help/index.md \
    usr/lib/systemd/user/syncplus-background.service \
    usr/lib/systemd/user/syncplus-background.timer; do
    test -e "$extract_root/$path"
done

test ! -e "$extract_root/etc/systemd/system"
if dpkg-deb --contents "$second_package" | grep -E ' /etc/| /var/| /home/|usr/lib/systemd/system/' >/dev/null; then
    echo "package must not install machine or system-service paths" >&2
    exit 1
fi
grep -F 'Exec=/usr/bin/syncplus' "$extract_root/usr/share/applications/syncplus.desktop" >/dev/null
grep -F 'ExecStart=/usr/bin/syncplus --background-scheduler' \
    "$extract_root/usr/lib/systemd/user/syncplus-background.service" >/dev/null
grep -F 'WantedBy=timers.target' \
    "$extract_root/usr/lib/systemd/user/syncplus-background.timer" >/dev/null
if grep -REn '^[[:space:]]*(User|Group)=root([[:space:]]*)$' \
    "$extract_root/usr/lib/systemd/user" >/dev/null; then
    echo "user scheduler must not run as root" >&2
    exit 1
fi

if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$extract_root/usr/share/applications/syncplus.desktop"
fi

if grep -RIE '/home/|/tmp/|DRAGNET|PRIVATE KEY|passphrase' \
    "$extract_root/usr/share" >/dev/null; then
    echo "package text assets must not contain machine paths or secrets" >&2
    exit 1
fi

XDG_DATA_HOME="$TEST_ROOT/data" \
XDG_CACHE_HOME="$TEST_ROOT/cache" \
    "$extract_root/usr/bin/syncplus" --background-scheduler

if [ "$(id -u)" -ne 0 ]; then
    fake_bin="$TEST_ROOT/fake-bin"
    calls="$TEST_ROOT/systemctl-calls"
    mkdir -p "$fake_bin"
    cat >"$fake_bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$SYSTEMCTL_CALLS"
EOF
    chmod 0755 "$fake_bin/systemctl"
    SYSTEMCTL_CALLS="$calls" PATH="$fake_bin:$PATH" \
        "$extract_root/usr/bin/syncplus-scheduler-register"
    SYSTEMCTL_CALLS="$calls" PATH="$fake_bin:$PATH" \
        "$extract_root/usr/bin/syncplus-scheduler-unregister"
    grep -F -- '--user enable --now syncplus-background.timer' "$calls" >/dev/null
    grep -F -- '--user disable --now syncplus-background.timer' "$calls" >/dev/null
fi

data_file="$TEST_ROOT/data/syncplus/syncplus.db"
mkdir -p "$(dirname -- "$data_file")"
printf '%s\n' preserved >"$data_file"
dpkg-deb --extract "$second_package" "$extract_root"
test "$(cat "$data_file")" = preserved
rm -rf "$extract_root"
test "$(cat "$data_file")" = preserved

echo "Debian package contract passed: $second_package"
