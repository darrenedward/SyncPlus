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
command -v strings >/dev/null 2>&1 || {
    echo "strings is required for the Debian packaging test" >&2
    exit 1
}
command -v fakeroot >/dev/null 2>&1 || {
    echo "fakeroot is required for the disposable dpkg install test" >&2
    exit 1
}
command -v sqlite3 >/dev/null 2>&1 || {
    echo "sqlite3 is required for the XDG preservation test" >&2
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

first_package=$(SYNCPLUS_PACKAGE_VERSION=0.1.0-1 ./packaging/build-deb.sh)
first_digest=$(sha256sum "$first_package" | awk '{print $1}')
second_package=$(SYNCPLUS_PACKAGE_VERSION=0.1.0-2 ./packaging/build-deb.sh)
same_version_package=$(SYNCPLUS_PACKAGE_VERSION=0.1.0-1 ./packaging/build-deb.sh)
same_version_digest=$(sha256sum "$same_version_package" | awk '{print $1}')
test "$first_digest" = "$same_version_digest"

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
if strings "$extract_root/usr/bin/syncplus" | grep -E '/home/[^/]+/(\.cargo|Websites)/' >/dev/null; then
    echo "release binary must not contain local build paths" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    fake_bin="$TEST_ROOT/fake-bin"
    calls="$TEST_ROOT/systemctl-calls"
    mkdir -p "$fake_bin"
    cat >"$fake_bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$SYSTEMCTL_CALLS"
EOF
    chmod 0755 "$fake_bin/systemctl"
fi

install_root="$TEST_ROOT/install-root"
data_home="$TEST_ROOT/canonical-xdg"
data_file="$data_home/syncplus/syncplus.db"
mkdir -p "$install_root/var/lib/dpkg" "$install_root/var/log" "$data_home"
: >"$install_root/var/lib/dpkg/status"
run_dpkg() {
    fakeroot dpkg --force-not-root --log="$install_root/var/log/dpkg.log" \
        --root="$install_root" --admindir="$install_root/var/lib/dpkg" \
        --instdir="$install_root" "$@"
}
run_dpkg --force-depends --unpack "$first_package" >/dev/null
test -x "$install_root/usr/bin/syncplus"
test -f "$install_root/usr/share/applications/syncplus.desktop"
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$install_root/usr/share/applications"
fi
XDG_DATA_HOME="$TEST_ROOT/installed-data" \
XDG_CACHE_HOME="$TEST_ROOT/installed-cache" \
    "$install_root/usr/bin/syncplus" --background-scheduler
test -f "$TEST_ROOT/installed-data/syncplus/syncplus.db"
XDG_DATA_HOME="$data_home" \
XDG_CACHE_HOME="$TEST_ROOT/canonical-cache" \
    "$install_root/usr/bin/syncplus" --background-scheduler
sqlite3 "$data_file" <<'EOF'
CREATE TABLE package_preservation_records (kind TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO package_preservation_records VALUES ('profile', 'profile-1');
INSERT INTO package_preservation_records VALUES ('report', 'report-1');
INSERT INTO package_preservation_records VALUES ('schedule', 'schedule-1');
INSERT INTO package_preservation_records VALUES ('recovery-record', 'recovery-1');
EOF
mkdir -p "$data_home/syncplus/backups" "$data_home/syncplus/quarantine" "$data_home/syncplus/recovery"
printf '%s\n' backup >"$data_home/syncplus/backups/backup.sqlite3.gz"
printf '%s\n' quarantined >"$data_home/syncplus/quarantine/corrupt.sqlite3"
printf '%s\n' recovery >"$data_home/syncplus/recovery/recovery-item"
if [ "$(id -u)" -ne 0 ]; then
    SYSTEMCTL_CALLS="$calls" PATH="$fake_bin:$PATH" \
        "$install_root/usr/bin/syncplus-scheduler-register"
    SYSTEMCTL_CALLS="$calls" PATH="$fake_bin:$PATH" \
        "$install_root/usr/bin/syncplus-scheduler-unregister"
    grep -F -- '--user enable --now syncplus-background.timer' "$calls" >/dev/null
    grep -F -- '--user disable --now syncplus-background.timer' "$calls" >/dev/null
fi
run_dpkg --force-depends --unpack "$second_package" >/dev/null
test "$(sqlite3 "$data_file" 'SELECT group_concat(kind, "|") FROM (SELECT kind FROM package_preservation_records ORDER BY kind)')" = 'profile|recovery-record|report|schedule'
test "$(cat "$data_home/syncplus/backups/backup.sqlite3.gz")" = backup
test "$(cat "$data_home/syncplus/quarantine/corrupt.sqlite3")" = quarantined
test "$(cat "$data_home/syncplus/recovery/recovery-item")" = recovery
run_dpkg --remove syncplus >/dev/null
test ! -e "$install_root/usr/bin/syncplus"
test "$(sqlite3 "$data_file" 'SELECT group_concat(kind, "|") FROM (SELECT kind FROM package_preservation_records ORDER BY kind)')" = 'profile|recovery-record|report|schedule'
test "$(cat "$data_home/syncplus/backups/backup.sqlite3.gz")" = backup
test "$(cat "$data_home/syncplus/quarantine/corrupt.sqlite3")" = quarantined
test "$(cat "$data_home/syncplus/recovery/recovery-item")" = recovery

rm -rf "$extract_root"

echo "Debian package contract passed: $second_package"
